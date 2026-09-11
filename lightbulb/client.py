"""Lightbulb platform API client.

Usage::

    from lightbulb import LightbulbClient, ApiKeyAuth

    auth = ApiKeyAuth(
        api_key="your-internal-api-key",
        tenant_id="00000000-0000-0000-0000-000000000001",
        user_id="00000000-0000-0000-0000-000000000002",
    )
    client = LightbulbClient("https://agents.lightbulbpartners.com", auth=auth)

    # Dispatch a document agent action
    result = client.dispatch("document_intelligence", action="search_documents", message="quarterly revenue")

    # Stream a domain agent chat
    for event in client.stream_chat("document_intelligence", message="Create a quarterly report"):
        print(event)

Security notes:
- Credentials are injected via the AuthStrategy and never logged.
- All inputs are validated before being sent.
- The client enforces HTTPS in production (non-localhost) by default.
- Request/response bodies are size-bounded to prevent memory exhaustion.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Mapping, Optional, Sequence
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from lightbulb.native_coding import NativeCodingClient
from lightbulb._version import __version__
from lightbulb.agent_ops import (
    AgentOpsProtocolError,
    build_training_pair_request,
    is_training_pair_admission_unavailable,
    parse_training_pair_admission_unavailable,
    parse_training_pair_input_custody,
    parse_training_pair_preflight,
    parse_training_pair_readiness,
    parse_training_pair_status,
    response_json as agent_ops_response_json,
    validate_training_pair_idempotency_key,
)
from lightbulb.auth import ApiKeyAuth, AuthStrategy, JwtAuth
from lightbulb.errors import LightbulbError, raise_if_error
from lightbulb.golden_loop_projections import (
    GovernedCommunicationAdmission,
    GovernedCommunicationAdmissionResult,
    ProjectWorkPacketStartResult,
    ServiceCaseResolutionRun,
    ServiceCaseResolutionStart,
    parse_governed_communication_admission,
    parse_project_work_packet_start,
    parse_service_case_resolution_run,
)
from lightbulb.finance_reconciliation import (
    FinanceReconciliationRequest,
    FinanceReconciliationResult,
    FinanceReconciliationRunDetails,
    FinanceReconciliationRunSummary,
    build_finance_reconciliation_request,
    parse_finance_reconciliation_run_details,
    parse_finance_reconciliation_run_summaries,
    parse_finance_reconciliation_result,
)
from lightbulb.governed_connector_contracts import (
    is_ephemeral_non_replayable_read,
    reject_ephemeral_read_idempotency,
)
from lightbulb.project_creation import (
    ProjectCreationDraft,
    ProjectCreationPreflightError,
    ProjectCreationPreflightReceipt,
    build_project_creation_preflight_request,
    build_project_creation_preflight_refinement_request,
    inspect_project_game_campaign as build_project_game_campaign,
    inspect_project_creation_world_ready as build_project_creation_world_ready,
    normalize_project_coding_harness,
    normalize_project_play_style,
    normalize_project_uuid,
    project_creation_preflight_receipt_from_events,
    project_creation_preflight_refinement_receipt_from_events,
)
from lightbulb.project_feedback import (
    ProjectPreflightSemanticFeedbackReceipt,
    SemanticFeedbackValue,
    bind_project_preflight_feedback_receipt,
    build_project_preflight_feedback_request,
)
from lightbulb.project_missions import (
    build_project_mission_action_binding,
    build_project_mission_run_start,
)
from lightbulb.project_learning_reviews import build_project_learning_review_request
from lightbulb.project_learning_runs import (
    build_project_learning_run_admission_request,
    build_project_learning_run_prepare_request,
)
from lightbulb.project_learning_result_evaluations import (
    build_project_learning_result_admission_request,
)
from lightbulb.project_shadow_learner_updates import (
    PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA,
)
from lightbulb.project_game_snapshot import (
    PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES,
    normalize_project_game_snapshot_uuid,
    validate_project_game_snapshot,
)
from lightbulb.project_outcomes import build_project_business_outcome_observation
from lightbulb.project_policy import (
    build_project_policy_assignment,
    build_project_policy_evaluation_request,
)
from lightbulb.project_science import build_project_science_evidence_observation
from lightbulb.procurement_golden_loop import (
    ProcurementAmbiguity,
    ProcurementApprovalBinding,
    ProcurementCancellation,
    ProcurementCommandReceipt,
    ProcurementCustodyReceipt,
    ProcurementFailure,
    ProcurementGoodsReceipt,
    ProcurementMatchedClose,
    ProcurementOutcomeReceipt,
    ProcurementPurchaseOrderJournalBinding,
    ProcurementReconciliation,
    ProcurementStart,
    ProcurementSupplierInvoice,
    ProcurementThreeWayMatch,
    validate_procurement_run_ref,
)

logger = logging.getLogger(__name__)

_MAX_MESSAGE_LENGTH = 100_000
_MAX_RESPONSE_BYTES = 50 * 1024 * 1024  # 50 MB total per stream
_MAX_SSE_LINE_BYTES = 1 * 1024 * 1024  # 1 MB per SSE line (DoS guard)
_MAX_SSE_EVENT_BYTES = 8 * 1024 * 1024  # 8 MB per accumulated event
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 120.0
_CONNECTOR_ROUTE_DESCRIPTOR_SCHEMA = "lightbulb.connector_route_descriptor.v1"

# Cap outbound request bodies. The hosted API sits behind an edge proxy (Cloudflare) that rejects
# oversized request bodies — historically as an opaque 403. Fail fast here with an actionable
# error instead, so callers know to trim/chunk the payload rather than chasing a confusing 403.
# Configurable via LIGHTBULB_MAX_REQUEST_BODY_BYTES; default ~5 MB stays well under the edge limit.
_MAX_REQUEST_BODY_BYTES = int(
    os.getenv("LIGHTBULB_MAX_REQUEST_BODY_BYTES", str(5 * 1024 * 1024))
)

_CONTEXT_TOKEN_BUDGET_MIN = 128
_CONTEXT_TOKEN_BUDGET_MAX = 16_384
_CONTEXT_TOKEN_BUDGET_DEFAULT = 2_400
_CONTEXT_MAX_ITEMS_MIN = 1
_CONTEXT_MAX_ITEMS_MAX = 50
_CONTEXT_SPACE_REF_PATTERN = re.compile(r"ctx_[A-Za-z0-9_-]{16,48}")
_CONTEXT_BINDING_REF_PATTERN = re.compile(r"cxs_[A-Za-z0-9_-]{16,48}")
_CONTEXT_ITEM_REF_PATTERN = re.compile(r"(?:cxe|cxp)_[A-Za-z0-9_-]{16,48}")
_CONTEXT_HOST_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
_CONTEXT_IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_CONTEXT_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CONTEXT_GIT_HEAD_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_CONTEXT_REPOSITORY_KEYS = {
    "workspace",
    "dirty",
    "dirtyDigest",
    "dirty_digest",
    "continuityKey",
    "continuity_key",
    "branch",
    "head",
}
_CONTEXT_COMPANY_INHERIT = object()

_DYNAMIC_WORKFLOW_ENDPOINTS = {
    "start": "start",
    "attach": "attach",
    "status": "status",
    "next_assignment": "next-assignment",
    "submit_plan": "submit-plan",
    "submit_builder_result": "submit-builder-result",
    "submit_evaluator_verdict": "submit-evaluator-verdict",
    "cancel": "cancel",
}


def _validated_dynamic_workflow_response(
    operation: str,
    request_payload: Mapping[str, Any],
    response: httpx.Response,
) -> Dict[str, Any]:
    """Bound and validate one hosted dynamic-workflow response envelope."""
    from lightbulb.dynamic_workflow_mcp import (
        get_operation,
        validate_operation_exchange,
    )

    descriptor = get_operation(operation)
    max_bytes = int(
        descriptor.output_schema.get("x-lightbulb-max-json-bytes", 1_048_576)
    )
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray, memoryview)) and len(content) > max_bytes:
        raise ValueError(
            f"Dynamic workflow {operation} response exceeds its {max_bytes}-byte limit"
        )
    response_payload = response.json()
    _, validated_output = validate_operation_exchange(
        operation,
        request_payload,
        response_payload,
    )
    return validated_output


def _normalize_context_repository(
    repository: Mapping[str, Any],
) -> Dict[str, Any]:
    """Accept only the content-free repository continuity fingerprint contract."""
    unknown = set(map(str, repository.keys())) - _CONTEXT_REPOSITORY_KEYS
    if unknown:
        raise ValueError(
            "repository contains unsupported fields; raw paths, remotes, URLs, "
            "credentials, and arbitrary metadata are not accepted"
        )

    result: Dict[str, Any] = {}
    for field_name in ("workspace", "branch"):
        value = repository.get(field_name)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(f"repository.{field_name} must be a string")
        clean = value.strip()
        if (
            not clean
            or len(clean) > 200
            or any(ord(char) < 32 or ord(char) == 127 for char in clean)
        ):
            raise ValueError(
                f"repository.{field_name} must contain 1-200 visible characters"
            )
        if field_name == "workspace" and any(
            char in clean for char in ("/", "\\", ":")
        ):
            raise ValueError("repository.workspace must be a basename, not a path")
        if "://" in clean or re.search(r"[^\s/:@]+:[^\s/@]+@", clean):
            raise ValueError(
                f"repository.{field_name} must not contain a URL or credentials"
            )
        result[field_name] = clean

    if "dirty" in repository:
        if not isinstance(repository["dirty"], bool):
            raise ValueError("repository.dirty must be a boolean")
        result["dirty"] = repository["dirty"]

    aliases = (
        ("dirtyDigest", "dirty_digest", "dirtyDigest"),
        ("continuityKey", "continuity_key", "continuityKey"),
    )
    for canonical, alias, output_name in aliases:
        values = [repository[key] for key in (canonical, alias) if key in repository]
        if not values:
            continue
        if len(values) > 1 and values[0] != values[1]:
            raise ValueError(f"repository.{canonical} aliases disagree")
        value = values[0]
        if (
            not isinstance(value, str)
            or _CONTEXT_SHA256_PATTERN.fullmatch(value) is None
        ):
            raise ValueError(
                f"repository.{canonical} must be a lowercase SHA-256 digest"
            )
        result[output_name] = value

    if "head" in repository:
        value = repository["head"]
        if (
            not isinstance(value, str)
            or _CONTEXT_GIT_HEAD_PATTERN.fullmatch(value) is None
        ):
            raise ValueError(
                "repository.head must be a full lowercase Git object digest"
            )
        result["head"] = value
    return result


def _guard_request_body(payload: object, *, endpoint: str = "") -> None:
    """Raise a clear ValueError when a JSON request body would exceed the configured ceiling,
    rather than letting the edge proxy reject it with an opaque 403/413."""
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except Exception:
        return
    if size > _MAX_REQUEST_BODY_BYTES:
        raise ValueError(
            f"Request body is {size} bytes, over the {_MAX_REQUEST_BODY_BYTES}-byte limit"
            + (f" for {endpoint}" if endpoint else "")
            + ". Trim or chunk the payload (large documents/context), or raise "
            "LIGHTBULB_MAX_REQUEST_BODY_BYTES if the server/edge allows it."
        )


def _validate_context_public_ref(value: Any, field_name: str) -> str:
    """Validate an opaque Context Broker reference before putting it in a URL."""
    candidate = str(value or "").strip()
    if field_name == "context_ref":
        pattern = _CONTEXT_SPACE_REF_PATTERN
        kind = "Context Space"
    elif field_name == "binding_ref":
        pattern = _CONTEXT_BINDING_REF_PATTERN
        kind = "context binding"
    elif field_name.startswith("refs["):
        pattern = _CONTEXT_ITEM_REF_PATTERN
        kind = "context item"
    else:
        raise ValueError(f"Unsupported Context Broker reference field: {field_name}")
    if pattern.fullmatch(candidate) is None:
        raise ValueError(f"{field_name} must be an opaque {kind} public reference")
    return candidate


def _validate_context_host(value: Any) -> str:
    candidate = str(value or "").strip().lower().replace("-", "_")
    if _CONTEXT_HOST_PATTERN.fullmatch(candidate) is None:
        raise ValueError(
            "host must be a 1-40 character harness name such as codex or claude_code"
        )
    return candidate


def _validate_context_token_budget(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("token_budget must be an integer")
    try:
        budget = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("token_budget must be an integer") from exc
    if not _CONTEXT_TOKEN_BUDGET_MIN <= budget <= _CONTEXT_TOKEN_BUDGET_MAX:
        raise ValueError(
            "token_budget must be between "
            f"{_CONTEXT_TOKEN_BUDGET_MIN} and {_CONTEXT_TOKEN_BUDGET_MAX}"
        )
    return budget


def _validate_context_max_items(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("max_items must be an integer")
    try:
        maximum = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("max_items must be an integer") from exc
    if not _CONTEXT_MAX_ITEMS_MIN <= maximum <= _CONTEXT_MAX_ITEMS_MAX:
        raise ValueError(
            f"max_items must be between {_CONTEXT_MAX_ITEMS_MIN} and {_CONTEXT_MAX_ITEMS_MAX}"
        )
    return maximum


def _optional_context_text(
    value: Any,
    field_name: str,
    *,
    max_length: int = _MAX_MESSAGE_LENGTH,
) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    if len(candidate) > max_length:
        raise ValueError(f"{field_name} exceeds the {max_length}-character limit")
    return candidate


def _normalize_context_state(state: Mapping[str, Any] | None) -> Dict[str, Any]:
    if state is None:
        return {}
    if not isinstance(state, Mapping):
        raise ValueError("state must be a JSON object")
    aliases = {
        "objective": "objective",
        "plan": "plan",
        "decisions": "decisions",
        "constraints": "constraints",
        "open_loops": "openLoops",
        "openLoops": "openLoops",
        "next_actions": "nextActions",
        "nextActions": "nextActions",
        "summary": "summary",
        "metadata": "metadata",
    }
    unknown = sorted(str(key) for key in state if key not in aliases)
    if unknown:
        raise ValueError(f"state contains unsupported field(s): {', '.join(unknown)}")
    normalized: Dict[str, Any] = {}
    for source, target in aliases.items():
        if source not in state:
            continue
        if target in normalized and normalized[target] != state[source]:
            raise ValueError(f"state supplies conflicting values for {target}")
        normalized[target] = state[source]
    text_bounds = {"objective": 8_192, "summary": 16_384}
    for field_name, max_length in text_bounds.items():
        if field_name not in normalized:
            continue
        value = normalized[field_name]
        if not isinstance(value, str) or len(value) > max_length:
            raise ValueError(
                f"state.{field_name} must be a string of at most {max_length} characters"
            )
    for field_name in ("plan", "decisions", "constraints", "openLoops", "nextActions"):
        if field_name not in normalized:
            continue
        values = normalized[field_name]
        if not isinstance(values, list) or len(values) > 50:
            raise ValueError(
                f"state.{field_name} must be a JSON array of at most 50 strings"
            )
        if any(not isinstance(value, str) or len(value) > 4_096 for value in values):
            raise ValueError(
                f"state.{field_name} entries must be strings of at most 4096 characters"
            )
    if "metadata" in normalized and not isinstance(normalized["metadata"], Mapping):
        raise ValueError("state.metadata must be a JSON object")
    if "metadata" in normalized:
        normalized["metadata"] = dict(normalized["metadata"])
    return normalized


def _normalize_context_events(
    events: Sequence[Mapping[str, Any]] | None,
) -> List[Dict[str, Any]]:
    if events is None:
        return []
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise ValueError("events must be a JSON array")
    if len(events) > 50:
        raise ValueError("events may contain at most 50 items")
    normalized: List[Dict[str, Any]] = []
    for index, raw_event in enumerate(events):
        if not isinstance(raw_event, Mapping):
            raise ValueError(f"events[{index}] must be a JSON object")
        event_type = _optional_context_text(
            raw_event.get("type"), f"events[{index}].type", max_length=80
        )
        content = _optional_context_text(
            raw_event.get("content"), f"events[{index}].content", max_length=65_536
        )
        if event_type is None or content is None:
            raise ValueError(f"events[{index}] requires non-empty type and content")
        if re.fullmatch(r"[A-Za-z0-9._-]+", event_type) is None:
            raise ValueError(f"events[{index}].type contains unsupported characters")
        event: Dict[str, Any] = {"type": event_type, "content": content}
        role = _optional_context_text(
            raw_event.get("role"), f"events[{index}].role", max_length=32
        )
        if role:
            if re.fullmatch(r"[A-Za-z0-9._-]+", role) is None:
                raise ValueError(
                    f"events[{index}].role contains unsupported characters"
                )
            event["role"] = role
        token_count = raw_event.get("token_count", raw_event.get("tokenCount"))
        if token_count is not None:
            if isinstance(token_count, bool):
                raise ValueError(f"events[{index}].token_count must be an integer")
            try:
                token_count = int(token_count)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(
                    f"events[{index}].token_count must be an integer"
                ) from exc
            if not 0 <= token_count <= 1_000_000:
                raise ValueError(
                    f"events[{index}].token_count must be between 0 and 1000000"
                )
            event["tokenCount"] = token_count
        metadata = raw_event.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, Mapping):
                raise ValueError(f"events[{index}].metadata must be a JSON object")
            event["metadata"] = dict(metadata)
        normalized.append(event)
    return normalized


def _build_memory_regulation_payload(
    *,
    idempotency_key: str | None,
    budget: int | None,
    categories: Sequence[str] | None,
    dry_run: bool,
    max_summary_chars: int,
    empirical_success_floor_ppm: int | None,
    empirical_success_min_samples: int,
    empirical_success_lookback_days: int,
    optimize_for_least_active_memory: bool,
    held_out_task_evaluation: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    raw_key = "" if idempotency_key is None else str(idempotency_key)
    normalized_key = raw_key.strip()
    if raw_key != normalized_key or (
        normalized_key
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", normalized_key) is None
    ):
        raise ValueError("Invalid memory regulation idempotency_key")
    if not dry_run and not normalized_key:
        raise ValueError("Mutating memory regulation requires an idempotency_key")
    if isinstance(budget, bool) or (
        budget is not None and not 10 <= int(budget) <= 100_000
    ):
        raise ValueError("memory regulation budget must be between 10 and 100000")
    if (
        isinstance(max_summary_chars, bool)
        or not 100 <= int(max_summary_chars) <= 4_000
    ):
        raise ValueError(
            "memory regulation max_summary_chars must be between 100 and 4000"
        )
    if not isinstance(optimize_for_least_active_memory, bool):
        raise ValueError("optimize_for_least_active_memory must be a boolean")
    if empirical_success_floor_ppm is not None and held_out_task_evaluation is not None:
        raise ValueError(
            "empirical_success_floor_ppm and held_out_task_evaluation "
            "cannot be combined"
        )
    if empirical_success_floor_ppm is None:
        if optimize_for_least_active_memory and held_out_task_evaluation is None:
            raise ValueError(
                "optimize_for_least_active_memory requires "
                "empirical_success_floor_ppm or held_out_task_evaluation"
            )
    elif (
        isinstance(empirical_success_floor_ppm, bool)
        or not 1 <= int(empirical_success_floor_ppm) <= 1_000_000
    ):
        raise ValueError("empirical_success_floor_ppm must be between 1 and 1000000")
    if (
        isinstance(empirical_success_min_samples, bool)
        or not 1 <= int(empirical_success_min_samples) <= 10_000
    ):
        raise ValueError("empirical_success_min_samples must be between 1 and 10000")
    if (
        isinstance(empirical_success_lookback_days, bool)
        or not 1 <= int(empirical_success_lookback_days) <= 365
    ):
        raise ValueError("empirical_success_lookback_days must be between 1 and 365")

    payload: Dict[str, Any] = {
        "dry_run": bool(dry_run),
        "max_summary_chars": int(max_summary_chars),
    }
    if budget is not None:
        payload["budget"] = int(budget)
    if categories is not None:
        if isinstance(categories, (str, bytes, bytearray)):
            raise ValueError("Invalid memory regulation categories")
        normalized_categories = sorted(
            {str(category or "").strip() for category in categories}
        )
        if len(normalized_categories) > 64 or any(
            not category or len(category) > 64 for category in normalized_categories
        ):
            raise ValueError("Invalid memory regulation categories")
        payload["categories"] = normalized_categories
    if normalized_key:
        payload["idempotency_key"] = normalized_key
    if empirical_success_floor_ppm is not None:
        payload.update(
            {
                "empirical_success_floor_ppm": int(empirical_success_floor_ppm),
                "empirical_success_min_samples": int(empirical_success_min_samples),
                "empirical_success_lookback_days": int(empirical_success_lookback_days),
                "optimize_for_least_active_memory": (optimize_for_least_active_memory),
            }
        )
    if held_out_task_evaluation is not None:
        if not isinstance(held_out_task_evaluation, Mapping):
            raise ValueError("held_out_task_evaluation must be a JSON object")
        normalized_held_out = dict(held_out_task_evaluation)
        raw_budgets = normalized_held_out.get("candidate_budgets", [])
        if isinstance(raw_budgets, (str, bytes, bytearray)) or not isinstance(
            raw_budgets, Sequence
        ):
            raise ValueError("held-out candidate_budgets must be an array")
        budgets = list(raw_budgets)
        if (
            len(budgets) > 16
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 10 <= value <= 100_000
                for value in budgets
            )
            or len(set(budgets)) != len(budgets)
        ):
            raise ValueError(
                "held-out candidate_budgets must be unique integers from 10 to 100000"
            )
        normalized_held_out["candidate_budgets"] = sorted(budgets)
        raw_receipts = normalized_held_out.get("authenticated_receipts", [])
        if isinstance(raw_receipts, (str, bytes, bytearray)) or not isinstance(
            raw_receipts, Sequence
        ):
            raise ValueError("held-out authenticated_receipts must be an array")
        receipts = list(raw_receipts)
        if (
            len(receipts) > 16
            or any(
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 64 * 1024
                for value in receipts
            )
            or len(set(receipts)) != len(receipts)
        ):
            raise ValueError(
                "held-out authenticated_receipts must be unique bounded strings"
            )
        normalized_held_out["authenticated_receipts"] = receipts
        payload["held_out_task_evaluation"] = normalized_held_out
        payload["optimize_for_least_active_memory"] = optimize_for_least_active_memory
    _guard_request_body(payload, endpoint="memory/regulate")
    return payload


def _workflow_author_payload(
    definition: Mapping[str, Any],
    *,
    prompt: str = "",
    name: str | None = None,
    workflow_type: str | None = None,
    site_project_id: str | None = None,
    category: str | None = None,
    change_notes: str | None = None,
) -> Dict[str, Any]:
    """Build the governed one-shot author request without recompiling its DSL."""
    if not isinstance(definition, Mapping):
        raise ValueError("definition must be a JSON object")
    steps = definition.get("steps")
    if (
        not isinstance(steps, list)
        or not steps
        or any(not isinstance(step, Mapping) for step in steps)
    ):
        raise ValueError("definition.steps must be a non-empty array of JSON objects")

    resolved_name = str(name or definition.get("name") or "").strip()
    resolved_type = str(
        workflow_type
        or definition.get("workflowType")
        or definition.get("workflow_type")
        or definition.get("workflow_key")
        or ""
    ).strip()
    if not resolved_name:
        raise ValueError("workflow name is required")
    if not resolved_type:
        raise ValueError("workflow type is required")

    raw_defaults = definition.get("defaults")
    if raw_defaults is None:
        defaults: Dict[str, Any] = {}
    elif isinstance(raw_defaults, Mapping):
        defaults = dict(raw_defaults)
    else:
        raise ValueError("definition.defaults must be a JSON object")

    raw_triggers = definition.get("triggers")
    if raw_triggers is None:
        trigger = definition.get("trigger")
        triggers: List[Any] = [dict(trigger)] if isinstance(trigger, Mapping) else []
    elif isinstance(raw_triggers, list) and all(
        isinstance(item, Mapping) for item in raw_triggers
    ):
        triggers = list(raw_triggers)
    else:
        raise ValueError("definition.triggers must be an array of JSON objects")

    description = str(
        definition.get("description")
        or definition.get("objective")
        or (f"Generated from prompt: {prompt[:220]}" if prompt else "")
    ).strip()
    payload: Dict[str, Any] = {
        "name": resolved_name,
        "workflowType": resolved_type,
        "description": description,
        "category": str(category or definition.get("category") or "agentic").strip(),
        "changeNotes": str(
            change_notes
            or "Published from the exact SDK-validated definition through the governed authoring spine."
        ).strip(),
        # These are deliberately the already-compiled values. The SDK never turns
        # them back into prose or asks the server compiler to produce a second DSL.
        "steps": steps,
        "triggers": triggers,
        "defaults": defaults,
    }
    if site_project_id:
        payload["siteProjectId"] = str(site_project_id).strip()
    _assert_no_sensitive_workflow_content(payload)
    return payload


def _workflow_definition_digest(definition: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        definition,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _workflow_executable_projection_digest(definition: Mapping[str, Any]) -> str:
    """Hash only the executable fields the current server version persists."""
    raw_triggers = definition.get("triggers")
    if raw_triggers is None:
        trigger = definition.get("trigger")
        triggers = [dict(trigger)] if isinstance(trigger, Mapping) else []
    else:
        triggers = list(raw_triggers) if isinstance(raw_triggers, list) else []
    return _workflow_definition_digest(
        {
            "steps": definition.get("steps") or [],
            "triggers": triggers,
            "defaults": definition.get("defaults") or {},
        }
    )


_WORKFLOW_EVENT_FILTER_KEYS = frozenset({"from_contains", "subject_contains", "equals"})
_WORKFLOW_SIDE_EFFECT_AGENTS = frozenset(
    {"action_executor", "database_writer", "email_sender", "slack_notifier"}
)
_WORKFLOW_READ_ONLY_PRIMITIVES = frozenset(
    {
        "finance.ingest_supplier_invoice",
        "communication.classify_reply",
        "legal.review_contract",
        "crm.qualify_lead",
    }
)
# Keep this aligned with Spring's reviewed governed READ catalog. Unknown or
# historically read-shaped connector actions remain side effects until their
# exact schemas, routes, and provider implementations are audited server-side.
_WORKFLOW_READ_ONLY_CONNECTOR_ACTIONS = frozenset(
    {
        "ecommerce.get_product",
        "gmail.get_thread",
        "google_analytics.fetch_metrics",
        "shopify.analytics_query",
        "shopify.get_shop_info",
        "shopify.list_abandoned_checkouts",
        "shopify.verify_product_readiness",
    }
)
_WORKFLOW_SENSITIVE_KEY_PARTS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "authorization",
        "bearertoken",
        "clientsecret",
        "connectorsecret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "requestedinputs",
        "secret",
        "token",
    }
)
_WORKFLOW_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"(?i)^bearer\s+[A-Za-z0-9._~+/=-]{8,}$"),
    re.compile(r"^sk-[A-Za-z0-9_-]{8,}$"),
    re.compile(r"^AKIA[A-Z0-9]{12,}$"),
    re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def _workflow_key_is_sensitive(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
    return any(
        normalized == part or normalized.endswith(part)
        for part in _WORKFLOW_SENSITIVE_KEY_PARTS
    )


def _credential_like_workflow_value(value: Any) -> bool:
    return isinstance(value, str) and any(
        pattern.search(value.strip()) for pattern in _WORKFLOW_CREDENTIAL_VALUE_PATTERNS
    )


def _sensitive_workflow_content_paths(
    value: Any,
    *,
    path: str = "$",
    depth: int = 0,
) -> List[str]:
    if depth > 20:
        return [f"{path} (nesting exceeds 20 levels)"]
    paths: List[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _workflow_key_is_sensitive(key):
                paths.append(child_path)
                continue
            paths.extend(
                _sensitive_workflow_content_paths(
                    child,
                    path=child_path,
                    depth=depth + 1,
                )
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(
                _sensitive_workflow_content_paths(
                    child,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                )
            )
    elif _credential_like_workflow_value(value):
        paths.append(path)
    return paths


def _assert_no_sensitive_workflow_content(value: Any) -> None:
    paths = _sensitive_workflow_content_paths(value)
    if paths:
        raise ValueError(
            "workflow definitions cannot persist credential-like fields or values; "
            "use governed connector storage instead (blocked: "
            + ", ".join(paths[:8])
            + ")"
        )


def _validate_workflow_trigger_filter(event_filter: Mapping[str, Any] | None) -> None:
    """Fail closed on event filters the server runtime would otherwise ignore."""
    if event_filter is None:
        return
    if not isinstance(event_filter, Mapping):
        raise ValueError("event_filter must be a JSON object")
    unknown = sorted(
        str(key) for key in event_filter if key not in _WORKFLOW_EVENT_FILTER_KEYS
    )
    if unknown:
        raise ValueError(
            "event_filter contains unsupported keys: "
            + ", ".join(unknown)
            + " (allowed: equals, from_contains, subject_contains)"
        )
    for key, value in event_filter.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"event_filter.{key} must be a non-empty string")
        if key == "equals" and not (value.strip().startswith("$.") and "==" in value):
            raise ValueError(
                "event_filter.equals must be a '$.path == value' expression"
            )
    _assert_no_sensitive_workflow_content(event_filter)


def _workflow_side_effect_descriptor(step: Mapping[str, Any]) -> str | None:
    agent_name = str(step.get("agent_name") or step.get("agent") or "").strip().lower()
    if agent_name in _WORKFLOW_SIDE_EFFECT_AGENTS:
        return agent_name
    config = step.get("config") if isinstance(step.get("config"), Mapping) else {}
    if agent_name == "connector":
        action = step.get("action") or config.get("action")
        if (
            action
            and str(action).strip().lower() not in _WORKFLOW_READ_ONLY_CONNECTOR_ACTIONS
        ):
            return str(action)
    primitive_ref = (
        step.get("primitive_ref")
        or step.get("primitive_id")
        or config.get("primitive_ref")
        or config.get("primitive_id")
    )
    normalized_primitive = str(primitive_ref or "").strip().lower()
    if (
        normalized_primitive
        and normalized_primitive not in _WORKFLOW_READ_ONLY_PRIMITIVES
    ):
        return str(primitive_ref)
    return None


def _local_workflow_validation(definition: Mapping[str, Any]) -> Dict[str, Any]:
    """Cheap deterministic preflight for generic server-compiled workflow DSL."""
    errors: List[Dict[str, str]] = []
    warnings = list(definition.get("warnings") or [])
    steps = definition.get("steps")
    allowed_step_types = {
        "agent",
        "agent_step",
        "decision",
        "decision_step",
        "hitl",
        "hitl_step",
        "parallel",
        "parallel_step",
        "end",
        "terminal",
        "terminal_step",
    }
    if not isinstance(steps, list) or not steps:
        errors.append(
            {"code": "steps_required", "path": "steps", "message": "steps are required"}
        )
    else:
        seen: set[str] = set()
        for index, step in enumerate(steps):
            path = f"steps[{index}]"
            if not isinstance(step, Mapping):
                errors.append(
                    {
                        "code": "step_invalid",
                        "path": path,
                        "message": "step must be an object",
                    }
                )
                continue
            step_id = str(step.get("id") or "").strip()
            if not step_id:
                errors.append(
                    {
                        "code": "step_id_required",
                        "path": f"{path}.id",
                        "message": "step id is required",
                    }
                )
            elif step_id in seen:
                errors.append(
                    {
                        "code": "duplicate_step_id",
                        "path": f"{path}.id",
                        "message": "step id must be unique",
                    }
                )
            seen.add(step_id)
            step_type = str(step.get("type") or "").strip()
            if not step_type:
                errors.append(
                    {
                        "code": "step_type_required",
                        "path": f"{path}.type",
                        "message": "step type is required",
                    }
                )
            elif step_type not in allowed_step_types:
                errors.append(
                    {
                        "code": "step_type_unsupported",
                        "path": f"{path}.type",
                        "message": f"unsupported step type: {step_type}",
                    }
                )
            if (
                step_type in {"agent", "agent_step"}
                and not str(step.get("agent_name") or step.get("agent") or "").strip()
            ):
                errors.append(
                    {
                        "code": "agent_required",
                        "path": path,
                        "message": "agent step requires agent_name",
                    }
                )
            if step_type in {"decision", "decision_step"}:
                for key in ("expression", "on_true", "on_false"):
                    if step.get(key) in (None, ""):
                        errors.append(
                            {
                                "code": f"decision_{key}_required",
                                "path": f"{path}.{key}",
                                "message": f"decision step requires {key}",
                            }
                        )
            if step_type in {"hitl", "hitl_step"}:
                config = step.get("config")
                has_reason = isinstance(config, Mapping) and bool(config.get("reason"))
                if not step.get("hitl_queue") and not has_reason:
                    errors.append(
                        {
                            "code": "hitl_queue_required",
                            "path": f"{path}.hitl_queue",
                            "message": "HITL step requires hitl_queue or config.reason",
                        }
                    )
            transitions = step.get("transitions")
            if transitions is not None:
                if not isinstance(transitions, list):
                    errors.append(
                        {
                            "code": "transitions_invalid",
                            "path": f"{path}.transitions",
                            "message": "transitions must be a list",
                        }
                    )
                elif len(transitions) > 100:
                    errors.append(
                        {
                            "code": "transition_limit",
                            "path": f"{path}.transitions",
                            "message": "step exceeds the 100-transition safety limit",
                        }
                    )
                else:
                    for transition_index, transition in enumerate(transitions):
                        transition_path = f"{path}.transitions[{transition_index}]"
                        if not isinstance(transition, Mapping):
                            errors.append(
                                {
                                    "code": "transition_invalid",
                                    "path": transition_path,
                                    "message": "transition must be an object",
                                }
                            )
                            continue
                        target = transition.get("to")
                        if not isinstance(target, str) or not target.strip():
                            errors.append(
                                {
                                    "code": "transition_target_invalid",
                                    "path": f"{transition_path}.to",
                                    "message": "transition target must be a non-empty string",
                                }
                            )
                        condition = transition.get("condition")
                        if condition is not None and (
                            not isinstance(condition, str) or not condition.strip()
                        ):
                            errors.append(
                                {
                                    "code": "transition_condition_invalid",
                                    "path": f"{transition_path}.condition",
                                    "message": "transition condition must be a non-empty string",
                                }
                            )
            if step_type in {"parallel", "parallel_step"}:
                branches = step.get("branches")
                if not isinstance(branches, list) or not branches:
                    errors.append(
                        {
                            "code": "parallel_branches_required",
                            "path": f"{path}.branches",
                            "message": "parallel step requires a non-empty branches list",
                        }
                    )
                elif len(branches) > 100:
                    errors.append(
                        {
                            "code": "parallel_branch_limit",
                            "path": f"{path}.branches",
                            "message": "parallel step exceeds the 100-branch safety limit",
                        }
                    )
                else:
                    branch_ids: set[str] = set()
                    for branch_index, branch in enumerate(branches):
                        branch_path = f"{path}.branches[{branch_index}]"
                        if not isinstance(branch, Mapping):
                            errors.append(
                                {
                                    "code": "parallel_branch_invalid",
                                    "path": branch_path,
                                    "message": "parallel branch must be an object",
                                }
                            )
                            continue
                        branch_id = str(branch.get("id") or "").strip()
                        if not branch_id or branch_id in branch_ids:
                            errors.append(
                                {
                                    "code": "parallel_branch_id_invalid",
                                    "path": f"{branch_path}.id",
                                    "message": "parallel branch id is required and must be unique",
                                }
                            )
                        branch_ids.add(branch_id)
                        if not str(
                            branch.get("agent_name") or branch.get("agent") or ""
                        ).strip():
                            errors.append(
                                {
                                    "code": "parallel_branch_agent_required",
                                    "path": branch_path,
                                    "message": "parallel branch requires agent_name",
                                }
                            )
                        if branch.get("config") is not None and not isinstance(
                            branch.get("config"), Mapping
                        ):
                            errors.append(
                                {
                                    "code": "parallel_branch_config_invalid",
                                    "path": f"{branch_path}.config",
                                    "message": "parallel branch config must be an object",
                                }
                            )
                        branch_as_step = {**branch, "type": "agent_step"}
                        branch_effect = _workflow_side_effect_descriptor(branch_as_step)
                        if branch_effect:
                            errors.append(
                                {
                                    "code": "parallel_side_effect_unsupported",
                                    "path": branch_path,
                                    "message": (
                                        "side-effecting parallel branches are unsupported; "
                                        "use a serial HITL-gated agent step"
                                    ),
                                }
                            )
            mapping = step.get("input_mapping")
            if mapping is not None and (
                not isinstance(mapping, Mapping)
                or any(
                    not isinstance(value, str) or not value.startswith("$.")
                    for value in mapping.values()
                )
            ):
                errors.append(
                    {
                        "code": "input_mapping_invalid",
                        "path": f"{path}.input_mapping",
                        "message": "input mappings must be JSON paths",
                    }
                )

        predecessors_by_step_id: Dict[str, List[Mapping[str, Any]]] = {}
        outgoing_by_step_id: Dict[str, List[str]] = {}
        for index, step in enumerate(steps):
            if not isinstance(step, Mapping):
                continue
            path = f"steps[{index}]"
            targets: List[Any] = [
                step.get("next"),
                step.get("on_true"),
                step.get("on_false"),
            ]
            transitions = step.get("transitions")
            if isinstance(transitions, list):
                targets.extend(
                    transition.get("to")
                    for transition in transitions
                    if isinstance(transition, Mapping)
                )
            for target in targets:
                if target in (None, "", "end"):
                    continue
                if not isinstance(target, str) or target not in seen:
                    errors.append(
                        {
                            "code": "transition_target_invalid",
                            "path": path,
                            "message": f"transition target is not a defined step: {target}",
                        }
                    )
                    continue
                predecessors_by_step_id.setdefault(target, []).append(step)
                source_id = str(step.get("id") or "").strip()
                if source_id:
                    outgoing_by_step_id.setdefault(source_id, []).append(target)

        entry_step_id = ""
        if steps and isinstance(steps[0], Mapping):
            entry_step_id = str(steps[0].get("id") or "").strip()
        if entry_step_id:
            predecessors_by_step_id.setdefault(entry_step_id, []).append(
                {"type": "__start__"}
            )
            reachable: set[str] = set()
            pending = [entry_step_id]
            while pending:
                current = pending.pop()
                if current in reachable:
                    continue
                reachable.add(current)
                pending.extend(outgoing_by_step_id.get(current, []))
            for missing in sorted(seen - reachable):
                errors.append(
                    {
                        "code": "step_unreachable",
                        "path": "steps",
                        "message": f"step is unreachable from the workflow entry: {missing}",
                    }
                )

        for index, step in enumerate(steps):
            if not isinstance(step, Mapping):
                continue
            descriptor = _workflow_side_effect_descriptor(step)
            if not descriptor:
                continue
            step_id = str(step.get("id") or "").strip()
            predecessors = predecessors_by_step_id.get(step_id, [])
            explicitly_gated = bool(predecessors) and all(
                str(predecessor.get("type") or "").strip().lower()
                in {"hitl", "hitl_step"}
                for predecessor in predecessors
            )
            if not explicitly_gated:
                errors.append(
                    {
                        "code": "side_effect_hitl_required",
                        "path": f"steps[{index}]",
                        "message": (
                            f"side-effecting step '{step_id or '<unknown>'}' ({descriptor}) requires "
                            "an explicit HITL predecessor on every incoming path"
                        ),
                    }
                )

    defaults = definition.get("defaults")
    if defaults is not None and not isinstance(defaults, Mapping):
        errors.append(
            {
                "code": "defaults_invalid",
                "path": "defaults",
                "message": "defaults must be an object",
            }
        )
    elif isinstance(defaults, Mapping):
        max_depth = defaults.get("max_depth")
        if max_depth is not None and (
            isinstance(max_depth, bool)
            or not isinstance(max_depth, int)
            or not 1 <= max_depth <= 100
        ):
            errors.append(
                {
                    "code": "max_depth_invalid",
                    "path": "defaults.max_depth",
                    "message": "max_depth must be an integer from 1 to 100",
                }
            )
        max_cost = defaults.get("max_cost_usd")
        if max_cost is not None and (
            isinstance(max_cost, bool)
            or not isinstance(max_cost, (int, float))
            or not math.isfinite(float(max_cost))
            or not 0 < float(max_cost) <= 1000
        ):
            errors.append(
                {
                    "code": "max_cost_usd_invalid",
                    "path": "defaults.max_cost_usd",
                    "message": "max_cost_usd must be finite and greater than 0, up to 1000",
                }
            )
        timeout = defaults.get("timeout_seconds")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 1 <= timeout <= 86400
        ):
            errors.append(
                {
                    "code": "timeout_seconds_invalid",
                    "path": "defaults.timeout_seconds",
                    "message": "timeout_seconds must be an integer from 1 to 86400",
                }
            )
    for sensitive_path in _sensitive_workflow_content_paths(
        {
            "steps": definition.get("steps"),
            "triggers": definition.get("triggers"),
            "defaults": definition.get("defaults"),
        }
    ):
        errors.append(
            {
                "code": "sensitive_persisted_content",
                "path": sensitive_path,
                "message": "credential-like fields and values must use governed connector storage",
            }
        )
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "source": "sdk_preflight",
    }


def _workflow_authoring_endpoint(auth: AuthStrategy, action: str) -> str:
    plane = (
        "/api/internal/workflow-designer"
        if isinstance(auth, ApiKeyAuth)
        else "/api/workflow-designer"
    )
    return f"{plane}/{str(action).strip('/')}"


_STREAM_READ_TIMEOUT = 300.0

_SAFE_STRING_RE = re.compile(
    r"^[\w\s\-.,;:!?()'\"/\\@#$%^&*+=\[\]{}|<>~`]+$", re.UNICODE
)

# ID validator shared with all path-component arguments — rejects '..',
# slashes, query separators, control chars, etc. See lightbulb.validators
# for the full helper module; this duplicate keeps client.py importable
# without triggering the cyclic import that pulling validators in at top
# level would cause.
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._~:+-]{1,200}$")
_MARKETPLACE_PUBLICATION_SLUG_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,158}[a-z0-9])?$"
)
_MARKETPLACE_PUBLICATION_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_GOVERNED_CONFLICT_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


def _governed_invoke_requested(
    *,
    project_ref: str | None,
    connector_account_ref: str | None,
    idempotency_key: str | None,
    approval_ref: str | None,
    runtime_context: Dict[str, Any] | None,
    effect: str | None,
    workflow_instance_id: str | None = None,
    workflow_step_generation: int | None = None,
) -> bool:
    """Return whether Spring's durable governed connector route is required."""

    return any(
        value is not None
        for value in (
            project_ref,
            connector_account_ref,
            idempotency_key,
            approval_ref,
            runtime_context,
            effect,
            workflow_instance_id,
            workflow_step_generation,
        )
    )


def _governed_conflict_error_code(response: httpx.Response) -> str | None:
    """Read only Spring's bounded governed-conflict error-code contract."""

    if response.status_code != 409:
        return None
    try:
        body = response.json()
    except Exception:
        return None
    if (
        not isinstance(body, dict)
        or body.get("status") != 409
        or body.get("retryable") is not False
        or not isinstance(body.get("message"), str)
    ):
        return None
    code = body.get("error")
    if not isinstance(code, str) or not _GOVERNED_CONFLICT_ERROR_CODE_RE.fullmatch(
        code
    ):
        return None
    return code


def _validate_ephemeral_read_invoke_contract(
    tool_name: str,
    *,
    project_id: str | None,
    project_ref: str | None,
    connector_account_ref: str | None,
    idempotency_key: str | None,
    effect: str | None,
) -> bool:
    """Validate governed reads whose private provider output cannot be replayed."""

    ephemeral_read = is_ephemeral_non_replayable_read(tool_name)
    reject_ephemeral_read_idempotency(tool_name, idempotency_key)
    if not ephemeral_read:
        return False
    custody = {
        "project_id": project_id,
        "project_ref": project_ref,
        "connector_account_ref": connector_account_ref,
        "effect": effect,
    }
    missing = sorted(
        key for key, value in custody.items() if value is None or not str(value).strip()
    )
    if missing:
        raise ValueError(
            "governed_connector_context_required: "
            f"{tool_name.strip().lower()} requires " + ", ".join(missing)
        )
    if str(effect).strip().lower() != "read":
        raise ValueError(f"{tool_name.strip().lower()} effect must be read")
    return True


def _normalize_workflow_execution_identity(
    *,
    workflow_instance_id: str | None,
    step_id: str | None,
    workflow_step_generation: int | None,
) -> tuple[str, str, int] | None:
    supplied = workflow_instance_id is not None or workflow_step_generation is not None
    if not supplied:
        return None
    if workflow_instance_id is None or workflow_step_generation is None:
        raise ValueError(
            "workflow_instance_id and workflow_step_generation must be supplied together"
        )
    clean_step_id = str(step_id or "").strip()
    if (
        not clean_step_id
        or len(clean_step_id) > 100
        or any(ord(char) < 32 for char in clean_step_id)
    ):
        raise ValueError(
            "step_id must be 1-100 non-control characters for workflow execution"
        )
    if isinstance(workflow_step_generation, bool):
        raise ValueError("workflow_step_generation must be a non-negative integer")
    try:
        clean_generation = int(workflow_step_generation)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "workflow_step_generation must be a non-negative integer"
        ) from exc
    if clean_generation < 0:
        raise ValueError("workflow_step_generation must be a non-negative integer")
    return (
        _validate_marketplace_uuid(workflow_instance_id, "workflow_instance_id"),
        clean_step_id,
        clean_generation,
    )


_MARKETPLACE_CONTRACT_DIGEST_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MARKETPLACE_PUBLICATION_IDEMPOTENCY_RE = re.compile(r"^[\x21-\x7e]{1,200}$")
_MARKETPLACE_PUBLICATION_VISIBILITIES = frozenset({"PRIVATE", "UNLISTED", "PUBLIC"})
_MARKETPLACE_PUBLICATION_TERMINAL_STATUSES = frozenset({"READY", "FAILED", "ARCHIVED"})
_MARKETPLACE_PUBLICATION_FAILED_OPERATIONS = frozenset(
    {"FAILED", "CANCELLED", "REJECTED"}
)
_MAX_MARKETPLACE_PUBLICATION_WAIT_SECONDS = 600.0
_MAX_MARKETPLACE_PUBLICATION_POLL_SECONDS = 30.0
_MIN_MARKETPLACE_PUBLICATION_POLL_SECONDS = 0.1
_RUNTIME_ACTION_MAX_JSON_BYTES = 64 * 1024
_RUNTIME_ACTION_STATUSES = frozenset({"pending_approval", "approved", "rejected"})
_RUNTIME_ACTION_AGENT_SPEC_FIELDS = frozenset(
    {"name", "system_prompt", "allowed_tools", "model", "domain"}
)
_RUNTIME_ACTION_EXECUTION_POLICY_FIELDS = frozenset(
    {
        "max_iterations",
        "max_output_tokens",
        "max_runtime_seconds",
        "max_cost_usd_micros",
    }
)
_RUNTIME_ACTION_EXECUTION_POLICY_DEFAULTS = {
    "max_iterations": 6,
    "max_output_tokens": 900,
    "max_runtime_seconds": 120,
    "max_cost_usd_micros": 250_000,
}
_RUNTIME_ACTION_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,149}$")
_RUNTIME_ACTION_TOOL_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")
_ACCOUNT_SHELL_SCHEMA = "lightbulb.frontend_customization.v1"
_ACCOUNT_SHELL_SURFACE = "account_shell"
_ACCOUNT_SHELL_MAX_DOCUMENT_BYTES = 2_048
_ACCOUNT_SHELL_ROOT_FIELDS = frozenset(
    {"schema", "surface", "name", "tokens", "components"}
)
_ACCOUNT_SHELL_TOKEN_FIELDS = frozenset({"colors"})
_ACCOUNT_SHELL_COLOR_FIELDS = frozenset({"primary", "secondary"})
_ACCOUNT_SHELL_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{3}(?:[0-9A-Fa-f]{3})?$")
_ACCOUNT_SHELL_MAX_COMPONENTS = 3
_ACCOUNT_SHELL_COMPONENT_FIELDS = frozenset(
    {"component_id", "component_version", "region", "props"}
)
_ACCOUNT_SHELL_LEGACY_COMPONENT_PROP_FIELDS = frozenset({"emphasis"})
_ACCOUNT_SHELL_CURRENT_COMPONENT_PROP_FIELDS = frozenset(
    {"emphasis", "visibility", "action"}
)
_ACCOUNT_SHELL_COMPONENT_CAPABILITIES = {
    "company_brain_launcher": "service.company-brain",
    "agent_marketplace_launcher": "permission.agent-marketplace.read",
    "projects_launcher": "service.projects-workspace",
}
_ACCOUNT_SHELL_COMPONENT_VERSIONS = frozenset({1, 2})
_ACCOUNT_SHELL_COMPONENT_VISIBILITY_FIELDS = frozenset({"page_scope"})
_ACCOUNT_SHELL_COMPONENT_PAGE_SCOPES = frozenset({"any", "tenant", "company"})
_ACCOUNT_SHELL_COMPONENT_ACTION_FIELDS = frozenset({"capability_id", "operation"})
_ACCOUNT_SHELL_COMPONENT_EMPHASIS = frozenset({"primary", "secondary", "neutral"})
_RUNTIME_RUN_REF_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_WORKFLOW_STOP_STATES = frozenset(
    {"completed", "failed", "cancelled", "canceled", "waiting_for_approval"}
)


def _validate_id(value: object, label: str) -> str:
    if value is None:
        raise ValueError(f"{label} is required")
    s = str(value).strip()
    if not _ID_RE.match(s) or ".." in s:
        raise ValueError(
            f"{label} must match {_ID_RE.pattern} and not contain '..' (got length-{len(s)})"
        )
    return s


def _validate_runtime_run_ref(value: object) -> str:
    if value is None:
        raise ValueError("run_ref is required")
    run_ref = str(value).strip()
    if not _RUNTIME_RUN_REF_RE.match(run_ref) or ".." in run_ref:
        raise ValueError(
            f"run_ref must match {_RUNTIME_RUN_REF_RE.pattern} and not contain '..' "
            f"(got length-{len(run_ref)})"
        )
    return run_ref


def _workflow_instance_state(instance: Dict[str, Any]) -> str:
    """Normalize the state returned by the entity and response DTO variants."""
    return str(instance.get("state") or instance.get("status") or "").strip().lower()


def _validate_domain(domain: str) -> str:
    domain = str(domain).strip().lower()
    if not domain or not re.match(r"^[a-z][a-z0-9_]{0,63}$", domain):
        raise ValueError(f"Invalid domain name: {domain!r}")
    return domain


def _validate_message(message: str) -> str:
    message = str(message).strip()
    if not message:
        raise ValueError("Message must not be empty")
    if len(message) > _MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message exceeds {_MAX_MESSAGE_LENGTH} character limit")
    return message


def _validate_action(action: str) -> str:
    action = str(action).strip().lower()
    if not action or not re.match(r"^[a-z][a-z0-9_]{0,63}$", action):
        raise ValueError(f"Invalid action name: {action!r}")
    return action


def _validate_idempotency_key(value: object) -> str:
    """Validate a caller-owned retry key before placing it in an HTTP header."""
    key = str(value or "").strip()
    if not _IDEMPOTENCY_KEY_RE.fullmatch(key):
        raise ValueError(
            "idempotency_key is required and must be 1-200 URL-safe characters "
            "(letters, digits, '.', '_', '~', ':', '+', or '-')"
        )
    return key


def _runtime_action_canonical_object(
    value: object,
    label: str,
    *,
    max_bytes: int = _RUNTIME_ACTION_MAX_JSON_BYTES,
) -> Dict[str, Any]:
    """Return a strict JSON object with deterministic key ordering and a byte cap."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain only finite JSON values") from exc
    size = len(serialized.encode("utf-8"))
    if size > max_bytes:
        raise ValueError(f"{label} must be at most {max_bytes} UTF-8 JSON bytes")
    parsed = json.loads(serialized)
    if not isinstance(parsed, dict):  # pragma: no cover - guarded above
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def _canonical_account_shell_document(
    document: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the bounded token and closed component-placement schema."""
    if not isinstance(document, Mapping):
        raise ValueError("document must be a JSON object")
    copied = dict(document)
    if not all(isinstance(key, str) for key in copied):
        raise ValueError("document property names must be strings")
    unsupported = sorted(set(copied) - _ACCOUNT_SHELL_ROOT_FIELDS)
    if unsupported:
        raise ValueError(
            "document contains unsupported fields: " + ", ".join(unsupported)
        )

    if copied.get("schema") != _ACCOUNT_SHELL_SCHEMA:
        raise ValueError(f"document.schema must be {_ACCOUNT_SHELL_SCHEMA}")
    if copied.get("surface") != _ACCOUNT_SHELL_SURFACE:
        raise ValueError("document.surface must be account_shell")
    name = copied.get("name")
    # The Spring contract uses Java String.length(), which counts UTF-16 code
    # units. Match it here so astral Unicode cannot pass SDK preflight and then
    # fail at the server boundary.
    name_length = len(name.encode("utf-16-le")) // 2 if isinstance(name, str) else 0
    if not isinstance(name, str) or not name.strip() or name_length > 100:
        raise ValueError("document.name must be 1..100 characters")

    tokens = copied.get("tokens")
    if not isinstance(tokens, Mapping):
        raise ValueError("document.tokens must be a JSON object")
    if not all(isinstance(key, str) for key in tokens):
        raise ValueError("document.tokens property names must be strings")
    unsupported_tokens = sorted(set(tokens) - _ACCOUNT_SHELL_TOKEN_FIELDS)
    if unsupported_tokens:
        raise ValueError(
            "document.tokens contains unsupported fields: "
            + ", ".join(str(field) for field in unsupported_tokens)
        )
    colors = tokens.get("colors")
    if not isinstance(colors, Mapping):
        raise ValueError("document.tokens.colors must be a JSON object")
    if not all(isinstance(key, str) for key in colors):
        raise ValueError("document.tokens.colors property names must be strings")
    unsupported_colors = sorted(set(colors) - _ACCOUNT_SHELL_COLOR_FIELDS)
    if unsupported_colors:
        raise ValueError(
            "document.tokens.colors contains unsupported fields: "
            + ", ".join(str(field) for field in unsupported_colors)
        )

    canonical_colors: Dict[str, str] = {}
    for color_field in ("primary", "secondary"):
        color = colors.get(color_field)
        if not isinstance(color, str) or not _ACCOUNT_SHELL_HEX_COLOR_RE.fullmatch(
            color
        ):
            raise ValueError(
                f"document.tokens.colors.{color_field} must be a 3- or 6-digit hex color"
            )
        canonical_colors[color_field] = color.lower()

    canonical = {
        "schema": _ACCOUNT_SHELL_SCHEMA,
        "surface": _ACCOUNT_SHELL_SURFACE,
        "name": name.strip(),
        "tokens": {"colors": canonical_colors},
    }
    # Keep old immutable documents stable when the optional field is absent.
    if "components" in copied:
        components = copied.get("components")
        if not isinstance(components, list):
            raise ValueError("document.components must be a JSON array")
        if len(components) > _ACCOUNT_SHELL_MAX_COMPONENTS:
            raise ValueError(
                "document.components may contain at most "
                f"{_ACCOUNT_SHELL_MAX_COMPONENTS} placements"
            )
        canonical_components: list[Dict[str, Any]] = []
        selected_components: set[str] = set()
        for index, placement_value in enumerate(components):
            label = f"document.components[{index}]"
            if not isinstance(placement_value, Mapping):
                raise ValueError(f"{label} must be a JSON object")
            placement = dict(placement_value)
            if not all(isinstance(key, str) for key in placement):
                raise ValueError(f"{label} property names must be strings")
            unsupported_placement = sorted(
                set(placement) - _ACCOUNT_SHELL_COMPONENT_FIELDS
            )
            if unsupported_placement:
                raise ValueError(
                    f"{label} contains unsupported fields: "
                    + ", ".join(unsupported_placement)
                )

            component_id = placement.get("component_id")
            approved_capability = (
                _ACCOUNT_SHELL_COMPONENT_CAPABILITIES.get(component_id)
                if isinstance(component_id, str)
                else None
            )
            if approved_capability is None:
                raise ValueError(
                    f"{label}.component_id is not in the approved registry"
                )
            component_version = placement.get("component_version")
            if (
                type(component_version) is not int
                or component_version not in _ACCOUNT_SHELL_COMPONENT_VERSIONS
            ):
                raise ValueError(f"{label}.component_version is not approved")
            if placement.get("region") != "header_actions":
                raise ValueError(f"{label}.region must be header_actions")
            if component_id in selected_components:
                raise ValueError(
                    "document.components cannot place the same component more than once"
                )
            selected_components.add(component_id)

            props_value = placement.get("props")
            if not isinstance(props_value, Mapping):
                raise ValueError(f"{label}.props must be a JSON object")
            props = dict(props_value)
            if not all(isinstance(key, str) for key in props):
                raise ValueError(f"{label}.props property names must be strings")
            allowed_props = (
                _ACCOUNT_SHELL_LEGACY_COMPONENT_PROP_FIELDS
                if component_version == 1
                else _ACCOUNT_SHELL_CURRENT_COMPONENT_PROP_FIELDS
            )
            unsupported_props = sorted(set(props) - allowed_props)
            if unsupported_props:
                raise ValueError(
                    f"{label}.props contains unsupported fields: "
                    + ", ".join(unsupported_props)
                )
            emphasis = props.get("emphasis")
            if (
                not isinstance(emphasis, str)
                or emphasis not in _ACCOUNT_SHELL_COMPONENT_EMPHASIS
            ):
                raise ValueError(
                    f"{label}.props.emphasis must be primary, secondary, or neutral"
                )

            canonical_props: Dict[str, Any] = {"emphasis": emphasis}
            if component_version == 2:
                missing_props = sorted(
                    _ACCOUNT_SHELL_CURRENT_COMPONENT_PROP_FIELDS - set(props)
                )
                if missing_props:
                    raise ValueError(
                        f"{label}.props is missing required fields: "
                        + ", ".join(missing_props)
                    )

                visibility_value = props.get("visibility")
                if not isinstance(visibility_value, Mapping):
                    raise ValueError(f"{label}.props.visibility must be a JSON object")
                visibility = dict(visibility_value)
                if not all(isinstance(key, str) for key in visibility):
                    raise ValueError(
                        f"{label}.props.visibility property names must be strings"
                    )
                unsupported_visibility = sorted(
                    set(visibility) - _ACCOUNT_SHELL_COMPONENT_VISIBILITY_FIELDS
                )
                if unsupported_visibility:
                    raise ValueError(
                        f"{label}.props.visibility contains unsupported fields: "
                        + ", ".join(unsupported_visibility)
                    )
                page_scope = visibility.get("page_scope")
                if (
                    not isinstance(page_scope, str)
                    or page_scope not in _ACCOUNT_SHELL_COMPONENT_PAGE_SCOPES
                ):
                    raise ValueError(
                        f"{label}.props.visibility.page_scope must be any, tenant, or company"
                    )

                action_value = props.get("action")
                if not isinstance(action_value, Mapping):
                    raise ValueError(f"{label}.props.action must be a JSON object")
                action = dict(action_value)
                if not all(isinstance(key, str) for key in action):
                    raise ValueError(
                        f"{label}.props.action property names must be strings"
                    )
                unsupported_action = sorted(
                    set(action) - _ACCOUNT_SHELL_COMPONENT_ACTION_FIELDS
                )
                if unsupported_action:
                    raise ValueError(
                        f"{label}.props.action contains unsupported fields: "
                        + ", ".join(unsupported_action)
                    )
                missing_action = sorted(
                    _ACCOUNT_SHELL_COMPONENT_ACTION_FIELDS - set(action)
                )
                if missing_action:
                    raise ValueError(
                        f"{label}.props.action is missing required fields: "
                        + ", ".join(missing_action)
                    )
                if action.get("capability_id") != approved_capability:
                    raise ValueError(
                        f"{label}.props.action.capability_id does not match "
                        "the approved component capability"
                    )
                if action.get("operation") != "navigate":
                    raise ValueError(f"{label}.props.action.operation must be navigate")
                canonical_props["visibility"] = {"page_scope": page_scope}
                canonical_props["action"] = {
                    "capability_id": approved_capability,
                    "operation": "navigate",
                }

            canonical_components.append(
                {
                    "component_id": component_id,
                    "component_version": component_version,
                    "region": "header_actions",
                    "props": canonical_props,
                }
            )
        canonical["components"] = canonical_components
    return _runtime_action_canonical_object(
        canonical,
        "document",
        max_bytes=_ACCOUNT_SHELL_MAX_DOCUMENT_BYTES,
    )


def _nullable_account_shell_revision_id(value: object, label: str) -> str | None:
    """Validate an optimistic-concurrency UUID while preserving explicit null."""
    if value is None:
        return None
    return _validate_marketplace_uuid(value, label)


def _runtime_action_text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) > limit:
        raise ValueError(f"{label} must be at most {limit} characters")
    if any(ord(character) < 32 and character not in "\n\r\t" for character in text):
        raise ValueError(f"{label} must not contain control characters")
    return text


def _validate_runtime_action_token(value: object, label: str) -> str:
    token = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not _RUNTIME_ACTION_TOKEN_RE.fullmatch(token):
        raise ValueError(
            f"{label} must be a lowercase action token of at most 150 characters"
        )
    return token


def _validate_runtime_action_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status not in _RUNTIME_ACTION_STATUSES:
        raise ValueError(
            "status must be one of: " + ", ".join(sorted(_RUNTIME_ACTION_STATUSES))
        )
    return status


def _validate_runtime_action_idempotency_key(value: object) -> str:
    key = str(value or "").strip()
    if not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
        raise ValueError(
            "idempotency_key is required and must contain 1-128 visible ASCII characters"
        )
    return key


def _normalize_runtime_action_string_list(
    values: Sequence[str] | None,
    label: str,
    *,
    dotted: bool = False,
    max_items: int = 64,
    max_chars: int = 200,
) -> List[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{label} must be a JSON array of strings")
    normalized: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError(f"{label} must be a JSON array of strings")
        item = raw.strip().lower()
        if not item or len(item) > max_chars:
            raise ValueError(f"{label} entries must contain 1-{max_chars} characters")
        if dotted:
            if not _RUNTIME_ACTION_TOOL_RE.fullmatch(item):
                raise ValueError(f"{label} entries must be dotted platform tool names")
        elif not _ID_RE.fullmatch(item) or ".." in item:
            raise ValueError(f"{label} entries must be safe component identifiers")
        normalized.add(item)
    if len(normalized) > max_items:
        raise ValueError(f"{label} may contain at most {max_items} unique entries")
    return sorted(normalized)


def _normalize_runtime_action_agent_spec(
    agent_spec: Dict[str, Any] | None,
    *,
    registration_domain: str,
) -> Dict[str, Any] | None:
    if agent_spec is None or agent_spec == {}:
        return None
    if not isinstance(agent_spec, dict):
        raise ValueError("agent_spec must be a JSON object")
    agent_spec = _runtime_action_canonical_object(
        agent_spec,
        "agent_spec",
        max_bytes=32 * 1024,
    )
    unknown = sorted(set(agent_spec) - _RUNTIME_ACTION_AGENT_SPEC_FIELDS)
    if unknown:
        raise ValueError(
            "agent_spec contains unsupported fields: " + ", ".join(unknown)
        )

    for spec_field in ("name", "system_prompt", "model", "domain"):
        if spec_field in agent_spec and not isinstance(agent_spec[spec_field], str):
            raise ValueError(f"agent_spec.{spec_field} must be a string")

    system_prompt = _runtime_action_text(
        agent_spec.get("system_prompt"), "agent_spec.system_prompt", 16_000
    )
    if not system_prompt:
        raise ValueError("agent_spec.system_prompt is required")
    name = _runtime_action_text(agent_spec.get("name"), "agent_spec.name", 120)
    model = _runtime_action_text(
        agent_spec.get("model") or "gpt-5-mini", "agent_spec.model", 128
    )
    if model != "gpt-5-mini":
        raise ValueError("agent_spec.model must be gpt-5-mini")
    spec_domain = _validate_domain(agent_spec.get("domain") or registration_domain)
    if spec_domain != registration_domain:
        raise ValueError("agent_spec.domain must match the registered action domain")
    allowed_tools = _normalize_runtime_action_string_list(
        agent_spec.get("allowed_tools"),
        "agent_spec.allowed_tools",
        dotted=True,
        max_items=16,
        max_chars=128,
    )
    return _runtime_action_canonical_object(
        {
            "name": name,
            "system_prompt": system_prompt,
            "allowed_tools": allowed_tools,
            "model": model,
            "domain": spec_domain,
        },
        "agent_spec",
        max_bytes=32 * 1024,
    )


def _normalize_runtime_action_execution_policy(
    execution_policy: Dict[str, Any] | None,
) -> Dict[str, int] | None:
    if execution_policy is None or execution_policy == {}:
        return None
    if not isinstance(execution_policy, dict):
        raise ValueError("execution_policy must be a JSON object")
    unknown = sorted(set(execution_policy) - _RUNTIME_ACTION_EXECUTION_POLICY_FIELDS)
    if unknown:
        raise ValueError(
            "execution_policy contains unsupported fields: " + ", ".join(unknown)
        )
    bounds = {
        "max_iterations": (1, 6),
        "max_output_tokens": (64, 900),
        "max_runtime_seconds": (5, 120),
        "max_cost_usd_micros": (10_000, 5_000_000),
    }
    normalized: Dict[str, int] = {}
    for policy_field, default in _RUNTIME_ACTION_EXECUTION_POLICY_DEFAULTS.items():
        raw = execution_policy.get(policy_field, default)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValueError(f"execution_policy.{policy_field} must be an integer")
        lower, upper = bounds[policy_field]
        if raw < lower or raw > upper:
            raise ValueError(
                f"execution_policy.{policy_field} must be between {lower} and {upper}"
            )
        normalized[policy_field] = raw
    return normalized


def _build_runtime_domain_action_payload(
    *,
    domain: str,
    action: str,
    description: str = "",
    component_ids: Sequence[str] | None = None,
    agent_spec: Dict[str, Any] | None = None,
    execution_policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build the narrow register request; scope, status, and approval are never accepted."""
    normalized_domain = _validate_domain(domain)
    normalized_action = _validate_runtime_action_token(action, "action")
    payload: Dict[str, Any] = {
        "domain": normalized_domain,
        "action": normalized_action,
        "componentIds": _normalize_runtime_action_string_list(
            component_ids,
            "component_ids",
            max_items=16,
            max_chars=100,
        ),
    }
    normalized_description = _runtime_action_text(description, "description", 2_000)
    if normalized_description:
        payload["description"] = normalized_description
    normalized_spec = _normalize_runtime_action_agent_spec(
        agent_spec,
        registration_domain=normalized_domain,
    )
    if normalized_spec is not None:
        payload["agentSpec"] = normalized_spec
    normalized_policy = _normalize_runtime_action_execution_policy(execution_policy)
    if normalized_policy is not None:
        payload["executionPolicy"] = normalized_policy
    return _runtime_action_canonical_object(payload, "runtime action registration")


def _validate_marketplace_uuid(value: object, label: str) -> str:
    """Use the SDK's canonical UUID validator for marketplace path IDs."""
    from lightbulb.validators import validate_uuid

    return validate_uuid(value, label)


def _validate_connector_provider(value: object) -> str:
    """Validate a connector provider before placing it in a URL path."""
    provider = str(value or "").strip().lower()
    if not provider:
        raise ValueError("provider is required")
    if len(provider) > 120 or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", provider):
        raise ValueError(
            "provider must contain only letters, numbers, dots, underscores, or hyphens"
        )
    return provider


def _validate_connector_account_ref(value: object) -> str:
    """Validate one exact project-bound account alias before query transport."""
    if not isinstance(value, str):
        raise ValueError("connector_account_ref must be a string")
    account_ref = value.strip()
    if (
        not account_ref
        or account_ref != value
        or len(account_ref) > 200
        or any(
            ord(character) < 33 or ord(character) == 127 for character in account_ref
        )
    ):
        raise ValueError(
            "connector_account_ref must be 1-200 visible characters without surrounding whitespace"
        )
    return account_ref


def _validate_connector_tool_name(value: object) -> str:
    """Normalize the exact server Tool key accepted by Spring's catalog."""
    if not isinstance(value, str):
        raise ValueError("tool_name must be a string")
    tool_name = value.strip().lower()
    if (
        not tool_name
        or len(tool_name) > 200
        or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", tool_name) is None
    ):
        raise ValueError(
            "tool_name must contain only letters, numbers, dots, underscores, or hyphens"
        )
    return tool_name


def _validated_connector_route_descriptor(
    value: object,
    *,
    project_id: str,
    connector_account_ref: str,
    tool_name: str,
) -> Dict[str, Any]:
    """Validate Spring's closed, secret-free governed route descriptor."""
    expected_fields = {
        "schema",
        "projectId",
        "connectorAccountRef",
        "targetResourceRef",
        "toolName",
        "toolVersion",
        "tenantConnectorId",
        "routeDigest",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ValueError(
            "Connector route descriptor must match the closed response contract"
        )
    if value.get("schema") != _CONNECTOR_ROUTE_DESCRIPTOR_SCHEMA:
        raise ValueError("Connector route descriptor schema is unsupported")
    response_project_id = _validate_marketplace_uuid(
        value.get("projectId"), "route_descriptor.projectId"
    )
    if response_project_id != project_id:
        raise ValueError(
            "Connector route descriptor project does not match the request"
        )
    response_account_ref = _validate_connector_account_ref(
        value.get("connectorAccountRef")
    )
    if response_account_ref != connector_account_ref:
        raise ValueError(
            "Connector route descriptor account does not match the request"
        )
    response_tool_name = _validate_connector_tool_name(value.get("toolName"))
    if response_tool_name != tool_name:
        raise ValueError("Connector route descriptor Tool does not match the request")
    target_resource_ref = value.get("targetResourceRef")
    if target_resource_ref is not None:
        if not isinstance(target_resource_ref, str):
            raise ValueError("Connector route target resource must be a string or null")
        clean_target = target_resource_ref.strip()
        if (
            not clean_target
            or clean_target != target_resource_ref
            or len(clean_target) > 500
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in clean_target
            )
        ):
            raise ValueError("Connector route target resource is invalid")
        target_resource_ref = clean_target
    tool_version = value.get("toolVersion")
    if type(tool_version) is not int or not 1 <= tool_version <= 2_147_483_647:
        raise ValueError("Connector route Tool version must be a positive integer")
    tenant_connector_id = _validate_marketplace_uuid(
        value.get("tenantConnectorId"), "route_descriptor.tenantConnectorId"
    )
    route_digest = value.get("routeDigest")
    if (
        not isinstance(route_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", route_digest) is None
    ):
        raise ValueError("Connector route digest must be lowercase SHA-256")
    return {
        "schema": _CONNECTOR_ROUTE_DESCRIPTOR_SCHEMA,
        "projectId": response_project_id,
        "connectorAccountRef": response_account_ref,
        "targetResourceRef": target_resource_ref,
        "toolName": response_tool_name,
        "toolVersion": tool_version,
        "tenantConnectorId": tenant_connector_id,
        "routeDigest": route_digest,
    }


def _validate_marketplace_inputs(value: Dict[str, Any] | None) -> Dict[str, Any]:
    """Keep authentication scope and retry authority out of action inputs."""
    if value is not None and not isinstance(value, dict):
        raise ValueError("Marketplace action inputs must be a JSON object")
    inputs = dict(value or {})
    reserved = {
        "tenant_id",
        "tenantId",
        "company_id",
        "companyId",
        "idempotency_key",
        "idempotencyKey",
    }
    present: set[str] = set()

    def find_reserved(item: Any) -> None:
        if isinstance(item, dict):
            present.update(reserved.intersection(str(key) for key in item))
            for nested in item.values():
                find_reserved(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                find_reserved(nested)

    find_reserved(inputs)
    if present:
        raise ValueError(
            "Marketplace action inputs must not set scope or idempotency fields: "
            + ", ".join(sorted(present))
        )
    return _sanitize_inputs(inputs)


def _bounded_marketplace_limit(value: object) -> int:
    try:
        return max(1, min(int(value), 200))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc


def _bounded_marketplace_publication_text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} must be at most {limit} characters")
    if any(ord(character) < 32 for character in text):
        raise ValueError(f"{label} must not contain control characters")
    return text


def _normalize_marketplace_publication_token(
    value: object,
    label: str,
    limit: int = 160,
) -> str:
    raw = _bounded_marketplace_publication_text(value, label, limit)
    normalized = raw.lower().replace("-", "_").replace(" ", "_")
    if not re.fullmatch(rf"[a-z][a-z0-9_]{{0,{limit - 1}}}", normalized):
        raise ValueError(
            f"{label} must normalize to a lowercase letter followed by letters, digits, or '_'"
        )
    return normalized


def _build_marketplace_action_publication_payload(
    *,
    slug: object,
    name: object,
    version: object,
    domain: object,
    action: object,
    visibility: object = "PRIVATE",
    pricing_model: object = "INCLUDED",
    changelog: object = "",
) -> Dict[str, Any]:
    """Build the intentionally narrow publication descriptor accepted by Spring.

    The governed publication endpoint derives the immutable action contract on
    the server.  Keeping this helper explicit prevents callers from smuggling a
    manifest, prompt, model/tool policy, or tenant/company authority through the
    SDK body.
    """
    normalized_slug = str(slug or "").strip()
    if not _MARKETPLACE_PUBLICATION_SLUG_RE.fullmatch(normalized_slug):
        raise ValueError(
            "slug is required, at most 160 characters, lowercase alphanumeric with internal hyphens"
        )
    normalized_version = str(version or "").strip()
    if len(
        normalized_version
    ) > 32 or not _MARKETPLACE_PUBLICATION_VERSION_RE.fullmatch(normalized_version):
        raise ValueError(
            "version is required and must be a SemVer value of at most 32 characters"
        )
    normalized_visibility = str(visibility or "PRIVATE").strip().upper()
    if normalized_visibility not in _MARKETPLACE_PUBLICATION_VISIBILITIES:
        raise ValueError("visibility must be PRIVATE, UNLISTED, or PUBLIC")
    normalized_pricing = str(pricing_model or "INCLUDED").strip().upper()
    if normalized_pricing != "INCLUDED":
        raise ValueError("pricing_model must be INCLUDED")

    payload: Dict[str, Any] = {
        "slug": normalized_slug,
        "name": _bounded_marketplace_publication_text(name, "name", 200),
        "version": normalized_version,
        "domain": _normalize_marketplace_publication_token(domain, "domain", 64),
        "action": _normalize_marketplace_publication_token(action, "action"),
        "visibility": normalized_visibility,
        "pricing_model": normalized_pricing,
    }
    normalized_changelog = str(changelog or "").strip()
    if normalized_changelog:
        if len(normalized_changelog) > 10_000:
            raise ValueError("changelog must be at most 10000 characters")
        if any(
            ord(character) < 32 and character not in "\n\r\t"
            for character in normalized_changelog
        ):
            raise ValueError("changelog must not contain control characters")
        payload["changelog"] = normalized_changelog
    _guard_request_body(payload, endpoint="agent-marketplace/action-publications")
    return payload


def _validate_marketplace_contract_digest(value: object) -> str:
    digest = str(value or "").strip().lower()
    if not _MARKETPLACE_CONTRACT_DIGEST_RE.fullmatch(digest):
        raise ValueError(
            "expected_contract_digest must be a 64-character SHA-256 hex digest"
        )
    return digest


def _validate_marketplace_publication_idempotency_key(value: object) -> str:
    key = str(value or "")
    if not _MARKETPLACE_PUBLICATION_IDEMPOTENCY_RE.fullmatch(key):
        raise ValueError(
            "idempotency_key is required and must contain 1-200 visible ASCII characters"
        )
    return key


def _validate_provisioning_instrument(value: object) -> str:
    """Validate the instrument name of a company provisioning proposal."""
    instrument = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,47}", instrument):
        raise ValueError(
            "instrument is required and must be 3-48 lowercase letters, digits, "
            "or underscores (e.g. 'stripe_connect_account', 'site', 'phone_number')"
        )
    return instrument


def _validate_provisioning_idempotency_key(value: object) -> str:
    """Validate the replay key Spring's provisioning journal pins a proposal to."""
    key = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key):
        raise ValueError(
            "idempotency_key is required and must be 8-128 characters of letters, "
            "digits, '_', or '-'"
        )
    return key


def _normalize_marketplace_deployment_targets(
    values: Sequence[str] | None,
) -> List[str]:
    aliases = {
        "backbone_agent": "codex_backbone",
        "backbone-agent": "codex_backbone",
    }
    normalized: List[str] = []
    for raw in values or ():
        target = str(raw or "").strip().lower()
        target = aliases.get(target, target)
        if re.fullmatch(r"(?:cc_)?[a-z0-9]+(?:_[a-z0-9]+)*_domain_agent", target):
            domain = re.sub(r"^(?:cc_)?|_domain_agent$", "", target)
            target = f"claude_code_domain:{domain}"
        if not re.fullmatch(
            r"codex_backbone|claude_code_domain(?:\:[a-z0-9]+(?:_[a-z0-9]+)*)?",
            target,
        ):
            raise ValueError(f"Unsupported marketplace deployment target: {raw}")
        if target not in normalized:
            normalized.append(target)
    if len(normalized) > 16:
        raise ValueError("At most 16 marketplace deployment targets are allowed")
    return sorted(normalized)


def _bounded_marketplace_publication_polling(
    timeout_seconds: object,
    poll_interval_seconds: object,
) -> tuple[float, float]:
    try:
        timeout = float(timeout_seconds)
        interval = float(poll_interval_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "timeout_seconds and poll_interval_seconds must be numbers"
        ) from exc
    if not (timeout > 0.0) or timeout != timeout:
        raise ValueError("timeout_seconds must be greater than zero")
    if not (interval > 0.0) or interval != interval:
        raise ValueError("poll_interval_seconds must be greater than zero")
    return (
        min(timeout, _MAX_MARKETPLACE_PUBLICATION_WAIT_SECONDS),
        min(
            max(interval, _MIN_MARKETPLACE_PUBLICATION_POLL_SECONDS),
            _MAX_MARKETPLACE_PUBLICATION_POLL_SECONDS,
        ),
    )


def _marketplace_action_publication_status(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        return "", ""
    publication_status = (
        str(
            value.get("publication_status")
            or value.get("publicationStatus")
            or value.get("status")
            or ""
        )
        .strip()
        .upper()
    )
    operation_status = (
        str(value.get("operation_status") or value.get("operationStatus") or "")
        .strip()
        .upper()
    )
    return publication_status, operation_status


def _is_terminal_marketplace_action_publication(value: object) -> bool:
    publication_status, operation_status = _marketplace_action_publication_status(value)
    return (
        publication_status in _MARKETPLACE_PUBLICATION_TERMINAL_STATUSES
        or operation_status in _MARKETPLACE_PUBLICATION_FAILED_OPERATIONS
    )


def _sanitize_inputs(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow validation of input dict — reject obviously dangerous payloads."""
    serialised = json.dumps(inputs, default=str)
    if len(serialised) > _MAX_RESPONSE_BYTES:
        raise ValueError("Inputs payload too large")
    return inputs


def _normalize_code_chat_attachment(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    normalized = dict(value)
    if "mime_type" in normalized and "mimeType" not in normalized:
        normalized["mimeType"] = normalized.pop("mime_type")
    return normalized


def _validate_max_tool_loops(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_tool_loops must be an integer between 4 and 48")
    if value < 4 or value > 48:
        raise ValueError("max_tool_loops must be between 4 and 48")
    return value


def _validate_max_cost_usd(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("max_cost_usd must be a finite number between 0.01 and 1000")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0.01 or normalized > 1000:
        raise ValueError("max_cost_usd must be between 0.01 and 1000")
    return normalized


def _validate_max_total_tokens(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_total_tokens must be an integer between 1 and 2000000")
    if value < 1 or value > 2_000_000:
        raise ValueError("max_total_tokens must be between 1 and 2000000")
    return value


def _normalize_code_chat_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    key_map = {
        "conversation_id": "conversationId",
        "active_file": "activeFile",
        "idempotency_key": "idempotencyKey",
        "agent_model_selection_id": "agentModelSelectionId",
        "agent_model_profile_id": "agentModelSelectionId",  # back-compat alias
        "agent_provider_connection_id": "agentProviderConnectionId",
        "agent_model_id": "agentModelId",
        "preview_mode": "previewMode",
        "auto_push": "autoPush",
        "max_tool_loops": "maxToolLoops",
        "max_cost_usd": "maxCostUsd",
        "max_total_tokens": "maxTotalTokens",
    }
    normalized: Dict[str, Any] = {}
    for key, value in (kwargs or {}).items():
        target_key = key_map.get(key, key)
        if target_key == "maxToolLoops":
            value = _validate_max_tool_loops(value)
        elif target_key == "maxCostUsd":
            value = _validate_max_cost_usd(value)
        elif target_key == "maxTotalTokens":
            value = _validate_max_total_tokens(value)
        if target_key == "attachments" and isinstance(value, list):
            normalized[target_key] = [
                _normalize_code_chat_attachment(item) for item in value
            ]
        else:
            normalized[target_key] = value
    return normalized


@dataclass(frozen=True)
class SSEEvent:
    """A single Server-Sent Event from a streaming endpoint."""

    event: str
    data: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass(frozen=True)
class DispatchResult:
    """Result of a one-shot domain agent dispatch."""

    domain: str
    action: str
    mode: str
    reply: str
    conversation_id: str
    trace_id: str
    outputs: Dict[str, Any]
    raw: Dict[str, Any]

    @property
    def success(self) -> bool:
        state = str(self.raw.get("state") or "").lower()
        return state in ("completed", "success", "") and bool(
            self.reply or self.outputs
        )


_VERIFIED_ENVELOPE_AUTH_PROOF = object()


@dataclass(frozen=True, slots=True)
class _VerifiedEnvelopeAuth(AuthStrategy):
    """Credential-free client scope minted from one verified worker envelope.

    This strategy intentionally cannot produce ordinary authenticated headers.
    It only lets :meth:`LightbulbClient.invoke_tool` confirm that a private
    runtime authority came from the same envelope used to construct the client.
    """

    _tenant_id: str
    _company_id: str
    _user_id: str
    _runtime_authority_sha256: bytes = field(repr=False)
    _proof: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._proof is not _VERIFIED_ENVELOPE_AUTH_PROOF:
            raise TypeError("worker auth must be minted from a verified envelope")

    @classmethod
    def from_runtime_authority(cls, authority: Any) -> "_VerifiedEnvelopeAuth":
        from lightbulb.connector_execution import _TrustedRuntimeAuthority

        if not isinstance(authority, _TrustedRuntimeAuthority):
            raise TypeError("worker auth must be minted from a verified envelope")
        return cls(
            _tenant_id=authority.tenant_id,
            _company_id=authority.company_id,
            _user_id=authority.user_id,
            _runtime_authority_sha256=hashlib.sha256(
                authority.token.encode("utf-8")
            ).digest(),
            _proof=_VERIFIED_ENVELOPE_AUTH_PROOF,
        )

    def apply(self, headers: Dict[str, str]) -> Dict[str, str]:
        raise RuntimeError(
            "verified-envelope clients support only governed runtime-authority requests"
        )

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def company_id(self) -> str:
        return self._company_id

    @property
    def user_id(self) -> str:
        return self._user_id

    def require_runtime_authority(self, authority: Any) -> None:
        from lightbulb.connector_execution import _TrustedRuntimeAuthority

        if not isinstance(authority, _TrustedRuntimeAuthority) or (
            hashlib.sha256(authority.token.encode("utf-8")).digest()
            != self._runtime_authority_sha256
        ):
            raise ValueError(
                "runtime authority does not match the verified-envelope client"
            )


class LightbulbClient:
    """Synchronous client for the Lightbulb platform API."""

    def __init__(
        self,
        base_url: str,
        auth: AuthStrategy,
        *,
        enforce_https: bool = True,
        connect_timeout: float = _CONNECT_TIMEOUT,
        read_timeout: float = _READ_TIMEOUT,
        auth_refresh: "Callable[[], AuthStrategy] | None" = None,
        outcome_recorder: Any = None,
    ) -> None:
        parsed = urlparse(base_url.rstrip("/"))
        # Use the canonical helper so IPv6 ::1 and any future loopback aliases
        # are treated consistently with the rest of the SDK (audit-id:
        # is_local_ipv6_0_5_1).
        from lightbulb.validators import is_local_url

        is_local = is_local_url(base_url)
        if enforce_https and parsed.scheme != "https" and not is_local:
            raise ValueError(
                f"HTTPS is required for non-localhost URLs (got {parsed.scheme}://{parsed.hostname}). "
                "Pass enforce_https=False only for local development."
            )
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._active_company_id: str | None = auth.company_id
        # Context calls normally inherit the selected company. Automatic host
        # hooks can explicitly set this override to ``None`` so an auth
        # strategy's cached company header cannot silently scope continuity.
        self._context_company_override: object | str | None = _CONTEXT_COMPANY_INHERIT
        # Optional callback invoked once after a 401 to refresh credentials.
        # The callback should return a fresh AuthStrategy (e.g. via device flow).
        self._auth_refresh = auth_refresh
        self._outcome_recorder_is_managed = outcome_recorder is None
        self._outcome_recorders_by_scope: Dict[str, Any] = {}
        if self._outcome_recorder_is_managed:
            self._activate_managed_outcome_recorder()
        else:
            self._outcome_recorder = outcome_recorder

    @classmethod
    def from_verified_envelope(
        cls,
        base_url: str,
        envelope: Any,
        *,
        enforce_https: bool = True,
        connect_timeout: float = _CONNECT_TIMEOUT,
        read_timeout: float = _READ_TIMEOUT,
        outcome_recorder: Any = None,
    ) -> "LightbulbClient":
        """Build a worker-only client without a JWT or shared API credential.

        The envelope must have a verified v2-or-newer signature and an exact
        company/project runtime authority whose public claims match its signed
        scope. Spring remains authoritative and verifies the HMAC token again.
        """

        from lightbulb.connector_execution import (
            TrustedWorkflowIdentity,
            _TrustedRuntimeAuthority,
        )

        workflow_identity = TrustedWorkflowIdentity.from_verified_envelope(envelope)
        runtime_authority = _TrustedRuntimeAuthority.from_verified_envelope(
            envelope,
            workflow_identity,
        )
        if runtime_authority is None:
            raise ValueError(
                "verified-envelope client requires exact runtime authority scope"
            )
        return cls(
            base_url,
            auth=_VerifiedEnvelopeAuth.from_runtime_authority(runtime_authority),
            enforce_https=enforce_https,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            outcome_recorder=outcome_recorder,
        )

    def _activate_managed_outcome_recorder(self) -> None:
        from lightbulb.local_storage import local_scope_fingerprint
        from lightbulb.runtime_outcomes import outcome_recorder_from_env

        company_id = self._active_company_id or self._auth.company_id
        fingerprint = local_scope_fingerprint(self._auth.tenant_id, company_id)
        recorder = self._outcome_recorders_by_scope.get(fingerprint)
        if recorder is None:
            recorder = outcome_recorder_from_env(
                tenant_id=self._auth.tenant_id,
                company_id=company_id,
            )
            self._outcome_recorders_by_scope[fingerprint] = recorder
        self._outcome_recorder = recorder

    _session: httpx.Client | None = None
    _csrf_token: str | None = None
    _refresh_in_flight: bool = False

    @property
    def active_company_id(self) -> str | None:
        """The currently selected company context (needed for write operations)."""
        return self._active_company_id

    @active_company_id.setter
    def active_company_id(self, value: str | None) -> None:
        self._active_company_id = value
        if getattr(self, "_outcome_recorder_is_managed", False):
            self._activate_managed_outcome_recorder()

    @property
    def context_company_id(self) -> str | None:
        """Company used only by Context Broker calls; defaults to the active company."""
        if self._context_company_override is _CONTEXT_COMPANY_INHERIT:
            return self._active_company_id
        if isinstance(self._context_company_override, str):
            return self._context_company_override
        return None

    @context_company_id.setter
    def context_company_id(self, value: str | None) -> None:
        self._context_company_override = (
            _validate_marketplace_uuid(value, "context_company_id") if value else None
        )

    def whoami(self) -> Dict[str, Any]:
        """Get the current user's identity, role, tenant, company, and permissions."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/users/me", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_connected_integrations(
        self, company_id: str | None = None
    ) -> List[Dict[str, Any]]:
        """List connected integrations (OAuth connections) for the current company scope."""
        session = self._get_session()
        params = {}
        effective_company = company_id or self._active_company_id
        if effective_company:
            params["company_id"] = effective_company
        resp = session.get(
            f"{self._base_url}/api/oauth/connections",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def get_ai_metered_cost(self, provider: str, *, window_start: str, window_end: str) -> Dict[str, Any]:
        """Read native metering for the active company; this neither reconciles nor posts costs."""
        from lightbulb.company_engine_core import timestamp
        company = _validate_marketplace_uuid(self.active_company_id, "active_company_id")
        timestamp(window_start, field_name="window_start")
        timestamp(window_end, field_name="window_end")
        session = self._get_session()
        response = session.get(f"{self._base_url}/api/ai/costs/metered",
            params={"provider":provider, "windowStart":window_start, "windowEnd":window_end, "companyId":company},
            headers=self._exact_company_headers(company))
        raise_if_error(response)
        return response.json()

    def list_companies(self) -> List[Dict[str, Any]]:
        """List companies the user has access to within their tenant."""
        session = self._get_session()
        tenant_id = self._auth.tenant_id
        resp = session.get(
            f"{self._base_url}/api/companies/tenant/{tenant_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("companies", []))
        )

    def request_provisioning(
        self,
        company_id: str,
        instrument: str,
        inputs: Dict[str, Any],
        *,
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Propose one platform-minted instrument (Stripe Connect account, site, phone number).

        Nothing is created here: Spring opens a provisioning journal and an
        approval task a *different* human decides, and returns the proposal with
        the human gates that instrument opens.  Execute it with
        :meth:`execute_provisioning` once the task is approved.
        """
        normalized_company = _validate_marketplace_uuid(company_id, "company_id")
        payload: Dict[str, Any] = {
            "instrument": _validate_provisioning_instrument(instrument),
            "idempotencyKey": _validate_provisioning_idempotency_key(idempotency_key),
            "inputs": dict(inputs or {}),
        }
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="companies/provisioning")
        response = self._get_session().post(
            f"{self._base_url}/api/companies/{normalized_company}/provisioning",
            json=payload,
            headers=self._exact_company_headers(normalized_company),
        )
        raise_if_error(response)
        return response.json()

    def execute_provisioning(
        self,
        company_id: str,
        journal_id: str,
        *,
        approval_ref: str,
    ) -> Dict[str, Any]:
        """Mint the proposed instrument with the approval a human already granted.

        Returns the durable ``lightbulb.company_provisioning_receipt.v1``; the
        one-shot hosted-onboarding URL, when the instrument has one, is present in
        this live response only and is never stored.
        """
        normalized_company = _validate_marketplace_uuid(company_id, "company_id")
        normalized_journal = _validate_marketplace_uuid(journal_id, "journal_id")
        payload = {
            "approvalRef": _validate_marketplace_uuid(approval_ref, "approval_ref")
        }
        response = self._get_session().post(
            f"{self._base_url}/api/companies/{normalized_company}"
            f"/provisioning/{normalized_journal}/execute",
            json=payload,
            headers=self._exact_company_headers(normalized_company),
        )
        raise_if_error(response)
        return response.json()

    def get_provisioning(self, company_id: str, journal_id: str) -> Dict[str, Any]:
        """The provisioning journal row and its durable receipt, without live-only fields."""
        normalized_company = _validate_marketplace_uuid(company_id, "company_id")
        normalized_journal = _validate_marketplace_uuid(journal_id, "journal_id")
        response = self._get_session().get(
            f"{self._base_url}/api/companies/{normalized_company}"
            f"/provisioning/{normalized_journal}",
            headers=self._exact_company_headers(normalized_company),
        )
        raise_if_error(response)
        return response.json()

    def mint_onboarding_link(self, company_id: str, journal_id: str) -> Dict[str, Any]:
        """A fresh one-shot hosted-onboarding link for an already-minted instrument.

        Hosted onboarding is the account owner's own legal act (identity, bank
        account, the Stripe Connected Account Agreement).  Show the URL once with
        its expiry and never store it; only ``stripe.observe_account_readiness``
        may report the instrument ready.
        """
        normalized_company = _validate_marketplace_uuid(company_id, "company_id")
        normalized_journal = _validate_marketplace_uuid(journal_id, "journal_id")
        response = self._get_session().post(
            f"{self._base_url}/api/companies/{normalized_company}"
            f"/provisioning/{normalized_journal}/onboarding-link",
            json={},
            headers=self._exact_company_headers(normalized_company),
        )
        raise_if_error(response)
        return response.json()

    def create_company(
        self,
        request: "Dict[str, Any] | Any | None" = None,
        /,
        **fields: Any,
    ) -> Any:
        """Create a company in the authenticated user's tenant through the guided flow.

        Supported in Australia and Canada only: ``country`` accepts ``AU``/``Australia``
        or ``CA``/``Canada`` and any other value is rejected before a request is made.
        The tenant comes from the credential, never from the caller; Spring authorizes
        the user as a tenant admin of that tenant and provisions the company.  Returns a
        :class:`lightbulb.company_formation.CompanyFormationResult`.
        """
        from lightbulb.company_formation import (
            GUIDED_COMPANY_PATH,
            CompanyFormationRequest,
            parse_guided_response,
        )

        parsed = (
            request
            if isinstance(request, CompanyFormationRequest)
            else CompanyFormationRequest.model_validate({**dict(request or {}), **fields})
        )
        payload = parsed.to_guided_payload(self._auth.tenant_id)
        _guard_request_body(payload, endpoint="companies/guided")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}{GUIDED_COMPANY_PATH}",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return parse_guided_response(resp.json(), parsed)

    def list_projects(self, *, company_id: str | None = None) -> List[Dict[str, Any]]:
        """List projects visible in one authenticated company scope.

        This is the discovery path used by host-neutral workflow adapters to
        resolve a public ``project_ref`` before selecting the existing hosted
        checkpoint store.  A caller-supplied company is applied only to this
        request; it does not mutate the client's selected-company context.
        """
        effective_company = company_id or self._active_company_id
        headers = self._tenant_headers()
        if effective_company:
            headers["X-Company-Id"] = _validate_marketplace_uuid(
                effective_company,
                "company_id" if company_id else "active_company_id",
            )
        resp = self._get_session().get(
            f"{self._base_url}/api/projects",
            headers=headers,
        )
        raise_if_error(resp)
        data = resp.json()
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            raise ValueError("Project list response must be a JSON array or object")
        projects = data.get("items", data.get("projects", []))
        if not isinstance(projects, list):
            raise ValueError("Project list response items must be a JSON array")
        return projects

    def get_project_coding_harnesses(self, project_id: str) -> Dict[str, Any]:
        """Read the durable additive harness selection for one project."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses",
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding harness response must be a JSON object")
        return result

    def add_project_coding_harness(
        self,
        project_id: str,
        harness: str,
        *,
        make_primary: bool = False,
    ) -> Dict[str, Any]:
        """Attach another harness without removing any existing project harness."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        payload = {
            "harness": normalize_project_coding_harness(harness),
            "make_primary": bool(make_primary),
        }
        _guard_request_body(payload, endpoint="projects/coding-harnesses")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding harness response must be a JSON object")
        return result

    def native_coding(self, project_id: str) -> NativeCodingClient:
        """Connect a user-owned Codex, Claude Code or Cursor runtime to Project tasks."""
        return NativeCodingClient(self, project_id)

    def request_project_native_coding_handoff(
        self, project_id: str, harness: str, *, expected_digest: str | None = None,
    ) -> Dict[str, Any]:
        """Propose a human review, or export its exact approved native work packet.

        Omit expected_digest to prepare/review. Pass the reviewed digest to
        export after the user decides the ApprovalTask. This never starts a
        hosted coding agent or marks an external delivery as verified.
        """
        import re
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        if expected_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            raise ValueError("expected_digest must be a SHA-256 digest")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/native-coding-handoffs/{selected_harness}",
            json={"expected_digest": expected_digest}, headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict) or result.get("schema") != "lightbulb.project_native_coding_handoff.v1":
            raise ValueError("Invalid native coding handoff response")
        if result.get("project_id") != normalized_project_id or result.get("harness") != selected_harness:
            raise ValueError("Native coding handoff scope mismatch")
        if expected_digest is not None and result.get("proposal_digest") != expected_digest:
            raise ValueError("Native coding handoff digest mismatch")
        return result

    def get_project_coding_handoff(
        self,
        project_id: str,
        harness: str,
    ) -> Dict[str, Any]:
        """Read the selected Project Agent handoff for a connected harness."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses/"
            f"{selected_harness}/handoff",
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding handoff response must be a JSON object")
        return result

    def claim_project_coding_handoff(
        self,
        project_id: str,
        *,
        harness: str,
        handoff_payload_id: str,
        host_session_ref: str | None = None,
    ) -> Dict[str, Any]:
        """Record routing of an approved handoff to the user's selected harness."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        target_surface = {
            "codex": "codex_app",
            "claude_code": "claude_code",
            "cursor": "cursor",
            "chatgpt": "chatgpt",
        }[selected_harness]
        payload: Dict[str, Any] = {
            "handoff_payload_id": str(handoff_payload_id).strip(),
            "target_surface": target_surface,
            "launch_channel": "mcp_project_harness_claim",
            "status": "claimed_by_selected_harness",
            "summary": f"Selected {selected_harness} harness claimed the Project Agent handoff.",
        }
        if host_session_ref:
            if selected_harness == "codex":
                payload["codex_thread_id"] = str(host_session_ref).strip()
            elif selected_harness == "claude_code":
                payload["claude_code_session_id"] = str(host_session_ref).strip()
        _guard_request_body(payload, endpoint="projects/coding-harnesses/claim")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/product-machine/"
            "handoffs/external-coding-agents/launches",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError(
                "Project coding handoff claim response must be a JSON object"
            )
        return result

    def record_project_coding_harness_result(
        self,
        project_id: str,
        *,
        harness: str,
        handoff_payload_id: str,
        status: str,
        summary: str,
        report_id: str | None = None,
        host_session_ref: str | None = None,
        changed_files: Sequence[str] | None = None,
        test_commands_and_results: Sequence[str] | None = None,
        unresolved_requirements_or_acceptance_gaps: str | None = None,
        pull_request_url: str | None = None,
        commit_sha: str | None = None,
    ) -> Dict[str, Any]:
        """Return bounded coding evidence to the Project Agent delivery loop."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        payload: Dict[str, Any] = {
            "harness": normalize_project_coding_harness(harness),
            "handoff_payload_id": str(handoff_payload_id).strip(),
            "status": str(status).strip().lower(),
            "summary": str(summary).strip(),
        }
        optional = {
            "report_id": report_id,
            "host_session_ref": host_session_ref,
            "changed_files": list(changed_files or []),
            "test_commands_and_results": list(test_commands_and_results or []),
            "unresolved_requirements_or_acceptance_gaps": unresolved_requirements_or_acceptance_gaps,
            "pull_request_url": pull_request_url,
            "commit_sha": commit_sha,
        }
        payload.update(
            {
                key: value
                for key, value in optional.items()
                if value not in (None, [], "")
            }
        )
        _guard_request_body(payload, endpoint="projects/coding-harnesses/results")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses/results",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError(
                "Project coding harness result response must be a JSON object"
            )
        return result

    def list_project_connector_accounts(
        self,
        project_id: str,
        *,
        company_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        """List connector accounts already bound to one accessible project.

        Spring remains authoritative for tenant, company, project-sharing, and
        RBAC checks. The response contains binding metadata, never OAuth access
        or refresh credentials. Pass ``company_id`` to pin this read without
        mutating the client's selected-company context.
        """
        project = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{project}/connectors",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        value = response.json()
        rows = (
            value
            if isinstance(value, list)
            else (value.get("items", []) if isinstance(value, dict) else None)
        )
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(
                "Project connector account response must be a JSON array of objects"
            )
        return rows

    def list_available_project_connector_accounts(
        self,
        project_id: str,
        provider: str,
        *,
        company_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        """List provider accounts eligible for binding to one accessible project.

        This mirrors Spring's account-selector contract. It returns connection
        identity and display metadata needed by a trusted binding UI, but never
        connector credentials. Project/company authorization is enforced by
        Spring on every request.
        """
        project = _validate_marketplace_uuid(project_id, "project_id")
        connector_provider = _validate_connector_provider(provider)
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{project}/connectors/"
                f"{connector_provider}/available"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        value = response.json()
        rows = (
            value
            if isinstance(value, list)
            else (value.get("items", []) if isinstance(value, dict) else None)
        )
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(
                "Available project connector account response must be a JSON array of objects"
            )
        return rows

    def get_project_connector_route_descriptor(
        self,
        project_id: str,
        connector_account_ref: str,
        tool_name: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Resolve exact governed execution coordinates for one project account Tool.

        Spring authenticates tenant/company/project access and resolves the same
        account, Tool, and Tenant Connector route used by governed execution.
        The closed descriptor contains no OAuth connection or credential data.
        Pass ``company_id`` to pin this read without changing selected-company
        state.
        """
        project = _validate_marketplace_uuid(project_id, "project_id")
        account_ref = _validate_connector_account_ref(connector_account_ref)
        connector_tool = _validate_connector_tool_name(tool_name)
        response = self._get_session().get(
            f"{self._base_url}/api/tools/governed-route",
            params={
                "projectId": project,
                "connectorAccountRef": account_ref,
                "toolName": connector_tool,
            },
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return _validated_connector_route_descriptor(
            response.json(),
            project_id=project,
            connector_account_ref=account_ref,
            tool_name=connector_tool,
        )

    # Agent runtime configuration

    def list_agent_runtime_options(
        self, agent_type: str | None = None
    ) -> Dict[str, Any]:
        """List coding-agent runtimes and Backbone host surfaces available to the account."""
        session = self._get_session()
        params: Dict[str, Any] = {}
        if agent_type:
            params["agent_type"] = str(agent_type).strip()
        resp = session.get(
            f"{self._base_url}/api/ai/agent-runtime-options",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_agent_runtime_config(
        self,
        agent_type: str = "coding",
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Get the effective Codex/Claude Code/Backbone runtime config for this account."""
        session = self._get_session()
        params: Dict[str, Any] = {
            "tenantId": self._auth.tenant_id,
            "agent_type": str(agent_type or "coding").strip(),
        }
        effective_company = company_id or self._active_company_id
        if effective_company:
            params["company_id"] = str(effective_company).strip()
        resp = session.get(
            f"{self._base_url}/api/ai/agent-runtime-config",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def configure_coding_agent_runtime(
        self,
        runtime_backend: str,
        *,
        model_provider: str | None = None,
        model_id: str | None = None,
        provider_connection_id: str | None = None,
        use_codex_account: bool | None = None,
        scope: str = "USER",
        company_id: str | None = None,
        request_overrides: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Configure Codex, Claude Code, or another coding harness for this account."""
        payload: Dict[str, Any] = {
            "scope": scope,
            "runtime_backend": str(runtime_backend).strip(),
        }
        if model_provider:
            payload["model_provider"] = str(model_provider).strip()
        if model_id:
            payload["model_id"] = str(model_id).strip()
        if provider_connection_id:
            payload["provider_connection_id"] = str(provider_connection_id).strip()
        if use_codex_account is not None:
            payload["use_codex_account"] = bool(use_codex_account)
        effective_company = company_id or self._active_company_id
        if effective_company:
            payload["company_id"] = str(effective_company).strip()
        if request_overrides:
            payload["request_overrides"] = request_overrides
        session = self._get_session()
        _guard_request_body(payload, endpoint="ai/agent-runtime-config/coding")
        resp = session.put(
            f"{self._base_url}/api/ai/agent-runtime-config/coding",
            params={"tenantId": self._auth.tenant_id},
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def configure_backbone_agent_surface(
        self,
        backbone_surface: str,
        *,
        model_provider: str | None = None,
        model_id: str | None = None,
        provider_connection_id: str | None = None,
        scope: str = "USER",
        company_id: str | None = None,
        request_overrides: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Configure the preferred Backbone host surface, such as ChatGPT MCP."""
        payload: Dict[str, Any] = {
            "scope": scope,
            "backbone_surface": str(backbone_surface).strip(),
        }
        if model_provider:
            payload["model_provider"] = str(model_provider).strip()
        if model_id:
            payload["model_id"] = str(model_id).strip()
        if provider_connection_id:
            payload["provider_connection_id"] = str(provider_connection_id).strip()
        effective_company = company_id or self._active_company_id
        if effective_company:
            payload["company_id"] = str(effective_company).strip()
        if request_overrides:
            payload["request_overrides"] = request_overrides
        session = self._get_session()
        _guard_request_body(payload, endpoint="ai/agent-runtime-config/backbone")
        resp = session.put(
            f"{self._base_url}/api/ai/agent-runtime-config/backbone",
            params={"tenantId": self._auth.tenant_id},
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def test_agent_runtime_config(
        self,
        agent_type: str = "coding",
        *,
        message: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Resolve the configured runtime path without performing code or connector writes."""
        payload: Dict[str, Any] = {}
        if message:
            payload["message"] = str(message)
        params: Dict[str, Any] = {
            "tenantId": self._auth.tenant_id,
            "agent_type": str(agent_type or "coding").strip(),
        }
        effective_company = company_id or self._active_company_id
        if effective_company:
            params["company_id"] = str(effective_company).strip()
        session = self._get_session()
        _guard_request_body(payload, endpoint="ai/agent-runtime-config/test")
        resp = session.post(
            f"{self._base_url}/api/ai/agent-runtime-config/test",
            params=params,
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def start_codex_account_link(
        self, *, company_id: str | None = None
    ) -> Dict[str, Any]:
        """Start the Codex device-auth flow for the current Lightbulb account."""
        params: Dict[str, Any] = {"tenant_id": self._auth.tenant_id}
        effective_company = company_id or self._active_company_id
        if effective_company:
            params["company_id"] = str(effective_company).strip()
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/connections/credentials/codex/device-auth",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_codex_account_link_status(self, session_id: str) -> Dict[str, Any]:
        """Poll a Codex device-auth session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/connections/credentials/codex/device-auth/{_validate_id(session_id, 'session_id')}",
            params={"tenant_id": self._auth.tenant_id},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def cancel_codex_account_link(self, session_id: str) -> Dict[str, Any]:
        """Cancel a Codex device-auth session."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/connections/credentials/codex/device-auth/{_validate_id(session_id, 'session_id')}",
            params={"tenant_id": self._auth.tenant_id},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def _get_session(self, *, stream: bool = False) -> httpx.Client:
        """Get or create a persistent HTTP session with cookies.

        The session is reused across requests so CSRF tokens and session
        cookies remain valid.
        """
        if self._session is None or self._session.is_closed:
            timeout = httpx.Timeout(
                connect=self._connect_timeout,
                read=_STREAM_READ_TIMEOUT if stream else self._read_timeout,
                write=30.0,
                pool=30.0,
            )
            self._session = httpx.Client(timeout=timeout, follow_redirects=False)
        return self._session

    def refresh_auth(self) -> bool:
        """Run the configured ``auth_refresh`` callback and swap in fresh auth.

        Returns ``True`` if a new ``AuthStrategy`` was installed. Callers
        typically invoke this after catching :class:`AuthenticationError`,
        then retry the failed request:

            try:
                client.dispatch("finance", action="chat", message="...")
            except AuthenticationError:
                if client.refresh_auth():
                    client.dispatch("finance", action="chat", message="...")
        """
        if self._auth_refresh is None or self._refresh_in_flight:
            return False
        self._refresh_in_flight = True
        try:
            new_auth = self._auth_refresh()
            if new_auth is None:
                return False
            self._auth = new_auth
            if new_auth.company_id and not self._active_company_id:
                self._active_company_id = new_auth.company_id
            if self._outcome_recorder_is_managed:
                self._activate_managed_outcome_recorder()
            # Force a new session so the CSRF/cookie state is rebuilt.
            if self._session is not None:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = None
            return True
        except Exception as exc:
            logger.warning("auth_refresh callback failed: %s", exc)
            return False
        finally:
            self._refresh_in_flight = False

    def _fetch_csrf_token(self) -> str:
        """Fetch a fresh CSRF token for each request."""
        try:
            session = self._get_session()
            resp = session.get(
                f"{self._base_url}/api/auth/csrf",
                headers=self._auth.apply({"Accept": "application/json"}),
            )
            if resp.status_code == 200:
                data = resp.json()
                self._csrf_token = data.get("token", "")
                return self._csrf_token
        except Exception:
            pass
        return ""

    def _headers(self, extra: Dict[str, str] | None = None) -> Dict[str, str]:
        base = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"lightbulb-mcp/{__version__}",
        }
        csrf = self._fetch_csrf_token()
        if csrf:
            base["X-XSRF-TOKEN"] = csrf
        if extra:
            base.update(extra)
        headers = self._auth.apply(base)
        # ``select_company`` is mutable account context.  It must override the
        # company originally embedded in the auth strategy so authenticated
        # discovery and execution resolve the same company scope.
        if self._active_company_id:
            headers["X-Company-Id"] = str(self._active_company_id).strip()
        return headers

    def _tenant_headers(self, extra: Dict[str, str] | None = None) -> Dict[str, str]:
        """Build normal authenticated headers without mutable company context."""
        headers = self._headers(extra)
        for key in tuple(headers):
            if key.lower() == "x-company-id":
                headers.pop(key, None)
        return headers

    def _exact_company_headers(
        self,
        company_id: str | None,
        extra: Dict[str, str] | None = None,
    ) -> Dict[str, str]:
        """Pin one request to an explicit company without changing client state."""
        if company_id is None:
            return self._headers(extra)
        headers = self._tenant_headers(extra)
        headers["X-Company-Id"] = _validate_marketplace_uuid(
            company_id,
            "company_id",
        )
        return headers

    def _context_headers(self, company_id: str | None = None) -> Dict[str, str]:
        """Build Context Broker headers without mutating selected-company state.

        An explicit company applies only to the current request.  Calls that do
        not provide one retain the existing independently pinned Context Broker
        behavior through ``context_company_id``.
        """
        if company_id is not None:
            return self._exact_company_headers(company_id)
        headers = self._headers()
        for key in tuple(headers):
            if key.lower() == "x-company-id":
                headers.pop(key, None)
        if self.context_company_id:
            headers["X-Company-Id"] = str(self.context_company_id).strip()
        return headers

    def _stream_headers(self) -> Dict[str, str]:
        return self._headers({"Accept": "text/event-stream"})

    def _client(self, *, stream: bool = False) -> httpx.Client:
        """Return the persistent session (context-manager compatible)."""
        return self._get_session(stream=stream)

    def _company_params(self, company_id: str | None = None) -> Dict[str, str]:
        effective_company = company_id or self._active_company_id
        return (
            {"companyId": str(effective_company).strip()} if effective_company else {}
        )

    def _finance_reconciliation_scope(
        self,
        company_id: str | None,
    ) -> tuple[Dict[str, str], Dict[str, str]]:
        """Capture one exact company scope for Spring's snake-case finance API."""

        if company_id is not None:
            captured_company = _validate_marketplace_uuid(company_id, "company_id")
            scope_label = "company_id"
        elif self._active_company_id is not None:
            captured_company = _validate_marketplace_uuid(
                self._active_company_id,
                "active_company_id",
            )
            scope_label = "active_company_id"
        else:
            captured_company = None
            scope_label = "company_id"
        generic_params = self._company_params(captured_company)
        if not generic_params:
            return {}, self._tenant_headers()

        scoped_company = _validate_marketplace_uuid(
            generic_params["companyId"],
            scope_label,
        )
        return (
            {"company_id": scoped_company},
            self._exact_company_headers(scoped_company),
        )

    def _require_marketplace_company(self) -> str:
        """Require the selected company used by company-scoped marketplace calls."""
        return _validate_marketplace_uuid(self._active_company_id, "active_company_id")

    def _require_runtime_action_company(self, company_id: str | None = None) -> str:
        """Capture the explicit or selected company for one governed call."""
        return _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id" if company_id else "active_company_id",
        )

    def _runtime_action_headers(
        self,
        project_id: str,
        company_id: str,
        extra: Dict[str, str] | None = None,
    ) -> Dict[str, str]:
        """Bind governed runtime actions to captured company/project headers."""
        project = _validate_marketplace_uuid(project_id, "project_id")
        company = _validate_marketplace_uuid(company_id, "company_id")
        headers = self._headers({"X-Project-Id": project, **(extra or {})})
        # _headers reads mutable select_company state after CSRF/auth work. Restore
        # the company captured at method entry so concurrent selection cannot
        # retarget this request.
        headers["X-Company-Id"] = company
        return headers

    # ── Finance: Spring-authoritative reconciliation ────────────────

    def run_finance_reconciliation(
        self,
        request: FinanceReconciliationRequest | Mapping[str, Any] | None = None,
        *,
        company_id: str | None = None,
    ) -> FinanceReconciliationResult:
        """Run the governed Stripe/ledger reconciliation in Spring.

        The SDK validates and normalizes the request, while authenticated
        Spring scope owns connector selection, persistence, and the run ID.
        """

        payload = build_finance_reconciliation_request(request)
        params, headers = self._finance_reconciliation_scope(company_id)
        _guard_request_body(
            payload,
            endpoint="finance/reconciliation/stripe-ledger",
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/finance/reconciliation/stripe-ledger",
            params=params,
            json=payload,
            headers=headers,
        )
        raise_if_error(resp)
        return parse_finance_reconciliation_result(resp.json())

    def list_finance_reconciliation_runs(
        self,
        *,
        company_id: str | None = None,
        limit: int = 50,
    ) -> tuple[FinanceReconciliationRunSummary, ...]:
        """List bounded reconciliation run summaries under one Spring scope."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")

        params, headers = self._finance_reconciliation_scope(company_id)
        request_params: Dict[str, Any] = {**params, "limit": limit}
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/finance/reconciliation/stripe-ledger/runs",
            params=request_params,
            headers=headers,
        )
        raise_if_error(resp)
        return parse_finance_reconciliation_run_summaries(resp.json())

    def get_finance_reconciliation_run(
        self,
        run_id: str,
        *,
        company_id: str | None = None,
    ) -> FinanceReconciliationRunDetails:
        """Get one exact reconciliation run and validate its stored envelope."""

        normalized_run_id = _validate_marketplace_uuid(run_id, "run_id")
        params, headers = self._finance_reconciliation_scope(company_id)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/finance/reconciliation/stripe-ledger/runs/"
            f"{normalized_run_id}",
            params=params,
            headers=headers,
        )
        raise_if_error(resp)
        return parse_finance_reconciliation_run_details(resp.json())

    # ── Domain Agent: One-shot dispatch ──────────────────────────────

    def dispatch(
        self,
        domain: str,
        *,
        action: str = "chat",
        message: str = "",
        objective: str = "",
        inputs: Dict[str, Any] | None = None,
        conversation_id: str | None = None,
        company_id: str | None = None,
        project_id: str | None = None,
    ) -> DispatchResult:
        """Dispatch a one-shot action to a domain agent and wait for the result."""
        domain = _validate_domain(domain)
        action = _validate_action(action)
        if message:
            message = _validate_message(message)

        payload: Dict[str, Any] = {"action": action}
        if message:
            payload["message"] = message
        if objective:
            payload["objective"] = str(objective)[:_MAX_MESSAGE_LENGTH]
        if inputs:
            payload["inputs"] = _sanitize_inputs(inputs)
        if conversation_id:
            payload["conversation_id"] = str(conversation_id).strip()
        # Use explicit company_id, fall back to active company context
        effective_company = company_id or self._active_company_id
        if effective_company:
            payload["company_id"] = str(effective_company).strip()

        url = f"{self._base_url}/api/domain-agents/{domain}/dispatch"
        session = self._get_session()
        _guard_request_body(payload, endpoint=f"domain-agents/{domain}/dispatch")
        headers = self._headers()
        if project_id is not None:
            headers["X-Project-Id"] = _validate_marketplace_uuid(project_id, "project_id")
        resp = session.post(url, json=payload, headers=headers)
        raise_if_error(resp)
        data = resp.json()

        return DispatchResult(
            domain=data.get("domain", domain),
            action=data.get("action", action),
            mode=data.get("mode", ""),
            reply=data.get("reply", ""),
            conversation_id=data.get("conversationId")
            or data.get("conversation_id", ""),
            trace_id=data.get("traceId") or data.get("trace_id", ""),
            outputs=data.get("outputs") or data.get("structuredOutputs") or {},
            raw=data,
        )

    # ── Domain Agent: Streaming chat ─────────────────────────────────

    def get_workflow_instance(
        self,
        trace_id: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Get a workflow instance through the authenticated public API."""
        trace_id = _validate_id(trace_id, "trace_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/instances/{trace_id}",
            params=self._company_params(company_id),
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def wait_for_workflow_instance(
        self,
        trace_id: str,
        *,
        company_id: str | None = None,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> Dict[str, Any]:
        """Poll a workflow until it stops or requires human approval."""
        trace_id = _validate_id(trace_id, "trace_id")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")

        deadline = time.monotonic() + timeout
        last_state = "unknown"
        while True:
            instance = self.get_workflow_instance(trace_id, company_id=company_id)
            last_state = _workflow_instance_state(instance) or "unknown"
            if last_state in _WORKFLOW_STOP_STATES:
                return instance
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Workflow {trace_id!r} did not stop within {timeout:g}s "
                    f"(last state: {last_state})"
                )
            time.sleep(min(poll_interval, remaining))

    def stream_chat(
        self,
        domain: str,
        *,
        message: str,
        action: str | None = None,
        inputs: Dict[str, Any] | None = None,
        conversation_id: str | None = None,
        company_id: str | None = None,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a domain agent chat via Server-Sent Events.

        Yields SSEEvent objects for each event (status, chat, artifact, complete, error).
        """
        domain = _validate_domain(domain)
        message = _validate_message(message)

        payload: Dict[str, Any] = {
            "domain": domain,
            "message": message,
            "tenant_id": self._auth.tenant_id,
        }
        if action:
            payload["action"] = _validate_action(action)
        if inputs:
            payload["inputs"] = _sanitize_inputs(inputs)
        if conversation_id:
            payload["conversation_id"] = str(conversation_id).strip()
        if company_id or self._auth.company_id:
            payload["company_id"] = str(company_id or self._auth.company_id).strip()

        url = f"{self._base_url}/api/domain-agent/chat"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json=payload, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def _parse_sse_stream(
        self, response: httpx.Response
    ) -> Generator[SSEEvent, None, None]:
        current_event = "message"
        data_buffer: List[str] = []
        bytes_read = 0
        event_bytes = 0  # accumulated per-event size

        for line in response.iter_lines():
            # Per-line cap: a malicious server can withhold newlines so a
            # single line balloons in memory — reject anything pathological.
            if len(line) > _MAX_SSE_LINE_BYTES:
                logger.warning(
                    "SSE line exceeded %d bytes; aborting stream.",
                    _MAX_SSE_LINE_BYTES,
                )
                break

            bytes_read += len(line) + 1
            if bytes_read > _MAX_RESPONSE_BYTES:
                logger.warning(
                    "SSE stream exceeded %d bytes, closing", _MAX_RESPONSE_BYTES
                )
                break

            if line.startswith("event:"):
                current_event = line[6:].strip()
            elif line.startswith("data:"):
                payload = line[5:].strip()
                event_bytes += len(payload) + 1
                if event_bytes > _MAX_SSE_EVENT_BYTES:
                    logger.warning(
                        "SSE event exceeded %d bytes; dropping.",
                        _MAX_SSE_EVENT_BYTES,
                    )
                    data_buffer.clear()
                    event_bytes = 0
                    continue
                data_buffer.append(payload)
            elif line == "" and data_buffer:
                raw_data = "\n".join(data_buffer)
                data_buffer.clear()
                event_bytes = 0
                try:
                    parsed = json.loads(raw_data) if raw_data else {}
                except json.JSONDecodeError:
                    parsed = {"raw_text": raw_data}
                yield SSEEvent(event=current_event, data=parsed, raw=raw_data)
                current_event = "message"
            elif line.startswith(":"):
                # SSE comment / keepalive
                continue

    # ── Streaming: code workspace / page builder / doc builder ──────

    def get_project_game_snapshot(self, project_id: str) -> Dict[str, Any]:
        """Fetch one server-owned, exact-scoped project snapshot.

        JWT users use the public project route. Trusted API-key workers use the
        internal route so Spring's internal authentication filter remains the
        sole service-auth boundary. The returned projection is orientation
        only and is rejected if it widens scope or authority.
        """

        project = normalize_project_game_snapshot_uuid(project_id, "project_id")
        company = normalize_project_game_snapshot_uuid(
            self._active_company_id,
            "active_company_id",
        )
        auth = self._auth
        tenant = normalize_project_game_snapshot_uuid(auth.tenant_id, "tenant_id")
        if isinstance(auth, ApiKeyAuth):
            route = f"/api/internal/projects/{project}/game-snapshot"
        elif isinstance(auth, JwtAuth):
            route = f"/api/projects/{project}/game-snapshot"
        else:
            raise ValueError("Project snapshots require JwtAuth or ApiKeyAuth")

        headers = self._headers({"X-Project-Id": project})
        if self._auth is not auth:
            raise RuntimeError(
                "authentication context changed while binding project snapshot scope"
            )
        headers["X-Tenant-Id"] = tenant
        headers["X-Company-Id"] = company
        response = self._get_session().get(
            f"{self._base_url}{route}",
            headers=headers,
        )
        if len(response.content or b"") > PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES:
            raise ValueError(
                "project snapshot response exceeds the bounded canonical "
                f"limit of {PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES} bytes"
            )
        raise_if_error(response)
        return validate_project_game_snapshot(
            response.json(),
            expected_tenant_id=tenant,
            expected_company_id=company,
            expected_project_id=project,
        )

    def inspect_project_game_campaign(
        self,
        *,
        project: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        business_cockpit: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Inspect the human/agent project campaign locally without network activity."""
        return build_project_game_campaign(
            project=project,
            plan=plan,
            business_cockpit=business_cockpit,
        )

    def list_project_science_evidence(
        self,
        project_id: str,
        *,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Read the scope-verified hypothesis-to-policy context spine."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/science-evidence",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def record_project_science_evidence(
        self,
        project_id: str,
        *,
        stage: Any,
        summary: Any,
        business_metric_id: Any,
        expected_direction: Any,
        artifact_kind: Any,
        artifact_system: Any,
        artifact_reference: Any,
        artifact_digest_sha256: Any,
        producer_role: Any,
        confirm_record: bool = False,
        tool_names: Sequence[Any] | None = None,
        skill_ids: Sequence[Any] | None = None,
        parent_receipt_ids: Sequence[Any] | None = None,
        artifact_schema: Any = None,
        observed_at: Any = None,
        evidence_id: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Append scientific lineage evidence; never authorize the underlying action."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to append science evidence"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_science_evidence_observation(
            stage=stage,
            summary=summary,
            business_metric_id=business_metric_id,
            expected_direction=expected_direction,
            artifact_kind=artifact_kind,
            artifact_system=artifact_system,
            artifact_reference=artifact_reference,
            artifact_digest_sha256=artifact_digest_sha256,
            producer_role=producer_role,
            tool_names=tool_names,
            skill_ids=skill_ids,
            parent_receipt_ids=parent_receipt_ids,
            artifact_schema=artifact_schema,
            observed_at=observed_at,
            evidence_id=evidence_id,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
        )
        _guard_request_body(payload, endpoint="projects/science-evidence")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["evidence_id"])
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/science-evidence",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_mission_runs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read briefing locks and action bindings for one accessible project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def start_project_mission_run(
        self,
        project_id: str,
        mission_briefing: Mapping[str, Any],
        *,
        confirm_start: bool = False,
        run_id: Any = None,
        play_style_id: Any = None,
        skill_trial_arm: Any = None,
        selected_skill_ids: Sequence[Any] | None = None,
        context_source_refs: Sequence[Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Lock an exact briefing before action; this never dispatches a worker."""
        if confirm_start is not True:
            raise ValueError(
                "confirm_start=True is required to lock a project mission briefing"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_mission_run_start(
            mission_briefing=mission_briefing,
            run_id=run_id,
            play_style_id=play_style_id,
            skill_trial_arm=skill_trial_arm,
            selected_skill_ids=selected_skill_ids,
            context_source_refs=context_source_refs,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/mission-runs")
        retry_key = _validate_idempotency_key(idempotency_key or str(payload["run_id"]))
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def bind_project_mission_action(
        self,
        project_id: str,
        mission_run_receipt_id: Any,
        action_event_id: Any,
        *,
        confirm_bind: bool = False,
        binding_id: Any = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Bind a later event to a mission; this proves timing and scope only."""
        if confirm_bind is not True:
            raise ValueError(
                "confirm_bind=True is required to bind a project mission action"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_mission_action_binding(
            mission_run_receipt_id=mission_run_receipt_id,
            action_event_id=action_event_id,
            binding_id=binding_id,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/mission-runs/action-bindings")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["binding_id"])
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs/action-bindings",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_learning_reviews(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read human after-action decisions and admitted shadow observations."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-reviews",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def list_project_skill_matches(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read the project's worker-verified shadow Training Arena ledger."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/skill-matches",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def list_project_training_packs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read exact Arena + human-lesson packs before any learning-run admission."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/training-packs",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def list_project_learning_runs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read receipt-backed Training Quest state without inferring missing execution."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def prepare_project_learning_run(
        self,
        project_id: str,
        *,
        training_pack_receipt_id: Any,
        primary_metric: Any,
        runtime: str = "automl",
        request_id: Any = None,
        direction: str = "maximize",
        minimum_improvement: Any = "0.010000",
        max_cost_usd: Any = "0.000000",
        max_platform_cost_usd: Any = "5.000000",
        max_gpu_seconds: Any = 3600,
        max_tokens: Any = 100_000,
        max_steps: Any = 10_000,
        provider_account_fingerprint: Any = None,
        provider_binding_expires_at: Any = None,
        max_attempts: Any = 3,
        lease_seconds: Any = 300,
        preemptible: bool = True,
        confirm_prepare: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Publish exact dataset custody and create a queued durable Memory run."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_learning_run_prepare_request(
            training_pack_receipt_id,
            primary_metric,
            runtime=runtime,
            request_id=request_id,
            direction=direction,
            minimum_improvement=minimum_improvement,
            max_cost_usd=max_cost_usd,
            max_platform_cost_usd=max_platform_cost_usd,
            max_gpu_seconds=max_gpu_seconds,
            max_tokens=max_tokens,
            max_steps=max_steps,
            provider_account_fingerprint=provider_account_fingerprint,
            provider_binding_expires_at=provider_binding_expires_at,
            max_attempts=max_attempts,
            lease_seconds=lease_seconds,
            preemptible=preemptible,
            confirm_prepare=confirm_prepare,
        )
        retry_key = _validate_idempotency_key(idempotency_key or payload["request_id"])
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(payload, endpoint="projects/learning-runs")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def admit_project_learning_run(
        self,
        project_id: str,
        learning_run_id: str,
        *,
        runtime: str,
        capacity_admission: Mapping[str, Any],
        operator_approved: bool = False,
        confirm_admission: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Reserve budget and admit a queued run; this still executes no training."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        normalized_run_id = _validate_id(learning_run_id, "learning_run_id")
        payload = build_project_learning_run_admission_request(
            runtime,
            capacity_admission,
            operator_approved=operator_approved,
            confirm_admission=confirm_admission,
        )
        default_key = (
            f"project-learning-admission:{normalized_run_id}:"
            f"{payload['capacity_admission']['decision_id']}"
        )
        retry_key = _validate_idempotency_key(idempotency_key or default_key)
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(payload, endpoint="projects/learning-runs/admit")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs/"
            f"{normalized_run_id}/admit",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_learning_result_evaluations(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read independent technical results and separate human decisions."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            "learning-result-evaluations",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def decide_project_learning_result_admission(
        self,
        project_id: str,
        evaluation_receipt_id: str,
        *,
        decision: Any,
        rationale: Any,
        confirm_admission: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Human admit/reject; never apply or promote the candidate."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        normalized_evaluation_id = _validate_id(
            evaluation_receipt_id, "evaluation_receipt_id"
        )
        payload = build_project_learning_result_admission_request(
            decision,
            rationale,
            confirm_admission=confirm_admission,
        )
        retry_key = _validate_idempotency_key(
            idempotency_key
            or f"project-learning-result-admission:{normalized_evaluation_id}"
        )
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(
            payload, endpoint="projects/learning-result-evaluations/admission"
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            f"learning-result-evaluations/{normalized_evaluation_id}/admission",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_shadow_learner_updates(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read bounded shadow update/rollback receipts; this grants no authority."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            "shadow-learner-updates",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, Mapping) or result.get("schema") != (
            PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA
        ):
            raise ValueError("shadow learner update ledger schema does not match")
        return dict(result)

    def record_project_learning_review(
        self,
        project_id: str,
        *,
        mission_run_receipt_id: Any,
        mission_action_receipt_id: Any,
        outcome_receipt_id: Any,
        decision: Any,
        skill_trial_arm: Any,
        selected_skill_ids: Sequence[Any] | None,
        label: Any,
        reason: Any,
        confirm_record: bool = False,
        review_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Human-review one exact chain for shadow training; no live learner mutation."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to record a project learning review"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_learning_review_request(
            mission_run_receipt_id=mission_run_receipt_id,
            mission_action_receipt_id=mission_action_receipt_id,
            outcome_receipt_id=outcome_receipt_id,
            decision=decision,
            skill_trial_arm=skill_trial_arm,
            selected_skill_ids=selected_skill_ids,
            label=label,
            reason=reason,
            review_id=review_id,
            evidence_refs=evidence_refs,
        )
        _guard_request_body(payload, endpoint="projects/learning-reviews")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["review_id"])
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-reviews",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_business_outcomes(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read the authenticated score ledger for one accessible project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        session = self._get_session()
        response = session.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/business-outcomes",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def record_project_business_outcome(
        self,
        project_id: str,
        *,
        metric_id: Any,
        metric_label: Any,
        direction: Any,
        baseline_value: Any,
        observed_value: Any,
        confirm_record: bool = False,
        unit: Any = None,
        observed_at: Any = None,
        observation_id: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        links: Mapping[str, Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Append one scoped metric observation; never admit learning or promotion."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to append a business outcome"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_business_outcome_observation(
            metric_id=metric_id,
            metric_label=metric_label,
            direction=direction,
            baseline_value=baseline_value,
            observed_value=observed_value,
            unit=unit,
            observed_at=observed_at,
            observation_id=observation_id,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
            links=links,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/business-outcomes")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["observation_id"])
        )
        session = self._get_session()
        response = session.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/business-outcomes",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_policy_assignments(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read immutable decision-time probability assignments for one project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-assignments",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def record_project_policy_assignment(
        self,
        project_id: str,
        *,
        metric_id: Any,
        direction: Any,
        actions: Sequence[Mapping[str, Any]],
        chosen_action_id: Any,
        behavior_policy: Mapping[str, Any],
        candidate_policies: Sequence[Mapping[str, Any]],
        confirm_record: bool = False,
        assignment_id: Any = None,
        unit: Any = None,
        decided_at: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        links: Mapping[str, Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Log propensities before an outcome; this never executes an action."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to append a policy assignment"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_policy_assignment(
            metric_id=metric_id,
            direction=direction,
            actions=actions,
            chosen_action_id=chosen_action_id,
            behavior_policy=behavior_policy,
            candidate_policies=candidate_policies,
            assignment_id=assignment_id,
            unit=unit,
            decided_at=decided_at,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
            links=links,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/policy-assignments")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["assignment_id"])
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-assignments",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def list_project_policy_evaluations(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read offline-policy receipts and their explicit truth boundary."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-evaluations",
            params={"limit": bounded_limit},
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def evaluate_project_offline_policy(
        self,
        project_id: str,
        *,
        behavior_policy_id: Any,
        candidate_policy_id: Any,
        metric_id: Any,
        pairs: Sequence[Mapping[str, Any]],
        confirm_evaluate: bool = False,
        evaluation_id: Any = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Estimate a candidate from verified receipts; never admit learning."""
        if confirm_evaluate is not True:
            raise ValueError(
                "confirm_evaluate=True is required to run offline policy evaluation"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_policy_evaluation_request(
            behavior_policy_id=behavior_policy_id,
            candidate_policy_id=candidate_policy_id,
            metric_id=metric_id,
            pairs=pairs,
            evaluation_id=evaluation_id,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/policy-evaluations")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["evaluation_id"])
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-evaluations",
            json=payload,
            headers=self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def inspect_project_creation_world_ready(
        self,
        name: str,
        instructions: str = "",
        *,
        participant_role: str = "agent_worker",
        experience_lens: str = "agent_protocol",
        play_style: str = "guided_human_in_the_loop",
    ) -> dict[str, Any]:
        """Inspect project-review readiness locally without network activity."""
        return build_project_creation_world_ready(
            name=name,
            instructions=instructions,
            tenant_id=self._auth.tenant_id,
            company_id=self._active_company_id,
            project_id=None,
            participant_role=participant_role,
            experience_lens=experience_lens,
            play_style=play_style,
            secure_receipt_verification=True,
        )

    def preflight_project_creation(
        self,
        name: str,
        instructions: str = "",
    ) -> ProjectCreationPreflightReceipt:
        """Review a project draft without creating or mutating anything.

        Only ``name`` and ``instructions`` are accepted. The request always
        runs in shadow/read-only mode, and the returned receipt trusts an
        execution UUID only when it arrived on the dedicated ``execution`` SSE
        event.
        """
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        draft = ProjectCreationDraft(name=name, instructions=instructions)
        payload = build_project_creation_preflight_request(draft)
        _guard_request_body(payload, endpoint="enterprise-copilot/project-preflight")
        session = self._get_session(stream=True)
        with session.stream(
            "POST",
            f"{self._base_url}/api/enterprise-copilot/project-preflight",
            json=payload,
            headers=self._stream_headers(),
        ) as response:
            raise_if_error(response)
            receipt = project_creation_preflight_receipt_from_events(
                draft,
                self._parse_sse_stream(response),
            )
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ProjectCreationPreflightError(
                "Project preflight episode tenant does not match the auth context"
            )
        if receipt.episode_scope.company_id != company_id:
            raise ProjectCreationPreflightError(
                "Project preflight episode company does not match the selected company"
            )
        return receipt

    def create_project_from_preflight(
        self,
        receipt: ProjectCreationPreflightReceipt,
        *,
        coding_harness: str,
        confirm_create: bool = False,
        confirm_open_questions: bool = False,
        workspace_id: str | None = None,
        repo_connection_id: str | None = None,
        idempotency_key: str | None = None,
        play_style: str | None = None,
    ) -> Dict[str, Any]:
        """Create exactly the draft bound to a validated preflight receipt.

        This method deliberately has no product-plan, scope, approval-state,
        or arbitrary request-body argument. A separate, literal confirmation
        and selected company context are required before the one POST occurs.
        """
        if confirm_create is not True:
            raise ValueError("confirm_create=True is required to create the project")
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError(
                "Preflight receipt company does not match the selected company"
            )
        # Kept as a compatibility keyword for existing callers. Advisory
        # questions and legacy-v1 blocking labels never require a second
        # confirmation; confirm_create is the user's explicit authority to
        # create the reversible project container.
        del confirm_open_questions
        selected_harness = normalize_project_coding_harness(coding_harness)

        payload: Dict[str, Any] = {
            "name": receipt.draft.name,
            "instructions": receipt.draft.instructions,
            "preflight_execution_id": receipt.preflight_execution_id,
            "coding_harnesses": [selected_harness],
            "primary_coding_harness": selected_harness,
        }
        if workspace_id is not None:
            payload["workspace_id"] = normalize_project_uuid(
                workspace_id, "workspace_id"
            )
        if repo_connection_id is not None:
            payload["repo_connection_id"] = normalize_project_uuid(
                repo_connection_id,
                "repo_connection_id",
            )
        if play_style is not None:
            payload["play_style"] = normalize_project_play_style(play_style)
        extra_headers: Dict[str, str] = {}
        if idempotency_key is not None:
            extra_headers["Idempotency-Key"] = _validate_idempotency_key(
                idempotency_key
            )

        _guard_request_body(payload, endpoint="projects")
        response = self._get_session().post(
            f"{self._base_url}/api/projects",
            json=payload,
            headers=self._headers(extra_headers),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project create response must be a JSON object")
        return result

    def refine_project_creation_preflight(
        self,
        receipt: ProjectCreationPreflightReceipt,
        answer: str,
    ) -> ProjectCreationPreflightReceipt:
        """Apply one explicit answer to the receipt's authoritative next question."""
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError(
                "Preflight receipt company does not match the selected company"
            )
        payload = build_project_creation_preflight_refinement_request(receipt, answer)
        _guard_request_body(
            payload,
            endpoint="enterprise-copilot/project-preflight/refine",
        )
        session = self._get_session(stream=True)
        with session.stream(
            "POST",
            f"{self._base_url}/api/enterprise-copilot/project-preflight/refine",
            json=payload,
            headers=self._stream_headers(),
        ) as response:
            raise_if_error(response)
            refreshed = project_creation_preflight_refinement_receipt_from_events(
                receipt,
                payload["answer"],
                self._parse_sse_stream(response),
            )
        if refreshed.episode_scope.tenant_id != tenant_id:
            raise ProjectCreationPreflightError(
                "Refined preflight episode tenant does not match the auth context"
            )
        if refreshed.episode_scope.company_id != company_id:
            raise ProjectCreationPreflightError(
                "Refined preflight episode company does not match the selected company"
            )
        return refreshed

    def submit_project_creation_preflight_feedback(
        self,
        receipt: ProjectCreationPreflightReceipt,
        *,
        helpfulness: SemanticFeedbackValue,
        calibrated_criticality: SemanticFeedbackValue,
        factual_grounding: SemanticFeedbackValue,
        idempotency_key: str,
    ) -> ProjectPreflightSemanticFeedbackReceipt:
        """Submit one explicit human judgment for this preflight's episode.

        Project creation or approval never calls this method automatically.
        The server derives actor and scope; callers can supply only the exact
        typed preflight receipt, three bounded judgments, and a stable retry
        key. A successful receipt is a preference signal, not independent
        factual or business-outcome proof.
        """
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError(
                "Preflight receipt company does not match the selected company"
            )
        payload, dimensions = build_project_preflight_feedback_request(
            helpfulness=helpfulness,
            calibrated_criticality=calibrated_criticality,
            factual_grounding=factual_grounding,
            idempotency_key=idempotency_key,
        )
        _guard_request_body(payload, endpoint="agent-episodes/semantic-feedback")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/memory/agent-episodes/"
                f"{receipt.episode_id}/semantic-feedback"
            ),
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return bind_project_preflight_feedback_receipt(
            response.json(),
            preflight_receipt=receipt,
            dimensions=dimensions,
            expected_tenant_id=tenant_id,
            expected_company_id=company_id,
        )

    def stream_code_workspace_chat(
        self,
        workspace_id: str,
        message: str,
        **kwargs: Any,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a coding agent chat as Server-Sent Events.

        Yields SSEEvent objects (status, token, tool_call, diff, complete, error).
        The non-streaming counterpart is :meth:`code_workspace_chat`.
        """
        message = _validate_message(message)
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        url = f"{self._base_url}/api/code/workspaces/{workspace_id}/chat/stream"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json=payload, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_page_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a page builder message via SSE (token-by-token output)."""
        content = _validate_message(content)
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/message"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json={"content": content}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_page_builder_workspace_automation(
        self,
        session_id: str,
        body: Dict[str, Any] | None = None,
    ) -> Generator[SSEEvent, None, None]:
        """Stream the page-builder workspace automation pipeline."""
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/workspace-automation/stream"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json=body or {}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_document_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a document builder message via SSE."""
        content = _validate_message(content)
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}/message"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json={"content": content}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    # ── Domain Agent: Conversations ──────────────────────────────────

    def list_conversations(self, domain: str) -> List[Dict[str, Any]]:
        """List all conversations for a domain."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_conversation(self, domain: str, conversation_id: str) -> Dict[str, Any]:
        """Get conversation history."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations/{conversation_id}"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def create_conversation(self, domain: str) -> Dict[str, Any]:
        """Create a new conversation for a domain."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations"
        session = self._get_session()
        resp = session.post(url, json={}, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def delete_conversation(self, domain: str, conversation_id: str) -> None:
        """Delete a conversation."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations/{conversation_id}"
        session = self._get_session()
        resp = session.delete(url, headers=self._headers())
        raise_if_error(resp)

    # ── Document Builder Sessions ────────────────────────────────────

    def create_document_session(
        self,
        *,
        document_type: str = "general",
        document_title: str = "Untitled Document",
    ) -> Dict[str, Any]:
        """Create a new document builder session."""
        url = f"{self._base_url}/api/document-builder/sessions"
        payload = {"documentType": document_type, "documentTitle": document_title}
        session = self._get_session()
        resp = session.post(url, json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_document_sessions(self) -> List[Dict[str, Any]]:
        """List document builder sessions."""
        url = f"{self._base_url}/api/document-builder/sessions"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_document_session(self, session_id: str) -> Dict[str, Any]:
        """Get a document builder session."""
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_document_schemas(self, session_id: str) -> Dict[str, Any]:
        """Get the document schemas for a session."""
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}/schemas"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Document Intelligence shortcuts ──────────────────────────────

    def search_documents(
        self,
        query: str,
        *,
        folder_path: str | None = None,
        top_k: int = 10,
    ) -> DispatchResult:
        """Search across all documents using semantic search."""
        inputs: Dict[str, Any] = {"message": query, "top_k": top_k}
        if folder_path:
            inputs["folder_path_prefix"] = folder_path
        return self.dispatch(
            "document_intelligence",
            action="search_documents",
            message=query,
            inputs=inputs,
        )

    def grep_documents(
        self,
        pattern: str,
        *,
        regex: bool = True,
        case_sensitive: bool = False,
        folder_path: str | None = None,
        top_k: int = 20,
    ) -> DispatchResult:
        """Grep across document content using pattern matching."""
        inputs: Dict[str, Any] = {
            "pattern": pattern,
            "regex": regex,
            "case_sensitive": case_sensitive,
            "top_k": top_k,
        }
        if folder_path:
            inputs["folder_path"] = folder_path
        return self.dispatch(
            "document_intelligence",
            action="grep_content",
            message=pattern,
            inputs=inputs,
        )

    def list_folder(
        self,
        folder_path: str = "",
        *,
        source_system: str | None = None,
        max_items: int = 100,
    ) -> DispatchResult:
        """List documents in a folder."""
        inputs: Dict[str, Any] = {"folder_path": folder_path, "max_items": max_items}
        if source_system:
            inputs["source_system"] = source_system
        return self.dispatch(
            "document_intelligence",
            action="list_folder",
            inputs=inputs,
        )

    def create_document(
        self,
        title: str,
        body: str,
        *,
        format: str = "docx",
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new document."""
        return self.dispatch(
            "document_intelligence",
            action="write_document",
            message=f"Create document: {title}",
            inputs={
                "title": title,
                "body": body,
                "format": format,
                "target_suite": target_suite,
            },
        )

    def create_spreadsheet(
        self,
        title: str,
        body: str = "",
        *,
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new spreadsheet."""
        return self.dispatch(
            "document_intelligence",
            action="create_spreadsheet",
            message=f"Create spreadsheet: {title}",
            inputs={"title": title, "body": body, "target_suite": target_suite},
        )

    def create_slide_deck(
        self,
        title: str,
        body: str = "",
        *,
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new slide deck."""
        return self.dispatch(
            "document_intelligence",
            action="create_slide_deck",
            message=f"Create slides: {title}",
            inputs={"title": title, "body": body, "target_suite": target_suite},
        )

    # ── Page Builder ──────────────────────────────────────────────────

    def create_page_builder_session(
        self, brand_name: str = "", initial_prompt: str = ""
    ) -> Dict[str, Any]:
        """Create a new page builder session."""
        payload: Dict[str, Any] = {}
        if brand_name:
            payload["brandName"] = brand_name
        if initial_prompt:
            payload["initialPrompt"] = initial_prompt
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_page_builder_sessions(self) -> List[Dict[str, Any]]:
        """List page builder sessions."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/page-builder/sessions", headers=self._headers()
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def page_builder_send_message(
        self, session_id: str, content: str
    ) -> Dict[str, Any]:
        """Send a message to a page builder session (non-streaming)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/message",
            json={"content": content},
            headers=self._headers({"Accept": "application/json"}),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_get_schemas(self, session_id: str) -> Dict[str, Any]:
        """Get the current page schemas for a session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/schemas",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_deploy(
        self, session_id: str, page_key: str = ""
    ) -> Dict[str, Any]:
        """Deploy a page builder session."""
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/deploy"
        if page_key:
            url += f"/{page_key}"
        session = self._get_session()
        resp = session.post(url, json={}, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def page_builder_get_preview(self, session_id: str) -> Dict[str, Any]:
        """Get the preview URL for a page builder session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/preview",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspaces ──────────────────────────────────────────────

    def create_code_workspace(
        self,
        *,
        source: str | None = None,
        repo_connection_id: str | None = None,
        branch: str | None = None,
        depth: int | None = None,
        label: str | None = None,
        metadata: Dict[str, Any] | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Create a code workspace."""
        payload: Dict[str, Any] = {}
        if source:
            payload["source"] = source
        if repo_connection_id:
            payload["repoConnectionId"] = repo_connection_id
        if branch:
            payload["branch"] = branch
        if depth is not None:
            payload["depth"] = depth
        if label:
            payload["label"] = label
        if metadata:
            payload["metadata"] = dict(metadata)
        if company_id:
            payload["companyId"] = company_id

        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_code_workspaces(self) -> List[Dict[str, Any]]:
        """List code workspaces."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_chat(
        self, workspace_id: str, message: str, **kwargs
    ) -> Dict[str, Any]:
        """Send a chat message to a code workspace."""
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_code_workspace_active_run(self, workspace_id: str) -> Dict[str, Any] | None:
        """Get the currently active run for a code workspace, if one exists."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/active",
            headers=self._headers(),
        )
        if resp.status_code == 204:
            return None
        raise_if_error(resp)
        return resp.json()

    def get_code_workspace_run(self, workspace_id: str, run_id: str) -> Dict[str, Any]:
        """Get a specific code workspace run."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Backbone Agent ───────────────────────────────────────────────

    def backbone_execute(
        self, objective: str, *, inputs: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Execute a task through the backbone agent (research, analysis, code generation)."""
        payload: Dict[str, Any] = {"objective": objective}
        if inputs:
            payload["inputs"] = inputs
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/v1/backbone/execute",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Artifacts ────────────────────────────────────────────────────

    # -- Business primitives -------------------------------------------------

    def list_executable_business_primitives(
        self,
        *,
        query: str = "",
        include_schemas: bool = True,
        offset: int = 0,
        limit: int | None = None,
    ) -> Dict[str, Any]:
        """List SDK primitive implementations from the canonical manifest."""
        from lightbulb.primitive_capability_manifest import primitive_manifest_catalog

        return primitive_manifest_catalog(
            query=query,
            include_schemas=include_schemas,
            offset=offset,
            limit=limit,
        )

    def run_sdk_business_primitive(
        self,
        primitive_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        primitive_version: str | None = None,
        project_ref: str,
        project_id: str | None = None,
        preview_only: bool = True,
        approval_refs: Dict[str, str] | None = None,
        connector_account_refs: Dict[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Run SDK code with hosted reads, previews, and governed writes.

        Preview mode uses the local typed runtime. Apply mode fails closed for
        connector-backed primitives until retained certification activates the
        manifest entry. Any future activated write still requires a Project UUID,
        exact account binding, idempotency, and Spring-issued approval custody.
        """
        from lightbulb.connector_execution import (
            ExecutionScope,
            HostedConnectorExecutor,
        )
        from lightbulb.executable_primitives import default_primitive_registry
        from lightbulb.primitive_capability_manifest import (
            primitive_capability_metadata,
        )
        from lightbulb.primitive_runtime import (
            ExecutablePrimitiveRuntime,
            PrimitiveCall,
            PrimitiveCorrelation,
            PrimitiveRunMode,
            StandalonePrimitiveRun,
        )

        metadata = primitive_capability_metadata(primitive_id)
        if metadata is None:
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "unknown_primitive",
                "primitive_ref": primitive_id,
                "message": "Unknown primitive refs fail closed.",
            }
        requested_version = str(primitive_version or "").strip()
        if requested_version and primitive_capability_metadata(
            primitive_id,
            primitive_version=requested_version,
        ) is None:
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "primitive_version_mismatch",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "requested_primitive_version": requested_version,
                "message": (
                    "The requested primitive version is not the canonical manifest version."
                ),
            }
        resolved_version = str(metadata["version"])
        clean_project_ref = _validate_id(project_ref, "project_ref")
        if run_ref and idempotency_key and run_ref != idempotency_key:
            raise ValueError(
                "idempotency_key is deprecated for SDK primitives; use one run_ref"
            )
        stable_run_ref = run_ref or idempotency_key
        if (
            not preview_only
            and metadata["effect_class"] == "consequential_write"
            and not stable_run_ref
        ):
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "idempotency_key_required",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "effect_class": metadata["effect_class"],
                "message": (
                    "Consequential apply requires an explicit stable run_ref "
                    "before any provider boundary."
                ),
            }
        if (
            not preview_only
            and metadata["effect_class"] == "consequential_write"
            and not str(project_id or "").strip()
        ):
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "project_scope_required",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "effect_class": metadata["effect_class"],
                "message": (
                    "Consequential apply requires an authenticated Project UUID "
                    "before certification or connector authority is evaluated."
                ),
            }
        if metadata["certification_state"] == "UNCERTIFIED" and (
            metadata["effect_class"] == "connector_read" or not preview_only
        ):
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "capability_uncertified",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "effect_class": metadata["effect_class"],
                "message": (
                    "This connector-backed primitive has no retained production "
                    "certification evidence."
                ),
            }
        actual_run_ref = stable_run_ref or f"sdk-{uuid4()}"
        runtime = ExecutablePrimitiveRuntime(
            default_primitive_registry(),
            HostedConnectorExecutor(self),
            outcome_recorder=self._outcome_recorder,
        )
        session = runtime.open(
            StandalonePrimitiveRun(
                scope=ExecutionScope(
                    tenant_ref=self._auth.tenant_id,
                    company_ref=(
                        self._active_company_id or self._auth.company_id or "selected"
                    ),
                    project_ref=clean_project_ref,
                    project_id=project_id,
                    actor_ref=self._auth.user_id,
                ),
                run_ref=actual_run_ref,
                mode=(
                    PrimitiveRunMode.PREVIEW if preview_only else PrimitiveRunMode.APPLY
                ),
                approval_refs=dict(approval_refs or {}),
                connector_account_refs=dict(connector_account_refs or {}),
                correlation=PrimitiveCorrelation(source="lightbulb_sdk"),
                idempotency_key=actual_run_ref,
            )
        )
        result = session.execute(
            PrimitiveCall(
                primitive_ref=metadata["primitive_ref"],
                primitive_version=resolved_version,
                inputs=dict(inputs or {}),
            )
        )
        return result.to_dict()

    def build_project_runtime(self, project: Any, *, registry: Any = None) -> Any:
        """Build a runtime using authenticated reads and safe connector previews."""
        from lightbulb.connector_execution import HostedConnectorExecutor
        from lightbulb.executable_primitives import default_primitive_registry
        from lightbulb.project_runtime import LightbulbProject, ProjectRuntime

        project_spec = (
            project
            if isinstance(project, LightbulbProject)
            else LightbulbProject.model_validate(project)
        )
        primitive_registry = registry or default_primitive_registry()
        return ProjectRuntime(
            project_spec,
            primitive_registry,
            HostedConnectorExecutor(self),
            outcome_recorder=self._outcome_recorder,
        )

    def build_durable_project_runtime(
        self,
        project: Any,
        *,
        registry: Any = None,
        checkpoint_store: Any = None,
    ) -> Any:
        """Build a durable runtime, using hosted checkpoints when possible."""
        runtime = self.build_project_runtime(project, registry=registry)
        if checkpoint_store is None and runtime.project.hosted_project_id is not None:
            from lightbulb.durable_runtime import HostedCheckpointStore
            from lightbulb.local_storage import local_scope_fingerprint

            company_id = self._active_company_id or self._auth.company_id
            checkpoint_store = HostedCheckpointStore(
                self,
                runtime.project.hosted_project_id,
                scope_fingerprint=local_scope_fingerprint(
                    self._auth.tenant_id,
                    company_id,
                ),
            )
        elif checkpoint_store is None:
            from lightbulb.durable_runtime import (
                JsonFileCheckpointStore,
                default_checkpoint_dir,
                local_scope_fingerprint,
            )

            company_id = self._active_company_id or self._auth.company_id
            if (
                os.getenv("LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE", "")
                .strip()
                .lower()
                == "sovereign"
                and not company_id
            ):
                raise ValueError(
                    "Sovereign local project runtime requires an authenticated company scope; "
                    "select a company before starting or reading durable workflow state."
                )
            checkpoint_store = JsonFileCheckpointStore(
                default_checkpoint_dir(
                    runtime.project.project_ref,
                    tenant_id=self._auth.tenant_id,
                    company_id=company_id,
                ),
                scope_fingerprint=local_scope_fingerprint(
                    self._auth.tenant_id,
                    company_id,
                ),
            )
        return runtime.durable(checkpoint_store)

    def _company_blueprint_company(self, company_id: str | None) -> str:
        return _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id" if company_id else "active_company_id",
        )

    def preview_reference_company_onboarding(
        self,
        project_id: str,
        blueprint_version_ref: str,
        *,
        connector_selections: Mapping[str, str],
        coding_harness: str | None = None,
        company_id: str | None = None,
    ) -> ReferenceCompanyOnboardingPreview:
        """Validate one exact-scope reference-company setup without activating it."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = reference_company_onboarding_payload(
            blueprint_version_ref=blueprint_version_ref,
            project_id=normalized_project_id,
            connector_selections=connector_selections,
            coding_harness=coding_harness,
        )
        _guard_request_body(
            payload,
            endpoint="company-blueprints/reference-company/onboarding-preview",
        )
        response = self._get_session().post(
            (
                f"{self._base_url}/api/company-blueprints/reference-company/"
                "onboarding-preview"
            ),
            json=payload,
            headers=self._exact_company_headers(
                scoped_company,
                {"X-Project-Id": normalized_project_id},
            ),
        )
        raise_if_error(response)
        return parse_reference_company_onboarding_preview(
            response.json(),
            expected_blueprint_version_ref=payload["blueprint_version_ref"],
            expected_tenant_id=self._auth.tenant_id,
            expected_company_id=scoped_company,
            expected_project_id=payload["project_id"],
        )

    def get_reference_company_onboarding_readiness(
        self,
        project_id: str,
        *,
        company_id: str | None = None,
    ) -> ReferenceCompanyOnboardingReadiness:
        """Discover secret-free Project/Blueprint/connector onboarding choices."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/company-blueprints/reference-company/projects/"
                f"{normalized_project_id}/onboarding-readiness"
            ),
            headers=self._exact_company_headers(
                scoped_company,
                {"X-Project-Id": normalized_project_id},
            ),
        )
        raise_if_error(response)
        return parse_reference_company_onboarding_readiness(
            response.json(),
            expected_tenant_id=self._auth.tenant_id,
            expected_company_id=scoped_company,
            expected_project_id=normalized_project_id,
        )

    def propose_company_blueprint_certification(
        self,
        project_id: str,
        candidate: CompanyBlueprintCertificationCandidate | Mapping[str, Any],
        *,
        evidence_target_id: str,
        idempotency_key: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        """Offer exact Blueprint evidence to Spring for independent review."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = company_blueprint_certification_payload(
            candidate,
            evidence_target_id=evidence_target_id,
            idempotency_key=idempotency_key,
        )
        _guard_request_body(payload, endpoint="company-blueprints/certifications")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates"
            ),
            json=payload,
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    def prepare_company_blueprint_native_proof(
        self,
        project_id: str,
        blueprint_version_id: str,
        golden_loop_certification_record_ids: Sequence[str],
        rollback_shadow_intent_id: str,
        *,
        company_id: str | None = None,
    ) -> dict[str, Any]:
        """Ask Spring to derive the exact no-effect Blueprint proof set."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = {
            "blueprint_version_id": _validate_marketplace_uuid(
                blueprint_version_id, "blueprint_version_id"
            ),
            "golden_loop_certification_record_ids": [
                _validate_marketplace_uuid(value, "golden_loop_certification_record_id")
                for value in golden_loop_certification_record_ids
            ],
            "rollback_shadow_intent_id": _validate_marketplace_uuid(
                rollback_shadow_intent_id, "rollback_shadow_intent_id"
            ),
        }
        if not payload["golden_loop_certification_record_ids"]:
            raise ValueError("golden_loop_certification_record_ids must not be empty")
        _guard_request_body(payload, endpoint="company-blueprints/certifications/native-proof")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/native-proof"
            ),
            json=payload,
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Company Blueprint native-proof response must be an object")
        return result

    def finalize_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        return self._company_blueprint_certification_action(
            project_id, candidate_id, action="finalize", company_id=company_id
        )

    def cancel_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        return self._company_blueprint_certification_action(
            project_id, candidate_id, action="cancel", company_id=company_id
        )

    def _company_blueprint_certification_action(
        self,
        project_id: str,
        candidate_id: str,
        *,
        action: str,
        company_id: str | None,
    ) -> CompanyBlueprintCertificationStatus:
        if action not in {"finalize", "cancel"}:
            raise ValueError("unsupported Company Blueprint certification action")
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        response = self._get_session().post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates/"
                f"{normalized_candidate_id}/{action}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    def get_company_blueprint_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        response = self._get_session().get(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates/"
                f"{normalized_candidate_id}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    def propose_company_blueprint_deployment(
        self, project_id: str,
        candidate: CompanyBlueprintDeploymentCandidate | Mapping[str, Any], *,
        idempotency_key: str, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        payload = company_blueprint_deployment_payload(candidate, idempotency_key=idempotency_key)
        _guard_request_body(payload, endpoint="company-blueprints/deployments")
        response = self._get_session().post(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments",
            json=payload, headers=self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    def transition_company_blueprint_deployment(
        self, project_id: str, deployment_id: str, *, action: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        if action not in {
            "finalize-deployment", "finalize-activation", "cancel",
            "request-rollback", "finalize-rollback",
        }:
            raise ValueError("unsupported Company Blueprint deployment action")
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        deployment = _validate_marketplace_uuid(deployment_id, "deployment_id")
        response = self._get_session().post(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments/{deployment}/{action}",
            headers=self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    def get_company_blueprint_deployment(
        self, project_id: str, deployment_id: str, *, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        deployment = _validate_marketplace_uuid(deployment_id, "deployment_id")
        response = self._get_session().get(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments/{deployment}",
            headers=self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    def get_company_blueprint_deployment_head(
        self, project_id: str, *, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentHead | None:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployment-head",
            headers=self._exact_company_headers(scoped_company))
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_company_blueprint_deployment_head(response.json())

    def get_current_company_blueprint_certification(
        self,
        project_id: str,
        *,
        blueprint_version_id: str,
        environment_ref: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationSpringRecord | None:
        """Resolve the current exact Blueprint certificate using Spring's clock."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_version_id = _validate_marketplace_uuid(
            blueprint_version_id, "blueprint_version_id"
        )
        response = self._get_session().get(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/current"
            ),
            params={
                "blueprint_version_id": normalized_version_id,
                "environment_ref": str(environment_ref or "").strip(),
            },
            headers=self._exact_company_headers(scoped_company),
        )
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_company_blueprint_certification_record(response.json())

    def register_executed_commercial_agreement(
        self,
        project_id: str,
        candidate: ExecutedCommercialAgreementCustodyCandidate | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        """Seal completed-envelope and signed-document READs into Spring custody."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = ExecutedCommercialAgreementCustodyCandidate.model_validate(
            candidate
        ).to_payload()
        _guard_request_body(payload, endpoint="commercial-agreements/executed/records")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "commercial-agreements/executed/records"
            ),
            json=payload,
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    def get_executed_commercial_agreement(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"commercial-agreements/executed/records/{normalized_record_id}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    def resolve_executed_commercial_agreement(
        self,
        project_id: str,
        agreement_ref: str,
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_ref = str(agreement_ref or "").strip()
        if re.fullmatch(r"agreement:docusign:[0-9a-f]{32}", clean_ref) is None:
            raise ValueError("agreement_ref is invalid")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "commercial-agreements/executed/records/resolve"
            ),
            params={"agreement_ref": clean_ref},
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    def register_golden_loop_catalog(
        self,
        project_id: str,
        request: GoldenLoopCatalogRegistrationRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCatalogVersion:
        """Register or replay one immutable, QUARANTINED catalog version."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = GoldenLoopCatalogRegistrationRequest.model_validate(request).to_payload()
        _guard_request_body(payload, endpoint="golden-loop-catalogs")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-catalogs"
            ),
            json=payload,
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_catalog_version(response.json())

    def get_golden_loop_catalog_version(
        self,
        project_id: str,
        catalog_version_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCatalogVersion:
        """Read one exact immutable catalog version and its declaration IDs."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_catalog_id = _validate_marketplace_uuid(
            catalog_version_id, "catalog_version_id"
        )
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"golden-loop-catalogs/{normalized_catalog_id}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_catalog_version(response.json())

    def get_golden_loop_declaration_version(
        self,
        project_id: str,
        catalog_version_id: str,
        declaration_version_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopDeclarationVersion:
        """Read one exact declaration through its containing catalog version."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_catalog_id = _validate_marketplace_uuid(
            catalog_version_id, "catalog_version_id"
        )
        normalized_declaration_id = _validate_marketplace_uuid(
            declaration_version_id, "declaration_version_id"
        )
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"golden-loop-catalogs/{normalized_catalog_id}/declarations/"
                f"{normalized_declaration_id}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_declaration_version(response.json())

    def propose_golden_loop_certification(
        self,
        project_id: str,
        request: GoldenLoopCertificationProposalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationCandidateStatus:
        """Submit one exact evidence-sealed candidate for independent review."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = GoldenLoopCertificationProposalRequest.model_validate(request)
        payload = parsed.to_payload()
        _guard_request_body(payload, endpoint="golden-loop-certifications/candidates")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/candidates"
            ),
            json=payload,
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_certification_candidate_status(response.json())

    def get_golden_loop_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationCandidateStatus:
        """Read one exact certification candidate without raw retained evidence."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/candidates/"
                f"{normalized_candidate_id}"
            ),
            headers=self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_certification_candidate_status(response.json())

    def get_current_golden_loop_certification(
        self,
        project_id: str,
        *,
        loop_ref: str,
        loop_version: str,
        environment_ref: str,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationSpringRecord | None:
        """Read the current exact-scope certificate, or ``None`` after expiry."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/current"
            ),
            params={
                "loop_ref": str(loop_ref or "").strip(),
                "loop_version": str(loop_version or "").strip(),
                "environment_ref": str(environment_ref or "").strip(),
            },
            headers=self._exact_company_headers(scoped_company),
        )
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_golden_loop_certification_spring_record(response.json())

    def get_golden_loop_economic_closure(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopEconomicClosureProjection:
        """Read Spring's canonical, non-mutating whole-run cost closure."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = canonical_golden_loop_run_ref(run_ref)
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/golden-loop-runs/"
                f"{clean_run_ref}/economic-closure"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_golden_loop_economic_closure(response.json())

    def propose_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceProposalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceProposalReceipt:
        """Create or replay one exact Spring-owned invoice approval proposal."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceProposalRequest)
            else ContractToCashInvoiceProposalRequest.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="finance/contract-to-cash/invoice/proposals")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/finance/"
                "contract-to-cash/invoice/proposals"
            ),
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceProposalReceipt.model_validate(response.json())

    def execute_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceExecutionRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceWriteReceipt:
        """Consume an exact approval without treating provider acceptance as issuance."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceExecutionRequest)
            else ContractToCashInvoiceExecutionRequest.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="finance/contract-to-cash/invoice/executions")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/finance/"
                "contract-to-cash/invoice/executions"
            ),
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceWriteReceipt.model_validate(response.json())

    def register_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        request: ContractToCashInvoiceIssuedRegistration | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceIssuedRecord:
        """Seal one exact reconciled invoice write/readback pair into Spring custody."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceIssuedRegistration)
            else ContractToCashInvoiceIssuedRegistration.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="contract-to-cash/invoices/issued/records")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "contract-to-cash/invoices/issued/records"
            ),
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceIssuedRecord.model_validate(response.json())

    def get_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceIssuedRecord:
        """Read one exact provider-observed invoice issuance custody record."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"contract-to-cash/invoices/issued/records/{normalized_record_id}"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceIssuedRecord.model_validate(response.json())

    def register_contract_to_cash_cash_collection(
        self,
        project_id: str,
        request: ContractToCashCashCollectionRegistration | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashCashCollectionRecord:
        """Seal independent accounting and payout evidence as collected cash."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashCashCollectionRegistration)
            else ContractToCashCashCollectionRegistration.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="contract-to-cash/cash-collections/records")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/cash-collections/records",
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashCashCollectionRecord.model_validate(response.json())

    def get_contract_to_cash_cash_collection(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ContractToCashCashCollectionRecord:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/cash-collections/records/{normalized_record_id}",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashCashCollectionRecord.model_validate(response.json())

    def start_contract_to_cash_run(
        self,
        project_id: str,
        request: ContractToCashRunStart | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        """Start the Spring-owned Golden Loop from executed-agreement custody."""
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, ContractToCashRunStart) else (
            ContractToCashRunStart.model_validate(request)
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs",
            json=parsed.to_dict(),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    def get_contract_to_cash_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> ContractToCashRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    def attach_contract_to_cash_invoice_issued(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunRecordBinding | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunRecordBinding) else (
            ContractToCashRunRecordBinding.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/invoice-issued",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    def attach_contract_to_cash_cash_collected(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunRecordBinding | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunRecordBinding) else (
            ContractToCashRunRecordBinding.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/cash-collected",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    def cancel_contract_to_cash_before_invoice(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunCancellation | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunCancellation) else (
            ContractToCashRunCancellation.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/cancel",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    def retain_period_reconciliation_scope(
        self,
        project_id: str,
        request: PeriodReconciliationScopeRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationScopeReceipt:
        parsed = request if isinstance(request, PeriodReconciliationScopeRequest) else (
            PeriodReconciliationScopeRequest.model_validate(request)
        )
        value = self._post_period_reconciliation(
            project_id, "scopes", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationScopeReceipt.model_validate(value)

    def start_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationStartRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationStartRequest) else (
            PeriodReconciliationStartRequest.model_validate(request)
        )
        value = self._post_period_reconciliation(
            project_id, "runs", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    def restart_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationRestartRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationRestartRequest) else (
            PeriodReconciliationRestartRequest.model_validate(request)
        )
        value = self._post_period_reconciliation(
            project_id, "runs/restarts", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    def retain_period_reconciliation_quickbooks_reads(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationQuickBooksReadSetRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationReadSetReceipt:
        parsed = (
            request
            if isinstance(request, PeriodReconciliationQuickBooksReadSetRequest)
            else PeriodReconciliationQuickBooksReadSetRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._post_period_reconciliation(
            project_id,
            f"runs/{run}/quickbooks-read-sets",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationReadSetReceipt.model_validate(value)

    def evaluate_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationEvaluationRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationEvaluationReceipt:
        parsed = (
            request
            if isinstance(request, PeriodReconciliationEvaluationRequest)
            else PeriodReconciliationEvaluationRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._post_period_reconciliation(
            project_id,
            f"runs/{run}/evaluations",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationEvaluationReceipt.model_validate(value)

    def retain_period_reconciliation_review(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationReviewRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationReviewReceipt:
        parsed = request if isinstance(request, PeriodReconciliationReviewRequest) else (
            PeriodReconciliationReviewRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._post_period_reconciliation(
            project_id,
            f"runs/{run}/reviews",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationReviewReceipt.model_validate(value)

    def advance_period_reconciliation_stage(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationStageRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationStageRequest) else (
            PeriodReconciliationStageRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._post_period_reconciliation(
            project_id,
            f"runs/{run}/stages",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    def get_period_reconciliation_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> PeriodReconciliationRun:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._get_period_reconciliation(
            project_id, f"runs/{run}", company_id=company_id
        )
        return PeriodReconciliationRun.model_validate(value)

    def get_period_reconciliation_outcomes(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> tuple[PeriodReconciliationOutcomeFact, ...]:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._get_period_reconciliation(
            project_id, f"runs/{run}/outcomes", company_id=company_id
        )
        return parse_period_reconciliation_outcomes(value)

    def get_period_reconciliation_campaign_facts(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> tuple[PeriodReconciliationCampaignFact, ...]:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._get_period_reconciliation(
            project_id, f"runs/{run}/campaign-facts", company_id=company_id
        )
        return parse_period_reconciliation_campaign_facts(value)

    def fail_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        return self._terminal_period_reconciliation_run(
            project_id, run_ref, "fail", request, company_id=company_id
        )

    def cancel_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        return self._terminal_period_reconciliation_run(
            project_id, run_ref, "cancel", request, company_id=company_id
        )

    def _terminal_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        action: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None,
    ) -> PeriodReconciliationRunReceipt:
        if action not in {"fail", "cancel"}:
            raise ValueError("Unreviewed Period Reconciliation terminal command")
        parsed = request if isinstance(request, PeriodReconciliationTerminalRequest) else (
            PeriodReconciliationTerminalRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = self._post_period_reconciliation(
            project_id,
            f"runs/{run}/{action}",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    def _post_period_reconciliation(
        self,
        project_id: str,
        suffix: str,
        payload: Mapping[str, Any],
        *,
        company_id: str | None,
    ) -> Any:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="finance/period-reconciliation")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}"
            f"/finance/period-reconciliation/{suffix}",
            json=dict(payload),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    def _get_period_reconciliation(
        self,
        project_id: str,
        suffix: str,
        *,
        company_id: str | None,
    ) -> Any:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}"
            f"/finance/period-reconciliation/{suffix}",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    def start_economic_spine_run(
        self,
        project_id: str,
        request: EconomicSpineRunStart | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        """Start Spring's exact procurement, period-close, or improvement custody."""
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunStart) else (
            EconomicSpineRunStart.model_validate(request)
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    def get_economic_spine_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> EconomicSpineRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    def advance_economic_spine_run(
        self,
        project_id: str,
        run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunTransition) else (
            EconomicSpineRunTransition.model_validate(request)
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}/transitions",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    def fail_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return self._command_economic_spine_run(
            project_id, run_ref, "fail", request, company_id=company_id
        )

    def cancel_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return self._command_economic_spine_run(
            project_id, run_ref, "cancel", request, company_id=company_id
        )

    def mark_economic_spine_effect_ambiguous(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return self._command_economic_spine_run(
            project_id, run_ref, "effect-ambiguous", request, company_id=company_id
        )

    def reconcile_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return self._command_economic_spine_run(
            project_id, run_ref, "reconcile", request, company_id=company_id
        )

    def _command_economic_spine_run(
        self, project_id: str, run_ref: str, action: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None,
    ) -> EconomicSpineRun:
        if action not in {"fail", "cancel", "effect-ambiguous", "reconcile"}:
            raise ValueError("Unreviewed Economic Spine command")
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunTransition) else (
            EconomicSpineRunTransition.model_validate(request)
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}/{action}",
            json=parsed.to_dict(), headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    def get_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        """Read one exact Spring-owned ``scr_`` run."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    def advance_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        """Ask Spring to consume at most one server-owned Service phase."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}/advance"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    def cancel_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        reason: str,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        """Cancel an undecided Service run through its canonical ApprovalTask."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        payload = ServiceCaseResolutionCancel(reason=reason).to_dict()
        _guard_request_body(payload, endpoint="service/case-resolution-runs/cancel")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}/cancel"
            ),
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    def list_governed_communication_sources(
        self,
        project_id: str,
        *,
        limit: int = 20,
        cursor: str | None = None,
        company_id: str | None = None,
    ) -> GovernedCommunicationSourcePage:
        """List a bounded page of opaque, currently admissible Gmail sources."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 50
        ):
            raise ValueError("limit must be an integer between 1 and 50")
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            clean_cursor = str(cursor or "").strip()
            if re.fullmatch(r"gcs_v1_[a-f0-9]{64}", clean_cursor) is None:
                raise ValueError("cursor must be a canonical gcs_v1 reference")
            params["cursor"] = clean_cursor
        response = self._get_session().get(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                "governed-communication-runs/sources"
            ),
            params=params,
            headers=self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_sources(response.json())

    def get_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GovernedCommunicationRun:
        """Read one exact public ``gcr_`` run projection."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"gcr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical gcr_ reference")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                f"governed-communication-runs/{clean_run_ref}"
            ),
            headers=self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_run(response.json())

    def cancel_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GovernedCommunicationRun:
        """Fence a cancellable communication run; execution remains worker-owned."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"gcr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical gcr_ reference")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                f"governed-communication-runs/{clean_run_ref}/actions/cancel"
            ),
            headers=self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_run(response.json())

    def get_project_work_packet_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ProjectWorkPacketRunRead:
        """Read one owned Project work-packet run without harness custody."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"dwr_[A-Za-z0-9_-]{16,64}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical dwr_ reference")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"work-packet-runs/{clean_run_ref}"
            ),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_project_work_packet_run(response.json())


    def start_service_case_resolution(
        self,
        project_id: str,
        request: ServiceCaseResolutionStart | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        """Admit one digest-bound candidate to Spring's Service authority."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ServiceCaseResolutionStart)
            else ServiceCaseResolutionStart.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="service/case-resolution-runs")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                "case-resolution-runs"
            ),
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    def start_governed_communication_run(
        self,
        project_id: str,
        request: GovernedCommunicationAdmission | Mapping[str, Any],
        *,
        idempotency_key: str,
        company_id: str | None = None,
    ) -> GovernedCommunicationAdmissionResult:
        """Admit one pre-approved CRM turn; this never dispatches communication."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_key = str(idempotency_key or "").strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}", clean_key) is None:
            raise ValueError(
                "idempotency_key must match the 1-100 character communication contract"
            )
        parsed = (
            request
            if isinstance(request, GovernedCommunicationAdmission)
            else GovernedCommunicationAdmission.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="governed-communication-runs")
        response = self._get_session().post(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                "governed-communication-runs"
            ),
            json=payload,
            headers=self._exact_company_headers(
                normalized_company_id,
                {"Idempotency-Key": clean_key},
            ),
        )
        raise_if_error(response)
        return parse_governed_communication_admission(response.json())

    def step_governed_sales_touch(
        self, project_id: str, request: Mapping[str, Any], *,
        idempotency_key: str, company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Prepare or reconcile one exact sales touch through Communication authority."""
        from lightbulb.company_sales_communication import _sales_proposal, _sales_result

        project = _validate_marketplace_uuid(project_id, "project_id")
        company = _validate_marketplace_uuid(company_id or self._active_company_id, "company_id")
        tenant = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        payload = _sales_proposal(request, idempotency_key)
        _guard_request_body(payload, endpoint="governed-communication-runs/sales-touches")
        response = self._get_session().post(
            f"{self._base_url}/api/tenants/{tenant}/companies/{company}/projects/{project}/governed-communication-runs/sales-touches",
            json=payload, headers=self._exact_company_headers(company, {"Idempotency-Key": idempotency_key}),
        )
        raise_if_error(response)
        return _sales_result(response.json(), payload["touch"]["request_digest"])

    def start_project_work_packet(
        self,
        project_id: str,
        *,
        company_id: str | None = None,
    ) -> ProjectWorkPacketStartResult:
        """Propose or start Spring's exact approved Project work packet."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/work-packet-runs",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_project_work_packet_start(response.json())

    def _post_dynamic_workflow(
        self,
        operation: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Call the dedicated hosted workflow authority with the canonical contract."""
        from lightbulb.dynamic_workflow_mcp import (
            get_operation,
            validate_operation_input,
        )

        descriptor = get_operation(operation)
        endpoint = _DYNAMIC_WORKFLOW_ENDPOINTS.get(descriptor.operation)
        if endpoint is None:
            raise ValueError(
                f"Unsupported hosted dynamic workflow operation: {operation}"
            )
        validated_input = validate_operation_input(descriptor.operation, payload)
        _guard_request_body(
            validated_input,
            endpoint=f"dynamic-workflows/{endpoint}",
        )
        response = self._get_session().post(
            f"{self._base_url}/api/dynamic-workflows/{endpoint}",
            json=validated_input,
            # Public company/project refs are resolved by the authority. A mutable
            # SDK company selection must not override that exact request scope.
            headers=self._tenant_headers(),
        )
        raise_if_error(response)
        return _validated_dynamic_workflow_response(
            descriptor.operation,
            validated_input,
            response,
        )

    def dynamic_workflow_start(
        self,
        *,
        company_ref: str,
        project_ref: str,
        objective: str,
        acceptance_criteria: Sequence[Mapping[str, Any]],
        host: str,
        expected_revision: int,
        idempotency_key: str,
        host_session_ref: str | None = None,
        acceptance_policy: str = "distinct_binding",
        workflow_spec: Mapping[str, Any] | None = None,
        inputs: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Start an authoritative planner/builder/evaluator workflow."""
        payload: Dict[str, Any] = {
            "company_ref": company_ref,
            "project_ref": project_ref,
            "objective": objective,
            "acceptance_criteria": list(acceptance_criteria),
            "host": host,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
            "acceptance_policy": acceptance_policy,
        }
        if host_session_ref is not None:
            payload["host_session_ref"] = host_session_ref
        if workflow_spec is not None:
            payload["workflow_spec"] = dict(workflow_spec)
        if inputs is not None:
            payload["inputs"] = dict(inputs)
        return self._post_dynamic_workflow("start", payload)

    def dynamic_workflow_attach(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host: str,
        host_session_ref: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Attach fresh role custody to an existing authoritative run."""
        return self._post_dynamic_workflow(
            "attach",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host": host,
                "host_session_ref": host_session_ref,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
            },
        )

    def dynamic_workflow_status(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
    ) -> Dict[str, Any]:
        """Read bounded status using a role-bound continuation receipt."""
        return self._post_dynamic_workflow(
            "status",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
            },
        )

    def dynamic_workflow_next_assignment(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Lease the next assignment from the dedicated workflow authority."""
        return self._post_dynamic_workflow(
            "next_assignment",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
            },
        )

    def dynamic_workflow_submit_plan(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        required_criterion_ids: Sequence[str],
        plan: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Submit a planner result under its exact assignment lease."""
        return self._post_dynamic_workflow(
            "submit_plan",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "required_criterion_ids": list(required_criterion_ids),
                "plan": dict(plan),
            },
        )

    def dynamic_workflow_submit_builder_result(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        outcome: str,
        summary: str,
        plan_digest: str,
        iteration: int,
        evidence_refs: Sequence[Mapping[str, Any]],
        progress_digest: str,
    ) -> Dict[str, Any]:
        """Submit content-addressed builder evidence under its assignment lease."""
        return self._post_dynamic_workflow(
            "submit_builder_result",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "outcome": outcome,
                "summary": summary,
                "plan_digest": plan_digest,
                "iteration": iteration,
                "evidence_refs": list(evidence_refs),
                "progress_digest": progress_digest,
            },
        )

    def dynamic_workflow_submit_evaluator_verdict(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        decision: str,
        accepted: bool,
        summary: str,
        plan_digest: str,
        builder_result_digest: str,
        required_criterion_ids: Sequence[str],
        criterion_results: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Submit a default-fail evaluator verdict under fresh role custody."""
        return self._post_dynamic_workflow(
            "submit_evaluator_verdict",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "decision": decision,
                "accepted": accepted,
                "summary": summary,
                "plan_digest": plan_digest,
                "builder_result_digest": builder_result_digest,
                "required_criterion_ids": list(required_criterion_ids),
                "criterion_results": list(criterion_results),
            },
        )

    def dynamic_workflow_cancel(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Cancel a non-terminal workflow using exact optimistic concurrency."""
        return self._post_dynamic_workflow(
            "cancel",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "reason": reason,
            },
        )

    def build_dynamic_workflow_runtime(
        self,
        *,
        project_ref: str,
        hosted_project_id: str | None = None,
        hosted_company_id: str | None = None,
        checkpoint_store: Any = None,
    ) -> Any:
        """Build the local planner/builder/evaluator state-machine runtime.

        Local harnesses use revisioned JSON state. Hosted dynamic workflows
        require the dedicated server command/query authority; the generic SDK
        project-checkpoint endpoint accepts caller-authored JSON and therefore
        must never be presented as authoritative workflow control.
        """
        from lightbulb.dynamic_workflow_runtime import (
            DynamicWorkflowRuntime,
            JsonDynamicWorkflowCheckpointStore,
            default_dynamic_workflow_dir,
        )
        from lightbulb.local_storage import local_scope_fingerprint

        clean_project_ref = _validate_id(project_ref, "project_ref").lower()
        if checkpoint_store is None and hosted_project_id:
            _validate_id(hosted_project_id, "hosted_project_id")
            if hosted_company_id is not None:
                _validate_marketplace_uuid(hosted_company_id, "hosted_company_id")
            raise RuntimeError(
                "hosted dynamic workflows require the authoritative dynamic-workflow "
                "command adapter; generic SDK checkpoints are not a control plane"
            )
        elif checkpoint_store is None:
            company_id = self._active_company_id or self._auth.company_id
            if (
                os.getenv("LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE", "")
                .strip()
                .lower()
                == "sovereign"
                and not company_id
            ):
                raise ValueError(
                    "Sovereign local dynamic workflow runtime requires an authenticated "
                    "company scope; select a company before using durable workflow state."
                )
            checkpoint_store = JsonDynamicWorkflowCheckpointStore(
                default_dynamic_workflow_dir(
                    clean_project_ref,
                    tenant_id=self._auth.tenant_id,
                    company_id=company_id,
                ),
                scope_fingerprint=local_scope_fingerprint(
                    self._auth.tenant_id,
                    company_id,
                ),
            )
        return DynamicWorkflowRuntime(checkpoint_store)

    def save_assessment_workspace(
        self, workspace: Any, *, run_ref: str, expected_revision: int,
    ) -> Dict[str, Any]:
        """Persist a draft assessment through the scoped, revision-checked project store."""
        from lightbulb.assessment_workspace import AssessmentWorkspace, AssessmentWorkspaceStore

        parsed = AssessmentWorkspace.model_validate(workspace)
        store = AssessmentWorkspaceStore(
            self, scope=parsed.dossier.inputs.scope, requested_by_ref=self._auth.user_id,
        )
        return store.save(parsed, run_ref=run_ref, expected_revision=expected_revision).to_dict()

    def get_assessment_workspace(self, project_id: str, run_ref: str) -> Dict[str, Any] | None:
        """Load one saved assessment in the selected company; validate its exact seals."""
        from lightbulb.assessment_workspace import AssessmentWorkspaceStore

        store = AssessmentWorkspaceStore.for_project(
            self, project_id=project_id, requested_by_ref=self._auth.user_id,
        )
        record = store.load(run_ref)
        return record.to_dict() if record is not None else None

    def recover_assessment_workspace(
        self, workspace: Any, *, run_ref: str, expected_revision: int,
    ) -> Dict[str, Any] | None:
        """Read back an uncertain save; never retry or overwrite the checkpoint."""
        from lightbulb.assessment_workspace import AssessmentWorkspace, AssessmentWorkspaceStore

        parsed = AssessmentWorkspace.model_validate(workspace)
        store = AssessmentWorkspaceStore(
            self, scope=parsed.dossier.inputs.scope, requested_by_ref=self._auth.user_id,
        )
        record = store.recover(parsed, run_ref=run_ref, expected_revision=expected_revision)
        return record.to_dict() if record is not None else None

    def put_sdk_project_checkpoint(
        self,
        project_id: str,
        run_ref: str,
        checkpoint: Dict[str, Any],
        *,
        expected_revision: int | None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        payload = {
            "expectedRevision": expected_revision,
            "checkpoint": checkpoint,
        }
        _guard_request_body(payload, endpoint="sdk-project-runtime/checkpoints")
        response = self._get_session().put(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/checkpoints/{_validate_runtime_run_ref(run_ref)}",
            json=payload,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    def list_customer_webhook_hints(self, project_id: str, *, connector_account_ref: str,
                                    start: str, end: str, cursor: dict | None = None,
                                    company_id: str | None = None) -> Dict[str, Any]:
        """Read scoped durable webhook wake hints; these do not authorize payment or effects."""
        from lightbulb.company_engine_core import timestamp
        from uuid import UUID
        params = {"connectorAccountRef": connector_account_ref,
                  "start": timestamp(start, field_name="start"), "end": timestamp(end, field_name="end")}
        if cursor is not None:
            if set(cursor) != {"after_at", "after_id"}:
                raise ValueError("CUSTOMER_WEBHOOK_CURSOR_INVALID")
            params.update(afterAt=timestamp(cursor["after_at"], field_name="after_at"),
                          afterId=str(UUID(cursor["after_id"])))
        response = self._get_session().get(
            f"{self._base_url}/api/sdk-engine/projects/{_validate_id(project_id, 'project_id')}/customer-events/webhook-hints",
            headers=self._exact_company_headers(company_id), params=params)
        raise_if_error(response)
        return response.json()

    def submit_customer_referral_event(self, project_id: str, event: dict, *, company_id: str | None = None) -> Dict[str, Any]:
        """Record an authenticated application referral claim, never payment evidence."""
        response = self._get_session().post(
            f"{self._base_url}/api/sdk-engine/projects/{_validate_id(project_id, 'project_id')}/customer-events/referrals",
            headers=self._exact_company_headers(company_id), json=event)
        raise_if_error(response)
        return response.json()

    def get_customer_referral_event(self, project_id: str, event_id: str, *, company_id: str | None = None) -> Dict[str, Any]:
        """Read a referral intake record for the authenticated company, actor and project."""
        response = self._get_session().get(
            f"{self._base_url}/api/sdk-engine/projects/{_validate_id(project_id, 'project_id')}/customer-events/referrals/{_validate_id(event_id, 'event_id')}",
            headers=self._exact_company_headers(company_id))
        raise_if_error(response)
        return response.json()

    def list_customer_inbound_events(self, project_id: str, *, start: str, end: str,
                                     cursor: dict | None = None, company_id: str | None = None) -> Dict[str, Any]:
        """Read accepted inquiries in an exact company, actor, project and time window."""
        from lightbulb.company_engine_core import timestamp
        from uuid import UUID
        params={"start":timestamp(start,field_name="start"),"end":timestamp(end,field_name="end")}
        if cursor is not None:
            if set(cursor)!={"after_at","after_id"}:raise ValueError("CUSTOMER_CRM_CURSOR_INVALID")
            params.update(afterAt=timestamp(cursor["after_at"],field_name="after_at"),afterId=str(UUID(cursor["after_id"])))
        response=self._get_session().get(
            f"{self._base_url}/api/sdk-engine/projects/{_validate_id(project_id,'project_id')}/customer-events/inbound",
            headers=self._exact_company_headers(company_id),params=params)
        raise_if_error(response)
        return response.json()

    def get_sdk_project_checkpoint(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any] | None:
        response = self._get_session().get(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/checkpoints/{_validate_runtime_run_ref(run_ref)}",
            headers=self._exact_company_headers(company_id),
        )
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return response.json()

    def list_ready_sdk_project_checkpoints(
        self,
        project_id: str,
        *,
        ready_at: str,
        limit: int = 100,
        company_id: str | None = None,
        run_ref: str | None = None,
    ) -> List[Dict[str, Any]]:
        response = self._get_session().get(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/checkpoints/ready",
            params={"readyAt": ready_at, "limit": max(1, min(int(limit), 1000)),
                    **({"runRef": _validate_runtime_run_ref(run_ref)} if run_ref is not None else {})},
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        value = response.json()
        return value if isinstance(value, list) else value.get("items", [])

    def claim_sdk_project_checkpoint(
        self,
        project_id: str,
        *,
        worker_ref: str,
        ready_at: str,
        lease_seconds: int = 60,
        company_id: str | None = None,
        run_ref: str | None = None,
    ) -> Dict[str, Any] | None:
        response = self._get_session().post(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/checkpoints/claim",
            json={
                **({"runRef": _validate_runtime_run_ref(run_ref)} if run_ref is not None else {}),
                "workerRef": str(worker_ref).strip(),
                "readyAt": ready_at,
                "leaseSeconds": max(1, min(int(lease_seconds), 3600)),
            },
            headers=self._exact_company_headers(company_id),
        )
        if response.status_code == 204:
            return None
        raise_if_error(response)
        return response.json()

    def renew_sdk_project_checkpoint_lease(
        self,
        project_id: str,
        run_ref: str,
        *,
        worker_ref: str,
        expected_revision: int,
        lease_seconds: int = 60,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        response = self._get_session().post(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/checkpoints/{_validate_runtime_run_ref(run_ref)}/lease",
            json={
                "workerRef": str(worker_ref).strip(),
                "expectedRevision": int(expected_revision),
                "leaseSeconds": max(1, min(int(lease_seconds), 3600)),
            },
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    def ingest_sdk_project_event(
        self,
        project_id: str,
        event: Dict[str, Any],
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        response = self._get_session().post(
            f"{self._base_url}/api/sdk-project-runtime/projects/{_validate_id(project_id, 'project_id')}/events",
            json=event,
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    def validate_sdk_project(
        self, project: Any, *, registry: Any = None
    ) -> Dict[str, Any]:
        """Validate a custom project against executable primitive implementations."""
        return (
            self.build_project_runtime(project, registry=registry).validate().to_dict()
        )

    def run_sdk_project_workflow(
        self,
        project: Any,
        workflow_key: str,
        inputs: Dict[str, Any] | None = None,
        *,
        preview_only: bool | None = None,
        approval_refs: Dict[str, str] | None = None,
        connector_account_refs: Dict[str, str] | None = None,
        run_ref: str | None = None,
        registry: Any = None,
    ) -> Dict[str, Any]:
        """Run a project workflow; hosted connector writes remain fail-closed."""
        runtime = self.build_project_runtime(project, registry=registry)
        result = runtime.run_workflow(
            workflow_key,
            dict(inputs or {}),
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
        )
        return result.to_dict()

    def list_business_primitives(
        self,
        *,
        category: str | None = None,
        query: str | None = None,
        include_inputs: bool = True,
    ) -> List[Dict[str, Any]]:
        """List the SDK/MCP canonical primitive manifest entries."""
        from lightbulb.primitive_capability_manifest import primitive_manifest_catalog

        catalog = primitive_manifest_catalog(
            category=category,
            query=query,
            include_schemas=include_inputs,
            limit=500,
        )
        return catalog["implementations"]

    def run_business_primitive(
        self,
        primitive_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        primitive_version: str | None = None,
        project_ref: str | None = None,
        project_id: str | None = None,
        approval_refs: Dict[str, str] | None = None,
        connector_account_refs: Dict[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
        source: str = "sdk",
        mode: str | None = None,
        preview_only: bool = True,
        request: str = "",
    ) -> Dict[str, Any]:
        """Run the same canonical Executable Primitive contract as MCP.

        ``source``, ``mode``, and ``request`` remain accepted for source
        compatibility but cannot alter the primitive input or execution path.
        Missing Project scope and unknown refs fail closed without a network
        call. Spring remains the sole connector-write authority.
        """
        del source, mode, request
        from lightbulb.primitive_capability_manifest import (
            primitive_capability_metadata,
        )

        metadata = primitive_capability_metadata(primitive_id)
        if metadata is None:
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "unknown_primitive",
                "primitive_ref": primitive_id,
                "message": "Unknown primitive refs fail closed.",
            }
        requested_version = str(primitive_version or "").strip()
        if requested_version and primitive_capability_metadata(
            primitive_id,
            primitive_version=requested_version,
        ) is None:
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "primitive_version_mismatch",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "requested_primitive_version": requested_version,
                "message": (
                    "The requested primitive version is not the canonical manifest version."
                ),
            }
        if not str(project_ref or "").strip():
            return {
                "schema": "lightbulb.primitive_execution_admission.v1",
                "status": "blocked",
                "terminal_state": "blocked",
                "error_code": "project_scope_required",
                "primitive_ref": metadata["primitive_ref"],
                "primitive_version": metadata["version"],
                "effect_class": metadata["effect_class"],
                "approval_required": metadata["approval"]["required"],
                "message": (
                    "Canonical primitive execution requires an exact Project ref."
                ),
            }
        return self.run_sdk_business_primitive(
            primitive_id,
            inputs,
            primitive_version=requested_version or str(metadata["version"]),
            project_ref=project_ref,
            project_id=project_id,
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
            idempotency_key=idempotency_key,
        )

    def compose_business_workflow(
        self,
        objective: str,
        *,
        primitive_ids: List[str] | None = None,
        inputs: Dict[str, Any] | None = None,
        loop: bool = False,
        max_iterations: int | None = None,
        workflow_name: str | None = None,
        workflow_type: str | None = None,
        trigger_event: str | None = None,
        owner_role: str = "workflow_owner",
        publish: bool = False,
        source: str = "sdk",
    ) -> Dict[str, Any]:
        """Draft an Agent Builder workflow from business primitive blocks."""
        from lightbulb.business_primitives import compose_business_workflow

        return compose_business_workflow(
            self,
            objective,
            primitive_ids=primitive_ids,
            inputs=inputs,
            loop=loop,
            max_iterations=max_iterations,
            workflow_name=workflow_name,
            workflow_type=workflow_type,
            trigger_event=trigger_event,
            owner_role=owner_role,
            publish=publish,
            source=source,
        )

    def compile_business_workflow(
        self,
        objective: str,
        *,
        primitive_ids: List[str] | None = None,
        inputs: Dict[str, Any] | None = None,
        workflow_name: str | None = None,
        workflow_type: str | None = None,
        trigger_event: str | None = None,
        owner_role: str = "workflow_owner",
        loop: bool = False,
        max_iterations: int | None = None,
        source: str = "sdk",
    ) -> Dict[str, Any]:
        """Compile a portable, governed workflow draft without network calls."""
        from lightbulb.business_primitives import compile_business_workflow_definition

        return compile_business_workflow_definition(
            objective,
            primitive_ids=primitive_ids,
            inputs=inputs,
            workflow_name=workflow_name,
            workflow_type=workflow_type,
            trigger_event=trigger_event,
            owner_role=owner_role,
            loop=loop,
            max_iterations=max_iterations,
            source=source,
        )

    def validate_business_workflow(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a portable workflow definition without network calls."""
        from lightbulb.business_primitives import validate_business_workflow_definition

        return validate_business_workflow_definition(definition)

    def simulate_business_workflow(
        self,
        definition: Dict[str, Any],
        *,
        events: List[str] | None = None,
        approvals: Dict[str, Any] | None = None,
        loop_iterations: int | None = None,
    ) -> Dict[str, Any]:
        """Dry-run a workflow within its bound without invoking live systems."""
        from lightbulb.business_primitives import simulate_business_workflow

        return simulate_business_workflow(
            definition,
            events=events,
            approvals=approvals,
            loop_iterations=loop_iterations,
        )

    def run_workflow_improvement_cycle(
        self,
        output_dir: str | os.PathLike[str] | None = None,
        *,
        observed_outcomes: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """Evaluate local workflow contracts and persist proposal-only work packets."""
        from lightbulb.workflow_improvement import run_workflow_improvement_cycle

        drained = None
        if observed_outcomes is None:
            from lightbulb.runtime_outcomes import improvement_outcomes

            drained = self._outcome_recorder.drain()
            observed_outcomes = improvement_outcomes(drained)
        try:
            return run_workflow_improvement_cycle(
                output_dir,
                observed_outcomes=observed_outcomes,
            )
        except Exception:
            for outcome in drained or ():
                self._outcome_recorder.record(outcome)
            raise

    def list_runtime_outcomes(self) -> List[Dict[str, Any]]:
        """Return sanitized outcomes recorded by this SDK process."""
        return [outcome.to_dict() for outcome in self._outcome_recorder.snapshot()]

    def drain_runtime_outcomes(self) -> List[Dict[str, Any]]:
        """Atomically consume outcomes in improvement-loop wire format."""
        from lightbulb.runtime_outcomes import improvement_outcomes

        return improvement_outcomes(self._outcome_recorder.drain())

    def record_server_runtime_outcomes(
        self,
        outcomes: List[Dict[str, Any]],
        *,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Persist a batch in the authenticated tenant/company runtime ledger."""
        payload = {
            "idempotencyKey": str(idempotency_key or f"sdk-outcomes-{uuid4()}").strip(),
            "outcomes": outcomes,
        }
        _guard_request_body(payload, endpoint="/api/sdk-project-runtime/outcomes")
        response = self._get_session().post(
            f"{self._base_url}/api/sdk-project-runtime/outcomes",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def flush_runtime_outcomes(
        self,
        *,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Upload queued outcomes, restoring them locally when upload fails."""
        outcomes = self._outcome_recorder.drain()
        payload = [outcome.to_dict() for outcome in outcomes]
        if not payload:
            return {"schema": "lightbulb.runtime_outcome_batch.v1", "accepted": 0}
        batch_key = (
            str(idempotency_key).strip()
            if idempotency_key
            else (
                "sdk-outcomes-"
                + hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ).hexdigest()[:40]
            )
        )
        try:
            return self.record_server_runtime_outcomes(
                payload,
                idempotency_key=batch_key,
            )
        except Exception:
            for outcome in outcomes:
                self._outcome_recorder.record(outcome)
            raise

    def get_workflow_improvement_status(
        self,
        output_dir: str | os.PathLike[str] | None = None,
    ) -> Dict[str, Any]:
        """Read local continuous-improvement state without network calls."""
        from lightbulb.workflow_improvement import load_workflow_improvement_status

        return load_workflow_improvement_status(output_dir)

    def list_workflow_improvement_packets(
        self,
        output_dir: str | os.PathLike[str] | None = None,
        *,
        status: str | None = None,
    ) -> List[Dict[str, Any]]:
        """List approval-gated workflow improvement packets."""
        from lightbulb.workflow_improvement import list_workflow_improvement_packets

        return list_workflow_improvement_packets(output_dir, status=status)

    def sync_workflow_improvement_report(
        self,
        report: Dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Persist one local evaluator report in the authenticated scoped ledger."""
        if (
            not isinstance(report, dict)
            or report.get("schema") != "lightbulb.workflow_improvement_report.v1"
        ):
            raise ValueError(
                "report must be a lightbulb.workflow_improvement_report.v1 object"
            )
        metrics = (
            report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
        )
        trend = report.get("trend") if isinstance(report.get("trend"), dict) else {}
        cycle = report.get("cycle") if isinstance(report.get("cycle"), dict) else {}
        source_run_id = str(cycle.get("run_id") or "").strip() or None
        key = str(
            idempotency_key or source_run_id or report.get("generated_at") or ""
        ).strip()
        if not key:
            raise ValueError("idempotency_key or report cycle.run_id is required")
        trend_direction = {
            "improved": "improving",
            "regressed": "regressing",
            "baseline": "stable",
        }.get(
            str(trend.get("direction") or "stable").lower(),
            str(trend.get("direction") or "stable").lower(),
        )
        run = self.record_server_workflow_improvement_run(
            idempotency_key=key,
            source_run_id=source_run_id,
            contract_score=metrics.get("contract_score", 0),
            primitive_count=metrics.get("primitive_count", 0),
            check_count=metrics.get("check_count", 0),
            passed_check_count=metrics.get("passed_check_count", 0),
            trend_direction=trend_direction,
            outcomes=report.get("observed_outcomes")
            if isinstance(report.get("observed_outcomes"), list)
            else [],
            metrics=metrics,
        )
        packets = []
        for packet in report.get("proposed_packets") or []:
            if isinstance(packet, dict):
                packets.append(
                    self.create_server_workflow_improvement_packet(
                        packet, source_run_id=run.get("id")
                    )
                )
        return {
            "schema": "lightbulb.workflow_improvement_sync.v1",
            "run": run,
            "packets": packets,
            "packet_count": len(packets),
        }

    def record_server_workflow_improvement_run(
        self,
        *,
        idempotency_key: str,
        contract_score: float,
        primitive_count: int,
        check_count: int,
        passed_check_count: int,
        trend_direction: str,
        source_run_id: str | None = None,
        outcomes: List[Dict[str, Any]] | None = None,
        metrics: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        payload = {
            "idempotencyKey": str(idempotency_key).strip(),
            "sourceRunId": str(source_run_id).strip() if source_run_id else None,
            "contractScore": contract_score,
            "primitiveCount": primitive_count,
            "checkCount": check_count,
            "passedCheckCount": passed_check_count,
            "trendDirection": str(trend_direction).strip(),
            "outcomes": outcomes or [],
            "metrics": metrics or {},
        }
        _guard_request_body(payload, endpoint="/api/workflow-improvements/runs")
        response = self._get_session().post(
            f"{self._base_url}/api/workflow-improvements/runs",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def create_server_workflow_improvement_packet(
        self,
        packet: Dict[str, Any],
        *,
        source_run_id: str | None = None,
    ) -> Dict[str, Any]:
        if not isinstance(packet, dict):
            raise ValueError("packet must be an object")
        payload = {
            "externalPacketId": packet.get("id"),
            "sourceRunId": source_run_id,
            "title": packet.get("title"),
            "objective": packet.get("objective"),
            "priority": packet.get("priority"),
            "taskKind": packet.get("task_kind") or "workflow_authoring",
            "assignedDomain": packet.get("assigned_domain"),
            "primitiveRefs": packet.get("target_primitive_refs")
            or packet.get("primitive_refs")
            or [],
            "targetFiles": packet.get("target_files") or [],
            "acceptanceCriteria": packet.get("acceptance_criteria") or [],
        }
        _guard_request_body(payload, endpoint="/api/workflow-improvements/packets")
        response = self._get_session().post(
            f"{self._base_url}/api/workflow-improvements/packets",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def get_server_workflow_improvement_status(self) -> Dict[str, Any]:
        response = self._get_session().get(
            f"{self._base_url}/api/workflow-improvements/status",
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def list_server_workflow_improvement_packets(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": max(1, min(int(limit), 100))}
        if status:
            params["status"] = str(status).strip()
        response = self._get_session().get(
            f"{self._base_url}/api/workflow-improvements/packets",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(response)
        data = response.json()
        return data if isinstance(data, list) else data.get("items", [])

    def get_server_workflow_improvement_packet(self, packet_id: str) -> Dict[str, Any]:
        """Read one exact tenant/company-scoped workflow improvement packet."""
        packet_id = _validate_id(packet_id, "packet_id")
        response = self._get_session().get(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}",
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def decide_workflow_improvement_packet(
        self,
        packet_id: str,
        *,
        approval_scope: str,
        decision: str,
        rationale: str = "",
        evidence: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        packet_id = _validate_id(packet_id, "packet_id")
        payload = {
            "approvalScope": str(approval_scope).strip(),
            "decision": str(decision).strip(),
            "rationale": rationale,
            "evidence": evidence or {},
        }
        _guard_request_body(payload, endpoint="workflow improvement decision")
        response = self._get_session().post(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/decisions",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def get_workflow_improvement_audit(self, packet_id: str) -> List[Dict[str, Any]]:
        packet_id = _validate_id(packet_id, "packet_id")
        response = self._get_session().get(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/audit",
            headers=self._headers(),
        )
        raise_if_error(response)
        data = response.json()
        return data if isinstance(data, list) else data.get("items", [])

    def start_workflow_improvement_delivery(
        self,
        packet_id: str,
        *,
        environment: str,
        repository_ref: str | None = None,
        base_branch: str = "main",
    ) -> Dict[str, Any]:
        packet_id = _validate_id(packet_id, "packet_id")
        payload = {
            "environment": str(environment).strip(),
            "repositoryRef": repository_ref,
            "baseBranch": str(base_branch).strip(),
        }
        response = self._get_session().post(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/deliveries",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def record_workflow_improvement_delivery_event(
        self,
        delivery_id: str,
        event_type: str,
        *,
        rationale: str = "",
        evidence: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        delivery_id = _validate_id(delivery_id, "delivery_id")
        payload = {
            "eventType": str(event_type).strip(),
            "rationale": rationale,
            "evidence": evidence or {},
        }
        _guard_request_body(payload, endpoint="workflow improvement delivery event")
        response = self._get_session().post(
            f"{self._base_url}/api/workflow-improvements/deliveries/{delivery_id}/events",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def get_workflow_improvement_delivery(self, delivery_id: str) -> Dict[str, Any]:
        delivery_id = _validate_id(delivery_id, "delivery_id")
        response = self._get_session().get(
            f"{self._base_url}/api/workflow-improvements/deliveries/{delivery_id}",
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def inspect_workflow_learning_candidate_attestation(
        self, delivery_id: str
    ) -> Dict[str, Any]:
        """Revalidate the exact candidate producer attestation using current keys."""

        delivery_id = _validate_id(delivery_id, "delivery_id")
        response = self._get_session().get(
            (
                f"{self._base_url}/api/workflow-improvements/deliveries/"
                f"{delivery_id}/candidate-artifact-attestation"
            ),
            headers=self._headers(),
        )
        raise_if_error(response)
        return response.json()

    def prepare_workflow_learning_handoff(
        self,
        packet_id: str,
        delivery_id: str,
        installation_id: str,
        revision_id: str,
        *,
        candidate_manifest: Dict[str, Any],
        episode_manifest: Dict[str, Any] | None = None,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Bind a validated delivery to read-only paired-learning readiness.

        This performs authenticated reads only. It cannot admit, fund, launch,
        evaluate, promote, or serve either training lane.
        """
        from lightbulb.workflow_learning import (
            WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA,
            compile_workflow_learning_handoff,
        )

        packet = self.get_server_workflow_improvement_packet(packet_id)
        delivery = self.get_workflow_improvement_delivery(delivery_id)
        audit = self.get_workflow_improvement_audit(packet_id)
        readiness = self.inspect_training_pair_readiness(
            installation_id,
            revision_id,
            project_id=project_id,
        )
        input_custody = None
        if episode_manifest is None or (
            isinstance(episode_manifest, dict)
            and episode_manifest.get("schema")
            == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA
        ):
            input_custody = self.inspect_training_pair_input_custody(
                installation_id,
                revision_id,
                project_id=project_id,
            )
        candidate_attestation = None
        if any(
            str(event.get("eventType") or event.get("event_type") or "").upper()
            == "IMPLEMENTATION_COMPLETED"
            and isinstance(event.get("evidence"), dict)
            and isinstance(
                event["evidence"].get("learning_candidate_artifact_attestation"),
                dict,
            )
            and event["evidence"]["learning_candidate_artifact_attestation"].get(
                "status"
            )
            == "signed"
            for event in audit
            if isinstance(event, dict)
        ):
            candidate_attestation = (
                self.inspect_workflow_learning_candidate_attestation(delivery_id)
            )
        return compile_workflow_learning_handoff(
            packet=packet,
            delivery=delivery,
            audit_events=audit,
            candidate_manifest=candidate_manifest,
            episode_manifest=episode_manifest,
            training_readiness=readiness,
            installation_id=installation_id,
            revision_id=revision_id,
            project_id=project_id,
            training_input_custody=input_custody,
            candidate_artifact_attestation=candidate_attestation,
        )

    def list_artifacts(self, **filters) -> List[Dict[str, Any]]:
        """List artifacts (charts, reports, analyses, etc.)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/artifacts",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("artifacts", []))
        )

    def get_artifact(self, artifact_id: str) -> Dict[str, Any]:
        """Get a specific artifact by ID."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/artifacts/{artifact_id}", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def register_external_artifact(
        self,
        *,
        type: str,
        title: str = "",
        summary: str = "",
        uri: str = "",
        content: str = "",
        project_id: Optional[str] = None,
        source_agent: str = "external_agent",
        metadata: Optional[Dict[str, Any]] = None,
        attach_workspace: bool = False,
    ) -> Dict[str, Any]:
        """Register an external artifact (codebase/document/slide deck/spreadsheet/url) created
        by a general agent so Lightbulb domain agents can discover and work on it.

        Either ``uri`` or ``content`` must be provided. For a ``codebase`` artifact with a repo
        ``uri``, set ``attach_workspace=True`` to also clone it into a Code Workspace so Lightbulb
        agents can work on it.
        """
        payload: Dict[str, Any] = {
            "type": type,
            "title": title,
            "summary": summary,
            "uri": uri,
            "content": content,
            "source_agent": source_agent,
        }
        if project_id:
            payload["project_id"] = project_id
        if metadata:
            payload["metadata"] = metadata
        if attach_workspace:
            payload["attach_workspace"] = True
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/artifacts/external/register",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Workflows ────────────────────────────────────────────────────

    def list_workflows(self, *, company_id: str | None = None) -> List[Dict[str, Any]]:
        """List active workflow definitions in the authenticated company scope."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/definitions",
            params=self._company_params(company_id),
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Get a workflow by ID."""
        workflow_id = _validate_id(workflow_id, "workflow_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/definitions/{workflow_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def trigger_workflow(
        self,
        workflow_type: str,
        objective: str,
        *,
        inputs: Dict[str, Any] | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Run a published workflow resolved by its public ``workflowType`` ref."""
        workflow_ref = str(workflow_type or "").strip()
        if not workflow_ref:
            raise ValueError("workflow_type is required")
        normalized_objective = _validate_message(objective)
        if inputs is not None and not isinstance(inputs, Mapping):
            raise ValueError("inputs must be a JSON object")
        definitions = self.list_workflows(company_id=company_id)
        matches = [
            definition
            for definition in definitions
            if isinstance(definition, Mapping)
            and str(definition.get("workflowType") or "").strip().casefold()
            == workflow_ref.casefold()
        ]
        if not matches:
            raise ValueError(
                f"No workflow found for workflow_ref {workflow_ref!r} in the active company scope"
            )
        if len(matches) != 1:
            raise ValueError(
                f"workflow_ref {workflow_ref!r} is ambiguous in the active company scope"
            )
        definition = matches[0]
        if str(definition.get("status") or "").strip().upper() != "PUBLISHED":
            raise ValueError(f"workflow_ref {workflow_ref!r} is not published")
        definition_id = str(definition.get("id") or "").strip()
        if not definition_id:
            raise ValueError(
                f"workflow_ref {workflow_ref!r} has no executable definition"
            )
        payload: Dict[str, Any] = {"objective": normalized_objective}
        if inputs:
            payload["inputs"] = dict(inputs)
        effective_company = company_id or self._active_company_id
        if effective_company:
            payload["companyId"] = str(effective_company).strip()
        _guard_request_body(payload, endpoint="workflows/execute")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/execute/{definition_id}",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def delete_workflow(
        self,
        workflow_id: str,
        *,
        company_id: str | None = None,
    ) -> None:
        """Soft-delete a workflow through the authenticated designer API."""
        workflow_id = _validate_id(workflow_id, "workflow_id")
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/workflow-designer/workflows/{workflow_id}",
            params=self._company_params(company_id),
            headers=self._headers(),
        )
        raise_if_error(resp)

    def cancel_workflow_instance(
        self,
        trace_id: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Cancel a scoped workflow run, including one waiting for approval."""
        trace_id = _validate_id(trace_id, "trace_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/instances/{trace_id}/cancel",
            params=self._company_params(company_id),
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def recursive_agent_execute(
        self,
        objective: str,
        *,
        inputs: Dict[str, Any] | None = None,
        policy: Any = None,
        execution_id: str | None = None,
    ) -> Dict[str, Any]:
        """Run a governed recursive objective with finite subagent and REPL limits."""
        from lightbulb.recursive_agents import build_recursive_agent_inputs

        normalized_objective = _validate_message(objective)
        recursive_inputs = build_recursive_agent_inputs(
            inputs, policy, execution_id=execution_id
        )
        result = self.backbone_execute(normalized_objective, inputs=recursive_inputs)
        result.setdefault(
            "recursive_execution",
            {
                "schema": "lightbulb.recursive_execution_ref.v1",
                "execution_id": recursive_inputs["recursive_execution_id"],
            },
        )
        return result

    def cancel_recursive_agent_execution(self, execution_id: str) -> Dict[str, Any]:
        """Cancel one exact user-owned recursive execution tree."""
        execution_id = _validate_id(execution_id, "execution_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/v1/backbone/recursive-executions/{execution_id}/cancel",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_recursive_agent_execution_status(self, execution_id: str) -> Dict[str, Any]:
        """Read privacy-minimized status for one exact user-owned recursive tree."""
        execution_id = _validate_id(execution_id, "execution_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/v1/backbone/recursive-executions/{execution_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Recursive execution status must be a JSON object")
        return result

    def author_workflow_definition(
        self,
        definition: Mapping[str, Any],
        *,
        prompt: str = "",
        name: str | None = None,
        workflow_type: str | None = None,
        site_project_id: str | None = None,
        category: str | None = None,
        change_notes: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Publish one exact executable workflow projection through governance.

        The server creates the definition/version, validates it as the gate of
        record, and publishes only a valid version. A validation rejection is a
        useful 422 result, so this method returns that structured body instead of
        converting it to an exception. JWT calls derive authority from the
        authenticated principal; ApiKeyAuth calls use the internal endpoint and
        its filter-validated tenant/company/user headers.
        """
        payload = _workflow_author_payload(
            definition,
            prompt=prompt,
            name=name,
            workflow_type=workflow_type,
            site_project_id=site_project_id,
            category=category,
            change_notes=change_notes,
        )
        internal_plane = isinstance(self._auth, ApiKeyAuth)
        effective_company = company_id or self._active_company_id
        if internal_plane:
            if effective_company:
                payload["companyId"] = str(effective_company).strip()
            if self._auth.user_id:
                payload["userId"] = str(self._auth.user_id).strip()
        _guard_request_body(payload, endpoint="workflow-designer/author")
        session = self._get_session()
        request_headers = self._headers()
        if internal_plane and effective_company:
            request_headers["X-Company-Id"] = str(effective_company).strip()
        response = session.post(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'author')}",
            params={} if internal_plane else self._company_params(company_id),
            json=payload,
            headers=request_headers,
        )
        if response.status_code != 422:
            raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow author response must be a JSON object")
        return result

    def author_workflow_trigger(
        self,
        workflow_definition_id: str,
        *,
        trigger_type: str = "schedule",
        schedule: str | None = None,
        event_type: str | None = None,
        event_filter: Mapping[str, Any] | None = None,
        name: str | None = None,
        description: str | None = None,
        site_project_id: str | None = None,
        configuration: Mapping[str, Any] | None = None,
        enabled: bool = False,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Create a principal-scoped schedule or event trigger for a workflow."""
        definition_id = str(workflow_definition_id or "").strip()
        if not definition_id:
            raise ValueError("workflow_definition_id is required")
        kind = str(trigger_type or "schedule").strip().lower()
        if kind not in {"schedule", "event"}:
            raise ValueError("trigger_type must be 'schedule' or 'event'")
        if kind == "schedule" and not str(schedule or "").strip():
            raise ValueError("schedule is required for a schedule trigger")
        if kind == "event" and not str(event_type or "").strip():
            raise ValueError("event_type is required for an event trigger")
        _validate_workflow_trigger_filter(event_filter)
        if configuration is not None and not isinstance(configuration, Mapping):
            raise ValueError("configuration must be a JSON object")
        if configuration:
            raise ValueError(
                "configuration does not accept arbitrary persisted values; use the typed schedule, event_type, event_filter, and site_project_id arguments"
            )

        payload: Dict[str, Any] = {
            "workflowDefinitionId": definition_id,
            "triggerType": kind,
        }
        if name:
            payload["name"] = str(name).strip()
        if description:
            payload["description"] = str(description).strip()
        if schedule:
            payload["schedule"] = str(schedule).strip()
        if event_type:
            payload["eventType"] = str(event_type).strip()
        if event_filter:
            payload["filter"] = dict(event_filter)
        if site_project_id:
            payload["siteProjectId"] = str(site_project_id).strip()
        if configuration:
            payload["configuration"] = dict(configuration)
        # Omission must never inherit the server's historical null -> active default.
        payload["enabled"] = bool(enabled)

        internal_plane = isinstance(self._auth, ApiKeyAuth)
        effective_company = company_id or self._active_company_id
        if internal_plane:
            if effective_company:
                payload["companyId"] = str(effective_company).strip()
            if self._auth.user_id:
                payload["userId"] = str(self._auth.user_id).strip()

        _guard_request_body(payload, endpoint="workflow-designer/triggers")
        session = self._get_session()
        request_headers = self._headers()
        if internal_plane and effective_company:
            request_headers["X-Company-Id"] = str(effective_company).strip()
        response = session.post(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'triggers')}",
            params={} if internal_plane else self._company_params(company_id),
            json=payload,
            headers=request_headers,
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow trigger response must be a JSON object")
        return result

    def get_workflow_trigger_catalog(self) -> Dict[str, Any]:
        """List the schedule literals and event types accepted by authoring."""
        session = self._get_session()
        response = session.get(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'triggers/catalog')}",
            headers=self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow trigger catalog response must be a JSON object")
        return result

    def author_agentic_workflow(
        self,
        prompt: str,
        *,
        name: str | None = None,
        workflow_type: str | None = None,
        preferred_domains: List[str] | None = None,
        include_approval_gates: bool = True,
        publish: bool = True,
        company_id: str | None = None,
        site_project_id: str | None = None,
        definition: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Compile once, then publish its exact executable projection through governance.

        Passing ``definition`` makes its ordered steps, triggers, and bounded
        defaults authoritative; they are never serialized back to prose or
        recompiled. Rich source metadata remains in the returned client artifact
        because the current server schema persists only that executable
        projection. With ``publish=False`` the method returns a local draft and
        performs no server-side authoring write.
        """
        prompt = _validate_message(prompt)
        if definition is None:
            compile_payload: Dict[str, Any] = {
                "prompt": prompt,
                "includeApprovalGates": bool(include_approval_gates),
            }
            if name:
                compile_payload["name"] = str(name).strip()
            if workflow_type:
                compile_payload["workflowType"] = str(workflow_type).strip()
            if preferred_domains:
                compile_payload["preferredDomains"] = [
                    str(item).strip() for item in preferred_domains if str(item).strip()
                ]
            _guard_request_body(compile_payload, endpoint="workflow-designer/compile")
            session = self._get_session()
            internal_plane = isinstance(self._auth, ApiKeyAuth)
            effective_company = company_id or self._active_company_id
            request_headers = self._headers()
            if internal_plane and effective_company:
                request_headers["X-Company-Id"] = str(effective_company).strip()
            compile_response = session.post(
                f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'compile')}",
                params={} if internal_plane else self._company_params(company_id),
                json=compile_payload,
                headers=request_headers,
            )
            raise_if_error(compile_response)
            compiled_result = compile_response.json()
            if not isinstance(compiled_result, dict):
                raise ValueError("Workflow compile response must be a JSON object")
            compiled: Dict[str, Any] = compiled_result
        else:
            if not isinstance(definition, Mapping):
                raise ValueError("definition must be a JSON object")
            compiled = dict(definition)

        workflow_name = str(name or compiled.get("name") or "Agentic Workflow").strip()
        workflow_type_value = str(
            workflow_type
            or compiled.get("workflowType")
            or compiled.get("workflow_type")
            or compiled.get("workflow_key")
            or "generated"
        ).strip()

        local_validation: Dict[str, Any]
        if compiled.get("schema") == "lightbulb.business_workflow_definition.v1":
            from lightbulb.business_primitives import (
                validate_business_workflow_definition,
            )

            local_validation = validate_business_workflow_definition(compiled)
        else:
            local_validation = _local_workflow_validation(compiled)

        author_result: Dict[str, Any] = {}
        local_rejected = local_validation.get("valid") is False
        if publish and not local_rejected:
            author_result = self.author_workflow_definition(
                compiled,
                prompt=prompt,
                name=workflow_name,
                workflow_type=workflow_type_value,
                site_project_id=site_project_id,
                company_id=company_id,
            )
        validation = author_result.get("validation") or local_validation
        published = bool(author_result.get("published"))
        rejected = bool(author_result.get("rejected")) or local_rejected
        status = author_result.get("status") or (
            "LOCAL_REJECTED"
            if local_rejected
            else "REJECTED"
            if rejected
            else "LOCAL_DRAFT"
            if not publish
            else "DRAFT"
        )
        workflow_id = author_result.get("workflowDefinitionId")
        warnings = list(compiled.get("warnings") or [])
        if isinstance(validation, Mapping):
            warnings.extend(list(validation.get("warnings") or []))

        artifact: Dict[str, Any] = {
            "schema": "lightbulb.agentic_workflow_artifact.v1",
            "prompt": prompt,
            "workflowDefinitionId": workflow_id,
            "name": workflow_name,
            "workflowType": author_result.get("workflowType") or workflow_type_value,
            "version": author_result.get("version"),
            "status": status,
            "published": published,
            "rejected": rejected,
            "persisted": bool(workflow_id),
            "validation": validation,
            "compiled": compiled,
            "steps": compiled.get("steps") or [],
            "triggers": compiled.get("triggers")
            or (
                [compiled["trigger"]]
                if isinstance(compiled.get("trigger"), Mapping)
                else []
            ),
            "defaults": compiled.get("defaults") or {},
            "capabilityRequirements": compiled.get("capabilityRequirements") or [],
            "missingCapabilities": compiled.get("missingCapabilities") or [],
            "warnings": warnings,
            "authoring": {
                "mode": (
                    "local_validation_rejected"
                    if local_rejected
                    else "governed_submitted_definition"
                    if publish
                    else "local_zero_write_draft"
                ),
                "endpoint": _workflow_authoring_endpoint(self._auth, "author")
                if publish and not local_rejected
                else None,
                "executableProjectionDigest": _workflow_executable_projection_digest(
                    compiled
                ),
                "definitionRecompiled": False,
                "sourceDefinitionPersisted": False,
                "sourceDefinitionRetainedInArtifact": True,
                "persistedProjectionVerified": bool(
                    author_result.get("persistedProjectionVerified")
                ),
                "serverNormalized": author_result.get("definitionNormalized"),
            },
            "sdk": {
                "trigger": f'client.trigger_workflow("{workflow_type_value}", objective, inputs={{}})',
                "authorTrigger": "client.author_workflow_trigger(workflow_definition_id, ...)",
            },
            "mcp": {
                "authorTool": "author_agentic_workflow",
                "authorTriggerTool": "author_workflow_trigger",
                "triggerTool": "trigger_workflow",
                "workflowType": workflow_type_value,
            },
        }
        for key in ("projectScope", "projectId", "binding", "bindingError"):
            if key in author_result:
                artifact[key] = author_result[key]
        return artifact

    # ── HITL / Approvals ───────────────────────────────────────────────

    def list_pending_approvals(self) -> List[Dict[str, Any]]:
        """List pending HITL approval tasks waiting for your decision."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/approvals/pending", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def get_approval(self, task_id: str) -> Dict[str, Any]:
        """Get full details of an approval task."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/approvals/{task_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def approve_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        """Approve a pending HITL task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/approve",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        """Reject a pending HITL task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/reject",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── RAG / Knowledge Base ─────────────────────────────────────────


    def request_engine_transition_approval(
        self,
        request: "Dict[str, Any] | Any",
    ) -> Dict[str, Any]:
        """Open a human approval for one sealed company-engine transition.

        ``request`` is a :class:`lightbulb.company_execution_bridge.EngineApprovalRequest`
        (or its dict form).  The body carries the exact transition binding
        (engine, entity, event, request and state digests); tenant and company
        come from the session, never from the body.  Returns the platform
        approval task; its ``id`` is the ``approval_ref`` once approved, and
        :func:`lightbulb.company_execution_bridge.bind_approval` proves the
        decision binds this request before it is placed on a command.
        """
        from lightbulb.company_execution_bridge import ENGINE_APPROVALS_PATH, EngineApprovalRequest

        # Any sealed request that renders its own body: an EngineApprovalRequest,
        # or a DecoratedApprovalRequest carrying the authority category and money.
        parsed = (
            request
            if hasattr(request, "to_platform_body")
            else EngineApprovalRequest.model_validate(dict(request))
        )
        payload = parsed.to_platform_body()
        _guard_request_body(payload, endpoint="workflows/approvals/engine-transitions")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}{ENGINE_APPROVALS_PATH}",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def request_launch_gate_approval(
        self,
        request: "Dict[str, Any] | Any",
        *,
        approver_user_id: str | None = None,
    ) -> Dict[str, Any]:
        """Open a human-only attestation for one ``company_launch`` step done outside Lightbulb.

        Registrar filing, bank account/KYC, signature, insurance, licence, Stripe-hosted
        payments onboarding and the kill-or-scale decision are performed by a person, not
        the platform.  ``request`` is the sealed launch-gate binding (the launch engine's
        command binding plus ``gate_kind``, ``evidence_sha256``, ``evidence_refs`` and
        ``attestation_sha256``) - an object exposing ``to_platform_body()`` or its dict
        form.  Tenant and company come from the session, never from the body.

        ``approver_user_id`` optionally pins the decision to one named member of the
        company; it is supplied by the MCP/CLI caller and never enters a sealed SDK model.
        Spring registers the task as ``sdk_launch_gate`` with ``workflow_generated_hitl``
        set, so no auto-accept preference applies and the requester cannot decide it.
        Returns the platform approval task; read the decision back with
        :meth:`get_approval`.
        """
        to_platform_body = getattr(request, "to_platform_body", None)
        payload: Dict[str, Any] = (
            dict(to_platform_body()) if callable(to_platform_body) else dict(request)
        )
        if approver_user_id:
            payload["approverUserId"] = approver_user_id
        _guard_request_body(payload, endpoint="workflows/approvals/launch-gates")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/launch-gates",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Operator policy: the AI operator's human-owned authority ceilings --------------

    def create_operator_policy(
        self,
        body: "Mapping[str, Any] | None" = None,
        *,
        operator_user_id: str,
        approver_user_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Draft the AI operator's per-category authority ceilings for one company.

        ``body`` carries ``currency``, ``matrixDigest``, optional ``effectiveFrom`` and
        ``reviewMonths``, and the ``ceilings`` list (``category``, ``engine``, ``event``,
        ``maxAmountCents``, ``requiresSecondApprover``, ``segregation``).  The operator and
        the approver are named explicitly and must differ: the platform refuses an operator
        without the AI_OPERATOR role and an approver that is one.  The policy is created
        ``draft`` and grants nothing until the approver activates it; human-only categories
        (people_change, wind_down, write_off) are forced human-only whatever is asked for.
        """
        scoped = self._require_runtime_action_company(company_id)
        payload: Dict[str, Any] = dict(body or {})
        payload["operatorUserId"] = str(operator_user_id)
        payload["approverUserId"] = str(approver_user_id)
        _guard_request_body(payload, endpoint="companies/operator-policy")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/companies/{scoped}/operator-policy",
            json=payload,
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()

    def activate_operator_policy(
        self,
        policy_id: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Activate a drafted policy.  Only the named human approver may call this.

        Activation mints exactly one amount-ceilinged approval preference per
        auto-acceptable ceiling, owned by the approver, and returns their ids.  Ceilings
        that require a second approver, and human-only ones, mint nothing: those
        transitions always wait in the approver's inbox.
        """
        scoped = self._require_runtime_action_company(company_id)
        policy = _validate_marketplace_uuid(policy_id, "policy_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/companies/{scoped}/operator-policy/{policy}/activate",
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()

    def suspend_operator_policy(
        self,
        policy_id: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Suspend an active policy (the approver or a tenant admin).

        Every minted preference is disabled before the status changes, so the operator
        falls back to asking a person for every engine transition.
        """
        scoped = self._require_runtime_action_company(company_id)
        policy = _validate_marketplace_uuid(policy_id, "policy_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/companies/{scoped}/operator-policy/{policy}/suspend",
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()

    def get_operator_policy(self, *, company_id: str | None = None) -> Dict[str, Any]:
        """The company's active operator policy and its ceilings.

        Raises :class:`~lightbulb.errors.LightbulbError` (404) when no policy is active: also the
        state in which every engine transition escalates to a human.
        """
        scoped = self._require_runtime_action_company(company_id)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/companies/{scoped}/operator-policy",
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()


    # -- Company lifecycle: the fence a company that has stopped trading lives behind ----

    def get_company_lifecycle(self, *, company_id: str | None = None) -> Dict[str, Any]:
        """The company's lifecycle status and every transition receipt so far.

        ``lifecycleStatus`` is ``ACTIVE``, ``WINDING_DOWN`` or ``CLOSED``.  A winding-down
        company refuses selling writes (409 ``company_winding_down``) while keeping final
        billing, refunds, notices, payroll and payables; a closed one refuses every tool
        (410 ``company_closed``) and will not hand a worker any work.
        """
        scoped = self._require_runtime_action_company(company_id)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/companies/{scoped}/lifecycle",
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()

    def wind_down_company(
        self,
        *,
        approval_task_id: str,
        resolution_sha256: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Move the company ACTIVE -> WINDING_DOWN and stop it selling.

        ``approval_task_id`` must name an APPROVED ``sdk_engine_transition`` task for
        ``wind_down_chain.decide`` that a human decided: the platform refuses an
        auto-accepted task, a task decided by its own requester, a task decided by the
        caller, and a task already spent.  ``resolution_sha256`` is the digest of the
        members'/directors' resolution signed off the platform.  Only a human tenant admin
        may call this: the AI operator principal is refused 403 unconditionally.

        Returns the lifecycle receipt (``companyId``, ``lifecycleStatus``, ``eventId``,
        ``approvalTaskId``, ``resolutionSha256``, ``decidedBy``, ``occurredAt``) plus
        ``receiptSha256``, the SHA-256 of those seven fields as canonical JSON.
        """
        scoped = self._require_runtime_action_company(company_id)
        payload: Dict[str, Any] = {
            "approvalTaskId": _validate_marketplace_uuid(approval_task_id, "approval_task_id"),
            "resolutionSha256": str(resolution_sha256),
        }
        _guard_request_body(payload, endpoint="companies/lifecycle/wind-down")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/companies/{scoped}/lifecycle/wind-down",
            json=payload,
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()

    def close_company(
        self,
        *,
        approval_task_id: str,
        resolution_sha256: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Move the company WINDING_DOWN -> CLOSED and revoke everything it was connected to.

        Same human-decision evidence as :meth:`wind_down_company`, for the
        ``wind_down_chain.close_accounts`` transition.  Closing revokes every OAuth
        connection, disables every tenant connector and project connector binding, and
        stops every open workflow checkpoint.  After it, every tool answers 410
        ``company_closed``.  Returns the same lifecycle receipt shape.
        """
        scoped = self._require_runtime_action_company(company_id)
        payload: Dict[str, Any] = {
            "approvalTaskId": _validate_marketplace_uuid(approval_task_id, "approval_task_id"),
            "resolutionSha256": str(resolution_sha256),
        }
        _guard_request_body(payload, endpoint="companies/lifecycle/close")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/companies/{scoped}/lifecycle/close",
            json=payload,
            headers=self._exact_company_headers(scoped),
        )
        raise_if_error(resp)
        return resp.json()


    def put_engine_state(
        self,
        project_id: str,
        engine: str,
        entity_ref: str,
        state: "Dict[str, Any]",
        *,
        expected_version: int | None,
        expected_state_digest: str | None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Persist one sealed company-engine state behind Spring's version and digest fences.

        ``expected_version`` and ``expected_state_digest`` are the prior persisted
        state's values (``0``/``None`` to create). Spring answers 409 when they are
        stale, when the document does not advance exactly one version, when the
        transition was already applied, or when the plan differs. The state carries
        opaque refs only; scope comes from the session and the path project.
        """
        _guard_request_body(state, endpoint="sdk-engine/states")
        payload: Dict[str, Any] = {"expectedVersion": expected_version, "expectedStateDigest": expected_state_digest, "state": dict(state)}
        session = self._get_session()
        resp = session.put(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}",
            json=payload,
            headers=self._exact_company_headers(company_id) if company_id else self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def migrate_engine_state(
        self,
        project_id: str,
        engine: str,
        entity_ref: str,
        state: "Dict[str, Any]",
        *,
        migration: "Dict[str, Any]",
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Persist a state migrated to a new plan behind Spring's migration fence.

        A migration keeps the persisted version and changes the plan digest; Spring
        admits it only when ``migration`` (the sealed ``PlanMigration`` proof from
        ``lightbulb.company_plan_migration``) starts from the persisted state digest
        and plan digest and ends at the supplied state. Anything else answers 409.
        """
        _guard_request_body(state, endpoint="sdk-engine/states/migrations")
        _guard_request_body(migration, endpoint="sdk-engine/states/migrations")
        payload: Dict[str, Any] = {"migration": dict(migration), "state": dict(state)}
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}/migrations",
            json=payload,
            headers=self._exact_company_headers(company_id) if company_id else self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_engine_state(
        self,
        project_id: str,
        engine: str,
        entity_ref: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any] | None:
        """Read one persisted engine state record, or ``None`` when it does not exist."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}",
            headers=self._exact_company_headers(company_id) if company_id else self._headers(),
        )
        if resp.status_code == 404:
            return None
        raise_if_error(resp)
        return resp.json()

    def get_engine_inventory(self, project_id: str, *, engine: str) -> Dict[str, Any]:
        """Read an unfiltered engine inventory pinned to the active company; partial reads remain marked."""
        from lightbulb._engine_inventory import validate_inventory
        company = _validate_marketplace_uuid(self.active_company_id, "active_company_id")
        project = _validate_marketplace_uuid(project_id, "project_id")
        session = self._get_session()
        response = session.get(f"{self._base_url}/api/sdk-engine/projects/{project}/states/inventory",
            params={"engine": engine}, headers=self._exact_company_headers(company))
        raise_if_error(response)
        return validate_inventory(response.json(), company_id=company, tenant_id=self._auth.tenant_id, project_id=project, engine=engine)

    def list_all_engine_states(self, project_id: str, *, engine: str | None = None,
            status: str | None = None, company_id: str | None = None) -> List[Dict[str, Any]]:
        """Read all states from immutable scoped pages; reject partial, mixed or expired snapshots.

        The host bounds snapshots to 10,000 rows and 32 MiB. An oversized scope
        raises an error instead of silently returning its first page.
        """
        from lightbulb._engine_inventory import EngineSnapshotRead
        company = _validate_marketplace_uuid(company_id or self.active_company_id, "company_id")
        project = _validate_marketplace_uuid(project_id, "project_id")
        engine = engine or None
        status = status.lower() if status else None
        reader = EngineSnapshotRead(company_id=company, tenant_id=self._auth.tenant_id,
            project_id=project, engine=engine, status=status)
        session = self._get_session()
        headers = self._exact_company_headers(company)
        path = f"{self._base_url}/api/sdk-engine/projects/{project}/states/snapshots"
        response = session.post(path, params={k:v for k,v in {"engine":engine,"status":status}.items() if v is not None},
            headers=headers)
        raise_if_error(response)
        reader.add(response.json())
        while reader.next_offset is not None:
            response = session.get(f"{path}/{reader.snapshot_id}", params={"offset":reader.next_offset}, headers=headers)
            raise_if_error(response)
            reader.add(response.json())
        return reader.records

    def list_engine_states(
        self,
        project_id: str,
        *,
        engine: str | None = None,
        status: str | None = None,
        limit: int = 50,
        company_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        """List persisted engine state records for a project, newest first."""
        params: Dict[str, Any] = {"limit": max(1, min(200, int(limit)))}
        if engine:
            params["engine"] = engine
        if status:
            params["status"] = status
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states",
            params=params,
            headers=self._exact_company_headers(company_id) if company_id else self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def rag_query(
        self, question: str, *, top_k: int = 5, document_ids: List[str] | None = None
    ) -> Dict[str, Any]:
        """Query the RAG knowledge base directly."""
        payload: Dict[str, Any] = {"question": question, "top_k": top_k}
        if document_ids:
            payload["document_ids"] = document_ids
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/rag/query", json=payload, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def rag_upload_document(
        self, filename: str, content: str, **metadata
    ) -> Dict[str, Any]:
        """Upload a document to the RAG library."""
        payload = {"filename": filename, "content": content, **metadata}
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/rag/library/documents",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Connectors ───────────────────────────────────────────────────

    def list_connectors(self) -> List[Dict[str, Any]]:
        """List available connectors and their status."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tools/connectors", headers=self._headers()
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def list_tool_contracts(self) -> List[Dict[str, Any]]:
        """List hosted Tool schemas used for connector drift detection."""
        response = self._get_session().get(
            f"{self._base_url}/api/tools",
            params={"activeOnly": True},
            headers=self._headers(),
        )
        raise_if_error(response)
        value = response.json()
        return value if isinstance(value, list) else value.get("items", [])

    def run_connector_conformance(
        self, *, check_live_schemas: bool = False
    ) -> Dict[str, Any]:
        """Verify every primitive provider and optionally compare hosted schemas."""
        from lightbulb.connector_conformance import run_connector_conformance

        schemas = self.list_tool_contracts() if check_live_schemas else None
        return run_connector_conformance(live_tool_schemas=schemas).to_dict()

    def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        project_id: str | None = None,
        project_ref: str | None = None,
        connector_account_ref: str | None = None,
        idempotency_key: str | None = None,
        approval_ref: str | None = None,
        workflow_id: str | None = None,
        step_id: str | None = None,
        workflow_instance_id: str | None = None,
        workflow_step_generation: int | None = None,
        runtime_context: Dict[str, Any] | None = None,
        effect: str | None = None,
        _runtime_authority: Any = None,
    ) -> Dict[str, Any]:
        """Invoke a platform tool by name (e.g. connector tools, utility tools).

        Calls without governance arguments use the legacy endpoint only for
        non-governed utility Tools. Once Spring's connector effect boundary is
        enabled, catalogued connector reads and writes fail closed unless this
        call supplies the exact governed project/account custody. Supplying an
        effect, approval, idempotency key, project reference, or runtime
        correlation uses Spring's Governed Connector Execution journal.
        ``effect`` is only a drift assertion; the server-owned Tool catalog is
        authoritative. Private-response reads such as
        ``shopify.list_abandoned_checkouts`` and ``gmail.get_thread`` require
        exact project/account/read custody and must omit ``idempotency_key`` so
        Spring always returns fresh provider data.
        """
        _validate_ephemeral_read_invoke_contract(
            tool_name,
            project_id=project_id,
            project_ref=project_ref,
            connector_account_ref=connector_account_ref,
            idempotency_key=idempotency_key,
            effect=effect,
        )
        governed = _governed_invoke_requested(
            project_ref=project_ref,
            connector_account_ref=connector_account_ref,
            idempotency_key=idempotency_key,
            approval_ref=approval_ref,
            runtime_context=runtime_context,
            effect=effect,
            workflow_instance_id=workflow_instance_id,
            workflow_step_generation=workflow_step_generation,
        )
        workflow_execution_identity = _normalize_workflow_execution_identity(
            workflow_instance_id=workflow_instance_id,
            step_id=step_id,
            workflow_step_generation=workflow_step_generation,
        )
        trusted_runtime = None
        if _runtime_authority is not None:
            from lightbulb.connector_execution import _TrustedRuntimeAuthority

            if not isinstance(_runtime_authority, _TrustedRuntimeAuthority):
                raise TypeError(
                    "runtime authority must be minted from a verified envelope"
                )
            if not governed:
                raise ValueError(
                    "runtime authority is accepted only for governed connector execution"
                )
            trusted_runtime = _runtime_authority
        if isinstance(self._auth, _VerifiedEnvelopeAuth):
            self._auth.require_runtime_authority(trusted_runtime)
        session = self._get_session()
        payload: Dict[str, Any] = {"toolName": tool_name, "inputs": arguments}
        tenant_id = (
            trusted_runtime.tenant_id
            if trusted_runtime is not None
            else getattr(self._auth, "tenant_id", None)
        )
        if tenant_id:
            payload["tenantId"] = tenant_id
        company_id = (
            trusted_runtime.company_id
            if trusted_runtime is not None
            else self._active_company_id
        )
        if company_id:
            payload["companyId"] = company_id
        if project_id:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        if workflow_id:
            payload["workflowId"] = str(workflow_id).strip()
        if step_id:
            payload["stepId"] = str(step_id).strip()
        if workflow_execution_identity is not None:
            bound_instance_id, bound_step_id, bound_generation = (
                workflow_execution_identity
            )
            payload["workflowInstanceId"] = bound_instance_id
            payload["stepId"] = bound_step_id
            payload["workflowStepGeneration"] = bound_generation
        if trusted_runtime is not None:
            if payload.get("projectId") != trusted_runtime.project_id:
                raise ValueError(
                    "project_id does not match the verified runtime authority"
                )
            if workflow_execution_identity is None or (
                payload.get("workflowInstanceId")
                != trusted_runtime.workflow_instance_id
                or payload.get("stepId") != trusted_runtime.step_id
                or payload.get("workflowStepGeneration")
                != trusted_runtime.step_generation
            ):
                raise ValueError(
                    "workflow identity does not match the verified runtime authority"
                )
        endpoint = "/api/tools/invoke"
        if governed:
            endpoint = (
                "/api/internal/tools/governed-invoke"
                if trusted_runtime is not None
                else "/api/tools/governed-invoke"
            )
            if project_ref is not None:
                clean_project_ref = str(project_ref).strip()
                if not clean_project_ref or len(clean_project_ref) > 160:
                    raise ValueError("project_ref must be 1-160 characters")
                payload["projectRef"] = clean_project_ref
            if connector_account_ref is not None:
                clean_account_ref = str(connector_account_ref).strip()
                if (
                    not clean_account_ref
                    or len(clean_account_ref) > 200
                    or any(ord(char) < 33 for char in clean_account_ref)
                ):
                    raise ValueError(
                        "connector_account_ref must be 1-200 visible characters"
                    )
                payload["connectorAccountRef"] = clean_account_ref
            if idempotency_key is not None:
                clean_key = str(idempotency_key).strip()
                if (
                    not clean_key
                    or len(clean_key) > 240
                    or any(ord(char) < 33 for char in clean_key)
                ):
                    raise ValueError("idempotency_key must be 1-240 visible characters")
                payload["idempotencyKey"] = clean_key
            if approval_ref is not None:
                payload["approvalRef"] = _validate_marketplace_uuid(
                    approval_ref, "approval_ref"
                )
            if runtime_context is not None:
                if not isinstance(runtime_context, dict):
                    raise ValueError("runtime_context must be an object")
                payload["runtimeContext"] = dict(runtime_context)
            if effect is not None:
                clean_effect = str(effect).strip().lower()
                if clean_effect not in {"read", "write"}:
                    raise ValueError("effect must be read or write")
                payload["claimedEffect"] = clean_effect
        _guard_request_body(
            payload,
            endpoint=(
                f"internal/tools/governed-invoke:{tool_name}"
                if trusted_runtime is not None
                else f"tools/{'governed-invoke' if governed else 'invoke'}:{tool_name}"
            ),
        )
        headers = (
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"lightbulb-mcp/{__version__}",
                "X-Agent-Runtime-Authority": trusted_runtime.token,
                "X-Tenant-Id": trusted_runtime.tenant_id,
                "X-Company-Id": trusted_runtime.company_id,
                "X-User-Id": trusted_runtime.user_id,
                "X-Project-Id": trusted_runtime.project_id,
                "X-Agent-Trace-Id": trusted_runtime.trace_id,
                "X-Agent-Workflow-Instance-Id": (trusted_runtime.workflow_instance_id),
                "X-Agent-Step-Id": trusted_runtime.step_id,
                "X-Agent-Workflow-Step-Generation": str(
                    trusted_runtime.step_generation
                ),
                "X-Agent-Principal": trusted_runtime.agent_principal,
            }
            if trusted_runtime is not None
            else self._headers()
        )
        resp = session.post(
            f"{self._base_url}{endpoint}",
            json=payload,
            headers=headers,
        )
        try:
            raise_if_error(resp)
        except LightbulbError as error:
            if governed:
                error.error_code = _governed_conflict_error_code(resp)
            raise
        return resp.json()

    # ── CRM ──────────────────────────────────────────────────────────

    def list_contacts(self, **filters) -> List[Dict[str, Any]]:
        """List CRM contacts."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/crm/contacts",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def list_deals(self, **filters) -> List[Dict[str, Any]]:
        """List CRM deals/opportunities."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/crm/deals",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    # ── Notifications ────────────────────────────────────────────────

    def list_notifications(self, **filters) -> List[Dict[str, Any]]:
        """List notifications (HITL decisions, workflow alerts, system messages)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/notifications",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("notifications", []))
        )

    # ── Memory ───────────────────────────────────────────────────────

    # -- Cross-host Context Broker -------------------------------------

    def context_open(
        self,
        host: str,
        *,
        host_session_ref: str | None = None,
        model: str | None = None,
        context_ref: str | None = None,
        project_id: str | None = None,
        company_id: str | None = None,
        token_budget: int = _CONTEXT_TOKEN_BUDGET_DEFAULT,
        query: str | None = None,
        repository: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Open or resume a private cross-host context binding.

        Tenant and user scope come only from the authenticated SDK session. An
        explicit ``company_id`` pins this request without changing selected
        client state and remains subject to server-side access checks.
        ``context_ref`` and the returned binding reference are opaque public
        handles, not caller-selectable identity fields.
        """
        payload: Dict[str, Any] = {
            "host": _validate_context_host(host),
            "tokenBudget": _validate_context_token_budget(token_budget),
        }
        optional_text = {
            "hostSessionRef": _optional_context_text(
                host_session_ref, "host_session_ref", max_length=512
            ),
            "model": _optional_context_text(model, "model", max_length=120),
            "query": _optional_context_text(query, "query", max_length=16_384),
        }
        payload.update({key: value for key, value in optional_text.items() if value})
        if context_ref is not None:
            payload["contextRef"] = _validate_context_public_ref(
                context_ref, "context_ref"
            )
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        if repository is not None:
            if not isinstance(repository, Mapping):
                raise ValueError("repository must be a JSON object")
            payload["repository"] = _normalize_context_repository(repository)
        _guard_request_body(payload, endpoint="context/open")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/context/open",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context open response must be a JSON object")
        return result

    def context_pack(
        self,
        context_ref: str,
        *,
        binding_ref: str | None = None,
        query: str | None = None,
        project_id: str | None = None,
        company_id: str | None = None,
        token_budget: int = _CONTEXT_TOKEN_BUDGET_DEFAULT,
        max_items: int = 12,
    ) -> Dict[str, Any]:
        """Build a bounded, prompt-aware working pack from durable context."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        payload: Dict[str, Any] = {
            "tokenBudget": _validate_context_token_budget(token_budget),
            "maxItems": _validate_context_max_items(max_items),
        }
        if binding_ref is not None:
            payload["bindingRef"] = _validate_context_public_ref(
                binding_ref, "binding_ref"
            )
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        normalized_query = _optional_context_text(query, "query", max_length=16_384)
        if normalized_query:
            payload["query"] = normalized_query
        _guard_request_body(payload, endpoint="context/pack")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/context/{context}/pack",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context pack response must be a JSON object")
        return result

    def context_search(
        self,
        context_ref: str,
        query: str,
        *,
        project_id: str | None = None,
        company_id: str | None = None,
        token_budget: int = _CONTEXT_TOKEN_BUDGET_DEFAULT,
        max_items: int = 10,
        kinds: Sequence[str] | None = None,
    ) -> Dict[str, Any]:
        """Search a Context Space without placing its full corpus in-model."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        normalized_query = _optional_context_text(query, "query", max_length=16_384)
        if normalized_query is None:
            raise ValueError("query must not be empty")
        payload: Dict[str, Any] = {
            "query": normalized_query,
            "tokenBudget": _validate_context_token_budget(token_budget),
            "maxItems": _validate_context_max_items(max_items),
        }
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        if kinds is not None:
            if isinstance(kinds, (str, bytes)) or not isinstance(kinds, Sequence):
                raise ValueError("kinds must be a JSON array")
            if len(kinds) > 8:
                raise ValueError("kinds may contain at most 8 items")
            normalized_kinds: List[str] = []
            for raw_kind in kinds:
                kind = _optional_context_text(raw_kind, "kind", max_length=80)
                kind = kind.lower() if kind else None
                if kind not in {"event", "checkpoint"}:
                    raise ValueError("kinds entries must be event or checkpoint")
                if kind and kind not in normalized_kinds:
                    normalized_kinds.append(kind)
            payload["kinds"] = normalized_kinds
        _guard_request_body(payload, endpoint="context/search")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/context/{context}/search",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context search response must be a JSON object")
        return result

    def context_read(
        self,
        context_ref: str,
        refs: Sequence[str],
        *,
        project_id: str | None = None,
        company_id: str | None = None,
        token_budget: int = _CONTEXT_TOKEN_BUDGET_DEFAULT,
    ) -> Dict[str, Any]:
        """Read exact opaque context items under a bounded token budget."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        if isinstance(refs, (str, bytes)) or not isinstance(refs, Sequence):
            raise ValueError("refs must be a non-empty JSON array")
        normalized_refs = [
            _validate_context_public_ref(item, f"refs[{index}]")
            for index, item in enumerate(refs)
        ]
        if not normalized_refs:
            raise ValueError("refs must be a non-empty JSON array")
        if len(normalized_refs) > _CONTEXT_MAX_ITEMS_MAX:
            raise ValueError(f"refs may contain at most {_CONTEXT_MAX_ITEMS_MAX} items")
        payload = {
            "refs": normalized_refs,
            "tokenBudget": _validate_context_token_budget(token_budget),
        }
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="context/read")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/context/{context}/read",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context read response must be a JSON object")
        return result

    def context_checkpoint(
        self,
        context_ref: str,
        *,
        binding_ref: str,
        base_revision: int,
        idempotency_key: str,
        events: Sequence[Mapping[str, Any]] | None = None,
        state: Mapping[str, Any] | None = None,
        project_id: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Append host deltas and structured state with optimistic concurrency."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        binding = _validate_context_public_ref(binding_ref, "binding_ref")
        if isinstance(base_revision, bool):
            raise ValueError("base_revision must be a non-negative integer")
        try:
            revision = int(base_revision)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("base_revision must be a non-negative integer") from exc
        if not 0 <= revision <= 9_223_372_036_854_775_807:
            raise ValueError("base_revision must be a non-negative integer")
        raw_key = str(idempotency_key or "")
        key = raw_key.strip()
        if raw_key != key or _CONTEXT_IDEMPOTENCY_KEY_PATTERN.fullmatch(key) is None:
            raise ValueError("Invalid context checkpoint idempotency_key")
        payload = {
            "bindingRef": binding,
            "baseRevision": revision,
            "idempotencyKey": key,
            "events": _normalize_context_events(events),
            "state": _normalize_context_state(state),
        }
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="context/checkpoint")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/context/{context}/checkpoint",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context checkpoint response must be a JSON object")
        return result

    def context_status(
        self,
        context_ref: str,
        *,
        binding_ref: str | None = None,
        project_id: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect one Context Space or one exact host-session binding."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        params: Dict[str, str] = {}
        if binding_ref is not None:
            params["bindingRef"] = _validate_context_public_ref(
                binding_ref, "binding_ref"
            )
        if project_id is not None:
            params["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/context/{context}/status",
            params=params or None,
            headers=self._context_headers(company_id),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Context status response must be a JSON object")
        return result

    def context_export(
        self,
        context_ref: str,
        *,
        project_id: str | None = None,
        company_id: str | None = None,
        event_after_sequence: int = 0,
        checkpoint_after_revision: int = 0,
        limit: int = 50,
        max_bytes: int = 1_048_576,
    ) -> Dict[str, Any]:
        """Export a bounded page from a private Context Space for user custody."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        if isinstance(event_after_sequence, bool) or not isinstance(
            event_after_sequence, int
        ):
            raise ValueError("event_after_sequence must be a non-negative integer")
        if isinstance(checkpoint_after_revision, bool) or not isinstance(
            checkpoint_after_revision, int
        ):
            raise ValueError("checkpoint_after_revision must be a non-negative integer")
        if event_after_sequence < 0 or checkpoint_after_revision < 0:
            raise ValueError("context export cursors must be non-negative")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 50
        ):
            raise ValueError("limit must be between 1 and 50")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 524_288 <= max_bytes <= 1_048_576
        ):
            raise ValueError("max_bytes must be between 524288 and 1048576")
        payload: Dict[str, Any] = {
            "eventAfterSequence": event_after_sequence,
            "checkpointAfterRevision": checkpoint_after_revision,
            "limit": limit,
            "maxBytes": max_bytes,
        }
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="context/export")
        response = self._get_session().post(
            f"{self._base_url}/api/context/{context}/export",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Context export response must be a JSON object")
        return result

    def context_archive(
        self,
        context_ref: str,
        *,
        project_id: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Archive a private Context Space and close its host bindings."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        payload: Dict[str, Any] = {}
        if project_id is not None:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        response = self._get_session().post(
            f"{self._base_url}/api/context/{context}/archive",
            json=payload,
            headers=self._context_headers(company_id),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Context archive response must be a JSON object")
        return result

    def context_delete(
        self,
        context_ref: str,
        *,
        project_id: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Request scoped physical deletion after the server's grace period."""
        context = _validate_context_public_ref(context_ref, "context_ref")
        params = (
            {"projectId": _validate_marketplace_uuid(project_id, "project_id")}
            if project_id is not None
            else None
        )
        response = self._get_session().delete(
            f"{self._base_url}/api/context/{context}",
            params=params,
            headers=self._context_headers(company_id),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Context deletion response must be a JSON object")
        return result

    def memory_store(
        self, key: str, value: str, *, namespace: str = "default"
    ) -> Dict[str, Any]:
        """Store a value in agent memory."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory",
            json={"key": key, "value": value, "namespace": namespace},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_recall(self, key: str, *, namespace: str = "default") -> Dict[str, Any]:
        """Recall a value from agent memory."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/{namespace}/{key}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_search(
        self, query: str, *, namespace: str = "default", top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Search agent memory semantically."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/search",
            json={"query": query, "namespace": namespace, "top_k": top_k},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    # ── Domain Agent Contracts ───────────────────────────────────────

    def list_domains(self) -> Dict[str, Dict[str, Any]] | List[Dict[str, Any]]:
        """List all available domain agents and their capabilities."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/domain-agents/contracts", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def list_domain_actions(self, domain: str) -> List[Dict[str, Any]]:
        """List available actions for a specific domain agent."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/domain-agents/{domain}/actions",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Governed account-shell customization ----------------------------

    def get_account_shell_customization(self) -> Dict[str, Any]:
        """Read the effective governed account-shell customization."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/frontend-customizations/account-shell",
            headers=self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def create_account_shell_customization_draft(
        self,
        document: Mapping[str, Any],
        *,
        base_revision_id: str | None,
    ) -> Dict[str, Any]:
        """Create an immutable draft from one exact base revision."""
        payload = {
            "document": _canonical_account_shell_document(document),
            "base_revision_id": _nullable_account_shell_revision_id(
                base_revision_id,
                "base_revision_id",
            ),
        }
        _guard_request_body(
            payload, endpoint="frontend-customizations/account-shell/drafts"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/drafts",
            json=payload,
            headers=self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def preview_account_shell_customization(
        self,
        draft_revision_id: str,
    ) -> Dict[str, Any]:
        """Compile a draft into a non-publishing preview receipt."""
        payload = {
            "draft_revision_id": _validate_marketplace_uuid(
                draft_revision_id,
                "draft_revision_id",
            )
        }
        _guard_request_body(
            payload, endpoint="frontend-customizations/account-shell/previews"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/previews",
            json=payload,
            headers=self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def publish_account_shell_customization(
        self,
        draft_revision_id: str,
        *,
        preview_receipt_id: str,
        expected_current_revision_id: str | None,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Publish the exact previewed draft with optimistic concurrency."""
        payload = {
            "draft_revision_id": _validate_marketplace_uuid(
                draft_revision_id,
                "draft_revision_id",
            ),
            "preview_receipt_id": _validate_marketplace_uuid(
                preview_receipt_id,
                "preview_receipt_id",
            ),
            "expected_current_revision_id": _nullable_account_shell_revision_id(
                expected_current_revision_id,
                "expected_current_revision_id",
            ),
        }
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        _guard_request_body(
            payload, endpoint="frontend-customizations/account-shell/publish"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/publish",
            json=payload,
            headers=self._tenant_headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def rollback_account_shell_customization(
        self,
        target_revision_id: str,
        *,
        expected_current_revision_id: str | None,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Roll back to an immutable revision with optimistic concurrency."""
        payload = {
            "target_revision_id": _validate_marketplace_uuid(
                target_revision_id,
                "target_revision_id",
            ),
            "expected_current_revision_id": _nullable_account_shell_revision_id(
                expected_current_revision_id,
                "expected_current_revision_id",
            ),
        }
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        _guard_request_body(
            payload, endpoint="frontend-customizations/account-shell/rollback"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/rollback",
            json=payload,
            headers=self._tenant_headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Governed runtime domain actions ---------------------------------

    def register_runtime_domain_action(
        self,
        domain: str,
        action: str,
        *,
        project_id: str,
        idempotency_key: str,
        description: str = "",
        component_ids: Sequence[str] | None = None,
        agent_spec: Dict[str, Any] | None = None,
        execution_policy: Dict[str, Any] | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Register a company-scoped action as ``pending_approval``.

        This method cannot set lifecycle status, approve the registration, or
        execute the action. The selected company is carried only by the
        authenticated ``X-Company-Id`` header.
        """
        company = self._require_runtime_action_company(company_id)
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        payload = _build_runtime_domain_action_payload(
            domain=domain,
            action=action,
            description=description,
            component_ids=component_ids,
            agent_spec=agent_spec,
            execution_policy=execution_policy,
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/domain-agents/runtime-actions",
            json=payload,
            headers=self._runtime_action_headers(
                project_id,
                company,
                {"Idempotency-Key": key},
            ),
        )
        raise_if_error(resp)
        return resp.json()

    def list_runtime_domain_actions(
        self,
        *,
        project_id: str,
        status: str = "pending_approval",
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """List one explicit lifecycle state for the selected company."""
        company = self._require_runtime_action_company(company_id)
        normalized_status = _validate_runtime_action_status(status)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/domain-agents/runtime-actions",
            params={"status": normalized_status},
            headers=self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    def get_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Review one exact-scope registration without changing its lifecycle."""
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}",
            headers=self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    def approve_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Approve a reviewed action and return its governed recursive reference.

        Approval does not activate ordinary domain dispatch. A response with
        ``recursive_spawnable=true`` may be placed in an explicit bounded
        ``RecursiveAgentPolicy.allowed_agent_ids`` using ``recursive_agent_id``.
        """
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}/approve",
            headers=self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Reject one reviewed pending registration without executing it."""
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}/reject",
            headers=self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    def search_agent_marketplace(
        self,
        *,
        query: str | None = None,
        kind: str | None = None,
        domain: str | None = None,
        limit: int = 50,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """Discover normalized Lightbulb action and worker listings.

        The result is discovery-only.  Static domain contracts are explicitly
        unverified.  When ``domain`` is provided, exactly one authenticated,
        tenant/company/RBAC-filtered action request overlays that domain; there
        is no per-domain fan-out and execution still re-checks entitlement and
        approval policy. Result IDs are stable synthetic references, not
        persisted lifecycle UUIDs. Use ``list_marketplace_listings`` to obtain
        the UUID listing and revision IDs accepted by lifecycle methods.
        """
        from lightbulb.marketplace import agent_marketplace_catalog

        normalized_domain = _validate_domain(domain) if domain else None
        primitives = self.list_business_primitives(include_inputs=include_inputs)
        contracts = self.list_domains()
        scoped_actions = (
            self.list_domain_actions(normalized_domain) if normalized_domain else []
        )
        return agent_marketplace_catalog(
            business_primitives=primitives,
            domain_contracts=contracts,
            scoped_domain=normalized_domain,
            scoped_actions=scoped_actions,
            query=query,
            kinds=kind,
            domain=normalized_domain,
            include_inputs=include_inputs,
            limit=limit,
        )

    # ── Voice / Phone Executions ────────────────────────────────────

    def list_marketplace_listings(
        self,
        *,
        query: str | None = None,
        kind: str | None = None,
        domain: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """List persisted lifecycle listings and authoritative UUID IDs."""
        params: Dict[str, Any] = {
            "limit": _bounded_marketplace_limit(limit),
            "include_inputs": bool(include_inputs),
        }
        if query:
            params["query"] = str(query).strip()[:1_000]
        if kind:
            params["kind"] = _validate_action(kind)
        if domain:
            params["domain"] = _validate_domain(domain)
        if cursor:
            params["cursor"] = str(cursor).strip()[:2_000]
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/listings",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_marketplace_listing(
        self,
        listing_id: str,
        *,
        revision_id: str | None = None,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """Get one persisted marketplace listing and optional immutable revision."""
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        params: Dict[str, Any] = {"include_inputs": bool(include_inputs)}
        if revision_id:
            params["revision_id"] = _validate_marketplace_uuid(
                revision_id, "revision_id"
            )
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/listings/{listing_id}",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def preview_marketplace_action_publication(
        self,
        *,
        slug: str,
        name: str,
        version: str,
        domain: str,
        action: str,
        visibility: str = "PRIVATE",
        pricing_model: str = "INCLUDED",
        changelog: str = "",
    ) -> Dict[str, Any]:
        """Preview a server-derived immutable action contract without publishing it."""
        payload = _build_marketplace_action_publication_payload(
            slug=slug,
            name=name,
            version=version,
            domain=domain,
            action=action,
            visibility=visibility,
            pricing_model=pricing_model,
            changelog=changelog,
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/action-publications/preview",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def publish_marketplace_action(
        self,
        *,
        slug: str,
        name: str,
        version: str,
        domain: str,
        action: str,
        expected_contract_digest: str,
        idempotency_key: str,
        visibility: str = "PRIVATE",
        pricing_model: str = "INCLUDED",
        changelog: str = "",
    ) -> Dict[str, Any]:
        """Publish the exact action contract approved by a prior preview."""
        payload = _build_marketplace_action_publication_payload(
            slug=slug,
            name=name,
            version=version,
            domain=domain,
            action=action,
            visibility=visibility,
            pricing_model=pricing_model,
            changelog=changelog,
        )
        payload["expected_contract_digest"] = _validate_marketplace_contract_digest(
            expected_contract_digest
        )
        _guard_request_body(payload, endpoint="agent-marketplace/action-publications")
        key = _validate_marketplace_publication_idempotency_key(idempotency_key)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/action-publications",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def get_marketplace_action_publication(self, publication_id: str) -> Dict[str, Any]:
        """Get governed publication and security-scan status by publication UUID."""
        publication_id = _validate_marketplace_uuid(publication_id, "publication_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/action-publications/{publication_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def wait_for_marketplace_action_publication(
        self,
        publication_id: str,
        *,
        timeout_seconds: float = 120.0,
        poll_interval_seconds: float = 2.0,
    ) -> Dict[str, Any]:
        """Poll until publication is READY, FAILED, or ARCHIVED, within hard bounds."""
        publication_id = _validate_marketplace_uuid(publication_id, "publication_id")
        timeout, interval = _bounded_marketplace_publication_polling(
            timeout_seconds,
            poll_interval_seconds,
        )
        deadline = time.monotonic() + timeout
        latest: Dict[str, Any] = {}
        while True:
            latest = self.get_marketplace_action_publication(publication_id)
            if _is_terminal_marketplace_action_publication(latest):
                return latest
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                publication_status, operation_status = (
                    _marketplace_action_publication_status(latest)
                )
                observed = publication_status or operation_status or "UNKNOWN"
                raise TimeoutError(
                    f"Marketplace action publication {publication_id} did not finish within "
                    f"{timeout:g} seconds (last status: {observed})"
                )
            time.sleep(min(interval, remaining))

    def archive_marketplace_action(
        self,
        listing_id: str,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Archive a publisher-owned listing with a replay-safe mutation."""
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        key = _validate_marketplace_publication_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        normalized_reason = str(reason or "").strip()
        if normalized_reason:
            payload["reason"] = _bounded_marketplace_publication_text(
                normalized_reason, "reason", 2_000
            )
        _guard_request_body(payload, endpoint="agent-marketplace/listings/archive")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/listings/{listing_id}/archive",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def list_marketplace_installations(
        self,
        *,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List marketplace installations for the selected active company."""
        self._require_marketplace_company()
        params: Dict[str, Any] = {"limit": _bounded_marketplace_limit(limit)}
        if status:
            params["status"] = _validate_action(status)
        if cursor:
            params["cursor"] = str(cursor).strip()[:2_000]
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/installations",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_marketplace_installation(self, installation_id: str) -> Dict[str, Any]:
        """Get one marketplace installation for the selected active company."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def install_marketplace_action(
        self,
        listing_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        deployment_targets: Sequence[str] | None = None,
    ) -> Dict[str, Any]:
        """Install a pinned revision and bind its explicit agent targets."""
        self._require_marketplace_company()
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        revision_id = _validate_marketplace_uuid(revision_id, "revision_id")
        key = _validate_idempotency_key(idempotency_key)
        payload = {"listing_id": listing_id, "revision_id": revision_id}
        if deployment_targets is not None:
            payload["deployment_targets"] = _normalize_marketplace_deployment_targets(
                deployment_targets
            )
        _guard_request_body(payload, endpoint="agent-marketplace/installations")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/installations",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def activate_marketplace_action(
        self,
        installation_id: str,
        *,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Activate an installed action; this never approves execution policy."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        _guard_request_body(
            payload, endpoint="agent-marketplace/installations/activate"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/activate",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def uninstall_marketplace_action(
        self,
        installation_id: str,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Uninstall an action from the selected company."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        if reason:
            payload["reason"] = str(reason).strip()[:2_000]
        _guard_request_body(
            payload, endpoint="agent-marketplace/installations/uninstall"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/uninstall",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def pin_marketplace_action(
        self,
        installation_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        expected_revision_id: str | None = None,
    ) -> Dict[str, Any]:
        """Pin an installation to an immutable listing revision."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        revision_id = _validate_marketplace_uuid(revision_id, "revision_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {"revision_id": revision_id}
        if expected_revision_id:
            payload["expected_revision_id"] = _validate_marketplace_uuid(
                expected_revision_id,
                "expected_revision_id",
            )
        _guard_request_body(payload, endpoint="agent-marketplace/installations/pin")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/pin",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def invoke_marketplace_action(
        self,
        installation_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        idempotency_key: str,
        message: str = "",
        objective: str = "",
        dry_run: bool = True,
        preview_invocation_id: str | None = None,
        confirm_live: bool = False,
    ) -> Dict[str, Any]:
        """Preview an installed action, or explicitly confirm an exact preview for live use."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {
            "inputs": _validate_marketplace_inputs(inputs),
            "dry_run": bool(dry_run),
        }
        if dry_run and preview_invocation_id:
            raise ValueError("preview_invocation_id is only valid when dry_run=False")
        if not dry_run:
            if not confirm_live:
                raise ValueError(
                    "confirm_live=True is required after reviewing a dry-run marketplace receipt"
                )
            payload["preview_invocation_id"] = _validate_marketplace_uuid(
                preview_invocation_id or "",
                "preview_invocation_id",
            )
        if message:
            payload["message"] = _validate_message(message)
        if objective:
            payload["objective"] = str(objective).strip()[:_MAX_MESSAGE_LENGTH]
        _guard_request_body(
            payload, endpoint="agent-marketplace/installations/invocations"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/invocations",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    def get_marketplace_invocation_status(self, invocation_id: str) -> Dict[str, Any]:
        """Get current invocation state for the selected company."""
        self._require_marketplace_company()
        invocation_id = _validate_marketplace_uuid(invocation_id, "invocation_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/invocations/{invocation_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_marketplace_invocation_receipt(self, invocation_id: str) -> Dict[str, Any]:
        """Get the immutable audit receipt for one marketplace invocation."""
        self._require_marketplace_company()
        invocation_id = _validate_marketplace_uuid(invocation_id, "invocation_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-marketplace/invocations/{invocation_id}/receipt",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Governed training-pair readiness/status ───────────────────────────

    def inspect_training_pair_readiness(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect structured source, authority, stage, and lane readiness.

        This call is read-only despite using POST. The v1 contract cannot
        report admission or execution authority.
        """
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-ops/training-pairs/readiness",
            json=payload,
            headers=self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair readiness must return exact HTTP 200"
            )
        return parse_training_pair_readiness(
            agent_ops_response_json(resp, "training-pair readiness"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    def inspect_training_pair_input_custody(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect exact-owner input custody without returning raw evidence.

        This read-only POST cannot upload or associate a receipt and cannot
        report training readiness, admission authority, or an execution surface.
        """
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-ops/training-pairs/input-custody",
            json=payload,
            headers=self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair input custody must return exact HTTP 200"
            )
        return parse_training_pair_input_custody(
            agent_ops_response_json(resp, "training-pair input custody"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    def preflight_training_pair(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Read readiness for one exact installed action revision.

        This call is read-only despite using POST. It never admits, schedules,
        or launches training.
        """
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-ops/training-pairs/preflight",
            json=payload,
            headers=self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair preflight must return exact HTTP 200"
            )
        return parse_training_pair_preflight(
            agent_ops_response_json(resp, "training-pair preflight"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    def request_training_pair_admission(
        self,
        installation_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Request admission and preserve the gateway's structured hard 503.

        Production currently has no admission, scheduler, or launcher. Only an
        exact ``lightbulb.training_pair_admission.v1`` unavailable response is
        returned normally for HTTP 503; every other error is raised.
        """
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        key = validate_training_pair_idempotency_key(idempotency_key)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/agent-ops/training-pairs",
            json=payload,
            headers=self._headers({"Idempotency-Key": key}),
        )
        if resp.status_code == 503:
            try:
                unavailable = agent_ops_response_json(resp, "training-pair admission")
            except AgentOpsProtocolError:
                raise_if_error(resp)
                raise
            if is_training_pair_admission_unavailable(unavailable):
                return parse_training_pair_admission_unavailable(unavailable)
            raise_if_error(resp)
        raise_if_error(resp)
        raise AgentOpsProtocolError(
            "training-pair admission returned an unsupported success contract; "
            "this SDK only accepts the current structured HTTP 503"
        )

    def get_training_pair_status(
        self,
        pair_handle: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Read the privacy-minimized status for one exact owned pair handle."""
        self._require_marketplace_company()
        normalized_pair = _validate_marketplace_uuid(pair_handle, "pair_handle")
        params: Dict[str, str] = {}
        if project_id is not None:
            params["project_id"] = _validate_marketplace_uuid(project_id, "project_id")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/agent-ops/training-pairs/{normalized_pair}",
            params=params,
            headers=self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair status must return exact HTTP 200"
            )
        return parse_training_pair_status(
            agent_ops_response_json(resp, "training-pair status"),
            pair_handle=normalized_pair,
            project_id=params.get("project_id"),
        )

    def list_voice_executions(self, **filters: Any) -> List[Dict[str, Any]]:
        """List voice agent executions (live and historical phone calls)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("executions", []))
        )

    def get_voice_execution(self, execution_id: str) -> Dict[str, Any]:
        """Get a voice execution detail (transcripts, status, agent decisions)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions/{execution_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_voice_pending_approvals(self) -> List[Dict[str, Any]]:
        """List in-call HITL approvals waiting for caller-side decision."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions/approvals/pending",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def approve_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        *,
        comments: str = "",
    ) -> Dict[str, Any]:
        """Approve a pending in-call action (e.g. transfer, wire info, commit booking)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/approve",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        *,
        comments: str = "",
    ) -> Dict[str, Any]:
        """Reject a pending in-call action."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/reject",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def modify_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        modifications: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Approve a voice action with modifications to the proposed payload."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/modify",
            json={"modifications": modifications},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── HR Live Connectors (BambooHR / Greenhouse / Monday) ─────────

    def hr_live_whos_out(self, **filters: Any) -> Dict[str, Any]:
        """BambooHR who's-out roster (current and upcoming time-off)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/whos-out",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_leave_balance(self, bamboo_employee_id: str) -> Dict[str, Any]:
        """BambooHR leave balance for an employee."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/leave/balances/{bamboo_employee_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_monday_onboarding_board(self, checklist_id: str) -> Dict[str, Any]:
        """Monday.com board view for an HR onboarding checklist."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/onboarding/{checklist_id}/monday-board",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_cases(self, **filters: Any) -> Dict[str, Any]:
        """HR case board items from Monday.com."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/cases/monday-items",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_recruiting_jobs(self, **filters: Any) -> Dict[str, Any]:
        """Greenhouse job listings."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/recruiting/jobs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_recruiting_applications(self, **filters: Any) -> Dict[str, Any]:
        """Greenhouse applications."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/recruiting/applications",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_advance_application(
        self, application_id: str, *, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Advance a Greenhouse candidate to the next stage (HITL-gated)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/hr/live/recruiting/applications/{application_id}/advance",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_reject_application(
        self, application_id: str, *, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Reject a Greenhouse application (HITL-gated)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/hr/live/recruiting/applications/{application_id}/reject",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_health(self) -> Dict[str, Any]:
        """Health check for HR connector tokens (BambooHR / Greenhouse / Monday)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/health", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Collaboration & Sharing ────────────────────

    def code_workspace_collaboration(self, workspace_id: str) -> Dict[str, Any]:
        """Get collaboration info (members, share links, pending requests)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaboration",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_add_collaborator(
        self,
        workspace_id: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
        role: str = "viewer",
    ) -> Dict[str, Any]:
        """Add a collaborator to a code workspace (role: viewer | editor | admin)."""
        body: Dict[str, Any] = {"role": role}
        if email:
            body["email"] = email
        if user_id:
            body["userId"] = user_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_update_collaborator(
        self, workspace_id: str, collaborator_id: str, *, role: str
    ) -> Dict[str, Any]:
        """Change a collaborator's role."""
        session = self._get_session()
        resp = session.put(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators/{collaborator_id}",
            json={"role": role},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_remove_collaborator(
        self, workspace_id: str, collaborator_id: str
    ) -> None:
        """Revoke a collaborator's access."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators/{collaborator_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    def code_workspace_create_share_link(
        self,
        workspace_id: str,
        *,
        role: str = "viewer",
        expires_in_seconds: int | None = None,
    ) -> Dict[str, Any]:
        """Create a share-link token granting access to the workspace."""
        body: Dict[str, Any] = {"role": role}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = int(expires_in_seconds)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/share-links",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_revoke_share_link(self, workspace_id: str, link_id: str) -> None:
        """Revoke a share link."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/share-links/{link_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    def code_workspace_redeem_share_link(self, token: str) -> Dict[str, Any]:
        """Redeem a workspace share-link token to gain access."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/share-links/{token}/redeem",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_approve_access_request(
        self, workspace_id: str, request_id: str
    ) -> Dict[str, Any]:
        """Approve a pending workspace access request."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/access-requests/{request_id}/approve",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_deny_access_request(
        self, workspace_id: str, request_id: str
    ) -> Dict[str, Any]:
        """Deny a pending workspace access request."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/access-requests/{request_id}/deny",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_add_note(
        self, workspace_id: str, content: str
    ) -> Dict[str, Any]:
        """Append a workspace note (visible to collaborators)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/notes",
            json={"content": content},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Runs / Reviews / Proposals / GitHub ────────

    def list_code_workspace_runs(
        self, workspace_id: str, **filters: Any
    ) -> List[Dict[str, Any]]:
        """List historical coding runs for a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data if isinstance(data, list) else data.get("items", data.get("runs", []))
        )

    def code_workspace_runs_insights(self, workspace_id: str) -> Dict[str, Any]:
        """Aggregate run-quality insights for a workspace (cost, latency, success rate)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/insights",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_telemetry(
        self, workspace_id: str, **filters: Any
    ) -> Dict[str, Any]:
        """Raw telemetry rows for a workspace's runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/telemetry",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_review(
        self,
        workspace_id: str,
        run_id: str,
        *,
        verdict: str,
        feedback: str = "",
    ) -> Dict[str, Any]:
        """Submit a human review verdict (accept | reject | request_changes) for a run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}/review",
            json={"verdict": verdict, "feedback": feedback},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_review_apply(
        self, workspace_id: str, run_id: str
    ) -> Dict[str, Any]:
        """Apply review-suggested changes to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}/review/apply",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_code_workspace_proposals(self, workspace_id: str) -> List[Dict[str, Any]]:
        """List code-change proposals submitted to the workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def submit_code_workspace_proposal(
        self, workspace_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Submit a code-change proposal (diff + summary)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def apply_code_workspace_proposal(
        self, workspace_id: str, proposal_id: str
    ) -> Dict[str, Any]:
        """Apply a previously-submitted proposal to the workspace files."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals/{proposal_id}/apply",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_code_workspace_proposal(
        self, workspace_id: str, proposal_id: str, *, reason: str = ""
    ) -> Dict[str, Any]:
        """Reject a proposal."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals/{proposal_id}/reject",
            json={"reason": reason},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_create_pull_request(
        self, workspace_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Open a GitHub pull request from the workspace branch."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/pull-request",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_link_repository(
        self, workspace_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Link a GitHub repository to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/repository",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def cancel_code_workspace_run(
        self, workspace_id: str, run_id: str
    ) -> Dict[str, Any]:
        """Cancel an in-flight coding run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat/{run_id}/cancel",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Tools (file / shell / git) ─────────────────

    def code_workspace_invoke_tool(
        self,
        workspace_id: str,
        tool_key: str,
        arguments: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Invoke a workspace-scoped tool (read/write files, run commands, git ops).

        Tool keys are registered in the workspace's runtime catalog. Common keys:
            - ``files.read`` — read a file by path
            - ``files.write`` — write a file
            - ``files.list`` — list directory contents
            - ``shell.run`` — execute a shell command
            - ``git.status`` — show git working-tree state
            - ``git.diff`` — produce a diff
            - ``git.commit`` — create a commit
        Use :meth:`code_workspace_runtime_catalog` to discover what's available
        for a specific workspace.
        """
        from lightbulb.validators import validate_tool_key

        workspace_id = _validate_id(workspace_id, "workspace_id")
        tool_key = validate_tool_key(tool_key)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/tools/{tool_key}",
            json=arguments or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_runtime_catalog(self, workspace_id: str) -> Dict[str, Any]:
        """Read the workspace's runtime tool catalog (which tool keys are available)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/catalog",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_register_runtime_tools(
        self,
        workspace_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Register or update workspace runtime tools."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/catalog",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Preview lifecycle ──────────────────────────

    def code_workspace_preview_start(
        self,
        workspace_id: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Start the workspace preview server (renders the in-progress code)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/start",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview(self, workspace_id: str) -> Dict[str, Any]:
        """Get the current preview state (URL, status, last build)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview_stop(self, workspace_id: str) -> Dict[str, Any]:
        """Stop the workspace preview server."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/stop",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview_proxy(
        self,
        workspace_id: str,
        path: str = "",
        *,
        method: str = "GET",
        body: Any = None,
        headers: Dict[str, str] | None = None,
    ) -> httpx.Response:
        """Proxy an HTTP call through the workspace preview.

        Returns the raw httpx.Response so callers can inspect status/headers/body.
        Use this for headless e2e tests against in-progress code.

        Security: caller-supplied ``headers`` are merged BEFORE auth headers, so
        a caller cannot overwrite ``Authorization`` / ``X-Tenant-Id`` /
        ``X-Internal-API-Key``. ``method`` and ``path`` are validated.
        """
        from lightbulb.validators import validate_method, validate_relative_path

        workspace_id = _validate_id(workspace_id, "workspace_id")
        method = validate_method(method)
        path = validate_relative_path(path)
        url = f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/proxy"
        if path:
            url = f"{url}/{path}"
        session = self._get_session()
        # Build caller headers first, then layer auth on top so auth wins.
        merged_headers: Dict[str, str] = dict(headers or {})
        # Strip any caller-supplied auth/scope headers explicitly.
        for blocked in (
            "authorization",
            "x-internal-api-key",
            "x-tenant-id",
            "x-company-id",
            "x-user-id",
            "x-xsrf-token",
        ):
            merged_headers.pop(blocked, None)
            merged_headers.pop(blocked.title(), None)
        merged_headers.update(self._headers())
        resp = session.request(method, url, json=body, headers=merged_headers)
        return resp

    # ── Code Workspace: Evals & policy replay ──────────────────────

    def code_workspace_evals(self, workspace_id: str) -> Dict[str, Any]:
        """Get accumulated eval rollups for a workspace's runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/evals",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_policy_replay(
        self, workspace_id: str, **filters: Any
    ) -> Dict[str, Any]:
        """Replay a policy decision over historical runs (debug helper)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/policy-replay",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_clear_policy(
        self, workspace_id: str, request_family: str
    ) -> Dict[str, Any]:
        """Clear cached policy decisions for a request family."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/policy/{request_family}/clear",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_promote_policy(
        self, workspace_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Promote workspace-scoped policy to a higher scope (company/tenant)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/policy/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Claude SDK runtime sessions ─────────────────

    def list_code_workspace_claude_sessions(
        self, workspace_id: str
    ) -> List[Dict[str, Any]]:
        """List Claude SDK sessions associated with a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("sessions", []))
        )

    def get_code_workspace_claude_session(
        self, workspace_id: str, session_id: str
    ) -> Dict[str, Any]:
        """Get a single Claude SDK session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions/{session_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def claude_session_action(
        self,
        workspace_id: str,
        session_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Perform an action on a Claude SDK session.

        action: one of rename, tag, fork, delete, interrupt, mcp/reconnect,
                mcp/toggle, rewind, tasks/stop, compact
        """
        from lightbulb.validators import validate_choice, CLAUDE_SESSION_ACTIONS

        workspace_id = _validate_id(workspace_id, "workspace_id")
        session_id = _validate_id(session_id, "session_id")
        action = validate_choice(
            action.strip().strip("/"), CLAUDE_SESSION_ACTIONS, "action"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions/{session_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Codex runtime threads ───────────────────────

    def list_code_workspace_codex_threads(
        self, workspace_id: str, **filters: Any
    ) -> List[Dict[str, Any]]:
        """List Codex runtime threads attached to a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("threads", []))
        )

    def get_code_workspace_codex_thread(
        self, workspace_id: str, thread_id: str
    ) -> Dict[str, Any]:
        """Get a Codex thread (turns, status, metadata)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def codex_thread_action(
        self,
        workspace_id: str,
        thread_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Perform a thread-level action (rename | archive | unarchive | compact | rollback)."""
        from lightbulb.validators import validate_choice, CODEX_THREAD_ACTIONS

        workspace_id = _validate_id(workspace_id, "workspace_id")
        thread_id = _validate_id(thread_id, "thread_id")
        action = validate_choice(
            action.strip().strip("/"), CODEX_THREAD_ACTIONS, "action"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def codex_turn_action(
        self,
        workspace_id: str,
        thread_id: str,
        turn_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Steer or interrupt a specific Codex turn (action: steer | interrupt)."""
        from lightbulb.validators import validate_choice, CODEX_TURN_ACTIONS

        workspace_id = _validate_id(workspace_id, "workspace_id")
        thread_id = _validate_id(thread_id, "thread_id")
        turn_id = _validate_id(turn_id, "turn_id")
        action = validate_choice(
            action.strip().strip("/"), CODEX_TURN_ACTIONS, "action"
        )
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}/turns/{turn_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── AutoCompany / AOC ───────────────────────────────────────────

    def list_aoc_runs(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany cognitive-loop runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/runs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data if isinstance(data, list) else data.get("items", data.get("runs", []))
        )

    def create_aoc_run(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new AutoCompany run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/runs", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def get_aoc_run(self, run_id: str) -> Dict[str, Any]:
        """Get an AutoCompany run detail."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/runs/{run_id}", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def stop_aoc_run(self, run_id: str) -> Dict[str, Any]:
        """Stop an in-flight AutoCompany cognitive-loop run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/runs/{run_id}/stop",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def validate_aoc_run_config(self, run_id: str) -> Dict[str, Any]:
        """Validate an AutoCompany run's configuration."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/runs/{run_id}/validate-config",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_tasks(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany tasks."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/tasks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data if isinstance(data, list) else data.get("items", data.get("tasks", []))
        )

    def create_aoc_task(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create an AutoCompany task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/tasks", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def get_aoc_task(self, task_id: str) -> Dict[str, Any]:
        """Get an AutoCompany task detail."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/tasks/{task_id}", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_task_events(self, task_id: str) -> List[Dict[str, Any]]:
        """List events recorded against an AutoCompany task."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/tasks/{task_id}/events",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("events", []))
        )

    def post_aoc_task_event(self, task_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Post a new event onto an AutoCompany task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/tasks/{task_id}/events",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_decisions(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany decisions awaiting or post-resolution."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/decisions",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("decisions", []))
        )

    def get_aoc_decision(self, decision_id: str) -> Dict[str, Any]:
        """Get a specific AutoCompany decision."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/decisions/{decision_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_ticks(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany cognitive-loop ticks."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/ticks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data if isinstance(data, list) else data.get("items", data.get("ticks", []))
        )

    def get_aoc_tick(self, tick_id: str) -> Dict[str, Any]:
        """Get a single AutoCompany tick."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/ticks/{tick_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def compute_aoc_tick(self, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Run a one-shot AutoCompany tick computation."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/ticks/compute",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def apply_aoc_tick(
        self, tick_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Apply a previously-computed AutoCompany tick (committing its decisions)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/ticks/{tick_id}/apply",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Memory Graph (beyond key/value) ─────────────────────────────

    def memory_list_entries(self, **filters: Any) -> List[Dict[str, Any]]:
        """List memory entries (structured records)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/entries",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("entries", []))
        )

    def memory_get_entry(self, entry_id: str) -> Dict[str, Any]:
        """Get a specific memory entry."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/entries/{entry_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_create_entry(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a structured memory entry."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/entries", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_query(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Run a structured memory query (filters, time-windows, semantic)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/query", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_projection_soul(self) -> Dict[str, Any]:
        """Identity / personality projection of the agent."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/projection/soul", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_projection_memory(self) -> Dict[str, Any]:
        """Memory-structure projection of the agent."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/projection/memory", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_status(self) -> Dict[str, Any]:
        """Health / capacity status of the memory subsystem."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/status", headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_regulation_storage_status(self) -> Dict[str, Any]:
        """Inspect finite company, tenant, and platform receipt admission."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/regulation/storage",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_regulate(
        self,
        *,
        idempotency_key: str | None = None,
        project_id: str | None = None,
        budget: int | None = None,
        categories: Sequence[str] | None = None,
        dry_run: bool = True,
        max_summary_chars: int = 900,
        empirical_success_floor_ppm: int | None = None,
        empirical_success_min_samples: int = 20,
        empirical_success_lookback_days: int = 90,
        optimize_for_least_active_memory: bool = False,
        held_out_task_evaluation: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Preview or execute bounded, success-evidence-aware compaction.

        Mutating calls require a caller-owned idempotency key. The raw key is
        used only for request replay and is retained by the server as a digest.
        An explicit empty ``categories`` sequence means select no categories;
        ``None`` means use the complete exact-owner scope.

        Supplying ``empirical_success_floor_ppm`` gates mutation on the share of
        Memory references from successful skill-execution receipts that remain
        raw and active. ``optimize_for_least_active_memory`` asks the server to
        select the smallest budget that clears that floor. This conservative
        metric preserves empirical success evidence; it does not claim held-out
        end-task success. ``held_out_task_evaluation`` instead carries a
        promotion-grade policy plus authenticated aggregate receipts bound to
        exact virtual compaction candidates. A dry run with candidate budgets
        and no receipts returns the bindings an evaluator must execute.
        """
        payload = _build_memory_regulation_payload(
            idempotency_key=idempotency_key,
            budget=budget,
            categories=categories,
            dry_run=dry_run,
            max_summary_chars=max_summary_chars,
            empirical_success_floor_ppm=empirical_success_floor_ppm,
            empirical_success_min_samples=empirical_success_min_samples,
            empirical_success_lookback_days=empirical_success_lookback_days,
            optimize_for_least_active_memory=(optimize_for_least_active_memory),
            held_out_task_evaluation=held_out_task_evaluation,
        )

        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/regulate",
            params={"projectId": project_id} if project_id else None,
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_graph(self, **filters: Any) -> Dict[str, Any]:
        """Full memory graph (or filtered subgraph)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/graph",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_graph_node(self, node_id: str) -> Dict[str, Any]:
        """Get a single node from the memory graph."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/graph/node",
            params={"id": node_id},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_identity(self) -> List[Dict[str, Any]]:
        """List identity records in the memory graph."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/identity", headers=self._headers()
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_create_identity(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create an identity record."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/identity", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_get_identity(self, doc_id: str) -> Dict[str, Any]:
        """Get an identity record by doc id."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/identity/{doc_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_events(self, **filters: Any) -> List[Dict[str, Any]]:
        """List memory events (timeline of state changes)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/events",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("events", []))
        )

    def memory_record_event(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Record a memory event."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/events", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_links(self, **filters: Any) -> List[Dict[str, Any]]:
        """List entity links in the memory graph."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/links",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_create_link(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a memory link between two entities."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/links", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_skills(self) -> List[Dict[str, Any]]:
        """List skills/capabilities recorded in memory."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/skills", headers=self._headers()
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_add_skill(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new skill / capability."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/skills", json=body, headers=self._headers()
        )
        raise_if_error(resp)
        return resp.json()

    # ── CRM Tasks ───────────────────────────────────────────────────

    def list_crm_tasks(
        self, tenant_id: str | None = None, **filters: Any
    ) -> List[Dict[str, Any]]:
        """List CRM tasks scoped to a tenant (defaults to authed tenant)."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data if isinstance(data, list) else data.get("items", data.get("tasks", []))
        )

    def get_crm_task(
        self, task_id: str, tenant_id: str | None = None
    ) -> Dict[str, Any]:
        """Get a single CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def create_crm_task(
        self, body: Dict[str, Any], tenant_id: str | None = None
    ) -> Dict[str, Any]:
        """Create a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def update_crm_task(
        self, task_id: str, body: Dict[str, Any], tenant_id: str | None = None
    ) -> Dict[str, Any]:
        """Update a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.put(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def delete_crm_task(self, task_id: str, tenant_id: str | None = None) -> None:
        """Delete a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    # ── Approval Auto-Accept Preferences ───────────────────────────

    def list_approval_preferences(self) -> List[Dict[str, Any]]:
        """List the user's HITL auto-accept rules."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/approval-preferences",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def create_approval_auto_accept(
        self, task_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Create an auto-accept rule keyed off the shape of an existing approval task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/auto-accept",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def delete_approval_preference(self, preference_id: str) -> Dict[str, Any]:
        """Remove an auto-accept rule."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approval-preferences/{preference_id}/delete",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def set_approval_preference_state(
        self, preference_id: str, *, enabled: bool
    ) -> Dict[str, Any]:
        """Enable or disable an auto-accept rule."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approval-preferences/{preference_id}/state",
            json={"enabled": bool(enabled)},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Notifications: read state ──────────────────────────────────

    def mark_notification_read(self, notification_id: str) -> Dict[str, Any]:
        """Mark a single notification as read."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/notifications/{notification_id}/read",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def mark_all_notifications_read(self) -> Dict[str, Any]:
        """Mark all notifications as read."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/notifications/read-all",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Domain Workspaces ──────────────────────────────────────────

    def workspace_bundle(self, domain: str) -> Dict[str, Any]:
        """Get a domain workspace data bundle (state, surfaces, recent runs)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/bundle",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_trace(self, domain: str, trace_id: str) -> Dict[str, Any]:
        """Get a workspace trace (full agent execution log)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/traces/{trace_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_conversation(
        self, domain: str, conversation_id: str
    ) -> Dict[str, Any]:
        """Get a domain workspace conversation."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/conversations/{conversation_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_surface(
        self, domain: str, surface: str, **filters: Any
    ) -> Dict[str, Any]:
        """Read a domain workspace surface (e.g. internal_suite, live connector)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/surfaces/{surface}",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def it_ops_live_connector(self, connector: str, **filters: Any) -> Dict[str, Any]:
        """Pass-through to a live IT-Ops connector (jira | slack | github | notion)."""
        connector = str(connector).strip().lower()
        if connector not in {"jira", "slack", "github", "notion"}:
            raise ValueError("connector must be one of jira | slack | github | notion")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/it_ops/connectors/{connector}/live",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def it_ops_mcp_manifest(self) -> Dict[str, Any]:
        """Get the IT-Ops workspace MCP manifest."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/it_ops/mcp/manifest",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Page Builder: automation, SEO, capabilities ────────────────

    def page_builder_workspace_automation(
        self, session_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Run the page-builder workspace automation (auto-wire pages → agents → backend)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/workspace-automation",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_promote_section(
        self, session_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Promote a section artifact to the install bundle."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/artifacts/sections/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_promote_install_bundle(
        self, session_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Promote an install bundle to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/artifacts/install-bundles/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_install_artifact(
        self, session_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Install a component artifact into the page session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/install-artifact",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_capabilities(self, session_id: str) -> Dict[str, Any]:
        """List page capabilities (forms, search, auth, etc.)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/capabilities",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_save_capability(
        self, session_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Save a capability to the page session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/capabilities",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_save_backend_contract(
        self, session_id: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Define a backend contract for a page (data shape + agent binding)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/backend-contracts",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_unpublish(self, session_id: str) -> Dict[str, Any]:
        """Unpublish a deployed page builder session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/unpublish",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Document Builder: collaboration, share-links, messages ─────

    def document_builder_collaboration(self, session_id: str) -> Dict[str, Any]:
        """Collaboration info for a document builder session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/collaboration",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_add_collaborator(
        self,
        session_id: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
        role: str = "viewer",
    ) -> Dict[str, Any]:
        """Add a collaborator to a document builder session."""
        body: Dict[str, Any] = {"role": role}
        if email:
            body["email"] = email
        if user_id:
            body["userId"] = user_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/collaborators",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_create_share_link(
        self,
        session_id: str,
        *,
        role: str = "viewer",
        expires_in_seconds: int | None = None,
    ) -> Dict[str, Any]:
        """Create a share-link token for a document builder session."""
        body: Dict[str, Any] = {"role": role}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = int(expires_in_seconds)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/share-links",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_redeem_share_link(
        self, session_id: str, token: str
    ) -> Dict[str, Any]:
        """Redeem a document builder share link."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/share-links/redeem",
            json={"token": token},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_get_messages(
        self, session_id: str, **filters: Any
    ) -> List[Dict[str, Any]]:
        """Get the message history for a document builder session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/messages",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return (
            data
            if isinstance(data, list)
            else data.get("items", data.get("messages", []))
        )

    def document_builder_save(
        self, session_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Save a document builder session's current state."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/save",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Marketing Content Connector Setup ──────────────────────────

    def marketing_content_setup(self) -> Dict[str, Any]:
        """Get the marketing content connector setup state."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_content_configure_provider(
        self, provider: str, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Configure a marketing-content provider (e.g. ga4, segment, plausible)."""
        provider = _validate_id(provider, "provider")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/providers/{provider}",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_add_website_analytics_site(
        self, body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register a website with the analytics setup."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_select_website_analytics_site(self, site_id: str) -> Dict[str, Any]:
        """Activate a registered analytics site."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites/{site_id}/select",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_remove_website_analytics_site(self, site_id: str) -> Dict[str, Any]:
        """Remove a registered analytics site."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites/{site_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json() if resp.content else {"removed": site_id}

    def marketing_verify_website_analytics(
        self, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Verify the website analytics setup is wired correctly."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/verify",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_install_website_analytics(
        self, workspace_id: str, body: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Install website analytics into a code workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/workspaces/{workspace_id}/install",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_add_note(
        self, session_id: str, content: str
    ) -> Dict[str, Any]:
        """Add a note to a document builder session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/notes",
            json={"content": content},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def start_procurement_matched_close_run(
        self,
        project_id: str,
        request: ProcurementStart | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        """Start Procurement 0.3 through Spring's exact scoped authority."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = ProcurementStart.model_validate(
            request.to_dict() if isinstance(request, ProcurementStart) else request
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/procurement/matched-close/runs",
            json=parsed.to_dict(),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        receipt = ProcurementCommandReceipt.model_validate(response.json())
        if receipt.operation != "START_REQUISITION":
            raise ValueError("Spring returned the wrong Procurement operation receipt")
        return receipt

    def submit_procurement_requisition(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementApprovalBinding | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "requisition-submission",
            request,
            ProcurementApprovalBinding,
            ProcurementCommandReceipt,
            "REQUISITION_SUBMISSION",
            company_id=company_id,
        )

    def approve_procurement_spend_commitment(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementApprovalBinding | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "approved-commitment",
            request,
            ProcurementApprovalBinding,
            ProcurementCommandReceipt,
            "APPROVED_COMMITMENT",
            company_id=company_id,
        )

    def bind_procurement_xero_purchase_order_readback(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementPurchaseOrderJournalBinding | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        """Bind opaque governed Xero write/readback journals; perform no provider call."""

        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "xero-purchase-order-readback",
            request,
            ProcurementPurchaseOrderJournalBinding,
            ProcurementCommandReceipt,
            "PURCHASE_ORDER_ISSUED",
            company_id=company_id,
        )

    def record_procurement_goods_receipt(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementGoodsReceipt | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "goods-receipt",
            request,
            ProcurementGoodsReceipt,
            ProcurementCommandReceipt,
            "RECORD_GOODS_RECEIPT",
            company_id=company_id,
        )

    def record_procurement_supplier_invoice(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementSupplierInvoice | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCustodyReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "supplier-invoice",
            request,
            ProcurementSupplierInvoice,
            ProcurementCustodyReceipt,
            "RECORD_SUPPLIER_INVOICE",
            company_id=company_id,
        )

    def derive_procurement_three_way_match(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementThreeWayMatch | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCustodyReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "three-way-match",
            request,
            ProcurementThreeWayMatch,
            ProcurementCustodyReceipt,
            "DERIVE_THREE_WAY_MATCH",
            company_id=company_id,
        )

    def approve_procurement_matched_close(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementMatchedClose | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "matched-close",
            request,
            ProcurementMatchedClose,
            ProcurementCommandReceipt,
            "MATCHED_CLOSE",
            company_id=company_id,
        )

    def get_procurement_matched_close_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_run_ref = validate_procurement_run_ref(run_ref)
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/procurement/matched-close/runs/{normalized_run_ref}",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        receipt = ProcurementCommandReceipt.model_validate(response.json())
        if receipt.operation != "GET":
            raise ValueError("Spring returned the wrong Procurement operation receipt")
        return receipt

    def get_procurement_matched_close_outcomes(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ProcurementOutcomeReceipt:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_run_ref = validate_procurement_run_ref(run_ref)
        response = self._get_session().get(
            f"{self._base_url}/api/projects/{normalized_project_id}/procurement/matched-close/runs/{normalized_run_ref}/outcomes",
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ProcurementOutcomeReceipt.model_validate(response.json())

    def fail_procurement_matched_close_run(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementFailure | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "fail",
            request,
            ProcurementFailure,
            ProcurementCommandReceipt,
            "FAILED",
            company_id=company_id,
        )

    def cancel_procurement_matched_close_run(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementCancellation | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "cancel",
            request,
            ProcurementCancellation,
            ProcurementCommandReceipt,
            "CANCELLED",
            company_id=company_id,
        )

    def mark_procurement_purchase_order_ambiguous(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementAmbiguity | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "effect-ambiguous",
            request,
            ProcurementAmbiguity,
            ProcurementCommandReceipt,
            "EFFECT_AMBIGUOUS",
            company_id=company_id,
        )

    def reconcile_procurement_purchase_order(
        self,
        project_id: str,
        run_ref: str,
        request: ProcurementReconciliation | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ProcurementCommandReceipt:
        return self._post_procurement_matched_close(
            project_id,
            run_ref,
            "reconcile",
            request,
            ProcurementReconciliation,
            ProcurementCommandReceipt,
            "RECONCILE",
            company_id=company_id,
        )

    def _post_procurement_matched_close(
        self,
        project_id: str,
        run_ref: str,
        action: str,
        request: Any,
        request_model: Any,
        receipt_model: Any,
        expected_operation: str,
        *,
        company_id: str | None,
    ) -> Any:
        if action not in {
            "requisition-submission",
            "approved-commitment",
            "xero-purchase-order-readback",
            "goods-receipt",
            "supplier-invoice",
            "three-way-match",
            "matched-close",
            "fail",
            "cancel",
            "effect-ambiguous",
            "reconcile",
        }:
            raise ValueError("Unreviewed Procurement Golden Loop command")
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_run_ref = validate_procurement_run_ref(run_ref)
        parsed = request_model.model_validate(
            request.to_dict() if isinstance(request, request_model) else request
        )
        response = self._get_session().post(
            f"{self._base_url}/api/projects/{normalized_project_id}/procurement/matched-close/runs/{normalized_run_ref}/{action}",
            json=parsed.to_dict(),
            headers=self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        receipt = receipt_model.model_validate(response.json())
        if receipt.operation != expected_operation:
            raise ValueError("Spring returned the wrong Procurement operation receipt")
        return receipt
