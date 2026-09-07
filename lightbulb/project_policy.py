"""Typed builders for the shared Project Strategy Lab contract."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid4


PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA = (
    "lightbulb.project_policy_assignment_observation.v1"
)
PROJECT_POLICY_ASSIGNMENT_RECEIPT_SCHEMA = "lightbulb.project_policy_assignment_receipt.v1"
PROJECT_POLICY_ASSIGNMENT_LEDGER_SCHEMA = "lightbulb.project_policy_assignment_ledger.v1"
PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA = (
    "lightbulb.project_policy_offline_evaluation_pair_request.v1"
)
PROJECT_POLICY_OFFLINE_EVALUATION_RECEIPT_SCHEMA = (
    "lightbulb.project_policy_offline_evaluation_receipt.v1"
)
PROJECT_POLICY_OFFLINE_EVALUATION_LEDGER_SCHEMA = (
    "lightbulb.project_policy_offline_evaluation_ledger.v1"
)
PROJECT_STRATEGY_LAB_SCHEMA = "lightbulb.project_strategy_lab.v1"


def _text(value: Any, field: str, maximum: int) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return normalized


def _uuid(value: Any, field: str) -> str:
    try:
        return str(UUID(_text(value, field, 64)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _timestamp(value: Any, field: str) -> str:
    if value is None or not str(value).strip():
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    normalized = _text(value, field, 80)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _probability(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite probability")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a finite probability") from exc
    if not math.isfinite(result) or result < 0.0 or result > 1.0:
        raise ValueError(f"{field} must be between zero and one")
    return result


def _actions(values: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, str]], set[str]]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError("actions must be an array")
    if len(values) < 2 or len(values) > 20:
        raise ValueError("actions must contain between 2 and 20 alternatives")
    result: list[dict[str, str]] = []
    action_ids: set[str] = set()
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise ValueError(f"actions[{index}] must be an object")
        action_id = _text(value.get("id"), f"actions[{index}].id", 160)
        if action_id in action_ids:
            raise ValueError("actions ids must be unique")
        action_ids.add(action_id)
        result.append({
            "id": action_id,
            "label": _text(value.get("label"), f"actions[{index}].label", 240),
        })
    return result, action_ids


def _policy(value: Mapping[str, Any], action_ids: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    probabilities = value.get("action_probabilities")
    if not isinstance(probabilities, Mapping) or set(probabilities) != action_ids:
        raise ValueError(
            f"{field}.action_probabilities must contain every action exactly once"
        )
    normalized = {
        action_id: _probability(
            probabilities[action_id], f"{field}.action_probabilities.{action_id}"
        )
        for action_id in sorted(action_ids)
    }
    if abs(sum(normalized.values()) - 1.0) > 0.000001:
        raise ValueError(f"{field} action probabilities must sum to one")
    version = str(value.get("version") or "").strip()
    if len(version) > 80:
        raise ValueError(f"{field}.version exceeds 80 characters")
    return {
        "id": _text(value.get("id"), f"{field}.id", 160),
        "version": version or None,
        "action_probabilities": normalized,
    }


def _evidence_refs(values: Sequence[Any] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError("evidence_refs must be an array")
    if len(values) > 16:
        raise ValueError("evidence_refs may contain at most 16 items")
    result: list[str] = []
    for value in values:
        item = _text(value, "evidence_refs item", 500)
        if item not in result:
            result.append(item)
    return result


def _links(values: Mapping[str, Any] | None) -> dict[str, Any]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise ValueError("links must be an object")
    allowed = {
        "approval_receipt_id",
        "hypothesis_receipt_id",
        "skill_tournament_receipt_id",
        "skill_ids",
    }
    unexpected = sorted(set(values) - allowed)
    if unexpected:
        raise ValueError(f"links contains unsupported keys: {unexpected}")
    result: dict[str, Any] = {}
    for key in sorted(values):
        if key == "skill_ids":
            items = values[key]
            if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
                raise ValueError("links.skill_ids must be an array")
            if len(items) > 8:
                raise ValueError("links.skill_ids may contain at most 8 items")
            result[key] = [_text(item, "links.skill_ids item", 240) for item in items]
        else:
            result[key] = _text(values[key], f"links.{key}", 240)
    return result


def build_project_policy_assignment(
    *,
    metric_id: Any,
    direction: Any,
    actions: Sequence[Mapping[str, Any]],
    chosen_action_id: Any,
    behavior_policy: Mapping[str, Any],
    candidate_policies: Sequence[Mapping[str, Any]],
    assignment_id: Any = None,
    unit: Any = None,
    decided_at: Any = None,
    source_kind: str = "human_attestation",
    source_event_id: Any = None,
    evidence_refs: Sequence[Any] | None = None,
    links: Mapping[str, Any] | None = None,
    note: Any = None,
) -> dict[str, Any]:
    """Build the exact immutable assignment body accepted by Spring."""

    normalized_actions, action_ids = _actions(actions)
    chosen = _text(chosen_action_id, "chosen_action_id", 160)
    if chosen not in action_ids:
        raise ValueError("chosen_action_id must name one of actions")
    behavior = _policy(behavior_policy, action_ids, "behavior_policy")
    if behavior["action_probabilities"][chosen] <= 0.0:
        raise ValueError("behavior policy must give the chosen action positive probability")
    if isinstance(candidate_policies, (str, bytes)) or not isinstance(candidate_policies, Sequence):
        raise ValueError("candidate_policies must be an array")
    if len(candidate_policies) < 1 or len(candidate_policies) > 8:
        raise ValueError("candidate_policies must contain between 1 and 8 policies")
    candidates = [
        _policy(value, action_ids, f"candidate_policies[{index}]")
        for index, value in enumerate(candidate_policies)
    ]
    policy_ids = [behavior["id"], *(policy["id"] for policy in candidates)]
    if len(set(policy_ids)) != len(policy_ids):
        raise ValueError("behavior and candidate policy ids must be unique")
    normalized_direction = _text(direction, "direction", 16).lower()
    if normalized_direction not in {"maximize", "minimize"}:
        raise ValueError("direction must be maximize or minimize")
    normalized_source = _text(source_kind, "source_kind", 32).lower()
    if normalized_source not in {"human_attestation", "project_event"}:
        raise ValueError("source_kind must be human_attestation or project_event")
    event_id = _uuid(source_event_id, "source_event_id") if source_event_id else None
    if normalized_source == "project_event" and event_id is None:
        raise ValueError("source_event_id is required for source_kind=project_event")
    if normalized_source == "human_attestation" and event_id is not None:
        raise ValueError("source_event_id is only allowed for source_kind=project_event")
    normalized_unit = str(unit or "").strip()
    if len(normalized_unit) > 64:
        raise ValueError("unit exceeds 64 characters")
    normalized_note = str(note or "").strip()
    if len(normalized_note) > 1_000:
        raise ValueError("note exceeds 1000 characters")
    return {
        "schema": PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA,
        "assignment_id": _uuid(assignment_id or uuid4(), "assignment_id"),
        "objective": {
            "metric_id": _text(metric_id, "metric_id", 160),
            "direction": normalized_direction,
            "unit": normalized_unit or None,
        },
        "actions": normalized_actions,
        "chosen_action_id": chosen,
        "behavior_policy": behavior,
        "candidate_policies": candidates,
        "decided_at": _timestamp(decided_at, "decided_at"),
        "source": {
            "kind": normalized_source,
            "event_id": event_id,
            "evidence_refs": _evidence_refs(evidence_refs),
        },
        "links": _links(links),
        "note": normalized_note or None,
    }


def build_project_policy_evaluation_request(
    *,
    behavior_policy_id: Any,
    candidate_policy_id: Any,
    metric_id: Any,
    pairs: Sequence[Mapping[str, Any]],
    evaluation_id: Any = None,
    note: Any = None,
) -> dict[str, Any]:
    """Build a bounded request from exact assignment/outcome receipt ids."""

    behavior = _text(behavior_policy_id, "behavior_policy_id", 160)
    candidate = _text(candidate_policy_id, "candidate_policy_id", 160)
    if behavior == candidate:
        raise ValueError("candidate_policy_id must differ from behavior_policy_id")
    if isinstance(pairs, (str, bytes)) or not isinstance(pairs, Sequence):
        raise ValueError("pairs must be an array")
    if len(pairs) < 20 or len(pairs) > 2_000:
        raise ValueError("pairs must contain between 20 and 2000 receipt pairs")
    assignments: set[str] = set()
    outcomes: set[str] = set()
    normalized_pairs: list[dict[str, str]] = []
    for index, value in enumerate(pairs):
        if not isinstance(value, Mapping):
            raise ValueError(f"pairs[{index}] must be an object")
        assignment = _uuid(
            value.get("assignment_receipt_id"),
            f"pairs[{index}].assignment_receipt_id",
        )
        outcome = _uuid(
            value.get("outcome_receipt_id"),
            f"pairs[{index}].outcome_receipt_id",
        )
        if assignment in assignments:
            raise ValueError("pairs require unique assignment_receipt_id values")
        if outcome in outcomes:
            raise ValueError("pairs require unique outcome_receipt_id values")
        assignments.add(assignment)
        outcomes.add(outcome)
        normalized_pairs.append({
            "assignment_receipt_id": assignment,
            "outcome_receipt_id": outcome,
        })
    normalized_note = str(note or "").strip()
    if len(normalized_note) > 1_000:
        raise ValueError("note exceeds 1000 characters")
    return {
        "schema": PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA,
        "evaluation_id": _uuid(evaluation_id or uuid4(), "evaluation_id"),
        "behavior_policy_id": behavior,
        "candidate_policy_id": candidate,
        "metric_id": _text(metric_id, "metric_id", 160),
        "pairs": normalized_pairs,
        "note": normalized_note or None,
    }


__all__ = [
    "PROJECT_POLICY_ASSIGNMENT_LEDGER_SCHEMA",
    "PROJECT_POLICY_ASSIGNMENT_OBSERVATION_SCHEMA",
    "PROJECT_POLICY_ASSIGNMENT_RECEIPT_SCHEMA",
    "PROJECT_POLICY_OFFLINE_EVALUATION_LEDGER_SCHEMA",
    "PROJECT_POLICY_OFFLINE_EVALUATION_PAIR_REQUEST_SCHEMA",
    "PROJECT_POLICY_OFFLINE_EVALUATION_RECEIPT_SCHEMA",
    "PROJECT_STRATEGY_LAB_SCHEMA",
    "build_project_policy_assignment",
    "build_project_policy_evaluation_request",
]
