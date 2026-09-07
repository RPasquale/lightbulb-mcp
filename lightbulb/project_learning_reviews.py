"""Human-reviewed shadow-learning admission for exact project mission receipts."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4


PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA = "lightbulb.project_learning_review_request.v1"
PROJECT_LEARNING_REVIEW_RECEIPT_SCHEMA = "lightbulb.project_learning_review_receipt.v1"
PROJECT_LEARNING_REVIEW_LEDGER_SCHEMA = "lightbulb.project_learning_review_ledger.v1"

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$")
_DECISIONS = frozenset(
    {
        "admit_shadow_training_observation",
        "reject_learning_candidate",
        "defer_for_more_evidence",
    }
)
_SKILL_ARMS = frozenset({"no_skill", "single_skill", "skill_combination"})


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


def _references(
    values: Sequence[Any] | None,
    field: str,
    maximum: int,
) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be an array")
    if len(values) > maximum:
        raise ValueError(f"{field} may contain at most {maximum} items")
    result: list[str] = []
    for value in values:
        normalized = _text(value, f"{field} item", 256)
        if _SAFE_REF.fullmatch(normalized) is None:
            raise ValueError(f"{field} item contains unsupported characters")
        if normalized not in result:
            result.append(normalized)
    return result


def build_project_learning_review_request(
    *,
    mission_run_receipt_id: Any,
    mission_action_receipt_id: Any,
    outcome_receipt_id: Any,
    decision: Any,
    skill_trial_arm: Any,
    selected_skill_ids: Sequence[Any] | None,
    label: Any,
    reason: Any,
    review_id: Any = None,
    evidence_refs: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Grade one exact mission chain for shadow training; never update live state."""

    normalized_decision = _text(decision, "decision", 80).lower()
    if normalized_decision not in _DECISIONS:
        raise ValueError("decision is not supported")
    normalized_label = _text(label, "label", 40).lower()
    if normalized_decision == "admit_shadow_training_observation":
        if normalized_label not in {"helped", "hurt"}:
            raise ValueError("admitted shadow observations require label helped or hurt")
    elif normalized_label != "inconclusive":
        raise ValueError("rejected or deferred evidence must remain inconclusive")

    arm = _text(skill_trial_arm, "skill_trial_arm", 40).lower()
    if arm not in _SKILL_ARMS:
        raise ValueError(
            "skill_trial_arm must be no_skill, single_skill, or skill_combination"
        )
    skill_ids = _references(selected_skill_ids, "selected_skill_ids", 8)
    if (
        (arm == "no_skill" and skill_ids)
        or (arm == "single_skill" and len(skill_ids) != 1)
        or (arm == "skill_combination" and len(skill_ids) < 2)
    ):
        raise ValueError("selected_skill_ids must match skill_trial_arm")
    normalized_reason = _text(reason, "reason", 1_000)
    if len(normalized_reason) < 12:
        raise ValueError("reason must explain why the evidence should or should not count")

    return {
        "schema": PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA,
        "review_id": _uuid(review_id or uuid4(), "review_id"),
        "mission_run_receipt_id": _uuid(
            mission_run_receipt_id, "mission_run_receipt_id"
        ),
        "mission_action_receipt_id": _uuid(
            mission_action_receipt_id, "mission_action_receipt_id"
        ),
        "outcome_receipt_id": _uuid(outcome_receipt_id, "outcome_receipt_id"),
        "decision": normalized_decision,
        "skill_trial": {
            "arm": arm,
            "selected_skill_ids": skill_ids,
        },
        "label": normalized_label,
        "reason": normalized_reason,
        "evidence_refs": _references(evidence_refs, "evidence_refs", 16),
    }


__all__ = [
    "PROJECT_LEARNING_REVIEW_LEDGER_SCHEMA",
    "PROJECT_LEARNING_REVIEW_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_REVIEW_REQUEST_SCHEMA",
    "build_project_learning_review_request",
]
