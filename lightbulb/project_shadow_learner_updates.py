"""Bounded Project shadow-learner update contracts.

The public SDK can construct the exact worker request and inspect its receipt
ledger. It deliberately exposes no HTTP mutation method: applying or rolling
back a candidate requires the internal worker route, an AgentContext envelope,
and an explicit confirmation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID


PROJECT_SHADOW_LEARNER_UPDATE_REQUEST_SCHEMA = (
    "lightbulb.project_shadow_learner_update_request.v1"
)
PROJECT_SHADOW_LEARNER_UPDATE_RECEIPT_SCHEMA = (
    "lightbulb.project_shadow_learner_update_receipt.v1"
)
PROJECT_SHADOW_LEARNER_ROLLBACK_REQUEST_SCHEMA = (
    "lightbulb.project_shadow_learner_rollback_request.v1"
)
PROJECT_SHADOW_LEARNER_ROLLBACK_RECEIPT_SCHEMA = (
    "lightbulb.project_shadow_learner_rollback_receipt.v1"
)
PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA = (
    "lightbulb.project_shadow_learner_update_ledger.v1"
)
PROJECT_SHADOW_LEARNER_UPDATE_CONFIRMATION = (
    "apply_bounded_project_shadow_learner_update"
)
PROJECT_SHADOW_LEARNER_ROLLBACK_CONFIRMATION = (
    "rollback_bounded_project_shadow_learner_update"
)
PROJECT_SHADOW_LEARNER_ALLOWED_MUTATION_PATHS = (
    "skill_template.project_shadow_learning",
    "last_validated_at",
    "updated_at",
)

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TARGET_FIELDS = {
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


def _text(value: Any, field: str, maximum: int = 255) -> str:
    normalized = str(value or "").strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(f"{field} must be printable text")
    return normalized


def _uuid(value: Any, field: str) -> str:
    try:
        return str(UUID(_text(value, field, 80)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _sha(value: Any, field: str) -> str:
    normalized = str(value or "").strip().lower()
    if _SHA256.fullmatch(normalized) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return normalized


def build_project_shadow_learner_target(
    *,
    skill_id: Any,
    skill_handle: Any,
    expected_active_skill_revision: Any,
    expected_active_instruction_sha256: Any,
    expected_champion_candidate_id: Any,
    expected_champion_instruction_sha256: Any,
) -> dict[str, Any]:
    """Build the only supported mutation target: one isolated Memory shadow slot."""

    if (
        isinstance(expected_active_skill_revision, bool)
        or not isinstance(expected_active_skill_revision, int)
        or not 1 <= expected_active_skill_revision <= 2_147_483_647
    ):
        raise ValueError("expected_active_skill_revision must be a positive integer")
    return {
        "kind": "memory_gepa_skill_instruction",
        "skill_id": _uuid(skill_id, "skill_id"),
        "skill_handle": _text(skill_handle, "skill_handle"),
        "expected_active_skill_revision": expected_active_skill_revision,
        "expected_active_instruction_sha256": _sha(
            expected_active_instruction_sha256,
            "expected_active_instruction_sha256",
        ),
        "expected_champion_candidate_id": _text(
            expected_champion_candidate_id,
            "expected_champion_candidate_id",
        ),
        "expected_champion_instruction_sha256": _sha(
            expected_champion_instruction_sha256,
            "expected_champion_instruction_sha256",
        ),
        "environment": "shadow",
        "max_shadow_revision_delta": 1,
        "allowed_mutation_paths": list(
            PROJECT_SHADOW_LEARNER_ALLOWED_MUTATION_PATHS
        ),
    }


def normalize_project_shadow_learner_target(value: Any) -> dict[str, Any]:
    """Reject target widening before a worker can call the internal route."""

    if not isinstance(value, Mapping) or set(value) != _TARGET_FIELDS:
        raise ValueError("target must contain the exact bounded shadow fields")
    if (
        value.get("kind") != "memory_gepa_skill_instruction"
        or value.get("environment") != "shadow"
        or value.get("max_shadow_revision_delta") != 1
        or isinstance(value.get("allowed_mutation_paths"), (str, bytes))
        or not isinstance(value.get("allowed_mutation_paths"), Sequence)
        or tuple(value.get("allowed_mutation_paths") or ())
        != PROJECT_SHADOW_LEARNER_ALLOWED_MUTATION_PATHS
    ):
        raise ValueError("target exceeds the bounded Memory shadow mutation ceiling")
    return build_project_shadow_learner_target(
        skill_id=value.get("skill_id"),
        skill_handle=value.get("skill_handle"),
        expected_active_skill_revision=value.get("expected_active_skill_revision"),
        expected_active_instruction_sha256=value.get(
            "expected_active_instruction_sha256"
        ),
        expected_champion_candidate_id=value.get(
            "expected_champion_candidate_id"
        ),
        expected_champion_instruction_sha256=value.get(
            "expected_champion_instruction_sha256"
        ),
    )


def build_project_shadow_learner_update_request(
    *,
    update_id: Any,
    admission_receipt_id: Any,
    target: Any,
    confirm_update: bool = False,
) -> dict[str, Any]:
    """Build an immutable apply request without sending it."""

    if confirm_update is not True:
        raise ValueError(
            "confirm_update=True is required for a bounded shadow learner update"
        )
    return {
        "schema": PROJECT_SHADOW_LEARNER_UPDATE_REQUEST_SCHEMA,
        "update_id": _uuid(update_id, "update_id"),
        "admission_receipt_id": _uuid(
            admission_receipt_id, "admission_receipt_id"
        ),
        "target": normalize_project_shadow_learner_target(target),
        "confirmation": PROJECT_SHADOW_LEARNER_UPDATE_CONFIRMATION,
    }


def build_project_shadow_learner_rollback_request(
    *,
    rollback_id: Any,
    confirm_rollback: bool = False,
) -> dict[str, Any]:
    """Build an immutable rollback request without supplying a replacement state."""

    if confirm_rollback is not True:
        raise ValueError(
            "confirm_rollback=True is required for a bounded shadow learner rollback"
        )
    return {
        "schema": PROJECT_SHADOW_LEARNER_ROLLBACK_REQUEST_SCHEMA,
        "rollback_id": _uuid(rollback_id, "rollback_id"),
        "confirmation": PROJECT_SHADOW_LEARNER_ROLLBACK_CONFIRMATION,
    }


__all__ = [
    "PROJECT_SHADOW_LEARNER_ALLOWED_MUTATION_PATHS",
    "PROJECT_SHADOW_LEARNER_ROLLBACK_CONFIRMATION",
    "PROJECT_SHADOW_LEARNER_ROLLBACK_RECEIPT_SCHEMA",
    "PROJECT_SHADOW_LEARNER_ROLLBACK_REQUEST_SCHEMA",
    "PROJECT_SHADOW_LEARNER_UPDATE_CONFIRMATION",
    "PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA",
    "PROJECT_SHADOW_LEARNER_UPDATE_RECEIPT_SCHEMA",
    "PROJECT_SHADOW_LEARNER_UPDATE_REQUEST_SCHEMA",
    "build_project_shadow_learner_rollback_request",
    "build_project_shadow_learner_target",
    "build_project_shadow_learner_update_request",
    "normalize_project_shadow_learner_target",
]
