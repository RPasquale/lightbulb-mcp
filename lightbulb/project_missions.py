"""Bounded mission-run requests for the shared human/agent project campaign."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID, uuid4


PROJECT_MISSION_RUN_START_SCHEMA = "lightbulb.project_mission_run_start.v1"
PROJECT_MISSION_RUN_RECEIPT_SCHEMA = "lightbulb.project_mission_run_receipt.v1"
PROJECT_MISSION_ACTION_BINDING_SCHEMA = "lightbulb.project_mission_action_binding.v1"
PROJECT_MISSION_ACTION_RECEIPT_SCHEMA = "lightbulb.project_mission_action_receipt.v1"
PROJECT_MISSION_RUN_LEDGER_SCHEMA = "lightbulb.project_mission_run_ledger.v1"

_MISSION_BRIEFING_SCHEMA = "lightbulb.project_mission_briefing.v1"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$")
_PLAY_STYLES = frozenset(
    {
        "guided_human_in_the_loop",
        "proactive_copilot",
        "autonomous_shadow",
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


def _safe(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    normalized = _text(value, field, 256)
    if not pattern.fullmatch(normalized):
        raise ValueError(f"{field} contains unsupported characters")
    return normalized


def _uuid(value: Any, field: str) -> str:
    try:
        return str(UUID(_text(value, field, 64)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _refs(values: Sequence[Any] | None, field: str, maximum: int) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be an array")
    if len(values) > maximum:
        raise ValueError(f"{field} may contain at most {maximum} items")
    result: list[str] = []
    for value in values:
        item = _safe(value, f"{field} item", _SAFE_REF)
        if item not in result:
            result.append(item)
    return result


def build_project_mission_run_start(
    *,
    mission_briefing: Mapping[str, Any],
    run_id: Any = None,
    play_style_id: Any = None,
    skill_trial_arm: Any = None,
    selected_skill_ids: Sequence[Any] | None = None,
    context_source_refs: Sequence[Any] | None = None,
    note: Any = None,
) -> dict[str, Any]:
    """Lock the exact current briefing and planned shadow loadout before action."""

    briefing = _mapping(mission_briefing, "mission_briefing")
    if briefing.get("schema") != _MISSION_BRIEFING_SCHEMA:
        raise ValueError(f"mission_briefing.schema must be {_MISSION_BRIEFING_SCHEMA}")
    mission = _mapping(briefing.get("mission"), "mission_briefing.mission")
    player = _mapping(briefing.get("player"), "mission_briefing.player")
    evidence = _mapping(briefing.get("evidence"), "mission_briefing.evidence")
    initiative = _mapping(briefing.get("initiative"), "mission_briefing.initiative")
    agent = _mapping(briefing.get("agent"), "mission_briefing.agent")
    briefing_skill = _mapping(
        agent.get("skill_trial"), "mission_briefing.agent.skill_trial"
    )

    style = _safe(
        play_style_id or initiative.get("mode_id"), "play_style_id", _SAFE_ID
    )
    if style not in _PLAY_STYLES:
        raise ValueError("play_style_id is not supported")
    arm = _safe(
        skill_trial_arm or briefing_skill.get("next_shadow_arm") or "no_skill",
        "skill_trial_arm",
        _SAFE_ID,
    )
    if arm not in _SKILL_ARMS:
        raise ValueError(
            "skill_trial_arm must be no_skill, single_skill, or skill_combination"
        )
    skills = _refs(
        selected_skill_ids
        if selected_skill_ids is not None
        else briefing_skill.get("selected_skill_ids"),
        "selected_skill_ids",
        8,
    )
    if (
        (arm == "no_skill" and skills)
        or (arm == "single_skill" and len(skills) != 1)
        or (arm == "skill_combination" and len(skills) < 2)
    ):
        raise ValueError("selected_skill_ids must match skill_trial_arm")
    normalized_note = str(note or "").strip()
    if len(normalized_note) > 1_000:
        raise ValueError("note exceeds 1000 characters")

    return {
        "schema": PROJECT_MISSION_RUN_START_SCHEMA,
        "run_id": _uuid(run_id or uuid4(), "run_id"),
        "mission": {
            "id": _safe(mission.get("id"), "mission.id", _SAFE_ID),
            "title": _text(mission.get("title"), "mission.title", 240),
            "phase": _safe(mission.get("phase"), "mission.phase", _SAFE_ID),
            "source_ref": _safe(
                mission.get("source_ref"), "mission.source_ref", _SAFE_REF
            ),
            "briefing_schema": _MISSION_BRIEFING_SCHEMA,
            "expected_result": _safe(
                player.get("expected_result"), "player.expected_result", _SAFE_ID
            ),
            "completion_receipt": _safe(
                evidence.get("completion_receipt"),
                "evidence.completion_receipt",
                _SAFE_REF,
            ),
        },
        "play_style_id": style,
        "skill_trial": {
            "arm": arm,
            "selected_skill_ids": skills,
        },
        "context_source_refs": _refs(
            context_source_refs, "context_source_refs", 16
        ),
        "note": normalized_note or None,
    }


def build_project_mission_action_binding(
    *,
    mission_run_receipt_id: Any,
    action_event_id: Any,
    binding_id: Any = None,
    note: Any = None,
) -> dict[str, Any]:
    """Bind one later same-project action event to a pre-existing mission run."""

    normalized_note = str(note or "").strip()
    if len(normalized_note) > 1_000:
        raise ValueError("note exceeds 1000 characters")
    return {
        "schema": PROJECT_MISSION_ACTION_BINDING_SCHEMA,
        "binding_id": _uuid(binding_id or uuid4(), "binding_id"),
        "mission_run_receipt_id": _uuid(
            mission_run_receipt_id, "mission_run_receipt_id"
        ),
        "action_event_id": _uuid(action_event_id, "action_event_id"),
        "note": normalized_note or None,
    }


__all__ = [
    "PROJECT_MISSION_ACTION_BINDING_SCHEMA",
    "PROJECT_MISSION_ACTION_RECEIPT_SCHEMA",
    "PROJECT_MISSION_RUN_LEDGER_SCHEMA",
    "PROJECT_MISSION_RUN_RECEIPT_SCHEMA",
    "PROJECT_MISSION_RUN_START_SCHEMA",
    "build_project_mission_action_binding",
    "build_project_mission_run_start",
]
