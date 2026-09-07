"""Typed request helpers for the shared Project Outcome Ledger."""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid4


PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA = (
    "lightbulb.project_business_outcome_observation.v1"
)
PROJECT_BUSINESS_OUTCOME_RECEIPT_SCHEMA = "lightbulb.project_business_outcome_receipt.v1"
PROJECT_BUSINESS_OUTCOME_LEDGER_SCHEMA = "lightbulb.project_business_outcome_ledger.v1"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$")
_LINK_KEYS = frozenset(
    {
        "action_receipt_id",
        "approval_receipt_id",
        "skill_invocation_id",
        "policy_id",
        "hypothesis_id",
        "policy_assignment_receipt_id",
        "mission_run_receipt_id",
    }
)


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


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a finite number") from exc
    if not math.isfinite(result) or abs(result) > 1e30:
        raise ValueError(f"{field} must be a finite supported number")
    return result


def _timestamp(value: Any) -> str:
    if value is None or not str(value).strip():
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    normalized = _text(value, "observed_at", 80)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("observed_at must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _evidence_refs(values: Sequence[Any] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError("evidence_refs must be an array")
    if len(values) > 16:
        raise ValueError("evidence_refs may contain at most 16 items")
    result: list[str] = []
    for value in values:
        normalized = _text(value, "evidence_refs item", 256)
        if not _SAFE_REF.fullmatch(normalized):
            raise ValueError("evidence_refs item contains unsupported characters")
        if normalized not in result:
            result.append(normalized)
    return result


def _links(values: Mapping[str, Any] | None) -> dict[str, str]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise ValueError("links must be an object")
    unexpected = sorted(set(values) - _LINK_KEYS)
    if unexpected:
        raise ValueError(f"links contains unsupported keys: {unexpected}")
    result: dict[str, str] = {}
    for key in sorted(values):
        if values[key] is None or not str(values[key]).strip():
            continue
        normalized = _text(values[key], f"links.{key}", 256)
        if not _SAFE_REF.fullmatch(normalized):
            raise ValueError(f"links.{key} contains unsupported characters")
        result[key] = normalized
    return result


def build_project_business_outcome_observation(
    *,
    metric_id: Any,
    metric_label: Any,
    direction: Any,
    baseline_value: Any,
    observed_value: Any,
    unit: Any = None,
    observed_at: Any = None,
    observation_id: Any = None,
    source_kind: str = "human_attestation",
    source_event_id: Any = None,
    evidence_refs: Sequence[Any] | None = None,
    links: Mapping[str, Any] | None = None,
    note: Any = None,
) -> dict[str, Any]:
    """Build the exact bounded body accepted by human and agent ledger paths."""

    metric_key = _text(metric_id, "metric_id", 128)
    if not _SAFE_ID.fullmatch(metric_key):
        raise ValueError("metric_id contains unsupported characters")
    normalized_direction = _text(direction, "direction", 20).lower()
    if normalized_direction not in {"maximize", "minimize"}:
        raise ValueError("direction must be maximize or minimize")
    normalized_source = _text(source_kind, "source_kind", 40).lower()
    if normalized_source not in {"human_attestation", "project_event"}:
        raise ValueError("source_kind must be human_attestation or project_event")
    event_id = _uuid(source_event_id, "source_event_id") if source_event_id else None
    if normalized_source == "project_event" and event_id is None:
        raise ValueError("source_event_id is required for source_kind=project_event")
    if normalized_source == "human_attestation" and event_id is not None:
        raise ValueError("source_event_id is only allowed for source_kind=project_event")
    normalized_note = str(note or "").strip()
    if len(normalized_note) > 1_000:
        raise ValueError("note exceeds 1000 characters")
    normalized_unit = str(unit or "").strip()
    if len(normalized_unit) > 40:
        raise ValueError("unit exceeds 40 characters")

    return {
        "schema": PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA,
        "observation_id": _uuid(observation_id or uuid4(), "observation_id"),
        "metric": {
            "id": metric_key,
            "label": _text(metric_label, "metric_label", 160),
            "direction": normalized_direction,
            "unit": normalized_unit or None,
            "baseline_value": _number(baseline_value, "baseline_value"),
            "observed_value": _number(observed_value, "observed_value"),
        },
        "observed_at": _timestamp(observed_at),
        "source": {
            "kind": normalized_source,
            "event_id": event_id,
            "evidence_refs": _evidence_refs(evidence_refs),
        },
        "links": _links(links),
        "note": normalized_note or None,
    }


__all__ = [
    "PROJECT_BUSINESS_OUTCOME_LEDGER_SCHEMA",
    "PROJECT_BUSINESS_OUTCOME_OBSERVATION_SCHEMA",
    "PROJECT_BUSINESS_OUTCOME_RECEIPT_SCHEMA",
    "build_project_business_outcome_observation",
]
