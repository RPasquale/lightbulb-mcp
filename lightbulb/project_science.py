"""Typed builders for the shared Project Science Ledger.

The ledger records a scope-verified lineage from hypothesis through search,
data, model, and solver artifacts. A receipt proves identity and predecessor
scope; it does not prove scientific validity, causality, or action authority.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import UUID, uuid4


PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA = (
    "lightbulb.project_science_evidence_observation.v1"
)
PROJECT_SCIENCE_EVIDENCE_RECEIPT_SCHEMA = "lightbulb.project_science_evidence_receipt.v1"
PROJECT_SCIENCE_LEDGER_SCHEMA = "lightbulb.project_science_ledger.v1"

PROJECT_SCIENCE_STAGES = (
    "hypothesis",
    "search",
    "data_engineering",
    "machine_learning_and_serving",
    "solver_and_optimal_control",
)
_ARTIFACT_KINDS_BY_STAGE = {
    "hypothesis": {"hypothesis"},
    "search": {"source_collection", "research_report"},
    "data_engineering": {"dataset", "etl_pipeline", "feature_matrix"},
    "machine_learning_and_serving": {
        "experiment",
        "model_candidate",
        "evaluation_report",
        "serving_endpoint",
    },
    "solver_and_optimal_control": {"solver_run", "policy_candidate", "control_model"},
}
_PRODUCER_ROLES = {
    "human_researcher",
    "data_scientist",
    "search_data_engineer",
    "ml_engineer",
    "rl_control_engineer",
    "project_agent",
}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:/._#@~-]{0,255}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _text(value: Any, field: str, maximum: int) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return normalized


def _safe(value: Any, field: str, pattern: re.Pattern[str], maximum: int = 256) -> str:
    normalized = _text(value, field, maximum)
    if pattern.fullmatch(normalized) is None:
        raise ValueError(f"{field} contains unsupported characters")
    return normalized


def _uuid(value: Any, field: str) -> str:
    try:
        return str(UUID(_text(value, field, 64)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID") from exc


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


def _list(
    values: Sequence[Any] | None,
    field: str,
    maximum: int,
    pattern: re.Pattern[str],
) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be an array")
    if len(values) > maximum:
        raise ValueError(f"{field} may contain at most {maximum} items")
    result: list[str] = []
    for value in values:
        item = _safe(value, f"{field} item", pattern)
        if item not in result:
            result.append(item)
    return result


def _parent_receipts(values: Sequence[Any] | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError("parent_receipt_ids must be an array")
    if len(values) > 8:
        raise ValueError("parent_receipt_ids may contain at most 8 items")
    result = [_uuid(value, "parent_receipt_ids item") for value in values]
    if len(set(result)) != len(result):
        raise ValueError("parent_receipt_ids must be unique")
    return result


def build_project_science_evidence_observation(
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
    tool_names: Sequence[Any] | None = None,
    skill_ids: Sequence[Any] | None = None,
    parent_receipt_ids: Sequence[Any] | None = None,
    artifact_schema: Any = None,
    observed_at: Any = None,
    evidence_id: Any = None,
    source_kind: str = "human_attestation",
    source_event_id: Any = None,
    evidence_refs: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Build the exact bounded body accepted by human and worker ledger paths."""

    normalized_stage = _text(stage, "stage", 80).lower()
    if normalized_stage not in PROJECT_SCIENCE_STAGES:
        raise ValueError(f"stage must be one of {', '.join(PROJECT_SCIENCE_STAGES)}")
    normalized_kind = _text(artifact_kind, "artifact_kind", 80).lower()
    if normalized_kind not in _ARTIFACT_KINDS_BY_STAGE[normalized_stage]:
        raise ValueError(f"artifact_kind is not allowed for stage={normalized_stage}")
    normalized_direction = _text(expected_direction, "expected_direction", 20).lower()
    if normalized_direction not in {"increase", "decrease", "unknown"}:
        raise ValueError("expected_direction must be increase, decrease, or unknown")
    normalized_role = _text(producer_role, "producer_role", 80).lower()
    if normalized_role not in _PRODUCER_ROLES:
        raise ValueError("producer_role is not supported")
    normalized_digest = _text(
        artifact_digest_sha256,
        "artifact_digest_sha256",
        64,
    ).lower()
    if _SHA256.fullmatch(normalized_digest) is None:
        raise ValueError("artifact_digest_sha256 must be a lowercase SHA-256 hex digest")
    normalized_source = _text(source_kind, "source_kind", 40).lower()
    if normalized_source not in {"human_attestation", "project_event"}:
        raise ValueError("source_kind must be human_attestation or project_event")
    event_id = _uuid(source_event_id, "source_event_id") if source_event_id else None
    if normalized_source == "project_event" and event_id is None:
        raise ValueError("source_event_id is required for source_kind=project_event")
    if normalized_source == "human_attestation" and event_id is not None:
        raise ValueError("source_event_id is only allowed for source_kind=project_event")
    parents = _parent_receipts(parent_receipt_ids)
    if normalized_stage == "hypothesis" and parents:
        raise ValueError("hypothesis evidence cannot have parent receipts")
    if normalized_stage != "hypothesis" and not parents:
        raise ValueError(f"stage={normalized_stage} requires at least one parent receipt")
    normalized_schema = str(artifact_schema or "").strip()
    if normalized_schema:
        normalized_schema = _safe(normalized_schema, "artifact_schema", _SAFE_REF)

    return {
        "schema": PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA,
        "evidence_id": _uuid(evidence_id or uuid4(), "evidence_id"),
        "stage": normalized_stage,
        "finding": {
            "summary": _text(summary, "summary", 1_000),
            "business_metric_id": _safe(business_metric_id, "business_metric_id", _SAFE_ID),
            "expected_direction": normalized_direction,
        },
        "artifact": {
            "kind": normalized_kind,
            "system": _safe(artifact_system, "artifact_system", _SAFE_ID),
            "reference": _safe(artifact_reference, "artifact_reference", _SAFE_REF),
            "schema": normalized_schema or None,
            "digest_sha256": normalized_digest,
        },
        "method": {
            "producer_role": normalized_role,
            "tool_names": _list(tool_names, "tool_names", 16, _SAFE_ID),
            "skill_ids": _list(skill_ids, "skill_ids", 8, _SAFE_ID),
        },
        "observed_at": _timestamp(observed_at),
        "source": {
            "kind": normalized_source,
            "event_id": event_id,
            "evidence_refs": _list(evidence_refs, "evidence_refs", 16, _SAFE_REF),
        },
        "parent_receipt_ids": parents,
    }


__all__ = [
    "PROJECT_SCIENCE_EVIDENCE_OBSERVATION_SCHEMA",
    "PROJECT_SCIENCE_EVIDENCE_RECEIPT_SCHEMA",
    "PROJECT_SCIENCE_LEDGER_SCHEMA",
    "PROJECT_SCIENCE_STAGES",
    "build_project_science_evidence_observation",
]
