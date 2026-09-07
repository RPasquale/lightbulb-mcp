"""Validation for the server-owned project snapshot.

The snapshot is a read-only projection assembled by Lightbulb's authenticated
project service.  It is deliberately distinct from ``project_game.py``'s local
orientation helper: callers may inspect a canonical snapshot, but cannot use
caller-supplied plan JSON to manufacture scope, evidence, or authority.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID


PROJECT_GAME_SNAPSHOT_SCHEMA = "lightbulb.project_game_snapshot.v1"
PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES = 256 * 1024

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "generated_at",
        "snapshot_digest",
        "scope",
        "project",
        "campaign",
        "wealth",
        "technical",
        "mission",
        "skill_trial",
        "evidence_assets",
        "resources",
        "truth_boundary",
        "authority",
    }
)
_SCOPE_FIELDS = frozenset(
    {"tenant_id", "company_id", "project_id", "exact_scope_verified"}
)
_PROJECT_FIELDS = frozenset({"id", "name", "status", "updated_at", "version"})
_CAMPAIGN_FIELDS = frozenset(
    {
        "status",
        "play_style_id",
        "play_style_semantics",
        "win_condition",
        "win_condition_source",
        "measurement_status",
        "current_phase",
        "next_move",
    }
)
_WEALTH_FIELDS = frozenset(
    {
        "status",
        "metric_id",
        "metric_label",
        "direction",
        "unit",
        "baseline_value",
        "observed_value",
        "delta",
        "movement",
        "observed_at",
        "receipt_id",
        "numeric_score_generated",
        "provenance",
    }
)
_WEALTH_PROVENANCE_FIELDS = frozenset(
    {
        "source_kind",
        "trust_tier",
        "scope_bound",
        "source_event_id",
        "evidence_refs",
        "external_source_truth_verified",
        "causality_proven",
    }
)
_TECHNICAL_FIELDS = frozenset(
    {
        "status",
        "reason",
        "exact_project_telemetry_available",
        "tenant_aggregate_excluded",
    }
)
_MISSION_FIELDS = frozenset(
    {
        "status",
        "source_kind",
        "run_receipt_id",
        "action_receipt_id",
        "id",
        "title",
        "phase",
        "source_ref",
        "currentness_verified",
        "completion_inferred",
    }
)
_SKILL_TRIAL_FIELDS = frozenset(
    {
        "status",
        "arm",
        "selected_skill_ids",
        "source_receipt_id",
        "execution_verified",
        "confidence_update_authorized",
        "promotion_authorized",
    }
)
_EVIDENCE_ASSET_FIELDS = frozenset(
    {
        "business_outcome_receipts",
        "mission_run_receipts",
        "mission_action_receipts",
        "science_evidence_receipts",
        "skill_match_receipts",
        "training_pack_receipts",
    }
)
_RESOURCE_FIELDS = frozenset(
    {
        "project",
        "business_cockpit",
        "business_outcomes",
        "mission_runs",
        "science_evidence",
        "skill_matches",
        "training_packs",
    }
)
_RESOURCE_SUFFIXES = {
    "project": "",
    "business_cockpit": "/business-cockpit",
    "business_outcomes": "/business-outcomes",
    "mission_runs": "/mission-runs",
    "science_evidence": "/science-evidence",
    "skill_matches": "/skill-matches",
    "training_packs": "/training-packs",
}
_TRUTH_BOUNDARY_FIELDS = frozenset(
    {
        "exact_scope_verified",
        "external_source_truth_verified",
        "causality_proven",
        "policy_optimality_verified",
        "learning_admitted",
        "exact_project_telemetry_verified",
    }
)
PROJECT_GAME_SNAPSHOT_LOCKED_AUTHORITY = MappingProxyType(
    {
        "orientation_only": True,
        "human_gate_required": True,
        "mutation_authorized": False,
        "dispatch_authorized": False,
        "live_action_authorized": False,
        "learning_admission_authorized": False,
        "skill_or_policy_promotion_authorized": False,
    }
)


def _uuid(value: Any, field: str) -> str:
    try:
        normalized = str(UUID(str(value or "").strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a canonical UUID") from exc
    if str(value or "").strip().lower() != normalized:
        raise ValueError(f"{field} must be a canonical UUID")
    return normalized


def normalize_project_game_snapshot_uuid(value: Any, field: str) -> str:
    """Return a canonical lower-case UUID for snapshot paths and scope headers."""

    return _uuid(value, field)


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{field} keys must be strings")
    return value


def _exact_mapping(
    value: Any,
    field: str,
    fields: frozenset[str],
) -> Mapping[str, Any]:
    result = _mapping(value, field)
    if set(result) != fields:
        missing = sorted(fields - set(result))
        extra = sorted(set(result) - fields)
        raise ValueError(
            f"{field} fields do not match the canonical contract "
            f"(missing={missing}, extra={extra})"
        )
    return result


def _text(value: Any, field: str, *, maximum: int = 2_000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(f"{field} must be bounded printable text")
    return normalized


def _timestamp(value: Any, field: str) -> str:
    normalized = _text(value, field, maximum=80)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return normalized


def _optional_text(value: Any, field: str, *, maximum: int = 2_000) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum=maximum)


def _optional_uuid(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _uuid(value, field)


def _optional_timestamp(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _timestamp(value, field)


def _optional_number(value: Any, field: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a JSON number or null")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return value


def _string_list(value: Any, field: str, *, maximum_items: int) -> None:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ValueError(f"{field} must be a JSON string array")
    if len(value) > maximum_items:
        raise ValueError(f"{field} may contain at most {maximum_items} items")
    for index, item in enumerate(value):
        _text(item, f"{field}[{index}]", maximum=1_000)


def _assert_finite_json(value: Any, field: str = "snapshot") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must contain finite JSON values")
        return
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError(f"{field} keys must be strings")
        for key, nested in value.items():
            _assert_finite_json(nested, f"{field}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            _assert_finite_json(nested, f"{field}[{index}]")
        return
    raise ValueError(f"{field} must contain JSON-compatible values")


def _bounded_json_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    _assert_finite_json(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("snapshot must contain finite JSON values") from exc
    if len(encoded) > PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES:
        raise ValueError(
            "snapshot exceeds the bounded canonical response limit of "
            f"{PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES} bytes"
        )
    return json.loads(encoded)


def validate_project_game_snapshot(
    value: Any,
    *,
    expected_tenant_id: Any,
    expected_company_id: Any,
    expected_project_id: Any,
) -> dict[str, Any]:
    """Validate and detach one exact-scoped, non-authoritative snapshot.

    The expected scope comes from the authenticated SDK context, never from the
    response.  Any mismatch or widening fails closed before data is returned to
    the caller.
    """

    snapshot = _exact_mapping(value, "snapshot", _TOP_LEVEL_FIELDS)
    if snapshot.get("schema") != PROJECT_GAME_SNAPSHOT_SCHEMA:
        raise ValueError(f"snapshot.schema must equal {PROJECT_GAME_SNAPSHOT_SCHEMA}")

    expected_tenant = _uuid(expected_tenant_id, "expected_tenant_id")
    expected_company = _uuid(expected_company_id, "expected_company_id")
    expected_project = _uuid(expected_project_id, "expected_project_id")

    scope = _exact_mapping(snapshot.get("scope"), "snapshot.scope", _SCOPE_FIELDS)
    actual_scope = {
        "tenant_id": _uuid(scope.get("tenant_id"), "snapshot.scope.tenant_id"),
        "company_id": _uuid(scope.get("company_id"), "snapshot.scope.company_id"),
        "project_id": _uuid(scope.get("project_id"), "snapshot.scope.project_id"),
    }
    if actual_scope != {
        "tenant_id": expected_tenant,
        "company_id": expected_company,
        "project_id": expected_project,
    }:
        raise ValueError(
            "snapshot scope does not match the authenticated request scope"
        )
    if scope.get("exact_scope_verified") is not True:
        raise ValueError("snapshot.scope.exact_scope_verified must be true")

    project = _exact_mapping(
        snapshot.get("project"), "snapshot.project", _PROJECT_FIELDS
    )
    if _uuid(project.get("id"), "snapshot.project.id") != expected_project:
        raise ValueError("snapshot.project.id does not match the requested project")
    _text(project.get("name"), "snapshot.project.name", maximum=500)
    _text(project.get("status"), "snapshot.project.status", maximum=80)
    _timestamp(project.get("updated_at"), "snapshot.project.updated_at")
    version = project.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("snapshot.project.version must be a non-negative integer")

    campaign = _exact_mapping(
        snapshot.get("campaign"), "snapshot.campaign", _CAMPAIGN_FIELDS
    )
    for field in (
        "status",
        "play_style_id",
        "win_condition_source",
        "measurement_status",
        "current_phase",
    ):
        _text(campaign.get(field), f"snapshot.campaign.{field}", maximum=500)
    for field in ("play_style_semantics", "win_condition", "next_move"):
        _text(campaign.get(field), f"snapshot.campaign.{field}", maximum=2_000)

    wealth = _exact_mapping(snapshot.get("wealth"), "snapshot.wealth", _WEALTH_FIELDS)
    _text(wealth.get("status"), "snapshot.wealth.status", maximum=200)
    for field in ("metric_id", "metric_label", "direction", "unit", "movement"):
        _optional_text(wealth.get(field), f"snapshot.wealth.{field}", maximum=500)
    for field in ("baseline_value", "observed_value", "delta"):
        _optional_number(wealth.get(field), f"snapshot.wealth.{field}")
    _optional_timestamp(wealth.get("observed_at"), "snapshot.wealth.observed_at")
    _optional_uuid(wealth.get("receipt_id"), "snapshot.wealth.receipt_id")
    if wealth.get("numeric_score_generated") is not False:
        raise ValueError("snapshot.wealth.numeric_score_generated must be false")
    provenance = _exact_mapping(
        wealth.get("provenance"),
        "snapshot.wealth.provenance",
        _WEALTH_PROVENANCE_FIELDS,
    )
    _text(
        provenance.get("source_kind"),
        "snapshot.wealth.provenance.source_kind",
        maximum=200,
    )
    _text(
        provenance.get("trust_tier"),
        "snapshot.wealth.provenance.trust_tier",
        maximum=200,
    )
    if not isinstance(provenance.get("scope_bound"), bool):
        raise ValueError("snapshot.wealth.provenance.scope_bound must be boolean")
    _optional_uuid(
        provenance.get("source_event_id"),
        "snapshot.wealth.provenance.source_event_id",
    )
    _string_list(
        provenance.get("evidence_refs"),
        "snapshot.wealth.provenance.evidence_refs",
        maximum_items=50,
    )
    for field in ("external_source_truth_verified", "causality_proven"):
        if provenance.get(field) is not False:
            raise ValueError(f"snapshot.wealth.provenance.{field} must be false")

    technical = _exact_mapping(
        snapshot.get("technical"), "snapshot.technical", _TECHNICAL_FIELDS
    )
    _text(technical.get("status"), "snapshot.technical.status", maximum=200)
    _text(technical.get("reason"), "snapshot.technical.reason", maximum=1_000)
    if technical.get("exact_project_telemetry_available") is not False:
        raise ValueError(
            "snapshot.technical.exact_project_telemetry_available must be false"
        )
    if technical.get("tenant_aggregate_excluded") is not True:
        raise ValueError("snapshot.technical.tenant_aggregate_excluded must be true")

    mission = _exact_mapping(
        snapshot.get("mission"), "snapshot.mission", _MISSION_FIELDS
    )
    for field in ("status", "source_kind", "id", "title", "phase", "source_ref"):
        _text(mission.get(field), f"snapshot.mission.{field}", maximum=2_000)
    for field in ("run_receipt_id", "action_receipt_id"):
        _optional_uuid(mission.get(field), f"snapshot.mission.{field}")
    for field in ("currentness_verified", "completion_inferred"):
        if mission.get(field) is not False:
            raise ValueError(f"snapshot.mission.{field} must be false")

    skill_trial = _exact_mapping(
        snapshot.get("skill_trial"),
        "snapshot.skill_trial",
        _SKILL_TRIAL_FIELDS,
    )
    _text(skill_trial.get("status"), "snapshot.skill_trial.status", maximum=200)
    _optional_text(skill_trial.get("arm"), "snapshot.skill_trial.arm", maximum=500)
    _string_list(
        skill_trial.get("selected_skill_ids"),
        "snapshot.skill_trial.selected_skill_ids",
        maximum_items=8,
    )
    _optional_uuid(
        skill_trial.get("source_receipt_id"),
        "snapshot.skill_trial.source_receipt_id",
    )
    for field in (
        "execution_verified",
        "confidence_update_authorized",
        "promotion_authorized",
    ):
        if skill_trial.get(field) is not False:
            raise ValueError(f"snapshot.skill_trial.{field} must be false")

    evidence_assets = _exact_mapping(
        snapshot.get("evidence_assets"),
        "snapshot.evidence_assets",
        _EVIDENCE_ASSET_FIELDS,
    )
    for name, count in evidence_assets.items():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(
                f"snapshot.evidence_assets.{name} must be a non-negative integer"
            )
    if sum(evidence_assets.values()) > 100:
        raise ValueError(
            "snapshot.evidence_assets total may not exceed the bounded 100-receipt query"
        )

    resources = _exact_mapping(
        snapshot.get("resources"), "snapshot.resources", _RESOURCE_FIELDS
    )
    project_resource_prefix = f"/api/projects/{expected_project}"
    for name, path in resources.items():
        normalized_path = _text(path, f"snapshot.resources.{name}", maximum=1_000)
        expected_path = f"{project_resource_prefix}{_RESOURCE_SUFFIXES[name]}"
        if normalized_path != expected_path:
            raise ValueError(f"snapshot.resources.{name} must be a canonical API path")

    truth_boundary = _exact_mapping(
        snapshot.get("truth_boundary"),
        "snapshot.truth_boundary",
        _TRUTH_BOUNDARY_FIELDS,
    )
    if truth_boundary.get("exact_scope_verified") is not True:
        raise ValueError("snapshot.truth_boundary.exact_scope_verified must be true")
    if not all(isinstance(value, bool) for value in truth_boundary.values()):
        raise ValueError("snapshot.truth_boundary values must be booleans")
    for field in _TRUTH_BOUNDARY_FIELDS - {"exact_scope_verified"}:
        if truth_boundary.get(field) is not False:
            raise ValueError(f"snapshot.truth_boundary.{field} must be false")

    authority = _exact_mapping(
        snapshot.get("authority"),
        "snapshot.authority",
        frozenset(PROJECT_GAME_SNAPSHOT_LOCKED_AUTHORITY),
    )
    if dict(authority) != PROJECT_GAME_SNAPSHOT_LOCKED_AUTHORITY:
        raise ValueError("snapshot authority must remain read-only and human-gated")

    _timestamp(snapshot.get("generated_at"), "snapshot.generated_at")
    digest = str(snapshot.get("snapshot_digest") or "").strip()
    if _SHA256_RE.fullmatch(digest) is None:
        raise ValueError("snapshot.snapshot_digest must be a lowercase SHA-256 digest")

    return _bounded_json_copy(snapshot)


__all__ = [
    "PROJECT_GAME_SNAPSHOT_LOCKED_AUTHORITY",
    "PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES",
    "PROJECT_GAME_SNAPSHOT_SCHEMA",
    "normalize_project_game_snapshot_uuid",
    "validate_project_game_snapshot",
]
