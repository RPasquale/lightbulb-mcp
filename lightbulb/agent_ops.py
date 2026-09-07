"""Bounded contracts for the governed training-pair gateway.

The production Spring gateway is intentionally a readiness and status surface.
It does not admit, schedule, or launch training.  Keeping its response parsing
strict prevents a generic 503 (or a malformed success response) from being
mistaken for the stable admission-unavailable contract.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from lightbulb.errors import LightbulbError, ValidationError
from lightbulb.validators import validate_uuid


TRAINING_PAIR_PREFLIGHT_SCHEMA = "lightbulb.training_pair_preflight.v1"
TRAINING_PAIR_READINESS_SCHEMA = "lightbulb.training_pair_readiness.v1"
TRAINING_PAIR_INPUT_CUSTODY_SCHEMA = "lightbulb.training_pair_input_custody.v2"
TRAINING_PAIR_ADMISSION_SCHEMA = "lightbulb.training_pair_admission.v1"
TRAINING_PAIR_STATUS_SCHEMA = "lightbulb.training_pair_status.v1"
TRAINING_PAIR_ADMISSION_UNAVAILABLE = "training_admission_unavailable"
TRAINING_PAIR_CONFIRMATION_SCHEMA = "lightbulb.training_pair_admission_confirmation.v2"
TRAINING_PAIR_CONFIRMATION_BINDING_SCHEMA = (
    "lightbulb.training_pair_admission_confirmation_binding.v1"
)

TRAINING_PAIR_AUTHORITY_BLOCKERS = (
    "training_profile_unavailable",
    "budget_authority_unavailable",
    "snapshot_authority_unavailable",
    "scheduler_unavailable",
    "metering_unavailable",
    "artifact_storage_unavailable",
)
TRAINING_PAIR_READINESS_AUTHORITY_BLOCKERS = (
    "training_profile_unavailable",
    "budget_authority_unavailable",
    "snapshot_authority_unavailable",
    "artifact_storage_unavailable",
    "input_attestation_unavailable",
    "scheduler_unavailable",
    "metering_unavailable",
)
TRAINING_PAIR_READINESS_STAGE_CODES = (
    "marketplace_source",
    "training_profile",
    "budget_authority",
    "snapshot_authority",
    "artifact_storage",
    "input_attestation",
    "scheduler",
    "metering",
)
TRAINING_PAIR_READINESS_LANES = ("puffer_v4", "prime_verifiers")
TRAINING_PAIR_INPUT_CUSTODY_STATUSES = (
    "authority_unavailable",
    "not_associated",
    "verification_failed",
    "expired",
    "verified",
)

_INPUT_CUSTODY_STATE = {
    "authority_unavailable": {
        "authority": False,
        "association": False,
        "verified": False,
        "blockers": ["artifact_storage_unavailable", "input_attestation_unavailable"],
        "next_action": "provision_input_custody_authority",
    },
    "not_associated": {
        "authority": True,
        "association": False,
        "verified": False,
        "blockers": ["input_custody_association_missing", "input_attestation_unavailable"],
        "next_action": "associate_verified_input_receipt",
    },
    "verification_failed": {
        "authority": True,
        "association": True,
        "verified": False,
        "blockers": ["input_attestation_invalid"],
        "next_action": "repair_input_attestation",
    },
    "expired": {
        "authority": True,
        "association": True,
        "verified": False,
        "blockers": ["input_attestation_expired"],
        "next_action": "refresh_input_attestation",
    },
    "verified": {
        "authority": True,
        "association": True,
        "verified": True,
        "blockers": [],
        "next_action": "inspect_training_readiness",
    },
}

_MAX_AGENT_OPS_RESPONSE_BYTES = 64 * 1024
_VISIBLE_ASCII_RE = re.compile(r"^[\x21-\x7e]{1,200}$")
_BLOCKER_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COORDINATOR_STATUSES = {
    "requested",
    "launching",
    "awaiting_evaluation",
    "evaluated",
    "partial_failure",
    "failed",
}
_CONTROL_COORDINATOR_STATUSES = {
    "active": {"requested", "launching", "awaiting_evaluation"},
    "evaluated": {"evaluated"},
    "failed": {"failed"},
    "partial_failure": {"partial_failure"},
    "blocked": _COORDINATOR_STATUSES,
    "expired": _COORDINATOR_STATUSES,
    "archived": _COORDINATOR_STATUSES,
}
_RETENTION_STATES = {"active", "pinned", "expired", "archived"}


class AgentOpsProtocolError(LightbulbError):
    """The agent-ops gateway returned a malformed or unexpected v1 contract."""


def build_training_pair_request(
    installation_id: object,
    revision_id: object,
    project_id: object | None = None,
) -> dict[str, str]:
    """Build the exact caller-selectable training-pair request allowlist."""
    payload = {
        "installation_id": validate_uuid(installation_id, "installation_id"),
        "revision_id": validate_uuid(revision_id, "revision_id"),
    }
    if project_id is not None:
        payload["project_id"] = validate_uuid(project_id, "project_id")
    return payload


def validate_training_pair_idempotency_key(value: object) -> str:
    """Require the gateway's exact 1-200 visible-ASCII retry key contract."""
    if not isinstance(value, str) or not _VISIBLE_ASCII_RE.fullmatch(value):
        raise ValidationError(
            "idempotency_key is required and must contain 1-200 visible ASCII "
            "characters (no spaces or control characters)"
        )
    return value


def build_training_pair_confirmation(
    installation_id: object,
    revision_id: object,
    idempotency_key: object,
    project_id: object | None = None,
) -> dict[str, Any]:
    """Build a versioned receipt bound to the exact future admission request."""
    request = build_training_pair_request(installation_id, revision_id, project_id)
    key = validate_training_pair_idempotency_key(idempotency_key)
    binding: dict[str, Any] = {
        "schema": TRAINING_PAIR_CONFIRMATION_BINDING_SCHEMA,
        "installation_id": request["installation_id"],
        "revision_id": request["revision_id"],
        "project_id": request.get("project_id"),
        "idempotency_key_sha256": hashlib.sha256(key.encode("ascii")).hexdigest(),
    }
    canonical = json.dumps(
        binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "schema": TRAINING_PAIR_CONFIRMATION_SCHEMA,
        "confirmation_receipt": hashlib.sha256(canonical).hexdigest(),
        "request_binding": binding,
    }


def training_pair_confirmation_matches(
    confirmation_receipt: object,
    installation_id: object,
    revision_id: object,
    idempotency_key: object,
    project_id: object | None = None,
) -> bool:
    """Verify that a confirmation receipt belongs to this exact request."""
    if not isinstance(confirmation_receipt, str):
        return False
    expected = build_training_pair_confirmation(
        installation_id, revision_id, idempotency_key, project_id
    )["confirmation_receipt"]
    return hmac.compare_digest(confirmation_receipt, expected)


def parse_training_pair_preflight(
    value: object,
    *,
    installation_id: str,
    revision_id: str,
    project_id: str | None,
) -> dict[str, Any]:
    payload = _mapping(value, "training-pair preflight")
    _exact_keys(
        payload,
        required={
            "schema",
            "admissible",
            "admission_available",
            "source_valid",
            "installation_id",
            "revision_id",
            "blockers",
        },
        optional={"project_id", "domain", "action"},
        label="training-pair preflight",
    )
    _schema(payload, TRAINING_PAIR_PREFLIGHT_SCHEMA)
    if payload["admissible"] is not False or payload["admission_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair preflight v1 must report admission as unavailable"
        )
    source_valid = _boolean(payload, "source_valid")
    _matching_uuid(payload, "installation_id", installation_id)
    _matching_uuid(payload, "revision_id", revision_id)
    _matching_optional_uuid(payload, "project_id", project_id)
    _optional_text(payload, "domain", 64)
    _optional_text(payload, "action", 160)
    blockers = _blockers(payload)
    _require_authority_blockers(blockers)
    _validate_source_validity(
        payload, blockers, source_valid=source_valid, require_identity=True
    )
    return dict(payload)


def parse_training_pair_readiness(
    value: object,
    *,
    installation_id: str,
    revision_id: str,
    project_id: str | None,
) -> dict[str, Any]:
    """Validate the structured read-only readiness contract without widening authority."""
    payload = _mapping(value, "training-pair readiness")
    _exact_keys(
        payload,
        required={
            "schema",
            "ready",
            "source_valid",
            "admission_available",
            "execution_surface_available",
            "installation_id",
            "revision_id",
            "project_scoped",
            "blockers",
            "stages",
            "lanes",
            "next_action",
        },
        optional={"project_id", "domain", "action"},
        label="training-pair readiness",
    )
    _schema(payload, TRAINING_PAIR_READINESS_SCHEMA)
    if payload["ready"] is not False:
        raise AgentOpsProtocolError("training-pair readiness v1 cannot report ready")
    if payload["admission_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair readiness v1 cannot report admission authority"
        )
    if payload["execution_surface_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair readiness v1 cannot report an execution surface"
        )
    source_valid = _boolean(payload, "source_valid")
    _matching_uuid(payload, "installation_id", installation_id)
    _matching_uuid(payload, "revision_id", revision_id)
    _matching_optional_uuid(payload, "project_id", project_id)
    project_scoped = _boolean(payload, "project_scoped")
    if project_scoped is not (project_id is not None):
        raise AgentOpsProtocolError(
            "training-pair readiness project_scoped did not match the requested project_id"
        )
    _optional_text(payload, "domain", 64)
    _optional_text(payload, "action", 160)

    blockers = _blockers(payload)
    authority = set(TRAINING_PAIR_READINESS_AUTHORITY_BLOCKERS)
    source_blockers = [blocker for blocker in blockers if blocker not in authority]
    if blockers != [*source_blockers, *TRAINING_PAIR_READINESS_AUTHORITY_BLOCKERS]:
        raise AgentOpsProtocolError(
            "training-pair readiness blockers must end with every authority blocker "
            "in deterministic order"
        )
    if source_valid is not (not source_blockers):
        raise AgentOpsProtocolError(
            "training-pair readiness source_valid must match its source blockers"
        )
    if source_valid:
        _required_text(payload, "domain", 64)
        _required_text(payload, "action", 160)

    raw_stages = payload["stages"]
    if not isinstance(raw_stages, list) or len(raw_stages) != len(
        TRAINING_PAIR_READINESS_STAGE_CODES
    ):
        raise AgentOpsProtocolError(
            "training-pair readiness stages must contain the exact v1 stage set"
        )
    authority_by_stage = dict(
        zip(
            TRAINING_PAIR_READINESS_STAGE_CODES[1:],
            TRAINING_PAIR_READINESS_AUTHORITY_BLOCKERS,
            strict=True,
        )
    )
    for index, expected_code in enumerate(TRAINING_PAIR_READINESS_STAGE_CODES):
        stage = _mapping(raw_stages[index], f"training-pair readiness stage {index}")
        _exact_keys(
            stage,
            required={"code", "status", "blockers"},
            optional=set(),
            label=f"training-pair readiness stage {index}",
        )
        if stage["code"] != expected_code:
            raise AgentOpsProtocolError(
                "training-pair readiness stages must use deterministic v1 order"
            )
        stage_blockers = _blockers(stage)
        if expected_code == "marketplace_source":
            expected_status = "ready" if source_valid else "blocked"
            if stage["status"] != expected_status or stage_blockers != source_blockers:
                raise AgentOpsProtocolError(
                    "marketplace_source stage did not match source validity"
                )
        elif stage["status"] != "blocked" or stage_blockers != [
            authority_by_stage[expected_code]
        ]:
            raise AgentOpsProtocolError(
                f"training-pair readiness stage {expected_code} widened authority"
            )

    raw_lanes = payload["lanes"]
    if not isinstance(raw_lanes, list) or len(raw_lanes) != len(
        TRAINING_PAIR_READINESS_LANES
    ):
        raise AgentOpsProtocolError(
            "training-pair readiness lanes must contain both exact v1 lanes"
        )
    for index, expected_lane in enumerate(TRAINING_PAIR_READINESS_LANES):
        lane = _mapping(raw_lanes[index], f"training-pair readiness lane {index}")
        _exact_keys(
            lane,
            required={
                "lane",
                "status",
                "input_attested",
                "training_input_ready",
                "evaluation_input_ready",
                "blockers",
            },
            optional=set(),
            label=f"training-pair readiness lane {index}",
        )
        if lane["lane"] != expected_lane or lane["status"] != "blocked":
            raise AgentOpsProtocolError(
                "training-pair readiness lanes must remain blocked in v1"
            )
        if any(
            lane[key] is not False
            for key in (
                "input_attested",
                "training_input_ready",
                "evaluation_input_ready",
            )
        ):
            raise AgentOpsProtocolError(
                "training-pair readiness lane claimed unavailable input authority"
            )
        if _blockers(lane) != ["input_attestation_unavailable"]:
            raise AgentOpsProtocolError(
                "training-pair readiness lane omitted its input-attestation blocker"
            )

    next_action = _mapping(payload["next_action"], "training-pair readiness next_action")
    _exact_keys(
        next_action,
        required={"code", "message"},
        optional=set(),
        label="training-pair readiness next_action",
    )
    expected_next_action = (
        "provision_training_authorities"
        if source_valid
        else "repair_marketplace_source"
    )
    if next_action["code"] != expected_next_action:
        raise AgentOpsProtocolError(
            "training-pair readiness next_action did not match source validity"
        )
    _required_text(next_action, "message", 300)
    return dict(payload)


def parse_training_pair_input_custody(
    value: object,
    *,
    installation_id: str,
    revision_id: str,
    project_id: str | None,
) -> dict[str, Any]:
    """Validate privacy-minimized custody evidence without granting authority."""
    payload = _mapping(value, "training-pair input custody")
    _exact_keys(
        payload,
        required={
            "schema",
            "association_status",
            "installation_id",
            "revision_id",
            "project_scoped",
            "custody_authority_available",
            "association_present",
            "receipt_verified",
            "admission_available",
            "execution_surface_available",
            "blockers",
            "lanes",
            "receipt_summary",
            "next_action",
        },
        optional={"project_id"},
        label="training-pair input custody",
    )
    _schema(payload, TRAINING_PAIR_INPUT_CUSTODY_SCHEMA)
    _matching_uuid(payload, "installation_id", installation_id)
    _matching_uuid(payload, "revision_id", revision_id)
    _matching_optional_uuid(payload, "project_id", project_id)
    project_scoped = _boolean(payload, "project_scoped")
    if project_scoped is not (project_id is not None):
        raise AgentOpsProtocolError(
            "training-pair input custody project_scoped did not match the requested project_id"
        )
    if payload["admission_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair input custody cannot report admission authority"
        )
    if payload["execution_surface_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair input custody cannot report an execution surface"
        )

    status = _required_enum(
        payload,
        "association_status",
        set(TRAINING_PAIR_INPUT_CUSTODY_STATUSES),
    )
    expected = _INPUT_CUSTODY_STATE[status]
    observed = {
        "authority": _boolean(payload, "custody_authority_available"),
        "association": _boolean(payload, "association_present"),
        "verified": _boolean(payload, "receipt_verified"),
    }
    if any(observed[key] is not expected[key] for key in observed):
        raise AgentOpsProtocolError(
            "training-pair input custody state booleans are inconsistent"
        )
    if _blockers(payload) != expected["blockers"]:
        raise AgentOpsProtocolError(
            "training-pair input custody blockers did not match association_status"
        )

    raw_lanes = payload["lanes"]
    if not isinstance(raw_lanes, list) or len(raw_lanes) != len(
        TRAINING_PAIR_READINESS_LANES
    ):
        raise AgentOpsProtocolError(
            "training-pair input custody must contain both exact lanes"
        )
    for index, expected_lane in enumerate(TRAINING_PAIR_READINESS_LANES):
        lane = _mapping(raw_lanes[index], f"training-pair input custody lane {index}")
        _exact_keys(
            lane,
            required={"lane", "custody_verified"},
            optional=set(),
            label=f"training-pair input custody lane {index}",
        )
        if lane["lane"] != expected_lane:
            raise AgentOpsProtocolError(
                "training-pair input custody lanes must use deterministic v1 order"
            )
        if _boolean(lane, "custody_verified") is not expected["verified"]:
            raise AgentOpsProtocolError(
                "training-pair input custody lane widened its verified state"
            )

    receipt_summary = payload["receipt_summary"]
    if status == "verified":
        _parse_input_custody_receipt_summary(receipt_summary)
    elif receipt_summary is not None:
        raise AgentOpsProtocolError(
            "unverified input custody cannot expose a receipt summary"
        )

    next_action = _mapping(
        payload["next_action"], "training-pair input custody next_action"
    )
    _exact_keys(
        next_action,
        required={"code", "message"},
        optional=set(),
        label="training-pair input custody next_action",
    )
    if next_action["code"] != expected["next_action"]:
        raise AgentOpsProtocolError(
            "training-pair input custody next_action did not match association_status"
        )
    _required_text(next_action, "message", 300)
    return dict(payload)


def _parse_input_custody_receipt_summary(value: object) -> None:
    summary = _mapping(value, "training-pair input custody receipt summary")
    _exact_keys(
        summary,
        required={
            "receipt_digest",
            "bundle_manifest_sha256",
            "bundle_file_count",
            "bundle_uncompressed_size_bytes",
            "storage_object_size_bytes",
            "issued_at",
            "expires_at",
            "snapshot",
            "source_cost",
            "lanes",
        },
        optional=set(),
        label="training-pair input custody receipt summary",
    )
    _required_digest(summary, "receipt_digest")
    _required_digest(summary, "bundle_manifest_sha256")
    if _required_int(summary, "bundle_file_count", minimum=1) != 10:
        raise AgentOpsProtocolError(
            "training-pair input custody bundle_file_count must be 10"
        )
    _required_int(summary, "bundle_uncompressed_size_bytes", minimum=1)
    _required_int(summary, "storage_object_size_bytes", minimum=1)
    issued_at = _required_timestamp(summary, "issued_at")
    expires_at = _required_timestamp(summary, "expires_at")
    if expires_at <= issued_at:
        raise AgentOpsProtocolError(
            "training-pair input custody receipt expiry is invalid"
        )
    if issued_at > datetime.now(timezone.utc):
        raise AgentOpsProtocolError(
            "verified training-pair input custody receipt is not yet valid"
        )
    if expires_at <= datetime.now(timezone.utc):
        raise AgentOpsProtocolError(
            "verified training-pair input custody receipt is expired"
        )

    snapshot = _mapping(summary["snapshot"], "input custody snapshot")
    _exact_keys(
        snapshot,
        required={
            "binding_sha256",
            "manifest_sha256",
            "dataset_sha256",
            "episode_count",
            "training_sample_count",
            "evaluation_sample_count",
        },
        optional=set(),
        label="input custody snapshot",
    )
    for key in ("binding_sha256", "manifest_sha256", "dataset_sha256"):
        _required_digest(snapshot, key)
    episode_count = _required_int(snapshot, "episode_count", minimum=2)
    training_count = _required_int(snapshot, "training_sample_count", minimum=1)
    evaluation_count = _required_int(
        snapshot, "evaluation_sample_count", minimum=1
    )
    if episode_count > 100_000 or episode_count != training_count + evaluation_count:
        raise AgentOpsProtocolError(
            "training-pair input custody snapshot counts are inconsistent"
        )

    source_cost = _mapping(summary["source_cost"], "input custody source_cost")
    _exact_keys(
        source_cost,
        required={"amount_micros", "currency"},
        optional=set(),
        label="input custody source_cost",
    )
    _required_int(source_cost, "amount_micros", minimum=0)
    currency = source_cost["currency"]
    if not isinstance(currency, str) or _CURRENCY_RE.fullmatch(currency) is None:
        raise AgentOpsProtocolError(
            "training-pair input custody source cost currency is invalid"
        )

    raw_lanes = summary["lanes"]
    if not isinstance(raw_lanes, list) or len(raw_lanes) != len(
        TRAINING_PAIR_READINESS_LANES
    ):
        raise AgentOpsProtocolError(
            "training-pair input custody receipt must bind both exact lanes"
        )
    for index, expected_lane in enumerate(TRAINING_PAIR_READINESS_LANES):
        lane = _mapping(raw_lanes[index], f"input custody receipt lane {index}")
        _exact_keys(
            lane,
            required={"lane", "framework_pin"},
            optional=set(),
            label=f"input custody receipt lane {index}",
        )
        if lane["lane"] != expected_lane:
            raise AgentOpsProtocolError(
                "training-pair input custody receipt lanes must use deterministic v1 order"
            )
        framework_pin = lane["framework_pin"]
        if (
            not isinstance(framework_pin, str)
            or _GIT_COMMIT_RE.fullmatch(framework_pin) is None
        ):
            raise AgentOpsProtocolError(
                "training-pair input custody framework_pin must be a full Git commit"
            )


def parse_training_pair_admission_unavailable(value: object) -> dict[str, Any]:
    payload = _mapping(value, "training-pair admission")
    _exact_keys(
        payload,
        required={"schema", "code", "admitted", "source_valid", "blockers"},
        optional=set(),
        label="training-pair admission",
    )
    _schema(payload, TRAINING_PAIR_ADMISSION_SCHEMA)
    if payload["code"] != TRAINING_PAIR_ADMISSION_UNAVAILABLE:
        raise AgentOpsProtocolError("unexpected training-pair admission code")
    if payload["admitted"] is not False:
        raise AgentOpsProtocolError(
            "the admission-unavailable contract cannot report an admitted pair"
        )
    source_valid = _boolean(payload, "source_valid")
    blockers = _blockers(payload)
    _require_authority_blockers(blockers)
    _validate_source_validity(
        payload, blockers, source_valid=source_valid, require_identity=False
    )
    return dict(payload)


def is_training_pair_admission_unavailable(value: object) -> bool:
    """Identify only the stable unavailable envelope before bypassing HTTP 503."""
    return (
        isinstance(value, Mapping)
        and value.get("schema") == TRAINING_PAIR_ADMISSION_SCHEMA
        and value.get("code") == TRAINING_PAIR_ADMISSION_UNAVAILABLE
    )


def parse_training_pair_status(
    value: object,
    *,
    pair_handle: str,
    project_id: str | None,
) -> dict[str, Any]:
    payload = _mapping(value, "training-pair status")
    _exact_keys(
        payload,
        required={
            "schema",
            "pair_handle",
            "domain",
            "task_type",
            "coordinator_status",
            "control_status",
            "retention_state",
            "project_scoped",
            "execution_surface_available",
            "created_at",
            "updated_at",
        },
        optional=set(),
        label="training-pair status",
    )
    _schema(payload, TRAINING_PAIR_STATUS_SCHEMA)
    _matching_uuid(payload, "pair_handle", pair_handle)
    for key, limit in (
        ("domain", 64),
        ("task_type", 64),
        ("created_at", 64),
        ("updated_at", 64),
    ):
        _required_text(payload, key, limit)
    coordinator_status = _required_enum(
        payload, "coordinator_status", _COORDINATOR_STATUSES
    )
    control_status = _required_enum(
        payload, "control_status", set(_CONTROL_COORDINATOR_STATUSES)
    )
    _required_enum(payload, "retention_state", _RETENTION_STATES)
    if coordinator_status not in _CONTROL_COORDINATOR_STATUSES[control_status]:
        raise AgentOpsProtocolError(
            "training-pair status coordinator/control mapping is invalid for V1683 v1"
        )
    project_scoped = _boolean(payload, "project_scoped")
    if project_id is not None:
        try:
            validate_uuid(project_id, "project_id")
        except ValidationError as exc:
            raise AgentOpsProtocolError(
                "requested training-pair project_id must be a UUID"
            ) from exc
    if project_scoped is not (project_id is not None):
        raise AgentOpsProtocolError(
            "training-pair status project_scoped did not match the requested project_id"
        )
    if payload["execution_surface_available"] is not False:
        raise AgentOpsProtocolError(
            "training-pair status v1 cannot report an execution surface"
        )
    return dict(payload)


def response_json(response: Any, label: str) -> object:
    """Read one small strict JSON value without trusting response volume."""
    raw_content = getattr(response, "content", None)
    if not isinstance(raw_content, (bytes, bytearray)):
        raise AgentOpsProtocolError(f"{label} response did not expose raw JSON bytes")
    if len(raw_content) > _MAX_AGENT_OPS_RESPONSE_BYTES:
        raise AgentOpsProtocolError(
            f"{label} response exceeded {_MAX_AGENT_OPS_RESPONSE_BYTES} bytes"
        )
    try:
        raw_text = bytes(raw_content).decode("utf-8")
        value = json.loads(
            raw_text,
            object_pairs_hook=lambda pairs: _strict_json_object(pairs, label),
            parse_constant=lambda constant: _reject_json_constant(constant, label),
        )
    except AgentOpsProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentOpsProtocolError(f"{label} response was not valid JSON") from exc
    _bounded_json(value, label)
    return value


def _strict_json_object(
    pairs: list[tuple[str, Any]], label: str
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentOpsProtocolError(
                f"{label} response contained duplicate JSON key {key}"
            )
        result[key] = value
    return result


def _reject_json_constant(constant: str, label: str) -> None:
    raise AgentOpsProtocolError(
        f"{label} response contained non-finite JSON value {constant}"
    )


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    _bounded_json(value, label)
    if not isinstance(value, Mapping):
        raise AgentOpsProtocolError(f"{label} response must be a JSON object")
    return value


def _bounded_json(value: object, label: str) -> None:
    try:
        size = len(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AgentOpsProtocolError(f"{label} response was not bounded JSON") from exc
    if size > _MAX_AGENT_OPS_RESPONSE_BYTES:
        raise AgentOpsProtocolError(
            f"{label} response exceeded {_MAX_AGENT_OPS_RESPONSE_BYTES} bytes"
        )


def _exact_keys(
    payload: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    keys = set(payload)
    missing = sorted(required - keys)
    unexpected = sorted(keys - required - optional)
    if missing or unexpected:
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        raise AgentOpsProtocolError(f"{label} schema mismatch: {'; '.join(detail)}")


def _schema(payload: Mapping[str, Any], expected: str) -> None:
    if payload.get("schema") != expected:
        raise AgentOpsProtocolError(f"expected agent-ops schema {expected}")


def _boolean(payload: Mapping[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise AgentOpsProtocolError(f"agent-ops field {key} must be a boolean")
    return value


def _matching_uuid(payload: Mapping[str, Any], key: str, expected: str) -> None:
    try:
        actual = validate_uuid(payload.get(key), key)
    except ValidationError as exc:
        raise AgentOpsProtocolError(f"agent-ops field {key} must be a UUID") from exc
    if actual.lower() != expected.lower():
        raise AgentOpsProtocolError(f"agent-ops field {key} did not match the request")


def _matching_optional_uuid(
    payload: Mapping[str, Any], key: str, expected: str | None
) -> None:
    actual_value = payload.get(key)
    if expected is None:
        if actual_value is not None:
            raise AgentOpsProtocolError(f"agent-ops field {key} did not match the request")
        return
    _matching_uuid(payload, key, expected)


def _required_text(payload: Mapping[str, Any], key: str, limit: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > limit:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} must be a non-empty string of at most {limit} characters"
        )
    return value


def _optional_text(payload: Mapping[str, Any], key: str, limit: int) -> None:
    if key not in payload or payload[key] is None:
        return
    _required_text(payload, key, limit)


def _required_enum(
    payload: Mapping[str, Any], key: str, allowed: set[str]
) -> str:
    value = _required_text(payload, key, 64)
    if value not in allowed:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} is not a V1683 v1 value"
        )
    return value


def _required_digest(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} must be a lowercase SHA-256 digest"
        )
    return value


def _required_int(
    payload: Mapping[str, Any],
    key: str,
    *,
    minimum: int,
) -> int:
    value = payload.get(key)
    if type(value) is not int or value < minimum or value > 2**63 - 1:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} must be an integer between {minimum} and 2^63-1"
        )
    return value


def _required_timestamp(payload: Mapping[str, Any], key: str) -> datetime:
    value = payload.get(key)
    if not isinstance(value, str) or _UTC_SECOND_RE.fullmatch(value) is None:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} must be a canonical UTC timestamp"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise AgentOpsProtocolError(
            f"agent-ops field {key} must be a canonical UTC-second timestamp"
        ) from exc
    return parsed


def _blockers(payload: Mapping[str, Any]) -> list[str]:
    value = payload.get("blockers")
    if not isinstance(value, list) or len(value) > 64:
        raise AgentOpsProtocolError("agent-ops blockers must be a list of at most 64 values")
    if any(not isinstance(item, str) or not _BLOCKER_RE.fullmatch(item) for item in value):
        raise AgentOpsProtocolError("agent-ops blockers contained an invalid value")
    if len(set(value)) != len(value):
        raise AgentOpsProtocolError("agent-ops blockers must be unique")
    return value


def _require_authority_blockers(blockers: list[str]) -> None:
    missing = [item for item in TRAINING_PAIR_AUTHORITY_BLOCKERS if item not in blockers]
    if missing:
        raise AgentOpsProtocolError(
            "training-pair response omitted authoritative blockers: " + ", ".join(missing)
        )


def _validate_source_validity(
    payload: Mapping[str, Any],
    blockers: list[str],
    *,
    source_valid: bool,
    require_identity: bool,
) -> None:
    authority = set(TRAINING_PAIR_AUTHORITY_BLOCKERS)
    expected_valid = all(blocker in authority for blocker in blockers)
    if source_valid is not expected_valid:
        raise AgentOpsProtocolError(
            "agent-ops source_valid must be true iff no non-authority blockers exist"
        )
    if source_valid and require_identity:
        _required_text(payload, "domain", 64)
        _required_text(payload, "action", 160)


__all__ = [
    "AgentOpsProtocolError",
    "TRAINING_PAIR_ADMISSION_SCHEMA",
    "TRAINING_PAIR_ADMISSION_UNAVAILABLE",
    "TRAINING_PAIR_AUTHORITY_BLOCKERS",
    "TRAINING_PAIR_CONFIRMATION_BINDING_SCHEMA",
    "TRAINING_PAIR_CONFIRMATION_SCHEMA",
    "TRAINING_PAIR_INPUT_CUSTODY_SCHEMA",
    "TRAINING_PAIR_INPUT_CUSTODY_STATUSES",
    "TRAINING_PAIR_PREFLIGHT_SCHEMA",
    "TRAINING_PAIR_READINESS_AUTHORITY_BLOCKERS",
    "TRAINING_PAIR_READINESS_LANES",
    "TRAINING_PAIR_READINESS_SCHEMA",
    "TRAINING_PAIR_READINESS_STAGE_CODES",
    "TRAINING_PAIR_STATUS_SCHEMA",
    "build_training_pair_request",
    "build_training_pair_confirmation",
    "is_training_pair_admission_unavailable",
    "parse_training_pair_admission_unavailable",
    "parse_training_pair_input_custody",
    "parse_training_pair_preflight",
    "parse_training_pair_readiness",
    "parse_training_pair_status",
    "response_json",
    "training_pair_confirmation_matches",
    "validate_training_pair_idempotency_key",
]
