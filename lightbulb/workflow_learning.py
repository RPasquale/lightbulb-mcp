"""Fail-closed handoff from workflow delivery to paired-learning readiness.

The handoff is intentionally read-only.  It binds a versioned candidate and a
compact episode manifest to immutable workflow-improvement audit evidence and
the exact installed Marketplace action inspected by Spring.  It never admits a
campaign, allocates compute, launches either lane, writes an artifact, promotes
a candidate, or changes serving state.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from lightbulb.agent_ops import (
    AgentOpsProtocolError,
    parse_training_pair_input_custody,
    parse_training_pair_readiness,
)
from lightbulb.errors import ValidationError
from lightbulb.validators import validate_uuid


WORKFLOW_LEARNING_HANDOFF_SCHEMA = "lightbulb.workflow_learning_handoff.v1"
WORKFLOW_LEARNING_ATTESTED_HANDOFF_SCHEMA = (
    "lightbulb.workflow_learning_handoff.v2"
)
WORKFLOW_LEARNING_CANDIDATE_ATTESTED_HANDOFF_SCHEMA = (
    "lightbulb.workflow_learning_handoff.v3"
)
WORKFLOW_LEARNING_CANDIDATE_SCHEMA = (
    "lightbulb.workflow_learning_candidate_manifest.v1"
)
WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCHEMA = (
    "lightbulb.workflow_learning_candidate_artifact_attestation.v1"
)
WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCOPE_SCHEMA = (
    "lightbulb.workflow_learning_candidate_artifact_scope.v1"
)
WORKFLOW_LEARNING_EPISODE_SCHEMA = "lightbulb.workflow_learning_episode_manifest.v1"
WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA = (
    "lightbulb.workflow_learning_episode_manifest.v2"
)

WORKFLOW_LEARNING_CANDIDATE_KINDS = (
    "workflow_graph",
    "prompt",
    "certified_skill",
    "parser",
    "budget_policy",
    "model",
    "primitive_implementation",
)
WORKFLOW_LEARNING_LANES = ("puffer_v4", "prime_verifiers")

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_UTC_SECOND_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_HANDOFF_BYTES = 256 * 1024
_MAX_EPISODES = 100_000
_MAX_RETENTION_SECONDS = 30 * 24 * 60 * 60
_MAX_ACCOUNTING_VALUE = 9_000_000_000_000_000

_REQUIRED_AUDIT_SEQUENCE = (
    ("APPROVAL_DECISION", "IMPLEMENTATION"),
    ("DELIVERY_CREATED", None),
    ("BRANCH_CREATED", None),
    ("IMPLEMENTATION_COMPLETED", None),
    ("PULL_REQUEST_OPENED", None),
    ("CI_PASSED", None),
    ("STAGING_DEPLOYED", None),
    ("CANARY_STARTED", None),
    ("CANARY_EVALUATED", None),
    ("STAGING_CLEANED", None),
)
_AUTHORITY_DENIALS = {
    "admission_authorized": False,
    "artifact_write_authorized": False,
    "evaluation_authorized": False,
    "funding_authorized": False,
    "promotion_authorized": False,
    "scheduler_authorized": False,
    "serving_authorized": False,
    "training_authorized": False,
}


class WorkflowLearningHandoffError(ValueError):
    """Raised when candidate evidence cannot safely cross the learning boundary."""


def _canonical_json_bytes(value: Any, *, label: str, limit: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkflowLearningHandoffError(
            f"{label} must contain finite JSON values only"
        ) from exc
    if len(encoded) > limit:
        raise WorkflowLearningHandoffError(
            f"{label} exceeds its {limit}-byte canonical limit"
        )
    return encoded


def _sha256_json(value: Any, *, label: str, limit: int = _MAX_MANIFEST_BYTES) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(value, label=label, limit=limit)
    ).hexdigest()


def workflow_learning_candidate_manifest_sha256(value: Mapping[str, Any]) -> str:
    """Validate and hash the exact candidate manifest used by Harness evidence."""
    manifest = _candidate_manifest(value)
    return _sha256_json(manifest, label="workflow learning candidate manifest")


def workflow_learning_candidate_attestation_scope_sha256(
    *,
    packet_id: str,
    delivery_id: str,
    candidate_manifest: Mapping[str, Any],
) -> str:
    """Hash the exact delivery/candidate scope signed by the artifact producer."""

    candidate = _candidate_manifest(candidate_manifest)
    scope = {
        "artifact_contract_sha256": candidate["artifact_contract_sha256"],
        "candidate_artifact_sha256": candidate["candidate_artifact_sha256"],
        "candidate_manifest_sha256": _sha256_json(
            candidate, label="workflow learning candidate manifest"
        ),
        "delivery_id": _uuid(delivery_id, "delivery_id"),
        "packet_id": _uuid(packet_id, "packet_id"),
        "repository_commit": candidate["repository_commit"],
        "schema": WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCOPE_SCHEMA,
    }
    return _sha256_json(scope, label="workflow learning candidate artifact scope")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkflowLearningHandoffError(f"{label} must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _exact_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    label: str,
) -> None:
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        extra = sorted(keys - required)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise WorkflowLearningHandoffError(f"{label} has {'; '.join(detail)}")


def _field(value: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return None


def _uuid(value: Any, label: str) -> str:
    try:
        return validate_uuid(value, label).lower()
    except ValidationError as exc:
        raise WorkflowLearningHandoffError(str(exc)) from exc


def _optional_uuid(value: Any, label: str) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    return _uuid(value, label)


def _digest(value: Any, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(normalized):
        raise WorkflowLearningHandoffError(f"{label} must be a lowercase SHA-256")
    return normalized


def _commit(value: Any, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _COMMIT_RE.fullmatch(normalized):
        raise WorkflowLearningHandoffError(f"{label} must be a lowercase 40-character Git commit")
    return normalized


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkflowLearningHandoffError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise WorkflowLearningHandoffError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return value


def _utc_second(value: Any, label: str) -> datetime:
    text = str(value or "").strip()
    if not _UTC_SECOND_RE.fullmatch(text):
        raise WorkflowLearningHandoffError(f"{label} must be UTC at whole-second precision")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorkflowLearningHandoffError(f"{label} is not a valid timestamp") from exc


def _candidate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _mapping(value, "workflow learning candidate manifest")
    _exact_keys(
        manifest,
        required={
            "schema",
            "candidate_kind",
            "workflow_key",
            "predecessor_revision",
            "candidate_revision",
            "baseline_artifact_sha256",
            "candidate_artifact_sha256",
            "artifact_contract_sha256",
            "repository_commit",
            "raw_artifact_included",
        },
        label="workflow learning candidate manifest",
    )
    if manifest["schema"] != WORKFLOW_LEARNING_CANDIDATE_SCHEMA:
        raise WorkflowLearningHandoffError("workflow learning candidate schema is unsupported")
    if manifest["candidate_kind"] not in WORKFLOW_LEARNING_CANDIDATE_KINDS:
        raise WorkflowLearningHandoffError("workflow learning candidate kind is unsupported")
    workflow_key = str(manifest["workflow_key"] or "").strip()
    if not _WORKFLOW_KEY_RE.fullmatch(workflow_key):
        raise WorkflowLearningHandoffError("workflow learning candidate workflow_key is invalid")
    predecessor = _bounded_int(
        manifest["predecessor_revision"], "predecessor_revision", 1, 1_000_000
    )
    candidate = _bounded_int(
        manifest["candidate_revision"], "candidate_revision", 2, 1_000_001
    )
    if candidate != predecessor + 1:
        raise WorkflowLearningHandoffError(
            "candidate_revision must be the immediate successor of predecessor_revision"
        )
    baseline_digest = _digest(
        manifest["baseline_artifact_sha256"], "baseline_artifact_sha256"
    )
    candidate_digest = _digest(
        manifest["candidate_artifact_sha256"], "candidate_artifact_sha256"
    )
    if baseline_digest == candidate_digest:
        raise WorkflowLearningHandoffError("candidate artifact must differ from its baseline")
    if manifest["raw_artifact_included"] is not False:
        raise WorkflowLearningHandoffError("workflow learning handoff cannot contain a raw artifact")

    normalized = dict(manifest)
    normalized.update(
        {
            "workflow_key": workflow_key,
            "predecessor_revision": predecessor,
            "candidate_revision": candidate,
            "baseline_artifact_sha256": baseline_digest,
            "candidate_artifact_sha256": candidate_digest,
            "artifact_contract_sha256": _digest(
                manifest["artifact_contract_sha256"], "artifact_contract_sha256"
            ),
            "repository_commit": _commit(
                manifest["repository_commit"], "repository_commit"
            ),
        }
    )
    _canonical_json_bytes(
        normalized, label="workflow learning candidate manifest", limit=_MAX_MANIFEST_BYTES
    )
    return normalized


def _candidate_artifact_attestation(
    value: Mapping[str, Any],
    *,
    packet_id: str,
    delivery_id: str,
    candidate: Mapping[str, Any],
    observed_now: datetime,
) -> dict[str, Any]:
    inspection = _mapping(value, "workflow learning candidate artifact attestation")
    _exact_keys(
        inspection,
        required={
            "schema",
            "status",
            "verified",
            "packet_id",
            "delivery_id",
            "candidate_manifest_sha256",
            "candidate_artifact_sha256",
            "artifact_contract_sha256",
            "repository_commit",
            "scope_sha256",
            "producer_authenticity",
            "key_id",
            "key_fingerprint_sha256",
            "algorithm",
            "expires_at",
            "observed_at",
            "blockers",
            "admission_available",
            "execution_surface_available",
        },
        label="workflow learning candidate artifact attestation",
    )
    if inspection["schema"] != WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCHEMA:
        raise WorkflowLearningHandoffError(
            "workflow learning candidate artifact attestation schema is unsupported"
        )
    if _uuid(inspection["packet_id"], "candidate attestation packet_id") != packet_id:
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation escaped packet scope"
        )
    if _uuid(inspection["delivery_id"], "candidate attestation delivery_id") != delivery_id:
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation escaped delivery scope"
        )

    expected_manifest_digest = _sha256_json(
        candidate, label="workflow learning candidate manifest"
    )
    exact_bindings = {
        "candidate_manifest_sha256": expected_manifest_digest,
        "candidate_artifact_sha256": candidate["candidate_artifact_sha256"],
        "artifact_contract_sha256": candidate["artifact_contract_sha256"],
        "repository_commit": candidate["repository_commit"],
        "scope_sha256": workflow_learning_candidate_attestation_scope_sha256(
            packet_id=packet_id,
            delivery_id=delivery_id,
            candidate_manifest=candidate,
        ),
    }
    normalized = dict(inspection)
    for field, expected in exact_bindings.items():
        observed = (
            _commit(inspection[field], field)
            if field == "repository_commit"
            else _digest(inspection[field], field)
        )
        if observed != expected:
            raise WorkflowLearningHandoffError(
                f"candidate artifact attestation {field} does not match the candidate"
            )
        normalized[field] = observed

    status = str(inspection["status"] or "").strip().lower()
    verified = inspection["verified"]
    if not isinstance(verified, bool):
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation verified must be boolean"
        )
    if status not in {"verified", "invalid", "unattested"}:
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation status is unsupported"
        )
    if verified != (status == "verified"):
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation status and verified flag disagree"
        )
    if inspection["admission_available"] is not False:
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation cannot grant admission authority"
        )
    if inspection["execution_surface_available"] is not False:
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation cannot grant execution authority"
        )
    blockers = inspection["blockers"]
    if not isinstance(blockers, list) or len(blockers) > 16 or any(
        not isinstance(item, str) or not item or len(item) > 160 for item in blockers
    ):
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation blockers are invalid"
        )
    if verified and blockers:
        raise WorkflowLearningHandoffError(
            "verified candidate artifact attestation cannot contain blockers"
        )
    if not verified and not blockers:
        raise WorkflowLearningHandoffError(
            "unverified candidate artifact attestation must explain its blocker"
        )

    observed_at = _utc_second(inspection["observed_at"], "candidate attestation observed_at")
    if observed_at > observed_now + timedelta(minutes=5):
        raise WorkflowLearningHandoffError(
            "candidate artifact attestation was observed in the future"
        )
    normalized["observed_at"] = observed_at.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    normalized["status"] = status
    normalized["blockers"] = list(blockers)

    if verified:
        key_id = str(inspection["key_id"] or "").strip()
        if not _KEY_ID_RE.fullmatch(key_id):
            raise WorkflowLearningHandoffError(
                "verified candidate artifact attestation key_id is invalid"
            )
        if inspection["producer_authenticity"] != "attested":
            raise WorkflowLearningHandoffError(
                "verified candidate artifact attestation lacks producer authenticity"
            )
        if inspection["algorithm"] != "Ed25519":
            raise WorkflowLearningHandoffError(
                "verified candidate artifact attestation algorithm is unsupported"
            )
        expires_at = _utc_second(
            inspection["expires_at"], "candidate attestation expires_at"
        )
        if expires_at <= observed_now:
            raise WorkflowLearningHandoffError(
                "verified candidate artifact attestation has expired"
            )
        normalized.update(
            {
                "key_id": key_id,
                "key_fingerprint_sha256": _digest(
                    inspection["key_fingerprint_sha256"],
                    "candidate attestation key_fingerprint_sha256",
                ),
                "expires_at": expires_at.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        )
    else:
        if inspection["producer_authenticity"] not in {"unattested", "invalid"}:
            raise WorkflowLearningHandoffError(
                "unverified candidate artifact attestation authenticity is invalid"
            )
        for field in ("key_id", "key_fingerprint_sha256", "algorithm", "expires_at"):
            field_value = inspection[field]
            if field_value is not None and not isinstance(field_value, str):
                raise WorkflowLearningHandoffError(
                    f"candidate artifact attestation {field} is invalid"
                )

    _canonical_json_bytes(
        normalized,
        label="workflow learning candidate artifact attestation",
        limit=_MAX_MANIFEST_BYTES,
    )
    return normalized


def build_attested_workflow_learning_episode_manifest(
    input_custody: Mapping[str, Any],
    *,
    installation_id: str,
    revision_id: str,
    project_id: str | None = None,
) -> dict[str, Any]:
    """Derive the only v2 episode manifest accepted from verified custody.

    The manifest contains no episodes. Its set identity is the authenticated
    snapshot dataset digest, and its count, cost, lifetime, receipt, and bundle
    bindings are copied from Spring's strict read-only custody response.
    """

    try:
        custody = parse_training_pair_input_custody(
            input_custody,
            installation_id=_uuid(installation_id, "installation_id"),
            revision_id=_uuid(revision_id, "revision_id"),
            project_id=_optional_uuid(project_id, "project_id"),
        )
    except (AgentOpsProtocolError, ValidationError, ValueError) as exc:
        raise WorkflowLearningHandoffError(
            f"training input custody is not an exact read-only contract: {exc}"
        ) from exc
    if custody["association_status"] != "verified" or not custody["receipt_verified"]:
        raise WorkflowLearningHandoffError(
            "verified training input custody is required for an attested episode manifest"
        )
    receipt = _mapping(custody["receipt_summary"], "training input custody receipt")
    snapshot = _mapping(receipt["snapshot"], "training input custody snapshot")
    created = _utc_second(receipt["issued_at"], "input custody issued_at")
    receipt_expires = _utc_second(receipt["expires_at"], "input custody expires_at")
    if receipt_expires <= created:
        raise WorkflowLearningHandoffError(
            "verified training input custody has no usable retention window"
        )
    created_at = created.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = receipt_expires.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    manifest = {
        "schema": WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA,
        "episode_count": snapshot["episode_count"],
        "eligible_episode_count": snapshot["episode_count"],
        "canonical_episode_set_sha256": snapshot["dataset_sha256"],
        "snapshot_binding_sha256": snapshot["binding_sha256"],
        "snapshot_manifest_sha256": snapshot["manifest_sha256"],
        "input_attestation_receipt_sha256": receipt["receipt_digest"],
        "bundle_manifest_sha256": receipt["bundle_manifest_sha256"],
        "created_at": created_at,
        "expires_at": expires_at,
        "source_cost": dict(_mapping(receipt["source_cost"], "input custody source_cost")),
        "raw_episode_content_included": False,
    }
    return _episode_manifest(manifest)


def _episode_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _mapping(value, "workflow learning episode manifest")
    schema = manifest.get("schema")
    base_fields = {
        "schema",
        "episode_count",
        "eligible_episode_count",
        "canonical_episode_set_sha256",
        "created_at",
        "expires_at",
        "source_cost",
        "raw_episode_content_included",
    }
    if schema == WORKFLOW_LEARNING_EPISODE_SCHEMA:
        required_fields = base_fields
    elif schema == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA:
        required_fields = base_fields | {
            "snapshot_binding_sha256",
            "snapshot_manifest_sha256",
            "input_attestation_receipt_sha256",
            "bundle_manifest_sha256",
        }
    else:
        raise WorkflowLearningHandoffError(
            "workflow learning episode schema is unsupported"
        )
    _exact_keys(
        manifest,
        required=required_fields,
        label="workflow learning episode manifest",
    )
    count = _bounded_int(manifest["episode_count"], "episode_count", 1, _MAX_EPISODES)
    eligible = _bounded_int(
        manifest["eligible_episode_count"], "eligible_episode_count", 1, count
    )
    if schema == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA and eligible != count:
        raise WorkflowLearningHandoffError(
            "attested episode manifest must bind every selected eligible episode"
        )
    created = _utc_second(manifest["created_at"], "created_at")
    expires = _utc_second(manifest["expires_at"], "expires_at")
    retention = int((expires - created).total_seconds())
    if not 1 <= retention <= _MAX_RETENTION_SECONDS:
        raise WorkflowLearningHandoffError(
            "episode manifest retention must be positive and no more than 30 days"
        )
    source_cost = _mapping(manifest["source_cost"], "episode manifest source_cost")
    _exact_keys(
        source_cost,
        required={"amount_micros", "currency"},
        label="episode manifest source_cost",
    )
    amount = _bounded_int(
        source_cost["amount_micros"],
        "source_cost.amount_micros",
        0,
        _MAX_ACCOUNTING_VALUE,
    )
    currency = str(source_cost["currency"] or "").strip()
    if not _CURRENCY_RE.fullmatch(currency):
        raise WorkflowLearningHandoffError("source_cost.currency must be an ISO-style code")
    if manifest["raw_episode_content_included"] is not False:
        raise WorkflowLearningHandoffError("workflow learning handoff cannot contain raw episodes")

    normalized = dict(manifest)
    normalized.update(
        {
            "episode_count": count,
            "eligible_episode_count": eligible,
            "canonical_episode_set_sha256": _digest(
                manifest["canonical_episode_set_sha256"],
                "canonical_episode_set_sha256",
            ),
            "source_cost": {"amount_micros": amount, "currency": currency},
        }
    )
    if schema == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA:
        for key in (
            "snapshot_binding_sha256",
            "snapshot_manifest_sha256",
            "input_attestation_receipt_sha256",
            "bundle_manifest_sha256",
        ):
            normalized[key] = _digest(manifest[key], key)
    _canonical_json_bytes(
        normalized, label="workflow learning episode manifest", limit=_MAX_MANIFEST_BYTES
    )
    return normalized


def _reconcile_attested_episode_input(
    *,
    episodes: Mapping[str, Any],
    input_custody: Mapping[str, Any],
    installation_id: str,
    revision_id: str,
    project_id: str | None,
) -> dict[str, Any]:
    if episodes.get("schema") != WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA:
        raise WorkflowLearningHandoffError(
            "verified input custody may only bind a v2 attested episode manifest"
        )
    expected = build_attested_workflow_learning_episode_manifest(
        input_custody,
        installation_id=installation_id,
        revision_id=revision_id,
        project_id=project_id,
    )
    if _canonical_json_bytes(
        episodes,
        label="attested workflow learning episode manifest",
        limit=_MAX_MANIFEST_BYTES,
    ) != _canonical_json_bytes(
        expected,
        label="verified input custody episode manifest",
        limit=_MAX_MANIFEST_BYTES,
    ):
        raise WorkflowLearningHandoffError(
            "workflow learning episode manifest does not match verified input custody"
        )
    custody = parse_training_pair_input_custody(
        input_custody,
        installation_id=installation_id,
        revision_id=revision_id,
        project_id=project_id,
    )
    receipt = _mapping(custody["receipt_summary"], "training input custody receipt")
    snapshot = _mapping(receipt["snapshot"], "training input custody snapshot")
    return {
        "schema": custody["schema"],
        "association_status": "verified",
        "receipt_verified": True,
        "receipt_digest": receipt["receipt_digest"],
        "bundle_manifest_sha256": receipt["bundle_manifest_sha256"],
        "snapshot": {
            "binding_sha256": snapshot["binding_sha256"],
            "manifest_sha256": snapshot["manifest_sha256"],
            "dataset_sha256": snapshot["dataset_sha256"],
            "episode_count": snapshot["episode_count"],
            "training_sample_count": snapshot["training_sample_count"],
            "evaluation_sample_count": snapshot["evaluation_sample_count"],
        },
        "source_cost": dict(_mapping(receipt["source_cost"], "input custody source_cost")),
        "lanes": [
            {
                "lane": lane["lane"],
                "framework_pin": lane["framework_pin"],
                "custody_verified": True,
            }
            for lane in receipt["lanes"]
        ],
        "admission_available": False,
        "execution_surface_available": False,
    }


def _event_type(event: Mapping[str, Any]) -> str:
    return str(_field(event, "eventType", "event_type") or "").strip().upper()


def _approval_scope(event: Mapping[str, Any]) -> str | None:
    value = _field(event, "approvalScope", "approval_scope")
    return str(value).strip().upper() if value is not None else None


def _validate_audit_trail(
    events: Iterable[Mapping[str, Any]],
    *,
    packet_id: str,
    delivery_id: str,
    candidate_manifest_sha256: str,
    candidate_manifest: Mapping[str, Any],
    delivery: Mapping[str, Any],
) -> dict[str, str]:
    rows = [_mapping(row, "workflow improvement audit event") for row in events]
    if not rows or len(rows) > 100:
        raise WorkflowLearningHandoffError(
            "workflow improvement audit must contain between 1 and 100 events"
        )

    previous_hash: str | None = None
    for index, row in enumerate(rows):
        if _uuid(_field(row, "packetId", "packet_id"), "audit packet_id") != packet_id:
            raise WorkflowLearningHandoffError("workflow improvement audit escaped packet scope")
        event_hash = _digest(_field(row, "eventHash", "event_hash"), "audit event_hash")
        observed_previous = _field(row, "previousHash", "previous_hash")
        if index == 0:
            if observed_previous not in (None, ""):
                raise WorkflowLearningHandoffError("workflow improvement audit does not start at its root")
        elif str(observed_previous or "").lower() != previous_hash:
            raise WorkflowLearningHandoffError("workflow improvement audit hash linkage is broken")
        previous_hash = event_hash

    matched: list[dict[str, Any]] = []
    cursor = -1
    for expected_type, expected_scope in _REQUIRED_AUDIT_SEQUENCE:
        found: tuple[int, dict[str, Any]] | None = None
        for index in range(cursor + 1, len(rows)):
            row = rows[index]
            if _event_type(row) != expected_type:
                continue
            if expected_scope is not None and _approval_scope(row) != expected_scope:
                continue
            found = (index, row)
            break
        if found is None:
            raise WorkflowLearningHandoffError(
                f"workflow improvement audit is missing ordered {expected_type} evidence"
            )
        cursor, row = found
        matched.append(row)

    approval, _, _, implementation, _, _, _, _, canary, cleaned = matched
    if str(approval.get("decision") or "").strip().upper() != "APPROVED":
        raise WorkflowLearningHandoffError("workflow implementation approval was not approved")
    for row in matched[1:]:
        observed_delivery = _uuid(
            _field(row, "deliveryId", "delivery_id"), "audit delivery_id"
        )
        if observed_delivery != delivery_id:
            raise WorkflowLearningHandoffError("workflow improvement audit escaped delivery scope")

    implementation_evidence = _mapping(
        implementation.get("evidence"), "implementation completion evidence"
    )
    if implementation_evidence.get("acceptance_checks_passed") is not True:
        raise WorkflowLearningHandoffError("implementation evidence did not pass acceptance checks")
    if _digest(
        implementation_evidence.get("learning_candidate_manifest_sha256"),
        "implementation candidate manifest digest",
    ) != candidate_manifest_sha256:
        raise WorkflowLearningHandoffError(
            "implementation evidence does not bind the supplied candidate manifest"
        )
    if _commit(
        implementation_evidence.get("repository_commit"),
        "implementation repository_commit",
    ) != candidate_manifest["repository_commit"]:
        raise WorkflowLearningHandoffError(
            "implementation evidence does not bind the candidate repository commit"
        )

    delivery_comparison = _mapping(delivery.get("comparison"), "delivery comparison")
    if delivery_comparison.get("passed") is not True:
        raise WorkflowLearningHandoffError("delivery canary comparison did not pass")
    regressions = delivery_comparison.get("regressions")
    if not isinstance(regressions, list) or regressions:
        raise WorkflowLearningHandoffError("delivery canary comparison contains regressions")
    canary_evidence = _mapping(canary.get("evidence"), "canary evaluation evidence")
    audit_comparison = _mapping(
        canary_evidence.get("comparison"), "audit canary comparison"
    )
    if _sha256_json(audit_comparison, label="audit canary comparison") != _sha256_json(
        delivery_comparison, label="delivery canary comparison"
    ):
        raise WorkflowLearningHandoffError("delivery comparison drifted from immutable audit evidence")
    cleaned_evidence = _mapping(cleaned.get("evidence"), "staging cleanup evidence")
    if str(cleaned_evidence.get("final_status") or "").strip().upper() != "CANARY_PASSED":
        raise WorkflowLearningHandoffError("staging cleanup did not preserve a passing canary")

    return {
        "implementation_approval_event_hash": _digest(
            _field(approval, "eventHash", "event_hash"), "approval event_hash"
        ),
        "implementation_event_hash": _digest(
            _field(implementation, "eventHash", "event_hash"),
            "implementation event_hash",
        ),
        "canary_event_hash": _digest(
            _field(canary, "eventHash", "event_hash"), "canary event_hash"
        ),
        "terminal_event_hash": _digest(
            _field(cleaned, "eventHash", "event_hash"), "terminal event_hash"
        ),
    }


def compile_workflow_learning_handoff(
    *,
    packet: Mapping[str, Any],
    delivery: Mapping[str, Any],
    audit_events: Iterable[Mapping[str, Any]],
    candidate_manifest: Mapping[str, Any],
    episode_manifest: Mapping[str, Any] | None,
    training_readiness: Mapping[str, Any],
    installation_id: str,
    revision_id: str,
    project_id: str | None = None,
    training_input_custody: Mapping[str, Any] | None = None,
    candidate_artifact_attestation: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compile a privacy-minimized candidate handoff with no training authority."""
    packet_value = _mapping(packet, "workflow improvement packet")
    delivery_value = _mapping(delivery, "workflow improvement delivery")
    packet_id = _uuid(packet_value.get("id"), "packet_id")
    delivery_id = _uuid(delivery_value.get("id"), "delivery_id")
    generated = now or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    generated = generated.astimezone(timezone.utc)
    if _uuid(
        _field(delivery_value, "packetId", "packet_id"), "delivery packet_id"
    ) != packet_id:
        raise WorkflowLearningHandoffError("delivery does not belong to the workflow packet")
    if str(packet_value.get("status") or "").strip().upper() != "STAGING_VALIDATED":
        raise WorkflowLearningHandoffError("workflow packet must be STAGING_VALIDATED")
    if str(delivery_value.get("status") or "").strip().upper() != "COMPLETED":
        raise WorkflowLearningHandoffError("workflow delivery must be COMPLETED")
    environment = str(delivery_value.get("environment") or "").strip().lower()
    if not (
        environment == "staging"
        or environment.startswith("staging-")
        or environment.startswith("disposable-")
    ):
        raise WorkflowLearningHandoffError("workflow learning requires a staging delivery")
    branch_name = str(
        _field(delivery_value, "branchName", "branch_name") or ""
    ).strip()
    if not branch_name.startswith("codex/"):
        raise WorkflowLearningHandoffError("workflow delivery branch is not server-isolated")
    if _field(delivery_value, "rollbackRef", "rollback_ref") not in (None, ""):
        raise WorkflowLearningHandoffError("rolled-back delivery cannot enter learning")

    normalized_installation = _uuid(installation_id, "installation_id")
    normalized_revision = _uuid(revision_id, "revision_id")
    normalized_project = _optional_uuid(project_id, "project_id")
    candidate = _candidate_manifest(candidate_manifest)
    candidate_attestation = None
    if candidate_artifact_attestation is not None:
        candidate_attestation = _candidate_artifact_attestation(
            candidate_artifact_attestation,
            packet_id=packet_id,
            delivery_id=delivery_id,
            candidate=candidate,
            observed_now=generated,
        )
    if episode_manifest is None:
        if training_input_custody is None:
            raise WorkflowLearningHandoffError(
                "episode_manifest or verified training_input_custody is required"
            )
        episode_manifest = build_attested_workflow_learning_episode_manifest(
            training_input_custody,
            installation_id=normalized_installation,
            revision_id=normalized_revision,
            project_id=normalized_project,
        )
    episodes = _episode_manifest(episode_manifest)
    custody_evidence = None
    if training_input_custody is not None:
        custody_evidence = _reconcile_attested_episode_input(
            episodes=episodes,
            input_custody=training_input_custody,
            installation_id=normalized_installation,
            revision_id=normalized_revision,
            project_id=normalized_project,
        )
    elif episodes["schema"] == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA:
        raise WorkflowLearningHandoffError(
            "v2 attested episode manifest requires verified training input custody"
        )
    candidate_manifest_digest = _sha256_json(
        candidate, label="workflow learning candidate manifest"
    )
    episode_manifest_digest = _sha256_json(
        episodes, label="workflow learning episode manifest"
    )
    audit = _validate_audit_trail(
        audit_events,
        packet_id=packet_id,
        delivery_id=delivery_id,
        candidate_manifest_sha256=candidate_manifest_digest,
        candidate_manifest=candidate,
        delivery=delivery_value,
    )

    try:
        readiness = parse_training_pair_readiness(
            training_readiness,
            installation_id=normalized_installation,
            revision_id=normalized_revision,
            project_id=normalized_project,
        )
    except (AgentOpsProtocolError, ValidationError, ValueError) as exc:
        raise WorkflowLearningHandoffError(
            f"training readiness is not an exact read-only contract: {exc}"
        ) from exc
    if readiness.get("source_valid") and readiness.get("action") != candidate["workflow_key"]:
        raise WorkflowLearningHandoffError(
            "candidate workflow_key does not match the exact Marketplace action"
        )

    generated_at = generated.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    custody_resolved = custody_evidence is not None
    candidate_attestation_resolved = bool(
        candidate_attestation and candidate_attestation["verified"]
    )
    readiness_blockers = [
        str(item)
        for item in readiness["blockers"]
        if not (
            custody_resolved
            and item in {"artifact_storage_unavailable", "input_attestation_unavailable"}
        )
    ]
    blockers = list(
        dict.fromkeys(
            [
                *(
                    []
                    if candidate_attestation_resolved
                    else ["candidate_artifact_attestation_required"]
                ),
                *([] if custody_resolved else ["episode_input_attestation_required"]),
                *readiness_blockers,
            ]
        )
    )
    core = {
        "packet_id": packet_id,
        "delivery_id": delivery_id,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "episode_manifest_sha256": episode_manifest_digest,
        "installation_id": normalized_installation,
        "revision_id": normalized_revision,
        "project_id": normalized_project,
        "terminal_audit_event_hash": audit["terminal_event_hash"],
    }
    if custody_resolved:
        core["input_attestation_receipt_sha256"] = custody_evidence["receipt_digest"]
    if candidate_attestation_resolved:
        core.update(
            {
                "candidate_artifact_attestation_scope_sha256": (
                    candidate_attestation["scope_sha256"]
                ),
                "candidate_artifact_attestation_key_fingerprint_sha256": (
                    candidate_attestation["key_fingerprint_sha256"]
                ),
                "candidate_artifact_attestation_expires_at": (
                    candidate_attestation["expires_at"]
                ),
            }
        )
    handoff_id = "workflow-learning-" + _sha256_json(
        core, label="workflow learning handoff identity"
    )[:24]
    handoff = {
        "schema": (
            WORKFLOW_LEARNING_CANDIDATE_ATTESTED_HANDOFF_SCHEMA
            if candidate_attestation_resolved
            else (
                WORKFLOW_LEARNING_ATTESTED_HANDOFF_SCHEMA
                if custody_resolved
                else WORKFLOW_LEARNING_HANDOFF_SCHEMA
            )
        ),
        "handoff_id": handoff_id,
        "generated_at": generated_at,
        "mode": (
            "read_only_candidate_and_input_attested_handoff"
            if candidate_attestation_resolved and custody_resolved
            else (
                "read_only_candidate_attested_handoff"
                if candidate_attestation_resolved
                else (
                    "read_only_attested_input_handoff"
                    if custody_resolved
                    else "read_only_candidate_handoff"
                )
            )
        ),
        "status": "blocked",
        "source": {
            "installation_id": normalized_installation,
            "revision_id": normalized_revision,
            "project_id": normalized_project,
            "project_scoped": normalized_project is not None,
            "domain": readiness.get("domain"),
            "action": readiness.get("action"),
            "source_valid": readiness["source_valid"],
        },
        "candidate": candidate,
        "candidate_manifest_sha256": candidate_manifest_digest,
        "episodes": episodes,
        "episode_manifest_sha256": episode_manifest_digest,
        "delivery_provenance": {
            "packet_id": packet_id,
            "delivery_id": delivery_id,
            "environment": environment,
            "branch_name": branch_name,
            **audit,
        },
        "paired_evaluation": {
            "lanes": [
                {
                    "lane": lane["lane"],
                    "status": "input_ready" if custody_resolved else lane["status"],
                    "input_attested": custody_resolved or lane["input_attested"],
                    "training_input_ready": (
                        custody_resolved or lane["training_input_ready"]
                    ),
                    "evaluation_input_ready": (
                        custody_resolved or lane["evaluation_input_ready"]
                    ),
                    "blockers": [] if custody_resolved else list(lane["blockers"]),
                }
                for lane in readiness["lanes"]
            ],
            "same_success_contract_required": True,
            "exact_prior_revision_required": True,
            "held_out_evaluator_required": True,
            "paired_promotion_required": True,
        },
        "readiness": {
            "ready": False,
            "source_valid": readiness["source_valid"],
            "blockers": blockers,
            "stages": [
                (
                    {"code": stage["code"], "status": "ready", "blockers": []}
                    if custody_resolved
                    and stage["code"] in {"artifact_storage", "input_attestation"}
                    else dict(stage)
                )
                for stage in readiness["stages"]
            ],
            "next_action": (
                readiness["next_action"]
                if candidate_attestation_resolved
                else {
                    "code": "attest_candidate_artifact",
                    "message": (
                        "Persist and attest the exact candidate artifact before "
                        "requesting any learning authority."
                    ),
                }
                if custody_resolved
                else readiness["next_action"]
            ),
        },
        "authority": dict(_AUTHORITY_DENIALS),
        "safety": {
            "raw_artifact_included": False,
            "raw_episode_content_included": False,
            "caller_scope_ids_accepted": False,
            "model_selected_budget_accepted": False,
            "provider_or_connector_call_performed": False,
            "production_write_performed": False,
        },
    }
    if custody_resolved:
        handoff["training_input_custody"] = custody_evidence
        handoff["safety"]["input_custody_verified"] = True
    if candidate_attestation is not None:
        handoff["candidate_artifact_attestation"] = candidate_attestation
    if candidate_attestation_resolved:
        handoff["safety"]["candidate_artifact_attestation_verified"] = True
    _canonical_json_bytes(
        handoff, label="workflow learning handoff", limit=_MAX_HANDOFF_BYTES
    )
    return handoff


__all__ = [
    "WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA",
    "WORKFLOW_LEARNING_ATTESTED_HANDOFF_SCHEMA",
    "WORKFLOW_LEARNING_CANDIDATE_ATTESTED_HANDOFF_SCHEMA",
    "WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCHEMA",
    "WORKFLOW_LEARNING_CANDIDATE_ATTESTATION_SCOPE_SCHEMA",
    "WORKFLOW_LEARNING_CANDIDATE_KINDS",
    "WORKFLOW_LEARNING_CANDIDATE_SCHEMA",
    "WORKFLOW_LEARNING_EPISODE_SCHEMA",
    "WORKFLOW_LEARNING_HANDOFF_SCHEMA",
    "WORKFLOW_LEARNING_LANES",
    "WorkflowLearningHandoffError",
    "build_attested_workflow_learning_episode_manifest",
    "compile_workflow_learning_handoff",
    "workflow_learning_candidate_manifest_sha256",
    "workflow_learning_candidate_attestation_scope_sha256",
]
