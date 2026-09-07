"""Deterministic, bounded JSON transport for Project401 context capsules.

The SDK runtimes pass shared context to the Project401 MCP bridge through an
environment variable.  This module owns that wire representation so producers
never truncate an encoded JSON string and consumers can verify that the
capsule arrived intact.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping, Optional


CONTEXT_CAPSULE_METADATA_KEY = "_context_capsule"
CONTEXT_CAPSULE_SCHEMA_VERSION = "project401.context-capsule.transport.v1"
DEFAULT_BYTES_PER_TOKEN = 4


class ContextCapsuleError(ValueError):
    """Base error for an invalid context-capsule transport."""


class ContextCapsuleBudgetError(ContextCapsuleError):
    """Raised when required capsule content cannot fit the declared budget."""


class ContextCapsuleDecodeError(ContextCapsuleError):
    """Raised when a capsule is not a valid JSON object."""


class ContextCapsuleIntegrityError(ContextCapsuleError):
    """Raised when capsule metadata, digest, or trusted identity is invalid."""


_IDENTITY_AND_SCOPE_KEYS = frozenset(
    {
        "tenant_id",
        "company_id",
        "user_id",
        "project_id",
        "workspace_id",
        "workspace_session_id",
        "assistant_conversation_id",
        "conversation_id",
        "artifact_lineage_id",
        "workflow_instance_id",
        "parent_workflow_instance_id",
        "handoff_context_id",
        "trace_id",
        "step_id",
        "agent_name",
        "requested_scope",
        "scope",
    }
)

# These fields carry upstream integrity and compaction provenance.  When they
# are already present they are required transport content, never optional data
# that may be discarded to make room.
_UPSTREAM_INTEGRITY_KEYS = frozenset(
    {
        "execution_grant_digest",
        "scope_digest",
        "context_digest",
        "capsule_digest",
        "compaction",
        "compaction_metadata",
    }
)

# Higher values survive longer.  Unknown fields have the middle priority so
# new context fields degrade predictably without requiring a serializer change.
_OPTIONAL_FIELD_PRIORITY = {
    "specialist_registry": 5,
    "rspl_tool_description_overlays": 8,
    "rspl_bundle": 10,
    "managed_skills": 20,
    "workspace_object_refs": 25,
    "artifact_handles": 30,
    "connector_tools": 35,
    "linked_workflow_ids": 40,
    "linked_claude_workspace": 42,
    "claude_code_workspace": 42,
    "handoff_context": 45,
    "plan_context": 50,
    "conversation_history": 55,
    "memory_context": 60,
    "rlm_child_summaries": 65,
    "context_summary": 80,
    "delegation_context_receipt": 88,
    "delegation_context": 90,
    "objective": 100,
}

# Each level is (maximum string code points, list items, object keys, depth).
# Strings are sliced before JSON encoding, so a multibyte UTF-8 character can
# never be split into malformed transport bytes.
_COMPACTION_LEVELS = (
    (4096, 48, 64, 10),
    (2048, 32, 48, 8),
    (1024, 20, 32, 7),
    (512, 12, 20, 6),
    (256, 8, 12, 5),
    (128, 4, 8, 4),
    (64, 2, 4, 3),
    (32, 1, 2, 2),
)


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContextCapsuleError("context capsule contains a non-JSON value") from exc


def _safe_json_value(
    value: Any,
    *,
    depth: int = 0,
    active_ids: Optional[set[int]] = None,
) -> Any:
    """Return a deterministic JSON-safe value without unbounded recursion."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        if math.isnan(value):
            return "NaN"
        return "Infinity" if value > 0 else "-Infinity"
    if isinstance(value, Path):
        return str(value)
    if depth >= 32:
        return {"_compacted": True, "reason": "maximum_depth"}

    active_ids = active_ids if active_ids is not None else set()
    container = isinstance(value, (Mapping, list, tuple, set, frozenset))
    value_id = id(value)
    if container:
        if value_id in active_ids:
            return {"_compacted": True, "reason": "cycle"}
        active_ids.add(value_id)
    try:
        if isinstance(value, Mapping):
            normalized: dict[str, Any] = {}
            ordered_items = sorted(
                value.items(),
                key=lambda item: (str(item[0]), type(item[0]).__name__),
            )
            for raw_key, raw_value in ordered_items:
                key = str(raw_key)
                # JSON itself collapses keys such as 1 and "1".  Reject the
                # ambiguous source instead of producing a digest over data that
                # silently changed identity.
                if key in normalized:
                    raise ContextCapsuleError(
                        f"context capsule contains colliding object key {key!r}"
                    )
                normalized[key] = _safe_json_value(
                    raw_value,
                    depth=depth + 1,
                    active_ids=active_ids,
                )
            return normalized
        if isinstance(value, (list, tuple)):
            return [
                _safe_json_value(item, depth=depth + 1, active_ids=active_ids)
                for item in value
            ]
        if isinstance(value, (set, frozenset)):
            normalized_items = [
                _safe_json_value(item, depth=depth + 1, active_ids=active_ids)
                for item in value
            ]
            return sorted(normalized_items, key=_canonical_json_bytes)
        isoformat = getattr(value, "isoformat", None)
        if callable(isoformat):
            try:
                return str(isoformat())
            except Exception:
                pass
        return str(value)
    finally:
        if container:
            active_ids.discard(value_id)


def _ordered_object_keys(value: Mapping[str, Any]) -> list[str]:
    return sorted(
        value,
        key=lambda key: (
            -int(_OPTIONAL_FIELD_PRIORITY.get(str(key), 50)),
            str(key),
        ),
    )


def _compact_value(
    value: Any,
    *,
    string_limit: int,
    list_limit: int,
    object_limit: int,
    depth_limit: int,
    depth: int = 0,
) -> Any:
    if isinstance(value, str):
        if len(value) <= string_limit:
            return value
        if string_limit <= 1:
            return "…"[:string_limit]
        return value[: string_limit - 1] + "…"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= depth_limit:
        if isinstance(value, list):
            return []
        if isinstance(value, dict):
            return {}
        return value
    if isinstance(value, list):
        return [
            _compact_value(
                item,
                string_limit=string_limit,
                list_limit=list_limit,
                object_limit=object_limit,
                depth_limit=depth_limit,
                depth=depth + 1,
            )
            for item in value[:list_limit]
        ]
    if isinstance(value, dict):
        keys = _ordered_object_keys(value)[:object_limit]
        return {
            key: _compact_value(
                value[key],
                string_limit=string_limit,
                list_limit=list_limit,
                object_limit=object_limit,
                depth_limit=depth_limit,
                depth=depth + 1,
            )
            for key in keys
        }
    return value


def _field_label(key: str) -> str:
    if len(key) <= 96:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{key[:72]}…#{digest}"


def _render_capsule(
    payload: dict[str, Any],
    *,
    source_digest: str,
    source_bytes: int,
    budget_bytes: int,
    requested_max_tokens: Optional[int],
    bytes_per_token: int,
    required_keys: set[str],
    transformed_fields: set[str],
    dropped_fields: set[str],
) -> bytes:
    payload_bytes = _canonical_json_bytes(payload)
    compacted = bool(transformed_fields or dropped_fields or len(payload_bytes) != source_bytes)
    compaction: dict[str, Any] = {
        "applied": compacted,
        "strategy": "deterministic-priority-v1",
        "budget_bytes": budget_bytes,
        "original_bytes": source_bytes,
        "retained_payload_bytes": len(payload_bytes),
        "serialized_bytes": 0,
        "estimated_tokens": 0,
        "bytes_per_token": bytes_per_token,
        "required_fields": sorted(_field_label(key) for key in required_keys),
        "transformed_optional_fields": sorted(transformed_fields),
        "dropped_optional_fields": sorted(dropped_fields),
    }
    if requested_max_tokens is not None:
        compaction["budget_tokens"] = requested_max_tokens
    metadata = {
        "schema_version": CONTEXT_CAPSULE_SCHEMA_VERSION,
        "source_digest": source_digest,
        "capsule_digest": hashlib.sha256(payload_bytes).hexdigest(),
        # A fixed-width placeholder lets serialized_bytes reach its numeric
        # fixed point before the transport digest binds the complete metadata.
        "transport_digest": "0" * 64,
        "compaction": compaction,
    }
    document = dict(payload)
    document[CONTEXT_CAPSULE_METADATA_KEY] = metadata

    # serialized_bytes and estimated_tokens describe the canonical document
    # that contains those values.  Iterate to the small numeric fixed point.
    rendered = b""
    for _ in range(8):
        rendered = _canonical_json_bytes(document)
        serialized_bytes = len(rendered)
        estimated_tokens = math.ceil(serialized_bytes / bytes_per_token)
        if (
            compaction["serialized_bytes"] == serialized_bytes
            and compaction["estimated_tokens"] == estimated_tokens
        ):
            break
        compaction["serialized_bytes"] = serialized_bytes
        compaction["estimated_tokens"] = estimated_tokens
    rendered = _canonical_json_bytes(document)
    if (
        compaction["serialized_bytes"] != len(rendered)
        or compaction["estimated_tokens"]
        != math.ceil(len(rendered) / bytes_per_token)
    ):
        raise ContextCapsuleIntegrityError(
            "context capsule size metadata did not reach a fixed point"
        )
    digest_document = dict(document)
    digest_metadata = dict(metadata)
    digest_metadata.pop("transport_digest", None)
    digest_document[CONTEXT_CAPSULE_METADATA_KEY] = digest_metadata
    metadata["transport_digest"] = hashlib.sha256(
        _canonical_json_bytes(digest_document)
    ).hexdigest()
    return _canonical_json_bytes(document)


def serialize_context_capsule(
    context: Mapping[str, Any],
    *,
    max_bytes: int,
    max_tokens: Optional[int] = None,
    bytes_per_token: int = DEFAULT_BYTES_PER_TOKEN,
    authoritative_identity: Optional[Mapping[str, Any]] = None,
) -> str:
    """Serialize ``context`` as canonical, digest-bound JSON within a budget.

    Trusted identity values overwrite the matching payload fields.  A key
    explicitly supplied with ``None`` or an empty string removes that field,
    which lets a broad scope prevent an untrusted company id from leaking into
    the capsule.  Required identity, scope, and upstream digest/compaction
    fields are never truncated; the function fails explicitly if they and the
    transport metadata cannot fit.
    """

    if not isinstance(context, Mapping):
        raise ContextCapsuleError("context capsule payload must be an object")
    if isinstance(max_bytes, bool) or int(max_bytes) <= 0:
        raise ContextCapsuleBudgetError("context capsule max_bytes must be positive")
    if isinstance(bytes_per_token, bool) or int(bytes_per_token) <= 0:
        raise ContextCapsuleBudgetError("context capsule bytes_per_token must be positive")
    max_bytes = int(max_bytes)
    bytes_per_token = int(bytes_per_token)
    requested_max_tokens: Optional[int] = None
    if max_tokens is not None:
        if isinstance(max_tokens, bool) or int(max_tokens) <= 0:
            raise ContextCapsuleBudgetError("context capsule max_tokens must be positive")
        requested_max_tokens = int(max_tokens)
        max_bytes = min(max_bytes, requested_max_tokens * bytes_per_token)

    normalized = _safe_json_value(context)
    if not isinstance(normalized, dict):  # defensive; Mapping normalizes to dict
        raise ContextCapsuleError("context capsule payload must normalize to an object")
    normalized.pop(CONTEXT_CAPSULE_METADATA_KEY, None)

    authoritative_keys: set[str] = set()
    if authoritative_identity is not None:
        if not isinstance(authoritative_identity, Mapping):
            raise ContextCapsuleError("authoritative_identity must be an object")
        for raw_key, raw_value in authoritative_identity.items():
            key = str(raw_key)
            authoritative_keys.add(key)
            if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
                normalized.pop(key, None)
                continue
            normalized[key] = _safe_json_value(raw_value)

    required_keys = {
        key
        for key in normalized
        if key in _IDENTITY_AND_SCOPE_KEYS or key in _UPSTREAM_INTEGRITY_KEYS
    }
    required_keys.update(key for key in authoritative_keys if key in normalized)

    source_bytes_value = _canonical_json_bytes(normalized)
    source_digest = hashlib.sha256(source_bytes_value).hexdigest()

    def render(
        payload: dict[str, Any],
        transformed: set[str],
        dropped: set[str],
    ) -> bytes:
        return _render_capsule(
            payload,
            source_digest=source_digest,
            source_bytes=len(source_bytes_value),
            budget_bytes=max_bytes,
            requested_max_tokens=requested_max_tokens,
            bytes_per_token=bytes_per_token,
            required_keys=required_keys,
            transformed_fields=transformed,
            dropped_fields=dropped,
        )

    rendered = render(normalized, set(), set())
    if len(rendered) <= max_bytes:
        return rendered.decode("utf-8")

    working = dict(normalized)
    transformed_fields: set[str] = set()
    dropped_fields: set[str] = set()
    optional_keys = sorted(
        (key for key in normalized if key not in required_keys),
        key=lambda key: (int(_OPTIONAL_FIELD_PRIORITY.get(key, 50)), key),
    )

    for key in optional_keys:
        original_value = normalized[key]
        previous_value = original_value
        label = _field_label(key)
        for string_limit, list_limit, object_limit, depth_limit in _COMPACTION_LEVELS:
            compacted_value = _compact_value(
                original_value,
                string_limit=string_limit,
                list_limit=list_limit,
                object_limit=object_limit,
                depth_limit=depth_limit,
            )
            if compacted_value == previous_value:
                continue
            previous_value = compacted_value
            working[key] = compacted_value
            transformed_fields.add(label)
            rendered = render(working, transformed_fields, dropped_fields)
            if len(rendered) <= max_bytes:
                return rendered.decode("utf-8")

        working.pop(key, None)
        transformed_fields.discard(label)
        dropped_fields.add(label)
        rendered = render(working, transformed_fields, dropped_fields)
        if len(rendered) <= max_bytes:
            return rendered.decode("utf-8")

    required_rendered = render(working, transformed_fields, dropped_fields)
    raise ContextCapsuleBudgetError(
        "required context capsule identity/scope and integrity metadata exceed "
        f"the {max_bytes}-byte transport budget "
        f"(minimum={len(required_rendered)} bytes)"
    )


def _raise_invalid_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def _validate_expected_identity(
    payload: dict[str, Any],
    expected_identity: Optional[Mapping[str, Any]],
    *,
    metadata_present: bool,
) -> None:
    if expected_identity is None:
        return
    for raw_key, raw_expected in expected_identity.items():
        key = str(raw_key)
        expected_missing = raw_expected is None or (
            isinstance(raw_expected, str) and not raw_expected.strip()
        )
        actual_present = key in payload and payload.get(key) not in (None, "")
        if expected_missing:
            if actual_present:
                raise ContextCapsuleIntegrityError(
                    f"context capsule contains unauthorized identity field {key!r}"
                )
            payload.pop(key, None)
            continue

        expected = _safe_json_value(raw_expected)
        if actual_present:
            if payload.get(key) != expected:
                raise ContextCapsuleIntegrityError(
                    f"context capsule identity mismatch for {key!r}"
                )
            continue
        if metadata_present:
            raise ContextCapsuleIntegrityError(
                f"context capsule is missing required identity field {key!r}"
            )
        # Compatibility for valid legacy (pre-digest) capsule JSON.  Invalid
        # JSON still raises and is never replaced with an empty object.
        payload[key] = expected


def deserialize_context_capsule(
    raw: Optional[str],
    *,
    expected_identity: Optional[Mapping[str, Any]] = None,
    require_metadata: bool = False,
) -> dict[str, Any]:
    """Parse and verify a context capsule.

    Empty input means no capsule.  Malformed JSON, a non-object payload,
    missing required metadata, digest mismatch, budget mismatch, and trusted
    identity mismatch all raise explicit errors rather than erasing context.
    Valid pre-v1 JSON objects remain readable during rollout; trusted missing
    identity fields are attached in memory, while conflicts still fail closed.
    """

    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text, parse_constant=_raise_invalid_constant)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ContextCapsuleDecodeError(
            "PROJECT401_SHARED_CONTEXT is not valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise ContextCapsuleDecodeError(
            "PROJECT401_SHARED_CONTEXT must be a JSON object"
        )

    metadata = parsed.get(CONTEXT_CAPSULE_METADATA_KEY)
    metadata_present = metadata is not None
    if not metadata_present:
        if require_metadata:
            raise ContextCapsuleIntegrityError(
                "context capsule integrity metadata is required"
            )
        _validate_expected_identity(
            parsed,
            expected_identity,
            metadata_present=False,
        )
        return parsed
    if not isinstance(metadata, dict):
        raise ContextCapsuleIntegrityError("context capsule metadata must be an object")
    if metadata.get("schema_version") != CONTEXT_CAPSULE_SCHEMA_VERSION:
        raise ContextCapsuleIntegrityError("unsupported context capsule schema version")
    compaction = metadata.get("compaction")
    if not isinstance(compaction, dict):
        raise ContextCapsuleIntegrityError("context capsule compaction metadata is missing")

    transport_digest = metadata.get("transport_digest")
    if not isinstance(transport_digest, str) or len(transport_digest) != 64:
        raise ContextCapsuleIntegrityError("context capsule transport digest is invalid")
    digest_document = dict(parsed)
    digest_metadata = dict(metadata)
    digest_metadata.pop("transport_digest", None)
    digest_document[CONTEXT_CAPSULE_METADATA_KEY] = digest_metadata
    expected_transport_digest = hashlib.sha256(
        _canonical_json_bytes(digest_document)
    ).hexdigest()
    if transport_digest != expected_transport_digest:
        raise ContextCapsuleIntegrityError("context capsule transport metadata digest mismatch")

    payload = dict(parsed)
    payload.pop(CONTEXT_CAPSULE_METADATA_KEY, None)
    expected_digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    if metadata.get("capsule_digest") != expected_digest:
        raise ContextCapsuleIntegrityError("context capsule digest mismatch")
    source_digest = metadata.get("source_digest")
    if not isinstance(source_digest, str) or len(source_digest) != 64:
        raise ContextCapsuleIntegrityError("context capsule source digest is invalid")

    canonical_size = len(_canonical_json_bytes(parsed))
    declared_size = compaction.get("serialized_bytes")
    budget_bytes = compaction.get("budget_bytes")
    if isinstance(declared_size, bool) or not isinstance(declared_size, int):
        raise ContextCapsuleIntegrityError("context capsule serialized byte count is invalid")
    if declared_size != canonical_size:
        raise ContextCapsuleIntegrityError("context capsule serialized byte count mismatch")
    if isinstance(budget_bytes, bool) or not isinstance(budget_bytes, int) or budget_bytes <= 0:
        raise ContextCapsuleIntegrityError("context capsule byte budget is invalid")
    if canonical_size > budget_bytes:
        raise ContextCapsuleIntegrityError("context capsule exceeds its declared byte budget")

    _validate_expected_identity(
        payload,
        expected_identity,
        metadata_present=True,
    )
    return parsed


__all__ = [
    "CONTEXT_CAPSULE_METADATA_KEY",
    "CONTEXT_CAPSULE_SCHEMA_VERSION",
    "ContextCapsuleBudgetError",
    "ContextCapsuleDecodeError",
    "ContextCapsuleError",
    "ContextCapsuleIntegrityError",
    "deserialize_context_capsule",
    "serialize_context_capsule",
]
