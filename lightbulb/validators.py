"""Input validators used to prevent path traversal and header injection.

Centralised here so client.py and async_client.py share the same regexes,
and so allowlists for things like ``action`` and ``provider`` live in one
place.

Every value that gets interpolated into a URL path component MUST go through
one of these validators. The platform does its own auth, but the SDK promises
defence-in-depth.
"""

from __future__ import annotations

import re
from typing import Iterable

from .errors import ValidationError


# ── Generic regexes ──────────────────────────────────────────────────

# Permissive identifier: dotted/dashed/underscored alnum, length-bounded. Used
# for IDs we don't strictly know the shape of (workspace_id, run_id, etc.).
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# UUID v1-5 (case-insensitive)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Tool key (Claude/Codex/etc. workspace tools): segments separated by dots.
_TOOL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$")

# OAuth-style token (URL-safe base64-ish). 1+ chars, length-bounded.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~=+/-]{1,2048}$")


# ── Allowlists ───────────────────────────────────────────────────────

CLAUDE_SESSION_ACTIONS: frozenset[str] = frozenset({
    "rename", "tag", "fork", "delete", "interrupt",
    "mcp/reconnect", "mcp/toggle", "rewind",
    "tasks/stop", "compact",
})

CODEX_THREAD_ACTIONS: frozenset[str] = frozenset({
    "rename", "archive", "unarchive", "compact", "rollback",
})

CODEX_TURN_ACTIONS: frozenset[str] = frozenset({"steer", "interrupt"})

IT_OPS_LIVE_CONNECTORS: frozenset[str] = frozenset({"jira", "slack", "github", "notion"})

MARKETING_PROVIDERS: frozenset[str] = frozenset({
    "ga4", "ga", "google_analytics",
    "segment", "plausible", "matomo", "mixpanel",
    "amplitude", "posthog", "fathom",
})

XERO_PLAYBOOKS: frozenset[str] = frozenset({
    "month_end_close", "ar_followup", "ap_intake_to_pay",
    "bank_reconciliation", "payroll_trueup", "reporting_pack", "consolidation",
})

HTTP_METHODS: frozenset[str] = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
})


# ── Validators ───────────────────────────────────────────────────────


def validate_id(value: object, label: str) -> str:
    """Validate a generic resource identifier interpolated into URL paths.

    Accepts alnum + ``.``, ``-``, ``_``; 1-128 chars. Rejects ``..``, ``/``,
    ``?``, ``#``, whitespace, control chars, URL-encoded escapes.
    """
    if value is None:
        raise ValidationError(f"{label} is required")
    s = str(value).strip()
    if not _ID_RE.match(s):
        raise ValidationError(f"{label} must match {_ID_RE.pattern} (got length-{len(s)})")
    if ".." in s:
        raise ValidationError(f"{label} must not contain '..'")
    return s


def validate_uuid(value: object, label: str) -> str:
    if value is None:
        raise ValidationError(f"{label} is required")
    s = str(value).strip()
    if not _UUID_RE.match(s):
        raise ValidationError(f"{label} must be a valid UUID")
    return s


def validate_tool_key(value: object, label: str = "tool_key") -> str:
    s = str(value or "").strip()
    if not _TOOL_KEY_RE.match(s):
        raise ValidationError(
            f"{label} must be lowercase dot-separated identifiers (got {s[:40]!r})"
        )
    return s


def validate_token(value: object, label: str) -> str:
    s = str(value or "").strip()
    if not _TOKEN_RE.match(s):
        raise ValidationError(f"{label} must be a URL-safe token (got length {len(s)})")
    return s


def validate_choice(value: object, allowed: Iterable[str], label: str) -> str:
    s = str(value or "").strip()
    allowed_set = set(allowed)
    if s not in allowed_set:
        sample = ", ".join(sorted(allowed_set)[:8])
        raise ValidationError(f"{label} must be one of {{{sample}}} (got {s!r})")
    return s


def validate_method(value: object) -> str:
    s = str(value or "").strip().upper()
    if s not in HTTP_METHODS:
        raise ValidationError(f"HTTP method must be one of {sorted(HTTP_METHODS)} (got {s!r})")
    return s


def is_local_url(base_url: str) -> bool:
    """True if ``base_url``'s *hostname* is local (loopback / docker-internal).

    Uses ``urlparse`` so we don't fall for substring tricks like
    ``https://evil.localhost.attacker.com`` or ``https://attacker.com/?ref=localhost``.
    """
    from urllib.parse import urlparse

    parsed = urlparse(base_url or "")
    return parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "::1")


def validate_relative_path(value: object, label: str = "path") -> str:
    """Validate a freeform sub-path that will be appended to a URL.

    Disallows scheme-injection, ``..`` segments, control chars. Allows
    alphanumerics and a small set of URL-safe punctuation.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    # Reject protocol-relative or scheme-prefixed inputs *before* normalizing.
    if raw.startswith("//"):
        raise ValidationError(f"{label} must not be protocol-relative")
    if "://" in raw:
        raise ValidationError(f"{label} must not contain a scheme")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", raw):
        raise ValidationError(f"{label} must not start with a URI scheme")
    s = raw.lstrip("/")
    if ".." in s.split("/"):
        raise ValidationError(f"{label} must not contain '..' segments")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        raise ValidationError(f"{label} must not contain control characters")
    if not re.match(r"^[A-Za-z0-9._~/?&=%+#@!$,;:'-]*$", s):
        raise ValidationError(f"{label} contains disallowed characters")
    return s
