"""Minimal, fail-closed process boundary for the Lightbulb MCP server."""

from __future__ import annotations

import os


_AUTH_ALLOWLIST_KEY = "LIGHTBULB_MCP_AUTH_ENV_ALLOWLIST"
_AUTH_ENV_KEYS = frozenset(
    {
        "LIGHTBULB_EMAIL",
        "LIGHTBULB_PASSWORD",
        "LIGHTBULB_JWT",
        "LIGHTBULB_TENANT_ID",
        "LIGHTBULB_API_KEY",
        "LIGHTBULB_USER_ID",
        "LIGHTBULB_COMPANY_ID",
    }
)
_PROXY_ENV_KEYS = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})

_SAFE_EXACT_KEYS = frozenset(
    {
        "PATH",
        "PATHEXT",
        "HOME",
        "USER",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "APPDATA",
        "LOCALAPPDATA",
        "LANG",
        "LANGUAGE",
        "TERM",
        "TZ",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "LIGHTBULB_URL",
        "LIGHTBULB_MCP_PROFILE",
        "LIGHTBULB_MCP_NAMESPACES",
        _AUTH_ALLOWLIST_KEY,
        "LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE",
        "LIGHTBULB_LOCAL_RUNTIME_ROOT",
        "LIGHTBULB_DOCUMENTS_DIR",
        "LIGHTBULB_PROJECT_RUNTIME_DIR",
        "LIGHTBULB_DYNAMIC_WORKFLOW_DIR",
        "LIGHTBULB_RUNTIME_OUTCOMES_FILE",
        "LIGHTBULB_WORKFLOW_IMPROVEMENT_DIR",
        "LIGHTBULB_ENABLE_PRIVATE_RUNTIME_ACTION_MCP",
        "LIGHTBULB_ENABLE_PRIVATE_PROJECT_LEARNING_MCP",
    }
)


def _explicit_auth_keys() -> frozenset[str]:
    raw = str(os.environ.get(_AUTH_ALLOWLIST_KEY) or "")
    requested = frozenset(
        part.strip().upper() for part in raw.split(",") if part.strip()
    )
    unsupported = requested - _AUTH_ENV_KEYS
    if unsupported:
        raise RuntimeError(
            "Unsupported Lightbulb MCP auth environment allowlist entries: "
            + ", ".join(sorted(unsupported))
        )
    return requested


def scrub_mcp_process_environment() -> None:
    """Remove ambient provider, cloud, connector, and platform credentials.

    Harness-configured Lightbulb authentication remains available. BYOK model
    credentials belong in the local credential broker and are never inherited
    by the MCP subprocess.
    """
    explicit_auth = _explicit_auth_keys()
    sovereign = (
        str(os.environ.get("LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE") or "")
        .strip()
        .lower()
        == "sovereign"
    )
    retained = {
        key: value
        for key, value in os.environ.items()
        if (
            not (sovereign and key.upper() in _PROXY_ENV_KEYS)
            and (
                key.upper() in _SAFE_EXACT_KEYS
                or key.upper() in explicit_auth
                or key.upper().startswith("LC_")
            )
        )
    }
    os.environ.clear()
    os.environ.update(retained)


def main() -> None:
    scrub_mcp_process_environment()
    from lightbulb.mcp_server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
