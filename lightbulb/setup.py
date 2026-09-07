"""Guided setup flow for the Lightbulb SDK / MCP server.

This module powers ``lightbulb setup`` — auto-detects the user's AI tool
(Claude Code, Codex, Cursor, or generic), runs the device-flow login,
verifies connectivity, and merges the MCP server entry into the right
config file (preserving other servers).

It also powers ``lightbulb status`` — a read-only diagnostic that shows
what's configured and what isn't.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat as stat_module
import sys
import textwrap
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 is part of the supported install matrix.
    import tomli as tomllib
from urllib.parse import urlsplit
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lightbulb import claude_hooks, codex_plugin
from lightbulb.context_hook import configured_project_refs
from lightbulb.auth import JwtAuth, device_login
from lightbulb.client import LightbulbClient
from lightbulb.token_cache import (
    _cache_path as cache_path_for,
    clear_cached_token,
    load_cached_token,
    save_cached_token,
)


DEFAULT_BASE_URL = "https://agents.lightbulbpartners.com"
SERVER_NAME = "lightbulb"
DEFAULT_MCP_PROFILE = "adaptive"
HOSTED_LIGHTBULB_DOMAINS = ("lightbulbpartners.com", "project401.ai")
_LOCAL_RUNTIME_SECURITY_PROFILE = "sovereign"


# ── Tool targets ─────────────────────────────────────────────────────


class ToolTarget(str, Enum):
    CLAUDE_CODE_USER = "claude-code-user"
    CLAUDE_CODE_PROJECT = "claude-code-project"
    CODEX = "codex"
    CURSOR = "cursor"
    GENERIC = "generic"

    @property
    def label(self) -> str:
        return {
            ToolTarget.CLAUDE_CODE_USER: "Claude Code (user-level)",
            ToolTarget.CLAUDE_CODE_PROJECT: "Claude Code (project-level)",
            ToolTarget.CODEX: "Codex CLI",
            ToolTarget.CURSOR: "Cursor",
            ToolTarget.GENERIC: "Generic / other",
        }[self]


SOVEREIGN_SETUP_TARGETS = frozenset(
    {
        ToolTarget.CLAUDE_CODE_USER,
        ToolTarget.CLAUDE_CODE_PROJECT,
        ToolTarget.CODEX,
    }
)


@dataclass
class DetectedTool:
    target: ToolTarget
    config_path: Optional[Path]
    binary_path: Optional[str]
    config_format: str  # "json" | "toml" | "none"
    notes: str = ""


def detect_tools(*, project_dir: Optional[Path] = None) -> List[DetectedTool]:
    """Return a list of AI tools we can target on the current machine.

    Detection is a *suggestion*, not a hard requirement — we list every tool
    we can write a config for, and indicate whether it appears installed.
    """
    home = Path.home()
    project = project_dir or Path.cwd()

    found: List[DetectedTool] = []

    # Claude Code: project-level .mcp.json (preferred when in a repo)
    project_mcp = project / ".mcp.json"
    found.append(DetectedTool(
        target=ToolTarget.CLAUDE_CODE_PROJECT,
        config_path=project_mcp,
        binary_path=shutil.which("claude"),
        config_format="json",
        notes="Project-scoped — checked into the repo so teammates share it.",
    ))

    # Claude Code: user-level (~/.claude.json or ~/.claude/mcp_servers.json)
    user_claude = home / ".claude.json"
    found.append(DetectedTool(
        target=ToolTarget.CLAUDE_CODE_USER,
        config_path=user_claude,
        binary_path=shutil.which("claude"),
        config_format="json",
        notes="User-scoped — applies to every Claude Code session for this user.",
    ))

    # Codex CLI
    codex_config = home / ".codex" / "config.toml"
    found.append(DetectedTool(
        target=ToolTarget.CODEX,
        config_path=codex_config,
        binary_path=shutil.which("codex"),
        config_format="toml",
        notes="OpenAI Codex CLI — uses ~/.codex/config.toml.",
    ))

    # Cursor
    cursor_config = home / ".cursor" / "mcp.json"
    found.append(DetectedTool(
        target=ToolTarget.CURSOR,
        config_path=cursor_config,
        binary_path=shutil.which("cursor"),
        config_format="json",
        notes="Cursor IDE — uses ~/.cursor/mcp.json.",
    ))

    return found


def installed_targets(detected: List[DetectedTool]) -> List[DetectedTool]:
    """Subset of detected tools where we found a binary OR a config file."""
    out: List[DetectedTool] = []
    for tool in detected:
        if tool.binary_path:
            out.append(tool)
            continue
        if tool.config_path and tool.config_path.exists():
            out.append(tool)
    return out


# ── Config snippet builders ──────────────────────────────────────────


def build_command_args() -> Tuple[str, List[str]]:
    """Pick the best command/args for the user's environment.

    If the ``lightbulb-mcp`` console script is on PATH (i.e. they pip-installed
    the package) we use that. Otherwise we fall back to ``python -m
    lightbulb.mcp_server``, which works for both pip-installed and source-tree
    setups.
    """
    if shutil.which("lightbulb-mcp"):
        return "lightbulb-mcp", []
    if not sys.executable:
        raise RuntimeError(
            "Cannot configure Lightbulb MCP because the active Python executable is unknown"
        )
    return str(Path(sys.executable).resolve()), ["-m", "lightbulb.mcp_launcher"]


def build_env_block(
    base_url: str,
    *,
    jwt: Optional[str] = None,
    tenant_id: Optional[str] = None,
    mcp_profile: Optional[str] = DEFAULT_MCP_PROFILE,
) -> Dict[str, str]:
    env: Dict[str, str] = {"LIGHTBULB_URL": base_url.rstrip("/")}
    if mcp_profile:
        env["LIGHTBULB_MCP_PROFILE"] = mcp_profile
        if _is_sovereign_mcp_profile(mcp_profile):
            env["LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE"] = (
                _LOCAL_RUNTIME_SECURITY_PROFILE
            )
    if jwt and tenant_id:
        env["LIGHTBULB_JWT"] = jwt
        env["LIGHTBULB_TENANT_ID"] = tenant_id
        env["LIGHTBULB_MCP_AUTH_ENV_ALLOWLIST"] = (
            "LIGHTBULB_JWT,LIGHTBULB_TENANT_ID"
        )
    return env


def build_mcp_entry(
    base_url: str,
    *,
    jwt: Optional[str] = None,
    tenant_id: Optional[str] = None,
    cwd: Optional[Path] = None,
    mcp_profile: Optional[str] = DEFAULT_MCP_PROFILE,
) -> Dict[str, Any]:
    """Build the JSON-shaped MCP server entry used by Claude Code / Cursor."""
    command, args = build_command_args()
    entry: Dict[str, Any] = {"command": command, "args": args}
    if cwd:
        entry["cwd"] = str(cwd)
    entry["env"] = build_env_block(
        base_url,
        jwt=jwt,
        tenant_id=tenant_id,
        mcp_profile=mcp_profile,
    )
    return entry


# ── JSON config writers (Claude Code, Cursor) ────────────────────────


def _safe_backup(config_path: Path, original_text: str, original_mode: int) -> Path:
    """Write a backup beside ``config_path`` with restrictive permissions.

    The backup may contain JWTs (e.g. embedded in env blocks), so it is
    chmod'd before any content is written. We refuse to follow symlinks at
    the backup target.
    """
    backup = config_path.with_suffix(config_path.suffix + ".bak")
    if backup.is_symlink():
        raise RuntimeError(f"Refusing to overwrite symlinked backup at {backup}")
    try:
        # Open with O_NOFOLLOW where supported; on Windows fall back.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        # Mirror the source's mode but clamp away group/other bits so a JWT
        # doesn't leak via a permissive backup file.
        mode = (original_mode or 0o600) & 0o600
        fd = os.open(str(backup), flags, mode)
        try:
            os.chmod(backup, mode)
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(original_text)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        return backup
    except OSError as exc:
        raise RuntimeError(
            f"Could not safely back up {config_path} to {backup}"
        ) from exc


def _atomic_write_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write ``content`` to ``path`` atomically with restrictive permissions.

    Uses tmpfile + ``os.replace``. Refuses to follow symlinks at the target.
    """
    if path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = __import__("tempfile").mkstemp(
        dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp"
    )
    tmp = Path(tmp_path)
    try:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def write_json_mcp_config(
    config_path: Path,
    entry: Dict[str, Any],
    *,
    server_name: str = SERVER_NAME,
) -> Tuple[Path, bool, Optional[Path]]:
    """Merge an MCP server entry into a JSON config, preserving siblings.

    Returns ``(config_path, replaced, backup_path)``.
    ``replaced`` is True if a server with the same name already existed.
    A backup is written next to the original when a file existed before.

    Security:
    - Refuses to write through a symlink at ``config_path`` or the backup.
    - Atomic write (tmpfile + rename) so concurrent readers see either the
      old or new file, never a torn one.
    - Backup file is chmod'd to 0o600 before content is written, since the
      original may contain a JWT in its env block.
    """
    config_path = config_path.expanduser()
    if config_path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {config_path}")
    config_path.parent.mkdir(parents=True, exist_ok=True)

    backup: Optional[Path] = None
    existing: Dict[str, Any] = {}
    original_text = ""
    original_mode = 0o600
    if config_path.exists():
        try:
            original_text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"Could not read existing MCP config at {config_path}"
            ) from exc
        try:
            original_mode = stat_module.S_IMODE(config_path.stat().st_mode)
        except OSError:
            original_mode = 0o600
        try:
            existing = json.loads(original_text or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Existing config at {config_path} is invalid JSON; refusing to overwrite."
            ) from exc
        if not isinstance(existing, dict):
            raise RuntimeError(
                f"Existing config at {config_path} is not a JSON object — "
                "refusing to overwrite. Move the file aside and re-run setup."
            )
        backup = _safe_backup(config_path, original_text, original_mode)

    servers = existing.get("mcpServers")
    if servers is None:
        servers_dict: Dict[str, Any] = {}
    elif isinstance(servers, dict):
        servers_dict = dict(servers)
    else:
        raise RuntimeError(
            f"Existing 'mcpServers' in {config_path} is not an object — "
            "refusing to overwrite."
        )
    replaced = server_name in servers_dict
    servers_dict[server_name] = entry
    existing["mcpServers"] = servers_dict
    _atomic_write_text(config_path, json.dumps(existing, indent=2) + "\n", mode=0o600)
    return config_path, replaced, backup


def default_claude_hooks_path(
    target: ToolTarget,
    *,
    project_dir: Optional[Path] = None,
    home: Optional[Path] = None,
) -> Path:
    """Resolve the official Claude Code settings location for a setup target."""
    if target == ToolTarget.CLAUDE_CODE_PROJECT:
        return (project_dir or Path.cwd()) / ".claude" / "settings.json"
    if target == ToolTarget.CLAUDE_CODE_USER:
        return (home or Path.home()) / ".claude" / "settings.json"
    raise ValueError(f"Claude hooks are not supported for target {target.value}")


def default_claude_skill_path(
    target: ToolTarget,
    *,
    project_dir: Optional[Path] = None,
    home: Optional[Path] = None,
) -> Path:
    """Resolve Claude Code's project/user Lightbulb skill location."""
    if target == ToolTarget.CLAUDE_CODE_PROJECT:
        root = project_dir or Path.cwd()
    elif target == ToolTarget.CLAUDE_CODE_USER:
        root = home or Path.home()
    else:
        raise ValueError(f"Claude skills are not supported for target {target.value}")
    return root / ".claude" / "skills" / "lightbulb" / "SKILL.md"


def validate_claude_skill_path(skill_path: Path) -> Path:
    """Reject symlinked or non-directory Claude skill paths before any write."""
    resolved = skill_path.expanduser()
    managed_root = resolved.parent.parent.parent
    for candidate in (
        managed_root,
        managed_root / "skills",
        resolved.parent,
        resolved,
    ):
        if candidate.is_symlink():
            raise RuntimeError(f"Refusing to write through symlink at {candidate}")
        if candidate != resolved and candidate.exists() and not candidate.is_dir():
            raise RuntimeError(f"Claude skill parent is not a directory: {candidate}")
    if resolved.exists() and not resolved.is_file():
        raise RuntimeError(f"Claude skill path is not a regular file: {resolved}")
    return resolved


def write_claude_skill(
    skill_path: Path,
    *,
    profile: str,
) -> Tuple[Path, bool, Optional[Path]]:
    """Install profile-accurate Claude guidance with backup and symlink safety."""
    skill_path = validate_claude_skill_path(skill_path)
    existed = skill_path.exists()
    backup: Optional[Path] = None
    if existed:
        try:
            original_text = skill_path.read_text(encoding="utf-8")
            original_mode = stat_module.S_IMODE(skill_path.stat().st_mode)
        except OSError as exc:
            raise RuntimeError(f"Could not read Claude skill at {skill_path}") from exc
        backup = _safe_backup(skill_path, original_text, original_mode)
    _atomic_write_text(
        skill_path,
        codex_plugin.claude_skill(profile),
        mode=0o600,
    )
    return skill_path, existed, backup


def write_claude_hooks_config(
    settings_path: Path,
    base_url: str,
    *,
    company_ref: str | None = None,
    project_ref: str | None = None,
    profile: str | None = None,
) -> Tuple[Path, bool, Optional[Path]]:
    """Merge Continuum hooks into Claude Code settings without losing siblings.

    Unlike the legacy MCP JSON writer, malformed settings are rejected rather
    than treated as empty because Claude settings can contain unrelated user
    permissions, plugins, and hooks that setup must never discard.
    """
    settings_path = settings_path.expanduser()
    if settings_path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {settings_path}")

    existing: Dict[str, Any] = {}
    original_text = ""
    original_mode = 0o600
    if settings_path.exists():
        try:
            original_text = settings_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Could not read Claude settings at {settings_path}") from exc
        try:
            existing = json.loads(original_text or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Existing Claude settings at {settings_path} are invalid JSON; "
                "refusing to overwrite."
            ) from exc
        if not isinstance(existing, dict):
            raise RuntimeError(
                f"Existing Claude settings at {settings_path} are not a JSON object; "
                "refusing to overwrite."
            )
        try:
            original_mode = stat_module.S_IMODE(settings_path.stat().st_mode)
        except OSError:
            original_mode = 0o600

    current_hooks = existing.get("hooks")
    if current_hooks is None:
        current_hooks = {}
    if not isinstance(current_hooks, dict):
        raise RuntimeError(
            f"Existing 'hooks' in {settings_path} is not an object; refusing to overwrite."
        )
    try:
        merged_hooks, replaced = claude_hooks.merge_hooks(
            current_hooks,
            base_url,
            company_ref=company_ref,
            project_ref=project_ref,
            profile=profile,
        )
    except ValueError as exc:
        raise RuntimeError(f"Invalid Claude hooks in {settings_path}: {exc}") from exc

    backup = None
    if settings_path.exists():
        backup = _safe_backup(settings_path, original_text, original_mode)
    existing["hooks"] = merged_hooks
    _atomic_write_text(settings_path, json.dumps(existing, indent=2) + "\n", mode=0o600)
    return settings_path, replaced, backup


# ── TOML config writer (Codex) ───────────────────────────────────────


_LIGHTBULB_TOML_BLOCK = re.compile(
    r"(?ms)^\[mcp_servers\.lightbulb(?:\.[\w]+)?\][^\[]*",
)


def _remove_lightbulb_toml_tables(text: str) -> Tuple[str, int]:
    """Remove complete Lightbulb TOML tables without mistaking array values for tables."""
    output: List[str] = []
    skipping = False
    removed_tables = 0
    target_prefix = f"mcp_servers.{SERVER_NAME}"
    for line in text.splitlines(keepends=True):
        table_name = _toml_table_name(line)
        if table_name is not None:
            if table_name == target_prefix or table_name.startswith(
                f"{target_prefix}."
            ):
                skipping = True
                removed_tables += 1
                continue
            if skipping:
                skipping = False
        if not skipping:
            output.append(line)
    return "".join(output), removed_tables


def _toml_table_name(line: str) -> Optional[str]:
    """Return a normalized TOML table name, or None for arrays and other values."""
    stripped = line.strip()
    if not stripped.startswith("["):
        return None
    candidate = stripped.split("#", 1)[0].strip()
    try:
        tomllib.loads(candidate + "\n")
    except tomllib.TOMLDecodeError:
        return None
    if candidate.startswith("[[") and candidate.endswith("]]"):
        inner = candidate[2:-2]
    elif candidate.startswith("[") and candidate.endswith("]"):
        inner = candidate[1:-1]
    else:
        return None
    return ".".join(part.strip().strip('"').strip("'") for part in inner.split("."))


def _toml_escape(value: str) -> str:
    """Escape a string so it can be safely embedded in a TOML basic string.

    Covers all characters TOML basic strings forbid raw: ``\\``, ``"``,
    ``\b``, ``\t``, ``\n``, ``\f``, ``\r``, and any control character
    (U+0000–U+001F, U+007F). Without this, a value containing a newline
    could break out of the string and inject arbitrary TOML keys — which,
    for a config file like ``~/.codex/config.toml``, means the ability to
    register a malicious ``[mcp_servers.X]`` block that runs an attacker
    command on every Codex launch.
    """
    out: list[str] = []
    for c in value:
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        elif c == "\b":
            out.append("\\b")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\f":
            out.append("\\f")
        elif c == "\r":
            out.append("\\r")
        elif ord(c) < 0x20 or ord(c) == 0x7F:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return "".join(out)


def render_codex_toml_block(
    base_url: str,
    *,
    jwt: Optional[str] = None,
    tenant_id: Optional[str] = None,
    cwd: Optional[Path] = None,
    startup_timeout_sec: int = 15,
    tool_timeout_sec: int = 120,
    mcp_profile: str = DEFAULT_MCP_PROFILE,
) -> str:
    """Render the Codex-flavoured TOML block for the lightbulb MCP entry."""
    command, args = build_command_args()
    args_repr = "[" + ", ".join(f'"{_toml_escape(a)}"' for a in args) + "]"
    lines = [
        "[mcp_servers.lightbulb]",
        f'command = "{_toml_escape(command)}"',
        f"args = {args_repr}",
    ]
    if cwd:
        lines.append(f'cwd = "{_toml_escape(str(cwd))}"')
    lines.extend([
        f"startup_timeout_sec = {startup_timeout_sec}",
        f"tool_timeout_sec = {tool_timeout_sec}",
        "enabled = true",
        "",
        "[mcp_servers.lightbulb.env]",
        f'LIGHTBULB_URL = "{_toml_escape(base_url.rstrip("/"))}"',
        f'LIGHTBULB_MCP_PROFILE = "{_toml_escape(mcp_profile)}"',
    ])
    if _is_sovereign_mcp_profile(mcp_profile):
        lines.append(
            "LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE = "
            f'"{_LOCAL_RUNTIME_SECURITY_PROFILE}"'
        )
    if jwt and tenant_id:
        lines.append(f'LIGHTBULB_JWT = "{_toml_escape(jwt)}"')
        lines.append(f'LIGHTBULB_TENANT_ID = "{_toml_escape(tenant_id)}"')
    return "\n".join(lines) + "\n"


def write_codex_toml(
    config_path: Path,
    block: str,
) -> Tuple[Path, bool, Optional[Path]]:
    """Merge the lightbulb block into ``~/.codex/config.toml``.

    Strips any pre-existing ``[mcp_servers.lightbulb]`` and
    ``[mcp_servers.lightbulb.env]`` blocks, then appends the new block.

    Security: refuses to follow symlinks; atomic write; backup chmod'd to
    0o600 since the file may contain a JWT in its env block.
    """
    config_path = config_path.expanduser()
    if config_path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {config_path}")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    backup: Optional[Path] = None
    text = ""
    replaced = False
    if config_path.exists():
        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"Could not read existing Codex config at {config_path}"
            ) from exc
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise RuntimeError(
                f"Existing Codex config at {config_path} is invalid TOML; refusing to overwrite."
            ) from exc
        try:
            original_mode = stat_module.S_IMODE(config_path.stat().st_mode)
        except OSError:
            original_mode = 0o600
        backup = _safe_backup(config_path, text, original_mode)
        new_text, count = _remove_lightbulb_toml_tables(text)
        if count > 0:
            replaced = True
            text = new_text
        text = text.rstrip() + ("\n\n" if text.strip() else "")
    final = text + block
    _atomic_write_text(config_path, final, mode=0o600)
    return config_path, replaced, backup


# ── Codex plugin installer ───────────────────────────────────────────


def default_codex_plugin_dir(*, home: Optional[Path] = None) -> Path:
    root = home or Path.home()
    return root / ".codex" / "plugins" / codex_plugin.PLUGIN_NAME


def default_codex_marketplace_path(*, home: Optional[Path] = None) -> Path:
    root = home or Path.home()
    return root / ".agents" / "plugins" / "marketplace.json"


def write_codex_plugin_marketplace(
    marketplace_path: Path,
    *,
    source_path: str = "./.codex/plugins/lightbulb-partners",
) -> Tuple[Path, bool, Optional[Path]]:
    """Merge the Lightbulb Codex plugin into the personal marketplace file."""
    marketplace_path = marketplace_path.expanduser()
    if marketplace_path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {marketplace_path}")
    marketplace_path.parent.mkdir(parents=True, exist_ok=True)

    backup: Optional[Path] = None
    existing: Dict[str, Any] = {}
    original_text = ""
    original_mode = 0o600
    if marketplace_path.exists():
        try:
            original_text = marketplace_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(
                f"Could not read marketplace at {marketplace_path}"
            ) from exc
        try:
            original_mode = stat_module.S_IMODE(marketplace_path.stat().st_mode)
        except OSError:
            original_mode = 0o600
        try:
            existing = json.loads(original_text or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Existing marketplace at {marketplace_path} is invalid JSON; refusing to overwrite."
            ) from exc
        if not isinstance(existing, dict):
            raise RuntimeError(
                f"Existing marketplace at {marketplace_path} is not a JSON object — "
                "refusing to overwrite. Move the file aside and re-run setup."
            )
        backup = _safe_backup(marketplace_path, original_text, original_mode)

    plugins = existing.get("plugins")
    if plugins is None:
        plugin_entries: List[Any] = []
    elif isinstance(plugins, list):
        plugin_entries = list(plugins)
    else:
        raise RuntimeError(
            f"Existing 'plugins' in {marketplace_path} is not an array — refusing to overwrite."
        )

    entry = codex_plugin.marketplace_entry(source_path)
    replaced = False
    merged_plugins: List[Any] = []
    for plugin_entry in plugin_entries:
        if isinstance(plugin_entry, dict) and plugin_entry.get("name") == codex_plugin.PLUGIN_NAME:
            merged_plugins.append(entry)
            replaced = True
        else:
            merged_plugins.append(plugin_entry)
    if not replaced:
        merged_plugins.append(entry)

    existing.setdefault("name", codex_plugin.MARKETPLACE_NAME)
    interface = existing.get("interface")
    if not isinstance(interface, dict):
        interface = {}
        existing["interface"] = interface
    interface.setdefault("displayName", codex_plugin.MARKETPLACE_DISPLAY_NAME)
    existing["plugins"] = merged_plugins
    _atomic_write_text(marketplace_path, json.dumps(existing, indent=2) + "\n", mode=0o600)
    return marketplace_path, replaced, backup


def install_codex_plugin(
    base_url: str,
    *,
    plugin_dir: Optional[Path] = None,
    marketplace_path: Optional[Path] = None,
    company_ref: str | None = None,
    project_ref: str | None = None,
    profile: str | None = None,
) -> Tuple[Path, Path, bool, Optional[Path]]:
    """Write the local Codex plugin files and marketplace entry."""
    plugin_root = (plugin_dir or default_codex_plugin_dir()).expanduser()
    if plugin_root.is_symlink():
        raise RuntimeError(f"Refusing to write through symlink at {plugin_root}")
    for relative_path, content in codex_plugin.plugin_files(
        base_url,
        company_ref=company_ref,
        project_ref=project_ref,
        profile=profile,
    ).items():
        target = plugin_root / relative_path
        if target.is_symlink():
            raise RuntimeError(f"Refusing to write through symlink at {target}")
        _atomic_write_text(target, content, mode=0o600)

    marketplace = marketplace_path or default_codex_marketplace_path()
    marketplace_root = marketplace.expanduser().parent.parent.parent
    try:
        source_path = "./" + plugin_root.resolve().relative_to(marketplace_root.resolve()).as_posix()
    except ValueError:
        source_path = "./.codex/plugins/lightbulb-partners"
    path, replaced, backup = write_codex_plugin_marketplace(marketplace, source_path=source_path)
    return plugin_root, path, replaced, backup


def codex_plugin_status(*, home: Optional[Path] = None) -> str:
    """Report published files without claiming Codex enabled or trusted them."""
    root = home or Path.home()
    plugin_manifest = default_codex_plugin_dir(home=root) / ".codex-plugin" / "plugin.json"
    marketplace = default_codex_marketplace_path(home=root)
    if not plugin_manifest.exists() and not marketplace.exists():
        return "not installed"
    if not plugin_manifest.exists():
        return "marketplace present, plugin files missing"
    if not marketplace.exists():
        return "plugin files present, marketplace missing"
    try:
        data = json.loads(marketplace.read_text(encoding="utf-8") or "{}")
        plugins = data.get("plugins") if isinstance(data, dict) else []
        if any(isinstance(item, dict) and item.get("name") == codex_plugin.PLUGIN_NAME for item in plugins or []):
            return "published; install/enable/hook trust unverified"
    except Exception:
        return "marketplace unreadable"
    return "plugin files present, marketplace entry missing"


# ── Connectivity test ────────────────────────────────────────────────


@dataclass
class ProbeResult:
    ok: bool
    detail: str
    user: Optional[Dict[str, Any]] = None


def probe_connection(base_url: str, *, jwt: Optional[str] = None, tenant_id: Optional[str] = None) -> ProbeResult:
    """Smoke-test the platform with whichever credentials we have.

    Tries cached token first, then a JWT pair if supplied. Returns a friendly
    summary the caller can print.
    """
    auth: Optional[JwtAuth] = None
    if jwt and tenant_id:
        try:
            auth = JwtAuth(token=jwt, tenant_id=tenant_id)
        except ValueError as exc:
            return ProbeResult(False, f"Invalid JWT/tenant pair: {exc}")
    if auth is None:
        cached = load_cached_token(base_url)
        if cached is None:
            return ProbeResult(False, "No cached token. Run `lightbulb setup` to authenticate.")
        auth = cached

    from lightbulb.validators import is_local_url
    is_local = is_local_url(base_url)
    client = LightbulbClient(base_url, auth=auth, enforce_https=not is_local)
    try:
        me = client.whoami()
    except Exception as exc:
        return ProbeResult(False, f"whoami() failed: {exc}")
    name = (me.get("email") or me.get("firstName") or "?")
    return ProbeResult(True, f"Authenticated as {name} ({me.get('role', '?')})", user=me)


# ── Status / report ──────────────────────────────────────────────────


def render_status_report(
    base_url: str,
    *,
    detected: Optional[List[DetectedTool]] = None,
    project_dir: Optional[Path] = None,
) -> str:
    """Build a human-readable status report (no I/O side-effects)."""
    detected = detected or detect_tools(project_dir=project_dir)
    cache = cache_path_for(base_url)
    cache_status = "yes" if load_cached_token(base_url) else "no"

    lines = [
        "Lightbulb SDK status",
        "─" * 40,
        f"Platform URL:        {base_url}",
        f"Cached login token:  {cache_status}  ({cache})",
        "",
        "Detected AI tools:",
    ]
    for tool in detected:
        present = "found" if (tool.binary_path or (tool.config_path and tool.config_path.exists())) else "not found"
        cfg_state = ""
        if tool.config_path and tool.config_path.exists():
            try:
                if tool.config_format == "json":
                    data = json.loads(tool.config_path.read_text(encoding="utf-8") or "{}")
                    has_lb = SERVER_NAME in (data.get("mcpServers") or {})
                else:
                    has_lb = bool(
                        _LIGHTBULB_TOML_BLOCK.search(
                            tool.config_path.read_text(encoding="utf-8")
                        )
                    )
                cfg_state = " — lightbulb wired in" if has_lb else " — no lightbulb entry"
            except Exception:
                cfg_state = " — could not parse"
        lines.append(f"  • {tool.target.label:<35} [{present}]{cfg_state}")
        if tool.config_path:
            lines.append(f"      config: {tool.config_path}")

    if cache_status == "no":
        lines.append("")
        lines.append("Next: run `lightbulb setup` to authenticate and wire up your AI tool.")
    lines.append("")
    lines.append(f"Codex plugin:        {codex_plugin_status()}")
    from lightbulb.context_hook import context_hook_health_status

    lines.append(f"Continuum hooks:     {context_hook_health_status()}")
    return "\n".join(lines)


# ── Interactive setup ────────────────────────────────────────────────


def _prompt(message: str, *, default: Optional[str] = None) -> str:
    if default:
        prompt = f"{message} [{default}]: "
    else:
        prompt = f"{message}: "
    try:
        answer = input(prompt).strip()
    except EOFError:
        answer = ""
    return answer or (default or "")


def _confirm(message: str, *, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"{message} {suffix} ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer.startswith("y")


def _pick_target(detected: List[DetectedTool], explicit: Optional[ToolTarget]) -> Optional[DetectedTool]:
    """Resolve which tool to configure.

    If ``explicit`` is given, return that. Otherwise prompt the user with a
    short menu of installed tools, with the first installed one as default.
    """
    if explicit:
        for t in detected:
            if t.target == explicit:
                return t
        return None

    installed = installed_targets(detected)
    if len(installed) == 1:
        return installed[0]

    candidates = installed if installed else detected
    print("\nWhich tool should I configure?")
    for i, t in enumerate(candidates, start=1):
        marker = " (installed)" if t in installed else ""
        print(f"  {i}. {t.target.label}{marker}")
    print(f"  {len(candidates) + 1}. Skip (just print the snippet)")

    while True:
        raw = _prompt("Pick a number", default="1")
        try:
            choice = int(raw)
        except ValueError:
            print("Please enter a number.")
            continue
        if 1 <= choice <= len(candidates):
            return candidates[choice - 1]
        if choice == len(candidates) + 1:
            return None
        print("Out of range, try again.")


def _print_snippet(target: ToolTarget, snippet: str) -> None:
    fence = "toml" if target == ToolTarget.CODEX else "json"
    print(f"\nAdd this to your {target.label} config:\n")
    print(f"```{fence}")
    print(snippet.rstrip())
    print("```\n")


def run_setup(
    *,
    base_url: Optional[str] = None,
    target: Optional[ToolTarget] = None,
    write: Optional[bool] = None,
    project_dir: Optional[Path] = None,
    skip_login: bool = False,
    context_company_ref: str | None = None,
    context_project_ref: str | None = None,
    mcp_profile: str = DEFAULT_MCP_PROFILE,
) -> int:
    """Interactive setup. Returns a process exit code (0 = success)."""
    print("Lightbulb setup")
    print("=" * 40)

    try:
        project_refs = configured_project_refs(
            context_company_ref,
            context_project_ref,
        )
    except ValueError as exc:
        print(f"Invalid Context Broker project selection: {exc}", file=sys.stderr)
        return 1
    if project_refs is not None:
        context_company_ref, context_project_ref = project_refs

    normalized_profile = str(mcp_profile or DEFAULT_MCP_PROFILE).strip().lower()
    if (
        normalized_profile == "sovereign"
        and target is not None
        and target not in SOVEREIGN_SETUP_TARGETS
    ):
        supported = ", ".join(
            sorted(candidate.value for candidate in SOVEREIGN_SETUP_TARGETS)
        )
        print(
            "Invalid Sovereign Local setup target: "
            f"{target.value!r} is not an approved harness target. "
            f"Choose one of: {supported}.",
            file=sys.stderr,
        )
        return 1
    if normalized_profile == "sovereign":
        base_url = (
            base_url or _prompt("Sovereign Local platform URL (customer-operated)")
        ).rstrip("/")
        endpoint_error = _sovereign_endpoint_error(base_url)
        if endpoint_error:
            print(f"Invalid Sovereign Local endpoint: {endpoint_error}", file=sys.stderr)
            return 1
    else:
        base_url = (base_url or _prompt("Platform URL", default=DEFAULT_BASE_URL)).rstrip("/")

    # Step 1 — auth
    if not skip_login:
        cached = load_cached_token(base_url)
        if cached:
            print(f"\n✓ Found cached login for {base_url}")
        else:
            print("\n→ Opening your browser to authorize this CLI...")
            try:
                auth, expires_in = device_login(base_url, client_id="lightbulb-cli")
                save_cached_token(base_url, auth, expires_in=expires_in)
            except Exception as exc:
                print(f"  Login failed: {exc}", file=sys.stderr)
                print("  You can re-run `lightbulb setup` after fixing the issue.")
                return 1

    # Step 2 — connectivity probe (with one auto-retry on stale token)
    probe = probe_connection(base_url)
    print(f"\n→ Probe: {probe.detail}")
    if not probe.ok and not skip_login:
        # If the cached token is stale (server says 401), clear it and re-run
        # the device flow once. This avoids the "I just ran setup, why does it
        # say I'm not authenticated" foot-gun.
        looks_like_auth_failure = any(
            kw in probe.detail.lower()
            for kw in ("401", "unauthorized", "expired", "invalid")
        )
        if looks_like_auth_failure:
            print("  → Cached token looks stale; clearing and re-authenticating.")
            clear_cached_token(base_url)
            try:
                auth, expires_in = device_login(base_url, client_id="lightbulb-cli")
                save_cached_token(base_url, auth, expires_in=expires_in)
            except Exception as exc:
                print(f"  Re-auth failed: {exc}", file=sys.stderr)
                return 1
            probe = probe_connection(base_url)
            print(f"  → Probe (after re-auth): {probe.detail}")
    if not probe.ok:
        return 1

    # Step 3 — detect / pick target
    detected = detect_tools(project_dir=project_dir)
    if normalized_profile == "sovereign":
        detected = [
            candidate
            for candidate in detected
            if candidate.target in SOVEREIGN_SETUP_TARGETS
        ]
    chosen = _pick_target(detected, target)
    if chosen is None:
        print("\nSkipping config write. Generic snippet:")
        chosen = next(t for t in detected if t.target == ToolTarget.CODEX)

    # Step 4 — build snippet for the chosen tool
    cwd = None  # keep config portable; rely on lightbulb-mcp / pip install
    if chosen.target == ToolTarget.CODEX:
        snippet = render_codex_toml_block(base_url, cwd=cwd, mcp_profile=mcp_profile)
    else:
        entry = build_mcp_entry(base_url, cwd=cwd, mcp_profile=mcp_profile)
        snippet = json.dumps({"mcpServers": {SERVER_NAME: entry}}, indent=2)

    _print_snippet(chosen.target, snippet)

    # Step 5 — write?
    if chosen.config_path is None:
        return 0
    do_write = write
    if do_write is None:
        do_write = _confirm(f"Write to {chosen.config_path}?", default=True)
    if not do_write:
        print("Skipped writing config. You can copy the snippet above manually.")
        return 0

    plugin_result: Optional[Tuple[Path, Path, bool, Optional[Path]]] = None
    claude_hooks_result: Optional[Tuple[Path, bool, Optional[Path]]] = None
    claude_skill_result: Optional[Tuple[Path, bool, Optional[Path]]] = None
    claude_skill_path: Optional[Path] = None
    if chosen.target in {ToolTarget.CLAUDE_CODE_USER, ToolTarget.CLAUDE_CODE_PROJECT}:
        claude_skill_path = default_claude_skill_path(
            chosen.target,
            project_dir=chosen.config_path.parent,
            home=chosen.config_path.parent,
        )
        validate_claude_skill_path(claude_skill_path)
    if chosen.target == ToolTarget.CODEX:
        path, replaced, backup = write_codex_toml(chosen.config_path, snippet)
        plugin_result = install_codex_plugin(
            base_url,
            company_ref=context_company_ref,
            project_ref=context_project_ref,
            profile=mcp_profile,
        )
    else:
        entry = build_mcp_entry(base_url, cwd=cwd, mcp_profile=mcp_profile)
        path, replaced, backup = write_json_mcp_config(chosen.config_path, entry)
        if chosen.target in {
            ToolTarget.CLAUDE_CODE_USER,
            ToolTarget.CLAUDE_CODE_PROJECT,
        }:
            hook_project_dir = (
                chosen.config_path.parent
                if chosen.target == ToolTarget.CLAUDE_CODE_PROJECT
                else None
            )
            hooks_path = default_claude_hooks_path(
                chosen.target,
                project_dir=hook_project_dir,
            )
            claude_hooks_result = write_claude_hooks_config(
                hooks_path,
                base_url,
                company_ref=context_company_ref,
                project_ref=context_project_ref,
                profile=mcp_profile,
            )
            if claude_skill_path is not None:
                claude_skill_result = write_claude_skill(
                    claude_skill_path,
                    profile=normalized_profile,
                )

    print(f"\n✓ Wrote MCP config to {path}")
    if replaced:
        print("  (an existing 'lightbulb' entry was replaced)")
    if backup:
        print(f"  Backup: {backup}")
    if claude_hooks_result:
        hooks_path, hooks_replaced, hooks_backup = claude_hooks_result
        print(f"✓ Wrote Claude Code Continuum hooks to {hooks_path}")
        if hooks_replaced:
            print("  (existing Lightbulb Continuum hooks were replaced)")
        if hooks_backup:
            print(f"  Hooks backup: {hooks_backup}")
    if claude_skill_result:
        skill_path, skill_replaced, skill_backup = claude_skill_result
        print(f"✓ Wrote Claude Code Lightbulb skill to {skill_path}")
        if skill_replaced:
            print("  (an existing Lightbulb Claude skill was replaced)")
        if skill_backup:
            print(f"  Skill backup: {skill_backup}")
    if plugin_result:
        plugin_path, marketplace_path, plugin_replaced, plugin_backup = plugin_result
        print(f"✓ Wrote Codex plugin to {plugin_path}")
        print(f"✓ Wrote Codex plugin marketplace to {marketplace_path}")
        if plugin_replaced:
            print("  (an existing Lightbulb plugin marketplace entry was replaced)")
        if plugin_backup:
            print(f"  Marketplace backup: {plugin_backup}")
    print(_next_steps(chosen.target))
    return 0


def _sovereign_endpoint_error(base_url: str) -> str | None:
    """Reject missing, malformed, insecure, or Lightbulb-hosted Local targets.

    Private DNS is intentionally not resolved here: customer VPC/VNet and
    split-horizon endpoints may be unreachable until the harness is on the
    customer's network. The setup contract can still prove that a Sovereign
    profile was explicitly pointed away from the managed Lightbulb service.
    """
    value = str(base_url or "").strip()
    if not value:
        return "provide --url for the customer-operated deployment"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return "URL is malformed"
    hostname = str(parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return (
            "URL must be an exact HTTP(S) origin without credentials, a path, "
            "query parameters, or a fragment"
        )
    if port is not None and not 1 <= port <= 65535:
        return "URL port must be between 1 and 65535"
    if any(
        hostname == domain or hostname.endswith(f".{domain}")
        for domain in HOSTED_LIGHTBULB_DOMAINS
    ):
        return "the sovereign profile cannot target the managed Lightbulb service"
    loopback = hostname == "localhost"
    if not loopback:
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = False
    if parsed.scheme != "https" and not loopback:
        return "non-loopback Sovereign Local endpoints must use HTTPS"
    return None


def _is_sovereign_mcp_profile(profile: object) -> bool:
    """Return whether a config explicitly selected the Local security profile."""
    return (
        str(profile or "").strip().lower().replace("_", "-")
        == _LOCAL_RUNTIME_SECURITY_PROFILE
    )


def _next_steps(target: ToolTarget) -> str:
    base = "\nNext steps:"
    if target == ToolTarget.CLAUDE_CODE_PROJECT:
        return base + textwrap.dedent("""
          • Restart Claude Code (or run `/mcp` and reconnect 'lightbulb').
          • Run `/hooks` to confirm the project-level Lightbulb Continuum hooks.
          • Confirm the project-level `lightbulb` skill is available.
          • Try: 'list domain agents' or 'whoami'.
        """)
    if target == ToolTarget.CLAUDE_CODE_USER:
        return base + textwrap.dedent("""
          • Restart Claude Code in any project.
          • Run `/mcp` to confirm 'lightbulb' is connected.
          • Run `/hooks` to confirm the user-level Lightbulb Continuum hooks.
          • Confirm the user-level `lightbulb` skill is available.
        """)
    if target == ToolTarget.CODEX:
        return base + textwrap.dedent("""
          • Restart `codex` to pick up the new MCP server and plugin marketplace.
          • Open Plugins, choose "Lightbulb Partners Local", and install/enable "Lightbulb Partners" if it is not already enabled.
          • Run `/hooks`, review the generated Lightbulb Continuum commands, and explicitly trust them; untrusted hooks are skipped.
          • Inside a Codex session, ask: 'Use Lightbulb Partners to start a consulting project workflow for this idea.'
        """)
    if target == ToolTarget.CURSOR:
        return base + textwrap.dedent("""
          • Restart Cursor (Cmd/Ctrl+Shift+P → 'Reload Window').
          • Open the MCP panel in settings to confirm 'lightbulb' is up.
        """)
    return base + "\n  • Configure your MCP-compatible tool with the snippet above."
