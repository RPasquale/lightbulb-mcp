"""Claude Code hook configuration for Lightbulb Continuum.

Claude Code loads user hooks from ``~/.claude/settings.json`` and shared
project hooks from ``.claude/settings.json``.  This module only builds and
merges the JSON-shaped ``hooks`` value; filesystem safety and atomic writes
remain in :mod:`lightbulb.setup` alongside the existing MCP config writers.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

from lightbulb.context_hook import (
    HOST_HOOK_TIMEOUT_SECONDS,
    configured_project_hook_args,
)


HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "PreCompact",
    "Stop",
)


def hook_groups(
    base_url: str,
    *,
    company_ref: str | None = None,
    project_ref: str | None = None,
    profile: str | None = None,
) -> Dict[str, list[dict[str, Any]]]:
    """Return Claude Code lifecycle groups for the Continuum adapter.

    Exec form (``command`` plus ``args``) avoids shell parsing and is the
    portable Claude Code representation for literal arguments.
    """

    args = [
        "context-hook",
        "--host",
        "claude_code",
        "--url",
        base_url.rstrip("/"),
    ]
    if str(profile or "").strip().lower().replace("_", "-") == "sovereign":
        args.extend(["--security-profile", "sovereign"])
    args.extend(configured_project_hook_args(company_ref, project_ref))

    def handler(status: str) -> dict[str, Any]:
        return {
            "type": "command",
            "command": "lightbulb",
            "args": list(args),
            "timeout": HOST_HOOK_TIMEOUT_SECONDS,
            "statusMessage": status,
        }

    return {
        "SessionStart": [
            {
                "matcher": "startup|resume|clear|compact",
                "hooks": [handler("Loading Lightbulb working context")],
            }
        ],
        "UserPromptSubmit": [
            {"hooks": [handler("Refreshing Lightbulb working context")]}
        ],
        "PostToolUse": [
            {
                "matcher": "*",
                "hooks": [handler("Applying Lightbulb tool-capture policy")],
            }
        ],
        "PreCompact": [
            {
                "matcher": "manual|auto",
                "hooks": [handler("Checkpointing before compaction")],
            }
        ],
        "Stop": [{"hooks": [handler("Saving Lightbulb checkpoint")]}],
    }


def _is_continuum_handler(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("type") != "command":
        return False

    command = str(value.get("command") or "").strip()
    args = value.get("args")
    if isinstance(args, list):
        executable = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
        normalized_args = [str(item) for item in args]
        if executable in {"lightbulb", "lightbulb.exe"}:
            for index, argument in enumerate(normalized_args[:-1]):
                if argument == "--host" and normalized_args[index + 1] == "claude_code":
                    return "context-hook" in normalized_args

    # Recognize the shell-form command emitted by early Continuum builds so a
    # setup re-run upgrades it instead of installing a duplicate hook.
    normalized_command = " ".join(command.lower().split())
    return (
        normalized_command.startswith((
            "lightbulb context-hook ",
            "lightbulb.exe context-hook ",
        ))
        and (
            "--host claude_code" in normalized_command
            or "--host=claude_code" in normalized_command
        )
    )


def merge_hooks(
    existing_hooks: Mapping[str, Any],
    base_url: str,
    *,
    company_ref: str | None = None,
    project_ref: str | None = None,
    profile: str | None = None,
) -> Tuple[Dict[str, Any], bool]:
    """Replace only Lightbulb's own hook handlers and preserve all others."""

    merged: Dict[str, Any] = dict(existing_hooks)
    replaced = False
    desired = hook_groups(
        base_url,
        company_ref=company_ref,
        project_ref=project_ref,
        profile=profile,
    )

    for event in HOOK_EVENTS:
        current = merged.get(event, [])
        if not isinstance(current, list):
            raise ValueError(f"Existing Claude hook event '{event}' is not an array")

        retained_groups: list[Any] = []
        for group in current:
            if not isinstance(group, Mapping):
                retained_groups.append(group)
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                retained_groups.append(dict(group))
                continue
            retained_handlers = [
                handler for handler in handlers if not _is_continuum_handler(handler)
            ]
            if len(retained_handlers) != len(handlers):
                replaced = True
            if retained_handlers:
                retained_group = dict(group)
                retained_group["hooks"] = retained_handlers
                retained_groups.append(retained_group)

        merged[event] = retained_groups + desired[event]

    return merged, replaced
