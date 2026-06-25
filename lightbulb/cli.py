"""Lightbulb CLI — `lightbulb <command>` for shell scripts and quick ops.

Reads auth config from the same env vars as the MCP server:

    LIGHTBULB_URL          base URL (default https://agents.lightbulbpartners.com)
    LIGHTBULB_JWT          direct JWT token
    LIGHTBULB_TENANT_ID    tenant UUID (required with JWT)
    LIGHTBULB_COMPANY_ID   optional company scope
    LIGHTBULB_EMAIL        for password login (legacy)
    LIGHTBULB_PASSWORD     for password login (legacy)
    LIGHTBULB_API_KEY      localhost integration only
    LIGHTBULB_USER_ID      with API_KEY

If none of the above are set and stdin is a TTY, the CLI runs the device flow
and caches the resulting token (same UX as the MCP server).

Examples::

    lightbulb whoami
    lightbulb list-domains
    lightbulb dispatch finance --action chat --message "Show this month's cash"
    lightbulb search-documents "quarterly revenue" --top-k 5
    lightbulb approvals list
    lightbulb approvals approve <task-id> --comment "ok"
    lightbulb voice list
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Optional

from lightbulb.auth import (
    AuthStrategy,
    JwtAuth,
    TwoFactorRequired,
    complete_2fa_login,
    device_login,
    exchange_local_api_key_for_jwt,
    login,
)
from lightbulb.client import LightbulbClient
from lightbulb import setup as setup_module
from lightbulb.token_cache import (
    clear_cached_token,
    load_cached_token,
    save_cached_token,
)


def _resolve_auth(base_url: str) -> AuthStrategy:
    """Mirror of the MCP server's auth resolution chain."""
    jwt = os.getenv("LIGHTBULB_JWT", "").strip()
    tenant_id = os.getenv("LIGHTBULB_TENANT_ID", "").strip()
    company_id = os.getenv("LIGHTBULB_COMPANY_ID", "").strip() or None
    api_key = os.getenv("LIGHTBULB_API_KEY", "").strip()
    user_id = os.getenv("LIGHTBULB_USER_ID", "").strip()
    email = os.getenv("LIGHTBULB_EMAIL", "").strip()
    password = os.getenv("LIGHTBULB_PASSWORD", "").strip()

    if jwt and tenant_id:
        return JwtAuth(token=jwt, tenant_id=tenant_id, company_id=company_id)

    if api_key and tenant_id and user_id:
        return exchange_local_api_key_for_jwt(
            base_url, api_key, tenant_id, user_id, company_id, purpose="lightbulb_cli"
        )

    cached = load_cached_token(base_url)
    if cached is not None:
        return cached

    if sys.stderr.isatty():
        try:
            auth, expires_in = device_login(base_url, client_id="lightbulb-cli")
            save_cached_token(base_url, auth, expires_in=expires_in)
            return auth
        except Exception as exc:
            print(f"Device-flow login failed: {exc}", file=sys.stderr)

    if email and password:
        try:
            return login(base_url, email, password, interactive=sys.stderr.isatty())
        except TwoFactorRequired as exc:
            if sys.stderr.isatty():
                code = input("2FA code: ").strip()
                return complete_2fa_login(exc.base_url, exc.email, code)
            raise

    raise RuntimeError(
        "No authentication available. Set LIGHTBULB_JWT + LIGHTBULB_TENANT_ID, "
        "or run interactively (device flow), or set LIGHTBULB_EMAIL + LIGHTBULB_PASSWORD."
    )


def _client_from_env() -> LightbulbClient:
    base_url = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com").rstrip("/")
    auth = _resolve_auth(base_url)
    from lightbulb.validators import is_local_url
    is_local = is_local_url(base_url)
    return LightbulbClient(base_url, auth=auth, enforce_https=not is_local)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _cmd_whoami(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().whoami())
    return 0


def _cmd_list_domains(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_domains())
    return 0


def _cmd_list_companies(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_companies())
    return 0


def _cmd_dispatch(args: argparse.Namespace) -> int:
    client = _client_from_env()
    inputs = json.loads(args.inputs) if args.inputs else None
    result = client.dispatch(
        args.domain,
        action=args.action,
        message=args.message or "",
        objective=args.objective or "",
        inputs=inputs,
        conversation_id=args.conversation_id,
        company_id=args.company_id,
    )
    _print_json(result.raw)
    return 0 if result.success else 2


def _cmd_search_documents(args: argparse.Namespace) -> int:
    result = _client_from_env().search_documents(
        args.query,
        folder_path=args.folder or None,
        top_k=args.top_k,
    )
    _print_json(result.raw)
    return 0


def _cmd_approvals_list(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_pending_approvals())
    return 0


def _cmd_approvals_get(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().get_approval(args.task_id))
    return 0


def _cmd_approvals_approve(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().approve_task(args.task_id, comments=args.comment or ""))
    return 0


def _cmd_approvals_reject(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().reject_task(args.task_id, comments=args.comment or ""))
    return 0


def _cmd_voice_list(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_voice_executions(limit=args.limit))
    return 0


def _cmd_voice_get(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().get_voice_execution(args.execution_id))
    return 0


def _cmd_aoc_list(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_aoc_runs())
    return 0


def _cmd_aoc_stop(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().stop_aoc_run(args.run_id))
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    base_url = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com").rstrip("/")
    clear_cached_token(base_url)
    print("Cached token cleared.")
    return 0


def _cmd_ping(_: argparse.Namespace) -> int:
    """Lightweight health probe: hits /api/users/me to confirm auth is live."""
    try:
        me = _client_from_env().whoami()
    except Exception as exc:
        print(f"unhealthy: {exc}")
        return 1
    print(f"ok — {me.get('email', '?')} ({me.get('role', '?')})")
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    """Interactive setup wizard."""
    target = setup_module.ToolTarget(args.target) if args.target else None
    write: Optional[bool]
    if args.yes:
        write = True
    elif args.no_write:
        write = False
    else:
        write = None  # ask interactively
    base_url = args.url or os.getenv("LIGHTBULB_URL") or None
    return setup_module.run_setup(
        base_url=base_url,
        target=target,
        write=write,
        skip_login=args.skip_login,
    )


def _cmd_status(_: argparse.Namespace) -> int:
    base_url = os.getenv("LIGHTBULB_URL", setup_module.DEFAULT_BASE_URL).rstrip("/")
    print(setup_module.render_status_report(base_url))
    return 0


def _load_mcp_main():
    """Import MCP entrypoint (test seam — patch this symbol)."""
    from lightbulb.mcp_server import main as mcp_main

    return mcp_main


def _cmd_mcp_run(_: argparse.Namespace) -> int:
    """Run the MCP server over stdio (alias for `python -m lightbulb.mcp_server`)."""
    _load_mcp_main()()
    return 0


# ── 0.6.2: connector hookup + tool surface introspection ──────────────


def _cmd_connect(args: argparse.Namespace) -> int:
    """Open the platform's OAuth flow for ``<provider>`` in the user's browser.

    Best-effort UX without a server-side `return_to=cli` redirect: we open the
    browser, the user completes login on the platform UI, and the user runs
    ``lightbulb connect --check <provider>`` (or ``lightbulb status``) to
    verify the connection landed.
    """
    base_url = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com").rstrip("/")
    provider = args.provider.strip().lower()

    if args.check:
        # Verify mode — list connected integrations and check if the provider
        # is in there. No browser open. Useful as the post-auth confirmation
        # step until the platform supports `return_to=cli`.
        client = _client_from_env()
        integrations = client.list_connected_integrations()
        match = next(
            (i for i in integrations if str(i.get("provider", "")).lower() == provider
             or str(i.get("name", "")).lower() == provider),
            None,
        )
        if match:
            status = match.get("status") or match.get("connectionStatus") or "connected"
            print(f"✓ {provider} is connected (status: {status}).")
            return 0
        print(f"✗ {provider} is not connected. Run `lightbulb connect {provider}` and complete the browser flow.")
        return 1

    # Validate provider against the known catalog before opening anything.
    try:
        client = _client_from_env()
        catalog = client.list_connectors()
    except Exception as exc:
        print(f"Could not fetch connector catalog: {exc}", file=sys.stderr)
        return 2

    known_providers = {str(c.get("provider", "")).lower() or str(c.get("name", "")).lower() for c in catalog}
    known_providers.discard("")
    if provider not in known_providers:
        print(f"Unknown provider {provider!r}.", file=sys.stderr)
        if known_providers:
            print(f"Available: {', '.join(sorted(known_providers))}", file=sys.stderr)
        return 2

    auth_url = f"{base_url}/api/oauth/authorize/{provider}"
    print(f"Opening browser to: {auth_url}")
    print("After completing login on the platform page, run:")
    print(f"  lightbulb connect --check {provider}")
    print("…to verify the connection landed.")

    try:
        from lightbulb.auth import _validate_redirect_url
        safe = _validate_redirect_url(auth_url, base_url)
        import webbrowser
        webbrowser.open(safe)
    except Exception as exc:
        print(f"Could not open browser ({exc}). Visit the URL above manually.", file=sys.stderr)
    return 0


def _cmd_tools(args: argparse.Namespace) -> int:
    """List tools currently exposed by the local MCP server (with namespace filter awareness).

    Helpful for customers diagnosing what's actually callable — particularly
    when ``LIGHTBULB_MCP_NAMESPACES`` is set or when the platform hasn't yet
    finished provisioning the full connector tool catalog.
    """
    # We don't actually boot the FastMCP server here — we just read what would
    # be registered by importing mcp_server in the same Python process and
    # reflecting on its registry.
    os.environ.setdefault("LIGHTBULB_API_KEY", "x")  # bypass auth-warning print
    os.environ.setdefault("LIGHTBULB_TENANT_ID", "00000000-0000-0000-0000-000000000000")
    os.environ.setdefault("LIGHTBULB_USER_ID", "00000000-0000-0000-0000-000000000001")
    import lightbulb.mcp_server as ms  # noqa: E402

    tools = sorted(ms.mcp._tool_manager._tools.keys())
    filt = (args.filter or "").lower().strip()
    if filt:
        tools = [t for t in tools if filt in t.lower()]

    if args.count_only:
        print(len(tools))
        return 0

    # Bucket by prefix for readability — same logic as the deep-research dump.
    from collections import defaultdict
    buckets: dict[str, list[str]] = defaultdict(list)
    for t in tools:
        prefix = t.split("_", 1)[0]
        buckets[prefix].append(t)
    for prefix in sorted(buckets):
        names = buckets[prefix]
        if len(names) > 1:
            print(f"━━━ {prefix} ({len(names)}) ━━━")
            for n in names:
                print(f"  {n}")
        else:
            print(f"{names[0]}")
    print()
    print(f"Total: {len(tools)} tools.")
    if os.getenv("LIGHTBULB_MCP_PROFILE"):
        print(f"Profile active: LIGHTBULB_MCP_PROFILE={os.getenv('LIGHTBULB_MCP_PROFILE')}")
    if os.getenv("LIGHTBULB_MCP_NAMESPACES"):
        print(f"Filter active: LIGHTBULB_MCP_NAMESPACES={os.getenv('LIGHTBULB_MCP_NAMESPACES')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lightbulb", description="Lightbulb Partners Agents CLI")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("setup", help="Interactive setup — auth + MCP wiring for Claude Code / Codex / Cursor")
    p.add_argument("--target", choices=[t.value for t in setup_module.ToolTarget],
                   help="Skip the menu and configure this tool directly")
    p.add_argument("--url", help="Platform URL (default: prompt)")
    p.add_argument("--yes", "-y", action="store_true", help="Write config without confirmation")
    p.add_argument("--no-write", action="store_true", help="Print snippet only, do not write")
    p.add_argument("--skip-login", action="store_true", help="Skip the device-flow login step")
    p.set_defaults(func=_cmd_setup)

    sub.add_parser("status", help="Show what's configured (default when no command given)").set_defaults(func=_cmd_status)
    sub.add_parser("mcp", help="Run the MCP server over stdio").set_defaults(func=_cmd_mcp_run)

    sub.add_parser("whoami", help="Show your identity").set_defaults(func=_cmd_whoami)
    sub.add_parser("ping", help="Auth health check").set_defaults(func=_cmd_ping)
    sub.add_parser("logout", help="Clear cached device-flow token").set_defaults(func=_cmd_logout)
    sub.add_parser("list-domains", help="List all domain agents").set_defaults(func=_cmd_list_domains)
    sub.add_parser("list-companies", help="List companies in tenant").set_defaults(func=_cmd_list_companies)

    p = sub.add_parser("dispatch", help="Dispatch to a domain agent")
    p.add_argument("domain")
    p.add_argument("--action", default="chat")
    p.add_argument("--message", "-m", default="")
    p.add_argument("--objective", default="")
    p.add_argument("--inputs", help="JSON object of structured inputs")
    p.add_argument("--conversation-id")
    p.add_argument("--company-id")
    p.set_defaults(func=_cmd_dispatch)

    p = sub.add_parser("search-documents", help="Semantic document search")
    p.add_argument("query")
    p.add_argument("--folder")
    p.add_argument("--top-k", type=int, default=10)
    p.set_defaults(func=_cmd_search_documents)

    appr = sub.add_parser("approvals", help="HITL approval ops")
    appr_sub = appr.add_subparsers(dest="subcommand", required=True)
    appr_sub.add_parser("list").set_defaults(func=_cmd_approvals_list)
    g = appr_sub.add_parser("get")
    g.add_argument("task_id"); g.set_defaults(func=_cmd_approvals_get)
    a = appr_sub.add_parser("approve")
    a.add_argument("task_id"); a.add_argument("--comment", "-c", default="")
    a.set_defaults(func=_cmd_approvals_approve)
    r = appr_sub.add_parser("reject")
    r.add_argument("task_id"); r.add_argument("--comment", "-c", default="")
    r.set_defaults(func=_cmd_approvals_reject)

    voice = sub.add_parser("voice", help="Voice/phone ops")
    voice_sub = voice.add_subparsers(dest="subcommand", required=True)
    vl = voice_sub.add_parser("list")
    vl.add_argument("--limit", type=int, default=20); vl.set_defaults(func=_cmd_voice_list)
    vg = voice_sub.add_parser("get")
    vg.add_argument("execution_id"); vg.set_defaults(func=_cmd_voice_get)

    aoc = sub.add_parser("aoc", help="AutoCompany cognitive-loop ops")
    aoc_sub = aoc.add_subparsers(dest="subcommand", required=True)
    aoc_sub.add_parser("list").set_defaults(func=_cmd_aoc_list)
    s = aoc_sub.add_parser("stop")
    s.add_argument("run_id"); s.set_defaults(func=_cmd_aoc_stop)

    # 0.6.2 — connect a connector (best-effort browser-based OAuth).
    p = sub.add_parser("connect", help="Open the platform's OAuth flow for a connector (Slack, HubSpot, Notion, …)")
    p.add_argument("provider", help="Connector name, e.g. slack / hubspot / notion / gmail / github")
    p.add_argument("--check", action="store_true",
                   help="Skip browser; just verify whether <provider> is already connected")
    p.set_defaults(func=_cmd_connect)

    # 0.6.2 — diagnose the local tool surface (namespace filter, catalog status, etc).
    p = sub.add_parser("tools", help="List MCP tools currently exposed by this install")
    p.add_argument("--filter", help="Substring filter on tool names")
    p.add_argument("--count-only", action="store_true", help="Print count only")
    p.set_defaults(func=_cmd_tools)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # No subcommand → run `status` so a bare `lightbulb` is useful.
    if not getattr(args, "command", None):
        args.func = _cmd_status
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
