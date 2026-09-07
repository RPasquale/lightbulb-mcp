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
    LIGHTBULB_CONTEXT_COMPANY_REF  optional public company ref for host hooks
    LIGHTBULB_CONTEXT_PROJECT_REF  optional public hosted-project ref for hooks

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
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

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
from lightbulb._version import __version__
from lightbulb.token_cache import (
    clear_cached_token,
    load_cached_token,
    save_cached_token,
)


_SOVEREIGN_SECURITY_PROFILE = "sovereign"
_HOOK_AUTH_ORIGIN_ENV = "LIGHTBULB_HOOK_AUTH_ORIGIN"


def _canonical_http_origin(value: str) -> str | None:
    """Return one exact HTTP(S) origin, or ``None`` for a non-origin URL."""
    try:
        parsed = urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    hostname = str(parsed.hostname or "").lower().rstrip(".")
    if (
        scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    if port == (443 if scheme == "https" else 80):
        port = None
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{rendered_host}" + (f":{port}" if port is not None else "")


def _resolve_auth(
    base_url: str,
    *,
    hook_security_profile: str | None = None,
) -> AuthStrategy:
    """Mirror of the MCP server's auth resolution chain."""
    sovereign_hook = (
        str(hook_security_profile or "").strip().lower()
        == _SOVEREIGN_SECURITY_PROFILE
    )
    if sovereign_hook:
        endpoint_error = setup_module._sovereign_endpoint_error(base_url)
        if endpoint_error:
            raise RuntimeError(f"Invalid Sovereign Local hook endpoint: {endpoint_error}")
    ambient_auth_allowed = not sovereign_hook or (
        _canonical_http_origin(os.getenv(_HOOK_AUTH_ORIGIN_ENV, ""))
        == _canonical_http_origin(base_url)
    )

    jwt = os.getenv("LIGHTBULB_JWT", "").strip()
    tenant_id = os.getenv("LIGHTBULB_TENANT_ID", "").strip()
    company_id = os.getenv("LIGHTBULB_COMPANY_ID", "").strip() or None
    api_key = os.getenv("LIGHTBULB_API_KEY", "").strip()
    user_id = os.getenv("LIGHTBULB_USER_ID", "").strip()
    email = os.getenv("LIGHTBULB_EMAIL", "").strip()
    password = os.getenv("LIGHTBULB_PASSWORD", "").strip()

    if ambient_auth_allowed and jwt and tenant_id:
        return JwtAuth(token=jwt, tenant_id=tenant_id, company_id=company_id)

    if ambient_auth_allowed and api_key and tenant_id and user_id:
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

    if ambient_auth_allowed and email and password:
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


def _client_from_env(
    *,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    hook_security_profile: str | None = None,
    auth_refresh: Any = None,
) -> LightbulbClient:
    base_url = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com").rstrip("/")
    auth = _resolve_auth(base_url, hook_security_profile=hook_security_profile)
    from lightbulb.validators import is_local_url
    is_local = is_local_url(base_url)
    timeout_kwargs: dict[str, float] = {}
    if connect_timeout is not None:
        timeout_kwargs["connect_timeout"] = connect_timeout
    if read_timeout is not None:
        timeout_kwargs["read_timeout"] = read_timeout
    return LightbulbClient(
        base_url,
        auth=auth,
        enforce_https=not is_local,
        auth_refresh=auth_refresh,
        **timeout_kwargs,
    )


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


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"lightbulb-mcp {__version__}")
    return 0


def _take_observed_outcomes(
    path: str | None,
) -> tuple[list[dict[str, Any]] | None, Any | None, list[Any]]:
    if not path:
        runtime_path = os.getenv("LIGHTBULB_RUNTIME_OUTCOMES_FILE", "").strip()
        if not runtime_path:
            return None, None, []
        from lightbulb.runtime_outcomes import JsonlOutcomeRecorder, improvement_outcomes

        recorder = JsonlOutcomeRecorder(runtime_path)
        drained = recorder.drain()
        return improvement_outcomes(drained), recorder, drained
    from lightbulb.workflow_improvement import MAX_OBSERVED_OUTCOME_FILE_BYTES

    source = Path(path)
    try:
        size = source.stat().st_size
        if size > MAX_OBSERVED_OUTCOME_FILE_BYTES:
            raise RuntimeError(
                "observed outcomes file exceeds the finite "
                f"{MAX_OBSERVED_OUTCOME_FILE_BYTES}-byte intake limit"
            )
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read observed outcomes from {path}: {exc}") from exc
    if isinstance(payload, dict):
        payload = payload.get("outcomes")
    if not isinstance(payload, list):
        raise RuntimeError("observed outcomes must be a JSON array or an object with an outcomes array")
    return [row for row in payload if isinstance(row, dict)], None, []


def _read_observed_outcomes(path: str | None) -> list[dict[str, Any]] | None:
    return _take_observed_outcomes(path)[0]


def _restore_observed_outcomes(recorder: Any | None, outcomes: list[Any]) -> None:
    if recorder is None:
        return
    for outcome in outcomes:
        recorder.record(outcome)


def _cmd_improvement_run(args: argparse.Namespace) -> int:
    from lightbulb.workflow_improvement import run_workflow_improvement_cycle

    observed, recorder, drained = _take_observed_outcomes(args.observed_outcomes)
    try:
        report = run_workflow_improvement_cycle(
            Path(args.output_dir),
            observed_outcomes=observed,
        )
    except Exception:
        _restore_observed_outcomes(recorder, drained)
        raise
    _print_json(report)
    return 0


def _cmd_improvement_watch(args: argparse.Namespace) -> int:
    from lightbulb.workflow_improvement import (
        load_workflow_improvement_status,
        run_continuous_workflow_improvement,
    )

    output_dir = Path(args.output_dir)
    max_iterations = args.max_iterations
    stop_file = Path(args.stop_file) if args.stop_file else output_dir / "STOP"
    server_client = _client_from_env() if args.sync_server else None
    cycle_stats = {"completed": 0, "sync_failures": 0, "last_server_run_id": None}
    runtime_path = os.getenv("LIGHTBULB_RUNTIME_OUTCOMES_FILE", "").strip()
    runtime_recorder = None
    pending_runtime_outcomes: list[Any] = []
    if not args.observed_outcomes and runtime_path:
        from lightbulb.runtime_outcomes import JsonlOutcomeRecorder

        runtime_recorder = JsonlOutcomeRecorder(runtime_path)

    def _provider():
        if args.observed_outcomes:
            return _read_observed_outcomes(args.observed_outcomes)
        from lightbulb.runtime_outcomes import improvement_outcomes

        drained = runtime_recorder.drain() if runtime_recorder is not None else []
        pending_runtime_outcomes[:] = drained
        return improvement_outcomes(drained)

    def _stream(report: dict[str, Any]) -> None:
        pending_runtime_outcomes.clear()
        cycle_stats["completed"] += 1
        if server_client is not None:
            try:
                synced = server_client.sync_workflow_improvement_report(report)
                cycle_stats["last_server_run_id"] = synced.get("run", {}).get("id")
            except Exception as exc:
                cycle_stats["sync_failures"] += 1
                print(f"Workflow improvement server sync failed: {exc}", file=sys.stderr)

    try:
        reports = run_continuous_workflow_improvement(
            output_dir,
            interval_seconds=args.interval_seconds,
            max_iterations=max_iterations,
            max_elapsed_seconds=args.max_elapsed_seconds,
            max_no_progress_runs=args.max_no_progress_runs,
            observed_outcomes_provider=(
                _provider
                if args.observed_outcomes or os.getenv("LIGHTBULB_RUNTIME_OUTCOMES_FILE", "").strip()
                else None
            ),
            stop_file=stop_file,
            on_cycle=_stream,
            retain_reports=False,
        )
    except KeyboardInterrupt:
        _restore_observed_outcomes(runtime_recorder, pending_runtime_outcomes)
        print("Workflow improvement supervisor stopped.", file=sys.stderr)
        return 130
    except Exception:
        _restore_observed_outcomes(runtime_recorder, pending_runtime_outcomes)
        raise
    local_status = load_workflow_improvement_status(output_dir)
    supervisor = local_status.get("state", {}).get("supervisor", {})
    stop_reason = supervisor.get("stop_reason") if isinstance(supervisor, dict) else None
    if not stop_reason:
        stop_reason = "stop_file" if stop_file.exists() else "max_iterations"
    _print_json(
        {
            "status": "completed" if stop_reason == "max_iterations" else "stopped",
            "stop_reason": stop_reason,
            "cycles_completed": cycle_stats["completed"] or len(reports),
            "output_dir": str(output_dir.resolve()),
            "stop_file": str(stop_file.resolve()),
            "server_sync_enabled": server_client is not None,
            "server_sync_failures": cycle_stats["sync_failures"],
            "last_server_run_id": cycle_stats["last_server_run_id"],
            "automatic_code_mutation": False,
            "human_approval_required": True,
            "supervisor_budget": local_status.get("safety", {}).get(
                "finite_supervisor_budget"
            ),
        }
    )
    return 2 if cycle_stats["sync_failures"] else 0


def _cmd_improvement_status(args: argparse.Namespace) -> int:
    from lightbulb.workflow_improvement import load_workflow_improvement_status

    _print_json(load_workflow_improvement_status(Path(args.output_dir)))
    return 0


def _cmd_improvement_queue(args: argparse.Namespace) -> int:
    from lightbulb.workflow_improvement import list_workflow_improvement_packets

    _print_json(
        list_workflow_improvement_packets(
            Path(args.output_dir),
            status=args.status or None,
        )
    )
    return 0


def _json_object_argument(value: str | None, label: str) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return parsed


def _cmd_improvement_sync(args: argparse.Namespace) -> int:
    path = Path(args.output_dir) / "latest.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"could not read {path}: {exc}") from exc
    _print_json(_client_from_env().sync_workflow_improvement_report(report))
    return 0


def _cmd_improvement_server_status(_: argparse.Namespace) -> int:
    _print_json(_client_from_env().get_server_workflow_improvement_status())
    return 0


def _cmd_improvement_server_queue(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().list_server_workflow_improvement_packets(
        status=args.status or None, limit=args.limit))
    return 0


def _cmd_improvement_decide(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().decide_workflow_improvement_packet(
        args.packet_id,
        approval_scope=args.approval_scope,
        decision=args.decision,
        rationale=args.rationale or "",
        evidence=_json_object_argument(args.evidence, "evidence"),
    ))
    return 0


def _cmd_improvement_audit(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().get_workflow_improvement_audit(args.packet_id))
    return 0


def _cmd_improvement_deliver(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().start_workflow_improvement_delivery(
        args.packet_id,
        environment=args.environment,
        repository_ref=args.repository_ref or None,
        base_branch=args.base_branch,
    ))
    return 0


def _cmd_improvement_delivery_event(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().record_workflow_improvement_delivery_event(
        args.delivery_id,
        args.event_type,
        rationale=args.rationale or "",
        evidence=_json_object_argument(args.evidence, "evidence"),
    ))
    return 0


def _cmd_improvement_delivery_status(args: argparse.Namespace) -> int:
    _print_json(_client_from_env().get_workflow_improvement_delivery(args.delivery_id))
    return 0


def _cmd_connector_conformance(args: argparse.Namespace) -> int:
    if args.live:
        report = _client_from_env().run_connector_conformance(check_live_schemas=True)
    else:
        from lightbulb.connector_conformance import run_connector_conformance

        report = run_connector_conformance().to_dict()
    _print_json(report)
    return 0 if report.get("passed") else 2


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
        context_company_ref=(
            args.context_company_ref
            or os.getenv("LIGHTBULB_CONTEXT_COMPANY_REF")
            or None
        ),
        context_project_ref=(
            args.context_project_ref
            or os.getenv("LIGHTBULB_CONTEXT_PROJECT_REF")
            or None
        ),
        mcp_profile=args.mcp_profile,
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


def _cmd_context_hook(args: argparse.Namespace) -> int:
    """Run one fail-open host lifecycle event from JSON on stdin."""
    from lightbulb.context_hook import (
        HOOK_CONNECT_TIMEOUT_SECONDS,
        HOOK_READ_TIMEOUT_SECONDS,
        run_hook_command,
    )

    if args.url:
        os.environ["LIGHTBULB_URL"] = args.url.rstrip("/")
    hook_security_profile = (
        str(getattr(args, "security_profile", None) or "").strip().lower() or None
    )
    if hook_security_profile == _SOVEREIGN_SECURITY_PROFILE:
        os.environ["LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE"] = (
            _SOVEREIGN_SECURITY_PROFILE
        )

    company_ref = (
        getattr(args, "company_ref", None)
        or os.getenv("LIGHTBULB_CONTEXT_COMPANY_REF")
        or None
    )
    project_ref = (
        getattr(args, "project_ref", None)
        or os.getenv("LIGHTBULB_CONTEXT_PROJECT_REF")
        or None
    )
    project_configured = bool(company_ref or project_ref)

    def context_client() -> LightbulbClient:
        client_kwargs: dict[str, Any] = {
            "connect_timeout": HOOK_CONNECT_TIMEOUT_SECONDS,
            "read_timeout": HOOK_READ_TIMEOUT_SECONDS,
        }
        if hook_security_profile is not None:
            client_kwargs["hook_security_profile"] = hook_security_profile
        client = _client_from_env(**client_kwargs)
        # Continuum is personal for tenant/admin accounts unless the hook is
        # explicitly pinned. Never inherit a mutable MCP select_company value
        # from a different process.
        if not project_configured:
            client.context_company_id = (
                os.getenv("LIGHTBULB_CONTEXT_COMPANY_ID", "").strip() or None
            )
        return client

    return run_hook_command(
        client_factory=context_client,
        host=args.host,
        token_budget=args.token_budget,
        company_ref=company_ref,
        project_ref=project_ref,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lightbulb", description="Lightbulb Partners Agents CLI")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser(
        "setup",
        help="Interactive setup — auth, MCP wiring, and supported host context hooks",
    )
    p.add_argument("--target", choices=[t.value for t in setup_module.ToolTarget],
                   help="Skip the menu and configure this tool directly")
    p.add_argument("--url", help="Platform URL (default: prompt)")
    p.add_argument("--yes", "-y", action="store_true", help="Write config without confirmation")
    p.add_argument("--no-write", action="store_true", help="Print snippet only, do not write")
    p.add_argument("--skip-login", action="store_true", help="Skip the device-flow login step")
    p.add_argument(
        "--mcp-profile",
        choices=["adaptive", "backbone", "discovery", "sovereign"],
        default=os.getenv("LIGHTBULB_MCP_PROFILE", setup_module.DEFAULT_MCP_PROFILE),
        help="Install a bounded MCP tool profile (use sovereign for Local deployments)",
    )
    p.add_argument(
        "--context-company-ref",
        help="Public company ref for project-scoped Codex/Claude context hooks",
    )
    p.add_argument(
        "--context-project-ref",
        help="Public hosted project ref for project-scoped Codex/Claude context hooks",
    )
    p.set_defaults(func=_cmd_setup)

    sub.add_parser("status", help="Show what's configured (default when no command given)").set_defaults(func=_cmd_status)
    sub.add_parser("mcp", help="Run the MCP server over stdio").set_defaults(func=_cmd_mcp_run)
    sub.add_parser("version", help="Print the installed lightbulb-mcp package version").set_defaults(func=_cmd_version)

    from lightbulb.company_cli import add_company_parser

    add_company_parser(sub, client_factory=_client_from_env)

    p = sub.add_parser(
        "context-hook",
        help="Process one Codex/Claude lifecycle hook event from JSON on stdin",
    )
    p.add_argument("--host", default="codex", choices=["codex", "claude_code"])
    p.add_argument("--url", help="Lightbulb API URL used by this hook invocation")
    p.add_argument("--token-budget", type=int, default=2_000)
    p.add_argument(
        "--security-profile",
        choices=[_SOVEREIGN_SECURITY_PROFILE],
        help="Activate the fail-closed Sovereign Local hook authentication policy",
    )
    p.add_argument(
        "--company-ref",
        help="Configured public company ref (must be paired with --project-ref)",
    )
    p.add_argument(
        "--project-ref",
        help="Configured public hosted project ref (must be paired with --company-ref)",
    )
    p.set_defaults(func=_cmd_context_hook)

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
    g.add_argument("task_id")
    g.set_defaults(func=_cmd_approvals_get)
    a = appr_sub.add_parser("approve")
    a.add_argument("task_id")
    a.add_argument("--comment", "-c", default="")
    a.set_defaults(func=_cmd_approvals_approve)
    r = appr_sub.add_parser("reject")
    r.add_argument("task_id")
    r.add_argument("--comment", "-c", default="")
    r.set_defaults(func=_cmd_approvals_reject)

    voice = sub.add_parser("voice", help="Voice/phone ops")
    voice_sub = voice.add_subparsers(dest="subcommand", required=True)
    vl = voice_sub.add_parser("list")
    vl.add_argument("--limit", type=int, default=20)
    vl.set_defaults(func=_cmd_voice_list)
    vg = voice_sub.add_parser("get")
    vg.add_argument("execution_id")
    vg.set_defaults(func=_cmd_voice_get)

    aoc = sub.add_parser("aoc", help="AutoCompany cognitive-loop ops")
    aoc_sub = aoc.add_subparsers(dest="subcommand", required=True)
    aoc_sub.add_parser("list").set_defaults(func=_cmd_aoc_list)
    s = aoc_sub.add_parser("stop")
    s.add_argument("run_id")
    s.set_defaults(func=_cmd_aoc_stop)

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

    p = sub.add_parser(
        "connector-conformance",
        help="Verify primitive connector contracts and optional hosted schema drift",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Compare with authenticated hosted Tool schemas without invoking vendors",
    )
    p.set_defaults(func=_cmd_connector_conformance)

    improve = sub.add_parser(
        "improve-workflows",
        help="Evaluate business primitives continuously and prepare approval-gated SDK work packets",
    )
    improve_sub = improve.add_subparsers(dest="improvement_command", required=True)

    p = improve_sub.add_parser("run", help="Run one proposal-only improvement cycle")
    p.add_argument("--output-dir", default=str(Path(".lightbulb") / "workflow-improvement"))
    p.add_argument("--observed-outcomes", help="JSON file with sanitized runtime outcome summaries")
    p.set_defaults(func=_cmd_improvement_run)

    p = improve_sub.add_parser("watch", help="Run a finite supervisor until a budget or STOP ends it")
    p.add_argument("--output-dir", default=str(Path(".lightbulb") / "workflow-improvement"))
    p.add_argument("--observed-outcomes", help="JSON file re-read before each cycle")
    p.add_argument("--interval-seconds", type=float, default=900)
    p.add_argument(
        "--max-iterations",
        type=int,
        default=96,
        help="Finite cycle limit (default: 96; unbounded mode is not supported)",
    )
    p.add_argument(
        "--max-elapsed-seconds",
        type=int,
        default=86_400,
        help="Finite wall-time limit (default: 86400)",
    )
    p.add_argument(
        "--max-no-progress-runs",
        type=int,
        default=2,
        help="Stop after this many stable no-progress cycles (default: 2)",
    )
    p.add_argument("--stop-file", help="Create this file to request a clean stop")
    p.add_argument("--sync-server", action="store_true", help="Persist every cycle to the authenticated scoped ledger")
    p.set_defaults(func=_cmd_improvement_watch)

    p = improve_sub.add_parser("status", help="Read the latest local improvement-loop state")
    p.add_argument("--output-dir", default=str(Path(".lightbulb") / "workflow-improvement"))
    p.set_defaults(func=_cmd_improvement_status)

    p = improve_sub.add_parser("queue", help="List proposal or approved SDK work packets")
    p.add_argument("--output-dir", default=str(Path(".lightbulb") / "workflow-improvement"))
    p.add_argument("--status", choices=["proposed", "approved", "rejected", "completed"])
    p.set_defaults(func=_cmd_improvement_queue)

    p = improve_sub.add_parser("sync", help="Sync latest local evidence to the authenticated scoped ledger")
    p.add_argument("--output-dir", default=str(Path(".lightbulb") / "workflow-improvement"))
    p.set_defaults(func=_cmd_improvement_sync)

    improve_sub.add_parser("server-status", help="Read durable scoped improvement status").set_defaults(
        func=_cmd_improvement_server_status)

    p = improve_sub.add_parser("server-queue", help="List durable scoped improvement packets")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=_cmd_improvement_server_queue)

    p = improve_sub.add_parser("decide", help="Record one immutable approval decision")
    p.add_argument("packet_id")
    p.add_argument("approval_scope", choices=["implementation", "publish", "deploy"])
    p.add_argument("decision", choices=["approved", "rejected"])
    p.add_argument("--rationale")
    p.add_argument("--evidence", default="{}", help="Sanitized JSON evidence object")
    p.set_defaults(func=_cmd_improvement_decide)

    p = improve_sub.add_parser("audit", help="Read a packet's immutable audit trail")
    p.add_argument("packet_id")
    p.set_defaults(func=_cmd_improvement_audit)

    p = improve_sub.add_parser("deliver", help="Start approved isolated branch and staging delivery")
    p.add_argument("packet_id")
    p.add_argument("--environment", required=True, help="staging, staging-*, or disposable-*")
    p.add_argument("--repository-ref")
    p.add_argument("--base-branch", default="main")
    p.set_defaults(func=_cmd_improvement_deliver)

    p = improve_sub.add_parser("delivery-event", help="Record branch, PR, CI, staging, canary, or rollback evidence")
    p.add_argument("delivery_id")
    p.add_argument("event_type", choices=[
        "branch_created", "implementation_completed", "pull_request_opened", "ci_passed", "ci_failed",
        "staging_deployed", "canary_started", "canary_evaluated",
        "rollback_completed", "staging_cleaned",
    ])
    p.add_argument("--rationale")
    p.add_argument("--evidence", default="{}", help="Sanitized JSON evidence object")
    p.set_defaults(func=_cmd_improvement_delivery_event)

    p = improve_sub.add_parser("delivery-status", help="Read one delivery state")
    p.add_argument("delivery_id")
    p.set_defaults(func=_cmd_improvement_delivery_status)

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
