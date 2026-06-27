"""Async-native Lightbulb platform client.

Mirrors the most-used methods of :class:`lightbulb.client.LightbulbClient` but
uses ``httpx.AsyncClient`` so callers in asyncio-based applications (FastAPI,
discord.py, aiohttp servers, etc.) don't have to bounce through a thread pool.

Coverage is curated, not exhaustive — the goal is "the methods you'll call in
a hot loop." For niche operations, use :class:`LightbulbClient` directly.

Usage::

    >>> from lightbulb import AsyncLightbulbClient, JwtAuth
    >>> async with AsyncLightbulbClient("https://...", auth=JwtAuth(...)) as c:
    ...     me = await c.whoami()
    ...     async for ev in c.stream_chat("finance", message="Run forecasting"):
    ...         print(ev.event, ev.data)
"""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncGenerator, Callable, Dict, List
from urllib.parse import urlparse

import httpx

from lightbulb._version import __version__
from lightbulb.auth import AuthStrategy
from lightbulb.errors import raise_if_error
from lightbulb.client import (
    SSEEvent,
    DispatchResult,
    _CONNECT_TIMEOUT,
    _MAX_RESPONSE_BYTES,
    _MAX_SSE_EVENT_BYTES,
    _MAX_SSE_LINE_BYTES,
    _READ_TIMEOUT,
    _STREAM_READ_TIMEOUT,
    _normalize_code_chat_kwargs,
    _sanitize_inputs,
    _validate_action,
    _validate_domain,
    _validate_message,
)

logger = logging.getLogger(__name__)


class AsyncLightbulbClient:
    """Async client for the Lightbulb platform API."""

    def __init__(
        self,
        base_url: str,
        auth: AuthStrategy,
        *,
        enforce_https: bool = True,
        connect_timeout: float = _CONNECT_TIMEOUT,
        read_timeout: float = _READ_TIMEOUT,
        auth_refresh: "Callable[[], AuthStrategy] | None" = None,
    ) -> None:
        parsed = urlparse(base_url.rstrip("/"))
        # Canonical helper: covers IPv6 ::1 + any future loopback aliases
        # (audit-id: is_local_ipv6_0_5_1).
        from lightbulb.validators import is_local_url
        is_local = is_local_url(base_url)
        if enforce_https and parsed.scheme != "https" and not is_local:
            raise ValueError(
                f"HTTPS is required for non-localhost URLs (got {parsed.scheme}://{parsed.hostname}). "
                "Pass enforce_https=False only for local development."
            )
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._auth_refresh = auth_refresh
        self._refresh_in_flight = False
        self._timeout = httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=30.0,
            pool=30.0,
        )
        self._stream_timeout = httpx.Timeout(
            connect=connect_timeout,
            read=_STREAM_READ_TIMEOUT,
            write=30.0,
            pool=30.0,
        )
        self._client: httpx.AsyncClient | None = None
        self._csrf_token: str | None = None
        self._active_company_id: str | None = auth.company_id

    # ── Lifecycle ────────────────────────────────────────────────────

    async def __aenter__(self) -> "AsyncLightbulbClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False)
            try:
                await self._client.post(
                    f"{self._base_url}/api/auth/csrf",
                    headers=self._auth.apply({"Accept": "application/json"}),
                )
            except Exception:
                pass
        return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def refresh_auth(self) -> bool:
        """Async equivalent of :meth:`LightbulbClient.refresh_auth`."""
        if self._auth_refresh is None or self._refresh_in_flight:
            return False
        self._refresh_in_flight = True
        try:
            result = self._auth_refresh()
            new_auth = await result if hasattr(result, "__await__") else result
            if new_auth is None:
                return False
            self._auth = new_auth
            if new_auth.company_id and not self._active_company_id:
                self._active_company_id = new_auth.company_id
            await self.close()  # force a fresh session next call
            return True
        except Exception as exc:
            logger.warning("auth_refresh callback failed: %s", exc)
            return False
        finally:
            self._refresh_in_flight = False

    @property
    def active_company_id(self) -> str | None:
        return self._active_company_id

    @active_company_id.setter
    def active_company_id(self, value: str | None) -> None:
        self._active_company_id = value

    async def _fetch_csrf_token(self) -> str:
        try:
            client = await self._ensure_client()
            resp = await client.get(
                f"{self._base_url}/api/auth/csrf",
                headers=self._auth.apply({"Accept": "application/json"}),
            )
            if resp.status_code == 200:
                self._csrf_token = (resp.json() or {}).get("token", "")
                return self._csrf_token or ""
        except Exception:
            pass
        return ""

    async def _headers(self, extra: Dict[str, str] | None = None) -> Dict[str, str]:
        base = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"lightbulb-mcp/{__version__} (async)",
        }
        csrf = await self._fetch_csrf_token()
        if csrf:
            base["X-XSRF-TOKEN"] = csrf
        if extra:
            base.update(extra)
        return self._auth.apply(base)

    async def _stream_headers(self) -> Dict[str, str]:
        return await self._headers({"Accept": "text/event-stream"})

    # ── Identity & Discovery ─────────────────────────────────────────

    async def whoami(self) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.get(f"{self._base_url}/api/users/me", headers=await self._headers())
        raise_if_error(resp)
        return resp.json()

    async def list_companies(self) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        tenant_id = self._auth.tenant_id
        resp = await client.get(
            f"{self._base_url}/api/companies/tenant/{tenant_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("companies", []))

    async def list_domains(self) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/domain-agents/contracts",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def list_connected_integrations(self, company_id: str | None = None) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        params = {}
        effective = company_id or self._active_company_id
        if effective:
            params["company_id"] = effective
        resp = await client.get(
            f"{self._base_url}/api/oauth/connections",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    # ── Domain Agent: dispatch + stream ──────────────────────────────

    async def dispatch(
        self,
        domain: str,
        *,
        action: str = "chat",
        message: str = "",
        objective: str = "",
        inputs: Dict[str, Any] | None = None,
        conversation_id: str | None = None,
        company_id: str | None = None,
    ) -> DispatchResult:
        domain = _validate_domain(domain)
        action = _validate_action(action)
        if message:
            message = _validate_message(message)

        payload: Dict[str, Any] = {"action": action}
        if message:
            payload["message"] = message
        if objective:
            payload["objective"] = str(objective)
        if inputs:
            payload["inputs"] = _sanitize_inputs(inputs)
        if conversation_id:
            payload["conversation_id"] = str(conversation_id).strip()
        effective = company_id or self._active_company_id
        if effective:
            payload["company_id"] = str(effective).strip()

        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/domain-agents/{domain}/dispatch",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return DispatchResult(
            domain=data.get("domain", domain),
            action=data.get("action", action),
            mode=data.get("mode", ""),
            reply=data.get("reply", ""),
            conversation_id=data.get("conversationId") or data.get("conversation_id", ""),
            trace_id=data.get("traceId") or data.get("trace_id", ""),
            outputs=data.get("outputs") or data.get("structuredOutputs") or {},
            raw=data,
        )

    async def stream_chat(
        self,
        domain: str,
        *,
        message: str,
        action: str | None = None,
        inputs: Dict[str, Any] | None = None,
        conversation_id: str | None = None,
        company_id: str | None = None,
    ) -> AsyncGenerator[SSEEvent, None]:
        domain = _validate_domain(domain)
        message = _validate_message(message)
        payload: Dict[str, Any] = {
            "domain": domain,
            "message": message,
            "tenant_id": self._auth.tenant_id,
        }
        if action:
            payload["action"] = _validate_action(action)
        if inputs:
            payload["inputs"] = _sanitize_inputs(inputs)
        if conversation_id:
            payload["conversation_id"] = str(conversation_id).strip()
        if company_id or self._auth.company_id:
            payload["company_id"] = str(company_id or self._auth.company_id).strip()

        async for ev in self._stream_sse(
            f"{self._base_url}/api/domain-agent/chat",
            payload=payload,
        ):
            yield ev

    async def stream_code_workspace_chat(
        self,
        workspace_id: str,
        message: str,
        **kwargs: Any,
    ) -> AsyncGenerator[SSEEvent, None]:
        message = _validate_message(message)
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        async for ev in self._stream_sse(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat/stream",
            payload=payload,
        ):
            yield ev

    async def stream_page_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> AsyncGenerator[SSEEvent, None]:
        async for ev in self._stream_sse(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/message",
            payload={"content": _validate_message(content)},
        ):
            yield ev

    async def stream_document_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> AsyncGenerator[SSEEvent, None]:
        async for ev in self._stream_sse(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/message",
            payload={"content": _validate_message(content)},
        ):
            yield ev

    async def _stream_sse(
        self,
        url: str,
        *,
        payload: Dict[str, Any],
    ) -> AsyncGenerator[SSEEvent, None]:
        # New AsyncClient with stream-friendly timeout — re-using the persistent
        # client for streaming can stall short calls, so we open a dedicated one.
        headers = await self._stream_headers()
        async with httpx.AsyncClient(timeout=self._stream_timeout, follow_redirects=False) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as response:
                raise_if_error(response)
                current_event = "message"
                buffer: List[str] = []
                bytes_read = 0
                event_bytes = 0
                async for line in response.aiter_lines():
                    if len(line) > _MAX_SSE_LINE_BYTES:
                        logger.warning(
                            "Async SSE line exceeded %d bytes; aborting.",
                            _MAX_SSE_LINE_BYTES,
                        )
                        break
                    bytes_read += len(line) + 1
                    if bytes_read > _MAX_RESPONSE_BYTES:
                        logger.warning("Async SSE exceeded %d bytes, closing", _MAX_RESPONSE_BYTES)
                        break
                    if line.startswith("event:"):
                        current_event = line[6:].strip()
                    elif line.startswith("data:"):
                        payload = line[5:].strip()
                        event_bytes += len(payload) + 1
                        if event_bytes > _MAX_SSE_EVENT_BYTES:
                            logger.warning(
                                "Async SSE event exceeded %d bytes; dropping.",
                                _MAX_SSE_EVENT_BYTES,
                            )
                            buffer.clear()
                            event_bytes = 0
                            continue
                        buffer.append(payload)
                    elif line == "" and buffer:
                        raw_data = "\n".join(buffer)
                        buffer.clear()
                        event_bytes = 0
                        try:
                            parsed = json.loads(raw_data) if raw_data else {}
                        except json.JSONDecodeError:
                            parsed = {"raw_text": raw_data}
                        yield SSEEvent(event=current_event, data=parsed, raw=raw_data)
                        current_event = "message"
                    elif line.startswith(":"):
                        continue

    # ── Code Workspace (high-traffic) ────────────────────────────────

    async def list_code_workspaces(self) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(f"{self._base_url}/api/code/workspaces", headers=await self._headers())
        raise_if_error(resp)
        return resp.json()

    async def code_workspace_chat(self, workspace_id: str, message: str, **kwargs: Any) -> Dict[str, Any]:
        client = await self._ensure_client()
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        resp = await client.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_code_workspace_run(self, workspace_id: str, run_id: str) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_code_workspace_active_run(self, workspace_id: str) -> Dict[str, Any] | None:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/active",
            headers=await self._headers(),
        )
        if resp.status_code == 204:
            return None
        raise_if_error(resp)
        return resp.json()

    # ── Document / Page Builder (non-streaming) ──────────────────────

    async def search_documents(self, query: str, *, top_k: int = 10) -> Dict[str, Any]:
        result = await self.dispatch(
            "document_intelligence",
            action="search_documents",
            message=query,
            inputs={"message": query, "top_k": top_k},
        )
        return result.raw

    async def page_builder_send_message(self, session_id: str, content: str) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/message",
            json={"content": content},
            headers=await self._headers({"Accept": "application/json"}),
        )
        raise_if_error(resp)
        return resp.json()

    async def document_builder_get_messages(self, session_id: str, **filters: Any) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/messages",
            params={k: v for k, v in filters.items() if v is not None},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("messages", []))

    # ── Approvals (HITL) ─────────────────────────────────────────────

    async def list_pending_approvals(self) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflows/approvals/pending",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def approve_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/approve",
            json={"comments": comments},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def reject_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/reject",
            json={"comments": comments},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Voice (live phone) ───────────────────────────────────────────

    async def list_voice_executions(self, **filters: Any) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/voice/executions",
            params={k: v for k, v in filters.items() if v is not None},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("executions", []))

    async def list_voice_pending_approvals(self) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/voice/executions/approvals/pending",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    async def approve_voice_action(self, execution_id: str, approval_task_id: str, *, comments: str = "") -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/approve",
            json={"comments": comments},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── AOC / AutoCompany ────────────────────────────────────────────

    async def list_aoc_runs(self, **filters: Any) -> List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/aoc/runs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("runs", []))

    async def stop_aoc_run(self, run_id: str) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/aoc/runs/{run_id}/stop",
            json={},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Generic invoke_tool (escape hatch) ──────────────────────────

    async def invoke_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke a platform tool by name. Mirrors the sync client's wire shape:
        ``toolName`` + ``inputs`` (plus tenant/company scope from auth)."""
        client = await self._ensure_client()
        payload: Dict[str, Any] = {"toolName": tool_name, "inputs": arguments}
        tenant_id = getattr(self._auth, "tenant_id", None)
        if tenant_id:
            payload["tenantId"] = tenant_id
        if self._active_company_id:
            payload["companyId"] = self._active_company_id
        resp = await client.post(
            f"{self._base_url}/api/tools/invoke",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()
