"""Lightbulb platform API client.

Usage::

    from lightbulb import LightbulbClient, ApiKeyAuth

    auth = ApiKeyAuth(
        api_key="your-internal-api-key",
        tenant_id="00000000-0000-0000-0000-000000000001",
        user_id="00000000-0000-0000-0000-000000000002",
    )
    client = LightbulbClient("https://agents.lightbulbpartners.com", auth=auth)

    # Dispatch a document agent action
    result = client.dispatch("document_intelligence", action="search_documents", message="quarterly revenue")

    # Stream a domain agent chat
    for event in client.stream_chat("document_intelligence", message="Create a quarterly report"):
        print(event)

Security notes:
- Credentials are injected via the AuthStrategy and never logged.
- All inputs are validated before being sent.
- The client enforces HTTPS in production (non-localhost) by default.
- Request/response bodies are size-bounded to prevent memory exhaustion.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Optional
from urllib.parse import urlparse

import httpx

from lightbulb._version import __version__
from lightbulb.auth import AuthStrategy
from lightbulb.errors import raise_if_error

logger = logging.getLogger(__name__)

_MAX_MESSAGE_LENGTH = 100_000
_MAX_RESPONSE_BYTES = 50 * 1024 * 1024  # 50 MB total per stream
_MAX_SSE_LINE_BYTES = 1 * 1024 * 1024   # 1 MB per SSE line (DoS guard)
_MAX_SSE_EVENT_BYTES = 8 * 1024 * 1024  # 8 MB per accumulated event
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 120.0

# Cap outbound request bodies. The hosted API sits behind an edge proxy (Cloudflare) that rejects
# oversized request bodies — historically as an opaque 403. Fail fast here with an actionable
# error instead, so callers know to trim/chunk the payload rather than chasing a confusing 403.
# Configurable via LIGHTBULB_MAX_REQUEST_BODY_BYTES; default ~5 MB stays well under the edge limit.
_MAX_REQUEST_BODY_BYTES = int(os.getenv("LIGHTBULB_MAX_REQUEST_BODY_BYTES", str(5 * 1024 * 1024)))


def _guard_request_body(payload: object, *, endpoint: str = "") -> None:
    """Raise a clear ValueError when a JSON request body would exceed the configured ceiling,
    rather than letting the edge proxy reject it with an opaque 403/413."""
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except Exception:
        return
    if size > _MAX_REQUEST_BODY_BYTES:
        raise ValueError(
            f"Request body is {size} bytes, over the {_MAX_REQUEST_BODY_BYTES}-byte limit"
            + (f" for {endpoint}" if endpoint else "")
            + ". Trim or chunk the payload (large documents/context), or raise "
            "LIGHTBULB_MAX_REQUEST_BODY_BYTES if the server/edge allows it."
        )
_STREAM_READ_TIMEOUT = 300.0

_SAFE_STRING_RE = re.compile(r"^[\w\s\-.,;:!?()'\"/\\@#$%^&*+=\[\]{}|<>~`]+$", re.UNICODE)

# ID validator shared with all path-component arguments — rejects '..',
# slashes, query separators, control chars, etc. See lightbulb.validators
# for the full helper module; this duplicate keeps client.py importable
# without triggering the cyclic import that pulling validators in at top
# level would cause.
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _validate_id(value: object, label: str) -> str:
    if value is None:
        raise ValueError(f"{label} is required")
    s = str(value).strip()
    if not _ID_RE.match(s) or ".." in s:
        raise ValueError(f"{label} must match {_ID_RE.pattern} and not contain '..' (got length-{len(s)})")
    return s


def _validate_domain(domain: str) -> str:
    domain = str(domain).strip().lower()
    if not domain or not re.match(r"^[a-z][a-z0-9_]{0,63}$", domain):
        raise ValueError(f"Invalid domain name: {domain!r}")
    return domain


def _validate_message(message: str) -> str:
    message = str(message).strip()
    if not message:
        raise ValueError("Message must not be empty")
    if len(message) > _MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message exceeds {_MAX_MESSAGE_LENGTH} character limit")
    return message


def _validate_action(action: str) -> str:
    action = str(action).strip().lower()
    if not action or not re.match(r"^[a-z][a-z0-9_]{0,63}$", action):
        raise ValueError(f"Invalid action name: {action!r}")
    return action


def _sanitize_inputs(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Shallow validation of input dict — reject obviously dangerous payloads."""
    serialised = json.dumps(inputs, default=str)
    if len(serialised) > _MAX_RESPONSE_BYTES:
        raise ValueError("Inputs payload too large")
    return inputs


def _normalize_code_chat_attachment(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    normalized = dict(value)
    if "mime_type" in normalized and "mimeType" not in normalized:
        normalized["mimeType"] = normalized.pop("mime_type")
    return normalized


def _normalize_code_chat_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    key_map = {
        "conversation_id": "conversationId",
        "active_file": "activeFile",
        "idempotency_key": "idempotencyKey",
        "agent_model_selection_id": "agentModelSelectionId",
        "agent_model_profile_id": "agentModelSelectionId",  # back-compat alias
        "agent_provider_connection_id": "agentProviderConnectionId",
        "agent_model_id": "agentModelId",
        "preview_mode": "previewMode",
        "auto_push": "autoPush",
    }
    normalized: Dict[str, Any] = {}
    for key, value in (kwargs or {}).items():
        target_key = key_map.get(key, key)
        if target_key == "attachments" and isinstance(value, list):
            normalized[target_key] = [_normalize_code_chat_attachment(item) for item in value]
        else:
            normalized[target_key] = value
    return normalized


@dataclass(frozen=True)
class SSEEvent:
    """A single Server-Sent Event from a streaming endpoint."""
    event: str
    data: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass(frozen=True)
class DispatchResult:
    """Result of a one-shot domain agent dispatch."""
    domain: str
    action: str
    mode: str
    reply: str
    conversation_id: str
    trace_id: str
    outputs: Dict[str, Any]
    raw: Dict[str, Any]

    @property
    def success(self) -> bool:
        state = str(self.raw.get("state") or "").lower()
        return state in ("completed", "success", "") and bool(self.reply or self.outputs)


class LightbulbClient:
    """Synchronous client for the Lightbulb platform API."""

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
        # Use the canonical helper so IPv6 ::1 and any future loopback aliases
        # are treated consistently with the rest of the SDK (audit-id:
        # is_local_ipv6_0_5_1).
        from lightbulb.validators import is_local_url
        is_local = is_local_url(base_url)
        if enforce_https and parsed.scheme != "https" and not is_local:
            raise ValueError(
                f"HTTPS is required for non-localhost URLs (got {parsed.scheme}://{parsed.hostname}). "
                "Pass enforce_https=False only for local development."
            )
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._active_company_id: str | None = auth.company_id
        # Optional callback invoked once after a 401 to refresh credentials.
        # The callback should return a fresh AuthStrategy (e.g. via device flow).
        self._auth_refresh = auth_refresh

    _session: httpx.Client | None = None
    _csrf_token: str | None = None
    _refresh_in_flight: bool = False

    @property
    def active_company_id(self) -> str | None:
        """The currently selected company context (needed for write operations)."""
        return self._active_company_id

    @active_company_id.setter
    def active_company_id(self, value: str | None) -> None:
        self._active_company_id = value

    def whoami(self) -> Dict[str, Any]:
        """Get the current user's identity, role, tenant, company, and permissions."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/users/me", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_connected_integrations(self, company_id: str | None = None) -> List[Dict[str, Any]]:
        """List connected integrations (OAuth connections) for the current company scope."""
        session = self._get_session()
        params = {}
        effective_company = company_id or self._active_company_id
        if effective_company:
            params["company_id"] = effective_company
        resp = session.get(
            f"{self._base_url}/api/oauth/connections",
            params=params,
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def list_companies(self) -> List[Dict[str, Any]]:
        """List companies the user has access to within their tenant."""
        session = self._get_session()
        tenant_id = self._auth.tenant_id
        resp = session.get(f"{self._base_url}/api/companies/tenant/{tenant_id}", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("companies", []))

    def _get_session(self, *, stream: bool = False) -> httpx.Client:
        """Get or create a persistent HTTP session with cookies.

        The session is reused across requests so CSRF tokens and session
        cookies remain valid.
        """
        if self._session is None or self._session.is_closed:
            timeout = httpx.Timeout(
                connect=self._connect_timeout,
                read=_STREAM_READ_TIMEOUT if stream else self._read_timeout,
                write=30.0,
                pool=30.0,
            )
            self._session = httpx.Client(timeout=timeout, follow_redirects=False)
            # Prime the session by logging in (sets auth cookie)
            try:
                self._session.post(
                    f"{self._base_url}/api/auth/csrf",
                    headers=self._auth.apply({"Accept": "application/json"}),
                )
            except Exception:
                pass
        return self._session

    def refresh_auth(self) -> bool:
        """Run the configured ``auth_refresh`` callback and swap in fresh auth.

        Returns ``True`` if a new ``AuthStrategy`` was installed. Callers
        typically invoke this after catching :class:`AuthenticationError`,
        then retry the failed request:

            try:
                client.dispatch("finance", action="chat", message="...")
            except AuthenticationError:
                if client.refresh_auth():
                    client.dispatch("finance", action="chat", message="...")
        """
        if self._auth_refresh is None or self._refresh_in_flight:
            return False
        self._refresh_in_flight = True
        try:
            new_auth = self._auth_refresh()
            if new_auth is None:
                return False
            self._auth = new_auth
            if new_auth.company_id and not self._active_company_id:
                self._active_company_id = new_auth.company_id
            # Force a new session so the CSRF/cookie state is rebuilt.
            if self._session is not None:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = None
            return True
        except Exception as exc:
            logger.warning("auth_refresh callback failed: %s", exc)
            return False
        finally:
            self._refresh_in_flight = False

    def _fetch_csrf_token(self) -> str:
        """Fetch a fresh CSRF token for each request."""
        try:
            session = self._get_session()
            resp = session.get(
                f"{self._base_url}/api/auth/csrf",
                headers=self._auth.apply({"Accept": "application/json"}),
            )
            if resp.status_code == 200:
                data = resp.json()
                self._csrf_token = data.get("token", "")
                return self._csrf_token
        except Exception:
            pass
        return ""

    def _headers(self, extra: Dict[str, str] | None = None) -> Dict[str, str]:
        base = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"lightbulb-mcp/{__version__}",
        }
        csrf = self._fetch_csrf_token()
        if csrf:
            base["X-XSRF-TOKEN"] = csrf
        if extra:
            base.update(extra)
        return self._auth.apply(base)

    def _stream_headers(self) -> Dict[str, str]:
        return self._headers({"Accept": "text/event-stream"})

    def _client(self, *, stream: bool = False) -> httpx.Client:
        """Return the persistent session (context-manager compatible)."""
        return self._get_session(stream=stream)

    # ── Domain Agent: One-shot dispatch ──────────────────────────────

    def dispatch(
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
        """Dispatch a one-shot action to a domain agent and wait for the result."""
        domain = _validate_domain(domain)
        action = _validate_action(action)
        if message:
            message = _validate_message(message)

        payload: Dict[str, Any] = {"action": action}
        if message:
            payload["message"] = message
        if objective:
            payload["objective"] = str(objective)[:_MAX_MESSAGE_LENGTH]
        if inputs:
            payload["inputs"] = _sanitize_inputs(inputs)
        if conversation_id:
            payload["conversation_id"] = str(conversation_id).strip()
        # Use explicit company_id, fall back to active company context
        effective_company = company_id or self._active_company_id
        if effective_company:
            payload["company_id"] = str(effective_company).strip()

        url = f"{self._base_url}/api/domain-agents/{domain}/dispatch"
        session = self._get_session()
        _guard_request_body(payload, endpoint=f"domain-agents/{domain}/dispatch")
        resp = session.post(url, json=payload, headers=self._headers())
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

    # ── Domain Agent: Streaming chat ─────────────────────────────────

    def stream_chat(
        self,
        domain: str,
        *,
        message: str,
        action: str | None = None,
        inputs: Dict[str, Any] | None = None,
        conversation_id: str | None = None,
        company_id: str | None = None,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a domain agent chat via Server-Sent Events.

        Yields SSEEvent objects for each event (status, chat, artifact, complete, error).
        """
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

        url = f"{self._base_url}/api/domain-agent/chat"
        session = self._get_session(stream=True)
        with session.stream("POST", url, json=payload, headers=self._stream_headers()) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def _parse_sse_stream(self, response: httpx.Response) -> Generator[SSEEvent, None, None]:
        current_event = "message"
        data_buffer: List[str] = []
        bytes_read = 0
        event_bytes = 0  # accumulated per-event size

        for line in response.iter_lines():
            # Per-line cap: a malicious server can withhold newlines so a
            # single line balloons in memory — reject anything pathological.
            if len(line) > _MAX_SSE_LINE_BYTES:
                logger.warning(
                    "SSE line exceeded %d bytes; aborting stream.",
                    _MAX_SSE_LINE_BYTES,
                )
                break

            bytes_read += len(line) + 1
            if bytes_read > _MAX_RESPONSE_BYTES:
                logger.warning("SSE stream exceeded %d bytes, closing", _MAX_RESPONSE_BYTES)
                break

            if line.startswith("event:"):
                current_event = line[6:].strip()
            elif line.startswith("data:"):
                payload = line[5:].strip()
                event_bytes += len(payload) + 1
                if event_bytes > _MAX_SSE_EVENT_BYTES:
                    logger.warning(
                        "SSE event exceeded %d bytes; dropping.",
                        _MAX_SSE_EVENT_BYTES,
                    )
                    data_buffer.clear()
                    event_bytes = 0
                    continue
                data_buffer.append(payload)
            elif line == "" and data_buffer:
                raw_data = "\n".join(data_buffer)
                data_buffer.clear()
                event_bytes = 0
                try:
                    parsed = json.loads(raw_data) if raw_data else {}
                except json.JSONDecodeError:
                    parsed = {"raw_text": raw_data}
                yield SSEEvent(event=current_event, data=parsed, raw=raw_data)
                current_event = "message"
            elif line.startswith(":"):
                # SSE comment / keepalive
                continue

    # ── Streaming: code workspace / page builder / doc builder ──────

    def stream_code_workspace_chat(
        self,
        workspace_id: str,
        message: str,
        **kwargs: Any,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a coding agent chat as Server-Sent Events.

        Yields SSEEvent objects (status, token, tool_call, diff, complete, error).
        The non-streaming counterpart is :meth:`code_workspace_chat`.
        """
        message = _validate_message(message)
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        url = f"{self._base_url}/api/code/workspaces/{workspace_id}/chat/stream"
        session = self._get_session(stream=True)
        with session.stream("POST", url, json=payload, headers=self._stream_headers()) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_page_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a page builder message via SSE (token-by-token output)."""
        content = _validate_message(content)
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/message"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json={"content": content}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_page_builder_workspace_automation(
        self,
        session_id: str,
        body: Dict[str, Any] | None = None,
    ) -> Generator[SSEEvent, None, None]:
        """Stream the page-builder workspace automation pipeline."""
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/workspace-automation/stream"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json=body or {}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    def stream_document_builder_message(
        self,
        session_id: str,
        content: str,
    ) -> Generator[SSEEvent, None, None]:
        """Stream a document builder message via SSE."""
        content = _validate_message(content)
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}/message"
        session = self._get_session(stream=True)
        with session.stream(
            "POST", url, json={"content": content}, headers=self._stream_headers()
        ) as response:
            raise_if_error(response)
            yield from self._parse_sse_stream(response)

    # ── Domain Agent: Conversations ──────────────────────────────────

    def list_conversations(self, domain: str) -> List[Dict[str, Any]]:
        """List all conversations for a domain."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_conversation(self, domain: str, conversation_id: str) -> Dict[str, Any]:
        """Get conversation history."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations/{conversation_id}"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def create_conversation(self, domain: str) -> Dict[str, Any]:
        """Create a new conversation for a domain."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations"
        session = self._get_session()
        resp = session.post(url, json={}, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def delete_conversation(self, domain: str, conversation_id: str) -> None:
        """Delete a conversation."""
        domain = _validate_domain(domain)
        url = f"{self._base_url}/api/domain-agents/{domain}/conversations/{conversation_id}"
        session = self._get_session()
        resp = session.delete(url, headers=self._headers())
        raise_if_error(resp)

    # ── Document Builder Sessions ────────────────────────────────────

    def create_document_session(
        self,
        *,
        document_type: str = "general",
        document_title: str = "Untitled Document",
    ) -> Dict[str, Any]:
        """Create a new document builder session."""
        url = f"{self._base_url}/api/document-builder/sessions"
        payload = {"documentType": document_type, "documentTitle": document_title}
        session = self._get_session()
        resp = session.post(url, json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_document_sessions(self) -> List[Dict[str, Any]]:
        """List document builder sessions."""
        url = f"{self._base_url}/api/document-builder/sessions"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_document_session(self, session_id: str) -> Dict[str, Any]:
        """Get a document builder session."""
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_document_schemas(self, session_id: str) -> Dict[str, Any]:
        """Get the document schemas for a session."""
        url = f"{self._base_url}/api/document-builder/sessions/{session_id}/schemas"
        session = self._get_session()
        resp = session.get(url, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Document Intelligence shortcuts ──────────────────────────────

    def search_documents(
        self,
        query: str,
        *,
        folder_path: str | None = None,
        top_k: int = 10,
    ) -> DispatchResult:
        """Search across all documents using semantic search."""
        inputs: Dict[str, Any] = {"message": query, "top_k": top_k}
        if folder_path:
            inputs["folder_path_prefix"] = folder_path
        return self.dispatch(
            "document_intelligence",
            action="search_documents",
            message=query,
            inputs=inputs,
        )

    def grep_documents(
        self,
        pattern: str,
        *,
        regex: bool = True,
        case_sensitive: bool = False,
        folder_path: str | None = None,
        top_k: int = 20,
    ) -> DispatchResult:
        """Grep across document content using pattern matching."""
        inputs: Dict[str, Any] = {
            "pattern": pattern,
            "regex": regex,
            "case_sensitive": case_sensitive,
            "top_k": top_k,
        }
        if folder_path:
            inputs["folder_path"] = folder_path
        return self.dispatch(
            "document_intelligence",
            action="grep_content",
            message=pattern,
            inputs=inputs,
        )

    def list_folder(
        self,
        folder_path: str = "",
        *,
        source_system: str | None = None,
        max_items: int = 100,
    ) -> DispatchResult:
        """List documents in a folder."""
        inputs: Dict[str, Any] = {"folder_path": folder_path, "max_items": max_items}
        if source_system:
            inputs["source_system"] = source_system
        return self.dispatch(
            "document_intelligence",
            action="list_folder",
            inputs=inputs,
        )

    def create_document(
        self,
        title: str,
        body: str,
        *,
        format: str = "docx",
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new document."""
        return self.dispatch(
            "document_intelligence",
            action="write_document",
            message=f"Create document: {title}",
            inputs={
                "title": title,
                "body": body,
                "format": format,
                "target_suite": target_suite,
            },
        )

    def create_spreadsheet(
        self,
        title: str,
        body: str = "",
        *,
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new spreadsheet."""
        return self.dispatch(
            "document_intelligence",
            action="create_spreadsheet",
            message=f"Create spreadsheet: {title}",
            inputs={"title": title, "body": body, "target_suite": target_suite},
        )

    def create_slide_deck(
        self,
        title: str,
        body: str = "",
        *,
        target_suite: str = "internal_library",
    ) -> DispatchResult:
        """Create a new slide deck."""
        return self.dispatch(
            "document_intelligence",
            action="create_slide_deck",
            message=f"Create slides: {title}",
            inputs={"title": title, "body": body, "target_suite": target_suite},
        )

    # ── Page Builder ──────────────────────────────────────────────────

    def create_page_builder_session(self, brand_name: str = "", initial_prompt: str = "") -> Dict[str, Any]:
        """Create a new page builder session."""
        payload: Dict[str, Any] = {}
        if brand_name:
            payload["brandName"] = brand_name
        if initial_prompt:
            payload["initialPrompt"] = initial_prompt
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/page-builder/sessions", json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_page_builder_sessions(self) -> List[Dict[str, Any]]:
        """List page builder sessions."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/page-builder/sessions", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def page_builder_send_message(self, session_id: str, content: str) -> Dict[str, Any]:
        """Send a message to a page builder session (non-streaming)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/message",
            json={"content": content},
            headers=self._headers({"Accept": "application/json"}),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_get_schemas(self, session_id: str) -> Dict[str, Any]:
        """Get the current page schemas for a session."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/page-builder/sessions/{session_id}/schemas", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def page_builder_deploy(self, session_id: str, page_key: str = "") -> Dict[str, Any]:
        """Deploy a page builder session."""
        url = f"{self._base_url}/api/page-builder/sessions/{session_id}/deploy"
        if page_key:
            url += f"/{page_key}"
        session = self._get_session()
        resp = session.post(url, json={}, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def page_builder_get_preview(self, session_id: str) -> Dict[str, Any]:
        """Get the preview URL for a page builder session."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/page-builder/sessions/{session_id}/preview", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspaces ──────────────────────────────────────────────

    def create_code_workspace(
        self,
        *,
        source: str | None = None,
        repo_connection_id: str | None = None,
        branch: str | None = None,
        depth: int | None = None,
        label: str | None = None,
        metadata: Dict[str, Any] | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Create a code workspace."""
        payload: Dict[str, Any] = {}
        if source:
            payload["source"] = source
        if repo_connection_id:
            payload["repoConnectionId"] = repo_connection_id
        if branch:
            payload["branch"] = branch
        if depth is not None:
            payload["depth"] = depth
        if label:
            payload["label"] = label
        if metadata:
            payload["metadata"] = dict(metadata)
        if company_id:
            payload["companyId"] = company_id

        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_code_workspaces(self) -> List[Dict[str, Any]]:
        """List code workspaces."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/code/workspaces", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def code_workspace_chat(self, workspace_id: str, message: str, **kwargs) -> Dict[str, Any]:
        """Send a chat message to a code workspace."""
        payload = {
            "message": message,
            "workspace_id": workspace_id,
            **_normalize_code_chat_kwargs(kwargs),
        }
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat",
            json=payload, headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def get_code_workspace_active_run(self, workspace_id: str) -> Dict[str, Any] | None:
        """Get the currently active run for a code workspace, if one exists."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/active",
            headers=self._headers(),
        )
        if resp.status_code == 204:
            return None
        raise_if_error(resp)
        return resp.json()

    def get_code_workspace_run(self, workspace_id: str, run_id: str) -> Dict[str, Any]:
        """Get a specific code workspace run."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Backbone Agent ───────────────────────────────────────────────

    def backbone_execute(self, objective: str, *, inputs: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Execute a task through the backbone agent (research, analysis, code generation)."""
        payload: Dict[str, Any] = {"objective": objective}
        if inputs:
            payload["inputs"] = inputs
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/v1/backbone/execute",
            json=payload, headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Artifacts ────────────────────────────────────────────────────

    def list_artifacts(self, **filters) -> List[Dict[str, Any]]:
        """List artifacts (charts, reports, analyses, etc.)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/artifacts",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("artifacts", []))

    def get_artifact(self, artifact_id: str) -> Dict[str, Any]:
        """Get a specific artifact by ID."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/artifacts/{artifact_id}", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def register_external_artifact(
        self,
        *,
        type: str,
        title: str = "",
        summary: str = "",
        uri: str = "",
        content: str = "",
        project_id: Optional[str] = None,
        source_agent: str = "external_agent",
        metadata: Optional[Dict[str, Any]] = None,
        attach_workspace: bool = False,
    ) -> Dict[str, Any]:
        """Register an external artifact (codebase/document/slide deck/spreadsheet/url) created
        by a general agent so Lightbulb domain agents can discover and work on it.

        Either ``uri`` or ``content`` must be provided. For a ``codebase`` artifact with a repo
        ``uri``, set ``attach_workspace=True`` to also clone it into a Code Workspace so Lightbulb
        agents can work on it.
        """
        payload: Dict[str, Any] = {
            "type": type,
            "title": title,
            "summary": summary,
            "uri": uri,
            "content": content,
            "source_agent": source_agent,
        }
        if project_id:
            payload["project_id"] = project_id
        if metadata:
            payload["metadata"] = metadata
        if attach_workspace:
            payload["attach_workspace"] = True
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/artifacts/external/register",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Workflows ────────────────────────────────────────────────────

    def list_workflows(self) -> List[Dict[str, Any]]:
        """List workflow definitions."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/workflows", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Get a workflow by ID."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/workflows/{workflow_id}", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def trigger_workflow(self, workflow_type: str, objective: str, *, inputs: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Trigger a workflow execution."""
        payload: Dict[str, Any] = {"workflowType": workflow_type, "objective": objective}
        if inputs:
            payload["inputs"] = inputs
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/workflows/trigger", json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── HITL / Approvals ───────────────────────────────────────────────

    def list_pending_approvals(self) -> List[Dict[str, Any]]:
        """List pending HITL approval tasks waiting for your decision."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/workflows/approvals/pending", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_approval(self, task_id: str) -> Dict[str, Any]:
        """Get full details of an approval task."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/workflows/approvals/{task_id}", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def approve_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        """Approve a pending HITL task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/approve",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_task(self, task_id: str, *, comments: str = "") -> Dict[str, Any]:
        """Reject a pending HITL task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/reject",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── RAG / Knowledge Base ─────────────────────────────────────────

    def rag_query(self, question: str, *, top_k: int = 5, document_ids: List[str] | None = None) -> Dict[str, Any]:
        """Query the RAG knowledge base directly."""
        payload: Dict[str, Any] = {"question": question, "top_k": top_k}
        if document_ids:
            payload["document_ids"] = document_ids
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/rag/query", json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def rag_upload_document(self, filename: str, content: str, **metadata) -> Dict[str, Any]:
        """Upload a document to the RAG library."""
        payload = {"filename": filename, "content": content, **metadata}
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/rag/library/documents", json=payload, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Connectors ───────────────────────────────────────────────────

    def list_connectors(self) -> List[Dict[str, Any]]:
        """List available connectors and their status."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/tools/connectors", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def invoke_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke a platform tool by name (e.g. connector tools, utility tools).

        Posts to ``POST /api/tools/invoke`` with ``toolName`` + ``inputs`` (plus
        tenant/company scope from auth so the platform's RBAC + HITL machinery
        can resolve the binding without re-reading the JWT for every field).
        """
        session = self._get_session()
        payload: Dict[str, Any] = {"toolName": tool_name, "inputs": arguments}
        tenant_id = getattr(self._auth, "tenant_id", None)
        if tenant_id:
            payload["tenantId"] = tenant_id
        if self._active_company_id:
            payload["companyId"] = self._active_company_id
        _guard_request_body(payload, endpoint=f"tools/invoke:{tool_name}")
        resp = session.post(
            f"{self._base_url}/api/tools/invoke",
            json=payload,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── CRM ──────────────────────────────────────────────────────────

    def list_contacts(self, **filters) -> List[Dict[str, Any]]:
        """List CRM contacts."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/crm/contacts",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def list_deals(self, **filters) -> List[Dict[str, Any]]:
        """List CRM deals/opportunities."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/crm/deals",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    # ── Notifications ────────────────────────────────────────────────

    def list_notifications(self, **filters) -> List[Dict[str, Any]]:
        """List notifications (HITL decisions, workflow alerts, system messages)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/notifications",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("notifications", []))

    # ── Memory ───────────────────────────────────────────────────────

    def memory_store(self, key: str, value: str, *, namespace: str = "default") -> Dict[str, Any]:
        """Store a value in agent memory."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory",
            json={"key": key, "value": value, "namespace": namespace},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_recall(self, key: str, *, namespace: str = "default") -> Dict[str, Any]:
        """Recall a value from agent memory."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/{namespace}/{key}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_search(self, query: str, *, namespace: str = "default", top_k: int = 5) -> List[Dict[str, Any]]:
        """Search agent memory semantically."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/memory/search",
            json={"query": query, "namespace": namespace, "top_k": top_k},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    # ── Domain Agent Contracts ───────────────────────────────────────

    def list_domains(self) -> List[Dict[str, Any]]:
        """List all available domain agents and their capabilities."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/domain-agents/contracts", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_domain_actions(self, domain: str) -> List[Dict[str, Any]]:
        """List available actions for a specific domain agent."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/domain-agents/{domain}/actions", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Voice / Phone Executions ────────────────────────────────────

    def list_voice_executions(self, **filters: Any) -> List[Dict[str, Any]]:
        """List voice agent executions (live and historical phone calls)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("executions", []))

    def get_voice_execution(self, execution_id: str) -> Dict[str, Any]:
        """Get a voice execution detail (transcripts, status, agent decisions)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions/{execution_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_voice_pending_approvals(self) -> List[Dict[str, Any]]:
        """List in-call HITL approvals waiting for caller-side decision."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/voice/executions/approvals/pending",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def approve_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        *,
        comments: str = "",
    ) -> Dict[str, Any]:
        """Approve a pending in-call action (e.g. transfer, wire info, commit booking)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/approve",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        *,
        comments: str = "",
    ) -> Dict[str, Any]:
        """Reject a pending in-call action."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/reject",
            json={"comments": comments},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def modify_voice_action(
        self,
        execution_id: str,
        approval_task_id: str,
        modifications: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Approve a voice action with modifications to the proposed payload."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/voice/executions/{execution_id}/approvals/{approval_task_id}/modify",
            json={"modifications": modifications},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── HR Live Connectors (BambooHR / Greenhouse / Monday) ─────────

    def hr_live_whos_out(self, **filters: Any) -> Dict[str, Any]:
        """BambooHR who's-out roster (current and upcoming time-off)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/whos-out",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_leave_balance(self, bamboo_employee_id: str) -> Dict[str, Any]:
        """BambooHR leave balance for an employee."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/leave/balances/{bamboo_employee_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_monday_onboarding_board(self, checklist_id: str) -> Dict[str, Any]:
        """Monday.com board view for an HR onboarding checklist."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/onboarding/{checklist_id}/monday-board",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_cases(self, **filters: Any) -> Dict[str, Any]:
        """HR case board items from Monday.com."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/cases/monday-items",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_recruiting_jobs(self, **filters: Any) -> Dict[str, Any]:
        """Greenhouse job listings."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/recruiting/jobs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_recruiting_applications(self, **filters: Any) -> Dict[str, Any]:
        """Greenhouse applications."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/hr/live/recruiting/applications",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_advance_application(self, application_id: str, *, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Advance a Greenhouse candidate to the next stage (HITL-gated)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/hr/live/recruiting/applications/{application_id}/advance",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_reject_application(self, application_id: str, *, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Reject a Greenhouse application (HITL-gated)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/hr/live/recruiting/applications/{application_id}/reject",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def hr_live_health(self) -> Dict[str, Any]:
        """Health check for HR connector tokens (BambooHR / Greenhouse / Monday)."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/hr/live/health", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Collaboration & Sharing ────────────────────

    def code_workspace_collaboration(self, workspace_id: str) -> Dict[str, Any]:
        """Get collaboration info (members, share links, pending requests)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaboration",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_add_collaborator(
        self,
        workspace_id: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
        role: str = "viewer",
    ) -> Dict[str, Any]:
        """Add a collaborator to a code workspace (role: viewer | editor | admin)."""
        body: Dict[str, Any] = {"role": role}
        if email:
            body["email"] = email
        if user_id:
            body["userId"] = user_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_update_collaborator(self, workspace_id: str, collaborator_id: str, *, role: str) -> Dict[str, Any]:
        """Change a collaborator's role."""
        session = self._get_session()
        resp = session.put(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators/{collaborator_id}",
            json={"role": role},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_remove_collaborator(self, workspace_id: str, collaborator_id: str) -> None:
        """Revoke a collaborator's access."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/collaborators/{collaborator_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    def code_workspace_create_share_link(self, workspace_id: str, *, role: str = "viewer", expires_in_seconds: int | None = None) -> Dict[str, Any]:
        """Create a share-link token granting access to the workspace."""
        body: Dict[str, Any] = {"role": role}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = int(expires_in_seconds)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/share-links",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_revoke_share_link(self, workspace_id: str, link_id: str) -> None:
        """Revoke a share link."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/share-links/{link_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    def code_workspace_redeem_share_link(self, token: str) -> Dict[str, Any]:
        """Redeem a workspace share-link token to gain access."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/share-links/{token}/redeem",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_approve_access_request(self, workspace_id: str, request_id: str) -> Dict[str, Any]:
        """Approve a pending workspace access request."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/access-requests/{request_id}/approve",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_deny_access_request(self, workspace_id: str, request_id: str) -> Dict[str, Any]:
        """Deny a pending workspace access request."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/access-requests/{request_id}/deny",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_add_note(self, workspace_id: str, content: str) -> Dict[str, Any]:
        """Append a workspace note (visible to collaborators)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/notes",
            json={"content": content},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Runs / Reviews / Proposals / GitHub ────────

    def list_code_workspace_runs(self, workspace_id: str, **filters: Any) -> List[Dict[str, Any]]:
        """List historical coding runs for a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("runs", []))

    def code_workspace_runs_insights(self, workspace_id: str) -> Dict[str, Any]:
        """Aggregate run-quality insights for a workspace (cost, latency, success rate)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/insights",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_telemetry(self, workspace_id: str, **filters: Any) -> Dict[str, Any]:
        """Raw telemetry rows for a workspace's runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/telemetry",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_review(
        self,
        workspace_id: str,
        run_id: str,
        *,
        verdict: str,
        feedback: str = "",
    ) -> Dict[str, Any]:
        """Submit a human review verdict (accept | reject | request_changes) for a run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}/review",
            json={"verdict": verdict, "feedback": feedback},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_run_review_apply(self, workspace_id: str, run_id: str) -> Dict[str, Any]:
        """Apply review-suggested changes to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/{run_id}/review/apply",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_code_workspace_proposals(self, workspace_id: str) -> List[Dict[str, Any]]:
        """List code-change proposals submitted to the workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def submit_code_workspace_proposal(self, workspace_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a code-change proposal (diff + summary)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def apply_code_workspace_proposal(self, workspace_id: str, proposal_id: str) -> Dict[str, Any]:
        """Apply a previously-submitted proposal to the workspace files."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals/{proposal_id}/apply",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def reject_code_workspace_proposal(self, workspace_id: str, proposal_id: str, *, reason: str = "") -> Dict[str, Any]:
        """Reject a proposal."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/proposals/{proposal_id}/reject",
            json={"reason": reason},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_create_pull_request(self, workspace_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Open a GitHub pull request from the workspace branch."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/pull-request",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_link_repository(self, workspace_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Link a GitHub repository to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/repository",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def cancel_code_workspace_run(self, workspace_id: str, run_id: str) -> Dict[str, Any]:
        """Cancel an in-flight coding run."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/chat/{run_id}/cancel",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Tools (file / shell / git) ─────────────────

    def code_workspace_invoke_tool(
        self,
        workspace_id: str,
        tool_key: str,
        arguments: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Invoke a workspace-scoped tool (read/write files, run commands, git ops).

        Tool keys are registered in the workspace's runtime catalog. Common keys:
            - ``files.read`` — read a file by path
            - ``files.write`` — write a file
            - ``files.list`` — list directory contents
            - ``shell.run`` — execute a shell command
            - ``git.status`` — show git working-tree state
            - ``git.diff`` — produce a diff
            - ``git.commit`` — create a commit
        Use :meth:`code_workspace_runtime_catalog` to discover what's available
        for a specific workspace.
        """
        from lightbulb.validators import validate_tool_key
        workspace_id = _validate_id(workspace_id, "workspace_id")
        tool_key = validate_tool_key(tool_key)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/tools/{tool_key}",
            json=arguments or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_runtime_catalog(self, workspace_id: str) -> Dict[str, Any]:
        """Read the workspace's runtime tool catalog (which tool keys are available)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/catalog",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_register_runtime_tools(
        self,
        workspace_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Register or update workspace runtime tools."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/catalog",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Preview lifecycle ──────────────────────────

    def code_workspace_preview_start(
        self,
        workspace_id: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Start the workspace preview server (renders the in-progress code)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/start",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview(self, workspace_id: str) -> Dict[str, Any]:
        """Get the current preview state (URL, status, last build)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview_stop(self, workspace_id: str) -> Dict[str, Any]:
        """Stop the workspace preview server."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/stop",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_preview_proxy(
        self,
        workspace_id: str,
        path: str = "",
        *,
        method: str = "GET",
        body: Any = None,
        headers: Dict[str, str] | None = None,
    ) -> httpx.Response:
        """Proxy an HTTP call through the workspace preview.

        Returns the raw httpx.Response so callers can inspect status/headers/body.
        Use this for headless e2e tests against in-progress code.

        Security: caller-supplied ``headers`` are merged BEFORE auth headers, so
        a caller cannot overwrite ``Authorization`` / ``X-Tenant-Id`` /
        ``X-Internal-API-Key``. ``method`` and ``path`` are validated.
        """
        from lightbulb.validators import validate_method, validate_relative_path
        workspace_id = _validate_id(workspace_id, "workspace_id")
        method = validate_method(method)
        path = validate_relative_path(path)
        url = f"{self._base_url}/api/code/workspaces/{workspace_id}/preview/proxy"
        if path:
            url = f"{url}/{path}"
        session = self._get_session()
        # Build caller headers first, then layer auth on top so auth wins.
        merged_headers: Dict[str, str] = dict(headers or {})
        # Strip any caller-supplied auth/scope headers explicitly.
        for blocked in ("authorization", "x-internal-api-key", "x-tenant-id",
                        "x-company-id", "x-user-id", "x-xsrf-token"):
            merged_headers.pop(blocked, None)
            merged_headers.pop(blocked.title(), None)
        merged_headers.update(self._headers())
        resp = session.request(method, url, json=body, headers=merged_headers)
        return resp

    # ── Code Workspace: Evals & policy replay ──────────────────────

    def code_workspace_evals(self, workspace_id: str) -> Dict[str, Any]:
        """Get accumulated eval rollups for a workspace's runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/evals",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_policy_replay(self, workspace_id: str, **filters: Any) -> Dict[str, Any]:
        """Replay a policy decision over historical runs (debug helper)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runs/policy-replay",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_clear_policy(self, workspace_id: str, request_family: str) -> Dict[str, Any]:
        """Clear cached policy decisions for a request family."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/policy/{request_family}/clear",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def code_workspace_promote_policy(self, workspace_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Promote workspace-scoped policy to a higher scope (company/tenant)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/policy/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Claude SDK runtime sessions ─────────────────

    def list_code_workspace_claude_sessions(self, workspace_id: str) -> List[Dict[str, Any]]:
        """List Claude SDK sessions associated with a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("sessions", []))

    def get_code_workspace_claude_session(self, workspace_id: str, session_id: str) -> Dict[str, Any]:
        """Get a single Claude SDK session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions/{session_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def claude_session_action(
        self,
        workspace_id: str,
        session_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Perform an action on a Claude SDK session.

        action: one of rename, tag, fork, delete, interrupt, mcp/reconnect,
                mcp/toggle, rewind, tasks/stop, compact
        """
        from lightbulb.validators import validate_choice, CLAUDE_SESSION_ACTIONS
        workspace_id = _validate_id(workspace_id, "workspace_id")
        session_id = _validate_id(session_id, "session_id")
        action = validate_choice(action.strip().strip("/"), CLAUDE_SESSION_ACTIONS, "action")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/claude/sessions/{session_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Code Workspace: Codex runtime threads ───────────────────────

    def list_code_workspace_codex_threads(self, workspace_id: str, **filters: Any) -> List[Dict[str, Any]]:
        """List Codex runtime threads attached to a workspace."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("threads", []))

    def get_code_workspace_codex_thread(self, workspace_id: str, thread_id: str) -> Dict[str, Any]:
        """Get a Codex thread (turns, status, metadata)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def codex_thread_action(
        self,
        workspace_id: str,
        thread_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Perform a thread-level action (rename | archive | unarchive | compact | rollback)."""
        from lightbulb.validators import validate_choice, CODEX_THREAD_ACTIONS
        workspace_id = _validate_id(workspace_id, "workspace_id")
        thread_id = _validate_id(thread_id, "thread_id")
        action = validate_choice(action.strip().strip("/"), CODEX_THREAD_ACTIONS, "action")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def codex_turn_action(
        self,
        workspace_id: str,
        thread_id: str,
        turn_id: str,
        action: str,
        body: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Steer or interrupt a specific Codex turn (action: steer | interrupt)."""
        from lightbulb.validators import validate_choice, CODEX_TURN_ACTIONS
        workspace_id = _validate_id(workspace_id, "workspace_id")
        thread_id = _validate_id(thread_id, "thread_id")
        turn_id = _validate_id(turn_id, "turn_id")
        action = validate_choice(action.strip().strip("/"), CODEX_TURN_ACTIONS, "action")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/code/workspaces/{workspace_id}/runtime/codex/threads/{thread_id}/turns/{turn_id}/{action}",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── AutoCompany / AOC ───────────────────────────────────────────

    def list_aoc_runs(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany cognitive-loop runs."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/runs",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("runs", []))

    def create_aoc_run(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new AutoCompany run."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/aoc/runs", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_aoc_run(self, run_id: str) -> Dict[str, Any]:
        """Get an AutoCompany run detail."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/aoc/runs/{run_id}", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def stop_aoc_run(self, run_id: str) -> Dict[str, Any]:
        """Stop an in-flight AutoCompany cognitive-loop run."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/aoc/runs/{run_id}/stop", json={}, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def validate_aoc_run_config(self, run_id: str) -> Dict[str, Any]:
        """Validate an AutoCompany run's configuration."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/runs/{run_id}/validate-config",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_tasks(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany tasks."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/tasks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("tasks", []))

    def create_aoc_task(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create an AutoCompany task."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/aoc/tasks", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def get_aoc_task(self, task_id: str) -> Dict[str, Any]:
        """Get an AutoCompany task detail."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/aoc/tasks/{task_id}", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def list_aoc_task_events(self, task_id: str) -> List[Dict[str, Any]]:
        """List events recorded against an AutoCompany task."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/tasks/{task_id}/events",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("events", []))

    def post_aoc_task_event(self, task_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Post a new event onto an AutoCompany task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/tasks/{task_id}/events",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_decisions(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany decisions awaiting or post-resolution."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/decisions",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("decisions", []))

    def get_aoc_decision(self, decision_id: str) -> Dict[str, Any]:
        """Get a specific AutoCompany decision."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/decisions/{decision_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def list_aoc_ticks(self, **filters: Any) -> List[Dict[str, Any]]:
        """List AutoCompany cognitive-loop ticks."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/ticks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("ticks", []))

    def get_aoc_tick(self, tick_id: str) -> Dict[str, Any]:
        """Get a single AutoCompany tick."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/aoc/ticks/{tick_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def compute_aoc_tick(self, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Run a one-shot AutoCompany tick computation."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/ticks/compute",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def apply_aoc_tick(self, tick_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Apply a previously-computed AutoCompany tick (committing its decisions)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/aoc/ticks/{tick_id}/apply",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Memory Graph (beyond key/value) ─────────────────────────────

    def memory_list_entries(self, **filters: Any) -> List[Dict[str, Any]]:
        """List memory entries (structured records)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/entries",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("entries", []))

    def memory_get_entry(self, entry_id: str) -> Dict[str, Any]:
        """Get a specific memory entry."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/entries/{entry_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_create_entry(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a structured memory entry."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/entries", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_query(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Run a structured memory query (filters, time-windows, semantic)."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/query", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_projection_soul(self) -> Dict[str, Any]:
        """Identity / personality projection of the agent."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/memory/projection/soul", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_projection_memory(self) -> Dict[str, Any]:
        """Memory-structure projection of the agent."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/memory/projection/memory", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_status(self) -> Dict[str, Any]:
        """Health / capacity status of the memory subsystem."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/memory/status", headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_graph(self, **filters: Any) -> Dict[str, Any]:
        """Full memory graph (or filtered subgraph)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/graph",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_graph_node(self, node_id: str) -> Dict[str, Any]:
        """Get a single node from the memory graph."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/graph/node",
            params={"id": node_id},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_identity(self) -> List[Dict[str, Any]]:
        """List identity records in the memory graph."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/memory/identity", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_create_identity(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create an identity record."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/identity", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_get_identity(self, doc_id: str) -> Dict[str, Any]:
        """Get an identity record by doc id."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/identity/{doc_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def memory_list_events(self, **filters: Any) -> List[Dict[str, Any]]:
        """List memory events (timeline of state changes)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/events",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("events", []))

    def memory_record_event(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Record a memory event."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/events", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_list_links(self, **filters: Any) -> List[Dict[str, Any]]:
        """List entity links in the memory graph."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/memory/links",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_create_link(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a memory link between two entities."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/links", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    def memory_list_skills(self) -> List[Dict[str, Any]]:
        """List skills/capabilities recorded in memory."""
        session = self._get_session()
        resp = session.get(f"{self._base_url}/api/memory/skills", headers=self._headers())
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def memory_add_skill(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new skill / capability."""
        session = self._get_session()
        resp = session.post(f"{self._base_url}/api/memory/skills", json=body, headers=self._headers())
        raise_if_error(resp)
        return resp.json()

    # ── CRM Tasks ───────────────────────────────────────────────────

    def list_crm_tasks(self, tenant_id: str | None = None, **filters: Any) -> List[Dict[str, Any]]:
        """List CRM tasks scoped to a tenant (defaults to authed tenant)."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("tasks", []))

    def get_crm_task(self, task_id: str, tenant_id: str | None = None) -> Dict[str, Any]:
        """Get a single CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def create_crm_task(self, body: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
        """Create a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def update_crm_task(self, task_id: str, body: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
        """Update a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.put(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def delete_crm_task(self, task_id: str, tenant_id: str | None = None) -> None:
        """Delete a CRM task."""
        tid = tenant_id or self._auth.tenant_id
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/tenants/{tid}/crm/tasks/{task_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)

    # ── Approval Auto-Accept Preferences ───────────────────────────

    def list_approval_preferences(self) -> List[Dict[str, Any]]:
        """List the user's HITL auto-accept rules."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workflows/approval-preferences",
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    def create_approval_auto_accept(self, task_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Create an auto-accept rule keyed off the shape of an existing approval task."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approvals/{task_id}/auto-accept",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def delete_approval_preference(self, preference_id: str) -> Dict[str, Any]:
        """Remove an auto-accept rule."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approval-preferences/{preference_id}/delete",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def set_approval_preference_state(self, preference_id: str, *, enabled: bool) -> Dict[str, Any]:
        """Enable or disable an auto-accept rule."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/workflows/approval-preferences/{preference_id}/state",
            json={"enabled": bool(enabled)},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Notifications: read state ──────────────────────────────────

    def mark_notification_read(self, notification_id: str) -> Dict[str, Any]:
        """Mark a single notification as read."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/notifications/{notification_id}/read",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def mark_all_notifications_read(self) -> Dict[str, Any]:
        """Mark all notifications as read."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/notifications/read-all",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Domain Workspaces ──────────────────────────────────────────

    def workspace_bundle(self, domain: str) -> Dict[str, Any]:
        """Get a domain workspace data bundle (state, surfaces, recent runs)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/bundle",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_trace(self, domain: str, trace_id: str) -> Dict[str, Any]:
        """Get a workspace trace (full agent execution log)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/traces/{trace_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_conversation(self, domain: str, conversation_id: str) -> Dict[str, Any]:
        """Get a domain workspace conversation."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/conversations/{conversation_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def workspace_surface(self, domain: str, surface: str, **filters: Any) -> Dict[str, Any]:
        """Read a domain workspace surface (e.g. internal_suite, live connector)."""
        domain = _validate_domain(domain)
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/{domain}/surfaces/{surface}",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def it_ops_live_connector(self, connector: str, **filters: Any) -> Dict[str, Any]:
        """Pass-through to a live IT-Ops connector (jira | slack | github | notion)."""
        connector = str(connector).strip().lower()
        if connector not in {"jira", "slack", "github", "notion"}:
            raise ValueError("connector must be one of jira | slack | github | notion")
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/it_ops/connectors/{connector}/live",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def it_ops_mcp_manifest(self) -> Dict[str, Any]:
        """Get the IT-Ops workspace MCP manifest."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/workspaces/it_ops/mcp/manifest",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Page Builder: automation, SEO, capabilities ────────────────

    def page_builder_workspace_automation(self, session_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Run the page-builder workspace automation (auto-wire pages → agents → backend)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/workspace-automation",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_promote_section(self, session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Promote a section artifact to the install bundle."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/artifacts/sections/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_promote_install_bundle(self, session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Promote an install bundle to the workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/artifacts/install-bundles/promote",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_install_artifact(self, session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Install a component artifact into the page session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/install-artifact",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_capabilities(self, session_id: str) -> Dict[str, Any]:
        """List page capabilities (forms, search, auth, etc.)."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/capabilities",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_save_capability(self, session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Save a capability to the page session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/capabilities",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_save_backend_contract(self, session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Define a backend contract for a page (data shape + agent binding)."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/backend-contracts",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def page_builder_unpublish(self, session_id: str) -> Dict[str, Any]:
        """Unpublish a deployed page builder session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/page-builder/sessions/{session_id}/unpublish",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Document Builder: collaboration, share-links, messages ─────

    def document_builder_collaboration(self, session_id: str) -> Dict[str, Any]:
        """Collaboration info for a document builder session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/collaboration",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_add_collaborator(
        self,
        session_id: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
        role: str = "viewer",
    ) -> Dict[str, Any]:
        """Add a collaborator to a document builder session."""
        body: Dict[str, Any] = {"role": role}
        if email:
            body["email"] = email
        if user_id:
            body["userId"] = user_id
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/collaborators",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_create_share_link(self, session_id: str, *, role: str = "viewer", expires_in_seconds: int | None = None) -> Dict[str, Any]:
        """Create a share-link token for a document builder session."""
        body: Dict[str, Any] = {"role": role}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = int(expires_in_seconds)
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/share-links",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_redeem_share_link(self, session_id: str, token: str) -> Dict[str, Any]:
        """Redeem a document builder share link."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/share-links/redeem",
            json={"token": token},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_get_messages(self, session_id: str, **filters: Any) -> List[Dict[str, Any]]:
        """Get the message history for a document builder session."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/messages",
            params={k: v for k, v in filters.items() if v is not None},
            headers=self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", data.get("messages", []))

    def document_builder_save(self, session_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Save a document builder session's current state."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/save",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Marketing Content Connector Setup ──────────────────────────

    def marketing_content_setup(self) -> Dict[str, Any]:
        """Get the marketing content connector setup state."""
        session = self._get_session()
        resp = session.get(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_content_configure_provider(self, provider: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Configure a marketing-content provider (e.g. ga4, segment, plausible)."""
        provider = _validate_id(provider, "provider")
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/providers/{provider}",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_add_website_analytics_site(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Register a website with the analytics setup."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites",
            json=body,
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_select_website_analytics_site(self, site_id: str) -> Dict[str, Any]:
        """Activate a registered analytics site."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites/{site_id}/select",
            json={},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_remove_website_analytics_site(self, site_id: str) -> Dict[str, Any]:
        """Remove a registered analytics site."""
        session = self._get_session()
        resp = session.delete(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/sites/{site_id}",
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json() if resp.content else {"removed": site_id}

    def marketing_verify_website_analytics(self, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Verify the website analytics setup is wired correctly."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/verify",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def marketing_install_website_analytics(self, workspace_id: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Install website analytics into a code workspace."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/tools/connectors/marketing/content-setup/website-analytics/workspaces/{workspace_id}/install",
            json=body or {},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    def document_builder_add_note(self, session_id: str, content: str) -> Dict[str, Any]:
        """Add a note to a document builder session."""
        session = self._get_session()
        resp = session.post(
            f"{self._base_url}/api/document-builder/sessions/{session_id}/notes",
            json={"content": content},
            headers=self._headers(),
        )
        raise_if_error(resp)
        return resp.json()
