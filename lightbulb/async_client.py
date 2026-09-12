"""Async Lightbulb platform client with complete sync-SDK parity.

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

import asyncio
import inspect
import json
import logging
import time
from typing import Any, AsyncGenerator, Callable, Dict, List, Mapping, Sequence
from urllib.parse import urlparse

import httpx

from lightbulb.native_coding import AsyncNativeCodingClient
from lightbulb._version import __version__
from lightbulb.agent_ops import (
    AgentOpsProtocolError,
    build_training_pair_request,
    is_training_pair_admission_unavailable,
    parse_training_pair_admission_unavailable,
    parse_training_pair_input_custody,
    parse_training_pair_preflight,
    parse_training_pair_readiness,
    parse_training_pair_status,
    response_json as agent_ops_response_json,
    validate_training_pair_idempotency_key,
)
from lightbulb.auth import ApiKeyAuth, AuthStrategy, JwtAuth
from lightbulb.errors import raise_if_error
from lightbulb.project_creation import (
    PROJECT_PREFLIGHT_MAX_EVENTS,
    ProjectCreationDraft,
    ProjectCreationPreflightError,
    ProjectCreationPreflightReceipt,
    build_project_creation_preflight_request,
    build_project_creation_preflight_refinement_request,
    inspect_project_game_campaign as build_project_game_campaign,
    inspect_project_creation_world_ready as build_project_creation_world_ready,
    normalize_project_coding_harness,
    normalize_project_play_style,
    normalize_project_uuid,
    project_creation_preflight_receipt_from_events,
    project_creation_preflight_refinement_receipt_from_events,
)
from lightbulb.project_feedback import (
    ProjectPreflightSemanticFeedbackReceipt,
    SemanticFeedbackValue,
    bind_project_preflight_feedback_receipt,
    build_project_preflight_feedback_request,
)
from lightbulb.project_missions import (
    build_project_mission_action_binding,
    build_project_mission_run_start,
)
from lightbulb.project_learning_reviews import build_project_learning_review_request
from lightbulb.project_learning_runs import (
    build_project_learning_run_admission_request,
    build_project_learning_run_prepare_request,
)
from lightbulb.project_learning_result_evaluations import (
    build_project_learning_result_admission_request,
)
from lightbulb.project_shadow_learner_updates import (
    PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA,
)
from lightbulb.project_game_snapshot import (
    PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES,
    normalize_project_game_snapshot_uuid,
    validate_project_game_snapshot,
)
from lightbulb.project_outcomes import build_project_business_outcome_observation
from lightbulb.project_policy import (
    build_project_policy_assignment,
    build_project_policy_evaluation_request,
)
from lightbulb.project_science import build_project_science_evidence_observation
from lightbulb.client import (
    LightbulbClient,
    SSEEvent,
    DispatchResult,
    _CONNECT_TIMEOUT,
    _DYNAMIC_WORKFLOW_ENDPOINTS,
    _MAX_MESSAGE_LENGTH,
    _MAX_RESPONSE_BYTES,
    _MAX_SSE_EVENT_BYTES,
    _MAX_SSE_LINE_BYTES,
    _READ_TIMEOUT,
    _STREAM_READ_TIMEOUT,
    _bounded_marketplace_publication_polling,
    _bounded_marketplace_publication_text,
    _bounded_marketplace_limit,
    _canonical_account_shell_document,
    _build_runtime_domain_action_payload,
    _build_marketplace_action_publication_payload,
    _build_memory_regulation_payload,
    _guard_request_body,
    _is_terminal_marketplace_action_publication,
    _local_workflow_validation,
    _marketplace_action_publication_status,
    _nullable_account_shell_revision_id,
    _normalize_marketplace_deployment_targets,
    _normalize_code_chat_kwargs,
    _governed_invoke_requested,
    _normalize_workflow_execution_identity,
    _validate_ephemeral_read_invoke_contract,
    _sanitize_inputs,
    _validate_action,
    _validate_domain,
    _validate_idempotency_key,
    _validate_marketplace_contract_digest,
    _validate_marketplace_inputs,
    _validate_marketplace_publication_idempotency_key,
    _validate_marketplace_uuid,
    _validate_message,
    _validate_runtime_action_idempotency_key,
    _validate_runtime_action_status,
    _WORKFLOW_STOP_STATES,
    _validate_id,
    _workflow_instance_state,
    _validate_workflow_trigger_filter,
    _validated_dynamic_workflow_response,
    _workflow_author_payload,
    _workflow_authoring_endpoint,
    _workflow_executable_projection_digest,
)

logger = logging.getLogger(__name__)


_ITERATION_END = object()
_CONTEXT_COMPANY_INHERIT = object()


def _next_or_end(iterator: Any) -> Any:
    try:
        return next(iterator)
    except StopIteration:
        return _ITERATION_END


class _ThreadedAsyncIterator:
    """Adapt a synchronous generator without blocking the event loop."""

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._iterator: Any = None

    def __aiter__(self) -> "_ThreadedAsyncIterator":
        return self

    async def __anext__(self) -> Any:
        if self._iterator is None:
            self._iterator = await asyncio.to_thread(self._factory)
        value = await asyncio.to_thread(_next_or_end, self._iterator)
        if value is _ITERATION_END:
            raise StopAsyncIteration
        return value

    async def aclose(self) -> None:
        close = getattr(self._iterator, "close", None)
        if callable(close):
            await asyncio.to_thread(close)


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
        self._enforce_https = enforce_https
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
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
        self._context_company_override: object | str | None = _CONTEXT_COMPANY_INHERIT
        self._sync_fallback: LightbulbClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def __aenter__(self) -> "AsyncLightbulbClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False)
        return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
        fallback = self._sync_fallback
        self._sync_fallback = None
        if fallback is not None and fallback._session is not None:
            await asyncio.to_thread(fallback._session.close)
            fallback._session = None

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
        if self._sync_fallback is not None:
            self._sync_fallback.active_company_id = value

    @property
    def context_company_id(self) -> str | None:
        """Company used only by forwarded Context Broker calls."""
        if self._context_company_override is _CONTEXT_COMPANY_INHERIT:
            return self._active_company_id
        if isinstance(self._context_company_override, str):
            return self._context_company_override
        return None

    @context_company_id.setter
    def context_company_id(self, value: str | None) -> None:
        self._context_company_override = (
            _validate_marketplace_uuid(value, "context_company_id")
            if value
            else None
        )
        if self._sync_fallback is not None:
            self._sync_fallback.context_company_id = value

    def _ensure_sync_fallback(self) -> LightbulbClient:
        if self._sync_fallback is None:
            self._sync_fallback = LightbulbClient(
                self._base_url,
                auth=self._auth,
                enforce_https=self._enforce_https,
                connect_timeout=self._connect_timeout,
                read_timeout=self._read_timeout,
            )
            self._sync_fallback.active_company_id = self._active_company_id
            if self._context_company_override is not _CONTEXT_COMPANY_INHERIT:
                self._sync_fallback.context_company_id = self.context_company_id
        return self._sync_fallback

    @classmethod
    def native_async_methods(cls) -> list[str]:
        """Public operations implemented directly with async I/O."""
        return sorted(
            name
            for name, value in inspect.getmembers(cls)
            if not name.startswith("_")
            and (inspect.iscoroutinefunction(value) or inspect.isasyncgenfunction(value))
        )

    @classmethod
    def forwarded_sync_methods(cls) -> list[str]:
        """Public sync operations supplied by the managed thread bridge."""
        native = set(cls.native_async_methods())
        return sorted(
            name
            for name, value in inspect.getmembers(LightbulbClient, inspect.isfunction)
            if not name.startswith("_") and name not in native
        )

    @classmethod
    def async_parity_report(cls) -> Dict[str, Any]:
        sync_methods = {
            name
            for name, value in inspect.getmembers(LightbulbClient, inspect.isfunction)
            if not name.startswith("_")
        }
        native = set(cls.native_async_methods()) & sync_methods
        forwarded = set(cls.forwarded_sync_methods())
        missing = sorted(sync_methods - native - forwarded)
        return {
            "schema": "lightbulb.async_client_parity.v1",
            "sync_method_count": len(sync_methods),
            "native_async_count": len(native),
            "thread_forwarded_count": len(forwarded),
            "missing_methods": missing,
            "parity_percent": round(
                ((len(sync_methods) - len(missing)) / len(sync_methods)) * 100.0,
                2,
            ) if sync_methods else 100.0,
        }

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        sync_definition = getattr(LightbulbClient, name, None)
        if not callable(sync_definition):
            raise AttributeError(f"{type(self).__name__} has no attribute {name!r}")

        if inspect.isgeneratorfunction(sync_definition):
            def forward_generator(*args: Any, **kwargs: Any) -> _ThreadedAsyncIterator:
                return _ThreadedAsyncIterator(
                    lambda: getattr(self._ensure_sync_fallback(), name)(*args, **kwargs)
                )

            forward_generator.__name__ = name
            forward_generator.__doc__ = sync_definition.__doc__
            return forward_generator

        async def forward(*args: Any, **kwargs: Any) -> Any:
            fallback = self._ensure_sync_fallback()
            try:
                return await asyncio.to_thread(getattr(fallback, name), *args, **kwargs)
            finally:
                self._auth = fallback._auth
                self._active_company_id = fallback.active_company_id

        forward.__name__ = name
        forward.__doc__ = sync_definition.__doc__
        return forward

    def _require_marketplace_company(self) -> str:
        """Require the selected company used by company-scoped marketplace calls."""
        return _validate_marketplace_uuid(self._active_company_id, "active_company_id")

    def _require_runtime_action_company(self, company_id: str | None = None) -> str:
        """Capture the explicit or selected company for one governed call."""
        return _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id" if company_id else "active_company_id",
        )

    async def _runtime_action_headers(
        self,
        project_id: str,
        company_id: str,
        extra: Dict[str, str] | None = None,
    ) -> Dict[str, str]:
        """Bind governed runtime actions to captured company/project headers."""
        project = _validate_marketplace_uuid(project_id, "project_id")
        company = _validate_marketplace_uuid(company_id, "company_id")
        headers = await self._headers({"X-Project-Id": project, **(extra or {})})
        headers["X-Company-Id"] = company
        return headers

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
        headers = self._auth.apply(base)
        if self._active_company_id:
            headers["X-Company-Id"] = str(self._active_company_id).strip()
        return headers

    async def _tenant_headers(
        self,
        extra: Dict[str, str] | None = None,
    ) -> Dict[str, str]:
        """Build normal authenticated headers without mutable company context."""
        headers = await self._headers(extra)
        for key in tuple(headers):
            if key.lower() == "x-company-id":
                headers.pop(key, None)
        return headers

    async def _stream_headers(self) -> Dict[str, str]:
        return await self._headers({"Accept": "text/event-stream"})

    async def _post_dynamic_workflow(
        self,
        operation: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Async call to the dedicated hosted dynamic-workflow authority."""
        from lightbulb.dynamic_workflow_mcp import (
            get_operation,
            validate_operation_input,
        )

        descriptor = get_operation(operation)
        endpoint = _DYNAMIC_WORKFLOW_ENDPOINTS.get(descriptor.operation)
        if endpoint is None:
            raise ValueError(f"Unsupported hosted dynamic workflow operation: {operation}")
        validated_input = validate_operation_input(descriptor.operation, payload)
        _guard_request_body(
            validated_input,
            endpoint=f"dynamic-workflows/{endpoint}",
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/dynamic-workflows/{endpoint}",
            json=validated_input,
            headers=await self._tenant_headers(),
        )
        raise_if_error(response)
        return _validated_dynamic_workflow_response(
            descriptor.operation,
            validated_input,
            response,
        )

    async def dynamic_workflow_start(
        self,
        *,
        company_ref: str,
        project_ref: str,
        objective: str,
        acceptance_criteria: Sequence[Mapping[str, Any]],
        host: str,
        expected_revision: int,
        idempotency_key: str,
        host_session_ref: str | None = None,
        acceptance_policy: str = "distinct_binding",
        workflow_spec: Mapping[str, Any] | None = None,
        inputs: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "company_ref": company_ref,
            "project_ref": project_ref,
            "objective": objective,
            "acceptance_criteria": list(acceptance_criteria),
            "host": host,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
            "acceptance_policy": acceptance_policy,
        }
        if host_session_ref is not None:
            payload["host_session_ref"] = host_session_ref
        if workflow_spec is not None:
            payload["workflow_spec"] = dict(workflow_spec)
        if inputs is not None:
            payload["inputs"] = dict(inputs)
        return await self._post_dynamic_workflow("start", payload)

    async def dynamic_workflow_attach(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host: str,
        host_session_ref: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "attach",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host": host,
                "host_session_ref": host_session_ref,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
            },
        )

    async def dynamic_workflow_status(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "status",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
            },
        )

    async def dynamic_workflow_next_assignment(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "next_assignment",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
            },
        )

    async def dynamic_workflow_submit_plan(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        required_criterion_ids: Sequence[str],
        plan: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "submit_plan",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "required_criterion_ids": list(required_criterion_ids),
                "plan": dict(plan),
            },
        )

    async def dynamic_workflow_submit_builder_result(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        outcome: str,
        summary: str,
        plan_digest: str,
        iteration: int,
        evidence_refs: Sequence[Mapping[str, Any]],
        progress_digest: str,
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "submit_builder_result",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "outcome": outcome,
                "summary": summary,
                "plan_digest": plan_digest,
                "iteration": iteration,
                "evidence_refs": list(evidence_refs),
                "progress_digest": progress_digest,
            },
        )

    async def dynamic_workflow_submit_evaluator_verdict(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        assignment_ref: str,
        assignment_receipt: str,
        expected_revision: int,
        idempotency_key: str,
        decision: str,
        accepted: bool,
        summary: str,
        plan_digest: str,
        builder_result_digest: str,
        required_criterion_ids: Sequence[str],
        criterion_results: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "submit_evaluator_verdict",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "assignment_ref": assignment_ref,
                "assignment_receipt": assignment_receipt,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "decision": decision,
                "accepted": accepted,
                "summary": summary,
                "plan_digest": plan_digest,
                "builder_result_digest": builder_result_digest,
                "required_criterion_ids": list(required_criterion_ids),
                "criterion_results": list(criterion_results),
            },
        )

    async def dynamic_workflow_cancel(
        self,
        *,
        company_ref: str,
        project_ref: str,
        run_ref: str,
        host_binding_ref: str,
        session_receipt: str,
        host_role: str,
        expected_revision: int,
        idempotency_key: str,
        reason: str,
    ) -> Dict[str, Any]:
        return await self._post_dynamic_workflow(
            "cancel",
            {
                "company_ref": company_ref,
                "project_ref": project_ref,
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "session_receipt": session_receipt,
                "host_role": host_role,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
                "reason": reason,
            },
        )

    # ── Identity & Discovery ─────────────────────────────────────────

    async def list_ready_sdk_project_checkpoints(
        self, project_id: str, *, ready_at: str, limit: int = 100,
        company_id: str | None = None, run_ref: str | None = None,
    ) -> List[Dict[str, Any]]:
        return await self._forward_declared_sync_operation(
            "list_ready_sdk_project_checkpoints", project_id, ready_at=ready_at,
            limit=limit, company_id=company_id, run_ref=run_ref,
        )

    async def claim_sdk_project_checkpoint(
        self, project_id: str, *, worker_ref: str, ready_at: str,
        lease_seconds: int = 60, company_id: str | None = None,
        run_ref: str | None = None,
    ) -> Dict[str, Any] | None:
        return await self._forward_declared_sync_operation(
            "claim_sdk_project_checkpoint", project_id, worker_ref=worker_ref,
            ready_at=ready_at, lease_seconds=lease_seconds,
            company_id=company_id, run_ref=run_ref,
        )

    async def whoami(self) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.get(f"{self._base_url}/api/users/me", headers=await self._headers())
        raise_if_error(resp)
        return resp.json()

    async def get_ai_metered_cost(self, provider: str, *, window_start: str, window_end: str) -> Dict[str, Any]:
        """Read native metering for the active company; this neither reconciles nor posts costs."""
        from lightbulb.company_engine_core import timestamp
        company = _validate_marketplace_uuid(self.active_company_id, "active_company_id")
        timestamp(window_start, field_name="window_start")
        timestamp(window_end, field_name="window_end")
        session = await self._ensure_client()
        response = await session.get(f"{self._base_url}/api/ai/costs/metered",
            params={"provider":provider, "windowStart":window_start, "windowEnd":window_end, "companyId":company},
            headers=await self._exact_company_headers(company))
        raise_if_error(response)
        return response.json()

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

    async def create_company(
        self,
        request: "Dict[str, Any] | Any | None" = None,
        /,
        **fields: Any,
    ) -> Any:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.create_company` (AU/CA only)."""
        from lightbulb.company_formation import (
            GUIDED_COMPANY_PATH,
            CompanyFormationRequest,
            parse_guided_response,
        )

        parsed = (
            request
            if isinstance(request, CompanyFormationRequest)
            else CompanyFormationRequest.model_validate({**dict(request or {}), **fields})
        )
        payload = parsed.to_guided_payload(self._auth.tenant_id)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}{GUIDED_COMPANY_PATH}",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return parse_guided_response(resp.json(), parsed)

    async def get_project_coding_harnesses(self, project_id: str) -> Dict[str, Any]:
        """Read the durable additive harness selection for one project."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses",
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding harness response must be a JSON object")
        return result

    async def add_project_coding_harness(
        self,
        project_id: str,
        harness: str,
        *,
        make_primary: bool = False,
    ) -> Dict[str, Any]:
        """Attach another harness without removing existing project harnesses."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        payload = {
            "harness": normalize_project_coding_harness(harness),
            "make_primary": bool(make_primary),
        }
        _guard_request_body(payload, endpoint="projects/coding-harnesses")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding harness response must be a JSON object")
        return result

    def native_coding(self, project_id: str) -> AsyncNativeCodingClient:
        """Connect a user-owned Codex, Claude Code or Cursor runtime to Project tasks."""
        return AsyncNativeCodingClient(self, project_id)

    async def request_project_native_coding_handoff(
        self, project_id: str, harness: str, *, expected_digest: str | None = None,
    ) -> Dict[str, Any]:
        """Propose a human review, or export its exact approved native work packet.

        Omit expected_digest to prepare/review. Pass the reviewed digest to
        export after the user decides the ApprovalTask. This never starts a
        hosted coding agent or marks an external delivery as verified.
        """
        import re
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        if expected_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            raise ValueError("expected_digest must be a SHA-256 digest")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/native-coding-handoffs/{selected_harness}",
            json={"expected_digest": expected_digest}, headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict) or result.get("schema") != "lightbulb.project_native_coding_handoff.v1":
            raise ValueError("Invalid native coding handoff response")
        if result.get("project_id") != normalized_project_id or result.get("harness") != selected_harness:
            raise ValueError("Native coding handoff scope mismatch")
        if expected_digest is not None and result.get("proposal_digest") != expected_digest:
            raise ValueError("Native coding handoff digest mismatch")
        return result

    async def get_project_coding_handoff(
        self,
        project_id: str,
        harness: str,
    ) -> Dict[str, Any]:
        """Read the selected Project Agent handoff for a connected harness."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses/"
            f"{selected_harness}/handoff",
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding handoff response must be a JSON object")
        return result

    async def claim_project_coding_handoff(
        self,
        project_id: str,
        *,
        harness: str,
        handoff_payload_id: str,
        host_session_ref: str | None = None,
    ) -> Dict[str, Any]:
        """Record routing of an approved handoff to the selected harness."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        selected_harness = normalize_project_coding_harness(harness)
        target_surface = {
            "codex": "codex_app",
            "claude_code": "claude_code",
            "cursor": "cursor",
            "chatgpt": "chatgpt",
        }[selected_harness]
        payload: Dict[str, Any] = {
            "handoff_payload_id": str(handoff_payload_id).strip(),
            "target_surface": target_surface,
            "launch_channel": "mcp_project_harness_claim",
            "status": "claimed_by_selected_harness",
            "summary": f"Selected {selected_harness} harness claimed the Project Agent handoff.",
        }
        if host_session_ref:
            if selected_harness == "codex":
                payload["codex_thread_id"] = str(host_session_ref).strip()
            elif selected_harness == "claude_code":
                payload["claude_code_session_id"] = str(host_session_ref).strip()
        _guard_request_body(payload, endpoint="projects/coding-harnesses/claim")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/product-machine/"
            "handoffs/external-coding-agents/launches",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding handoff claim response must be a JSON object")
        return result

    async def record_project_coding_harness_result(
        self,
        project_id: str,
        *,
        harness: str,
        handoff_payload_id: str,
        status: str,
        summary: str,
        report_id: str | None = None,
        host_session_ref: str | None = None,
        changed_files: Sequence[str] | None = None,
        test_commands_and_results: Sequence[str] | None = None,
        unresolved_requirements_or_acceptance_gaps: str | None = None,
        pull_request_url: str | None = None,
        commit_sha: str | None = None,
    ) -> Dict[str, Any]:
        """Return bounded coding evidence to the Project Agent delivery loop."""
        normalized_project_id = normalize_project_uuid(project_id, "project_id")
        payload: Dict[str, Any] = {
            "harness": normalize_project_coding_harness(harness),
            "handoff_payload_id": str(handoff_payload_id).strip(),
            "status": str(status).strip().lower(),
            "summary": str(summary).strip(),
        }
        optional = {
            "report_id": report_id,
            "host_session_ref": host_session_ref,
            "changed_files": list(changed_files or []),
            "test_commands_and_results": list(test_commands_and_results or []),
            "unresolved_requirements_or_acceptance_gaps": unresolved_requirements_or_acceptance_gaps,
            "pull_request_url": pull_request_url,
            "commit_sha": commit_sha,
        }
        payload.update(
            {
                key: value
                for key, value in optional.items()
                if value not in (None, [], "")
            }
        )
        _guard_request_body(payload, endpoint="projects/coding-harnesses/results")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/coding-harnesses/results",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project coding harness result response must be a JSON object")
        return result

    async def list_business_primitives(
        self,
        *,
        category: str | None = None,
        query: str | None = None,
        include_inputs: bool = True,
    ) -> List[Dict[str, Any]]:
        """List canonical primitive manifest entries without a network call."""
        from lightbulb.primitive_capability_manifest import primitive_manifest_catalog

        return primitive_manifest_catalog(
            category=category,
            query=query,
            include_schemas=include_inputs,
            limit=500,
        )["implementations"]

    async def list_executable_business_primitives(
        self,
        *,
        query: str = "",
        include_schemas: bool = True,
        offset: int = 0,
        limit: int | None = None,
    ) -> Dict[str, Any]:
        """Return the same canonical manifest page as the synchronous SDK."""
        from lightbulb.primitive_capability_manifest import primitive_manifest_catalog

        return primitive_manifest_catalog(
            query=query,
            include_schemas=include_schemas,
            offset=offset,
            limit=limit,
        )

    async def run_sdk_business_primitive(
        self,
        primitive_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        primitive_version: str | None = None,
        project_ref: str,
        project_id: str | None = None,
        preview_only: bool = True,
        approval_refs: Dict[str, str] | None = None,
        connector_account_refs: Dict[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Execute through the synchronous canonical runtime on its managed thread."""
        return await self._forward_declared_sync_operation(
            "run_sdk_business_primitive",
            primitive_id,
            inputs,
            primitive_version=primitive_version,
            project_ref=project_ref,
            project_id=project_id,
            preview_only=preview_only,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
            idempotency_key=idempotency_key,
        )

    async def run_business_primitive(
        self,
        primitive_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        primitive_version: str | None = None,
        project_ref: str | None = None,
        project_id: str | None = None,
        approval_refs: Dict[str, str] | None = None,
        connector_account_refs: Dict[str, str] | None = None,
        run_ref: str | None = None,
        idempotency_key: str | None = None,
        source: str = "sdk",
        mode: str | None = None,
        preview_only: bool = True,
        request: str = "",
    ) -> Dict[str, Any]:
        """Execute the canonical generic primitive path on its managed thread."""
        return await self._forward_declared_sync_operation(
            "run_business_primitive",
            primitive_id,
            inputs,
            primitive_version=primitive_version,
            project_ref=project_ref,
            project_id=project_id,
            approval_refs=approval_refs,
            connector_account_refs=connector_account_refs,
            run_ref=run_ref,
            idempotency_key=idempotency_key,
            source=source,
            mode=mode,
            preview_only=preview_only,
            request=request,
        )

    async def author_workflow_definition(
        self,
        definition: Mapping[str, Any],
        *,
        prompt: str = "",
        name: str | None = None,
        workflow_type: str | None = None,
        site_project_id: str | None = None,
        category: str | None = None,
        change_notes: str | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Publish one exact executable workflow projection through governance."""
        payload = _workflow_author_payload(
            definition,
            prompt=prompt,
            name=name,
            workflow_type=workflow_type,
            site_project_id=site_project_id,
            category=category,
            change_notes=change_notes,
        )
        internal_plane = isinstance(self._auth, ApiKeyAuth)
        effective_company = company_id or self._active_company_id
        if internal_plane:
            if effective_company:
                payload["companyId"] = str(effective_company).strip()
            if self._auth.user_id:
                payload["userId"] = str(self._auth.user_id).strip()
        _guard_request_body(payload, endpoint="workflow-designer/author")
        client = await self._ensure_client()
        request_headers = await self._headers()
        if internal_plane and effective_company:
            request_headers["X-Company-Id"] = str(effective_company).strip()
        response = await client.post(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'author')}",
            params=(
                {}
                if internal_plane
                else {"companyId": str(effective_company).strip()} if effective_company else {}
            ),
            json=payload,
            headers=request_headers,
        )
        if response.status_code != 422:
            raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow author response must be a JSON object")
        return result

    async def author_workflow_trigger(
        self,
        workflow_definition_id: str,
        *,
        trigger_type: str = "schedule",
        schedule: str | None = None,
        event_type: str | None = None,
        event_filter: Mapping[str, Any] | None = None,
        name: str | None = None,
        description: str | None = None,
        site_project_id: str | None = None,
        configuration: Mapping[str, Any] | None = None,
        enabled: bool = False,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Create a principal-scoped schedule or event trigger for a workflow."""
        definition_id = str(workflow_definition_id or "").strip()
        if not definition_id:
            raise ValueError("workflow_definition_id is required")
        kind = str(trigger_type or "schedule").strip().lower()
        if kind not in {"schedule", "event"}:
            raise ValueError("trigger_type must be 'schedule' or 'event'")
        if kind == "schedule" and not str(schedule or "").strip():
            raise ValueError("schedule is required for a schedule trigger")
        if kind == "event" and not str(event_type or "").strip():
            raise ValueError("event_type is required for an event trigger")
        _validate_workflow_trigger_filter(event_filter)
        if configuration is not None and not isinstance(configuration, Mapping):
            raise ValueError("configuration must be a JSON object")
        if configuration:
            raise ValueError(
                "configuration does not accept arbitrary persisted values; use the typed schedule, event_type, event_filter, and site_project_id arguments"
            )

        payload: Dict[str, Any] = {
            "workflowDefinitionId": definition_id,
            "triggerType": kind,
        }
        optional_values = {
            "name": name,
            "description": description,
            "schedule": schedule,
            "eventType": event_type,
            "siteProjectId": site_project_id,
        }
        for key, value in optional_values.items():
            if value:
                payload[key] = str(value).strip()
        if event_filter:
            payload["filter"] = dict(event_filter)
        if configuration:
            payload["configuration"] = dict(configuration)
        # Omission must never inherit the server's historical null -> active default.
        payload["enabled"] = bool(enabled)

        internal_plane = isinstance(self._auth, ApiKeyAuth)
        effective_company = company_id or self._active_company_id
        if internal_plane:
            if effective_company:
                payload["companyId"] = str(effective_company).strip()
            if self._auth.user_id:
                payload["userId"] = str(self._auth.user_id).strip()

        _guard_request_body(payload, endpoint="workflow-designer/triggers")
        client = await self._ensure_client()
        request_headers = await self._headers()
        if internal_plane and effective_company:
            request_headers["X-Company-Id"] = str(effective_company).strip()
        response = await client.post(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'triggers')}",
            params=(
                {}
                if internal_plane
                else {"companyId": str(effective_company).strip()} if effective_company else {}
            ),
            json=payload,
            headers=request_headers,
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow trigger response must be a JSON object")
        return result

    async def get_workflow_trigger_catalog(self) -> Dict[str, Any]:
        """List the schedule literals and event types accepted by authoring."""
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'triggers/catalog')}",
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Workflow trigger catalog response must be a JSON object")
        return result

    async def author_agentic_workflow(
        self,
        prompt: str,
        *,
        name: str | None = None,
        workflow_type: str | None = None,
        preferred_domains: List[str] | None = None,
        include_approval_gates: bool = True,
        publish: bool = True,
        company_id: str | None = None,
        site_project_id: str | None = None,
        definition: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Async compile-once authoring with exact executable-projection fidelity."""
        prompt = _validate_message(prompt)
        if definition is None:
            compile_payload: Dict[str, Any] = {
                "prompt": prompt,
                "includeApprovalGates": bool(include_approval_gates),
            }
            if name:
                compile_payload["name"] = str(name).strip()
            if workflow_type:
                compile_payload["workflowType"] = str(workflow_type).strip()
            if preferred_domains:
                compile_payload["preferredDomains"] = [
                    str(item).strip() for item in preferred_domains if str(item).strip()
                ]
            _guard_request_body(compile_payload, endpoint="workflow-designer/compile")
            client = await self._ensure_client()
            effective_company = company_id or self._active_company_id
            internal_plane = isinstance(self._auth, ApiKeyAuth)
            request_headers = await self._headers()
            if internal_plane and effective_company:
                request_headers["X-Company-Id"] = str(effective_company).strip()
            compile_response = await client.post(
                f"{self._base_url}{_workflow_authoring_endpoint(self._auth, 'compile')}",
                params=(
                    {}
                    if internal_plane
                    else {"companyId": str(effective_company).strip()} if effective_company else {}
                ),
                json=compile_payload,
                headers=request_headers,
            )
            raise_if_error(compile_response)
            compiled_result = compile_response.json()
            if not isinstance(compiled_result, dict):
                raise ValueError("Workflow compile response must be a JSON object")
            compiled: Dict[str, Any] = compiled_result
        else:
            if not isinstance(definition, Mapping):
                raise ValueError("definition must be a JSON object")
            compiled = dict(definition)

        workflow_name = str(name or compiled.get("name") or "Agentic Workflow").strip()
        workflow_type_value = str(
            workflow_type
            or compiled.get("workflowType")
            or compiled.get("workflow_type")
            or compiled.get("workflow_key")
            or "generated"
        ).strip()
        if compiled.get("schema") == "lightbulb.business_workflow_definition.v1":
            from lightbulb.business_primitives import validate_business_workflow_definition

            local_validation: Dict[str, Any] = validate_business_workflow_definition(compiled)
        else:
            local_validation = _local_workflow_validation(compiled)

        author_result: Dict[str, Any] = {}
        local_rejected = local_validation.get("valid") is False
        if publish and not local_rejected:
            author_result = await self.author_workflow_definition(
                compiled,
                prompt=prompt,
                name=workflow_name,
                workflow_type=workflow_type_value,
                site_project_id=site_project_id,
                company_id=company_id,
            )
        validation = author_result.get("validation") or local_validation
        published = bool(author_result.get("published"))
        rejected = bool(author_result.get("rejected")) or local_rejected
        workflow_id = author_result.get("workflowDefinitionId")
        warnings = list(compiled.get("warnings") or [])
        if isinstance(validation, Mapping):
            warnings.extend(list(validation.get("warnings") or []))
        artifact: Dict[str, Any] = {
            "schema": "lightbulb.agentic_workflow_artifact.v1",
            "prompt": prompt,
            "workflowDefinitionId": workflow_id,
            "name": workflow_name,
            "workflowType": author_result.get("workflowType") or workflow_type_value,
            "version": author_result.get("version"),
            "status": author_result.get("status") or (
                "LOCAL_REJECTED" if local_rejected else "REJECTED" if rejected else "LOCAL_DRAFT" if not publish else "DRAFT"
            ),
            "published": published,
            "rejected": rejected,
            "persisted": bool(workflow_id),
            "validation": validation,
            "compiled": compiled,
            "steps": compiled.get("steps") or [],
            "triggers": compiled.get("triggers") or (
                [compiled["trigger"]] if isinstance(compiled.get("trigger"), Mapping) else []
            ),
            "defaults": compiled.get("defaults") or {},
            "capabilityRequirements": compiled.get("capabilityRequirements") or [],
            "missingCapabilities": compiled.get("missingCapabilities") or [],
            "warnings": warnings,
            "authoring": {
                "mode": (
                    "local_validation_rejected"
                    if local_rejected
                    else "governed_submitted_definition"
                    if publish
                    else "local_zero_write_draft"
                ),
                "endpoint": _workflow_authoring_endpoint(self._auth, "author") if publish and not local_rejected else None,
                "executableProjectionDigest": _workflow_executable_projection_digest(compiled),
                "definitionRecompiled": False,
                "sourceDefinitionPersisted": False,
                "sourceDefinitionRetainedInArtifact": True,
                "persistedProjectionVerified": bool(author_result.get("persistedProjectionVerified")),
                "serverNormalized": author_result.get("definitionNormalized"),
            },
            "sdk": {
                "trigger": f'client.trigger_workflow("{workflow_type_value}", objective, inputs={{}})',
                "authorTrigger": "await client.author_workflow_trigger(workflow_definition_id, ...)",
            },
            "mcp": {
                "authorTool": "author_agentic_workflow",
                "authorTriggerTool": "author_workflow_trigger",
                "triggerTool": "trigger_workflow",
                "workflowType": workflow_type_value,
            },
        }
        for key in ("projectScope", "projectId", "binding", "bindingError"):
            if key in author_result:
                artifact[key] = author_result[key]
        return artifact

    async def list_domains(self) -> Dict[str, Dict[str, Any]] | List[Dict[str, Any]]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/domain-agents/contracts",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def list_domain_actions(self, domain: str) -> List[Dict[str, Any]]:
        """List authenticated, RBAC-visible actions for one domain."""
        domain = _validate_domain(domain)
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/domain-agents/{domain}/actions",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Bounded Memory regulation --------------------------------------

    async def memory_regulation_storage_status(self) -> Dict[str, Any]:
        """Inspect finite compaction-receipt admission without mutation."""
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/memory/regulation/storage",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def memory_regulate(
        self,
        *,
        idempotency_key: str | None = None,
        project_id: str | None = None,
        budget: int | None = None,
        categories: Sequence[str] | None = None,
        dry_run: bool = True,
        max_summary_chars: int = 900,
        empirical_success_floor_ppm: int | None = None,
        empirical_success_min_samples: int = 20,
        empirical_success_lookback_days: int = 90,
        optimize_for_least_active_memory: bool = False,
        held_out_task_evaluation: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Preview or execute success-evidence-aware Memory compaction."""
        payload = _build_memory_regulation_payload(
            idempotency_key=idempotency_key,
            budget=budget,
            categories=categories,
            dry_run=dry_run,
            max_summary_chars=max_summary_chars,
            empirical_success_floor_ppm=empirical_success_floor_ppm,
            empirical_success_min_samples=empirical_success_min_samples,
            empirical_success_lookback_days=empirical_success_lookback_days,
            optimize_for_least_active_memory=(
                optimize_for_least_active_memory
            ),
            held_out_task_evaluation=held_out_task_evaluation,
        )
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/memory/regulate",
            params={"projectId": project_id} if project_id else None,
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Governed account-shell customization ----------------------------

    async def get_account_shell_customization(self) -> Dict[str, Any]:
        """Read the effective governed account-shell customization."""
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/frontend-customizations/account-shell",
            headers=await self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def create_account_shell_customization_draft(
        self,
        document: Mapping[str, Any],
        *,
        base_revision_id: str | None,
    ) -> Dict[str, Any]:
        """Create an immutable draft from one exact base revision."""
        payload = {
            "document": _canonical_account_shell_document(document),
            "base_revision_id": _nullable_account_shell_revision_id(
                base_revision_id,
                "base_revision_id",
            ),
        }
        _guard_request_body(payload, endpoint="frontend-customizations/account-shell/drafts")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/drafts",
            json=payload,
            headers=await self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def preview_account_shell_customization(
        self,
        draft_revision_id: str,
    ) -> Dict[str, Any]:
        """Compile a draft into a non-publishing preview receipt."""
        payload = {
            "draft_revision_id": _validate_marketplace_uuid(
                draft_revision_id,
                "draft_revision_id",
            )
        }
        _guard_request_body(payload, endpoint="frontend-customizations/account-shell/previews")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/previews",
            json=payload,
            headers=await self._tenant_headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def publish_account_shell_customization(
        self,
        draft_revision_id: str,
        *,
        preview_receipt_id: str,
        expected_current_revision_id: str | None,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Publish the exact previewed draft with optimistic concurrency."""
        payload = {
            "draft_revision_id": _validate_marketplace_uuid(
                draft_revision_id,
                "draft_revision_id",
            ),
            "preview_receipt_id": _validate_marketplace_uuid(
                preview_receipt_id,
                "preview_receipt_id",
            ),
            "expected_current_revision_id": _nullable_account_shell_revision_id(
                expected_current_revision_id,
                "expected_current_revision_id",
            ),
        }
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        _guard_request_body(payload, endpoint="frontend-customizations/account-shell/publish")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/publish",
            json=payload,
            headers=await self._tenant_headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def rollback_account_shell_customization(
        self,
        target_revision_id: str,
        *,
        expected_current_revision_id: str | None,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Roll back to an immutable revision with optimistic concurrency."""
        payload = {
            "target_revision_id": _validate_marketplace_uuid(
                target_revision_id,
                "target_revision_id",
            ),
            "expected_current_revision_id": _nullable_account_shell_revision_id(
                expected_current_revision_id,
                "expected_current_revision_id",
            ),
        }
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        _guard_request_body(payload, endpoint="frontend-customizations/account-shell/rollback")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/frontend-customizations/account-shell/rollback",
            json=payload,
            headers=await self._tenant_headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    # -- Governed runtime domain actions ---------------------------------

    async def register_runtime_domain_action(
        self,
        domain: str,
        action: str,
        *,
        project_id: str,
        idempotency_key: str,
        description: str = "",
        component_ids: Sequence[str] | None = None,
        agent_spec: Dict[str, Any] | None = None,
        execution_policy: Dict[str, Any] | None = None,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Register a company-scoped action as ``pending_approval`` only."""
        company = self._require_runtime_action_company(company_id)
        key = _validate_runtime_action_idempotency_key(idempotency_key)
        payload = _build_runtime_domain_action_payload(
            domain=domain,
            action=action,
            description=description,
            component_ids=component_ids,
            agent_spec=agent_spec,
            execution_policy=execution_policy,
        )
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/domain-agents/runtime-actions",
            json=payload,
            headers=await self._runtime_action_headers(
                project_id,
                company,
                {"Idempotency-Key": key},
            ),
        )
        raise_if_error(resp)
        return resp.json()

    async def list_runtime_domain_actions(
        self,
        *,
        project_id: str,
        status: str = "pending_approval",
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """List one explicit lifecycle state for the selected company."""
        company = self._require_runtime_action_company(company_id)
        normalized_status = _validate_runtime_action_status(status)
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/domain-agents/runtime-actions",
            params={"status": normalized_status},
            headers=await self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Review one exact-scope registration without changing its lifecycle."""
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}",
            headers=await self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    async def approve_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Approve a reviewed action and return its governed recursive reference.

        Approval does not activate ordinary domain dispatch. A response with
        ``recursive_spawnable=true`` may be placed in an explicit bounded
        ``RecursiveAgentPolicy.allowed_agent_ids`` using ``recursive_agent_id``.
        """
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}/approve",
            headers=await self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    async def reject_runtime_domain_action(
        self,
        runtime_action_id: str,
        *,
        project_id: str,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Reject one reviewed pending registration without executing it."""
        company = self._require_runtime_action_company(company_id)
        action_id = _validate_marketplace_uuid(runtime_action_id, "runtime_action_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/domain-agents/runtime-actions/{action_id}/reject",
            headers=await self._runtime_action_headers(project_id, company),
        )
        raise_if_error(resp)
        return resp.json()

    async def search_agent_marketplace(
        self,
        *,
        query: str | None = None,
        kind: str | None = None,
        domain: str | None = None,
        limit: int = 50,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """Discover synthetic rows; use the persisted list for lifecycle UUIDs."""
        from lightbulb.marketplace import agent_marketplace_catalog

        normalized_domain = _validate_domain(domain) if domain else None
        primitives = await self.list_business_primitives(include_inputs=include_inputs)
        contracts = await self.list_domains()
        scoped_actions = (
            await self.list_domain_actions(normalized_domain)
            if normalized_domain
            else []
        )
        return agent_marketplace_catalog(
            business_primitives=primitives,
            domain_contracts=contracts,
            scoped_domain=normalized_domain,
            scoped_actions=scoped_actions,
            query=query,
            kinds=kind,
            domain=normalized_domain,
            include_inputs=include_inputs,
            limit=limit,
        )

    async def list_marketplace_listings(
        self,
        *,
        query: str | None = None,
        kind: str | None = None,
        domain: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """List persisted lifecycle listings and authoritative UUID IDs."""
        params: Dict[str, Any] = {
            "limit": _bounded_marketplace_limit(limit),
            "include_inputs": bool(include_inputs),
        }
        if query:
            params["query"] = str(query).strip()[:1_000]
        if kind:
            params["kind"] = _validate_action(kind)
        if domain:
            params["domain"] = _validate_domain(domain)
        if cursor:
            params["cursor"] = str(cursor).strip()[:2_000]
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/listings",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_marketplace_listing(
        self,
        listing_id: str,
        *,
        revision_id: str | None = None,
        include_inputs: bool = True,
    ) -> Dict[str, Any]:
        """Get one persisted marketplace listing and optional immutable revision."""
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        params: Dict[str, Any] = {"include_inputs": bool(include_inputs)}
        if revision_id:
            params["revision_id"] = _validate_marketplace_uuid(revision_id, "revision_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/listings/{listing_id}",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def preview_marketplace_action_publication(
        self,
        *,
        slug: str,
        name: str,
        version: str,
        domain: str,
        action: str,
        visibility: str = "PRIVATE",
        pricing_model: str = "INCLUDED",
        changelog: str = "",
    ) -> Dict[str, Any]:
        """Preview a server-derived immutable action contract without publishing it."""
        payload = _build_marketplace_action_publication_payload(
            slug=slug,
            name=name,
            version=version,
            domain=domain,
            action=action,
            visibility=visibility,
            pricing_model=pricing_model,
            changelog=changelog,
        )
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/action-publications/preview",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def publish_marketplace_action(
        self,
        *,
        slug: str,
        name: str,
        version: str,
        domain: str,
        action: str,
        expected_contract_digest: str,
        idempotency_key: str,
        visibility: str = "PRIVATE",
        pricing_model: str = "INCLUDED",
        changelog: str = "",
    ) -> Dict[str, Any]:
        """Publish the exact action contract approved by a prior preview."""
        payload = _build_marketplace_action_publication_payload(
            slug=slug,
            name=name,
            version=version,
            domain=domain,
            action=action,
            visibility=visibility,
            pricing_model=pricing_model,
            changelog=changelog,
        )
        payload["expected_contract_digest"] = _validate_marketplace_contract_digest(
            expected_contract_digest
        )
        _guard_request_body(payload, endpoint="agent-marketplace/action-publications")
        key = _validate_marketplace_publication_idempotency_key(idempotency_key)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/action-publications",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_marketplace_action_publication(self, publication_id: str) -> Dict[str, Any]:
        """Get governed publication and security-scan status by publication UUID."""
        publication_id = _validate_marketplace_uuid(publication_id, "publication_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/action-publications/{publication_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def wait_for_marketplace_action_publication(
        self,
        publication_id: str,
        *,
        timeout_seconds: float = 120.0,
        poll_interval_seconds: float = 2.0,
    ) -> Dict[str, Any]:
        """Poll until publication is READY, FAILED, or ARCHIVED, within hard bounds."""
        publication_id = _validate_marketplace_uuid(publication_id, "publication_id")
        timeout, interval = _bounded_marketplace_publication_polling(
            timeout_seconds,
            poll_interval_seconds,
        )
        deadline = time.monotonic() + timeout
        latest: Dict[str, Any] = {}
        while True:
            latest = await self.get_marketplace_action_publication(publication_id)
            if _is_terminal_marketplace_action_publication(latest):
                return latest
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                publication_status, operation_status = _marketplace_action_publication_status(latest)
                observed = publication_status or operation_status or "UNKNOWN"
                raise TimeoutError(
                    f"Marketplace action publication {publication_id} did not finish within "
                    f"{timeout:g} seconds (last status: {observed})"
                )
            await asyncio.sleep(min(interval, remaining))

    async def archive_marketplace_action(
        self,
        listing_id: str,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Archive a publisher-owned listing with a replay-safe mutation."""
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        key = _validate_marketplace_publication_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        normalized_reason = str(reason or "").strip()
        if normalized_reason:
            payload["reason"] = _bounded_marketplace_publication_text(
                normalized_reason, "reason", 2_000
            )
        _guard_request_body(payload, endpoint="agent-marketplace/listings/archive")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/listings/{listing_id}/archive",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def list_marketplace_installations(
        self,
        *,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List marketplace installations for the selected active company."""
        self._require_marketplace_company()
        params: Dict[str, Any] = {"limit": _bounded_marketplace_limit(limit)}
        if status:
            params["status"] = _validate_action(status)
        if cursor:
            params["cursor"] = str(cursor).strip()[:2_000]
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/installations",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_marketplace_installation(self, installation_id: str) -> Dict[str, Any]:
        """Get one marketplace installation for the selected active company."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def install_marketplace_action(
        self,
        listing_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        deployment_targets: Sequence[str] | None = None,
    ) -> Dict[str, Any]:
        """Install a pinned revision and bind its explicit agent targets."""
        self._require_marketplace_company()
        listing_id = _validate_marketplace_uuid(listing_id, "listing_id")
        revision_id = _validate_marketplace_uuid(revision_id, "revision_id")
        key = _validate_idempotency_key(idempotency_key)
        payload = {"listing_id": listing_id, "revision_id": revision_id}
        if deployment_targets is not None:
            payload["deployment_targets"] = _normalize_marketplace_deployment_targets(
                deployment_targets
            )
        _guard_request_body(payload, endpoint="agent-marketplace/installations")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/installations",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def activate_marketplace_action(
        self,
        installation_id: str,
        *,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Activate an installed action; this never approves execution policy."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        _guard_request_body(payload, endpoint="agent-marketplace/installations/activate")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/activate",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def uninstall_marketplace_action(
        self,
        installation_id: str,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Uninstall an action from the selected company."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {}
        if reason:
            payload["reason"] = str(reason).strip()[:2_000]
        _guard_request_body(payload, endpoint="agent-marketplace/installations/uninstall")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/uninstall",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def pin_marketplace_action(
        self,
        installation_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        expected_revision_id: str | None = None,
    ) -> Dict[str, Any]:
        """Pin an installation to an immutable listing revision."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        revision_id = _validate_marketplace_uuid(revision_id, "revision_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {"revision_id": revision_id}
        if expected_revision_id:
            payload["expected_revision_id"] = _validate_marketplace_uuid(
                expected_revision_id,
                "expected_revision_id",
            )
        _guard_request_body(payload, endpoint="agent-marketplace/installations/pin")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/pin",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def invoke_marketplace_action(
        self,
        installation_id: str,
        inputs: Dict[str, Any] | None = None,
        *,
        idempotency_key: str,
        message: str = "",
        objective: str = "",
        dry_run: bool = True,
        preview_invocation_id: str | None = None,
        confirm_live: bool = False,
    ) -> Dict[str, Any]:
        """Preview an installed action, or explicitly confirm an exact preview for live use."""
        self._require_marketplace_company()
        installation_id = _validate_marketplace_uuid(installation_id, "installation_id")
        key = _validate_idempotency_key(idempotency_key)
        payload: Dict[str, Any] = {
            "inputs": _validate_marketplace_inputs(inputs),
            "dry_run": bool(dry_run),
        }
        if dry_run and preview_invocation_id:
            raise ValueError("preview_invocation_id is only valid when dry_run=False")
        if not dry_run:
            if not confirm_live:
                raise ValueError(
                    "confirm_live=True is required after reviewing a dry-run marketplace receipt"
                )
            payload["preview_invocation_id"] = _validate_marketplace_uuid(
                preview_invocation_id or "",
                "preview_invocation_id",
            )
        if message:
            payload["message"] = _validate_message(message)
        if objective:
            payload["objective"] = str(objective).strip()[:_MAX_MESSAGE_LENGTH]
        _guard_request_body(payload, endpoint="agent-marketplace/installations/invocations")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-marketplace/installations/{installation_id}/invocations",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_marketplace_invocation_status(self, invocation_id: str) -> Dict[str, Any]:
        """Get current invocation state for the selected company."""
        self._require_marketplace_company()
        invocation_id = _validate_marketplace_uuid(invocation_id, "invocation_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/invocations/{invocation_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_marketplace_invocation_receipt(self, invocation_id: str) -> Dict[str, Any]:
        """Get the immutable audit receipt for one marketplace invocation."""
        self._require_marketplace_company()
        invocation_id = _validate_marketplace_uuid(invocation_id, "invocation_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-marketplace/invocations/{invocation_id}/receipt",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    # ── Governed training-pair readiness/status ───────────────────────────

    async def inspect_training_pair_readiness(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect structured readiness without admitting or launching training."""
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-ops/training-pairs/readiness",
            json=payload,
            headers=await self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair readiness must return exact HTTP 200"
            )
        return parse_training_pair_readiness(
            agent_ops_response_json(resp, "training-pair readiness"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    async def inspect_training_pair_input_custody(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect exact-owner input custody without widening authority."""
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-ops/training-pairs/input-custody",
            json=payload,
            headers=await self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair input custody must return exact HTTP 200"
            )
        return parse_training_pair_input_custody(
            agent_ops_response_json(resp, "training-pair input custody"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    async def preflight_training_pair(
        self,
        installation_id: str,
        revision_id: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Read readiness without admitting, scheduling, or launching training."""
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-ops/training-pairs/preflight",
            json=payload,
            headers=await self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair preflight must return exact HTTP 200"
            )
        return parse_training_pair_preflight(
            agent_ops_response_json(resp, "training-pair preflight"),
            installation_id=payload["installation_id"],
            revision_id=payload["revision_id"],
            project_id=payload.get("project_id"),
        )

    async def request_training_pair_admission(
        self,
        installation_id: str,
        revision_id: str,
        *,
        idempotency_key: str,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Request admission while preserving only the structured hard-503 body."""
        self._require_marketplace_company()
        payload = build_training_pair_request(installation_id, revision_id, project_id)
        key = validate_training_pair_idempotency_key(idempotency_key)
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/agent-ops/training-pairs",
            json=payload,
            headers=await self._headers({"Idempotency-Key": key}),
        )
        if resp.status_code == 503:
            try:
                unavailable = agent_ops_response_json(resp, "training-pair admission")
            except AgentOpsProtocolError:
                raise_if_error(resp)
                raise
            if is_training_pair_admission_unavailable(unavailable):
                return parse_training_pair_admission_unavailable(unavailable)
            raise_if_error(resp)
        raise_if_error(resp)
        raise AgentOpsProtocolError(
            "training-pair admission returned an unsupported success contract; "
            "this SDK only accepts the current structured HTTP 503"
        )

    async def get_training_pair_status(
        self,
        pair_handle: str,
        *,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Read the privacy-minimized status for one exact owned pair handle."""
        self._require_marketplace_company()
        normalized_pair = _validate_marketplace_uuid(pair_handle, "pair_handle")
        params: Dict[str, str] = {}
        if project_id is not None:
            params["project_id"] = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/agent-ops/training-pairs/{normalized_pair}",
            params=params,
            headers=await self._headers(),
        )
        if resp.status_code != 200:
            raise_if_error(resp)
            raise AgentOpsProtocolError(
                "training-pair status must return exact HTTP 200"
            )
        return parse_training_pair_status(
            agent_ops_response_json(resp, "training-pair status"),
            pair_handle=normalized_pair,
            project_id=params.get("project_id"),
        )

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

    async def record_server_workflow_improvement_run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a pre-sanitized evaluator run in the authenticated company scope."""
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflow-improvements/runs",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def create_server_workflow_improvement_packet(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflow-improvements/packets",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_server_workflow_improvement_status(self) -> Dict[str, Any]:
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflow-improvements/status",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def list_server_workflow_improvement_packets(
        self, *, status: str | None = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": max(1, min(int(limit), 100))}
        if status:
            params["status"] = str(status).strip()
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflow-improvements/packets",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    async def get_server_workflow_improvement_packet(self, packet_id: str) -> Dict[str, Any]:
        """Read one exact tenant/company-scoped workflow improvement packet."""
        from lightbulb.client import _validate_id

        packet_id = _validate_id(packet_id, "packet_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def decide_workflow_improvement_packet(
        self,
        packet_id: str,
        *,
        approval_scope: str,
        decision: str,
        rationale: str = "",
        evidence: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        from lightbulb.client import _validate_id

        packet_id = _validate_id(packet_id, "packet_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/decisions",
            json={
                "approvalScope": str(approval_scope).strip(),
                "decision": str(decision).strip(),
                "rationale": rationale,
                "evidence": evidence or {},
            },
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def start_workflow_improvement_delivery(
        self,
        packet_id: str,
        *,
        environment: str,
        repository_ref: str | None = None,
        base_branch: str = "main",
    ) -> Dict[str, Any]:
        from lightbulb.client import _validate_id

        packet_id = _validate_id(packet_id, "packet_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/deliveries",
            json={
                "environment": str(environment).strip(),
                "repositoryRef": repository_ref,
                "baseBranch": str(base_branch).strip(),
            },
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def record_workflow_improvement_delivery_event(
        self,
        delivery_id: str,
        event_type: str,
        *,
        rationale: str = "",
        evidence: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        from lightbulb.client import _validate_id

        delivery_id = _validate_id(delivery_id, "delivery_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/workflow-improvements/deliveries/{delivery_id}/events",
            json={"eventType": str(event_type).strip(), "rationale": rationale, "evidence": evidence or {}},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_workflow_improvement_audit(self, packet_id: str) -> List[Dict[str, Any]]:
        """Read the immutable scoped audit trail for one workflow packet."""
        from lightbulb.client import _validate_id

        packet_id = _validate_id(packet_id, "packet_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflow-improvements/packets/{packet_id}/audit",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

    async def get_workflow_improvement_delivery(self, delivery_id: str) -> Dict[str, Any]:
        """Read one exact scoped workflow-improvement delivery."""
        from lightbulb.client import _validate_id

        delivery_id = _validate_id(delivery_id, "delivery_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflow-improvements/deliveries/{delivery_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def inspect_workflow_learning_candidate_attestation(
        self, delivery_id: str
    ) -> Dict[str, Any]:
        """Revalidate the exact candidate producer attestation using current keys."""

        from lightbulb.client import _validate_id

        delivery_id = _validate_id(delivery_id, "delivery_id")
        client = await self._ensure_client()
        resp = await client.get(
            (
                f"{self._base_url}/api/workflow-improvements/deliveries/"
                f"{delivery_id}/candidate-artifact-attestation"
            ),
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def prepare_workflow_learning_handoff(
        self,
        packet_id: str,
        delivery_id: str,
        installation_id: str,
        revision_id: str,
        *,
        candidate_manifest: Dict[str, Any],
        episode_manifest: Dict[str, Any] | None = None,
        project_id: str | None = None,
    ) -> Dict[str, Any]:
        """Bind a validated delivery to read-only paired-learning readiness."""
        from lightbulb.workflow_learning import (
            WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA,
            compile_workflow_learning_handoff,
        )

        packet = await self.get_server_workflow_improvement_packet(packet_id)
        delivery = await self.get_workflow_improvement_delivery(delivery_id)
        audit = await self.get_workflow_improvement_audit(packet_id)
        readiness = await self.inspect_training_pair_readiness(
            installation_id,
            revision_id,
            project_id=project_id,
        )
        input_custody = None
        if episode_manifest is None or (
            isinstance(episode_manifest, dict)
            and episode_manifest.get("schema")
            == WORKFLOW_LEARNING_ATTESTED_EPISODE_SCHEMA
        ):
            input_custody = await self.inspect_training_pair_input_custody(
                installation_id,
                revision_id,
                project_id=project_id,
            )
        candidate_attestation = None
        if any(
            str(event.get("eventType") or event.get("event_type") or "").upper()
            == "IMPLEMENTATION_COMPLETED"
            and isinstance(event.get("evidence"), dict)
            and isinstance(
                event["evidence"].get("learning_candidate_artifact_attestation"),
                dict,
            )
            and event["evidence"]["learning_candidate_artifact_attestation"].get(
                "status"
            )
            == "signed"
            for event in audit
            if isinstance(event, dict)
        ):
            candidate_attestation = (
                await self.inspect_workflow_learning_candidate_attestation(delivery_id)
            )
        return compile_workflow_learning_handoff(
            packet=packet,
            delivery=delivery,
            audit_events=audit,
            candidate_manifest=candidate_manifest,
            episode_manifest=episode_manifest,
            training_readiness=readiness,
            installation_id=installation_id,
            revision_id=revision_id,
            project_id=project_id,
            training_input_custody=input_custody,
            candidate_artifact_attestation=candidate_attestation,
        )

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
        project_id: str | None = None,
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
        headers = await self._headers()
        if project_id is not None:
            headers["X-Project-Id"] = _validate_marketplace_uuid(project_id, "project_id")
        resp = await client.post(
            f"{self._base_url}/api/domain-agents/{domain}/dispatch",
            json=payload,
            headers=headers,
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

    async def get_workflow_instance(
        self,
        trace_id: str,
        *,
        company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Get a workflow instance through the authenticated public API."""
        trace_id = _validate_id(trace_id, "trace_id")
        client = await self._ensure_client()
        effective_company = company_id or self._active_company_id
        params = {"companyId": str(effective_company).strip()} if effective_company else {}
        resp = await client.get(
            f"{self._base_url}/api/workflows/instances/{trace_id}",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def wait_for_workflow_instance(
        self,
        trace_id: str,
        *,
        company_id: str | None = None,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> Dict[str, Any]:
        """Poll a workflow until it stops or requires human approval."""
        trace_id = _validate_id(trace_id, "trace_id")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        last_state = "unknown"
        while True:
            instance = await self.get_workflow_instance(trace_id, company_id=company_id)
            last_state = _workflow_instance_state(instance) or "unknown"
            if last_state in _WORKFLOW_STOP_STATES:
                return instance
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"Workflow {trace_id!r} did not stop within {timeout:g}s "
                    f"(last state: {last_state})"
                )
            await asyncio.sleep(min(poll_interval, remaining))

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

    async def get_project_game_snapshot(self, project_id: str) -> Dict[str, Any]:
        """Fetch and validate one server-owned, exact-scoped project snapshot."""

        project = normalize_project_game_snapshot_uuid(project_id, "project_id")
        company = normalize_project_game_snapshot_uuid(
            self._active_company_id,
            "active_company_id",
        )
        auth = self._auth
        tenant = normalize_project_game_snapshot_uuid(auth.tenant_id, "tenant_id")
        if isinstance(auth, ApiKeyAuth):
            route = f"/api/internal/projects/{project}/game-snapshot"
        elif isinstance(auth, JwtAuth):
            route = f"/api/projects/{project}/game-snapshot"
        else:
            raise ValueError(
                "Project snapshots require JwtAuth or ApiKeyAuth"
            )

        headers = await self._headers({"X-Project-Id": project})
        if self._auth is not auth:
            raise RuntimeError(
                "authentication context changed while binding project snapshot scope"
            )
        headers["X-Tenant-Id"] = tenant
        headers["X-Company-Id"] = company
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}{route}",
            headers=headers,
        )
        if len(response.content or b"") > PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES:
            raise ValueError(
                "project snapshot response exceeds the bounded canonical "
                f"limit of {PROJECT_GAME_SNAPSHOT_MAX_JSON_BYTES} bytes"
            )
        raise_if_error(response)
        return validate_project_game_snapshot(
            response.json(),
            expected_tenant_id=tenant,
            expected_company_id=company,
            expected_project_id=project,
        )


    def inspect_project_game_campaign(
        self,
        *,
        project: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        business_cockpit: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Inspect the human/agent project campaign locally without network activity."""
        return build_project_game_campaign(
            project=project,
            plan=plan,
            business_cockpit=business_cockpit,
        )

    async def list_project_science_evidence(
        self,
        project_id: str,
        *,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Read the scope-verified hypothesis-to-policy context spine."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/science-evidence",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def record_project_science_evidence(
        self,
        project_id: str,
        *,
        stage: Any,
        summary: Any,
        business_metric_id: Any,
        expected_direction: Any,
        artifact_kind: Any,
        artifact_system: Any,
        artifact_reference: Any,
        artifact_digest_sha256: Any,
        producer_role: Any,
        confirm_record: bool = False,
        tool_names: Sequence[Any] | None = None,
        skill_ids: Sequence[Any] | None = None,
        parent_receipt_ids: Sequence[Any] | None = None,
        artifact_schema: Any = None,
        observed_at: Any = None,
        evidence_id: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Append scientific lineage evidence; never authorize the underlying action."""
        if confirm_record is not True:
            raise ValueError("confirm_record=True is required to append science evidence")
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_science_evidence_observation(
            stage=stage,
            summary=summary,
            business_metric_id=business_metric_id,
            expected_direction=expected_direction,
            artifact_kind=artifact_kind,
            artifact_system=artifact_system,
            artifact_reference=artifact_reference,
            artifact_digest_sha256=artifact_digest_sha256,
            producer_role=producer_role,
            tool_names=tool_names,
            skill_ids=skill_ids,
            parent_receipt_ids=parent_receipt_ids,
            artifact_schema=artifact_schema,
            observed_at=observed_at,
            evidence_id=evidence_id,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
        )
        _guard_request_body(payload, endpoint="projects/science-evidence")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["evidence_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/science-evidence",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_mission_runs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read briefing locks and action bindings for one accessible project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def start_project_mission_run(
        self,
        project_id: str,
        mission_briefing: Mapping[str, Any],
        *,
        confirm_start: bool = False,
        run_id: Any = None,
        play_style_id: Any = None,
        skill_trial_arm: Any = None,
        selected_skill_ids: Sequence[Any] | None = None,
        context_source_refs: Sequence[Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Lock an exact briefing before action; this never dispatches a worker."""
        if confirm_start is not True:
            raise ValueError(
                "confirm_start=True is required to lock a project mission briefing"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_mission_run_start(
            mission_briefing=mission_briefing,
            run_id=run_id,
            play_style_id=play_style_id,
            skill_trial_arm=skill_trial_arm,
            selected_skill_ids=selected_skill_ids,
            context_source_refs=context_source_refs,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/mission-runs")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["run_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def bind_project_mission_action(
        self,
        project_id: str,
        mission_run_receipt_id: Any,
        action_event_id: Any,
        *,
        confirm_bind: bool = False,
        binding_id: Any = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Bind a later event to a mission; this proves timing and scope only."""
        if confirm_bind is not True:
            raise ValueError(
                "confirm_bind=True is required to bind a project mission action"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_mission_action_binding(
            mission_run_receipt_id=mission_run_receipt_id,
            action_event_id=action_event_id,
            binding_id=binding_id,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/mission-runs/action-bindings")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["binding_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/mission-runs/action-bindings",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_learning_reviews(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read human after-action decisions and admitted shadow observations."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-reviews",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_skill_matches(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read the project's worker-verified shadow Training Arena ledger."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/skill-matches",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_training_packs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read exact Arena + human-lesson packs before any learning-run admission."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/training-packs",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_learning_runs(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read receipt-backed Training Quest state without inferring missing execution."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def prepare_project_learning_run(
        self,
        project_id: str,
        *,
        training_pack_receipt_id: Any,
        primary_metric: Any,
        runtime: str = "automl",
        request_id: Any = None,
        direction: str = "maximize",
        minimum_improvement: Any = "0.010000",
        max_cost_usd: Any = "0.000000",
        max_platform_cost_usd: Any = "5.000000",
        max_gpu_seconds: Any = 3600,
        max_tokens: Any = 100_000,
        max_steps: Any = 10_000,
        provider_account_fingerprint: Any = None,
        provider_binding_expires_at: Any = None,
        max_attempts: Any = 3,
        lease_seconds: Any = 300,
        preemptible: bool = True,
        confirm_prepare: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Publish exact dataset custody and create a queued durable Memory run."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_learning_run_prepare_request(
            training_pack_receipt_id,
            primary_metric,
            runtime=runtime,
            request_id=request_id,
            direction=direction,
            minimum_improvement=minimum_improvement,
            max_cost_usd=max_cost_usd,
            max_platform_cost_usd=max_platform_cost_usd,
            max_gpu_seconds=max_gpu_seconds,
            max_tokens=max_tokens,
            max_steps=max_steps,
            provider_account_fingerprint=provider_account_fingerprint,
            provider_binding_expires_at=provider_binding_expires_at,
            max_attempts=max_attempts,
            lease_seconds=lease_seconds,
            preemptible=preemptible,
            confirm_prepare=confirm_prepare,
        )
        retry_key = _validate_idempotency_key(idempotency_key or payload["request_id"])
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(payload, endpoint="projects/learning-runs")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def admit_project_learning_run(
        self,
        project_id: str,
        learning_run_id: str,
        *,
        runtime: str,
        capacity_admission: Mapping[str, Any],
        operator_approved: bool = False,
        confirm_admission: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Reserve budget and admit a queued run; this still executes no training."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        normalized_run_id = _validate_id(learning_run_id, "learning_run_id")
        payload = build_project_learning_run_admission_request(
            runtime,
            capacity_admission,
            operator_approved=operator_approved,
            confirm_admission=confirm_admission,
        )
        default_key = (
            f"project-learning-admission:{normalized_run_id}:"
            f"{payload['capacity_admission']['decision_id']}"
        )
        retry_key = _validate_idempotency_key(idempotency_key or default_key)
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(payload, endpoint="projects/learning-runs/admit")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-runs/"
            f"{normalized_run_id}/admit",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_learning_result_evaluations(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read independent technical results and separate human decisions."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            "learning-result-evaluations",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def decide_project_learning_result_admission(
        self,
        project_id: str,
        evaluation_receipt_id: str,
        *,
        decision: Any,
        rationale: Any,
        confirm_admission: bool = False,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Human admit/reject; never apply or promote the candidate."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        normalized_evaluation_id = _validate_id(
            evaluation_receipt_id, "evaluation_receipt_id"
        )
        payload = build_project_learning_result_admission_request(
            decision,
            rationale,
            confirm_admission=confirm_admission,
        )
        retry_key = _validate_idempotency_key(
            idempotency_key
            or f"project-learning-result-admission:{normalized_evaluation_id}"
        )
        if len(retry_key) < 8:
            raise ValueError("idempotency_key must contain at least 8 characters")
        _guard_request_body(
            payload, endpoint="projects/learning-result-evaluations/admission"
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            f"learning-result-evaluations/{normalized_evaluation_id}/admission",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_shadow_learner_updates(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read bounded shadow update/rollback receipts; this grants no authority."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/"
            "shadow-learner-updates",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, Mapping) or result.get("schema") != (
            PROJECT_SHADOW_LEARNER_UPDATE_LEDGER_SCHEMA
        ):
            raise ValueError("shadow learner update ledger schema does not match")
        return dict(result)

    async def record_project_learning_review(
        self,
        project_id: str,
        *,
        mission_run_receipt_id: Any,
        mission_action_receipt_id: Any,
        outcome_receipt_id: Any,
        decision: Any,
        skill_trial_arm: Any,
        selected_skill_ids: Sequence[Any] | None,
        label: Any,
        reason: Any,
        confirm_record: bool = False,
        review_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Human-review one exact chain for shadow training; no live learner mutation."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to record a project learning review"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_learning_review_request(
            mission_run_receipt_id=mission_run_receipt_id,
            mission_action_receipt_id=mission_action_receipt_id,
            outcome_receipt_id=outcome_receipt_id,
            decision=decision,
            skill_trial_arm=skill_trial_arm,
            selected_skill_ids=selected_skill_ids,
            label=label,
            reason=reason,
            review_id=review_id,
            evidence_refs=evidence_refs,
        )
        _guard_request_body(payload, endpoint="projects/learning-reviews")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["review_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/learning-reviews",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_business_outcomes(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read the authenticated score ledger for one accessible project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/business-outcomes",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def record_project_business_outcome(
        self,
        project_id: str,
        *,
        metric_id: Any,
        metric_label: Any,
        direction: Any,
        baseline_value: Any,
        observed_value: Any,
        confirm_record: bool = False,
        unit: Any = None,
        observed_at: Any = None,
        observation_id: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        links: Mapping[str, Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Append one scoped metric observation; never admit learning or promotion."""
        if confirm_record is not True:
            raise ValueError("confirm_record=True is required to append a business outcome")
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_business_outcome_observation(
            metric_id=metric_id,
            metric_label=metric_label,
            direction=direction,
            baseline_value=baseline_value,
            observed_value=observed_value,
            unit=unit,
            observed_at=observed_at,
            observation_id=observation_id,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
            links=links,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/business-outcomes")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["observation_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/business-outcomes",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_policy_assignments(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read immutable decision-time probability assignments for one project."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-assignments",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def record_project_policy_assignment(
        self,
        project_id: str,
        *,
        metric_id: Any,
        direction: Any,
        actions: Sequence[Mapping[str, Any]],
        chosen_action_id: Any,
        behavior_policy: Mapping[str, Any],
        candidate_policies: Sequence[Mapping[str, Any]],
        confirm_record: bool = False,
        assignment_id: Any = None,
        unit: Any = None,
        decided_at: Any = None,
        source_kind: str = "human_attestation",
        source_event_id: Any = None,
        evidence_refs: Sequence[Any] | None = None,
        links: Mapping[str, Any] | None = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Log propensities before an outcome; this never executes an action."""
        if confirm_record is not True:
            raise ValueError(
                "confirm_record=True is required to append a policy assignment"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_policy_assignment(
            metric_id=metric_id,
            direction=direction,
            actions=actions,
            chosen_action_id=chosen_action_id,
            behavior_policy=behavior_policy,
            candidate_policies=candidate_policies,
            assignment_id=assignment_id,
            unit=unit,
            decided_at=decided_at,
            source_kind=source_kind,
            source_event_id=source_event_id,
            evidence_refs=evidence_refs,
            links=links,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/policy-assignments")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["assignment_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-assignments",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    async def list_project_policy_evaluations(
        self,
        project_id: str,
        *,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Read offline-policy receipts and their explicit truth boundary."""
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        bounded_limit = max(1, min(int(limit), 50))
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-evaluations",
            params={"limit": bounded_limit},
            headers=await self._headers(),
        )
        raise_if_error(response)
        return response.json()

    async def evaluate_project_offline_policy(
        self,
        project_id: str,
        *,
        behavior_policy_id: Any,
        candidate_policy_id: Any,
        metric_id: Any,
        pairs: Sequence[Mapping[str, Any]],
        confirm_evaluate: bool = False,
        evaluation_id: Any = None,
        note: Any = None,
        idempotency_key: str | None = None,
    ) -> Dict[str, Any]:
        """Estimate a candidate from verified receipts; never admit learning."""
        if confirm_evaluate is not True:
            raise ValueError(
                "confirm_evaluate=True is required to run offline policy evaluation"
            )
        self._require_marketplace_company()
        normalized_project_id = _validate_id(project_id, "project_id")
        payload = build_project_policy_evaluation_request(
            behavior_policy_id=behavior_policy_id,
            candidate_policy_id=candidate_policy_id,
            metric_id=metric_id,
            pairs=pairs,
            evaluation_id=evaluation_id,
            note=note,
        )
        _guard_request_body(payload, endpoint="projects/policy-evaluations")
        retry_key = _validate_idempotency_key(
            idempotency_key or str(payload["evaluation_id"])
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/policy-evaluations",
            json=payload,
            headers=await self._headers({"Idempotency-Key": retry_key}),
        )
        raise_if_error(response)
        return response.json()

    def inspect_project_creation_world_ready(
        self,
        name: str,
        instructions: str = "",
        *,
        participant_role: str = "agent_worker",
        experience_lens: str = "agent_protocol",
        play_style: str = "guided_human_in_the_loop",
    ) -> dict[str, Any]:
        """Inspect project-review readiness locally without network activity."""
        return build_project_creation_world_ready(
            name=name,
            instructions=instructions,
            tenant_id=self._auth.tenant_id,
            company_id=self._active_company_id,
            project_id=None,
            participant_role=participant_role,
            experience_lens=experience_lens,
            play_style=play_style,
            secure_receipt_verification=True,
        )

    async def preflight_project_creation(
        self,
        name: str,
        instructions: str = "",
    ) -> ProjectCreationPreflightReceipt:
        """Run the typed, shadow/read-only project-creation preflight."""
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        draft = ProjectCreationDraft(name=name, instructions=instructions)
        payload = build_project_creation_preflight_request(draft)
        _guard_request_body(payload, endpoint="enterprise-copilot/project-preflight")
        events: List[SSEEvent] = []
        async for event in self._stream_sse(
            f"{self._base_url}/api/enterprise-copilot/project-preflight",
            payload=payload,
        ):
            events.append(event)
            if len(events) > PROJECT_PREFLIGHT_MAX_EVENTS:
                raise ProjectCreationPreflightError(
                    "Project preflight SSE event limit exceeded"
                )
        receipt = project_creation_preflight_receipt_from_events(draft, events)
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ProjectCreationPreflightError(
                "Project preflight episode tenant does not match the auth context"
            )
        if receipt.episode_scope.company_id != company_id:
            raise ProjectCreationPreflightError(
                "Project preflight episode company does not match the selected company"
            )
        return receipt

    async def create_project_from_preflight(
        self,
        receipt: ProjectCreationPreflightReceipt,
        *,
        coding_harness: str,
        confirm_create: bool = False,
        confirm_open_questions: bool = False,
        workspace_id: str | None = None,
        repo_connection_id: str | None = None,
        idempotency_key: str | None = None,
        play_style: str | None = None,
    ) -> Dict[str, Any]:
        """Create exactly the draft bound to a validated preflight receipt."""
        if confirm_create is not True:
            raise ValueError("confirm_create=True is required to create the project")
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError("Preflight receipt company does not match the selected company")
        # Compatibility keyword only; advisory questions and legacy-v1 blocking
        # labels do not add a second confirmation gate beyond the user's explicit
        # create instruction.
        del confirm_open_questions
        selected_harness = normalize_project_coding_harness(coding_harness)

        payload: Dict[str, Any] = {
            "name": receipt.draft.name,
            "instructions": receipt.draft.instructions,
            "preflight_execution_id": receipt.preflight_execution_id,
            "coding_harnesses": [selected_harness],
            "primary_coding_harness": selected_harness,
        }
        if workspace_id is not None:
            payload["workspace_id"] = normalize_project_uuid(workspace_id, "workspace_id")
        if repo_connection_id is not None:
            payload["repo_connection_id"] = normalize_project_uuid(
                repo_connection_id,
                "repo_connection_id",
            )
        if play_style is not None:
            payload["play_style"] = normalize_project_play_style(play_style)
        extra_headers: Dict[str, str] = {}
        if idempotency_key is not None:
            extra_headers["Idempotency-Key"] = _validate_idempotency_key(idempotency_key)

        _guard_request_body(payload, endpoint="projects")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects",
            json=payload,
            headers=await self._headers(extra_headers),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Project create response must be a JSON object")
        return result

    async def refine_project_creation_preflight(
        self,
        receipt: ProjectCreationPreflightReceipt,
        answer: str,
    ) -> ProjectCreationPreflightReceipt:
        """Async parity for one explicit, receipt-bound preflight answer."""
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError("Preflight receipt company does not match the selected company")
        payload = build_project_creation_preflight_refinement_request(receipt, answer)
        _guard_request_body(
            payload,
            endpoint="enterprise-copilot/project-preflight/refine",
        )
        events: List[SSEEvent] = []
        async for event in self._stream_sse(
            f"{self._base_url}/api/enterprise-copilot/project-preflight/refine",
            payload=payload,
        ):
            events.append(event)
            if len(events) > PROJECT_PREFLIGHT_MAX_EVENTS:
                raise ProjectCreationPreflightError(
                    "Project preflight SSE event limit exceeded"
                )
        refreshed = project_creation_preflight_refinement_receipt_from_events(
            receipt,
            payload["answer"],
            events,
        )
        if refreshed.episode_scope.tenant_id != tenant_id:
            raise ProjectCreationPreflightError(
                "Refined preflight episode tenant does not match the auth context"
            )
        if refreshed.episode_scope.company_id != company_id:
            raise ProjectCreationPreflightError(
                "Refined preflight episode company does not match the selected company"
            )
        return refreshed

    async def submit_project_creation_preflight_feedback(
        self,
        receipt: ProjectCreationPreflightReceipt,
        *,
        helpfulness: SemanticFeedbackValue,
        calibrated_criticality: SemanticFeedbackValue,
        factual_grounding: SemanticFeedbackValue,
        idempotency_key: str,
    ) -> ProjectPreflightSemanticFeedbackReceipt:
        """Async parity for explicit project-preflight semantic feedback."""
        if not isinstance(receipt, ProjectCreationPreflightReceipt):
            raise TypeError("receipt must be a ProjectCreationPreflightReceipt")
        company_id = self._require_marketplace_company()
        tenant_id = normalize_project_uuid(self._auth.tenant_id, "tenant_id")
        if receipt.episode_scope.tenant_id != tenant_id:
            raise ValueError("Preflight receipt tenant does not match the auth context")
        if receipt.episode_scope.company_id != company_id:
            raise ValueError("Preflight receipt company does not match the selected company")
        payload, dimensions = build_project_preflight_feedback_request(
            helpfulness=helpfulness,
            calibrated_criticality=calibrated_criticality,
            factual_grounding=factual_grounding,
            idempotency_key=idempotency_key,
        )
        _guard_request_body(payload, endpoint="agent-episodes/semantic-feedback")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/memory/agent-episodes/"
                f"{receipt.episode_id}/semantic-feedback"
            ),
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(response)
        return bind_project_preflight_feedback_receipt(
            response.json(),
            preflight_receipt=receipt,
            dimensions=dimensions,
            expected_tenant_id=tenant_id,
            expected_company_id=company_id,
        )

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

    async def backbone_execute(
        self,
        objective: str,
        *,
        inputs: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Execute a task through the tenant-scoped backbone agent."""
        payload: Dict[str, Any] = {"objective": _validate_message(objective)}
        if inputs:
            if not isinstance(inputs, dict):
                raise TypeError("inputs must be a dict or None")
            payload["inputs"] = dict(inputs)
        _guard_request_body(payload, endpoint="backbone/execute")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/v1/backbone/execute",
            json=payload,
            headers=await self._headers(),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Backbone execute response must be a JSON object")
        return result

    async def recursive_agent_execute(
        self,
        objective: str,
        *,
        inputs: Dict[str, Any] | None = None,
        policy: Any = None,
        execution_id: str | None = None,
    ) -> Dict[str, Any]:
        """Run a governed recursive objective with finite subagent and REPL limits."""
        from lightbulb.recursive_agents import build_recursive_agent_inputs

        recursive_inputs = build_recursive_agent_inputs(
            inputs, policy, execution_id=execution_id
        )
        result = await self.backbone_execute(
            objective,
            inputs=recursive_inputs,
        )
        result.setdefault("recursive_execution", {
            "schema": "lightbulb.recursive_execution_ref.v1",
            "execution_id": recursive_inputs["recursive_execution_id"],
        })
        return result

    async def cancel_recursive_agent_execution(
        self, execution_id: str
    ) -> Dict[str, Any]:
        """Cancel one exact user-owned recursive execution tree."""
        execution_id = _validate_id(execution_id, "execution_id")
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/v1/backbone/recursive-executions/{execution_id}/cancel",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_recursive_agent_execution_status(
        self, execution_id: str
    ) -> Dict[str, Any]:
        """Read privacy-minimized status for one exact user-owned recursive tree."""
        execution_id = _validate_id(execution_id, "execution_id")
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/v1/backbone/recursive-executions/{execution_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        result = resp.json()
        if not isinstance(result, dict):
            raise ValueError("Recursive execution status must be a JSON object")
        return result

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


    async def get_approval(self, task_id: str) -> Dict[str, Any]:
        """Read one approval task (async twin of :meth:`LightbulbClient.get_approval`)."""
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/workflows/approvals/{task_id}",
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def request_engine_transition_approval(
        self,
        request: "Dict[str, Any] | Any",
    ) -> Dict[str, Any]:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.request_engine_transition_approval`."""
        from lightbulb.company_execution_bridge import ENGINE_APPROVALS_PATH, EngineApprovalRequest

        parsed = (
            request
            if isinstance(request, EngineApprovalRequest)
            else EngineApprovalRequest.model_validate(dict(request))
        )
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}{ENGINE_APPROVALS_PATH}",
            json=parsed.to_platform_body(),
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()


    async def put_engine_state(
        self,
        project_id: str,
        engine: str,
        entity_ref: str,
        state: "Dict[str, Any]",
        *,
        expected_version: int | None,
        expected_state_digest: str | None,
    ) -> Dict[str, Any]:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.put_engine_state`."""
        client = await self._ensure_client()
        resp = await client.put(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}",
            json={"expectedVersion": expected_version, "expectedStateDigest": expected_state_digest, "state": dict(state)},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def migrate_engine_state(
        self,
        project_id: str,
        engine: str,
        entity_ref: str,
        state: "Dict[str, Any]",
        *,
        migration: "Dict[str, Any]",
    ) -> Dict[str, Any]:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.migrate_engine_state`."""
        client = await self._ensure_client()
        resp = await client.post(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}/migrations",
            json={"migration": dict(migration), "state": dict(state)},
            headers=await self._headers(),
        )
        raise_if_error(resp)
        return resp.json()

    async def get_engine_state(self, project_id: str, engine: str, entity_ref: str) -> Dict[str, Any] | None:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.get_engine_state`."""
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states/{engine}/{entity_ref}",
            headers=await self._headers(),
        )
        if resp.status_code == 404:
            return None
        raise_if_error(resp)
        return resp.json()

    async def get_engine_inventory(self, project_id: str, *, engine: str) -> Dict[str, Any]:
        """Read an unfiltered engine inventory pinned to the active company; partial reads remain marked."""
        from lightbulb._engine_inventory import validate_inventory
        company = _validate_marketplace_uuid(self.active_company_id, "active_company_id")
        project = _validate_marketplace_uuid(project_id, "project_id")
        session = await self._ensure_client()
        response = await session.get(f"{self._base_url}/api/sdk-engine/projects/{project}/states/inventory",
            params={"engine": engine}, headers=await self._exact_company_headers(company))
        raise_if_error(response)
        return validate_inventory(response.json(), company_id=company, tenant_id=self._auth.tenant_id, project_id=project, engine=engine)

    async def list_all_engine_states(self, project_id: str, *, engine: str | None = None,
            status: str | None = None, company_id: str | None = None) -> List[Dict[str, Any]]:
        """Read all states from immutable scoped pages; reject partial, mixed or expired snapshots.

        The host bounds snapshots to 10,000 rows and 32 MiB. An oversized scope
        raises an error instead of silently returning its first page.
        """
        from lightbulb._engine_inventory import EngineSnapshotRead
        company = _validate_marketplace_uuid(company_id or self.active_company_id, "company_id")
        project = _validate_marketplace_uuid(project_id, "project_id")
        engine = engine or None
        status = status.lower() if status else None
        reader = EngineSnapshotRead(company_id=company, tenant_id=self._auth.tenant_id,
            project_id=project, engine=engine, status=status)
        session = await self._ensure_client()
        headers = await self._exact_company_headers(company)
        path = f"{self._base_url}/api/sdk-engine/projects/{project}/states/snapshots"
        response = await session.post(path, params={k:v for k,v in {"engine":engine,"status":status}.items() if v is not None},
            headers=headers)
        raise_if_error(response)
        reader.add(response.json())
        while reader.next_offset is not None:
            response = await session.get(f"{path}/{reader.snapshot_id}", params={"offset":reader.next_offset}, headers=headers)
            raise_if_error(response)
            reader.add(response.json())
        return reader.records

    async def list_engine_states(
        self,
        project_id: str,
        *,
        engine: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Async twin of :meth:`lightbulb.client.LightbulbClient.list_engine_states`."""
        params: Dict[str, Any] = {"limit": max(1, min(200, int(limit)))}
        if engine:
            params["engine"] = engine
        if status:
            params["status"] = status
        client = await self._ensure_client()
        resp = await client.get(
            f"{self._base_url}/api/sdk-engine/projects/{project_id}/states",
            params=params,
            headers=await self._headers(),
        )
        raise_if_error(resp)
        data = resp.json()
        return data if isinstance(data, list) else data.get("items", [])

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

    async def sync_customer_recovery_task(self, request, *, application_id, workspace_ref, action_ref, completed=False):
        """Create/reconcile the scoped CRM escalation; never resend the customer action."""
        from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorEffect
        from uuid import UUID
        request = ConnectorExecutionRequest.model_validate(request)
        if request.effect != ConnectorEffect.WRITE or request.scope.project_id is None:
            raise ValueError("customer write identity required")
        payload = {"projectId": str(request.scope.project_id), "applicationId": str(UUID(str(application_id))),
                   "workspaceRef": workspace_ref, "actionRef": str(UUID(str(action_ref))),
                   "requestDigest": request.custody_fingerprint(), "toolName": request.tool,
                   "connectorAccountRef": request.connector_account_ref, "approvalRef": request.approval_ref,
                   "completed": completed}
        session = await self._ensure_client()
        response = await session.post(f"{self._base_url}/api/tools/customer-recovery-tasks", json=payload, headers=await self._headers())
        raise_if_error(response)
        return response.json()

    async def acknowledge_customer_recovery_task(self, project_id, task_id):
        """Acknowledge as the assigned owner; acknowledgment does not resolve the effect."""
        from uuid import UUID
        session = await self._ensure_client()
        response = await session.post(f"{self._base_url}/api/tools/customer-recovery-tasks/{UUID(str(task_id))}/acknowledge",
                                     params={"projectId": str(UUID(str(project_id)))}, headers=await self._headers())
        raise_if_error(response)
        return response.json()

    async def lookup_connector_receipt(self, request) -> Dict[str, Any]:
        """Read the original governed receipt; this endpoint cannot dispatch a Tool."""
        from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorEffect
        request = ConnectorExecutionRequest.model_validate(request)
        if request.effect != ConnectorEffect.WRITE or not request.scope.project_id or not request.approval_ref:
            raise ValueError("approved write identity required for receipt lookup")
        payload = {"projectId": str(request.scope.project_id), "toolName": request.tool,
                   "connectorAccountRef": request.connector_account_ref,
                   "requestDigest": request.custody_fingerprint(), "approvalRef": request.approval_ref}
        session = await self._ensure_client()
        response = await session.post(f"{self._base_url}/api/tools/governed-receipt",
                                     json=payload, headers=await self._headers())
        raise_if_error(response)
        return response.json()

    async def invoke_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        project_id: str | None = None,
        project_ref: str | None = None,
        connector_account_ref: str | None = None,
        idempotency_key: str | None = None,
        approval_ref: str | None = None,
        workflow_id: str | None = None,
        step_id: str | None = None,
        workflow_instance_id: str | None = None,
        workflow_step_generation: int | None = None,
        runtime_context: Dict[str, Any] | None = None,
        effect: str | None = None,
    ) -> Dict[str, Any]:
        """Invoke a utility through legacy routing or a connector through exact custody.

        With Spring's connector effect boundary enabled, catalogued connector
        reads and writes require the governed project/account arguments and fail
        closed on the legacy endpoint. Private-response reads such as
        ``shopify.list_abandoned_checkouts`` and ``gmail.get_thread`` require
        exact project/account/read custody and must omit ``idempotency_key`` so
        every response contains fresh provider data.
        """
        _validate_ephemeral_read_invoke_contract(
            tool_name,
            project_id=project_id,
            project_ref=project_ref,
            connector_account_ref=connector_account_ref,
            idempotency_key=idempotency_key,
            effect=effect,
        )
        governed = _governed_invoke_requested(
            project_ref=project_ref,
            connector_account_ref=connector_account_ref,
            idempotency_key=idempotency_key,
            approval_ref=approval_ref,
            runtime_context=runtime_context,
            effect=effect,
            workflow_instance_id=workflow_instance_id,
            workflow_step_generation=workflow_step_generation,
        )
        workflow_execution_identity = _normalize_workflow_execution_identity(
            workflow_instance_id=workflow_instance_id,
            step_id=step_id,
            workflow_step_generation=workflow_step_generation,
        )
        client = await self._ensure_client()
        payload: Dict[str, Any] = {"toolName": tool_name, "inputs": arguments}
        tenant_id = getattr(self._auth, "tenant_id", None)
        if tenant_id:
            payload["tenantId"] = tenant_id
        if self._active_company_id:
            payload["companyId"] = self._active_company_id
        if project_id:
            payload["projectId"] = _validate_marketplace_uuid(project_id, "project_id")
        if workflow_id:
            payload["workflowId"] = str(workflow_id).strip()
        if step_id:
            payload["stepId"] = str(step_id).strip()
        if workflow_execution_identity is not None:
            bound_instance_id, bound_step_id, bound_generation = (
                workflow_execution_identity
            )
            payload["workflowInstanceId"] = bound_instance_id
            payload["stepId"] = bound_step_id
            payload["workflowStepGeneration"] = bound_generation
        endpoint = "/api/tools/invoke"
        if governed:
            endpoint = "/api/tools/governed-invoke"
            if project_ref is not None:
                clean_project_ref = str(project_ref).strip()
                if not clean_project_ref or len(clean_project_ref) > 160:
                    raise ValueError("project_ref must be 1-160 characters")
                payload["projectRef"] = clean_project_ref
            if connector_account_ref is not None:
                clean_account_ref = str(connector_account_ref).strip()
                if (
                    not clean_account_ref
                    or len(clean_account_ref) > 200
                    or any(ord(char) < 33 for char in clean_account_ref)
                ):
                    raise ValueError(
                        "connector_account_ref must be 1-200 visible characters"
                    )
                payload["connectorAccountRef"] = clean_account_ref
            if idempotency_key is not None:
                clean_key = str(idempotency_key).strip()
                if not clean_key or len(clean_key) > 240 or any(ord(char) < 33 for char in clean_key):
                    raise ValueError("idempotency_key must be 1-240 visible characters")
                payload["idempotencyKey"] = clean_key
            if approval_ref is not None:
                payload["approvalRef"] = _validate_marketplace_uuid(approval_ref, "approval_ref")
            if runtime_context is not None:
                if not isinstance(runtime_context, dict):
                    raise ValueError("runtime_context must be an object")
                payload["runtimeContext"] = dict(runtime_context)
            if effect is not None:
                clean_effect = str(effect).strip().lower()
                if clean_effect not in {"read", "write"}:
                    raise ValueError("effect must be read or write")
                payload["claimedEffect"] = clean_effect
        _guard_request_body(payload, endpoint=f"tools/{'governed-invoke' if governed else 'invoke'}:{tool_name}")
        headers = await self._headers()
        resp = await client.post(
            f"{self._base_url}{endpoint}",
            json=payload,
            headers=headers,
        )
        raise_if_error(resp)
        return resp.json()

    async def _forward_declared_sync_operation(
        self, operation: str, *args: Any, **kwargs: Any
    ) -> Any:
        fallback = self._ensure_sync_fallback()
        try:
            return await asyncio.to_thread(
                getattr(fallback, operation), *args, **kwargs
            )
        finally:
            self._auth = fallback._auth
            self._active_company_id = fallback.active_company_id

    async def _exact_company_headers(
        self,
        company_id: str | None,
        extra: Dict[str, str] | None = None,
    ) -> Dict[str, str]:
        """Pin one request to an explicit company without changing client state."""

        if company_id is None:
            return await self._headers(extra)
        headers = await self._tenant_headers(extra)
        headers["X-Company-Id"] = _validate_marketplace_uuid(
            company_id,
            "company_id",
        )
        return headers

    def _company_blueprint_company(self, company_id: str | None) -> str:
        return _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id" if company_id else "active_company_id",
        )

    async def preview_reference_company_onboarding(
        self,
        project_id: str,
        blueprint_version_ref: str,
        *,
        connector_selections: Mapping[str, str],
        coding_harness: str | None = None,
        company_id: str | None = None,
    ) -> ReferenceCompanyOnboardingPreview:
        """Validate one exact-scope reference-company setup without activating it."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = reference_company_onboarding_payload(
            blueprint_version_ref=blueprint_version_ref,
            project_id=normalized_project_id,
            connector_selections=connector_selections,
            coding_harness=coding_harness,
        )
        _guard_request_body(
            payload,
            endpoint="company-blueprints/reference-company/onboarding-preview",
        )
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/company-blueprints/reference-company/"
                "onboarding-preview"
            ),
            json=payload,
            headers=await self._exact_company_headers(
                scoped_company,
                {"X-Project-Id": normalized_project_id},
            ),
        )
        raise_if_error(response)
        return parse_reference_company_onboarding_preview(
            response.json(),
            expected_blueprint_version_ref=payload["blueprint_version_ref"],
            expected_tenant_id=self._auth.tenant_id,
            expected_company_id=scoped_company,
            expected_project_id=payload["project_id"],
        )

    async def get_reference_company_onboarding_readiness(
        self,
        project_id: str,
        *,
        company_id: str | None = None,
    ) -> ReferenceCompanyOnboardingReadiness:
        """Async secret-free reference-company readiness projection."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/company-blueprints/reference-company/projects/"
                f"{normalized_project_id}/onboarding-readiness"
            ),
            headers=await self._exact_company_headers(
                scoped_company,
                {"X-Project-Id": normalized_project_id},
            ),
        )
        raise_if_error(response)
        return parse_reference_company_onboarding_readiness(
            response.json(),
            expected_tenant_id=self._auth.tenant_id,
            expected_company_id=scoped_company,
            expected_project_id=normalized_project_id,
        )

    async def propose_company_blueprint_certification(
        self,
        project_id: str,
        candidate: CompanyBlueprintCertificationCandidate | Mapping[str, Any],
        *,
        evidence_target_id: str,
        idempotency_key: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = company_blueprint_certification_payload(
            candidate,
            evidence_target_id=evidence_target_id,
            idempotency_key=idempotency_key,
        )
        _guard_request_body(payload, endpoint="company-blueprints/certifications")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates"
            ),
            json=payload,
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    async def prepare_company_blueprint_native_proof(
        self,
        project_id: str,
        blueprint_version_id: str,
        golden_loop_certification_record_ids: Sequence[str],
        rollback_shadow_intent_id: str,
        *,
        company_id: str | None = None,
    ) -> dict[str, Any]:
        """Ask Spring to derive the exact no-effect Blueprint proof set."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = {
            "blueprint_version_id": _validate_marketplace_uuid(
                blueprint_version_id, "blueprint_version_id"
            ),
            "golden_loop_certification_record_ids": [
                _validate_marketplace_uuid(value, "golden_loop_certification_record_id")
                for value in golden_loop_certification_record_ids
            ],
            "rollback_shadow_intent_id": _validate_marketplace_uuid(
                rollback_shadow_intent_id, "rollback_shadow_intent_id"
            ),
        }
        if not payload["golden_loop_certification_record_ids"]:
            raise ValueError("golden_loop_certification_record_ids must not be empty")
        _guard_request_body(payload, endpoint="company-blueprints/certifications/native-proof")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/native-proof"
            ),
            json=payload,
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Company Blueprint native-proof response must be an object")
        return result

    async def finalize_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        return await self._company_blueprint_certification_action(
            project_id, candidate_id, action="finalize", company_id=company_id
        )

    async def cancel_company_blueprint_certification(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        return await self._company_blueprint_certification_action(
            project_id, candidate_id, action="cancel", company_id=company_id
        )

    async def _company_blueprint_certification_action(
        self,
        project_id: str,
        candidate_id: str,
        *,
        action: str,
        company_id: str | None,
    ) -> CompanyBlueprintCertificationStatus:
        if action not in {"finalize", "cancel"}:
            raise ValueError("unsupported Company Blueprint certification action")
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates/"
                f"{normalized_candidate_id}/{action}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    async def get_company_blueprint_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationStatus:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/candidates/"
                f"{normalized_candidate_id}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_company_blueprint_certification_status(response.json())

    async def get_current_company_blueprint_certification(
        self,
        project_id: str,
        *,
        blueprint_version_id: str,
        environment_ref: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintCertificationSpringRecord | None:
        """Resolve the current exact Blueprint certificate using Spring's clock."""

        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_version_id = _validate_marketplace_uuid(
            blueprint_version_id, "blueprint_version_id"
        )
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/company-blueprints/projects/"
                f"{normalized_project_id}/certifications/current"
            ),
            params={
                "blueprint_version_id": normalized_version_id,
                "environment_ref": str(environment_ref or "").strip(),
            },
            headers=await self._exact_company_headers(scoped_company),
        )
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_company_blueprint_certification_record(response.json())

    async def propose_company_blueprint_deployment(
        self, project_id: str,
        candidate: CompanyBlueprintDeploymentCandidate | Mapping[str, Any], *,
        idempotency_key: str, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        payload = company_blueprint_deployment_payload(candidate, idempotency_key=idempotency_key)
        _guard_request_body(payload, endpoint="company-blueprints/deployments")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments",
            json=payload, headers=await self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    async def transition_company_blueprint_deployment(
        self, project_id: str, deployment_id: str, *, action: str,
        company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        if action not in {
            "finalize-deployment", "finalize-activation", "cancel",
            "request-rollback", "finalize-rollback",
        }:
            raise ValueError("unsupported Company Blueprint deployment action")
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        deployment = _validate_marketplace_uuid(deployment_id, "deployment_id")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments/{deployment}/{action}",
            headers=await self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    async def get_company_blueprint_deployment(
        self, project_id: str, deployment_id: str, *, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentStatus:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        deployment = _validate_marketplace_uuid(deployment_id, "deployment_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployments/{deployment}",
            headers=await self._exact_company_headers(scoped_company))
        raise_if_error(response)
        return parse_company_blueprint_deployment_status(response.json())

    async def get_company_blueprint_deployment_head(
        self, project_id: str, *, company_id: str | None = None,
    ) -> CompanyBlueprintDeploymentHead | None:
        scoped_company = self._company_blueprint_company(company_id)
        project = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/company-blueprints/projects/{project}/deployment-head",
            headers=await self._exact_company_headers(scoped_company))
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_company_blueprint_deployment_head(response.json())

    async def register_executed_commercial_agreement(
        self,
        project_id: str,
        candidate: ExecutedCommercialAgreementCustodyCandidate | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = ExecutedCommercialAgreementCustodyCandidate.model_validate(
            candidate
        ).to_payload()
        _guard_request_body(payload, endpoint="commercial-agreements/executed/records")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "commercial-agreements/executed/records"
            ),
            json=payload,
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    async def get_executed_commercial_agreement(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"commercial-agreements/executed/records/{normalized_record_id}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    async def resolve_executed_commercial_agreement(
        self,
        project_id: str,
        agreement_ref: str,
        *,
        company_id: str | None = None,
    ) -> ExecutedCommercialAgreementRecord:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_ref = str(agreement_ref or "").strip()
        if re.fullmatch(r"agreement:docusign:[0-9a-f]{32}", clean_ref) is None:
            raise ValueError("agreement_ref is invalid")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "commercial-agreements/executed/records/resolve"
            ),
            params={"agreement_ref": clean_ref},
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_executed_commercial_agreement_record(response.json())

    async def register_golden_loop_catalog(
        self,
        project_id: str,
        request: GoldenLoopCatalogRegistrationRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCatalogVersion:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = GoldenLoopCatalogRegistrationRequest.model_validate(request).to_payload()
        _guard_request_body(payload, endpoint="golden-loop-catalogs")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-catalogs"
            ),
            json=payload,
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_catalog_version(response.json())

    async def get_golden_loop_catalog_version(
        self,
        project_id: str,
        catalog_version_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCatalogVersion:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_catalog_id = _validate_marketplace_uuid(
            catalog_version_id, "catalog_version_id"
        )
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"golden-loop-catalogs/{normalized_catalog_id}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_catalog_version(response.json())

    async def get_golden_loop_declaration_version(
        self,
        project_id: str,
        catalog_version_id: str,
        declaration_version_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopDeclarationVersion:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_catalog_id = _validate_marketplace_uuid(
            catalog_version_id, "catalog_version_id"
        )
        normalized_declaration_id = _validate_marketplace_uuid(
            declaration_version_id, "declaration_version_id"
        )
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"golden-loop-catalogs/{normalized_catalog_id}/declarations/"
                f"{normalized_declaration_id}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_declaration_version(response.json())

    async def propose_golden_loop_certification(
        self,
        project_id: str,
        request: GoldenLoopCertificationProposalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationCandidateStatus:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        payload = GoldenLoopCertificationProposalRequest.model_validate(
            request
        ).to_payload()
        _guard_request_body(payload, endpoint="golden-loop-certifications/candidates")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/candidates"
            ),
            json=payload,
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_certification_candidate_status(response.json())

    async def get_golden_loop_certification_candidate(
        self,
        project_id: str,
        candidate_id: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationCandidateStatus:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_candidate_id = _validate_marketplace_uuid(
            candidate_id, "candidate_id"
        )
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/candidates/"
                f"{normalized_candidate_id}"
            ),
            headers=await self._exact_company_headers(scoped_company),
        )
        raise_if_error(response)
        return parse_golden_loop_certification_candidate_status(response.json())

    async def get_current_golden_loop_certification(
        self,
        project_id: str,
        *,
        loop_ref: str,
        loop_version: str,
        environment_ref: str,
        company_id: str | None = None,
    ) -> GoldenLoopCertificationSpringRecord | None:
        scoped_company = self._company_blueprint_company(company_id)
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "golden-loop-certifications/current"
            ),
            params={
                "loop_ref": str(loop_ref or "").strip(),
                "loop_version": str(loop_version or "").strip(),
                "environment_ref": str(environment_ref or "").strip(),
            },
            headers=await self._exact_company_headers(scoped_company),
        )
        if response.status_code == 404:
            return None
        raise_if_error(response)
        return parse_golden_loop_certification_spring_record(response.json())

    async def get_golden_loop_economic_closure(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GoldenLoopEconomicClosureProjection:
        """Read Spring's canonical, non-mutating whole-run cost closure."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = canonical_golden_loop_run_ref(run_ref)
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/golden-loop-runs/"
                f"{clean_run_ref}/economic-closure"
            ),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_golden_loop_economic_closure(response.json())

    async def propose_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceProposalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceProposalReceipt:
        """Create or replay one exact Spring-owned invoice approval proposal."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceProposalRequest)
            else ContractToCashInvoiceProposalRequest.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="finance/contract-to-cash/invoice/proposals")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/finance/"
                "contract-to-cash/invoice/proposals"
            ),
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceProposalReceipt.model_validate(response.json())

    async def execute_contract_to_cash_invoice(
        self,
        project_id: str,
        request: ContractToCashInvoiceExecutionRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceWriteReceipt:
        """Consume an exact approval without treating provider acceptance as issuance."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceExecutionRequest)
            else ContractToCashInvoiceExecutionRequest.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="finance/contract-to-cash/invoice/executions")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/finance/"
                "contract-to-cash/invoice/executions"
            ),
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceWriteReceipt.model_validate(response.json())

    async def register_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        request: ContractToCashInvoiceIssuedRegistration | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceIssuedRecord:
        """Seal one exact reconciled invoice write/readback pair into Spring custody."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashInvoiceIssuedRegistration)
            else ContractToCashInvoiceIssuedRegistration.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="contract-to-cash/invoices/issued/records")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                "contract-to-cash/invoices/issued/records"
            ),
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceIssuedRecord.model_validate(response.json())

    async def get_contract_to_cash_invoice_issued(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ContractToCashInvoiceIssuedRecord:
        """Read one exact provider-observed invoice issuance custody record."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"contract-to-cash/invoices/issued/records/{normalized_record_id}"
            ),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashInvoiceIssuedRecord.model_validate(response.json())

    async def register_contract_to_cash_cash_collection(
        self,
        project_id: str,
        request: ContractToCashCashCollectionRegistration | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ContractToCashCashCollectionRecord:
        """Seal independent accounting and payout evidence as collected cash."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ContractToCashCashCollectionRegistration)
            else ContractToCashCashCollectionRegistration.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="contract-to-cash/cash-collections/records")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/cash-collections/records",
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashCashCollectionRecord.model_validate(response.json())

    async def get_contract_to_cash_cash_collection(
        self,
        project_id: str,
        record_id: str,
        *,
        company_id: str | None = None,
    ) -> ContractToCashCashCollectionRecord:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_record_id = _validate_marketplace_uuid(record_id, "record_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/cash-collections/records/{normalized_record_id}",
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashCashCollectionRecord.model_validate(response.json())

    async def start_contract_to_cash_run(
        self, project_id: str, request: ContractToCashRunStart | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, ContractToCashRunStart) else (
            ContractToCashRunStart.model_validate(request)
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    async def get_contract_to_cash_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> ContractToCashRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}",
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    async def attach_contract_to_cash_invoice_issued(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunRecordBinding | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunRecordBinding) else (
            ContractToCashRunRecordBinding.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/invoice-issued",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    async def attach_contract_to_cash_cash_collected(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunRecordBinding | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunRecordBinding) else (
            ContractToCashRunRecordBinding.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/cash-collected",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    async def cancel_contract_to_cash_before_invoice(
        self, project_id: str, run_ref: str,
        request: ContractToCashRunCancellation | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> ContractToCashRun:
        parsed = request if isinstance(request, ContractToCashRunCancellation) else (
            ContractToCashRunCancellation.model_validate(request)
        )
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/contract-to-cash/runs/{run_ref}/cancel",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return ContractToCashRun.model_validate(response.json())

    async def retain_period_reconciliation_scope(
        self,
        project_id: str,
        request: PeriodReconciliationScopeRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationScopeReceipt:
        parsed = request if isinstance(request, PeriodReconciliationScopeRequest) else (
            PeriodReconciliationScopeRequest.model_validate(request)
        )
        value = await self._post_period_reconciliation(
            project_id, "scopes", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationScopeReceipt.model_validate(value)

    async def start_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationStartRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationStartRequest) else (
            PeriodReconciliationStartRequest.model_validate(request)
        )
        value = await self._post_period_reconciliation(
            project_id, "runs", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    async def restart_period_reconciliation_run(
        self,
        project_id: str,
        request: PeriodReconciliationRestartRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationRestartRequest) else (
            PeriodReconciliationRestartRequest.model_validate(request)
        )
        value = await self._post_period_reconciliation(
            project_id, "runs/restarts", parsed.to_dict(), company_id=company_id
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    async def retain_period_reconciliation_quickbooks_reads(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationQuickBooksReadSetRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationReadSetReceipt:
        parsed = (
            request
            if isinstance(request, PeriodReconciliationQuickBooksReadSetRequest)
            else PeriodReconciliationQuickBooksReadSetRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._post_period_reconciliation(
            project_id,
            f"runs/{run}/quickbooks-read-sets",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationReadSetReceipt.model_validate(value)

    async def evaluate_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationEvaluationRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationEvaluationReceipt:
        parsed = (
            request
            if isinstance(request, PeriodReconciliationEvaluationRequest)
            else PeriodReconciliationEvaluationRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._post_period_reconciliation(
            project_id,
            f"runs/{run}/evaluations",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationEvaluationReceipt.model_validate(value)

    async def retain_period_reconciliation_review(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationReviewRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationReviewReceipt:
        parsed = request if isinstance(request, PeriodReconciliationReviewRequest) else (
            PeriodReconciliationReviewRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._post_period_reconciliation(
            project_id,
            f"runs/{run}/reviews",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationReviewReceipt.model_validate(value)

    async def advance_period_reconciliation_stage(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationStageRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        parsed = request if isinstance(request, PeriodReconciliationStageRequest) else (
            PeriodReconciliationStageRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._post_period_reconciliation(
            project_id,
            f"runs/{run}/stages",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    async def get_period_reconciliation_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> PeriodReconciliationRun:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._get_period_reconciliation(
            project_id, f"runs/{run}", company_id=company_id
        )
        return PeriodReconciliationRun.model_validate(value)

    async def get_period_reconciliation_outcomes(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> tuple[PeriodReconciliationOutcomeFact, ...]:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._get_period_reconciliation(
            project_id, f"runs/{run}/outcomes", company_id=company_id
        )
        return parse_period_reconciliation_outcomes(value)

    async def get_period_reconciliation_campaign_facts(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> tuple[PeriodReconciliationCampaignFact, ...]:
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._get_period_reconciliation(
            project_id, f"runs/{run}/campaign-facts", company_id=company_id
        )
        return parse_period_reconciliation_campaign_facts(value)

    async def fail_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        return await self._terminal_period_reconciliation_run(
            project_id, run_ref, "fail", request, company_id=company_id
        )

    async def cancel_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> PeriodReconciliationRunReceipt:
        return await self._terminal_period_reconciliation_run(
            project_id, run_ref, "cancel", request, company_id=company_id
        )

    async def _terminal_period_reconciliation_run(
        self,
        project_id: str,
        run_ref: str,
        action: str,
        request: PeriodReconciliationTerminalRequest | Mapping[str, Any],
        *,
        company_id: str | None,
    ) -> PeriodReconciliationRunReceipt:
        if action not in {"fail", "cancel"}:
            raise ValueError("Unreviewed Period Reconciliation terminal command")
        parsed = request if isinstance(request, PeriodReconciliationTerminalRequest) else (
            PeriodReconciliationTerminalRequest.model_validate(request)
        )
        run = _validate_period_reconciliation_run_ref(run_ref)
        value = await self._post_period_reconciliation(
            project_id,
            f"runs/{run}/{action}",
            parsed.to_dict(),
            company_id=company_id,
        )
        return PeriodReconciliationRunReceipt.model_validate(value)

    async def _post_period_reconciliation(
        self,
        project_id: str,
        suffix: str,
        payload: Mapping[str, Any],
        *,
        company_id: str | None,
    ) -> Any:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        _guard_request_body(payload, endpoint="finance/period-reconciliation")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}"
            f"/finance/period-reconciliation/{suffix}",
            json=dict(payload),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    async def _get_period_reconciliation(
        self,
        project_id: str,
        suffix: str,
        *,
        company_id: str | None,
    ) -> Any:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}"
            f"/finance/period-reconciliation/{suffix}",
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return response.json()

    async def start_economic_spine_run(
        self, project_id: str,
        request: EconomicSpineRunStart | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunStart) else (
            EconomicSpineRunStart.model_validate(request)
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    async def get_economic_spine_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> EconomicSpineRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.get(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}",
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    async def advance_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunTransition) else (
            EconomicSpineRunTransition.model_validate(request)
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}/transitions",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    async def fail_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return await self._command_economic_spine_run(
            project_id, run_ref, "fail", request, company_id=company_id
        )

    async def cancel_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return await self._command_economic_spine_run(
            project_id, run_ref, "cancel", request, company_id=company_id
        )

    async def mark_economic_spine_effect_ambiguous(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return await self._command_economic_spine_run(
            project_id, run_ref, "effect-ambiguous", request, company_id=company_id
        )

    async def reconcile_economic_spine_run(
        self, project_id: str, run_ref: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None = None,
    ) -> EconomicSpineRun:
        return await self._command_economic_spine_run(
            project_id, run_ref, "reconcile", request, company_id=company_id
        )

    async def _command_economic_spine_run(
        self, project_id: str, run_ref: str, action: str,
        request: EconomicSpineRunTransition | Mapping[str, Any], *,
        company_id: str | None,
    ) -> EconomicSpineRun:
        if action not in {"fail", "cancel", "effect-ambiguous", "reconcile"}:
            raise ValueError("Unreviewed Economic Spine command")
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = request if isinstance(request, EconomicSpineRunTransition) else (
            EconomicSpineRunTransition.model_validate(request)
        )
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/economic-spine/runs/{run_ref}/{action}",
            json=parsed.to_dict(), headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return EconomicSpineRun.model_validate(response.json())

    async def start_service_case_resolution(
        self,
        project_id: str,
        request: ServiceCaseResolutionStart | Mapping[str, Any],
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        parsed = (
            request
            if isinstance(request, ServiceCaseResolutionStart)
            else ServiceCaseResolutionStart.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="service/case-resolution-runs")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                "case-resolution-runs"
            ),
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    async def get_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}"
            ),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    async def advance_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}/advance"
            ),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    async def cancel_service_case_resolution(
        self,
        project_id: str,
        run_ref: str,
        *,
        reason: str,
        company_id: str | None = None,
    ) -> ServiceCaseResolutionRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"scr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical scr_ reference")
        payload = ServiceCaseResolutionCancel(reason=reason).to_dict()
        _guard_request_body(payload, endpoint="service/case-resolution-runs/cancel")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/service/"
                f"case-resolution-runs/{clean_run_ref}/cancel"
            ),
            json=payload,
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_service_case_resolution_run(response.json())

    async def list_governed_communication_sources(
        self,
        project_id: str,
        *,
        limit: int = 20,
        cursor: str | None = None,
        company_id: str | None = None,
    ) -> GovernedCommunicationSourcePage:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 50
        ):
            raise ValueError("limit must be an integer between 1 and 50")
        params: dict[str, Any] = {"limit": limit}
        if cursor is not None:
            clean_cursor = str(cursor or "").strip()
            if re.fullmatch(r"gcs_v1_[a-f0-9]{64}", clean_cursor) is None:
                raise ValueError("cursor must be a canonical gcs_v1 reference")
            params["cursor"] = clean_cursor
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                "governed-communication-runs/sources"
            ),
            params=params,
            headers=await self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_sources(response.json())

    async def start_governed_communication_run(
        self,
        project_id: str,
        request: GovernedCommunicationAdmission | Mapping[str, Any],
        *,
        idempotency_key: str,
        company_id: str | None = None,
    ) -> GovernedCommunicationAdmissionResult:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_key = str(idempotency_key or "").strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}", clean_key) is None:
            raise ValueError(
                "idempotency_key must match the 1-100 character communication contract"
            )
        parsed = (
            request
            if isinstance(request, GovernedCommunicationAdmission)
            else GovernedCommunicationAdmission.model_validate(request)
        )
        payload = parsed.to_dict()
        _guard_request_body(payload, endpoint="governed-communication-runs")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                "governed-communication-runs"
            ),
            json=payload,
            headers=await self._exact_company_headers(
                normalized_company_id, {"Idempotency-Key": clean_key}
            ),
        )
        raise_if_error(response)
        return parse_governed_communication_admission(response.json())

    async def step_governed_sales_touch(
        self, project_id: str, request: Mapping[str, Any], *,
        idempotency_key: str, company_id: str | None = None,
    ) -> Dict[str, Any]:
        """Prepare or reconcile one exact sales touch through Communication authority."""
        from lightbulb.company_sales_communication import _sales_proposal, _sales_result

        project = _validate_marketplace_uuid(project_id, "project_id")
        company = _validate_marketplace_uuid(company_id or self._active_company_id, "company_id")
        tenant = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        payload = _sales_proposal(request, idempotency_key)
        _guard_request_body(payload, endpoint="governed-communication-runs/sales-touches")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/tenants/{tenant}/companies/{company}/projects/{project}/governed-communication-runs/sales-touches",
            json=payload, headers=await self._exact_company_headers(company, {"Idempotency-Key": idempotency_key}),
        )
        raise_if_error(response)
        return _sales_result(response.json(), payload["touch"]["request_digest"])

    async def get_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GovernedCommunicationRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"gcr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical gcr_ reference")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                f"governed-communication-runs/{clean_run_ref}"
            ),
            headers=await self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_run(response.json())

    async def cancel_governed_communication_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> GovernedCommunicationRun:
        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        normalized_company_id = _validate_marketplace_uuid(
            company_id or self._active_company_id,
            "company_id",
        )
        tenant_id = _validate_marketplace_uuid(self._auth.tenant_id, "tenant_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"gcr_[a-f0-9]{32}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical gcr_ reference")
        client = await self._ensure_client()
        response = await client.post(
            (
                f"{self._base_url}/api/tenants/{tenant_id}/companies/"
                f"{normalized_company_id}/projects/{normalized_project_id}/"
                f"governed-communication-runs/{clean_run_ref}/actions/cancel"
            ),
            headers=await self._exact_company_headers(normalized_company_id),
        )
        raise_if_error(response)
        return parse_governed_communication_run(response.json())

    async def start_project_work_packet(
        self,
        project_id: str,
        *,
        company_id: str | None = None,
    ) -> ProjectWorkPacketStartResult:
        """Propose or start Spring's exact approved Project work packet."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        client = await self._ensure_client()
        response = await client.post(
            f"{self._base_url}/api/projects/{normalized_project_id}/work-packet-runs",
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_project_work_packet_start(response.json())

    async def get_project_work_packet_run(
        self,
        project_id: str,
        run_ref: str,
        *,
        company_id: str | None = None,
    ) -> ProjectWorkPacketRunRead:
        """Read one owned Project work-packet run without harness custody."""

        normalized_project_id = _validate_marketplace_uuid(project_id, "project_id")
        clean_run_ref = str(run_ref or "").strip()
        if re.fullmatch(r"dwr_[A-Za-z0-9_-]{16,64}", clean_run_ref) is None:
            raise ValueError("run_ref must be a canonical dwr_ reference")
        client = await self._ensure_client()
        response = await client.get(
            (
                f"{self._base_url}/api/projects/{normalized_project_id}/"
                f"work-packet-runs/{clean_run_ref}"
            ),
            headers=await self._exact_company_headers(company_id),
        )
        raise_if_error(response)
        return parse_project_work_packet_run(response.json())


    async def save_assessment_workspace(
        self, workspace: Any, *, run_ref: str, expected_revision: int,
    ) -> Dict[str, Any]:
        return await self._forward_declared_sync_operation(
            "save_assessment_workspace", workspace, run_ref=run_ref, expected_revision=expected_revision,
        )

    async def get_assessment_workspace(self, project_id: str, run_ref: str) -> Dict[str, Any] | None:
        return await self._forward_declared_sync_operation("get_assessment_workspace", project_id, run_ref)

    async def recover_assessment_workspace(
        self, workspace: Any, *, run_ref: str, expected_revision: int,
    ) -> Dict[str, Any] | None:
        return await self._forward_declared_sync_operation(
            "recover_assessment_workspace", workspace, run_ref=run_ref, expected_revision=expected_revision,
        )

    async def start_procurement_matched_close_run(
        self, project_id: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "start_procurement_matched_close_run",
            project_id,
            request,
            company_id=company_id,
        )

    async def submit_procurement_requisition(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "submit_procurement_requisition", project_id, run_ref, request,
            company_id=company_id,
        )

    async def approve_procurement_spend_commitment(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "approve_procurement_spend_commitment", project_id, run_ref, request,
            company_id=company_id,
        )

    async def bind_procurement_xero_purchase_order_readback(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "bind_procurement_xero_purchase_order_readback", project_id, run_ref,
            request, company_id=company_id,
        )

    async def record_procurement_goods_receipt(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "record_procurement_goods_receipt", project_id, run_ref, request,
            company_id=company_id,
        )

    async def record_procurement_supplier_invoice(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "record_procurement_supplier_invoice", project_id, run_ref, request,
            company_id=company_id,
        )

    async def derive_procurement_three_way_match(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "derive_procurement_three_way_match", project_id, run_ref, request,
            company_id=company_id,
        )

    async def approve_procurement_matched_close(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "approve_procurement_matched_close", project_id, run_ref, request,
            company_id=company_id,
        )

    async def get_procurement_matched_close_run(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "get_procurement_matched_close_run", project_id, run_ref,
            company_id=company_id,
        )

    async def get_procurement_matched_close_outcomes(
        self, project_id: str, run_ref: str, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "get_procurement_matched_close_outcomes", project_id, run_ref,
            company_id=company_id,
        )

    async def fail_procurement_matched_close_run(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "fail_procurement_matched_close_run", project_id, run_ref, request,
            company_id=company_id,
        )

    async def cancel_procurement_matched_close_run(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "cancel_procurement_matched_close_run", project_id, run_ref, request,
            company_id=company_id,
        )

    async def mark_procurement_purchase_order_ambiguous(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "mark_procurement_purchase_order_ambiguous", project_id, run_ref,
            request, company_id=company_id,
        )

    async def reconcile_procurement_purchase_order(
        self, project_id: str, run_ref: str, request: Any, *, company_id: str | None = None
    ) -> Any:
        return await self._forward_declared_sync_operation(
            "reconcile_procurement_purchase_order", project_id, run_ref, request,
            company_id=company_id,
        )

    async def list_customer_webhook_hints(self, project_id: str, *, connector_account_ref: str,
                                         start: str, end: str, cursor: dict | None = None,
                                         company_id: str | None = None) -> Dict[str, Any]:
        return await self._forward_declared_sync_operation("list_customer_webhook_hints", project_id,
            connector_account_ref=connector_account_ref, start=start, end=end, cursor=cursor, company_id=company_id)

    async def submit_customer_referral_event(self, project_id: str, event: dict, *, company_id: str | None = None):
        return await self._forward_declared_sync_operation("submit_customer_referral_event", project_id, event, company_id=company_id)

    async def get_customer_referral_event(self, project_id: str, event_id: str, *, company_id: str | None = None):
        return await self._forward_declared_sync_operation("get_customer_referral_event", project_id, event_id, company_id=company_id)

    async def list_customer_inbound_events(self, project_id: str, *, start: str, end: str,
                                          cursor: dict | None = None, company_id: str | None = None) -> Dict[str, Any]:
        return await self._forward_declared_sync_operation("list_customer_inbound_events",project_id,
            start=start,end=end,cursor=cursor,company_id=company_id)
