"""User-owned native runtime transport. Spring owns approval, custody and delivery state.

No vendor executable, account login, or model API is assumed by this contract.
"""
from __future__ import annotations

from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from lightbulb.errors import raise_if_error

Harness = Literal["codex", "claude_code", "cursor"]
Status = Literal["queued", "claimed", "running", "waiting_for_user", "cancel_requested", "cancelled", "result_review", "failed"]


class NativeDeliveryEvidence(BaseModel):
    """Signed UTF-8 JSON from a configured independent observer, never a coding-agent claim."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    key_id: str = Field(min_length=1, max_length=120)
    payload: str = Field(min_length=1, max_length=16000)
    signature: str = Field(min_length=1, max_length=128)


class NativeDeliveryStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["lightbulb.native_coding_delivery.v1"] = Field(alias="schema")
    task_id: UUID
    project_id: UUID
    connection_id: UUID
    proposal_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    stage: Literal["awaiting_verification", "verified", "merged", "released", "installed", "evidence_held", "multiple_capabilities"]
    available: bool
    execution_authorized: Literal[False]
    checked_at: str
    evidence_digest: str | None = None
    gap_packet_digest: str | None = None
    source_context_digest: str | None = None
    capability_ref: str | None = None
    artifact_sha256: str | None = None
    package_version: str | None = None
    expires_at: str | None = None
    hold_reason: str | None = None
    issued_at: str | None = None
    repository: str | None = None
    pull_request_url: str | None = None
    source_commit: str | None = None
    merge_commit: str | None = None
    acceptance_digest: str | None = None
    deployment_target_ref: str | None = None
    dependencies: list[NativeDeliveryStatus] = Field(default_factory=list)


class RuntimeConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    project_id: UUID
    harness: Harness
    label: str = Field(min_length=1, max_length=120)
    protocol: Literal["lightbulb.native_coding_runtime.v1"]
    last_seen_at: str
    vendor_identity_attested: Literal[False]
    connection_secret: SecretStr | None = Field(default=None, repr=False)
    online: bool | None = None


class NativeCodingTask(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["lightbulb.native_coding_task.v1"] = Field(alias="schema")
    id: UUID
    project_id: UUID
    connection_id: UUID
    harness: Harness
    proposal_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_task_id: UUID
    status: Status
    revision: int = Field(ge=0)
    created_at: str
    updated_at: str | None = None
    independently_verified: Literal[False]
    business_resume_authorized: Literal[False]
    reconciliation_required: bool
    cancel_requested: bool = False
    reconcile_existing_execution_only: bool = False
    lease_expires_at: str | None = None
    runtime_session_ref: str | None = None
    question_approval_id: UUID | None = None
    summary: str | None = None
    result: dict[str, Any] | None = None
    packet: dict[str, Any] | None = Field(default=None, repr=False)
    events: list[dict[str, Any]] = Field(default_factory=list)


class NativeCodingReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: UUID
    expected_revision: int = Field(ge=0)
    claim_token: SecretStr = Field(repr=False)
    kind: Literal["started", "progress", "question", "completed", "failed", "cancelled"]
    summary: str = Field(min_length=1, max_length=10000)
    runtime_session_ref: str | None = Field(default=None, max_length=512)
    changed_files: list[str] = Field(default_factory=list, max_length=100)
    test_results: list[str] = Field(default_factory=list, max_length=100)
    pull_request_url: str | None = Field(default=None, max_length=2048)
    commit_sha: str | None = Field(default=None, max_length=64)

    def wire(self) -> dict[str, Any]:
        body = self.model_dump(mode="json", exclude_none=True)
        body["claim_token"] = _token(self.claim_token)
        if any(len(x) > 1024 for x in self.changed_files) or any(len(x) > 4096 for x in self.test_results):
            raise ValueError("Native coding evidence exceeds the transport limit")
        return body


def _token(value: SecretStr | str) -> str:
    import re
    text = value.get_secret_value() if isinstance(value, SecretStr) else value
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", text):
        raise ValueError("Invalid native coding custody token")
    return text


class _Channel:
    def __init__(self, client: Any, project_id: UUID | str):
        self._client = client
        self.project_id = UUID(str(project_id))
        self._base = f"{client._base_url}/api/projects/{self.project_id}/native-coding"

    def _task(self, value: Any, connection: UUID | str | None = None) -> NativeCodingTask:
        task = NativeCodingTask.model_validate(value)
        if task.project_id != self.project_id or (connection is not None and task.connection_id != UUID(str(connection))):
            raise ValueError("Native coding task scope mismatch")
        return task

    def _delivery_path(self, task: UUID | str, gap_packet_digest: str | None) -> str:
        import re
        if gap_packet_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", gap_packet_digest):
            raise ValueError("Exact gap packet digest required")
        return f"/tasks/{UUID(str(task))}/delivery" + (f"/{gap_packet_digest}" if gap_packet_digest else "")

    def _delivery(self, value: Any, task: UUID | str) -> NativeDeliveryStatus:
        status = NativeDeliveryStatus.model_validate(value)
        if status.project_id != self.project_id or status.task_id != UUID(str(task)):
            raise ValueError("Native delivery scope mismatch")
        if status.available and (status.stage != "installed" or not status.evidence_digest or not status.expires_at):
            raise ValueError("Native delivery availability lacks evidence")
        return status

    def _connection(self, value: Any) -> RuntimeConnection:
        connection = RuntimeConnection.model_validate(value)
        if connection.project_id != self.project_id:
            raise ValueError("Native coding connection scope mismatch")
        return connection

    def _runtime_path(self, connection: UUID | str, task: UUID | str | None, operation: str) -> str:
        path = f"/connections/{UUID(str(connection))}"
        if task is not None:
            path += f"/tasks/{UUID(str(task))}"
        return f"{path}/{operation}"


class NativeCodingClient(_Channel):
    """Synchronous projection of the canonical native coding channel."""
    def _call(self, method: str, path: str, body: Any = None, secret: SecretStr | str | None = None) -> Any:
        headers = dict(self._client._headers())
        if secret is not None:
            headers["X-Native-Coding-Secret"] = _token(secret)
        response = self._client._get_session().request(method, self._base + path, json=body, headers=headers)
        raise_if_error(response)
        return response.json()

    def connect(self, harness: Harness, label: str) -> RuntimeConnection:
        if harness not in {"codex", "claude_code", "cursor"} or not 1 <= len(label) <= 120:
            raise ValueError("Select a supported harness and bounded connection label")
        return self._connection(self._call("POST", "/connections", {"harness": harness, "label": label, "protocol": "lightbulb.native_coding_runtime.v1"}))

    def connections(self) -> list[RuntimeConnection]:
        return [self._connection(v) for v in self._call("GET", "/connections")]

    def prepare(self, connection: UUID | str, expected_digest: str | None = None, *, expected_gap_packet_digest: str | None = None) -> dict[str, Any] | NativeCodingTask:
        import re
        connection = UUID(str(connection))
        if expected_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            raise ValueError("Expected digest must be SHA-256")
        if expected_gap_packet_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_gap_packet_digest):
            raise ValueError("Expected gap packet digest must be SHA-256")
        body = {"connection_id": str(connection), "expected_digest": expected_digest}
        if expected_gap_packet_digest is not None:
            body["expected_gap_packet_digest"] = expected_gap_packet_digest
        value = self._call("POST", "/tasks", body)
        if value.get("schema") == "lightbulb.native_coding_task.v1":
            result = self._task(value, connection)
            if expected_digest is not None and result.proposal_digest != expected_digest:
                raise ValueError("Approved native task digest mismatch")
            return result
        if value.get("schema") != "lightbulb.project_native_coding_handoff.v1" or value.get("project_id") != str(self.project_id) or value.get("connection_id") != str(connection):
            raise ValueError("Native coding approval scope mismatch")
        return value

    def delivery(self, task: UUID | str, gap_packet_digest: str | None = None) -> NativeDeliveryStatus:
        return self._delivery(self._call("GET", self._delivery_path(task, gap_packet_digest)), task)

    def observe_delivery(self, task: UUID | str, evidence: NativeDeliveryEvidence) -> NativeDeliveryStatus:
        return self._delivery(self._call("POST", f"/tasks/{UUID(str(task))}/delivery", evidence.model_dump(mode="json")), task)

    def tasks(self) -> list[NativeCodingTask]:
        return [self._task(v) for v in self._call("GET", "/tasks")]

    def get(self, task: UUID | str, after: int = 0) -> NativeCodingTask:
        if after < 0:
            raise ValueError("Event cursor cannot be negative")
        return self._task(self._call("GET", f"/tasks/{UUID(str(task))}?after={after}"))

    def cancel(self, task: UUID | str) -> NativeCodingTask:
        return self._task(self._call("POST", f"/tasks/{UUID(str(task))}/cancel", {}))

    def poll(self, connection: UUID | str, secret: SecretStr | str) -> list[NativeCodingTask]:
        return [self._task(v, connection) for v in self._call("POST", self._runtime_path(connection, None, "poll"), {}, secret)]

    def custody(self, connection: UUID | str, secret: SecretStr | str, task: UUID | str, claim_token: SecretStr | str,
                operation: Literal["claim", "heartbeat", "reconcile", "decision"]) -> NativeCodingTask | dict[str, Any]:
        if operation not in {"claim", "heartbeat", "reconcile", "decision"}:
            raise ValueError("Unsupported custody operation")
        value = self._call("POST", self._runtime_path(connection, task, operation), {"claim_token": _token(claim_token)}, secret)
        if operation == "decision":
            if value.get("task_id") != str(UUID(str(task))) or value.get("decision") not in {"pending", "approved", "rejected"}:
                raise ValueError("Invalid runtime question decision")
            return value
        result = self._task(value, connection)
        if result.id != UUID(str(task)):
            raise ValueError("Native coding task identity mismatch")
        return result

    def report(self, connection: UUID | str, secret: SecretStr | str, task: UUID | str, report: NativeCodingReport) -> NativeCodingTask:
        result = self._task(self._call("POST", self._runtime_path(connection, task, "events"), report.wire(), secret), connection)
        if result.id != UUID(str(task)):
            raise ValueError("Native coding task identity mismatch")
        return result


class AsyncNativeCodingClient(_Channel):
    """Asynchronous projection of the canonical native coding channel."""
    async def _call(self, method: str, path: str, body: Any = None, secret: SecretStr | str | None = None) -> Any:
        headers = dict(await self._client._headers())
        if secret is not None:
            headers["X-Native-Coding-Secret"] = _token(secret)
        session = await self._client._ensure_client()
        response = await session.request(method, self._base + path, json=body, headers=headers)
        raise_if_error(response)
        return response.json()

    async def connect(self, harness: Harness, label: str) -> RuntimeConnection:
        if harness not in {"codex", "claude_code", "cursor"} or not 1 <= len(label) <= 120:
            raise ValueError("Select a supported harness and bounded connection label")
        return self._connection(await self._call("POST", "/connections", {"harness": harness, "label": label, "protocol": "lightbulb.native_coding_runtime.v1"}))

    async def connections(self) -> list[RuntimeConnection]:
        return [self._connection(v) for v in await self._call("GET", "/connections")]

    async def prepare(self, connection: UUID | str, expected_digest: str | None = None, *, expected_gap_packet_digest: str | None = None) -> dict[str, Any] | NativeCodingTask:
        import re
        connection = UUID(str(connection))
        if expected_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
            raise ValueError("Expected digest must be SHA-256")
        if expected_gap_packet_digest is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_gap_packet_digest):
            raise ValueError("Expected gap packet digest must be SHA-256")
        body = {"connection_id": str(connection), "expected_digest": expected_digest}
        if expected_gap_packet_digest is not None:
            body["expected_gap_packet_digest"] = expected_gap_packet_digest
        value = await self._call("POST", "/tasks", body)
        if value.get("schema") == "lightbulb.native_coding_task.v1":
            result = self._task(value, connection)
            if expected_digest is not None and result.proposal_digest != expected_digest:
                raise ValueError("Approved native task digest mismatch")
            return result
        if value.get("schema") != "lightbulb.project_native_coding_handoff.v1" or value.get("project_id") != str(self.project_id) or value.get("connection_id") != str(connection):
            raise ValueError("Native coding approval scope mismatch")
        return value

    async def delivery(self, task: UUID | str, gap_packet_digest: str | None = None) -> NativeDeliveryStatus:
        return self._delivery(await self._call("GET", self._delivery_path(task, gap_packet_digest)), task)

    async def observe_delivery(self, task: UUID | str, evidence: NativeDeliveryEvidence) -> NativeDeliveryStatus:
        return self._delivery(await self._call("POST", f"/tasks/{UUID(str(task))}/delivery", evidence.model_dump(mode="json")), task)

    async def tasks(self) -> list[NativeCodingTask]:
        return [self._task(v) for v in await self._call("GET", "/tasks")]

    async def get(self, task: UUID | str, after: int = 0) -> NativeCodingTask:
        if after < 0:
            raise ValueError("Event cursor cannot be negative")
        return self._task(await self._call("GET", f"/tasks/{UUID(str(task))}?after={after}"))

    async def cancel(self, task: UUID | str) -> NativeCodingTask:
        return self._task(await self._call("POST", f"/tasks/{UUID(str(task))}/cancel", {}))

    async def poll(self, connection: UUID | str, secret: SecretStr | str) -> list[NativeCodingTask]:
        return [self._task(v, connection) for v in await self._call("POST", self._runtime_path(connection, None, "poll"), {}, secret)]

    async def custody(self, connection: UUID | str, secret: SecretStr | str, task: UUID | str, claim_token: SecretStr | str,
                operation: Literal["claim", "heartbeat", "reconcile", "decision"]) -> NativeCodingTask | dict[str, Any]:
        if operation not in {"claim", "heartbeat", "reconcile", "decision"}:
            raise ValueError("Unsupported custody operation")
        value = await self._call("POST", self._runtime_path(connection, task, operation), {"claim_token": _token(claim_token)}, secret)
        if operation == "decision":
            if value.get("task_id") != str(UUID(str(task))) or value.get("decision") not in {"pending", "approved", "rejected"}:
                raise ValueError("Invalid runtime question decision")
            return value
        result = self._task(value, connection)
        if result.id != UUID(str(task)):
            raise ValueError("Native coding task identity mismatch")
        return result

    async def report(self, connection: UUID | str, secret: SecretStr | str, task: UUID | str, report: NativeCodingReport) -> NativeCodingTask:
        result = self._task(await self._call("POST", self._runtime_path(connection, task, "events"), report.wire(), secret), connection)
        if result.id != UUID(str(task)):
            raise ValueError("Native coding task identity mismatch")
        return result
