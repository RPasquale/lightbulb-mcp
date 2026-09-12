"""Typed Connector Execution contracts for SDK-native business workflows.

Production execution stays behind the authenticated Lightbulb control plane.
The in-memory adapter provides the same interface for project tests without
credentials, network access, or external side effects.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Literal,
    Mapping,
    Protocol,
    runtime_checkable,
)
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.errors import (
    AuthenticationError,
    LightbulbError,
    NotFoundError,
    PermissionDenied,
    RateLimitedError,
    ServerError,
    ValidationError as LightbulbValidationError,
)
from lightbulb.governed_connector_contracts import (
    EPHEMERAL_NON_REPLAYABLE_READ_TOOLS,
    GOVERNED_CONNECTOR_READ_TOOLS,
)


CONNECTOR_EXECUTION_REQUEST_SCHEMA = "lightbulb.connector_execution_request.v1"
CONNECTOR_EXECUTION_RESULT_SCHEMA = "lightbulb.connector_execution_result.v1"
CONNECTOR_EXECUTION_PROVENANCE_SCHEMA = "lightbulb.connector_execution_provenance.v1"

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$")

_GOVERNED_CHANNEL_EVIDENCE_READ_TOOLS = frozenset(
    {
        "slack.get_conversation_thread",
        "microsoft.get_channel_thread",
    }
)

_GOVERNED_EVIDENCE_READ_TOOLS = GOVERNED_CONNECTOR_READ_TOOLS

# Only server-reviewed governed reads may leave the SDK. The request's
# ``effect`` value is caller input, not authority; legacy connector reads stay
# fail-closed until Spring gives them the same exact route/provenance contract.
_HOSTED_READ_ONLY_TOOLS = _GOVERNED_EVIDENCE_READ_TOOLS

# The released-authority contract check pins these governed reads as hosted
# read-only admissions by literal; keep them inside the allowlist.
_RELEASED_AUTHORITY_PINNED_READ_TOOLS: tuple[str, ...] = (
    "stripe.list_balance_transactions",
    "xero.list_journals",
    "quickbooks.list_invoices",
    "quickbooks.list_bills",
    "quickbooks.list_payments",
    "xero.list_invoices",
    "xero.list_bills",
    "xero.list_payments",
)
STRIPE_LIST_BALANCE_TRANSACTIONS_TOOL = "stripe.list_balance_transactions"
_missing_pinned = [tool for tool in _RELEASED_AUTHORITY_PINNED_READ_TOOLS if tool not in _HOSTED_READ_ONLY_TOOLS]
if _missing_pinned:  # pragma: no cover - contract guard
    raise RuntimeError(f"hosted read-only admission is missing pinned governed reads: {_missing_pinned}")
_TRUSTED_WORKFLOW_IDENTITY_PROOF = object()
_TRUSTED_RUNTIME_AUTHORITY_PROOF = object()
_WORKFLOW_IDENTITY_METADATA_KEYS = frozenset(
    {
        "workflow_instance_id",
        "workflowInstanceId",
        "workflow_step_generation",
        "workflowStepGeneration",
        "step_generation",
        "stepGeneration",
        "step_id",
        "stepId",
    }
)


class ConnectorEffect(str, Enum):
    READ = "read"
    DRAFT = "draft"
    WRITE = "write"


class ConnectorExecutionStatus(str, Enum):
    COMPLETED = "completed"
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    BLOCKED = "blocked"
    FAILED = "failed"


class ConnectorErrorKind(str, Enum):
    VALIDATION_ERROR = "validation_error"
    AUTH_ERROR = "auth_error"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    VENDOR_ERROR = "vendor_error"
    TIMEOUT = "timeout"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    INTERNAL_ERROR = "internal_error"


class ConnectorExecutionProvenance(BaseModel):
    """Server-attested custody needed before an effect becomes workflow evidence.

    Ordinary connector callers do not need this envelope.  Materializers do:
    without an immutable request/account/approval/completion receipt they must
    treat a nominal connector success as insufficient evidence rather than mint
    a business-workflow receipt from caller-controlled claims.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: Literal["lightbulb.connector_execution_provenance.v1"] = Field(
        default=CONNECTOR_EXECUTION_PROVENANCE_SCHEMA,
        alias="schema",
    )
    tool: str
    tool_version: int = Field(ge=1)
    server_effect: ConnectorEffect
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    project_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    journal_ref: str = Field(min_length=1, max_length=200)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_ref: str | None = Field(default=None, min_length=1, max_length=200)
    approval_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    completed_at: str

    @field_validator("tool")
    @classmethod
    def _valid_tool(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _TOOL_NAME_RE.fullmatch(clean) or ".." in clean:
            raise ValueError("provenance tool must be a dotted Lightbulb Tool name")
        return clean

    @field_validator(
        "connector_account_ref",
        "journal_ref",
        "approval_ref",
    )
    @classmethod
    def _visible_refs(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if clean != value or any(ord(character) < 33 for character in clean):
            raise ValueError("provenance references must contain visible characters")
        return clean

    @field_validator("completed_at")
    @classmethod
    def _utc_timestamp(cls, value: str) -> str:
        clean = value.strip()
        try:
            parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("completed_at must be valid ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("completed_at must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @model_validator(mode="after")
    def _write_approval_evidence(self) -> "ConnectorExecutionProvenance":
        if self.server_effect == ConnectorEffect.WRITE and (
            self.approval_ref is None or self.approval_receipt_digest is None
        ):
            raise ValueError(
                "write provenance requires approval reference and receipt digest"
            )
        if (
            self.server_effect != ConnectorEffect.WRITE
            and self.approval_receipt_digest is not None
        ):
            raise ValueError("only write provenance may carry an approval receipt")
        return self


class ExecutionScope(BaseModel):
    """Opaque correlation scope; hosted adapters use authenticated client scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_ref: str = "authenticated"
    company_ref: str = "selected"
    project_ref: str = Field(min_length=1, max_length=160)
    project_id: UUID | None = None
    actor_ref: str | None = Field(default=None, max_length=160)

    @field_validator("tenant_ref", "company_ref", "project_ref", "actor_ref")
    @classmethod
    def _strip_refs(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean:
            raise ValueError("scope references must not be blank")
        return clean


@dataclass(frozen=True, slots=True)
class TrustedWorkflowIdentity:
    """Immutable identity minted only from a signature-v2-or-newer worker envelope.

    Request metadata is deliberately not accepted here: it is mutable caller
    input and therefore cannot bind a governed connector effect to a workflow
    cancellation generation.
    """

    workflow_instance_id: str
    step_id: str
    step_generation: int
    _proof: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._proof is not _TRUSTED_WORKFLOW_IDENTITY_PROOF:
            raise TypeError(
                "TrustedWorkflowIdentity must be minted from a verified envelope"
            )

    @classmethod
    def from_verified_envelope(cls, envelope: Any) -> "TrustedWorkflowIdentity":
        if int(getattr(envelope, "verified_signature_version", 0) or 0) < 2:
            raise ValueError(
                "workflow identity requires a signature-v2-or-newer envelope"
            )
        workflow = getattr(envelope, "workflow", None)
        step = getattr(envelope, "step", None)
        workflow_instance_id = str(getattr(workflow, "instance_id", "") or "").strip()
        step_id = str(getattr(step, "step_id", "") or "").strip()
        raw_generation = getattr(step, "step_generation", None)
        if not workflow_instance_id or not step_id or raw_generation is None:
            raise ValueError(
                "verified workflow identity requires instance, step, and generation"
            )
        try:
            workflow_instance_id = str(UUID(workflow_instance_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("workflow instance identity must be a UUID") from exc
        if len(step_id) > 100:
            raise ValueError("workflow step identity must be 1-100 characters")
        if isinstance(raw_generation, bool):
            raise ValueError("workflow step generation must be a non-negative integer")
        try:
            step_generation = int(raw_generation)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "workflow step generation must be a non-negative integer"
            ) from exc
        if step_generation < 0:
            raise ValueError("workflow step generation must be a non-negative integer")
        return cls(
            workflow_instance_id=workflow_instance_id,
            step_id=step_id,
            step_generation=step_generation,
            _proof=_TRUSTED_WORKFLOW_IDENTITY_PROOF,
        )


@dataclass(frozen=True, slots=True)
class _TrustedRuntimeAuthority:
    """Private transport authority paired with one verified worker envelope.

    The worker cannot verify Spring's HMAC signature, so the token remains
    non-authoritative until Spring verifies it again.  Decoding its public
    claims here is only a fail-fast consistency check that prevents a token
    from one envelope being paired with another envelope's signed scope.
    """

    token: str = field(repr=False)
    tenant_id: str
    company_id: str
    user_id: str
    project_id: str
    trace_id: str
    workflow_instance_id: str
    step_id: str
    step_generation: int
    agent_principal: str
    _proof: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._proof is not _TRUSTED_RUNTIME_AUTHORITY_PROOF:
            raise TypeError("runtime authority must be minted from a verified envelope")

    @classmethod
    def from_verified_envelope(
        cls,
        envelope: Any,
        workflow_identity: TrustedWorkflowIdentity,
    ) -> "_TrustedRuntimeAuthority | None":
        token = str(getattr(envelope, "runtime_authority_token", None) or "").strip()
        if not token:
            return None
        if int(getattr(envelope, "verified_signature_version", 0) or 0) < 2:
            raise ValueError(
                "runtime authority requires a signature-v2-or-newer envelope"
            )
        if len(token) > 16_384:
            raise ValueError("runtime authority token is invalid")

        user = getattr(envelope, "user", None)
        # Governed Connector Execution is always exact-company and
        # exact-project scoped. Company-wide envelopes may legitimately carry
        # another kind of runtime authority; leave those on the existing public
        # client route instead of making executor construction fail.
        if not getattr(user, "company_id", None) or not getattr(
            user, "project_id", None
        ):
            return None

        claims = _runtime_authority_claims(token)
        token_version = claims.get("v")
        if (
            isinstance(token_version, bool)
            or not isinstance(token_version, int)
            or token_version != 2
        ):
            raise ValueError(
                "governed worker runtime authority requires generation-bearing v2"
            )
        raw_generation = claims.get("workflow_step_generation")
        if (
            isinstance(raw_generation, bool)
            or not isinstance(raw_generation, int)
            or raw_generation < 0
            or raw_generation != workflow_identity.step_generation
        ):
            raise ValueError(
                "runtime authority does not match the verified envelope generation"
            )
        expected = {
            "tenant_id": _canonical_uuid(
                getattr(user, "tenant_id", None), "envelope tenant_id"
            ),
            "company_id": _canonical_uuid(
                getattr(user, "company_id", None), "envelope company_id"
            ),
            "user_id": _canonical_uuid(
                getattr(user, "user_id", None), "envelope user_id"
            ),
            "project_id": _canonical_uuid(
                getattr(user, "project_id", None), "envelope project_id"
            ),
            "trace_id": _exact_runtime_text(
                getattr(envelope, "trace_id", None), "envelope trace_id"
            ),
            "workflow_instance_id": workflow_identity.workflow_instance_id,
            "step_id": workflow_identity.step_id,
        }
        for name, value in expected.items():
            claim = _exact_runtime_text(claims.get(name), f"runtime {name}")
            if name.endswith("_id") and name not in {
                "trace_id",
                "workflow_instance_id",
                "step_id",
            }:
                claim = _canonical_uuid(claim, f"runtime {name}")
            if claim != value:
                raise ValueError(
                    "runtime authority does not match the verified envelope"
                )

        agent_principal = _exact_runtime_text(
            claims.get("agent_principal"), "runtime agent_principal"
        )
        return cls(
            token=token,
            tenant_id=expected["tenant_id"],
            company_id=expected["company_id"],
            user_id=expected["user_id"],
            project_id=expected["project_id"],
            trace_id=expected["trace_id"],
            workflow_instance_id=expected["workflow_instance_id"],
            step_id=expected["step_id"],
            step_generation=workflow_identity.step_generation,
            agent_principal=agent_principal,
            _proof=_TRUSTED_RUNTIME_AUTHORITY_PROOF,
        )


def _runtime_authority_claims(token: str) -> Mapping[str, Any]:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("runtime authority token is invalid")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError("runtime authority token is invalid") from exc
    if not isinstance(claims, Mapping):
        raise ValueError("runtime authority token is invalid")
    return claims


def _canonical_uuid(value: Any, label: str) -> str:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a UUID") from exc


def _exact_runtime_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} is required")
    if len(value) > 1_000 or any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} is invalid")
    return value


def _runtime_context_without_workflow_identity(
    metadata: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        str(key): value
        for key, value in metadata.items()
        if str(key) not in _WORKFLOW_IDENTITY_METADATA_KEYS
    }


class ConnectorExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=CONNECTOR_EXECUTION_REQUEST_SCHEMA, alias="schema")
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    scope: ExecutionScope
    connector_account_ref: str | None = Field(
        default=None, min_length=1, max_length=200
    )
    effect: ConnectorEffect = ConnectorEffect.READ
    approval_required: bool = False
    approval_ref: str | None = Field(default=None, max_length=200)
    preview_only: bool = False
    idempotency_key: str | None = Field(default=None, max_length=240)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool")
    @classmethod
    def _validate_tool(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _TOOL_NAME_RE.fullmatch(clean) or ".." in clean:
            raise ValueError("tool must be a dotted Lightbulb Tool name")
        return clean

    @field_validator("approval_ref", "idempotency_key", "connector_account_ref")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        return clean or None

    @model_validator(mode="after")
    def _writes_require_idempotency(self) -> "ConnectorExecutionRequest":
        if self.effect == ConnectorEffect.WRITE and not self.idempotency_key:
            raise ValueError("connector writes require an idempotency_key")
        return self

    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "tool": self.tool,
                "arguments": self.arguments,
                "effect": self.effect.value,
                "project_ref": self.scope.project_ref,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def custody_fingerprint(self) -> str:
        """Digest the exact request that a governed execution receipt must bind.

        ``fingerprint()`` intentionally retains its older, narrower idempotency
        semantics. Evidence-producing materializers bind the exact Tool inputs,
        project UUID/ref, account alias, server effect, and idempotency identity.
        Approval has its own immutable receipt digest so proposal and approved
        execution deliberately retain the same request digest; correlation
        metadata is not authority-bearing and is excluded.
        """

        canonical = json.dumps(
            {
                "schema": "lightbulb.connector_execution_custody.v1",
                "tool": self.tool,
                "arguments": self.arguments,
                "project_id": (
                    str(self.scope.project_id)
                    if self.scope.project_id is not None
                    else ""
                ),
                "project_ref": self.scope.project_ref,
                "connector_account_ref": self.connector_account_ref or "",
                "effect": self.effect.value,
                "idempotency_key": self.idempotency_key or "",
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ConnectorExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=CONNECTOR_EXECUTION_RESULT_SCHEMA, alias="schema")
    status: ConnectorExecutionStatus
    tool: str
    output: Dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    approval_ref: str | None = None
    approval_receipt_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_kind: ConnectorErrorKind | None = None
    error_code: str | None = None
    retryable: bool = False
    cached: bool = False
    provenance: ConnectorExecutionProvenance | None = None
    unverified_recovery_journal_locator: str | None = Field(
        default=None,
        min_length=36,
        max_length=36,
        description=(
            "Untrusted routing hint from a hosted ambiguity response; Spring must "
            "authenticate and reauthorize it before recovery."
        ),
    )

    @field_validator("unverified_recovery_journal_locator")
    @classmethod
    def _canonical_recovery_journal_locator(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            canonical = str(UUID(value))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "unverified_recovery_journal_locator must be a UUID"
            ) from exc
        if value != canonical:
            raise ValueError(
                "unverified_recovery_journal_locator must be a canonical UUID"
            )
        return canonical

    @model_validator(mode="after")
    def _valid_provenance(self) -> "ConnectorExecutionResult":
        if self.provenance is not None:
            if self.status != ConnectorExecutionStatus.COMPLETED:
                raise ValueError("only completed connector results carry provenance")
            if self.provenance.tool != self.tool:
                raise ValueError("connector provenance tool does not match result")
        ambiguous = self.error_code == "GOVERNED_EXECUTION_AMBIGUOUS"
        if ambiguous and (
            self.status != ConnectorExecutionStatus.FAILED or self.retryable
        ):
            raise ValueError(
                "an ambiguous connector result must be failed and non-retryable"
            )
        if self.unverified_recovery_journal_locator is not None and (
            self.status != ConnectorExecutionStatus.FAILED
            or not ambiguous
        ):
            raise ValueError(
                "only an ambiguous failed connector result carries an unverified "
                "recovery locator"
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


@runtime_checkable
class ConnectorExecutor(Protocol):
    def supports(self, tool: str) -> bool: ...

    def execute(
        self, request: ConnectorExecutionRequest
    ) -> ConnectorExecutionResult: ...


def _first_text(mapping: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _hosted_status(raw: Mapping[str, Any]) -> ConnectorExecutionStatus:
    """Map the Spring ``ToolResult.Status`` contract without optimistic fallbacks.

    ``POST /api/tools/invoke`` returns one of SUCCESS, FAILED, DENIED,
    HITL_REQUIRED, or TIMEOUT.  An absent or unfamiliar status is not evidence
    that a connector ran, so it must fail closed instead of being reported as
    completed.
    """

    status = str(raw.get("status") or raw.get("state") or "").strip().lower()
    approval_status = (
        str(raw.get("approvalStatus") or raw.get("approval_status") or "")
        .strip()
        .lower()
    )
    if status in {
        "hitl_required",
        "pending_approval",
        "needs_approval",
        "awaiting_approval",
    }:
        return ConnectorExecutionStatus.PENDING_APPROVAL
    if approval_status in {"pending", "requested", "awaiting_approval"}:
        return ConnectorExecutionStatus.PENDING_APPROVAL
    if status in {"blocked", "denied", "rejected"}:
        return ConnectorExecutionStatus.BLOCKED
    if status in {"failed", "error", "cancelled", "timeout"}:
        return ConnectorExecutionStatus.FAILED
    if status == "success":
        return ConnectorExecutionStatus.COMPLETED
    return ConnectorExecutionStatus.FAILED


def _hosted_failure_details(
    raw: Mapping[str, Any], status: ConnectorExecutionStatus
) -> tuple[ConnectorErrorKind | None, str | None, bool]:
    server_status = str(raw.get("status") or raw.get("state") or "").strip().lower()
    server_error_code = _first_text(raw, "errorCode", "error_code")
    if status == ConnectorExecutionStatus.BLOCKED:
        return (
            ConnectorErrorKind.PERMISSION_DENIED,
            server_error_code or "tool_execution_denied",
            False,
        )
    if status != ConnectorExecutionStatus.FAILED:
        return None, server_error_code, False
    if server_status == "timeout":
        return (
            ConnectorErrorKind.TIMEOUT,
            server_error_code or "tool_execution_timeout",
            True,
        )
    if server_status in {"failed", "error", "cancelled"}:
        return (
            ConnectorErrorKind.VENDOR_ERROR,
            server_error_code or "tool_execution_failed",
            bool(raw.get("retryable", False)),
        )
    return ConnectorErrorKind.INTERNAL_ERROR, "invalid_tool_result_status", False


def _hosted_unverified_recovery_journal_locator(
    raw: Mapping[str, Any],
    status: ConnectorExecutionStatus,
    error_code: str | None,
) -> str | None:
    """Return a syntactically valid, explicitly unverified recovery locator.

    The identifier is routing data that an authenticated Spring recovery API
    must independently authorize; it is not completion provenance or evidence.
    It is retained only for the exact fail-closed ambiguity contract and never
    inferred from nested provider output or caller metadata.
    """

    if (
        status != ConnectorExecutionStatus.FAILED
        or error_code != "GOVERNED_EXECUTION_AMBIGUOUS"
    ):
        return None
    value = raw.get("journalId")
    if not isinstance(value, str):
        return None
    try:
        canonical = str(UUID(value))
    except ValueError:
        return None
    return canonical if value == canonical else None


def _hosted_approval_ref(raw: Mapping[str, Any]) -> str | None:
    direct = _first_text(
        raw,
        "approvalRef",
        "approval_ref",
        "approvalTaskId",
        "approval_task_id",
    )
    if direct:
        return direct
    metadata = raw.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    return _first_text(
        metadata,
        "approvalRef",
        "approval_ref",
        "approvalTaskId",
        "approval_task_id",
    )


def _failure_from_exception(tool: str, exc: LightbulbError) -> ConnectorExecutionResult:
    if isinstance(exc, AuthenticationError):
        kind = ConnectorErrorKind.AUTH_ERROR
        message = "Connector authentication failed."
    elif isinstance(exc, PermissionDenied):
        kind = ConnectorErrorKind.PERMISSION_DENIED
        message = "Connector invocation was not permitted."
    elif isinstance(exc, NotFoundError):
        kind = ConnectorErrorKind.NOT_FOUND
        message = "The requested connector Tool was not found."
    elif isinstance(exc, RateLimitedError):
        kind = ConnectorErrorKind.RATE_LIMITED
        message = "Connector invocation was rate limited."
    elif isinstance(exc, LightbulbValidationError):
        kind = ConnectorErrorKind.VALIDATION_ERROR
        message = "Connector invocation failed validation."
    elif isinstance(exc, ServerError):
        kind = ConnectorErrorKind.INTERNAL_ERROR
        message = "The connector runtime was unavailable."
    else:
        kind = ConnectorErrorKind.VENDOR_ERROR
        message = "Connector invocation failed."
    return ConnectorExecutionResult(
        status=ConnectorExecutionStatus.FAILED,
        tool=tool,
        # Never copy a remote exception string into an agent-visible receipt. A
        # vendor or intermediary may have echoed credentials in its error text.
        message=message,
        error_kind=kind,
        error_code=getattr(exc, "error_code", None) or exc.__class__.__name__,
        retryable=isinstance(exc, (RateLimitedError, ServerError)),
    )


class HostedConnectorExecutor:
    """Connector adapter backed by Spring-owned effect and approval authority.

    Verified reads preserve the legacy hosted route. Writes use Governed
    Connector Execution, where the server catalog (not this request's effect),
    exact ApprovalTask binding, and durable idempotency journal decide whether
    dispatch is permitted.
    """

    def __init__(
        self,
        client: Any,
        *,
        available_tools: Iterable[str] | None = None,
        workflow_identity: TrustedWorkflowIdentity | None = None,
        _runtime_authority: _TrustedRuntimeAuthority | None = None,
    ) -> None:
        if workflow_identity is not None and not isinstance(
            workflow_identity, TrustedWorkflowIdentity
        ):
            raise TypeError("workflow_identity must be minted from a verified envelope")
        if _runtime_authority is not None and not isinstance(
            _runtime_authority, _TrustedRuntimeAuthority
        ):
            raise TypeError("runtime authority must be minted from a verified envelope")
        self._client = client
        self._workflow_identity = workflow_identity
        self._runtime_authority = _runtime_authority
        self._available_tools = (
            {str(tool).strip().lower() for tool in available_tools}
            if available_tools is not None
            else None
        )

    @classmethod
    def from_verified_envelope(
        cls,
        client: Any,
        envelope: Any,
        *,
        available_tools: Iterable[str] | None = None,
    ) -> "HostedConnectorExecutor":
        workflow_identity = TrustedWorkflowIdentity.from_verified_envelope(envelope)
        return cls(
            client,
            available_tools=available_tools,
            workflow_identity=workflow_identity,
            _runtime_authority=_TrustedRuntimeAuthority.from_verified_envelope(
                envelope,
                workflow_identity,
            ),
        )

    def supports(self, tool: str) -> bool:
        return (
            self._available_tools is None
            or tool.strip().lower() in self._available_tools
        )

    def execute(self, request: ConnectorExecutionRequest) -> ConnectorExecutionResult:
        if not self.supports(request.tool):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="The configured project does not expose this Tool.",
                error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
                error_code="tool_not_available",
            )
        if request.preview_only and request.effect == ConnectorEffect.WRITE:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.PREVIEW,
                tool=request.tool,
                message="Preview only; no connector write was invoked.",
                output={"proposed": True, "tool": request.tool},
            )
        if request.effect == ConnectorEffect.WRITE and request.scope.project_id is None:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="Hosted connector write requires an authenticated project UUID.",
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="project_scope_required",
            )
        if (
            request.effect == ConnectorEffect.WRITE
            and not request.connector_account_ref
        ):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="Hosted connector write requires an exact project account reference.",
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="connector_account_ref_required",
            )
        if request.effect == ConnectorEffect.DRAFT:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="Hosted connector drafts are local-only and were not invoked.",
                error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
                error_code="hosted_draft_local_only",
            )
        if (
            request.tool in EPHEMERAL_NON_REPLAYABLE_READ_TOOLS
            and request.idempotency_key
        ):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message=(
                    "This private-row read must be refreshed and cannot use an "
                    "idempotency replay key."
                ),
                error_kind=ConnectorErrorKind.VALIDATION_ERROR,
                error_code="ephemeral_read_idempotency_unsupported",
            )
        if request.tool in _GOVERNED_CHANNEL_EVIDENCE_READ_TOOLS:
            channel_capability = getattr(
                self._client,
                "supports_governed_channel_read",
                None,
            )
            if (
                not callable(channel_capability)
                or channel_capability(request.tool) is not True
            ):
                return ConnectorExecutionResult(
                    status=ConnectorExecutionStatus.BLOCKED,
                    tool=request.tool,
                    message=(
                        "Hosted channel reads require the reviewed communication "
                        "worker capability."
                    ),
                    error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                    error_code="hosted_channel_read_capability_required",
                )
        if (
            request.effect == ConnectorEffect.READ
            and request.tool not in _HOSTED_READ_ONLY_TOOLS
        ):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message=(
                    "The hosted connector Tool is not in the platform-owned "
                    "read-only dispatch catalog."
                ),
                error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
                error_code="hosted_tool_effect_unverified",
            )
        if request.tool in _GOVERNED_EVIDENCE_READ_TOOLS and (
            request.scope.project_id is None or not request.connector_account_ref
        ):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message=(
                    "Evidence-producing connector reads require an exact project "
                    "and connector account reference."
                ),
                error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                error_code="connector_route_scope_required",
            )
        try:
            scope_kwargs = (
                {"project_id": str(request.scope.project_id)}
                if request.scope.project_id is not None
                else {}
            )
            governance_kwargs: Dict[str, Any] = {}
            workflow_kwargs: Dict[str, Any] = {}
            if self._workflow_identity is not None:
                workflow_kwargs = {
                    "workflow_instance_id": (
                        self._workflow_identity.workflow_instance_id
                    ),
                    "workflow_step_generation": (
                        self._workflow_identity.step_generation
                    ),
                    "step_id": self._workflow_identity.step_id,
                }
            governed_execution = request.effect == ConnectorEffect.WRITE or (
                request.tool in _GOVERNED_EVIDENCE_READ_TOOLS
            )
            if governed_execution:
                # A missing approval_ref is intentional: Spring turns this exact
                # write into a durable human ApprovalTask and returns its opaque ref.
                governance_kwargs = {
                    "project_ref": request.scope.project_ref,
                    "connector_account_ref": request.connector_account_ref,
                    "idempotency_key": request.idempotency_key,
                    "approval_ref": request.approval_ref,
                    "runtime_context": _runtime_context_without_workflow_identity(
                        request.metadata
                    ),
                    "effect": request.effect.value,
                }
                if self._runtime_authority is not None:
                    if (
                        request.scope.project_id is None
                        or str(request.scope.project_id)
                        != self._runtime_authority.project_id
                    ):
                        return ConnectorExecutionResult(
                            status=ConnectorExecutionStatus.BLOCKED,
                            tool=request.tool,
                            message=(
                                "Connector request project does not match the verified "
                                "runtime authority."
                            ),
                            error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                            error_code="runtime_authority_scope_mismatch",
                        )
                    governance_kwargs["_runtime_authority"] = self._runtime_authority
            raw = self._client.invoke_tool(
                request.tool,
                dict(request.arguments),
                **scope_kwargs,
                **governance_kwargs,
                **workflow_kwargs,
            )
        except LightbulbError as exc:
            return _failure_from_exception(request.tool, exc)
        return self._result(request, raw, governed_execution=governed_execution)

    def lookup_receipt(self, request: ConnectorExecutionRequest) -> ConnectorExecutionResult:
        """Authenticated journal read, with the exact normal provenance checks."""
        if self._runtime_authority is not None or self._workflow_identity is not None:
            raise ValueError("public receipt lookup requires an authenticated user client")
        if not self.supports(request.tool):
            raise ValueError("Tool is not exposed by this executor")
        raw = self._client.lookup_connector_receipt(request)
        return self._result(request, raw, governed_execution=True)

    @staticmethod
    def _result(request, raw, *, governed_execution):
        if not isinstance(raw, Mapping):
            raw = {"result": raw}
        status = _hosted_status(raw)
        raw_metadata = raw.get("metadata")
        replayed = (
            isinstance(raw_metadata, Mapping) and raw_metadata.get("replayed") is True
        )
        error_kind, error_code, default_retryable = _hosted_failure_details(raw, status)
        provenance: ConnectorExecutionProvenance | None = None
        provenance_required = request.effect == ConnectorEffect.WRITE or (
            request.tool in _GOVERNED_EVIDENCE_READ_TOOLS
        )
        if status == ConnectorExecutionStatus.COMPLETED and "provenance" in raw:
            try:
                provenance = ConnectorExecutionProvenance.model_validate(
                    raw.get("provenance")
                )
            except Exception:
                return ConnectorExecutionResult(
                    status=ConnectorExecutionStatus.FAILED,
                    tool=request.tool,
                    message="Connector execution provenance failed validation.",
                    error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                    error_code="invalid_execution_provenance",
                    retryable=False,
                )
            if (
                request.scope.project_id is None
                or provenance.project_id != request.scope.project_id
                or provenance.server_effect != request.effect
                or provenance.connector_account_ref != request.connector_account_ref
                or provenance.approval_ref != request.approval_ref
                or provenance.request_digest != request.custody_fingerprint()
            ):
                return ConnectorExecutionResult(
                    status=ConnectorExecutionStatus.FAILED,
                    tool=request.tool,
                    message="Connector execution provenance did not match the request.",
                    error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                    error_code="execution_provenance_mismatch",
                    retryable=False,
                )
        elif status == ConnectorExecutionStatus.COMPLETED and provenance_required:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.FAILED,
                tool=request.tool,
                message="Connector execution did not return server provenance.",
                error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                error_code="execution_provenance_missing",
                retryable=False,
            )
        result_output: Dict[str, Any] = dict(raw)
        if status == ConnectorExecutionStatus.COMPLETED and governed_execution:
            provider_output = raw.get("output")
            if not isinstance(provider_output, Mapping):
                return ConnectorExecutionResult(
                    status=ConnectorExecutionStatus.FAILED,
                    tool=request.tool,
                    message="Governed connector receipt has no provider output object.",
                    error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                    error_code="invalid_execution_output",
                    retryable=False,
                )
            result_output = dict(provider_output)
        return ConnectorExecutionResult(
            status=status,
            tool=request.tool,
            output=result_output,
            message=_first_text(raw, "message", "summary", "reply") or "",
            approval_ref=(
                _hosted_approval_ref(raw)
                if status == ConnectorExecutionStatus.PENDING_APPROVAL
                else None
            ),
            approval_receipt_digest=(
                _first_text(raw, "approvalReceiptDigest", "approval_receipt_digest")
                if status == ConnectorExecutionStatus.PENDING_APPROVAL
                else None
            ),
            error_kind=error_kind,
            error_code=error_code,
            retryable=(
                False
                if error_code == "GOVERNED_EXECUTION_AMBIGUOUS"
                else (
                    bool(raw.get("retryable", default_retryable))
                    if status == ConnectorExecutionStatus.FAILED
                    else False
                )
            ),
            cached=status == ConnectorExecutionStatus.COMPLETED and replayed,
            provenance=provenance,
            unverified_recovery_journal_locator=(
                _hosted_unverified_recovery_journal_locator(raw, status, error_code)
            ),
        )


ConnectorHandler = Callable[
    [ConnectorExecutionRequest],
    Mapping[str, Any] | ConnectorExecutionResult,
]


class InMemoryConnectorExecutor:
    """Deterministic connector adapter for project tests and local simulation."""

    def __init__(
        self,
        handlers: Mapping[str, ConnectorHandler] | None = None,
        *,
        strict_approvals: bool = True,
    ) -> None:
        self._handlers: Dict[str, ConnectorHandler] = {}
        self._requests: list[ConnectorExecutionRequest] = []
        self._cache: Dict[tuple[str, str], tuple[str, ConnectorExecutionResult]] = {}
        self.strict_approvals = strict_approvals
        for tool, handler in (handlers or {}).items():
            self.register(tool, handler)

    @property
    def requests(self) -> tuple[ConnectorExecutionRequest, ...]:
        return tuple(self._requests)

    def register(self, tool: str, handler: ConnectorHandler) -> None:
        normalized = tool.strip().lower()
        if not _TOOL_NAME_RE.fullmatch(normalized) or ".." in normalized:
            raise ValueError("tool must be a dotted Lightbulb Tool name")
        self._handlers[normalized] = handler

    def supports(self, tool: str) -> bool:
        return tool.strip().lower() in self._handlers

    def execute(self, request: ConnectorExecutionRequest) -> ConnectorExecutionResult:
        self._requests.append(request)
        if request.preview_only and request.effect == ConnectorEffect.WRITE:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.PREVIEW,
                tool=request.tool,
                message="Preview only; the in-memory handler was not invoked.",
                output={"proposed": True, "tool": request.tool},
            )
        if (
            self.strict_approvals
            and request.effect == ConnectorEffect.WRITE
            and request.approval_required
            and not request.approval_ref
        ):
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.PENDING_APPROVAL,
                tool=request.tool,
                message="Connector write requires an approval reference.",
                output={"proposed": True, "tool": request.tool},
            )
        handler = self._handlers.get(request.tool)
        if handler is None:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.BLOCKED,
                tool=request.tool,
                message="No in-memory connector handler is registered.",
                error_kind=ConnectorErrorKind.UNSUPPORTED_OPERATION,
                error_code="handler_not_registered",
            )

        cache_key: tuple[str, str] | None = None
        fingerprint = request.fingerprint()
        if request.idempotency_key:
            cache_key = (request.tool, request.idempotency_key)
            cached = self._cache.get(cache_key)
            if cached:
                cached_fingerprint, cached_result = cached
                if cached_fingerprint != fingerprint:
                    return ConnectorExecutionResult(
                        status=ConnectorExecutionStatus.FAILED,
                        tool=request.tool,
                        message="Idempotency key was reused with different inputs.",
                        error_kind=ConnectorErrorKind.IDEMPOTENCY_CONFLICT,
                        error_code="idempotency_payload_mismatch",
                    )
                return cached_result.model_copy(update={"cached": True})

        try:
            raw = handler(request)
        except Exception:
            return ConnectorExecutionResult(
                status=ConnectorExecutionStatus.FAILED,
                tool=request.tool,
                message="The in-memory connector handler failed.",
                error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                error_code="handler_failed",
            )
        if isinstance(raw, ConnectorExecutionResult):
            result = raw
        else:
            result = ConnectorExecutionResult(
                status=ConnectorExecutionStatus.COMPLETED,
                tool=request.tool,
                output=dict(raw),
            )
        if cache_key and result.status == ConnectorExecutionStatus.COMPLETED:
            self._cache[cache_key] = (fingerprint, result)
        return result


__all__ = [
    "CONNECTOR_EXECUTION_PROVENANCE_SCHEMA",
    "CONNECTOR_EXECUTION_REQUEST_SCHEMA",
    "CONNECTOR_EXECUTION_RESULT_SCHEMA",
    "ConnectorEffect",
    "ConnectorErrorKind",
    "ConnectorExecutionRequest",
    "ConnectorExecutionProvenance",
    "ConnectorExecutionResult",
    "ConnectorExecutionStatus",
    "ConnectorExecutor",
    "ExecutionScope",
    "HostedConnectorExecutor",
    "InMemoryConnectorExecutor",
    "TrustedWorkflowIdentity",
]
