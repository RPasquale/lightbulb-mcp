"""Host-neutral identities for dynamic workflow harness sessions.

The adapters in this module are deliberately local and declarative. They do
not call a model provider, accept a workflow on a host's behalf, or establish
authorization. Callers must supply the scope already established by the
authenticated Lightbulb control plane; adapters only fail closed when the
workflow scope differs from that authority scope.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID

from lightbulb.dynamic_workflows import DynamicWorkflowScope, ScopeMismatchError


DYNAMIC_WORKFLOW_HOST_SESSION_SCHEMA = "lightbulb.dynamic_workflow_host_session.v1"

BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS = (
    "claude",
    "claude_code",
    "codex",
    "cursor",
    "chatgpt",
    "lightbulb",
)

_HARNESS_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_SESSION_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,79}$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_SCOPE_FIELDS = ("tenant_id", "company_id", "user_id", "project_ref")
_SCOPE_ALIASES = {
    "tenant_id": ("tenant_id", "tenantId"),
    "company_id": ("company_id", "companyId"),
    "user_id": ("user_id", "userId", "owner_user_id", "ownerUserId"),
    "project_ref": ("project_ref", "projectRef"),
}


class DynamicWorkflowHostError(ValueError):
    """Base class for deterministic host-adapter validation failures."""


class DynamicWorkflowScopeMismatch(DynamicWorkflowHostError):
    """Raised when workflow scope differs from authenticated authority scope."""


class DynamicWorkflowHostNotRegistered(DynamicWorkflowHostError):
    """Raised when no adapter is registered for a harness id."""


class DynamicWorkflowHostRegistrationError(DynamicWorkflowHostError):
    """Raised when an adapter cannot be safely registered."""


def _normalize_harness_id(value: object) -> str:
    if not isinstance(value, str):
        raise DynamicWorkflowHostError("harness_id must be a string")
    clean = value.strip().lower()
    if not _HARNESS_ID_RE.fullmatch(clean):
        raise DynamicWorkflowHostError("harness_id has an invalid format")
    return clean


def _normalize_opaque_text(
    value: object,
    *,
    field_name: str,
    max_length: int,
) -> str:
    if value is None:
        raise DynamicWorkflowHostError(f"{field_name} is required")
    if isinstance(value, UUID):
        clean = str(value)
    elif isinstance(value, str):
        clean = value.strip()
    else:
        raise DynamicWorkflowHostError(f"{field_name} must be a string or UUID")
    if not clean:
        raise DynamicWorkflowHostError(f"{field_name} must not be blank")
    if len(clean) > max_length:
        raise DynamicWorkflowHostError(f"{field_name} exceeds {max_length} characters")
    if _CONTROL_CHAR_RE.search(clean):
        raise DynamicWorkflowHostError(f"{field_name} contains control characters")
    return clean


def _normalize_scope(
    value: DynamicWorkflowScope | Mapping[str, object],
) -> DynamicWorkflowScope:
    """Coerce aliases into the canonical core scope without redefining it."""

    if isinstance(value, DynamicWorkflowScope):
        raw: Mapping[str, object] = {
            field_name: getattr(value, field_name)
            for field_name in _SCOPE_FIELDS
        }
    elif isinstance(value, Mapping):
        raw = value
    else:
        raise DynamicWorkflowHostError(
            "scope must be a DynamicWorkflowScope or mapping"
        )

    allowed_keys = {
        alias
        for aliases in _SCOPE_ALIASES.values()
        for alias in aliases
    }
    if any(key not in allowed_keys for key in raw):
        raise DynamicWorkflowHostError("scope contains unsupported fields")

    normalized: dict[str, str] = {}
    for field_name, aliases in _SCOPE_ALIASES.items():
        candidates = [raw[alias] for alias in aliases if alias in raw]
        if not candidates:
            raise DynamicWorkflowHostError(f"{field_name} is required")
        clean_candidates = {
            _normalize_opaque_text(
                candidate,
                field_name=field_name,
                max_length=200,
            )
            for candidate in candidates
        }
        if len(clean_candidates) != 1:
            raise DynamicWorkflowHostError(
                f"scope aliases disagree for {field_name}"
            )
        normalized[field_name] = clean_candidates.pop()

    try:
        model_validate = getattr(DynamicWorkflowScope, "model_validate", None)
        if callable(model_validate):
            return model_validate(normalized)
        return DynamicWorkflowScope(**normalized)
    except (TypeError, ValueError) as exc:
        raise DynamicWorkflowHostError("scope does not satisfy the core contract") from exc


def _assert_scope_matches(
    scope: DynamicWorkflowScope,
    authorized_scope: DynamicWorkflowScope | Mapping[str, object],
) -> None:
    """Compare all four dimensions; this does not establish authorization."""

    authority = _normalize_scope(authorized_scope)
    try:
        scope.require_exact(authority)
    except ScopeMismatchError as exc:
        mismatches = [
            field_name
            for field_name in _SCOPE_FIELDS
            if getattr(scope, field_name) != getattr(authority, field_name)
        ]
        raise DynamicWorkflowScopeMismatch(
            "dynamic workflow scope does not match authorized scope fields: "
            + ", ".join(mismatches)
        ) from exc


def _scope_to_dict(scope: DynamicWorkflowScope) -> dict[str, str]:
    return {
        field_name: str(getattr(scope, field_name))
        for field_name in _SCOPE_FIELDS
    }


class DynamicWorkflowHostCapability(str, Enum):
    SESSION_RESUME = "session.resume"
    SESSION_COMPACT = "session.compact"
    SESSION_FORK = "session.fork"
    TOOL_CALL = "tools.call"
    WORKSPACE_READ = "workspace.read"
    WORKSPACE_WRITE = "workspace.write"
    APPROVAL_REQUEST = "approval.request"
    STRUCTURED_OUTPUT = "output.structured"
    CONTEXT_EXTENSION = "context.extend"


@dataclass(frozen=True, slots=True)
class DynamicWorkflowHostCapabilities:
    """Observed host capabilities normalized to a bounded vocabulary."""

    values: frozenset[DynamicWorkflowHostCapability] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        normalized: set[DynamicWorkflowHostCapability] = set()
        try:
            for value in self.values:
                normalized.add(
                    value
                    if isinstance(value, DynamicWorkflowHostCapability)
                    else DynamicWorkflowHostCapability(str(value))
                )
        except ValueError as exc:
            raise DynamicWorkflowHostError("capabilities contain an unsupported value") from exc
        object.__setattr__(self, "values", frozenset(normalized))

    def supports(self, capability: DynamicWorkflowHostCapability) -> bool:
        return capability in self.values

    def to_list(self) -> list[str]:
        return sorted(capability.value for capability in self.values)


@dataclass(frozen=True, slots=True)
class DynamicWorkflowHostSessionIdentity:
    """Opaque, host-neutral session identity bound to exact Lightbulb scope."""

    harness_id: str
    opaque_session_id: str = field(repr=False)
    scope: DynamicWorkflowScope
    capabilities: DynamicWorkflowHostCapabilities = field(
        default_factory=DynamicWorkflowHostCapabilities
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "harness_id", _normalize_harness_id(self.harness_id))
        object.__setattr__(
            self,
            "opaque_session_id",
            _normalize_opaque_text(
                self.opaque_session_id,
                field_name="opaque_session_id",
                max_length=512,
            ),
        )
        if not isinstance(self.scope, DynamicWorkflowScope):
            raise DynamicWorkflowHostError("scope must be normalized before session creation")
        if not isinstance(self.capabilities, DynamicWorkflowHostCapabilities):
            raise DynamicWorkflowHostError(
                "capabilities must be normalized before session creation"
            )

    @property
    def session_binding_ref(self) -> str:
        """Return a domain-separated digest safe for persistence and logs."""

        digest = hashlib.sha256(
            (
                "lightbulb.dynamic_workflow_host_session\x00"
                + self.harness_id
                + "\x00"
                + self.opaque_session_id
            ).encode("utf-8")
        ).hexdigest()
        return "dwh_" + digest

    def to_dict(self) -> dict[str, object]:
        """Serialize without exposing the provider's raw session identifier."""

        return {
            "schema": DYNAMIC_WORKFLOW_HOST_SESSION_SCHEMA,
            "harness_id": self.harness_id,
            "session_binding_ref": self.session_binding_ref,
            "scope": _scope_to_dict(self.scope),
            "capabilities": self.capabilities.to_list(),
        }


@runtime_checkable
class DynamicWorkflowHostAdapter(Protocol):
    """Contract implemented by deterministic harness identity adapters."""

    @property
    def harness_id(self) -> str:
        ...

    def normalize_capabilities(
        self,
        capabilities: object,
    ) -> DynamicWorkflowHostCapabilities:
        ...

    def normalize_session_identity(
        self,
        session: object,
        *,
        scope: DynamicWorkflowScope | Mapping[str, object],
        authorized_scope: DynamicWorkflowScope | Mapping[str, object],
        capabilities: object = None,
    ) -> DynamicWorkflowHostSessionIdentity:
        ...


def _normalize_capability_alias(value: object) -> str:
    if isinstance(value, DynamicWorkflowHostCapability):
        return value.value
    if not isinstance(value, str):
        raise DynamicWorkflowHostError("capability names must be strings")
    clean = re.sub(r"[\s-]+", "_", value.strip().lower())
    if not clean or len(clean) > 120 or _CONTROL_CHAR_RE.search(clean):
        raise DynamicWorkflowHostError("capability name has an invalid format")
    return clean


@dataclass(frozen=True, slots=True)
class DeclarativeDynamicWorkflowHostAdapter:
    """Field/alias-only adapter; it has no provider transport or authority."""

    harness_id: str
    session_fields: tuple[str, ...]
    capability_aliases: Mapping[str, DynamicWorkflowHostCapability]

    def __post_init__(self) -> None:
        object.__setattr__(self, "harness_id", _normalize_harness_id(self.harness_id))
        if not self.session_fields:
            raise DynamicWorkflowHostRegistrationError(
                "host adapter requires at least one session field"
            )
        session_fields: list[str] = []
        for value in self.session_fields:
            if not isinstance(value, str) or not _SESSION_FIELD_RE.fullmatch(value):
                raise DynamicWorkflowHostRegistrationError(
                    "host adapter has an invalid session field"
                )
            if value not in session_fields:
                session_fields.append(value)

        normalized_aliases: dict[str, DynamicWorkflowHostCapability] = {
            capability.value: capability
            for capability in DynamicWorkflowHostCapability
        }
        for alias, capability in self.capability_aliases.items():
            try:
                clean_alias = _normalize_capability_alias(alias)
                clean_capability = (
                    capability
                    if isinstance(capability, DynamicWorkflowHostCapability)
                    else DynamicWorkflowHostCapability(str(capability))
                )
            except (DynamicWorkflowHostError, ValueError) as exc:
                raise DynamicWorkflowHostRegistrationError(
                    "host adapter has an invalid capability alias"
                ) from exc
            existing = normalized_aliases.get(clean_alias)
            if existing is not None and existing != clean_capability:
                raise DynamicWorkflowHostRegistrationError(
                    "host adapter capability aliases conflict"
                )
            normalized_aliases[clean_alias] = clean_capability

        object.__setattr__(self, "session_fields", tuple(session_fields))
        object.__setattr__(
            self,
            "capability_aliases",
            MappingProxyType(normalized_aliases),
        )

    def normalize_capabilities(
        self,
        capabilities: object,
    ) -> DynamicWorkflowHostCapabilities:
        if capabilities is None:
            return DynamicWorkflowHostCapabilities()
        if isinstance(capabilities, DynamicWorkflowHostCapabilities):
            return capabilities

        if isinstance(capabilities, Mapping):
            normalized: set[DynamicWorkflowHostCapability] = set()
            for label, enabled in capabilities.items():
                if type(enabled) is not bool:
                    raise DynamicWorkflowHostError(
                        "capability mappings require boolean values"
                    )
                alias = _normalize_capability_alias(label)
                capability = self.capability_aliases.get(alias)
                if capability is None:
                    raise DynamicWorkflowHostError(
                        f"unsupported capability for {self.harness_id}"
                    )
                if enabled:
                    normalized.add(capability)
            return DynamicWorkflowHostCapabilities(frozenset(normalized))

        labels: list[object]
        if isinstance(capabilities, (str, DynamicWorkflowHostCapability)):
            labels = [capabilities]
        elif isinstance(capabilities, Iterable) and not isinstance(
            capabilities, (bytes, bytearray)
        ):
            labels = list(capabilities)
        else:
            raise DynamicWorkflowHostError(
                "capabilities must be a mapping, iterable, or capability name"
            )

        normalized: set[DynamicWorkflowHostCapability] = set()
        for label in labels:
            alias = _normalize_capability_alias(label)
            capability = self.capability_aliases.get(alias)
            if capability is None:
                raise DynamicWorkflowHostError(
                    f"unsupported capability for {self.harness_id}"
                )
            normalized.add(capability)
        return DynamicWorkflowHostCapabilities(frozenset(normalized))

    def normalize_session_identity(
        self,
        session: object,
        *,
        scope: DynamicWorkflowScope | Mapping[str, object],
        authorized_scope: DynamicWorkflowScope | Mapping[str, object],
        capabilities: object = None,
    ) -> DynamicWorkflowHostSessionIdentity:
        normalized_scope = _normalize_scope(scope)
        _assert_scope_matches(normalized_scope, authorized_scope)

        payload_capabilities: object = None
        if isinstance(session, (str, UUID)):
            opaque_session_id = _normalize_opaque_text(
                session,
                field_name="opaque_session_id",
                max_length=512,
            )
        elif isinstance(session, Mapping):
            candidates = [
                session[field]
                for field in self.session_fields
                if field in session and session[field] is not None
            ]
            if not candidates:
                raise DynamicWorkflowHostError(
                    f"{self.harness_id} session payload has no recognized session identity"
                )
            clean_candidates = {
                _normalize_opaque_text(
                    candidate,
                    field_name="opaque_session_id",
                    max_length=512,
                )
                for candidate in candidates
            }
            if len(clean_candidates) != 1:
                raise DynamicWorkflowHostError(
                    f"{self.harness_id} session identity fields disagree"
                )
            opaque_session_id = clean_candidates.pop()
            payload_capabilities = session.get("capabilities")
        else:
            raise DynamicWorkflowHostError(
                "session must be an opaque string, UUID, or host payload mapping"
            )

        if capabilities is not None and payload_capabilities is not None:
            explicit = self.normalize_capabilities(capabilities)
            payload = self.normalize_capabilities(payload_capabilities)
            if explicit != payload:
                raise DynamicWorkflowHostError(
                    "explicit and session-payload capabilities disagree"
                )
            normalized_capabilities = explicit
        else:
            normalized_capabilities = self.normalize_capabilities(
                capabilities if capabilities is not None else payload_capabilities
            )

        return DynamicWorkflowHostSessionIdentity(
            harness_id=self.harness_id,
            opaque_session_id=opaque_session_id,
            scope=normalized_scope,
            capabilities=normalized_capabilities,
        )


class DynamicWorkflowHostRegistry:
    """Registry that dispatches normalization without dispatching host calls."""

    def __init__(
        self,
        adapters: Iterable[DynamicWorkflowHostAdapter] = (),
    ) -> None:
        self._adapters: dict[str, DynamicWorkflowHostAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    @property
    def harness_ids(self) -> tuple[str, ...]:
        return tuple(self._adapters)

    @property
    def adapters(self) -> Mapping[str, DynamicWorkflowHostAdapter]:
        return MappingProxyType(dict(self._adapters))

    def register(
        self,
        adapter: DynamicWorkflowHostAdapter,
        *,
        replace: bool = False,
    ) -> None:
        if not isinstance(adapter, DynamicWorkflowHostAdapter):
            raise DynamicWorkflowHostRegistrationError(
                "adapter does not implement DynamicWorkflowHostAdapter"
            )
        harness_id = _normalize_harness_id(adapter.harness_id)
        if harness_id in self._adapters and not replace:
            raise DynamicWorkflowHostRegistrationError(
                f"adapter already registered for {harness_id}"
            )
        self._adapters[harness_id] = adapter

    def get(self, harness_id: str) -> DynamicWorkflowHostAdapter:
        clean = _normalize_harness_id(harness_id)
        try:
            return self._adapters[clean]
        except KeyError as exc:
            raise DynamicWorkflowHostNotRegistered(
                f"no dynamic workflow adapter is registered for {clean}"
            ) from exc

    def normalize_capabilities(
        self,
        harness_id: str,
        capabilities: object,
    ) -> DynamicWorkflowHostCapabilities:
        return self.get(harness_id).normalize_capabilities(capabilities)

    def normalize_session_identity(
        self,
        harness_id: str,
        session: object,
        *,
        scope: DynamicWorkflowScope | Mapping[str, object],
        authorized_scope: DynamicWorkflowScope | Mapping[str, object],
        capabilities: object = None,
    ) -> DynamicWorkflowHostSessionIdentity:
        return self.get(harness_id).normalize_session_identity(
            session,
            scope=scope,
            authorized_scope=authorized_scope,
            capabilities=capabilities,
        )


_COMMON_CAPABILITY_ALIASES = {
    "resume_session": DynamicWorkflowHostCapability.SESSION_RESUME,
    "compact_session": DynamicWorkflowHostCapability.SESSION_COMPACT,
    "fork_session": DynamicWorkflowHostCapability.SESSION_FORK,
    "tool_use": DynamicWorkflowHostCapability.TOOL_CALL,
    "tool_calls": DynamicWorkflowHostCapability.TOOL_CALL,
    "read_workspace": DynamicWorkflowHostCapability.WORKSPACE_READ,
    "write_workspace": DynamicWorkflowHostCapability.WORKSPACE_WRITE,
    "request_approval": DynamicWorkflowHostCapability.APPROVAL_REQUEST,
    "structured_output": DynamicWorkflowHostCapability.STRUCTURED_OUTPUT,
    "context_extension": DynamicWorkflowHostCapability.CONTEXT_EXTENSION,
}


def _capability_aliases(
    **host_aliases: DynamicWorkflowHostCapability,
) -> Mapping[str, DynamicWorkflowHostCapability]:
    return {**_COMMON_CAPABILITY_ALIASES, **host_aliases}


BUILTIN_DYNAMIC_WORKFLOW_HOST_ADAPTERS = (
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="claude",
        session_fields=("session_id", "sessionId"),
        capability_aliases=_capability_aliases(),
    ),
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="claude_code",
        session_fields=(
            "claude_session_id",
            "claudeSessionId",
            "session_id",
            "sessionId",
        ),
        capability_aliases=_capability_aliases(),
    ),
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="codex",
        session_fields=("thread_id", "threadId", "session_id", "sessionId"),
        capability_aliases=_capability_aliases(
            resume_thread=DynamicWorkflowHostCapability.SESSION_RESUME,
            compact_thread=DynamicWorkflowHostCapability.SESSION_COMPACT,
            fork_thread=DynamicWorkflowHostCapability.SESSION_FORK,
        ),
    ),
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="cursor",
        session_fields=(
            "cursor_agent_id",
            "cursorAgentId",
            "session_id",
            "sessionId",
        ),
        capability_aliases=_capability_aliases(
            resume_agent=DynamicWorkflowHostCapability.SESSION_RESUME,
        ),
    ),
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="chatgpt",
        session_fields=(
            "conversation_id",
            "conversationId",
            "session_id",
            "sessionId",
        ),
        capability_aliases=_capability_aliases(
            resume_conversation=DynamicWorkflowHostCapability.SESSION_RESUME,
        ),
    ),
    DeclarativeDynamicWorkflowHostAdapter(
        harness_id="lightbulb",
        session_fields=(
            "workflow_run_id",
            "workflowRunId",
            "run_id",
            "runId",
            "session_id",
            "sessionId",
        ),
        capability_aliases=_capability_aliases(
            resume_run=DynamicWorkflowHostCapability.SESSION_RESUME,
        ),
    ),
)


def default_dynamic_workflow_host_registry() -> DynamicWorkflowHostRegistry:
    """Return a fresh registry containing the supported host adapters."""

    return DynamicWorkflowHostRegistry(BUILTIN_DYNAMIC_WORKFLOW_HOST_ADAPTERS)


__all__ = [
    "BUILTIN_DYNAMIC_WORKFLOW_HOST_ADAPTERS",
    "BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS",
    "DYNAMIC_WORKFLOW_HOST_SESSION_SCHEMA",
    "DeclarativeDynamicWorkflowHostAdapter",
    "DynamicWorkflowHostAdapter",
    "DynamicWorkflowHostCapabilities",
    "DynamicWorkflowHostCapability",
    "DynamicWorkflowHostError",
    "DynamicWorkflowHostNotRegistered",
    "DynamicWorkflowHostRegistrationError",
    "DynamicWorkflowHostRegistry",
    "DynamicWorkflowHostSessionIdentity",
    "DynamicWorkflowScopeMismatch",
    "default_dynamic_workflow_host_registry",
]
