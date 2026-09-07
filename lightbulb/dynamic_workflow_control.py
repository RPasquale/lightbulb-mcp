"""Atomic role custody and assignment leasing for Dynamic Project Workflows.

The outer checkpoint is the single compare-and-swap unit.  It embeds the core
runtime checkpoint, role bindings, bounded replay history, and assignment lease
history, so a core transition and custody consumption cannot commit separately.
Raw host session identifiers and continuation/assignment receipts are never
persisted.  Receipts are restart-stable HMAC capabilities derived on demand.

Context Broker writes are deliberately outside this state machine.  A hosted
adapter commits a deterministic, idempotent Context Broker checkpoint first,
then supplies its opaque receipt through the trusted controller argument.  If
the outer workflow CAS loses a race, the adapter retries the exact mutation (or
repairs the already-committed context checkpoint) as a small saga.  The single
outer workflow checkpoint remains the only workflow CAS boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Protocol
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.dynamic_workflow_hosts import (
    BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS,
    DynamicWorkflowHostRegistry,
    default_dynamic_workflow_host_registry,
)
from lightbulb.dynamic_workflow_runtime import (
    DynamicWorkflowCheckpoint,
    DynamicWorkflowCheckpointConflict,
    DynamicWorkflowRuntime,
    InMemoryDynamicWorkflowCheckpointStore,
)
from lightbulb.dynamic_workflow_scope_resolution import (
    canonical_dynamic_workflow_company_ref,
)
from lightbulb.dynamic_workflow_mcp import (
    validate_operation_exchange,
    validate_operation_input,
)
from lightbulb.dynamic_workflows import (
    AcceptanceCriterion,
    BuilderAssignment,
    BuilderOutcome,
    BuilderResult,
    CriterionEvaluation,
    DynamicWorkflowScope,
    EvaluatorDecision,
    EvaluatorVerdict,
    EvidenceRef,
    PlannerPlan,
    UsageDelta,
    WorkflowLimits,
    WorkflowRunStatus,
)


DYNAMIC_WORKFLOW_CONTROL_SCHEMA = "lightbulb.dynamic_workflow_control.v1"
DYNAMIC_WORKFLOW_CONTROL_MUTATION_SCHEMA = (
    "lightbulb.dynamic_workflow_control_mutation.v1"
)
DYNAMIC_WORKFLOW_ROLE_BINDING_SCHEMA = "lightbulb.dynamic_workflow_role_binding.v1"
DYNAMIC_WORKFLOW_ASSIGNMENT_LEASE_SCHEMA = (
    "lightbulb.dynamic_workflow_assignment_lease.v1"
)
DYNAMIC_WORKFLOW_CONTEXT_LINK_SCHEMA = "lightbulb.dynamic_workflow_context_link.v1"
DYNAMIC_WORKFLOW_CONTEXT_BINDING_ANCHOR_SCHEMA = (
    "lightbulb.dynamic_workflow_context_binding_anchor.v1"
)
DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_ANCHOR_SCHEMA = (
    "lightbulb.dynamic_workflow_context_checkpoint_anchor.v1"
)
DYNAMIC_WORKFLOW_CONTEXT_START_ANCHOR_SCHEMA = (
    "lightbulb.dynamic_workflow_context_start_anchor.v1"
)
DYNAMIC_WORKFLOW_CONTEXT_ATTACH_ANCHOR_SCHEMA = (
    "lightbulb.dynamic_workflow_context_attach_anchor.v1"
)
DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_COMMIT_SCHEMA = (
    "lightbulb.dynamic_workflow_context_checkpoint_commit.v1"
)

_RUN_REF_RE = re.compile(r"^dwr_[A-Za-z0-9_-]{16,64}$")
_BINDING_REF_RE = re.compile(r"^dwh_[a-f0-9]{64}$")
_SESSION_FINGERPRINT_RE = re.compile(r"^dwf_[a-f0-9]{64}$")
_SESSION_RECEIPT_RE = re.compile(r"^dws_[A-Za-z0-9_-]{24,128}$")
_ASSIGNMENT_REF_RE = re.compile(r"^dwa_[A-Za-z0-9_-]{16,64}$")
_ASSIGNMENT_RECEIPT_RE = re.compile(r"^dwl_[A-Za-z0-9_-]{24,128}$")
_SUBMISSION_REF_RE = re.compile(r"^dwb_[A-Za-z0-9_-]{16,64}$")
_CONTEXT_REF_RE = re.compile(r"^ctx_[A-Za-z0-9_-]{16,48}$")
_CONTEXT_BINDING_REF_RE = re.compile(r"^cxs_[A-Za-z0-9_-]{16,48}$")
_CONTEXT_CHECKPOINT_REF_RE = re.compile(r"^cxp_[A-Za-z0-9_-]{16,48}$")
_CONTEXT_ITEM_REF_RE = re.compile(r"^(?:cxe|cxp)_[A-Za-z0-9_-]{16,48}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_HISTORY = 1_000
_MAX_CONTROL_CHECKPOINT_BYTES = 1_800_000
_EMPTY_INTEGRITY_MAC = "dwc_" + "0" * 64
_SENSITIVE_STORAGE_KEYS = {
    "host_session_ref",
    "session_receipt",
    "assignment_receipt",
}
_CREDENTIAL_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "jwt",
)
_SAFE_TOKEN_ACCOUNTING_FIELDS = {
    "token_budget",
    "tokens_used",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "max_tokens",
    "estimated_tokens",
    "token_count",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)

    def encode(item: Any) -> Any:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json", by_alias=True)
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, datetime):
            return _utc(item).isoformat()
        if isinstance(item, (tuple, set, frozenset)):
            return list(item)
        raise TypeError(f"value is not canonically JSON serializable: {type(item).__name__}")

    return json.dumps(
        value,
        default=encode,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _nonblank(value: str, *, label: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} must not be blank")
    return clean


def _validate_json_storage(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must contain canonical JSON values") from exc
    if len(encoded) > 131_072:
        raise ValueError(f"{label} exceeds 131072 encoded bytes")

    def inspect(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError(f"{label} object keys must be strings")
                normalized_key = key.strip().lower()
                if normalized_key in _SENSITIVE_STORAGE_KEYS:
                    raise ValueError(f"{label} cannot persist custody or raw-session fields")
                if normalized_key in _SAFE_TOKEN_ACCOUNTING_FIELDS:
                    if (
                        isinstance(nested, bool)
                        or not isinstance(nested, (int, float))
                        or not math.isfinite(float(nested))
                        or float(nested) < 0
                        or float(nested) > 1_000_000_000_000
                    ):
                        raise ValueError(
                            f"{label} token-accounting field is outside the allowed range"
                        )
                elif any(
                    fragment in normalized_key
                    for fragment in _CREDENTIAL_KEY_FRAGMENTS
                ):
                    raise ValueError(f"{label} cannot persist credential fields")
                inspect(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                inspect(nested)
        elif isinstance(item, str) and item.startswith(("dws_", "dwl_")):
            raise ValueError(f"{label} cannot persist custody receipts")

    detached = json.loads(encoded.decode("utf-8"))
    inspect(detached)
    return detached


class DynamicWorkflowControlError(RuntimeError):
    """Base error for role custody and assignment control."""


class DynamicWorkflowCustodyError(DynamicWorkflowControlError):
    """A binding or receipt did not prove the required custody."""


class DynamicWorkflowControlConflict(DynamicWorkflowControlError):
    """An external revision, idempotency key, or exclusive lease conflicted."""


class DynamicWorkflowControlNotFound(DynamicWorkflowControlError):
    """The requested outer control checkpoint does not exist."""


class DynamicWorkflowControlPersistenceError(DynamicWorkflowControlError):
    """An outer control checkpoint could not be safely persisted or loaded."""


class DynamicWorkflowRolePhaseError(DynamicWorkflowControlError):
    """The requested role is not active in the current core phase."""


class DynamicWorkflowHostRole(str, Enum):
    PLANNER = "planner"
    BUILDER = "builder"
    EVALUATOR = "evaluator"


class DynamicWorkflowAcceptancePolicy(str, Enum):
    DISTINCT_BINDING = "distinct_binding"
    RUNTIME_ATTESTED_REQUIRED = "runtime_attested_required"


class DynamicWorkflowEvaluatorFreshnessAssurance(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    DISTINCT_BINDING_EXTERNAL_REF = "distinct_binding_external_ref"
    DISTINCT_MCP_SESSION = "distinct_mcp_session"
    RUNTIME_ATTESTED_FRESH_CONTEXT = "runtime_attested_fresh_context"


class DynamicWorkflowAcceptanceAssurance(str, Enum):
    NOT_ACCEPTED = "not_accepted"
    DISTINCT_BINDING = "distinct_binding"
    DISTINCT_MCP_SESSION = "distinct_mcp_session"
    RUNTIME_ATTESTED = "runtime_attested"


class DynamicWorkflowLeaseResolution(str, Enum):
    OPEN = "open"
    SUBMITTED = "submitted"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


def _context_ref(value: str, *, label: str, pattern: re.Pattern[str]) -> str:
    clean = value.strip()
    if not pattern.fullmatch(clean):
        raise ValueError(f"{label} must be an opaque Context Broker public reference")
    return clean


def _context_supporting_refs(value: tuple[str, ...]) -> tuple[str, ...]:
    clean = tuple(
        _context_ref(
            item,
            label="supporting_ref",
            pattern=_CONTEXT_ITEM_REF_RE,
        )
        for item in value
    )
    if len(clean) != len(set(clean)):
        raise ValueError("context supporting refs must be unique")
    return clean


class DynamicWorkflowContextStartAnchor(_FrozenModel):
    """Server-only Context Broker result used while starting a linked run."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_START_ANCHOR_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_START_ANCHOR_SCHEMA,
        alias="schema",
    )
    context_ref: str
    context_binding_ref: str
    context_revision: int = Field(ge=0)
    latest_checkpoint_ref: str | None = None
    supporting_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=256)

    @field_validator("context_ref")
    @classmethod
    def _space_ref(cls, value: str) -> str:
        return _context_ref(value, label="context_ref", pattern=_CONTEXT_REF_RE)

    @field_validator("context_binding_ref")
    @classmethod
    def _context_binding(cls, value: str) -> str:
        return _context_ref(
            value,
            label="context_binding_ref",
            pattern=_CONTEXT_BINDING_REF_RE,
        )

    @field_validator("latest_checkpoint_ref")
    @classmethod
    def _checkpoint_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _context_ref(
            value,
            label="latest_checkpoint_ref",
            pattern=_CONTEXT_CHECKPOINT_REF_RE,
        )

    @field_validator("supporting_refs")
    @classmethod
    def _supporting(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _context_supporting_refs(value)

    @model_validator(mode="after")
    def _checkpoint_consistent(self) -> Self:
        if self.latest_checkpoint_ref is None and self.supporting_refs:
            raise ValueError("supporting refs require a latest context checkpoint")
        if self.latest_checkpoint_ref is not None and self.context_revision < 1:
            raise ValueError("a context checkpoint requires a positive context revision")
        return self


class DynamicWorkflowContextAttachAnchor(_FrozenModel):
    """Server-only proof that an attached binding belongs to the linked space."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_ATTACH_ANCHOR_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_ATTACH_ANCHOR_SCHEMA,
        alias="schema",
    )
    context_ref: str
    context_binding_ref: str
    context_revision: int = Field(ge=0)

    @field_validator("context_ref")
    @classmethod
    def _space_ref(cls, value: str) -> str:
        return _context_ref(value, label="context_ref", pattern=_CONTEXT_REF_RE)

    @field_validator("context_binding_ref")
    @classmethod
    def _context_binding(cls, value: str) -> str:
        return _context_ref(
            value,
            label="context_binding_ref",
            pattern=_CONTEXT_BINDING_REF_RE,
        )


class DynamicWorkflowContextCheckpointCommit(_FrozenModel):
    """Server-only receipt for a Context Broker commit completed before workflow CAS."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_COMMIT_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_COMMIT_SCHEMA,
        alias="schema",
    )
    context_ref: str
    context_binding_ref: str
    base_context_revision: int = Field(ge=0)
    context_revision: int = Field(ge=1)
    checkpoint_ref: str
    supporting_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=256)

    @field_validator("context_ref")
    @classmethod
    def _space_ref(cls, value: str) -> str:
        return _context_ref(value, label="context_ref", pattern=_CONTEXT_REF_RE)

    @field_validator("context_binding_ref")
    @classmethod
    def _context_binding(cls, value: str) -> str:
        return _context_ref(
            value,
            label="context_binding_ref",
            pattern=_CONTEXT_BINDING_REF_RE,
        )

    @field_validator("checkpoint_ref")
    @classmethod
    def _checkpoint_ref(cls, value: str) -> str:
        return _context_ref(
            value,
            label="checkpoint_ref",
            pattern=_CONTEXT_CHECKPOINT_REF_RE,
        )

    @field_validator("supporting_refs")
    @classmethod
    def _supporting(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _context_supporting_refs(value)

    @model_validator(mode="after")
    def _revision_advanced(self) -> Self:
        if self.context_revision != self.base_context_revision + 1:
            raise ValueError(
                "context checkpoint revision must advance its base revision by exactly one"
            )
        return self


class DynamicWorkflowContextBindingAnchor(_FrozenModel):
    """Sealed dwh_ to cxs_ role mapping; neither value is an internal id."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_BINDING_ANCHOR_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_BINDING_ANCHOR_SCHEMA,
        alias="schema",
    )
    host_binding_ref: str
    context_binding_ref: str
    role: DynamicWorkflowHostRole
    bound_at_context_revision: int = Field(ge=0)

    @field_validator("host_binding_ref")
    @classmethod
    def _host_binding(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _BINDING_REF_RE.fullmatch(clean):
            raise ValueError("host_binding_ref has an invalid format")
        return clean

    @field_validator("context_binding_ref")
    @classmethod
    def _context_binding(cls, value: str) -> str:
        return _context_ref(
            value,
            label="context_binding_ref",
            pattern=_CONTEXT_BINDING_REF_RE,
        )


class DynamicWorkflowContextCheckpointAnchor(_FrozenModel):
    """Small provenance anchor, never a Context Pack or assurance claim."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_ANCHOR_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_ANCHOR_SCHEMA,
        alias="schema",
    )
    host_binding_ref: str
    context_binding_ref: str
    context_revision: int = Field(ge=0)
    checkpoint_ref: str | None = None
    supporting_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    evidence_trust: Literal["untrusted"] = "untrusted"
    contains_context_pack: Literal[False] = False

    @field_validator("host_binding_ref")
    @classmethod
    def _host_binding(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _BINDING_REF_RE.fullmatch(clean):
            raise ValueError("host_binding_ref has an invalid format")
        return clean

    @field_validator("context_binding_ref")
    @classmethod
    def _context_binding(cls, value: str) -> str:
        return _context_ref(
            value,
            label="context_binding_ref",
            pattern=_CONTEXT_BINDING_REF_RE,
        )

    @field_validator("checkpoint_ref")
    @classmethod
    def _checkpoint_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _context_ref(
            value,
            label="checkpoint_ref",
            pattern=_CONTEXT_CHECKPOINT_REF_RE,
        )

    @field_validator("supporting_refs")
    @classmethod
    def _supporting(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _context_supporting_refs(value)

    @model_validator(mode="after")
    def _checkpoint_consistent(self) -> Self:
        if self.checkpoint_ref is None and self.supporting_refs:
            raise ValueError("supporting refs require a context checkpoint ref")
        if self.checkpoint_ref is not None and self.context_revision < 1:
            raise ValueError("a context checkpoint requires a positive context revision")
        return self

    def public_payload(self) -> dict[str, Any]:
        payload = {
            "context_binding_ref": self.context_binding_ref,
            "context_revision": self.context_revision,
            "supporting_refs": list(self.supporting_refs),
            "evidence_trust": self.evidence_trust,
            "contains_context_pack": self.contains_context_pack,
        }
        if self.checkpoint_ref is not None:
            payload["checkpoint_ref"] = self.checkpoint_ref
        return payload


class DynamicWorkflowContextLink(_FrozenModel):
    """Sealed workflow-to-Context-Broker linkage with exact-scope custody."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTEXT_LINK_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTEXT_LINK_SCHEMA,
        alias="schema",
    )
    context_ref: str
    exact_scope_digest: str = Field(repr=False)
    current_context_revision: int = Field(ge=0)
    binding_anchors: tuple[DynamicWorkflowContextBindingAnchor, ...] = Field(
        min_length=1,
        max_length=_MAX_HISTORY,
    )
    latest_checkpoint_anchor: DynamicWorkflowContextCheckpointAnchor | None = None

    @field_validator("context_ref")
    @classmethod
    def _space_ref(cls, value: str) -> str:
        return _context_ref(value, label="context_ref", pattern=_CONTEXT_REF_RE)

    @field_validator("exact_scope_digest")
    @classmethod
    def _scope_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("exact_scope_digest must be a keyed lowercase SHA-256 digest")
        return clean

    @model_validator(mode="after")
    def _anchors_consistent(self) -> Self:
        host_refs: set[str] = set()
        context_refs: set[str] = set()
        for anchor in self.binding_anchors:
            if anchor.host_binding_ref in host_refs:
                raise ValueError("context host binding anchors must be unique")
            if anchor.context_binding_ref in context_refs:
                raise ValueError("context binding refs cannot be shared across role bindings")
            if anchor.bound_at_context_revision > self.current_context_revision:
                raise ValueError("context binding anchor is newer than the current revision")
            host_refs.add(anchor.host_binding_ref)
            context_refs.add(anchor.context_binding_ref)
        latest = self.latest_checkpoint_anchor
        if latest is not None:
            if latest.context_revision != self.current_context_revision:
                raise ValueError("latest context checkpoint must equal the current revision")
            binding = next(
                (
                    item
                    for item in self.binding_anchors
                    if item.host_binding_ref == latest.host_binding_ref
                ),
                None,
            )
            if binding is None or binding.context_binding_ref != latest.context_binding_ref:
                raise ValueError("latest context checkpoint has no matching role mapping")
        return self

    def binding_for(self, host_binding_ref: str) -> DynamicWorkflowContextBindingAnchor | None:
        return next(
            (
                anchor
                for anchor in self.binding_anchors
                if anchor.host_binding_ref == host_binding_ref
            ),
            None,
        )


class DynamicWorkflowControlAuthority(_FrozenModel):
    """Resolver-owned authority combining internal scope with public refs.

    The MCP ``company_ref`` is intentionally not compared with the internal
    ``company_id``.  A server resolver must establish both values and pass this
    object after authenticating the principal.
    """

    scope: DynamicWorkflowScope = Field(repr=False)
    company_ref: str = Field(min_length=1, max_length=200)
    project_ref: str = Field(min_length=1, max_length=200)

    @field_validator("company_ref", "project_ref")
    @classmethod
    def _public_ref(cls, value: str) -> str:
        return _nonblank(value, label="authorized public reference")

    @model_validator(mode="after")
    def _project_consistent(self) -> Self:
        if self.project_ref != self.scope.project_ref:
            raise ValueError("authorized project_ref must match the internal workflow scope")
        return self


class DynamicWorkflowRoleBinding(_FrozenModel):
    schema_id: Literal[DYNAMIC_WORKFLOW_ROLE_BINDING_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_ROLE_BINDING_SCHEMA, alias="schema"
    )
    host_binding_ref: str
    scoped_session_fingerprint: str
    harness_id: str
    role: DynamicWorkflowHostRole
    evaluator_builder_result_digest: str | None = None
    session_identity_attested: bool = False
    identity_source: str = Field(default="external_ref", min_length=1, max_length=80)
    attached_at: datetime

    @field_validator("host_binding_ref")
    @classmethod
    def _binding_ref(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _BINDING_REF_RE.fullmatch(clean):
            raise ValueError("host_binding_ref has an invalid format")
        return clean

    @field_validator("scoped_session_fingerprint")
    @classmethod
    def _session_fingerprint(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SESSION_FINGERPRINT_RE.fullmatch(clean):
            raise ValueError("scoped_session_fingerprint has an invalid format")
        return clean

    @field_validator("harness_id")
    @classmethod
    def _harness(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean not in BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS:
            raise ValueError("harness_id is not one of the five supported harnesses")
        return clean

    @field_validator("identity_source")
    @classmethod
    def _identity_source(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean not in {
            "external_ref",
            "mcp_session_distinct",
            "runtime_attested",
            "anonymous_start",
        }:
            raise ValueError("identity_source is not supported")
        return clean

    @field_validator("evaluator_builder_result_digest")
    @classmethod
    def _evaluator_anchor(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("evaluator builder-result anchor must be lowercase SHA-256")
        return clean

    @field_validator("attached_at")
    @classmethod
    def _time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _attestation_consistent(self) -> Self:
        if self.session_identity_attested != (self.identity_source == "runtime_attested"):
            raise ValueError("session attestation flag and identity_source disagree")
        if self.role == DynamicWorkflowHostRole.EVALUATOR:
            if self.evaluator_builder_result_digest is None:
                raise ValueError("evaluator binding requires a builder-result anchor")
        elif self.evaluator_builder_result_digest is not None:
            raise ValueError("only evaluator bindings may anchor a builder result")
        return self


class DynamicWorkflowEvidenceBinding(_FrozenModel):
    ref: str = Field(min_length=1, max_length=2_000)
    sha256: str
    kind: str = Field(min_length=1, max_length=120)
    criterion_ids: tuple[str, ...] = Field(min_length=1, max_length=500)
    media_type: str | None = Field(default=None, max_length=200)

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("evidence sha256 has an invalid format")
        return clean

    @field_validator("criterion_ids")
    @classmethod
    def _criteria(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        clean = tuple(_nonblank(item, label="criterion_id") for item in value)
        if len(clean) != len(set(clean)):
            raise ValueError("evidence criterion_ids must be unique")
        return clean


class DynamicWorkflowAssignmentLease(_FrozenModel):
    schema_id: Literal[DYNAMIC_WORKFLOW_ASSIGNMENT_LEASE_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_ASSIGNMENT_LEASE_SCHEMA, alias="schema"
    )
    assignment_ref: str
    host_binding_ref: str
    role: DynamicWorkflowHostRole
    attempt: int = Field(ge=1, le=10_000)
    instructions: str = Field(min_length=1, max_length=32_768)
    payload: dict[str, Any] = Field(default_factory=dict)
    issued_at: datetime
    lease_expires_at: datetime
    resolution: DynamicWorkflowLeaseResolution = DynamicWorkflowLeaseResolution.OPEN
    resolved_at: datetime | None = None
    submission_ref: str | None = None
    evidence_bindings: tuple[DynamicWorkflowEvidenceBinding, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    context_anchor: DynamicWorkflowContextCheckpointAnchor | None = None

    @field_validator("assignment_ref")
    @classmethod
    def _assignment_ref(cls, value: str) -> str:
        if not _ASSIGNMENT_REF_RE.fullmatch(value):
            raise ValueError("assignment_ref has an invalid format")
        return value

    @field_validator("host_binding_ref")
    @classmethod
    def _binding_ref(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _BINDING_REF_RE.fullmatch(clean):
            raise ValueError("host_binding_ref has an invalid format")
        return clean

    @field_validator("submission_ref")
    @classmethod
    def _submission_ref(cls, value: str | None) -> str | None:
        if value is not None and not _SUBMISSION_REF_RE.fullmatch(value):
            raise ValueError("submission_ref has an invalid format")
        return value

    @field_validator("issued_at", "lease_expires_at", "resolved_at")
    @classmethod
    def _time(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value is not None else None

    @field_validator("payload")
    @classmethod
    def _payload(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        return _validate_json_storage(value, label="assignment payload")

    @model_validator(mode="after")
    def _lease_invariants(self) -> Self:
        if self.lease_expires_at <= self.issued_at:
            raise ValueError("assignment lease must expire after issuance")
        if self.resolution == DynamicWorkflowLeaseResolution.OPEN:
            if self.resolved_at is not None or self.submission_ref is not None:
                raise ValueError("open assignment lease cannot be resolved")
            if self.evidence_bindings:
                raise ValueError("open assignment lease cannot contain submitted evidence")
        else:
            if self.resolved_at is None:
                raise ValueError("resolved assignment lease requires resolved_at")
            if self.resolution == DynamicWorkflowLeaseResolution.SUBMITTED:
                if self.submission_ref is None:
                    raise ValueError("submitted lease requires submission_ref")
            elif self.submission_ref is not None:
                raise ValueError("only submitted leases may contain submission_ref")
        if self.evidence_bindings and self.role != DynamicWorkflowHostRole.BUILDER:
            raise ValueError("only builder submissions may bind evidence to criteria")
        if (
            self.context_anchor is not None
            and self.context_anchor.host_binding_ref != self.host_binding_ref
        ):
            raise ValueError("assignment context anchor must belong to the leased binding")
        return self

    def is_active(self, now: datetime) -> bool:
        return (
            self.resolution == DynamicWorkflowLeaseResolution.OPEN
            and _utc(now) < self.lease_expires_at
        )


class DynamicWorkflowControlMutationRecord(_FrozenModel):
    schema_id: Literal[DYNAMIC_WORKFLOW_CONTROL_MUTATION_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTROL_MUTATION_SCHEMA,
        alias="schema",
    )
    operation: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(min_length=1, max_length=128)
    request_digest: str
    committed_revision: int = Field(ge=1)
    runtime_revision: int = Field(ge=1)
    committed_status: WorkflowRunStatus
    subject_ref: str = Field(min_length=1, max_length=200)
    next_role: DynamicWorkflowHostRole | None = None
    context_revision: int | None = Field(default=None, ge=0)
    context_checkpoint_ref: str | None = None
    occurred_at: datetime

    @field_validator("operation")
    @classmethod
    def _operation(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean not in {
            "start",
            "attach",
            "next_assignment",
            "submit_plan",
            "submit_builder_result",
            "submit_evaluator_verdict",
            "cancel",
        }:
            raise ValueError("control mutation operation is unsupported")
        return clean

    @field_validator("idempotency_key")
    @classmethod
    def _idempotency(cls, value: str) -> str:
        if not _IDEMPOTENCY_RE.fullmatch(value):
            raise ValueError("idempotency_key has an invalid format")
        return value

    @field_validator("request_digest")
    @classmethod
    def _request_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("request_digest has an invalid format")
        return clean

    @field_validator("context_checkpoint_ref")
    @classmethod
    def _context_checkpoint_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _context_ref(
            value,
            label="context_checkpoint_ref",
            pattern=_CONTEXT_CHECKPOINT_REF_RE,
        )

    @field_validator("occurred_at")
    @classmethod
    def _time(cls, value: datetime) -> datetime:
        return _utc(value)

    @model_validator(mode="after")
    def _context_receipt_consistent(self) -> Self:
        if self.context_checkpoint_ref is not None:
            if self.context_revision is None:
                raise ValueError("context checkpoint receipt requires its context revision")
            if self.operation not in {
                "submit_plan",
                "submit_builder_result",
                "submit_evaluator_verdict",
            }:
                raise ValueError("only artifact submissions may anchor a context checkpoint")
        return self


class DynamicWorkflowControlCheckpoint(_FrozenModel):
    """Single external CAS envelope for core state and all custody state."""

    schema_id: Literal[DYNAMIC_WORKFLOW_CONTROL_SCHEMA] = Field(
        default=DYNAMIC_WORKFLOW_CONTROL_SCHEMA, alias="schema"
    )
    run_ref: str
    hosted_project_id: str | None = Field(default=None, max_length=200)
    status: WorkflowRunStatus
    revision: int = Field(ge=1)
    scope: DynamicWorkflowScope
    runtime_checkpoint: DynamicWorkflowCheckpoint
    role_bindings: tuple[DynamicWorkflowRoleBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_HISTORY,
    )
    assignment_leases: tuple[DynamicWorkflowAssignmentLease, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_HISTORY,
    )
    mutation_records: tuple[DynamicWorkflowControlMutationRecord, ...] = Field(
        min_length=1,
        max_length=_MAX_HISTORY,
    )
    workflow_spec: dict[str, Any] = Field(default_factory=dict)
    initial_inputs: dict[str, Any] = Field(default_factory=dict)
    context_link: DynamicWorkflowContextLink | None = None
    acceptance_policy: DynamicWorkflowAcceptancePolicy = (
        DynamicWorkflowAcceptancePolicy.DISTINCT_BINDING
    )
    receipt_key_id: str = Field(min_length=8, max_length=80)
    integrity_mac: str
    created_at: datetime
    updated_at: datetime
    resume_at: datetime | None = None
    lease_owner: str | None = None
    lease_until: datetime | None = None

    @field_validator("run_ref")
    @classmethod
    def _run_ref(cls, value: str) -> str:
        if not _RUN_REF_RE.fullmatch(value):
            raise ValueError("run_ref has an invalid dynamic-workflow format")
        return value

    @field_validator("integrity_mac")
    @classmethod
    def _integrity_mac(cls, value: str) -> str:
        clean = value.strip().lower()
        if not re.fullmatch(r"^dwc_[a-f0-9]{64}$", clean):
            raise ValueError("integrity_mac has an invalid format")
        return clean

    @field_validator("created_at", "updated_at", "resume_at", "lease_until")
    @classmethod
    def _time(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value is not None else None

    @field_validator("workflow_spec", "initial_inputs")
    @classmethod
    def _stored_json(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        return _validate_json_storage(value, label="control checkpoint JSON")

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.runtime_checkpoint.run_ref != self.run_ref:
            raise ValueError("embedded runtime checkpoint run_ref differs")
        if self.runtime_checkpoint.scope != self.scope:
            raise ValueError("embedded runtime checkpoint scope differs")
        if self.runtime_checkpoint.status != self.status:
            raise ValueError("embedded runtime checkpoint status differs")
        if self.runtime_checkpoint.updated_at > self.updated_at:
            raise ValueError("outer checkpoint cannot predate embedded runtime")

        binding_refs = [binding.host_binding_ref for binding in self.role_bindings]
        if len(binding_refs) != len(set(binding_refs)):
            raise ValueError("role binding refs must be unique")
        if self.context_link is not None:
            context_mappings = {
                anchor.host_binding_ref: anchor
                for anchor in self.context_link.binding_anchors
            }
            if set(context_mappings) != set(binding_refs):
                raise ValueError(
                    "a linked workflow requires one context binding for every host binding"
                )
            for binding in self.role_bindings:
                anchor = context_mappings[binding.host_binding_ref]
                if anchor.role != binding.role:
                    raise ValueError("context binding role differs from host binding role")
        builder_sessions = {
            binding.scoped_session_fingerprint
            for binding in self.role_bindings
            if binding.role == DynamicWorkflowHostRole.BUILDER
        }
        evaluator_sessions = [
            binding.scoped_session_fingerprint
            for binding in self.role_bindings
            if binding.role == DynamicWorkflowHostRole.EVALUATOR
        ]
        if builder_sessions & set(evaluator_sessions):
            raise ValueError("builder and evaluator session fingerprints must be distinct")
        if len(evaluator_sessions) != len(set(evaluator_sessions)):
            raise ValueError("evaluator session fingerprints cannot be reused")

        known_bindings = {binding.host_binding_ref: binding for binding in self.role_bindings}
        assignment_refs: set[str] = set()
        unresolved: list[DynamicWorkflowAssignmentLease] = []
        for lease in self.assignment_leases:
            if lease.assignment_ref in assignment_refs:
                raise ValueError("assignment refs must be unique")
            binding = known_bindings.get(lease.host_binding_ref)
            if binding is None or binding.role != lease.role:
                raise ValueError("assignment lease does not bind a matching role binding")
            if self.context_link is None:
                if lease.context_anchor is not None:
                    raise ValueError("unlinked workflow cannot store assignment context anchors")
            else:
                context_binding = self.context_link.binding_for(lease.host_binding_ref)
                if lease.context_anchor is None or context_binding is None:
                    raise ValueError("linked assignment requires a sealed context anchor")
                if (
                    lease.context_anchor.context_binding_ref
                    != context_binding.context_binding_ref
                ):
                    raise ValueError("assignment context binding differs from role mapping")
                if (
                    lease.context_anchor.context_revision
                    > self.context_link.current_context_revision
                ):
                    raise ValueError("assignment context anchor is newer than the context link")
            assignment_refs.add(lease.assignment_ref)
            if lease.resolution == DynamicWorkflowLeaseResolution.OPEN:
                unresolved.append(lease)
        if len(unresolved) > 1:
            raise ValueError("only one unresolved assignment lease may exist")
        if unresolved:
            if self.lease_owner != unresolved[0].assignment_ref:
                raise ValueError("lease_owner must mirror the unresolved assignment")
            if self.lease_until != unresolved[0].lease_expires_at:
                raise ValueError("lease_until must mirror the unresolved assignment")
        elif self.lease_owner is not None or self.lease_until is not None:
            raise ValueError("top-level lease fields require an unresolved assignment")

        keys: set[str] = set()
        context_checkpoint_refs: set[str] = set()
        previous_context_revision: int | None = None
        previous_revision = 0
        for record in self.mutation_records:
            if record.idempotency_key in keys:
                raise ValueError("control idempotency keys must be unique")
            if record.committed_revision <= previous_revision:
                raise ValueError("control mutation revisions must increase")
            if record.committed_revision > self.revision:
                raise ValueError("control mutation cannot exceed checkpoint revision")
            if record.runtime_revision > self.runtime_checkpoint.revision:
                raise ValueError("control mutation cannot exceed embedded runtime revision")
            if self.context_link is None:
                if (
                    record.context_revision is not None
                    or record.context_checkpoint_ref is not None
                ):
                    raise ValueError("unlinked workflow cannot store context mutation anchors")
            else:
                if record.context_revision is None:
                    raise ValueError("linked workflow mutation requires a context revision")
                if record.context_revision > self.context_link.current_context_revision:
                    raise ValueError("mutation context revision exceeds the current context")
                if previous_context_revision is not None:
                    if record.context_revision < previous_context_revision:
                        raise ValueError("mutation context revisions cannot move backwards")
                    if record.context_checkpoint_ref is None:
                        if record.context_revision != previous_context_revision:
                            raise ValueError(
                                "only a context-anchored submission may advance context"
                            )
                    elif record.context_revision != previous_context_revision + 1:
                        raise ValueError(
                            "context-anchored submission must advance revision exactly once"
                        )
                if record.context_checkpoint_ref is not None:
                    if record.context_checkpoint_ref in context_checkpoint_refs:
                        raise ValueError("context checkpoint refs cannot be reused")
                    context_checkpoint_refs.add(record.context_checkpoint_ref)
                previous_context_revision = record.context_revision
            keys.add(record.idempotency_key)
            previous_revision = record.committed_revision
        latest = self.mutation_records[-1]
        if latest.committed_revision != self.revision:
            raise ValueError("latest mutation must seal the external revision")
        if latest.runtime_revision != self.runtime_checkpoint.revision:
            raise ValueError("latest mutation must seal the embedded runtime revision")
        if latest.committed_status != self.status:
            raise ValueError("latest mutation must seal the current status")
        if (
            self.context_link is not None
            and latest.context_revision != self.context_link.current_context_revision
        ):
            raise ValueError("latest mutation must seal the current context revision")
        if self.status == WorkflowRunStatus.ACCEPTED:
            verdict = self.runtime_checkpoint.workflow_state.current_verdict
            result = self.runtime_checkpoint.workflow_state.current_builder_result
            if verdict is None or result is None:
                raise ValueError("accepted state requires evaluator artifacts")
            binding = known_bindings.get(verdict.evaluator_session_id)
            if (
                binding is None
                or binding.role != DynamicWorkflowHostRole.EVALUATOR
                or binding.evaluator_builder_result_digest != result.digest
            ):
                raise ValueError(
                    "accepted state requires an evaluator anchored to its builder result"
                )
            if (
                self.acceptance_policy
                == DynamicWorkflowAcceptancePolicy.RUNTIME_ATTESTED_REQUIRED
                and binding.identity_source != "runtime_attested"
            ):
                raise ValueError(
                    "strict accepted state requires runtime-attested evaluator freshness"
                )
        return self

    @property
    def runtime_revision(self) -> int:
        """Internal embedded revision; MCP callers use ``revision`` instead."""

        return self.runtime_checkpoint.revision

    @property
    def terminal(self) -> bool:
        return self.status.terminal

    def mutation_for(self, idempotency_key: str) -> DynamicWorkflowControlMutationRecord | None:
        return next(
            (
                record
                for record in self.mutation_records
                if record.idempotency_key == idempotency_key
            ),
            None,
        )

    def binding_for(self, host_binding_ref: str) -> DynamicWorkflowRoleBinding | None:
        return next(
            (
                binding
                for binding in self.role_bindings
                if binding.host_binding_ref == host_binding_ref
            ),
            None,
        )

    def assignment_for(self, assignment_ref: str) -> DynamicWorkflowAssignmentLease | None:
        return next(
            (
                lease
                for lease in self.assignment_leases
                if lease.assignment_ref == assignment_ref
            ),
            None,
        )

    def unresolved_assignment(self) -> DynamicWorkflowAssignmentLease | None:
        return next(
            (
                lease
                for lease in self.assignment_leases
                if lease.resolution == DynamicWorkflowLeaseResolution.OPEN
            ),
            None,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class DynamicWorkflowControlStore(Protocol):
    """Pluggable CAS store for the single outer control checkpoint."""

    def get(self, run_ref: str) -> DynamicWorkflowControlCheckpoint | None:
        ...

    def save(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowControlCheckpoint:
        ...


def _validate_save_revision(
    checkpoint: DynamicWorkflowControlCheckpoint,
    *,
    actual_revision: int,
    expected_revision: int,
) -> None:
    if actual_revision != expected_revision:
        raise DynamicWorkflowControlConflict(
            f"control revision is {actual_revision}, expected {expected_revision}"
        )
    if checkpoint.revision != expected_revision + 1:
        raise DynamicWorkflowControlConflict(
            "candidate control revision must increase by exactly one"
        )


class InMemoryDynamicWorkflowControlStore:
    def __init__(self) -> None:
        self._checkpoints: dict[str, DynamicWorkflowControlCheckpoint] = {}
        self._lock = threading.RLock()

    def get(self, run_ref: str) -> DynamicWorkflowControlCheckpoint | None:
        with self._lock:
            value = self._checkpoints.get(run_ref)
            return value.model_copy(deep=True) if value is not None else None

    def save(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowControlCheckpoint:
        with self._lock:
            current = self._checkpoints.get(checkpoint.run_ref)
            actual = current.revision if current is not None else 0
            _validate_save_revision(
                checkpoint,
                actual_revision=actual,
                expected_revision=expected_revision,
            )
            stored = checkpoint.model_copy(deep=True)
            self._checkpoints[checkpoint.run_ref] = stored
            return stored.model_copy(deep=True)


@contextmanager
def _file_lock(path: Path):
    lock_path = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 3.0
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 30:
                    lock_path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise DynamicWorkflowControlPersistenceError(
                    "dynamic workflow control checkpoint is busy"
                )
            time.sleep(0.05)
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


class JsonDynamicWorkflowControlStore:
    """Atomic local JSON implementation of the outer control CAS store."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, run_ref: str) -> Path:
        if not _RUN_REF_RE.fullmatch(run_ref):
            raise ValueError("run_ref has an invalid dynamic-workflow format")
        # Lexical path: resolve() would follow a planted symlink, making every
        # later is_symlink() refusal examine the target instead of the link.
        target = self.root / f"{run_ref}.control.json"
        if target.is_symlink():
            raise DynamicWorkflowControlPersistenceError(
                "refusing symlinked dynamic workflow control checkpoint"
            )
        if target.resolve().parent != self.root:
            raise ValueError("run_ref escapes the control checkpoint root")
        return target

    def _get_unlocked(self, path: Path) -> DynamicWorkflowControlCheckpoint | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, TypeError, ValueError) as exc:
            raise DynamicWorkflowControlPersistenceError(
                "cannot load dynamic workflow control checkpoint"
            ) from exc
        try:
            return DynamicWorkflowControlCheckpoint.model_validate(payload)
        except ValueError as exc:
            raise DynamicWorkflowControlPersistenceError(
                "dynamic workflow control checkpoint failed validation"
            ) from exc

    def get(self, run_ref: str) -> DynamicWorkflowControlCheckpoint | None:
        return self._get_unlocked(self._path(run_ref))

    def save(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowControlCheckpoint:
        path = self._path(checkpoint.run_ref)
        with _file_lock(path):
            current = self._get_unlocked(path)
            actual = current.revision if current is not None else 0
            _validate_save_revision(
                checkpoint,
                actual_revision=actual,
                expected_revision=expected_revision,
            )
            temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
            try:
                temporary.write_text(
                    json.dumps(checkpoint.to_dict(), sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                try:
                    os.chmod(temporary, 0o600)
                except OSError:
                    pass
                os.replace(temporary, path)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                raise DynamicWorkflowControlPersistenceError(
                    "cannot save dynamic workflow control checkpoint"
                ) from exc
            return checkpoint.model_copy(deep=True)


class DynamicWorkflowReceiptKeyRing:
    """Restart-stable HMAC keys for custody receipts and checkpoint seals.

    A run records only the key identifier that created it.  Rotating the active
    key therefore does not invalidate existing continuations as long as the old
    key remains in the ring.
    """

    def __init__(
        self,
        keys: Mapping[str, bytes | str],
        *,
        active_key_id: str,
    ) -> None:
        normalized: dict[str, bytes] = {}
        for raw_key_id, raw_key in keys.items():
            key_id = str(raw_key_id).strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}", key_id):
                raise ValueError("receipt key identifiers must contain 8-80 safe characters")
            if isinstance(raw_key, str):
                key = raw_key.encode("utf-8")
            elif isinstance(raw_key, bytes):
                key = raw_key
            else:
                raise TypeError("receipt keys must be bytes or strings")
            if len(key) < 32:
                raise ValueError("dynamic workflow receipt keys must contain at least 32 bytes")
            normalized[key_id] = bytes(key)
        if not normalized:
            raise ValueError("at least one dynamic workflow receipt key is required")
        clean_active = active_key_id.strip()
        if clean_active not in normalized:
            raise ValueError("active receipt key identifier is absent from the key ring")
        self._keys = normalized
        self.active_key_id = clean_active

    def _key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise DynamicWorkflowControlPersistenceError(
                "the checkpoint receipt key is unavailable"
            ) from exc

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes:
        message = domain.encode("ascii") + b"\x00" + _canonical_json(payload)
        return hmac.new(self._key(key_id), message, hashlib.sha256).digest()

    def scoped_session_fingerprint(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
        harness_id: str,
        opaque_session_id: str,
    ) -> str:
        digest = self.sign(
            key_id,
            "lightbulb.dynamic_workflow.session_fingerprint.v1",
            {
                "scope": scope,
                "harness_id": harness_id,
                "opaque_session_id": opaque_session_id,
            },
        ).hex()
        return "dwf_" + digest

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str:
        """Keyed digest binding Context Broker refs to the exact actor scope."""

        return self.sign(
            key_id,
            "lightbulb.dynamic_workflow.context_exact_scope.v1",
            {"scope": scope},
        ).hex()

    def host_binding_ref(
        self,
        *,
        key_id: str,
        run_ref: str,
        role: DynamicWorkflowHostRole,
        session_fingerprint: str,
    ) -> str:
        digest = self.sign(
            key_id,
            "lightbulb.dynamic_workflow.host_binding.v1",
            {
                "run_ref": run_ref,
                "role": role.value,
                "session_fingerprint": session_fingerprint,
            },
        ).hex()
        return "dwh_" + digest

    def session_receipt(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        binding: DynamicWorkflowRoleBinding,
    ) -> str:
        signature = self.sign(
            checkpoint.receipt_key_id,
            "lightbulb.dynamic_workflow.session_receipt.v1",
            {
                "run_ref": checkpoint.run_ref,
                "scope": checkpoint.scope,
                "host_binding_ref": binding.host_binding_ref,
                "scoped_session_fingerprint": binding.scoped_session_fingerprint,
                "harness_id": binding.harness_id,
                "role": binding.role.value,
                "evaluator_builder_result_digest": (
                    binding.evaluator_builder_result_digest
                ),
            },
        )
        return "dws_" + _b64url(signature)

    def assignment_ref(
        self,
        *,
        key_id: str,
        run_ref: str,
        host_binding_ref: str,
        role: DynamicWorkflowHostRole,
        attempt: int,
        idempotency_key: str,
    ) -> str:
        signature = self.sign(
            key_id,
            "lightbulb.dynamic_workflow.assignment_ref.v1",
            {
                "run_ref": run_ref,
                "host_binding_ref": host_binding_ref,
                "role": role.value,
                "attempt": attempt,
                "idempotency_key": idempotency_key,
            },
        )
        return "dwa_" + _b64url(signature)

    def assignment_receipt(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        lease: DynamicWorkflowAssignmentLease,
    ) -> str:
        signature = self.sign(
            checkpoint.receipt_key_id,
            "lightbulb.dynamic_workflow.assignment_receipt.v1",
            {
                "run_ref": checkpoint.run_ref,
                "scope": checkpoint.scope,
                "assignment_ref": lease.assignment_ref,
                "host_binding_ref": lease.host_binding_ref,
                "role": lease.role.value,
                "attempt": lease.attempt,
                "issued_at": lease.issued_at,
                "lease_expires_at": lease.lease_expires_at,
            },
        )
        return "dwl_" + _b64url(signature)

    def opaque_submission_ref(
        self,
        *,
        key_id: str,
        run_ref: str,
        operation: str,
        assignment_ref: str,
        idempotency_key: str,
    ) -> str:
        signature = self.sign(
            key_id,
            "lightbulb.dynamic_workflow.submission_ref.v1",
            {
                "run_ref": run_ref,
                "operation": operation,
                "assignment_ref": assignment_ref,
                "idempotency_key": idempotency_key,
            },
        )
        return "dwb_" + _b64url(signature)

    def seal(self, checkpoint: DynamicWorkflowControlCheckpoint) -> str:
        return "dwc_" + self.sign(
            checkpoint.receipt_key_id,
            "lightbulb.dynamic_workflow.control_integrity.v1",
            _checkpoint_integrity_payload(checkpoint),
        ).hex()

    def verify(self, checkpoint: DynamicWorkflowControlCheckpoint) -> None:
        if checkpoint.context_link is not None:
            expected_scope = self.exact_scope_digest(
                key_id=checkpoint.receipt_key_id,
                scope=checkpoint.scope,
            )
            if not hmac.compare_digest(
                expected_scope,
                checkpoint.context_link.exact_scope_digest,
            ):
                raise DynamicWorkflowControlPersistenceError(
                    "dynamic workflow context link exact-scope verification failed"
                )
        expected = self.seal(checkpoint)
        if not hmac.compare_digest(expected, checkpoint.integrity_mac):
            raise DynamicWorkflowControlPersistenceError(
                "dynamic workflow control checkpoint integrity verification failed"
            )


def _checkpoint_integrity_payload(
    checkpoint: DynamicWorkflowControlCheckpoint,
) -> dict[str, Any]:
    """Return semantic state, excluding server-canonical envelope metadata.

    Spring is authoritative for hosted ids, outer CAS metadata, and envelope
    timestamps.  Those values are either derived/validated by the checkpoint
    model or legitimately canonicalized on a hosted round-trip.  The embedded
    workflow state and mutation ledgers remain sealed in full.
    """

    runtime = checkpoint.runtime_checkpoint
    return {
        "run_ref": checkpoint.run_ref,
        "scope": checkpoint.scope,
        "runtime_checkpoint": {
            "run_ref": runtime.run_ref,
            "workflow_state": runtime.workflow_state,
            "mutation_records": runtime.mutation_records,
        },
        "role_bindings": checkpoint.role_bindings,
        "assignment_leases": checkpoint.assignment_leases,
        "mutation_records": checkpoint.mutation_records,
        "workflow_spec": checkpoint.workflow_spec,
        "initial_inputs": checkpoint.initial_inputs,
        "context_link": checkpoint.context_link,
        "acceptance_policy": checkpoint.acceptance_policy.value,
        "receipt_key_id": checkpoint.receipt_key_id,
    }


class _EphemeralDynamicWorkflowCheckpointStore:
    """Single-checkpoint CAS used before one outer control commit."""

    def __init__(self, checkpoint: DynamicWorkflowCheckpoint) -> None:
        self._checkpoint = checkpoint.model_copy(deep=True)

    def get(self, run_ref: str) -> DynamicWorkflowCheckpoint | None:
        if run_ref != self._checkpoint.run_ref:
            return None
        return self._checkpoint.model_copy(deep=True)

    def save(
        self,
        checkpoint: DynamicWorkflowCheckpoint,
        *,
        expected_revision: int,
    ) -> DynamicWorkflowCheckpoint:
        if self._checkpoint.revision != expected_revision:
            raise DynamicWorkflowCheckpointConflict(
                f"embedded checkpoint revision is {self._checkpoint.revision}, "
                f"expected {expected_revision}"
            )
        if checkpoint.revision != expected_revision + 1:
            raise DynamicWorkflowCheckpointConflict(
                "embedded checkpoint revision must increase by exactly one"
            )
        self._checkpoint = checkpoint.model_copy(deep=True)
        return self._checkpoint.model_copy(deep=True)


def _dynamic_run_ref(scope: DynamicWorkflowScope, idempotency_key: str) -> str:
    digest = _sha256(
        {
            "domain": "lightbulb.dynamic_workflow.run_ref.v1",
            "scope": scope,
            "idempotency_key": idempotency_key,
        }
    )
    return "dwr_" + digest[:40]


def _active_role(status: WorkflowRunStatus) -> DynamicWorkflowHostRole | None:
    return {
        WorkflowRunStatus.PLANNING: DynamicWorkflowHostRole.PLANNER,
        WorkflowRunStatus.BUILDING: DynamicWorkflowHostRole.BUILDER,
        WorkflowRunStatus.EVALUATING: DynamicWorkflowHostRole.EVALUATOR,
    }.get(status)


class DynamicWorkflowController:
    """Atomic, host-neutral implementation of the eight canonical MCP operations."""

    def __init__(
        self,
        store: DynamicWorkflowControlStore,
        key_ring: DynamicWorkflowReceiptKeyRing,
        *,
        host_registry: DynamicWorkflowHostRegistry | None = None,
        lease_seconds: int = 900,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= lease_seconds <= 86_400:
            raise ValueError("lease_seconds must be between 1 and 86400")
        self.store = store
        self.key_ring = key_ring
        self.host_registry = host_registry or default_dynamic_workflow_host_registry()
        if tuple(self.host_registry.harness_ids) != BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS:
            if set(self.host_registry.harness_ids) != set(BUILTIN_DYNAMIC_WORKFLOW_HOST_IDS):
                raise ValueError("controller registry must contain exactly the five harnesses")
        self.lease_seconds = lease_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def execute(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_identity_source: str = "external_ref",
        trusted_usage: UsageDelta | Mapping[str, Any] | None = None,
        trusted_context_start: (
            DynamicWorkflowContextStartAnchor | Mapping[str, Any] | None
        ) = None,
        trusted_context_attach: (
            DynamicWorkflowContextAttachAnchor | Mapping[str, Any] | None
        ) = None,
        trusted_context_checkpoint: (
            DynamicWorkflowContextCheckpointCommit | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        validated = validate_operation_input(operation, payload)
        resolved_authority = DynamicWorkflowControlAuthority.model_validate(authority)
        scope = self._authorized_scope(validated, resolved_authority)
        now = _utc(occurred_at if occurred_at is not None else self.clock())
        handler = getattr(self, f"_{operation}", None)
        if handler is None or operation not in {
            "start",
            "attach",
            "status",
            "next_assignment",
            "submit_plan",
            "submit_builder_result",
            "submit_evaluator_verdict",
            "cancel",
        }:
            raise ValueError(f"unsupported dynamic workflow operation: {operation}")
        clean_identity_source = trusted_identity_source.strip().lower()
        if clean_identity_source not in {
            "external_ref",
            "mcp_session_distinct",
            "runtime_attested",
        }:
            raise ValueError("trusted_identity_source is not supported")
        resolved_usage = UsageDelta.model_validate(trusted_usage or {})
        resolved_context_start = (
            DynamicWorkflowContextStartAnchor.model_validate(trusted_context_start)
            if trusted_context_start is not None
            else None
        )
        resolved_context_attach = (
            DynamicWorkflowContextAttachAnchor.model_validate(trusted_context_attach)
            if trusted_context_attach is not None
            else None
        )
        resolved_context_checkpoint = (
            DynamicWorkflowContextCheckpointCommit.model_validate(
                trusted_context_checkpoint
            )
            if trusted_context_checkpoint is not None
            else None
        )
        supplied_context_arguments = {
            "start": resolved_context_start is not None,
            "attach": resolved_context_attach is not None,
            "checkpoint": resolved_context_checkpoint is not None,
        }
        allowed_context_argument = {
            "start": "start",
            "attach": "attach",
            "submit_plan": "checkpoint",
            "submit_builder_result": "checkpoint",
            "submit_evaluator_verdict": "checkpoint",
        }.get(operation)
        if any(
            supplied and name != allowed_context_argument
            for name, supplied in supplied_context_arguments.items()
        ):
            raise ValueError(
                "trusted context arguments are server-only and operation-specific"
            )
        if operation == "start":
            if resolved_usage != UsageDelta():
                raise ValueError("trusted_usage applies only to artifact submissions")
            output = handler(
                validated,
                scope=scope,
                now=now,
                trusted_identity_source=clean_identity_source,
                trusted_context_start=resolved_context_start,
            )
        elif operation == "attach":
            if resolved_usage != UsageDelta():
                raise ValueError("trusted_usage applies only to artifact submissions")
            output = handler(
                validated,
                scope=scope,
                now=now,
                trusted_identity_source=clean_identity_source,
                trusted_context_attach=resolved_context_attach,
            )
        elif operation in {
            "submit_plan",
            "submit_builder_result",
            "submit_evaluator_verdict",
        }:
            if clean_identity_source != "external_ref":
                raise ValueError(
                    "trusted_identity_source applies only to start and attach"
                )
            output = handler(
                validated,
                scope=scope,
                now=now,
                trusted_usage=resolved_usage,
                trusted_context_checkpoint=resolved_context_checkpoint,
            )
        else:
            if clean_identity_source != "external_ref":
                raise ValueError(
                    "trusted_identity_source applies only to start and attach"
                )
            if resolved_usage != UsageDelta():
                raise ValueError("trusted_usage applies only to artifact submissions")
            output = handler(validated, scope=scope, now=now)
        _, resolved = validate_operation_exchange(operation, validated, output)
        return resolved

    def start(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_identity_source: str = "external_ref",
        trusted_context_start: (
            DynamicWorkflowContextStartAnchor | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        return self.execute(
            "start",
            payload,
            authority=authority,
            occurred_at=occurred_at,
            trusted_identity_source=trusted_identity_source,
            trusted_context_start=trusted_context_start,
        )

    def attach(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_identity_source: str = "external_ref",
        trusted_context_attach: (
            DynamicWorkflowContextAttachAnchor | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        return self.execute(
            "attach",
            payload,
            authority=authority,
            occurred_at=occurred_at,
            trusted_identity_source=trusted_identity_source,
            trusted_context_attach=trusted_context_attach,
        )

    def status(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        return self.execute(
            "status", payload, authority=authority, occurred_at=occurred_at
        )

    def next_assignment(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        return self.execute(
            "next_assignment",
            payload,
            authority=authority,
            occurred_at=occurred_at,
        )

    def submit_plan(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_usage: UsageDelta | Mapping[str, Any] | None = None,
        trusted_context_checkpoint: (
            DynamicWorkflowContextCheckpointCommit | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        return self.execute(
            "submit_plan",
            payload,
            authority=authority,
            occurred_at=occurred_at,
            trusted_usage=trusted_usage,
            trusted_context_checkpoint=trusted_context_checkpoint,
        )

    def submit_builder_result(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_usage: UsageDelta | Mapping[str, Any] | None = None,
        trusted_context_checkpoint: (
            DynamicWorkflowContextCheckpointCommit | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        return self.execute(
            "submit_builder_result",
            payload,
            authority=authority,
            occurred_at=occurred_at,
            trusted_usage=trusted_usage,
            trusted_context_checkpoint=trusted_context_checkpoint,
        )

    def submit_evaluator_verdict(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
        trusted_usage: UsageDelta | Mapping[str, Any] | None = None,
        trusted_context_checkpoint: (
            DynamicWorkflowContextCheckpointCommit | Mapping[str, Any] | None
        ) = None,
    ) -> dict[str, Any]:
        return self.execute(
            "submit_evaluator_verdict",
            payload,
            authority=authority,
            occurred_at=occurred_at,
            trusted_usage=trusted_usage,
            trusted_context_checkpoint=trusted_context_checkpoint,
        )

    def cancel(
        self,
        payload: Mapping[str, Any],
        *,
        authority: DynamicWorkflowControlAuthority | Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        return self.execute(
            "cancel", payload, authority=authority, occurred_at=occurred_at
        )

    def _authorized_scope(
        self,
        payload: Mapping[str, Any],
        authority: DynamicWorkflowControlAuthority,
    ) -> DynamicWorkflowScope:
        if payload["company_ref"] != authority.company_ref:
            raise DynamicWorkflowCustodyError(
                "company_ref does not match the authenticated workflow scope"
            )
        if payload["project_ref"] != authority.project_ref:
            raise DynamicWorkflowCustodyError(
                "project_ref does not match the authenticated workflow scope"
            )
        return authority.scope

    def _load(
        self,
        run_ref: str,
        *,
        scope: DynamicWorkflowScope,
    ) -> DynamicWorkflowControlCheckpoint:
        checkpoint = self.store.get(run_ref)
        if checkpoint is None:
            raise DynamicWorkflowControlNotFound(
                f"dynamic workflow control checkpoint not found: {run_ref}"
            )
        checkpoint.scope.require_exact(scope)
        self.key_ring.verify(checkpoint)
        return checkpoint

    def _seal(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> DynamicWorkflowControlCheckpoint:
        unsigned = checkpoint.model_copy(update={"integrity_mac": _EMPTY_INTEGRITY_MAC})
        if unsigned.context_link is not None:
            expected_scope = self.key_ring.exact_scope_digest(
                key_id=unsigned.receipt_key_id,
                scope=unsigned.scope,
            )
            if not hmac.compare_digest(
                expected_scope,
                unsigned.context_link.exact_scope_digest,
            ):
                raise DynamicWorkflowCustodyError(
                    "context link does not belong to the exact workflow scope"
                )
        sealed = unsigned.model_copy(update={"integrity_mac": self.key_ring.seal(unsigned)})
        if len(_canonical_json(sealed)) > _MAX_CONTROL_CHECKPOINT_BYTES:
            raise DynamicWorkflowControlPersistenceError(
                "dynamic workflow control checkpoint exceeds the hosted 1.8 MiB safety limit"
            )
        return DynamicWorkflowControlCheckpoint.model_validate(
            sealed.model_dump(mode="python", by_alias=False)
        )

    @staticmethod
    def _request_digest(
        operation: str,
        payload: Mapping[str, Any],
        scope: DynamicWorkflowScope,
        trusted_context: BaseModel | str | None = None,
    ) -> str:
        material: dict[str, Any] = {
            "operation": operation,
            "scope": scope,
            "payload": payload,
        }
        if trusted_context is not None:
            material["trusted_context"] = trusted_context
        return _sha256(material)

    @staticmethod
    def _existing_record(
        checkpoint: DynamicWorkflowControlCheckpoint,
        *,
        operation: str,
        idempotency_key: str,
        request_digest: str,
    ) -> DynamicWorkflowControlMutationRecord | None:
        record = checkpoint.mutation_for(idempotency_key)
        if record is None:
            return None
        if record.operation != operation or record.request_digest != request_digest:
            raise DynamicWorkflowControlConflict(
                "idempotency_key was reused for a different control mutation"
            )
        return record

    @staticmethod
    def _require_expected_revision(
        checkpoint: DynamicWorkflowControlCheckpoint,
        expected_revision: int,
    ) -> None:
        if checkpoint.revision != expected_revision:
            raise DynamicWorkflowControlConflict(
                f"control revision is {checkpoint.revision}, expected {expected_revision}"
            )

    @staticmethod
    def _require_active(checkpoint: DynamicWorkflowControlCheckpoint) -> None:
        if checkpoint.terminal:
            raise DynamicWorkflowRolePhaseError(
                f"dynamic workflow is terminal: {checkpoint.status.value}"
            )

    @staticmethod
    def _append_bounded(
        values: tuple[Any, ...],
        value: Any,
        *,
        label: str,
    ) -> tuple[Any, ...]:
        if len(values) >= _MAX_HISTORY:
            raise DynamicWorkflowControlPersistenceError(
                f"bounded {label} history reached its {_MAX_HISTORY}-entry capacity"
            )
        return values + (value,)

    def _candidate(
        self,
        previous: DynamicWorkflowControlCheckpoint,
        *,
        runtime_checkpoint: DynamicWorkflowCheckpoint | None = None,
        role_bindings: tuple[DynamicWorkflowRoleBinding, ...] | None = None,
        assignment_leases: tuple[DynamicWorkflowAssignmentLease, ...] | None = None,
        context_link: DynamicWorkflowContextLink | None = None,
        record: DynamicWorkflowControlMutationRecord,
        updated_at: datetime,
    ) -> DynamicWorkflowControlCheckpoint:
        runtime = runtime_checkpoint or previous.runtime_checkpoint
        records = self._append_bounded(
            previous.mutation_records,
            record,
            label="mutation replay",
        )
        leases = assignment_leases or previous.assignment_leases
        unresolved = next(
            (
                lease
                for lease in leases
                if lease.resolution == DynamicWorkflowLeaseResolution.OPEN
            ),
            None,
        )
        candidate = DynamicWorkflowControlCheckpoint(
            run_ref=previous.run_ref,
            hosted_project_id=previous.hosted_project_id,
            status=runtime.status,
            revision=previous.revision + 1,
            scope=previous.scope,
            runtime_checkpoint=runtime,
            role_bindings=role_bindings or previous.role_bindings,
            assignment_leases=leases,
            mutation_records=records,
            workflow_spec=previous.workflow_spec,
            initial_inputs=previous.initial_inputs,
            context_link=(
                context_link if context_link is not None else previous.context_link
            ),
            acceptance_policy=previous.acceptance_policy,
            receipt_key_id=previous.receipt_key_id,
            integrity_mac=_EMPTY_INTEGRITY_MAC,
            created_at=previous.created_at,
            updated_at=updated_at,
            resume_at=previous.resume_at,
            lease_owner=unresolved.assignment_ref if unresolved else None,
            lease_until=unresolved.lease_expires_at if unresolved else None,
        )
        return self._seal(candidate)

    def _commit(
        self,
        candidate: DynamicWorkflowControlCheckpoint,
        *,
        previous: DynamicWorkflowControlCheckpoint,
        operation: str,
        idempotency_key: str,
        request_digest: str,
    ) -> tuple[
        DynamicWorkflowControlCheckpoint,
        DynamicWorkflowControlMutationRecord,
        bool,
    ]:
        try:
            saved = self.store.save(candidate, expected_revision=previous.revision)
        except DynamicWorkflowControlConflict:
            concurrent = self._load(previous.run_ref, scope=previous.scope)
            record = self._existing_record(
                concurrent,
                operation=operation,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if record is None:
                raise
            return concurrent, record, True
        self.key_ring.verify(saved)
        record = saved.mutation_for(idempotency_key)
        if record is None:
            raise DynamicWorkflowControlPersistenceError(
                "saved checkpoint omitted the committed mutation record"
            )
        return saved, record, False

    @staticmethod
    def _base_output(
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord | None = None,
    ) -> dict[str, Any]:
        output: dict[str, Any] = {
            "run_ref": checkpoint.run_ref,
            "revision": record.committed_revision if record else checkpoint.revision,
            "status": (
                record.committed_status.value if record else checkpoint.status.value
            ),
            "scope": {
                "company_scoped": True,
                "project_scoped": True,
                "company_ref": canonical_dynamic_workflow_company_ref(
                    tenant_id=checkpoint.scope.tenant_id,
                    company_id=checkpoint.scope.company_id,
                ),
                "project_ref": checkpoint.scope.project_ref,
            },
            "context_linked": checkpoint.context_link is not None,
        }
        if checkpoint.context_link is not None:
            output["context_revision"] = (
                record.context_revision
                if record is not None and record.context_revision is not None
                else checkpoint.context_link.current_context_revision
            )
        return output

    def _binding_from_payload(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        payload: Mapping[str, Any],
    ) -> DynamicWorkflowRoleBinding:
        binding = checkpoint.binding_for(payload["host_binding_ref"])
        if binding is None:
            raise DynamicWorkflowCustodyError("host binding is unknown for this run")
        requested_role = DynamicWorkflowHostRole(payload["host_role"])
        if binding.role != requested_role:
            raise DynamicWorkflowCustodyError("host binding does not hold the requested role")
        expected = self.key_ring.session_receipt(checkpoint, binding)
        if not hmac.compare_digest(expected, payload["session_receipt"]):
            raise DynamicWorkflowCustodyError("session receipt did not prove host custody")
        return binding

    def _new_context_link(
        self,
        *,
        scope: DynamicWorkflowScope,
        key_id: str,
        binding: DynamicWorkflowRoleBinding,
        trusted: DynamicWorkflowContextStartAnchor | None,
    ) -> DynamicWorkflowContextLink | None:
        if trusted is None:
            return None
        binding_anchor = DynamicWorkflowContextBindingAnchor(
            host_binding_ref=binding.host_binding_ref,
            context_binding_ref=trusted.context_binding_ref,
            role=binding.role,
            bound_at_context_revision=trusted.context_revision,
        )
        latest = None
        if trusted.latest_checkpoint_ref is not None:
            latest = DynamicWorkflowContextCheckpointAnchor(
                host_binding_ref=binding.host_binding_ref,
                context_binding_ref=trusted.context_binding_ref,
                context_revision=trusted.context_revision,
                checkpoint_ref=trusted.latest_checkpoint_ref,
                supporting_refs=trusted.supporting_refs,
            )
        return DynamicWorkflowContextLink(
            context_ref=trusted.context_ref,
            exact_scope_digest=self.key_ring.exact_scope_digest(
                key_id=key_id,
                scope=scope,
            ),
            current_context_revision=trusted.context_revision,
            binding_anchors=(binding_anchor,),
            latest_checkpoint_anchor=latest,
        )

    def _attach_context_binding(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        binding: DynamicWorkflowRoleBinding,
        trusted_context_attach: DynamicWorkflowContextAttachAnchor | None,
    ) -> DynamicWorkflowContextLink | None:
        link = checkpoint.context_link
        if link is None:
            if trusted_context_attach is not None:
                raise DynamicWorkflowCustodyError(
                    "an offline workflow cannot accept a Context Broker binding"
                )
            return None
        if trusted_context_attach is None:
            raise DynamicWorkflowCustodyError(
                "linked attach requires a trusted Context Broker binding"
            )
        if trusted_context_attach.context_ref != link.context_ref:
            raise DynamicWorkflowCustodyError(
                "attached Context Broker binding belongs to a different context space"
            )
        if trusted_context_attach.context_revision != link.current_context_revision:
            raise DynamicWorkflowCustodyError(
                "attached Context Broker binding is stale for the linked context revision"
            )
        if any(
            item.context_binding_ref == trusted_context_attach.context_binding_ref
            for item in link.binding_anchors
        ):
            raise DynamicWorkflowCustodyError(
                "each workflow role binding requires its own Context Broker binding"
            )
        anchors = self._append_bounded(
            link.binding_anchors,
            DynamicWorkflowContextBindingAnchor(
                host_binding_ref=binding.host_binding_ref,
                context_binding_ref=trusted_context_attach.context_binding_ref,
                role=binding.role,
                bound_at_context_revision=trusted_context_attach.context_revision,
            ),
            label="context binding",
        )
        payload = link.model_dump(mode="python", by_alias=False)
        payload["binding_anchors"] = anchors
        return DynamicWorkflowContextLink.model_validate(payload)

    @staticmethod
    def _context_anchor_for_binding(
        checkpoint: DynamicWorkflowControlCheckpoint,
        binding: DynamicWorkflowRoleBinding,
    ) -> DynamicWorkflowContextCheckpointAnchor | None:
        link = checkpoint.context_link
        if link is None:
            return None
        context_binding = link.binding_for(binding.host_binding_ref)
        if context_binding is None or context_binding.role != binding.role:
            raise DynamicWorkflowCustodyError(
                "linked host binding has no matching Context Broker role mapping"
            )
        latest = link.latest_checkpoint_anchor
        return DynamicWorkflowContextCheckpointAnchor(
            host_binding_ref=binding.host_binding_ref,
            context_binding_ref=context_binding.context_binding_ref,
            context_revision=link.current_context_revision,
            checkpoint_ref=latest.checkpoint_ref if latest is not None else None,
            supporting_refs=latest.supporting_refs if latest is not None else (),
        )

    @staticmethod
    def _advance_context_checkpoint(
        checkpoint: DynamicWorkflowControlCheckpoint,
        binding: DynamicWorkflowRoleBinding,
        trusted: DynamicWorkflowContextCheckpointCommit | None,
    ) -> DynamicWorkflowContextLink | None:
        link = checkpoint.context_link
        if link is None:
            if trusted is not None:
                raise DynamicWorkflowCustodyError(
                    "an offline workflow cannot accept a Context Broker checkpoint"
                )
            return None
        if trusted is None:
            raise DynamicWorkflowCustodyError(
                "linked artifact submission requires a committed context checkpoint anchor"
            )
        context_binding = link.binding_for(binding.host_binding_ref)
        if context_binding is None or context_binding.role != binding.role:
            raise DynamicWorkflowCustodyError(
                "linked host binding has no matching Context Broker role mapping"
            )
        if trusted.context_binding_ref != context_binding.context_binding_ref:
            raise DynamicWorkflowCustodyError(
                "context checkpoint binding differs from the submitting role mapping"
            )
        if trusted.context_ref != link.context_ref:
            raise DynamicWorkflowCustodyError(
                "context checkpoint space differs from the linked Context Broker space"
            )
        if trusted.base_context_revision != link.current_context_revision:
            raise DynamicWorkflowControlConflict(
                f"context revision is {link.current_context_revision}, expected "
                f"{trusted.base_context_revision}"
            )
        latest = DynamicWorkflowContextCheckpointAnchor(
            host_binding_ref=binding.host_binding_ref,
            context_binding_ref=context_binding.context_binding_ref,
            context_revision=trusted.context_revision,
            checkpoint_ref=trusted.checkpoint_ref,
            supporting_refs=trusted.supporting_refs,
        )
        payload = link.model_dump(mode="python", by_alias=False)
        payload.update(
            current_context_revision=trusted.context_revision,
            latest_checkpoint_anchor=latest,
        )
        return DynamicWorkflowContextLink.model_validate(payload)

    def _new_binding(
        self,
        *,
        checkpoint: DynamicWorkflowControlCheckpoint | None,
        scope: DynamicWorkflowScope,
        run_ref: str,
        harness_id: str,
        host_session_ref: str | None,
        role: DynamicWorkflowHostRole,
        key_id: str,
        attached_at: datetime,
        trusted_identity_source: str,
    ) -> DynamicWorkflowRoleBinding:
        self.host_registry.get(harness_id)
        if host_session_ref is None or not host_session_ref.strip():
            if checkpoint is not None:
                raise DynamicWorkflowCustodyError(
                    "only the start operation may create an anonymous binding"
                )
            opaque_session_id = f"anonymous:{run_ref}"
            identity_source = "anonymous_start"
        else:
            identity = self.host_registry.normalize_session_identity(
                harness_id,
                host_session_ref,
                scope=scope,
                authorized_scope=scope,
            )
            opaque_session_id = identity.opaque_session_id
            identity_source = trusted_identity_source
        fingerprint = self.key_ring.scoped_session_fingerprint(
            key_id=key_id,
            scope=scope,
            harness_id=harness_id,
            opaque_session_id=opaque_session_id,
        )
        binding_ref = self.key_ring.host_binding_ref(
            key_id=key_id,
            run_ref=run_ref,
            role=role,
            session_fingerprint=fingerprint,
        )
        if checkpoint is not None:
            if checkpoint.binding_for(binding_ref) is not None:
                raise DynamicWorkflowControlConflict(
                    "this host session already has the requested role binding"
                )
            if role == DynamicWorkflowHostRole.EVALUATOR:
                forbidden = {
                    item.scoped_session_fingerprint
                    for item in checkpoint.role_bindings
                    if item.role
                    in {
                        DynamicWorkflowHostRole.BUILDER,
                        DynamicWorkflowHostRole.EVALUATOR,
                    }
                }
                if fingerprint in forbidden:
                    raise DynamicWorkflowCustodyError(
                        "evaluator session must be fresh from every builder and prior evaluator"
                    )
            elif role == DynamicWorkflowHostRole.BUILDER:
                evaluator_fingerprints = {
                    item.scoped_session_fingerprint
                    for item in checkpoint.role_bindings
                    if item.role == DynamicWorkflowHostRole.EVALUATOR
                }
                if fingerprint in evaluator_fingerprints:
                    raise DynamicWorkflowCustodyError(
                        "builder session cannot reuse an evaluator session"
                    )
        evaluator_anchor: str | None = None
        if role == DynamicWorkflowHostRole.EVALUATOR:
            if checkpoint is None:
                raise DynamicWorkflowRolePhaseError(
                    "an evaluator cannot be created by the start operation"
                )
            builder_result = checkpoint.runtime_checkpoint.workflow_state.current_builder_result
            if builder_result is None:
                raise DynamicWorkflowRolePhaseError(
                    "evaluator binding requires the current builder result"
                )
            evaluator_anchor = builder_result.digest
        return DynamicWorkflowRoleBinding(
            host_binding_ref=binding_ref,
            scoped_session_fingerprint=fingerprint,
            harness_id=harness_id,
            role=role,
            evaluator_builder_result_digest=evaluator_anchor,
            session_identity_attested=identity_source == "runtime_attested",
            identity_source=identity_source,
            attached_at=attached_at,
        )

    @staticmethod
    def _require_role_phase(
        checkpoint: DynamicWorkflowControlCheckpoint,
        role: DynamicWorkflowHostRole,
    ) -> None:
        active = _active_role(checkpoint.status)
        if active != role:
            raise DynamicWorkflowRolePhaseError(
                f"{role.value} custody is unavailable while status is "
                f"{checkpoint.status.value}"
            )

    @staticmethod
    def _core_idempotency_key(operation: str, idempotency_key: str, suffix: str) -> str:
        return f"control:{operation}:{suffix}:{_sha256(idempotency_key)[:32]}"

    @staticmethod
    def _embedded_runtime(
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> DynamicWorkflowRuntime:
        return DynamicWorkflowRuntime(
            _EphemeralDynamicWorkflowCheckpointStore(checkpoint.runtime_checkpoint)
        )

    @staticmethod
    def _binding_freshness_assurance(
        binding: DynamicWorkflowRoleBinding,
    ) -> DynamicWorkflowEvaluatorFreshnessAssurance:
        return {
            "external_ref": (
                DynamicWorkflowEvaluatorFreshnessAssurance.DISTINCT_BINDING_EXTERNAL_REF
            ),
            "mcp_session_distinct": (
                DynamicWorkflowEvaluatorFreshnessAssurance.DISTINCT_MCP_SESSION
            ),
            "runtime_attested": (
                DynamicWorkflowEvaluatorFreshnessAssurance.RUNTIME_ATTESTED_FRESH_CONTEXT
            ),
            "anonymous_start": DynamicWorkflowEvaluatorFreshnessAssurance.NOT_EVALUATED,
        }[binding.identity_source]

    @staticmethod
    def _require_current_evaluator_anchor(
        checkpoint: DynamicWorkflowControlCheckpoint,
        binding: DynamicWorkflowRoleBinding,
    ) -> None:
        result = checkpoint.runtime_checkpoint.workflow_state.current_builder_result
        if (
            binding.role != DynamicWorkflowHostRole.EVALUATOR
            or result is None
            or binding.evaluator_builder_result_digest != result.digest
        ):
            raise DynamicWorkflowCustodyError(
                "evaluator binding is not anchored to the current builder result"
            )

    @staticmethod
    def _binding_for_current_verdict(
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> DynamicWorkflowRoleBinding | None:
        state = checkpoint.runtime_checkpoint.workflow_state
        verdict = state.current_verdict
        result = state.current_builder_result
        if (
            verdict is None
            or result is None
            or verdict.builder_result_digest != result.digest
        ):
            return None
        binding = checkpoint.binding_for(verdict.evaluator_session_id)
        if (
            binding is None
            or binding.role != DynamicWorkflowHostRole.EVALUATOR
            or binding.evaluator_builder_result_digest != result.digest
        ):
            return None
        return binding

    def _status_freshness_assurance(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        caller_binding: DynamicWorkflowRoleBinding,
    ) -> DynamicWorkflowEvaluatorFreshnessAssurance:
        if caller_binding.role == DynamicWorkflowHostRole.EVALUATOR:
            try:
                self._require_current_evaluator_anchor(checkpoint, caller_binding)
            except DynamicWorkflowCustodyError:
                return DynamicWorkflowEvaluatorFreshnessAssurance.NOT_EVALUATED
            return self._binding_freshness_assurance(caller_binding)
        verdict_binding = self._binding_for_current_verdict(checkpoint)
        if verdict_binding is None:
            return DynamicWorkflowEvaluatorFreshnessAssurance.NOT_EVALUATED
        return self._binding_freshness_assurance(verdict_binding)

    def _acceptance_assurance(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> DynamicWorkflowAcceptanceAssurance:
        if checkpoint.status != WorkflowRunStatus.ACCEPTED:
            return DynamicWorkflowAcceptanceAssurance.NOT_ACCEPTED
        binding = self._binding_for_current_verdict(checkpoint)
        if binding is None:
            raise DynamicWorkflowControlPersistenceError(
                "accepted workflow has no anchored evaluator binding"
            )
        if binding.identity_source == "runtime_attested":
            return DynamicWorkflowAcceptanceAssurance.RUNTIME_ATTESTED
        if binding.identity_source == "mcp_session_distinct":
            return DynamicWorkflowAcceptanceAssurance.DISTINCT_MCP_SESSION
        return DynamicWorkflowAcceptanceAssurance.DISTINCT_BINDING

    def _start(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
        trusted_identity_source: str,
        trusted_context_start: DynamicWorkflowContextStartAnchor | None,
    ) -> dict[str, Any]:
        idempotency_key = payload["idempotency_key"]
        run_ref = _dynamic_run_ref(scope, idempotency_key)
        request_digest = self._request_digest(
            "start",
            payload,
            scope,
            trusted_context_start,
        )
        existing = self.store.get(run_ref)
        if existing is not None:
            existing.scope.require_exact(scope)
            self.key_ring.verify(existing)
            record = self._existing_record(
                existing,
                operation="start",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if record is None:
                raise DynamicWorkflowControlConflict(
                    f"dynamic workflow run already exists: {run_ref}"
                )
            return self._start_output(existing, record)

        criteria = tuple(
            AcceptanceCriterion.model_validate(item)
            for item in payload["acceptance_criteria"]
        )
        workflow_spec = payload.get("workflow_spec", {})
        limit_source = workflow_spec.get("limits", workflow_spec)
        if not isinstance(limit_source, Mapping):
            raise ValueError("workflow_spec limits must be an object")
        limit_fields = set(WorkflowLimits.model_fields)
        limit_values = {
            key: value for key, value in limit_source.items() if key in limit_fields
        }
        limits = WorkflowLimits.model_validate(limit_values)
        core_store = InMemoryDynamicWorkflowCheckpointStore()
        core_result = DynamicWorkflowRuntime(core_store).start(
            scope=scope,
            run_ref=run_ref,
            objective=payload["objective"],
            acceptance_criteria=criteria,
            created_at=now,
            idempotency_key=self._core_idempotency_key(
                "start", idempotency_key, "create"
            ),
            limits=limits,
        )
        key_id = self.key_ring.active_key_id
        binding = self._new_binding(
            checkpoint=None,
            scope=scope,
            run_ref=run_ref,
            harness_id=payload["host"],
            host_session_ref=payload.get("host_session_ref"),
            role=DynamicWorkflowHostRole.PLANNER,
            key_id=key_id,
            attached_at=now,
            trusted_identity_source=trusted_identity_source,
        )
        context_link = self._new_context_link(
            scope=scope,
            key_id=key_id,
            binding=binding,
            trusted=trusted_context_start,
        )
        record = DynamicWorkflowControlMutationRecord(
            operation="start",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            committed_revision=1,
            runtime_revision=core_result.checkpoint.revision,
            committed_status=core_result.checkpoint.status,
            subject_ref=binding.host_binding_ref,
            next_role=DynamicWorkflowHostRole.PLANNER,
            context_revision=(
                context_link.current_context_revision
                if context_link is not None
                else None
            ),
            occurred_at=now,
        )
        checkpoint = DynamicWorkflowControlCheckpoint(
            run_ref=run_ref,
            status=core_result.checkpoint.status,
            revision=1,
            scope=scope,
            runtime_checkpoint=core_result.checkpoint,
            role_bindings=(binding,),
            mutation_records=(record,),
            workflow_spec=workflow_spec,
            initial_inputs=payload.get("inputs", {}),
            context_link=context_link,
            acceptance_policy=DynamicWorkflowAcceptancePolicy(
                payload.get("acceptance_policy", "distinct_binding")
            ),
            receipt_key_id=key_id,
            integrity_mac=_EMPTY_INTEGRITY_MAC,
            created_at=now,
            updated_at=now,
        )
        checkpoint = self._seal(checkpoint)
        try:
            saved = self.store.save(checkpoint, expected_revision=0)
        except DynamicWorkflowControlConflict:
            concurrent = self._load(run_ref, scope=scope)
            concurrent_record = self._existing_record(
                concurrent,
                operation="start",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if concurrent_record is None:
                raise
            return self._start_output(concurrent, concurrent_record)
        self.key_ring.verify(saved)
        return self._start_output(saved, record)

    def _start_output(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        binding = checkpoint.binding_for(record.subject_ref)
        if binding is None:
            raise DynamicWorkflowControlPersistenceError(
                "start mutation references a missing host binding"
            )
        return {
            **self._base_output(checkpoint, record),
            "host_binding_ref": binding.host_binding_ref,
            "session_receipt": self.key_ring.session_receipt(checkpoint, binding),
            "bound_role": binding.role.value,
            "created_at": checkpoint.created_at.isoformat(),
            "acceptance_policy": checkpoint.acceptance_policy.value,
        }

    def _attach(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
        trusted_identity_source: str,
        trusted_context_attach: DynamicWorkflowContextAttachAnchor | None,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        if checkpoint.context_link is None and trusted_context_attach is not None:
            raise DynamicWorkflowCustodyError(
                "an offline workflow cannot accept a Context Broker binding"
            )
        if checkpoint.context_link is not None and trusted_context_attach is None:
            raise DynamicWorkflowCustodyError(
                "linked attach requires a trusted Context Broker binding"
            )
        request_digest = self._request_digest(
            "attach",
            payload,
            scope,
            trusted_context_attach,
        )
        existing = self._existing_record(
            checkpoint,
            operation="attach",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._attach_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        role = DynamicWorkflowHostRole(payload["host_role"])
        self._require_role_phase(checkpoint, role)
        binding = self._new_binding(
            checkpoint=checkpoint,
            scope=scope,
            run_ref=checkpoint.run_ref,
            harness_id=payload["host"],
            host_session_ref=payload["host_session_ref"],
            role=role,
            key_id=checkpoint.receipt_key_id,
            attached_at=now,
            trusted_identity_source=trusted_identity_source,
        )
        context_link = self._attach_context_binding(
            checkpoint,
            binding,
            trusted_context_attach,
        )
        bindings = self._append_bounded(
            checkpoint.role_bindings,
            binding,
            label="role binding",
        )
        record = DynamicWorkflowControlMutationRecord(
            operation="attach",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=checkpoint.runtime_revision,
            committed_status=checkpoint.status,
            subject_ref=binding.host_binding_ref,
            next_role=role,
            context_revision=(
                context_link.current_context_revision
                if context_link is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            role_bindings=bindings,
            context_link=context_link,
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="attach",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._attach_output(saved, committed)

    def _attach_output(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        binding = checkpoint.binding_for(record.subject_ref)
        if binding is None:
            raise DynamicWorkflowControlPersistenceError(
                "attach mutation references a missing host binding"
            )
        return {
            **self._base_output(checkpoint, record),
            "host_binding_ref": binding.host_binding_ref,
            "session_receipt": self.key_ring.session_receipt(checkpoint, binding),
            "bound_role": binding.role.value,
            "attached_at": record.occurred_at.isoformat(),
        }

    def _status(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        binding = self._binding_from_payload(checkpoint, payload)
        active = _active_role(checkpoint.status)
        unresolved = checkpoint.unresolved_assignment()
        lease_unavailable = unresolved is not None and unresolved.is_active(now)
        evaluator_reused = (
            binding.role == DynamicWorkflowHostRole.EVALUATOR
            and any(
                lease.role == DynamicWorkflowHostRole.EVALUATOR
                and lease.host_binding_ref == binding.host_binding_ref
                for lease in checkpoint.assignment_leases
            )
        )
        evaluator_anchor_current = True
        if binding.role == DynamicWorkflowHostRole.EVALUATOR:
            try:
                self._require_current_evaluator_anchor(checkpoint, binding)
            except DynamicWorkflowCustodyError:
                evaluator_anchor_current = False
        output = {
            **self._base_output(checkpoint),
            "terminal": checkpoint.terminal,
            "assignment_available": bool(
                not checkpoint.terminal
                and active == binding.role
                and not lease_unavailable
                and not evaluator_reused
                and evaluator_anchor_current
            ),
            "iteration": checkpoint.runtime_checkpoint.workflow_state.iterations,
            "updated_at": checkpoint.updated_at.isoformat(),
            "evaluator_freshness_assurance": self._status_freshness_assurance(
                checkpoint, binding
            ).value,
            "acceptance_assurance": self._acceptance_assurance(checkpoint).value,
            "acceptance_policy": checkpoint.acceptance_policy.value,
        }
        if active is not None:
            output["active_role"] = active.value
        return output

    def _next_assignment(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        binding = self._binding_from_payload(checkpoint, payload)
        request_digest = self._request_digest("next_assignment", payload, scope)
        existing = self._existing_record(
            checkpoint,
            operation="next_assignment",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._assignment_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        self._require_role_phase(checkpoint, binding.role)
        if binding.role == DynamicWorkflowHostRole.EVALUATOR:
            self._require_current_evaluator_anchor(checkpoint, binding)
        if binding.role == DynamicWorkflowHostRole.EVALUATOR and any(
            lease.role == DynamicWorkflowHostRole.EVALUATOR
            and lease.host_binding_ref == binding.host_binding_ref
            for lease in checkpoint.assignment_leases
        ):
            raise DynamicWorkflowCustodyError(
                "each evaluator attempt requires a freshly attached session"
            )

        leases = list(checkpoint.assignment_leases)
        unresolved = checkpoint.unresolved_assignment()
        if unresolved is not None:
            if unresolved.is_active(now):
                raise DynamicWorkflowControlConflict(
                    "another exclusive dynamic workflow assignment lease is active"
                )
            leases = [
                self._resolve_lease(
                    lease,
                    resolution=DynamicWorkflowLeaseResolution.EXPIRED,
                    resolved_at=now,
                )
                if lease.assignment_ref == unresolved.assignment_ref
                else lease
                for lease in leases
            ]

        state = checkpoint.runtime_checkpoint.workflow_state
        attempt = {
            DynamicWorkflowHostRole.PLANNER: state.plan_revisions + 1,
            DynamicWorkflowHostRole.BUILDER: state.iterations + 1,
            DynamicWorkflowHostRole.EVALUATOR: state.evaluation_attempts + 1,
        }[binding.role]
        assignment_ref = self.key_ring.assignment_ref(
            key_id=checkpoint.receipt_key_id,
            run_ref=checkpoint.run_ref,
            host_binding_ref=binding.host_binding_ref,
            role=binding.role,
            attempt=attempt,
            idempotency_key=payload["idempotency_key"],
        )
        instructions, assignment_payload = self._assignment_material(
            checkpoint, binding.role
        )
        context_anchor = self._context_anchor_for_binding(checkpoint, binding)
        lease = DynamicWorkflowAssignmentLease(
            assignment_ref=assignment_ref,
            host_binding_ref=binding.host_binding_ref,
            role=binding.role,
            attempt=attempt,
            instructions=instructions,
            payload=assignment_payload,
            issued_at=now,
            lease_expires_at=now + timedelta(seconds=self.lease_seconds),
            context_anchor=context_anchor,
        )
        if len(leases) >= _MAX_HISTORY:
            raise DynamicWorkflowControlPersistenceError(
                f"bounded assignment lease history reached its {_MAX_HISTORY}-entry capacity"
            )
        leases.append(lease)
        record = DynamicWorkflowControlMutationRecord(
            operation="next_assignment",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=checkpoint.runtime_revision,
            committed_status=checkpoint.status,
            subject_ref=assignment_ref,
            next_role=binding.role,
            context_revision=(
                checkpoint.context_link.current_context_revision
                if checkpoint.context_link is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            assignment_leases=tuple(leases),
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="next_assignment",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._assignment_output(saved, committed)

    def _assignment_material(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        role: DynamicWorkflowHostRole,
    ) -> tuple[str, dict[str, Any]]:
        state = checkpoint.runtime_checkpoint.workflow_state
        criteria = [item.model_dump(mode="json") for item in state.acceptance_criteria]
        criterion_ids = [item.criterion_id for item in state.acceptance_criteria]
        common: dict[str, Any] = {
            "objective": state.objective,
            "acceptance_criteria": criteria,
            "required_criterion_ids": criterion_ids,
            "acceptance_policy": checkpoint.acceptance_policy.value,
        }
        if role == DynamicWorkflowHostRole.PLANNER:
            return (
                "Create the next bounded plan without changing the objective or immutable "
                "acceptance criteria.",
                {
                    **common,
                    "plan_revision": state.plan_revisions + 1,
                    "workflow_spec": checkpoint.workflow_spec,
                    "inputs": checkpoint.initial_inputs,
                    "prior_verdict": (
                        state.current_verdict.model_dump(
                            mode="json", exclude={"scope"}
                        )
                        if state.current_verdict is not None
                        else None
                    ),
                },
            )
        if role == DynamicWorkflowHostRole.BUILDER:
            if state.current_plan is None:
                raise DynamicWorkflowRolePhaseError(
                    "builder assignment requires a durable planner plan"
                )
            return (
                "Implement the current immutable plan and return content-addressed evidence "
                "mapped to every criterion it supports or disproves.",
                {
                    **common,
                    "iteration": state.iterations + 1,
                    "plan": state.current_plan.model_dump(
                        mode="json", exclude={"scope"}
                    ),
                    "prior_verdict": (
                        state.current_verdict.model_dump(
                            mode="json", exclude={"scope"}
                        )
                        if state.current_verdict is not None
                        else None
                    ),
                },
            )
        if state.current_plan is None or state.current_builder_result is None:
            raise DynamicWorkflowRolePhaseError(
                "evaluator assignment requires a plan and completed builder result"
            )
        evidence_bindings = self._current_builder_evidence_bindings(checkpoint)
        return (
            "Evaluate every immutable criterion independently. Fail closed unless the "
            "builder evidence mapped to that criterion exactly covers its requirements.",
            {
                **common,
                "iteration": state.iterations,
                "plan": state.current_plan.model_dump(
                    mode="json", exclude={"scope"}
                ),
                "builder_result": state.current_builder_result.model_dump(
                    mode="json", exclude={"scope"}
                ),
                "evidence_bindings": [
                    item.model_dump(mode="json") for item in evidence_bindings
                ],
            },
        )

    def _assignment_output(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        lease = checkpoint.assignment_for(record.subject_ref)
        if lease is None:
            raise DynamicWorkflowControlPersistenceError(
                "assignment mutation references a missing durable lease"
            )
        assignment: dict[str, Any] = {
            "assignment_ref": lease.assignment_ref,
            "assignment_receipt": self.key_ring.assignment_receipt(
                checkpoint, lease
            ),
            "role": lease.role.value,
            "attempt": lease.attempt,
            "instructions": lease.instructions,
            "payload": lease.payload,
            "lease_expires_at": lease.lease_expires_at.isoformat(),
        }
        if lease.context_anchor is not None:
            if checkpoint.context_link is None:
                raise DynamicWorkflowControlPersistenceError(
                    "assignment context anchor has no enclosing context link"
                )
            assignment["context_anchor"] = {
                "context_ref": checkpoint.context_link.context_ref,
                **lease.context_anchor.public_payload(),
            }
        return {
            **self._base_output(checkpoint, record),
            "assignment_available": True,
            "assignment": assignment,
        }

    @staticmethod
    def _resolve_lease(
        lease: DynamicWorkflowAssignmentLease,
        *,
        resolution: DynamicWorkflowLeaseResolution,
        resolved_at: datetime,
        submission_ref: str | None = None,
        evidence_bindings: tuple[DynamicWorkflowEvidenceBinding, ...] = (),
    ) -> DynamicWorkflowAssignmentLease:
        payload = lease.model_dump(mode="python", by_alias=False)
        payload.update(
            resolution=resolution,
            resolved_at=resolved_at,
            submission_ref=submission_ref,
            evidence_bindings=evidence_bindings,
        )
        return DynamicWorkflowAssignmentLease.model_validate(payload)

    @staticmethod
    def _replace_lease(
        leases: tuple[DynamicWorkflowAssignmentLease, ...],
        replacement: DynamicWorkflowAssignmentLease,
    ) -> tuple[DynamicWorkflowAssignmentLease, ...]:
        found = False
        values: list[DynamicWorkflowAssignmentLease] = []
        for lease in leases:
            if lease.assignment_ref == replacement.assignment_ref:
                found = True
                values.append(replacement)
            else:
                values.append(lease)
        if not found:
            raise DynamicWorkflowControlPersistenceError(
                "cannot resolve a missing assignment lease"
            )
        return tuple(values)

    def _leased_submission(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        payload: Mapping[str, Any],
        binding: DynamicWorkflowRoleBinding,
        *,
        role: DynamicWorkflowHostRole,
        now: datetime,
    ) -> DynamicWorkflowAssignmentLease:
        if binding.role != role:
            raise DynamicWorkflowCustodyError(
                f"submission requires {role.value} binding custody"
            )
        if role == DynamicWorkflowHostRole.EVALUATOR:
            self._require_current_evaluator_anchor(checkpoint, binding)
        lease = checkpoint.assignment_for(payload["assignment_ref"])
        if lease is None:
            raise DynamicWorkflowCustodyError("assignment lease is unknown for this run")
        if lease.host_binding_ref != binding.host_binding_ref or lease.role != role:
            raise DynamicWorkflowCustodyError(
                "assignment lease does not belong to this role binding"
            )
        expected = self.key_ring.assignment_receipt(checkpoint, lease)
        if not hmac.compare_digest(expected, payload["assignment_receipt"]):
            raise DynamicWorkflowCustodyError(
                "assignment receipt did not prove exclusive lease custody"
            )
        if lease.resolution != DynamicWorkflowLeaseResolution.OPEN:
            raise DynamicWorkflowCustodyError(
                f"assignment lease is already {lease.resolution.value}"
            )
        if not lease.is_active(now):
            raise DynamicWorkflowCustodyError("assignment lease has expired")
        return lease

    @staticmethod
    def _submission_output(
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        output: dict[str, Any] = {
            **DynamicWorkflowController._base_output(checkpoint, record),
            "accepted": True,
            "submission_ref": record.subject_ref,
        }
        if record.next_role is not None:
            output["next_role"] = record.next_role.value
        if record.context_checkpoint_ref is not None:
            output["context_checkpoint_ref"] = record.context_checkpoint_ref
            output["context_revision"] = record.context_revision
        return output

    def _evaluator_submission_output(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        lease = next(
            (
                item
                for item in checkpoint.assignment_leases
                if item.role == DynamicWorkflowHostRole.EVALUATOR
                and item.submission_ref == record.subject_ref
            ),
            None,
        )
        if lease is None:
            raise DynamicWorkflowControlPersistenceError(
                "evaluator submission has no matching resolved lease"
            )
        binding = checkpoint.binding_for(lease.host_binding_ref)
        if binding is None:
            raise DynamicWorkflowControlPersistenceError(
                "evaluator submission has no matching role binding"
            )
        if record.committed_status == WorkflowRunStatus.ACCEPTED:
            if binding.identity_source == "runtime_attested":
                acceptance = DynamicWorkflowAcceptanceAssurance.RUNTIME_ATTESTED
            elif binding.identity_source == "mcp_session_distinct":
                acceptance = (
                    DynamicWorkflowAcceptanceAssurance.DISTINCT_MCP_SESSION
                )
            else:
                acceptance = DynamicWorkflowAcceptanceAssurance.DISTINCT_BINDING
        else:
            acceptance = DynamicWorkflowAcceptanceAssurance.NOT_ACCEPTED
        return {
            **self._submission_output(checkpoint, record),
            "evaluator_freshness_assurance": self._binding_freshness_assurance(
                binding
            ).value,
            "acceptance_assurance": acceptance.value,
        }

    @staticmethod
    def _required_criterion_ids(
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> tuple[str, ...]:
        return tuple(
            item.criterion_id
            for item in checkpoint.runtime_checkpoint.workflow_state.acceptance_criteria
        )

    def _require_exact_criterion_ids(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        supplied: Iterable[str],
    ) -> None:
        expected = self._required_criterion_ids(checkpoint)
        values = tuple(supplied)
        if len(values) != len(set(values)) or set(values) != set(expected):
            raise DynamicWorkflowCustodyError(
                "submission must preserve every immutable criterion exactly"
            )

    def _submit_plan(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
        trusted_usage: UsageDelta,
        trusted_context_checkpoint: DynamicWorkflowContextCheckpointCommit | None,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        binding = self._binding_from_payload(checkpoint, payload)
        if checkpoint.context_link is None and trusted_context_checkpoint is not None:
            raise DynamicWorkflowCustodyError(
                "an offline workflow cannot accept a Context Broker checkpoint"
            )
        if checkpoint.context_link is not None and trusted_context_checkpoint is None:
            raise DynamicWorkflowCustodyError(
                "linked artifact submission requires a context checkpoint anchor"
            )
        request_digest = self._request_digest(
            "submit_plan",
            payload,
            scope,
            trusted_context_checkpoint,
        )
        existing = self._existing_record(
            checkpoint,
            operation="submit_plan",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._submission_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        self._require_role_phase(checkpoint, DynamicWorkflowHostRole.PLANNER)
        lease = self._leased_submission(
            checkpoint,
            payload,
            binding,
            role=DynamicWorkflowHostRole.PLANNER,
            now=now,
        )
        context_link = self._advance_context_checkpoint(
            checkpoint,
            binding,
            trusted_context_checkpoint,
        )
        self._require_exact_criterion_ids(
            checkpoint, payload["required_criterion_ids"]
        )
        state = checkpoint.runtime_checkpoint.workflow_state
        plan_payload = payload["plan"]
        plan = PlannerPlan(
            scope=scope,
            run_ref=checkpoint.run_ref,
            plan_id="dwp_" + _sha256(
                {
                    "run_ref": checkpoint.run_ref,
                    "assignment_ref": lease.assignment_ref,
                    "plan": plan_payload,
                }
            )[:40],
            revision=state.plan_revisions + 1,
            objective=plan_payload["objective"],
            acceptance_criteria=tuple(
                AcceptanceCriterion.model_validate(item)
                for item in plan_payload["acceptance_criteria"]
            ),
            work_items=tuple(plan_payload["work_items"]),
            planner_context_id=binding.host_binding_ref,
            planner_session_id=binding.host_binding_ref,
            occurred_at=now,
            usage=trusted_usage,
        )
        runtime = self._embedded_runtime(checkpoint)
        core_result = runtime.submit_plan(
            plan,
            expected_revision=checkpoint.runtime_revision,
            idempotency_key=self._core_idempotency_key(
                "submit_plan", payload["idempotency_key"], "plan"
            ),
        )
        submission_ref = self.key_ring.opaque_submission_ref(
            key_id=checkpoint.receipt_key_id,
            run_ref=checkpoint.run_ref,
            operation="submit_plan",
            assignment_ref=lease.assignment_ref,
            idempotency_key=payload["idempotency_key"],
        )
        resolved = self._resolve_lease(
            lease,
            resolution=DynamicWorkflowLeaseResolution.SUBMITTED,
            resolved_at=now,
            submission_ref=submission_ref,
        )
        leases = self._replace_lease(checkpoint.assignment_leases, resolved)
        next_role = _active_role(core_result.checkpoint.status)
        record = DynamicWorkflowControlMutationRecord(
            operation="submit_plan",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=core_result.checkpoint.revision,
            committed_status=core_result.checkpoint.status,
            subject_ref=submission_ref,
            next_role=next_role,
            context_revision=(
                context_link.current_context_revision
                if context_link is not None
                else None
            ),
            context_checkpoint_ref=(
                trusted_context_checkpoint.checkpoint_ref
                if trusted_context_checkpoint is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            runtime_checkpoint=core_result.checkpoint,
            assignment_leases=leases,
            context_link=context_link,
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="submit_plan",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._submission_output(saved, committed)

    def _builder_evidence_bindings(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        values: Iterable[Mapping[str, Any]],
    ) -> tuple[
        tuple[EvidenceRef, ...],
        tuple[DynamicWorkflowEvidenceBinding, ...],
    ]:
        criteria = {
            item.criterion_id: item
            for item in checkpoint.runtime_checkpoint.workflow_state.acceptance_criteria
        }
        evidence_refs: list[EvidenceRef] = []
        bindings: list[DynamicWorkflowEvidenceBinding] = []
        seen_refs: set[str] = set()
        for value in values:
            ref = value["ref"]
            if ref in seen_refs:
                raise DynamicWorkflowCustodyError(
                    "builder evidence refs must be unique within a submission"
                )
            seen_refs.add(ref)
            criterion_ids = tuple(value["criterion_ids"])
            for criterion_id in criterion_ids:
                criterion = criteria.get(criterion_id)
                if criterion is None:
                    raise DynamicWorkflowCustodyError(
                        "builder evidence references an unknown acceptance criterion"
                    )
                if value["kind"] not in criterion.required_evidence:
                    raise DynamicWorkflowCustodyError(
                        f"evidence kind {value['kind']} is not declared for "
                        f"criterion {criterion_id}"
                    )
            media_type = value.get("media_type") or None
            evidence_refs.append(
                EvidenceRef(
                    ref=ref,
                    sha256=value["sha256"],
                    kind=value["kind"],
                    media_type=media_type,
                )
            )
            bindings.append(
                DynamicWorkflowEvidenceBinding(
                    ref=ref,
                    sha256=value["sha256"],
                    kind=value["kind"],
                    criterion_ids=criterion_ids,
                    media_type=media_type,
                )
            )
        return tuple(evidence_refs), tuple(bindings)

    def _submit_builder_result(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
        trusted_usage: UsageDelta,
        trusted_context_checkpoint: DynamicWorkflowContextCheckpointCommit | None,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        binding = self._binding_from_payload(checkpoint, payload)
        if checkpoint.context_link is None and trusted_context_checkpoint is not None:
            raise DynamicWorkflowCustodyError(
                "an offline workflow cannot accept a Context Broker checkpoint"
            )
        if checkpoint.context_link is not None and trusted_context_checkpoint is None:
            raise DynamicWorkflowCustodyError(
                "linked artifact submission requires a context checkpoint anchor"
            )
        request_digest = self._request_digest(
            "submit_builder_result",
            payload,
            scope,
            trusted_context_checkpoint,
        )
        existing = self._existing_record(
            checkpoint,
            operation="submit_builder_result",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._submission_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        self._require_role_phase(checkpoint, DynamicWorkflowHostRole.BUILDER)
        lease = self._leased_submission(
            checkpoint,
            payload,
            binding,
            role=DynamicWorkflowHostRole.BUILDER,
            now=now,
        )
        context_link = self._advance_context_checkpoint(
            checkpoint,
            binding,
            trusted_context_checkpoint,
        )
        state = checkpoint.runtime_checkpoint.workflow_state
        plan = state.current_plan
        if plan is None:
            raise DynamicWorkflowRolePhaseError(
                "builder submission requires the current durable plan"
            )
        if payload["plan_digest"] != plan.digest:
            raise DynamicWorkflowCustodyError(
                "builder result references a stale planner plan"
            )
        if payload["iteration"] != state.iterations + 1 or lease.attempt != payload["iteration"]:
            raise DynamicWorkflowCustodyError(
                "builder result iteration differs from its leased assignment"
            )
        evidence_refs, evidence_bindings = self._builder_evidence_bindings(
            checkpoint, payload["evidence_refs"]
        )
        assignment = BuilderAssignment(
            scope=scope,
            run_ref=checkpoint.run_ref,
            assignment_id=lease.assignment_ref,
            plan_digest=plan.digest,
            plan_revision=plan.revision,
            iteration=payload["iteration"],
            instructions=lease.instructions,
            acceptance_criteria_digest=state.acceptance_criteria_digest,
            builder_context_id=binding.host_binding_ref,
            builder_session_id=binding.host_binding_ref,
            prior_verdict_digest=(
                state.current_verdict.digest if state.current_verdict is not None else None
            ),
            occurred_at=now,
            usage=UsageDelta(),
        )
        result = BuilderResult(
            scope=scope,
            run_ref=checkpoint.run_ref,
            assignment_id=lease.assignment_ref,
            plan_digest=payload["plan_digest"],
            iteration=payload["iteration"],
            builder_context_id=binding.host_binding_ref,
            builder_session_id=binding.host_binding_ref,
            outcome=BuilderOutcome(payload["outcome"]),
            summary=payload["summary"],
            evidence_refs=evidence_refs,
            progress_digest=payload["progress_digest"],
            occurred_at=now,
            usage=trusted_usage,
        )
        runtime = self._embedded_runtime(checkpoint)
        assigned = runtime.assign_builder(
            assignment,
            expected_revision=checkpoint.runtime_revision,
            idempotency_key=self._core_idempotency_key(
                "submit_builder_result", payload["idempotency_key"], "assign"
            ),
        )
        if assigned.checkpoint.status.terminal:
            final_core = assigned.checkpoint
        else:
            submitted = runtime.submit_builder_result(
                result,
                expected_revision=assigned.checkpoint.revision,
                idempotency_key=self._core_idempotency_key(
                    "submit_builder_result", payload["idempotency_key"], "result"
                ),
            )
            final_core = submitted.checkpoint
        submission_ref = self.key_ring.opaque_submission_ref(
            key_id=checkpoint.receipt_key_id,
            run_ref=checkpoint.run_ref,
            operation="submit_builder_result",
            assignment_ref=lease.assignment_ref,
            idempotency_key=payload["idempotency_key"],
        )
        resolved = self._resolve_lease(
            lease,
            resolution=DynamicWorkflowLeaseResolution.SUBMITTED,
            resolved_at=now,
            submission_ref=submission_ref,
            evidence_bindings=evidence_bindings,
        )
        leases = self._replace_lease(checkpoint.assignment_leases, resolved)
        record = DynamicWorkflowControlMutationRecord(
            operation="submit_builder_result",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=final_core.revision,
            committed_status=final_core.status,
            subject_ref=submission_ref,
            next_role=_active_role(final_core.status),
            context_revision=(
                context_link.current_context_revision
                if context_link is not None
                else None
            ),
            context_checkpoint_ref=(
                trusted_context_checkpoint.checkpoint_ref
                if trusted_context_checkpoint is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            runtime_checkpoint=final_core,
            assignment_leases=leases,
            context_link=context_link,
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="submit_builder_result",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._submission_output(saved, committed)

    def _current_builder_evidence_bindings(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
    ) -> tuple[DynamicWorkflowEvidenceBinding, ...]:
        state = checkpoint.runtime_checkpoint.workflow_state
        assignment = state.current_assignment
        if assignment is None:
            raise DynamicWorkflowControlPersistenceError(
                "evaluating workflow has no current builder assignment"
            )
        for lease in reversed(checkpoint.assignment_leases):
            if (
                lease.assignment_ref == assignment.assignment_id
                and lease.role == DynamicWorkflowHostRole.BUILDER
                and lease.resolution == DynamicWorkflowLeaseResolution.SUBMITTED
            ):
                return lease.evidence_bindings
        raise DynamicWorkflowControlPersistenceError(
            "current builder result has no sealed evidence-to-criterion mapping"
        )

    def _criterion_evaluations(
        self,
        checkpoint: DynamicWorkflowControlCheckpoint,
        values: Iterable[Mapping[str, Any]],
    ) -> tuple[CriterionEvaluation, ...]:
        supplied_values = tuple(values)
        criteria = {
            item.criterion_id: item
            for item in checkpoint.runtime_checkpoint.workflow_state.acceptance_criteria
        }
        supplied_ids = [item["criterion_id"] for item in supplied_values]
        if len(supplied_ids) != len(set(supplied_ids)):
            raise DynamicWorkflowCustodyError(
                "evaluator criterion results must be unique"
            )
        unknown_ids = sorted(set(supplied_ids) - set(criteria))
        if unknown_ids:
            raise DynamicWorkflowCustodyError(
                "evaluator returned unknown acceptance criteria: "
                + ", ".join(unknown_ids)
            )
        evidence_by_ref = {
            item.ref: item for item in self._current_builder_evidence_bindings(checkpoint)
        }
        results: list[CriterionEvaluation] = []
        for value in supplied_values:
            criterion_id = value["criterion_id"]
            criterion = criteria.get(criterion_id)
            if criterion is None:
                raise DynamicWorkflowCustodyError(
                    "evaluator returned an unknown acceptance criterion"
                )
            if set(value["required_evidence"]) != set(criterion.required_evidence):
                raise DynamicWorkflowCustodyError(
                    f"evaluator required_evidence differs from immutable criterion "
                    f"{criterion_id}"
                )
            supplied_evidence = tuple(value["evidence_refs"])
            supplied_refs = [item["ref"] for item in supplied_evidence]
            if len(supplied_refs) != len(set(supplied_refs)):
                raise DynamicWorkflowCustodyError(
                    f"criterion {criterion_id} contains duplicate evidence refs"
                )
            supplied_kinds = {item["kind"] for item in supplied_evidence}
            required_kinds = set(criterion.required_evidence)
            if value["accepted"] and supplied_kinds != required_kinds:
                raise DynamicWorkflowCustodyError(
                    f"passing criterion {criterion_id} evidence kinds must exactly equal "
                    "its immutable required_evidence"
                )
            if not value["accepted"] and not supplied_kinds.issubset(required_kinds):
                raise DynamicWorkflowCustodyError(
                    f"failing criterion {criterion_id} evidence kinds must be a subset of "
                    "its immutable required_evidence"
                )
            evidence: list[EvidenceRef] = []
            for supplied in supplied_evidence:
                binding = evidence_by_ref.get(supplied["ref"])
                if binding is None:
                    raise DynamicWorkflowCustodyError(
                        "evaluator cited evidence absent from the builder submission"
                    )
                if criterion_id not in binding.criterion_ids:
                    raise DynamicWorkflowCustodyError(
                        "evaluator cannot reassign builder evidence to another criterion"
                    )
                if (
                    supplied["sha256"] != binding.sha256
                    or supplied["kind"] != binding.kind
                    or (
                        supplied.get("media_type")
                        and supplied["media_type"] != binding.media_type
                    )
                ):
                    raise DynamicWorkflowCustodyError(
                        "evaluator evidence identity differs from the sealed builder evidence"
                    )
                evidence.append(
                    EvidenceRef(
                        ref=binding.ref,
                        sha256=binding.sha256,
                        kind=binding.kind,
                        media_type=binding.media_type,
                    )
                )
            results.append(
                CriterionEvaluation(
                    criterion_id=criterion_id,
                    accepted=value["accepted"],
                    reason=value["reason"],
                    evidence_refs=tuple(evidence),
                )
            )
        return tuple(results)

    def _submit_evaluator_verdict(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
        trusted_usage: UsageDelta,
        trusted_context_checkpoint: DynamicWorkflowContextCheckpointCommit | None,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        binding = self._binding_from_payload(checkpoint, payload)
        if checkpoint.context_link is None and trusted_context_checkpoint is not None:
            raise DynamicWorkflowCustodyError(
                "an offline workflow cannot accept a Context Broker checkpoint"
            )
        if checkpoint.context_link is not None and trusted_context_checkpoint is None:
            raise DynamicWorkflowCustodyError(
                "linked artifact submission requires a context checkpoint anchor"
            )
        request_digest = self._request_digest(
            "submit_evaluator_verdict",
            payload,
            scope,
            trusted_context_checkpoint,
        )
        existing = self._existing_record(
            checkpoint,
            operation="submit_evaluator_verdict",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._evaluator_submission_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        self._require_role_phase(checkpoint, DynamicWorkflowHostRole.EVALUATOR)
        lease = self._leased_submission(
            checkpoint,
            payload,
            binding,
            role=DynamicWorkflowHostRole.EVALUATOR,
            now=now,
        )
        context_link = self._advance_context_checkpoint(
            checkpoint,
            binding,
            trusted_context_checkpoint,
        )
        if (
            payload["decision"] == EvaluatorDecision.ACCEPT.value
            and checkpoint.acceptance_policy
            == DynamicWorkflowAcceptancePolicy.RUNTIME_ATTESTED_REQUIRED
            and binding.identity_source != "runtime_attested"
        ):
            raise DynamicWorkflowCustodyError(
                "strict acceptance policy requires a runtime-attested fresh evaluator context"
            )
        self._require_exact_criterion_ids(
            checkpoint, payload["required_criterion_ids"]
        )
        state = checkpoint.runtime_checkpoint.workflow_state
        if state.current_plan is None or state.current_builder_result is None:
            raise DynamicWorkflowRolePhaseError(
                "evaluation requires current plan and builder result artifacts"
            )
        if payload["plan_digest"] != state.current_plan.digest:
            raise DynamicWorkflowCustodyError("evaluator references a stale planner plan")
        if payload["builder_result_digest"] != state.current_builder_result.digest:
            raise DynamicWorkflowCustodyError(
                "evaluator references a stale builder result"
            )
        criterion_results = self._criterion_evaluations(
            checkpoint, payload["criterion_results"]
        )
        verdict = EvaluatorVerdict(
            scope=scope,
            run_ref=checkpoint.run_ref,
            verdict_id="dwv_" + _sha256(
                {
                    "run_ref": checkpoint.run_ref,
                    "assignment_ref": lease.assignment_ref,
                    "criterion_results": criterion_results,
                }
            )[:40],
            plan_digest=payload["plan_digest"],
            builder_result_digest=payload["builder_result_digest"],
            evaluator_context_id=binding.host_binding_ref,
            evaluator_session_id=binding.host_binding_ref,
            decision=EvaluatorDecision(payload["decision"]),
            accepted=payload["accepted"],
            summary=payload["summary"],
            criterion_results=criterion_results,
            occurred_at=now,
            usage=trusted_usage,
        )
        runtime = self._embedded_runtime(checkpoint)
        core_result = runtime.submit_evaluator_verdict(
            verdict,
            expected_revision=checkpoint.runtime_revision,
            idempotency_key=self._core_idempotency_key(
                "submit_evaluator_verdict", payload["idempotency_key"], "verdict"
            ),
        )
        submission_ref = self.key_ring.opaque_submission_ref(
            key_id=checkpoint.receipt_key_id,
            run_ref=checkpoint.run_ref,
            operation="submit_evaluator_verdict",
            assignment_ref=lease.assignment_ref,
            idempotency_key=payload["idempotency_key"],
        )
        resolved = self._resolve_lease(
            lease,
            resolution=DynamicWorkflowLeaseResolution.SUBMITTED,
            resolved_at=now,
            submission_ref=submission_ref,
        )
        leases = self._replace_lease(checkpoint.assignment_leases, resolved)
        record = DynamicWorkflowControlMutationRecord(
            operation="submit_evaluator_verdict",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=core_result.checkpoint.revision,
            committed_status=core_result.checkpoint.status,
            subject_ref=submission_ref,
            next_role=_active_role(core_result.checkpoint.status),
            context_revision=(
                context_link.current_context_revision
                if context_link is not None
                else None
            ),
            context_checkpoint_ref=(
                trusted_context_checkpoint.checkpoint_ref
                if trusted_context_checkpoint is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            runtime_checkpoint=core_result.checkpoint,
            assignment_leases=leases,
            context_link=context_link,
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="submit_evaluator_verdict",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._evaluator_submission_output(saved, committed)

    def _cancel(
        self,
        payload: Mapping[str, Any],
        *,
        scope: DynamicWorkflowScope,
        now: datetime,
    ) -> dict[str, Any]:
        checkpoint = self._load(payload["run_ref"], scope=scope)
        self._binding_from_payload(checkpoint, payload)
        request_digest = self._request_digest("cancel", payload, scope)
        existing = self._existing_record(
            checkpoint,
            operation="cancel",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        if existing is not None:
            return self._cancel_output(checkpoint, existing)
        self._require_active(checkpoint)
        self._require_expected_revision(checkpoint, payload["expected_revision"])
        runtime = self._embedded_runtime(checkpoint)
        core_result = runtime.cancel(
            checkpoint.run_ref,
            scope=scope,
            reason=payload["reason"],
            occurred_at=now,
            expected_revision=checkpoint.runtime_revision,
            idempotency_key=self._core_idempotency_key(
                "cancel", payload["idempotency_key"], "cancel"
            ),
        )
        leases = tuple(
            self._resolve_lease(
                lease,
                resolution=DynamicWorkflowLeaseResolution.CANCELLED,
                resolved_at=now,
            )
            if lease.resolution == DynamicWorkflowLeaseResolution.OPEN
            else lease
            for lease in checkpoint.assignment_leases
        )
        record = DynamicWorkflowControlMutationRecord(
            operation="cancel",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
            committed_revision=checkpoint.revision + 1,
            runtime_revision=core_result.checkpoint.revision,
            committed_status=core_result.checkpoint.status,
            subject_ref=checkpoint.run_ref,
            context_revision=(
                checkpoint.context_link.current_context_revision
                if checkpoint.context_link is not None
                else None
            ),
            occurred_at=now,
        )
        candidate = self._candidate(
            checkpoint,
            runtime_checkpoint=core_result.checkpoint,
            assignment_leases=leases,
            record=record,
            updated_at=now,
        )
        saved, committed, _ = self._commit(
            candidate,
            previous=checkpoint,
            operation="cancel",
            idempotency_key=payload["idempotency_key"],
            request_digest=request_digest,
        )
        return self._cancel_output(saved, committed)

    @staticmethod
    def _cancel_output(
        checkpoint: DynamicWorkflowControlCheckpoint,
        record: DynamicWorkflowControlMutationRecord,
    ) -> dict[str, Any]:
        return {
            **DynamicWorkflowController._base_output(checkpoint, record),
            "cancelled": True,
            "cancelled_at": record.occurred_at.isoformat(),
        }


__all__ = [
    "DYNAMIC_WORKFLOW_ASSIGNMENT_LEASE_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_ATTACH_ANCHOR_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_BINDING_ANCHOR_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_ANCHOR_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_CHECKPOINT_COMMIT_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_LINK_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTEXT_START_ANCHOR_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTROL_MUTATION_SCHEMA",
    "DYNAMIC_WORKFLOW_CONTROL_SCHEMA",
    "DYNAMIC_WORKFLOW_ROLE_BINDING_SCHEMA",
    "DynamicWorkflowAcceptanceAssurance",
    "DynamicWorkflowAcceptancePolicy",
    "DynamicWorkflowAssignmentLease",
    "DynamicWorkflowControlAuthority",
    "DynamicWorkflowControlCheckpoint",
    "DynamicWorkflowControlConflict",
    "DynamicWorkflowControlError",
    "DynamicWorkflowControlNotFound",
    "DynamicWorkflowControlPersistenceError",
    "DynamicWorkflowControlStore",
    "DynamicWorkflowController",
    "DynamicWorkflowContextAttachAnchor",
    "DynamicWorkflowContextBindingAnchor",
    "DynamicWorkflowContextCheckpointAnchor",
    "DynamicWorkflowContextCheckpointCommit",
    "DynamicWorkflowContextLink",
    "DynamicWorkflowContextStartAnchor",
    "DynamicWorkflowCustodyError",
    "DynamicWorkflowEvidenceBinding",
    "DynamicWorkflowEvaluatorFreshnessAssurance",
    "DynamicWorkflowHostRole",
    "DynamicWorkflowLeaseResolution",
    "DynamicWorkflowReceiptKeyRing",
    "DynamicWorkflowRoleBinding",
    "DynamicWorkflowRolePhaseError",
    "InMemoryDynamicWorkflowControlStore",
    "JsonDynamicWorkflowControlStore",
]
