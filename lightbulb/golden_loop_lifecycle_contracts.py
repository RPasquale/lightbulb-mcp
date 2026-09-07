"""Successor lifecycle declarations for the eight GTM Golden Operating Loops.

This module is a typed, metadata-only SDK source.  It inventories the real SDK,
host-neutral MCP, optional ChatGPT, and managed-Agent entrypoints that already
exist; it does not execute a loop, authorize an effect, or promote a capability
out of quarantine.

The historical ``lightbulb.golden_loop_portfolio_lifecycle.v1`` contract remains
immutable.  In particular, Period Reconciliation's corrected read-only
ambiguity semantics are declared here as successor-only metadata and explicitly
require a new declaration and execution identity before publication.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from lightbulb.golden_loop_projections import (
    GoldenLoopProjectionParticipation,
    GoldenLoopRef,
)
from lightbulb.golden_loops import AmbiguousOutcomePolicy


GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_SCHEMA = (
    "lightbulb.golden_loop_lifecycle_registry.v2"
)
GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_VERSION = "2.0.0"
GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_SCHEMA = (
    "lightbulb.golden_loop_lifecycle_registry.v3"
)
GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_VERSION = "3.0.0"

# Compatibility names remain pinned to the V2 contract. New call paths must use
# GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT instead of assuming a generation.
GOLDEN_LOOP_LIFECYCLE_REGISTRY_SCHEMA = GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_SCHEMA
GOLDEN_LOOP_LIFECYCLE_REGISTRY_VERSION = GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_VERSION

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_OPERATION_REF = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_SDK_ENTRYPOINT = re.compile(
    r"^lightbulb\.client\.LightbulbClient\.([a-z][a-z0-9_]{0,99})$"
)
_AGENT_ENTRYPOINT = re.compile(
    r"^agent-workers\.agents\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.[a-z][a-z0-9_]*$"
)


class GoldenLoopLifecycleOperationKind(str, Enum):
    """Business meaning of one concrete lifecycle operation."""

    PREFLIGHT_CUSTODY = "PREFLIGHT_CUSTODY"
    START = "START"
    READ = "READ"
    PROPOSAL = "PROPOSAL"
    GOVERNED_EFFECT = "GOVERNED_EFFECT"
    TRANSITION = "TRANSITION"
    ROLE_PROTOCOL = "ROLE_PROTOCOL"
    TERMINAL = "TERMINAL"
    AMBIGUITY = "AMBIGUITY"
    RECONCILIATION = "RECONCILIATION"


class GoldenLoopLifecycleAuthorityAvailability(str, Enum):
    """Where the authoritative operation may be invoked."""

    PUBLIC = "PUBLIC"
    ROLE_PROTOCOL_ONLY = "ROLE_PROTOCOL_ONLY"
    WORKER_ONLY = "WORKER_ONLY"
    UNAVAILABLE = "UNAVAILABLE"


class GoldenLoopLifecycleSurface(str, Enum):
    AGENTS = "agents"
    SDK = "sdk"
    MCP = "mcp"
    CHATGPT = "chatgpt"


class GoldenLoopLifecycleEffect(str, Enum):
    """Maximum effect reachable from one authority operation."""

    NO_EXTERNAL_EFFECT = "NO_EXTERNAL_EFFECT"
    EXTERNAL_READ = "EXTERNAL_READ"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    CODING_HARNESS = "CODING_HARNESS"
    WORKER_INTERNAL = "WORKER_INTERNAL"


class GoldenLoopLifecycleApprovalRequirement(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PROPOSES_APPROVAL = "PROPOSES_APPROVAL"
    EXACT_APPROVAL_REQUIRED = "EXACT_APPROVAL_REQUIRED"
    PRIOR_APPROVAL_CUSTODY = "PRIOR_APPROVAL_CUSTODY"
    WORKER_OWNED = "WORKER_OWNED"


class GoldenLoopLifecycleIdempotencyClass(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    IDEMPOTENCY_KEY = "IDEMPOTENCY_KEY"
    COMMAND_ID = "COMMAND_ID"
    WORKFLOW_STEP = "WORKFLOW_STEP"
    SOURCE_IDENTITY = "SOURCE_IDENTITY"
    IDEMPOTENCY_KEY_AND_REVISION = "IDEMPOTENCY_KEY_AND_REVISION"
    WORKER_OWNED = "WORKER_OWNED"


class GoldenLoopLifecycleRetryClass(str, Enum):
    SAFE_READ = "SAFE_READ"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    NO_AUTOMATIC_RETRY = "NO_AUTOMATIC_RETRY"
    BLOCKED = "BLOCKED"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class GoldenLoopForbiddenAlias(_StrictModel):
    """A deliberately absent generic alias for transition-specific work."""

    alias_ref: str = Field(pattern=_OPERATION_REF.pattern)
    blocker_code: str = Field(min_length=1, max_length=200)
    blocked_surfaces: tuple[GoldenLoopLifecycleSurface, ...] = tuple(
        GoldenLoopLifecycleSurface
    )

    @field_validator("blocked_surfaces", mode="before")
    @classmethod
    def _tuple_surfaces(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _all_access_surfaces_are_blocked(self) -> Self:
        if self.blocked_surfaces != tuple(GoldenLoopLifecycleSurface):
            raise ValueError(
                "forbidden lifecycle aliases must be blocked on every access surface"
            )
        return self


class GoldenLoopLifecycleOperation(_StrictModel):
    """One real operation and its existing access-surface entrypoints."""

    operation_ref: str = Field(pattern=_OPERATION_REF.pattern)
    kind: GoldenLoopLifecycleOperationKind
    authority_availability: GoldenLoopLifecycleAuthorityAvailability
    surface_participation: GoldenLoopProjectionParticipation
    http_method: Literal["GET", "POST"] | None = None
    endpoint_template: str | None = Field(default=None, min_length=1, max_length=500)
    run_extraction_path: Literal["$", "$.run"] | None = None
    response_schema: str | None = Field(
        default=None,
        pattern=r"^lightbulb\.[a-z][a-z0-9_.]{0,198}\.v[1-9][0-9]*$",
    )
    effect: GoldenLoopLifecycleEffect
    approval_requirement: GoldenLoopLifecycleApprovalRequirement
    idempotency_class: GoldenLoopLifecycleIdempotencyClass
    retry_class: GoldenLoopLifecycleRetryClass
    ambiguity_policy: AmbiguousOutcomePolicy
    sdk_entrypoint_ref: str | None = Field(default=None, max_length=300)
    mcp_tool_name: str | None = Field(
        default=None, pattern=_OPERATION_REF.pattern
    )
    chatgpt_tool_name: str | None = Field(
        default=None, pattern=_OPERATION_REF.pattern
    )
    agent_surface_participation: GoldenLoopProjectionParticipation
    agent_mcp_tool_name: str | None = Field(
        default=None, pattern=_OPERATION_REF.pattern
    )
    agent_entrypoint_refs: tuple[str, ...] = Field(
        default=(), max_length=4
    )
    blocker_code: str | None = Field(default=None, min_length=1, max_length=200)
    forbidden_entrypoint_ref: str | None = Field(
        default=None, pattern=_OPERATION_REF.pattern
    )
    agent_surface_blocker_code: str | None = Field(
        default=None, min_length=1, max_length=200
    )

    @field_validator("agent_entrypoint_refs", mode="before")
    @classmethod
    def _tuple_agent_entrypoints(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _entrypoints_match_participation(self) -> Self:
        if len(self.agent_entrypoint_refs) != len(set(self.agent_entrypoint_refs)):
            raise ValueError("agent lifecycle entrypoints must be unique")
        for entrypoint_ref in self.agent_entrypoint_refs:
            if _AGENT_ENTRYPOINT.fullmatch(entrypoint_ref) is None:
                raise ValueError(
                    f"agent lifecycle entrypoint is not canonical: {entrypoint_ref}"
                )

        callable_projection = (
            self.surface_participation is GoldenLoopProjectionParticipation.CALLABLE
        )
        public_entrypoints = (
            self.sdk_entrypoint_ref,
            self.mcp_tool_name,
            self.chatgpt_tool_name,
        )
        if callable_projection:
            if self.authority_availability not in {
                GoldenLoopLifecycleAuthorityAvailability.PUBLIC,
                GoldenLoopLifecycleAuthorityAvailability.ROLE_PROTOCOL_ONLY,
            }:
                raise ValueError("callable lifecycle operations need callable authority")
            if any(value is None for value in public_entrypoints):
                raise ValueError(
                    "callable lifecycle operations require SDK, MCP, and ChatGPT entrypoints"
                )
            if self.blocker_code is not None or self.forbidden_entrypoint_ref is not None:
                raise ValueError("callable lifecycle operations cannot declare a blocker")
            if self.http_method is None or self.endpoint_template is None:
                raise ValueError(
                    "callable lifecycle operations require an exact Spring endpoint"
                )
            if self.response_schema is None:
                raise ValueError(
                    "callable lifecycle operations require an exact response schema"
                )
            if self.retry_class is GoldenLoopLifecycleRetryClass.BLOCKED:
                raise ValueError("callable lifecycle operations cannot use blocked retry")
            match = _SDK_ENTRYPOINT.fullmatch(str(self.sdk_entrypoint_ref))
            if match is None:
                raise ValueError("SDK lifecycle entrypoint is not canonical")
            if self.operation_ref != self.mcp_tool_name:
                raise ValueError("callable operation_ref must equal its MCP tool name")
            if self.chatgpt_tool_name != self.mcp_tool_name:
                raise ValueError("ChatGPT must project the same host-neutral MCP tool")
            if (
                self.agent_surface_participation
                is GoldenLoopProjectionParticipation.CALLABLE
            ):
                if self.agent_surface_blocker_code is not None:
                    raise ValueError(
                        "callable Agent lifecycle operations cannot declare a blocker"
                    )
                if self.agent_mcp_tool_name is None:
                    raise ValueError(
                        "callable Agent lifecycle operations require an MCP tool"
                    )
                if self.agent_mcp_tool_name != self.mcp_tool_name:
                    raise ValueError("Agents must use the same host-neutral MCP tool")
                if not self.agent_entrypoint_refs:
                    raise ValueError(
                        "managed-Agent MCP tools require a concrete projection entrypoint"
                    )
            elif (
                self.agent_surface_participation
                is GoldenLoopProjectionParticipation.BLOCKED
            ):
                if self.agent_mcp_tool_name is not None or self.agent_entrypoint_refs:
                    raise ValueError(
                        "blocked Agent lifecycle operations cannot advertise entrypoints"
                    )
                if self.agent_surface_blocker_code is None:
                    raise ValueError(
                        "blocked Agent lifecycle operations require an exact blocker"
                    )
            else:
                raise ValueError(
                    "v2 Agent lifecycle operations are callable or explicitly blocked"
                )
        else:
            if self.surface_participation is not GoldenLoopProjectionParticipation.BLOCKED:
                raise ValueError("v2 lifecycle operations are callable or explicitly blocked")
            if self.authority_availability not in {
                GoldenLoopLifecycleAuthorityAvailability.WORKER_ONLY,
                GoldenLoopLifecycleAuthorityAvailability.UNAVAILABLE,
            }:
                raise ValueError(
                    "blocked access-surface operations must be worker-only or unavailable"
                )
            if any(value is not None for value in public_entrypoints):
                raise ValueError("blocked lifecycle operations cannot advertise entrypoints")
            if self.agent_mcp_tool_name is not None or self.agent_entrypoint_refs:
                raise ValueError("blocked lifecycle operations cannot advertise Agent tools")
            if self.agent_surface_participation is not (
                GoldenLoopProjectionParticipation.BLOCKED
            ):
                raise ValueError("blocked operations must block the Agent surface")
            if self.agent_surface_blocker_code is None:
                raise ValueError("blocked operations require an Agent blocker")
            if self.agent_surface_blocker_code != self.blocker_code:
                raise ValueError(
                    "blocked operations must use the same blocker on every surface"
                )
            if (
                self.http_method is not None
                or self.endpoint_template is not None
                or self.run_extraction_path is not None
                or self.response_schema is not None
            ):
                raise ValueError("blocked lifecycle operations cannot advertise authority")
            if self.blocker_code is None or self.forbidden_entrypoint_ref is None:
                raise ValueError(
                    "blocked lifecycle operations require a blocker and forbidden name"
                )
            if self.operation_ref != self.forbidden_entrypoint_ref:
                raise ValueError(
                    "blocked operation_ref must equal its forbidden entrypoint name"
                )

        dangerous_effect = self.effect in {
            GoldenLoopLifecycleEffect.EXTERNAL_WRITE,
            GoldenLoopLifecycleEffect.CODING_HARNESS,
        }
        approval_bound = self.approval_requirement in {
            GoldenLoopLifecycleApprovalRequirement.EXACT_APPROVAL_REQUIRED,
            GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY,
        }
        if dangerous_effect and not approval_bound:
            raise ValueError(
                "dangerous lifecycle effects require exact or prior approval custody"
            )
        if (
            dangerous_effect
            and self.ambiguity_policy is AmbiguousOutcomePolicy.NOT_APPLICABLE
        ):
            raise ValueError(
                "dangerous lifecycle effects require an ambiguity recovery policy"
            )
        if (
            self.retry_class is GoldenLoopLifecycleRetryClass.IDEMPOTENT_REPLAY
            and self.idempotency_class
            is GoldenLoopLifecycleIdempotencyClass.NOT_APPLICABLE
        ):
            raise ValueError("idempotent replay requires an idempotency authority")
        if self.kind is GoldenLoopLifecycleOperationKind.READ and callable_projection:
            if self.http_method != "GET":
                raise ValueError("lifecycle reads must use GET authority")
            if self.retry_class is not GoldenLoopLifecycleRetryClass.SAFE_READ:
                raise ValueError("lifecycle reads must use the safe-read retry class")
            if self.idempotency_class is not (
                GoldenLoopLifecycleIdempotencyClass.NOT_APPLICABLE
            ):
                raise ValueError("lifecycle reads do not mint idempotency identities")
        if not callable_projection:
            worker_only = self.authority_availability is (
                GoldenLoopLifecycleAuthorityAvailability.WORKER_ONLY
            )
            expected_effect = (
                GoldenLoopLifecycleEffect.WORKER_INTERNAL
                if worker_only
                else GoldenLoopLifecycleEffect.NO_EXTERNAL_EFFECT
            )
            expected_approval = (
                GoldenLoopLifecycleApprovalRequirement.WORKER_OWNED
                if worker_only
                else GoldenLoopLifecycleApprovalRequirement.NOT_REQUIRED
            )
            expected_idempotency = (
                GoldenLoopLifecycleIdempotencyClass.WORKER_OWNED
                if worker_only
                else GoldenLoopLifecycleIdempotencyClass.NOT_APPLICABLE
            )
            if self.effect is not expected_effect:
                raise ValueError("blocked lifecycle effect does not match its authority")
            if self.approval_requirement is not expected_approval:
                raise ValueError("blocked lifecycle approval does not match its authority")
            if self.idempotency_class is not expected_idempotency:
                raise ValueError(
                    "blocked lifecycle idempotency does not match its authority"
                )
            if self.retry_class is not GoldenLoopLifecycleRetryClass.BLOCKED:
                raise ValueError("blocked lifecycle operations cannot advertise retry")
        return self

    @property
    def sdk_method_name(self) -> str | None:
        if self.sdk_entrypoint_ref is None:
            return None
        match = _SDK_ENTRYPOINT.fullmatch(self.sdk_entrypoint_ref)
        if match is None:  # pragma: no cover - model validation rejects this shape.
            raise RuntimeError("invalid SDK lifecycle entrypoint")
        return match.group(1)


class GoldenLoopLifecycleContract(_StrictModel):
    """Successor operation matrix for one exact Golden Operating Loop ref."""

    loop_ref: GoldenLoopRef
    source_declaration_version: str = Field(pattern=_SEMVER.pattern)
    source_execution_loop_version: str = Field(pattern=_SEMVER.pattern)
    lifecycle: Literal["QUARANTINED"] = "QUARANTINED"
    ambiguous_effect_applicable: bool
    distinct_successor_identity_required: bool = False
    operations: tuple[GoldenLoopLifecycleOperation, ...] = Field(
        min_length=1, max_length=100
    )
    forbidden_aliases: tuple[GoldenLoopForbiddenAlias, ...] = Field(
        default=(), max_length=10
    )

    @field_validator("operations", "forbidden_aliases", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _operation_matrix_is_unique(self) -> Self:
        operation_refs = tuple(item.operation_ref for item in self.operations)
        if len(operation_refs) != len(set(operation_refs)):
            raise ValueError("Golden Loop lifecycle operation refs must be unique")
        alias_refs = tuple(item.alias_ref for item in self.forbidden_aliases)
        if len(alias_refs) != len(set(alias_refs)):
            raise ValueError("Golden Loop forbidden aliases must be unique")
        if set(operation_refs).intersection(alias_refs):
            raise ValueError("forbidden aliases cannot be real lifecycle operations")
        if (
            not self.ambiguous_effect_applicable
            and not self.distinct_successor_identity_required
        ):
            raise ValueError(
                "corrected ambiguity semantics require a distinct successor identity"
            )
        if not self.ambiguous_effect_applicable:
            non_applicable_drift = tuple(
                operation.operation_ref
                for operation in self.operations
                if operation.ambiguity_policy
                is not AmbiguousOutcomePolicy.NOT_APPLICABLE
                or operation.effect
                in {
                    GoldenLoopLifecycleEffect.EXTERNAL_WRITE,
                    GoldenLoopLifecycleEffect.CODING_HARNESS,
                }
            )
            if non_applicable_drift:
                raise ValueError(
                    "ambiguity-not-applicable loops cannot declare dangerous or "
                    f"recoverable effects: {', '.join(non_applicable_drift)}"
                )
        return self

    def operation(self, operation_ref: str) -> GoldenLoopLifecycleOperation:
        for operation in self.operations:
            if operation.operation_ref == operation_ref:
                return operation
        raise KeyError(
            f"{operation_ref} is not classified for Golden Loop {self.loop_ref.value}"
        )

    @property
    def agent_mcp_tool_names(self) -> tuple[str, ...]:
        return tuple(
            operation.agent_mcp_tool_name
            for operation in self.operations
            if operation.agent_mcp_tool_name is not None
        )


EXPECTED_GOLDEN_LOOP_V2_OPERATION_COUNTS: Mapping[GoldenLoopRef, int] = (
    MappingProxyType(
        {
            GoldenLoopRef.CONTRACT_TO_CASH: 14,
            GoldenLoopRef.FINANCE_JOURNAL: 5,
            GoldenLoopRef.PERIOD_RECONCILIATION: 12,
            GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE: 14,
            GoldenLoopRef.PROJECT_WORK_PACKET: 4,
            GoldenLoopRef.REVENUE_VERIFIED_REPLY: 4,
            GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION: 4,
            GoldenLoopRef.VERIFIED_IMPROVEMENT: 7,
        }
    )
)


class GoldenLoopLifecycleRegistry(_StrictModel):
    """Canonical, digest-sealed v2 declaration set; never execution authority."""

    schema_id: Literal["lightbulb.golden_loop_lifecycle_registry.v2"] = Field(
        default=GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_SCHEMA,
        alias="schema",
    )
    version: Literal["2.0.0"] = GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_VERSION
    loops: tuple[GoldenLoopLifecycleContract, ...] = Field(
        min_length=8, max_length=8
    )
    registry_digest: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")

    @field_validator("loops", mode="before")
    @classmethod
    def _tuple_loops(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _portfolio_is_exact_and_sealed(self) -> Self:
        expected_order = tuple(EXPECTED_GOLDEN_LOOP_V2_OPERATION_COUNTS)
        actual_order = tuple(loop.loop_ref for loop in self.loops)
        if actual_order != expected_order:
            raise ValueError("v2 Golden Loop lifecycle order or coverage drifted")
        counts = {loop.loop_ref: len(loop.operations) for loop in self.loops}
        if counts != dict(EXPECTED_GOLDEN_LOOP_V2_OPERATION_COUNTS):
            raise ValueError("v2 Golden Loop lifecycle operation counts drifted")

        operation_refs = tuple(
            operation.operation_ref
            for loop in self.loops
            for operation in loop.operations
        )
        if len(operation_refs) != 64 or len(operation_refs) != len(set(operation_refs)):
            raise ValueError("v2 Golden Loop lifecycle operations must be exactly 64 unique refs")

        sdk_entrypoints = tuple(
            operation.sdk_entrypoint_ref
            for loop in self.loops
            for operation in loop.operations
            if operation.sdk_entrypoint_ref is not None
        )
        mcp_tools = tuple(
            operation.mcp_tool_name
            for loop in self.loops
            for operation in loop.operations
            if operation.mcp_tool_name is not None
        )
        if len(sdk_entrypoints) != len(set(sdk_entrypoints)):
            raise ValueError("v2 SDK lifecycle entrypoints must be unique")
        if len(mcp_tools) != len(set(mcp_tools)):
            raise ValueError("v2 MCP lifecycle tools must be unique")

        agent_participation = tuple(
            operation.agent_surface_participation
            for loop in self.loops
            for operation in loop.operations
        )
        if agent_participation.count(GoldenLoopProjectionParticipation.CALLABLE) != 20:
            raise ValueError("v2 Agent lifecycle callable coverage drifted")
        if agent_participation.count(GoldenLoopProjectionParticipation.BLOCKED) != 44:
            raise ValueError("v2 Agent lifecycle blocker coverage drifted")

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        expected_digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if self.registry_digest and self.registry_digest != expected_digest:
            raise ValueError("registry_digest does not match the v2 lifecycle declaration")
        object.__setattr__(self, "registry_digest", expected_digest)
        return self

    def get(self, loop_ref: GoldenLoopRef | str) -> GoldenLoopLifecycleContract:
        selected = GoldenLoopRef(loop_ref)
        for loop in self.loops:
            if loop.loop_ref is selected:
                return loop
        raise KeyError(f"Golden Loop lifecycle is not declared: {selected.value}")

    def assert_sdk_entrypoints(
        self,
        sync_client_type: type[object],
        async_client_type: type[object],
    ) -> None:
        """Fail closed when a declared sync/async SDK method is not concrete."""

        failures: list[str] = []
        for loop in self.loops:
            for operation in loop.operations:
                method_name = operation.sdk_method_name
                if method_name is None:
                    continue
                if not callable(getattr(sync_client_type, method_name, None)):
                    failures.append(
                        f"{loop.loop_ref.value}.{operation.operation_ref}: sync {method_name}"
                    )
                if not callable(getattr(async_client_type, method_name, None)):
                    failures.append(
                        f"{loop.loop_ref.value}.{operation.operation_ref}: async {method_name}"
                    )
        if failures:
            raise RuntimeError(
                "Golden Loop v2 SDK lifecycle entrypoint drift: " + "; ".join(failures)
            )


class GoldenLoopLifecycleRegistryV3(GoldenLoopLifecycleRegistry):
    """Current digest-sealed lifecycle generation under a distinct schema."""

    schema_id: Literal["lightbulb.golden_loop_lifecycle_registry.v3"] = Field(
        default=GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_SCHEMA,
        alias="schema",
    )
    version: Literal["3.0.0"] = GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_VERSION


class _LifecycleAuthorityMetadata(_StrictModel):
    """Typed transport and recovery metadata for one callable authority row."""

    http_method: Literal["GET", "POST"]
    endpoint_template: str = Field(min_length=1, max_length=500)
    run_extraction_path: Literal["$", "$.run"] | None = None
    response_schema: str = Field(
        pattern=r"^lightbulb\.[a-z][a-z0-9_.]{0,198}\.v[1-9][0-9]*$"
    )
    effect: GoldenLoopLifecycleEffect
    approval_requirement: GoldenLoopLifecycleApprovalRequirement
    idempotency_class: GoldenLoopLifecycleIdempotencyClass
    retry_class: GoldenLoopLifecycleRetryClass
    ambiguity_policy: AmbiguousOutcomePolicy


def _authority(
    http_method: Literal["GET", "POST"],
    endpoint_template: str,
    response_schema: str,
    *,
    run_extraction_path: Literal["$", "$.run"] | None = None,
    effect: GoldenLoopLifecycleEffect = (
        GoldenLoopLifecycleEffect.NO_EXTERNAL_EFFECT
    ),
    approval_requirement: GoldenLoopLifecycleApprovalRequirement = (
        GoldenLoopLifecycleApprovalRequirement.NOT_REQUIRED
    ),
    idempotency_class: GoldenLoopLifecycleIdempotencyClass = (
        GoldenLoopLifecycleIdempotencyClass.SOURCE_IDENTITY
    ),
    retry_class: GoldenLoopLifecycleRetryClass = (
        GoldenLoopLifecycleRetryClass.IDEMPOTENT_REPLAY
    ),
    ambiguity_policy: AmbiguousOutcomePolicy = AmbiguousOutcomePolicy.NOT_APPLICABLE,
) -> _LifecycleAuthorityMetadata:
    return _LifecycleAuthorityMetadata(
        http_method=http_method,
        endpoint_template=endpoint_template,
        run_extraction_path=run_extraction_path,
        response_schema=response_schema,
        effect=effect,
        approval_requirement=approval_requirement,
        idempotency_class=idempotency_class,
        retry_class=retry_class,
        ambiguity_policy=ambiguity_policy,
    )


def _read_authority(
    endpoint_template: str,
    response_schema: str,
    *,
    run_extraction_path: Literal["$", "$.run"] | None = None,
    effect: GoldenLoopLifecycleEffect = (
        GoldenLoopLifecycleEffect.NO_EXTERNAL_EFFECT
    ),
) -> _LifecycleAuthorityMetadata:
    return _authority(
        "GET",
        endpoint_template,
        response_schema,
        run_extraction_path=run_extraction_path,
        effect=effect,
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.NOT_APPLICABLE,
        retry_class=GoldenLoopLifecycleRetryClass.SAFE_READ,
    )


_SDK_PREFIX = "lightbulb.client.LightbulbClient."
_AGENT_PREFIX = "agent-workers.agents."


def _agent(module: str, class_name: str, method_name: str) -> str:
    return f"{_AGENT_PREFIX}{module}.{class_name}.{method_name}"


def _admission(method_name: str) -> str:
    return _agent(
        "golden_loop_admission",
        "ManagedGoldenLoopAdmissionClient",
        method_name,
    )


_CTC_RUN_ROOT = "/api/projects/{project_id}/contract-to-cash/runs"
_PERIOD_ROOT = "/api/projects/{project_id}/finance/period-reconciliation"
_SERVICE_RUN_ROOT = "/api/projects/{project_id}/service/case-resolution-runs"
_REVENUE_RUN_ROOT = (
    "/api/tenants/{tenant_id}/companies/{company_id}/projects/{project_id}/"
    "governed-communication-runs"
)

_authority_row_data: dict[str, _LifecycleAuthorityMetadata] = {
    "register_executed_commercial_agreement": _authority(
        "POST",
        "/api/projects/{project_id}/commercial-agreements/executed/records",
        "lightbulb.executed_commercial_agreement_record.v1",
    ),
    "get_executed_commercial_agreement": _read_authority(
        "/api/projects/{project_id}/commercial-agreements/executed/records/{record_id}",
        "lightbulb.executed_commercial_agreement_record.v1",
    ),
    "resolve_executed_commercial_agreement": _read_authority(
        "/api/projects/{project_id}/commercial-agreements/executed/records/resolve",
        "lightbulb.executed_commercial_agreement_record.v1",
    ),
    "propose_contract_to_cash_invoice": _authority(
        "POST",
        "/api/projects/{project_id}/finance/contract-to-cash/invoice/proposals",
        "lightbulb.contract_to_cash_invoice_proposal_receipt.v1",
        approval_requirement=(
            GoldenLoopLifecycleApprovalRequirement.PROPOSES_APPROVAL
        ),
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.WORKFLOW_STEP,
    ),
    "execute_contract_to_cash_invoice": _authority(
        "POST",
        "/api/projects/{project_id}/finance/contract-to-cash/invoice/executions",
        "lightbulb.contract_to_cash_invoice_write_receipt.v1",
        effect=GoldenLoopLifecycleEffect.EXTERNAL_WRITE,
        approval_requirement=(
            GoldenLoopLifecycleApprovalRequirement.EXACT_APPROVAL_REQUIRED
        ),
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.WORKFLOW_STEP,
        retry_class=GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY,
        ambiguity_policy=(
            AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY
        ),
    ),
    "register_contract_to_cash_invoice_issued": _authority(
        "POST",
        "/api/projects/{project_id}/contract-to-cash/invoices/issued/records",
        "lightbulb.contract_to_cash_invoice_issued_record.v1",
        approval_requirement=(
            GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
        ),
    ),
    "get_contract_to_cash_invoice_issued": _read_authority(
        "/api/projects/{project_id}/contract-to-cash/invoices/issued/records/{record_id}",
        "lightbulb.contract_to_cash_invoice_issued_record.v1",
    ),
    "register_contract_to_cash_cash_collection": _authority(
        "POST",
        "/api/projects/{project_id}/contract-to-cash/cash-collections/records",
        "lightbulb.contract_to_cash_collection_record.v1",
    ),
    "get_contract_to_cash_cash_collection": _read_authority(
        "/api/projects/{project_id}/contract-to-cash/cash-collections/records/{record_id}",
        "lightbulb.contract_to_cash_collection_record.v1",
    ),
    "start_contract_to_cash_run": _authority(
        "POST",
        _CTC_RUN_ROOT,
        "lightbulb.contract_to_cash_run.v1",
        run_extraction_path="$",
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.IDEMPOTENCY_KEY,
    ),
    "get_contract_to_cash_run": _read_authority(
        f"{_CTC_RUN_ROOT}/{{run_ref}}",
        "lightbulb.contract_to_cash_run.v1",
        run_extraction_path="$",
    ),
    "attach_contract_to_cash_invoice_issued": _authority(
        "POST",
        f"{_CTC_RUN_ROOT}/{{run_ref}}/invoice-issued",
        "lightbulb.contract_to_cash_run.v1",
        run_extraction_path="$",
        approval_requirement=(
            GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
        ),
    ),
    "attach_contract_to_cash_cash_collected": _authority(
        "POST",
        f"{_CTC_RUN_ROOT}/{{run_ref}}/cash-collected",
        "lightbulb.contract_to_cash_run.v1",
        run_extraction_path="$",
    ),
    "cancel_contract_to_cash_before_invoice": _authority(
        "POST",
        f"{_CTC_RUN_ROOT}/{{run_ref}}/cancel",
        "lightbulb.contract_to_cash_run.v1",
        run_extraction_path="$",
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.WORKFLOW_STEP,
    ),
}

_authority_row_data.update(
    {
        "start_project_work_packet": _authority(
            "POST",
            "/api/projects/{project_id}/work-packet-runs",
            "lightbulb.project_work_packet_start.v1",
            effect=GoldenLoopLifecycleEffect.CODING_HARNESS,
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
            ),
            retry_class=GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY,
            ambiguity_policy=(
                AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY
            ),
        ),
        "get_project_work_packet_run": _read_authority(
            "/api/projects/{project_id}/work-packet-runs/{run_ref}",
            "lightbulb.project_work_packet_run.v1",
        ),
        "dynamic_workflow_next_assignment": _authority(
            "POST",
            "/api/dynamic-workflows/next-assignment",
            "lightbulb.dynamic_workflow_next_assignment.v1",
            run_extraction_path="$",
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
            ),
            idempotency_class=(
                GoldenLoopLifecycleIdempotencyClass.IDEMPOTENCY_KEY_AND_REVISION
            ),
        ),
        "dynamic_workflow_cancel": _authority(
            "POST",
            "/api/dynamic-workflows/cancel",
            "lightbulb.dynamic_workflow_cancel.v1",
            run_extraction_path="$",
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
            ),
            idempotency_class=(
                GoldenLoopLifecycleIdempotencyClass.IDEMPOTENCY_KEY_AND_REVISION
            ),
        ),
        "start_governed_communication_run": _authority(
            "POST",
            _REVENUE_RUN_ROOT,
            "lightbulb.governed_communication_admission.v1",
            run_extraction_path="$.run",
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
            ),
            idempotency_class=GoldenLoopLifecycleIdempotencyClass.IDEMPOTENCY_KEY,
        ),
        "get_governed_communication_run": _read_authority(
            f"{_REVENUE_RUN_ROOT}/{{run_ref}}",
            "lightbulb.governed_communication_run.v1",
            run_extraction_path="$",
        ),
        "cancel_governed_communication_run": _authority(
            "POST",
            f"{_REVENUE_RUN_ROOT}/{{run_ref}}/actions/cancel",
            "lightbulb.governed_communication_run.v1",
            run_extraction_path="$",
            idempotency_class=GoldenLoopLifecycleIdempotencyClass.WORKFLOW_STEP,
        ),
        "start_service_case_resolution": _authority(
            "POST",
            _SERVICE_RUN_ROOT,
            "lightbulb.service_case_resolution_run.v1",
            run_extraction_path="$",
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PROPOSES_APPROVAL
            ),
            idempotency_class=GoldenLoopLifecycleIdempotencyClass.IDEMPOTENCY_KEY,
        ),
        "get_service_case_resolution": _read_authority(
            f"{_SERVICE_RUN_ROOT}/{{run_ref}}",
            "lightbulb.service_case_resolution_run.v1",
            run_extraction_path="$",
        ),
        "advance_service_case_resolution": _authority(
            "POST",
            f"{_SERVICE_RUN_ROOT}/{{run_ref}}/advance",
            "lightbulb.service_case_resolution_run.v1",
            run_extraction_path="$",
            effect=GoldenLoopLifecycleEffect.EXTERNAL_WRITE,
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.EXACT_APPROVAL_REQUIRED
            ),
            retry_class=GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY,
            ambiguity_policy=(
                AmbiguousOutcomePolicy.MANUAL_RECONCILIATION_NO_REPLAY
            ),
        ),
        "cancel_service_case_resolution": _authority(
            "POST",
            f"{_SERVICE_RUN_ROOT}/{{run_ref}}/cancel",
            "lightbulb.service_case_resolution_run.v1",
            run_extraction_path="$",
            approval_requirement=(
                GoldenLoopLifecycleApprovalRequirement.PRIOR_APPROVAL_CUSTODY
            ),
        ),
    }
)

_AUTHORITY_ROWS: Mapping[str, _LifecycleAuthorityMetadata] = MappingProxyType(
    _authority_row_data
)
del _authority_row_data


def _callable_operation(
    operation_ref: str,
    kind: GoldenLoopLifecycleOperationKind,
    *,
    availability: GoldenLoopLifecycleAuthorityAvailability = (
        GoldenLoopLifecycleAuthorityAvailability.PUBLIC
    ),
    sdk_method_name: str | None = None,
    agent_mcp: bool = False,
    agent_entrypoint_refs: tuple[str, ...] = (),
    agent_surface_blocker_code: str | None = None,
) -> GoldenLoopLifecycleOperation:
    if agent_mcp == (agent_surface_blocker_code is not None):
        raise RuntimeError(
            f"{operation_ref} must declare exactly one Agent entrypoint or blocker"
        )
    try:
        authority = _AUTHORITY_ROWS[operation_ref]
    except KeyError as exc:
        raise RuntimeError(
            f"Golden Loop v2 authority metadata is missing for {operation_ref}"
        ) from exc
    return GoldenLoopLifecycleOperation(
        operation_ref=operation_ref,
        kind=kind,
        authority_availability=availability,
        surface_participation=GoldenLoopProjectionParticipation.CALLABLE,
        http_method=authority.http_method,
        endpoint_template=authority.endpoint_template,
        run_extraction_path=authority.run_extraction_path,
        response_schema=authority.response_schema,
        effect=authority.effect,
        approval_requirement=authority.approval_requirement,
        idempotency_class=authority.idempotency_class,
        retry_class=authority.retry_class,
        ambiguity_policy=authority.ambiguity_policy,
        sdk_entrypoint_ref=f"{_SDK_PREFIX}{sdk_method_name or operation_ref}",
        mcp_tool_name=operation_ref,
        chatgpt_tool_name=operation_ref,
        agent_surface_participation=(
            GoldenLoopProjectionParticipation.CALLABLE
            if agent_mcp
            else GoldenLoopProjectionParticipation.BLOCKED
        ),
        agent_mcp_tool_name=operation_ref if agent_mcp else None,
        agent_entrypoint_refs=agent_entrypoint_refs,
        agent_surface_blocker_code=agent_surface_blocker_code,
    )


def _worker_only_operation(
    operation_ref: str,
    *,
    blocker_code: str,
) -> GoldenLoopLifecycleOperation:
    return GoldenLoopLifecycleOperation(
        operation_ref=operation_ref,
        kind=GoldenLoopLifecycleOperationKind.TRANSITION,
        authority_availability=GoldenLoopLifecycleAuthorityAvailability.WORKER_ONLY,
        surface_participation=GoldenLoopProjectionParticipation.BLOCKED,
        effect=GoldenLoopLifecycleEffect.WORKER_INTERNAL,
        approval_requirement=GoldenLoopLifecycleApprovalRequirement.WORKER_OWNED,
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.WORKER_OWNED,
        retry_class=GoldenLoopLifecycleRetryClass.BLOCKED,
        ambiguity_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        agent_surface_participation=GoldenLoopProjectionParticipation.BLOCKED,
        blocker_code=blocker_code,
        forbidden_entrypoint_ref=operation_ref,
        agent_surface_blocker_code=blocker_code,
    )


def _unavailable_operation(
    operation_ref: str,
    kind: GoldenLoopLifecycleOperationKind,
    *,
    blocker_code: str,
) -> GoldenLoopLifecycleOperation:
    return GoldenLoopLifecycleOperation(
        operation_ref=operation_ref,
        kind=kind,
        authority_availability=GoldenLoopLifecycleAuthorityAvailability.UNAVAILABLE,
        surface_participation=GoldenLoopProjectionParticipation.BLOCKED,
        effect=GoldenLoopLifecycleEffect.NO_EXTERNAL_EFFECT,
        approval_requirement=GoldenLoopLifecycleApprovalRequirement.NOT_REQUIRED,
        idempotency_class=GoldenLoopLifecycleIdempotencyClass.NOT_APPLICABLE,
        retry_class=GoldenLoopLifecycleRetryClass.BLOCKED,
        ambiguity_policy=AmbiguousOutcomePolicy.NOT_APPLICABLE,
        agent_surface_participation=GoldenLoopProjectionParticipation.BLOCKED,
        blocker_code=blocker_code,
        forbidden_entrypoint_ref=operation_ref,
        agent_surface_blocker_code=blocker_code,
    )


_CTC_AGENT = "contract_to_cash_agent_projection"
_CTC_CLASS = "ContractToCashAgentProjection"
_PERIOD_AGENT = "period_reconciliation_agent_projection"
_PERIOD_CLASS = "PeriodReconciliationAgentProjection"


CONTRACT_TO_CASH_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.CONTRACT_TO_CASH,
    source_declaration_version="0.2.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=True,
    forbidden_aliases=(
        GoldenLoopForbiddenAlias(
            alias_ref="advance_contract_to_cash_run",
            blocker_code="golden_loop.contract_to_cash.advance_transition_specific",
        ),
    ),
    operations=(
        _callable_operation(
            "register_executed_commercial_agreement",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "register_executed_commercial_agreement"),
            ),
        ),
        _callable_operation(
            "get_executed_commercial_agreement",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "get_executed_commercial_agreement"),
            ),
        ),
        _callable_operation(
            "resolve_executed_commercial_agreement",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "resolve_executed_commercial_agreement"),
            ),
        ),
        _callable_operation(
            "propose_contract_to_cash_invoice",
            GoldenLoopLifecycleOperationKind.PROPOSAL,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "propose_invoice"),
            ),
        ),
        _callable_operation(
            "execute_contract_to_cash_invoice",
            GoldenLoopLifecycleOperationKind.GOVERNED_EFFECT,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "execute_invoice"),
            ),
        ),
        _callable_operation(
            "register_contract_to_cash_invoice_issued",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "register_invoice_issued"),
            ),
        ),
        _callable_operation(
            "get_contract_to_cash_invoice_issued",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "get_invoice_issued"),
            ),
        ),
        _callable_operation(
            "register_contract_to_cash_cash_collection",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "register_cash_collection"),
            ),
        ),
        _callable_operation(
            "get_contract_to_cash_cash_collection",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "get_cash_collection"),
            ),
        ),
        _callable_operation(
            "start_contract_to_cash_run",
            GoldenLoopLifecycleOperationKind.START,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "start_run"),
                _admission("start_contract_to_cash"),
            ),
        ),
        _callable_operation(
            "get_contract_to_cash_run",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "get_run"),
                _admission("get_run"),
            ),
        ),
        _callable_operation(
            "attach_contract_to_cash_invoice_issued",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "attach_invoice_issued"),
            ),
        ),
        _callable_operation(
            "attach_contract_to_cash_cash_collected",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "attach_cash_collected"),
            ),
        ),
        _callable_operation(
            "cancel_contract_to_cash_before_invoice",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            agent_mcp=True,
            agent_entrypoint_refs=(
                _agent(_CTC_AGENT, _CTC_CLASS, "cancel_before_invoice"),
            ),
        ),
    ),
)


FINANCE_JOURNAL_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.FINANCE_JOURNAL,
    source_declaration_version="0.3.0",
    source_execution_loop_version="0.2.0",
    ambiguous_effect_applicable=True,
    operations=(
        _unavailable_operation(
            "start_finance_journal_settlement",
            GoldenLoopLifecycleOperationKind.START,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "get_finance_journal_settlement",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "advance_finance_journal_settlement",
            GoldenLoopLifecycleOperationKind.GOVERNED_EFFECT,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "cancel_finance_journal_settlement",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "step_finance_journal_settlement",
            GoldenLoopLifecycleOperationKind.GOVERNED_EFFECT,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)


PERIOD_RECONCILIATION_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.PERIOD_RECONCILIATION,
    source_declaration_version="0.3.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=False,
    distinct_successor_identity_required=True,
    operations=(
        _unavailable_operation(
            "retain_period_reconciliation_scope",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "start_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.START,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "restart_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.START,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "retain_period_reconciliation_quickbooks_reads",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "evaluate_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "retain_period_reconciliation_review",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "advance_period_reconciliation_stage",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "get_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "get_period_reconciliation_outcomes",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "get_period_reconciliation_campaign_facts",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "fail_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
        _unavailable_operation(
            "cancel_period_reconciliation_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.finance.canonical_runtime_not_bound",
        ),
    ),
)


PROCUREMENT_MATCHED_CLOSE_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.PROCUREMENT_MATCHED_CLOSE,
    source_declaration_version="0.3.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=True,
    forbidden_aliases=(
        GoldenLoopForbiddenAlias(
            alias_ref="advance_procurement_matched_close_run",
            blocker_code="golden_loop.procurement.advance_transition_specific",
        ),
    ),
    operations=(
        _unavailable_operation(
            "start_procurement_matched_close_run",
            GoldenLoopLifecycleOperationKind.START,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "submit_procurement_requisition",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "approve_procurement_spend_commitment",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "bind_procurement_xero_purchase_order_readback",
            GoldenLoopLifecycleOperationKind.GOVERNED_EFFECT,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "record_procurement_goods_receipt",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "record_procurement_supplier_invoice",
            GoldenLoopLifecycleOperationKind.PREFLIGHT_CUSTODY,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "derive_procurement_three_way_match",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "approve_procurement_matched_close",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "get_procurement_matched_close_run",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "get_procurement_matched_close_outcomes",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "fail_procurement_matched_close_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "cancel_procurement_matched_close_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "mark_procurement_purchase_order_ambiguous",
            GoldenLoopLifecycleOperationKind.AMBIGUITY,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
        _unavailable_operation(
            "reconcile_procurement_purchase_order",
            GoldenLoopLifecycleOperationKind.RECONCILIATION,
            blocker_code="golden_loop.procurement.derived_match_authority_not_bound",
        ),
    ),
)


PROJECT_WORK_PACKET_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.PROJECT_WORK_PACKET,
    source_declaration_version="0.2.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=True,
    operations=(
        _callable_operation(
            "start_project_work_packet",
            GoldenLoopLifecycleOperationKind.START,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("start_project"),),
        ),
        _callable_operation(
            "get_project_work_packet_run",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("get_run"),),
        ),
        _callable_operation(
            "dynamic_workflow_next_assignment",
            GoldenLoopLifecycleOperationKind.ROLE_PROTOCOL,
            availability=(
                GoldenLoopLifecycleAuthorityAvailability.ROLE_PROTOCOL_ONLY
            ),
            agent_surface_blocker_code=(
                "golden_loop.agent.project_assignment_requires_role_custody"
            ),
        ),
        _callable_operation(
            "dynamic_workflow_cancel",
            GoldenLoopLifecycleOperationKind.ROLE_PROTOCOL,
            availability=(
                GoldenLoopLifecycleAuthorityAvailability.ROLE_PROTOCOL_ONLY
            ),
            sdk_method_name="cancel_project_work_packet",
            agent_surface_blocker_code=(
                "golden_loop.agent.project_cancel_requires_role_custody"
            ),
        ),
    ),
)


REVENUE_VERIFIED_REPLY_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.REVENUE_VERIFIED_REPLY,
    source_declaration_version="0.2.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=True,
    operations=(
        _callable_operation(
            "start_governed_communication_run",
            GoldenLoopLifecycleOperationKind.START,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("start_revenue"),),
        ),
        _callable_operation(
            "get_governed_communication_run",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("get_run"),),
        ),
        _worker_only_operation(
            "advance_governed_communication_run",
            blocker_code="golden_loop.revenue.advance_worker_only",
        ),
        _callable_operation(
            "cancel_governed_communication_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            agent_surface_blocker_code=(
                "golden_loop.agent.revenue_cancel_not_projected"
            ),
        ),
    ),
)


SERVICE_VERIFIED_RESOLUTION_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.SERVICE_VERIFIED_RESOLUTION,
    source_declaration_version="0.3.0",
    source_execution_loop_version="0.2.0",
    ambiguous_effect_applicable=True,
    operations=(
        _callable_operation(
            "start_service_case_resolution",
            GoldenLoopLifecycleOperationKind.START,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("start_service"),),
        ),
        _callable_operation(
            "get_service_case_resolution",
            GoldenLoopLifecycleOperationKind.READ,
            agent_mcp=True,
            agent_entrypoint_refs=(_admission("get_run"),),
        ),
        _callable_operation(
            "advance_service_case_resolution",
            GoldenLoopLifecycleOperationKind.GOVERNED_EFFECT,
            agent_surface_blocker_code=(
                "golden_loop.agent.service_advance_worker_owned"
            ),
        ),
        _callable_operation(
            "cancel_service_case_resolution",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            agent_surface_blocker_code=(
                "golden_loop.agent.service_cancel_not_projected"
            ),
        ),
    ),
)


VERIFIED_IMPROVEMENT_LIFECYCLE_V2 = GoldenLoopLifecycleContract(
    loop_ref=GoldenLoopRef.VERIFIED_IMPROVEMENT,
    source_declaration_version="0.3.0",
    source_execution_loop_version="0.1.0",
    ambiguous_effect_applicable=True,
    operations=(
        _unavailable_operation(
            "start_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.START,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "get_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.READ,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "advance_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.TRANSITION,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "fail_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "cancel_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.TERMINAL,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "mark_verified_improvement_harness_outcome_ambiguous",
            GoldenLoopLifecycleOperationKind.AMBIGUITY,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
        _unavailable_operation(
            "reconcile_verified_improvement_run",
            GoldenLoopLifecycleOperationKind.RECONCILIATION,
            blocker_code="golden_loop.verified_improvement.source_authority_quarantined",
        ),
    ),
)


def _period_lifecycle_with_retry_overrides(
    *,
    source_declaration_version: str,
    source_execution_loop_version: str,
    retry_overrides: Mapping[str, GoldenLoopLifecycleRetryClass] | None = None,
) -> GoldenLoopLifecycleContract:
    """Revalidate a retained Period generation without mutating frozen models."""

    overrides = retry_overrides or {}
    operations: list[GoldenLoopLifecycleOperation] = []
    for operation in PERIOD_RECONCILIATION_LIFECYCLE_V2.operations:
        payload = operation.model_dump(mode="python")
        if (
            operation.surface_participation
            is GoldenLoopProjectionParticipation.CALLABLE
            and operation.operation_ref in overrides
        ):
            payload["retry_class"] = overrides[operation.operation_ref]
        operations.append(GoldenLoopLifecycleOperation.model_validate(payload))
    return GoldenLoopLifecycleContract(
        loop_ref=GoldenLoopRef.PERIOD_RECONCILIATION,
        source_declaration_version=source_declaration_version,
        source_execution_loop_version=source_execution_loop_version,
        ambiguous_effect_applicable=False,
        distinct_successor_identity_required=True,
        operations=tuple(operations),
    )


# This exact subgeneration was emitted before the retry annotation was corrected.
# It remains resolvable because admissions persist its registry/lifecycle digests.
PERIOD_RECONCILIATION_LIFECYCLE_V2_PRE_CORRECTION = (
    _period_lifecycle_with_retry_overrides(
        source_declaration_version="0.3.0",
        source_execution_loop_version="0.1.0",
        retry_overrides={
            "advance_period_reconciliation_stage": (
                GoldenLoopLifecycleRetryClass.IDEMPOTENT_REPLAY
            ),
            "cancel_period_reconciliation_run": (
                GoldenLoopLifecycleRetryClass.IDEMPOTENT_REPLAY
            ),
        },
    )
)

PERIOD_RECONCILIATION_LIFECYCLE_V3 = _period_lifecycle_with_retry_overrides(
    source_declaration_version="0.4.0",
    source_execution_loop_version="0.2.0",
    retry_overrides={
        "retain_period_reconciliation_scope": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
        "restart_period_reconciliation_run": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
        "retain_period_reconciliation_quickbooks_reads": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
        "evaluate_period_reconciliation_run": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
        "retain_period_reconciliation_review": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
        "fail_period_reconciliation_run": (
            GoldenLoopLifecycleRetryClass.NO_AUTOMATIC_RETRY
        ),
    },
)


GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_PRE_CORRECTION = GoldenLoopLifecycleRegistry(
    loops=(
        CONTRACT_TO_CASH_LIFECYCLE_V2,
        FINANCE_JOURNAL_LIFECYCLE_V2,
        PERIOD_RECONCILIATION_LIFECYCLE_V2_PRE_CORRECTION,
        PROCUREMENT_MATCHED_CLOSE_LIFECYCLE_V2,
        PROJECT_WORK_PACKET_LIFECYCLE_V2,
        REVENUE_VERIFIED_REPLY_LIFECYCLE_V2,
        SERVICE_VERIFIED_RESOLUTION_LIFECYCLE_V2,
        VERIFIED_IMPROVEMENT_LIFECYCLE_V2,
    )
)


GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2 = GoldenLoopLifecycleRegistry(
    loops=(
        CONTRACT_TO_CASH_LIFECYCLE_V2,
        FINANCE_JOURNAL_LIFECYCLE_V2,
        PERIOD_RECONCILIATION_LIFECYCLE_V2,
        PROCUREMENT_MATCHED_CLOSE_LIFECYCLE_V2,
        PROJECT_WORK_PACKET_LIFECYCLE_V2,
        REVENUE_VERIFIED_REPLY_LIFECYCLE_V2,
        SERVICE_VERIFIED_RESOLUTION_LIFECYCLE_V2,
        VERIFIED_IMPROVEMENT_LIFECYCLE_V2,
    )
)


GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3 = GoldenLoopLifecycleRegistryV3(
    loops=(
        CONTRACT_TO_CASH_LIFECYCLE_V2,
        FINANCE_JOURNAL_LIFECYCLE_V2,
        PERIOD_RECONCILIATION_LIFECYCLE_V3,
        PROCUREMENT_MATCHED_CLOSE_LIFECYCLE_V2,
        PROJECT_WORK_PACKET_LIFECYCLE_V2,
        REVENUE_VERIFIED_REPLY_LIFECYCLE_V2,
        SERVICE_VERIFIED_RESOLUTION_LIFECYCLE_V2,
        VERIFIED_IMPROVEMENT_LIFECYCLE_V2,
    )
)

# Generation-agnostic consumers follow this alias; replay code must select an
# explicit retained generation by persisted digest instead.
GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT = GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3

_declared_callable_operation_refs = {
    operation.operation_ref
    for loop in GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT.loops
    for operation in loop.operations
    if operation.surface_participation
    is GoldenLoopProjectionParticipation.CALLABLE
}
if set(_AUTHORITY_ROWS) != _declared_callable_operation_refs:
    missing = sorted(_declared_callable_operation_refs.difference(_AUTHORITY_ROWS))
    extra = sorted(set(_AUTHORITY_ROWS).difference(_declared_callable_operation_refs))
    raise RuntimeError(
        "Golden Loop current authority metadata coverage drifted; "
        f"missing={missing}, extra={extra}"
    )
del _declared_callable_operation_refs


__all__ = [
    "CONTRACT_TO_CASH_LIFECYCLE_V2",
    "EXPECTED_GOLDEN_LOOP_V2_OPERATION_COUNTS",
    "FINANCE_JOURNAL_LIFECYCLE_V2",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_SCHEMA",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_CURRENT",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_PRE_CORRECTION",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_SCHEMA",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V2_VERSION",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_SCHEMA",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_V3_VERSION",
    "GOLDEN_LOOP_LIFECYCLE_REGISTRY_VERSION",
    "GoldenLoopForbiddenAlias",
    "GoldenLoopLifecycleApprovalRequirement",
    "GoldenLoopLifecycleAuthorityAvailability",
    "GoldenLoopLifecycleContract",
    "GoldenLoopLifecycleEffect",
    "GoldenLoopLifecycleIdempotencyClass",
    "GoldenLoopLifecycleOperation",
    "GoldenLoopLifecycleOperationKind",
    "GoldenLoopLifecycleRegistry",
    "GoldenLoopLifecycleRegistryV3",
    "GoldenLoopLifecycleRetryClass",
    "GoldenLoopLifecycleSurface",
    "PERIOD_RECONCILIATION_LIFECYCLE_V2",
    "PERIOD_RECONCILIATION_LIFECYCLE_V2_PRE_CORRECTION",
    "PERIOD_RECONCILIATION_LIFECYCLE_V3",
    "PROCUREMENT_MATCHED_CLOSE_LIFECYCLE_V2",
    "PROJECT_WORK_PACKET_LIFECYCLE_V2",
    "REVENUE_VERIFIED_REPLY_LIFECYCLE_V2",
    "SERVICE_VERIFIED_RESOLUTION_LIFECYCLE_V2",
    "VERIFIED_IMPROVEMENT_LIFECYCLE_V2",
]
