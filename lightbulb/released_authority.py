"""Fail-closed release authority contract for governed Lightbulb execution.

The capability inventory describes breadth.  This module describes the much
smaller set of governed capabilities that a release is allowed to claim.  It
does not grant runtime authority; Spring and PostgreSQL remain authoritative.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

LEGACY_RELEASED_AUTHORITY_SCHEMA = "lightbulb.released_authority_manifest.v1"
LEGACY_RELEASED_AUTHORITY_VERSION = "1.0.0"
RELEASED_AUTHORITY_SCHEMA = "lightbulb.released_authority_manifest.v2"
RELEASED_AUTHORITY_VERSION = "2.0.0"
# The largest reviewed Tool projection currently has 160 source paths. Keep a
# bounded 20% reserve for adjacent release proofs without making the contract
# effectively unbounded.
MAX_RELEASED_TOOL_SOURCE_PATHS = 192

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$")
_GATE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_MIGRATION_RE = re.compile(r"^V[0-9]{1,9}$")
_HTTP_PATH_RE = re.compile(r"^/api(?:/[A-Za-z0-9_.{}-]+)+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def released_authority_digest(value: Any) -> str:
    """Return SHA-256 over portable canonical JSON."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _portable_repo_path(value: str) -> str:
    clean = value.strip().replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    if (
        not clean
        or clean.startswith("/")
        or re.match(r"^[A-Za-z]:", clean)
        or ".." in clean.split("/")
        or _CONTROL_RE.search(clean)
    ):
        raise ValueError("path must be safe and repository-relative")
    return clean


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class AuthorityEffect(str, Enum):
    READ = "READ"
    WRITE = "WRITE"


class EndpointAvailability(str, Enum):
    DECLARED_DARK = "DECLARED_DARK"
    PRODUCTION_ENABLED = "PRODUCTION_ENABLED"


class EndpointAuthorityClass(str, Enum):
    SPRING_RUNTIME = "SPRING_RUNTIME"
    SPRING_OPERATOR_CONTROL = "SPRING_OPERATOR_CONTROL"


class CredentialMechanism(str, Enum):
    SPRING_SELECTED_OAUTH_CONNECTION = "SPRING_SELECTED_OAUTH_CONNECTION"
    SPRING_ROUTE_SELECTED_CONNECTION_DARK = "SPRING_ROUTE_SELECTED_CONNECTION_DARK"
    SPRING_EXACT_OAUTH_TARGET_CUSTODY_DARK = "SPRING_EXACT_OAUTH_TARGET_CUSTODY_DARK"


class ApprovalPolicyClass(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    SPRING_GENERIC_HITL_DARK = "SPRING_GENERIC_HITL_DARK"
    SPRING_INDEPENDENT_FINANCIAL_REVIEW_V1 = "SPRING_INDEPENDENT_FINANCIAL_REVIEW_V1"


class RecoverySupport(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    AMBIGUOUS_BLOCK_ONLY = "AMBIGUOUS_BLOCK_ONLY"
    APPLIED_RECONCILIATION_DARK = "APPLIED_RECONCILIATION_DARK"
    COMPLETE = "COMPLETE"


class ConnectorCertificationState(str, Enum):
    UNCERTIFIED = "UNCERTIFIED"
    CERTIFIED = "CERTIFIED"


class ProductionEnablementState(str, Enum):
    DISABLED = "DISABLED"
    CANARY = "CANARY"
    ENABLED = "ENABLED"


class GovernedEndpointAuthority(_StrictModel):
    endpoint_id: str = Field(min_length=1, max_length=200)
    method: Literal["GET", "POST"]
    path: str = Field(min_length=1, max_length=500)
    availability: EndpointAvailability
    authority_class: EndpointAuthorityClass
    required_feature_gates: tuple[str, ...] = Field(min_length=1, max_length=20)
    source_path: str

    @field_validator("endpoint_id")
    @classmethod
    def _endpoint_id(cls, value: str) -> str:
        clean = value.strip()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError("endpoint_id must be nonblank and contain no controls")
        return clean

    @field_validator("path")
    @classmethod
    def _http_path(cls, value: str) -> str:
        clean = value.strip()
        if not _HTTP_PATH_RE.fullmatch(clean):
            raise ValueError("endpoint path must be an exact /api path")
        return clean

    @field_validator("required_feature_gates", mode="before")
    @classmethod
    def _gate_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("required_feature_gates")
    @classmethod
    def _known_gate_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if not normalized or any(not _GATE_RE.fullmatch(item) for item in normalized):
            raise ValueError("endpoint feature gates must use exact environment names")
        return normalized

    @field_validator("source_path")
    @classmethod
    def _source_path(cls, value: str) -> str:
        return _portable_repo_path(value)


class FeatureGateAuthority(_StrictModel):
    name: str
    default_value: str = Field(max_length=1_000)
    production_value: str = Field(max_length=1_000)
    dangerous: bool
    source_paths: tuple[str, ...] = Field(min_length=1, max_length=20)

    @field_validator("name")
    @classmethod
    def _gate_name(cls, value: str) -> str:
        clean = value.strip()
        if not _GATE_RE.fullmatch(clean):
            raise ValueError("feature gate name is invalid")
        return clean

    @field_validator("source_paths", mode="before")
    @classmethod
    def _path_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("source_paths")
    @classmethod
    def _source_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_portable_repo_path(item) for item in value}))


class CatalogToolAuthority(_StrictModel):
    name: str
    version: int = Field(ge=1)

    @field_validator("name")
    @classmethod
    def _tool_name(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _TOOL_RE.fullmatch(clean):
            raise ValueError("Tool name is invalid")
        return clean


class ReviewedCatalogAuthority(_StrictModel):
    catalog_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=160)
    version: int = Field(ge=1)
    effect: AuthorityEffect
    tools: tuple[CatalogToolAuthority, ...] = Field(min_length=1, max_length=1_000)
    catalog_digest: str = ""
    source_paths: tuple[str, ...] = Field(min_length=1, max_length=20)

    @field_validator("catalog_id", "name")
    @classmethod
    def _catalog_text(cls, value: str) -> str:
        clean = value.strip()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError(
                "catalog identity must be nonblank and contain no controls"
            )
        return clean

    @field_validator("tools", "source_paths", mode="before")
    @classmethod
    def _tuple_fields(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("catalog_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("catalog_digest must be a lowercase SHA-256")
        return clean

    @field_validator("source_paths")
    @classmethod
    def _source_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_portable_repo_path(item) for item in value}))

    @model_validator(mode="after")
    def _catalog_is_exact(self) -> Self:
        tools = tuple(sorted(set(self.tools), key=lambda item: item.name))
        if len({item.name for item in tools}) != len(tools):
            raise ValueError("catalog Tool names must be unique")
        object.__setattr__(self, "tools", tools)
        expected_id = f"{self.name}-v{self.version}"
        if self.catalog_id != expected_id:
            raise ValueError("catalog_id must be the exact name/version composite")
        expected_digest = released_authority_digest(
            {
                "catalog_id": self.catalog_id,
                "effect": self.effect.value,
                "tools": [item.to_dict() for item in tools],
            }
        )
        if self.catalog_digest and self.catalog_digest != expected_digest:
            raise ValueError("catalog_digest does not match the exact catalog")
        object.__setattr__(self, "catalog_digest", expected_digest)
        return self


class ReleasedToolAuthority(_StrictModel):
    tool_name: str
    tool_version: int = Field(ge=1)
    provider: str = Field(min_length=1, max_length=64)
    effect: AuthorityEffect
    catalog_id: str = Field(min_length=1, max_length=200)
    credential_mechanism: CredentialMechanism
    approval_policy_class: ApprovalPolicyClass
    recovery_support: RecoverySupport
    production_recoverable: bool
    certification_state: ConnectorCertificationState
    certification_evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    production_enablement: ProductionEnablementState
    production_allowlisted: bool
    native_connector_required: bool
    exact_tool_binding_required: bool
    immutable_target_required: bool
    source_paths: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_RELEASED_TOOL_SOURCE_PATHS,
    )

    @field_validator("tool_name")
    @classmethod
    def _tool_name(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _TOOL_RE.fullmatch(clean):
            raise ValueError("Tool name is invalid")
        return clean

    @field_validator("provider")
    @classmethod
    def _provider(cls, value: str) -> str:
        clean = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", clean):
            raise ValueError("provider is invalid")
        return clean

    @field_validator("certification_evidence_refs", "source_paths", mode="before")
    @classmethod
    def _tuple_fields(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("certification_evidence_refs")
    @classmethod
    def _evidence_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({item.strip() for item in value if item.strip()}))
        if any(_CONTROL_RE.search(item) for item in normalized):
            raise ValueError("certification evidence refs contain controls")
        return normalized

    @field_validator("source_paths")
    @classmethod
    def _source_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_portable_repo_path(item) for item in value}))

    @model_validator(mode="after")
    def _status_is_fail_closed(self) -> Self:
        if self.effect == AuthorityEffect.READ:
            if self.approval_policy_class != ApprovalPolicyClass.NOT_REQUIRED:
                raise ValueError(
                    "READ Tools cannot claim a financial write approval policy"
                )
            if self.recovery_support != RecoverySupport.NOT_APPLICABLE:
                raise ValueError("READ Tools cannot claim external-effect recovery")
            if self.production_recoverable:
                raise ValueError("READ Tools cannot be marked production recoverable")
        elif self.approval_policy_class == ApprovalPolicyClass.NOT_REQUIRED:
            raise ValueError("WRITE Tools require an explicit approval policy class")

        if (
            self.production_recoverable
            and self.recovery_support != RecoverySupport.COMPLETE
        ):
            raise ValueError("production recovery requires COMPLETE recovery support")
        if (
            self.certification_state == ConnectorCertificationState.CERTIFIED
            and not self.certification_evidence_refs
        ):
            raise ValueError("CERTIFIED Tools require retained evidence")
        if self.production_enablement != ProductionEnablementState.DISABLED and (
            self.certification_state != ConnectorCertificationState.CERTIFIED
            or not self.certification_evidence_refs
        ):
            raise ValueError(
                "production-enabled Tools must be evidence-backed and certified"
            )
        return self


class ConnectorPairAuthority(_StrictModel):
    pair_id: str = Field(min_length=1, max_length=200)
    provider: str = Field(min_length=1, max_length=64)
    write_tool: str
    read_tool: str
    certification_state: ConnectorCertificationState
    certification_evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    production_enablement: ProductionEnablementState

    @field_validator("pair_id", "provider")
    @classmethod
    def _identity(cls, value: str) -> str:
        clean = value.strip().lower()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError("connector-pair identity is invalid")
        return clean

    @field_validator("write_tool", "read_tool")
    @classmethod
    def _tool_name(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _TOOL_RE.fullmatch(clean):
            raise ValueError("connector-pair Tool name is invalid")
        return clean

    @field_validator("certification_evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @model_validator(mode="after")
    def _certification_is_evidence_backed(self) -> Self:
        evidence = tuple(
            sorted(
                {
                    item.strip()
                    for item in self.certification_evidence_refs
                    if item.strip()
                }
            )
        )
        object.__setattr__(self, "certification_evidence_refs", evidence)
        if (
            self.certification_state == ConnectorCertificationState.CERTIFIED
            and not evidence
        ):
            raise ValueError("CERTIFIED connector pairs require retained evidence")
        if self.production_enablement != ProductionEnablementState.DISABLED and (
            self.certification_state != ConnectorCertificationState.CERTIFIED
            or not evidence
        ):
            raise ValueError("production-enabled connector pairs must be certified")
        return self


class RequiredMigrationAuthority(_StrictModel):
    version: str
    path: str
    sha256: str

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        clean = value.strip().upper()
        if not _MIGRATION_RE.fullmatch(clean):
            raise ValueError("migration version is invalid")
        return clean

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _portable_repo_path(value)

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("migration digest must be a lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _path_matches_version(self) -> Self:
        if not Path(self.path).name.startswith(f"{self.version}__"):
            raise ValueError("migration path does not match its version")
        return self


class AuthorityDocumentationContract(_StrictModel):
    generated_path: str
    claim_scan_globs: tuple[str, ...] = Field(min_length=1, max_length=20)
    claim_language_version: Literal["lightbulb.authority_claims.v1"] = (
        "lightbulb.authority_claims.v1"
    )

    @field_validator("generated_path")
    @classmethod
    def _generated_path(cls, value: str) -> str:
        return _portable_repo_path(value)

    @field_validator("claim_scan_globs", mode="before")
    @classmethod
    def _glob_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("claim_scan_globs")
    @classmethod
    def _globs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        allowed_exact = {"lightbulb-sdk/README.md"}
        if any(
            (not item.startswith("docs/") and item not in allowed_exact)
            or item.startswith("/")
            or ".." in item.split("/")
            or _CONTROL_RE.search(item)
            for item in normalized
        ):
            raise ValueError(
                "documentation claim globs must stay under docs/ or equal the SDK README"
            )
        return normalized


class FinancialApprovalLifecycleAuthority(_StrictModel):
    service_source_path: str
    worker_source_path: str
    scheduler_source_path: str
    scheduler_enabled_by_default: Literal[False]
    operator_rollout_state: Literal["DARK_DISABLED"]

    @field_validator(
        "service_source_path",
        "worker_source_path",
        "scheduler_source_path",
    )
    @classmethod
    def _source_path(cls, value: str) -> str:
        return _portable_repo_path(value)


class ReleasedFinancialApprovalAuthority(_StrictModel):
    approval_policy_class: ApprovalPolicyClass
    controlled_write_tools: tuple[str, ...] = Field(min_length=12, max_length=12)
    operational_classifier_tools: tuple[str, ...] = Field(min_length=9, max_length=9)
    unavailable_provider_fact_tools: tuple[str, ...] = Field(min_length=3, max_length=3)
    classifier_source_path: str
    provider_dispatch_surface: Literal["GOVERNED_WORKER_ONLY"]
    public_direct_finance_surface: Literal["UNSHIPPED"]
    direct_provider_mcp_runtime_state: Literal[
        "DISABLED_SUPPRESSED_UNTIL_CANONICAL_GCE"
    ]
    dark_posture_source_paths: tuple[str, ...] = Field(min_length=22, max_length=22)
    emergency_authority_state: Literal["DARK_DISABLED"]
    lifecycle: FinancialApprovalLifecycleAuthority

    @field_validator(
        "controlled_write_tools",
        "operational_classifier_tools",
        "unavailable_provider_fact_tools",
        mode="before",
    )
    @classmethod
    def _tool_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("dark_posture_source_paths", mode="before")
    @classmethod
    def _source_path_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator(
        "controlled_write_tools",
        "operational_classifier_tools",
        "unavailable_provider_fact_tools",
    )
    @classmethod
    def _tool_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({str(item).strip().lower() for item in value}))
        if len(normalized) != len(value) or any(
            not _TOOL_RE.fullmatch(item) for item in normalized
        ):
            raise ValueError("financial approval Tool names must be unique and valid")
        return normalized

    @field_validator("classifier_source_path")
    @classmethod
    def _classifier_source_path(cls, value: str) -> str:
        return _portable_repo_path(value)

    @field_validator("dark_posture_source_paths")
    @classmethod
    def _dark_posture_source_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({_portable_repo_path(item) for item in value}))
        if len(normalized) != len(value):
            raise ValueError("financial dark-posture source paths must be unique")
        return normalized

    @model_validator(mode="after")
    def _classifier_lanes_are_exact(self) -> Self:
        if (
            self.approval_policy_class
            != ApprovalPolicyClass.SPRING_INDEPENDENT_FINANCIAL_REVIEW_V1
        ):
            raise ValueError(
                "controlled finance writes require independent financial review"
            )
        controlled = set(self.controlled_write_tools)
        operational = set(self.operational_classifier_tools)
        unavailable = set(self.unavailable_provider_fact_tools)
        if operational & unavailable or operational | unavailable != controlled:
            raise ValueError(
                "operational and unavailable classifier lanes must partition "
                "controlled finance writes"
            )
        expected_unavailable = {
            "square.create_invoice",
            "stripe.create_invoice",
            "stripe.create_refund",
        }
        if unavailable != expected_unavailable:
            raise ValueError(
                "unavailable provider-fact lanes must match the reviewed Slice 4 set"
            )
        expected_dark_sources = {
            "springboot-server/src/main/java/com/project401/controller/"
            "InternalConnectorController.java",
            "springboot-server/src/main/java/com/project401/service/finance/xero/"
            "XeroWriteProposalService.java",
            "springboot-server/src/main/java/com/project401/repository/finance/xero/"
            "XeroCustomConnectionRepository.java",
            "springboot-server/src/main/java/com/project401/service/oauth/"
            "OAuthTenantConnectorProvisioningService.java",
            "springboot-server/src/main/java/com/project401/service/oauth/"
            "XeroCustomConnectionService.java",
            "springboot-server/src/main/java/com/project401/service/stripe/orchestrator/"
            "handlers/StripeApiRequestHandler.java",
            "springboot-server/src/main/java/com/project401/service/stripe/orchestrator/"
            "mcp/StripeMcpBridge.java",
            "springboot-server/src/main/java/com/project401/service/tools/"
            "GovernedConnectorExecutionAuthority.java",
            "springboot-server/src/main/java/com/project401/service/tools/"
            "McpServerConfigResolverService.java",
            "springboot-server/src/main/java/com/project401/service/tools/"
            "McpConnectivityProbeService.java",
            "springboot-server/src/main/java/com/project401/service/tools/connectors/"
            "adapters/StripeAdapter.java",
            "springboot-server/src/main/resources/db/migration/"
            "V1862__govern_independent_financial_approval.sql",
            "agent-workers/mcp_runtime_security.py",
            "agent-workers/agents/claude_code_sdk_runtime.py",
            "agent-workers/agents/codex_code_workspace_runtime.py",
            "agent-workers/backbone/sdk_runtime.py",
            "springboot-server/src/main/java/com/project401/service/ai/"
            "AiAgentRuntimeConfigService.java",
            "springboot-server/src/main/java/com/project401/controller/"
            "ChatGptMcpController.java",
            "springboot-server/src/main/java/com/project401/controller/"
            "InternalAiController.java",
            "lightbulb-sdk/lightbulb/mcp_server.py",
            "agent-workers/requirements.txt",
            "agent-workers/requirements-local-runtime.txt",
        }
        if set(self.dark_posture_source_paths) != expected_dark_sources:
            raise ValueError(
                "financial dark-posture sources must match the reviewed Slice 4 fences"
            )
        return self


class WorkflowPublicationAuthority(_StrictModel):
    completion_state: Literal["COMPLETE_SLICE5"]
    transactional_publication_kinds: tuple[
        Literal[
            "DIRECT_STEP_REQUEST",
            "HITL_DECISION",
            "HITL_REQUEST",
            "STEP_REQUEST",
            "WORKFLOW_DLQ",
            "WORKFLOW_EVENT",
            "WORKFLOW_REQUEST",
        ],
        ...,
    ] = Field(min_length=7, max_length=7)
    payload_protection: Literal["DEDICATED_AES256_GCM_REQUIRED"]
    production_relay_enabled: Literal[True]
    remaining_blockers: tuple[str, ...] = Field(min_length=0, max_length=0)
    configuration_source_paths: tuple[str, ...] = Field(min_length=23, max_length=23)
    persistence_source_paths: tuple[str, ...] = Field(min_length=19, max_length=19)
    spring_authority_source_paths: tuple[str, ...] = Field(min_length=28, max_length=28)
    worker_enforcement_source_paths: tuple[str, ...] = Field(min_length=4, max_length=4)
    operations_source_paths: tuple[str, ...] = Field(min_length=10, max_length=10)
    documentation_source_paths: tuple[str, ...] = Field(min_length=2, max_length=2)
    test_source_paths: tuple[str, ...] = Field(min_length=34, max_length=34)

    @field_validator(
        "transactional_publication_kinds",
        "remaining_blockers",
        "configuration_source_paths",
        "persistence_source_paths",
        "spring_authority_source_paths",
        "worker_enforcement_source_paths",
        "operations_source_paths",
        "documentation_source_paths",
        "test_source_paths",
        mode="before",
    )
    @classmethod
    def _tuple_fields(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator(
        "configuration_source_paths",
        "persistence_source_paths",
        "spring_authority_source_paths",
        "worker_enforcement_source_paths",
        "operations_source_paths",
        "documentation_source_paths",
        "test_source_paths",
    )
    @classmethod
    def _source_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({_portable_repo_path(item) for item in value}))
        if len(normalized) != len(value):
            raise ValueError("workflow publication source paths must be unique")
        return normalized

    @model_validator(mode="after")
    def _complete_slice_is_exact(self) -> Self:
        expected_kinds = (
            "DIRECT_STEP_REQUEST",
            "HITL_DECISION",
            "HITL_REQUEST",
            "STEP_REQUEST",
            "WORKFLOW_DLQ",
            "WORKFLOW_EVENT",
            "WORKFLOW_REQUEST",
        )
        expected_blockers: tuple[str, ...] = ()
        kinds = tuple(sorted(set(self.transactional_publication_kinds)))
        blockers = tuple(sorted(set(self.remaining_blockers)))
        if kinds != expected_kinds:
            raise ValueError(
                "workflow publication kinds must equal the reviewed complete Slice 5 set"
            )
        if blockers != expected_blockers:
            raise ValueError(
                "complete Slice 5 workflow publication authority cannot retain blockers"
            )
        source_groups = (
            self.configuration_source_paths,
            self.persistence_source_paths,
            self.spring_authority_source_paths,
            self.worker_enforcement_source_paths,
            self.operations_source_paths,
            self.documentation_source_paths,
            self.test_source_paths,
        )
        flattened = [path for group in source_groups for path in group]
        if len(set(flattened)) != len(flattened):
            raise ValueError("workflow publication source categories must not overlap")
        object.__setattr__(self, "transactional_publication_kinds", kinds)
        object.__setattr__(self, "remaining_blockers", blockers)
        return self


class ReleasedAuthorityLookupError(LookupError):
    """Raised when a caller requests authority absent from the released contract."""


class ReleasedAuthorityManifest(_StrictModel):
    schema_name: Literal[
        "lightbulb.released_authority_manifest.v1",
        "lightbulb.released_authority_manifest.v2",
    ] = Field(
        default=RELEASED_AUTHORITY_SCHEMA,
        alias="schema",
    )
    version: Literal["1.0.0", "2.0.0"] = RELEASED_AUTHORITY_VERSION
    release_posture: Literal["DARK_BASELINE"] = "DARK_BASELINE"
    production_enablement: ProductionEnablementState
    production_flyway_baseline: str
    endpoints: tuple[GovernedEndpointAuthority, ...]
    feature_gates: tuple[FeatureGateAuthority, ...] = Field(min_length=1)
    catalogs: tuple[ReviewedCatalogAuthority, ...]
    tools: tuple[ReleasedToolAuthority, ...]
    financial_approval: ReleasedFinancialApprovalAuthority
    # The v1 contract predates workflow-publication authority. Absence therefore
    # means no such authority and is valid only for the exact v1@1.0.0 pair.
    workflow_publication: WorkflowPublicationAuthority | None = None
    connector_pairs: tuple[ConnectorPairAuthority, ...]
    required_migrations: tuple[RequiredMigrationAuthority, ...]
    documentation: AuthorityDocumentationContract
    source_file_digests: dict[str, str] = Field(min_length=1)
    manifest_digest: str = ""

    @field_validator(
        "endpoints",
        "feature_gates",
        "catalogs",
        "tools",
        "connector_pairs",
        "required_migrations",
        mode="before",
    )
    @classmethod
    def _tuple_fields(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("production_flyway_baseline")
    @classmethod
    def _baseline(cls, value: str) -> str:
        clean = value.strip().upper()
        if not _MIGRATION_RE.fullmatch(clean):
            raise ValueError("production Flyway baseline is invalid")
        return clean

    @field_validator("source_file_digests")
    @classmethod
    def _source_digests(cls, value: Mapping[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for raw_path, raw_digest in value.items():
            path = _portable_repo_path(str(raw_path))
            digest = str(raw_digest).strip().lower()
            if not _SHA256_RE.fullmatch(digest):
                raise ValueError("source file digests must be lowercase SHA-256")
            normalized[path] = digest
        return dict(sorted(normalized.items()))

    @field_validator("manifest_digest")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("manifest_digest must be a lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _manifest_is_closed_and_reproducible(self) -> Self:
        contract_pair = (self.schema_name, self.version)
        legacy_pair = (
            LEGACY_RELEASED_AUTHORITY_SCHEMA,
            LEGACY_RELEASED_AUTHORITY_VERSION,
        )
        current_pair = (RELEASED_AUTHORITY_SCHEMA, RELEASED_AUTHORITY_VERSION)
        if contract_pair == legacy_pair:
            if self.workflow_publication is not None:
                raise ValueError(
                    "released-authority v1 must not claim workflow publication authority"
                )
        elif contract_pair == current_pair:
            if self.workflow_publication is None:
                raise ValueError(
                    "released-authority v2 requires workflow publication authority"
                )
        else:
            raise ValueError(
                "released-authority schema and version must form an exact supported pair"
            )

        if (
            self.release_posture == "DARK_BASELINE"
            and self.production_enablement != ProductionEnablementState.DISABLED
        ):
            raise ValueError("DARK_BASELINE requires production enablement DISABLED")

        endpoints = tuple(sorted(self.endpoints, key=lambda item: item.endpoint_id))
        gates = tuple(sorted(self.feature_gates, key=lambda item: item.name))
        catalogs = tuple(sorted(self.catalogs, key=lambda item: item.catalog_id))
        tools = tuple(sorted(self.tools, key=lambda item: item.tool_name))
        pairs = tuple(sorted(self.connector_pairs, key=lambda item: item.pair_id))
        migrations = tuple(
            sorted(
                self.required_migrations,
                key=lambda item: int(item.version.removeprefix("V")),
            )
        )
        for field_name, values, key in (
            ("endpoint", endpoints, lambda item: item.endpoint_id),
            ("feature gate", gates, lambda item: item.name),
            ("catalog", catalogs, lambda item: item.catalog_id),
            ("Tool", tools, lambda item: item.tool_name),
            ("connector pair", pairs, lambda item: item.pair_id),
            ("migration", migrations, lambda item: item.version),
        ):
            identities = [key(item) for item in values]
            if len(set(identities)) != len(identities):
                raise ValueError(f"{field_name} identities must be unique")

        object.__setattr__(self, "endpoints", endpoints)
        object.__setattr__(self, "feature_gates", gates)
        object.__setattr__(self, "catalogs", catalogs)
        object.__setattr__(self, "tools", tools)
        object.__setattr__(self, "connector_pairs", pairs)
        object.__setattr__(self, "required_migrations", migrations)

        gate_names = {item.name for item in gates}
        for endpoint in endpoints:
            unknown = set(endpoint.required_feature_gates) - gate_names
            if unknown:
                raise ValueError(
                    f"endpoint references unknown feature gates: {sorted(unknown)}"
                )

        catalog_by_id = {item.catalog_id: item for item in catalogs}
        catalog_tools: dict[str, tuple[str, int, AuthorityEffect]] = {}
        for catalog in catalogs:
            for tool in catalog.tools:
                if tool.name in catalog_tools:
                    raise ValueError("a Tool may belong to only one released catalog")
                catalog_tools[tool.name] = (tool.name, tool.version, catalog.effect)
        if set(catalog_tools) != {item.tool_name for item in tools}:
            raise ValueError(
                "released Tool entries must exactly equal the catalog Tool union"
            )
        for tool in tools:
            catalog = catalog_by_id.get(tool.catalog_id)
            catalog_entry = catalog_tools.get(tool.tool_name)
            if catalog is None or catalog_entry is None:
                raise ValueError("released Tool references an unknown catalog")
            if (
                catalog_entry[1] != tool.tool_version
                or catalog_entry[2] != tool.effect
                or catalog.catalog_id != tool.catalog_id
            ):
                raise ValueError(
                    "released Tool identity/effect does not match its catalog"
                )

        tool_by_name = {item.tool_name: item for item in tools}
        write_tools = tuple(
            sorted(
                item.tool_name for item in tools if item.effect == AuthorityEffect.WRITE
            )
        )
        if self.financial_approval.controlled_write_tools != write_tools:
            raise ValueError(
                "financial approval controlled Tools must equal released WRITE Tools"
            )
        if any(
            item.approval_policy_class != self.financial_approval.approval_policy_class
            for item in tools
            if item.effect == AuthorityEffect.WRITE
        ):
            raise ValueError(
                "released finance WRITE Tools must use the declared approval policy"
            )
        for pair in pairs:
            write = tool_by_name.get(pair.write_tool)
            read = tool_by_name.get(pair.read_tool)
            if (
                write is None
                or read is None
                or write.effect != AuthorityEffect.WRITE
                or read.effect != AuthorityEffect.READ
                or write.provider != pair.provider
                or read.provider != pair.provider
            ):
                raise ValueError(
                    "connector pair does not bind one exact provider WRITE/READ pair"
                )

        workflow_publication_sources: set[str] = set()
        if self.workflow_publication is not None:
            workflow_publication_sources = {
                path
                for group in (
                    self.workflow_publication.configuration_source_paths,
                    self.workflow_publication.persistence_source_paths,
                    self.workflow_publication.spring_authority_source_paths,
                    self.workflow_publication.worker_enforcement_source_paths,
                    self.workflow_publication.operations_source_paths,
                    self.workflow_publication.documentation_source_paths,
                    self.workflow_publication.test_source_paths,
                )
                for path in group
            }

        referenced_sources = (
            {endpoint.source_path for endpoint in endpoints}
            | {path for gate in gates for path in gate.source_paths}
            | {path for catalog in catalogs for path in catalog.source_paths}
            | {path for tool in tools for path in tool.source_paths}
            | {
                self.financial_approval.classifier_source_path,
                self.financial_approval.lifecycle.service_source_path,
                self.financial_approval.lifecycle.worker_source_path,
                self.financial_approval.lifecycle.scheduler_source_path,
            }
            | set(self.financial_approval.dark_posture_source_paths)
            | workflow_publication_sources
        )
        missing_sources = referenced_sources - set(self.source_file_digests)
        if missing_sources:
            raise ValueError(
                f"authority claims have unpinned sources: {sorted(missing_sources)}"
            )
        for migration in migrations:
            if self.source_file_digests.get(migration.path) != migration.sha256:
                raise ValueError(
                    "required migration digest is not pinned as a source digest"
                )

        if self.production_enablement == ProductionEnablementState.DISABLED:
            if any(
                item.production_enablement != ProductionEnablementState.DISABLED
                for item in (*tools, *pairs)
            ):
                raise ValueError(
                    "a dark manifest cannot contain production-enabled Tools"
                )

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"manifest_digest"},
            exclude_none=True,
        )
        expected_digest = released_authority_digest(payload)
        if self.manifest_digest and self.manifest_digest != expected_digest:
            raise ValueError(
                "manifest_digest does not match the released authority manifest"
            )
        object.__setattr__(self, "manifest_digest", expected_digest)
        return self

    def require_tool(self, tool_name: str) -> ReleasedToolAuthority:
        normalized = str(tool_name).strip().lower()
        for tool in self.tools:
            if tool.tool_name == normalized:
                return tool
        raise ReleasedAuthorityLookupError(f"unknown released Tool: {tool_name}")

    def require_catalog(self, catalog_id: str) -> ReviewedCatalogAuthority:
        normalized = str(catalog_id).strip()
        for catalog in self.catalogs:
            if catalog.catalog_id == normalized:
                return catalog
        raise ReleasedAuthorityLookupError(f"unknown released catalog: {catalog_id}")

    def require_feature_gate(self, name: str) -> FeatureGateAuthority:
        normalized = str(name).strip()
        for gate in self.feature_gates:
            if gate.name == normalized:
                return gate
        raise ReleasedAuthorityLookupError(f"unknown released feature gate: {name}")


class ReleasedAuthorityManifestV2(ReleasedAuthorityManifest):
    """Exact current v2 contract used to generate the public JSON Schema."""

    schema_name: Literal["lightbulb.released_authority_manifest.v2"] = Field(
        default=RELEASED_AUTHORITY_SCHEMA,
        alias="schema",
    )
    version: Literal["2.0.0"] = RELEASED_AUTHORITY_VERSION
    workflow_publication: WorkflowPublicationAuthority


def load_released_authority_manifest(path: str | Path) -> ReleasedAuthorityManifest:
    """Load and semantically verify one checked-in released-authority artifact."""

    return ReleasedAuthorityManifest.model_validate_json(
        Path(path).read_text(encoding="utf-8")
    )


__all__ = [
    "MAX_RELEASED_TOOL_SOURCE_PATHS",
    "LEGACY_RELEASED_AUTHORITY_SCHEMA",
    "LEGACY_RELEASED_AUTHORITY_VERSION",
    "RELEASED_AUTHORITY_SCHEMA",
    "RELEASED_AUTHORITY_VERSION",
    "ApprovalPolicyClass",
    "AuthorityDocumentationContract",
    "AuthorityEffect",
    "CatalogToolAuthority",
    "ConnectorCertificationState",
    "ConnectorPairAuthority",
    "CredentialMechanism",
    "EndpointAuthorityClass",
    "EndpointAvailability",
    "FeatureGateAuthority",
    "FinancialApprovalLifecycleAuthority",
    "GovernedEndpointAuthority",
    "ProductionEnablementState",
    "RecoverySupport",
    "ReleasedAuthorityLookupError",
    "ReleasedAuthorityManifest",
    "ReleasedAuthorityManifestV2",
    "ReleasedFinancialApprovalAuthority",
    "ReleasedToolAuthority",
    "RequiredMigrationAuthority",
    "ReviewedCatalogAuthority",
    "WorkflowPublicationAuthority",
    "load_released_authority_manifest",
    "released_authority_digest",
]
