"""Versioned Company Blueprint contracts and deterministic validation.

The SDK owns this declarative language.  It intentionally contains no tenant
credentials, live connector account IDs, runtime sessions, RBAC grants, or
deployment authority.  Spring must persist immutable versions, resolve exact
scope and secrets, authorize deployment, and compile validated bindings into
the existing AutoCompany and Dynamic Workflow runtimes.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Literal

from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.project_creation import PROJECT_CODING_HARNESS_IDS
from lightbulb.golden_loops import (
    CapabilityLifecycleState,
    GoldenLoopCatalog,
    LoopOutcomeCertificationMeasurement,
    OpaqueRef,
    PortableRef,
)
from lightbulb.golden_loop_workflow_registry import (
    GoldenLoopWorkflowBindingError,
    GoldenLoopWorkflowRegistry,
)
from lightbulb.primitive_runtime import (
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveRegistry,
)


COMPANY_BLUEPRINT_SCHEMA = "lightbulb.company_blueprint.v1"
COMPANY_BLUEPRINT_VALIDATION_SCHEMA = "lightbulb.company_blueprint_validation.v1"
COMPANY_BLUEPRINT_CERTIFICATION_RECORD_SCHEMA = (
    "lightbulb.company_blueprint_certification_record.v1"
)
COMPANY_PROJECT_SPEC_SCHEMA = "lightbulb.company_project_spec.v1"
ECONOMIC_SPINE_CONTRACT_SCHEMA = "lightbulb.economic_spine_contract.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _unique(values: tuple[Any, ...], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _timestamp(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _enum_value(value: Any, enum_type: type[Enum]) -> Any:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            return value
    return value


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


class BlueprintValidationSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class EconomicSpineStage(str, Enum):
    ACQUIRE_DEMAND = "acquire_demand"
    AGREE_WORK = "agree_work"
    DELIVER_VALUE = "deliver_value"
    ACCEPT_VALUE = "accept_value"
    INVOICE_CUSTOMER = "invoice_customer"
    COLLECT_CASH = "collect_cash"
    SUPPORT_CUSTOMER = "support_customer"
    CONTROL_SPEND = "control_spend"
    RECONCILE_BOOKS = "reconcile_books"
    IMPROVE_FROM_EVIDENCE = "improve_from_evidence"


class EconomicSpineStageBinding(_StrictModel):
    stage: EconomicSpineStage
    objective_ref: PortableRef
    loop_refs: tuple[PortableRef, ...] = Field(default_factory=tuple, max_length=100)
    required_artifact_refs: tuple[PortableRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    terminal_outcome_ref: PortableRef
    required_evidence_kind: PortableRef
    lifecycle: CapabilityLifecycleState
    known_blockers: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    stage_binding_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("stage", mode="before")
    @classmethod
    def _stage_enum(cls, value: Any) -> Any:
        return _enum_value(value, EconomicSpineStage)

    @field_validator("lifecycle", mode="before")
    @classmethod
    def _lifecycle_enum(cls, value: Any) -> Any:
        return _enum_value(value, CapabilityLifecycleState)

    @field_validator(
        "loop_refs",
        "required_artifact_refs",
        "known_blockers",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("stage_binding_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("stage_binding_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _stage_is_closed_and_honest(self) -> Self:
        _unique(self.loop_refs, label="economic-spine stage loops")
        _unique(
            self.required_artifact_refs,
            label="economic-spine required artifacts",
        )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"lifecycle", "known_blockers", "stage_binding_digest"},
        )
        expected_digest = _stable_digest(payload)
        if self.stage_binding_digest and self.stage_binding_digest != expected_digest:
            raise ValueError(
                "stage_binding_digest must match the exact economic-spine binding"
            )
        object.__setattr__(self, "stage_binding_digest", expected_digest)
        if self.lifecycle == CapabilityLifecycleState.CERTIFIED:
            if not self.loop_refs:
                raise ValueError("CERTIFIED economic-spine stages require a Golden Loop")
            if self.known_blockers:
                raise ValueError("CERTIFIED economic-spine stages cannot retain blockers")
        elif self.lifecycle in {
            CapabilityLifecycleState.PREVIEW,
            CapabilityLifecycleState.QUARANTINED,
        } and not self.known_blockers:
            raise ValueError(
                "PREVIEW and QUARANTINED economic-spine stages must disclose blockers"
            )
        return self


class EconomicSpineContract(_StrictModel):
    schema_id: Literal["lightbulb.economic_spine_contract.v1"] = Field(
        default=ECONOMIC_SPINE_CONTRACT_SCHEMA,
        alias="schema",
    )
    version: str = Field(min_length=5, max_length=80)
    stages: tuple[EconomicSpineStageBinding, ...] = Field(
        min_length=10,
        max_length=10,
    )
    contract_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("economic-spine version must use semantic versioning")
        return value

    @field_validator("stages", mode="before")
    @classmethod
    def _tuple_stages(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("contract_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("economic-spine contract_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _spine_is_complete_and_content_addressed(self) -> Self:
        stages = tuple(item.stage for item in self.stages)
        if stages != tuple(EconomicSpineStage):
            raise ValueError(
                "economic spine must declare all ten stages in canonical order"
            )
        expected_digest = _stable_digest(
            {
                "schema": ECONOMIC_SPINE_CONTRACT_SCHEMA,
                "version": self.version,
                "stage_binding_digests": [
                    item.stage_binding_digest for item in self.stages
                ],
            }
        )
        if self.contract_digest and self.contract_digest != expected_digest:
            raise ValueError("economic-spine contract_digest does not match")
        object.__setattr__(self, "contract_digest", expected_digest)
        return self


class CompanyObjective(_StrictModel):
    objective_ref: PortableRef
    description: str = Field(min_length=1, max_length=2_000)
    metric_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("metric_refs", mode="before")
    @classmethod
    def _tuple_metrics(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _metrics_are_unique(self) -> Self:
        _unique(self.metric_refs, label="objective metrics")
        return self


class AgentRoleBinding(_StrictModel):
    role_ref: PortableRef
    title: str = Field(min_length=1, max_length=300)
    responsibilities: tuple[str, ...] = Field(min_length=1, max_length=100)
    allowed_primitive_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    allowed_tool_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    may_self_approve: Literal[False] = False

    @field_validator(
        "responsibilities",
        "allowed_primitive_refs",
        "allowed_tool_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _permissions_are_unique(self) -> Self:
        _unique(self.responsibilities, label="agent responsibilities")
        _unique(self.allowed_primitive_refs, label="agent primitive permissions")
        _unique(self.allowed_tool_refs, label="agent Tool permissions")
        return self


class GoldenLoopBinding(_StrictModel):
    loop_ref: PortableRef
    version: str = Field(min_length=5, max_length=80)
    declaration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    declared_lifecycle: CapabilityLifecycleState
    department_ref: PortableRef
    required: Literal[True] = True

    @field_validator("declared_lifecycle", mode="before")
    @classmethod
    def _lifecycle_enum(cls, value: Any) -> Any:
        return _enum_value(value, CapabilityLifecycleState)

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("Golden Loop version must use semantic versioning")
        return value

    @field_validator("declaration_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("loop declaration digest must be lowercase SHA-256")
        return clean


class DepartmentBinding(_StrictModel):
    department_ref: PortableRef
    title: str = Field(min_length=1, max_length=300)
    objective_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    agent_role_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    loop_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("objective_refs", "agent_role_refs", "loop_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bindings_are_unique(self) -> Self:
        _unique(self.objective_refs, label="department objectives")
        _unique(self.agent_role_refs, label="department agent roles")
        _unique(self.loop_refs, label="department loops")
        return self


class ConnectorRequirement(_StrictModel):
    requirement_ref: PortableRef
    provider: PortableRef
    required_tool_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=1_000)
    required_at_deployment: bool = True
    production_conformance_required: Literal[True] = True

    @field_validator("required_tool_refs", mode="before")
    @classmethod
    def _tuple_tools(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _tools_are_exact_and_unique(self) -> Self:
        _unique(self.required_tool_refs, label="connector requirement Tools")
        if any(tool.split(".", 1)[0] != self.provider for tool in self.required_tool_refs):
            raise ValueError("connector requirement Tools must match the provider")
        return self


class SecretRequirement(_StrictModel):
    secret_ref: PortableRef
    connector_requirement_ref: PortableRef
    custody_owner: Literal["spring_control_plane"] = "spring_control_plane"
    purpose: str = Field(min_length=1, max_length=500)
    rotation_max_age_days: int = Field(ge=1, le=3_650)
    secret_value_embedded: Literal[False] = False


class CompanyProjectSpecification(_StrictModel):
    """Content-addressed capability and authority boundary for one Company Project."""

    schema_id: Literal["lightbulb.company_project_spec.v1"] = Field(
        default=COMPANY_PROJECT_SPEC_SCHEMA,
        alias="schema",
    )
    project_ref: PortableRef
    version: str = Field(min_length=5, max_length=80)
    title: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=1, max_length=2_000)
    department_ref: PortableRef
    objective_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    agent_role_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=500)
    workflow_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=1_000)
    loop_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    allowed_primitive_refs: tuple[PortableRef, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    allowed_tool_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=50_000,
    )
    secret_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    approval_policy_refs: tuple[PortableRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    allowed_harnesses: tuple[str, ...] = Field(min_length=1, max_length=20)
    user_selects_harness: Literal[True] = True
    spec_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("Company Project version must use semantic versioning")
        return value

    @field_validator(
        "objective_refs",
        "agent_role_refs",
        "workflow_refs",
        "loop_refs",
        "allowed_primitive_refs",
        "allowed_tool_refs",
        "secret_refs",
        "approval_policy_refs",
        "allowed_harnesses",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("spec_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("spec_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _spec_is_closed_and_content_addressed(self) -> Self:
        keyed_refs = (
            ("Company Project objectives", self.objective_refs),
            ("Company Project agent roles", self.agent_role_refs),
            ("Company Project workflows", self.workflow_refs),
            ("Company Project Golden Loops", self.loop_refs),
            ("Company Project allowed primitives", self.allowed_primitive_refs),
            ("Company Project allowed Tools", self.allowed_tool_refs),
            ("Company Project secrets", self.secret_refs),
            ("Company Project approval policies", self.approval_policy_refs),
            ("Company Project harnesses", self.allowed_harnesses),
        )
        for label, refs in keyed_refs:
            _unique(refs, label=label)
        if any(
            harness not in PROJECT_CODING_HARNESS_IDS
            for harness in self.allowed_harnesses
        ):
            raise ValueError(
                "Company Project harnesses must be codex, claude_code, or cursor; "
                "access-surface host ids are not coding harnesses"
            )

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"spec_digest"},
        )
        expected_digest = _stable_digest(payload)
        if self.spec_digest and self.spec_digest != expected_digest:
            raise ValueError("spec_digest does not match the exact Company Project specification")
        object.__setattr__(self, "spec_digest", expected_digest)
        return self


class ProjectBinding(_StrictModel):
    project_ref: PortableRef
    project_version: str = Field(min_length=5, max_length=80)
    project_spec_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=1_000)
    loop_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    project_spec: CompanyProjectSpecification | None = None

    @field_validator("project_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("project_version must use semantic versioning")
        return value

    @field_validator("project_spec_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("project_spec_digest must be lowercase SHA-256")
        return clean

    @field_validator("workflow_refs", "loop_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _project_bindings_are_unique(self) -> Self:
        _unique(self.workflow_refs, label="project workflows")
        _unique(self.loop_refs, label="project loops")
        if self.project_spec is not None:
            spec = self.project_spec
            if self.project_ref != spec.project_ref:
                raise ValueError("project binding and specification refs must match")
            if self.project_version != spec.version:
                raise ValueError("project binding and specification versions must match")
            if self.project_spec_digest != spec.spec_digest:
                raise ValueError(
                    "project_spec_digest must attest the exact Company Project specification"
                )
            if self.workflow_refs != spec.workflow_refs:
                raise ValueError("project binding and specification workflows must match")
            if self.loop_refs != spec.loop_refs:
                raise ValueError("project binding and specification Golden Loops must match")
        return self


class ScheduleBinding(_StrictModel):
    schedule_ref: PortableRef
    loop_ref: PortableRef
    trigger_ref: PortableRef
    schedule_expression: str = Field(min_length=1, max_length=200)
    timezone: str = Field(min_length=1, max_length=100)
    enabled_by_default: bool = False


class KnowledgeEvidencePolicy(_StrictModel):
    context_space_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade
    required_retention_policy_ref: PortableRef
    cross_company_retrieval_allowed: Literal[False] = False
    successful_outcomes_require_evidence: Literal[True] = True
    learning_requires_verified_outcome: Literal[True] = True

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _evidence_grade_enum(cls, value: Any) -> Any:
        return _enum_value(value, PrimitiveEvidenceVerificationGrade)

    @field_validator("context_space_refs", mode="before")
    @classmethod
    def _tuple_spaces(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _spaces_are_unique(self) -> Self:
        _unique(self.context_space_refs, label="Context Spaces")
        return self


class HumanAuthorityPolicy(_StrictModel):
    approval_policy_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=100)
    consequential_effects_require_spring_approval: Literal[True] = True
    agents_may_self_approve: Literal[False] = False
    harnesses_may_self_approve: Literal[False] = False
    harnesses_may_merge: Literal[False] = False
    harnesses_may_deploy: Literal[False] = False
    project_completion_requires_human_or_independent_authority: Literal[True] = True

    @field_validator("approval_policy_refs", mode="before")
    @classmethod
    def _tuple_policies(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _policies_are_unique(self) -> Self:
        _unique(self.approval_policy_refs, label="approval policies")
        return self


class BudgetCapacityPolicy(_StrictModel):
    monthly_budget_microusd: int = Field(ge=0, le=10_000_000_000_000_000)
    max_loop_cost_microusd: int = Field(ge=0, le=10_000_000_000_000)
    max_concurrent_company_runs: int = Field(ge=1, le=100_000)
    max_concurrent_background_runs: int = Field(ge=0, le=100_000)
    interactive_capacity_reserve: int = Field(ge=1, le=100_000)

    @model_validator(mode="after")
    def _capacity_reserve_is_real(self) -> Self:
        if self.max_concurrent_background_runs + self.interactive_capacity_reserve > self.max_concurrent_company_runs:
            raise ValueError(
                "background capacity plus interactive reserve cannot exceed the company cap"
            )
        return self


class ExecutionHostPolicy(_StrictModel):
    contract_ref: Literal["lightbulb.dynamic_workflow_control.v1"] = (
        "lightbulb.dynamic_workflow_control.v1"
    )
    allowed_harnesses: tuple[str, ...] = Field(min_length=1, max_length=20)
    preferred_harnesses: tuple[str, ...] = Field(min_length=1, max_length=20)
    user_selects_harness: Literal[True] = True
    access_surface_independent: Literal[True] = True
    live_session_ids_in_blueprint: Literal[False] = False
    spring_resolves_runtime_binding: Literal[True] = True

    @field_validator("allowed_harnesses", "preferred_harnesses", mode="before")
    @classmethod
    def _tuple_harnesses(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _harness_policy_is_closed(self) -> Self:
        _unique(self.allowed_harnesses, label="allowed harnesses")
        _unique(self.preferred_harnesses, label="preferred harnesses")
        if not set(self.preferred_harnesses).issubset(self.allowed_harnesses):
            raise ValueError("preferred harnesses must be allowed")
        if any(item not in PROJECT_CODING_HARNESS_IDS for item in self.allowed_harnesses):
            raise ValueError(
                "allowed harnesses must be codex, claude_code, or cursor; "
                "access-surface host ids are not coding harnesses"
            )
        return self


class CompanyOutcomeMetricBinding(_StrictModel):
    metric_ref: PortableRef
    loop_refs: tuple[PortableRef, ...] = Field(default_factory=tuple, max_length=100)
    direction: Literal["increase", "decrease"]
    unit: str = Field(min_length=1, max_length=80)
    source_system_ref: OpaqueRef
    required_sample_count: int = Field(ge=1, le=1_000_000_000)
    measurement_window_seconds: int = Field(ge=1, le=31_536_000)
    certification_target: Decimal | None = None
    certification_comparison: Literal["at_least", "at_most"] | None = None
    executive_visible: bool = True

    @field_validator("certification_target", mode="before")
    @classmethod
    def _target_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("company metric target must be a finite decimal") from exc
        if not parsed.is_finite() or parsed < 0:
            raise ValueError(
                "company metric target must be a finite non-negative decimal"
            )
        return parsed

    @field_validator("loop_refs", mode="before")
    @classmethod
    def _tuple_loops(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _metric_contract_is_coherent(self) -> Self:
        _unique(self.loop_refs, label="metric loops")
        if (self.certification_target is None) != (
            self.certification_comparison is None
        ):
            raise ValueError("company metric target and comparison must be declared together")
        if self.certification_target is not None:
            expected = "at_least" if self.direction == "increase" else "at_most"
            if self.certification_comparison != expected:
                raise ValueError("company metric comparison must match direction")
            if self.unit == "percent" and self.certification_target > Decimal("100"):
                raise ValueError("percent company metric targets cannot exceed 100")
        return self


class DeploymentUpgradePolicy(_StrictModel):
    deployment_mode: Literal["manual_approval", "staged_canary"]
    immutable_versions: Literal[True] = True
    migration_plan_required: Literal[True] = True
    rollback_plan_required: Literal[True] = True
    automatic_major_upgrade: Literal[False] = False
    certification_revalidation_required: Literal[True] = True
    superseded_versions_remain_auditable: Literal[True] = True


class CertifiedGoldenLoopRecordBinding(_StrictModel):
    loop_ref: PortableRef
    loop_version: str = Field(min_length=5, max_length=80)
    declaration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    certification_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    certification_environment_ref: OpaqueRef

    @field_validator("loop_version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("certified loop version must use semantic versioning")
        return value

    @field_validator("declaration_digest", "certification_record_digest")
    @classmethod
    def _digests(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("certified loop digests must be lowercase SHA-256")
        return clean


class CertifiedEconomicSpineStageEvidence(_StrictModel):
    stage: EconomicSpineStage
    stage_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator("stage", mode="before")
    @classmethod
    def _stage_enum(cls, value: Any) -> Any:
        return _enum_value(value, EconomicSpineStage)

    @field_validator("stage_binding_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("stage binding digest must be lowercase SHA-256")
        return clean

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _tuple_evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _evidence_is_canonical(self) -> Self:
        refs = tuple(item.evidence_ref for item in self.evidence_refs)
        _unique(refs, label="economic-spine stage evidence refs")
        if refs != tuple(sorted(refs)):
            raise ValueError("economic-spine stage evidence must use canonical order")
        return self


class CompanyBlueprintCertificationRecord(_StrictModel):
    """Spring/operator certification of one exact Company Blueprint declaration."""

    schema_id: Literal[
        "lightbulb.company_blueprint_certification_record.v1"
    ] = Field(
        default=COMPANY_BLUEPRINT_CERTIFICATION_RECORD_SCHEMA,
        alias="schema",
    )
    blueprint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_ref: OpaqueRef
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_readiness_evaluation_digest: str = Field(
        pattern=r"^[0-9a-f]{64}$"
    )
    certified_loops: tuple[CertifiedGoldenLoopRecordBinding, ...] = Field(
        min_length=1,
        max_length=500,
    )
    economic_spine_stage_evidence: tuple[
        CertifiedEconomicSpineStageEvidence,
        ...,
    ] = Field(
        min_length=10,
        max_length=10,
    )
    company_outcome_measurements: tuple[
        LoopOutcomeCertificationMeasurement,
        ...,
    ] = Field(
        min_length=1,
        max_length=1_000,
    )
    rollback_rehearsal_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=500,
    )
    spring_certification_ref: OpaqueRef
    spring_audit_event_ref: OpaqueRef
    spring_evidence_custody_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_ref: OpaqueRef
    certified_at: str
    expires_at: str
    operator_approved: Literal[True]
    record_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator(
        "blueprint_digest",
        "candidate_digest",
        "runtime_artifact_digest",
        "operational_readiness_evaluation_digest",
        "spring_evidence_custody_digest",
    )
    @classmethod
    def _digests(cls, value: str) -> str:
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("Blueprint certification digests must be lowercase SHA-256")
        return clean

    @field_validator("record_digest")
    @classmethod
    def _optional_record_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("record_digest must be lowercase SHA-256")
        return clean

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator(
        "certified_loops",
        "economic_spine_stage_evidence",
        "company_outcome_measurements",
        "rollback_rehearsal_evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    def _record_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"record_digest"},
        )

    @model_validator(mode="after")
    def _record_is_exact_evidence_bound_and_expiring(self) -> Self:
        loop_keys = tuple(
            (item.loop_ref, item.loop_version) for item in self.certified_loops
        )
        _unique(loop_keys, label="certified Golden Loop versions")
        if loop_keys != tuple(sorted(loop_keys)):
            raise ValueError("certified Golden Loops must use canonical order")
        if any(
            item.certification_environment_ref != self.environment_ref
            for item in self.certified_loops
        ):
            raise ValueError(
                "every Golden Loop certificate must use the Blueprint environment"
            )
        if _parsed_timestamp(self.certified_at) >= _parsed_timestamp(self.expires_at):
            raise ValueError("Blueprint certification must expire after it is granted")

        stages = tuple(item.stage for item in self.economic_spine_stage_evidence)
        if stages != tuple(EconomicSpineStage):
            raise ValueError(
                "Blueprint certification must cover all economic-spine stages "
                "in canonical order"
            )
        metric_refs = tuple(
            item.metric_ref for item in self.company_outcome_measurements
        )
        _unique(metric_refs, label="Blueprint outcome measurement refs")
        if metric_refs != tuple(sorted(metric_refs)):
            raise ValueError(
                "Blueprint outcome measurements must use canonical metric order"
            )

        certified_at = _parsed_timestamp(self.certified_at)
        groups = (
            tuple(
                evidence
                for stage in self.economic_spine_stage_evidence
                for evidence in stage.evidence_refs
            ),
            tuple(
                evidence
                for measurement in self.company_outcome_measurements
                for evidence in measurement.evidence_refs
            ),
            self.rollback_rehearsal_evidence_refs,
        )
        evidence_refs = tuple(
            evidence.evidence_ref for group in groups for evidence in group
        )
        _unique(evidence_refs, label="Blueprint certification evidence refs")
        for group in groups:
            for evidence in group:
                if evidence.subject_ref != self.blueprint_digest:
                    raise ValueError(
                        "Blueprint certification evidence must bind the exact Blueprint digest"
                    )
                if evidence.verification_grade not in {
                    PrimitiveEvidenceVerificationGrade.ATTESTED,
                    PrimitiveEvidenceVerificationGrade.VERIFIED,
                }:
                    raise ValueError(
                        "Blueprint certification evidence must be attested or verified"
                    )
                observed_at = _parsed_timestamp(evidence.observed_at)
                effective_at = (
                    _parsed_timestamp(evidence.effective_at)
                    if evidence.effective_at is not None
                    else observed_at
                )
                if observed_at > certified_at or effective_at > certified_at:
                    raise ValueError(
                        "Blueprint certification evidence cannot post-date certification"
                    )
        rollback_refs = tuple(
            item.evidence_ref for item in self.rollback_rehearsal_evidence_refs
        )
        if rollback_refs != tuple(sorted(rollback_refs)):
            raise ValueError("rollback evidence must use canonical order")
        if any(
            evidence.verification_grade
            != PrimitiveEvidenceVerificationGrade.VERIFIED
            for group in groups[:2]
            for evidence in group
        ):
            raise ValueError(
                "economic-spine and company-outcome evidence must be independently verified"
            )

        expected_digest = _stable_digest(self._record_payload())
        if self.record_digest and self.record_digest != expected_digest:
            raise ValueError("record_digest does not match the exact certification record")
        object.__setattr__(self, "record_digest", expected_digest)
        return self


class CompanyBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint.v1"] = Field(
        default=COMPANY_BLUEPRINT_SCHEMA,
        alias="schema",
    )
    blueprint_ref: PortableRef
    version: str = Field(min_length=5, max_length=80)
    name: str = Field(min_length=1, max_length=300)
    company_archetype: PortableRef
    lifecycle: CapabilityLifecycleState
    gtm_visible: bool = False
    objectives: tuple[CompanyObjective, ...] = Field(min_length=1, max_length=100)
    departments: tuple[DepartmentBinding, ...] = Field(min_length=1, max_length=100)
    agent_roles: tuple[AgentRoleBinding, ...] = Field(min_length=1, max_length=500)
    golden_loops: tuple[GoldenLoopBinding, ...] = Field(min_length=1, max_length=500)
    allowed_primitive_refs: tuple[PortableRef, ...] = Field(min_length=1, max_length=10_000)
    allowed_tool_refs: tuple[PortableRef, ...] = Field(default_factory=tuple, max_length=50_000)
    connector_requirements: tuple[ConnectorRequirement, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    secret_requirements: tuple[SecretRequirement, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    projects: tuple[ProjectBinding, ...] = Field(default_factory=tuple, max_length=1_000)
    schedules: tuple[ScheduleBinding, ...] = Field(default_factory=tuple, max_length=5_000)
    economic_spine: EconomicSpineContract
    knowledge_evidence_policy: KnowledgeEvidencePolicy
    human_authority_policy: HumanAuthorityPolicy
    budget_capacity_policy: BudgetCapacityPolicy
    execution_host_policy: ExecutionHostPolicy
    outcome_metrics: tuple[CompanyOutcomeMetricBinding, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    deployment_upgrade_policy: DeploymentUpgradePolicy
    known_blockers: tuple[str, ...] = Field(default_factory=tuple, max_length=200)
    certification: CompanyBlueprintCertificationRecord | None = None
    blueprint_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("lifecycle", mode="before")
    @classmethod
    def _lifecycle_enum(cls, value: Any) -> Any:
        return _enum_value(value, CapabilityLifecycleState)

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("Company Blueprint version must use semantic versioning")
        return value

    @field_validator(
        "objectives",
        "departments",
        "agent_roles",
        "golden_loops",
        "allowed_primitive_refs",
        "allowed_tool_refs",
        "connector_requirements",
        "secret_requirements",
        "projects",
        "schedules",
        "outcome_metrics",
        "known_blockers",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("blueprint_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("blueprint_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _blueprint_is_closed_and_sealed(self) -> Self:
        keyed_groups = (
            ("objectives", tuple(item.objective_ref for item in self.objectives)),
            ("departments", tuple(item.department_ref for item in self.departments)),
            ("agent roles", tuple(item.role_ref for item in self.agent_roles)),
            ("Golden Loops", tuple(item.loop_ref for item in self.golden_loops)),
            (
                "connector requirements",
                tuple(item.requirement_ref for item in self.connector_requirements),
            ),
            ("secret requirements", tuple(item.secret_ref for item in self.secret_requirements)),
            ("projects", tuple(item.project_ref for item in self.projects)),
            ("schedules", tuple(item.schedule_ref for item in self.schedules)),
            ("outcome metrics", tuple(item.metric_ref for item in self.outcome_metrics)),
        )
        for label, values in keyed_groups:
            _unique(values, label=label)
        _unique(self.allowed_primitive_refs, label="allowed primitives")
        _unique(self.allowed_tool_refs, label="allowed Tools")

        objectives = {item.objective_ref for item in self.objectives}
        outcome_metric_refs = {item.metric_ref for item in self.outcome_metrics}
        roles = {item.role_ref for item in self.agent_roles}
        loops = {item.loop_ref: item for item in self.golden_loops}
        departments_by_ref = {
            item.department_ref: item for item in self.departments
        }
        departments = set(departments_by_ref)
        if any(
            not set(item.metric_refs).issubset(outcome_metric_refs)
            for item in self.objectives
        ):
            raise ValueError("company objective references an undeclared outcome metric")
        if any(item.department_ref not in departments for item in self.golden_loops):
            raise ValueError("every Golden Loop must bind a declared department")
        for department in self.departments:
            if not set(department.objective_refs).issubset(objectives):
                raise ValueError("department references an undeclared objective")
            if not set(department.agent_role_refs).issubset(roles):
                raise ValueError("department references an undeclared agent role")
            if not set(department.loop_refs).issubset(loops):
                raise ValueError("department references an undeclared Golden Loop")
            if any(
                loops[loop_ref].department_ref != department.department_ref
                for loop_ref in department.loop_refs
            ):
                raise ValueError("department and Golden Loop bindings disagree")
        loop_departments: dict[str, list[str]] = {loop_ref: [] for loop_ref in loops}
        for department in self.departments:
            for loop_ref in department.loop_refs:
                loop_departments[loop_ref].append(department.department_ref)
        for loop_ref, binding in loops.items():
            if loop_departments[loop_ref] != [binding.department_ref]:
                raise ValueError(
                    "every Golden Loop must appear exactly once in its bound department"
                )

        allowed_primitives = set(self.allowed_primitive_refs)
        allowed_tools = set(self.allowed_tool_refs)
        if any(
            not set(role.allowed_primitive_refs).issubset(allowed_primitives)
            for role in self.agent_roles
        ):
            raise ValueError("agent primitive permissions exceed the Blueprint allow-list")
        if any(
            not set(role.allowed_tool_refs).issubset(allowed_tools)
            for role in self.agent_roles
        ):
            raise ValueError("agent Tool permissions exceed the Blueprint allow-list")
        if any(
            not set(item.required_tool_refs).issubset(allowed_tools)
            for item in self.connector_requirements
        ):
            raise ValueError("connector requirements exceed the Blueprint Tool allow-list")

        connector_refs = {item.requirement_ref for item in self.connector_requirements}
        secret_refs = {item.secret_ref for item in self.secret_requirements}
        if any(
            item.connector_requirement_ref not in connector_refs
            for item in self.secret_requirements
        ):
            raise ValueError("secret requirement references an unknown connector requirement")
        if any(not set(item.loop_refs).issubset(loops) for item in self.projects):
            raise ValueError("project references an undeclared Golden Loop")
        version_match = _SEMVER_RE.fullmatch(self.version)
        if (
            version_match is not None
            and tuple(int(version_match.group(index)) for index in range(1, 4))
            >= (0, 6, 0)
            and any(item.project_spec is None for item in self.projects)
        ):
            raise ValueError(
                "Company Blueprint versions 0.6.0 and later require a typed specification "
                "for every Company Project"
            )
        approval_policy_refs = set(self.human_authority_policy.approval_policy_refs)
        allowed_harnesses = set(self.execution_host_policy.allowed_harnesses)
        for project in self.projects:
            spec = project.project_spec
            if spec is None:
                continue
            if spec.department_ref not in departments_by_ref:
                raise ValueError(
                    "Company Project specification references an undeclared department"
                )
            department = departments_by_ref[spec.department_ref]
            if not set(spec.objective_refs).issubset(objectives):
                raise ValueError(
                    "Company Project specification references an undeclared objective"
                )
            if not set(spec.objective_refs).issubset(department.objective_refs):
                raise ValueError(
                    "Company Project objectives exceed its department assignment"
                )
            if not set(spec.agent_role_refs).issubset(roles):
                raise ValueError(
                    "Company Project specification references an undeclared agent role"
                )
            if not set(spec.agent_role_refs).issubset(department.agent_role_refs):
                raise ValueError(
                    "Company Project agent roles exceed its department assignment"
                )
            if any(
                loops[loop_ref].department_ref != spec.department_ref
                for loop_ref in spec.loop_refs
            ):
                raise ValueError(
                    "Company Project Golden Loops must belong to its declared department"
                )
            if not set(spec.allowed_primitive_refs).issubset(allowed_primitives):
                raise ValueError(
                    "Company Project primitive permissions exceed the Blueprint allow-list"
                )
            if not set(spec.allowed_tool_refs).issubset(allowed_tools):
                raise ValueError(
                    "Company Project Tool permissions exceed the Blueprint allow-list"
                )
            if not set(spec.secret_refs).issubset(secret_refs):
                raise ValueError(
                    "Company Project specification references an undeclared secret"
                )
            if not set(spec.approval_policy_refs).issubset(approval_policy_refs):
                raise ValueError(
                    "Company Project approval policies exceed the human-authority policy"
                )
            if not set(spec.allowed_harnesses).issubset(allowed_harnesses):
                raise ValueError(
                    "Company Project harnesses exceed the execution-host policy"
                )
        if any(item.loop_ref not in loops for item in self.schedules):
            raise ValueError("schedule references an undeclared Golden Loop")
        if any(not set(item.loop_refs).issubset(loops) for item in self.outcome_metrics):
            raise ValueError("company metric references an undeclared Golden Loop")
        for stage in self.economic_spine.stages:
            if stage.objective_ref not in objectives:
                raise ValueError(
                    "economic-spine stage references an undeclared objective"
                )
            if not set(stage.loop_refs).issubset(loops):
                raise ValueError(
                    "economic-spine stage references an undeclared Golden Loop"
                )
            if stage.lifecycle == CapabilityLifecycleState.CERTIFIED and any(
                loops[loop_ref].declared_lifecycle
                != CapabilityLifecycleState.CERTIFIED
                for loop_ref in stage.loop_refs
            ):
                raise ValueError(
                    "CERTIFIED economic-spine stages require certified loop bindings"
                )

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "lifecycle",
                "gtm_visible",
                "known_blockers",
                "certification",
                "blueprint_digest",
            },
            exclude_none=True,
        )
        for loop in payload.get("golden_loops", []):
            loop.pop("declared_lifecycle", None)
        for stage in payload.get("economic_spine", {}).get("stages", []):
            stage.pop("lifecycle", None)
            stage.pop("known_blockers", None)
        expected = _stable_digest(payload)
        if self.blueprint_digest and self.blueprint_digest != expected:
            raise ValueError("blueprint_digest does not match the exact Blueprint declaration")
        object.__setattr__(self, "blueprint_digest", expected)

        if self.lifecycle == CapabilityLifecycleState.CERTIFIED:
            if not self.gtm_visible:
                raise ValueError("CERTIFIED Company Blueprints must be GTM-visible")
            if self.known_blockers:
                raise ValueError("CERTIFIED Company Blueprints cannot retain blockers")
            if any(
                item.declared_lifecycle != CapabilityLifecycleState.CERTIFIED
                for item in self.golden_loops
            ):
                raise ValueError("CERTIFIED Company Blueprints require certified loops")
            if self.certification is None:
                raise ValueError(
                    "CERTIFIED Company Blueprints require a Spring/operator certification"
                )
            if any(
                stage.lifecycle != CapabilityLifecycleState.CERTIFIED
                for stage in self.economic_spine.stages
            ):
                raise ValueError(
                    "CERTIFIED Company Blueprints require a certified economic spine"
                )
            if any(
                metric.certification_target is None
                for metric in self.outcome_metrics
            ):
                raise ValueError(
                    "CERTIFIED Company Blueprints require explicit outcome targets"
                )
            if self.certification.blueprint_digest != expected:
                raise ValueError(
                    "Blueprint certification must bind the exact declaration digest"
                )
            expected_loops = tuple(
                sorted(
                    (
                        item.loop_ref,
                        item.version,
                        item.declaration_digest,
                    )
                    for item in self.golden_loops
                )
            )
            certified_loops = tuple(
                (
                    item.loop_ref,
                    item.loop_version,
                    item.declaration_digest,
                )
                for item in self.certification.certified_loops
            )
            if certified_loops != expected_loops:
                raise ValueError(
                    "Blueprint certification must bind every exact Golden Loop"
                )
            certified_stages = {
                item.stage: item
                for item in self.certification.economic_spine_stage_evidence
            }
            for stage in self.economic_spine.stages:
                evidence = certified_stages[stage.stage]
                if evidence.stage_binding_digest != stage.stage_binding_digest:
                    raise ValueError(
                        "Blueprint certification must bind every exact economic-spine stage"
                    )
                if stage.required_evidence_kind not in {
                    item.kind for item in evidence.evidence_refs
                }:
                    raise ValueError(
                        "economic-spine certification evidence kind is incomplete"
                    )
            measurements = {
                item.metric_ref: item
                for item in self.certification.company_outcome_measurements
            }
            metrics = {item.metric_ref: item for item in self.outcome_metrics}
            if set(measurements) != set(metrics):
                raise ValueError(
                    "Blueprint certification must measure every exact company outcome"
                )
            for metric_ref, metric in metrics.items():
                measurement = measurements[metric_ref]
                if (
                    measurement.direction != metric.direction
                    or measurement.unit != metric.unit
                    or measurement.source_system_ref != metric.source_system_ref
                    or measurement.required_sample_count
                    != metric.required_sample_count
                    or measurement.target != metric.certification_target
                    or measurement.comparison != metric.certification_comparison
                ):
                    raise ValueError(
                        "Blueprint certification must bind each exact company metric"
                    )
                window_seconds = (
                    _parsed_timestamp(measurement.window_ended_at)
                    - _parsed_timestamp(measurement.window_started_at)
                ).total_seconds()
                if window_seconds > metric.measurement_window_seconds:
                    raise ValueError(
                        "company outcome measurement exceeds its declared window"
                    )
        else:
            if self.gtm_visible:
                raise ValueError("only CERTIFIED Company Blueprints may be GTM-visible")
            if self.certification is not None:
                raise ValueError(
                    "non-certified Company Blueprints cannot carry certification authority"
                )
            if self.lifecycle in {
                CapabilityLifecycleState.PREVIEW,
                CapabilityLifecycleState.QUARANTINED,
            } and not self.known_blockers:
                raise ValueError("PREVIEW and QUARANTINED Blueprints must disclose blockers")
        return self


class CompanyBlueprintValidationFinding(_StrictModel):
    severity: BlueprintValidationSeverity
    code: PortableRef
    message: str = Field(min_length=1, max_length=1_000)
    affected_ref: OpaqueRef | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _severity_enum(cls, value: Any) -> Any:
        return _enum_value(value, BlueprintValidationSeverity)


class CompanyBlueprintValidationResult(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint_validation.v1"] = Field(
        default=COMPANY_BLUEPRINT_VALIDATION_SCHEMA,
        alias="schema",
    )
    blueprint_ref: PortableRef
    blueprint_version: str
    blueprint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    loop_catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    workflow_registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluated_at: str | None = None
    structurally_valid: bool
    spring_authority_verified: Literal[False] = False
    deployment_eligible: Literal[False] = False
    deployment_authorized: Literal[False] = False
    findings: tuple[CompanyBlueprintValidationFinding, ...]

    @field_validator(
        "blueprint_digest",
        "loop_catalog_digest",
        "workflow_registry_digest",
    )
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("blueprint validation requires a SHA-256 Blueprint digest")
        return value

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _timestamp(value, label="evaluated_at")

    @field_validator("findings", mode="before")
    @classmethod
    def _tuple_findings(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _status_matches_findings(self) -> Self:
        has_error = any(
            item.severity == BlueprintValidationSeverity.ERROR for item in self.findings
        )
        if self.structurally_valid == has_error:
            raise ValueError("structurally_valid must be false exactly when errors exist")
        return self


def validate_company_blueprint(
    blueprint: CompanyBlueprint | dict[str, Any],
    *,
    loop_catalog: GoldenLoopCatalog,
    workflow_registry: GoldenLoopWorkflowRegistry | None = None,
    primitive_registry: PrimitiveRegistry | None = None,
    evaluated_at: str | None = None,
) -> CompanyBlueprintValidationResult:
    """Validate exact manifest, primitive, Tool, and certification bindings.

    This function cannot authenticate Spring records, authorize, or deploy a
    company. It returns a deterministic structural proposal for Spring's
    scoped, trusted-clock deployment gate. Certificate-shaped SDK values are
    never production eligibility evidence by themselves.
    """

    if workflow_registry is None:
        from lightbulb.reference_golden_loop_workflows import (
            REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY,
        )

        workflow_registry = REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY
    parsed_workflow_registry = GoldenLoopWorkflowRegistry.model_validate(
        workflow_registry
    )
    parsed = CompanyBlueprint.model_validate(blueprint)
    normalized_evaluated_at = (
        _timestamp(evaluated_at, label="evaluated_at")
        if evaluated_at is not None
        else None
    )
    evaluation_time = (
        _parsed_timestamp(normalized_evaluated_at)
        if normalized_evaluated_at is not None
        else None
    )
    findings: list[CompanyBlueprintValidationFinding] = []
    chosen_tools = {
        tool
        for requirement in parsed.connector_requirements
        if requirement.required_at_deployment
        for tool in requirement.required_tool_refs
    }
    roles_by_ref = {item.role_ref: item for item in parsed.agent_roles}
    departments_by_ref = {
        item.department_ref: item for item in parsed.departments
    }
    schedules_by_loop: dict[str, list[ScheduleBinding]] = {}
    for schedule in parsed.schedules:
        schedules_by_loop.setdefault(schedule.loop_ref, []).append(schedule)
    allowed_primitives = set(parsed.allowed_primitive_refs)
    certified_loop_bindings = {
        (item.loop_ref, item.loop_version): item
        for item in (
            parsed.certification.certified_loops
            if parsed.certification is not None
            else ()
        )
    }
    manifests_by_loop_ref: dict[str, Any] = {}

    for binding in parsed.golden_loops:
        try:
            manifest = loop_catalog.get(binding.loop_ref, binding.version)
        except KeyError:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.loop_missing",
                    message="The exact Golden Loop version is absent from the supplied catalog.",
                    affected_ref=f"{binding.loop_ref}@{binding.version}",
                )
            )
            continue
        manifests_by_loop_ref[manifest.loop_ref] = manifest
        try:
            parsed_workflow_registry.assert_manifest_binding(manifest)
        except GoldenLoopWorkflowBindingError as exc:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code=exc.code.replace("golden_loop.", "blueprint.", 1),
                    message=str(exc),
                    affected_ref=f"{binding.loop_ref}@{binding.version}",
                )
            )
        if binding.declaration_digest != manifest.declaration_digest:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.loop_digest_mismatch",
                    message="Golden Loop binding does not match the exact manifest declaration.",
                    affected_ref=f"{binding.loop_ref}@{binding.version}",
                )
            )
        if binding.declared_lifecycle != manifest.lifecycle:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.loop_lifecycle_mismatch",
                    message="Golden Loop lifecycle differs from the catalog classification.",
                    affected_ref=f"{binding.loop_ref}@{binding.version}",
                )
            )
        if manifest.lifecycle != CapabilityLifecycleState.CERTIFIED:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.WARNING,
                    code="blueprint.loop_not_certified",
                    message="The Golden Loop is not eligible for a production deployment.",
                    affected_ref=f"{binding.loop_ref}@{binding.version}",
                )
            )
        elif parsed.certification is not None:
            certified_binding = certified_loop_bindings.get(
                (manifest.loop_ref, manifest.version)
            )
            if certified_binding is None:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.loop_certification_binding_missing",
                        message="Blueprint certification omits an exact Golden Loop certificate.",
                        affected_ref=f"{binding.loop_ref}@{binding.version}",
                    )
                )
            elif manifest.certification is None:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.loop_certification_missing",
                        message="The certified loop manifest has no certification record.",
                        affected_ref=f"{binding.loop_ref}@{binding.version}",
                    )
                )
            else:
                expected_record_digest = manifest.certification.record_digest
                if (
                    certified_binding.certification_record_digest
                    != expected_record_digest
                    or certified_binding.certification_environment_ref
                    != manifest.certification.environment_ref
                ):
                    findings.append(
                        CompanyBlueprintValidationFinding(
                            severity=BlueprintValidationSeverity.ERROR,
                            code="blueprint.loop_certification_mismatch",
                            message=(
                                "Blueprint certification does not bind the exact loop "
                                "certification record and environment."
                            ),
                            affected_ref=f"{binding.loop_ref}@{binding.version}",
                        )
                    )
                company_certified_at = _parsed_timestamp(
                    parsed.certification.certified_at
                )
                if not (
                    _parsed_timestamp(manifest.certification.certified_at)
                    <= company_certified_at
                    < _parsed_timestamp(manifest.certification.expires_at)
                ):
                    findings.append(
                        CompanyBlueprintValidationFinding(
                            severity=BlueprintValidationSeverity.ERROR,
                            code="blueprint.loop_certification_not_current_at_grant",
                            message=(
                                "Golden Loop certification was not current when the "
                                "Blueprint was certified."
                            ),
                            affected_ref=f"{binding.loop_ref}@{binding.version}",
                        )
                    )
                if (
                    evaluation_time is not None
                    and evaluation_time
                    >= _parsed_timestamp(manifest.certification.expires_at)
                ):
                    findings.append(
                        CompanyBlueprintValidationFinding(
                            severity=BlueprintValidationSeverity.WARNING,
                            code="blueprint.loop_certification_expired",
                            message="Golden Loop certification has expired.",
                            affected_ref=f"{binding.loop_ref}@{binding.version}",
                        )
                    )
        department = departments_by_ref[binding.department_ref]
        department_roles = set(department.agent_role_refs)
        for role_ref in manifest.agent_role_refs:
            role = roles_by_ref.get(role_ref)
            if role is None:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.loop_role_missing",
                        message="A Golden Loop agent role is absent from the Blueprint.",
                        affected_ref=f"{manifest.loop_ref}:{role_ref}",
                    )
                )
            elif role_ref not in department_roles:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.loop_role_outside_department",
                        message=(
                            "A Golden Loop agent role is not assigned to the loop's "
                            "bound department."
                        ),
                        affected_ref=f"{manifest.loop_ref}:{role_ref}",
                    )
                )

        tool_requirements = {
            item.binding_ref: item for item in manifest.tool_requirements
        }
        for step in manifest.primitive_steps:
            if step.primitive_ref not in allowed_primitives:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.primitive_not_allowed",
                        message="A Golden Loop primitive is absent from the Blueprint allow-list.",
                        affected_ref=step.primitive_ref,
                    )
                )
            if primitive_registry is not None:
                if not primitive_registry.supports(step.primitive_ref):
                    findings.append(
                        CompanyBlueprintValidationFinding(
                            severity=BlueprintValidationSeverity.ERROR,
                            code="blueprint.primitive_not_registered",
                            message="No executable implementation is registered for this primitive.",
                            affected_ref=step.primitive_ref,
                        )
                    )
                else:
                    implementation = primitive_registry.get(step.primitive_ref)
                    if implementation.version != step.primitive_version:
                        findings.append(
                            CompanyBlueprintValidationFinding(
                                severity=BlueprintValidationSeverity.ERROR,
                                code="blueprint.primitive_version_mismatch",
                                message="The registered primitive version differs from the loop manifest.",
                                affected_ref=step.primitive_ref,
                            )
                        )
            role = roles_by_ref.get(step.agent_role_ref)
            if (
                role is not None
                and step.primitive_ref not in role.allowed_primitive_refs
            ):
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.role_primitive_not_allowed",
                        message=(
                            "The assigned Blueprint role is not permitted to invoke "
                            "this loop primitive."
                        ),
                        affected_ref=f"{manifest.loop_ref}:{step.step_ref}",
                    )
                )
            if role is not None:
                for tool_binding_ref in step.tool_binding_refs:
                    requirement = tool_requirements[tool_binding_ref]
                    selected_tools = set(requirement.acceptable_tools).intersection(
                        chosen_tools
                    )
                    if not selected_tools.intersection(role.allowed_tool_refs):
                        findings.append(
                            CompanyBlueprintValidationFinding(
                                severity=BlueprintValidationSeverity.ERROR,
                                code="blueprint.role_tool_not_allowed",
                                message=(
                                    "The assigned Blueprint role has no production-required "
                                    "Tool permitted for this loop binding."
                                ),
                                affected_ref=f"{manifest.loop_ref}:{step.step_ref}",
                            )
                        )
        for tool_requirement in manifest.tool_requirements:
            if not set(tool_requirement.acceptable_tools).intersection(chosen_tools):
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.tool_binding_unsatisfied",
                        message="No selected connector Tool satisfies a required loop binding.",
                        affected_ref=f"{manifest.loop_ref}:{tool_requirement.binding_ref}",
                    )
                )
        if manifest.budget.max_cost_microusd > parsed.budget_capacity_policy.max_loop_cost_microusd:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.loop_budget_exceeds_company_limit",
                    message="The Golden Loop cost ceiling exceeds the company per-loop limit.",
                    affected_ref=manifest.loop_ref,
                )
            )
        declared_trigger_refs = {item.trigger_ref for item in manifest.triggers}
        for schedule in schedules_by_loop.get(manifest.loop_ref, []):
            if schedule.trigger_ref not in declared_trigger_refs:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.schedule_trigger_mismatch",
                        message=(
                            "The company schedule does not bind an exact trigger declared "
                            "by the Golden Loop."
                        ),
                        affected_ref=schedule.schedule_ref,
                    )
                )
        if manifest.harness_policy.required and not set(
            manifest.harness_policy.allowed_harnesses
        ).intersection(parsed.execution_host_policy.allowed_harnesses):
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.harness_binding_unsatisfied",
                    message="No allowed company harness satisfies the Golden Loop policy.",
                    affected_ref=manifest.loop_ref,
                )
            )

    loop_bindings_by_ref = {
        item.loop_ref: item for item in parsed.golden_loops
    }
    for project in parsed.projects:
        expected_workflow_refs: list[str] = []
        bound_manifests: list[Any] = []
        for loop_ref in project.loop_refs:
            binding = loop_bindings_by_ref[loop_ref]
            manifest = manifests_by_loop_ref.get(loop_ref)
            if manifest is not None:
                bound_manifests.append(manifest)
            try:
                workflow = parsed_workflow_registry.get_for_loop(
                    loop_ref,
                    binding.version,
                )
            except KeyError:
                continue
            expected_workflow_refs.append(workflow.workflow_ref)
        if (
            len(expected_workflow_refs) == len(project.loop_refs)
            and project.workflow_refs != tuple(expected_workflow_refs)
        ):
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.project_workflow_binding_mismatch",
                    message=(
                        "The Company Project workflows are not the exact canonical "
                        "workflows for its ordered Golden Loop bindings."
                    ),
                    affected_ref=project.project_ref,
                )
            )
        if project.project_spec is None:
            continue
        required_roles = {
            role_ref
            for manifest in bound_manifests
            for role_ref in manifest.agent_role_refs
        }
        if not required_roles.issubset(project.project_spec.agent_role_refs):
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.project_loop_role_missing",
                    message=(
                        "The Company Project specification omits an agent role required "
                        "by one of its Golden Loops."
                    ),
                    affected_ref=project.project_ref,
                )
            )
        required_primitives = {
            step.primitive_ref
            for manifest in bound_manifests
            for step in manifest.primitive_steps
        }
        if not required_primitives.issubset(
            project.project_spec.allowed_primitive_refs
        ):
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.ERROR,
                    code="blueprint.project_loop_primitive_missing",
                    message=(
                        "The Company Project specification omits a primitive required "
                        "by one of its Golden Loops."
                    ),
                    affected_ref=project.project_ref,
                )
            )

    for stage in parsed.economic_spine.stages:
        if not stage.loop_refs:
            continue
        artifacts = {
            artifact.artifact_ref: artifact
            for loop_ref in stage.loop_refs
            if loop_ref in manifests_by_loop_ref
            for artifact in manifests_by_loop_ref[loop_ref].artifact_requirements
        }
        for artifact_ref in stage.required_artifact_refs:
            artifact = artifacts.get(artifact_ref)
            if artifact is None:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.economic_spine_artifact_missing",
                        message=(
                            "An economic-spine stage requires an artifact not produced "
                            "by any bound Golden Loop."
                        ),
                        affected_ref=f"{stage.stage.value}:{artifact_ref}",
                    )
                )
            elif artifact.evidence_kind != stage.required_evidence_kind:
                findings.append(
                    CompanyBlueprintValidationFinding(
                        severity=BlueprintValidationSeverity.ERROR,
                        code="blueprint.economic_spine_evidence_kind_mismatch",
                        message=(
                            "The economic-spine stage evidence kind differs from its "
                            "bound Golden Loop artifact contract."
                        ),
                        affected_ref=f"{stage.stage.value}:{artifact_ref}",
                    )
                )

    for stage in parsed.economic_spine.stages:
        if stage.lifecycle != CapabilityLifecycleState.CERTIFIED:
            findings.append(
                CompanyBlueprintValidationFinding(
                    severity=BlueprintValidationSeverity.WARNING,
                    code="blueprint.economic_spine_stage_not_certified",
                    message=(
                        "The economic-spine stage has no certified recurring outcome."
                    ),
                    affected_ref=stage.stage.value,
                )
            )

    if parsed.lifecycle != CapabilityLifecycleState.CERTIFIED:
        findings.append(
            CompanyBlueprintValidationFinding(
                severity=BlueprintValidationSeverity.WARNING,
                code="blueprint.not_certified",
                message="Spring must not deploy this Blueprint to production until it is certified.",
                affected_ref=f"{parsed.blueprint_ref}@{parsed.version}",
            )
        )
    elif normalized_evaluated_at is None:
        findings.append(
            CompanyBlueprintValidationFinding(
                severity=BlueprintValidationSeverity.WARNING,
                code="blueprint.certification_time_required",
                message=(
                    "Production eligibility requires an explicit time at which "
                    "certificate currency was evaluated."
                ),
                affected_ref=f"{parsed.blueprint_ref}@{parsed.version}",
            )
        )
    elif parsed.certification is not None and not (
        _parsed_timestamp(parsed.certification.certified_at)
        <= evaluation_time
        < _parsed_timestamp(parsed.certification.expires_at)
    ):
        findings.append(
            CompanyBlueprintValidationFinding(
                severity=BlueprintValidationSeverity.WARNING,
                code="blueprint.certification_not_current",
                message="Company Blueprint certification is not current.",
                affected_ref=f"{parsed.blueprint_ref}@{parsed.version}",
            )
        )

    if parsed.lifecycle == CapabilityLifecycleState.CERTIFIED:
        findings.append(
            CompanyBlueprintValidationFinding(
                severity=BlueprintValidationSeverity.WARNING,
                code="blueprint.spring_authority_unverified",
                message=(
                    "The SDK can validate certificate shape and exact digests but cannot "
                    "authenticate Spring authority; production eligibility must be resolved "
                    "by Spring under tenant/company scope and its trusted clock."
                ),
                affected_ref=f"{parsed.blueprint_ref}@{parsed.version}",
            )
        )

    findings.sort(
        key=lambda item: (
            item.severity.value,
            item.code,
            item.affected_ref or "",
        )
    )
    has_error = any(
        item.severity == BlueprintValidationSeverity.ERROR for item in findings
    )
    return CompanyBlueprintValidationResult(
        blueprint_ref=parsed.blueprint_ref,
        blueprint_version=parsed.version,
        blueprint_digest=parsed.blueprint_digest,
        loop_catalog_digest=loop_catalog.catalog_digest,
        workflow_registry_digest=parsed_workflow_registry.registry_digest,
        evaluated_at=normalized_evaluated_at,
        structurally_valid=not has_error,
        findings=tuple(findings),
    )


__all__ = [
    "AgentRoleBinding",
    "BlueprintValidationSeverity",
    "BudgetCapacityPolicy",
    "COMPANY_BLUEPRINT_CERTIFICATION_RECORD_SCHEMA",
    "COMPANY_BLUEPRINT_SCHEMA",
    "COMPANY_BLUEPRINT_VALIDATION_SCHEMA",
    "COMPANY_PROJECT_SPEC_SCHEMA",
    "CompanyBlueprint",
    "CompanyBlueprintCertificationRecord",
    "CompanyBlueprintValidationFinding",
    "CompanyBlueprintValidationResult",
    "CompanyObjective",
    "CompanyOutcomeMetricBinding",
    "CompanyProjectSpecification",
    "ConnectorRequirement",
    "CertifiedEconomicSpineStageEvidence",
    "CertifiedGoldenLoopRecordBinding",
    "DepartmentBinding",
    "DeploymentUpgradePolicy",
    "ECONOMIC_SPINE_CONTRACT_SCHEMA",
    "EconomicSpineContract",
    "EconomicSpineStage",
    "EconomicSpineStageBinding",
    "ExecutionHostPolicy",
    "GoldenLoopBinding",
    "HumanAuthorityPolicy",
    "KnowledgeEvidencePolicy",
    "ProjectBinding",
    "ScheduleBinding",
    "SecretRequirement",
    "validate_company_blueprint",
]
