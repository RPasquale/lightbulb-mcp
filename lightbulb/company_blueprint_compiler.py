"""Pure compilation of Company Blueprints into Spring deployment plans.

The compiler validates and materializes an immutable proposal. It never scopes
a tenant or company, resolves a secret or live Host Binding, authorizes a
deployment, starts a runtime, or performs an external effect. Spring remains
the authority for all of those operations.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, Literal, Mapping

from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.company_blueprints import (
    CompanyBlueprint,
    CompanyBlueprintValidationResult,
    ExecutionHostPolicy,
    GoldenLoopBinding,
    ProjectBinding,
    ScheduleBinding,
    validate_company_blueprint,
)
from lightbulb.golden_loops import (
    GoldenLoopCatalog,
    LoopCertificationManifest,
    OpaqueRef,
    PortableRef,
)
from lightbulb.golden_loop_workflow_registry import (
    GoldenLoopWorkflowRegistry,
    GoldenLoopWorkflowRegistryEntry,
)
from lightbulb.primitive_runtime import PrimitiveRegistry


COMPANY_BLUEPRINT_DEPLOYMENT_PLAN_SCHEMA = (
    "lightbulb.company_blueprint_deployment_plan.v1"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


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


def _sha256(value: str, *, label: str, allow_empty: bool = False) -> str:
    clean = value.strip().lower()
    if allow_empty and not clean:
        return clean
    if not _SHA256_RE.fullmatch(clean):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return clean


def _unique(values: tuple[Any, ...], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


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


class CompanyBlueprintCompilationMode(str, Enum):
    PREVIEW = "preview"
    PRODUCTION = "production"


class CompanyBlueprintCompilationError(ValueError):
    """Raised when no safe deployment plan can be compiled."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        validation: CompanyBlueprintValidationResult | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.validation = validation


class SpringAuthorityReferences(_StrictModel):
    """Opaque future authority correlations; never authority by themselves."""

    authority_owner: Literal["spring_control_plane"] = "spring_control_plane"
    blueprint_certification_ref: OpaqueRef | None = None
    deployment_authority_ref: OpaqueRef | None = None
    authority_refs_verified: Literal[False] = False
    deployment_authorized: Literal[False] = False


class AutoCompanyLoopDeploymentPlan(_StrictModel):
    target: Literal["spring_autocompany_kernel"] = "spring_autocompany_kernel"
    binding: GoldenLoopBinding
    manifest: LoopCertificationManifest
    workflow_registry_entry: GoldenLoopWorkflowRegistryEntry
    manifest_digest: str
    schedule_bindings: tuple[ScheduleBinding, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    project_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    delegated_execution_authority: Literal["spring_dynamic_workflow"] | None = None

    @field_validator("manifest_digest")
    @classmethod
    def _manifest_digest(cls, value: str) -> str:
        return _sha256(value, label="manifest_digest")

    @field_validator("schedule_bindings", "project_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _binding_is_exact(self) -> Self:
        if (
            self.binding.loop_ref != self.manifest.loop_ref
            or self.binding.version != self.manifest.version
            or self.binding.declaration_digest != self.manifest.declaration_digest
            or self.binding.declared_lifecycle != self.manifest.lifecycle
        ):
            raise ValueError("loop deployment must bind the exact manifest version")
        if self.manifest_digest != self.manifest.manifest_digest():
            raise ValueError("manifest_digest does not match the exact loop manifest")
        self.workflow_registry_entry.assert_manifest_binding(self.manifest)
        if any(
            schedule.loop_ref != self.binding.loop_ref
            for schedule in self.schedule_bindings
        ):
            raise ValueError("loop schedules must reference the deployed loop")
        _unique(
            tuple(schedule.schedule_ref for schedule in self.schedule_bindings),
            label="loop schedules",
        )
        _unique(self.project_refs, label="loop project references")

        requires_dynamic_workflow = (
            self.workflow_registry_entry.runtime_owner == "spring_dynamic_workflow"
        )
        if requires_dynamic_workflow:
            if self.delegated_execution_authority != "spring_dynamic_workflow":
                raise ValueError(
                    "Dynamic Workflow loops must delegate to Spring Dynamic Workflow"
                )
            if not self.project_refs:
                raise ValueError(
                    "Dynamic Workflow loops require an exact Project binding"
                )
        elif self.delegated_execution_authority is not None:
            raise ValueError(
                "only Dynamic Workflow loops may declare delegated execution authority"
            )
        return self


class AutoCompanyKernelDeploymentPlan(_StrictModel):
    target: Literal["spring_autocompany_kernel"] = "spring_autocompany_kernel"
    loops: tuple[AutoCompanyLoopDeploymentPlan, ...] = Field(
        min_length=1,
        max_length=1_000,
    )

    @field_validator("loops", mode="before")
    @classmethod
    def _tuple_loops(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _loops_are_unique(self) -> Self:
        _unique(
            tuple((item.binding.loop_ref, item.binding.version) for item in self.loops),
            label="AutoCompany loop versions",
        )
        return self


class DynamicWorkflowAuthorityDeploymentPlan(_StrictModel):
    target: Literal["spring_dynamic_workflow"] = "spring_dynamic_workflow"
    project_bindings: tuple[ProjectBinding, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    execution_host_policy: ExecutionHostPolicy

    @field_validator("project_bindings", mode="before")
    @classmethod
    def _tuple_projects(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _projects_are_unique(self) -> Self:
        _unique(
            tuple(item.project_ref for item in self.project_bindings),
            label="Dynamic Workflow Project bindings",
        )
        return self


class CompanyBlueprintDeploymentPlan(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint_deployment_plan.v1"] = Field(
        default=COMPANY_BLUEPRINT_DEPLOYMENT_PLAN_SCHEMA,
        alias="schema",
    )
    compilation_mode: CompanyBlueprintCompilationMode
    preview_only: Literal[True] = True
    production_eligible: Literal[False] = False
    blueprint_ref: PortableRef
    blueprint_version: str = Field(min_length=5, max_length=80)
    blueprint_digest: str
    loop_catalog_digest: str
    loop_catalog: GoldenLoopCatalog
    workflow_registry_digest: str
    workflow_registry: GoldenLoopWorkflowRegistry
    blueprint: CompanyBlueprint
    validation: CompanyBlueprintValidationResult
    autocompany_kernel: AutoCompanyKernelDeploymentPlan
    dynamic_workflow_authority: DynamicWorkflowAuthorityDeploymentPlan | None = None
    spring_authority: SpringAuthorityReferences = Field(
        default_factory=SpringAuthorityReferences
    )
    credentials_embedded: Literal[False] = False
    live_host_sessions_embedded: Literal[False] = False
    side_effects_performed: Literal[False] = False
    plan_digest: str = ""

    @field_validator("compilation_mode", mode="before")
    @classmethod
    def _mode_enum(cls, value: Any) -> Any:
        if isinstance(value, CompanyBlueprintCompilationMode):
            return value
        if isinstance(value, str):
            try:
                return CompanyBlueprintCompilationMode(value)
            except ValueError:
                return value
        return value

    @field_validator(
        "blueprint_digest",
        "loop_catalog_digest",
        "workflow_registry_digest",
    )
    @classmethod
    def _source_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("plan_digest")
    @classmethod
    def _optional_plan_digest(cls, value: str) -> str:
        return _sha256(value, label="plan_digest", allow_empty=True)

    def _plan_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _plan_is_exact_non_authoritative_and_sealed(self) -> Self:
        if (
            self.blueprint_ref != self.blueprint.blueprint_ref
            or self.blueprint_version != self.blueprint.version
            or self.blueprint_digest != self.blueprint.blueprint_digest
        ):
            raise ValueError("deployment plan must bind the exact Company Blueprint")
        if (
            self.validation.blueprint_ref != self.blueprint_ref
            or self.validation.blueprint_version != self.blueprint_version
            or self.validation.blueprint_digest != self.blueprint_digest
            or self.validation.loop_catalog_digest != self.loop_catalog_digest
            or self.validation.workflow_registry_digest
            != self.workflow_registry_digest
        ):
            raise ValueError("deployment plan must bind the exact validation result")
        if self.compilation_mode != CompanyBlueprintCompilationMode.PREVIEW:
            raise ValueError("the pure SDK emits preview deployment plans only")
        if self.production_eligible != self.validation.deployment_eligible:
            raise ValueError("SDK validation and compilation must remain non-authoritative")
        if self.loop_catalog_digest != self.loop_catalog.catalog_digest:
            raise ValueError(
                "loop_catalog_digest does not match the exact Golden Loop catalog"
            )
        if self.workflow_registry_digest != self.workflow_registry.registry_digest:
            raise ValueError(
                "workflow_registry_digest does not match the exact workflow registry"
            )

        expected_bindings = self.blueprint.golden_loops
        actual_bindings = tuple(
            item.binding for item in self.autocompany_kernel.loops
        )
        if actual_bindings != expected_bindings:
            raise ValueError(
                "AutoCompany plan must preserve every exact Golden Loop binding"
            )
        for loop in self.autocompany_kernel.loops:
            try:
                expected_manifest = self.loop_catalog.get(
                    loop.binding.loop_ref,
                    loop.binding.version,
                )
            except KeyError as exc:
                raise ValueError(
                    "loop deployment manifest is absent from the bound catalog"
                ) from exc
            if loop.manifest != expected_manifest:
                raise ValueError(
                    "loop deployment must preserve its exact catalog manifest"
                )
            try:
                expected_workflow = self.workflow_registry.get_for_loop(
                    loop.binding.loop_ref,
                    loop.binding.version,
                )
            except KeyError as exc:
                raise ValueError(
                    "loop deployment workflow is absent from the bound registry"
                ) from exc
            if loop.workflow_registry_entry != expected_workflow:
                raise ValueError(
                    "loop deployment must bind its exact canonical workflow entry"
                )

        expected_schedules = {
            item.schedule_ref: item for item in self.blueprint.schedules
        }
        actual_schedules = {
            schedule.schedule_ref: schedule
            for loop in self.autocompany_kernel.loops
            for schedule in loop.schedule_bindings
        }
        if actual_schedules != expected_schedules:
            raise ValueError("AutoCompany plan must preserve every schedule binding")

        if self.blueprint.projects:
            if self.dynamic_workflow_authority is None:
                raise ValueError(
                    "Project bindings require the Spring Dynamic Workflow target"
                )
            if (
                self.dynamic_workflow_authority.project_bindings
                != self.blueprint.projects
            ):
                raise ValueError(
                    "Dynamic Workflow plan must preserve every Project binding"
                )
            if (
                self.dynamic_workflow_authority.execution_host_policy
                != self.blueprint.execution_host_policy
            ):
                raise ValueError(
                    "Dynamic Workflow plan must preserve the Execution Host Policy"
                )
        elif self.dynamic_workflow_authority is not None:
            raise ValueError(
                "a Dynamic Workflow target requires at least one Project binding"
            )

        projects_by_ref = {
            item.project_ref: item for item in self.blueprint.projects
        }
        for loop in self.autocompany_kernel.loops:
            expected_project_refs = tuple(
                project.project_ref
                for project in self.blueprint.projects
                if loop.binding.loop_ref in project.loop_refs
            )
            if loop.project_refs != expected_project_refs:
                raise ValueError(
                    "loop deployment must preserve its exact Project references"
                )
            if loop.delegated_execution_authority == "spring_dynamic_workflow":
                workflow_ref = loop.workflow_registry_entry.workflow_ref
                if not any(
                    loop.binding.loop_ref in projects_by_ref[project_ref].loop_refs
                    and workflow_ref
                    in projects_by_ref[project_ref].workflow_refs
                    for project_ref in loop.project_refs
                ):
                    raise ValueError(
                        "Dynamic Workflow delegation requires the canonical workflow reference"
                    )

        expected_digest = _stable_digest(self._plan_payload())
        if self.plan_digest and self.plan_digest != expected_digest:
            raise ValueError("plan_digest does not match the exact deployment plan")
        object.__setattr__(self, "plan_digest", expected_digest)
        return self


def _compilation_mode(
    mode: CompanyBlueprintCompilationMode | Literal["preview", "production"],
) -> CompanyBlueprintCompilationMode:
    if isinstance(mode, CompanyBlueprintCompilationMode):
        return mode
    try:
        return CompanyBlueprintCompilationMode(mode)
    except ValueError as exc:
        raise ValueError("compilation mode must be preview or production") from exc


def compile_company_blueprint_deployment_plan(
    blueprint: CompanyBlueprint | Mapping[str, Any],
    *,
    loop_catalog: GoldenLoopCatalog | Mapping[str, Any],
    workflow_registry: GoldenLoopWorkflowRegistry | Mapping[str, Any] | None = None,
    primitive_registry: PrimitiveRegistry,
    mode: CompanyBlueprintCompilationMode | Literal["preview", "production"] = (
        CompanyBlueprintCompilationMode.PREVIEW
    ),
    evaluated_at: str | None = None,
) -> CompanyBlueprintDeploymentPlan:
    """Compile one exact Blueprint into a non-authoritative Spring plan.

    Preview mode emits an immutable proposal and labels it ineligible.
    Production mode always fails closed: caller-supplied SDK records and time
    cannot authenticate Spring certification or mint deployment authority.
    """

    if primitive_registry is None:
        raise TypeError("primitive_registry is required for Company Blueprint compilation")

    parsed_blueprint = CompanyBlueprint.model_validate(blueprint)
    parsed_catalog = GoldenLoopCatalog.model_validate(loop_catalog)
    if workflow_registry is None:
        from lightbulb.reference_golden_loop_workflows import (
            REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY,
        )

        workflow_registry = REFERENCE_GOLDEN_LOOP_WORKFLOW_REGISTRY
    parsed_workflow_registry = GoldenLoopWorkflowRegistry.model_validate(
        workflow_registry
    )
    parsed_mode = _compilation_mode(mode)
    validation = validate_company_blueprint(
        parsed_blueprint,
        loop_catalog=parsed_catalog,
        workflow_registry=parsed_workflow_registry,
        primitive_registry=primitive_registry,
        evaluated_at=evaluated_at,
    )
    if not validation.structurally_valid:
        raise CompanyBlueprintCompilationError(
            "blueprint_validation_failed",
            "Company Blueprint validation failed; no deployment plan was emitted",
            validation=validation,
        )
    if parsed_mode == CompanyBlueprintCompilationMode.PRODUCTION:
        raise CompanyBlueprintCompilationError(
            "spring_authority_required",
            (
                "The pure SDK cannot emit a production deployment plan; Spring must "
                "authenticate persisted certifications and re-evaluate the exact "
                "Blueprint under tenant/company scope and its trusted clock"
            ),
            validation=validation,
        )

    loop_plans: list[AutoCompanyLoopDeploymentPlan] = []
    for binding in parsed_blueprint.golden_loops:
        manifest = parsed_catalog.get(binding.loop_ref, binding.version)
        workflow_entry = parsed_workflow_registry.assert_manifest_binding(manifest)
        schedules = tuple(
            item
            for item in parsed_blueprint.schedules
            if item.loop_ref == binding.loop_ref
        )
        projects = tuple(
            item
            for item in parsed_blueprint.projects
            if binding.loop_ref in item.loop_refs
        )
        delegated_authority: Literal["spring_dynamic_workflow"] | None = None
        if workflow_entry.runtime_owner == "spring_dynamic_workflow":
            delegated_authority = "spring_dynamic_workflow"
            if not projects:
                raise CompanyBlueprintCompilationError(
                    "dynamic_workflow_project_missing",
                    (
                        "Dynamic Workflow Golden Loop has no exact Project binding: "
                        f"{binding.loop_ref}@{binding.version}"
                    ),
                    validation=validation,
                )
            if not any(
                workflow_entry.workflow_ref in project.workflow_refs
                for project in projects
            ):
                raise CompanyBlueprintCompilationError(
                    "dynamic_workflow_ref_missing",
                    (
                        "Project binding omits the Golden Loop canonical Dynamic "
                        f"Workflow: {binding.loop_ref}@{binding.version}"
                    ),
                    validation=validation,
                )

        loop_plans.append(
            AutoCompanyLoopDeploymentPlan(
                binding=binding,
                manifest=manifest,
                workflow_registry_entry=workflow_entry,
                manifest_digest=manifest.manifest_digest(),
                schedule_bindings=schedules,
                project_refs=tuple(item.project_ref for item in projects),
                delegated_execution_authority=delegated_authority,
            )
        )

    dynamic_workflow_authority = (
        DynamicWorkflowAuthorityDeploymentPlan(
            project_bindings=parsed_blueprint.projects,
            execution_host_policy=parsed_blueprint.execution_host_policy,
        )
        if parsed_blueprint.projects
        else None
    )
    return CompanyBlueprintDeploymentPlan(
        compilation_mode=parsed_mode,
        blueprint_ref=parsed_blueprint.blueprint_ref,
        blueprint_version=parsed_blueprint.version,
        blueprint_digest=parsed_blueprint.blueprint_digest,
        loop_catalog_digest=parsed_catalog.catalog_digest,
        loop_catalog=parsed_catalog,
        workflow_registry_digest=parsed_workflow_registry.registry_digest,
        workflow_registry=parsed_workflow_registry,
        blueprint=parsed_blueprint,
        validation=validation,
        autocompany_kernel=AutoCompanyKernelDeploymentPlan(loops=tuple(loop_plans)),
        dynamic_workflow_authority=dynamic_workflow_authority,
    )


__all__ = [
    "AutoCompanyKernelDeploymentPlan",
    "AutoCompanyLoopDeploymentPlan",
    "COMPANY_BLUEPRINT_DEPLOYMENT_PLAN_SCHEMA",
    "CompanyBlueprintCompilationError",
    "CompanyBlueprintCompilationMode",
    "CompanyBlueprintDeploymentPlan",
    "DynamicWorkflowAuthorityDeploymentPlan",
    "SpringAuthorityReferences",
    "compile_company_blueprint_deployment_plan",
]
