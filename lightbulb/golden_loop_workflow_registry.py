"""Canonical workflow identities for Golden Operating Loop projections.

The registry is a pure, metadata-sealed SDK contract. It proves that a loop
manifest names one declared workflow, runtime adapter, and surface mapping.
Its binding digest is not a deployed-artifact digest. It does not prove that
the adapter is deployed, authorize a run, or certify a business outcome; those
remain Spring/operator responsibilities.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, Iterable, Literal

from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.golden_loops import (
    LoopCertificationManifest,
    LoopSurface,
    OpaqueRef,
    PortableRef,
)
from lightbulb.golden_loop_projections import GoldenLoopProjectionParticipation


GOLDEN_LOOP_WORKFLOW_REGISTRY_SCHEMA = (
    "lightbulb.golden_loop_workflow_registry.v1"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

GoldenLoopRuntimeOwner = Literal[
    "spring_autocompany_kernel",
    "spring_dynamic_workflow",
    "spring_hosted_lifecycle",
]


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


def _unique(values: tuple[Any, ...], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


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


class GoldenLoopWorkflowBindingError(ValueError):
    """Raised when a loop is not an exact projection of its registry entry."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class GoldenLoopWorkflowSurfaceEntrypoint(_StrictModel):
    surface: LoopSurface
    entrypoint_ref: OpaqueRef
    participation: GoldenLoopProjectionParticipation = (
        GoldenLoopProjectionParticipation.CALLABLE
    )
    blocker_code: PortableRef | None = None

    @field_validator("surface", mode="before")
    @classmethod
    def _surface_enum(cls, value: Any) -> Any:
        return _enum_value(value, LoopSurface)

    @field_validator("participation", mode="before")
    @classmethod
    def _participation_enum(cls, value: Any) -> Any:
        return _enum_value(value, GoldenLoopProjectionParticipation)

    @model_validator(mode="after")
    def _participation_is_explicit(self) -> Self:
        callable_projection = (
            self.participation is GoldenLoopProjectionParticipation.CALLABLE
        )
        if callable_projection != (self.blocker_code is None):
            raise ValueError(
                "candidate-only and blocked surfaces require an exact blocker_code; "
                "callable surfaces must not declare one"
            )
        blocked_ref = (
            f"blocked:{self.blocker_code}" if self.blocker_code is not None else None
        )
        if self.participation is GoldenLoopProjectionParticipation.BLOCKED:
            if self.entrypoint_ref != blocked_ref:
                raise ValueError(
                    "blocked surfaces must use entrypoint_ref=blocked:<blocker_code>"
                )
        elif self.entrypoint_ref.startswith("blocked:"):
            raise ValueError("only blocked surfaces may use a blocked: entrypoint_ref")
        return self


class GoldenLoopWorkflowRegistryEntry(_StrictModel):
    loop_ref: PortableRef
    loop_version: str = Field(
        min_length=5,
        max_length=80,
        pattern=_SEMVER_RE.pattern,
    )
    # Certification declarations may add stricter evidence/metric contracts
    # without pretending the immutable runtime protocol changed. This is the
    # exact version emitted and accepted by the canonical execution authority.
    execution_loop_version: str = Field(
        min_length=5,
        max_length=80,
        pattern=_SEMVER_RE.pattern,
    )
    workflow_ref: OpaqueRef
    workflow_version: str = Field(
        min_length=5,
        max_length=80,
        pattern=_SEMVER_RE.pattern,
    )
    runtime_owner: GoldenLoopRuntimeOwner
    runtime_adapter_ref: OpaqueRef
    runtime_adapter_source_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=100,
    )
    runtime_artifact_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    runtime_revision_ref: OpaqueRef | None = None
    runtime_artifact_identity_bound: bool = False
    surface_entrypoints: tuple[GoldenLoopWorkflowSurfaceEntrypoint, ...] = Field(
        min_length=4,
        max_length=4,
    )
    workflow_binding_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("loop_version", "execution_loop_version", "workflow_version")
    @classmethod
    def _semantic_versions(cls, value: str, info: Any) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError(f"{info.field_name} must use semantic versioning")
        return value

    @field_validator(
        "runtime_adapter_source_refs",
        "surface_entrypoints",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("runtime_artifact_digest")
    @classmethod
    def _optional_artifact_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        if not _SHA256_RE.fullmatch(clean):
            raise ValueError("runtime_artifact_digest must be lowercase SHA-256")
        return clean

    @field_validator("workflow_binding_digest")
    @classmethod
    def _optional_binding_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("workflow_binding_digest must be lowercase SHA-256")
        return clean

    def _binding_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"workflow_binding_digest"},
        )

    @model_validator(mode="after")
    def _entry_is_exact_and_binding_sealed(self) -> Self:
        _unique(
            self.runtime_adapter_source_refs,
            label="runtime adapter source references",
        )
        surfaces = tuple(item.surface for item in self.surface_entrypoints)
        _unique(surfaces, label="workflow surface entrypoints")
        if surfaces != tuple(LoopSurface):
            raise ValueError(
                "workflow surface entrypoints must use canonical Agents, SDK, MCP, "
                "and ChatGPT order"
            )
        artifact_identity_bound = self.runtime_artifact_digest is not None
        if self.runtime_artifact_identity_bound != artifact_identity_bound:
            raise ValueError(
                "runtime_artifact_identity_bound must disclose whether an immutable "
                "runtime artifact digest is declared"
            )
        if self.runtime_revision_ref is not None and not artifact_identity_bound:
            raise ValueError(
                "runtime_revision_ref cannot substitute for an immutable runtime "
                "artifact digest"
            )
        expected_digest = _stable_digest(self._binding_payload())
        if (
            self.workflow_binding_digest
            and self.workflow_binding_digest != expected_digest
        ):
            raise ValueError(
                "workflow_binding_digest does not match the exact workflow binding"
            )
        object.__setattr__(self, "workflow_binding_digest", expected_digest)
        return self

    def assert_manifest_binding(self, manifest: LoopCertificationManifest) -> None:
        """Fail unless ``manifest`` is an exact projection of this entry."""

        if (manifest.loop_ref, manifest.version) != (
            self.loop_ref,
            self.loop_version,
        ):
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_loop_version_mismatch",
                "workflow registry entry does not bind this exact Golden Loop version",
            )
        implementation = manifest.implementation
        if implementation.canonical_workflow_ref != self.workflow_ref:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_ref_mismatch",
                "Golden Loop canonical workflow differs from the registry entry",
            )
        if implementation.workflow_version != self.workflow_version:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_version_mismatch",
                "Golden Loop workflow version differs from the registry entry",
            )
        if implementation.execution_loop_version != self.execution_loop_version:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.execution_loop_version_mismatch",
                "Golden Loop execution protocol version differs from the registry entry",
            )
        if implementation.runtime_owner != self.runtime_owner:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_runtime_owner_mismatch",
                "Golden Loop runtime owner differs from the registry entry",
            )
        if implementation.runtime_adapter_ref != self.runtime_adapter_ref:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.runtime_adapter_ref_mismatch",
                "Golden Loop runtime adapter differs from the registry entry",
            )
        if implementation.source_refs != self.runtime_adapter_source_refs:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_adapter_sources_mismatch",
                "Golden Loop implementation sources differ from the registry adapter",
            )
        manifest_entrypoints = tuple(
            (
                projection.surface,
                projection.entrypoint_ref,
                projection.participation,
                projection.blocker_code,
            )
            for projection in manifest.surfaces
        )
        registry_entrypoints = tuple(
            (
                projection.surface,
                projection.entrypoint_ref,
                projection.participation.value,
                projection.blocker_code,
            )
            for projection in self.surface_entrypoints
        )
        if manifest_entrypoints != registry_entrypoints:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_surface_mapping_mismatch",
                "Golden Loop surface projections differ from the registry entry",
            )


class GoldenLoopWorkflowRegistry(_StrictModel):
    schema_id: Literal["lightbulb.golden_loop_workflow_registry.v1"] = Field(
        default=GOLDEN_LOOP_WORKFLOW_REGISTRY_SCHEMA,
        alias="schema",
    )
    entries: tuple[GoldenLoopWorkflowRegistryEntry, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    registry_digest: str = Field(
        default="",
        pattern=r"^(?:[0-9a-f]{64})?$",
    )

    @field_validator("entries", mode="before")
    @classmethod
    def _tuple_entries(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("registry_digest")
    @classmethod
    def _optional_registry_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("registry_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _registry_is_canonical_and_binding_sealed(self) -> Self:
        loop_keys = tuple((item.loop_ref, item.loop_version) for item in self.entries)
        workflow_keys = tuple(
            (item.workflow_ref, item.workflow_version) for item in self.entries
        )
        _unique(loop_keys, label="Golden Loop workflow bindings")
        _unique(workflow_keys, label="canonical workflow versions")
        if loop_keys != tuple(sorted(loop_keys)):
            raise ValueError("workflow registry entries must use canonical loop order")
        expected_digest = _stable_digest([item.to_dict() for item in self.entries])
        if self.registry_digest and self.registry_digest != expected_digest:
            raise ValueError("registry_digest does not match the exact workflow entries")
        object.__setattr__(self, "registry_digest", expected_digest)
        return self

    def get_for_loop(
        self,
        loop_ref: str,
        loop_version: str,
    ) -> GoldenLoopWorkflowRegistryEntry:
        for entry in self.entries:
            if entry.loop_ref == loop_ref and entry.loop_version == loop_version:
                return entry
        raise KeyError(
            f"canonical Golden Loop workflow is not registered: "
            f"{loop_ref}@{loop_version}"
        )

    def assert_manifest_binding(
        self,
        manifest: LoopCertificationManifest,
    ) -> GoldenLoopWorkflowRegistryEntry:
        try:
            entry = self.get_for_loop(manifest.loop_ref, manifest.version)
        except KeyError as exc:
            raise GoldenLoopWorkflowBindingError(
                "golden_loop.workflow_not_registered",
                str(exc),
            ) from exc
        entry.assert_manifest_binding(manifest)
        return entry

    def assert_manifest_set(
        self,
        manifests: Iterable[LoopCertificationManifest],
        *,
        require_exact_coverage: bool = False,
    ) -> None:
        selected = tuple(manifests)
        for manifest in selected:
            self.assert_manifest_binding(manifest)
        if require_exact_coverage:
            manifest_keys = {
                (manifest.loop_ref, manifest.version) for manifest in selected
            }
            registry_keys = {
                (entry.loop_ref, entry.loop_version) for entry in self.entries
            }
            if manifest_keys != registry_keys:
                raise GoldenLoopWorkflowBindingError(
                    "golden_loop.workflow_registry_coverage_mismatch",
                    "workflow registry must cover the exact Golden Loop manifest set",
                )


__all__ = [
    "GOLDEN_LOOP_WORKFLOW_REGISTRY_SCHEMA",
    "GoldenLoopRuntimeOwner",
    "GoldenLoopWorkflowBindingError",
    "GoldenLoopWorkflowRegistry",
    "GoldenLoopWorkflowRegistryEntry",
    "GoldenLoopWorkflowSurfaceEntrypoint",
]
