"""Typed, fail-closed inventory contract for Lightbulb capabilities.

This module classifies repository declarations; it does not grant runtime,
connector, deployment, or certification authority.  Discovery alone can never
produce ``CERTIFIED``.  A certified entry must bind explicit retained evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, Literal, Mapping

from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.golden_loops import CapabilityLifecycleState


CAPABILITY_INVENTORY_SCHEMA = "lightbulb.capability_inventory.v1"
CAPABILITY_INVENTORY_VERSION = "1.0.0"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def stable_digest(value: Any) -> str:
    """Return a portable SHA-256 over canonical JSON."""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


class CapabilityKind(str, Enum):
    SDK_EXECUTABLE_PRIMITIVE = "sdk_executable_primitive"
    SDK_CLIENT_API = "sdk_client_api"
    SDK_PACKAGE_API = "sdk_package_api"
    DOMAIN_AGENT = "domain_agent"
    DOMAIN_AGENT_ACTION = "domain_agent_action"
    AUTOCOMPANY_WORKFLOW = "autocompany_workflow"
    WORKFLOW_CATALOG_ENTRY = "workflow_catalog_entry"
    CONNECTOR_TOOL = "connector_tool"
    CONNECTOR_PROVIDER = "connector_provider"
    MCP_TOOL = "mcp_tool"
    UI_ROUTE = "ui_route"
    CHATGPT_TOOL = "chatgpt_tool"
    CHATGPT_FEATURE = "chatgpt_feature"
    RUNTIME = "runtime"
    HARNESS_ADAPTER = "harness_adapter"
    GOLDEN_OPERATING_LOOP = "golden_operating_loop"
    COMPANY_BLUEPRINT = "company_blueprint"
    GENERATED_CONTRACT = "generated_contract"
    GENERATED_REGISTRY = "generated_registry"


class DiscoveryMethod(str, Enum):
    RUNTIME_REGISTRY = "runtime_registry"
    DECLARED_REGISTRY = "declared_registry"
    GENERATED_PROJECTION = "generated_projection"
    STATIC_SYNTAX = "static_syntax"
    GENERATED_ARTIFACT = "generated_artifact"


class CapabilitySourceRef(_StrictModel):
    path: str = Field(min_length=1, max_length=1_000)
    symbol: str | None = Field(default=None, min_length=1, max_length=1_000)
    line: int | None = Field(default=None, ge=1)
    discovery_method: DiscoveryMethod

    @field_validator("path")
    @classmethod
    def _portable_repo_path(cls, value: str) -> str:
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
            raise ValueError("source path must be a safe repository-relative path")
        return clean

    @field_validator("symbol")
    @classmethod
    def _bounded_symbol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError("source symbol must be nonblank and contain no controls")
        return clean


class CapabilityInventoryEntry(_StrictModel):
    entry_ref: str = ""
    capability_ref: str = Field(min_length=1, max_length=1_000)
    kind: CapabilityKind
    display_name: str = Field(min_length=1, max_length=1_000)
    version: str | None = Field(default=None, min_length=1, max_length=100)
    lifecycle: CapabilityLifecycleState
    classification_rationale: str = Field(min_length=1, max_length=4_000)
    discovery_method: DiscoveryMethod
    source_refs: tuple[CapabilitySourceRef, ...] = Field(min_length=1, max_length=1_000)
    certification_record_ref: str | None = Field(default=None, min_length=1, max_length=2_000)
    certification_evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=1_000)
    supporting_certified_loop_record_refs: tuple[str, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    attributes: dict[str, Any] = Field(default_factory=dict)
    entry_digest: str = ""

    @field_validator("capability_ref", "display_name", "classification_rationale")
    @classmethod
    def _bounded_text(cls, value: str) -> str:
        clean = value.strip()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError("inventory text must be nonblank and contain no controls")
        return clean

    @field_validator(
        "certification_evidence_refs",
        "supporting_certified_loop_record_refs",
        mode="before",
    )
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return tuple(value or ())

    @field_validator("certification_record_ref")
    @classmethod
    def _certification_record_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip()
        if not clean or _CONTROL_RE.search(clean):
            raise ValueError("certification_record_ref must be nonblank and contain no controls")
        return clean

    @field_validator("entry_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("entry_digest must be a lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _entry_is_closed_and_evidence_bound(self) -> Self:
        expected_ref = f"{self.kind.value}:{self.capability_ref}"
        if self.entry_ref and self.entry_ref != expected_ref:
            raise ValueError("entry_ref must be the exact kind/capability composite")
        object.__setattr__(self, "entry_ref", expected_ref)

        ordered_sources = tuple(
            sorted(
                set(self.source_refs),
                key=lambda item: (
                    item.path,
                    item.line or 0,
                    item.symbol or "",
                    item.discovery_method.value,
                ),
            )
        )
        object.__setattr__(self, "source_refs", ordered_sources)

        evidence = tuple(sorted({item.strip() for item in self.certification_evidence_refs if item.strip()}))
        object.__setattr__(self, "certification_evidence_refs", evidence)
        if self.lifecycle == CapabilityLifecycleState.CERTIFIED and not evidence:
            raise ValueError("CERTIFIED inventory entries require retained certification evidence")
        if (
            self.kind == CapabilityKind.GOLDEN_OPERATING_LOOP
            and self.lifecycle == CapabilityLifecycleState.CERTIFIED
            and self.certification_record_ref is None
        ):
            raise ValueError("CERTIFIED Golden Loops require an exact certification_record_ref")
        if self.certification_record_ref is not None and not (
            self.kind == CapabilityKind.GOLDEN_OPERATING_LOOP
            and self.lifecycle == CapabilityLifecycleState.CERTIFIED
        ):
            raise ValueError(
                "certification_record_ref is reserved for CERTIFIED Golden Loop entries"
            )

        supporting_refs = tuple(
            sorted(
                {
                    item.strip()
                    for item in self.supporting_certified_loop_record_refs
                    if item.strip()
                }
            )
        )
        object.__setattr__(self, "supporting_certified_loop_record_refs", supporting_refs)
        if self.lifecycle == CapabilityLifecycleState.SUPPORTING and not supporting_refs:
            raise ValueError(
                "SUPPORTING inventory entries require a retained certified-loop record binding"
            )
        if self.lifecycle != CapabilityLifecycleState.SUPPORTING and supporting_refs:
            raise ValueError(
                "only SUPPORTING inventory entries may bind certified-loop dependency records"
            )

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"entry_digest"},
            exclude_none=True,
        )
        expected_digest = stable_digest(payload)
        if self.entry_digest and self.entry_digest != expected_digest:
            raise ValueError("entry_digest does not match the canonical entry")
        object.__setattr__(self, "entry_digest", expected_digest)
        return self


class CapabilityInventoryCoverage(_StrictModel):
    inventory_scope: tuple[CapabilityKind, ...] = Field(min_length=1)
    source_file_digests: dict[str, str] = Field(min_length=1)
    counts_by_kind: dict[str, int]
    counts_by_lifecycle: dict[str, int]
    counts_by_discovery_method: dict[str, int]
    total_entries: int = Field(ge=1)
    coverage_statement: str = Field(min_length=1, max_length=4_000)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=100)

    @field_validator("source_file_digests")
    @classmethod
    def _source_digests(cls, value: Mapping[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for raw_path, raw_digest in value.items():
            source = CapabilitySourceRef(
                path=str(raw_path),
                discovery_method=DiscoveryMethod.STATIC_SYNTAX,
            )
            digest = str(raw_digest).strip().lower()
            if not _SHA256_RE.fullmatch(digest):
                raise ValueError("source file digests must be lowercase SHA-256")
            normalized[source.path] = digest
        return dict(sorted(normalized.items()))

    @field_validator("limitations", mode="before")
    @classmethod
    def _limitations_tuple(cls, value: Any) -> Any:
        return tuple(value or ())


class CapabilityInventory(_StrictModel):
    schema_id: Literal["lightbulb.capability_inventory.v1"] = Field(
        default=CAPABILITY_INVENTORY_SCHEMA,
        alias="schema",
    )
    version: str = CAPABILITY_INVENTORY_VERSION
    entries: tuple[CapabilityInventoryEntry, ...] = Field(min_length=1)
    coverage: CapabilityInventoryCoverage
    inventory_digest: str = ""

    @field_validator("version")
    @classmethod
    def _semantic_version(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("inventory version must use semantic versioning")
        return value

    @field_validator("inventory_digest")
    @classmethod
    def _optional_digest(cls, value: str) -> str:
        clean = value.strip().lower()
        if clean and not _SHA256_RE.fullmatch(clean):
            raise ValueError("inventory_digest must be a lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _inventory_is_complete_and_deterministic(self) -> Self:
        entries = tuple(sorted(self.entries, key=lambda item: item.entry_ref))
        if len({item.entry_ref for item in entries}) != len(entries):
            raise ValueError("inventory entry refs must be unique")
        object.__setattr__(self, "entries", entries)

        expected_kind = {item.value: 0 for item in CapabilityKind}
        expected_lifecycle = {item.value: 0 for item in CapabilityLifecycleState}
        expected_method = {item.value: 0 for item in DiscoveryMethod}
        for entry in entries:
            expected_kind[entry.kind.value] += 1
            expected_lifecycle[entry.lifecycle.value] += 1
            expected_method[entry.discovery_method.value] += 1

        if self.coverage.total_entries != len(entries):
            raise ValueError("coverage total does not match inventory entries")
        if self.coverage.counts_by_kind != expected_kind:
            raise ValueError("coverage kind counts do not match inventory entries")
        if self.coverage.counts_by_lifecycle != expected_lifecycle:
            raise ValueError("coverage lifecycle counts do not match inventory entries")
        if self.coverage.counts_by_discovery_method != expected_method:
            raise ValueError("coverage discovery counts do not match inventory entries")
        if set(self.coverage.inventory_scope) != set(CapabilityKind):
            raise ValueError("inventory scope must name every requested capability class")

        certified_loop_record_refs = {
            item.certification_record_ref
            for item in entries
            if item.kind == CapabilityKind.GOLDEN_OPERATING_LOOP
            and item.lifecycle == CapabilityLifecycleState.CERTIFIED
            and item.certification_record_ref is not None
        }
        for entry in entries:
            if entry.lifecycle != CapabilityLifecycleState.SUPPORTING:
                continue
            missing_bindings = (
                set(entry.supporting_certified_loop_record_refs)
                - certified_loop_record_refs
            )
            if missing_bindings:
                raise ValueError(
                    "SUPPORTING inventory entries must bind certification records from "
                    "CERTIFIED Golden Loops present in the same inventory"
                )

        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"inventory_digest"},
            exclude_none=True,
        )
        expected_digest = stable_digest(payload)
        if self.inventory_digest and self.inventory_digest != expected_digest:
            raise ValueError("inventory_digest does not match the canonical inventory")
        object.__setattr__(self, "inventory_digest", expected_digest)
        return self


def conservative_lifecycle(
    kind: CapabilityKind,
    *,
    declared: CapabilityLifecycleState | None = None,
    certification_evidence_refs: tuple[str, ...] = (),
    supporting_certified_loop_record_refs: tuple[str, ...] = (),
    spring_authority_verified: bool = False,
) -> CapabilityLifecycleState:
    """Classify without treating caller-authored records as Spring authority."""

    if declared == CapabilityLifecycleState.SUPPORTING:
        if supporting_certified_loop_record_refs:
            return CapabilityLifecycleState.SUPPORTING
        return CapabilityLifecycleState.QUARANTINED
    if declared is not None and declared != CapabilityLifecycleState.CERTIFIED:
        return declared
    if (
        declared == CapabilityLifecycleState.CERTIFIED
        and certification_evidence_refs
        and spring_authority_verified
    ):
        return CapabilityLifecycleState.CERTIFIED
    return CapabilityLifecycleState.QUARANTINED


def build_capability_inventory(
    entries: tuple[CapabilityInventoryEntry, ...],
    *,
    source_file_digests: Mapping[str, str],
    limitations: tuple[str, ...],
    coverage_statement: str,
) -> CapabilityInventory:
    ordered = tuple(sorted(entries, key=lambda item: item.entry_ref))
    counts_by_kind = {item.value: 0 for item in CapabilityKind}
    counts_by_lifecycle = {item.value: 0 for item in CapabilityLifecycleState}
    counts_by_discovery_method = {item.value: 0 for item in DiscoveryMethod}
    for entry in ordered:
        counts_by_kind[entry.kind.value] += 1
        counts_by_lifecycle[entry.lifecycle.value] += 1
        counts_by_discovery_method[entry.discovery_method.value] += 1
    return CapabilityInventory(
        entries=ordered,
        coverage=CapabilityInventoryCoverage(
            inventory_scope=tuple(CapabilityKind),
            source_file_digests=dict(source_file_digests),
            counts_by_kind=counts_by_kind,
            counts_by_lifecycle=counts_by_lifecycle,
            counts_by_discovery_method=counts_by_discovery_method,
            total_entries=len(ordered),
            coverage_statement=coverage_statement,
            limitations=limitations,
        ),
    )


__all__ = [
    "CAPABILITY_INVENTORY_SCHEMA",
    "CAPABILITY_INVENTORY_VERSION",
    "CapabilityInventory",
    "CapabilityInventoryCoverage",
    "CapabilityInventoryEntry",
    "CapabilityKind",
    "CapabilitySourceRef",
    "DiscoveryMethod",
    "build_capability_inventory",
    "conservative_lifecycle",
    "stable_digest",
]
