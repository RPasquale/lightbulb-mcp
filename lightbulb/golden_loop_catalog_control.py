"""Typed SDK projection of Spring's immutable Golden Loop catalog custody.

Catalog registration is content-addressed and exact-scope, but deliberately
effect-dark. It creates stable Spring catalog/declaration IDs for later
operator certification; it never certifies, deploys, or enables a loop.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.golden_loops import GoldenLoopCatalog, LoopCertificationManifest

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
    )


def _uuid(value: str, *, label: str) -> str:
    clean = str(value or "").strip().lower()
    try:
        parsed = UUID(clean)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != clean:
        raise ValueError(f"{label} must be a canonical UUID")
    return clean


def _sha256(value: str, *, label: str) -> str:
    clean = str(value or "").strip()
    if not _SHA256.fullmatch(clean):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return clean


def _timestamp(value: str, *, label: str) -> str:
    clean = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an offset")
    return clean


class GoldenLoopCatalogRegistrationRequest(_StrictModel):
    catalog: GoldenLoopCatalog

    @model_validator(mode="after")
    def _catalog_remains_dark(self) -> "GoldenLoopCatalogRegistrationRequest":
        if any(manifest.lifecycle.value != "QUARANTINED" for manifest in self.catalog.manifests):
            raise ValueError("registered Golden Loop declarations must remain QUARANTINED")
        if any(
            surface.lifecycle.value != "QUARANTINED"
            for manifest in self.catalog.manifests
            for surface in manifest.surfaces
        ):
            raise ValueError("registered Golden Loop surfaces must remain QUARANTINED")
        return self

    def to_payload(self) -> dict[str, Any]:
        # to_dict() omits optional nulls and therefore preserves the catalog's
        # content-addressed canonical form across SDK, MCP, and Spring.
        return {"catalog": self.catalog.to_dict()}


class GoldenLoopDeclarationSummary(_StrictModel):
    declaration_version_id: str
    loop_ref: str = Field(min_length=1, max_length=200)
    loop_version: str = Field(min_length=5, max_length=80)
    declaration_digest: str
    ordinal: int = Field(ge=0, le=999)

    @field_validator("declaration_version_id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _uuid(value, label="declaration_version_id")

    @field_validator("declaration_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        return _sha256(value, label="declaration_digest")


class _DarkRegistrationEnvelope(_StrictModel):
    lifecycle: Literal["QUARANTINED"]
    registration_only: Literal[True]
    certification_authorized: Literal[False]
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]


class GoldenLoopCatalogVersion(_DarkRegistrationEnvelope):
    schema_id: Literal["lightbulb.golden_loop_catalog_version.v1"] = Field(
        alias="schema"
    )
    catalog_version_id: str
    tenant_id: str
    company_id: str
    project_id: str
    catalog_digest: str
    source_digest: str
    catalog: GoldenLoopCatalog
    registered_by_user_id: str
    registered_at: str
    declaration_count: int = Field(ge=1, le=1_000)
    declarations: tuple[GoldenLoopDeclarationSummary, ...] = Field(
        min_length=1, max_length=1_000
    )
    idempotent_replay: bool | None = None

    @field_validator(
        "catalog_version_id",
        "tenant_id",
        "company_id",
        "project_id",
        "registered_by_user_id",
    )
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator("catalog_digest", "source_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("registered_at")
    @classmethod
    def _registered_at(cls, value: str) -> str:
        return _timestamp(value, label="registered_at")

    @field_validator("declarations", mode="before")
    @classmethod
    def _declaration_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _exact_catalog_binding(self) -> "GoldenLoopCatalogVersion":
        if self.catalog.catalog_digest != self.catalog_digest:
            raise ValueError("Spring catalog digest differs from the SDK catalog")
        if len(self.declarations) != self.declaration_count:
            raise ValueError("Spring declaration count differs from its exact bindings")
        if tuple(item.ordinal for item in self.declarations) != tuple(
            range(self.declaration_count)
        ):
            raise ValueError("Spring declaration bindings must use exhaustive ordinals")
        manifests = self.catalog.manifests
        for summary, manifest in zip(self.declarations, manifests, strict=True):
            if (
                summary.loop_ref != manifest.loop_ref
                or summary.loop_version != manifest.version
                or summary.declaration_digest != manifest.declaration_digest
            ):
                raise ValueError("Spring declaration binding differs from the SDK catalog")
        return self


class GoldenLoopDeclarationVersion(_DarkRegistrationEnvelope):
    schema_id: Literal["lightbulb.golden_loop_declaration_version.v1"] = Field(
        alias="schema"
    )
    declaration_version_id: str
    catalog_version_id: str
    tenant_id: str
    company_id: str
    project_id: str
    loop_ref: str = Field(min_length=1, max_length=200)
    loop_version: str = Field(min_length=5, max_length=80)
    declaration_digest: str
    source_digest: str
    declaration: LoopCertificationManifest
    ordinal: int = Field(ge=0, le=999)
    registered_by_user_id: str
    registered_at: str

    @field_validator(
        "declaration_version_id",
        "catalog_version_id",
        "tenant_id",
        "company_id",
        "project_id",
        "registered_by_user_id",
    )
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator("declaration_digest", "source_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("registered_at")
    @classmethod
    def _registered_at(cls, value: str) -> str:
        return _timestamp(value, label="registered_at")

    @model_validator(mode="after")
    def _exact_declaration_binding(self) -> "GoldenLoopDeclarationVersion":
        if (
            self.declaration.loop_ref != self.loop_ref
            or self.declaration.version != self.loop_version
            or self.declaration.declaration_digest != self.declaration_digest
            or self.declaration.lifecycle.value != "QUARANTINED"
            or any(
                surface.lifecycle.value != "QUARANTINED"
                for surface in self.declaration.surfaces
            )
        ):
            raise ValueError("Spring declaration envelope differs from its SDK declaration")
        return self


def parse_golden_loop_catalog_version(
    value: Mapping[str, Any],
) -> GoldenLoopCatalogVersion:
    return GoldenLoopCatalogVersion.model_validate(value)


def parse_golden_loop_declaration_version(
    value: Mapping[str, Any],
) -> GoldenLoopDeclarationVersion:
    return GoldenLoopDeclarationVersion.model_validate(value)


__all__ = [
    "GoldenLoopCatalogRegistrationRequest",
    "GoldenLoopCatalogVersion",
    "GoldenLoopDeclarationSummary",
    "GoldenLoopDeclarationVersion",
    "parse_golden_loop_catalog_version",
    "parse_golden_loop_declaration_version",
]
