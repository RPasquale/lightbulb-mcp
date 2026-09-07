"""Resolve public workflow refs into an authenticated hosted project scope.

The resolver is deliberately a discovery adapter, not an authorization layer.
Spring remains responsible for authentication, RBAC, capabilities, and access
decisions.  This module only binds public company/project handles to the exact
tenant and actor identity already established by the local adapter.

``LightbulbClient`` does not currently expose its auth context through public
identity properties.  Callers must therefore pass the tenant ID established by
their auth setup and the authenticated actor ID their adapter already obtained
(for JWT clients, from its earlier ``/users/me`` response).  The resolver never
reads the client's private auth object or any credential.  Its fresh
``whoami()`` call is a consistency check, not a second authentication decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import re
from typing import Protocol
from uuid import UUID

from lightbulb.dynamic_workflows import DynamicWorkflowScope


_MAX_REF_LENGTH = 200
_MAX_NAME_LENGTH = 240
_MAX_DISCOVERY_ITEMS = 10_000
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class DynamicWorkflowScopeResolutionError(ValueError):
    """Raised when authenticated public scope discovery cannot resolve safely."""


class DynamicWorkflowScopeDiscoveryClient(Protocol):
    """Small client surface required by :class:`DynamicWorkflowScopeResolver`."""

    def whoami(self) -> Mapping[str, object]: ...

    def list_companies(self) -> list[Mapping[str, object]]: ...

    def list_projects(
        self,
        *,
        company_id: str | None = None,
    ) -> list[Mapping[str, object]]: ...


def _bounded_string(
    value: object,
    *,
    field_name: str,
    max_length: int,
) -> str:
    if not isinstance(value, str):
        raise DynamicWorkflowScopeResolutionError(f"{field_name} must be a string")
    clean = value.strip()
    if not clean:
        raise DynamicWorkflowScopeResolutionError(f"{field_name} must not be blank")
    if len(clean) > max_length:
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} exceeds {max_length} characters"
        )
    if _CONTROL_CHAR_RE.search(clean):
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} contains control characters"
        )
    return clean


def _canonical_uuid(value: object, *, field_name: str) -> str:
    clean = _bounded_string(value, field_name=field_name, max_length=36)
    if _UUID_RE.fullmatch(clean) is None:
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} must be a canonical UUID"
        )
    try:
        return str(UUID(clean))
    except ValueError as exc:
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} must be a canonical UUID"
        ) from exc


def _required_uuid_alias(
    value: Mapping[str, object],
    aliases: tuple[str, ...],
    *,
    field_name: str,
) -> str:
    resolved = [
        _canonical_uuid(value[alias], field_name=field_name)
        for alias in aliases
        if alias in value
    ]
    if not resolved:
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} is missing from the authenticated response"
        )
    if any(candidate != resolved[0] for candidate in resolved[1:]):
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} aliases disagree in the authenticated response"
        )
    return resolved[0]


def _required_string_field(
    value: Mapping[str, object],
    key: str,
    *,
    field_name: str,
    max_length: int,
) -> str:
    if key not in value:
        raise DynamicWorkflowScopeResolutionError(
            f"{field_name} is missing from the discovery response"
        )
    return _bounded_string(
        value[key],
        field_name=field_name,
        max_length=max_length,
    )


def _optional_string_field(
    value: Mapping[str, object],
    key: str,
    *,
    field_name: str,
    max_length: int,
) -> str | None:
    raw = value.get(key)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise DynamicWorkflowScopeResolutionError(f"{field_name} must be a string")
    if not raw.strip():
        return None
    return _bounded_string(
        raw,
        field_name=field_name,
        max_length=max_length,
    )


def _normalize_ref(value: str) -> str:
    return value.strip().lower()


def _normalize_natural_language(value: str) -> str:
    return re.sub(r"\s+", " ", value.lower()).strip()


def _slug(value: str) -> str:
    normalized = _normalize_natural_language(value)
    clean = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")
    return clean or "item"


def _java_name_uuid(value: str) -> UUID:
    """Match Java ``UUID.nameUUIDFromBytes`` (raw UTF-8 MD5, UUID v3)."""

    digest = bytearray(
        hashlib.md5(value.encode("utf-8"), usedforsecurity=False).digest()
    )
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(digest))


def canonical_dynamic_workflow_company_ref(
    *,
    tenant_id: str,
    company_id: str,
) -> str:
    """Return the rename- and key-rotation-stable public company selector."""

    tenant = _bounded_string(tenant_id, field_name="tenant_id", max_length=200)
    company = _bounded_string(company_id, field_name="company_id", max_length=200)
    return f"company:{_java_name_uuid(f'{tenant}:company:{company}').hex}"


def canonical_dynamic_workflow_project_ref(
    *,
    tenant_id: str,
    project_id: str,
) -> str:
    """Return the rename- and key-rotation-stable public project selector."""

    tenant = _bounded_string(tenant_id, field_name="tenant_id", max_length=200)
    project = _bounded_string(project_id, field_name="project_id", max_length=200)
    return f"project:{_java_name_uuid(f'{tenant}:project:{project}').hex}"


def _ensure_public_refs_do_not_expose_scope_ids(
    *,
    company_ref: str,
    project_ref: str,
    sensitive_ids: tuple[str, ...],
) -> None:
    public_values = (company_ref.lower(), project_ref.lower())
    if any(
        sensitive_id.lower() in public_value
        for sensitive_id in sensitive_ids
        for public_value in public_values
    ):
        raise DynamicWorkflowScopeResolutionError(
            "resolved public refs would expose an internal scope UUID"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DynamicWorkflowScopeResolution:
    """Immutable binding of public refs to one internal hosted checkpoint store."""

    scope: DynamicWorkflowScope
    hosted_project_id: str
    company_ref: str
    project_ref: str

    def __post_init__(self) -> None:
        hosted_project_id = _canonical_uuid(
            self.hosted_project_id,
            field_name="hosted_project_id",
        )
        company_ref = _bounded_string(
            self.company_ref,
            field_name="company_ref",
            max_length=_MAX_REF_LENGTH,
        )
        project_ref = _bounded_string(
            self.project_ref,
            field_name="project_ref",
            max_length=_MAX_REF_LENGTH,
        )
        if project_ref != self.scope.project_ref:
            raise DynamicWorkflowScopeResolutionError(
                "public project_ref must match the resolved workflow scope"
            )
        _ensure_public_refs_do_not_expose_scope_ids(
            company_ref=company_ref,
            project_ref=project_ref,
            sensitive_ids=(
                self.scope.tenant_id,
                self.scope.company_id,
                self.scope.user_id,
                hosted_project_id,
            ),
        )
        object.__setattr__(self, "hosted_project_id", hosted_project_id)
        object.__setattr__(self, "company_ref", company_ref)
        object.__setattr__(self, "project_ref", project_ref)

    def to_dict(self) -> dict[str, str]:
        """Serialize public selection handles without internal scope UUIDs."""

        return {
            "company_ref": self.company_ref,
            "project_ref": self.project_ref,
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(company_ref={self.company_ref!r}, "
            f"project_ref={self.project_ref!r})"
        )


# Readable compatibility name for callers that prefer a resolved-result noun.
ResolvedDynamicWorkflowScope = DynamicWorkflowScopeResolution


@dataclass(frozen=True, slots=True, repr=False)
class _CompanyCandidate:
    company_id: str
    public_ref: str
    normalized_slug: str | None
    normalized_name: str
    name_slug: str | None

    def matches(self, value: str) -> bool:
        normalized = _normalize_ref(value)
        return _normalize_natural_language(
            value
        ) == self.normalized_name or normalized in {
            self.normalized_slug,
            self.name_slug,
            _normalize_ref(self.public_ref),
        }


@dataclass(frozen=True, slots=True, repr=False)
class _ProjectCandidate:
    project_id: str
    public_ref: str
    normalized_name: str
    slugs: frozenset[str]
    legacy_suffix: str

    def matches(self, value: str) -> bool:
        normalized = _normalize_ref(value)
        if normalized in {self.normalized_name, _normalize_ref(self.public_ref)}:
            return True
        if normalized.startswith("project:") and normalized.endswith(
            f"-{self.legacy_suffix}"
        ):
            return True
        return any(normalized in {slug, f"project:{slug}"} for slug in self.slugs)


def _discovery_rows(value: object, *, resource_name: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise DynamicWorkflowScopeResolutionError(
            f"{resource_name} discovery must return a list"
        )
    if len(value) > _MAX_DISCOVERY_ITEMS:
        raise DynamicWorkflowScopeResolutionError(
            f"{resource_name} discovery exceeds {_MAX_DISCOVERY_ITEMS} items"
        )
    if any(not isinstance(item, Mapping) for item in value):
        raise DynamicWorkflowScopeResolutionError(
            f"{resource_name} discovery entries must be objects"
        )
    return value


class DynamicWorkflowScopeResolver:
    """Resolve public refs against authenticated SDK discovery responses.

    ``authenticated_tenant_id`` and ``authenticated_user_id`` must come from
    the adapter's trusted authenticated context, never from model/tool input.
    For JWT clients, the actor ID can be the adapter's already-fetched
    ``/users/me`` ID; the resolver checks that it remains consistent.
    """

    def __init__(
        self,
        client: DynamicWorkflowScopeDiscoveryClient,
        *,
        authenticated_tenant_id: str,
        authenticated_user_id: str,
    ) -> None:
        self._client = client
        self._tenant_id = _canonical_uuid(
            authenticated_tenant_id,
            field_name="authenticated_tenant_id",
        )
        self._user_id = _canonical_uuid(
            authenticated_user_id,
            field_name="authenticated_user_id",
        )

    def resolve(
        self,
        company_ref: str,
        project_ref: str,
    ) -> DynamicWorkflowScopeResolution:
        clean_company_ref = _bounded_string(
            company_ref,
            field_name="company_ref",
            max_length=_MAX_REF_LENGTH,
        )
        clean_project_ref = _bounded_string(
            project_ref,
            field_name="project_ref",
            max_length=_MAX_REF_LENGTH,
        )
        self._verify_authenticated_identity()
        company = self._resolve_company(clean_company_ref)
        project = self._resolve_project(company, clean_project_ref)
        scope = DynamicWorkflowScope(
            tenant_id=self._tenant_id,
            company_id=company.company_id,
            user_id=self._user_id,
            project_ref=project.public_ref,
        )
        return DynamicWorkflowScopeResolution(
            scope=scope,
            hosted_project_id=project.project_id,
            company_ref=company.public_ref,
            project_ref=project.public_ref,
        )

    def _verify_authenticated_identity(self) -> None:
        identity = self._client.whoami()
        if not isinstance(identity, Mapping):
            raise DynamicWorkflowScopeResolutionError(
                "whoami must return an authenticated identity object"
            )
        user_id = _required_uuid_alias(
            identity,
            ("id", "user_id", "userId"),
            field_name="whoami user_id",
        )
        tenant_id = _required_uuid_alias(
            identity,
            ("tenant_id", "tenantId"),
            field_name="whoami tenant_id",
        )
        if tenant_id != self._tenant_id:
            raise DynamicWorkflowScopeResolutionError(
                "whoami tenant does not match the authenticated adapter context"
            )
        if user_id != self._user_id:
            raise DynamicWorkflowScopeResolutionError(
                "whoami user does not match the authenticated adapter context"
            )

    def _resolve_company(self, company_ref: str) -> _CompanyCandidate:
        rows = _discovery_rows(
            self._client.list_companies(),
            resource_name="company",
        )
        candidates: list[_CompanyCandidate] = []
        for row in rows:
            company_id = _required_uuid_alias(
                row,
                ("id", "company_id", "companyId"),
                field_name="company id",
            )
            tenant_id = _required_uuid_alias(
                row,
                ("tenant_id", "tenantId"),
                field_name="company tenant_id",
            )
            if tenant_id != self._tenant_id:
                raise DynamicWorkflowScopeResolutionError(
                    "company discovery returned an object outside the authenticated tenant"
                )
            name = _required_string_field(
                row,
                "name",
                field_name="company name",
                max_length=_MAX_NAME_LENGTH,
            )
            slug = _optional_string_field(
                row,
                "slug",
                field_name="company slug",
                max_length=_MAX_REF_LENGTH,
            )
            public_ref = canonical_dynamic_workflow_company_ref(
                tenant_id=self._tenant_id,
                company_id=company_id,
            )
            _ensure_public_refs_do_not_expose_scope_ids(
                company_ref=public_ref,
                project_ref="safe-project-ref",
                sensitive_ids=(self._tenant_id, self._user_id, company_id),
            )
            candidates.append(
                _CompanyCandidate(
                    company_id=company_id,
                    public_ref=public_ref,
                    normalized_slug=_normalize_ref(slug) if slug else None,
                    normalized_name=_normalize_natural_language(name),
                    name_slug=_slug(name),
                )
            )

        matches = [
            candidate
            for candidate in candidates
            if candidate.matches(company_ref)
        ]
        if not matches:
            raise DynamicWorkflowScopeResolutionError(
                "company_ref does not identify an accessible company"
            )
        if len(matches) != 1:
            raise DynamicWorkflowScopeResolutionError(
                "company_ref is ambiguous among accessible companies"
            )
        return matches[0]

    def _resolve_project(
        self,
        company: _CompanyCandidate,
        project_ref: str,
    ) -> _ProjectCandidate:
        rows = _discovery_rows(
            self._client.list_projects(company_id=company.company_id),
            resource_name="project",
        )
        candidates: list[_ProjectCandidate] = []
        for row in rows:
            project_id = _required_uuid_alias(
                row,
                ("id", "project_id", "projectId"),
                field_name="project id",
            )
            tenant_id = _required_uuid_alias(
                row,
                ("tenant_id", "tenantId"),
                field_name="project tenant_id",
            )
            company_id = _required_uuid_alias(
                row,
                ("company_id", "companyId"),
                field_name="project company_id",
            )
            if tenant_id != self._tenant_id or company_id != company.company_id:
                raise DynamicWorkflowScopeResolutionError(
                    "project discovery returned an object outside the resolved company scope"
                )
            name = _required_string_field(
                row,
                "name",
                field_name="project name",
                max_length=_MAX_NAME_LENGTH,
            )
            explicit_slug = _optional_string_field(
                row,
                "slug",
                field_name="project slug",
                max_length=_MAX_REF_LENGTH,
            )
            public_ref = canonical_dynamic_workflow_project_ref(
                tenant_id=self._tenant_id,
                project_id=project_id,
            )
            _ensure_public_refs_do_not_expose_scope_ids(
                company_ref=company.public_ref,
                project_ref=public_ref,
                sensitive_ids=(
                    self._tenant_id,
                    self._user_id,
                    company.company_id,
                    project_id,
                ),
            )
            slugs = {_slug(name)}
            if explicit_slug:
                slugs.add(_normalize_ref(explicit_slug))
            candidates.append(
                _ProjectCandidate(
                    project_id=project_id,
                    public_ref=public_ref,
                    normalized_name=_normalize_ref(name),
                    slugs=frozenset(slugs),
                    legacy_suffix=_java_name_uuid(
                        f"{self._tenant_id}:project:{project_id}"
                    ).hex[:10],
                )
            )

        matches = [
            candidate
            for candidate in candidates
            if candidate.matches(project_ref)
        ]
        if not matches:
            raise DynamicWorkflowScopeResolutionError(
                "project_ref does not identify an accessible project"
            )
        if len(matches) != 1:
            raise DynamicWorkflowScopeResolutionError(
                "project_ref is ambiguous in the resolved company"
            )
        return matches[0]


def resolve_dynamic_workflow_scope(
    client: DynamicWorkflowScopeDiscoveryClient,
    company_ref: str,
    project_ref: str,
    *,
    authenticated_tenant_id: str,
    authenticated_user_id: str,
) -> DynamicWorkflowScopeResolution:
    """Resolve public handles using explicit authenticated adapter identity."""

    return DynamicWorkflowScopeResolver(
        client,
        authenticated_tenant_id=authenticated_tenant_id,
        authenticated_user_id=authenticated_user_id,
    ).resolve(company_ref, project_ref)


__all__ = [
    "canonical_dynamic_workflow_company_ref",
    "canonical_dynamic_workflow_project_ref",
    "DynamicWorkflowScopeDiscoveryClient",
    "DynamicWorkflowScopeResolution",
    "DynamicWorkflowScopeResolutionError",
    "DynamicWorkflowScopeResolver",
    "ResolvedDynamicWorkflowScope",
    "resolve_dynamic_workflow_scope",
]
