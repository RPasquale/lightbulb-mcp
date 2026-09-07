"""Typed, default-dark projection for reference-company onboarding.

The SDK owns only request/response validation. Spring remains authoritative for
tenant/company/Project scope, Tenant Connector and Tool Binding resolution,
RBAC, and every eventual state transition. This contract deliberately accepts
opaque identifiers rather than credentials and exposes no activation flags.
"""

from __future__ import annotations

import re
from hashlib import md5
from datetime import datetime
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.company_blueprint_control import CompanyBlueprintSpringVersion
from lightbulb.company_blueprints import CompanyBlueprint
from lightbulb.reference_company_blueprints import (
    AI_NATIVE_SERVICES_STUDIO_BLUEPRINT,
)

REFERENCE_COMPANY_ONBOARDING_PREVIEW_SCHEMA = (
    "lightbulb.reference_company_onboarding_preview.v2"
)
REFERENCE_COMPANY_ONBOARDING_READINESS_SCHEMA = (
    "lightbulb.reference_company_onboarding_readiness.v2"
)
REFERENCE_COMPANY_BLUEPRINT_REF = "company.ai_native_services_studio"
REFERENCE_COMPANY_BLUEPRINT_VERSION = AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.version
REFERENCE_COMPANY_BLUEPRINT_DIGEST = (
    AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.blueprint_digest
)
REFERENCE_COMPANY_GOLDEN_LOOP_REFS = tuple(
    binding.loop_ref for binding in AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.golden_loops
)
_REFERENCE_COMPANY_GOLDEN_LOOP_BINDINGS = {
    binding.loop_ref: (binding.version, binding.department_ref)
    for binding in AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.golden_loops
}
_REFERENCE_COMPANY_CONNECTOR_REQUIREMENTS = {
    requirement.requirement_ref: requirement
    for requirement in sorted(
        AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.connector_requirements,
        key=lambda item: item.requirement_ref,
    )
}
REFERENCE_COMPANY_CONNECTOR_PROVIDERS = {
    requirement_ref: requirement.provider
    for requirement_ref, requirement in _REFERENCE_COMPANY_CONNECTOR_REQUIREMENTS.items()
}
REFERENCE_COMPANY_CONNECTOR_TOOL_REFS = {
    requirement_ref: tuple(sorted(requirement.required_tool_refs))
    for requirement_ref, requirement in _REFERENCE_COMPANY_CONNECTOR_REQUIREMENTS.items()
}
REFERENCE_COMPANY_CONNECTOR_CATALOG_NAMES = {
    "signing": "docusign",
    "gmail": "gmail",
    "quickbooks": "quickbooks_accounting",
    "stripe": "stripe_payments",
    "xero": "xero_accounting",
    "freshservice": "freshservice",
}
REFERENCE_COMPANY_CODING_HARNESSES = tuple(
    sorted(AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.execution_host_policy.allowed_harnesses)
)
REFERENCE_COMPANY_LOOP_READ_PERMISSIONS = {
    "finance.contract_to_cash_collected_cash": (
        ("contract-to-cash.run.read", ("TARGET_COMPANY",)),
    ),
    "finance.journal_post_readback_settlement": (
        ("connectors.reconcile.view", ("TARGET_COMPANY",)),
    ),
    "finance.period_reconciliation_approved_close_candidate": (
        ("economic-spine.run.read", ("TARGET_COMPANY",)),
        ("finance.period-reconciliation.source.read", ("TARGET_COMPANY",)),
    ),
    "procurement.approved_commitment_to_matched_close": (
        ("economic-spine.run.read", ("TARGET_COMPANY",)),
        ("procurement.golden-loop.source.read", ("TARGET_COMPANY",)),
    ),
    "project.work_packet_independent_acceptance": (
        ("dynamic_workflow.read", ("TENANT",)),
    ),
    "revenue.governed_crm_turn_verified_reply": (),
    "service.case_customer_verified_resolution": (
        ("connectors.reconcile.view", ("TARGET_COMPANY",)),
    ),
    "workflow.verified_evidence_to_publish_approval": (
        ("economic-spine.run.read", ("TARGET_COMPANY",)),
        ("workflow_improvements.read", ("TARGET_COMPANY", "GLOBAL")),
    ),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_REF = {
    kind: re.compile(rf"^{re.escape(kind)}:[0-9a-f]{{32}}$")
    for kind in ("company", "project", "blueprint-version", "tenant-connector")
}


class ReferenceCompanyMaterializationError(RuntimeError):
    """A staged SDK composition failed after zero or more authoritative writes.

    The message intentionally identifies only the failed stage. Exact retained
    identities remain available as attributes for an idempotent retry or an
    authenticated read; they are never treated as deployment authority.
    """

    def __init__(
        self,
        stage: Literal["project", "blueprint_version", "onboarding_preview"],
        *,
        project_id: str | None = None,
        blueprint_version_id: str | None = None,
    ) -> None:
        super().__init__(f"Reference company materialization failed at {stage}")
        self.stage = stage
        self.project_id = project_id
        self.blueprint_version_id = blueprint_version_id


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def _uuid(value: str, *, label: str) -> str:
    clean = str(value or "").strip().lower()
    try:
        parsed = UUID(clean)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != clean:
        raise ValueError(f"{label} must be a canonical UUID")
    return clean


def _tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _timestamp(value: str, *, label: str) -> str:
    clean = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an offset")
    return clean


def _exact_public_ref(value: str, *, kind: str, label: str) -> str:
    clean = str(value or "")
    pattern = _PUBLIC_REF.get(kind)
    if pattern is None or clean != clean.strip() or not pattern.fullmatch(clean):
        raise ValueError(f"{label} must be an exact {kind} public reference")
    return clean


def reference_company_public_ref(
    kind: Literal["company", "project", "blueprint-version", "tenant-connector"],
    *,
    tenant_id: str,
    object_id: str,
) -> str:
    """Recompute Spring's rename-stable tenant-scoped public reference."""

    tenant = _uuid(tenant_id, label="tenant_id")
    object_ref = _uuid(object_id, label="object_id")
    digest = bytearray(
        md5(
            f"{tenant}:{kind}:{object_ref}".encode(),
            usedforsecurity=False,
        ).digest()
    )
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return f"{kind}:{UUID(bytes=bytes(digest)).hex}"


class ReferenceCompanyBlueprintSelection(_StrictModel):
    blueprint_version_ref: str
    blueprint_ref: Literal["company.ai_native_services_studio"]
    blueprint_version: str = Field(min_length=1, max_length=100)
    blueprint_digest: str
    declared_lifecycle: Literal["QUARANTINED"]

    @field_validator("blueprint_version_ref")
    @classmethod
    def _version_ref(cls, value: str) -> str:
        return _exact_public_ref(
            value,
            kind="blueprint-version",
            label="blueprint_version_ref",
        )

    @field_validator("blueprint_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _SHA256.fullmatch(clean):
            raise ValueError("blueprint_digest must be lowercase SHA-256")
        return clean

    @model_validator(mode="after")
    def _exact_reference_declaration(self) -> "ReferenceCompanyBlueprintSelection":
        if self.blueprint_version != REFERENCE_COMPANY_BLUEPRINT_VERSION:
            raise ValueError(
                "blueprint_version does not match the immutable reference declaration"
            )
        if self.blueprint_digest != REFERENCE_COMPANY_BLUEPRINT_DIGEST:
            raise ValueError(
                "blueprint_digest does not match the immutable reference declaration"
            )
        return self


class ReferenceCompanyGoldenLoopSelection(_StrictModel):
    loop_ref: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)
    department_ref: str = Field(min_length=1, max_length=240)
    declared_lifecycle: Literal["QUARANTINED"]

    @field_validator("loop_ref")
    @classmethod
    def _canonical_loop_ref(cls, value: str) -> str:
        if value not in REFERENCE_COMPANY_GOLDEN_LOOP_REFS:
            raise ValueError("loop_ref is not bound by the reference Company Blueprint")
        return value

    @model_validator(mode="after")
    def _exact_loop_binding(self) -> "ReferenceCompanyGoldenLoopSelection":
        expected_version, expected_department = (
            _REFERENCE_COMPANY_GOLDEN_LOOP_BINDINGS[self.loop_ref]
        )
        if self.version != expected_version:
            raise ValueError("loop version does not match the reference Company Blueprint")
        if self.department_ref != expected_department:
            raise ValueError(
                "loop department does not match the reference Company Blueprint"
            )
        return self


class ReferenceCompanyConnectorSelection(_StrictModel):
    requirement_ref: str = Field(min_length=1, max_length=200)
    provider: str = Field(min_length=1, max_length=100)
    tenant_connector_ref: str
    connector_name: str = Field(min_length=1, max_length=240)
    required_tool_refs: tuple[str, ...]
    missing_tool_refs: tuple[str, ...]
    connector_connected: bool
    provider_matched: bool
    all_required_tools_bound: bool
    credential_custody_ready: bool
    credential_material_returned: Literal[False]

    @field_validator(
        "required_tool_refs",
        "missing_tool_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("tenant_connector_ref")
    @classmethod
    def _connector_ref(cls, value: str) -> str:
        return _exact_public_ref(
            value,
            kind="tenant-connector",
            label="tenant_connector_ref",
        )

    @model_validator(mode="after")
    def _selection_is_coherent(self) -> "ReferenceCompanyConnectorSelection":
        expected_provider = REFERENCE_COMPANY_CONNECTOR_PROVIDERS.get(
            self.requirement_ref
        )
        if expected_provider is None:
            raise ValueError(
                "requirement_ref is not bound by the reference Company Blueprint"
            )
        if self.provider != expected_provider:
            raise ValueError("connector provider does not match requirement_ref")
        if self.connector_name != REFERENCE_COMPANY_CONNECTOR_CATALOG_NAMES[
            self.provider
        ]:
            raise ValueError("connector_name does not match the provider catalog")
        if self.required_tool_refs != REFERENCE_COMPANY_CONNECTOR_TOOL_REFS[
            self.requirement_ref
        ]:
            raise ValueError(
                "required_tool_refs do not match the reference Company Blueprint"
            )
        if len(set(self.missing_tool_refs)) != len(self.missing_tool_refs):
            raise ValueError("missing_tool_refs must be unique")
        if not set(self.missing_tool_refs).issubset(self.required_tool_refs):
            raise ValueError("missing_tool_refs must be required Tool refs")
        expected_bound = (
            self.connector_connected and self.provider_matched and not self.missing_tool_refs
        )
        if self.all_required_tools_bound != expected_bound:
            raise ValueError("all_required_tools_bound is inconsistent")
        return self


class ReferenceCompanyCodingHarnessSelection(_StrictModel):
    selected_harness: str | None = Field(default=None, min_length=1, max_length=80)
    allowed_harnesses: tuple[str, ...]
    selection_recorded_in_preview: bool
    host_binding_created: Literal[False]
    access_surface_independent: Literal[True]
    live_session_identifier_accepted: Literal[False]

    @field_validator("allowed_harnesses", mode="before")
    @classmethod
    def _allowed_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _harness_is_coherent(self) -> "ReferenceCompanyCodingHarnessSelection":
        if self.allowed_harnesses != REFERENCE_COMPANY_CODING_HARNESSES:
            raise ValueError(
                "allowed_harnesses must match the exact reference Company Blueprint"
            )
        if (
            self.selected_harness is not None
            and self.selected_harness not in REFERENCE_COMPANY_CODING_HARNESSES
        ):
            raise ValueError("selected_harness is not allowed by the Company Blueprint")
        if self.selection_recorded_in_preview != (self.selected_harness is not None):
            raise ValueError("selection_recorded_in_preview is inconsistent")
        return self


class ReferenceCompanyOnboardingAuthority(_StrictModel):
    exact_scope_validated: Literal[True]
    connector_bindings_verified: bool
    connector_credential_custody_verified: bool
    connector_setup_performed: Literal[False]
    credential_material_accepted: Literal[False]
    schedules_enabled: Literal[False]
    external_effects_enabled: Literal[False]
    host_binding_created: Literal[False]
    deployment_authorized: Literal[False]
    certification_claimed: Literal[False]
    gtm_visible: Literal[False]


class ReferenceCompanyOnboardingPreview(_StrictModel):
    """Read-only Spring projection; it is never an activation receipt."""

    schema_id: Literal["lightbulb.reference_company_onboarding_preview.v2"] = Field(
        alias="schema"
    )
    company_ref: str
    project_ref: str
    blueprint: ReferenceCompanyBlueprintSelection
    golden_loops: tuple[ReferenceCompanyGoldenLoopSelection, ...]
    connector_selections: tuple[ReferenceCompanyConnectorSelection, ...]
    coding_harness: ReferenceCompanyCodingHarnessSelection
    authority: ReferenceCompanyOnboardingAuthority
    blocker_codes: tuple[str, ...]
    evaluated_at: str

    @field_validator("company_ref")
    @classmethod
    def _company_ref(cls, value: str) -> str:
        return _exact_public_ref(value, kind="company", label="company_ref")

    @field_validator("project_ref")
    @classmethod
    def _project_ref(cls, value: str) -> str:
        return _exact_public_ref(value, kind="project", label="project_ref")

    @field_validator("golden_loops", "connector_selections", "blocker_codes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @model_validator(mode="after")
    def _preview_is_coherent(self) -> "ReferenceCompanyOnboardingPreview":
        loop_refs = tuple(loop.loop_ref for loop in self.golden_loops)
        if loop_refs != REFERENCE_COMPANY_GOLDEN_LOOP_REFS:
            raise ValueError("golden_loops must be exactly the canonical reference portfolio")
        connector_refs = tuple(item.requirement_ref for item in self.connector_selections)
        if connector_refs != tuple(REFERENCE_COMPANY_CONNECTOR_PROVIDERS):
            raise ValueError("connector_selections must exactly cover the reference company")
        if self.authority.connector_bindings_verified != all(
            item.all_required_tools_bound for item in self.connector_selections
        ):
            raise ValueError("connector_bindings_verified is inconsistent")
        if self.authority.connector_credential_custody_verified != all(
            item.credential_custody_ready for item in self.connector_selections
        ):
            raise ValueError("connector_credential_custody_verified is inconsistent")
        if not self.blocker_codes or len(set(self.blocker_codes)) != len(self.blocker_codes):
            raise ValueError("blocker_codes must be non-empty and unique")
        required_blockers = {
            "COMPANY_BLUEPRINT_QUARANTINED",
            "GOLDEN_LOOPS_UNCERTIFIED",
            "PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED",
        }
        if not required_blockers.issubset(self.blocker_codes):
            raise ValueError("default-dark authority blockers must be disclosed")
        if self.coding_harness.selected_harness is None and (
            "CODING_HARNESS_NOT_SELECTED" not in self.blocker_codes
        ):
            raise ValueError("an omitted coding harness must remain blocked")
        expected_custody_blockers = {
            f"CONNECTOR_CREDENTIAL_CUSTODY_NOT_READY:{item.requirement_ref}"
            for item in self.connector_selections
            if not item.credential_custody_ready
        }
        actual_custody_blockers = {
            blocker
            for blocker in self.blocker_codes
            if blocker.startswith("CONNECTOR_CREDENTIAL_CUSTODY_NOT_READY:")
        }
        if actual_custody_blockers != expected_custody_blockers:
            raise ValueError("connector credential custody blockers are inconsistent")
        return self


class ReferenceCompanyConnectorCandidate(_StrictModel):
    """One secret-free Spring-custodied connector choice."""

    tenant_connector_ref: str
    display_name: str = Field(min_length=1, max_length=240)
    connector_name: str = Field(min_length=1, max_length=240)
    missing_tool_refs: tuple[str, ...]
    connector_connected: bool
    all_required_tools_bound: bool
    credential_custody_ready: bool
    default_connector: bool
    credential_material_returned: Literal[False]

    @field_validator("missing_tool_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("tenant_connector_ref")
    @classmethod
    def _connector_ref(cls, value: str) -> str:
        return _exact_public_ref(
            value,
            kind="tenant-connector",
            label="tenant_connector_ref",
        )

    @field_validator("missing_tool_refs")
    @classmethod
    def _missing_tools(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or value != value.strip() for value in values):
            raise ValueError("missing_tool_refs must contain exact non-empty values")
        if len(set(values)) != len(values):
            raise ValueError("missing_tool_refs must be unique")
        return values


class ReferenceCompanyConnectorRequirementReadiness(_StrictModel):
    requirement_ref: str = Field(min_length=1, max_length=200)
    provider: str = Field(min_length=1, max_length=100)
    required_tool_refs: tuple[str, ...]
    candidates: tuple[ReferenceCompanyConnectorCandidate, ...]

    @field_validator("required_tool_refs", "candidates", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _exact_requirement(self) -> "ReferenceCompanyConnectorRequirementReadiness":
        expected_provider = REFERENCE_COMPANY_CONNECTOR_PROVIDERS.get(
            self.requirement_ref
        )
        if expected_provider is None or self.provider != expected_provider:
            raise ValueError("connector readiness requirement is not canonical")
        expected_tools = REFERENCE_COMPANY_CONNECTOR_TOOL_REFS[self.requirement_ref]
        if self.required_tool_refs != expected_tools:
            raise ValueError(
                "required_tool_refs do not match the reference Company Blueprint"
            )
        candidate_ids = tuple(
            candidate.tenant_connector_ref for candidate in self.candidates
        )
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("connector readiness candidates must be unique")
        for candidate in self.candidates:
            if candidate.connector_name != REFERENCE_COMPANY_CONNECTOR_CATALOG_NAMES[
                self.provider
            ]:
                raise ValueError("connector_name does not match the provider catalog")
            if not set(candidate.missing_tool_refs).issubset(expected_tools):
                raise ValueError("missing_tool_refs must be required Tool refs")
            expected_bound = (
                candidate.connector_connected
                and not candidate.missing_tool_refs
            )
            if candidate.all_required_tools_bound != expected_bound:
                raise ValueError("all_required_tools_bound is inconsistent")
        return self


class ReferenceCompanyPermissionCheck(_StrictModel):
    permission_name: str = Field(min_length=1, max_length=200)
    authority_scope: Literal["TARGET_COMPANY", "TENANT", "GLOBAL"]
    granted: bool


class ReferenceCompanyGoldenLoopReadAuthorization(_StrictModel):
    loop_ref: str = Field(min_length=1, max_length=200)
    permission_checks: tuple[ReferenceCompanyPermissionCheck, ...]
    read_authorized: bool

    @field_validator("permission_checks", mode="before")
    @classmethod
    def _checks_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _exact_read_contract(self) -> "ReferenceCompanyGoldenLoopReadAuthorization":
        expected = REFERENCE_COMPANY_LOOP_READ_PERMISSIONS.get(self.loop_ref)
        if expected is None:
            raise ValueError("loop_ref is not bound by the reference Company Blueprint")
        actual = tuple(
            (check.permission_name, check.authority_scope)
            for check in self.permission_checks
        )
        if len(actual) != len(set(actual)):
            raise ValueError("permission_checks must be unique")
        if len(actual) != len(expected):
            raise ValueError("permission_checks do not match the Golden Loop read contract")
        for check, (permission_name, allowed_scopes) in zip(
            self.permission_checks,
            expected,
            strict=True,
        ):
            if (
                check.permission_name != permission_name
                or check.authority_scope not in allowed_scopes
            ):
                raise ValueError(
                    "permission_checks do not match the Golden Loop read contract"
                )
        if self.read_authorized != all(
            check.granted for check in self.permission_checks
        ):
            raise ValueError("read_authorized is inconsistent")
        return self


class ReferenceCompanyOnboardingReadiness(_StrictModel):
    """Secret-free options for one exact Project; never an activation receipt."""

    schema_id: Literal["lightbulb.reference_company_onboarding_readiness.v2"] = (
        Field(alias="schema")
    )
    company_ref: str
    project_ref: str
    project_name: str = Field(min_length=1, max_length=255)
    blueprint: ReferenceCompanyBlueprintSelection
    golden_loops: tuple[ReferenceCompanyGoldenLoopSelection, ...]
    connector_requirements: tuple[
        ReferenceCompanyConnectorRequirementReadiness, ...
    ]
    allowed_harnesses: tuple[str, ...]
    all_prerequisite_options_available: bool
    loop_read_authorizations: tuple[
        ReferenceCompanyGoldenLoopReadAuthorization, ...
    ]
    all_loop_reads_authorized: bool
    effect_dark: Literal[True]
    certification_claimed: Literal[False]
    deployment_authorized: Literal[False]
    external_effects_authorized: Literal[False]
    blocker_codes: tuple[str, ...]
    evaluated_at: str

    @field_validator("company_ref")
    @classmethod
    def _company_ref(cls, value: str) -> str:
        return _exact_public_ref(value, kind="company", label="company_ref")

    @field_validator("project_ref")
    @classmethod
    def _project_ref(cls, value: str) -> str:
        return _exact_public_ref(value, kind="project", label="project_ref")

    @field_validator(
        "golden_loops",
        "connector_requirements",
        "loop_read_authorizations",
        "allowed_harnesses",
        "blocker_codes",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @model_validator(mode="after")
    def _readiness_is_coherent(self) -> "ReferenceCompanyOnboardingReadiness":
        if tuple(loop.loop_ref for loop in self.golden_loops) != (
            REFERENCE_COMPANY_GOLDEN_LOOP_REFS
        ):
            raise ValueError(
                "golden_loops must be exactly the canonical reference portfolio"
            )
        if tuple(
            requirement.requirement_ref
            for requirement in self.connector_requirements
        ) != tuple(REFERENCE_COMPANY_CONNECTOR_PROVIDERS):
            raise ValueError(
                "connector_requirements must exactly cover the reference company"
            )
        if self.allowed_harnesses != REFERENCE_COMPANY_CODING_HARNESSES:
            raise ValueError(
                "allowed_harnesses must match the exact reference Company Blueprint"
            )
        authorization_refs = tuple(
            authorization.loop_ref
            for authorization in self.loop_read_authorizations
        )
        if authorization_refs != REFERENCE_COMPANY_GOLDEN_LOOP_REFS:
            raise ValueError(
                "loop_read_authorizations must exactly cover the reference portfolio"
            )
        all_authorized = all(
            authorization.read_authorized
            for authorization in self.loop_read_authorizations
        )
        if self.all_loop_reads_authorized != all_authorized:
            raise ValueError("all_loop_reads_authorized is inconsistent")
        available = all(
            any(
                candidate.all_required_tools_bound
                and candidate.credential_custody_ready
                for candidate in requirement.candidates
            )
            for requirement in self.connector_requirements
        )
        if self.all_prerequisite_options_available != available:
            raise ValueError("all_prerequisite_options_available is inconsistent")
        if not self.blocker_codes or len(set(self.blocker_codes)) != len(
            self.blocker_codes
        ):
            raise ValueError("blocker_codes must be non-empty and unique")
        required_blockers = {
            "COMPANY_BLUEPRINT_QUARANTINED",
            "GOLDEN_LOOPS_UNCERTIFIED",
            "PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED",
            "CONNECTOR_SELECTION_REQUIRED",
            "CODING_HARNESS_SELECTION_REQUIRED",
        }
        if not required_blockers.issubset(self.blocker_codes):
            raise ValueError("readiness must disclose every default-dark blocker")
        expected_permission_blockers = {
            f"GOLDEN_LOOP_READ_PERMISSION_REQUIRED:{authorization.loop_ref}"
            for authorization in self.loop_read_authorizations
            if not authorization.read_authorized
        }
        actual_permission_blockers = {
            blocker
            for blocker in self.blocker_codes
            if blocker.startswith("GOLDEN_LOOP_READ_PERMISSION_REQUIRED:")
        }
        if actual_permission_blockers != expected_permission_blockers:
            raise ValueError("Golden Loop read permission blockers are inconsistent")
        expected_option_blockers = {
            f"CONNECTOR_OPTION_NOT_READY:{requirement.requirement_ref}"
            for requirement in self.connector_requirements
            if not any(
                candidate.all_required_tools_bound
                and candidate.credential_custody_ready
                for candidate in requirement.candidates
            )
        }
        actual_option_blockers = {
            blocker
            for blocker in self.blocker_codes
            if blocker.startswith("CONNECTOR_OPTION_NOT_READY:")
        }
        if actual_option_blockers != expected_option_blockers:
            raise ValueError("connector option blockers are inconsistent")
        expected_custody_blockers = {
            f"CONNECTOR_CREDENTIAL_CUSTODY_NOT_READY:{requirement.requirement_ref}"
            for requirement in self.connector_requirements
            if requirement.candidates
            and not any(
                candidate.credential_custody_ready
                for candidate in requirement.candidates
            )
        }
        actual_custody_blockers = {
            blocker
            for blocker in self.blocker_codes
            if blocker.startswith("CONNECTOR_CREDENTIAL_CUSTODY_NOT_READY:")
        }
        if actual_custody_blockers != expected_custody_blockers:
            raise ValueError("connector credential custody blockers are inconsistent")
        return self


class ReferenceCompanyCandidateMaterialization(_StrictModel):
    """One real Project plus one immutable, effect-dark Blueprint candidate.

    This receipt proves only that Spring retained the Project and Blueprint
    version and evaluated the exact connector/harness onboarding request. It is
    deliberately incapable of representing certification or deployment.
    """

    schema_id: Literal[
        "lightbulb.reference_company_candidate_materialization.v1"
    ] = Field(
        default="lightbulb.reference_company_candidate_materialization.v1",
        alias="schema",
    )
    tenant_id: str
    company_id: str
    project_id: str
    project: Mapping[str, Any]
    blueprint_version: CompanyBlueprintSpringVersion
    onboarding_preview: ReferenceCompanyOnboardingPreview
    effect_dark: Literal[True] = True
    certification_claimed: Literal[False] = False
    deployment_authorized: Literal[False] = False
    schedules_enabled: Literal[False] = False
    external_effects_authorized: Literal[False] = False

    @field_validator("tenant_id", "company_id", "project_id")
    @classmethod
    def _scope_ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @model_validator(mode="after")
    def _exact_authority_chain(self) -> "ReferenceCompanyCandidateMaterialization":
        raw_project_id = self.project.get("id")
        if _uuid(str(raw_project_id or ""), label="project.id") != self.project_id:
            raise ValueError("project response does not match project_id")
        raw_company_id = self.project.get("company_id", self.project.get("companyId"))
        if raw_company_id is not None and (
            _uuid(str(raw_company_id), label="project.company_id") != self.company_id
        ):
            raise ValueError("project response does not match company_id")
        if self.onboarding_preview.blueprint.blueprint_version_ref != (
            reference_company_public_ref(
                "blueprint-version",
                tenant_id=self.tenant_id,
                object_id=self.blueprint_version.version_id,
            )
        ):
            raise ValueError("onboarding preview does not match Blueprint version")
        if self.onboarding_preview.project_ref != reference_company_public_ref(
            "project",
            tenant_id=self.tenant_id,
            object_id=self.project_id,
        ):
            raise ValueError("onboarding preview does not match Project")
        if self.onboarding_preview.company_ref != reference_company_public_ref(
            "company",
            tenant_id=self.tenant_id,
            object_id=self.company_id,
        ):
            raise ValueError("onboarding preview does not match Company")
        return self


def exact_reference_company_blueprint(
    value: CompanyBlueprint | Mapping[str, Any],
) -> CompanyBlueprint:
    """Validate the exact maintained reference declaration before any write."""

    blueprint = (
        value
        if isinstance(value, CompanyBlueprint)
        else CompanyBlueprint.model_validate(dict(value))
    )
    if (
        blueprint.blueprint_ref != REFERENCE_COMPANY_BLUEPRINT_REF
        or blueprint.version != REFERENCE_COMPANY_BLUEPRINT_VERSION
        or blueprint.blueprint_digest != REFERENCE_COMPANY_BLUEPRINT_DIGEST
        or str(getattr(blueprint.lifecycle, "value", blueprint.lifecycle))
        != "QUARANTINED"
        or blueprint.gtm_visible
    ):
        raise ValueError(
            "blueprint must be the exact immutable QUARANTINED reference company"
        )
    return blueprint


def normalize_reference_company_connector_selections(
    connector_selections: Mapping[str, str],
) -> dict[str, str]:
    """Validate and canonicalize the complete opaque connector selection."""

    if not isinstance(connector_selections, Mapping):
        raise ValueError("connector_selections must be a mapping")
    if set(connector_selections) != set(REFERENCE_COMPANY_CONNECTOR_PROVIDERS):
        raise ValueError(
            "connector_selections must exactly cover the reference Company Blueprint"
        )
    return {
        requirement_ref: _uuid(
            connector_selections[requirement_ref], label=requirement_ref
        )
        for requirement_ref in REFERENCE_COMPANY_CONNECTOR_PROVIDERS
    }


def normalize_reference_company_connector_refs(
    connector_selections: Mapping[str, str],
) -> dict[str, str]:
    """Validate the complete public-reference selection accepted by Spring."""

    if not isinstance(connector_selections, Mapping):
        raise ValueError("connector_selections must be a mapping")
    if set(connector_selections) != set(REFERENCE_COMPANY_CONNECTOR_PROVIDERS):
        raise ValueError(
            "connector_selections must exactly cover the reference Company Blueprint"
        )
    return {
        requirement_ref: _exact_public_ref(
            connector_selections[requirement_ref],
            kind="tenant-connector",
            label=requirement_ref,
        )
        for requirement_ref in REFERENCE_COMPANY_CONNECTOR_PROVIDERS
    }


def reference_company_project_id(
    project: Mapping[str, Any],
    *,
    expected_company_id: str,
) -> str:
    """Bind an authoritative Project response to the selected Company."""

    if not isinstance(project, Mapping):
        raise ValueError("Project create response must be an object")
    project_id = _uuid(str(project.get("id") or ""), label="project.id")
    company_id = project.get("company_id", project.get("companyId"))
    if company_id is not None and (
        _uuid(str(company_id), label="project.company_id")
        != _uuid(expected_company_id, label="expected_company_id")
    ):
        raise ValueError("Project create response is outside the selected Company")
    return project_id


def reference_company_onboarding_payload(
    *,
    blueprint_version_ref: str,
    project_id: str,
    connector_selections: Mapping[str, str],
    coding_harness: str | None = None,
) -> dict[str, Any]:
    """Build the only accepted secret-free, non-authorizing preview request."""

    normalized_selections = normalize_reference_company_connector_refs(
        connector_selections
    )
    if coding_harness not in (None, *REFERENCE_COMPANY_CODING_HARNESSES):
        raise ValueError(
            "coding_harness must be allowed by the reference Company Blueprint or None"
        )
    return {
        "blueprint_version_ref": _exact_public_ref(
            blueprint_version_ref,
            kind="blueprint-version",
            label="blueprint_version_ref",
        ),
        "project_id": _uuid(project_id, label="project_id"),
        "connector_selections": {
            requirement_ref: normalized_selections[requirement_ref]
            for requirement_ref in REFERENCE_COMPANY_CONNECTOR_PROVIDERS
        },
        "coding_harness": coding_harness,
    }


def parse_reference_company_onboarding_preview(
    payload: Mapping[str, Any],
    *,
    expected_blueprint_version_ref: str | None = None,
    expected_tenant_id: str | None = None,
    expected_company_id: str | None = None,
    expected_project_id: str | None = None,
) -> ReferenceCompanyOnboardingPreview:
    """Validate and optionally bind one Spring response to its exact request."""

    preview = ReferenceCompanyOnboardingPreview.model_validate(dict(payload))
    if expected_blueprint_version_ref is not None:
        expected_version = _exact_public_ref(
            expected_blueprint_version_ref,
            kind="blueprint-version",
            label="expected_blueprint_version_ref",
        )
        if preview.blueprint.blueprint_version_ref != expected_version:
            raise ValueError(
                "response blueprint_version_ref does not match the exact request"
            )
    if expected_project_id is not None:
        if expected_tenant_id is None:
            raise ValueError("expected_tenant_id is required to bind expected_project_id")
        expected_project = reference_company_public_ref(
            "project",
            tenant_id=expected_tenant_id,
            object_id=expected_project_id,
        )
        if preview.project_ref != expected_project:
            raise ValueError("response project_ref does not match the exact request")
    if expected_company_id is not None:
        if expected_tenant_id is None:
            raise ValueError("expected_tenant_id is required to bind expected_company_id")
        expected_company = reference_company_public_ref(
            "company",
            tenant_id=expected_tenant_id,
            object_id=expected_company_id,
        )
        if preview.company_ref != expected_company:
            raise ValueError("response company_ref does not match the exact request")
    return preview


def parse_reference_company_onboarding_readiness(
    payload: Mapping[str, Any],
    *,
    expected_tenant_id: str | None = None,
    expected_company_id: str | None = None,
    expected_project_id: str | None = None,
) -> ReferenceCompanyOnboardingReadiness:
    """Validate and bind one secret-free Spring readiness projection."""

    readiness = ReferenceCompanyOnboardingReadiness.model_validate(dict(payload))
    if expected_project_id is not None:
        if expected_tenant_id is None:
            raise ValueError("expected_tenant_id is required to bind expected_project_id")
        expected_project = reference_company_public_ref(
            "project",
            tenant_id=expected_tenant_id,
            object_id=expected_project_id,
        )
        if readiness.project_ref != expected_project:
            raise ValueError("response project_ref does not match the exact request")
    if expected_company_id is not None:
        if expected_tenant_id is None:
            raise ValueError("expected_tenant_id is required to bind expected_company_id")
        expected_company = reference_company_public_ref(
            "company",
            tenant_id=expected_tenant_id,
            object_id=expected_company_id,
        )
        if readiness.company_ref != expected_company:
            raise ValueError("response company_ref does not match the exact request")
    return readiness


__all__ = [
    "REFERENCE_COMPANY_BLUEPRINT_REF",
    "REFERENCE_COMPANY_BLUEPRINT_DIGEST",
    "REFERENCE_COMPANY_BLUEPRINT_VERSION",
    "REFERENCE_COMPANY_CODING_HARNESSES",
    "REFERENCE_COMPANY_CONNECTOR_PROVIDERS",
    "REFERENCE_COMPANY_CONNECTOR_CATALOG_NAMES",
    "REFERENCE_COMPANY_CONNECTOR_TOOL_REFS",
    "REFERENCE_COMPANY_GOLDEN_LOOP_REFS",
    "REFERENCE_COMPANY_LOOP_READ_PERMISSIONS",
    "REFERENCE_COMPANY_ONBOARDING_PREVIEW_SCHEMA",
    "REFERENCE_COMPANY_ONBOARDING_READINESS_SCHEMA",
    "ReferenceCompanyBlueprintSelection",
    "ReferenceCompanyCodingHarnessSelection",
    "ReferenceCompanyConnectorCandidate",
    "ReferenceCompanyConnectorRequirementReadiness",
    "ReferenceCompanyConnectorSelection",
    "ReferenceCompanyGoldenLoopSelection",
    "ReferenceCompanyGoldenLoopReadAuthorization",
    "ReferenceCompanyPermissionCheck",
    "ReferenceCompanyOnboardingAuthority",
    "ReferenceCompanyOnboardingPreview",
    "ReferenceCompanyOnboardingReadiness",
    "ReferenceCompanyCandidateMaterialization",
    "ReferenceCompanyMaterializationError",
    "exact_reference_company_blueprint",
    "normalize_reference_company_connector_selections",
    "normalize_reference_company_connector_refs",
    "parse_reference_company_onboarding_preview",
    "parse_reference_company_onboarding_readiness",
    "reference_company_project_id",
    "reference_company_onboarding_payload",
    "reference_company_public_ref",
]
