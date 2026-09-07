"""Canonical software-production request contract and composition seam.

Any Lightbulb workflow can say, in typed form: *this business objective
requires a software change; produce the bounded change in an approved
repository, prove it meets this Acceptance Contract, release it according to
this Company policy, and return verified production evidence or a typed
failure.*

This module defines that request (``SoftwareProductionRequest``), compiles it
onto the existing Project Work Packet (``project.create_work_packet``) and
immutable Dynamic Workflow ``AcceptanceCriterion`` contracts, derives the
finite ``WorkflowLimits`` and effect classification from explicit risk,
release, rollout, rollback, budget, and evidence policies, and defines the
provider-neutral child-run contract (``SoftwareProductionRunHandle``,
``SoftwareProductionReceiptSet``, ``SoftwareProductionResult``) that an
originating workflow waits on.

It carries intent, never authority: no tenant/company override, no
credential, no raw host session, no provider call, no deployment call.  The
harness is resolved by Spring under Company Execution Host Policy; merge,
staging, and production effects are separately classified and fail closed
without approval.  Terminal success is only ``production_verified`` with
independent health and business-outcome evidence.  "Code generated",
"builder complete", "PR opened", and "deployment requested" are milestones.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.dynamic_workflows import AcceptanceCriterion, WorkflowLimits
from lightbulb.growth_primitives import CreateWorkPacketInput


SOFTWARE_PRODUCTION_GOLDEN_LOOP = "software.approved_change_to_verified_production@0.1.0"
SOFTWARE_PRODUCTION_REQUEST_SCHEMA = "lightbulb.software_production_request.v1"
SOFTWARE_PRODUCTION_COMPILATION_SCHEMA = "lightbulb.software_production_compilation.v1"
SOFTWARE_PRODUCTION_RUN_HANDLE_SCHEMA = "lightbulb.software_production_run_handle.v1"
SOFTWARE_PRODUCTION_RESULT_SCHEMA = "lightbulb.software_production_result.v1"
SOFTWARE_PRODUCTION_WORKFLOW_SPEC_SCHEMA = "software-production.v1"

GENESIS_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_AUTHORITY_LIKE_KEYS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "client_secret",
    "tenant_id",
    "company_id",
    "user_id",
    "host_session",
    "session_ref",
    "session_id",
    "provider_session",
    "model_ref",
    "filesystem_path",
)
_SECRET_LIKE_VALUE_PATTERNS = (
    re.compile(r"(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(xox[abprs]-|ghp_|gho_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(Bearer|Basic) [A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"^(/|[A-Za-z]:\\|\\\\|~/)"),
)


def _reject_secret_like_text(value: str, *, label: str) -> None:
    for pattern in _SECRET_LIKE_VALUE_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"{label} must not carry credential-like material or raw filesystem paths")


def _reject_authority_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _AUTHORITY_LIKE_KEYS) and not lowered.endswith("_tokens"):
                raise ValueError(f"{path}.{key} is a credential-, session-, or authority-like field and is never accepted")
            _reject_authority_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_authority_like_payload(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _reject_secret_like_text(value, label=path)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    _reject_secret_like_text(value, label="reference")
    return value


OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN), AfterValidator(_visible_ref)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4000)]

Urgency = Literal["low", "normal", "high", "urgent"]
ChangeType = Literal["feature", "defect_fix", "refactor", "configuration", "content", "infrastructure", "dependency_update", "security_fix"]
HarnessFamily = Literal["codex", "claude_code", "claude", "cursor", "chatgpt", "lightbulb"]
HostCapability = Literal[
    "session.resume", "session.compact", "session.fork", "tools.call", "workspace.read", "workspace.write", "approval.request", "output.structured", "context.extend"
]
EvaluatorPolicy = Literal["distinct_binding", "runtime_attested_required"]
ChangeRisk = Literal["low", "medium", "high", "critical"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]
SecurityFlag = Literal["handles_credentials", "auth_or_rbac", "payment_path", "pii_processing", "external_network_egress", "infrastructure_privilege"]
ComplianceFlag = Literal["sox", "gdpr", "hipaa", "pci_dss", "soc2", "regulated_industry"]
BlastRadius = Literal["single_component", "single_service", "multi_service", "tenant_wide", "platform_wide"]
AutomationLevel = Literal["candidate_only", "pr_automation", "staging_automation", "low_risk_production_automation", "fully_supervised_production"]
Environment = Literal["preview", "staging", "production"]
ProductionApproval = Literal["not_applicable", "policy_evaluated", "human_required"]
RolloutStrategy = Literal["all_at_once", "canary", "progressive"]
RollbackStrategy = Literal["not_applicable", "manual", "automatic_on_health_breach"]
EffectKind = Literal["branch_create", "pull_request_open", "merge", "staging_deploy", "production_deploy", "rollback"]
EffectClassification = Literal["preview", "proposed_write", "approved_write"]
RunStatus = Literal[
    "request_admitted",
    "work_packet_compiled",
    "harness_selected",
    "builder_authorized",
    "change_produced",
    "independent_acceptance",
    "release_candidate_formed",
    "ci_and_policy_verified",
    "staging_verified",
    "production_release_authorized",
    "production_effect_executed",
    "production_observed",
    "production_verified",
    "rejected",
    "blocked",
    "budget_exhausted",
    "release_not_authorized",
    "deployment_failed",
    "rolled_back",
    "cancelled",
    "reconciliation_required",
]
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"production_verified", "rejected", "blocked", "budget_exhausted", "release_not_authorized", "deployment_failed", "rolled_back", "cancelled", "reconciliation_required"}
)
MILESTONE_ORDER: tuple[str, ...] = (
    "request_admitted",
    "work_packet_compiled",
    "harness_selected",
    "builder_authorized",
    "change_produced",
    "independent_acceptance",
    "release_candidate_formed",
    "ci_and_policy_verified",
    "staging_verified",
    "production_release_authorized",
    "production_effect_executed",
    "production_observed",
)
RunEvent = Literal[
    "admit", "compile_work_packet", "select_harness", "authorize_builder", "produce_change", "accept", "reject", "form_release_candidate",
    "verify_ci_and_policy", "verify_staging", "authorize_production", "execute_production", "observe_production", "verify_production",
    "block", "exhaust_budget", "deny_release", "fail_deployment", "roll_back", "cancel", "require_reconciliation",
]
_ADVANCE: dict[str, dict[str, str]] = {
    "request_admitted": {"compile_work_packet": "work_packet_compiled"},
    "work_packet_compiled": {"select_harness": "harness_selected"},
    "harness_selected": {"authorize_builder": "builder_authorized"},
    "builder_authorized": {"produce_change": "change_produced"},
    "change_produced": {"accept": "independent_acceptance", "reject": "rejected"},
    "independent_acceptance": {"form_release_candidate": "release_candidate_formed", "reject": "rejected"},
    "release_candidate_formed": {"verify_ci_and_policy": "ci_and_policy_verified"},
    "ci_and_policy_verified": {"verify_staging": "staging_verified", "authorize_production": "production_release_authorized"},
    "staging_verified": {"authorize_production": "production_release_authorized"},
    "production_release_authorized": {"execute_production": "production_effect_executed", "deny_release": "release_not_authorized", "fail_deployment": "deployment_failed"},
    "production_effect_executed": {"observe_production": "production_observed", "fail_deployment": "deployment_failed"},
    "production_observed": {"verify_production": "production_verified", "roll_back": "rolled_back"},
}
_UNIVERSAL_EVENTS: dict[str, str] = {"block": "blocked", "exhaust_budget": "budget_exhausted", "cancel": "cancelled", "require_reconciliation": "reconciliation_required"}
_AUTOMATION_RANK: dict[str, int] = {"candidate_only": 0, "pr_automation": 1, "staging_automation": 2, "low_risk_production_automation": 3, "fully_supervised_production": 4}
_RISK_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_authority_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _controlled(model: type[BaseModel]) -> Any:
    def validate(value: Any) -> Any:
        return model.model_validate(_detached(value))

    return BeforeValidator(validate)


ControlledCriterion = Annotated[AcceptanceCriterion, _controlled(AcceptanceCriterion)]


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest_without(payload: Mapping[str, Any], *fields: str) -> str:
    return _stable_digest({key: value for key, value in payload.items() if key not in fields})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sorted_unique(value: Any, *, label: str) -> Any:
    if not isinstance(value, (tuple, list)):
        return value
    items = tuple(value)
    _unique(list(items), label=label)
    return tuple(sorted(items))


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_software_production_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_software_production_digests": True})
    return _digest_without(parsed.to_dict(), field)


# --------------------------------------------------------------------------- #
# Request field groups
# --------------------------------------------------------------------------- #


class SoftwareProductionScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        from uuid import UUID

        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return value


class RequestOrigin(_StrictModel):
    originating_workflow_ref: OpaqueRef
    originating_run_ref: OpaqueRef
    originating_step_ref: OpaqueRef | None = None
    requesting_agent_ref: OpaqueRef
    idempotency_key: OpaqueRef


class ChangeObjective(_StrictModel):
    business_objective: BoundedText
    expected_outcome: BoundedText
    urgency: Urgency = "normal"
    change_type: ChangeType


class ChangeScope(_StrictModel):
    repository_binding_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    workspace_binding_ref: OpaqueRef | None = None
    included_areas: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    excluded_areas: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    source_context_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)

    @field_validator("repository_binding_refs", "source_context_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _areas_disjoint(self) -> "ChangeScope":
        if set(self.included_areas) & set(self.excluded_areas):
            raise ValueError("an area cannot be both included and excluded")
        return self


class WorkSpecification(_StrictModel):
    title: ShortText
    summary: BoundedText
    deliverables: tuple[ShortText, ...] = Field(min_length=1, max_length=100)
    dependencies: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    constraints: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("dependencies", mode="before")
    @classmethod
    def _deps(cls, value: Any) -> Any:
        return _sorted_unique(value, label="dependencies")


class AcceptanceSpecification(_StrictModel):
    criteria: tuple[ControlledCriterion, ...] = Field(min_length=1, max_length=100)
    evaluator_policy: EvaluatorPolicy = "distinct_binding"

    @model_validator(mode="after")
    def _criteria_unique(self) -> "AcceptanceSpecification":
        _unique([item.criterion_id for item in self.criteria], label="acceptance criterion ids")
        return self

    @property
    def acceptance_contract_digest(self) -> str:
        return _stable_digest([item.digest for item in self.criteria])

    @property
    def required_evidence_kinds(self) -> tuple[str, ...]:
        return tuple(sorted({kind for item in self.criteria for kind in item.required_evidence}))


class HarnessPolicy(_StrictModel):
    """Which harness families and capabilities are allowed; Spring resolves the exact host."""

    allowed_harness_families: tuple[HarnessFamily, ...] = Field(min_length=1, max_length=6)
    preferred_family: HarnessFamily | None = None
    required_capabilities: tuple[HostCapability, ...] = Field(default=("output.structured", "workspace.read", "workspace.write"), max_length=9)
    resolution: Literal["spring_execution_host_policy"] = "spring_execution_host_policy"

    @field_validator("allowed_harness_families", "required_capabilities", mode="before")
    @classmethod
    def _sorted(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _preferred_is_allowed(self) -> "HarnessPolicy":
        if self.preferred_family is not None and self.preferred_family not in self.allowed_harness_families:
            raise ValueError("preferred harness family must be an allowed family")
        return self


class RiskPolicy(_StrictModel):
    change_risk: ChangeRisk
    data_classification: DataClassification = "internal"
    security_flags: tuple[SecurityFlag, ...] = Field(default_factory=tuple, max_length=6)
    compliance_flags: tuple[ComplianceFlag, ...] = Field(default_factory=tuple, max_length=6)
    blast_radius: BlastRadius = "single_service"

    @field_validator("security_flags", "compliance_flags", mode="before")
    @classmethod
    def _sorted(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique(value, label=str(info.field_name))

    @property
    def effective_risk(self) -> ChangeRisk:
        rank = _RISK_RANK[self.change_risk]
        if self.security_flags or self.compliance_flags or self.data_classification == "restricted":
            rank = max(rank, _RISK_RANK["high"])
        if self.blast_radius in {"tenant_wide", "platform_wide"}:
            rank = max(rank, _RISK_RANK["high"])
        return ("low", "medium", "high", "critical")[rank]  # type: ignore[return-value]


class DeploymentWindow(_StrictModel):
    start_at: str
    end_at: str

    @field_validator("start_at", "end_at")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> "DeploymentWindow":
        if _parsed_timestamp(self.end_at) <= _parsed_timestamp(self.start_at):
            raise ValueError("deployment window must end after it starts")
        return self


class ReleasePolicy(_StrictModel):
    automation_level: AutomationLevel
    allowed_environments: tuple[Environment, ...] = Field(min_length=1, max_length=3)
    production_approval: ProductionApproval = "human_required"
    deployment_window: DeploymentWindow | None = None
    rollout: RolloutStrategy = "canary"
    rollback: RollbackStrategy = "automatic_on_health_breach"
    rollback_verification_required: bool = True
    required_reviewer_role_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("allowed_environments", "required_reviewer_role_refs", mode="before")
    @classmethod
    def _sorted(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _policy_is_coherent(self) -> "ReleasePolicy":
        level = self.automation_level
        production_allowed = "production" in self.allowed_environments
        if level == "candidate_only" and set(self.allowed_environments) - {"preview"}:
            raise ValueError("candidate_only permits no environment beyond preview")
        if level in {"pr_automation", "staging_automation"} and production_allowed:
            raise ValueError(f"{level} cannot allow the production environment")
        if level in {"low_risk_production_automation", "fully_supervised_production"} and not production_allowed:
            raise ValueError(f"{level} requires the production environment to be allowed")
        if production_allowed:
            if self.production_approval == "not_applicable":
                raise ValueError("production releases require policy-evaluated or human approval")
            if level == "fully_supervised_production" and self.production_approval != "human_required":
                raise ValueError("fully supervised production requires human approval")
            if self.rollback == "not_applicable":
                raise ValueError("production releases require a rollback strategy")
            if not self.rollback_verification_required:
                raise ValueError("production releases require rollback verification")
        elif self.production_approval != "not_applicable":
            raise ValueError("production approval applies only when production is allowed")
        return self


class BudgetPolicy(_StrictModel):
    max_elapsed_seconds: int = Field(default=14_400, ge=60, le=31_536_000)
    max_tokens: int = Field(default=10_000_000, ge=1_000)
    max_cost_microusd: int = Field(default=100_000_000, ge=0)
    max_build_attempts: int = Field(default=8, ge=1, le=10_000)
    max_evaluation_attempts: int = Field(default=8, ge=1, le=10_000)
    max_plan_revisions: int = Field(default=3, ge=1, le=100)
    max_tool_calls: int = Field(default=2_000, ge=1, le=1_000_000)

    def to_workflow_limits(self) -> WorkflowLimits:
        return WorkflowLimits(
            max_plan_revisions=self.max_plan_revisions,
            max_build_attempts=self.max_build_attempts,
            max_evaluation_attempts=self.max_evaluation_attempts,
            max_iterations=max(self.max_build_attempts, self.max_evaluation_attempts),
            max_elapsed_seconds=self.max_elapsed_seconds,
            max_tokens=self.max_tokens,
            max_cost_microusd=self.max_cost_microusd,
        )


class EvidenceRequirements(_StrictModel):
    branch: bool = True
    commit: bool = True
    pull_request: bool = True
    tests: bool = True
    review: bool = True
    security_scan: bool = False
    staging_verification: bool = False
    deployment_receipt: bool = False
    production_health: bool = False
    business_outcome: bool = False
    rollback_verification: bool = False

    def enabled(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, value in self.to_dict().items() if value is True))


def minimum_evidence_requirements(release: ReleasePolicy, risk: RiskPolicy) -> EvidenceRequirements:
    """The evidence floor implied by release and risk policy; requests may add, never remove."""

    production = "production" in release.allowed_environments
    staging = "staging" in release.allowed_environments or production
    return EvidenceRequirements(
        branch=True,
        commit=True,
        pull_request=release.automation_level != "candidate_only",
        tests=True,
        review=True,
        security_scan=bool(risk.security_flags) or risk.effective_risk in {"high", "critical"},
        staging_verification=staging,
        deployment_receipt=staging,
        production_health=production,
        business_outcome=production,
        rollback_verification=production and release.rollback_verification_required,
    )


class SoftwareProductionRequest(_StrictModel):
    schema_id: Literal["lightbulb.software_production_request.v1"] = Field(default=SOFTWARE_PRODUCTION_REQUEST_SCHEMA, alias="schema")
    scope: SoftwareProductionScope
    origin: RequestOrigin
    objective: ChangeObjective
    change_scope: ChangeScope
    work: WorkSpecification
    acceptance: AcceptanceSpecification
    harness_policy: HarnessPolicy
    risk: RiskPolicy
    release: ReleasePolicy
    budget: BudgetPolicy = Field(default_factory=BudgetPolicy)
    evidence: EvidenceRequirements | None = None
    requested_at: str
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("requested_at")
    @classmethod
    def _requested(cls, value: str) -> str:
        return _timestamp(value, field_name="requested_at")

    @model_validator(mode="after")
    def _request_is_exact(self, info: ValidationInfo) -> "SoftwareProductionRequest":
        effective = self.risk.effective_risk
        if self.release.automation_level == "low_risk_production_automation" and effective != "low":
            raise ValueError("low_risk_production_automation is only available to low effective-risk changes")
        if effective == "critical" and self.release.automation_level not in {"candidate_only", "fully_supervised_production"}:
            raise ValueError("critical changes allow only candidate_only or fully supervised production")
        if effective in {"high", "critical"} and "production" in self.release.allowed_environments and self.release.production_approval != "human_required":
            raise ValueError("high and critical changes require human production approval")
        floor = minimum_evidence_requirements(self.release, self.risk)
        if self.evidence is not None:
            for name, required in floor.to_dict().items():
                if required and not getattr(self.evidence, name):
                    raise ValueError(f"evidence requirement {name} cannot be removed below the policy floor")
        if self.change_scope.workspace_binding_ref is None and self.release.automation_level != "candidate_only":
            raise ValueError("automated release levels require a workspace binding reference")
        if _skip(info):
            return self
        if self.request_digest != _sealed_digest(SoftwareProductionRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self

    @property
    def effective_evidence(self) -> EvidenceRequirements:
        floor = minimum_evidence_requirements(self.release, self.risk)
        if self.evidence is None:
            return floor
        merged = {name: (value or getattr(floor, name)) for name, value in self.evidence.to_dict().items()}
        return EvidenceRequirements.model_validate(merged)


def software_production_request_digest(request: SoftwareProductionRequest | Mapping[str, Any]) -> str:
    return _sealed_digest(SoftwareProductionRequest, request, "request_digest")


def seal_software_production_request(request: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(request))
    raw["request_digest"] = software_production_request_digest(raw)
    return SoftwareProductionRequest.model_validate(raw).to_dict()


# --------------------------------------------------------------------------- #
# Compilation onto existing Work Packet / Dynamic Workflow contracts
# --------------------------------------------------------------------------- #


class ClassifiedEffect(_StrictModel):
    effect: EffectKind
    classification: EffectClassification
    approval_required: bool
    environment: Environment | None = None
    rationale: ShortText


class DynamicWorkflowStartPayload(_StrictModel):
    """Exactly the keyword arguments of ``LightbulbClient.dynamic_workflow_start`` except ``host``.

    ``host`` is resolved by Spring under Company Execution Host Policy from
    ``allowed_hosts``; the originating workflow never names the host itself.
    """

    company_ref: OpaqueRef
    project_ref: OpaqueRef
    objective: BoundedText
    acceptance_criteria: tuple[ControlledCriterion, ...] = Field(min_length=1, max_length=100)
    allowed_hosts: tuple[HarnessFamily, ...] = Field(min_length=1, max_length=6)
    acceptance_policy: EvaluatorPolicy
    workflow_spec: dict[str, Any]
    inputs: dict[str, Any]
    expected_revision: Literal[0] = 0
    idempotency_key: OpaqueRef

    def start_arguments(self, host: HarnessFamily) -> dict[str, Any]:
        if host not in self.allowed_hosts:
            raise ValueError(f"host {host} is not allowed by the harness policy")
        return {
            "company_ref": self.company_ref,
            "project_ref": self.project_ref,
            "objective": self.objective,
            "acceptance_criteria": [item.model_dump(mode="json") for item in self.acceptance_criteria],
            "host": host,
            "expected_revision": self.expected_revision,
            "idempotency_key": self.idempotency_key,
            "acceptance_policy": self.acceptance_policy,
            "workflow_spec": dict(self.workflow_spec),
            "inputs": dict(self.inputs),
        }


class LifecycleContract(_StrictModel):
    golden_loop: Literal["software.approved_change_to_verified_production@0.1.0"] = SOFTWARE_PRODUCTION_GOLDEN_LOOP
    milestones: tuple[str, ...] = MILESTONE_ORDER
    terminal_statuses: tuple[str, ...] = tuple(sorted(TERMINAL_STATUSES))
    success_status: Literal["production_verified"] = "production_verified"
    maximum_automatic_authority: AutomationLevel


class SoftwareProductionCompilation(_StrictModel):
    schema_id: Literal["lightbulb.software_production_compilation.v1"] = Field(default=SOFTWARE_PRODUCTION_COMPILATION_SCHEMA, alias="schema")
    request_digest: Sha256Digest
    scope: SoftwareProductionScope
    origin: RequestOrigin
    work_packet_input: dict[str, Any]
    work_packet_digest: Sha256Digest
    acceptance_contract: tuple[ControlledCriterion, ...] = Field(min_length=1, max_length=100)
    acceptance_contract_digest: Sha256Digest
    required_evidence_kinds: tuple[ShortText, ...] = Field(min_length=1, max_length=200)
    dynamic_workflow_start: DynamicWorkflowStartPayload
    workflow_limits: dict[str, Any]
    effective_risk: ChangeRisk
    effective_evidence: EvidenceRequirements
    effects: tuple[ClassifiedEffect, ...] = Field(min_length=1, max_length=6)
    lifecycle: LifecycleContract
    compilation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _compilation_is_exact(self, info: ValidationInfo) -> "SoftwareProductionCompilation":
        CreateWorkPacketInput.model_validate(self.work_packet_input)
        if self.work_packet_digest != _stable_digest(self.work_packet_input):
            raise ValueError("work_packet_digest must commit the exact work packet input")
        if self.acceptance_contract_digest != _stable_digest([item.digest for item in self.acceptance_contract]):
            raise ValueError("acceptance_contract_digest must commit the immutable criteria")
        if self.dynamic_workflow_start.acceptance_criteria != self.acceptance_contract:
            raise ValueError("dynamic workflow start must carry the exact acceptance contract")
        if any(item.effect == "production_deploy" and item.classification == "approved_write" for item in self.effects):
            raise ValueError("compilation can never pre-approve a production deploy")
        WorkflowLimits.model_validate(self.workflow_limits)
        if _skip(info):
            return self
        if self.compilation_digest != _sealed_digest(SoftwareProductionCompilation, self, "compilation_digest"):
            raise ValueError("compilation_digest must commit the exact compilation")
        return self


def _classify_effects(release: ReleasePolicy, effective_risk: ChangeRisk) -> tuple[ClassifiedEffect, ...]:
    level = release.automation_level
    rank = _AUTOMATION_RANK[level]
    effects: list[ClassifiedEffect] = [
        ClassifiedEffect(effect="branch_create", classification="proposed_write", approval_required=False, rationale="builder branch under the one-use harness grant"),
        ClassifiedEffect(
            effect="pull_request_open",
            classification="proposed_write" if rank >= 1 else "preview",
            approval_required=False,
            rationale="opened after independent acceptance" if rank >= 1 else "candidate_only never opens a pull request",
        ),
        ClassifiedEffect(
            effect="merge",
            classification="proposed_write" if rank >= 2 else "preview",
            approval_required=rank < 3 or effective_risk != "low",
            rationale="merge requires policy or human approval unless low-risk automation applies",
        ),
        ClassifiedEffect(
            effect="staging_deploy",
            classification="proposed_write" if rank >= 2 else "preview",
            approval_required=False if rank >= 2 else True,
            environment="staging",
            rationale="non-production deploy under staging automation policy",
        ),
        ClassifiedEffect(
            effect="production_deploy",
            classification="proposed_write" if rank >= 3 else "preview",
            approval_required=True,
            environment="production",
            rationale="production always requires policy evaluation and, above low risk, human approval; never pre-approved",
        ),
        ClassifiedEffect(
            effect="rollback",
            classification="proposed_write" if "production" in release.allowed_environments else "preview",
            approval_required=release.rollback != "automatic_on_health_breach",
            environment="production" if "production" in release.allowed_environments else None,
            rationale="rollback is an executable terminal path when production is in scope",
        ),
    ]
    return tuple(effects)


def compile_software_production_request(request: SoftwareProductionRequest | Mapping[str, Any]) -> SoftwareProductionCompilation:
    """Compile the request onto the existing Work Packet and Dynamic Workflow contracts."""

    parsed = SoftwareProductionRequest.model_validate(_detached(request))
    risk_level = {"low": "low", "medium": "medium", "high": "high", "critical": "high"}[parsed.risk.effective_risk]
    work_packet = CreateWorkPacketInput(
        title=parsed.work.title,
        implementation_objective=parsed.objective.business_objective,
        scope=[*parsed.change_scope.included_areas, *parsed.work.deliverables],
        acceptance_criteria=[item.description for item in parsed.acceptance.criteria],
        target_files=[],
        dependencies=list(parsed.work.dependencies),
        risk_level=risk_level,  # type: ignore[arg-type]
        submit_for_approval=False,
    ).model_dump(mode="json")
    evidence = parsed.effective_evidence
    effects = _classify_effects(parsed.release, parsed.risk.effective_risk)
    limits = parsed.budget.to_workflow_limits().model_dump(mode="json")
    workflow_spec = {
        "schema": SOFTWARE_PRODUCTION_WORKFLOW_SPEC_SCHEMA,
        "golden_loop": SOFTWARE_PRODUCTION_GOLDEN_LOOP,
        "request_digest": parsed.request_digest,
        "limits": limits,
        "release_policy": parsed.release.to_dict(),
        "risk": {"effective_risk": parsed.risk.effective_risk, **parsed.risk.to_dict()},
        "evidence_requirements": evidence.enabled(),
        "effects": [item.to_dict() for item in effects],
        "harness_policy": parsed.harness_policy.to_dict(),
    }
    start = {
        "company_ref": parsed.scope.company_ref,
        "project_ref": parsed.scope.project_ref,
        "objective": parsed.objective.business_objective,
        "acceptance_criteria": [item.model_dump(mode="json") for item in parsed.acceptance.criteria],
        "allowed_hosts": list(parsed.harness_policy.allowed_harness_families),
        "acceptance_policy": parsed.acceptance.evaluator_policy,
        "workflow_spec": workflow_spec,
        "inputs": {
            "originating_workflow_ref": parsed.origin.originating_workflow_ref,
            "originating_run_ref": parsed.origin.originating_run_ref,
            "originating_step_ref": parsed.origin.originating_step_ref,
            "repository_binding_refs": list(parsed.change_scope.repository_binding_refs),
            "workspace_binding_ref": parsed.change_scope.workspace_binding_ref,
            "source_context_refs": list(parsed.change_scope.source_context_refs),
            "work_specification": parsed.work.to_dict(),
        },
        "expected_revision": 0,
        "idempotency_key": parsed.origin.idempotency_key,
    }
    compilation = {
        "request_digest": parsed.request_digest,
        "scope": parsed.scope.to_dict(),
        "origin": parsed.origin.to_dict(),
        "work_packet_input": work_packet,
        "work_packet_digest": _stable_digest(work_packet),
        "acceptance_contract": [item.model_dump(mode="json") for item in parsed.acceptance.criteria],
        "acceptance_contract_digest": parsed.acceptance.acceptance_contract_digest,
        "required_evidence_kinds": list(parsed.acceptance.required_evidence_kinds),
        "dynamic_workflow_start": start,
        "workflow_limits": limits,
        "effective_risk": parsed.risk.effective_risk,
        "effective_evidence": evidence.to_dict(),
        "effects": [item.to_dict() for item in effects],
        "lifecycle": {"maximum_automatic_authority": parsed.release.automation_level},
    }
    compilation["compilation_digest"] = _sealed_digest(SoftwareProductionCompilation, compilation, "compilation_digest")
    return SoftwareProductionCompilation.model_validate(compilation)


# --------------------------------------------------------------------------- #
# Child-run composition contract
# --------------------------------------------------------------------------- #


class SoftwareProductionRunHandle(_StrictModel):
    """What an originating workflow holds while it waits on the child run."""

    schema_id: Literal["lightbulb.software_production_run_handle.v1"] = Field(default=SOFTWARE_PRODUCTION_RUN_HANDLE_SCHEMA, alias="schema")
    request_digest: Sha256Digest
    compilation_digest: Sha256Digest
    dynamic_workflow_run_ref: OpaqueRef | None = None
    execution_run_ref: OpaqueRef | None = None
    status: RunStatus
    updated_at: str
    handle_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("updated_at")
    @classmethod
    def _updated(cls, value: str) -> str:
        return _timestamp(value, field_name="updated_at")

    @model_validator(mode="after")
    def _handle_is_exact(self, info: ValidationInfo) -> "SoftwareProductionRunHandle":
        if _skip(info):
            return self
        if self.handle_digest != _sealed_digest(SoftwareProductionRunHandle, self, "handle_digest"):
            raise ValueError("handle_digest must commit the exact handle")
        return self

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES


def advance_software_production_status(current: RunStatus, event: RunEvent) -> RunStatus:
    """Deterministic lifecycle table; raises ValueError on an illegal move."""

    if current in TERMINAL_STATUSES:
        raise ValueError(f"{current} is terminal")
    if event in _UNIVERSAL_EVENTS:
        return _UNIVERSAL_EVENTS[event]  # type: ignore[return-value]
    target = _ADVANCE.get(current, {}).get(event)
    if target is None:
        raise ValueError(f"{event} is not a legal transition from {current}")
    return target  # type: ignore[return-value]


class EvidenceReceipt(_StrictModel):
    kind: Literal[
        "work_packet", "builder_result", "evaluator_verdict", "branch", "commit", "pull_request", "ci", "security_scan", "policy", "review",
        "staging", "canary", "merge_approval", "release_approval", "deployment", "production_health", "business_outcome", "rollback", "provider_grant",
    ]
    ref: OpaqueRef
    digest: Sha256Digest | None = None
    issuer_ref: OpaqueRef
    observed_at: str
    independent_of_builder: bool = True

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")


class SoftwareProductionReceiptSet(_StrictModel):
    request_digest: Sha256Digest
    compilation_digest: Sha256Digest
    work_packet_ref: OpaqueRef | None = None
    acceptance_contract_digest: Sha256Digest
    dynamic_workflow_run_ref: OpaqueRef | None = None
    execution_run_ref: OpaqueRef | None = None
    selected_harness_family: HarnessFamily | None = None
    builder_assignment_ref: OpaqueRef | None = None
    evaluator_binding_ref: OpaqueRef | None = None
    evaluator_accepted: bool | None = None
    receipts: tuple[EvidenceReceipt, ...] = Field(default_factory=tuple, max_length=200)

    def kinds(self) -> frozenset[str]:
        return frozenset(item.kind for item in self.receipts)


_STATUS_EVIDENCE: dict[str, frozenset[str]] = {
    "production_verified": frozenset({"builder_result", "evaluator_verdict", "commit", "deployment", "production_health", "business_outcome"}),
    "rolled_back": frozenset({"deployment", "rollback"}),
    "deployment_failed": frozenset({"deployment"}),
    "release_not_authorized": frozenset({"evaluator_verdict"}),
    "rejected": frozenset({"evaluator_verdict"}),
}


class SoftwareProductionResult(_StrictModel):
    """Typed terminal result the originating workflow consumes."""

    schema_id: Literal["lightbulb.software_production_result.v1"] = Field(default=SOFTWARE_PRODUCTION_RESULT_SCHEMA, alias="schema")
    handle: SoftwareProductionRunHandle
    receipt_set: SoftwareProductionReceiptSet
    terminal_status: RunStatus
    failure_reason: BoundedText | None = None
    reconciliation_required: bool = False
    production_verified: bool
    result_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _result_is_coherent(self, info: ValidationInfo) -> "SoftwareProductionResult":
        if self.terminal_status not in TERMINAL_STATUSES:
            raise ValueError("a result requires a terminal status; milestones are not results")
        if self.handle.status != self.terminal_status:
            raise ValueError("handle status must match the terminal status")
        if self.receipt_set.request_digest != self.handle.request_digest or self.receipt_set.compilation_digest != self.handle.compilation_digest:
            raise ValueError("receipt set must bind the handle's request and compilation")
        if self.production_verified != (self.terminal_status == "production_verified"):
            raise ValueError("production_verified must follow the terminal status")
        if self.reconciliation_required != (self.terminal_status == "reconciliation_required"):
            raise ValueError("reconciliation_required must follow the terminal status")
        required = _STATUS_EVIDENCE.get(self.terminal_status, frozenset())
        missing = sorted(required - self.receipt_set.kinds())
        if missing:
            raise ValueError(f"{self.terminal_status} requires evidence: {', '.join(missing)}")
        if self.terminal_status == "production_verified":
            if self.receipt_set.evaluator_accepted is not True:
                raise ValueError("production_verified requires an accepting independent evaluator verdict")
            for item in self.receipt_set.receipts:
                if item.kind in {"evaluator_verdict", "production_health", "business_outcome"} and not item.independent_of_builder:
                    raise ValueError(f"{item.kind} evidence must be independent of the builder")
        if self.terminal_status != "production_verified" and self.failure_reason is None and self.terminal_status != "cancelled":
            raise ValueError("non-success terminal results carry a failure reason")
        if _skip(info):
            return self
        if self.result_digest != _sealed_digest(SoftwareProductionResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact result")
        return self


class SoftwareProductionResultInput(_StrictModel):
    compilation: SoftwareProductionCompilation
    handle: SoftwareProductionRunHandle
    receipt_set: SoftwareProductionReceiptSet
    failure_reason: BoundedText | None = None
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "SoftwareProductionResultInput":
        if self.handle.compilation_digest != self.compilation.compilation_digest or self.handle.request_digest != self.compilation.request_digest:
            raise ValueError("handle must bind the exact compilation")
        if self.receipt_set.acceptance_contract_digest != self.compilation.acceptance_contract_digest:
            raise ValueError("receipts must bind the immutable acceptance contract")
        return self


class SoftwareProductionAssessment(_StrictModel):
    result: SoftwareProductionResult | None = None
    blockers: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    effect_boundary: dict[str, bool] = Field(default_factory=lambda: {"sdk_candidate_only": True, "provider_called": False, "deployment_executed": False, "production_success_claimed_from_receipt_alone": False})

    @model_validator(mode="after")
    def _coherent(self) -> "SoftwareProductionAssessment":
        if (self.result is None) == (not self.blockers):
            raise ValueError("an assessment carries exactly a result or blockers")
        return self


def assess_software_production_result(inputs: SoftwareProductionResultInput | Mapping[str, Any]) -> SoftwareProductionAssessment:
    """Turn a run handle and receipt set into a typed terminal result, or explain why not."""

    parsed = SoftwareProductionResultInput.model_validate(_detached(inputs))
    handle = parsed.handle
    receipts = parsed.receipt_set
    compilation = parsed.compilation
    blockers: list[str] = []
    if handle.status not in TERMINAL_STATUSES:
        blockers.append(f"run is at milestone {handle.status}; not a terminal outcome")
    if handle.status == "production_verified":
        required_evidence = compilation.effective_evidence
        kinds = receipts.kinds()
        checks = {
            "tests": "ci",
            "pull_request": "pull_request",
            "review": "review",
            "security_scan": "security_scan",
            "staging_verification": "staging",
            "deployment_receipt": "deployment",
            "production_health": "production_health",
            "business_outcome": "business_outcome",
            "rollback_verification": "rollback",
            "branch": "branch",
            "commit": "commit",
        }
        for requirement, kind in checks.items():
            if getattr(required_evidence, requirement) and kind not in kinds:
                blockers.append(f"policy requires {kind} evidence before production can be verified")
        if receipts.evaluator_accepted is not True:
            blockers.append("production cannot be verified without an accepting independent evaluator verdict")
        if receipts.selected_harness_family is not None and receipts.selected_harness_family not in compilation.dynamic_workflow_start.allowed_hosts:
            blockers.append("selected harness family is outside the harness policy")
    if blockers:
        return SoftwareProductionAssessment(blockers=tuple(blockers))
    result = {
        "handle": handle.to_dict(),
        "receipt_set": receipts.to_dict(),
        "terminal_status": handle.status,
        "failure_reason": parsed.failure_reason,
        "reconciliation_required": handle.status == "reconciliation_required",
        "production_verified": handle.status == "production_verified",
    }
    try:
        result["result_digest"] = _sealed_digest(SoftwareProductionResult, result, "result_digest")
        return SoftwareProductionAssessment(result=SoftwareProductionResult.model_validate(result))
    except Exception as exc:  # typed contract violation → blocker, never a silent success
        lines = [line.strip() for line in str(exc).splitlines() if "Value error" in line or "value_error" in line]
        detail = (lines[0].replace("Value error, ", "").split(" [type=")[0] if lines else (str(exc) or type(exc).__name__))[:300]
        return SoftwareProductionAssessment(blockers=(detail,))


# --------------------------------------------------------------------------- #
# Sync / async composition seam over the existing hosted clients
# --------------------------------------------------------------------------- #


class SoftwareProductionComposer:
    """Compile a request and hand the exact start payload to the hosted client (sync)."""

    def compile(self, request: SoftwareProductionRequest | Mapping[str, Any]) -> SoftwareProductionCompilation:
        return compile_software_production_request(request)

    def start(self, client: Any, compilation: SoftwareProductionCompilation, *, resolved_host: HarnessFamily) -> dict[str, Any]:
        """Start the hosted Dynamic Workflow through ``client.dynamic_workflow_start``.

        ``resolved_host`` must come from Spring's execution-host policy resolution,
        never from the originating workflow or the calling agent.
        """

        return client.dynamic_workflow_start(**compilation.dynamic_workflow_start.start_arguments(resolved_host))


class AsyncSoftwareProductionComposer:
    """Async twin of ``SoftwareProductionComposer`` with identical payloads."""

    def compile(self, request: SoftwareProductionRequest | Mapping[str, Any]) -> SoftwareProductionCompilation:
        return compile_software_production_request(request)

    async def start(self, client: Any, compilation: SoftwareProductionCompilation, *, resolved_host: HarnessFamily) -> dict[str, Any]:
        return await client.dynamic_workflow_start(**compilation.dynamic_workflow_start.start_arguments(resolved_host))


__all__ = [
    "MILESTONE_ORDER",
    "SOFTWARE_PRODUCTION_COMPILATION_SCHEMA",
    "SOFTWARE_PRODUCTION_GOLDEN_LOOP",
    "SOFTWARE_PRODUCTION_REQUEST_SCHEMA",
    "SOFTWARE_PRODUCTION_RESULT_SCHEMA",
    "SOFTWARE_PRODUCTION_RUN_HANDLE_SCHEMA",
    "SOFTWARE_PRODUCTION_WORKFLOW_SPEC_SCHEMA",
    "TERMINAL_STATUSES",
    "AcceptanceSpecification",
    "AsyncSoftwareProductionComposer",
    "BudgetPolicy",
    "ChangeObjective",
    "ChangeScope",
    "ClassifiedEffect",
    "DeploymentWindow",
    "DynamicWorkflowStartPayload",
    "EvidenceReceipt",
    "EvidenceRequirements",
    "HarnessPolicy",
    "LifecycleContract",
    "ReleasePolicy",
    "RequestOrigin",
    "RiskPolicy",
    "SoftwareProductionAssessment",
    "SoftwareProductionCompilation",
    "SoftwareProductionComposer",
    "SoftwareProductionReceiptSet",
    "SoftwareProductionRequest",
    "SoftwareProductionResult",
    "SoftwareProductionResultInput",
    "SoftwareProductionRunHandle",
    "SoftwareProductionScope",
    "WorkSpecification",
    "advance_software_production_status",
    "assess_software_production_result",
    "compile_software_production_request",
    "minimum_evidence_requirements",
    "seal_software_production_request",
    "software_production_request_digest",
]
