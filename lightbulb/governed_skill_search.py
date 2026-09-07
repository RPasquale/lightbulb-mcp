"""Governed default skill search and workflow-learning receipts.

This module is deliberately read-only.  It can select already governed skills,
bind the exact version used by a workflow, and describe which learning lane may
receive an immutable outcome artifact.  It cannot create, promote, publish,
train, schedule, fund, or serve a skill or model.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Protocol, Sequence
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.workflow_learning import (
    WORKFLOW_LEARNING_CANDIDATE_ATTESTED_HANDOFF_SCHEMA,
    WORKFLOW_LEARNING_LANES,
)


GOVERNED_SKILL_SEARCH_REQUEST_SCHEMA = "lightbulb.governed_skill_search_request.v1"
GOVERNED_SKILL_BINDING_SCHEMA = "lightbulb.governed_skill_binding.v1"
GOVERNED_SKILL_SEARCH_RECEIPT_SCHEMA = "lightbulb.governed_skill_search_receipt.v1"
WORKFLOW_EXECUTION_LEARNING_RECORD_SCHEMA = (
    "lightbulb.workflow_execution_learning_record.v1"
)
WORKFLOW_LEARNING_DISPOSITION_SCHEMA = "lightbulb.workflow_learning_disposition.v1"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")
# Technical verification admits a skill only to explicit shadow/pilot
# evaluation. Default execution remains business-certified/published.
_EXECUTABLE_STAGES = frozenset({"certified", "published"})
_SHADOW_STAGES = frozenset({"candidate", "verified", *_EXECUTABLE_STAGES})
_MAX_MEMORY_SKILL_SEARCH_RESPONSE_BYTES = 1_048_576
_MAX_INTERNAL_API_KEY_CHARS = 4_096
_LIFECYCLE_SCORE = {
    "candidate": 0.0,
    "verified": 0.55,
    "certified": 0.8,
    "published": 1.0,
}


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _normalized_handle(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _as_float(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _nullable_uuid(value: Any) -> tuple[bool, UUID | None]:
    if value is None or str(value).strip() == "":
        return True, None
    try:
        return True, UUID(str(value))
    except (TypeError, ValueError):
        return False, None


def _safe_evidence_refs(skill: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []

    def add(value: Any) -> None:
        candidate = str(value or "").strip()
        if candidate and _SAFE_REF_RE.fullmatch(candidate) and candidate not in refs:
            refs.append(candidate)

    for value in skill.get("source_memory_ids") or []:
        add(value)
    verification = (
        skill.get("verification_json")
        if isinstance(skill.get("verification_json"), Mapping)
        else {}
    )
    for key in (
        "evidence_refs",
        "artifact_refs",
        "receipt_ids",
        "verification_receipts",
    ):
        values = verification.get(key)
        if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
            for value in values[:16]:
                add(value)
    for key in (
        "evidence_ref",
        "artifact_ref",
        "receipt_id",
        "verification_receipt_id",
    ):
        add(verification.get(key))
    return refs[:24]


class SkillSearchMode(str, Enum):
    EXECUTABLE = "executable"
    SHADOW = "shadow"


class ExactAgentSkillScope(BaseModel):
    """Exact authenticated scope used for both search and binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    company_id: UUID
    project_id: UUID | None = None
    user_id: UUID
    agent_scope: str = Field(pattern=r"^(backbone|domain)$")
    agent_id: str = Field(min_length=1, max_length=128)
    domain_id: str | None = Field(default=None, max_length=128)

    @field_validator("agent_id", "domain_id")
    @classmethod
    def _strip_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = value.strip().lower()
        if not clean or any(ord(character) < 32 for character in clean):
            raise ValueError("agent identifiers must be non-blank printable text")
        return clean

    @model_validator(mode="after")
    def _domain_scope_is_complete(self) -> "ExactAgentSkillScope":
        if self.agent_scope == "domain" and not self.domain_id:
            raise ValueError("domain_id is required for a domain agent")
        if self.agent_scope == "backbone" and self.domain_id is not None:
            raise ValueError("backbone scope cannot carry domain_id")
        return self


class GovernedSkillSearchRequest(BaseModel):
    """Server-built search request.

    There is intentionally no ``skill_id`` or selected-skill field.  User text
    may influence relevance, but it cannot bind a specific executable skill.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=GOVERNED_SKILL_SEARCH_REQUEST_SCHEMA, alias="schema")
    scope: ExactAgentSkillScope
    task_text: str = Field(min_length=1, max_length=2_000)
    task_kind: str | None = Field(default=None, max_length=128)
    workflow_handle: str | None = Field(default=None, max_length=160)
    mode: SkillSearchMode = SkillSearchMode.EXECUTABLE
    top_k: int = Field(default=5, ge=1, le=8)

    @field_validator("task_text", "task_kind", "workflow_handle")
    @classmethod
    def _strip_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        clean = _bounded_text(value, 2_000)
        return clean or None

    def memory_query_text(self) -> str:
        parts = [
            self.task_text,
            self.task_kind,
            self.workflow_handle,
            self.scope.domain_id,
            self.scope.agent_id,
        ]
        return " ".join(str(part) for part in parts if part).strip()[:2_000]

    def memory_query_body(self) -> dict[str, Any]:
        return {
            "query_text": self.memory_query_text(),
            "top_k": min(24, max(self.top_k * 4, 12)),
            "agent_scope": self.scope.agent_scope,
            "agent_id": self.scope.agent_id,
            "domain_id": self.scope.domain_id,
            "include_shared": True,
            "lifecycle_stages": sorted(
                _SHADOW_STAGES
                if self.mode == SkillSearchMode.SHADOW
                else _EXECUTABLE_STAGES
            ),
            "min_confidence": 0.0,
            "require_template": False,
            "require_model_artifact": False,
            # Exploration belongs only to explicit shadow runs.
            "thompson": self.mode == SkillSearchMode.SHADOW,
        }


class GovernedSkillBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=GOVERNED_SKILL_BINDING_SCHEMA, alias="schema")
    skill_id: str = Field(min_length=1, max_length=255)
    skill_handle: str = Field(min_length=1, max_length=255)
    semantic_key: str = Field(min_length=1, max_length=384)
    summary: str | None = Field(default=None, max_length=500)
    objective: str | None = Field(default=None, max_length=500)
    procedure: str | None = Field(default=None, max_length=2_000)
    version: int = Field(ge=1)
    lifecycle_stage: str = Field(pattern=r"^(candidate|verified|certified|published)$")
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    executable: bool
    relevance_score: float = Field(ge=0.0, le=1.0)
    text_score: float = Field(ge=0.0, le=1.0)
    success_rate: float = Field(ge=0.0, le=1.0)
    recency_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=24)
    rationale: list[str] = Field(default_factory=list, max_length=8)


class GovernedSkillSearchReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=GOVERNED_SKILL_SEARCH_RECEIPT_SCHEMA, alias="schema")
    scope: ExactAgentSkillScope
    mode: SkillSearchMode
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected: list[GovernedSkillBinding] = Field(default_factory=list, max_length=8)
    excluded_counts: dict[str, int] = Field(default_factory=dict)
    generated_at: datetime
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class GovernedSkillSearchProvider(Protocol):
    def search(self, request: GovernedSkillSearchRequest) -> GovernedSkillSearchReceipt: ...


def _row_matches_exact_scope(
    skill: Mapping[str, Any],
    scope: ExactAgentSkillScope,
) -> bool:
    tenant_valid, tenant_id = _nullable_uuid(skill.get("tenant_id"))
    company_valid, company_id = _nullable_uuid(skill.get("company_id"))
    project_valid, project_id = _nullable_uuid(skill.get("project_id"))
    user_valid, row_user = _nullable_uuid(skill.get("user_id"))
    if not all((tenant_valid, company_valid, project_valid, user_valid)):
        return False
    if tenant_id != scope.tenant_id:
        return False
    if company_id != scope.company_id:
        return False
    if project_id != scope.project_id:
        return False
    if row_user not in {None, scope.user_id}:
        return False
    row_scope = str(skill.get("agent_scope") or "shared").strip().lower()
    row_agent = str(skill.get("agent_id") or "").strip().lower()
    row_domain = str(skill.get("domain_id") or "").strip().lower()
    if row_scope == "shared":
        return True
    if scope.agent_scope == "backbone":
        return row_scope == "backbone" and (not row_agent or row_agent == scope.agent_id)
    return bool(
        row_scope == "domain"
        and (not row_agent or row_agent == scope.agent_id)
        and (not row_domain or row_domain == scope.domain_id)
    )


def _artifact_digest(skill: Mapping[str, Any]) -> str | None:
    signature = (
        skill.get("model_signature")
        if isinstance(skill.get("model_signature"), Mapping)
        else {}
    )
    for key in ("artifact_sha256", "sha256", "digest_sha256", "model_sha256"):
        value = str(signature.get(key) or "").strip().lower()
        if _DIGEST_RE.fullmatch(value):
            return value
    verification = (
        skill.get("verification_json")
        if isinstance(skill.get("verification_json"), Mapping)
        else {}
    )
    for key in ("artifact_sha256", "package_sha256", "digest_sha256"):
        value = str(verification.get(key) or "").strip().lower()
        if _DIGEST_RE.fullmatch(value):
            return value
    return None


def _has_independent_lifecycle_evidence(skill: Mapping[str, Any]) -> bool:
    """Fail closed for legacy elevated rows without server-attested quality.

    A process receipt can improve routing, but it is not independent outcome
    verification and cannot make a skill executable by itself.
    """
    verification = (
        skill.get("verification_json")
        if isinstance(skill.get("verification_json"), Mapping)
        else {}
    )
    if verification.get("outcome_revalidation_required") is True:
        return False
    counts = verification.get("verified_outcome_counts")
    if isinstance(counts, Mapping):
        try:
            decision_count = int(counts.get("decision_count") or 0)
            success_count = int(counts.get("success_count") or 0)
            failure_count = int(counts.get("failure_count") or 0)
            deferred_count = int(counts.get("deferred_count") or 0)
        except (TypeError, ValueError):
            return False
        return bool(
            decision_count > 0
            and min(success_count, failure_count, deferred_count) >= 0
            and success_count + failure_count + deferred_count == decision_count
        )
    return False


def _binding_for_item(
    *,
    item: Mapping[str, Any],
    request: GovernedSkillSearchRequest,
) -> tuple[GovernedSkillBinding | None, str | None]:
    skill = item.get("skill") if isinstance(item.get("skill"), Mapping) else {}
    if not skill or not _row_matches_exact_scope(skill, request.scope):
        return None, "scope_mismatch"
    stage = str(skill.get("lifecycle_stage") or "").strip().lower()
    if stage not in _SHADOW_STAGES:
        return None, "lifecycle_ineligible"
    executable = stage in _EXECUTABLE_STAGES
    if request.mode == SkillSearchMode.EXECUTABLE and not executable:
        return None, "not_verified"

    skill_id = str(skill.get("id") or "").strip()
    handle = _bounded_text(skill.get("skill_handle"), 255)
    if not skill_id or not handle:
        return None, "identity_missing"
    try:
        version = max(1, int(skill.get("revision") or 1))
    except (TypeError, ValueError):
        return None, "version_invalid"
    domain = str(skill.get("domain_id") or request.scope.domain_id or "shared").lower()
    semantic_key = f"{_normalized_handle(domain)}:{_normalized_handle(handle)}"[:384]
    if not semantic_key or semantic_key.endswith(":"):
        return None, "semantic_identity_missing"

    evidence_refs = _safe_evidence_refs(skill)
    artifact_sha256 = _artifact_digest(skill)
    if executable and not _has_independent_lifecycle_evidence(skill):
        if request.mode == SkillSearchMode.EXECUTABLE:
            return None, "independent_evidence_missing"
        executable = False
    template = (
        skill.get("skill_template")
        if isinstance(skill.get("skill_template"), Mapping)
        else {}
    )
    procedure_value = (
        template.get("procedure")
        or template.get("instructions")
        or template.get("steps")
    )
    if isinstance(procedure_value, (list, tuple)):
        procedure_value = "\n".join(
            f"{index + 1}. {_bounded_text(value, 300)}"
            for index, value in enumerate(procedure_value[:20])
        )
    elif isinstance(procedure_value, Mapping):
        procedure_value = json.dumps(
            procedure_value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    summary = _bounded_text(skill.get("summary"), 500) or None
    objective = _bounded_text(skill.get("objective"), 500) or None
    procedure = str(procedure_value or "").strip()[:2_000] or None
    binding_core = {
        "schema": GOVERNED_SKILL_BINDING_SCHEMA,
        "skill_id": skill_id,
        "skill_handle": handle,
        "semantic_key": semantic_key,
        "summary": summary,
        "objective": objective,
        "procedure": procedure,
        "version": version,
        "lifecycle_stage": stage,
        "tenant_id": str(request.scope.tenant_id),
        "company_id": str(request.scope.company_id),
        "project_id": (
            str(request.scope.project_id) if request.scope.project_id else None
        ),
        "user_id": str(skill.get("user_id") or "") or None,
        "agent_scope": str(skill.get("agent_scope") or "shared").lower(),
        "agent_id": str(skill.get("agent_id") or "").lower() or None,
        "domain_id": str(skill.get("domain_id") or "").lower() or None,
        "artifact_sha256": artifact_sha256,
        "model_id": str(skill.get("model_id") or "") or None,
        "experiment_id": str(skill.get("experiment_id") or "") or None,
        "model_signature": skill.get("model_signature"),
        "skill_template": skill.get("skill_template"),
        "data_contract": skill.get("data_contract"),
        "recipes": {
            key: skill.get(key)
            for key in (
                "feature_engineering_recipe",
                "training_recipe",
                "inference_recipe",
                "outcome_recipe",
            )
        },
    }
    text_score = _as_float(item.get("text_score"))
    success_rate = _as_float(item.get("success_rate"))
    recency_score = _as_float(item.get("recency_score"))
    confidence = _as_float(skill.get("confidence"))
    service_relevance = _as_float(item.get("relevance_score"))
    evidence_score = 1.0 if evidence_refs or artifact_sha256 else 0.0
    rank_score = (
        service_relevance * 0.3
        + text_score * 0.2
        + success_rate * 0.15
        + recency_score * 0.1
        + confidence * 0.1
        + _LIFECYCLE_SCORE[stage] * 0.1
        + evidence_score * 0.05
    )
    rationale = [
        f"lifecycle:{stage}",
        f"task_text:{text_score:.3f}",
        f"success:{success_rate:.3f}",
        f"recency:{recency_score:.3f}",
    ]
    if evidence_score:
        rationale.append("evidence:present")
    if not executable:
        rationale.append("binding:shadow_only")
    return (
        GovernedSkillBinding(
            skill_id=skill_id,
            skill_handle=handle,
            semantic_key=semantic_key,
            summary=summary,
            objective=objective,
            procedure=procedure,
            version=version,
            lifecycle_stage=stage,
            binding_sha256=_canonical_digest(binding_core),
            artifact_sha256=artifact_sha256,
            executable=executable,
            relevance_score=max(0.0, min(1.0, rank_score)),
            text_score=text_score,
            success_rate=success_rate,
            recency_score=recency_score,
            confidence=confidence,
            evidence_refs=evidence_refs,
            rationale=rationale,
        ),
        None,
    )


def compile_memory_skill_search_receipt(
    request: GovernedSkillSearchRequest,
    payload: Mapping[str, Any],
    *,
    generated_at: datetime | None = None,
) -> GovernedSkillSearchReceipt:
    """Validate, re-rank, semantically deduplicate, and bind a Memory response."""

    parsed_request = GovernedSkillSearchRequest.model_validate(request)
    rows = payload.get("items")
    if not isinstance(rows, list):
        raise ValueError("memory skill search response must contain an items array")
    excluded: dict[str, int] = {}
    bindings: list[GovernedSkillBinding] = []
    for raw in rows[:64]:
        if not isinstance(raw, Mapping):
            excluded["invalid_item"] = excluded.get("invalid_item", 0) + 1
            continue
        binding, reason = _binding_for_item(item=raw, request=parsed_request)
        if binding is None:
            key = reason or "invalid_item"
            excluded[key] = excluded.get(key, 0) + 1
            continue
        bindings.append(binding)

    # One semantic procedure/model identity per exact scope.  Newer versions
    # win only after lifecycle, evidence and measured routing quality.
    bindings.sort(
        key=lambda binding: (
            binding.executable,
            _LIFECYCLE_SCORE[binding.lifecycle_stage],
            binding.relevance_score,
            binding.version,
            binding.binding_sha256,
        ),
        reverse=True,
    )
    selected_by_semantic_key: dict[str, GovernedSkillBinding] = {}
    for binding in bindings:
        if binding.semantic_key in selected_by_semantic_key:
            excluded["semantic_duplicate"] = excluded.get("semantic_duplicate", 0) + 1
            continue
        selected_by_semantic_key[binding.semantic_key] = binding
    selected = list(selected_by_semantic_key.values())[: parsed_request.top_k]
    if len(selected_by_semantic_key) > parsed_request.top_k:
        excluded["top_k"] = len(selected_by_semantic_key) - parsed_request.top_k

    moment = generated_at or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    core = {
        "schema": GOVERNED_SKILL_SEARCH_RECEIPT_SCHEMA,
        "scope": parsed_request.scope.model_dump(mode="json"),
        "mode": parsed_request.mode.value,
        "query_sha256": _canonical_digest(parsed_request.memory_query_text()),
        "selected": [
            binding.model_dump(mode="json", by_alias=True) for binding in selected
        ],
        "excluded_counts": dict(sorted(excluded.items())),
        "generated_at": moment.astimezone(timezone.utc).isoformat(),
    }
    return GovernedSkillSearchReceipt(
        **core,
        receipt_sha256=_canonical_digest(core),
    )


def _verify_skill_search_receipt(receipt: GovernedSkillSearchReceipt) -> None:
    generated_at = receipt.generated_at
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    core = {
        "schema": GOVERNED_SKILL_SEARCH_RECEIPT_SCHEMA,
        "scope": receipt.scope.model_dump(mode="json"),
        "mode": receipt.mode.value,
        "query_sha256": receipt.query_sha256,
        "selected": [
            binding.model_dump(mode="json", by_alias=True)
            for binding in receipt.selected
        ],
        "excluded_counts": dict(sorted(receipt.excluded_counts.items())),
        "generated_at": generated_at.astimezone(timezone.utc).isoformat(),
    }
    if receipt.receipt_sha256 != _canonical_digest(core):
        raise ValueError("skill search receipt digest does not match its contents")


class MemorySkillSearchClient:
    """Exact-scope adapter for the existing Memory ``/skills/query`` route."""

    def __init__(
        self,
        base_url: str,
        *,
        internal_api_key: str,
        client: httpx.Client | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        self._base_url = str(base_url).strip().rstrip("/")
        if not self._base_url:
            raise ValueError("base_url is required")
        if not isinstance(internal_api_key, str):
            raise ValueError("internal_api_key is required")
        clean_internal_api_key = internal_api_key.strip()
        if (
            not clean_internal_api_key
            or len(clean_internal_api_key) > _MAX_INTERNAL_API_KEY_CHARS
            or any(
                ord(char) < 0x20 or ord(char) == 0x7F
                for char in clean_internal_api_key
            )
        ):
            raise ValueError("internal_api_key is missing or invalid")
        self._internal_api_key = clean_internal_api_key
        self._client = client
        self._timeout_seconds = max(0.1, min(float(timeout_seconds), 10.0))

    def search(self, request: GovernedSkillSearchRequest) -> GovernedSkillSearchReceipt:
        parsed = GovernedSkillSearchRequest.model_validate(request)
        scope = parsed.scope
        headers = {
            "X-Internal-API-Key": self._internal_api_key,
            "X-Tenant-Id": str(scope.tenant_id),
            "X-Company-Id": str(scope.company_id),
            "X-User-Id": str(scope.user_id),
        }
        params = {"project_id": str(scope.project_id)} if scope.project_id else {}
        if self._client is not None:
            response = self._client.post(
                f"{self._base_url}/api/memory/skills/query",
                headers=headers,
                params=params,
                json=parsed.memory_query_body(),
                timeout=self._timeout_seconds,
            )
        else:
            with httpx.Client(timeout=self._timeout_seconds) as client:
                response = client.post(
                    f"{self._base_url}/api/memory/skills/query",
                    headers=headers,
                    params=params,
                    json=parsed.memory_query_body(),
                )
        if len(response.content) > _MAX_MEMORY_SKILL_SEARCH_RESPONSE_BYTES:
            raise ValueError("memory skill search response exceeds the bounded byte limit")
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, Mapping):
            raise ValueError("memory skill search returned a non-object response")
        return compile_memory_skill_search_receipt(parsed, body)


class TypedDataReference(BaseModel):
    """Immutable typed data, never an inline raw workflow payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_ref: str = Field(min_length=1, max_length=512)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = Field(default="application/json", max_length=160)
    record_count: int | None = Field(default=None, ge=0)

    @field_validator("artifact_ref")
    @classmethod
    def _artifact_ref_is_bounded(cls, value: str) -> str:
        clean = value.strip()
        if not _SAFE_REF_RE.fullmatch(clean):
            raise ValueError("artifact_ref must be a bounded non-network reference")
        if "://" in clean:
            raise ValueError("artifact_ref cannot be a network URL")
        return clean


class LearningEvidenceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome_verified: bool = False
    outcome_evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    eligible_episode_count: int = Field(default=0, ge=0)
    stable_typed_schema: bool = False
    training_dataset_ref: str | None = Field(default=None, max_length=512)
    policy_approval_ref: str | None = Field(default=None, max_length=512)
    reward_contract_ref: str | None = Field(default=None, max_length=512)
    off_policy_evaluation_ref: str | None = Field(default=None, max_length=512)

    @field_validator(
        "outcome_evidence_refs",
        "training_dataset_ref",
        "policy_approval_ref",
        "reward_contract_ref",
        "off_policy_evaluation_ref",
    )
    @classmethod
    def _refs_are_non_network(
        cls, value: list[str] | str | None
    ) -> list[str] | str | None:
        values = value if isinstance(value, list) else [value]
        for raw in values:
            if raw is None:
                continue
            clean = str(raw).strip()
            if not _SAFE_REF_RE.fullmatch(clean) or "://" in clean:
                raise ValueError("learning evidence must use bounded non-network refs")
        return value


class ServerLearningPolicy(BaseModel):
    """Trusted-host policy input; workflow/user inputs must never populate it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_gepa: bool = True
    allow_automl: bool = True
    allow_paired_rl: bool = False
    min_rl_episode_count: int = Field(default=100, ge=20, le=1_000_000)


class WorkflowLearningDisposition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(default=WORKFLOW_LEARNING_DISPOSITION_SCHEMA, alias="schema")
    action: str = Field(pattern=r"^(hold|enqueue_candidate)$")
    eligible_lanes: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    paired_learning_handoff_schema: str | None = None
    requires_control_plane_admission: bool = True
    training_authorized: bool = False
    promotion_authorized: bool = False
    serving_authorized: bool = False


class PrimitiveVersionBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(min_length=1, max_length=128)
    primitive_ref: str = Field(min_length=3, max_length=200)
    primitive_version: str = Field(min_length=1, max_length=80)
    contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkflowExecutionLearningRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: str = Field(
        default=WORKFLOW_EXECUTION_LEARNING_RECORD_SCHEMA, alias="schema"
    )
    scope: ExactAgentSkillScope
    project_ref: str = Field(min_length=1, max_length=128)
    workflow_key: str = Field(min_length=1, max_length=128)
    run_ref: str = Field(min_length=1, max_length=200)
    workflow_status: str = Field(min_length=1, max_length=80)
    selected_skills: list[GovernedSkillBinding] = Field(default_factory=list, max_length=8)
    used_skill_ids: list[str] = Field(default_factory=list, max_length=8)
    used_skill_binding_sha256s: list[str] = Field(default_factory=list, max_length=8)
    primitive_bindings: list[PrimitiveVersionBinding] = Field(
        default_factory=list, max_length=1_000
    )
    typed_inputs: list[TypedDataReference] = Field(default_factory=list, max_length=64)
    typed_outputs: list[TypedDataReference] = Field(default_factory=list, max_length=64)
    outcome_evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    disposition: WorkflowLearningDisposition
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


def _compile_learning_disposition(
    *,
    workflow_status: str,
    skill_bindings: Sequence[GovernedSkillBinding],
    typed_inputs: Sequence[TypedDataReference],
    typed_outputs: Sequence[TypedDataReference],
    evidence: LearningEvidenceSummary,
    policy: ServerLearningPolicy,
) -> WorkflowLearningDisposition:
    reasons: list[str] = []
    lanes: list[str] = []
    completed = workflow_status == "completed"
    all_skills_executable = all(binding.executable for binding in skill_bindings)
    typed = bool(typed_inputs and typed_outputs)
    evidenced = bool(evidence.outcome_verified and evidence.outcome_evidence_refs)
    base_eligible = completed and all_skills_executable and typed and evidenced
    if not completed:
        reasons.append("workflow_not_completed")
    if not all_skills_executable:
        reasons.append("shadow_or_unverified_skill_bound")
    if not typed:
        reasons.append("typed_input_output_artifacts_required")
    if not evidenced:
        reasons.append("verified_outcome_evidence_required")

    if base_eligible and policy.allow_gepa:
        lanes.append("gepa")
    if (
        base_eligible
        and policy.allow_automl
        and evidence.stable_typed_schema
        and evidence.training_dataset_ref
    ):
        lanes.append("automl")
    elif base_eligible and policy.allow_automl:
        reasons.append("automl_requires_stable_schema_and_training_dataset")

    rl_ready = bool(
        base_eligible
        and policy.allow_paired_rl
        and evidence.stable_typed_schema
        and evidence.eligible_episode_count >= policy.min_rl_episode_count
        and evidence.policy_approval_ref
        and evidence.reward_contract_ref
        and evidence.off_policy_evaluation_ref
    )
    if rl_ready:
        lanes.extend(WORKFLOW_LEARNING_LANES)
    elif policy.allow_paired_rl:
        reasons.append("paired_rl_policy_or_evidence_gate_not_met")
    if not lanes:
        reasons.append("no_learning_lane_eligible")
    return WorkflowLearningDisposition(
        action="enqueue_candidate" if lanes else "hold",
        eligible_lanes=lanes,
        reason_codes=list(dict.fromkeys(reasons)),
        paired_learning_handoff_schema=(
            WORKFLOW_LEARNING_CANDIDATE_ATTESTED_HANDOFF_SCHEMA
            if rl_ready
            else None
        ),
    )


def compile_workflow_execution_learning_record(
    *,
    run: Any,
    scope: ExactAgentSkillScope,
    skill_search_receipt: GovernedSkillSearchReceipt,
    primitive_contracts: Mapping[str, Mapping[str, Any]],
    typed_inputs: Iterable[TypedDataReference],
    typed_outputs: Iterable[TypedDataReference],
    evidence: LearningEvidenceSummary,
    policy: ServerLearningPolicy,
    used_skill_binding_sha256s: Iterable[str] = (),
) -> WorkflowExecutionLearningRecord:
    """Bind an existing ``ProjectRuntime`` run to proposal-only learning data."""

    parsed_scope = ExactAgentSkillScope.model_validate(scope)
    receipt = GovernedSkillSearchReceipt.model_validate(skill_search_receipt)
    _verify_skill_search_receipt(receipt)
    if receipt.scope != parsed_scope:
        raise ValueError("skill search receipt scope does not match workflow scope")
    step_runs = list(getattr(run, "step_runs", None) or [])
    primitive_bindings: list[PrimitiveVersionBinding] = []
    for step_run in step_runs:
        step_id = str(getattr(step_run, "step_id", "") or "").strip()
        primitive_ref = str(getattr(step_run, "primitive_ref", "") or "").strip()
        result = getattr(step_run, "result", None)
        version = str(getattr(result, "primitive_version", "") or "").strip()
        contract = primitive_contracts.get(primitive_ref)
        if not step_id or not primitive_ref or not version or not isinstance(contract, Mapping):
            raise ValueError("every executed primitive requires an exact implementation contract")
        if str(contract.get("primitive_ref") or "").strip() != primitive_ref:
            raise ValueError("primitive implementation contract identity mismatch")
        if str(contract.get("version") or "").strip() != version:
            raise ValueError("primitive implementation contract version mismatch")
        primitive_bindings.append(
            PrimitiveVersionBinding(
                step_id=step_id,
                primitive_ref=primitive_ref,
                primitive_version=version,
                contract_sha256=_canonical_digest(contract),
            )
        )
    parsed_inputs = [TypedDataReference.model_validate(value) for value in typed_inputs]
    parsed_outputs = [TypedDataReference.model_validate(value) for value in typed_outputs]
    parsed_evidence = LearningEvidenceSummary.model_validate(evidence)
    parsed_policy = ServerLearningPolicy.model_validate(policy)
    selected_by_digest = {
        binding.binding_sha256: binding for binding in receipt.selected
    }
    actual_used_digests: list[str] = []
    for raw in used_skill_binding_sha256s:
        digest = str(raw or "").strip().lower()
        if not _DIGEST_RE.fullmatch(digest):
            raise ValueError("used skill binding digest is invalid")
        if digest not in selected_by_digest:
            raise ValueError("used skill was not selected by the governed search receipt")
        if not selected_by_digest[digest].executable:
            raise ValueError("non-executable skill cannot be recorded as actually used")
        if digest not in actual_used_digests:
            actual_used_digests.append(digest)
    used_skill_ids = [
        selected_by_digest[digest].skill_id for digest in actual_used_digests
    ]
    status_value = getattr(run, "status", "")
    workflow_status = str(getattr(status_value, "value", status_value) or "").strip()
    disposition = _compile_learning_disposition(
        workflow_status=workflow_status,
        skill_bindings=[
            selected_by_digest[digest] for digest in actual_used_digests
        ],
        typed_inputs=parsed_inputs,
        typed_outputs=parsed_outputs,
        evidence=parsed_evidence,
        policy=parsed_policy,
    )
    core = {
        "schema": WORKFLOW_EXECUTION_LEARNING_RECORD_SCHEMA,
        "scope": parsed_scope.model_dump(mode="json"),
        "project_ref": str(getattr(run, "project_ref", "") or "").strip(),
        "workflow_key": str(getattr(run, "workflow_key", "") or "").strip(),
        "run_ref": str(getattr(run, "run_ref", "") or "").strip(),
        "workflow_status": workflow_status,
        "selected_skills": [
            binding.model_dump(mode="json", by_alias=True)
            for binding in receipt.selected
        ],
        "used_skill_ids": used_skill_ids,
        "used_skill_binding_sha256s": actual_used_digests,
        "primitive_bindings": [
            binding.model_dump(mode="json") for binding in primitive_bindings
        ],
        "typed_inputs": [value.model_dump(mode="json") for value in parsed_inputs],
        "typed_outputs": [value.model_dump(mode="json") for value in parsed_outputs],
        "outcome_evidence_refs": parsed_evidence.outcome_evidence_refs,
        "disposition": disposition.model_dump(mode="json", by_alias=True),
    }
    return WorkflowExecutionLearningRecord(
        **core,
        record_sha256=_canonical_digest(core),
    )


__all__ = [
    "GOVERNED_SKILL_BINDING_SCHEMA",
    "GOVERNED_SKILL_SEARCH_RECEIPT_SCHEMA",
    "GOVERNED_SKILL_SEARCH_REQUEST_SCHEMA",
    "WORKFLOW_EXECUTION_LEARNING_RECORD_SCHEMA",
    "WORKFLOW_LEARNING_DISPOSITION_SCHEMA",
    "ExactAgentSkillScope",
    "GovernedSkillBinding",
    "GovernedSkillSearchProvider",
    "GovernedSkillSearchReceipt",
    "GovernedSkillSearchRequest",
    "LearningEvidenceSummary",
    "MemorySkillSearchClient",
    "PrimitiveVersionBinding",
    "ServerLearningPolicy",
    "SkillSearchMode",
    "TypedDataReference",
    "WorkflowExecutionLearningRecord",
    "WorkflowLearningDisposition",
    "compile_memory_skill_search_receipt",
    "compile_workflow_execution_learning_record",
]
