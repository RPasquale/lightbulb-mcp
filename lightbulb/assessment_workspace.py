"""Retain assessment drafts through Spring's scoped, revisioned checkpoints.

The checkpoint is a saved working document. Its selected offer is proposed
intent, and saving it does not supply agreement, acceptance or billing authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.productised_assessment import ProductisedAssessmentDossier
from lightbulb.service_engagement import (
    OpaqueRef, ServiceEngagementScope, Sha256Digest, _StrictModel,
    _detached, _digest_without, _parsed_timestamp, _timestamp,
)


ASSESSMENT_WORKSPACE_SCHEMA = "lightbulb.assessment_workspace.v1"
ASSESSMENT_WORKSPACE_CHECKPOINT_SCHEMA = "lightbulb.assessment_workspace_checkpoint.v1"
ASSESSMENT_WORKSPACE_RECORD_SCHEMA = "lightbulb.assessment_workspace_record.v1"


class AssessmentWorkspaceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AssessmentWorkspaceError("SCOPE_REQUIRED", f"{field} must be a concrete UUID.")
    try:
        parsed = str(UUID(value))
    except ValueError as exc:
        raise AssessmentWorkspaceError("SCOPE_REQUIRED", f"{field} must be a concrete UUID.") from exc
    if parsed != value:
        raise AssessmentWorkspaceError("SCOPE_REQUIRED", f"{field} must be a canonical UUID.")
    return value


def _run_ref(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", value) or ".." in value:
        raise AssessmentWorkspaceError("RUN_REF_INVALID", "Use a portable checkpoint reference of 1 to 200 characters.")
    return value


def _revision(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise AssessmentWorkspaceError("REVISION_REQUIRED", "expected_revision must be a non-negative integer.")
    return value


class AssessmentWorkspace(_StrictModel):
    schema_id: Literal["lightbulb.assessment_workspace.v1"] = Field(default=ASSESSMENT_WORKSPACE_SCHEMA, alias="schema")
    dossier: ProductisedAssessmentDossier
    selected_offer_ref: OpaqueRef | None = None
    selection_status: Literal["proposed_only"] = "proposed_only"
    workspace_digest: Sha256Digest

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "AssessmentWorkspace":
        if self.selected_offer_ref is not None and self.selected_offer_ref not in {
            offer.offer_ref for offer in self.dossier.inputs.offers
        }:
            raise ValueError("selected_offer_ref must name an offer in this exact dossier")
        if not (info.context or {}).get("skip_assessment_workspace_digest"):
            if self.workspace_digest != _digest_without(self.to_dict(), "workspace_digest"):
                raise ValueError("workspace_digest must commit the exact dossier and selected offer")
        return self


def create_assessment_workspace(
    dossier: ProductisedAssessmentDossier | Mapping[str, Any],
    *,
    selected_offer_ref: str | None = None,
) -> AssessmentWorkspace:
    """Seal a working draft; selecting an offer records no customer decision."""
    candidate = AssessmentWorkspace.model_validate(
        {"dossier": _detached(dossier), "selected_offer_ref": selected_offer_ref, "workspace_digest": "0" * 64},
        context={"skip_assessment_workspace_digest": True},
    ).to_dict()
    candidate["workspace_digest"] = _digest_without(candidate, "workspace_digest")
    return AssessmentWorkspace.model_validate(candidate)


class _Checkpoint(_StrictModel):
    schema_id: Literal["lightbulb.assessment_workspace_checkpoint.v1"] = Field(alias="schema")
    run_ref: str
    hosted_project_id: str
    status: Literal["preview"]
    workspace: AssessmentWorkspace
    revision: int = Field(ge=1)
    created_at: str
    updated_at: str
    resume_at: None = None
    lease_owner: None = None
    lease_until: None = None

    @field_validator("created_at", "updated_at")
    @classmethod
    def _time(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> "_Checkpoint":
        if _parsed_timestamp(self.updated_at) < _parsed_timestamp(self.created_at):
            raise ValueError("checkpoint update cannot precede creation")
        return self


class AssessmentWorkspaceRecord(BaseModel):
    """Validated echo of a hosted draft, never an acceptance or payment receipt."""

    # Transport identity comes from the pinned authenticated request, not from
    # business inputs. The business-model scanner intentionally rejects *_id
    # authority fields; keep this narrowly typed receipt separate from that base.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True,
                              serialize_by_alias=True, revalidate_instances="always")
    schema_id: Literal["lightbulb.assessment_workspace_record.v1"] = Field(default=ASSESSMENT_WORKSPACE_RECORD_SCHEMA, alias="schema")
    workspace: AssessmentWorkspace
    tenant_id: str
    company_id: str
    project_id: str
    run_ref: str
    revision: int = Field(ge=1)
    created_at: str
    updated_at: str
    persisted: Literal[True] = True
    provider_effect_executed: Literal[False] = False
    acceptance_recorded: Literal[False] = False

    @field_validator("tenant_id", "company_id", "project_id")
    @classmethod
    def _identity(cls, value: str, info: ValidationInfo) -> str:
        return _uuid(value, str(info.field_name))

    @field_validator("run_ref")
    @classmethod
    def _reference(cls, value: str) -> str:
        return _run_ref(value)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _time(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _echo(self) -> "AssessmentWorkspaceRecord":
        scope = self.workspace.dossier.inputs.scope
        if (self.tenant_id, self.company_id, self.project_id) != (scope.tenant_ref, scope.company_ref, scope.project_id):
            raise ValueError("record identities must match the retained workspace")
        if _parsed_timestamp(self.updated_at) < _parsed_timestamp(self.created_at):
            raise ValueError("record update cannot precede creation")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class AssessmentWorkspaceStore:
    """Pin one authenticated project; Spring owns writes, access and revisions.

    A mutable company selection never retargets an existing store. An auth
    identity change requires a new store. Transport errors propagate without
    replay; ``recover`` performs a separate, exact read to check an uncertain save.
    """

    def __init__(
        self, client: Any, *, scope: ServiceEngagementScope | Mapping[str, Any], requested_by_ref: str,
    ) -> None:
        parsed = ServiceEngagementScope.model_validate(_detached(scope))
        self._initialize(client, parsed.project_id, requested_by_ref)
        if parsed.tenant_ref != self.tenant_id or parsed.company_ref != self.company_id:
            raise AssessmentWorkspaceError("SCOPE_MISMATCH", "The workspace must belong to the authenticated selected company.")
        self._scope: ServiceEngagementScope | None = parsed

    @classmethod
    def for_project(cls, client: Any, *, project_id: str, requested_by_ref: str) -> "AssessmentWorkspaceStore":
        """Open a reader using only the retained project and checkpoint reference."""
        result = cls.__new__(cls)
        result._initialize(client, project_id, requested_by_ref)
        result._scope = None
        return result

    def _initialize(self, client: Any, project_id: str, requested_by_ref: str) -> None:
        auth = getattr(client, "_auth", None)
        self.tenant_id = _uuid(getattr(auth, "tenant_id", None), "authenticated tenant")
        self.company_id = _uuid(getattr(client, "active_company_id", None), "selected company")
        self.requested_by_ref = _uuid(getattr(auth, "user_id", None), "authenticated actor")
        if requested_by_ref != self.requested_by_ref:
            raise AssessmentWorkspaceError("SCOPE_MISMATCH", "The requester must match the authenticated actor.")
        self.project_id = _uuid(project_id, "project_id")
        self._client = client

    def _check_identity(self) -> None:
        auth = getattr(self._client, "_auth", None)
        if (getattr(auth, "tenant_id", None), getattr(auth, "user_id", None)) != (self.tenant_id, self.requested_by_ref):
            raise AssessmentWorkspaceError("AUTH_IDENTITY_CHANGED", "Reopen the workspace using the current authenticated identity.")

    def _workspace(self, value: AssessmentWorkspace | Mapping[str, Any]) -> AssessmentWorkspace:
        parsed = AssessmentWorkspace.model_validate(_detached(value))
        inputs = parsed.dossier.inputs
        scope = inputs.scope
        if (
            (scope.tenant_ref, scope.company_ref, scope.project_id, inputs.requested_by_ref)
            != (self.tenant_id, self.company_id, self.project_id, self.requested_by_ref)
            or (self._scope is not None and scope != self._scope)
        ):
            raise AssessmentWorkspaceError("SCOPE_MISMATCH", "The retained assessment differs from the exact workspace scope or actor.")
        return parsed

    def _record(self, response: Any, run_ref: str) -> AssessmentWorkspaceRecord:
        self._check_identity()
        try:
            checkpoint = _Checkpoint.model_validate(_detached(response))
        except (ValidationError, TypeError, ValueError) as exc:
            raise AssessmentWorkspaceError("CHECKPOINT_INVALID", "The hosted response is not a valid sealed assessment checkpoint.") from exc
        if checkpoint.run_ref != run_ref or checkpoint.hosted_project_id != self.project_id:
            raise AssessmentWorkspaceError("SCOPE_MISMATCH", "The hosted response belongs to another project or checkpoint.")
        workspace = self._workspace(checkpoint.workspace)
        return AssessmentWorkspaceRecord(
            workspace=workspace, tenant_id=self.tenant_id, company_id=self.company_id,
            project_id=self.project_id, run_ref=run_ref, revision=checkpoint.revision,
            created_at=checkpoint.created_at, updated_at=checkpoint.updated_at,
        )

    def save(
        self, workspace: AssessmentWorkspace | Mapping[str, Any], *, run_ref: str, expected_revision: int,
    ) -> AssessmentWorkspaceRecord:
        self._check_identity()
        ref, revision = _run_ref(run_ref), _revision(expected_revision)
        parsed = self._workspace(workspace)
        if revision > 0:
            existing = self.load(ref)
            if existing is None or existing.revision != revision:
                raise AssessmentWorkspaceError("REVISION_CONFLICT", "Reload the saved draft before proposing another revision.")
            if (
                existing.workspace.dossier.inputs.scope != parsed.dossier.inputs.scope
                or existing.workspace.dossier.inputs.assessment_ref != parsed.dossier.inputs.assessment_ref
            ):
                raise AssessmentWorkspaceError("WORKSPACE_IDENTITY_CONFLICT", "A revision cannot replace the assessment or its customer scope.")
        response = self._client.put_sdk_project_checkpoint(
            self.project_id, ref,
            {"schema": ASSESSMENT_WORKSPACE_CHECKPOINT_SCHEMA, "run_ref": ref,
             "hosted_project_id": self.project_id, "status": "preview", "workspace": parsed.to_dict()},
            expected_revision=revision, company_id=self.company_id,
        )
        record = self._record(response, ref)
        self._confirm(record, parsed, revision)
        return record

    def load(self, run_ref: str) -> AssessmentWorkspaceRecord | None:
        self._check_identity()
        ref = _run_ref(run_ref)
        response = self._client.get_sdk_project_checkpoint(self.project_id, ref, company_id=self.company_id)
        self._check_identity()
        return None if response is None else self._record(response, ref)

    @staticmethod
    def _confirm(record: AssessmentWorkspaceRecord, workspace: AssessmentWorkspace, expected_revision: int) -> None:
        if record.revision != expected_revision + 1 or record.workspace.workspace_digest != workspace.workspace_digest:
            raise AssessmentWorkspaceError("SAVE_NOT_CONFIRMED", "The stored revision or content differs from this save; inspect the retained draft before continuing.")

    def recover(
        self, workspace: AssessmentWorkspace | Mapping[str, Any], *, run_ref: str, expected_revision: int,
    ) -> AssessmentWorkspaceRecord | None:
        """Read only: confirm the exact next revision after an uncertain write."""
        parsed, revision = self._workspace(workspace), _revision(expected_revision)
        record = self.load(run_ref)
        if record is not None:
            self._confirm(record, parsed, revision)
        return record


__all__ = [
    "ASSESSMENT_WORKSPACE_SCHEMA", "ASSESSMENT_WORKSPACE_CHECKPOINT_SCHEMA", "ASSESSMENT_WORKSPACE_RECORD_SCHEMA",
    "AssessmentWorkspace", "AssessmentWorkspaceError", "AssessmentWorkspaceRecord", "AssessmentWorkspaceStore",
    "create_assessment_workspace",
]
