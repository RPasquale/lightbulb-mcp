"""Business evidence for an SDK implementation work packet, never build authority."""
import json
import re
from pathlib import PurePosixPath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, stable_digest
from lightbulb.company_sales_research import SalesResearchPreparation
from lightbulb.growth_primitives import CreateWorkPacketPrimitive
from lightbulb.primitive_runtime import PrimitiveExecutionContext
from lightbulb.connector_execution import InMemoryConnectorExecutor


class _TransportModel(BaseModel):
    # Authenticated identifiers travel in this transport contract, not in the
    # privacy-filtered company state model. Customer reply text stays ephemeral.
    model_config = ConfigDict(extra="forbid", frozen=True)

    def to_dict(self):
        return self.model_dump(mode="json")


class SalesAgentScope(_TransportModel):
    tenant_id: UUID
    company_id: UUID
    user_id: UUID
    project_id: UUID


class SdkCapabilityGap(StrictModel):
    capability_ref: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    business_outcome: str = Field(min_length=1, max_length=1000)
    missing_behavior: str = Field(min_length=1, max_length=2000)
    existing_capabilities_checked: tuple[str, ...] = Field(min_length=1, max_length=20)
    reuse_assessment: str = Field(min_length=1, max_length=1000)
    acceptance_criteria: tuple[str, ...] = Field(min_length=2, max_length=10)
    target_files: tuple[str, ...] = Field(min_length=1, max_length=20)
    expected_business_value: str = Field(min_length=1, max_length=1000)

    @field_validator("target_files")
    @classmethod
    def safe_targets(cls, paths):
        for path in paths:
            parts = PurePosixPath(path).parts
            if (not parts or parts[0] not in {"lightbulb-sdk", "agent-workers", "docs"}
                    or ".." in parts or "\\" in path or ":" in path or len(path) > 300):
                raise ValueError("SDK_GAP_TARGET_OUTSIDE_IMPLEMENTATION_SCOPE")
        return paths

    @field_validator("acceptance_criteria", "existing_capabilities_checked")
    @classmethod
    def bounded_rows(cls, rows):
        if any(not row.strip() or len(row) > 1000 for row in rows):
            raise ValueError("SDK_GAP_INVALID_EVIDENCE")
        return rows


class SalesAgentPreparationRequest(_TransportModel):
    schema_version: Literal["lightbulb.sdk_sales_preparation.v1"] = "lightbulb.sdk_sales_preparation.v1"
    request_ref: OpaqueRef
    scope: SalesAgentScope
    research_context: dict
    reply_text: str = Field(default="", max_length=20000)

    @field_validator("research_context")
    @classmethod
    def bounded_context(cls, value):
        sources = value.get("sources", [])
        if (len(json.dumps(value)) > 60000 or not isinstance(value.get("context_digest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["context_digest"])
                or not isinstance(sources, list) or len(sources) > 15
                or any(not isinstance(row, dict) or not isinstance(row.get("source_ref"), str) for row in sources)):
            raise ValueError("SDK_SALES_CONTEXT_INVALID")
        return value


class SalesAgentDecision(StrictModel):
    decision: Literal["prepared", "capability_gap"]
    preparation: SalesResearchPreparation | None = None
    gap: SdkCapabilityGap | None = None

    @model_validator(mode="after")
    def exact_decision(self):
        if ((self.decision == "prepared" and (self.preparation is None or self.gap is not None))
                or (self.decision == "capability_gap" and (self.gap is None or self.preparation is not None))):
            raise ValueError("SDK_SALES_DECISION_INVALID")
        return self


def sdk_gap_work_packet(gap, *, scope, source_context_digest, implementation_budget_usd):
    """Reuse canonical packet creation; requested budget is not a spending grant."""
    from lightbulb.business_primitives import BUSINESS_PRIMITIVES
    gap = SdkCapabilityGap.model_validate(gap)
    known = {row.id for row in BUSINESS_PRIMITIVES}
    if not set(gap.existing_capabilities_checked) <= known:
        raise ValueError("SDK_GAP_REUSE_EVIDENCE_UNKNOWN")
    if gap.capability_ref in known:
        raise ValueError("SDK_GAP_CAPABILITY_ALREADY_EXISTS")
    if not isinstance(implementation_budget_usd, int) or isinstance(implementation_budget_usd, bool) or not 1 <= implementation_budget_usd <= 1000:
        raise ValueError("SDK_GAP_BUDGET_REQUIRED")
    criteria = list(gap.acceptance_criteria) + [
        "Run the actual SDK and worker path with tenant/company isolation and rejection tests.",
        "Return a source commit, focused test evidence and a reviewable PR; do not merge, publish or deploy."]
    result = CreateWorkPacketPrimitive().execute(PrimitiveExecutionContext(scope=scope, connectors=InMemoryConnectorExecutor()), {
        "title": "Implement " + gap.capability_ref,
        "implementation_objective": gap.missing_behavior,
        "scope": [gap.business_outcome, gap.reuse_assessment, "SDK capability and owning agent integration"],
        "acceptance_criteria": criteria, "target_files": list(gap.target_files), "submit_for_approval": False})
    packet = result.output.model_dump(mode="json")
    packet.update(source_context_digest=source_context_digest, capability_gap=gap.to_dict(),
                  requested_budget_usd=implementation_budget_usd, budget_authorized=False,
                  implementation_approval_required=True, independent_acceptance_required=True)
    packet["packet_digest"] = stable_digest(packet)
    return packet


def sdk_gap_project_package(gap, *, scope, source_context_digest, implementation_budget_usd):
    """One canonical draft requirement and packet; caller input cannot add authority."""
    packet = sdk_gap_work_packet(gap, scope=scope, source_context_digest=source_context_digest,
                                 implementation_budget_usd=implementation_budget_usd)
    requirement_id = "sdk-gap-requirement-" + packet["packet_digest"]
    packet.update(id="sdk-gap-" + packet["packet_digest"], packet_type="coding",
        source_requirement_ids=[requirement_id], status="draft", approval_required=True,
        sdk_authoring_brief=True, sdk_reuse_flywheel=True)
    package = {"requirements": [{"id": requirement_id, "title": packet["title"],
        "description": packet["capability_gap"]["business_outcome"], "status": "draft"}], "work_packets": [packet]}
    package["package_digest"] = stable_digest(package)
    return package
