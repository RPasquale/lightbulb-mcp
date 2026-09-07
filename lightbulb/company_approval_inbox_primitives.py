"""Executable primitive: ``company.render_approval_inbox``.

Renders platform approval tasks into the sealed operator inbox from the
tasks, the persisted engine state records, and a clock.  Read-only; the
inbox never decides.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_approval_inbox import ApprovalInbox, build_inbox
from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class RenderInboxInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    tasks: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    states: dict[str, tuple[dict[str, Any], ...]] = Field(default_factory=dict)
    now: str
    expiring_within_hours: int = Field(default=24, ge=1, le=720)

    @field_validator("tasks", "states", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        if isinstance(value, dict):
            return {str(key): tuple(item) if isinstance(item, (list, tuple)) else item for key, item in value.items()}
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")


_TASK = {"id": "7d7a1e2e-0000-4000-8000-000000000042", "status": "PENDING", "approvalType": "sdk_engine_transition", "summary": "Shift 20% growth to SaaS", "description": "Replan above the 15% threshold", "riskLevel": 6, "createdAt": "2026-10-12T03:00:00", "expiresAt": "2026-10-15T03:00:00", "contextData": {"engine": "company_operating_system", "entity_ref": "company-example:period:0001", "event": "replan", "transition_ref": "cadence:replan:1", "idempotency_key": "idem:replan:1", "request_digest": "a" * 64, "expected_version": 11, "expected_state_digest": "b" * 64, "plan_digest": "c" * 64, "actor_ref": EXAMPLE_ACTOR, "approval_request_digest": "d" * 64, "rejection_code": "APPROVAL_REQUIRED"}}
_EXAMPLE = {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "tasks": [_TASK], "states": {"company_operating_system": [{"entity_ref": "company-example:period:0001", "version": 11, "status": "reconciled", "state_digest": "b" * 64}]}, "now": "2026-10-12T04:00:00Z"}


class _Examples:
    def get(self) -> dict[str, Any]:
        return {"render": _EXAMPLE}


class RenderApprovalInboxPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.render_approval_inbox"
    version = "0.1.0"
    title = "Render the operator approval inbox"
    description = "Render platform approval tasks for a person: engine transition approvals show which engine wants which transition on which entity, why it stopped, whether the binding is still current against the persisted state, and what approving or rejecting does; other approvals are listed plainly. Never decides."
    input_model = RenderInboxInput
    output_model = ApprovalInbox
    risk_level = "low"
    operation_spec = read_spec("company_render_approval_inbox", "sdk.company.render_approval_inbox")
    example_inputs: Mapping[str, Any] = LazyExample(_Examples(), "render")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = ("list", "render", "decide", "resume")
    profiles = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")
    hard_rules = {"renders_never_decides": True, "freshness_checked_against_persisted_state": True, "resume_only_with_a_bound_approval": True}
    authority_boundary = {"agent": "relays the inbox to the operator", "sdk": "renders, plans decisions, resumes engines after a bound approval", "spring": "records decisions with separation of duties", "connectors": "none", "mcp": "projects the inbox and decision tools"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: RenderInboxInput) -> PrimitiveExecutionResult[ApprovalInbox]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            inbox = build_inbox(inputs.tasks, states={engine: list(records) for engine, records in inputs.states.items()}, now=inputs.now, expiring_within_hours=inputs.expiring_within_hours)
        except ValueError as exc:
            return self.blocked(digest=digest, code="TASKS_INVALID", message=str(exc))
        return self.preview(output=inbox, digest=digest, external_refs={"inbox_digest": inbox.inbox_digest}, event_type="company.approval_inbox_rendered", event_payload={"items": len(inbox.items), "engine_items": inbox.engine_items, "stale_items": inbox.stale_items, "expiring_soon": len(inbox.expiring_soon)}, evidence_kind="company_approval_inbox", evidence_summary="Rendered inbox; nothing decided.", summary=f"{inbox.engine_items} engine approval(s) of {len(inbox.items)} pending; {inbox.stale_items} stale, {len(inbox.expiring_soon)} expiring soon.")


INBOX_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (RenderApprovalInboxPrimitive(),)

INBOX_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_approval_inbox",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "company_approval_inbox", "golden_loop": COMPANY_OS_GOLDEN_LOOP, "stages": ["list", "render", "decide", "resume"], "required_connectors": ["lightbulb.approvals"], "hard_rules": ["renders, never decides", "freshness checked against the persisted state", "engines resume only with a bound approval"]},
    "modules": {"domain": "lightbulb.company_approval_inbox", "primitives": "lightbulb.company_approval_inbox_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_execution_bridge bind_approval", "company_engine_store EngineRuntime.resume_pending", "LightbulbClient approvals", "MCP list_engine_approvals / decide_engine_approval"],
    "required_connectors": ["lightbulb.approvals"],
    "primitive_refs": [item.primitive_ref for item in INBOX_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no decision made here", "no certification or production-readiness claim"],
}

__all__ = ["INBOX_EXECUTABLE_PRIMITIVES", "INBOX_INTEGRATION_MANIFEST", "RenderApprovalInboxPrimitive", "RenderInboxInput"]
