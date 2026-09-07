"""Executable primitive for bring-up readiness: ``company.assess_bring_up_readiness``.

Read-only preview: compares a cadence bundle's engines against the account's
active OAuth connections (supplied as the platform returned them) and says
which engine is blocked by which missing provider.  Nothing is connected,
hired, opened, or scheduled here; ``BringUpOrchestrator`` does that behind
the bring-up lifecycle's fences.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_bring_up import BRING_UP_MANIFEST, ConnectorReadiness, assess_readiness
from lightbulb.company_cadence_primitives import example_cadence_inputs
from lightbulb.company_cadence_runner import CadenceBundle
from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

BRING_UP_STAGES: tuple[str, ...] = ("form", "verify_connectors", "hire_workforce", "open_period", "start_cadence", "schedule", "go_live")


class AssessBringUpReadinessInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    bundle: CadenceBundle
    connections: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    now: str

    @field_validator("connections", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        cadence = example_cadence_inputs()["plan"]
        connections = [{"provider": provider, "connectionScope": "company", "status": "active"} for provider in ("stripe", "google_analytics", "gmail", "hubspot", "posthog", "github", "xero")]
        self._built = {"readiness": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "bundle": cadence["bundle"], "connections": connections, "now": cadence["now"]}}
        return self._built


_EXAMPLES = _Examples()


def example_bring_up_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class AssessBringUpReadinessPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.assess_bring_up_readiness"
    version = "0.1.0"
    title = "Check a company bundle against the account's connected providers"
    description = "Compare every engine in a cadence bundle with the OAuth connections the account actually holds and return the sealed readiness: which engines are ready, which are blocked, and which provider (or alternative) would unblock each; nothing is connected or started."
    input_model = AssessBringUpReadinessInput
    output_model = ConnectorReadiness
    risk_level = "low"
    operation_spec = read_spec("company_assess_bring_up_readiness", "sdk.company.assess_bring_up_readiness")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "readiness")
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = BRING_UP_STAGES
    profiles = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")
    hard_rules = {"readiness_from_active_connections_only": True, "blocked_engine_blocks_bring_up": True, "nothing_connected_or_started": True}
    authority_boundary = {"agent": "lists the account's connections", "sdk": "compares and seals readiness", "spring": "owns OAuth connections and their scope", "connectors": "none", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessBringUpReadinessInput) -> PrimitiveExecutionResult[ConnectorReadiness]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            readiness = assess_readiness(inputs.bundle, list(inputs.connections), now=inputs.now)
        except ValueError as exc:
            return self.blocked(digest=digest, code="READINESS_INVALID", message=str(exc))
        missing = readiness.missing_providers()
        summary = "every engine has its providers connected; bring-up can proceed." if readiness.ready else "; ".join(f"{engine} needs {' and '.join(groups)}" for engine, groups in missing.items())
        return self.preview(output=readiness, digest=digest, external_refs={"readiness_digest": readiness.readiness_digest, "bundle_digest": readiness.bundle_digest}, event_type="company.bring_up_readiness_assessed", event_payload={"ready": readiness.ready, "blocked_engines": list(readiness.blocked_engines), "connected": [item.provider for item in readiness.connected]}, evidence_kind="company_connector_readiness", evidence_summary="Readiness computed; nothing connected.", summary=f"{len(readiness.connected)} provider(s) connected; {summary}")


BRING_UP_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (AssessBringUpReadinessPrimitive(),)

BRING_UP_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_bring_up",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": {**BRING_UP_MANIFEST, "golden_loop": COMPANY_OS_GOLDEN_LOOP},
    "modules": {"domain": "lightbulb.company_bring_up", "primitives": "lightbulb.company_bring_up_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_formation create_company", "company_workforce hire and activate", "company_cadence_runner first tick", "company_hosted_scheduler register", "company_engine_store fences"],
    "required_connectors": BRING_UP_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in BRING_UP_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no provider connected here", "no worker hired or period opened here", "no certification or production-readiness claim"],
}

__all__ = ["BRING_UP_EXECUTABLE_PRIMITIVES", "BRING_UP_INTEGRATION_MANIFEST", "AssessBringUpReadinessInput", "AssessBringUpReadinessPrimitive", "example_bring_up_inputs"]
