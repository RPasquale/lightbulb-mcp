"""Executable primitive for the provisioning plan: ``company.plan_provisioning``.

Read-only preview: turn a company's sealed operating plan into the list of
instruments it needs, the exact tool that would mint or observe each, whether
that tool runs behind an approval task, and the human step the instrument
opens.  Nothing is minted, proposed, approved, signed, or filed here; the
per-instrument lifecycle in ``lightbulb.company_provisioning`` records what
the platform actually did, and only against a sealed provisioning receipt.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP, CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_provisioning import (
    INSTRUMENT_CATALOG,
    INSTRUMENT_HUMAN_GATE,
    MAX_INSTRUMENTS,
    PROVISIONING_GOLDEN_LOOP,
    PROVISIONING_MANIFEST,
    ProvisioningPlan,
    compile_provisioning_plan,
)
from lightbulb.company_provisioning_receipts import HUMAN_STEP_TEXT, HumanStep, InstrumentKind, Lane
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

PROVISIONING_BRIEF_SCHEMA = "lightbulb.company_provisioning_brief.v1"
PROVISIONING_STAGES: tuple[str, ...] = ("plan", "request_approval", "record_write", "hand_to_human", "observe")


class ProvisioningStep(StrictModel):
    """One instrument's route: who provides it, which tool moves it, and which person must finish it."""

    instrument: InstrumentKind
    provider: ShortText
    lane: Lane
    write_tool: ShortText | None = None
    observe_tool: ShortText | None = None
    approval_required: bool
    human_step: HumanStep | None = None


class ProvisioningBrief(StrictModel):
    schema_id: str = Field(default=PROVISIONING_BRIEF_SCHEMA, alias="schema")
    plan: ProvisioningPlan
    steps: tuple[ProvisioningStep, ...] = Field(min_length=1, max_length=MAX_INSTRUMENTS)
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("steps", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProvisioningBrief:
        if tuple(item.instrument for item in self.steps) != self.plan.instrument_kinds:
            raise ValueError("steps must mirror the plan's instruments in order")
        if not skip_digests(info) and self.brief_digest != sealed_digest(ProvisioningBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self


def _human_step(instrument: str) -> dict[str, Any] | None:
    gate = INSTRUMENT_HUMAN_GATE.get(instrument)
    if gate is None:
        return None
    actor, action, legal_basis = HUMAN_STEP_TEXT[gate]
    return {"kind": gate, "actor": actor, "action": action, "legal_basis": legal_basis, "status": "not_started"}


def compile_provisioning_brief(operating_plan: CompanyOperatingPlan | Mapping[str, Any], *, overrides: Mapping[str, bool] | None = None, company_ref: str | None = None) -> ProvisioningBrief:
    """The read-only preview of what provisioning this company would ask a person to do."""

    plan = compile_provisioning_plan(operating_plan, overrides=overrides, company_ref=company_ref)
    steps = []
    for requirement in plan.instruments:
        spec = INSTRUMENT_CATALOG[requirement.instrument]
        steps.append({"instrument": requirement.instrument, "provider": requirement.provider, "lane": spec.lane, "write_tool": spec.write_tool, "observe_tool": spec.observe_tool, "approval_required": spec.write_tool is not None, "human_step": _human_step(requirement.instrument)})
    return seal(ProvisioningBrief, {"plan": plan.to_dict(), "steps": steps}, "brief_digest")


class PlanProvisioningInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    operating_plan: CompanyOperatingPlan
    overrides: dict[str, bool] = Field(default_factory=dict, max_length=8)
    now: str

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
        operating = compile_company_operating_blueprint("services_firm")
        self._built = {"provisioning": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "operating_plan": operating.to_dict(), "overrides": {"receptionist": True, "esign": True}, "now": "2026-09-05T00:00:00Z"}}
        return self._built


_EXAMPLES = _Examples()


def example_provisioning_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class PlanProvisioningPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "company.plan_provisioning"
    version = "0.1.0"
    title = "Plan the instruments a formed company needs before it can trade"
    description = "Turn a company's sealed operating plan into the instruments it must provision - payments, a site, a phone number, e-signature, treasury, payee, tax registration - naming the exact tool that mints or observes each, whether that tool runs behind an approval a human decides, and the legally-human step each instrument opens. Nothing is minted, proposed, approved, signed, or filed here."
    input_model = PlanProvisioningInput
    output_model = ProvisioningBrief
    risk_level = "low"
    operation_spec = read_spec("company_plan_provisioning", "sdk.company.plan_provisioning")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "provisioning")
    golden_loop = PROVISIONING_GOLDEN_LOOP
    engine = "company_provisioning"
    loop_stages = PROVISIONING_STAGES
    profiles = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")
    hard_rules = {"nothing_provisioned_here": True, "every_write_approval_required": True, "human_steps_named_not_performed": True}
    authority_boundary = {"agent": "asks what the company needs", "sdk": "types the instruments and names the human steps", "spring": "owns the provisioning authority, the approval tasks, and the journals", "connectors": "execute the governed writes and reads under approval", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanProvisioningInput) -> PrimitiveExecutionResult[ProvisioningBrief]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            brief = compile_provisioning_brief(inputs.operating_plan, overrides=dict(inputs.overrides))
        except ValueError as exc:
            return self.blocked(digest=digest, code="PROVISIONING_PLAN_INVALID", message=str(exc))
        human = [f"{item.instrument}: {item.human_step.kind} ({item.human_step.actor})" for item in brief.steps if item.human_step is not None]
        return self.preview(
            output=brief,
            digest=digest,
            external_refs={"plan_digest": brief.plan.plan_digest, "brief_digest": brief.brief_digest, "operating_plan_digest": str(brief.plan.operating_plan_digest)},
            event_type="company.provisioning_planned",
            event_payload={"instruments": list(brief.plan.instrument_kinds), "required": list(brief.plan.required_kinds), "country": brief.plan.country},
            evidence_kind="company_provisioning_brief",
            evidence_summary="Provisioning planned; nothing minted, proposed, or filed.",
            summary=f"{len(brief.steps)} instrument(s) planned for a {brief.plan.archetype} in {brief.plan.country}; human steps: {'; '.join(human) or 'none'}.",
        )


PROVISIONING_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (PlanProvisioningPrimitive(),)

PROVISIONING_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_provisioning",
    "golden_loop": PROVISIONING_GOLDEN_LOOP,
    "engine": PROVISIONING_MANIFEST,
    "modules": {"domain": "lightbulb.company_provisioning", "receipts": "lightbulb.company_provisioning_receipts", "primitives": "lightbulb.company_provisioning_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_operating_system operating plan", "company_provisioning_receipts sealed receipts", "company_bring_up verify_connectors gate", "company_engine_store fences"],
    "required_connectors": PROVISIONING_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in PROVISIONING_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no instrument minted here", "no approval decided here", "no registration lodged here", "no certification or production-readiness claim"],
    "company_os_golden_loop": COMPANY_OS_GOLDEN_LOOP,
}

__all__ = [
    "PROVISIONING_BRIEF_SCHEMA",
    "PROVISIONING_EXECUTABLE_PRIMITIVES",
    "PROVISIONING_INTEGRATION_MANIFEST",
    "PROVISIONING_STAGES",
    "PlanProvisioningInput",
    "PlanProvisioningPrimitive",
    "ProvisioningBrief",
    "ProvisioningStep",
    "compile_provisioning_brief",
    "example_provisioning_inputs",
]
