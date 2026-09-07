"""Aggregate of the Fable capability packs and the one-line integration splice.

Every pack was built without touching the shared surfaces
(``executable_primitives.py``, ``business_primitives.py``, ``__init__.py``,
``mcp_server.py``, ``mcp_generated_tools.py``, the registries).  This module
gathers their executable primitives, integration manifests, Golden Operating
Loops, and Company Blueprint archetypes so the eventual integration commit is
a single splice::

    from lightbulb.fable_capability_packs import FABLE_EXECUTABLE_PRIMITIVES
    BUILTIN_EXECUTABLE_PRIMITIVES = (..., *FABLE_EXECUTABLE_PRIMITIVES)

``validate_capability_packs`` proves the packs are mutually consistent and
consistent with the built-in registry: unique primitive references, no
collision with built-ins, every example input validates, every loop-bound
primitive reference resolves, unique loop names, and symmetric archetype
composability.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from lightbulb.commercial_legal_handoff import COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP
from lightbulb.commercial_legal_handoff_primitives import COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES, COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST
from lightbulb.contract_delivery_acceptance import CONTRACT_DELIVERY_GOLDEN_LOOP
from lightbulb.contract_delivery_acceptance_primitives import CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES, CONTRACT_DELIVERY_INTEGRATION_MANIFEST
from lightbulb.contract_obligation_primitives import CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES, CONTRACT_OBLIGATION_INTEGRATION_MANIFEST
from lightbulb.contract_obligations import CONTRACT_OBLIGATION_GOLDEN_LOOP
from lightbulb.appointment_business_loop import APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST, APPOINTMENT_BUSINESS_GOLDEN_LOOP, APPOINTMENT_BUSINESS_PROFILES, AppointmentBusinessLoopPlan, compile_appointment_business_blueprint
from lightbulb.appointment_business_primitives import APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES, APPOINTMENT_BUSINESS_INTEGRATION_MANIFEST
from lightbulb.business_artifact_production import BUSINESS_ARTIFACT_GOLDEN_LOOP
from lightbulb.marketplace_business_loop import MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST, MARKETPLACE_BUSINESS_GOLDEN_LOOP, MARKETPLACE_BUSINESS_PROFILES, MarketplaceBusinessLoopPlan, compile_marketplace_business_blueprint
from lightbulb.marketplace_business_primitives import MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES, MARKETPLACE_BUSINESS_INTEGRATION_MANIFEST
from lightbulb.company_operating_primitives import COMPANY_OS_EXECUTABLE_PRIMITIVES, COMPANY_OS_INTEGRATION_MANIFEST
from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES, COMPANY_OS_GOLDEN_LOOP, COMPANY_OS_MANIFEST, CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.growth_engine_loop import GROWTH_ENGINE_GOLDEN_LOOP, GROWTH_ENGINE_MANIFEST, GROWTH_ENGINE_PROFILES, GrowthEngineLoopPlan, compile_growth_engine_blueprint
from lightbulb.growth_engine_primitives import GROWTH_ENGINE_EXECUTABLE_PRIMITIVES, GROWTH_ENGINE_INTEGRATION_MANIFEST
from lightbulb.pipeline_engine_loop import PIPELINE_ENGINE_GOLDEN_LOOP, PIPELINE_ENGINE_MANIFEST, PIPELINE_ENGINE_PROFILES, PipelineEngineLoopPlan, compile_pipeline_engine_blueprint
from lightbulb.pipeline_engine_primitives import PIPELINE_ENGINE_EXECUTABLE_PRIMITIVES, PIPELINE_ENGINE_INTEGRATION_MANIFEST
from lightbulb.saas_operating_loop import SAAS_OPERATING_GOLDEN_LOOP, SAAS_OPERATING_MANIFEST, SAAS_OPERATING_PROFILES, SaasOperatingLoopPlan, compile_saas_operating_blueprint
from lightbulb.saas_operating_primitives import SAAS_OPERATING_EXECUTABLE_PRIMITIVES, SAAS_OPERATING_INTEGRATION_MANIFEST
from lightbulb.company_simulator_primitives import SIMULATION_EXECUTABLE_PRIMITIVES, SIMULATION_INTEGRATION_MANIFEST
from lightbulb.company_workforce import STANDARD_ROSTERS, WORKFORCE_GOLDEN_LOOP, WORKFORCE_MANIFEST
from lightbulb.company_workforce_primitives import WORKFORCE_EXECUTABLE_PRIMITIVES, WORKFORCE_INTEGRATION_MANIFEST
from lightbulb.finance_close_engine import FINANCE_CLOSE_GOLDEN_LOOP, FINANCE_CLOSE_MANIFEST, FINANCE_CLOSE_PROFILES, FinanceCloseLoopPlan, compile_finance_close_blueprint
from lightbulb.finance_close_primitives import FINANCE_CLOSE_EXECUTABLE_PRIMITIVES, FINANCE_CLOSE_INTEGRATION_MANIFEST
from lightbulb.service_delivery_engine import SERVICE_DELIVERY_GOLDEN_LOOP, SERVICE_DELIVERY_MANIFEST, SERVICE_DELIVERY_PROFILES, ServiceDeliveryLoopPlan, compile_service_delivery_blueprint
from lightbulb.service_delivery_primitives import SERVICE_DELIVERY_EXECUTABLE_PRIMITIVES, SERVICE_DELIVERY_INTEGRATION_MANIFEST
from lightbulb.company_cadence_primitives import CADENCE_EXECUTABLE_PRIMITIVES, CADENCE_INTEGRATION_MANIFEST
from lightbulb.company_cadence_runner import CADENCE_GOLDEN_LOOP, CADENCE_MANIFEST
from lightbulb.company_signal_primitives import SIGNAL_CONSUMER_EXECUTABLE_PRIMITIVES, SIGNAL_CONSUMER_INTEGRATION_MANIFEST
from lightbulb.company_approval_inbox_primitives import INBOX_EXECUTABLE_PRIMITIVES, INBOX_INTEGRATION_MANIFEST
from lightbulb.company_bring_up_primitives import BRING_UP_EXECUTABLE_PRIMITIVES, BRING_UP_INTEGRATION_MANIFEST
from lightbulb.company_deepening_primitives import DEEPENING_EXECUTABLE_PRIMITIVES, DEEPENING_INTEGRATION_MANIFEST
from lightbulb.vertical_deepening_primitives import VERTICAL_EXECUTABLE_PRIMITIVES, VERTICAL_INTEGRATION_MANIFEST
from lightbulb.primitive_runtime import BusinessProcessPrimitive
from lightbulb.product_commerce_loop import PRODUCT_COMMERCE_ARCHETYPE_MANIFEST, PRODUCT_COMMERCE_GOLDEN_LOOP, ProductCommerceLoopPlan, compile_product_commerce_blueprint
from lightbulb.product_commerce_loop import PRODUCT_COMMERCE_PROFILES
from lightbulb.product_commerce_primitives import PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES, PRODUCT_COMMERCE_INTEGRATION_MANIFEST
from lightbulb.saas_product_loop import SAAS_PRODUCT_ARCHETYPE_MANIFEST, SAAS_PRODUCT_GOLDEN_LOOP, SAAS_PRODUCT_PROFILES, SaasProductLoopPlan, compile_saas_product_blueprint
from lightbulb.saas_product_primitives import SAAS_PRODUCT_EXECUTABLE_PRIMITIVES, SAAS_PRODUCT_INTEGRATION_MANIFEST
from lightbulb.service_business_exception_primitives import SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES, SERVICE_EXCEPTION_INTEGRATION_MANIFEST
from lightbulb.service_business_exceptions import SERVICE_EXCEPTIONS_LOOP_EXTENSION
from lightbulb.service_business_loop import SERVICE_BUSINESS_ARCHETYPE_MANIFEST, SERVICE_BUSINESS_GOLDEN_LOOP, SERVICE_BUSINESS_PROFILES, ServiceBusinessLoopPlan, compile_service_business_blueprint
from lightbulb.service_business_primitives import SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES, SERVICE_BUSINESS_INTEGRATION_MANIFEST
from lightbulb.subscription_business_loop import SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST, SUBSCRIPTION_BUSINESS_GOLDEN_LOOP, SUBSCRIPTION_BUSINESS_PROFILES, SubscriptionBusinessLoopPlan, compile_subscription_business_blueprint
from lightbulb.subscription_business_primitives import SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES, SUBSCRIPTION_BUSINESS_INTEGRATION_MANIFEST
from lightbulb.service_engagement import SERVICE_ENGAGEMENT_GOLDEN_LOOP
from lightbulb.service_operations_primitives import SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES, SERVICE_OPERATIONS_INTEGRATION_MANIFEST
from lightbulb.software_production import SOFTWARE_PRODUCTION_GOLDEN_LOOP
from lightbulb.software_production_loop_primitives import SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES, SOFTWARE_PRODUCTION_LOOP_INTEGRATION_MANIFEST
from lightbulb.software_production_mcp import SOFTWARE_PRODUCTION_MCP_INTEGRATION_MANIFEST
from lightbulb.software_production_primitives import SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES, SOFTWARE_PRODUCTION_INTEGRATION_MANIFEST


FABLE_PACKS_SCHEMA = "lightbulb.fable_capability_packs.v1"

# Integration order: each pack after the first may bind by reference to those before it.
FABLE_PACK_MANIFESTS: tuple[Mapping[str, Any], ...] = (
    COMMERCIAL_LEGAL_HANDOFF_INTEGRATION_MANIFEST,
    CONTRACT_OBLIGATION_INTEGRATION_MANIFEST,
    CONTRACT_DELIVERY_INTEGRATION_MANIFEST,
    SERVICE_OPERATIONS_INTEGRATION_MANIFEST,
    SERVICE_BUSINESS_INTEGRATION_MANIFEST,
    SERVICE_EXCEPTION_INTEGRATION_MANIFEST,
    SOFTWARE_PRODUCTION_INTEGRATION_MANIFEST,
    SOFTWARE_PRODUCTION_LOOP_INTEGRATION_MANIFEST,
    SOFTWARE_PRODUCTION_MCP_INTEGRATION_MANIFEST,
    PRODUCT_COMMERCE_INTEGRATION_MANIFEST,
    SUBSCRIPTION_BUSINESS_INTEGRATION_MANIFEST,
    SAAS_PRODUCT_INTEGRATION_MANIFEST,
    APPOINTMENT_BUSINESS_INTEGRATION_MANIFEST,
    MARKETPLACE_BUSINESS_INTEGRATION_MANIFEST,
    GROWTH_ENGINE_INTEGRATION_MANIFEST,
    PIPELINE_ENGINE_INTEGRATION_MANIFEST,
    SAAS_OPERATING_INTEGRATION_MANIFEST,
    COMPANY_OS_INTEGRATION_MANIFEST,
    FINANCE_CLOSE_INTEGRATION_MANIFEST,
    SERVICE_DELIVERY_INTEGRATION_MANIFEST,
    WORKFORCE_INTEGRATION_MANIFEST,
    SIMULATION_INTEGRATION_MANIFEST,
    CADENCE_INTEGRATION_MANIFEST,
    SIGNAL_CONSUMER_INTEGRATION_MANIFEST,
    INBOX_INTEGRATION_MANIFEST,
    DEEPENING_INTEGRATION_MANIFEST,
    BRING_UP_INTEGRATION_MANIFEST,
    VERTICAL_INTEGRATION_MANIFEST,
)

FABLE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    *COMMERCIAL_LEGAL_HANDOFF_EXECUTABLE_PRIMITIVES,
    *CONTRACT_OBLIGATION_EXECUTABLE_PRIMITIVES,
    *CONTRACT_DELIVERY_EXECUTABLE_PRIMITIVES,
    *SERVICE_OPERATIONS_EXECUTABLE_PRIMITIVES,
    *SERVICE_BUSINESS_EXECUTABLE_PRIMITIVES,
    *SERVICE_EXCEPTION_EXECUTABLE_PRIMITIVES,
    *SOFTWARE_PRODUCTION_EXECUTABLE_PRIMITIVES,
    *SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES,
    *PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES,
    *SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES,
    *SAAS_PRODUCT_EXECUTABLE_PRIMITIVES,
    *APPOINTMENT_BUSINESS_EXECUTABLE_PRIMITIVES,
    *MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES,
    *GROWTH_ENGINE_EXECUTABLE_PRIMITIVES,
    *PIPELINE_ENGINE_EXECUTABLE_PRIMITIVES,
    *SAAS_OPERATING_EXECUTABLE_PRIMITIVES,
    *COMPANY_OS_EXECUTABLE_PRIMITIVES,
    *FINANCE_CLOSE_EXECUTABLE_PRIMITIVES,
    *SERVICE_DELIVERY_EXECUTABLE_PRIMITIVES,
    *WORKFORCE_EXECUTABLE_PRIMITIVES,
    *SIMULATION_EXECUTABLE_PRIMITIVES,
    *CADENCE_EXECUTABLE_PRIMITIVES,
    *SIGNAL_CONSUMER_EXECUTABLE_PRIMITIVES,
    *INBOX_EXECUTABLE_PRIMITIVES,
    *DEEPENING_EXECUTABLE_PRIMITIVES,
    *BRING_UP_EXECUTABLE_PRIMITIVES,
    *VERTICAL_EXECUTABLE_PRIMITIVES,
)

FABLE_GOLDEN_LOOPS: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.commercial_legal_handoff", "kind": "handoff"}),
        CONTRACT_OBLIGATION_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.contract_obligations", "kind": "lifecycle"}),
        CONTRACT_DELIVERY_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.contract_delivery_acceptance", "kind": "lifecycle"}),
        BUSINESS_ARTIFACT_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.business_artifact_production", "kind": "production"}),
        SERVICE_ENGAGEMENT_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.service_engagement", "kind": "lifecycle"}),
        SERVICE_BUSINESS_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.service_business_loop", "kind": "operating_loop", "archetype": "service_business"}),
        SERVICE_EXCEPTIONS_LOOP_EXTENSION: MappingProxyType({"module": "lightbulb.service_business_exceptions", "kind": "loop_extension", "extends": SERVICE_BUSINESS_GOLDEN_LOOP}),
        SOFTWARE_PRODUCTION_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.software_production_loop", "kind": "operating_loop"}),
        PRODUCT_COMMERCE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.product_commerce_loop", "kind": "operating_loop", "archetype": "product_commerce"}),
        SUBSCRIPTION_BUSINESS_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.subscription_business_loop", "kind": "operating_loop", "archetype": "subscription_business"}),
        SAAS_PRODUCT_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.saas_product_loop", "kind": "operating_loop", "archetype": "saas_product"}),
        APPOINTMENT_BUSINESS_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.appointment_business_loop", "kind": "operating_loop", "archetype": "appointment_business"}),
        MARKETPLACE_BUSINESS_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.marketplace_business_loop", "kind": "operating_loop", "archetype": "marketplace_business"}),
        GROWTH_ENGINE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.growth_engine_loop", "kind": "company_engine", "archetype": "growth_engine"}),
        PIPELINE_ENGINE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.pipeline_engine_loop", "kind": "company_engine", "archetype": "pipeline_engine"}),
        SAAS_OPERATING_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.saas_operating_loop", "kind": "company_engine", "archetype": "saas_operating_engine"}),
        COMPANY_OS_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.company_operating_system", "kind": "company_operating_system", "archetype": "company_operating_system"}),
        FINANCE_CLOSE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.finance_close_engine", "kind": "company_engine", "archetype": "finance_close"}),
        SERVICE_DELIVERY_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.service_delivery_engine", "kind": "company_engine", "archetype": "service_delivery"}),
        WORKFORCE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.company_workforce", "kind": "company_workforce", "archetype": "company_workforce"}),
        CADENCE_GOLDEN_LOOP: MappingProxyType({"module": "lightbulb.company_cadence_runner", "kind": "company_cadence", "archetype": "company_cadence"}),
    }
)

FABLE_COMPANY_BLUEPRINT_ARCHETYPES: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        SERVICE_BUSINESS_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**SERVICE_BUSINESS_ARCHETYPE_MANIFEST, "profile_catalog": SERVICE_BUSINESS_PROFILES}),
        PRODUCT_COMMERCE_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**PRODUCT_COMMERCE_ARCHETYPE_MANIFEST, "profile_catalog": PRODUCT_COMMERCE_PROFILES}),
        SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST, "profile_catalog": SUBSCRIPTION_BUSINESS_PROFILES}),
        SAAS_PRODUCT_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**SAAS_PRODUCT_ARCHETYPE_MANIFEST, "profile_catalog": SAAS_PRODUCT_PROFILES}),
        APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**APPOINTMENT_BUSINESS_ARCHETYPE_MANIFEST, "profile_catalog": APPOINTMENT_BUSINESS_PROFILES}),
        MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST["archetype"]: MappingProxyType({**MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST, "profile_catalog": MARKETPLACE_BUSINESS_PROFILES}),
        "growth_engine": MappingProxyType({"archetype": "growth_engine", "kind": "company_engine", "golden_loop": GROWTH_ENGINE_GOLDEN_LOOP, "composable_with": [], "profile_catalog": GROWTH_ENGINE_PROFILES, "engine_manifest": GROWTH_ENGINE_MANIFEST}),
        "pipeline_engine": MappingProxyType({"archetype": "pipeline_engine", "kind": "company_engine", "golden_loop": PIPELINE_ENGINE_GOLDEN_LOOP, "composable_with": [], "profile_catalog": PIPELINE_ENGINE_PROFILES, "engine_manifest": PIPELINE_ENGINE_MANIFEST}),
        "saas_operating_engine": MappingProxyType({"archetype": "saas_operating_engine", "kind": "company_engine", "golden_loop": SAAS_OPERATING_GOLDEN_LOOP, "composable_with": [], "profile_catalog": SAAS_OPERATING_PROFILES, "engine_manifest": SAAS_OPERATING_MANIFEST}),
        "company_operating_system": MappingProxyType({"archetype": "company_operating_system", "kind": "company_operating_system", "golden_loop": COMPANY_OS_GOLDEN_LOOP, "composable_with": [], "profile_catalog": COMPANY_OS_ARCHETYPES, "engine_manifest": COMPANY_OS_MANIFEST}),
        "finance_close": MappingProxyType({"archetype": "finance_close", "kind": "company_engine", "golden_loop": FINANCE_CLOSE_GOLDEN_LOOP, "composable_with": [], "profile_catalog": FINANCE_CLOSE_PROFILES, "engine_manifest": FINANCE_CLOSE_MANIFEST}),
        "service_delivery": MappingProxyType({"archetype": "service_delivery", "kind": "company_engine", "golden_loop": SERVICE_DELIVERY_GOLDEN_LOOP, "composable_with": [], "profile_catalog": SERVICE_DELIVERY_PROFILES, "engine_manifest": SERVICE_DELIVERY_MANIFEST}),
        "company_workforce": MappingProxyType({"archetype": "company_workforce", "kind": "company_workforce", "golden_loop": WORKFORCE_GOLDEN_LOOP, "composable_with": [], "profile_catalog": STANDARD_ROSTERS, "engine_manifest": WORKFORCE_MANIFEST}),
        "company_cadence": MappingProxyType({"archetype": "company_cadence", "kind": "company_cadence", "golden_loop": CADENCE_GOLDEN_LOOP, "composable_with": [], "profile_catalog": {}, "engine_manifest": CADENCE_MANIFEST}),
    }
)

FABLE_MCP_REGISTRATIONS: tuple[Mapping[str, Any], ...] = (
    MappingProxyType({"module": "lightbulb.mcp_service_operations", "function": "register_service_operations", "arguments": "mcp"}),
    MappingProxyType({"module": "lightbulb.software_production_mcp", "function": "register_software_production", "arguments": "mcp, backend=<Spring-backed backend>, principal_provider=<session principal>"}),
)


def fable_primitive_refs() -> tuple[str, ...]:
    return tuple(item.primitive_ref for item in FABLE_EXECUTABLE_PRIMITIVES)


_LoopPlan = ServiceBusinessLoopPlan | ProductCommerceLoopPlan | SubscriptionBusinessLoopPlan | SaasProductLoopPlan | AppointmentBusinessLoopPlan | MarketplaceBusinessLoopPlan | GrowthEngineLoopPlan | PipelineEngineLoopPlan | SaasOperatingLoopPlan | CompanyOperatingPlan | FinanceCloseLoopPlan | ServiceDeliveryLoopPlan


def _loop_plans() -> list[_LoopPlan]:
    plans: list[_LoopPlan] = [compile_service_business_blueprint(profile) for profile in sorted(SERVICE_BUSINESS_PROFILES)]
    plans.extend(compile_product_commerce_blueprint(profile) for profile in sorted(PRODUCT_COMMERCE_PROFILES))
    plans.extend(compile_subscription_business_blueprint(profile) for profile in sorted(SUBSCRIPTION_BUSINESS_PROFILES))
    plans.extend(compile_saas_product_blueprint(profile) for profile in sorted(SAAS_PRODUCT_PROFILES))
    plans.extend(compile_appointment_business_blueprint(profile) for profile in sorted(APPOINTMENT_BUSINESS_PROFILES))
    plans.extend(compile_marketplace_business_blueprint(profile) for profile in sorted(MARKETPLACE_BUSINESS_PROFILES))
    plans.extend(compile_growth_engine_blueprint(profile) for profile in sorted(GROWTH_ENGINE_PROFILES))
    plans.extend(compile_pipeline_engine_blueprint(profile) for profile in sorted(PIPELINE_ENGINE_PROFILES))
    plans.extend(compile_saas_operating_blueprint(profile) for profile in sorted(SAAS_OPERATING_PROFILES))
    plans.extend(compile_company_operating_blueprint(archetype) for archetype in sorted(COMPANY_OS_ARCHETYPES))
    plans.extend(compile_finance_close_blueprint(profile) for profile in sorted(FINANCE_CLOSE_PROFILES))
    plans.extend(compile_service_delivery_blueprint(profile) for profile in sorted(SERVICE_DELIVERY_PROFILES))
    return plans


def validate_capability_packs(builtin_refs: Mapping[str, Any] | set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None) -> dict[str, Any]:
    """Prove cross-pack consistency; returns a report or raises ValueError with every finding."""

    if builtin_refs is None:
        from lightbulb.executable_primitives import BUILTIN_EXECUTABLE_PRIMITIVES

        # After the splice the packs are part of the built-in tuple; compare against everything else.
        pack_ids = {id(item) for item in FABLE_EXECUTABLE_PRIMITIVES}
        builtin = {item.primitive_ref for item in BUILTIN_EXECUTABLE_PRIMITIVES if id(item) not in pack_ids}
    else:
        builtin = set(builtin_refs)
    findings: list[str] = []
    refs = fable_primitive_refs()
    duplicates = sorted({ref for ref in refs if refs.count(ref) > 1})
    if duplicates:
        findings.append(f"duplicate primitive refs across packs: {duplicates}")
    collisions = sorted(set(refs) & builtin)
    if collisions:
        findings.append(f"pack primitive refs collide with built-ins: {collisions}")
    for primitive in FABLE_EXECUTABLE_PRIMITIVES:
        if primitive.connector_tools != () or getattr(primitive, "mcp_read_only", False) is not True:
            findings.append(f"{primitive.primitive_ref} must stay read-only with no connector tools until integration")
        try:
            primitive.input_model.model_validate(dict(primitive.example_inputs))
        except Exception as exc:  # noqa: BLE001
            findings.append(f"{primitive.primitive_ref} example inputs do not validate: {str(exc)[:160]}")
    manifest_refs = [ref for manifest in FABLE_PACK_MANIFESTS for ref in manifest.get("primitive_refs", [])]
    missing_from_manifests = sorted(set(refs) - set(manifest_refs))
    if missing_from_manifests:
        findings.append(f"primitives without an integration manifest entry: {missing_from_manifests}")
    unknown_in_manifests = sorted(set(manifest_refs) - set(refs))
    if unknown_in_manifests:
        findings.append(f"manifest primitive refs with no executable primitive: {unknown_in_manifests}")
    known = builtin | set(refs)
    for plan in _loop_plans():
        for stage in plan.stages:
            unresolved = [ref for ref in stage.primitive_refs if ref not in known]
            if unresolved:
                findings.append(f"{plan.golden_loop} stage {stage.stage} binds unresolved primitives: {unresolved}")
    loops = list(FABLE_GOLDEN_LOOPS)
    if len(set(loops)) != len(loops) or any("@" not in loop for loop in loops):
        findings.append("golden loop names must be unique and versioned")
    for archetype, manifest in FABLE_COMPANY_BLUEPRINT_ARCHETYPES.items():
        for other in manifest.get("composable_with", []):
            if other not in FABLE_COMPANY_BLUEPRINT_ARCHETYPES or archetype not in FABLE_COMPANY_BLUEPRINT_ARCHETYPES[other].get("composable_with", []):
                findings.append(f"archetype composability is not symmetric between {archetype} and {other}")
        if manifest.get("golden_loop") not in FABLE_GOLDEN_LOOPS:
            findings.append(f"archetype {archetype} names an unregistered golden loop")
    if findings:
        raise ValueError("; ".join(findings))
    return {
        "schema": FABLE_PACKS_SCHEMA,
        "packs": [manifest["capability_pack"] for manifest in FABLE_PACK_MANIFESTS],
        "primitive_count": len(refs),
        "primitive_refs": list(refs),
        "golden_loops": loops,
        "archetypes": sorted(FABLE_COMPANY_BLUEPRINT_ARCHETYPES),
        "builtin_count_before": len(builtin),
        "builtin_count_after": len(builtin) + len(refs),
        "mcp_registrations": [dict(item) for item in FABLE_MCP_REGISTRATIONS],
    }


FABLE_INTEGRATION_PLAN: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_plan.v1",
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "splice": "from lightbulb.fable_capability_packs import FABLE_EXECUTABLE_PRIMITIVES; *FABLE_EXECUTABLE_PRIMITIVES appended to BUILTIN_EXECUTABLE_PRIMITIVES"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["FABLE_EXECUTABLE_PRIMITIVES", "FABLE_GOLDEN_LOOPS", "FABLE_COMPANY_BLUEPRINT_ARCHETYPES", "FABLE_PACK_MANIFESTS", "validate_capability_packs"]},
    "mcp_server": {"file": "lightbulb/mcp_server.py", "registrations": [dict(item) for item in FABLE_MCP_REGISTRATIONS], "deprecations": SOFTWARE_PRODUCTION_MCP_INTEGRATION_MANIFEST["mcp_server"]["deprecate"]},
    "registries": {"golden_loops": "register FABLE_GOLDEN_LOOPS", "company_blueprints": "register FABLE_COMPANY_BLUEPRINT_ARCHETYPES"},
    "tests_pinning_counts": ["tests/test_sdk_runtime.py (executable catalog count)", "tests/test_workflow_improvement.py (executable catalog count)"],
}

__all__ = [
    "FABLE_COMPANY_BLUEPRINT_ARCHETYPES",
    "FABLE_EXECUTABLE_PRIMITIVES",
    "FABLE_GOLDEN_LOOPS",
    "FABLE_INTEGRATION_PLAN",
    "FABLE_MCP_REGISTRATIONS",
    "FABLE_PACKS_SCHEMA",
    "FABLE_PACK_MANIFESTS",
    "fable_primitive_refs",
    "validate_capability_packs",
]
