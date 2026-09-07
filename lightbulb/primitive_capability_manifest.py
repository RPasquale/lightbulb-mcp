"""Canonical, versioned capability metadata for Executable Primitives.

The checked manifest is the contract projected by SDK and hosted MCP surfaces.
It is generated from :func:`default_primitive_registry`; callers never maintain
a second catalog by hand.
"""

from __future__ import annotations

import copy
import hashlib
import json
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from lightbulb.governed_connector_contracts import connector_surface_effect
from lightbulb.primitive_runtime import (
    PRIMITIVE_EVIDENCE_REF_SCHEMA,
    PRIMITIVE_EXECUTION_RESULT_SCHEMA,
    PRIMITIVE_OPERATION_RECEIPT_SCHEMA,
    PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA,
    PRIMITIVE_RECOVERY_PLAN_SCHEMA,
    PrimitiveEvidenceClassification,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionStatus,
    PrimitiveOperationStatus,
)


PRIMITIVE_CAPABILITY_MANIFEST_SCHEMA = (
    "lightbulb.primitive_capability_manifest.v1"
)
PRIMITIVE_CAPABILITY_MANIFEST_VERSION = "1.0.0"
PRIMITIVE_CAPABILITY_MANIFEST_RESOURCE = (
    "data/primitive-capability-manifest.v1.json"
)
PRIMITIVE_TERMINAL_SEMANTICS_SCHEMA = (
    "lightbulb.primitive_terminal_semantics.v1"
)
PRIMITIVE_ERROR_SEMANTICS_SCHEMA = "lightbulb.primitive_error_semantics.v1"
PRIMITIVE_EVENT_SEMANTICS_SCHEMA = "lightbulb.primitive_event_semantics.v1"
PRIMITIVE_EVIDENCE_SEMANTICS_SCHEMA = (
    "lightbulb.primitive_evidence_semantics.v1"
)
PRIMITIVE_CAPABILITY_COMPILER_CONTRACT = {
    "mode": "projection_validator_no_business_logic_generation",
    "required_projections": [
        "python_catalog_and_runtime",
        "sdk_sync_and_async",
        "python_mcp",
        "spring_hosted_manifest",
        "agent_and_workflow_binding",
        "documentation_and_capability_inventory",
    ],
    "lighthouse_contracts": [
        "quickbooks.journal_proposal_approval_write_observe_reconcile.v1"
    ],
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _memberships() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return primitive-to-loop and primitive-to-blueprint memberships."""

    from lightbulb.reference_company_blueprints import (
        AI_NATIVE_SERVICES_STUDIO_BLUEPRINT,
    )
    from lightbulb.reference_golden_loops import INITIAL_GTM_GOLDEN_LOOP_CATALOG

    loop_memberships: dict[str, set[str]] = {}
    for manifest in INITIAL_GTM_GOLDEN_LOOP_CATALOG.manifests:
        for step in manifest.primitive_steps:
            loop_memberships.setdefault(step.primitive_ref, set()).add(
                manifest.loop_ref
            )

    blueprint_memberships = {
        primitive_ref: {AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.blueprint_ref}
        for primitive_ref in AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.allowed_primitive_refs
    }
    return loop_memberships, blueprint_memberships


def _effect_metadata(connector_tools: list[str]) -> dict[str, Any]:
    tool_effects = {
        tool_ref: connector_surface_effect(tool_ref)
        for tool_ref in connector_tools
    }
    if not connector_tools:
        effect_class = "provider_free"
    elif any(effect == "write" for effect in tool_effects.values()):
        effect_class = "consequential_write"
    else:
        effect_class = "connector_read"
    return {
        "effect_class": effect_class,
        "connector_tool_effects": tool_effects,
    }


def _runtime_semantics(
    *,
    primitive_version: str,
    effect_class: str,
    agentic_workflow: Mapping[str, Any],
    runtime_guarantees: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Project the existing runtime result contracts into portable metadata."""

    consequential_write = effect_class == "consequential_write"
    declared_event_types = sorted(
        {
            event_type.strip()
            for event_type in agentic_workflow.get("emits", ())
            if isinstance(event_type, str) and event_type.strip()
        }
    )
    return {
        "terminal_semantics": {
            "schema": PRIMITIVE_TERMINAL_SEMANTICS_SCHEMA,
            "primitive_version": primitive_version,
            "result_schema": PRIMITIVE_EXECUTION_RESULT_SCHEMA,
            "statuses": [status.value for status in PrimitiveExecutionStatus],
            "terminal_statuses": [
                PrimitiveExecutionStatus.COMPLETED.value,
                PrimitiveExecutionStatus.PREVIEW.value,
                PrimitiveExecutionStatus.BLOCKED.value,
                PrimitiveExecutionStatus.FAILED.value,
            ],
            "resumable_statuses": [
                PrimitiveExecutionStatus.PENDING_APPROVAL.value,
                PrimitiveExecutionStatus.NEEDS_INPUT.value,
            ],
            "successful_terminal_statuses": [
                PrimitiveExecutionStatus.COMPLETED.value
            ],
            "effect_free_terminal_statuses": [
                PrimitiveExecutionStatus.PREVIEW.value
            ],
            "completed_requires_resolved_operation_receipts": True,
            "ambiguity": {
                "applicable": consequential_write,
                "representation": (
                    "operation_receipt" if consequential_write else "not_applicable"
                ),
                "operation_status": (
                    PrimitiveOperationStatus.IN_DOUBT.value
                    if consequential_write
                    else "not_applicable"
                ),
                "top_level_success_permitted": False,
                "redispatch_before_reconciliation_permitted": False,
                "resolution": (
                    "independent_observation_required"
                    if consequential_write
                    else "not_applicable"
                ),
            },
        },
        "error_semantics": {
            "schema": PRIMITIVE_ERROR_SEMANTICS_SCHEMA,
            "primitive_version": primitive_version,
            "result_schema": PRIMITIVE_EXECUTION_RESULT_SCHEMA,
            "container": "blockers",
            "item_type": "PrimitiveBlocker",
            "required_fields": ["code", "message"],
            "optional_fields": ["field", "retryable"],
            "additional_properties": False,
            "status_mapping": {
                "input_validation": {
                    "status_contract": "execution_result",
                    "status": PrimitiveExecutionStatus.NEEDS_INPUT.value,
                },
                "authority_or_policy_denial": {
                    "status_contract": "execution_result",
                    "status": PrimitiveExecutionStatus.BLOCKED.value,
                },
                "implementation_exception": {
                    "status_contract": "execution_result",
                    "status": PrimitiveExecutionStatus.FAILED.value,
                },
                "post_boundary_unknown": {
                    "status_contract": (
                        "operation_receipt"
                        if consequential_write
                        else "not_applicable"
                    ),
                    "status": (
                        PrimitiveOperationStatus.IN_DOUBT.value
                        if consequential_write
                        else "not_applicable"
                    ),
                },
            },
            "raw_exception_details_exposed": False,
        },
        "event_semantics": {
            "schema": PRIMITIVE_EVENT_SEMANTICS_SCHEMA,
            "primitive_version": primitive_version,
            "result_schema": PRIMITIVE_EXECUTION_RESULT_SCHEMA,
            "container": "events",
            "item_type": "PrimitiveEvent",
            "required_fields": ["type", "payload"],
            "additional_properties": False,
            "structured": runtime_guarantees.get("events_are_structured") is True,
            "publication": "after_output_validation",
            "declaration_scope": (
                "composition_declared_subset"
                if declared_event_types
                else "runtime_typed_without_static_event_types"
            ),
            "declared_event_types": declared_event_types,
        },
        "evidence_semantics": {
            "schema": PRIMITIVE_EVIDENCE_SEMANTICS_SCHEMA,
            "primitive_version": primitive_version,
            "result_schema": PRIMITIVE_EXECUTION_RESULT_SCHEMA,
            "inline": {
                "container": "evidence",
                "item_type": "PrimitiveEvidence",
                "required_fields": ["kind", "summary"],
                "optional_fields": ["labels", "refs"],
                "additional_properties": False,
            },
            "references": {
                "container": "evidence_refs",
                "item_schema": PRIMITIVE_EVIDENCE_REF_SCHEMA,
                "typed": runtime_guarantees.get("typed_evidence_refs") is True,
                "verification_grades": [
                    grade.value for grade in PrimitiveEvidenceVerificationGrade
                ],
                "classifications": [
                    classification.value
                    for classification in PrimitiveEvidenceClassification
                ],
            },
            "operation_receipts": {
                "container": "operation_receipts",
                "item_schema": PRIMITIVE_OPERATION_RECEIPT_SCHEMA,
                "typed": runtime_guarantees.get("typed_operation_receipts") is True,
            },
            "recovery_plan": {
                "field": "recovery_plan",
                "schema": PRIMITIVE_RECOVERY_PLAN_SCHEMA,
                "typed": runtime_guarantees.get("typed_recovery_plans") is True,
            },
            "completion": {
                "write_provenance_required": consequential_write,
                "unresolved_operation_receipts_permitted": False,
            },
            "ambiguity_resolution": {
                "applicable": consequential_write,
                "attestation_schema": (
                    PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA
                    if consequential_write
                    else "not_applicable"
                ),
                "independent_observation_required": consequential_write,
                "caller_assertion_sufficient": False,
            },
        },
    }


def build_primitive_capability_manifest() -> dict[str, Any]:
    """Build one projection from the executable registry plus composition metadata."""

    from lightbulb.business_primitives import BUSINESS_PRIMITIVES
    from lightbulb.executable_primitives import default_primitive_registry

    loop_memberships, blueprint_memberships = _memberships()
    registry_catalog = default_primitive_registry().catalog()
    descriptive_contracts = {
        primitive.id: primitive.to_dict(include_inputs=False)
        for primitive in BUSINESS_PRIMITIVES
    }
    registered_refs = {entry["primitive_ref"] for entry in registry_catalog}
    descriptive_only_refs = set(descriptive_contracts).difference(registered_refs)
    if descriptive_only_refs:
        raise RuntimeError(
            "Descriptive-only primitive refs cannot enter the canonical manifest: "
            + ", ".join(sorted(descriptive_only_refs))
        )
    primitives: list[dict[str, Any]] = []
    for catalog_entry in registry_catalog:
        primitive_ref = catalog_entry["primitive_ref"]
        descriptive = descriptive_contracts.get(primitive_ref, {})
        connector_tools = list(catalog_entry["connector_tools"])
        effect = _effect_metadata(connector_tools)
        consequential_write = effect["effect_class"] == "consequential_write"
        connector_backed = bool(connector_tools)
        agentic_workflow = dict(descriptive.get("agentic_workflow") or {})
        runtime_guarantees = dict(catalog_entry["runtime_guarantees"])
        runtime_semantics = _runtime_semantics(
            primitive_version=catalog_entry["version"],
            effect_class=effect["effect_class"],
            agentic_workflow=agentic_workflow,
            runtime_guarantees=runtime_guarantees,
        )
        approval_required = bool(
            catalog_entry["approval_required"] or consequential_write
        )
        primitives.append(
            {
                "schema": catalog_entry["schema"],
                "primitive_ref": primitive_ref,
                "version": catalog_entry["version"],
                "title": catalog_entry["title"],
                "description": catalog_entry["description"],
                "category": descriptive.get(
                    "category", primitive_ref.split(".", 1)[0]
                ),
                "input_schema": catalog_entry["input_schema"],
                "output_schema": catalog_entry["output_schema"],
                "example_inputs": catalog_entry["example_inputs"],
                "composition": {
                    "default_mode": descriptive.get("default_mode"),
                    "preferred_domain_action": descriptive.get(
                        "preferred_domain_action"
                    ),
                    "capability_hints": list(
                        descriptive.get("capability_hints") or ()
                    ),
                    "agentic_workflow": agentic_workflow,
                    "backbone_fallback_available": descriptive.get(
                        "backbone_fallback_available"
                    ),
                },
                # Retained at the legacy field while Agent Builder moves to the
                # versioned ``composition`` object. Both are generated here;
                # hosted MCP no longer maintains its own primitive rows.
                "agentic_workflow": agentic_workflow,
                "risk_level": catalog_entry["risk_level"],
                "effect_class": effect["effect_class"],
                "connector_tools": connector_tools,
                "connector_tool_effects": effect["connector_tool_effects"],
                "approval": {
                    "required": approval_required,
                    "authority": "spring",
                    "binding": (
                        "exact_project_account_operation_payload_preimage"
                        if approval_required
                        else "not_required"
                    ),
                },
                "idempotency": {
                    "required": consequential_write,
                    "scope": (
                        "spring_governed_execution_journal"
                        if consequential_write
                        else "not_required"
                    ),
                },
                "execution": {
                    "sdk_sync": "executable_primitive_runtime",
                    "sdk_async": "managed_sync_runtime_bridge",
                    "python_mcp": "executable_primitive_runtime",
                    "hosted_mcp": "manifest_only_fail_closed",
                    "live_write_authority": "spring",
                },
                "recovery": {
                    "post_boundary_unknown": (
                        "ambiguous_requires_independent_observation"
                        if consequential_write
                        else "not_applicable"
                    ),
                    "transport_retry": (
                        "disabled_for_writes"
                        if consequential_write
                        else "safe_for_provider_free_or_read"
                    ),
                },
                **runtime_semantics,
                "availability": {
                    "local_source": "LOCAL_SOURCE_COMPLETE",
                    "python_runtime": "LOCAL_TARGETED_VERIFICATION_REQUIRED",
                    "hosted_runtime": "EXTERNAL_BLOCKED",
                    "production_effects": (
                        "EXTERNAL_BLOCKED" if connector_backed else "NOT_APPLICABLE"
                    ),
                },
                "certification_state": (
                    "UNCERTIFIED" if connector_backed else "NOT_APPLICABLE"
                ),
                "mcp_annotations": catalog_entry["mcp_annotations"],
                "runtime_guarantees": runtime_guarantees,
                "memberships": {
                    "golden_operating_loops": sorted(
                        loop_memberships.get(primitive_ref, ())
                    ),
                    "company_blueprints": sorted(
                        blueprint_memberships.get(primitive_ref, ())
                    ),
                },
            }
        )

    payload: dict[str, Any] = {
        "schema": PRIMITIVE_CAPABILITY_MANIFEST_SCHEMA,
        "manifest_version": PRIMITIVE_CAPABILITY_MANIFEST_VERSION,
        "source_registry": (
            "lightbulb.executable_primitives.default_primitive_registry"
        ),
        "composition_metadata_source": (
            "lightbulb.business_primitives.BUSINESS_PRIMITIVES"
        ),
        "entry_count": len(primitives),
        "unknown_capability_policy": "fail_closed",
        "hosted_execution_policy": "manifest_only_fail_closed_without_managed_runtime",
        "compiler_contract": copy.deepcopy(
            PRIMITIVE_CAPABILITY_COMPILER_CONTRACT
        ),
        "primitives": primitives,
    }
    payload["manifest_digest"] = _digest(payload)
    return payload


def validate_primitive_capability_contract(
    payload: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Compile-time projection validation; never generates capability behavior."""

    validated = _validate_manifest(dict(payload))
    if validated.get("compiler_contract") != PRIMITIVE_CAPABILITY_COMPILER_CONTRACT:
        raise RuntimeError("Primitive capability compiler contract drifted")
    entries = {
        entry["primitive_ref"]: entry for entry in validated["primitives"]
    }
    required_runtime_refs = (
        "finance.prepare_journal_entry",
        "finance.post_journal_entry",
        "finance.reconcile_journal_post",
    )
    if not set(required_runtime_refs).issubset(entries):
        raise RuntimeError("QuickBooks journal lighthouse runtime projection is incomplete")
    post = entries["finance.post_journal_entry"]
    if (
        post["effect_class"] != "consequential_write"
        or post["approval"] != {
            "required": True,
            "authority": "spring",
            "binding": "exact_project_account_operation_payload_preimage",
        }
        or post["idempotency"]["required"] is not True
        or "quickbooks.create_journal_entry" not in post["connector_tools"]
        or post["recovery"]["post_boundary_unknown"]
        != "ambiguous_requires_independent_observation"
        or post["terminal_semantics"]["ambiguity"]
        != {
            "applicable": True,
            "representation": "operation_receipt",
            "operation_status": PrimitiveOperationStatus.IN_DOUBT.value,
            "top_level_success_permitted": False,
            "redispatch_before_reconciliation_permitted": False,
            "resolution": "independent_observation_required",
        }
        or post["evidence_semantics"]["completion"][
            "write_provenance_required"
        ]
        is not True
        or post["evidence_semantics"]["ambiguity_resolution"]
        != {
            "applicable": True,
            "attestation_schema": PRIMITIVE_RECOVERY_ATTESTATION_SCHEMA,
            "independent_observation_required": True,
            "caller_assertion_sufficient": False,
        }
        or post["execution"]["live_write_authority"] != "spring"
        or "finance.journal_post_readback_settlement"
        not in post["memberships"]["golden_operating_loops"]
    ):
        raise RuntimeError("QuickBooks journal write contract is not fail-closed")

    from lightbulb.async_client import AsyncLightbulbClient
    from lightbulb.client import LightbulbClient
    from lightbulb.reference_golden_loop_workflows import FINANCE_JOURNAL_WORKFLOW
    from lightbulb.reference_golden_loops import FINANCE_JOURNAL_READBACK_SETTLEMENT

    for client_type in (LightbulbClient, AsyncLightbulbClient):
        for method_name in (
            "list_executable_business_primitives",
            "run_sdk_business_primitive",
            "run_business_primitive",
        ):
            if not callable(getattr(client_type, method_name, None)):
                raise RuntimeError(
                    f"Primitive SDK projection is absent: {client_type.__name__}.{method_name}"
                )
    loop_steps = tuple(
        step.primitive_ref
        for step in FINANCE_JOURNAL_READBACK_SETTLEMENT.primitive_steps
    )
    expected_steps = (
        "finance.discover_ledger_accounts",
        "finance.prepare_journal_entry",
        "finance.evaluate_journal_entry_controls",
        "finance.post_journal_entry",
        "finance.reconcile_journal_post",
    )
    if loop_steps != expected_steps:
        raise RuntimeError("QuickBooks journal Golden Loop ordering drifted")
    if (
        FINANCE_JOURNAL_WORKFLOW.loop_ref
        != FINANCE_JOURNAL_READBACK_SETTLEMENT.loop_ref
        or FINANCE_JOURNAL_WORKFLOW.runtime_owner != "spring_hosted_lifecycle"
        or FINANCE_JOURNAL_WORKFLOW.runtime_adapter_ref
        != "spring.governed_finance_canary"
        or any(
            surface.participation.value != "BLOCKED"
            for surface in FINANCE_JOURNAL_WORKFLOW.surface_entrypoints
        )
    ):
        raise RuntimeError("QuickBooks journal workflow authority drifted")
    tool_bindings = {
        requirement.binding_ref: requirement
        for requirement in FINANCE_JOURNAL_READBACK_SETTLEMENT.tool_requirements
    }
    if (
        tool_bindings["journal_post"].acceptable_tools
        != ("quickbooks.create_journal_entry",)
        or tool_bindings["journal_readback"].acceptable_tools
        != ("quickbooks.get_journal_entry",)
    ):
        raise RuntimeError("QuickBooks journal write/readback contract drifted")

    if repository_root is not None:
        root = Path(repository_root).resolve()

        def require_text(relative_path: str, *needles: str) -> str:
            path = root / relative_path
            if not path.is_file():
                raise RuntimeError(f"Required primitive projection is absent: {relative_path}")
            source = path.read_text(encoding="utf-8")
            missing = [needle for needle in needles if needle not in source]
            if missing:
                raise RuntimeError(
                    f"Primitive projection drift in {relative_path}: {missing}"
                )
            return source

        python_mcp = require_text(
            "lightbulb-sdk/lightbulb/mcp_server.py",
            "def run_business_primitive(",
            "run_sdk_business_primitive(",
            "def list_business_primitives(",
        )
        start = python_mcp.index("def run_business_primitive(")
        end = python_mcp.index("\n@mcp.tool", start)
        if "backbone" in python_mcp[start:end].lower():
            raise RuntimeError("Python MCP primitive execution still routes through Backbone")
        spring_controller = require_text(
            "springboot-server/src/main/java/com/project401/controller/ChatGptMcpController.java",
            "PrimitiveCapabilityManifestService",
            'case "run_business_primitive"',
            "managed_primitive_runtime_unavailable",
        )
        spring_start = spring_controller.index(
            "private Map<String, Object> runBusinessPrimitive("
        )
        spring_end = spring_controller.index(
            "private Map<String, Object> findOperatingLoops(", spring_start
        )
        if "BACKBONE_WORKFLOW_TYPE" in spring_controller[spring_start:spring_end]:
            raise RuntimeError("Hosted primitive execution still routes through Backbone")
        require_text(
            "lightbulb-sdk/scripts/generate_capability_inventory.py",
            "def discover_sdk_primitives",
            "default_primitive_registry",
        )
        require_text(
            "lightbulb-sdk/README.md",
            "finance.post_journal_entry",
            "independently evidenced readback",
        )
        spring_manifest = require_text(
            "springboot-server/src/main/resources/lightbulb/primitive-capability-manifest.v1.json",
            '"finance.post_journal_entry"',
            '"quickbooks.create_journal_entry"',
        )
        if _canonical_json(json.loads(spring_manifest)) != _canonical_json(validated):
            raise RuntimeError("Spring hosted primitive manifest is stale")

    return validated


def render_primitive_capability_manifest(payload: Mapping[str, Any]) -> str:
    """Render the checked artifact with stable ordering and one trailing newline."""

    return (
        json.dumps(
            payload,
            default=str,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _validate_entry_runtime_semantics(entry: Mapping[str, Any]) -> None:
    primitive_ref = entry.get("primitive_ref")
    primitive_version = entry.get("version")
    effect_class = entry.get("effect_class")
    if not isinstance(primitive_version, str) or not primitive_version.strip():
        raise RuntimeError(
            f"Primitive capability semantics require a version: {primitive_ref}"
        )
    if effect_class not in {
        "provider_free",
        "connector_read",
        "consequential_write",
    }:
        raise RuntimeError(
            f"Primitive capability effect class is invalid: {primitive_ref}"
        )

    composition = entry.get("composition")
    agentic_workflow = (
        composition.get("agentic_workflow")
        if isinstance(composition, Mapping)
        else None
    )
    runtime_guarantees = entry.get("runtime_guarantees")
    if not isinstance(agentic_workflow, Mapping) or not isinstance(
        runtime_guarantees, Mapping
    ):
        raise RuntimeError(
            f"Primitive capability runtime contract is invalid: {primitive_ref}"
        )
    required_guarantees = (
        "preview_writes_have_no_side_effects",
        "events_are_structured",
        "typed_evidence_refs",
        "typed_operation_receipts",
        "typed_recovery_plans",
        "completed_writes_require_provenance",
        "in_doubt_requires_recovery",
    )
    if any(runtime_guarantees.get(key) is not True for key in required_guarantees):
        raise RuntimeError(
            f"Primitive capability runtime guarantees are incomplete: {primitive_ref}"
        )

    expected = _runtime_semantics(
        primitive_version=primitive_version,
        effect_class=effect_class,
        agentic_workflow=agentic_workflow,
        runtime_guarantees=runtime_guarantees,
    )
    for field_name, expected_semantics in expected.items():
        if entry.get(field_name) != expected_semantics:
            raise RuntimeError(
                f"Primitive capability {field_name} is invalid: {primitive_ref}"
            )


def _validate_manifest(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("Primitive capability manifest must be a JSON object")
    if payload.get("schema") != PRIMITIVE_CAPABILITY_MANIFEST_SCHEMA:
        raise RuntimeError("Unsupported primitive capability manifest schema")
    primitives = payload.get("primitives")
    if not isinstance(primitives, list) or payload.get("entry_count") != len(primitives):
        raise RuntimeError("Primitive capability manifest entry count is invalid")
    refs = [entry.get("primitive_ref") for entry in primitives if isinstance(entry, dict)]
    if len(refs) != len(primitives) or len(refs) != len(set(refs)):
        raise RuntimeError("Primitive capability manifest refs must be unique")
    for entry in primitives:
        _validate_entry_runtime_semantics(entry)
    claimed_digest = payload.get("manifest_digest")
    unsigned = dict(payload)
    unsigned.pop("manifest_digest", None)
    if claimed_digest != _digest(unsigned):
        raise RuntimeError("Primitive capability manifest digest is invalid")
    return payload


@lru_cache(maxsize=1)
def _loaded_manifest() -> dict[str, Any]:
    resource = files("lightbulb").joinpath(PRIMITIVE_CAPABILITY_MANIFEST_RESOURCE)
    return _validate_manifest(json.loads(resource.read_text(encoding="utf-8")))


def canonical_primitive_manifest() -> dict[str, Any]:
    """Return an isolated copy of the checked canonical manifest."""

    return copy.deepcopy(_loaded_manifest())


@lru_cache(maxsize=1)
def _manifest_index() -> dict[str, dict[str, Any]]:
    return {
        entry["primitive_ref"]: entry
        for entry in _loaded_manifest()["primitives"]
    }


def primitive_capability_metadata(
    capability_ref: str,
    *,
    primitive_version: str | None = None,
) -> dict[str, Any] | None:
    """Look up exact canonical primitive metadata; unknown refs or versions return ``None``.

    Generated callers may use either the raw primitive ref or the namespaced
    ``business_primitive.<ref>`` capability form.
    """

    normalized = str(capability_ref or "").strip()
    prefix = "business_primitive."
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix) :]
    entry = _manifest_index().get(normalized)
    requested_version = str(primitive_version or "").strip()
    if (
        entry is not None
        and requested_version
        and requested_version != str(entry["version"])
    ):
        return None
    return copy.deepcopy(entry) if entry is not None else None


def primitive_manifest_catalog(
    *,
    category: str | None = None,
    query: str | None = None,
    include_schemas: bool = True,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return a bounded catalog page from the checked canonical manifest."""

    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit is not None and not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    normalized_category = str(category or "").strip().lower()
    normalized_query = str(query or "").strip().lower()
    entries: list[dict[str, Any]] = []
    for entry in _loaded_manifest()["primitives"]:
        primitive_ref = entry["primitive_ref"]
        if normalized_category and primitive_ref.split(".", 1)[0] != normalized_category:
            continue
        if normalized_query:
            haystack = " ".join(
                (
                    primitive_ref,
                    entry["title"],
                    entry["description"],
                    " ".join(entry["connector_tools"]),
                )
            ).lower()
            if normalized_query not in haystack:
                continue
        projected = copy.deepcopy(entry)
        if not include_schemas:
            projected.pop("input_schema", None)
            projected.pop("output_schema", None)
            projected.pop("example_inputs", None)
        entries.append(projected)
    total = len(entries)
    page = entries[offset : None if limit is None else offset + limit]
    manifest = _loaded_manifest()
    return {
        "schema": "lightbulb.primitive_capability_catalog.v1",
        "manifest_version": manifest["manifest_version"],
        "manifest_digest": manifest["manifest_digest"],
        "count": len(page),
        "total": total,
        "offset": offset,
        "limit": limit,
        "implementations": page,
    }


__all__ = [
    "PRIMITIVE_CAPABILITY_MANIFEST_RESOURCE",
    "PRIMITIVE_CAPABILITY_MANIFEST_SCHEMA",
    "PRIMITIVE_CAPABILITY_MANIFEST_VERSION",
    "PRIMITIVE_CAPABILITY_COMPILER_CONTRACT",
    "PRIMITIVE_ERROR_SEMANTICS_SCHEMA",
    "PRIMITIVE_EVENT_SEMANTICS_SCHEMA",
    "PRIMITIVE_EVIDENCE_SEMANTICS_SCHEMA",
    "PRIMITIVE_TERMINAL_SEMANTICS_SCHEMA",
    "build_primitive_capability_manifest",
    "canonical_primitive_manifest",
    "primitive_capability_metadata",
    "primitive_manifest_catalog",
    "render_primitive_capability_manifest",
    "validate_primitive_capability_contract",
]
