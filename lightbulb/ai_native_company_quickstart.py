"""Build and inspect an effect-dark AI-native company with Lightbulb.

This installed SDK module performs no network call, deployment, connector
effect, certification, or schedule activation.  It starts from the maintained
reference portfolio so a new company inherits complete typed loops without
copying their implementations.
"""

from __future__ import annotations

import json
from typing import Any

from lightbulb.company_blueprint_compiler import (
    CompanyBlueprintCompilationError,
    compile_company_blueprint_deployment_plan,
)
from lightbulb.company_blueprints import CompanyBlueprint
from lightbulb.executable_primitives import default_primitive_registry
from lightbulb.reference_company_blueprints import (
    AI_NATIVE_SERVICES_STUDIO_BLUEPRINT,
)
from lightbulb.reference_golden_loops import INITIAL_GTM_GOLDEN_LOOP_CATALOG


def build_example_company() -> CompanyBlueprint:
    """Create a distinct immutable declaration over the governed portfolio."""

    declaration = AI_NATIVE_SERVICES_STUDIO_BLUEPRINT.to_dict()
    declaration.pop("blueprint_digest", None)
    declaration.pop("certification", None)
    declaration.update(
        {
            "blueprint_ref": "company.example_customer_operations_studio",
            "version": "0.1.0",
            "name": "Example customer operations studio candidate",
        }
    )
    return CompanyBlueprint.model_validate(declaration)


def preview() -> dict[str, Any]:
    """Compile the declaration without granting it runtime authority."""

    blueprint = build_example_company()
    try:
        plan = compile_company_blueprint_deployment_plan(
            blueprint,
            loop_catalog=INITIAL_GTM_GOLDEN_LOOP_CATALOG,
            primitive_registry=default_primitive_registry(),
            mode="preview",
        )
        validation = plan.validation
        compilation_blocker = None
    except CompanyBlueprintCompilationError as failure:
        if failure.validation is None:
            raise
        plan = None
        validation = failure.validation
        compilation_blocker = failure.code
    return {
        "schema": "lightbulb.company_blueprint_quickstart_summary.v1",
        "blueprint_ref": blueprint.blueprint_ref,
        "blueprint_version": blueprint.version,
        "blueprint_digest": blueprint.blueprint_digest,
        "departments": len(blueprint.departments),
        "golden_operating_loops": len(blueprint.golden_loops),
        "economic_spine_stages": len(blueprint.economic_spine.stages),
        "connector_requirements": [
            requirement.requirement_ref
            for requirement in blueprint.connector_requirements
        ],
        "coding_harness_choices": list(
            blueprint.execution_host_policy.allowed_harnesses
        ),
        "preview_only": True if plan is None else plan.preview_only,
        "deployment_authorized": (
            False if plan is None else plan.spring_authority.deployment_authorized
        ),
        "compilation_blocker": compilation_blocker,
        "declared_blockers": list(blueprint.known_blockers),
        "validation_findings": [
            finding.to_dict() for finding in validation.findings
        ],
    }


def main() -> None:
    print(json.dumps(preview(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()


__all__ = ["build_example_company", "main", "preview"]
