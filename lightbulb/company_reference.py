"""Generated reference for the company engines: lifecycles, primitives, rejection codes, action kinds.

``render_company_reference`` derives everything from the live modules (the
lifecycle specs, the executable primitive registry, the manifests, and the
rejection codes each engine raises), so the document can never describe an
engine the code does not have.  ``scripts/generate_company_reference.py``
writes it to ``docs/lightbulb-company-reference.md`` and the reference test
refuses drift.
"""

from __future__ import annotations

import ast
import inspect
import re
from collections.abc import Iterable
from typing import Any

REFERENCE_SCHEMA = "lightbulb.company_reference.v1"
_CODE_PATTERN = re.compile(r"""(?:require|Rejected|MigrationRefused|[A-Za-z_][A-Za-z0-9_]*Error|_require)\(\s*(?:[^,()]+,\s*)?["']([A-Z][A-Z0-9_]{3,})["']""")
_FSTRING_CODE = re.compile(r"""f["']\{[^}]+\}_([A-Z][A-Z0-9_]+)["']""")

COMPANY_MODULES: tuple[str, ...] = (
    "lightbulb.company_engine_core",
    "lightbulb.company_round5_primitives",
    "lightbulb.company_operating_system",
    "lightbulb.growth_engine_loop",
    "lightbulb.pipeline_engine_loop",
    "lightbulb.saas_operating_loop",
    "lightbulb.finance_close_engine",
    "lightbulb.service_delivery_engine",
    "lightbulb.company_workforce",
    "lightbulb.company_formation",
    "lightbulb.company_execution_bridge",
    "lightbulb.company_engine_store",
    "lightbulb.company_simulator",
    "lightbulb.company_cadence_runner",
    "lightbulb.company_signal_consumers",
    "lightbulb.company_approval_inbox",
    "lightbulb.company_observation_jobs",
    "lightbulb.company_dispatch_metering",
    "lightbulb.company_hosted_scheduler",
    "lightbulb.company_plan_migration",
    "lightbulb.company_portfolio",
    "lightbulb.company_bring_up",
    "lightbulb.finance_close_observations",
    "lightbulb.pipeline_execution",
    "lightbulb.growth_execution",
    "lightbulb.growth_reallocation",
    "lightbulb.channel_spend_statements",
    "lightbulb.conversion_attribution",
    "lightbulb.growth_period_fold",
    "lightbulb.content_asset_lifecycle",
    "lightbulb.live_signal_observations",
    "lightbulb.revenue_chain",
    "lightbulb.company_explain",
    "lightbulb.company_decisions",
    "lightbulb.company_treasury",
    "lightbulb.company_operating_memory",
    "lightbulb.company_workforce_learning",
    "lightbulb.company_chaos",
    "lightbulb.company_console",
    "lightbulb.payables_chain",
    "lightbulb.retention_chain",
    "lightbulb.compliance_calendar",
    "lightbulb.exceptions_desk",
    "lightbulb.company_brief",
    "lightbulb.company_evals",
    "lightbulb.provider_fixtures",
    "lightbulb.authority_matrix",
    "lightbulb.company_cost_centres",
    "lightbulb.payroll_run_chain",
    "lightbulb.bank_reconciliation",
    "lightbulb.subscription_chain",
    "lightbulb.storefront_settlement_chain",
    "lightbulb.collections_chain",
    "lightbulb.spend_control_chain",
    "lightbulb.disbursement_run",
    "lightbulb.obligation_paper",
    "lightbulb.deal_desk_engine",
    "lightbulb.permission_register",
    "lightbulb.people_engine",
    "lightbulb.marketplace_supply_engine",
    "lightbulb.engagement_engine",
    "lightbulb.wip_billing",
    "lightbulb.payout_chain",
    "lightbulb.custodial_funds",
    "lightbulb.refund_and_dispute_chain",
    "lightbulb.company_unit_economics",
    "lightbulb.company_chain_catalog",
    "lightbulb.company_operator_surface",
)

COMPANY_ENGINE_KINDS: frozenset[str] = frozenset({"company_operating_system", "growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery", "people_engine", "marketplace_supply_engine", "engagement_engine", "company_workforce", "company_cadence", "company_signal_consumers", "company_approval_inbox", "company_simulator", "company_formation", "company_runtime_deepening", "company_bring_up", "vertical_deepening"})


def _lifecycles() -> list[tuple[str, Any]]:
    from lightbulb import company_plan_migration as migration
    from lightbulb.company_cadence_runner import CADENCE_LIFECYCLE

    migration._register_late_lifecycles()
    items = [(engine, lifecycle.spec) for engine, lifecycle in migration.ENGINE_LIFECYCLES.items()]
    items.append(("company_cadence", CADENCE_LIFECYCLE))
    from lightbulb.company_bring_up import BRING_UP_LIFECYCLE

    items.append(("company_bring_up", BRING_UP_LIFECYCLE))
    return sorted(items)


def rejection_codes(module_names: Iterable[str] = COMPANY_MODULES) -> dict[str, list[str]]:
    """Rejection codes each module raises, read from its source; the core's generic fences are listed under the core."""

    import importlib

    out: dict[str, list[str]] = {}
    for name in module_names:
        module = importlib.import_module(name)
        source = inspect.getsource(module)
        codes = set(_CODE_PATTERN.findall(source))
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            call_name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            index = 1 if call_name in {"require", "_require"} else 0
            if call_name not in {"require", "_require", "Rejected", "MigrationRefused"} and not call_name.endswith("Error"):
                continue
            if len(node.args) > index and isinstance(node.args[index], ast.Constant) and isinstance(node.args[index].value, str):
                code = node.args[index].value.split(":", 1)[0]
                if re.fullmatch(r"[A-Z][A-Z0-9_]{3,}", code):
                    codes.add(code)
        codes.update(f"<ENTITY>_{suffix}" for suffix in _FSTRING_CODE.findall(source))
        for literal in ("TRANSITION_ALREADY_APPLIED", "IDEMPOTENCY_CONFLICT", "STALE_STATE", "NON_CHRONOLOGICAL_TRANSITION", "TRANSITION_BOUND_REACHED", "ILLEGAL_TRANSITION"):
            if f'"{literal}"' in source:
                codes.add(literal)
        out[name] = sorted(codes)
    return out


def _engine_names(raw: Any) -> list[str]:
    items = raw.get("engine_kinds", raw.get("engines", []))
    return [item if isinstance(item, str) else str(item.get("kind") or item.get("engine") or item.get("name")) for item in items]


def _table(spec: Any) -> list[str]:
    rows = ["| from | event | to |", "|---|---|---|"]
    for (status, event), target in sorted(spec.table.items()):
        rows.append(f"| {status} | {event} | {target} |")
    return rows


def _primitives() -> list[Any]:
    from lightbulb.executable_primitives import BUILTIN_EXECUTABLE_PRIMITIVES

    return [item for item in BUILTIN_EXECUTABLE_PRIMITIVES if getattr(item, "engine", None) in COMPANY_ENGINE_KINDS or item.primitive_ref.startswith(("company.", "growth.", "pipeline.", "saas_ops.", "finance_close.", "service_delivery.", "workforce."))]


def render_company_reference() -> str:
    from lightbulb._version import __version__
    from lightbulb.company_cadence_runner import CADENCE_MANIFEST
    from lightbulb.company_observation_jobs import OBSERVATION_SOURCES, lane_for
    from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES
    from lightbulb.company_portfolio import PORTFOLIO_MANIFEST
    from lightbulb.company_simulator import STANDARD_SCENARIOS

    lines: list[str] = []
    lines.append("# Lightbulb company engines: reference")
    lines.append("")
    lines.append(f"Generated from `lightbulb-mcp` {__version__} by `scripts/generate_company_reference.py`. Do not edit by hand; regenerate after an engine change. Everything below is derived from the live lifecycle specs, primitive registry, and manifests.")
    lines.append("")
    lines.append("Every engine is preview-only in the SDK: states are self-proving, transitions are fenced by version and digest, effects are executed by the platform behind approvals, and nothing here claims hosted execution, certification, or production readiness.")
    lines.append("")
    lines.append("## Archetypes and scenarios")
    lines.append("")
    lines.append("| archetype | country | currency | budget per period | engines |")
    lines.append("|---|---|---|---|---|")
    for name in sorted(COMPANY_OS_ARCHETYPES):
        raw = COMPANY_OS_ARCHETYPES[name]
        engines = ", ".join(_engine_names(raw))
        lines.append(f"| {name} | {raw.get('country')} | {raw.get('currency')} | {raw.get('operating_budget_per_period')} | {engines} |")
    lines.append("")
    lines.append("Standard simulation scenarios: " + ", ".join(f"`{name}`" for name in sorted(STANDARD_SCENARIOS)) + ".")
    lines.append("")
    lines.append("## Lifecycles")
    lines.append("")
    for engine, spec in _lifecycles():
        lines.append(f"### {engine} (`{spec.entity}`)")
        lines.append("")
        lines.append(f"- Statuses: {', '.join(f'`{s}`' for s in sorted(spec.statuses))}")
        lines.append(f"- Terminal: {', '.join(f'`{s}`' for s in sorted(spec.terminal)) or 'none'}")
        lines.append(f"- Events: {', '.join(f'`{e}`' for e in sorted(spec.events))} (opens with `{spec.opening_event}`; reasons required for {', '.join(f'`{e}`' for e in sorted(spec.reason_events)) or 'none'})")
        lines.append(f"- State schema: `{spec.State.model_fields['schema_id'].default}`; bounded to {spec.max_transitions} transitions")
        lines.append("")
        lines.extend(_table(spec))
        lines.append("")
    lines.append("## Cadence")
    lines.append("")
    lines.append("- Action kinds: " + ", ".join(f"`{kind}`" for kind in CADENCE_MANIFEST["action_kinds"]))
    lines.append("- Stages: " + ", ".join(f"`{stage}`" for stage in CADENCE_MANIFEST["stages"]))
    lines.append("")
    lines.append("## Observation sources and lanes")
    lines.append("")
    lines.append("| tool | lane | feeds | adapter |")
    lines.append("|---|---|---|---|")
    for tool in sorted(OBSERVATION_SOURCES):
        source = OBSERVATION_SOURCES[tool]
        lines.append(f"| `{tool}` | {lane_for(tool)} | {source['engine']}.{source['event']} | `{source['adapter']}` |")
    lines.append("")
    lines.append("A tool on the host lane is not admitted to the platform's governed read executor; the harness performs the read and the SDK only seals what it was handed.")
    lines.append("")
    lines.append("## Portfolio attention reasons")
    lines.append("")
    lines.append(", ".join(f"`{code}`" for code in PORTFOLIO_MANIFEST["reason_codes"]))
    lines.append("")
    lines.append("## Executable primitives")
    lines.append("")
    lines.append("| primitive | engine | risk | title |")
    lines.append("|---|---|---|---|")
    for item in sorted(_primitives(), key=lambda value: value.primitive_ref):
        lines.append(f"| `{item.primitive_ref}` | {getattr(item, 'engine', '')} | {getattr(item, 'risk_level', '')} | {item.title} |")
    lines.append("")
    lines.append("## Rejection codes by module")
    lines.append("")
    for module, codes in rejection_codes().items():
        if not codes:
            continue
        lines.append(f"- `{module}`: " + ", ".join(f"`{code}`" for code in codes))
    lines.append("")
    return "\n".join(lines)


__all__ = ["COMPANY_MODULES", "REFERENCE_SCHEMA", "rejection_codes", "render_company_reference"]
