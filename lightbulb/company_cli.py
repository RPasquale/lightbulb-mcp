"""``lightbulb company``: the company runtime from the terminal, on local JSON files and the signed-in account.

Local subcommands (no platform call) compile blueprints, simulate, plan
cadence ticks and observation reads, route signals, preview plan migrations,
assess a portfolio, and print the generated reference.  Account subcommands
(``form``, ``inbox``, ``states``, ``exceptions``, ``compliance``,
``brief``, ``board-pack``, ``evals``) go through the SDK client with the
session's credential; none of them executes an engine effect.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _emit(value: Any, *, out: str | None = None) -> None:
    text = json.dumps(value, indent=2, default=str, sort_keys=False)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)


def _type_label(expected: type[Any]) -> str:
    return "object" if expected is dict else "list"


def _load_json_file(path: str, label: str, expected: type[Any]) -> Any:
    try:
        value = _load(path)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} must be valid JSON: {exc}") from exc
    if not isinstance(value, expected):
        raise RuntimeError(f"{label} must be a JSON {_type_label(expected)}")
    return value


def _console_from(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> tuple[Any, Any]:
    from lightbulb.company_console import CompanyConsole
    from lightbulb.company_engine_store import HostedEngineStateStore

    bundle = _load_json_file(args.bundle, "--bundle", dict)
    from lightbulb.company_cadence_runner import build_bundle
    if args.project_id != build_bundle(bundle).scope["project_id"]:
        raise RuntimeError("SCOPE_MISMATCH: the project must match the bundle")
    client = client_factory()
    store = HostedEngineStateStore(client, project_id=args.project_id)
    clock = (lambda: args.now) if getattr(args, "now", None) else _now
    return CompanyConsole.from_document(bundle, store, clock, approval_requester=lambda request: client.request_engine_transition_approval(request)), client


def _console_call(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return fn()
    except (ValueError, LookupError) as exc:
        raise RuntimeError(str(exc)) from exc


def _explain_fields(values: list[str]) -> list[tuple[str, str, str]]:
    fields = []
    for value in values:
        if ":" not in value:
            raise RuntimeError("--explain values must be engine:entity:field")
        engine, rest = value.split(":", 1)
        if ":" not in rest:
            raise RuntimeError("--explain values must be engine:entity:field")
        entity_ref, field = rest.rsplit(":", 1)
        if not engine or not entity_ref or not field:
            raise RuntimeError("--explain values must be engine:entity:field")
        fields.append((engine, entity_ref, field))
    return fields


def _inbox_from_client(client: Any) -> list[dict[str, str]]:
    inbox = client.list_pending_approvals() or []
    rows = inbox if isinstance(inbox, list) else dict(inbox).get("items", [])
    items = []
    for item in rows:
        raw = dict(item)
        items.append({"task_id": str(raw.get("id") or raw.get("task_id")), "status": str(raw.get("status", "pending")), "approval_type": str(raw.get("approval_type") or raw.get("type") or "approval"), "summary": str(raw.get("summary") or raw.get("title") or "")[:900], "rendered": "", "on_approve": "", "on_reject": ""})
    return items


def _plan_from(value: str) -> Any:
    from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES, CompanyOperatingPlan, compile_company_operating_blueprint

    if value in COMPANY_OS_ARCHETYPES:
        return compile_company_operating_blueprint(value)
    raw = _load(value)
    if isinstance(raw, dict) and "plan_digest" in raw:
        return CompanyOperatingPlan.model_validate(raw)
    return compile_company_operating_blueprint(raw)


def _cmd_blueprints(_: argparse.Namespace) -> int:
    from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES
    from lightbulb.company_simulator import STANDARD_SCENARIOS

    rows = []
    for name in sorted(COMPANY_OS_ARCHETYPES):
        raw = COMPANY_OS_ARCHETYPES[name]
        rows.append({"archetype": name, "name": raw.get("name"), "country": raw.get("country"), "currency": raw.get("currency"), "operating_budget_per_period": raw.get("operating_budget_per_period"), "engines": list(raw.get("engine_kinds", raw.get("engines", [])))})
    _emit({"archetypes": rows, "scenarios": sorted(STANDARD_SCENARIOS)})
    return 0


def _cmd_compile(args: argparse.Namespace) -> int:
    from lightbulb.company_operating_system import compile_company_operating_blueprint

    overrides = _load(args.overrides) if args.overrides else None
    source = args.archetype if not Path(args.archetype).exists() else _load(args.archetype)
    plan = compile_company_operating_blueprint(source, overrides)
    _emit(plan.to_dict(), out=args.out)
    return 0


def _cmd_simulate(args: argparse.Namespace) -> int:
    from lightbulb.company_simulator import evaluate_scenario, simulate_company, standard_scenario

    plan = _plan_from(args.plan)
    scenario = standard_scenario(args.scenario) if not Path(args.scenario).exists() else _load(args.scenario)
    result = simulate_company(plan, scenario)
    payload: dict[str, Any] = result.to_dict()
    if args.expect:
        evaluation = evaluate_scenario(result, _load(args.expect))
        payload = {"result": payload, "evaluation": evaluation.to_dict()}
        _emit(payload, out=args.out)
        return 0 if evaluation.passed else 2
    _emit(payload, out=args.out)
    return 0


def _cmd_goldens(args: argparse.Namespace) -> int:
    from lightbulb.company_operating_system import compile_company_operating_blueprint
    from lightbulb.company_scenario_goldens import COMPANY_SCENARIO_GOLDENS
    from lightbulb.company_simulator import simulate_company, standard_scenario

    drifted = []
    for golden in COMPANY_SCENARIO_GOLDENS:
        if args.archetype and golden["archetype"] != args.archetype:
            continue
        plan = compile_company_operating_blueprint(golden["archetype"])
        result = simulate_company(plan, standard_scenario(golden["scenario"]))
        if plan.plan_digest != golden["plan_digest"] or result.result_digest != golden["result_digest"]:
            drifted.append({"archetype": golden["archetype"], "scenario": golden["scenario"], "expected": golden["result_digest"], "actual": result.result_digest})
    _emit({"goldens": len(COMPANY_SCENARIO_GOLDENS), "drifted": drifted})
    return 0 if not drifted else 2


def _cmd_tick_plan(args: argparse.Namespace) -> int:
    from lightbulb.company_cadence_runner import plan_cadence_tick

    bundle = _load(args.bundle)
    states = _load(args.states) if args.states else {}
    plan = plan_cadence_tick(bundle, states, now=args.now or _now())
    _emit(plan.to_dict(), out=args.out)
    return 0


def _cmd_observation_jobs(args: argparse.Namespace) -> int:
    from lightbulb.company_observation_jobs import plan_observation_jobs

    plan = plan_observation_jobs(_load(args.bundle), _load(args.tick_plan), window_start=args.window_start, window_end=args.window_end)
    _emit(plan.to_dict(), out=args.out)
    return 0


def _cmd_consume(args: argparse.Namespace) -> int:
    from lightbulb.company_signal_consumers import consume_signal

    consumption = consume_signal(_load(args.plan), _load(args.signal), states=_load(args.states) if args.states else {}, now=args.now or _now())
    _emit(consumption.to_dict(), out=args.out)
    return 0


def _cmd_migrate_preview(args: argparse.Namespace) -> int:
    from lightbulb.company_plan_migration import MigrationRefused, lifecycle_for, migrate_state

    lifecycle = lifecycle_for(args.engine)
    try:
        result = migrate_state(lifecycle.spec, state=_load(args.state), from_plan=_load(args.from_plan), to_plan=_load(args.to_plan), migrated_at=args.migrated_at or _now(), actor_ref=args.actor_ref, reason=args.reason)
    except MigrationRefused as exc:
        _emit({"refused": True, "code": exc.code, "version": exc.version, "detail": str(exc)})
        return 2
    _emit({"migration": result.migration.to_dict(), "state": result.state.to_dict()}, out=args.out)
    return 0


def _cmd_portfolio(args: argparse.Namespace) -> int:
    from lightbulb.company_portfolio import assess_portfolio, render_portfolio

    assessment = assess_portfolio(_load(args.companies), assessed_at=args.assessed_at or _now())
    if args.json:
        _emit(assessment.to_dict(), out=args.out)
    else:
        print(render_portfolio(assessment))
    return 0


def _cmd_reference(args: argparse.Namespace) -> int:
    from lightbulb.company_reference import render_company_reference

    text = render_company_reference()
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def _cmd_form(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    from lightbulb.company_formation import UnsupportedFormationCountryError

    fields: dict[str, Any] = {"name": args.name, "country": args.country}
    if args.industry:
        fields["industry"] = args.industry
    if args.purpose:
        fields["purpose"] = args.purpose
    try:
        result = client_factory().create_company(**fields)
    except UnsupportedFormationCountryError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    _emit({"company_id": getattr(result, "company_id", None), "name": getattr(result, "name", None), "country": getattr(result, "country", None), "region": getattr(result, "region", None), "message": getattr(result, "message", None)})
    return 0


def _cmd_inbox(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    from lightbulb.company_approval_inbox import build_inbox

    tasks = client_factory().list_pending_approvals() or []
    inbox = build_inbox(tasks, now=args.now or _now(), states=_load(args.states) if args.states else None)
    if args.json:
        _emit(inbox.to_dict())
        return 0
    items = [item for item in inbox.items if item.engine_binding is not None] if args.engine_only else list(inbox.items)
    print(f"{len(items)} approval(s); {inbox.stale_items} stale; {len(inbox.expiring_soon)} expiring soon")
    for item in items:
        print(f"- {item.task_id} [{item.freshness}] {item.rendered}")
    return 0


def _cmd_states(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    records = client_factory().list_engine_states(args.project_id, engine=args.engine or None, status=args.status or None, limit=args.limit)
    _emit(records if args.json else [{"engine": r.get("engine"), "entity_ref": r.get("entity_ref"), "status": r.get("status"), "version": r.get("version"), "updated_at": r.get("updated_at")} for r in records])
    return 0


def _connections_from(args: argparse.Namespace, client_factory: Callable[[], Any]) -> list[Any]:
    if getattr(args, "connections", None):
        loaded = _load(args.connections)
        return list(loaded if isinstance(loaded, list) else loaded.get("items", []))
    return list(client_factory().list_connected_integrations() or [])


def _cmd_readiness(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    from lightbulb.company_bring_up import assess_readiness

    readiness = assess_readiness(_load(args.bundle), _connections_from(args, client_factory), now=args.now or _now(), company_id=args.company_id)
    if args.json:
        _emit(readiness.to_dict())
    else:
        print(f"{'ready' if readiness.ready else 'blocked'}: {len(readiness.connected)} provider(s) connected ({', '.join(item.provider for item in readiness.connected) or 'none'})")
        for engine, groups in readiness.missing_providers().items():
            print(f"- {engine} needs {' and '.join(groups)}")
    return 0 if readiness.ready else 2


def _cmd_bring_up(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    from lightbulb.company_bring_up import BringUpOrchestrator
    from lightbulb.company_cadence_runner import build_bundle
    from lightbulb.company_engine_store import HostedEngineStateStore, InMemoryEngineStateStore
    from lightbulb.company_hosted_scheduler import HostedCheckpointGateway, InMemoryCheckpointGateway

    bundle = build_bundle(_load(args.bundle))
    connections = _connections_from(args, client_factory)
    if args.dry_run:
        store: Any = InMemoryEngineStateStore()
        gateway: Any = InMemoryCheckpointGateway()
    else:
        client = client_factory()
        store = HostedEngineStateStore(client, project_id=bundle.scope["project_id"], company_id=args.company_id)
        gateway = HostedCheckpointGateway(client=client, project_id=bundle.scope["project_id"], company_id=args.company_id)
    orchestrator = BringUpOrchestrator(bundle=bundle, store=store, connections=lambda: connections, clock=lambda: args.now or _now(), formed_company_ref=args.company_ref, gateway=gateway, company_id=args.company_id, worker_ref=args.worker_ref, interval_seconds=args.interval_seconds)
    report = orchestrator.run(first_tick_at=args.first_tick_at, paper_sources=_load(args.paper_sources) if args.paper_sources else ())
    if args.json:
        _emit(report.to_dict())
    else:
        print(f"{report.company_ref}: {report.status}{' (dry run)' if args.dry_run else ''}")
        for step in report.steps:
            print(f"- {step.event}: {step.outcome}" + (f" [{step.rejection_code}] {step.detail}" if step.outcome != "applied" else f" -> {step.to_status}"))
    return 0 if report.live else 2


def _cmd_chain(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    from lightbulb.company_console import CompanyConsole
    from lightbulb.company_engine_store import HostedEngineStateStore, InMemoryEngineStateStore
    from lightbulb.company_cadence_runner import build_bundle
    from lightbulb.company_plan_migration import lifecycle_for
    from lightbulb.company_chain_catalog import plan_for_chain
    bundle = build_bundle(_load(args.bundle))
    if args.project_id:
        if args.project_id != bundle.scope["project_id"]:
            raise ValueError("SCOPE_MISMATCH: the project must match the bundle")
        store = HostedEngineStateStore(client_factory(), project_id=args.project_id)
    else:
        store = InMemoryEngineStateStore()
        for record in (_load(args.states) if args.states else []):
            engine = record["engine"]
            spec = lifecycle_for(engine).spec
            _, state = spec.bind(CompanyConsole.from_document(bundle, store, lambda: args.now or _now())._plan_for(engine), record["state"])
            store.put(engine, state.scope.entity_ref, state.to_dict(), expected_version=None, expected_state_digest=None)
    console = CompanyConsole.from_document(bundle, store, lambda: args.now or _now())
    payload = _load(args.payload) if args.payload else {}
    if getattr(args, "console_verb", None):
        result = getattr(console, args.console_verb)(**payload)
    else:
        result = console.chain(args.chain_verb, operation=args.operation, engine=args.engine, entity_ref=args.entity_ref, payload=payload)
    output = {"result": result, "states": store.list(limit=200)} if not args.project_id else result
    _emit(output, out=args.out)
    return 2 if result.get("persisted") is False else 0


def _cmd_exceptions(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    console, _client = _console_from(args, client_factory=client_factory)
    tick_result = _load_json_file(args.tick_result, "--tick-result", dict) if args.tick_result else None
    observations = _load_json_file(args.observations, "--observations", list) if args.observations else []
    covers = _load_json_file(args.covers, "--covers", list) if args.covers else []
    result = _console_call(lambda: console.exceptions(now=args.now or None, tick_result=tick_result, observations=observations, covers=covers))
    print(result["rendered"])
    return 2 if int(result.get("past_sla", 0) or 0) > 0 else 0


def _cmd_compliance(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    if not args.jurisdiction:
        raise RuntimeError("--jurisdiction is required with named options")
    console, _client = _console_from(args, client_factory=client_factory)
    result = _console_call(lambda: console.compliance(jurisdiction=args.jurisdiction, now=args.now or None, horizon_months=max(1, min(int(args.horizon_months), 24)), estimated_revenue_per_month=args.revenue_per_month or "0", estimated_payroll_per_month=args.payroll_per_month or "0", has_payroll=not args.no_payroll, registered_for_gst=not args.not_registered_for_gst))
    print(result["rendered"])
    if args.flows_out:
        _emit(result.get("flows", []), out=args.flows_out)
    return 0


def _cmd_brief(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    console, client = _console_from(args, client_factory=client_factory)
    forecast = _load_json_file(args.forecast, "--forecast", dict) if args.forecast else None
    exceptions = _load_json_file(args.exceptions, "--exceptions", dict) if args.exceptions else None
    compliance = _load_json_file(args.compliance, "--compliance", dict) if args.compliance else None
    decisions = _load_json_file(args.decisions, "--decisions", list) if args.decisions else []
    result = _console_call(lambda: console.brief(now=args.now or None, forecast=forecast, inbox=_inbox_from_client(client), decisions=decisions, exceptions=exceptions, compliance=compliance, explain_fields=_explain_fields(args.explain or [])))
    if args.json:
        _emit(result)
    else:
        print(result["rendered"], end="")
    return 0


def _cmd_board_pack(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    if not args.month:
        raise RuntimeError("--month is required with named options")
    console, _client = _console_from(args, client_factory=client_factory)
    forecast = _load_json_file(args.forecast, "--forecast", dict) if args.forecast else None
    exceptions = _load_json_file(args.exceptions, "--exceptions", dict) if args.exceptions else None
    decisions = _load_json_file(args.decisions, "--decisions", list) if args.decisions else []
    evals = _load_json_file(args.evals, "--evals", dict) if args.evals else None
    result = _console_call(lambda: console.board_pack(month=args.month, now=args.now or None, forecast=forecast, exceptions=exceptions, decisions=decisions, evals=evals))
    if args.json:
        _emit(result)
    else:
        print(result["rendered"], end="")
    return 0


def _cmd_evals(args: argparse.Namespace, *, client_factory: Callable[[], Any]) -> int:
    if not args.records:
        raise RuntimeError("--records is required with named options")
    console, _client = _console_from(args, client_factory=client_factory)
    records = _load_json_file(args.records, "--records", list)
    result = _console_call(lambda: console.evals(records, now=args.now or None, learn=args.learn))
    print(result["rendered"])
    return 2 if int(dict(result.get("scenarios") or {}).get("failed", 0) or 0) > 0 else 0


def add_company_parser(sub: Any, *, client_factory: Callable[[], Any]) -> None:
    """Attach ``lightbulb company ...`` to the top-level subparsers."""

    company = sub.add_parser("company", help="Company engines: compile, simulate, plan ticks and reads, migrate plans, assess a portfolio, form a company")
    group = company.add_subparsers(dest="company_command", required=True)
    from lightbulb.company_chain_catalog import CHAIN_VERBS
    for verb in CHAIN_VERBS:
        name = verb.replace("_", "-")
        p = group.add_parser(name, aliases=[verb] if name != verb else [], help=f"Inspect or advance {verb} using sealed sources and bound authority")
        p.add_argument("--bundle", required=True)
        p.add_argument("--operation", default="list", choices=("list", "summary", "plan", "open", "advance", "supply", "authorize", "assess"))
        p.add_argument("--engine")
        p.add_argument("--entity-ref")
        p.add_argument("--payload", help="JSON file containing operation arguments and sealed receipts")
        p.add_argument("--states", help="JSON file of local persisted chain records")
        p.add_argument("--project-id", help="Use the authenticated hosted store for this matching bundle project")
        p.add_argument("--now")
        p.add_argument("--out")
        p.set_defaults(chain_verb=verb, func=lambda args: _cmd_chain(args, client_factory=client_factory))

    group.add_parser("blueprints", help="List the company archetypes and standard scenarios").set_defaults(func=_cmd_blueprints)

    p = group.add_parser("compile", help="Compile an archetype (or a blueprint JSON file) into a sealed operating plan")
    p.add_argument("archetype", help="Archetype name (see blueprints) or a blueprint JSON path")
    p.add_argument("--overrides", help="JSON file of blueprint overrides")
    p.add_argument("--out", help="Write the plan JSON here instead of stdout")
    p.set_defaults(func=_cmd_compile)

    p = group.add_parser("simulate", help="Run a synthetic scenario against a plan; exit 2 when an expectation fails")
    p.add_argument("plan", help="Archetype name or plan JSON path")
    p.add_argument("--scenario", default="steady_state", help="Standard scenario name or scenario JSON path")
    p.add_argument("--expect", help="JSON file with a scenario expectation to evaluate")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_simulate)

    p = group.add_parser("goldens", help="Re-run the golden trajectories and report drift (exit 2 on drift)")
    p.add_argument("--archetype")
    p.set_defaults(func=_cmd_goldens)

    p = group.add_parser("tick-plan", help="Plan one cadence tick from a bundle and persisted states (pure)")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--states", help="JSON mapping engine -> [state records]")
    p.add_argument("--now")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_tick_plan)

    p = group.add_parser("observation-jobs", help="Plan the platform reads that satisfy a tick plan's evidence items")
    p.add_argument("--bundle", required=True)
    p.add_argument("--tick-plan", required=True)
    p.add_argument("--window-start", required=True)
    p.add_argument("--window-end")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_observation_jobs)

    p = group.add_parser("consume", help="Route a cross-loop signal into engine commands and intents")
    p.add_argument("--plan", required=True, help="Operating plan JSON")
    p.add_argument("--signal", required=True, help="Signal JSON")
    p.add_argument("--states")
    p.add_argument("--now")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_consume)

    p = group.add_parser("migrate-preview", help="Replay an engine state under a revised plan and print the proof (exit 2 when refused)")
    p.add_argument("--engine", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--from-plan", required=True)
    p.add_argument("--to-plan", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--actor-ref", default="cli-operator")
    p.add_argument("--migrated-at")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_migrate_preview)

    p = group.add_parser("portfolio", help="Assess and rank several companies from their sealed inputs")
    p.add_argument("--companies", required=True, help="JSON list of portfolio inputs")
    p.add_argument("--assessed-at")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_portfolio)

    p = group.add_parser("reference", help="Print the generated company engine reference (lifecycles, primitives, rejection codes)")
    p.add_argument("--out")
    p.set_defaults(func=_cmd_reference)

    p = group.add_parser("form", help="Create a company in the signed-in account (Australia and Canada only)")
    p.add_argument("--name", required=True)
    p.add_argument("--country", required=True, help="AU or CA")
    p.add_argument("--industry")
    p.add_argument("--purpose")
    p.set_defaults(func=lambda args: _cmd_form(args, client_factory=client_factory))

    p = group.add_parser("inbox", help="Render the operator approval inbox from the account's pending approvals")
    p.add_argument("--states", help="JSON mapping engine -> [state records] for freshness checks")
    p.add_argument("--now")
    p.add_argument("--engine-only", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=lambda args: _cmd_inbox(args, client_factory=client_factory))

    p = group.add_parser("readiness", help="Compare a bundle's engines with the account's connected providers (exit 2 when blocked)")
    p.add_argument("--bundle", required=True)
    p.add_argument("--connections", help="JSON list of connection records instead of reading the account")
    p.add_argument("--company-id")
    p.add_argument("--now")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=lambda args: _cmd_readiness(args, client_factory=client_factory))

    p = group.add_parser("bring-up", help="Walk a formed company through readiness, hiring, first period, cadence start, and scheduling (exit 2 when blocked)")
    p.add_argument("--paper-sources", help="JSON list of current paper states and their sealed source plans")
    p.add_argument("--bundle", required=True)
    p.add_argument("--company-ref", required=True, help="Opaque ref for the formed company")
    p.add_argument("--first-tick-at", required=True)
    p.add_argument("--connections", help="JSON list of connection records instead of reading the account")
    p.add_argument("--company-id")
    p.add_argument("--worker-ref", default="cli-bring-up")
    p.add_argument("--interval-seconds", type=int, default=3600)
    p.add_argument("--now")
    p.add_argument("--dry-run", action="store_true", help="Run against in-memory stores; persist nothing")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=lambda args: _cmd_bring_up(args, client_factory=client_factory))

    p = group.add_parser("exceptions", help="Open and render the exceptions desk (exit 2 when a case is past SLA)")
    p.add_argument("--project-id")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--tick-result", help="Tick result JSON object")
    p.add_argument("--observations", help="JSON list of observation records")
    p.add_argument("--covers", help="JSON list of cash cover records")
    p.add_argument("--now")
    p.add_argument("--payload", help="JSON object for the existing console operation")
    p.add_argument("--states", help="Local engine state records")
    p.add_argument("--out")
    p.set_defaults(console_verb="exceptions", func=lambda args: _cmd_chain(args, client_factory=client_factory)
                   if args.payload is not None or args.states is not None or not args.project_id
                   else _cmd_exceptions(args, client_factory=client_factory))

    p = group.add_parser("compliance", help="Open and render the statutory calendar")
    p.add_argument("--project-id")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--jurisdiction")
    p.add_argument("--revenue-per-month", default="0")
    p.add_argument("--payroll-per-month", default="0")
    p.add_argument("--no-payroll", action="store_true")
    p.add_argument("--not-registered-for-gst", action="store_true")
    p.add_argument("--horizon-months", type=int, default=12)
    p.add_argument("--flows-out")
    p.add_argument("--now")
    p.add_argument("--payload", help="JSON object for the existing console operation")
    p.add_argument("--states", help="Local engine state records")
    p.add_argument("--out")
    p.set_defaults(console_verb="compliance", func=lambda args: _cmd_chain(args, client_factory=client_factory)
                   if args.payload is not None or args.states is not None or not args.project_id
                   else _cmd_compliance(args, client_factory=client_factory))

    p = group.add_parser("brief", help="Render the operator brief from hosted company state")
    p.add_argument("--project-id")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--forecast", help="Forecast JSON object")
    p.add_argument("--exceptions", help="Exceptions desk JSON object")
    p.add_argument("--compliance", help="Compliance summary JSON object")
    p.add_argument("--decisions", help="JSON list of decision briefs")
    p.add_argument("--explain", action="append", default=[], metavar="ENGINE:ENTITY:FIELD")
    p.add_argument("--now")
    p.add_argument("--json", action="store_true")
    p.add_argument("--payload", help="JSON object for the existing console operation")
    p.add_argument("--states", help="Local engine state records")
    p.add_argument("--out")
    p.set_defaults(console_verb="brief", func=lambda args: _cmd_chain(args, client_factory=client_factory)
                   if args.payload is not None or args.states is not None or not args.project_id
                   else _cmd_brief(args, client_factory=client_factory))

    p = group.add_parser("board-pack", aliases=["board_pack"], help="Render the monthly board pack from hosted company state")
    p.add_argument("--project-id")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--month", help="YYYY-MM")
    p.add_argument("--forecast", help="Forecast JSON object")
    p.add_argument("--exceptions", help="Exceptions desk JSON object")
    p.add_argument("--decisions", help="JSON list of decision records")
    p.add_argument("--evals", help="Company evals JSON object")
    p.add_argument("--now")
    p.add_argument("--json", action="store_true")
    p.add_argument("--payload", help="JSON object for the existing console operation")
    p.add_argument("--states", help="Local engine state records")
    p.add_argument("--out")
    p.set_defaults(console_verb="board_pack", func=lambda args: _cmd_chain(args, client_factory=client_factory)
                   if args.payload is not None or args.states is not None or not args.project_id
                   else _cmd_board_pack(args, client_factory=client_factory))

    p = group.add_parser("evals", help="Score recommendation records and simulator scenarios (exit 2 when a scenario fails)")
    p.add_argument("--project-id")
    p.add_argument("--bundle", required=True, help="Cadence bundle JSON")
    p.add_argument("--records", help="JSON list of recommendation records")
    p.add_argument("--learn", action="store_true")
    p.add_argument("--now")
    p.add_argument("--payload", help="JSON object for the existing console operation")
    p.add_argument("--states", help="Local engine state records")
    p.add_argument("--out")
    p.set_defaults(console_verb="evals", func=lambda args: _cmd_chain(args, client_factory=client_factory)
                   if args.payload is not None or args.states is not None or not args.project_id
                   else _cmd_evals(args, client_factory=client_factory))

    p = group.add_parser("states", help="List persisted engine states for a project")
    p.add_argument("--project-id", required=True)
    p.add_argument("--engine")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=lambda args: _cmd_states(args, client_factory=client_factory))

    from lightbulb.company_console import CONSOLE_VERBS
    for verb in CONSOLE_VERBS:
        name = verb.replace("_", "-")
        if name in group.choices:
            continue
        p = group.add_parser(name, aliases=[verb] if name != verb else [], help=f"Run the {verb} console operation")
        p.add_argument("--bundle", required=True)
        p.add_argument("--payload", help="JSON object with the console operation's arguments")
        p.add_argument("--states", help="Local persisted engine records with retained bundle plans")
        p.add_argument("--project-id")
        p.add_argument("--now")
        p.add_argument("--out")
        p.set_defaults(console_verb=verb, func=lambda args: _cmd_chain(args, client_factory=client_factory))


__all__ = ["add_company_parser"]


def _unused(_: Mapping[str, Any]) -> None:  # pragma: no cover - keeps Mapping imported for type readers
    return None
