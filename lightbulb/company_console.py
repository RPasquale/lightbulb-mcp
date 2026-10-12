"""The operator console: about ten verbs over a company, each returning sealed JSON.

This is what an agent (or a person in a chat) needs to *run* a company
through the SDK without knowing the module map: tick it, see the work
items, hand it a read or a receipt, explain a number, brief a decision,
simulate, migrate, assess the portfolio, forecast cash, check readiness,
bring it up.  Every verb takes the company's cadence bundle (as a JSON
document the caller holds), a state store, and a clock, and returns a plain
dict that is the sealed SDK object plus a short summary.  The MCP tools and
the CLI are thin wrappers over these verbs, so the harness surface and the
terminal surface cannot drift apart.

The console executes nothing itself: ticks go through the cadence runner's
fences, supplied receipts through the engines' guards, migrations through
the store's migration fence; reads and writes stay with the platform.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from functools import wraps
from typing import Any

from lightbulb.company_cadence_runner import CadenceBundle, CadenceWorker, CompanyCadenceRunner, build_bundle
from lightbulb.company_engine_core import parsed, replaying_for, timestamp
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_chain_catalog import CHAIN_VERBS

CONSOLE_VERBS: tuple[str, ...] = ("tick", "work_items", "supply", "explain", "decide", "simulate", "migrate_preview", "portfolio", "treasury", "readiness", "bring_up", "memory", "grades", "chaos", "exceptions", "compliance", "brief", "board_pack", "evals", "settle_dispatch", "inference_cost", "growth_period", "content_library")
CONSOLE_VERBS += tuple(CHAIN_VERBS)


def _scope_dict(scope: Any) -> dict[str, Any]:
    return dict(scope.to_dict() if hasattr(scope, "to_dict") else scope)


def _md_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("\n", " ").replace("|", "\\|")


def _render_exceptions(summary: Mapping[str, Any]) -> str:
    lines = [
        f"**Exceptions desk** for {summary.get('company_ref')}: {summary.get('open', 0)} open, {summary.get('past_sla', 0)} past SLA",
        "",
        "| Kind | Source | Code | SLA deadline | Waiting on |",
        "|---|---|---|---|---|",
    ]
    for case in summary.get("cases") or []:
        row = dict(case)
        lines.append(f"| {_md_cell(row.get('kind'))} | {_md_cell(row.get('source_ref'))} | {_md_cell(row.get('code'))} | {_md_cell(row.get('sla_deadline'))} | {_md_cell(row.get('waiting_on'))} |")
    return "\n".join(lines)


def _render_compliance(summary: Mapping[str, Any]) -> str:
    from lightbulb.compliance_calendar import obligation_due_on
    rows = list(summary.get("open") or [])
    lines = [
        f"**Compliance {summary.get('jurisdiction')}** as of {summary.get('as_of')}: {len(rows)} obligation(s) open",
        f"reserved from reads: {summary.get('reserved_from_reads', '0')}; still estimated: {summary.get('still_estimated', '0')}; overdue: {summary.get('overdue', '0')}",
        "",
        "| Due | Kind | Status | Amount | Basis | Overdue |",
        "|---|---|---|---|---|---|",
    ]
    for item in rows:
        row = dict(item)
        due_on = obligation_due_on(row)
        lines.append(f"| {_md_cell(due_on)} | {_md_cell(row.get('kind'))} | {_md_cell(row.get('status'))} | {_md_cell(row.get('amount'))} | {_md_cell(row.get('basis'))} | {_md_cell('yes' if row.get('overdue') else 'no')} |")
    if "statutory_obligations" in summary:
        lines += ["", "Statutory dates (calendar only; amounts unknown until read):", "| Due date | Obligation | Basis | Source |", "|---|---|---|---|"]
        for row in summary["statutory_obligations"]:
            lines.append(f"| {_md_cell(row.get('due_on') or 'Unknown')} | {_md_cell(row['kind'])} | {_md_cell(row['basis'])} | {_md_cell(row['source_url'])} |")
        if summary.get("missing_calendar_facts"):
            lines += ["", "Confirm calendar facts: " + "; ".join(summary["missing_calendar_facts"])]
    return "\n".join(lines)


def _unbound_opening(row: Mapping[str, Any]) -> dict[str, Any]:
    """The exceptions desk's opening receipt for a persisted state no plan the console holds accepts."""

    engine, entity = str(row.get("engine")), str(row.get("entity_ref"))
    return {"kind": "unbound_state", "source_engine": engine, "source_ref": f"{engine}:{entity}", "source_digest": str(row.get("state_digest") or "0" * 64), "code": str(row.get("reason", "UNBOUND")).split(":", 1)[0][:120] or "UNBOUND", "detail": f"{engine} {entity} ({row.get('status')}) is persisted but no plan the console holds accepts it: {row.get('reason')}"[:900], "evidence_refs": [f"state:{entity}"[:200]]}


def _render_evals(scorecard_render: str, scenarios: Mapping[str, Any]) -> str:
    passed = int(scenarios.get("passed", 0) or 0)
    failed = int(scenarios.get("failed", 0) or 0)
    return scorecard_render.rstrip() + f"\n\nSimulator scenarios: {passed}/{passed + failed} passed, {failed} failed"


@dataclass
class CompanyConsole:
    """One company: its bundle, its store, its clock, and optionally its formed-company ref and connections."""

    bundle: CadenceBundle
    store: EngineStateStore
    clock: Callable[[], str]
    approval_requester: Callable[[Any], Mapping[str, Any]] | None = None
    # Host-owned verifier configuration, never accepted from a bundle or MCP JSON.
    cohort_scope: Any = None
    cohort_keyring: Any = field(default=None, repr=False)
    # Host-owned: the platform's governed connector path (a HostedConnectorExecutor), used only by the act loop's dispatch.
    connector_executor: Any = field(default=None, repr=False)
    # Host-owned: delivers an in-app notification to the owner the agent works for (the owner digest's in-app channel).
    owner_notifier: Callable[..., Mapping[str, Any]] | None = field(default=None, repr=False)
    # Host-owned: reads the platform's owner stop (/api/autonomy/control) so the autopilot honours it on every path.
    autonomy_reader: Callable[[], Mapping[str, Any]] | None = field(default=None, repr=False)

    @classmethod
    def from_document(cls, bundle: Mapping[str, Any] | CadenceBundle, store: EngineStateStore, clock: Callable[[], str], **kwargs: Any) -> CompanyConsole:
        return cls(bundle=build_bundle(bundle), store=store, clock=clock, **kwargs)

    def _runner(self) -> CompanyCadenceRunner:
        return CompanyCadenceRunner(bundle=self.bundle, store=self.store, approval_requester=self.approval_requester or (lambda request: {"id": "unrequested"}))

    def _states(self) -> dict[str, list[Mapping[str, Any]]]:
        return self._runner().states()

    def _periods(self) -> list[Mapping[str, Any]]:
        from lightbulb.company_operating_system import PERIOD_LIFECYCLE
        from lightbulb.company_operator_surface import _scope
        records = list(self.store.list(engine="company_operating_system"))
        for record in records:
            _, state = PERIOD_LIFECYCLE.bind(self.bundle.operating_plan, record["state"])
            _scope(self.bundle, state)
        return records

    # -- the loop -------------------------------------------------------- #

    def work_items(self, *, now: str | None = None) -> dict[str, Any]:
        plan = self._runner().plan(now=now or self.clock())
        available = f"; {len(plan.available)} move(s) available" if plan.available else ""
        return {"schema": plan.schema_id, "period_ref": plan.period_ref, "period_status": plan.period_status, "automatic": [item.to_dict() for item in plan.automatic], "work_items": [item.to_dict() for item in plan.work_items], "available": [item.to_dict() for item in plan.available], "plan_digest": plan.plan_digest, "summary": f"{len(plan.automatic)} automatic action(s), {len(plan.work_items)} work item(s) on {plan.period_ref or 'no period'} ({plan.period_status or 'none'}){available}"}

    def tick(self, *, now: str | None = None, inputs: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        runner = self._runner()
        stamp = now or self.clock()
        result = runner.tick(now=stamp, inputs=list(inputs))
        return {**result.to_dict(), "summary": f"{len(result.applied)} applied, {len(result.outstanding)} outstanding, {len(result.approvals_pending)} approval(s) pending"}

    def supply(self, action_id: str, receipt: Mapping[str, Any], *, now: str | None = None, source_digest: str | None = None, reason: str | None = None) -> dict[str, Any]:
        entry: dict[str, Any] = {"action_id": action_id, "receipt": dict(receipt)}
        if source_digest:
            entry["source_digest"] = source_digest
        if reason:
            entry["reason"] = reason
        return self.tick(now=now, inputs=[entry])

    def record_tick(self, *, now: str | None = None) -> dict[str, Any]:
        """Tick through the durable cadence worker so the tick itself is a fenced transition."""

        worker = CadenceWorker(runner=self._runner(), clock=lambda: now or self.clock())
        if self.store.get("company_cadence", worker.cadence_ref) is None:
            worker.start()
        followed = worker.follow_bundle()  # the owner amended the bundle: the cadence carries on under it, with a proof
        result = worker.run_once()
        if result is None:
            return {"summary": "cadence is not running; resume it first", "recorded": False, "followed_bundle": followed}
        return {**result.to_dict(), "recorded": True, "followed_bundle": followed, "summary": f"tick recorded: {len(result.applied)} applied, {len(result.outstanding)} outstanding" + ("; the cadence moved onto the amended bundle" if followed else "")}

    # -- understanding --------------------------------------------------- #

    def explain(self, engine: str, entity_ref: str, field: str) -> dict[str, Any]:
        from lightbulb.company_explain import explain_engine_field

        record = self.store.get(engine, entity_ref)
        if record is None:
            raise LookupError(f"{engine} state {entity_ref} is not persisted")
        plan = self._plan_for(engine)
        explanation = explain_engine_field(engine, plan, dict(record["state"]), field)
        return {**explanation.to_dict(), "summary": explanation.narrative()}

    def _plan_for(self, engine: str) -> Any:
        plans = {"company_operating_system": self.bundle.operating_plan, "growth_engine": self.bundle.growth_plan, "pipeline_engine": self.bundle.pipeline_plan, "saas_operating_engine": self.bundle.saas_plan, "finance_close": self.bundle.finance_close_plan, "service_delivery": self.bundle.service_delivery_plan, "company_workforce": self.bundle.workforce_plan}
        plan = plans.get(engine)
        if plan is None:
            from lightbulb.company_chain_catalog import plan_for_chain
            return plan_for_chain(self.bundle, engine)
        return plan

    def chain(self, verb: str, **kwargs: Any) -> dict[str, Any]:
        from lightbulb.company_operator_surface import operate_chain
        return operate_chain(self, verb, **kwargs)

    def payroll_tie_out(self, *, payruns=(), expected_components=None, exemptions=None, books=None, liability_accounts=(), unpaid_basis=None, now=None) -> dict[str, Any]:
        """Check scoped payroll reads against this company's saved calendar and books."""
        from lightbulb.payroll_tie_out import check_payroll_tie_out
        from lightbulb.compliance_calendar_store import current_scoped_calendar_plan
        scope = self.bundle.engine_scope("payroll-tie-out")
        plan = current_scoped_calendar_plan(self.store, self.bundle)
        result = check_payroll_tie_out(scope=scope, company_ref=self.bundle.company_ref,
            jurisdiction=self.bundle.operating_plan.blueprint.country, as_of=now or self.clock(),
            payruns=payruns, expected_components=expected_components, exemptions=exemptions,
            calendar=None if plan is None else {"scope": scope, "document": plan.to_dict()},
            books=books, liability_accounts=liability_accounts, unpaid_basis=unpaid_basis)
        return {**result.to_dict(), "summary": result.render()}

    def decide(self, task: Mapping[str, Any], *, now: str | None = None, cash_on_hand: Any = None, memory_state: Any = None) -> dict[str, Any]:
        from lightbulb.company_approval_inbox import render_item
        from lightbulb.company_decisions import brief_for_item

        stamp = now or self.clock()
        runner = self._runner()
        item = render_item(task, states=runner.states(), pending_requests={ref: request for runtime in runner.runtimes.values() for ref, request in runtime.pending.items()}, now=stamp)
        pending_command = None
        current_state = None
        if item.engine_binding is not None:
            for runtime in runner.runtimes.values():
                if runtime.engine == item.engine_binding.engine:
                    pending_command = runtime.pending_commands.get(item.engine_binding.transition_ref)
                    record = self.store.get(runtime.engine, item.engine_binding.entity_ref)
                    current_state = runtime.load(item.engine_binding.entity_ref) if record is not None else None
        brief = brief_for_item(item, plan=self.bundle.operating_plan, periods=self._periods(), pending_command=pending_command, now=stamp, cash_on_hand=cash_on_hand, current_state=current_state, memory_state=memory_state)
        return {**brief.to_dict(), "inbox_item": item.to_dict(), "summary": brief.render()}

    def simulate(self, scenario: str | Mapping[str, Any] = "steady_state") -> dict[str, Any]:
        from lightbulb.company_simulator import simulate_company, standard_scenario

        result = simulate_company(self.bundle.operating_plan, standard_scenario(scenario) if isinstance(scenario, str) else scenario)
        return {**result.to_dict(), "summary": f"{result.periods_run} period(s): revenue {result.total_revenue}, final cash {result.final_cash}" + (f", halted at {result.halted_at_period} ({result.halt_reason})" if result.halted_at_period else "")}

    def migrate_preview(self, engine: str, entity_ref: str, to_plan: Mapping[str, Any], *, reason: str, now: str | None = None) -> dict[str, Any]:
        from lightbulb.company_plan_migration import lifecycle_for, migrate_state

        record = self.store.get(engine, entity_ref)
        if record is None:
            raise LookupError(f"{engine} state {entity_ref} is not persisted")
        result = migrate_state(lifecycle_for(engine).spec, state=dict(record["state"]), from_plan=self._plan_for(engine), to_plan=to_plan, migrated_at=now or self.clock(), actor_ref=self.bundle.actor_ref, reason=reason)
        return {**result.migration.to_dict(), "migrated_state_digest": result.state.state_digest, "summary": f"{engine} {entity_ref} replays cleanly under the revised plan at version {result.migration.version}"}

    def migrate(self, engine: str, entity_ref: str, to_plan: Mapping[str, Any], *, reason: str, now: str | None = None) -> dict[str, Any]:
        from lightbulb.company_plan_migration import lifecycle_for

        lifecycle = lifecycle_for(engine)
        runtime = EngineRuntime(spec=lifecycle.spec, engine=engine, plan=self._plan_for(engine), store=self.store, advance=lifecycle.advance)
        outcome = runtime.migrate(entity_ref, to_plan, migrated_at=now or self.clock(), actor_ref=self.bundle.actor_ref, reason=reason)
        return {**outcome.migration.to_dict(), "record": dict(outcome.record), "summary": f"{engine} {entity_ref} migrated and persisted at version {outcome.migration.version}"}

    # -- the wider picture ----------------------------------------------- #

    def portfolio(self, companies: Sequence[Mapping[str, Any]], *, now: str | None = None) -> dict[str, Any]:
        from lightbulb.company_portfolio import assess_portfolio, render_portfolio

        assessment = assess_portfolio(companies, assessed_at=now or self.clock())
        return {**assessment.to_dict(), "summary": render_portfolio(assessment)}

    def treasury(self, position: Mapping[str, Any], *, horizon_weeks: int = 13, flows: Sequence[Mapping[str, Any]] = (), payroll: Mapping[str, Any] | None = None, fixed_costs: Mapping[str, Any] | None = None, floor: Any = "0", period_starts: Sequence[str] = (), now: str | None = None, inference_cost_registers: Sequence[Mapping[str, Any]] = (), include_payroll: bool = False) -> dict[str, Any]:
        """The cash forecast from a balance read and the flows supplied.

        ``include_payroll`` adds the wages the persisted pay runs prove: every
        committed run not yet paid, and the paydays projected after the last
        committed run on the payroll plan's cycle (the days the calendar projects
        super on), never wages already paid.  It replaces a typed ``payroll``
        schedule and refuses one, and refuses a supplied flow that repeats one of
        its own.
        """

        from lightbulb.company_treasury import CashPosition, forecast_cash, render_forecast

        stamp = now or self.clock()
        rows = [dict(item) for item in flows]
        if include_payroll:
            from lightbulb.company_chain_catalog import plan_for_chain
            from lightbulb.company_engine_store import complete_engine_states
            from lightbulb.payroll_run_chain import forecast_flows

            if payroll is not None:
                raise ValueError("PAYROLL_TWICE: the pay runs already give the wages; a typed payroll schedule would count them again")
            try:
                payroll_plan = plan_for_chain(self.bundle, "payroll_run_chain")
            except LookupError:
                payroll_plan = None
            if payroll_plan is not None:
                wages = [flow.to_dict() for flow in forecast_flows([dict(record["state"]) for record in complete_engine_states(self.store, engine="payroll_run_chain")], plan=payroll_plan, as_of=stamp, horizon_days=int(horizon_weeks) * 7)]
                repeated = {str(row.get("ref")) for row in rows} & {str(row["ref"]) for row in wages}
                if repeated:
                    raise ValueError(f"FLOW_DUPLICATED: {', '.join(sorted(repeated))} is supplied and also comes from the pay runs")
                rows.extend(wages)
        forecast = forecast_cash(CashPosition.model_validate(dict(position)), as_of=stamp, horizon_weeks=horizon_weeks, flows=rows, operating_plan=self.bundle.operating_plan, payroll=payroll, fixed_costs=fixed_costs, floor=floor, period_starts=period_starts, inference_cost_registers=inference_cost_registers)
        return {**forecast.to_dict(), "summary": render_forecast(forecast, weeks=6)}

    def settle_dispatch(self, *, worker_ref: str, instance: Mapping[str, Any], currency: str | None = None, now: str | None = None, usd_rate: Any = None) -> dict[str, Any]:
        """Meter a worker's open dispatch from the platform's workflow-instance record and, if settled, record its outcome."""

        from lightbulb.company_dispatch_metering import settle_dispatch

        runner = self._runner()
        runtime = runner.runtimes.get("company_workforce")
        if runtime is None:
            raise ValueError("NO_WORKFORCE_PLAN: this bundle runs no workforce, so no dispatch can be settled")
        metered, outcome = settle_dispatch(runtime, worker_ref=worker_ref, instance=instance, currency=currency or self.bundle.operating_plan.blueprint.currency, occurred_at=now or self.clock(), actor_ref=self.bundle.actor_ref, usd_rate=usd_rate)
        result = getattr(outcome, "result", None)
        return {"metered": metered.to_dict(), "settled": metered.settled, "persisted": bool(getattr(outcome, "persisted", False)), "rejection_code": getattr(getattr(result, "receipt", None), "rejection_code", None), "summary": f"{worker_ref}: {metered.outcome}" + (f", {metered.cost_usd} USD metered" if metered.cost_micro_usd is not None else ", still running")}

    def inference_cost(self, metered: Mapping[str, Any], statement: Mapping[str, Any], *, tolerance_ratio: Any = None, register_ref: str | None = None, now: str | None = None) -> dict[str, Any]:
        """Reconcile a provider statement against metered cost; within tolerance, the register lines that would enter the period."""

        from lightbulb.inference_cost_register import build_register, inference_cost_summary, reconcile_inference_cost

        verdict = reconcile_inference_cost(metered, statement, tolerance_ratio=tolerance_ratio)
        register = build_register(verdict, metered, statement) if verdict.verdict == "WITHIN_TOLERANCE" else None
        summary = inference_cost_summary(verdict, register)
        ingestion = None
        if register_ref is not None and register is not None:
            from lightbulb.company_operator_surface import record_inference_bill
            ingestion = record_inference_bill(self, register_ref, bill=register.to_dict(), now=now or self.clock())
        return {"ingestion": ingestion, "verdict": verdict.to_dict(), "register": None if register is None else register.to_dict(), **{f"summary_{key}": value for key, value in summary.items()}, "summary": f"{verdict.provider} {verdict.window_start[:10]}..{verdict.window_end[:10]}: billed {summary['billed']}, metered {summary['metered']}, {verdict.verdict}" + (f" ({verdict.rejection_code})" if verdict.rejection_code else "")}

    def content_library(self, asset_refs: Sequence[str], *, register_ref: str, allocations: Sequence[Mapping[str,Any]], now: str | None = None) -> dict[str,Any]:
        """Read selected persisted assets and allocate protected production costs for reporting."""
        from lightbulb.content_asset_lifecycle import content_library
        assets=[]
        for ref in asset_refs:
            record=self.store.get("content_asset_lifecycle",ref)
            if record is None:
                raise LookupError(f"content asset {ref} is not persisted")
            assets.append({"plan":self._plan_for("content_asset_lifecycle"),"state":record["state"]})
        costs=self.store.get("company_cost_centres",register_ref)
        if costs is None:
            raise LookupError(f"protected cost register {register_ref} is not persisted")
        report=content_library(assets,costs["state"],cost_plan=self._plan_for("company_cost_centres"),allocations=allocations,
            company_ref=self.bundle.company_ref,scope={**self.bundle.scope,"entity_ref":register_ref,"currency":self.bundle.operating_plan.blueprint.currency},observed_at=now or self.clock())
        return {"library":report.to_dict(),"summary":f"{len(report.rows)} assets; {report.allocated_production_cost} production cost allocated from the protected register"}

    def growth_period(self, portfolio: Mapping[str, Any], attribution_ledger: Mapping[str, Any], *,
                      register_ref: str, acquisition_engines: Sequence[str] = ("growth_engine", "pipeline_engine"),
                      now: str | None = None, customer_cohort: Mapping[str,Any] | None = None) -> dict[str, Any]:
        """Replay the selected company's persisted protected costs and supplied conversion sources."""
        from lightbulb.growth_period_fold import fold_growth_period, growth_period_signals
        if self.bundle.growth_plan is None:
            raise ValueError("NO_GROWTH_PLAN: this company bundle has no growth plan")
        record = self.store.get("company_cost_centres", register_ref)
        if record is None:
            raise LookupError(f"protected cost register {register_ref} is not persisted")
        fold = fold_growth_period(self.bundle.growth_plan, portfolio, attribution_ledger, record["state"],
            cost_plan=self._plan_for("company_cost_centres"), company_ref=self.bundle.company_ref,
            scope={**self.bundle.scope, "entity_ref":register_ref, "currency":self.bundle.operating_plan.blueprint.currency},
            folded_at=now or self.clock(), acquisition_engines=acquisition_engines,customer_cohort=customer_cohort,cohort_scope=self.cohort_scope,cohort_keyring=self.cohort_keyring)
        return {"fold":fold.to_dict(), "signals":[signal.to_dict() for signal in growth_period_signals(fold,cohort_scope=self.cohort_scope,cohort_keyring=self.cohort_keyring)],
            "summary":f"{fold.conversions} conversions; {fold.attributed_revenue} attributed revenue; {fold.acquisition_cost} recorded acquisition cost {fold.currency}"}

    def readiness(self, connections: Sequence[Mapping[str, Any]], *, now: str | None = None, company_id: str | None = None) -> dict[str, Any]:
        from lightbulb.company_bring_up import assess_readiness

        readiness = assess_readiness(self.bundle, connections, now=now or self.clock(), company_id=company_id)
        missing = readiness.missing_providers()
        return {**readiness.to_dict(), "summary": "ready" if readiness.ready else "; ".join(f"{engine} needs {' and '.join(groups)}" for engine, groups in missing.items())}

    def bring_up(self, connections: Sequence[Mapping[str, Any]], *, formed_company_ref: str, first_tick_at: str, gateway: Any = None, company_id: str | None = None, paper_sources: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        from lightbulb.company_bring_up import BringUpOrchestrator

        orchestrator = BringUpOrchestrator(bundle=self.bundle, store=self.store, connections=lambda: list(connections), clock=self.clock, formed_company_ref=formed_company_ref, gateway=gateway, company_id=company_id, approval_requester=self.approval_requester)
        report = orchestrator.run(first_tick_at=first_tick_at, paper_sources=paper_sources)
        return {**report.to_dict(), "summary": f"{report.company_ref}: {report.status}; " + ", ".join(f"{step.event} {step.outcome}" for step in report.steps)}

    def memory(self, *, now: str | None = None, lesson: str | None = None) -> dict[str, Any]:
        """Learn from every closed period and graded worker into the company's operating memory (persisted like any engine)."""

        from lightbulb.company_operating_memory import MEMORY_KIND, MEMORY_LIFECYCLE, advance_memory, learn_command, learn_from_periods, learn_from_workers, memory_plan, memory_ref, memory_summary, open_memory

        plan = memory_plan(self.bundle.operating_plan.blueprint.archetype, self.bundle.company_ref)
        runtime = EngineRuntime(spec=MEMORY_LIFECYCLE, engine=MEMORY_KIND, plan=plan, store=self.store, advance=advance_memory)
        ref = memory_ref(plan)
        stamp = now or self.clock()
        if self.store.get(MEMORY_KIND, ref) is None:
            runtime.open(ref, open_memory(plan, self.bundle.scope, opened_at=stamp))
        state = runtime.load(ref)
        samples = learn_from_periods(self.bundle.operating_plan, self._periods())
        if self.bundle.workforce_plan is not None:
            samples.extend(learn_from_workers(self.bundle.workforce_plan, self.store.list(engine="company_workforce"), archetype=plan.archetype))
        learned = {sample["source_state_digest"] for sample in samples}
        fresh = [sample for sample in samples if sample["source_state_digest"] not in set(state.ledger.learned_state_digests)]
        if fresh:
            outcome = runtime.advance_and_persist(ref, learn_command(plan, state, fresh, learned_at=stamp, lesson=lesson))
            if not outcome.persisted:
                return {"summary": f"memory refused: {outcome.result.receipt.rejection_code}", **memory_summary(state)}
            state = runtime.load(ref)
        return {**memory_summary(state), "learned_now": len(fresh), "candidates": len(learned), "summary": f"memory holds {len(state.ledger.priors)} prior(s) from {len(state.ledger.learned_state_digests)} state(s); learned {len(fresh)} new sample(s)"}

    def grades(self, *, now: str | None = None) -> dict[str, Any]:
        from lightbulb.company_operating_memory import MEMORY_KIND, MEMORY_LIFECYCLE, memory_plan, memory_ref
        from lightbulb.company_workforce_learning import grade_workers, revise_roster

        if self.bundle.workforce_plan is None:
            raise LookupError("the bundle carries no workforce plan")
        memory_state = None
        plan = memory_plan(self.bundle.operating_plan.blueprint.archetype, self.bundle.company_ref)
        record = self.store.get(MEMORY_KIND, memory_ref(plan))
        if record is not None:
            memory_state = MEMORY_LIFECYCLE.State.model_validate(dict(record["state"]), context={MEMORY_LIFECYCLE.plan_context_key: plan})
        grades = grade_workers(self.bundle.workforce_plan, self.store.list(engine="company_workforce"), graded_at=now or self.clock(), memory_state=memory_state)
        revision = revise_roster(self.bundle.operating_plan, self.bundle.workforce_plan, grades, revised_at=now or self.clock()) if grades.workers else None
        return {"grades": grades.to_dict(), "revision": revision.to_dict() if revision is not None else None, "summary": ", ".join(f"{row.worker_ref} {row.grade} ({row.score})" for row in grades.workers) or "no workers graded"}

    def chaos(self, faults: Sequence[str] | None = None) -> dict[str, Any]:
        from lightbulb.company_chaos import FAULT_KINDS, run_chaos

        report = run_chaos(self.bundle, faults=tuple(faults or FAULT_KINDS))
        return {**report.to_dict(), "summary": "all invariants held" if report.all_held else "; ".join(f"{item.fault} failed: {item.runner_did}" for item in report.failures())}
    # -- round four: the desk, the calendar, the page ------------------- #

    def _engine_states(self, engine: str, plan: Any, lifecycle: Any) -> tuple[list[Any], list[dict[str, Any]]]:
        """Every persisted state of the engine bound to ``plan``, and every one that does not bind, with why: a state that fails validation is reported, never dropped."""

        from lightbulb.company_engine_store import complete_engine_states

        out: list[Any] = []
        unbound: list[dict[str, Any]] = []
        for record in complete_engine_states(self.store, engine=engine):
            try:
                out.append(lifecycle.State.model_validate(dict(record["state"]), context={lifecycle.plan_context_key: plan}))
            except ValueError as exc:
                raw = dict(record.get("state") or {})
                unbound.append({"engine": engine, "entity_ref": str(record.get("entity_ref")), "status": str(raw.get("status") or record.get("status") or ""), "plan_digest": str(raw.get("plan_digest") or ""), "state_digest": str(raw.get("state_digest") or ""), "reason": ("PLAN_MISMATCH: " if str(raw.get("plan_digest")) != plan.plan_digest else "STATE_DOES_NOT_REPLAY: ") + str(exc).splitlines()[0][:240]})
        return out, unbound

    def exceptions(self, *, now: str | None = None, tick_result: Mapping[str, Any] | None = None, observations: Sequence[Mapping[str, Any]] = (), covers: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        """Open exception cases from what was refused (a tick result, observations, covers, chains, obligations) and summarise the desk; opening persists, nothing else does."""

        from lightbulb.exceptions_desk import EXCEPTIONS_KIND, EXCEPTIONS_LIFECYCLE, advance_exception, compile_exceptions_desk, desk_summary, exception_from_chain, exception_from_cover, exception_from_obligation, exception_from_observation, exception_ref, exceptions_from_tick, open_exception

        stamp = now or self.clock()
        plan = compile_exceptions_desk(self.bundle.company_ref)
        runtime = EngineRuntime(spec=EXCEPTIONS_LIFECYCLE, engine=EXCEPTIONS_KIND, plan=plan, store=self.store, advance=advance_exception)
        openings: list[dict[str, Any]] = []
        if tick_result is not None:
            openings.extend(exceptions_from_tick(tick_result))
        for index, observation in enumerate(observations):
            raw = dict(observation)
            opening = exception_from_observation(raw, source_engine=str(raw.get("source_engine") or "observation"), source_ref=str(raw.get("source_ref") or f"observation:{index}"))
            if opening is not None:
                openings.append(opening)
        for index, cover in enumerate(covers):
            opening = exception_from_cover(cover, source_ref=str(dict(cover).get("source_ref") or f"cover:{index}"))
            if opening is not None:
                openings.append(opening)
        from lightbulb.company_engine_store import complete_engine_states
        from datetime import timedelta

        from lightbulb.compliance_calendar_store import calendar_obligations

        for engine, module_name, plan_attr in (("revenue_chain", "lightbulb.revenue_chain", "REVENUE_CHAIN_LIFECYCLE"), ("payables_chain", "lightbulb.payables_chain", "PAYABLES_CHAIN_LIFECYCLE")):
            for record in complete_engine_states(self.store, engine=engine):
                state = dict(record["state"])
                if state.get("status") == "reconciliation_required":
                    openings.append({"kind": "chain_reconciliation", "source_engine": engine, "source_ref": f"{engine}:{state['scope']['entity_ref']}", "source_digest": str(state["state_digest"]), "code": "RECONCILIATION_REQUIRED", "detail": str(dict(state.get("ledger") or {}).get("reconciliation_reason") or "reconciliation required")[:900], "evidence_refs": [f"{engine}:{state['scope']['entity_ref']}:{str(state['state_digest'])[:16]}"]})
        obligations = calendar_obligations(self.store, self.bundle)
        # an obligation overdue by its return, due before its payment, says so (New Zealand's IR4 in July, terminal tax in February)
        return_dates = {str(bound.scope.entity_ref): row.lodge_due_at for own, bound in obligations.bound if (row := own.obligation(str(bound.ledger.obligation_ref))) is not None and row.lodge_due_at and not bound.ledger.lodged_at and parsed(row.lodge_due_at) < parsed(row.due_at)}
        for record in complete_engine_states(self.store, engine="compliance_obligation"):
            state = dict(record["state"])
            if state.get("status") == "overdue" and dict(state.get("ledger") or {}).get("deadline_status") != "unknown":
                ledger = dict(state.get("ledger") or {})
                return_due = return_dates.get(str(state["scope"]["entity_ref"]))
                last_day = lambda stamp: (parsed(str(stamp)) - timedelta(days=1)).date().isoformat()  # a due date is the end of its day
                detail = f"{ledger.get('kind')} due {ledger.get('due_at')} is {ledger.get('days_late')} day(s) late" if return_due is None else f"{ledger.get('kind')}: the return due {last_day(return_due)} is {ledger.get('days_late')} day(s) late and not lodged; the payment is due {last_day(ledger.get('due_at'))}"
                openings.append({"kind": "overdue_obligation", "source_engine": "compliance_obligation", "source_ref": f"compliance_obligation:{state['scope']['entity_ref']}", "source_digest": str(state["state_digest"]), "code": "OBLIGATION_OVERDUE", "detail": detail, "evidence_refs": [f"obligation:{state['scope']['entity_ref']}"]})
        for own, bound in obligations.bound:
            # paid first and never lodged: once its return is late, the lodgement is overdue even though the money went
            row = own.obligation(str(bound.ledger.obligation_ref))
            if bound.status != "paid_awaiting_lodgement" or row is None or row.deadline_status == "unknown":
                continue
            lodge_due = row.lodge_due_at or row.due_at
            if parsed(lodge_due) + timedelta(days=own.overdue_grace_days) < parsed(stamp):
                openings.append({"kind": "overdue_obligation", "source_engine": "compliance_obligation", "source_ref": f"compliance_obligation:{bound.scope.entity_ref}", "source_digest": bound.state_digest, "code": "LODGEMENT_OVERDUE", "detail": f"{bound.ledger.kind} was paid {str(bound.ledger.paid_at)[:10]} but its return, due {lodge_due[:10]}, is not lodged", "evidence_refs": [f"obligation:{bound.scope.entity_ref}"]})
        # a persisted obligation no plan accepts is a case of its own: it is never left out of sight
        for row in obligations.unbound:
            openings.append(_unbound_opening(row))
        # work that has waited a fortnight, unchanged, is put in front of the owner
        openings.extend(self._stale_work(now=stamp))
        opened = 0
        for opening in openings:
            ref = exception_ref(str(opening["kind"]), str(opening["source_ref"]), str(opening["source_digest"]))
            if self.store.get(EXCEPTIONS_KIND, ref) is None:
                runtime.open(ref, open_exception(plan, self.bundle.engine_scope(ref), receipt=opening, opened_at=stamp, actor_ref=self.bundle.actor_ref))
                opened += 1
        states, unbound = self._engine_states(EXCEPTIONS_KIND, plan, EXCEPTIONS_LIFECYCLE)
        summary = desk_summary(plan, states, now=stamp)
        note = f"; {len(unbound)} case(s) cannot be read under the desk's plan" if unbound else ""
        return {**summary, "unbound": unbound, "opened_now": opened, "rendered": _render_exceptions(summary), "summary": f"{summary['open']} open exception(s), {summary['past_sla']} past SLA; {opened} opened now{note}"}

    def _stale_work(self, *, now: str) -> list[dict[str, Any]]:
        """An opening for every piece of work that has waited more than a fortnight unchanged: a cadence work item, an owner action waiting on the owner or the platform, a document waiting for the owner to send it.

        The fortnight counts from when the work last changed, or from its own due date when that is later: work
        waiting for its date is not stale.  One case per unchanged wait; if the work moves and stalls again, it gets
        a new one.
        """

        from datetime import timedelta

        from lightbulb.company_engine_core import stable_digest
        from lightbulb.company_engine_store import complete_engine_states
        from lightbulb.exceptions_desk import STALE_WORK_DAYS

        at = parsed(now)
        limit = timedelta(days=STALE_WORK_DAYS)
        out: list[dict[str, Any]] = []

        def opening(source_ref: str, digest: str, since: str, what: str) -> None:
            days = (at - parsed(since)).days
            out.append({"kind": "stale_work", "source_engine": source_ref.split(":", 1)[0][:300], "source_ref": source_ref[:200], "source_digest": digest, "code": "WORK_STALE", "detail": f"{what} has waited since {since[:10]} ({days} days) with nothing moving it"[:900], "evidence_refs": [f"since:{since[:10]}"]})

        for item in self._runner().plan(now=now).work_items:
            if item.engine == "exception_case":
                continue  # the desk's own cases are the escalation, never escalated again
            record = self.store.get(item.engine, item.entity_ref)
            since, digest = str(self.bundle.start_at), stable_digest({"action": item.action_id, "prepared": item.prepared})
            if record is not None:
                state = dict(record["state"])
                history = state.get("transition_history") or []
                since = str(dict(history[-1]).get("command", {}).get("occurred_at")) if history else str(state.get("as_of") or since)
                digest = str(record.get("state_digest") or digest)
            if item.due_at and parsed(str(item.due_at)) > parsed(since):
                since = str(item.due_at)
            if at - parsed(since) > limit:
                opening(f"work:{item.action_id}", digest, since, item.summary[:300])
        from lightbulb.company_act_surface import persisted_owner_actions

        for action in persisted_owner_actions(self):
            if action.status in ("planned", "awaiting_approval", "blocked", "failed", "reconcile") and at - parsed(action.updated_at) > limit:
                opening(f"owner_action:{action.action_ref}", action.action_digest, action.updated_at, f"{action.action_kind} for {action.subject} ({action.status.replace('_', ' ')})")
        from lightbulb.company_exchange import verify_thread
        from lightbulb.company_exchange_sourcing import sourced_exchange_refs
        from lightbulb.company_exchange_standing import standing_exchange_refs
        from lightbulb.company_exchange_surface import current_card, exchange_payment, quote_lapsed

        card = current_card(self)
        # not answers this company owes: a quote a sourcing request did not choose (left to lapse on purpose), and a
        # remittance before the books show the invoice paid (until then the payables chain holds the bill's due date)
        sourced = sourced_exchange_refs(self)
        # a standing order's quote is decided by the standing order: within its ceilings on the next tick, above them by the owner, who is asked
        standing = standing_exchange_refs(self)
        for record in complete_engine_states(self.store, engine="commercial_exchange"):
            state = dict(record["state"])
            if not str(record.get("entity_ref", "")).startswith("thread:") or state.get("status") == "withdrawn":
                continue
            exchange_ref = str(record["entity_ref"])[7:]
            delivery = dict(state.get("delivery") or {})
            pending = False
            for digest, row in delivery.items():
                row = dict(row)
                if row.get("status") in ("waiting_for_owner", "ready_to_deliver"):
                    pending = True
                    if at - parsed(str(row.get("at"))) > limit:
                        opening(f"commercial_exchange:{exchange_ref}", str(digest), str(row["at"]), f"a document in exchange {exchange_ref} ({str(row['status']).replace('_', ' ')})")
            thread = verify_thread(dict(state["thread"])["documents"])
            owed = thread.next_kind is not None and not (thread.next_kind == "purchase_order" and (exchange_ref in sourced or exchange_ref in standing)) \
                and (thread.next_kind != "remittance" or bool(dict(exchange_payment(self, exchange_ref) or {}).get("paid")))
            if not pending and card is not None and thread.next_from == card.party_ref and owed and not quote_lapsed(thread, at=now):
                # the other business is waiting on this company's answer
                last = thread.last()
                since = str(dict(delivery.get(last.document_digest) or {}).get("at") or last.issued_at)
                if at - parsed(since) > limit:
                    opening(f"commercial_exchange:{exchange_ref}", last.document_digest, since, f"exchange {exchange_ref}: {thread.next_kind.replace('_', ' ')} owed to {last.from_party}")
        return out

    def compliance(self, *, jurisdiction: str | None = None, now: str | None = None, horizon_months: int = 12, estimated_revenue_per_month: Any = "0", estimated_payroll_per_month: Any = "0", has_payroll: bool = True, registered_for_gst: bool = True, pay_cycle: str | None = None, next_pay_date: str | None = None, gst_reporting: str | None = None, withholder: str | None = None, instalments: str | None = None, income_tax_program: str | None = None, australia_facts: Mapping[str, Any] | None = None, canada_facts: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Compile the calendar, open every obligation not yet persisted, and summarise what is due; the treasury flows it produces are returned for the forecast.

        The jurisdiction is the company's own unless one is named.  The company's approved and
        paid pay runs are its payday obligations; the pay cycle is the one named, else the
        payroll plan's, and projected paydays are forecast, never opened.  ``gst_reporting``,
        ``withholder``, ``instalments`` and ``income_tax_program`` are the Australian and Canadian
        facts the dates turn on; the ones left out are assumed and listed in the plan.
        """

        from lightbulb.company_engine_store import complete_engine_states
        from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE, advance_obligation, calendar_summary, committed_pay_runs, compile_compliance_calendar, open_obligation, pay_cycle_for_days, reservations
        from lightbulb.compliance_calendar_store import adopt_unkept_obligations, calendar_obligations, calendar_content_digest, current_scoped_calendar_plan, follow_corrected_rules, keep_calendar_plan, kept_versions, mark_overdue, retain_payroll_periods, retain_uncertain_deadlines, restore_known_deadlines

        stamp = timestamp(now or self.clock(), field_name="now")
        currency = self.bundle.operating_plan.blueprint.currency
        jurisdiction = jurisdiction or self.bundle.operating_plan.blueprint.country
        payroll_states = [dict(record["state"]) for record in complete_engine_states(self.store, engine="payroll_run_chain")]
        for state in payroll_states:
            scope = dict(state.get("scope") or {})
            expected = self.bundle.engine_scope(str(scope.get("entity_ref") or "unknown"))
            if any(scope.get(key) != expected.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")):
                raise ValueError("SCOPE_MISMATCH: payroll dates belong to another execution scope")
        pay_runs = committed_pay_runs(payroll_states)
        cycle = pay_cycle or pay_cycle_for_days(dict(self.bundle.supporting_plans.get("payroll_run_chain") or {}).get("pay_cycle_days"))

        previous = None
        calendar_read_failed = False
        if str(jurisdiction).upper() in ("CA", "AU"):
            try:
                previous = current_scoped_calendar_plan(self.store, self.bundle)
            except (ValueError, KeyError, TypeError, LookupError):
                calendar_read_failed = True
        if australia_facts is None and str(jurisdiction).upper() == "AU":
            if previous is not None and previous.australia_calendar:
                stored = dict(previous.australia_calendar.get("facts") or {})
                australia_facts = stored if any(value not in (None, {}, [], ()) for value in stored.values()) else None
                for key, value in (("gst_reporting", gst_reporting), ("withholder", withholder), ("instalments", instalments), ("company_tax_program", income_tax_program)):
                    if value is not None:
                        australia_facts = {**(australia_facts or {}), key: value}

        if canada_facts is None and str(jurisdiction).upper() == "CA":
            if previous is not None and previous.canada_calendar:
                if previous.company_ref != self.bundle.company_ref:
                    raise ValueError("SCOPE_MISMATCH: calendar belongs to another company")
                canada_facts = dict(previous.canada_calendar.get("facts") or {})
                for key, value in (("gst_reporting", gst_reporting), ("remitter", withholder), ("corporate_instalments", instalments)):
                    if value is not None:
                        canada_facts[key] = value

        def compile_at(start_at: str) -> Any:
            return compile_compliance_calendar(self.bundle.company_ref, jurisdiction=jurisdiction, currency=currency, start_at=start_at, horizon_months=horizon_months, estimated_revenue_per_month=estimated_revenue_per_month, estimated_payroll_per_month=estimated_payroll_per_month, has_payroll=has_payroll, registered_for_gst=registered_for_gst, pay_cycle=cycle, next_pay_date=next_pay_date, pay_runs=pay_runs, gst_reporting=gst_reporting, withholder=withholder, instalments=instalments, income_tax_program=income_tax_program, australia_facts=australia_facts, canada_facts=canada_facts)

        plan = compile_at(stamp)
        if calendar_read_failed:
            # An invalid scope/pointer is not permission to overwrite stored evidence.
            summary = calendar_summary(plan, now=stamp)
            return {**summary, "plan": plan.to_dict(), "flows": [], "opened_now": 0,
                "marked_overdue_now": [], "adopted": [], "corrected": [], "superseded": [], "unbound": [],
                "calendar": {"version": None, "current_plan_digest": None, "opened_under": None},
                "stored_obligations_available": False, "persistence_status": "unavailable",
                "rendered": _render_compliance(summary),
                "summary": "Stored calendar is unavailable; this preview uses supplied facts only. No stored obligation was changed."}
        # every obligation already persisted reads under the plan it was opened under; one opened before plans were kept is migrated onto its rebuilt plan
        kept = calendar_obligations(self.store, self.bundle)
        adopted: list[dict[str, Any]] = []
        if any(str(row.get("reason", "")).startswith("PLAN_NOT_KEPT") for row in kept.unbound):
            adopted = adopt_unkept_obligations(self.store, self.bundle, kept.unbound, rebuild=compile_at, migrated_at=stamp, actor_ref=self.bundle.actor_ref)
            kept = calendar_obligations(self.store, self.bundle)
        plan = retain_payroll_periods(plan, kept)
        plan = retain_uncertain_deadlines(plan, kept)
        plan = restore_known_deadlines(plan, kept, rebuild=compile_at)
        persisted = {str(row["obligation_ref"]) for row in kept.unbound} | set(kept.by_ref())
        to_open = [item for item in plan.schedule if not item.projected and item.deadline_status is None and item.obligation_ref not in persisted and self.store.get(COMPLIANCE_KIND, item.obligation_ref) is None]  # a projected payday is forecast, and opened once its pay run is approved
        version = None
        previous_plan = current_scoped_calendar_plan(self.store, self.bundle) if str(jurisdiction).upper() in ("AU", "CA") else previous
        changed = (plan.canada_calendar is not None or plan.australia_calendar is not None) and (previous_plan is None or calendar_content_digest(previous_plan) != calendar_content_digest(plan))
        if to_open or changed:
            # the plan is kept before anything is opened under it, so every obligation can always be read back under its own plan
            version = keep_calendar_plan(self.store, self.bundle, plan, as_of=stamp, opened=len(to_open))
            runtime = EngineRuntime(spec=COMPLIANCE_LIFECYCLE, engine=COMPLIANCE_KIND, plan=plan, store=self.store, advance=advance_obligation)
            for item in to_open:
                state = open_obligation(plan, self.bundle.engine_scope(item.obligation_ref), obligation_ref=item.obligation_ref, opened_at=stamp, actor_ref=self.bundle.actor_ref)
                runtime.open(item.obligation_ref, state)
                kept.bound.append((plan, state))
        # an open obligation whose period a corrected rule dates differently follows the correction, with a proof, before anything is judged overdue
        corrected, superseded = follow_corrected_rules(self.store, self.bundle, kept, plan, migrated_at=stamp, actor_ref=self.bundle.actor_ref)
        marked = mark_overdue(self.store, self.bundle, kept, now=stamp, actor_ref=self.bundle.actor_ref)
        summary = calendar_summary(plan, now=stamp, bound=kept.bound)
        flows = reservations(plan, now=stamp, bound=kept.bound)
        for row in kept.unbound:
            # never out of sight: an obligation no plan accepts is listed with its persisted status, and overdue by its own due date
            summary["open"].append({"obligation_ref": row["obligation_ref"], "kind": row.get("kind"), "due_at": row.get("due_at"), "status": row["status"], "amount": None, "basis": "unbound", "overdue": bool(row.get("due_at")) and row["status"] not in ("paid", "waived") and parsed(str(row["due_at"])) < parsed(stamp), "unbound": row["reason"]})
        versions = kept_versions(self.store)
        calendar = {"version": len(versions), "current_plan_digest": versions[-1]["plan_digest"] if versions else None, "opened_under": None if version is None else version["calendar_version"]}
        unbound_note = f"; {len(kept.unbound)} obligation(s) no plan accepts" if kept.unbound else ""
        assumed_note = f"; assumed {', '.join(f'{name} {plan.calendar_facts[name]}' for name in plan.assumed_facts)} (confirm them)" if plan.assumed_facts and plan.calendar_facts else ""
        return {**summary, "plan": plan.to_dict(), "flows": flows, "opened_now": len(to_open), "marked_overdue_now": marked, "adopted": adopted, "corrected": corrected, "superseded": superseded, "unbound": kept.unbound, "calendar": calendar, "rendered": _render_compliance(summary), "summary": f"{len(summary['open'])} obligation(s) open; {summary['reserved_from_reads']} reserved from reads, {summary['still_estimated']} still estimated, {summary['overdue']} overdue{unbound_note}{assumed_note}"}

    def _chain_sources(self) -> list[dict[str, Any]]:
        """Every persisted chain state with the plan it reads under: the bundle's, or for the calendar and the desk, the plan the console opened it under."""

        from lightbulb.company_chain_catalog import CONSOLE_PLAN_ENGINES, OPERATOR_CHAIN_MODULES, plan_for_chain, plan_for_state
        from lightbulb.company_engine_store import complete_engine_states
        from lightbulb.company_operator_surface import _scope
        from lightbulb.company_plan_migration import lifecycle_for
        out = []
        for engine in OPERATOR_CHAIN_MODULES:
            records = complete_engine_states(self.store, engine=engine)
            if not records:
                continue
            bundle_plan = None if engine in CONSOLE_PLAN_ENGINES else plan_for_chain(self.bundle, engine)
            for record in records:
                source_plan = bundle_plan if bundle_plan is not None else plan_for_state(self.bundle, self.store, engine, state=record["state"])
                _, state = lifecycle_for(engine).spec.bind(source_plan, record["state"])
                _scope(self.bundle, state)
                out.append({"engine": engine, "state": state.to_dict(), "source_plan": source_plan.to_dict()})
        return out

    def brief(self, *, now: str | None = None, forecast: Mapping[str, Any] | None = None, inbox: Sequence[Mapping[str, Any]] = (), decisions: Sequence[Mapping[str, Any]] = (), exceptions: Mapping[str, Any] | None = None, compliance: Mapping[str, Any] | None = None, explain_fields: Sequence[tuple[str, str, str]] = ()) -> dict[str, Any]:
        """The operator brief from the console's own documents: work items, the current period, and whatever else the caller has already obtained."""

        from lightbulb.company_brief import daily_brief
        from lightbulb.retention_chain import RETENTION_LIFECYCLE, retention_summary

        stamp = now or self.clock()
        periods = self._periods()
        latest = max(periods, key=lambda record: (str(dict(record["state"]).get("ledger", {}).get("period_start") or ""), int(dict(record["state"]).get("version") or 0)), default=None)
        explanations = []
        for engine, entity_ref, field in explain_fields:
            try:
                explanations.append(self.explain(engine, entity_ref, field))
            except (LookupError, ValueError):
                continue
        retention = None
        renewal_records = list(self.store.list(engine="retention_chain"))
        if renewal_records:
            states = []
            for record in renewal_records:
                try:
                    states.append(RETENTION_LIFECYCLE.State.model_validate(dict(record["state"])))
                except ValueError:
                    continue
            retention = retention_summary(states) if states else None
        document = daily_brief(company_ref=self.bundle.company_ref, now=stamp, work_items=self.work_items(now=stamp), inbox=inbox, decisions=decisions, forecast=forecast, exceptions=exceptions, compliance=compliance, explanations=explanations, period=dict(latest["state"]) if latest is not None else None, retention=retention, chain_sources=self._chain_sources())
        return {**document.to_dict(), "rendered": document.render(), "summary": document.headline}

    def intelligence_documents_for_month(self, month: str, *, now: str | None = None) -> dict[str, Any]:
        """The newer intelligence documents the bundle's plans allow, built now over the calendar month from the persisted chains, plus the open decision work items of the latest persisted ledger; a document whose plan the bundle lacks is left out."""

        from datetime import timedelta

        from lightbulb.company_engine_core import iso, parsed
        from lightbulb.company_operator_surface import build_break_even_document, build_customer_cohorts_document, build_returns_ledger_document, build_stockouts_document, build_working_capital_document, persisted_review_decisions

        stamp = now or self.clock()
        start = f"{month[:7]}-01T00:00:00Z"
        first = parsed(start)
        end = iso((first.replace(day=28) + timedelta(days=4)).replace(day=1))
        builders = {"working_capital": build_working_capital_document, "break_even": build_break_even_document, "customer_cohorts": build_customer_cohorts_document, "stockouts": build_stockouts_document, "returns_ledger": build_returns_ledger_document}
        documents: dict[str, Any] = {}
        from lightbulb.company_operator_surface import books_for_window

        books = books_for_window(self, start, end)
        if books is not None:
            documents["books_snapshot"] = books
            from lightbulb.company_operator_surface import build_tie_out_document

            try:
                built = build_tie_out_document(self, now=stamp, window_start=start, window_end=end)
                documents["ledger_tie_out"] = {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed", "documents_built"}}
            except LookupError:
                pass
        for kind, builder in builders.items():
            try:
                built = builder(self, now=stamp, window_start=start, window_end=end)
            except LookupError:
                continue
            documents[kind] = {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed", "documents_built"}}
        from lightbulb.company_operator_surface import build_intelligence_history_document

        try:
            documents["intelligence_history"] = {key: value for key, value in build_intelligence_history_document(self, now=stamp).items() if key not in {"summary", "provider_effect_executed", "gaps"}}
        except LookupError:
            pass
        ledgers = persisted_review_decisions(self)
        if ledgers:
            from lightbulb.decision_work_items import plan_decision_work_items

            documents["decision_work_items"] = plan_decision_work_items({key: value for key, value in ledgers[0].items() if key != "version"}, as_of=stamp).to_dict()
        return documents

    def board_pack(self, *, month: str, now: str | None = None, forecast: Mapping[str, Any] | None = None, exceptions: Mapping[str, Any] | None = None, decisions: Sequence[Mapping[str, Any]] = (), evals: Mapping[str, Any] | None = None, growth_review: Mapping[str, Any] | None = None, intelligence_review: Mapping[str, Any] | None = None, intelligence_documents: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """The month's board pack from the persisted periods, chains, and retention cases plus whatever the caller obtained; the newer intelligence documents are built for the month from the persisted chains unless supplied."""

        from lightbulb.company_brief import board_pack
        from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE
        from lightbulb.retention_chain import RETENTION_LIFECYCLE, retention_summary
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE

        stamp = now or self.clock()

        def states(engine: str, lifecycle: Any) -> list[Any]:
            out = []
            for record in self.store.list(engine=engine):
                try:
                    out.append(lifecycle.State.model_validate(dict(record["state"])))
                except ValueError:
                    continue
            return out

        renewals = states("retention_chain", RETENTION_LIFECYCLE)
        documents = self.intelligence_documents_for_month(month, now=stamp) if intelligence_documents is None else dict(intelligence_documents)
        pack = board_pack(company_ref=self.bundle.company_ref, month=month, prepared_at=stamp, periods=self._periods(), revenue_cases=states("revenue_chain", REVENUE_CHAIN_LIFECYCLE), payable_cases=states("payables_chain", PAYABLES_CHAIN_LIFECYCLE), retention=retention_summary(renewals) if renewals else None, forecast=forecast, exceptions=exceptions, decisions=decisions, evals=evals, chain_sources=self._chain_sources(), growth_review=growth_review, intelligence_review=intelligence_review, intelligence_documents=documents)
        return {**pack.to_dict(), "rendered": pack.render(), "summary": f"{month}: revenue {pack.revenue}, spend {pack.spend}, cash proven in {pack.revenue_cash_proven}, out {pack.payables_cash_proven}"}

    def evals(self, records: Sequence[Mapping[str, Any]], *, now: str | None = None, learn: bool = False) -> dict[str, Any]:
        """Score recorded recommendations against the periods that followed; optionally learn the errors into memory."""

        from lightbulb.company_evals import evaluate_recommendations, samples_for_memory, scenario_scorecard

        stamp = now or self.clock()
        card = evaluate_recommendations(self.bundle.operating_plan, self._periods(), records, company_ref=self.bundle.company_ref, scored_at=stamp)
        scenarios = scenario_scorecard(self.bundle.operating_plan.blueprint.archetype)
        learned = 0
        if learn:
            from lightbulb.company_operating_memory import MEMORY_KIND, MEMORY_LIFECYCLE, advance_memory, learn_command, memory_plan, memory_ref, open_memory

            samples = samples_for_memory(card)
            if samples:
                plan = memory_plan(self.bundle.operating_plan.blueprint.archetype, self.bundle.company_ref)
                runtime = EngineRuntime(spec=MEMORY_LIFECYCLE, engine=MEMORY_KIND, plan=plan, store=self.store, advance=advance_memory)
                ref = memory_ref(plan)
                if self.store.get(MEMORY_KIND, ref) is None:
                    runtime.open(ref, open_memory(plan, self.bundle.scope, opened_at=stamp))
                state = runtime.load(ref)
                fresh = [sample for sample in samples if sample["source_state_digest"] not in set(state.ledger.learned_state_digests)]
                if fresh:
                    outcome = runtime.advance_and_persist(ref, learn_command(plan, state, fresh, learned_at=stamp))
                    learned = len(fresh) if outcome.persisted else 0
        return {**card.to_dict(), "scenarios": scenarios.to_dict(), "learned_now": learned, "rendered": _render_evals(card.render(), scenarios.to_dict()), "summary": card.render().splitlines()[0] + f"; simulator {scenarios.passed}/{scenarios.passed + scenarios.failed} scenario(s) pass"}


CONSOLE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_console",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": list(CONSOLE_VERBS),
    "growth_period": "replay attributed revenue and persisted protected acquisition costs without posting money",
    "inference_cost": "reconcile a provider statement against metered cost; only a within-tolerance verdict yields register lines",
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every verb returns the sealed SDK object plus a summary; the MCP tools and the CLI wrap the same verbs",
        "ticks, supplied receipts, migrations, and memory go through the engines' own fences",
        "the console executes no read or write; the platform does",
    ],
}

def _chain_verb(name: str) -> Any:
    def method(self: CompanyConsole, **kwargs: Any) -> dict[str, Any]:
        return self.chain(name, **kwargs)
    method.__name__ = name
    method.__doc__ = f"Inspect or advance {name} through the scoped chain lifecycle."
    return method


for _verb in CHAIN_VERBS:
    setattr(CompanyConsole, _verb, _chain_verb(_verb))


def _replaying(method: Any) -> Any:
    @wraps(method)
    def verb(self: CompanyConsole, *args: Any, **kwargs: Any) -> Any:
        # every verb on one store shares the replays already made: a persisted state is replayed once per change, not once per verb
        with replaying_for(self.store):
            return method(self, *args, **kwargs)
    return verb


for _name, _member in list(vars(CompanyConsole).items()):
    if not _name.startswith("_") and inspect.isfunction(_member):
        setattr(CompanyConsole, _name, _replaying(_member))


__all__ = ["CONSOLE_MANIFEST", "CONSOLE_VERBS", "CompanyConsole"]
