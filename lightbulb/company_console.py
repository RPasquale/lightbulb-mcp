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

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from lightbulb.company_cadence_runner import CadenceBundle, CadenceWorker, CompanyCadenceRunner, build_bundle
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_chain_catalog import CHAIN_VERBS

CONSOLE_VERBS: tuple[str, ...] = ("tick", "work_items", "supply", "explain", "decide", "simulate", "migrate_preview", "portfolio", "treasury", "readiness", "bring_up", "memory", "grades", "chaos", "exceptions", "compliance", "brief", "board_pack", "evals", "settle_dispatch", "inference_cost", "growth_period", "content_library")
CONSOLE_VERBS += tuple(CHAIN_VERBS)


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
        return {"schema": plan.schema_id, "period_ref": plan.period_ref, "period_status": plan.period_status, "automatic": [item.to_dict() for item in plan.automatic], "work_items": [item.to_dict() for item in plan.work_items], "plan_digest": plan.plan_digest, "summary": f"{len(plan.automatic)} automatic action(s), {len(plan.work_items)} work item(s) on {plan.period_ref or 'no period'} ({plan.period_status or 'none'})"}

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
        result = worker.run_once()
        if result is None:
            return {"summary": "cadence is not running; resume it first", "recorded": False}
        return {**result.to_dict(), "recorded": True, "summary": f"tick recorded: {len(result.applied)} applied, {len(result.outstanding)} outstanding"}

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

    def treasury(self, position: Mapping[str, Any], *, horizon_weeks: int = 13, flows: Sequence[Mapping[str, Any]] = (), payroll: Mapping[str, Any] | None = None, fixed_costs: Mapping[str, Any] | None = None, floor: Any = "0", period_starts: Sequence[str] = (), now: str | None = None, inference_cost_registers: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        from lightbulb.company_treasury import CashPosition, forecast_cash, render_forecast

        forecast = forecast_cash(CashPosition.model_validate(dict(position)), as_of=now or self.clock(), horizon_weeks=horizon_weeks, flows=flows, operating_plan=self.bundle.operating_plan, payroll=payroll, fixed_costs=fixed_costs, floor=floor, period_starts=period_starts, inference_cost_registers=inference_cost_registers)
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

    def _engine_states(self, engine: str, plan: Any, lifecycle: Any) -> list[Any]:
        out = []
        for record in self.store.list(engine=engine):
            try:
                out.append(lifecycle.State.model_validate(dict(record["state"]), context={lifecycle.plan_context_key: plan}))
            except ValueError:
                continue
        return out

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
        for engine, module_name, plan_attr in (("revenue_chain", "lightbulb.revenue_chain", "REVENUE_CHAIN_LIFECYCLE"), ("payables_chain", "lightbulb.payables_chain", "PAYABLES_CHAIN_LIFECYCLE")):
            for record in self.store.list(engine=engine):
                state = dict(record["state"])
                if state.get("status") == "reconciliation_required":
                    openings.append({"kind": "chain_reconciliation", "source_engine": engine, "source_ref": f"{engine}:{state['scope']['entity_ref']}", "source_digest": str(state["state_digest"]), "code": "RECONCILIATION_REQUIRED", "detail": str(dict(state.get("ledger") or {}).get("reconciliation_reason") or "reconciliation required")[:900], "evidence_refs": [f"{engine}:{state['scope']['entity_ref']}:{str(state['state_digest'])[:16]}"]})
        for record in self.store.list(engine="compliance_obligation"):
            state = dict(record["state"])
            if state.get("status") == "overdue":
                ledger = dict(state.get("ledger") or {})
                openings.append({"kind": "overdue_obligation", "source_engine": "compliance_obligation", "source_ref": f"compliance_obligation:{state['scope']['entity_ref']}", "source_digest": str(state["state_digest"]), "code": "OBLIGATION_OVERDUE", "detail": f"{ledger.get('kind')} due {ledger.get('due_at')} is {ledger.get('days_late')} day(s) late", "evidence_refs": [f"obligation:{state['scope']['entity_ref']}"]})
        opened = 0
        for opening in openings:
            ref = exception_ref(str(opening["kind"]), str(opening["source_ref"]), str(opening["source_digest"]))
            if self.store.get(EXCEPTIONS_KIND, ref) is None:
                runtime.open(ref, open_exception(plan, self.bundle.engine_scope(ref), receipt=opening, opened_at=stamp, actor_ref=self.bundle.actor_ref))
                opened += 1
        states = self._engine_states(EXCEPTIONS_KIND, plan, EXCEPTIONS_LIFECYCLE)
        summary = desk_summary(plan, states, now=stamp)
        return {**summary, "opened_now": opened, "summary": f"{summary['open']} open exception(s), {summary['past_sla']} past SLA; {opened} opened now"}

    def compliance(self, *, jurisdiction: str, now: str | None = None, horizon_months: int = 12, estimated_revenue_per_month: Any = "0", estimated_payroll_per_month: Any = "0", has_payroll: bool = True, registered_for_gst: bool = True) -> dict[str, Any]:
        """Compile the calendar, open every obligation not yet persisted, and summarise what is due; the treasury flows it produces are returned for the forecast."""

        from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE, advance_obligation, calendar_summary, compile_compliance_calendar, open_obligation, reservations

        stamp = now or self.clock()
        currency = self.bundle.operating_plan.blueprint.currency
        plan = compile_compliance_calendar(self.bundle.company_ref, jurisdiction=jurisdiction, currency=currency, start_at=stamp, horizon_months=horizon_months, estimated_revenue_per_month=estimated_revenue_per_month, estimated_payroll_per_month=estimated_payroll_per_month, has_payroll=has_payroll, registered_for_gst=registered_for_gst)
        runtime = EngineRuntime(spec=COMPLIANCE_LIFECYCLE, engine=COMPLIANCE_KIND, plan=plan, store=self.store, advance=advance_obligation)
        opened = 0
        for item in plan.schedule:
            if self.store.get(COMPLIANCE_KIND, item.obligation_ref) is None:
                runtime.open(item.obligation_ref, open_obligation(plan, self.bundle.engine_scope(item.obligation_ref), obligation_ref=item.obligation_ref, opened_at=stamp, actor_ref=self.bundle.actor_ref))
                opened += 1
        states = self._engine_states(COMPLIANCE_KIND, plan, COMPLIANCE_LIFECYCLE)
        summary = calendar_summary(plan, states, now=stamp)
        flows = reservations(plan, states, now=stamp)
        return {**summary, "plan": plan.to_dict(), "flows": flows, "opened_now": opened, "summary": f"{len(summary['open'])} obligation(s) open; {summary['reserved_from_reads']} reserved from reads, {summary['still_estimated']} still estimated, {summary['overdue']} overdue"}

    def _chain_sources(self) -> list[dict[str, Any]]:
        from lightbulb.company_chain_catalog import OPERATOR_CHAIN_MODULES, plan_for_chain
        from lightbulb.company_operator_surface import _scope
        from lightbulb.company_plan_migration import lifecycle_for
        out = []
        for engine in OPERATOR_CHAIN_MODULES:
            records = list(self.store.list(engine=engine, limit=200))
            if not records:
                continue
            source_plan = plan_for_chain(self.bundle, engine)
            for record in records:
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

    def board_pack(self, *, month: str, now: str | None = None, forecast: Mapping[str, Any] | None = None, exceptions: Mapping[str, Any] | None = None, decisions: Sequence[Mapping[str, Any]] = (), evals: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """The month's board pack from the persisted periods, chains, and retention cases plus whatever the caller obtained."""

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
        pack = board_pack(company_ref=self.bundle.company_ref, month=month, prepared_at=stamp, periods=self._periods(), revenue_cases=states("revenue_chain", REVENUE_CHAIN_LIFECYCLE), payable_cases=states("payables_chain", PAYABLES_CHAIN_LIFECYCLE), retention=retention_summary(renewals) if renewals else None, forecast=forecast, exceptions=exceptions, decisions=decisions, evals=evals, chain_sources=self._chain_sources())
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
        return {**card.to_dict(), "scenarios": scenarios.to_dict(), "learned_now": learned, "summary": card.render().splitlines()[0] + f"; simulator {scenarios.passed}/{scenarios.passed + scenarios.failed} scenario(s) pass"}


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


__all__ = ["CONSOLE_MANIFEST", "CONSOLE_VERBS", "CompanyConsole"]
