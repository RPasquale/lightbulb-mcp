"""Operating cadence runner: the loop that makes a company run unattended.

Every engine so far advances only when a harness or a person calls it.  The
cadence runner wakes on a clock, reads the persisted engine states of one
company, works out the next legal moves for the current operating period,
applies the ones whose inputs are already in hand, and turns everything else
into typed work items: exactly what is missing, from which engine, and which
receipt would satisfy it.  It never invents an input.  A dispatch needs an
execution receipt from the platform; evidence needs a sealed observation;
reconciliation needs the finance close engine's verified-books proof; a
replan above the approval threshold needs a human decision through the
approval bridge.

The runner itself is a replay-fenced lifecycle (``running → paused → stopped``)
persisted in the same engine state store, so every tick is a sealed
transition whose receipt commits the tick result digest.  Two ticks with the
same persisted states, inputs, and clock produce the same plan.

Nothing here dispatches an agent, sends a message, posts a journal, or
spends money; Spring authorizes those through the receipts the runner asks
for.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore, InMemoryEngineStateStore, complete_engine_states
from lightbulb.company_execution_bridge import EngineApprovalRequest
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan, CompanySignal, advance_period, open_period
from lightbulb.company_signal_consumers import ConsumerApplied, SignalConsumption, apply_consumption, consume_signal
from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE, GrowthEngineLoopPlan, advance_campaign
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, advance_prospect
from lightbulb.saas_operating_loop import RELEASE_LIFECYCLE, SaasOperatingLoopPlan, advance_release
from lightbulb.company_workforce import WORKER_LIFECYCLE, WorkforcePlan, plan_dispatch
from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, FinanceCloseLoopPlan, open_period_close, verify_books
from lightbulb.service_delivery_engine import CASE_LIFECYCLE, ServiceDeliveryLoopPlan

CADENCE_GOLDEN_LOOP = "company.operating_cadence_unattended@0.1.0"
CADENCE_KIND = "company_cadence"
BUNDLE_SCHEMA = "lightbulb.company_cadence_bundle.v1"
TICK_PLAN_SCHEMA = "lightbulb.company_cadence_tick_plan.v1"
TICK_RESULT_SCHEMA = "lightbulb.company_cadence_tick_result.v1"
MAX_CADENCE_TRANSITIONS = 120
#: Once a wind-down is persisted for this company, ``CadenceWorker.control("stop")``
#: only accepts ``wind_down_chain.cadence_stop_receipt``'s reason: the cadence is
#: not stopped by an operator's sentence while the shutdown is still fenced.
WIND_DOWN_ENGINE = "wind_down_chain"
OPEN_PERIOD_STATUSES: frozenset[str] = frozenset({"planned", "dispatched", "evidenced", "reconciled", "replanned"})
CLOSE_NEXT_EVENT: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "opened": ("capture_trial_balance", ("trial_balance_ref", "debits", "credits")),
    "trial_balance_captured": ("reconcile_account", ("account_kind", "reconciliation_ref", "ledger_balance", "source_balance")),
    "reconciling": ("reconcile_account or resolve_exception or complete_reconciliation", ("account_kind", "reconciliation_ref", "exception_ref", "resolution_ref")),
    "reconciled": ("lock_subledgers", ("lock_ref",)),
    "adjusted": ("lock_subledgers", ("lock_ref",)),
    "locked": ("approve", ("approver_ref", "approval_ref")),
    "approved": ("close", ("close_ref",)),
    "reopened": ("reconcile_account", ("account_kind", "reconciliation_ref", "ledger_balance", "source_balance")),
}
ActionKind = Literal['open_period', 'dispatch_engine', 'collect_evidence', 'open_period_close', 'advance_close', 'reconcile_period', 'replan_period', 'close_period', 'activate_worker', 'case_overdue', 'approval_pending', 'advance_chain', 'run_payroll', 'assemble_disbursement', 'code_spend', 'reconcile_bank', 'triage_exception', 'advance_obligation', 'roster_people', 'approve_timesheets', 'run_pay', 'book_jobs', 'assign_jobs', 'advance_job', 'wind_down_step']
ActionMode = Literal["automatic", "needs_input", "needs_approval"]
CadenceStatus = Literal["running", "paused", "stopped"]
CADENCE_STATUSES: tuple[str, ...] = ("running", "paused", "stopped")
TERMINAL_CADENCE_STATUSES: frozenset[str] = frozenset({"stopped"})
CadenceEvent = Literal["start", "tick", "pause", "resume", "stop"]
CADENCE_EVENTS: tuple[str, ...] = ("start", "tick", "pause", "resume", "stop")
_CADENCE_TABLE: dict[tuple[str, str], str] = {
    ("new", "start"): "running",
    ("running", "tick"): "running",
    ("running", "pause"): "paused",
    ("running", "stop"): "stopped",
    ("paused", "resume"): "running",
    ("paused", "stop"): "stopped",
}


# --------------------------------------------------------------------------- #
# Bundle: everything one company runs on
# --------------------------------------------------------------------------- #


class CadenceBundle(StrictModel):
    """The plans one company runs on, plus the refs the runner uses to name its entities."""

    schema_id: str = Field(default=BUNDLE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    scope: dict[str, str]
    actor_ref: OpaqueRef
    operating_plan: CompanyOperatingPlan
    workforce_plan: WorkforcePlan | None = None
    finance_close_plan: FinanceCloseLoopPlan | None = None
    service_delivery_plan: ServiceDeliveryLoopPlan | None = None
    growth_plan: GrowthEngineLoopPlan | None = None
    pipeline_plan: PipelineEngineLoopPlan | None = None
    saas_plan: SaasOperatingLoopPlan | None = None
    people_plan: dict[str, Any] | None = None
    marketplace_supply_plan: dict[str, Any] | None = None
    engagement_plan: dict[str, Any] | None = None
    supporting_plans: dict[str, dict[str, Any]] = Field(default_factory=dict)
    require_cost_evidence: bool = False
    required_paper_kinds: tuple[ShortText, ...] = ()
    ledger_ref: OpaqueRef = "ledger"
    preparer_ref: OpaqueRef | None = None
    start_at: str
    bundle_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("start_at")
    @classmethod
    def _start(cls, value: str) -> str:
        return timestamp(value, field_name="start_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CadenceBundle:
        for key in ("tenant_ref", "company_ref", "project_ref", "project_id"):
            if key not in self.scope:
                raise ValueError(f"scope needs {key}")
        for key in ("entity_ref", "tenant_id", "company_id", "user_id"):
            if key in self.scope:
                raise ValueError(f"scope must not carry {key}")
        bp = self.operating_plan.blueprint
        for candidate in (self.growth_plan, self.pipeline_plan, self.saas_plan, self.service_delivery_plan):
            if candidate is not None and candidate.blueprint.currency != bp.currency:
                raise ValueError("ENGINE_CURRENCY_MISMATCH: every compiled engine must share the company currency")
        if self.workforce_plan is not None and self.workforce_plan.operating_plan_digest != self.operating_plan.plan_digest:
            raise ValueError("workforce plan belongs to a different operating plan")
        if "finance_close" in bp.engine_kinds and self.finance_close_plan is None:
            raise ValueError("this company runs the finance close engine; the bundle needs a finance close plan")
        if self.finance_close_plan is not None and self.finance_close_plan.blueprint.currency != bp.currency:
            raise ValueError("finance close plan currency must match the company")
        if self.finance_close_plan is not None and self.finance_close_plan.blueprint.period_days != bp.period_days:
            raise ValueError("finance close period must match the operating period")
        if not skip_digests(info) and self.bundle_digest != sealed_digest(CadenceBundle, self, "bundle_digest"):
            raise ValueError("bundle_digest must commit the exact bundle")
        return self

    def engine_scope(self, entity_ref: str) -> dict[str, str]:
        return {**self.scope, "entity_ref": entity_ref, "currency": self.operating_plan.blueprint.currency}

    @property
    def plan_digest(self) -> str:
        """The bundle is the cadence lifecycle's plan; its digest is the plan digest."""

        return self.bundle_digest


def build_bundle(bundle: CadenceBundle | Mapping[str, Any]) -> CadenceBundle:
    if isinstance(bundle, CadenceBundle):
        return bundle
    return seal(CadenceBundle, bundle, "bundle_digest")


def compile_company_bundle(archetype: str, *, company_ref: str, scope: Mapping[str, str], actor_ref: str, start_at: str, operating_overrides: Mapping[str, Any] | None = None) -> CadenceBundle:
    """Compile actual engine profiles together in the company's currency."""
    from lightbulb.company_operating_system import compile_company_operating_blueprint
    from lightbulb.company_workforce import compile_workforce, standard_roster
    from lightbulb.growth_engine_loop import compile_growth_engine_blueprint
    from lightbulb.pipeline_engine_loop import compile_pipeline_engine_blueprint
    from lightbulb.saas_operating_loop import compile_saas_operating_blueprint
    from lightbulb.finance_close_engine import compile_finance_close_blueprint
    from lightbulb.service_delivery_engine import compile_service_delivery_blueprint
    from lightbulb.people_engine import compile_people_engine
    from lightbulb.marketplace_supply_engine import compile_marketplace_supply_engine
    from lightbulb.revenue_chain import compile_revenue_chain
    from lightbulb.payables_chain import compile_payables_chain

    operating = compile_company_operating_blueprint(archetype, operating_overrides)
    bp = operating.blueprint
    values: dict[str, Any] = {"company_ref": company_ref, "scope": dict(scope), "actor_ref": actor_ref, "start_at": start_at, "operating_plan": operating, "workforce_plan": compile_workforce(operating, standard_roster(archetype))}
    factories = {"growth_engine": ("growth_plan", compile_growth_engine_blueprint), "pipeline_engine": ("pipeline_plan", compile_pipeline_engine_blueprint), "saas_operating_engine": ("saas_plan", compile_saas_operating_blueprint), "finance_close": ("finance_close_plan", compile_finance_close_blueprint), "service_delivery": ("service_delivery_plan", compile_service_delivery_blueprint)}
    for binding in bp.engines:
        if binding.engine in factories:
            field, compile_plan = factories[binding.engine]
            overrides: dict[str, Any] = {"currency": bp.currency}
            if binding.engine == "finance_close":
                overrides["period_days"] = bp.period_days
            if binding.engine in {"growth_engine", "pipeline_engine"}:
                overrides.update(require_permission_register=True, permission_company_ref=company_ref)
            if binding.engine == "growth_engine":
                overrides.update(claim_jurisdiction=bp.country, claim_product_ref=company_ref, require_demand_registry=True)
            if binding.engine == "service_delivery":
                overrides["company_ref"] = company_ref
            values[field] = compile_plan(binding.profile, overrides)
        elif binding.engine == "people_engine":
            values["people_plan"] = compile_people_engine(company_ref, operating_plan=operating, profile=binding.profile).to_dict()
        elif binding.engine == "marketplace_supply_engine":
            values["marketplace_supply_plan"] = compile_marketplace_supply_engine(company_ref, operating_plan=operating, profile=binding.profile).to_dict()
        elif binding.engine == "engagement_engine":
            from lightbulb.engagement_engine import compile_engagement_engine
            values["engagement_plan"] = compile_engagement_engine(company_ref, operating_plan=operating, profile=binding.profile).to_dict()
    return complete_company_bundle_plans(values)


def complete_company_bundle_plans(values: Mapping[str, Any]) -> CadenceBundle:
    """Bind shared supporting plans after the caller has finalized engine plans.

    Both archetype and planning-intake launch compilers use this boundary. Existing
    persisted bundles remain readable; newly compiled bundles require cost and paper
    evidence. This creates candidate plans only, never approvals or provider writes.
    """
    from lightbulb.people_engine import compile_people_engine
    from lightbulb.marketplace_supply_engine import compile_marketplace_supply_engine
    from lightbulb.engagement_engine import compile_engagement_engine
    from lightbulb.revenue_chain import compile_revenue_chain
    from lightbulb.payables_chain import compile_payables_chain

    values = dict(values)
    operating = CompanyOperatingPlan.model_validate(detached(values["operating_plan"]))
    bp = operating.blueprint
    company_ref = values["company_ref"]
    factories = {
        "people_engine": ("people_plan", compile_people_engine),
        "marketplace_supply_engine": ("marketplace_supply_plan", compile_marketplace_supply_engine),
        "engagement_engine": ("engagement_plan", compile_engagement_engine),
    }
    for binding in bp.engines:
        if binding.engine in factories:
            field, factory = factories[binding.engine]
            if values.get(field) is None:
                values[field] = factory(company_ref, operating_plan=operating, profile=binding.profile).to_dict()
    supporting = dict(values.get("supporting_plans", {}))
    supporting["revenue_chain"] = compile_revenue_chain(company_ref, currency=bp.currency,
        pipeline_plan=values.get("pipeline_plan"), overrides={"require_agreement_paper": True}).to_dict()
    supporting["payables_chain"] = compile_payables_chain(company_ref, currency=bp.currency,
        overrides={"require_vendor_paper": True}).to_dict()
    values["supporting_plans"] = supporting
    values["require_cost_evidence"] = True
    values["required_paper_kinds"] = tuple(dict.fromkeys(("business_registration", *values.get("required_paper_kinds", ()))))
    return build_bundle(values)


# --------------------------------------------------------------------------- #
# Tick plan: what is due, what is missing
# --------------------------------------------------------------------------- #


class CadenceAction(StrictModel):
    action_id: OpaqueRef
    kind: ActionKind
    mode: ActionMode
    engine: ShortText
    entity_ref: OpaqueRef
    event: ShortText | None = None
    summary: BoundedText
    required_receipt_fields: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    satisfied_by: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    prepared: dict[str, Any] = Field(default_factory=dict)
    due_at: str | None = None


class CadenceTickPlan(StrictModel):
    schema_id: str = Field(default=TICK_PLAN_SCHEMA, alias="schema")
    bundle_digest: Sha256Digest
    now: str
    period_ref: OpaqueRef | None = None
    period_status: str | None = None
    actions: tuple[CadenceAction, ...] = Field(default_factory=tuple, max_length=50000)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CadenceTickPlan:
        ids = [item.action_id for item in self.actions]
        if len(ids) != len(set(ids)):
            raise ValueError("action ids must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CadenceTickPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact tick plan")
        return self

    @property
    def automatic(self) -> tuple[CadenceAction, ...]:
        return tuple(item for item in self.actions if item.mode == "automatic")

    @property
    def work_items(self) -> tuple[CadenceAction, ...]:
        return tuple(item for item in self.actions if item.mode != "automatic")


def _period_ref(company_ref: str, index: int) -> str:
    return f"{company_ref}:period:{index:04d}"


def _close_ref(company_ref: str, index: int) -> str:
    return f"{company_ref}:close:{index:04d}"


def _period_index(entity_ref: str) -> int:
    return int(entity_ref.rsplit(":", 1)[-1])


def _returns_seen(period_state: Any) -> dict[str, Decimal]:
    spend, revenue = period_state.ledger.spend_by_engine, period_state.ledger.revenue_by_engine
    return {kind: (Decimal(str(revenue.get(kind, "0"))) / Decimal(str(spend[kind]))).quantize(Decimal("0.01")) for kind in spend if Decimal(str(spend[kind])) > 0}


def _replan_shifts(plan: CompanyOperatingPlan, returns: Mapping[str, Decimal]) -> tuple[dict[str, str], bool]:
    bp = plan.blueprint
    candidates = [kind for kind in bp.engine_kinds if kind in returns and kind in ("growth_engine", "pipeline_engine", "saas_operating_engine")]
    if len(candidates) < 2:
        return {}, False
    best = max(candidates, key=lambda kind: (returns[kind], kind))
    worst = min(candidates, key=lambda kind: (returns[kind], kind))
    if returns[best] == returns[worst]:
        return {}, False
    share_worst = bp.engine(worst).budget_share_percent  # type: ignore[union-attr]
    delta = min(bp.max_shift_percent_per_replan, share_worst - Decimal("5"), (returns[best] - returns[worst]) * Decimal("10")).quantize(Decimal("1"))
    if delta <= 0:
        return {}, False
    return {worst: str(-delta), best: str(delta)}, delta > bp.approval_threshold_percent


def plan_cadence_tick(bundle: CadenceBundle | Mapping[str, Any], states: Mapping[str, Sequence[Mapping[str, Any]]], *, now: str) -> CadenceTickPlan:
    """Pure planner: from persisted engine state records (by engine) and a clock, the next legal moves and the missing inputs."""

    parsed_bundle = build_bundle(bundle)
    now = timestamp(now, field_name="now")
    plan = parsed_bundle.operating_plan
    bp = plan.blueprint
    company = parsed_bundle.company_ref
    actions: list[CadenceAction] = []

    def act(kind: str, mode: str, engine: str, entity_ref: str, summary: str, *, event: str | None = None, fields: Sequence[str] = (), satisfied_by: Sequence[str] = (), prepared: Mapping[str, Any] | None = None, due_at: str | None = None, key: str | None = None) -> None:
        actions.append(CadenceAction(action_id=f"{kind}:{engine}:{entity_ref}" + (f":{event}" if event else "") + (f":{key}" if key else ""), kind=kind, mode=mode, engine=engine, entity_ref=entity_ref, event=event, summary=summary, required_receipt_fields=tuple(fields), satisfied_by=tuple(satisfied_by), prepared=dict(prepared or {}), due_at=due_at))

    periods = [PERIOD_LIFECYCLE.State.model_validate(dict(record["state"]), context={PERIOD_LIFECYCLE.plan_context_key: plan}) for record in states.get("company_operating_system", ())]
    periods.sort(key=lambda item: _period_index(item.scope.entity_ref))
    open_periods = [item for item in periods if item.status in OPEN_PERIOD_STATUSES]
    closes = {item.ledger.period_end: item for item in (CLOSE_LIFECYCLE.State.model_validate(dict(record["state"]), context={CLOSE_LIFECYCLE.plan_context_key: parsed_bundle.finance_close_plan}) for record in states.get("finance_close", ())) if parsed_bundle.finance_close_plan is not None}
    workers = {str(state.ledger.worker_ref): state for state in (WORKER_LIFECYCLE.State.model_validate(dict(record["state"]), context={WORKER_LIFECYCLE.plan_context_key: parsed_bundle.workforce_plan}) for record in states.get("company_workforce", ())) if parsed_bundle.workforce_plan is not None}
    from lightbulb.company_operator_surface import _scope
    for source in (*periods, *closes.values(), *workers.values()):
        _scope(parsed_bundle, source)

    period_ref = period_status = None
    if not open_periods:
        last = periods[-1] if periods else None
        next_index = (_period_index(last.scope.entity_ref) + 1) if last else 1
        start = last.ledger.period_end if last and last.ledger.period_end else parsed_bundle.start_at
        if parsed(str(start)) <= parsed(now):
            act("open_period", "automatic", "company_operating_system", _period_ref(company, next_index), f"Open operating period {next_index} starting {start}", event="open", prepared={"period_start": str(start)})
    else:
        current = open_periods[0]
        period_ref, period_status = current.scope.entity_ref, current.status
        ledger = current.ledger
        period_end = str(ledger.period_end)
        ended = parsed(period_end) <= parsed(now)
        if current.status in ("planned", "dispatched", "evidenced") and not ended:
            for envelope in plan.envelopes:
                if envelope.engine in ledger.dispatched_engines:
                    continue
                prepared: dict[str, Any] = {"engine": envelope.engine, "envelope_budget": str(envelope.budget), "dispatches_per_period": envelope.dispatches_per_period}
                worker = next((state for state in workers.values() if state.ledger.engine == envelope.engine), None)
                if worker is not None and parsed_bundle.workforce_plan is not None:
                    if worker.status == "active" and worker.ledger.open_dispatch_ref is None:
                        role = parsed_bundle.workforce_plan.worker(str(worker.ledger.worker_ref))
                        assert role is not None
                        try:
                            request = plan_dispatch(parsed_bundle.workforce_plan, worker, action=role.actions[0], message=f"Run {envelope.engine} for {period_ref}", period_ref=period_ref, estimated_cost=str(min(role.max_cost_per_dispatch, role.budget_per_period)))
                            prepared["dispatch_request"] = request.to_dict()
                        except ValueError as exc:
                            prepared["dispatch_blocked"] = str(exc)
                            if role.effect_class == "write_with_approval":
                                prepared["required_receipt_fields"] = ["authorization_proof"]
                                prepared["satisfied_by"] = ["authority_matrix.authorize", "company_execution_bridge.bind_approval"]
                    elif worker.status == "hired":
                        act("activate_worker", "needs_input", "company_workforce", str(worker.ledger.worker_ref), f"Activate {worker.ledger.worker_ref} before dispatching {envelope.engine}", event="activate")
                act("dispatch_engine", "needs_input", "company_operating_system", period_ref, f"Dispatch {envelope.engine} inside its {bp.currency} {envelope.budget} envelope; needs the platform dispatch receipt", event="dispatch", fields=("engine", "dispatch_refs"), satisfied_by=("execution_receipt:dispatch", "workforce.dispatch_receipt"), prepared=prepared, due_at=period_end, key=envelope.engine)
        if current.status in ("dispatched", "evidenced"):
            for engine in ledger.dispatched_engines:
                if engine not in ledger.spend_by_engine:
                    fields = ("engine", "evidence_ref", "spend", "revenue", "signals")
                    sources = ("observation:shopify.analytics_query", "observation:google_analytics.fetch_metrics", "observation:stripe.list_balance_transactions", "execution_receipt:read")
                    if parsed_bundle.require_cost_evidence:
                        fields += ("source_state", "source_plan", "source_kind", "source_digest", "source_digests", "revenue_only")
                        sources = ("company_cost_centres.period_evidence_receipt", "observation:host.company_cost_register")
                    act("collect_evidence", "needs_input", "company_operating_system", period_ref, f"Record {engine} evidence (spend, revenue, signals) from a sealed observation", event="record_evidence", fields=fields, satisfied_by=sources, due_at=period_end, key=engine, prepared={"engine": engine})
        if current.status == "evidenced" and all(kind in ledger.spend_by_engine for kind in bp.engine_kinds):
            close = closes.get(period_end)
            if "finance_close" not in bp.engine_kinds:
                act("reconcile_period", "needs_input", "company_operating_system", period_ref, "Reconcile the period against verified books", event="reconcile", fields=("reconciliation_ref", "books_verified"))
            elif close is None:
                if ended:
                    act("open_period_close", "automatic", "finance_close", _close_ref(company, _period_index(period_ref)), f"Open the finance close for the period ending {period_end}", event="open", prepared={"period_start": str(ledger.period_start), "period_end": period_end})
                else:
                    act("close_period", "needs_input", "finance_close", _close_ref(company, _period_index(period_ref)), f"The period ends {period_end}; the close opens then", due_at=period_end)
            elif close.status == "closed":
                verification = verify_books(parsed_bundle.finance_close_plan, close)
                if verification.verified:
                    act("reconcile_period", "automatic", "company_operating_system", period_ref, "Reconcile against the verified books proof", event="reconcile", prepared={"reconciliation_ref": f"books:{verification.verification_digest[:24]}", "books_verified": True, "close_state_digest": verification.close_state_digest})
                else:
                    act("advance_close", "needs_input", "finance_close", close.scope.entity_ref, "Books are closed but not verified: " + "; ".join(verification.reasons), fields=("exception_ref", "resolution_ref"))
            else:
                next_event, fields = CLOSE_NEXT_EVENT.get(close.status, ("close", ()))
                act("advance_close", "needs_input", "finance_close", close.scope.entity_ref, f"Finance close is {close.status}; next: {next_event}", event=next_event.split(" ")[0], fields=fields, satisfied_by=("finance.discover_trial_balance", "finance.evaluate_period_reconciliation", "execution_receipt:read"))
        if current.status == "reconciled":
            shifts, needs_approval = _replan_shifts(plan, _returns_seen(current))
            if shifts:
                prepared = {"shifts": [{"engine": kind, "delta_percent": delta} for kind, delta in sorted(shifts.items())]}
                if needs_approval:
                    from lightbulb.company_execution_bridge import engine_approval_request

                    command = PERIOD_LIFECYCLE.seal_command({"event": "replan", "transition_ref": f"replan:{period_ref}:{current.version}", "idempotency_key": f"replan:{period_ref}:{current.version}", "expected_version": current.version, "expected_state_digest": current.state_digest, "occurred_at": now, "actor_ref": parsed_bundle.actor_ref, "receipt": prepared})
                    rejected = advance_period(plan, current, command)
                    request = engine_approval_request(rejected, command, engine="company_operating_system", entity_ref=period_ref, plan_digest=plan.plan_digest, summary="Approve operating envelope reallocation", description="Review the exact budget-neutral shifts and bind the approved task through the authority matrix.", risk_level=6)
                    prepared["approval_request"] = request.to_platform_body()
                    prepared["proposed_command"] = command
                act("replan_period", "needs_approval" if needs_approval else "automatic", "company_operating_system", period_ref, "Shift budget toward the best-returning engine: " + ", ".join(f"{kind} {delta}%" for kind, delta in sorted(shifts.items())), event="replan", fields=("authorization_proof",) if needs_approval else (), satisfied_by=("authority_matrix.authorize", "company_execution_bridge.bind_approval") if needs_approval else (), prepared=prepared)
            elif ended:
                act("close_period", "automatic", "company_operating_system", period_ref, "No reallocation warranted; close the period", event="close")
        if current.status == "replanned" and ended:
            act("close_period", "automatic", "company_operating_system", period_ref, "Close the replanned period", event="close")
        if current.status == "replanned" and not ended:
            act("close_period", "needs_input", "company_operating_system", period_ref, f"Replanned; closes at {period_end}", due_at=period_end)
    if parsed_bundle.service_delivery_plan is not None:
        for record in states.get("service_delivery", ()):
            case = CASE_LIFECYCLE.State.model_validate(dict(record["state"]), context={CASE_LIFECYCLE.plan_context_key: parsed_bundle.service_delivery_plan})
            _scope(parsed_bundle, case)
            due = case.ledger.resolution_due
            if case.status in ("classified", "assigned", "escalated", "in_progress", "rejected") and due and parsed(str(due)) < parsed(now):
                act("case_overdue", "needs_input", "service_delivery", case.scope.entity_ref, f"Case {case.ledger.case_ref} ({case.ledger.severity}) passed its resolution window at {due}", due_at=str(due))
    from lightbulb.company_chain_catalog import OPERATOR_CHAIN_MODULES as CHAIN_MODULES, CHAIN_ACTION_KINDS, plan_for_chain, receipt_requirements
    from lightbulb.company_plan_migration import lifecycle_for
    for engine, module in CHAIN_MODULES.items():
        try:
            chain_plan = plan_for_chain(parsed_bundle, engine)
        except LookupError:
            continue
        lifecycle = lifecycle_for(engine)
        records = states.get(engine, ())
        if not records:
            event = lifecycle.spec.opening_event
            fields = ("open_entity_ref", *receipt_requirements(lifecycle.spec, event))[:24]
            act(CHAIN_ACTION_KINDS.get(engine, "advance_chain"), "needs_input", engine, f"{company}:{engine}:new", f"Open {engine} from its source artifacts; supply the source-derived entity reference", event=event, fields=fields, satisfied_by=(f"lightbulb.{module}",), prepared={"opening": True})
        for record in records:
            _, source = lifecycle.spec.bind(chain_plan, record["state"])
            if any(getattr(source.scope, key) != parsed_bundle.engine_scope(source.scope.entity_ref)[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")):
                raise ValueError("SCOPE_MISMATCH: cadence cannot plan a foreign chain")
            if source.status in lifecycle.spec.terminal:
                continue
            for (status, event), target in lifecycle.spec.table.items():
                if status != source.status or event in {"cancel", "abandon", "halt", "require_reconciliation"}:
                    continue
                fields = receipt_requirements(lifecycle.spec, event)
                if event in lifecycle.spec.reason_events:
                    fields = (*fields, "reason")[:24]
                act(CHAIN_ACTION_KINDS.get(engine, "advance_chain"), "needs_input", engine, source.scope.entity_ref, f"{engine} is {status}; {event} requires the event's sealed source receipt", event=event, fields=fields, satisfied_by=(f"lightbulb.{module}", "authority_matrix.authorize" if "authorization_proof" in fields else "company_observation_jobs"), prepared={"source_state_digest": source.state_digest})
    return seal(CadenceTickPlan, {"bundle_digest": parsed_bundle.bundle_digest, "now": now, "period_ref": period_ref, "period_status": period_status, "actions": tuple(actions)}, "plan_digest")


# --------------------------------------------------------------------------- #
# Tick execution
# --------------------------------------------------------------------------- #


class CadenceInput(StrictModel):
    """A supplied receipt for one work item: the fields the engine event needs, obtained outside the runner."""

    action_id: OpaqueRef
    receipt: dict[str, Any]
    source_digest: Sha256Digest | None = None
    reason: BoundedText | None = None


class AppliedAction(StrictModel):
    action_id: OpaqueRef
    engine: ShortText
    entity_ref: OpaqueRef
    event: ShortText
    outcome: Literal["applied", "rejected", "approval_requested"]
    to_status: str | None = None
    to_version: int | None = None
    rejection_code: str | None = None
    detail: BoundedText | None = None


class CadenceTickResult(StrictModel):
    schema_id: str = Field(default=TICK_RESULT_SCHEMA, alias="schema")
    tick_plan_digest: Sha256Digest
    now: str
    applied: tuple[AppliedAction, ...] = Field(default_factory=tuple, max_length=50000)
    outstanding: tuple[CadenceAction, ...] = Field(default_factory=tuple, max_length=50000)
    approvals_pending: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50000)
    result_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CadenceTickResult:
        if not skip_digests(info) and self.result_digest != sealed_digest(CadenceTickResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact tick result")
        return self


@dataclass
class CompanyCadenceRunner:
    """Applies tick plans against the store through per-engine runtimes."""

    bundle: CadenceBundle
    store: EngineStateStore
    approval_requester: Callable[[EngineApprovalRequest], Mapping[str, Any]] | None = None
    runtimes: dict[str, EngineRuntime] = field(default_factory=dict)
    _counter: int = 0

    def __post_init__(self) -> None:
        self.runtimes["company_operating_system"] = EngineRuntime(spec=PERIOD_LIFECYCLE, engine="company_operating_system", plan=self.bundle.operating_plan, store=self.store, advance=advance_period, approval_requester=self.approval_requester)
        if self.bundle.finance_close_plan is not None:
            from lightbulb.finance_close_engine import advance_period_close

            self.runtimes["finance_close"] = EngineRuntime(spec=CLOSE_LIFECYCLE, engine="finance_close", plan=self.bundle.finance_close_plan, store=self.store, advance=advance_period_close, approval_requester=self.approval_requester)
        if self.bundle.workforce_plan is not None:
            from lightbulb.company_workforce import advance_worker

            self.runtimes["company_workforce"] = EngineRuntime(spec=WORKER_LIFECYCLE, engine="company_workforce", plan=self.bundle.workforce_plan, store=self.store, advance=advance_worker, approval_requester=self.approval_requester)
        if self.bundle.growth_plan is not None:
            self.runtimes["growth_engine"] = EngineRuntime(spec=CAMPAIGN_LIFECYCLE, engine="growth_engine", plan=self.bundle.growth_plan, store=self.store, advance=advance_campaign, approval_requester=self.approval_requester)
        if self.bundle.pipeline_plan is not None:
            self.runtimes["pipeline_engine"] = EngineRuntime(spec=PROSPECT_LIFECYCLE, engine="pipeline_engine", plan=self.bundle.pipeline_plan, store=self.store, advance=advance_prospect, approval_requester=self.approval_requester)
        if self.bundle.saas_plan is not None:
            self.runtimes["saas_operating_engine"] = EngineRuntime(spec=RELEASE_LIFECYCLE, engine="saas_operating_engine", plan=self.bundle.saas_plan, store=self.store, advance=advance_release, approval_requester=self.approval_requester)
        from lightbulb.company_chain_catalog import OPERATOR_CHAIN_MODULES as CHAIN_MODULES, plan_for_chain
        from lightbulb.company_plan_migration import lifecycle_for
        for engine, module in CHAIN_MODULES.items():
            try:
                plan = plan_for_chain(self.bundle, engine)
            except LookupError:
                continue
            lifecycle = lifecycle_for(engine)
            from lightbulb.company_chain_catalog import chain_runtime
            self.runtimes[engine] = chain_runtime(self.bundle, engine, self.store, approval_requester=self.approval_requester)

    def states(self) -> dict[str, list[Mapping[str, Any]]]:
        return {engine: complete_engine_states(self.store, engine=engine) for engine in dict.fromkeys((*self.runtimes, "service_delivery"))}

    def consume(self, signal: CompanySignal | Mapping[str, Any], *, now: str) -> tuple[SignalConsumption, tuple[ConsumerApplied, ...]]:
        """Route a signal through the operating plan and apply the commands it justifies through the bound runtimes."""

        consumption = consume_signal(self.bundle.operating_plan, signal, states=self.states(), now=now)
        applied = apply_consumption(consumption, self.runtimes, now=now, actor_ref=self.bundle.actor_ref)
        return consumption, applied

    def plan(self, *, now: str) -> CadenceTickPlan:
        return plan_cadence_tick(self.bundle, self.states(), now=now)

    def _ref(self, action: CadenceAction, now: str) -> tuple[str, str]:
        self._counter += 1
        base = f"cadence:{action.action_id}:{now}:{self._counter}"
        return base, f"idem:{stable_digest({'action': action.action_id, 'now': now, 'n': self._counter})[:32]}"

    def _apply(self, action: CadenceAction, receipt: Mapping[str, Any], *, now: str, reason: str | None = None) -> AppliedAction:
        runtime = self.runtimes.get(action.engine)
        if runtime is None or action.event is None:
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event or "none", outcome="rejected", rejection_code="NO_RUNTIME", detail=f"no runtime for {action.engine}")
        if action.kind == "collect_evidence" and self.bundle.require_cost_evidence and not (receipt.get("source_state") and receipt.get("source_plan")):
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event, outcome="rejected", rejection_code="COST_SOURCE_REQUIRED", detail="compiled companies record money from a replayed cost register and its source plan")
        transition_ref, idempotency_key = self._ref(action, now)
        proposed = action.prepared.get("proposed_command")
        if receipt.get("authorization_proof"):
            from lightbulb.authority_matrix import AuthorizationProof
            proof = AuthorizationProof.model_validate(receipt["authorization_proof"])
            if proof.entity_ref != action.entity_ref or proof.event != action.event:
                raise ValueError("APPROVAL_BINDING_MISMATCH: the supplied proof belongs to another cadence action")
            proposed = proof.approved_command
        if isinstance(proposed, Mapping):
            transition_ref, idempotency_key = str(proposed["transition_ref"]), str(proposed["idempotency_key"])
            receipt = {**proposed["receipt"], **receipt}
        if action.prepared.get("opening"):
            from lightbulb.company_chain_catalog import opening_receipt
            fields = dict(receipt)
            ref = fields.pop("open_entity_ref", None)
            if ref is None:
                return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event, outcome="rejected", rejection_code="ENTITY_REF_MISSING", detail="opening requires the source-derived open_entity_ref")
            scope = self.bundle.engine_scope(ref)
            try:
                state = runtime.spec.open(runtime.plan, scope, receipt=opening_receipt(runtime.spec, scope, fields), opened_at=now, actor_ref=self.bundle.actor_ref)
                runtime.open(ref, state)
            except (ValueError, RuntimeError) as exc:
                return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=ref, event=action.event, outcome="rejected", rejection_code=getattr(exc, "code", "OPENING_REFUSED"), detail=str(exc)[:900])
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=ref, event=action.event, outcome="applied", to_status=state.status, to_version=state.version)
        if action.event == "open" and action.engine in {"company_operating_system", "finance_close"}:
            if action.engine == "company_operating_system":
                state = open_period(self.bundle.operating_plan, self.bundle.engine_scope(action.entity_ref), period_start=str(receipt["period_start"]), opened_at=now, actor_ref=self.bundle.actor_ref)
            else:
                assert self.bundle.finance_close_plan is not None
                state = open_period_close(self.bundle.finance_close_plan, self.bundle.engine_scope(action.entity_ref), period_start=str(receipt["period_start"]), period_end=str(receipt["period_end"]), ledger_ref=self.bundle.ledger_ref, preparer_ref=self.bundle.preparer_ref or self.bundle.actor_ref, opened_at=now, actor_ref=self.bundle.actor_ref)
            runtime.open(action.entity_ref, state)
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event="open", outcome="applied", to_status=state.status, to_version=state.version)
        state = runtime.load(action.entity_ref)
        command = runtime.command(state, event=action.event, transition_ref=transition_ref, idempotency_key=idempotency_key, occurred_at=now, actor_ref=self.bundle.actor_ref, receipt=receipt, reason=reason)
        outcome = runtime.advance_and_persist(action.entity_ref, command, summary=action.summary, description=action.summary)
        if outcome.persisted:
            assert outcome.record is not None
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event, outcome="applied", to_status=str(outcome.record["status"]), to_version=int(outcome.record["version"]))
        if outcome.awaiting_approval:
            return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event, outcome="approval_requested", detail=str(outcome.result.receipt.recovery.instructions))
        return AppliedAction(action_id=action.action_id, engine=action.engine, entity_ref=action.entity_ref, event=action.event, outcome="rejected", rejection_code=outcome.result.receipt.rejection_code, detail=str(outcome.result.receipt.recovery.instructions))

    def tick(self, *, now: str, inputs: Sequence[CadenceInput | Mapping[str, Any]] = ()) -> CadenceTickResult:
        """One pass: apply automatic actions and any work item whose input was supplied; report the rest."""

        now = timestamp(now, field_name="now")
        supplied = {item.action_id: item for item in (CadenceInput.model_validate(dict(detached(raw))) for raw in inputs)}
        plan = self.plan(now=now)
        applied: list[AppliedAction] = []
        outstanding: list[CadenceAction] = []
        for action in plan.actions:
            if action.mode == "automatic":
                applied.append(self._apply(action, action.prepared, now=now))
            elif action.action_id in supplied:
                given = supplied[action.action_id]
                receipt = {**{key: value for key, value in action.prepared.items() if key in ("shifts",)}, **given.receipt}
                applied.append(self._apply(action, receipt, now=now, reason=given.reason))
            else:
                outstanding.append(action)
        pending = tuple(sorted({ref for runtime in self.runtimes.values() for ref in runtime.pending}))
        return seal(CadenceTickResult, {"tick_plan_digest": plan.plan_digest, "now": now, "applied": tuple(applied), "outstanding": tuple(outstanding), "approvals_pending": pending}, "result_digest")


# --------------------------------------------------------------------------- #
# The cadence itself as a replay-fenced lifecycle
# --------------------------------------------------------------------------- #


class CadenceReceipt(StrictModel):
    bundle_digest: Sha256Digest | None = None
    tick_result_digest: Sha256Digest | None = None
    tick_plan_digest: Sha256Digest | None = None
    applied: int | None = Field(default=None, ge=0)
    outstanding: int | None = Field(default=None, ge=0)
    approvals_pending: int | None = Field(default=None, ge=0)
    period_ref: OpaqueRef | None = None


class CadenceLedger(StrictModel):
    bundle_digest: str | None = None
    ticks: int = Field(default=0, ge=0)
    last_tick_at: str | None = None
    last_tick_result_digest: str | None = None
    last_period_ref: str | None = None
    applied_total: int = Field(default=0, ge=0)
    outstanding_last: int = Field(default=0, ge=0)
    approvals_pending_last: int = Field(default=0, ge=0)
    pause_reason: str | None = None
    stop_reason: str | None = None
    outcome: Literal["running", "paused", "stopped"] = "running"


class CadenceEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    agent_dispatched: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_cadence(plan: CadenceBundle, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event = command.receipt, command.event
    if event == "start":
        require(r.bundle_digest == plan.bundle_digest, "BUNDLE_MISMATCH", "the cadence starts against this exact bundle")
        data.update({"bundle_digest": r.bundle_digest})
    elif event == "tick":
        require(r.tick_result_digest is not None and r.tick_plan_digest is not None and r.applied is not None and r.outstanding is not None, "TICK_RECEIPT_MISSING", "a tick records its plan and result digests and counts")
        last = data.get("last_tick_at")
        require(last is None or parsed(command.occurred_at) >= parsed(str(last)), "TICK_NOT_LATER", "ticks advance the clock")
        data.update({"ticks": int(data.get("ticks", 0)) + 1, "last_tick_at": command.occurred_at, "last_tick_result_digest": r.tick_result_digest, "last_period_ref": r.period_ref, "applied_total": int(data.get("applied_total", 0)) + int(r.applied or 0), "outstanding_last": int(r.outstanding or 0), "approvals_pending_last": int(r.approvals_pending or 0)})
    elif event == "pause":
        data.update({"pause_reason": command.reason, "outcome": "paused"})
    elif event == "resume":
        data.update({"pause_reason": None, "outcome": "running"})
    elif event == "stop":
        data.update({"stop_reason": command.reason, "outcome": "stopped"})
    return next_status, data


CADENCE_LIFECYCLE = LifecycleSpec(entity="cadence", schema_prefix="company_cadence", statuses=CADENCE_STATUSES, terminal=TERMINAL_CADENCE_STATUSES, events=CADENCE_EVENTS, table=_CADENCE_TABLE, opening_event="start", reason_events=("pause", "stop"), apply=_apply_cadence, ledger_model=CadenceLedger, receipt_model=CadenceReceipt, effect_boundary_model=CadenceEffectBoundary, plan_model=CadenceBundle, max_transitions=MAX_CADENCE_TRANSITIONS)
CadenceCommand = CADENCE_LIFECYCLE.Command
CadenceState = CADENCE_LIFECYCLE.State
CadenceTransitionResult = CADENCE_LIFECYCLE.TransitionResult
seal_cadence_command = CADENCE_LIFECYCLE.seal_command


def start_cadence(bundle: CadenceBundle | Mapping[str, Any], *, started_at: str) -> Any:
    parsed_bundle = build_bundle(bundle)
    return CADENCE_LIFECYCLE.open(parsed_bundle, parsed_bundle.engine_scope(f"{parsed_bundle.company_ref}:cadence"), opened_at=started_at, actor_ref=parsed_bundle.actor_ref, receipt={"bundle_digest": parsed_bundle.bundle_digest})


def advance_cadence(bundle: CadenceBundle | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CADENCE_LIFECYCLE.advance(bundle, state, command)


@dataclass
class CadenceWorker:
    """Durable loop: load the cadence state, tick, record the tick as a fenced transition."""

    runner: CompanyCadenceRunner
    clock: Callable[[], str]
    inputs: Callable[[CadenceTickPlan], Sequence[CadenceInput | Mapping[str, Any]]] | None = None
    _counter: int = 0

    @property
    def cadence_ref(self) -> str:
        return f"{self.runner.bundle.company_ref}:cadence"

    def _runtime(self) -> EngineRuntime:
        return EngineRuntime(spec=CADENCE_LIFECYCLE, engine=CADENCE_KIND, plan=self.runner.bundle, store=self.runner.store, advance=advance_cadence)

    def start(self) -> Any:
        state = start_cadence(self.runner.bundle, started_at=self.clock())
        self._runtime().open(self.cadence_ref, state)
        return state

    def run_once(self) -> CadenceTickResult | None:
        runtime = self._runtime()
        state = runtime.load(self.cadence_ref)
        if state.status != "running":
            return None
        now = self.clock()
        plan = self.runner.plan(now=now)
        supplied = self.inputs(plan) if self.inputs is not None else ()
        result = self.runner.tick(now=now, inputs=supplied)
        self._counter += 1
        command = runtime.command(state, event="tick", transition_ref=f"tick:{now}:{self._counter}", idempotency_key=f"tick:{result.result_digest[:32]}", occurred_at=now, actor_ref=self.runner.bundle.actor_ref, receipt={"tick_result_digest": result.result_digest, "tick_plan_digest": result.tick_plan_digest, "applied": len(result.applied), "outstanding": len(result.outstanding), "approvals_pending": len(result.approvals_pending), "period_ref": plan.period_ref})
        outcome = runtime.advance_and_persist(self.cadence_ref, command)
        if not outcome.persisted:
            raise RuntimeError(f"cadence tick could not be recorded: {outcome.result.receipt.rejection_code}")
        return result

    def _wind_down_stop_reasons(self) -> tuple[list[str], int]:
        """The stop reasons the persisted wind-downs would accept, and how many wind-downs exist.

        Imported lazily: ``wind_down_chain`` reads ``CADENCE_LIFECYCLE`` from
        this module, so the only source of truth for the reason format stays
        :func:`lightbulb.wind_down_chain.cadence_stop_receipt`.
        """

        from lightbulb.wind_down_chain import WindDownError, cadence_stop_receipt

        rows = complete_engine_states(self.runner.store, engine=WIND_DOWN_ENGINE)
        reasons: list[str] = []
        for row in rows:
            try:
                reasons.append(cadence_stop_receipt(dict(row)["state"]))
            except (WindDownError, ValueError, KeyError):
                continue
        return reasons, len(rows)

    def control(self, event: Literal["pause", "resume", "stop"], *, reason: str | None = None) -> Any:
        if event == "stop":
            accepted, winding = self._wind_down_stop_reasons()
            if winding and reason not in accepted:
                raise RuntimeError(f"cadence stop refused: {winding} wind-down(s) hold this company; the only accepted reason is wind_down_chain.cadence_stop_receipt of a wind-down whose final pay run is done")
        runtime = self._runtime()
        state = runtime.load(self.cadence_ref)
        now = self.clock()
        self._counter += 1
        command = runtime.command(state, event=event, transition_ref=f"{event}:{now}:{self._counter}", idempotency_key=f"{event}:{now}:{self._counter}", occurred_at=now, actor_ref=self.runner.bundle.actor_ref, reason=reason)
        outcome = runtime.advance_and_persist(self.cadence_ref, command)
        if not outcome.persisted:
            raise RuntimeError(f"cadence {event} refused: {outcome.result.receipt.rejection_code}")
        return outcome.result.state


CADENCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": CADENCE_KIND,
    "golden_loop": CADENCE_GOLDEN_LOOP,
    "stages": ["wake", "read_states", "plan_tick", "apply_automatic", "raise_work_items", "route_approvals", "record_tick"],
    "action_kinds": ["open_period", "dispatch_engine", "collect_evidence", "open_period_close", "advance_close", "reconcile_period", "replan_period", "close_period", "activate_worker", "case_overdue", "approval_pending", "advance_chain", "run_payroll", "assemble_disbursement", "code_spend", "reconcile_bank", "triage_exception", "advance_obligation"],
    "cadence_statuses": list(CADENCE_STATUSES),
    "cadence_events": list(CADENCE_EVENTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": ["the runner never invents an input: dispatches need execution receipts, evidence needs sealed observations, reconciliation needs the verified-books proof", "automatic actions are only the ones whose inputs the engines already hold", "replans above the approval threshold wait for a bound human decision", "every tick is a fenced transition committing its plan and result digests"],
}

__all__ = [
    "CADENCE_EVENTS",
    "CADENCE_GOLDEN_LOOP",
    "CADENCE_KIND",
    "CADENCE_LIFECYCLE",
    "CADENCE_MANIFEST",
    "CADENCE_STATUSES",
    "OPEN_PERIOD_STATUSES",
    "WIND_DOWN_ENGINE",
    "AppliedAction",
    "CadenceAction",
    "CadenceBundle",
    "CadenceCommand",
    "CadenceInput",
    "CadenceLedger",
    "CadenceReceipt",
    "CadenceState",
    "CadenceTickPlan",
    "CadenceTickResult",
    "CadenceTransitionResult",
    "CadenceWorker",
    "CompanyCadenceRunner",
    "InMemoryEngineStateStore",
    "advance_cadence",
    "build_bundle",
    "compile_company_bundle",
    "plan_cadence_tick",
    "seal_cadence_command",
    "start_cadence",
]
