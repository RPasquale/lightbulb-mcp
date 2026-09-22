"""Reviewable chain operations over the existing scoped store and approval bridge.

Commands never execute a provider effect. They consume retained observations,
governed execution receipts and human authority proofs through real lifecycles.
"""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from lightbulb.company_chain_catalog import OPERATOR_CHAIN_MODULES as CHAIN_MODULES, CHAIN_VERBS, opening_receipt, plan_for_chain, receipt_requirements
from lightbulb.company_engine_core import detached, parsed, stable_digest, timestamp
from lightbulb.company_engine_store import EngineRuntime


def _scope(bundle: Any, state: Any) -> None:
    scope = state.scope.to_dict()
    expected = bundle.engine_scope(scope["entity_ref"])
    if any(scope.get(key) != expected.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")):
        raise ValueError("SCOPE_MISMATCH: the chain is outside this company's authenticated execution scope")


@dataclass
class CompanyOperatorSurface:
    console: Any

    def runtime(self, engine: str) -> EngineRuntime:
        from lightbulb.company_plan_migration import lifecycle_for
        lifecycle = lifecycle_for(engine)
        plan = plan_for_chain(self.console.bundle, engine)
        from lightbulb.company_chain_catalog import chain_runtime
        return chain_runtime(self.console.bundle, engine, self.console.store, approval_requester=self.console.approval_requester)

    def supply(self, engine: str, entity_ref: str, *, event: str, receipt: Mapping[str, Any], now: str | None = None, command: Mapping[str, Any] | None = None, approval_binding: Any = None, authorization_proof: Any = None, reason: str | None = None) -> dict[str, Any]:
        runtime = self.runtime(engine)
        at = timestamp(now or self.console.clock(), field_name="now")
        state = runtime.load(entity_ref)
        _scope(self.console.bundle, state)
        fields = dict(detached(receipt))
        proof = authorization_proof or fields.get("authorization_proof")
        if proof is not None:
            from lightbulb.authority_matrix import AuthorizationProof
            verified = AuthorizationProof.model_validate(detached(proof))
            if approval_binding is not None and verified.source_binding.to_dict() != detached(approval_binding):
                raise ValueError("APPROVAL_BINDING_MISMATCH: the proof must retain this exact platform decision")
            original = verified.approved_command
            if original["event"] != event or verified.entity_ref != entity_ref or verified.engine != CHAIN_MODULES.get(engine, engine):
                raise ValueError("APPROVAL_BINDING_MISMATCH: the proof belongs to another chain operation")
            if command is not None and dict(detached(command)) != original:
                raise ValueError("APPROVAL_BINDING_MISMATCH: the supplied command differs from the human-reviewed command")
            command = original
            fields = {**original["receipt"], **fields, "authorization_proof": verified.to_dict()}
        elif approval_binding is not None:
            raise ValueError("APPROVAL_NOT_BOUND: monetary transitions require the matrix proof derived from this platform binding")
        if command is not None:
            payload = {**detached(command), "occurred_at": at, "receipt": fields}
            if payload["event"] != event:
                raise ValueError("EVENT_MISMATCH: the command must name the requested event")
            sealed = runtime.spec.seal_command(payload)
        else:
            key = stable_digest({"engine": engine, "entity_ref": entity_ref, "event": event, "state_digest": state.state_digest, "receipt": fields, "reason": reason})
            sealed = runtime.command(state, event=event, transition_ref=f"operator:{key}", idempotency_key=f"operator:{key}", occurred_at=at, actor_ref=self.console.bundle.actor_ref, receipt=fields, reason=reason)
        result = runtime.advance_and_persist(entity_ref, sealed)
        return {"schema": "lightbulb.company_chain_operation.v1", "engine": engine, "entity_ref": entity_ref, "event": event, "persisted": result.persisted, "result": result.result.to_dict(), "approval_request": result.approval_request.to_dict() if result.approval_request else None, "command": detached(sealed), "provider_effect_executed": False}


def record_inference_bill(console: Any, register_ref: str, *, bill: Mapping[str, Any], now: str) -> dict[str, Any]:
    """Accrue every allocation through the protected register's actual runtime.

    Replay and preflight the entire batch before writing. The host store fences
    each transition; interrupted batches are retried against their retained
    source identities, never as a second bill or a cash movement.
    """
    from lightbulb.inference_cost_register import verify_register
    from lightbulb.company_cost_centres import inference_cost_receipt
    source = verify_register(bill)
    runtime = CompanyOperatorSurface(console).runtime("company_cost_centres")
    current = runtime.load(register_ref)
    _scope(console.bundle, current)
    receipts = [inference_cost_receipt(source, source_plan=runtime.plan, centre_ref=centre)
                for centre in sorted({line.cost_centre_ref for line in source.lines})]
    commands, candidate, already = [], current, []
    retained = {row.source_ref: row for row in current.ledger.sources}
    for receipt in receipts:
        prior = retained.get(receipt["source_ref"])
        if prior is not None:
            if prior.source_digest != receipt["source_digest"] or str(prior.inference_register_digest) != source.register_digest:
                raise ValueError("BILL_VERSION_CONFLICT: a different version of this bill has already been recorded")
            already.append(receipt["centre_ref"])
            continue
        key = "inference:" + stable_digest({"register": register_ref, "bill": source.register_digest, "centre": receipt["centre_ref"]})
        command = runtime.command(candidate, event="record_source", transition_ref=key, idempotency_key=key,
            occurred_at=now, actor_ref=console.bundle.actor_ref, receipt=receipt)
        result = runtime.spec.advance(runtime.plan, candidate, command)
        if not result.candidate_validated:
            return {"complete": False, "persisted": False, "already_recorded": already,
                "recorded": [], "rejection_code": result.receipt.rejection_code,
                "register_ref": register_ref, "bill_digest": source.register_digest, "provider_effect_executed": False}
        candidate = result.state
        commands.append((receipt["centre_ref"], command))
    recorded = []
    for centre, command in commands:
        result = runtime.advance_and_persist(register_ref, command)
        if not result.persisted:
            return {"complete": False, "persisted": bool(recorded), "already_recorded": already,
                "recorded": recorded, "rejection_code": result.result.receipt.rejection_code,
                "register_ref": register_ref, "bill_digest": source.register_digest, "provider_effect_executed": False}
        recorded.append(centre)
    return {"complete": True, "persisted": bool(recorded), "already_recorded": already,
        "recorded": recorded, "register_ref": register_ref, "bill_digest": source.register_digest,
        "state_digest": runtime.load(register_ref).state_digest, "provider_effect_executed": False}


def open_claimed_campaign(console: Any, registry_ref: str, *, campaign_ref: str,
                          envelope_ref: str, budget: Any, now: str) -> dict[str, Any]:
    """Persist the shared reservation before opening its campaign, with safe retry.

    A failed second write retains the reservation. Retrying the same claim can
    finish the campaign write; it cannot spend the reservation twice. The host
    store still owns durable compare-and-swap and authenticated request scope.
    """
    from lightbulb.company_engine_core import EngineScope, decimal_value
    from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE, advance_campaign, open_campaign
    from lightbulb.growth_paced_envelope import verify_campaign_claim
    runtime = CompanyOperatorSurface(console).runtime("demand_envelope")
    registry = runtime.load(registry_ref)
    _scope(console.bundle, registry)
    plan = runtime.plan
    if console.bundle.growth_plan is None or plan.growth_plan.plan_digest != console.bundle.growth_plan.plan_digest:
        raise ValueError("PORTFOLIO_NOT_BOUND: demand plan must bind the company's current growth plan")
    at = timestamp(now, field_name="now")
    amount = decimal_value(budget, field_name="budget")
    campaign_scope = EngineScope.model_validate(console.bundle.engine_scope(campaign_ref))
    existing_claims = [claim for claim in registry.ledger.claims if claim.campaign_ref == campaign_ref]
    if existing_claims:
        existing = existing_claims[0]
        if existing.envelope_ref != envelope_ref or existing.budget != amount or existing.campaign_scope != campaign_scope:
            raise ValueError("CLAIM_INTENT_MISMATCH: retry must preserve the exact campaign reservation")
    else:
        # Never reserve funds for a pre-existing unrelated campaign.
        if console.store.get("growth_engine", campaign_ref) is not None:
            raise ValueError("CAMPAIGN_ALREADY_EXISTS: use a new campaign identity")
        receipt = {"campaign_ref": campaign_ref, "campaign_scope": campaign_scope.to_dict(),
                   "envelope_ref": envelope_ref, "budget": str(amount)}
        key = stable_digest({"registry_ref": registry_ref, "receipt": receipt})
        command = runtime.command(registry, event="claim", transition_ref=f"claim:{key}",
            idempotency_key=f"claim:{key}", occurred_at=at, actor_ref=console.bundle.actor_ref, receipt=receipt)
        outcome = runtime.advance_and_persist(registry_ref, command)
        if not outcome.persisted:
            return {"schema": "lightbulb.claimed_campaign_open.v1", "persisted": False,
                    "reservation_persisted": False, "result": outcome.result.to_dict(), "provider_effect_executed": False}
    registry = runtime.load(registry_ref)
    _scope(console.bundle, registry)
    verify_campaign_claim(registry, source_plan=plan, campaign_scope=campaign_scope,
                          envelope_ref=envelope_ref, at=at)
    campaign_runtime = EngineRuntime(spec=CAMPAIGN_LIFECYCLE, engine="growth_engine",
        plan=plan.growth_plan, store=console.store, advance=advance_campaign)
    record = console.store.get("growth_engine", campaign_ref)
    if record is not None:
        campaign = campaign_runtime.load(campaign_ref)
        _scope(console.bundle, campaign)
        if (campaign.ledger.demand_plan_digest != plan.plan_digest
                or campaign.ledger.envelope_ref != envelope_ref or campaign.ledger.budget != amount):
            raise ValueError("CLAIM_INTENT_MISMATCH: existing campaign belongs to another reservation")
    else:
        campaign = open_campaign(plan.growth_plan, campaign_scope, portfolio=plan.portfolio,
            envelope_ref=envelope_ref, opened_at=at, actor_ref=console.bundle.actor_ref,
            demand_source={"plan": plan.to_dict(), "state": registry.to_dict()})
        record = campaign_runtime.open(campaign_ref, campaign)
    return {"schema": "lightbulb.claimed_campaign_open.v1", "persisted": True,
            "reservation_persisted": True, "registry_ref": registry_ref,
            "registry_digest": registry.state_digest, "state": campaign.to_dict(),
            "record": record, "provider_effect_executed": False}


def _period_handoffs(engine: str, state: Any, plan: Any, *, default_at: str) -> list[tuple[dict[str, Any], str | None]]:
    """The hand-offs one persisted state offers the cash period, with the date each lands when the hand-off carries none."""

    status = state.status
    ledger = state.ledger
    if engine == "incentive_claim_chain" and status in ("lodged", "assessed"):
        from lightbulb.incentive_claim_chain import expected_inflow
        return [(expected_inflow(state, source_plan=plan, expected_at=default_at), None)]
    if engine == "fundraise_chain" and status == "closed":
        from lightbulb.fundraise_chain import expected_inflows
        return [(item, None) for item in expected_inflows(state, source_plan=plan)]
    if engine == "fulfilment_chain" and status in ("returned", "cancelled", "exception"):
        from lightbulb.fulfilment_chain import refund_expectation
        try:
            return [(refund_expectation(state, source_plan=plan), default_at)]
        except ValueError:
            return []
    if engine == "inventory_chain" and status in ("purchase_committed", "received") and ledger.po_ref is not None:
        from lightbulb.inventory_chain import expected_bill
        return [(expected_bill(state, source_plan=plan), str(ledger.expected_receipt_at or default_at))]
    if engine == "compliance_obligation" and status in ("reserved", "lodged", "overdue"):
        from lightbulb.compliance_calendar import obligation_expectation
        try:
            return [(obligation_expectation(state, source_plan=plan), None)]
        except ValueError:
            return []
    if engine == "partner_commission_chain" and status in ("accrued", "approved"):
        from lightbulb.partner_commission_chain import commission_expectation
        try:
            return [(commission_expectation(state, source_plan=plan, expected_at=default_at), None)]
        except ValueError:
            return []
    if engine == "payroll_run_chain" and status in ("costed", "approved", "funded"):
        from lightbulb.payroll_run_chain import pay_run_expectation
        try:
            return [(pay_run_expectation(state, source_plan=plan), None)]
        except ValueError:
            return []
    if engine == "prepayment_chain" and status == "held":
        from lightbulb.prepayment_chain import refund_expectation as deposit_refund
        try:
            return [(deposit_refund(state, source_plan=plan), None)]
        except ValueError:
            return []
    if engine == "insurance_claim_chain" and status in ("lodged", "assessed"):
        from lightbulb.insurance_claim_chain import expected_inflow as claim_inflow
        return [(claim_inflow(state, source_plan=plan, expected_at=default_at), None)]
    if engine == "payables_chain" and status in ("bill_received", "approved", "scheduled"):
        from lightbulb.payables_chain import bill_expectation
        try:
            return [(bill_expectation(state, source_plan=plan), None)]
        except ValueError:
            return []
    if engine == "collections_chain" and status in ("outstanding", "due", "reminded", "promised", "partially_paid", "escalated", "disputed"):
        from lightbulb.collections_chain import receivable_expectation
        try:
            return [(receivable_expectation(state, source_plan=plan), None)]
        except ValueError:
            return []
    if engine == "vendor_commitment" and status in ("active", "assurance_due", "renewal_due", "decision_pending", "renewed", "renegotiated"):
        from lightbulb.spend_control_chain import commitment_expectation
        try:
            return [(commitment_expectation(state, source_plan=plan), None)]
        except ValueError:
            return []
    return []


def assemble_cash_period(console: Any, period_ref: str, *, as_of: str, preparer_ref: str, balances: Sequence[Mapping[str, Any]], now: str, days_ahead: int = 30, documents: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Open (or resume) the treasury period, bind every balance read, bind every hand-off the persisted chains offer, and project.

    Each step is a real transition through the cash position chain's runtime, persisted through the host store; a hand-off
    already bound is skipped, a chain whose plan the bundle does not carry is reported, and nothing here reads a provider.
    """

    from datetime import timedelta

    from lightbulb.cash_position_chain import EXPECTATION_SCHEMAS, balance_receipt, expectation_receipt, period_receipt
    from lightbulb.company_engine_core import iso, parsed

    surface = CompanyOperatorSurface(console)
    runtime = surface.runtime("cash_position_chain")
    at = timestamp(now, field_name="now")
    entity_ref = f"cash:{period_ref}"
    if console.store.get("cash_position_chain", entity_ref) is None:
        scope = console.bundle.engine_scope(entity_ref)
        state = runtime.spec.open(runtime.plan, scope, receipt=period_receipt(period_ref=period_ref, as_of=as_of, preparer_ref=preparer_ref), opened_at=at, actor_ref=console.bundle.actor_ref)
        runtime.open(entity_ref, state)
    steps: list[dict[str, Any]] = []

    def step(event: str, receipt: Mapping[str, Any], label: str) -> bool:
        outcome = surface.supply("cash_position_chain", entity_ref, event=event, receipt=receipt, now=at)
        result = outcome["result"]
        steps.append({"event": event, "label": label, "persisted": outcome["persisted"], "rejection_code": None if result["candidate_validated"] else result["receipt"]["rejection_code"]})
        return bool(outcome["persisted"])

    for item in balances:
        row = dict(detached(item))
        step("observe_balance", balance_receipt(row["provenance"], row["payload"], account_ref=str(row["account_ref"]), currency=runtime.plan.currency), f"balance:{row['account_ref']}")
    default_at = iso(parsed(timestamp(as_of, field_name="as_of")) + timedelta(days=days_ahead))
    bound: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for engine in sorted({engine for engine, _direction in EXPECTATION_SCHEMAS.values()}):
        try:
            source_runtime = surface.runtime(engine)
        except (LookupError, ValueError) as exc:
            skipped.append({"engine": engine, "reason": str(exc)[:200]})
            continue
        for record in console.store.list(engine=engine, limit=200):
            ref = str(dict(record["state"]).get("scope", {}).get("entity_ref"))
            try:
                source_state = source_runtime.load(ref)
                _scope(console.bundle, source_state)
                handoffs = _period_handoffs(engine, source_state, source_runtime.plan, default_at=default_at)
            except (ValueError, LookupError, KeyError) as exc:
                skipped.append({"engine": engine, "entity_ref": ref, "reason": str(exc)[:200]})
                continue
            for handoff, due_at in handoffs:
                flow_ref = str(handoff.get("flow_ref") or handoff.get("order_ref") or handoff.get("po_ref") or ref)
                try:
                    receipt = expectation_receipt(handoff, source_engine=engine, source_state=source_state, source_plan=source_runtime.plan, due_at=due_at)
                except ValueError as exc:
                    skipped.append({"engine": engine, "entity_ref": ref, "flow_ref": flow_ref, "reason": str(exc)[:200]})
                    continue
                if step("bind_expectation", receipt, f"{engine}:{flow_ref}"):
                    bound.append({"engine": engine, "entity_ref": ref, "flow_ref": flow_ref, "amount": str(handoff.get("amount")), "direction": EXPECTATION_SCHEMAS[str(handoff.get("schema"))][1]})
                else:
                    skipped.append({"engine": engine, "entity_ref": ref, "flow_ref": flow_ref, "reason": steps[-1]["rejection_code"]})
    for document in documents:
        doc = dict(detached(document))
        schema = str(doc.get("schema", ""))
        if schema == "lightbulb.revenue_model.v1":
            from lightbulb.growth_revenue_model import expected_inflows as model_inflows

            try:
                handoffs = [(item, None) for item in model_inflows(doc)]
            except ValueError as exc:
                skipped.append({"engine": "growth_revenue_model", "reason": str(exc)[:200]})
                continue
            for handoff, due_at in handoffs:
                try:
                    receipt = expectation_receipt(handoff, source_engine="growth_revenue_model", source_state=doc, due_at=due_at)
                except ValueError as exc:
                    skipped.append({"engine": "growth_revenue_model", "flow_ref": str(handoff.get("flow_ref")), "reason": str(exc)[:200]})
                    continue
                if step("bind_expectation", receipt, f"growth_revenue_model:{handoff['flow_ref']}"):
                    bound.append({"engine": "growth_revenue_model", "entity_ref": str(doc.get("model_digest", ""))[:16], "flow_ref": str(handoff["flow_ref"]), "amount": str(handoff.get("amount")), "direction": "receivable"})
                else:
                    skipped.append({"engine": "growth_revenue_model", "flow_ref": str(handoff["flow_ref"]), "reason": steps[-1]["rejection_code"]})
        else:
            skipped.append({"engine": "document", "reason": f"{schema or 'untyped'} is not a document the period accepts"})
    step("project", {}, "project")
    final = runtime.load(entity_ref)
    return {"schema": "lightbulb.company_cash_period_assembly.v1", "engine": "cash_position_chain", "entity_ref": entity_ref, "period_ref": period_ref, "status": final.status, "state": final.to_dict(), "balances_observed": len(final.ledger.balances), "bound": bound, "skipped": skipped, "steps": steps, "first_breach_week": final.ledger.first_breach_week, "runway_weeks": final.ledger.runway_weeks, "provider_effect_executed": False}


def build_cap_table_register(console: Any, *, now: str) -> dict[str, Any]:
    """The sealed cap table from the bundle's fundraise plan and every persisted round and grant."""

    from lightbulb.company_cap_table import build_cap_table

    surface = CompanyOperatorSurface(console)
    rounds_runtime = surface.runtime("fundraise_chain")
    rounds = []
    for record in console.store.list(engine="fundraise_chain", limit=200):
        state = rounds_runtime.load(str(dict(record["state"]).get("scope", {}).get("entity_ref")))
        _scope(console.bundle, state)
        rounds.append((rounds_runtime.plan, state))
    grants = []
    try:
        grants_runtime = surface.runtime("equity_grant_chain")
    except (LookupError, ValueError):
        grants_runtime = None
    if grants_runtime is not None:
        for record in console.store.list(engine="equity_grant_chain", limit=200):
            state = grants_runtime.load(str(dict(record["state"]).get("scope", {}).get("entity_ref")))
            _scope(console.bundle, state)
            grants.append((grants_runtime.plan, state))
    register = build_cap_table(rounds_runtime.plan, rounds=rounds, grants=grants, as_of=timestamp(now, field_name="now"))
    return {**register.to_dict(), "summary": register.render(), "rounds_read": len(rounds), "grants_read": len(grants), "provider_effect_executed": False}


def _persisted(console: Any, engine: str) -> list[tuple[Any, Any]]:
    """Every persisted state of one chain, replayed against the bundle's plan; empty when the bundle carries no plan."""

    surface = CompanyOperatorSurface(console)
    try:
        runtime = surface.runtime(engine)
    except (LookupError, ValueError):
        runner = getattr(console, "runner", None) or (console._runner() if hasattr(console, "_runner") else None)
        runtime = runner.runtimes.get(engine) if runner is not None else None
        if runtime is None:
            return []
    rows = []
    for record in console.store.list(engine=engine, limit=200):
        state = runtime.load(str(dict(record["state"]).get("scope", {}).get("entity_ref")))
        _scope(console.bundle, state)
        rows.append((runtime.plan, state))
    return rows


def build_channel_cohort_report(console: Any, *, now: str, attribution: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed cohort table from the bundle's cohort plan and every persisted revenue case, subscription, commission, and cost register."""

    from lightbulb.growth_channel_cohorts import ChannelCohortPlan, build_channel_cohorts

    raw = console.bundle.supporting_plans.get("growth_channel_cohorts")
    if raw is None:
        raise LookupError("the bundle carries no sealed plan for growth_channel_cohorts")
    plan = ChannelCohortPlan.model_validate(detached(raw))
    if plan.company_ref != console.bundle.company_ref or plan.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the cohort plan must name this company and its currency")
    report = build_channel_cohorts(plan, revenue_states=_persisted(console, "revenue_chain"), subscription_states=_persisted(console, "subscription_chain"), register_states=_persisted(console, "company_cost_centres"), commission_states=_persisted(console, "partner_commission_chain"), attribution=attribution, as_of=timestamp(now, field_name="now"))
    return {**report.to_dict(), "summary": report.render(), "provider_effect_executed": False}


def build_revenue_model_document(console: Any, *, now: str, pipeline_forecast: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed revenue model from the bundle's model plan, every persisted subscription, revenue case, and deposit, and the persisted pipeline's forecast."""

    from lightbulb.growth_revenue_model import RevenueModelPlan, build_revenue_model

    raw = console.bundle.supporting_plans.get("growth_revenue_model")
    if raw is None:
        raise LookupError("the bundle carries no sealed plan for growth_revenue_model")
    plan = RevenueModelPlan.model_validate(detached(raw))
    if plan.company_ref != console.bundle.company_ref or plan.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the revenue model plan must name this company and its currency")
    forecast = pipeline_forecast
    if forecast is None and console.bundle.pipeline_plan is not None:
        from lightbulb.pipeline_engine_loop import forecast_pipeline

        prospects = [state for _plan, state in _persisted(console, "pipeline_engine")]
        if prospects:
            forecast = forecast_pipeline(console.bundle.pipeline_plan, prospects, forecast_at=timestamp(now, field_name="now")).to_dict()
    model = build_revenue_model(plan, subscription_states=_persisted(console, "subscription_chain"), revenue_states=_persisted(console, "revenue_chain"), deposit_states=_persisted(console, "prepayment_chain"), pipeline_forecast=forecast, as_of=timestamp(now, field_name="now"))
    return {**model.to_dict(), "summary": model.render(), "provider_effect_executed": False}


def _persisted_one(console: Any, engine: str, entity_ref: str | None = None) -> tuple[Any, Any]:
    """One persisted state of a chain (the named one, or the only one), replayed against the bundle's plan."""

    rows = _persisted(console, engine)
    if entity_ref is not None:
        match = [row for row in rows if row[1].scope.entity_ref == entity_ref]
        if not match:
            raise LookupError(f"{engine} {entity_ref} is not persisted")
        return match[0]
    if len(rows) != 1:
        raise LookupError(f"{len(rows)} {engine} state(s) persisted; name the entity_ref")
    return rows[0]


def _supporting_plan(console: Any, engine: str, model: Any) -> Any:
    raw = console.bundle.supporting_plans.get(engine)
    if raw is None:
        raise LookupError(f"the bundle carries no sealed plan for {engine}")
    plan = model.model_validate(detached(raw))
    if plan.company_ref != console.bundle.company_ref or plan.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError(f"SCOPE_MISMATCH: the {engine} plan must name this company and its currency")
    return plan


def build_pipeline_coverage_document(console: Any, *, now: str, period_ref: str, operating_plan_ref: str | None = None, revenue_model: Mapping[str, Any] | None = None, target_amount: Any | None = None, current_sales_heads: int = 0) -> dict[str, Any]:
    """The sealed coverage assessment from the bundle's coverage plan, its pipeline plan, the persisted prospects, and one target: the persisted operating plan's period, a revenue model's month, or a typed amount."""

    from lightbulb.pipeline_coverage import PipelineCoveragePlan, build_pipeline_coverage

    plan = _supporting_plan(console, "pipeline_coverage", PipelineCoveragePlan)
    if console.bundle.pipeline_plan is None:
        raise LookupError("the bundle carries no pipeline plan")
    prospects = [state for _plan, state in _persisted(console, "pipeline_engine")]
    operating_plan_state = None
    if revenue_model is None and target_amount is None:
        operating_plan_state = _persisted_one(console, "operating_plan", operating_plan_ref)
    coverage = build_pipeline_coverage(plan, pipeline_plan=console.bundle.pipeline_plan, prospect_states=prospects, period_ref=period_ref, as_of=timestamp(now, field_name="now"), operating_plan_state=operating_plan_state, revenue_model=revenue_model, target_amount=target_amount, current_sales_heads=int(current_sales_heads))
    return {**coverage.to_dict(), "summary": coverage.render(), "provider_effect_executed": False}


def build_objective_plan_document(console: Any, *, now: str, objective: Mapping[str, Any], operating_plan_ref: str | None = None, revenue_model: Mapping[str, Any] | None = None, assessment: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed reconciliation of the growth objective with the persisted operating plan, and optionally the sealed revenue model and assessment."""

    from lightbulb.growth_plan_reconciliation import ReconciliationPlan, build_objective_plan_reconciliation

    plan = _supporting_plan(console, "growth_plan_reconciliation", ReconciliationPlan)
    reconciliation = build_objective_plan_reconciliation(plan, objective=objective, operating_plan_state=_persisted_one(console, "operating_plan", operating_plan_ref), revenue_model=revenue_model, assessment=assessment, as_of=timestamp(now, field_name="now"))
    return {**reconciliation.to_dict(), "summary": reconciliation.render(), "provider_effect_executed": False}


def build_channel_allocation_document(console: Any, *, now: str, allocation_ref: str, funding_gate: Mapping[str, Any] | None = None, budget_envelope: Mapping[str, Any] | None = None, attribution: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed monthly budget per channel from the bundle's allocation plan, the cohort table built from the persisted chains, and one deployable amount."""

    from lightbulb.growth_channel_allocation import ChannelAllocationPlan, build_channel_allocation

    plan = _supporting_plan(console, "growth_channel_allocation", ChannelAllocationPlan)
    report = build_channel_cohort_report(console, now=now, attribution=attribution)
    cohorts = {key: value for key, value in report.items() if key not in {"summary", "provider_effect_executed"}}
    allocation = build_channel_allocation(plan, cohorts=cohorts, as_of=timestamp(now, field_name="now"), allocation_ref=allocation_ref, funding_gate=funding_gate, budget_envelope=budget_envelope)
    return {**allocation.to_dict(), "summary": allocation.render(), "provider_effect_executed": False}


def draft_catalog_from_price_plan(console: Any, entity_ref: str, *, now: str, price_plan: Mapping[str, Any], version_ref: str, drafter_ref: str, current_ref: str, item_refs: Sequence[str] | None = None) -> dict[str, Any]:
    """Open the catalog version that implements a sealed growth price plan against the persisted current version; approval and notice stay the catalog's."""

    from lightbulb.price_catalog import draft_from_price_plan

    surface = CompanyOperatorSurface(console)
    runtime = surface.runtime("price_catalog")
    current = runtime.load(current_ref)
    _scope(console.bundle, current)
    receipt = draft_from_price_plan(price_plan, version_ref=version_ref, drafter_ref=drafter_ref, current=current, current_plan=runtime.plan, item_refs=item_refs)
    scope = console.bundle.engine_scope(entity_ref)
    at = timestamp(now, field_name="now")
    state = runtime.spec.open(runtime.plan, scope, receipt=receipt, opened_at=at, actor_ref=console.bundle.actor_ref)
    record = runtime.open(entity_ref, state)
    return {"schema": "lightbulb.company_chain_operation.v1", "engine": "price_catalog", "entity_ref": entity_ref, "persisted": True, "state": state.to_dict(), "record": record, "provider_effect_executed": False}


def _document(built: Mapping[str, Any]) -> dict[str, Any]:
    """A builder's answer without the console's own keys, so the sealed document validates again."""

    return {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed"}}


def build_win_loss_report(console: Any, *, now: str, facts: Mapping[str, Mapping[str, Any]] | None = None, since: str | None = None) -> dict[str, Any]:
    """The sealed win/loss report from the bundle's pipeline plan and every persisted prospect."""

    from lightbulb.pipeline_win_loss import build_win_loss

    if console.bundle.pipeline_plan is None:
        raise LookupError("the bundle carries no pipeline plan")
    prospects = [state for _plan, state in _persisted(console, "pipeline_engine")]
    report = build_win_loss(console.bundle.pipeline_plan, prospects, as_of=timestamp(now, field_name="now"), facts=facts, since=since)
    return {**report.to_dict(), "summary": report.render(), "provider_effect_executed": False}


def score_allocation_document(console: Any, *, now: str, allocation: Mapping[str, Any], attribution: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed outcome of an earlier allocation against the cohort table built now from the persisted chains."""

    from lightbulb.growth_allocation_outcomes import score_allocation

    cohorts = _document(build_channel_cohort_report(console, now=now, attribution=attribution))
    outcome = score_allocation(allocation, cohorts=cohorts, as_of=timestamp(now, field_name="now"))
    return {**outcome.to_dict(), "summary": outcome.render(), "provider_effect_executed": False}


GROWTH_REVIEW_RECORD_SCHEMA = "lightbulb.growth_review_record.v1"


def persist_growth_review(console: Any, review: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a sealed growth review as a version-1 record under its own entity (``review:<ref>``); a second write for the same ref is refused by the store's fence."""

    from lightbulb.growth_operating_review import verify_growth_review

    verified = verify_growth_review(review)
    if verified.company_ref != console.bundle.company_ref or verified.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the review names another company or currency")
    entity_ref = f"review:{verified.review_ref}"
    state = {"schema": GROWTH_REVIEW_RECORD_SCHEMA, "status": "reviewed", "plan_digest": console.bundle.plan_digest, "version": 1, "state_digest": verified.review_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": verified.as_of, "review": verified.to_dict()}
    record = console.store.put("growth_operating_review", entity_ref, state, expected_version=0, expected_state_digest=None)
    return {"entity_ref": entity_ref, "record": record, "review_digest": verified.review_digest}


def persisted_growth_reviews(console: Any) -> list[dict[str, Any]]:
    """Every persisted review for this bundle, newest first."""

    from lightbulb.growth_operating_review import verify_growth_review

    rows = []
    for record in console.store.list(engine="growth_operating_review", limit=200):
        state = dict(record["state"])
        if state.get("schema") != GROWTH_REVIEW_RECORD_SCHEMA or dict(state.get("scope") or {}).get("company_ref") != console.bundle.scope.get("company_ref"):
            continue
        review = verify_growth_review(state["review"])
        if review.company_ref == console.bundle.company_ref:
            rows.append(review.to_dict())
    rows.sort(key=lambda item: str(item["as_of"]), reverse=True)
    return rows


def latest_growth_review(console: Any, *, before: str | None = None) -> dict[str, Any] | None:
    for row in persisted_growth_reviews(console):
        if before is None or str(row["as_of"]) < before:
            return row
    return None


def latest_cash_envelope(console: Any, *, now: str, runway_floor_months: Any = "6") -> dict[str, Any]:
    """The budget envelope derived from the latest projected treasury period at or before ``now``."""

    from lightbulb.cash_position_chain import budget_envelope_from_period

    stamp = timestamp(now, field_name="now")
    periods = [(plan, state) for plan, state in _persisted(console, "cash_position_chain") if state.status in ("projected", "reviewed", "closed") and state.ledger.as_of is not None and parsed(str(state.ledger.as_of)) <= parsed(stamp)]
    if not periods:
        raise LookupError("no projected treasury period at or before now; assemble the cash period first")
    plan, state = max(periods, key=lambda row: (str(row[1].ledger.as_of), row[1].version))
    return budget_envelope_from_period(state, source_plan=plan, runway_floor_months=runway_floor_months)


def bundle_growth_objective(console: Any) -> dict[str, Any]:
    """The growth objective the bundle carries under supporting_plans["growth_objective"], re-validated."""

    from lightbulb.growth_objectives import GrowthObjective

    raw = console.bundle.supporting_plans.get("growth_objective")
    if raw is None:
        raise LookupError("the bundle carries no growth objective; supply one or add it under supporting_plans[\"growth_objective\"]")
    objective = GrowthObjective.model_validate(dict(detached(raw)))
    if objective.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the bundle's growth objective is in another currency")
    return objective.model_dump(mode="json", by_alias=True, exclude_none=True)


def build_growth_review_document(console: Any, *, now: str, review_ref: str, period_ref: str, allocation_ref: str, objective: Mapping[str, Any] | None = None, funding_gate: Mapping[str, Any] | None = None, budget_envelope: Mapping[str, Any] | None = None, operating_plan_ref: str | None = None, current_sales_heads: int = 0, attribution: Mapping[str, Any] | None = None, authorizations: Sequence[Mapping[str, Any]] = (), pipeline_forecast: Mapping[str, Any] | None = None, assessment: Mapping[str, Any] | None = None, previous: Mapping[str, Any] | None = None, carry: bool = True) -> dict[str, Any]:
    """The weekly growth review: the revenue model, cohort table, coverage, reconciliation, and allocation built now from the bundle and the persisted chains, read together; the latest persisted review is carried unless ``carry`` is off."""

    from lightbulb.growth_operating_review import build_growth_review

    if objective is None:
        objective = bundle_growth_objective(console)
    if funding_gate is None and budget_envelope is None:
        budget_envelope = latest_cash_envelope(console, now=now)
    model = _document(build_revenue_model_document(console, now=now, pipeline_forecast=pipeline_forecast))
    cohorts = _document(build_channel_cohort_report(console, now=now, attribution=attribution))
    coverage = _document(build_pipeline_coverage_document(console, now=now, period_ref=period_ref, revenue_model=model, current_sales_heads=current_sales_heads))
    reconciliation = _document(build_objective_plan_document(console, now=now, objective=objective, operating_plan_ref=operating_plan_ref, revenue_model=model, assessment=assessment))
    allocation = _document(build_channel_allocation_document(console, now=now, allocation_ref=allocation_ref, funding_gate=funding_gate, budget_envelope=budget_envelope, attribution=attribution))
    prior = previous if previous is not None else (latest_growth_review(console, before=timestamp(now, field_name="now")) if carry else None)
    review = build_growth_review(review_ref=review_ref, as_of=timestamp(now, field_name="now"), revenue_model=model, cohorts=cohorts, coverage=coverage, reconciliation=reconciliation, allocation=allocation, authorizations=authorizations, previous=prior)
    return {**review.to_dict(), "summary": review.render(), "documents_built": {"revenue_model": model, "cohorts": cohorts, "coverage": coverage, "reconciliation": reconciliation, "allocation": allocation}, "provider_effect_executed": False}


def plan_company_adoption(console: Any, *, now: str, sources: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The sealed adoption plan from the bundle's plans and the supplied provider reads; nothing is persisted."""

    from lightbulb.company_adoption import plan_adoption

    bundle = console.bundle
    kinds = {str(dict(detached(source)).get("kind", "")) for source in sources}
    subscription_plan = plan_for_chain(bundle, "subscription_chain") if "stripe_invoices" in kinds else None
    payables_plan = plan_for_chain(bundle, "payables_chain") if "ledger_bills" in kinds else None
    plan = plan_adoption(company_ref=bundle.company_ref, currency=bundle.operating_plan.blueprint.currency, as_of=timestamp(now, field_name="now"), sources=sources, saas_plan=bundle.saas_plan, subscription_plan=subscription_plan, payables_plan=payables_plan, pipeline_plan=bundle.pipeline_plan)
    return {**plan.to_dict(), "summary": plan.render(), "provider_effect_executed": False}


def run_company_adoption(console: Any, *, now: str, plan: Mapping[str, Any] | None = None, sources: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Apply a sealed adoption plan (or plan the supplied reads first) through the console's runtimes."""

    from lightbulb.company_adoption import run_adoption

    if plan is None:
        plan = {key: value for key, value in plan_company_adoption(console, now=now, sources=sources).items() if key not in {"summary", "provider_effect_executed"}}
    report = run_adoption(console, plan)
    return {**report, "plan": dict(detached(plan))}


def build_sales_capacity_document(console: Any, *, now: str, window_start: str | None = None) -> dict[str, Any]:
    """The sealed sales capacity assessment from the bundle's capacity plan, its pipeline plan, and the persisted prospects."""

    from lightbulb.sales_capacity import SalesCapacityPlan, build_sales_capacity

    plan = _supporting_plan(console, "sales_capacity", SalesCapacityPlan)
    if console.bundle.pipeline_plan is None:
        raise LookupError("the bundle carries no pipeline plan")
    prospects = [state for _plan, state in _persisted(console, "pipeline_engine")]
    capacity = build_sales_capacity(plan, pipeline_plan=console.bundle.pipeline_plan, prospect_states=prospects, as_of=timestamp(now, field_name="now"), window_start=window_start)
    return {**capacity.to_dict(), "summary": capacity.render(), "provider_effect_executed": False}


def plan_company_sync(console: Any, *, now: str, sources: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The sealed sync plan from fresh reads and the persisted subscription, payable, and finance close states; nothing is persisted."""

    from lightbulb.company_sync import plan_sync

    bundle = console.bundle
    kinds = {str(dict(detached(source)).get("kind", "")) for source in sources}
    subscription_plan = plan_for_chain(bundle, "subscription_chain") if kinds & {"stripe_invoices", "stripe_charges", "stripe_settlements"} else None
    payables_plan = plan_for_chain(bundle, "payables_chain") if "ledger_bills" in kinds else None
    plan = plan_sync(company_ref=bundle.company_ref, currency=bundle.operating_plan.blueprint.currency, as_of=timestamp(now, field_name="now"), sources=sources, subscription_states=_persisted(console, "subscription_chain"), payable_states=_persisted(console, "payables_chain"), close_states=_persisted(console, "finance_close"), saas_plan=bundle.saas_plan, subscription_plan=subscription_plan, payables_plan=payables_plan)
    return {**plan.to_dict(), "summary": plan.render(), "provider_effect_executed": False}


def run_company_sync(console: Any, *, now: str, plan: Mapping[str, Any] | None = None, sources: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Apply a sealed sync plan (or plan the supplied reads first) through the console's runtimes."""

    from lightbulb.company_sync import run_sync

    if plan is None:
        plan = {key: value for key, value in plan_company_sync(console, now=now, sources=sources).items() if key not in {"summary", "provider_effect_executed"}}
    report = run_sync(console, plan)
    return {**report, "plan": dict(detached(plan))}


def _window(now: str, window_start: str | None, window_end: str | None) -> tuple[str, str]:
    from datetime import timedelta

    from lightbulb.company_engine_core import iso, parsed

    end = timestamp(window_end, field_name="window_end") if window_end else timestamp(now, field_name="now")
    start = timestamp(window_start, field_name="window_start") if window_start else iso(parsed(end) - timedelta(days=30))
    return start, end


def _product_states(console: Any) -> dict[str, list[tuple[Any, Any]]]:
    return {engine: _persisted(console, engine) for engine in ("fulfilment_chain", "inventory_chain", "storefront_settlement_chain", "price_catalog")}


def build_product_margin_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed product margin report from the bundle's margin plan and every persisted order, stock position, settlement batch, and published catalog; the window defaults to the thirty days to now."""

    from lightbulb.product_margin import ProductMarginPlan, build_product_margin

    plan = _supporting_plan(console, "product_margin", ProductMarginPlan)
    start, end = _window(now, window_start, window_end)
    states = _product_states(console)
    report = build_product_margin(plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**report.to_dict(), "summary": report.render(), "provider_effect_executed": False}


def build_product_portfolio_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, previous_window_start: str | None = None) -> dict[str, Any]:
    """The sealed product portfolio: the window's margin report (and the previous window's when ``previous_window_start`` is given) placed against the persisted stock positions under the bundle's portfolio plan."""

    from lightbulb.product_margin import ProductMarginPlan, build_product_margin
    from lightbulb.product_portfolio import ProductPortfolioPlan, build_product_portfolio

    margin_plan = _supporting_plan(console, "product_margin", ProductMarginPlan)
    plan = _supporting_plan(console, "product_portfolio", ProductPortfolioPlan)
    start, end = _window(now, window_start, window_end)
    states = _product_states(console)
    at = timestamp(now, field_name="now")
    current = build_product_margin(margin_plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=start, window_end=end, as_of=at)
    previous = None
    if previous_window_start is not None:
        previous = build_product_margin(margin_plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=timestamp(previous_window_start, field_name="previous_window_start"), window_end=start, as_of=at)
    portfolio = build_product_portfolio(plan, margin_report=current, previous_report=previous, inventory_states=states["inventory_chain"], as_of=at)
    return {**portfolio.to_dict(), "documents_built": {"margin_report": current.to_dict(), "previous_report": None if previous is None else previous.to_dict()}, "summary": portfolio.render(), "provider_effect_executed": False}


def bundle_skills_taxonomy(console: Any) -> Any:
    """The sealed skills taxonomy the bundle carries under ``supporting_plans["skills_taxonomy"]``."""

    from lightbulb.skills_matching import SkillsTaxonomy

    raw = console.bundle.supporting_plans.get("skills_taxonomy")
    if raw is None:
        raise LookupError("the bundle carries no skills taxonomy")
    taxonomy = SkillsTaxonomy.model_validate(detached(raw))
    if taxonomy.company_ref != console.bundle.company_ref:
        raise ValueError("SCOPE_MISMATCH: the skills taxonomy must name this company")
    return taxonomy


def build_skills_match_document(console: Any, *, now: str, jobs: Sequence[Mapping[str, Any]], profiles: Sequence[Mapping[str, Any]], taxonomy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed skills match report: the supplied jobs and worker profiles under the bundle's matching plan and taxonomy, with every persisted work order's recorded hours credited as evidence."""

    from lightbulb.skills_matching import SkillsMatchingPlan, SkillsTaxonomy, build_skills_match_report

    plan = _supporting_plan(console, "skills_matching", SkillsMatchingPlan)
    parsed_taxonomy = SkillsTaxonomy.model_validate(detached(taxonomy)) if taxonomy is not None else bundle_skills_taxonomy(console)
    report = build_skills_match_report(plan, taxonomy=parsed_taxonomy, jobs=list(jobs), profiles=list(profiles), work_order_states=_persisted(console, "work_order_chain"), as_of=timestamp(now, field_name="now"))
    return {**report.to_dict(), "summary": report.render(), "provider_effect_executed": False}


def build_labour_sourcing_document(console: Any, *, now: str, jobs: Sequence[Mapping[str, Any]], profiles: Sequence[Mapping[str, Any]], taxonomy: Mapping[str, Any] | None = None, match_report: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed labour sourcing plan for every gap in the match report (built first when not supplied), priced against the bundle's sourcing plan and the hiring chain's pay bands when the bundle carries one."""

    from lightbulb.labour_sourcing import LabourSourcingPlan, build_labour_sourcing
    from lightbulb.skills_matching import SkillsMatchingPlan, SkillsTaxonomy

    plan = _supporting_plan(console, "labour_sourcing", LabourSourcingPlan)
    matching_plan = _supporting_plan(console, "skills_matching", SkillsMatchingPlan)
    parsed_taxonomy = SkillsTaxonomy.model_validate(detached(taxonomy)) if taxonomy is not None else bundle_skills_taxonomy(console)
    report = dict(detached(match_report)) if match_report is not None else _document(build_skills_match_document(console, now=now, jobs=jobs, profiles=profiles, taxonomy=parsed_taxonomy.to_dict()))
    try:
        hiring_plan = plan_for_chain(console.bundle, "hiring_chain")
    except LookupError:
        hiring_plan = None
    sourcing = build_labour_sourcing(plan, match_report=report, taxonomy=parsed_taxonomy, matching_plan=matching_plan, jobs=list(jobs), profiles=list(profiles), hiring_plan=hiring_plan, as_of=timestamp(now, field_name="now"))
    return {**sourcing.to_dict(), "documents_built": {"match_report": report}, "summary": sourcing.render(), "provider_effect_executed": False}


def build_services_margin_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, profiles: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The sealed services margin over the window from every persisted engagement, with the persisted work orders as internal hours and the supplied worker profiles as available hours."""

    from lightbulb.services_margin import ServicesMarginPlan, build_services_margin

    plan = _supporting_plan(console, "services_margin", ServicesMarginPlan)
    start, end = _window(now, window_start, window_end)
    document = build_services_margin(plan, engagement_states=_persisted(console, "engagement_engine"), work_order_states=_persisted(console, "work_order_chain"), profiles=list(profiles), window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**document.to_dict(), "summary": document.render(), "provider_effect_executed": False}


def build_skills_inventory_document(console: Any, *, now: str, profiles: Sequence[Mapping[str, Any]], jobs: Sequence[Mapping[str, Any]] = (), taxonomy: Mapping[str, Any] | None = None, minimum_depth: int = 2, licence_horizon_days: int = 90) -> dict[str, Any]:
    """The sealed skills inventory: depth, single points of failure, licence alerts, and upskilling candidates under the bundle's matching plan and taxonomy, with every persisted work order's recorded hours credited as evidence."""

    from lightbulb.skills_inventory import build_skills_inventory
    from lightbulb.skills_matching import SkillsMatchingPlan, SkillsTaxonomy

    plan = _supporting_plan(console, "skills_matching", SkillsMatchingPlan)
    parsed_taxonomy = SkillsTaxonomy.model_validate(detached(taxonomy)) if taxonomy is not None else bundle_skills_taxonomy(console)
    inventory = build_skills_inventory(plan, taxonomy=parsed_taxonomy, profiles=list(profiles), jobs=list(jobs), work_order_states=_persisted(console, "work_order_chain"), as_of=timestamp(now, field_name="now"), minimum_depth=int(minimum_depth), licence_horizon_days=int(licence_horizon_days))
    return {**inventory.to_dict(), "summary": inventory.render(), "provider_effect_executed": False}


def build_price_probes_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, previous_window_start: str | None = None) -> dict[str, Any]:
    """The sealed price probes for the window's margin report; when a previous window is given the portfolio is built too and its actions decide which SKUs are probed."""

    from lightbulb.price_probes import PriceProbePlan, plan_price_probes

    plan = _supporting_plan(console, "price_probes", PriceProbePlan)
    built = build_product_portfolio_document(console, now=now, window_start=window_start, window_end=window_end, previous_window_start=previous_window_start)
    margin_report = built["documents_built"]["margin_report"]
    portfolio = _document({key: value for key, value in built.items() if key != "documents_built"})
    probes = plan_price_probes(plan, margin_report=margin_report, portfolio=portfolio if previous_window_start is not None else None, as_of=timestamp(now, field_name="now"))
    return {**probes.to_dict(), "documents_built": {"margin_report": margin_report, "portfolio": portfolio}, "summary": probes.render(), "provider_effect_executed": False}


def build_contribution_bridge_document(console: Any, *, now: str, previous_window_start: str, window_start: str, window_end: str | None = None) -> dict[str, Any]:
    """The sealed contribution bridge between the previous window (ending where this one starts) and this window, both margin reports built now from the persisted commerce chains."""

    from lightbulb.contribution_bridge import build_contribution_bridge
    from lightbulb.product_margin import ProductMarginPlan, build_product_margin

    margin_plan = _supporting_plan(console, "product_margin", ProductMarginPlan)
    start, end = _window(now, window_start, window_end)
    states = _product_states(console)
    at = timestamp(now, field_name="now")
    previous = build_product_margin(margin_plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=timestamp(previous_window_start, field_name="previous_window_start"), window_end=start, as_of=at)
    current = build_product_margin(margin_plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=start, window_end=end, as_of=at)
    bridge = build_contribution_bridge(previous, current)
    return {**bridge.to_dict(), "documents_built": {"previous_report": previous.to_dict(), "current_report": current.to_dict()}, "summary": bridge.render(), "provider_effect_executed": False}


def build_rate_card_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, profiles: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The sealed rate card from the services margin built now over the window, under the bundle's rate card plan."""

    from lightbulb.rate_card import RateCardPlan, build_rate_card

    plan = _supporting_plan(console, "rate_card", RateCardPlan)
    margin = _document(build_services_margin_document(console, now=now, window_start=window_start, window_end=window_end, profiles=profiles))
    card = build_rate_card(plan, services_margin=margin, as_of=timestamp(now, field_name="now"))
    return {**card.to_dict(), "documents_built": {"services_margin": margin}, "summary": card.render(), "provider_effect_executed": False}


def build_workforce_capacity_document(console: Any, *, now: str, profiles: Sequence[Mapping[str, Any]], jobs: Sequence[Mapping[str, Any]], taxonomy: Mapping[str, Any] | None = None, weeks: int = 8) -> dict[str, Any]:
    """The sealed weekly capacity plan for the supplied jobs and profiles under the bundle's matching plan and taxonomy, with every persisted work order's recorded hours credited as evidence."""

    from lightbulb.skills_matching import SkillsMatchingPlan, SkillsTaxonomy
    from lightbulb.workforce_capacity import build_workforce_capacity

    plan = _supporting_plan(console, "skills_matching", SkillsMatchingPlan)
    parsed_taxonomy = SkillsTaxonomy.model_validate(detached(taxonomy)) if taxonomy is not None else bundle_skills_taxonomy(console)
    capacity = build_workforce_capacity(plan, taxonomy=parsed_taxonomy, profiles=list(profiles), jobs=list(jobs), work_order_states=_persisted(console, "work_order_chain"), as_of=timestamp(now, field_name="now"), weeks=int(weeks))
    return {**capacity.to_dict(), "summary": capacity.render(), "provider_effect_executed": False}


def build_job_quote_document(console: Any, *, now: str, job: Mapping[str, Any], profiles: Sequence[Mapping[str, Any]], offered_price: Any | None = None, taxonomy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed job quote: the matched team from the bundle's matching plan and taxonomy (with the persisted work orders' hours as evidence), its loaded cost under the bundle's quote plan, the floor and target prices, and the verdict against the offered price or the job's budget."""

    from lightbulb.job_quote import JobQuotePlan, build_job_quote
    from lightbulb.skills_matching import SkillsMatchingPlan, SkillsTaxonomy

    plan = _supporting_plan(console, "job_quote", JobQuotePlan)
    matching_plan = _supporting_plan(console, "skills_matching", SkillsMatchingPlan)
    parsed_taxonomy = SkillsTaxonomy.model_validate(detached(taxonomy)) if taxonomy is not None else bundle_skills_taxonomy(console)
    quote = build_job_quote(plan, job=job, taxonomy=parsed_taxonomy, matching_plan=matching_plan, profiles=list(profiles), work_order_states=_persisted(console, "work_order_chain"), offered_price=offered_price, as_of=timestamp(now, field_name="now"))
    return {**quote.to_dict(), "summary": quote.render(), "provider_effect_executed": False}


def build_customer_profitability_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, target_margin_percent: Any = "30", return_rate_threshold_percent: Any = "10", core_share_percent: Any = "80") -> dict[str, Any]:
    """The sealed customer profitability for the window: the margin report built now from the persisted commerce chains, then every persisted order captured with its customer costed to serve."""

    from lightbulb.customer_profitability import build_customer_profitability
    from lightbulb.product_margin import ProductMarginPlan, build_product_margin

    plan = _supporting_plan(console, "product_margin", ProductMarginPlan)
    start, end = _window(now, window_start, window_end)
    states = _product_states(console)
    at = timestamp(now, field_name="now")
    report = build_product_margin(plan, fulfilment_states=states["fulfilment_chain"], inventory_states=states["inventory_chain"], settlement_states=states["storefront_settlement_chain"], catalog_states=states["price_catalog"], window_start=start, window_end=end, as_of=at)
    document = build_customer_profitability(plan, margin_report=report, fulfilment_states=states["fulfilment_chain"], as_of=at, target_margin_percent=target_margin_percent, return_rate_threshold_percent=return_rate_threshold_percent, core_share_percent=core_share_percent)
    return {**document.to_dict(), "documents_built": {"margin_report": report.to_dict()}, "summary": document.render(), "provider_effect_executed": False}


def _sealed(built: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed", "documents_built"}}


def build_intelligence_review_document(console: Any, *, now: str, review_ref: str, documents: Mapping[str, Any] | None = None, window_start: str | None = None, window_end: str | None = None, previous_window_start: str | None = None, profiles: Sequence[Mapping[str, Any]] = (), max_age_days: int = 7, previous: Mapping[str, Any] | None = None, carry: bool = True) -> dict[str, Any]:
    """The sealed weekly intelligence review: every product and services document the bundle's plans allow is built now from the persisted chains (margin, portfolio, price probes, the bridge when a previous window is given, customer profitability, services margin, rate card), the supplied sealed documents are added (a supplied document wins), and the actions are ranked by the money at stake."""

    from lightbulb.intelligence_review import build_intelligence_review

    built: dict[str, Any] = {}

    def attempt(kind: str, factory: Any) -> None:
        try:
            built[kind] = _sealed(factory())
        except LookupError:
            return

    attempt("product_margin", lambda: build_product_margin_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("product_portfolio", lambda: build_product_portfolio_document(console, now=now, window_start=window_start, window_end=window_end, previous_window_start=previous_window_start))
    attempt("price_probes", lambda: build_price_probes_document(console, now=now, window_start=window_start, window_end=window_end, previous_window_start=previous_window_start))
    if previous_window_start is not None:
        attempt("contribution_bridge", lambda: build_contribution_bridge_document(console, now=now, previous_window_start=previous_window_start, window_start=window_start or _window(now, None, window_end)[0], window_end=window_end))
    attempt("customer_profitability", lambda: build_customer_profitability_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("supplier_scorecard", lambda: build_supplier_scorecard_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("job_costing", lambda: build_job_costing_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("open_to_buy", lambda: build_open_to_buy_document(console, now=now, window_start=window_start, window_end=window_end, previous_window_start=previous_window_start))
    attempt("working_capital", lambda: build_working_capital_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("books_snapshot", lambda: latest_books_snapshot(console))
    attempt("customer_ledger", lambda: latest_customer_ledger(console))
    attempt("ledger_tie_out", lambda: build_tie_out_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("break_even", lambda: build_break_even_document(console, now=now, window_start=window_start, window_end=window_end, profiles=profiles))
    attempt("customer_cohorts", lambda: build_customer_cohorts_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("stockouts", lambda: build_stockouts_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("returns_ledger", lambda: build_returns_ledger_document(console, now=now, window_start=window_start, window_end=window_end))
    attempt("services_margin", lambda: build_services_margin_document(console, now=now, window_start=window_start, window_end=window_end, profiles=profiles))
    attempt("rate_card", lambda: build_rate_card_document(console, now=now, window_start=window_start, window_end=window_end, profiles=profiles))
    supplied = {str(kind): value for kind, value in dict(documents or {}).items() if value is not None}
    prior = previous if previous is not None else (latest_intelligence_review(console, before=timestamp(now, field_name="now")) if carry else None)
    ledger = None if prior is None else latest_review_decisions(console, str(dict(prior)["review_ref"]))
    if ledger is not None and ledger.get("review_digest") != dict(prior)["review_digest"]:
        ledger = None
    review = build_intelligence_review(review_ref=review_ref, company_ref=console.bundle.company_ref, currency=console.bundle.operating_plan.blueprint.currency, as_of=timestamp(now, field_name="now"), max_age_days=int(max_age_days), documents={**built, **supplied}, previous=prior, decisions=ledger)
    return {**review.to_dict(), "documents_built": built, "summary": review.render(), "provider_effect_executed": False}


INTELLIGENCE_REVIEW_RECORD_SCHEMA = "lightbulb.intelligence_review_record.v1"


def persist_intelligence_review(console: Any, review: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a sealed intelligence review as a version-1 record under its own entity (``review:<ref>``); a second write for the same ref is refused by the store's fence."""

    from lightbulb.intelligence_review import verify_intelligence_review

    verified = verify_intelligence_review(review)
    if verified.company_ref != console.bundle.company_ref or verified.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the review names another company or currency")
    entity_ref = f"review:{verified.review_ref}"
    state = {"schema": INTELLIGENCE_REVIEW_RECORD_SCHEMA, "status": "reviewed", "plan_digest": console.bundle.plan_digest, "version": 1, "state_digest": verified.review_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": verified.as_of, "review": verified.to_dict()}
    record = console.store.put("intelligence_review", entity_ref, state, expected_version=0, expected_state_digest=None)
    return {"entity_ref": entity_ref, "record": record, "review_digest": verified.review_digest}


def persisted_intelligence_reviews(console: Any) -> list[dict[str, Any]]:
    """Every persisted intelligence review for this bundle, newest first."""

    from lightbulb.intelligence_review import verify_intelligence_review

    rows = []
    for record in console.store.list(engine="intelligence_review", limit=200):
        state = dict(record["state"])
        if state.get("schema") != INTELLIGENCE_REVIEW_RECORD_SCHEMA or dict(state.get("scope") or {}).get("company_ref") != console.bundle.scope.get("company_ref"):
            continue
        review = verify_intelligence_review(state["review"])
        if review.company_ref == console.bundle.company_ref:
            rows.append(review.to_dict())
    rows.sort(key=lambda item: str(item["as_of"]), reverse=True)
    return rows


def latest_intelligence_review(console: Any, *, before: str | None = None) -> dict[str, Any] | None:
    for row in persisted_intelligence_reviews(console):
        if before is None or str(row["as_of"]) < before:
            return row
    return None


def build_supplier_scorecard_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed supplier scorecard over the window from every persisted stock position, under the bundle's scorecard plan."""

    from lightbulb.supplier_scorecard import SupplierScorecardPlan, build_supplier_scorecard

    plan = _supporting_plan(console, "supplier_scorecard", SupplierScorecardPlan)
    start, end = _window(now, window_start, window_end)
    card = build_supplier_scorecard(plan, inventory_states=_persisted(console, "inventory_chain"), window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**card.to_dict(), "summary": card.render(), "provider_effect_executed": False}


def build_job_costing_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed job costing over the window from every persisted work order and contractor engagement, under the bundle's costing plan."""

    from lightbulb.job_costing import JobCostingPlan, build_job_costing

    plan = _supporting_plan(console, "job_costing", JobCostingPlan)
    start, end = _window(now, window_start, window_end)
    costing = build_job_costing(plan, work_order_states=_persisted(console, "work_order_chain"), contractor_states=_persisted(console, "contractor_chain"), window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**costing.to_dict(), "summary": costing.render(), "provider_effect_executed": False}


def build_open_to_buy_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, previous_window_start: str | None = None, budget_envelope: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed buy list: the window's portfolio (built now from the persisted commerce chains) sized to the target cover under the bundle's open-to-buy plan, funded inside the supplied envelope or the latest projected treasury period's."""

    from lightbulb.open_to_buy import OpenToBuyPlan, build_open_to_buy

    plan = _supporting_plan(console, "open_to_buy", OpenToBuyPlan)
    built = build_product_portfolio_document(console, now=now, window_start=window_start, window_end=window_end, previous_window_start=previous_window_start)
    portfolio = _sealed(built)
    envelope = budget_envelope
    if envelope is None:
        try:
            envelope = latest_cash_envelope(console, now=now)
        except LookupError:
            envelope = None
    buy = build_open_to_buy(plan, portfolio=portfolio, margin_report=built["documents_built"]["margin_report"], budget_envelope=envelope, as_of=timestamp(now, field_name="now"))
    return {**buy.to_dict(), "documents_built": {"portfolio": portfolio, "margin_report": built["documents_built"]["margin_report"], "budget_envelope": envelope}, "summary": buy.render(), "provider_effect_executed": False}


BOOKS_SNAPSHOT_RECORD_SCHEMA = "lightbulb.books_snapshot_record.v1"


def build_books_snapshot_document(console: Any, *, now: str, sources: Sequence[Mapping[str, Any]], window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed books snapshot from the supplied ledger reads; with no window given, the window is the one the profit and loss report states for itself."""

    from lightbulb.books_snapshot import BooksPlan, build_books_snapshot, report_period

    plan = _supporting_plan(console, "books_snapshot", BooksPlan)
    if window_start is None or window_end is None:
        stated = next((report_period(item["payload"]) for item in sources if isinstance(item, Mapping) and item.get("kind") == "profit_and_loss" and item.get("payload") is not None), None)
        if stated is None:
            raise ValueError("SOURCES_MISSING: the snapshot needs the profit and loss read")
        window_start, window_end = stated[0], stated[1]
    snapshot = build_books_snapshot(plan, sources=sources, window_start=window_start, window_end=window_end, as_of=now)
    return {**snapshot.to_dict(), "summary": snapshot.render(), "provider_effect_executed": False}


def _books_entity(snapshot: Any) -> str:
    return f"books:{snapshot.window_start[:10]}:{snapshot.window_end[:10]}"


def persist_books_snapshot(console: Any, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a sealed books snapshot under its window (``books:<start>:<end>``); a later read of the same window amends it by exactly one version, and an identical one is returned as it stands."""

    from lightbulb.books_snapshot import verify_books_snapshot

    verified = verify_books_snapshot(snapshot)
    if verified.company_ref != console.bundle.company_ref or verified.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the snapshot names another company or currency")
    entity_ref = _books_entity(verified)
    current = next((record for record in console.store.list(engine="books_snapshot", limit=200) if record.get("entity_ref") == entity_ref), None)
    if current is not None and dict(current["state"]).get("state_digest") == verified.snapshot_digest:
        return {"entity_ref": entity_ref, "record": current, "snapshot_digest": verified.snapshot_digest, "unchanged": True}
    version = 1 if current is None else int(dict(current["state"])["version"]) + 1
    # The record's plan is the company's books series: the bundle and the books plan both change as the owner confirms roles, and the series must survive that.
    state = {"schema": BOOKS_SNAPSHOT_RECORD_SCHEMA, "status": "read", "plan_digest": stable_digest({"books_series": console.bundle.company_ref}), "version": version, "state_digest": verified.snapshot_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": verified.as_of, "snapshot": verified.to_dict()}
    record = console.store.put("books_snapshot", entity_ref, state, expected_version=version - 1, expected_state_digest=None if current is None else dict(current["state"])["state_digest"])
    return {"entity_ref": entity_ref, "record": record, "snapshot_digest": verified.snapshot_digest, "unchanged": False}


def persisted_books_snapshots(console: Any) -> list[dict[str, Any]]:
    """Every persisted books snapshot for this bundle, latest window first."""

    from lightbulb.books_snapshot import verify_books_snapshot

    rows = []
    for record in console.store.list(engine="books_snapshot", limit=200):
        state = dict(record["state"])
        if state.get("schema") != BOOKS_SNAPSHOT_RECORD_SCHEMA or dict(state.get("scope") or {}).get("company_ref") != console.bundle.scope.get("company_ref"):
            continue
        snapshot = verify_books_snapshot(state["snapshot"])
        if snapshot.company_ref == console.bundle.company_ref:
            rows.append({**snapshot.to_dict(), "version": int(state["version"])})
    rows.sort(key=lambda item: (str(item["window_end"]), str(item["as_of"])), reverse=True)
    return rows


def books_for_window(console: Any, window_start: str, window_end: str) -> dict[str, Any] | None:
    """The persisted books snapshot covering exactly this window, or ``None``: a document only ever reads books that describe its own window."""

    for row in persisted_books_snapshots(console):
        if row["window_start"] == window_start and row["window_end"] == window_end:
            return {key: value for key, value in row.items() if key != "version"}
    return None


def latest_books_snapshot(console: Any) -> dict[str, Any]:
    rows = persisted_books_snapshots(console)
    if not rows:
        raise LookupError("no books snapshot is persisted; record one with the ledger's profit and loss and balance sheet reads")
    return {key: value for key, value in rows[0].items() if key != "version"}


def build_books_cash_forecast_document(console: Any, *, now: str, horizon_weeks: int = 13, receivables_collected_in_days: int | None = None, payables_paid_in_days: int | None = None, tax_paid_in_days: int | None = None, weekly_receipts_at_run_rate: bool = False) -> dict[str, Any]:
    """The sealed cash calendar from the latest persisted books snapshot.  A timing the caller does not give comes from the bundle's working capital plan (its receivable and payable day targets) when there is one, and is otherwise left unscheduled; the tax timing is only ever the caller's."""

    from lightbulb.books_cash_forecast import build_books_cash_forecast

    books = latest_books_snapshot(console)
    raw = console.bundle.supporting_plans.get("working_capital")
    if raw is not None:
        from lightbulb.working_capital import WorkingCapitalPlan

        targets = _supporting_plan(console, "working_capital", WorkingCapitalPlan)
        receivables_collected_in_days = targets.receivable_days_target if receivables_collected_in_days is None else receivables_collected_in_days
        payables_paid_in_days = targets.payable_days_target if payables_paid_in_days is None else payables_paid_in_days
    calendar = build_books_cash_forecast(books, as_of=timestamp(now, field_name="now"), horizon_weeks=horizon_weeks, receivables_collected_in_days=receivables_collected_in_days, payables_paid_in_days=payables_paid_in_days, tax_paid_in_days=tax_paid_in_days, weekly_receipts_at_run_rate=weekly_receipts_at_run_rate)
    return {**calendar.to_dict(), "summary": calendar.render(), "provider_effect_executed": False}


def build_intelligence_readiness_document(console: Any, *, now: str, connectors_bound: Sequence[str] = ()) -> dict[str, Any]:
    """The sealed readiness of every intelligence document, from the bundle's plans, the state count of every chain a document reads, the recorded books, and the connectors the caller says are bound."""

    from lightbulb.intelligence_readiness import DOCUMENT_REQUIREMENTS, assess_intelligence_readiness

    chains = sorted({chain for need in DOCUMENT_REQUIREMENTS.values() for chain in need["chains"]})
    company = console.bundle.scope.get("company_ref")
    counts = {chain: sum(1 for record in console.store.list(engine=chain, limit=200) if dict(dict(record["state"]).get("scope") or {}).get("company_ref") == company) for chain in chains}
    books = persisted_books_snapshots(console)
    readiness = assess_intelligence_readiness(company_ref=console.bundle.company_ref, as_of=timestamp(now, field_name="now"), plans=sorted(console.bundle.supporting_plans), chain_states=counts, books_recorded=bool(books), books_with_balances=any(row.get("balances_as_at") for row in books), connectors_bound=connectors_bound)
    return {**readiness.to_dict(), "summary": readiness.render(), "provider_effect_executed": False}


# The verbs an answer can be built from with nothing but a window.
_ANSWERABLE_VERBS = frozenset({"break_even", "working_capital", "cash_calendar", "product_margin", "product_portfolio", "price_probes", "customer_profitability", "customer_cohorts", "stockouts", "returns_ledger", "open_to_buy", "supplier_scorecard", "services_margin", "rate_card", "job_costing"})


def answer_company_question(console: Any, *, now: str, question: str, limit: int = 3, connectors_bound: Sequence[str] = ()) -> dict[str, Any]:
    """The documents that answer an owner's question, best first, and the best one built now when it is ready and needs no input.  A document that reads the books is built over the recorded books' own window."""

    from lightbulb.company_questions import match_questions

    readiness = _sealed(build_intelligence_readiness_document(console, now=now, connectors_bound=connectors_bound))
    found = match_questions(question, readiness=readiness, limit=limit)
    answer: dict[str, Any] | None = None
    answered_with = None
    for match in found["matches"]:
        if match["status"] != "ready":
            continue
        verb = match["verb"]
        if verb == "books":
            built = {**latest_books_snapshot(console)}
            from lightbulb.books_snapshot import verify_books_snapshot

            answer = {"verdict": built["verdict"], "summary": verify_books_snapshot(built).render(), "digest": built["snapshot_digest"]}
        elif verb in _ANSWERABLE_VERBS:
            payload: dict[str, Any] = {}
            if match["basis"] == "books" and verb != "cash_calendar":
                books = latest_books_snapshot(console)
                payload = {"window_start": books["window_start"], "window_end": books["window_end"]}
            built = operate_chain(console, verb, operation="build", payload=payload, now=now)
            answer = {"verdict": built.get("verdict") or (built.get("recommendations") or [built.get("summary", "")])[0], "summary": built.get("summary"), "digest": next((value for key, value in built.items() if key.endswith("_digest") and key not in {"plan_digest", "books_digest", "margin_report_digest", "services_margin_digest"}), None)}
        else:
            continue
        answered_with = verb
        break
    return {**found, "answered_with": answered_with, "answer": answer, "readiness_digest": readiness["readiness_digest"], "provider_effect_executed": False}


def build_tie_out_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The tie-out of every chain-built document the bundle's plans allow against the books recorded for the same window.  With no window given, the latest recorded books set it."""

    from lightbulb.ledger_tie_out import TieOutPlan, tie_out_documents

    plan = _supporting_plan(console, "ledger_tie_out", TieOutPlan)
    if window_start is None or window_end is None:
        books = latest_books_snapshot(console)
        window_start, window_end = books["window_start"], books["window_end"]
    else:
        books = books_for_window(console, timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end"))
        if books is None:
            raise LookupError(f"no books snapshot is recorded for {window_start[:10]} to {window_end[:10]}; record the books for that window first")
    documents: dict[str, Any] = {}
    builders = {"product_margin": build_product_margin_document, "services_margin": build_services_margin_document, "break_even": build_break_even_document, "working_capital": build_working_capital_document}
    for kind, builder in builders.items():
        try:
            documents[kind] = _sealed(builder(console, now=now, window_start=window_start, window_end=window_end))
        except LookupError:
            continue
    if not documents:
        raise LookupError("nothing to tie out: the bundle carries none of the product margin, services margin, break-even or working capital plans")
    tie = tie_out_documents(plan, books=books, documents=documents, as_of=timestamp(now, field_name="now"))
    return {**tie.to_dict(), "documents_built": sorted(documents), "summary": tie.render(), "provider_effect_executed": False}


def build_scenario_document(console: Any, *, now: str, scenario_ref: str, levers: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The sealed what-if over the latest recorded books."""

    from lightbulb.company_scenario import run_scenario

    scenario = run_scenario(latest_books_snapshot(console), scenario_ref=scenario_ref, levers=levers, as_of=timestamp(now, field_name="now"))
    return {**scenario.to_dict(), "summary": scenario.render(), "provider_effect_executed": False}


def compare_scenario_documents(console: Any, *, now: str, scenarios: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Several what-ifs over the same recorded books, side by side."""

    from lightbulb.company_scenario import compare_scenarios, run_scenario

    books = latest_books_snapshot(console)
    at = timestamp(now, field_name="now")
    built = [run_scenario(books, scenario_ref=str(item["scenario_ref"]), levers=item["levers"], as_of=at) for item in scenarios]
    comparison = compare_scenarios(built, as_of=at)
    return {**comparison.to_dict(), "scenarios": [item.to_dict() for item in built], "summary": comparison.verdict, "provider_effect_executed": False}


CUSTOMER_LEDGER_RECORD_SCHEMA = "lightbulb.customer_ledger_record.v1"


def build_customer_ledger_document(console: Any, *, now: str, source: Mapping[str, Any], window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed customer ledger from one sales invoice read over the window (default: the last thirty days)."""

    from lightbulb.customer_ledger import CustomerLedgerPlan, build_customer_ledger

    plan = _supporting_plan(console, "customer_ledger", CustomerLedgerPlan)
    start, end = _window(now, window_start, window_end)
    ledger = build_customer_ledger(plan, source=source, window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**ledger.to_dict(), "summary": ledger.render(), "provider_effect_executed": False}


def persist_customer_ledger(console: Any, ledger: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a sealed customer ledger under its window (``customers:<start>:<end>``); a re-read amends by one version, an identical one changes nothing."""

    from lightbulb.customer_ledger import verify_customer_ledger

    verified = verify_customer_ledger(ledger)
    if verified.company_ref != console.bundle.company_ref or verified.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the customer ledger names another company or currency")
    entity_ref = f"customers:{verified.window_start[:10]}:{verified.window_end[:10]}"
    current = next((record for record in console.store.list(engine="customer_ledger", limit=200) if record.get("entity_ref") == entity_ref), None)
    if current is not None and dict(current["state"]).get("state_digest") == verified.ledger_digest:
        return {"entity_ref": entity_ref, "record": current, "ledger_digest": verified.ledger_digest, "unchanged": True}
    version = 1 if current is None else int(dict(current["state"])["version"]) + 1
    state = {"schema": CUSTOMER_LEDGER_RECORD_SCHEMA, "status": "read", "plan_digest": stable_digest({"customer_series": console.bundle.company_ref}), "version": version, "state_digest": verified.ledger_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": verified.as_of, "ledger": verified.to_dict()}
    record = console.store.put("customer_ledger", entity_ref, state, expected_version=version - 1, expected_state_digest=None if current is None else dict(current["state"])["state_digest"])
    return {"entity_ref": entity_ref, "record": record, "ledger_digest": verified.ledger_digest, "unchanged": False}


def persisted_customer_ledgers(console: Any) -> list[dict[str, Any]]:
    from lightbulb.customer_ledger import verify_customer_ledger

    rows = []
    for record in console.store.list(engine="customer_ledger", limit=200):
        state = dict(record["state"])
        if state.get("schema") != CUSTOMER_LEDGER_RECORD_SCHEMA or dict(state.get("scope") or {}).get("company_ref") != console.bundle.scope.get("company_ref"):
            continue
        ledger = verify_customer_ledger(state["ledger"])
        if ledger.company_ref == console.bundle.company_ref:
            rows.append({**ledger.to_dict(), "version": int(state["version"])})
    rows.sort(key=lambda item: (str(item["window_end"]), str(item["as_of"])), reverse=True)
    return rows


def latest_customer_ledger(console: Any) -> dict[str, Any]:
    rows = persisted_customer_ledgers(console)
    if not rows:
        raise LookupError("no customer ledger is persisted; record one from the ledger's sales invoice read")
    return {key: value for key, value in rows[0].items() if key != "version"}


def build_job_assignment_document(console: Any, *, now: str, jobs: Sequence[Mapping[str, Any]], profiles: Sequence[Mapping[str, Any]], taxonomy: Mapping[str, Any] | None = None, match_report: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed assignment of every worker's hours across every supplied job: the bundle's match report (built now unless supplied) allocated so no hour is given twice."""

    from lightbulb.job_assignment import JobAssignmentPlan, assign_jobs

    plan = _supporting_plan(console, "job_assignment", JobAssignmentPlan)
    report = match_report if match_report is not None else _sealed(build_skills_match_document(console, now=now, jobs=jobs, profiles=profiles, taxonomy=taxonomy))
    assignment = assign_jobs(plan, match_report=report, profiles=list(profiles), as_of=timestamp(now, field_name="now"))
    return {**assignment.to_dict(), "documents_built": {"match_report": report}, "summary": assignment.render(), "provider_effect_executed": False}


def history_windows(console: Any, *, now: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Every recorded window, oldest first, assembled from what this bundle has persisted: one window per books snapshot, joined by the customer ledger recorded for the same window, the working capital, break-even and tie-out the bundle's plans allow (built for that window from the persisted chains), and the decision actions still open at the window's end.  A document a window cannot build is named in the gaps and left out of the series."""

    from lightbulb.decision_work_items import plan_decision_work_items

    ledgers = {(row["window_start"], row["window_end"]): {key: value for key, value in row.items() if key != "version"} for row in persisted_customer_ledgers(console)}
    decided = persisted_review_decisions(console)
    builders = (("working_capital", build_working_capital_document), ("break_even", build_break_even_document), ("ledger_tie_out", build_tie_out_document))
    windows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for books in reversed(persisted_books_snapshots(console)):
        start, end = str(books["window_start"]), str(books["window_end"])
        ref = f"books:{start[:10]}:{end[:10]}"
        documents: dict[str, Any] = {"books_snapshot": {key: value for key, value in books.items() if key != "version"}}
        if (start, end) in ledgers:
            documents["customer_ledger"] = ledgers[(start, end)]
        for kind, builder in builders:
            if kind not in console.bundle.supporting_plans:
                continue
            try:
                documents[kind] = _sealed(builder(console, now=end, window_start=start, window_end=end))
            except LookupError as exc:
                gaps.append(f"{ref}: {kind} not built ({str(exc)[:120]})")
        window: dict[str, Any] = {"window_ref": ref, "as_of": end, "documents": documents}
        if decided:
            window["open_actions"] = sum(1 for row in decided for item in plan_decision_work_items({key: value for key, value in row.items() if key != "version"}, as_of=end).items if item.status in ("open", "overdue"))
        windows.append(window)
    if not windows:
        raise LookupError("no books snapshot is persisted; record one window of the ledger's reads before asking for a history")
    return windows, gaps


def build_intelligence_history_document(console: Any, *, now: str, windows: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """The sealed series of headline figures across every recorded window (assembled from the persisted documents unless the windows are supplied), with a warning for each figure that has moved the wrong way three windows running."""

    from lightbulb.intelligence_history import build_history

    assembled, gaps = (list(windows), []) if windows is not None else history_windows(console, now=now)
    history = build_history(assembled, company_ref=console.bundle.company_ref, currency=console.bundle.operating_plan.blueprint.currency, as_of=timestamp(now, field_name="now"))
    return {**history.to_dict(), "gaps": gaps, "summary": history.render(), "provider_effect_executed": False}


def build_threshold_calibration_document(console: Any, *, now: str, minimum_observations: int = 6, windows: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Plan settings proposed from the company's own history by percentile, beside the setting each bundle plan carries now; proposals only, applied by nothing until the owner writes them into the bundle."""

    from lightbulb.intelligence_history import calibrate_thresholds

    history = _sealed(build_intelligence_history_document(console, now=now, windows=windows))
    calibration = calibrate_thresholds({key: value for key, value in history.items() if key != "gaps"}, as_of=timestamp(now, field_name="now"), minimum_observations=int(minimum_observations))
    current = {f"{row.plan}.{row.setting}": (dict(console.bundle.supporting_plans.get(row.plan) or {}).get(row.setting)) for row in calibration.proposals}
    return {**calibration.to_dict(), "current_settings": {key: None if value is None else str(value) for key, value in current.items()}, "documents_built": {"history": history}, "summary": calibration.verdict, "provider_effect_executed": False}


def build_working_capital_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed cash conversion cycle over the window from every persisted receivable, payable, and stock position, with the window's margin report (built now when the bundle carries the product margin plan) pricing the stock's daily cost of goods."""

    from lightbulb.working_capital import WorkingCapitalPlan, build_working_capital

    plan = _supporting_plan(console, "working_capital", WorkingCapitalPlan)
    start, end = _window(now, window_start, window_end)
    report = None
    if "product_margin" in console.bundle.supporting_plans:
        report = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end))
    capital = build_working_capital(plan, collections_states=_persisted(console, "collections_chain"), payables_states=_persisted(console, "payables_chain"), inventory_states=_persisted(console, "inventory_chain"), margin_report=report, books=books_for_window(console, start, end), window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**capital.to_dict(), "documents_built": {"margin_report": report}, "summary": capital.render(), "provider_effect_executed": False}


def build_review_outcomes_document(console: Any, *, now: str, previous: Mapping[str, Any] | None = None, current: Mapping[str, Any] | None = None, previous_ref: str | None = None, current_ref: str | None = None) -> dict[str, Any]:
    """The sealed outcomes of the previous review's actions by the current one: by default the two latest persisted reviews at or before now, or the reviews named by ref, or the supplied sealed reviews."""

    from lightbulb.intelligence_outcomes import score_review_outcomes

    stamp = timestamp(now, field_name="now")
    persisted = [row for row in persisted_intelligence_reviews(console) if str(row["as_of"]) <= stamp]

    def named(ref: str) -> dict[str, Any]:
        for row in persisted:
            if row["review_ref"] == ref:
                return row
        raise LookupError(f"no persisted intelligence review {ref}")

    after = dict(current) if current is not None else (named(current_ref) if current_ref else (persisted[0] if persisted else None))
    if after is None:
        raise LookupError("no persisted intelligence review at or before now; record one first")
    if previous is not None:
        before: dict[str, Any] | None = dict(previous)
    elif previous_ref:
        before = named(previous_ref)
    else:
        before = next((row for row in persisted if str(row["as_of"]) < str(after["as_of"])), None)
    if before is None:
        raise LookupError("fewer than two persisted intelligence reviews at or before now; record the next one first")
    ledger = latest_review_decisions(console, str(before["review_ref"]))
    if ledger is not None and ledger.get("review_digest") != before.get("review_digest"):
        ledger = None
    outcomes = score_review_outcomes(before, after, decisions=ledger)
    return {**outcomes.to_dict(), "summary": outcomes.render(), "provider_effect_executed": False}


def build_break_even_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None, profiles: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The sealed break-even over the window: the margin report and the services margin the bundle's plans allow (built now from the persisted chains) against the fixed cost of every persisted cost register overlapping the window, under the bundle's break-even plan."""

    from lightbulb.break_even import BreakEvenPlan, build_break_even

    plan = _supporting_plan(console, "break_even", BreakEvenPlan)
    start, end = _window(now, window_start, window_end)
    report = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end)) if "product_margin" in console.bundle.supporting_plans else None
    services = _sealed(build_services_margin_document(console, now=now, window_start=start, window_end=end, profiles=profiles)) if "services_margin" in console.bundle.supporting_plans else None
    books = books_for_window(console, start, end)
    if report is None and services is None and books is None:
        raise LookupError("break-even needs a product margin plan, a services margin plan, or a books snapshot recorded for exactly this window")
    document = build_break_even(plan, margin_report=report, services_margin=services, register_states=_persisted(console, "company_cost_centres"), books=books, window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**document.to_dict(), "documents_built": {"margin_report": report, "services_margin": services}, "summary": document.render(), "provider_effect_executed": False}


def build_probe_outcomes_document(console: Any, *, now: str, probes: Mapping[str, Any], window_start: str | None = None, window_end: str | None = None, before: Mapping[str, Any] | None = None, previous_window_start: str | None = None) -> dict[str, Any]:
    """The sealed outcomes of a supplied probe table: the after window's margin report is built now from the persisted commerce chains, and the before report is the supplied one or rebuilt over the window the probes were planned from (the same length ending where this window starts, unless previous_window_start is given)."""

    from datetime import timedelta

    from lightbulb.probe_outcomes import ProbeOutcomesPlan, score_probe_outcomes

    plan = _supporting_plan(console, "probe_outcomes", ProbeOutcomesPlan)
    start, end = _window(now, window_start, window_end)
    after = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end))
    if before is None:
        first = parsed(start)
        if previous_window_start is not None:
            earlier = previous_window_start
        elif first.day == 1 and first.hour == 0 and first.minute == 0:
            earlier = (first.replace(day=1) - timedelta(days=1)).replace(day=1).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            earlier = (first - (parsed(end) - first)).strftime("%Y-%m-%dT%H:%M:%SZ")
        before = _sealed(build_product_margin_document(console, now=now, window_start=earlier, window_end=start))
    outcomes = score_probe_outcomes(plan, probes=probes, before=before, after=after, as_of=timestamp(now, field_name="now"))
    return {**outcomes.to_dict(), "documents_built": {"before": before, "after": after}, "summary": outcomes.render(), "provider_effect_executed": False}


def build_skills_development_document(console: Any, *, now: str, profiles: Sequence[Mapping[str, Any]], jobs: Sequence[Mapping[str, Any]] = (), taxonomy: Mapping[str, Any] | None = None, weeks: int = 8, minimum_depth: int = 2, licence_horizon_days: int = 90) -> dict[str, Any]:
    """The sealed skills development plan: the inventory and, when jobs are supplied, the weekly capacity plan are built now from the supplied profiles and jobs under the bundle's matching plan and taxonomy (every persisted work order credited as evidence), then priced against the bundle's labour sourcing plan under its development plan."""

    from lightbulb.labour_sourcing import LabourSourcingPlan
    from lightbulb.skills_development import SkillsDevelopmentPlan, build_skills_development

    plan = _supporting_plan(console, "skills_development", SkillsDevelopmentPlan)
    market = _supporting_plan(console, "labour_sourcing", LabourSourcingPlan)
    inventory = _sealed(build_skills_inventory_document(console, now=now, profiles=profiles, jobs=jobs, taxonomy=taxonomy, minimum_depth=minimum_depth, licence_horizon_days=licence_horizon_days))
    capacity = _sealed(build_workforce_capacity_document(console, now=now, profiles=profiles, jobs=jobs, taxonomy=taxonomy, weeks=weeks)) if jobs else None
    document = build_skills_development(plan, inventory=inventory, capacity=capacity, sourcing_plan=market, profiles=list(profiles), as_of=timestamp(now, field_name="now"))
    return {**document.to_dict(), "documents_built": {"skills_inventory": inventory, "workforce_capacity": capacity}, "summary": document.render(), "provider_effect_executed": False}


def build_customer_cohorts_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed cohort table over the window from every persisted order (customers first seen in the window), with the window's margin report (built now when the bundle carries the product margin plan) setting the contribution margin and every persisted cost register supplying the acquisition spend by month."""

    from lightbulb.customer_cohorts import CustomerCohortPlan, build_customer_cohorts

    plan = _supporting_plan(console, "customer_cohorts", CustomerCohortPlan)
    start, end = _window(now, window_start, window_end)
    report = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end)) if "product_margin" in console.bundle.supporting_plans else None
    cohorts = build_customer_cohorts(plan, fulfilment_states=_persisted(console, "fulfilment_chain"), register_states=_persisted(console, "company_cost_centres"), margin_report=report, window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**cohorts.to_dict(), "documents_built": {"margin_report": report}, "summary": cohorts.render(), "provider_effect_executed": False}


def build_quote_outcomes_document(console: Any, *, now: str, quotes: Sequence[Mapping[str, Any]], window_start: str | None = None, window_end: str | None = None, contingency_percent: Any = None) -> dict[str, Any]:
    """The sealed outcomes of the supplied sealed quotes against the window's job costing, built now from every persisted work order and contractor engagement under the bundle's costing plan; the contingency carried now defaults to the bundle's job quote plan."""

    from lightbulb.job_quote import JobQuotePlan
    from lightbulb.quote_outcomes import QuoteOutcomesPlan, score_quote_outcomes

    plan = _supporting_plan(console, "quote_outcomes", QuoteOutcomesPlan)
    start, end = _window(now, window_start, window_end)
    costing = _sealed(build_job_costing_document(console, now=now, window_start=start, window_end=end))
    carried = contingency_percent
    if carried is None:
        try:
            carried = _supporting_plan(console, "job_quote", JobQuotePlan).stretch_contingency_percent
        except LookupError:
            carried = "15"
    outcomes = score_quote_outcomes(plan, quotes=list(quotes), costing=costing, contingency_percent=carried, as_of=timestamp(now, field_name="now"))
    return {**outcomes.to_dict(), "documents_built": {"job_costing": costing}, "summary": outcomes.render(), "provider_effect_executed": False}


REVIEW_DECISIONS_RECORD_SCHEMA = "lightbulb.review_decisions_record.v1"


def persisted_review_decisions(console: Any) -> list[dict[str, Any]]:
    """Every persisted decisions ledger for this bundle, newest first."""

    from lightbulb.review_decisions import verify_review_decisions

    rows = []
    for record in console.store.list(engine="intelligence_decisions", limit=200):
        state = dict(record["state"])
        if state.get("schema") != REVIEW_DECISIONS_RECORD_SCHEMA or dict(state.get("scope") or {}).get("company_ref") != console.bundle.scope.get("company_ref"):
            continue
        ledger = verify_review_decisions(state["decisions"])
        if ledger.company_ref == console.bundle.company_ref:
            rows.append({**ledger.to_dict(), "version": int(record["version"])})
    rows.sort(key=lambda item: (str(item["as_of"]), item["review_ref"]), reverse=True)
    return rows


def latest_review_decisions(console: Any, review_ref: str) -> dict[str, Any] | None:
    """The persisted decisions ledger for one review, without the record's version."""

    for row in persisted_review_decisions(console):
        if row["review_ref"] == review_ref:
            return {key: value for key, value in row.items() if key != "version"}
    return None


def persist_review_decisions(console: Any, ledger: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a sealed decisions ledger under its review (``decisions:<review_ref>``); a ledger already recorded advances one version, and an unchanged ledger is refused by the store's fence."""

    from lightbulb.review_decisions import verify_review_decisions

    verified = verify_review_decisions(ledger)
    if verified.company_ref != console.bundle.company_ref or verified.currency != console.bundle.operating_plan.blueprint.currency:
        raise ValueError("SCOPE_MISMATCH: the ledger names another company or currency")
    entity_ref = f"decisions:{verified.review_ref}"
    existing = console.store.get("intelligence_decisions", entity_ref)
    version = 1 if existing is None else int(existing["version"]) + 1
    state = {"schema": REVIEW_DECISIONS_RECORD_SCHEMA, "status": "decided", "plan_digest": console.bundle.plan_digest, "version": version, "state_digest": verified.decisions_digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": verified.as_of, "decisions": verified.to_dict()}
    record = console.store.put("intelligence_decisions", entity_ref, state, expected_version=None if existing is None else int(existing["version"]), expected_state_digest=None if existing is None else str(existing["state_digest"]))
    return {"entity_ref": entity_ref, "record": record, "decisions_digest": verified.decisions_digest, "version": version}


def build_review_decisions_document(console: Any, *, now: str, decisions: Sequence[Mapping[str, Any]] = (), review_ref: str | None = None, review: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The sealed decisions ledger for a persisted review (the latest at or before now unless a ref or a sealed review is supplied): the ledger already recorded for that review, with the supplied decisions merged over it by action key."""

    from lightbulb.review_decisions import decide_review_actions

    stamp = timestamp(now, field_name="now")
    if review is not None:
        target = dict(review)
    elif review_ref is not None:
        target = next((row for row in persisted_intelligence_reviews(console) if row["review_ref"] == review_ref), None)
        if target is None:
            raise LookupError(f"no persisted intelligence review {review_ref}")
    else:
        target = next((row for row in persisted_intelligence_reviews(console) if str(row["as_of"]) <= stamp), None)
        if target is None:
            raise LookupError("no persisted intelligence review at or before now; record one first")
    recorded = latest_review_decisions(console, str(target["review_ref"]))
    merged: dict[str, dict[str, Any]] = {}
    if recorded is not None and recorded.get("review_digest") == target.get("review_digest"):
        for row in recorded["actions"]:
            if row.get("decision") is not None:
                merged[row["key"]] = {"key": row["key"], "decision": row["decision"], "owner_ref": row.get("owner_ref"), "due_at": row.get("due_at"), "decided_at": row.get("decided_at"), "note": row.get("note"), "outcome": row.get("outcome"), "closed_at": row.get("closed_at"), "outcome_note": row.get("outcome_note")}
    for item in decisions:
        raw = dict(item)
        key = str(raw.get("key") or f"{raw.get('source', '')}:{raw.get('kind', '')}:{raw.get('subject', '')}")
        merged[key] = {**merged.get(key, {}), **raw, "key": key}
    ledger = decide_review_actions(target, list(merged.values()), as_of=stamp)
    return {**ledger.to_dict(), "summary": ledger.render(), "provider_effect_executed": False}


def build_stockouts_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed stockout ledger over the window from every persisted stock position, priced at the window's margin report (built now when the bundle carries the product margin plan), under the bundle's stockout plan."""

    from lightbulb.stockouts import StockoutPlan, build_stockouts

    plan = _supporting_plan(console, "stockouts", StockoutPlan)
    start, end = _window(now, window_start, window_end)
    report = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end)) if "product_margin" in console.bundle.supporting_plans else None
    ledger = build_stockouts(plan, inventory_states=_persisted(console, "inventory_chain"), margin_report=report, window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**ledger.to_dict(), "documents_built": {"margin_report": report}, "summary": ledger.render(), "provider_effect_executed": False}


def build_returns_ledger_document(console: Any, *, now: str, window_start: str | None = None, window_end: str | None = None) -> dict[str, Any]:
    """The sealed returns ledger over the window from every persisted order and stock position, priced at the window's margin report (built now when the bundle carries the product margin plan), under the bundle's returns plan."""

    from lightbulb.returns_ledger import ReturnsPlan, build_returns_ledger

    plan = _supporting_plan(console, "returns_ledger", ReturnsPlan)
    start, end = _window(now, window_start, window_end)
    report = _sealed(build_product_margin_document(console, now=now, window_start=start, window_end=end)) if "product_margin" in console.bundle.supporting_plans else None
    ledger = build_returns_ledger(plan, fulfilment_states=_persisted(console, "fulfilment_chain"), inventory_states=_persisted(console, "inventory_chain"), margin_report=report, window_start=start, window_end=end, as_of=timestamp(now, field_name="now"))
    return {**ledger.to_dict(), "documents_built": {"margin_report": report}, "summary": ledger.render(), "provider_effect_executed": False}


def build_decision_work_items_document(console: Any, *, now: str, review_ref: str | None = None) -> dict[str, Any]:
    """The open decision work items at ``now`` for one persisted ledger (by review ref) or for every persisted ledger, each sealed on its own."""

    from lightbulb.decision_work_items import plan_decision_work_items

    stamp = timestamp(now, field_name="now")
    ledgers = persisted_review_decisions(console)
    if review_ref is not None:
        ledgers = [row for row in ledgers if row["review_ref"] == review_ref]
        if not ledgers:
            raise LookupError(f"no persisted decisions ledger for {review_ref}")
    documents = [plan_decision_work_items({key: value for key, value in row.items() if key != "version"}, as_of=stamp).to_dict() for row in ledgers]
    items = [item for document in documents for item in document["items"]]
    items.sort(key=lambda row: (row["status"] != "overdue", row["due_at"], row["item_ref"]))
    return {"schema": "lightbulb.decision_work_items_inventory.v1", "as_of": stamp, "ledgers": documents, "items": items, "open": len(items), "overdue": sum(1 for row in items if row["status"] == "overdue"), "closed": sum(int(document["closed"]) for document in documents), "summary": "\n".join(document["verdict"] for document in documents) or "no persisted decisions ledger", "provider_effect_executed": False}


def operate_chain(console: Any, verb: str, *, operation: str = "list", engine: str | None = None, entity_ref: str | None = None, payload: Mapping[str, Any] | None = None, now: str | None = None) -> dict[str, Any]:
    if verb not in CHAIN_VERBS:
        raise ValueError(f"unknown company chain verb {verb}")
    allowed = CHAIN_VERBS[verb]
    engine = engine or allowed[0]
    if engine not in allowed:
        raise ValueError(f"{verb} does not operate {engine}")
    values = dict(detached(payload or {}))
    at = timestamp(now or console.clock(), field_name="now")
    if engine == "authority_matrix":
        from lightbulb.authority_matrix import AuthorityMatrix, authorize, authority_summary
        if verb == "approvals" and operation in {"list", "summary"}:
            from lightbulb.company_approval_inbox import build_inbox
            inbox = build_inbox(values.get("tasks", ()), states=console._states(), now=at)
            return inbox.to_dict()
        matrix = values.get("matrix") or console.bundle.supporting_plans.get("authority_matrix")
        if matrix is None:
            raise LookupError("the bundle carries no adopted authority matrix")
        matrix = AuthorityMatrix.model_validate(matrix)
        if matrix.company_ref != console.bundle.company_ref or matrix.currency != console.bundle.operating_plan.blueprint.currency:
            raise ValueError("SCOPE_MISMATCH: the authority matrix belongs to another company or currency")
        if operation == "authorize":
            return authorize(**{**values, "matrix": matrix}).to_dict()
        if operation not in {"list", "summary", "plan"}:
            raise ValueError(f"unsupported authority operation {operation}")
        return authority_summary(matrix, now=at, proofs=values.get("proofs", ()), adoption=values.get("adoption"))
    if engine == "company_unit_economics":
        from lightbulb.company_unit_economics import assess_unit_economics, UnitEconomics
        if operation == "assess":
            report = assess_unit_economics(**values)
        else:
            report = UnitEconomics.model_validate(values.get("report", values))
        if report.plan.company_ref != console.bundle.company_ref or report.plan.operating_plan.plan_digest != console.bundle.operating_plan.plan_digest:
            raise ValueError("SCOPE_MISMATCH: unit economics must describe this company's operating plan")
        from lightbulb.company_operating_system import PERIOD_LIFECYCLE
        for source in report.period_sources:
            _, period = PERIOD_LIFECYCLE.bind(source.source_plan, source.source_state)
            _scope(console.bundle, period)
        return report.to_dict()
    if engine == "company_cost_centres" and operation == "record_inference_bill":
        if entity_ref is None or set(values) != {"bill"}:
            raise ValueError("record_inference_bill requires a register entity_ref and a full bill only")
        return record_inference_bill(console, entity_ref, now=at, **values)
    if engine == "demand_envelope" and operation == "open_campaign":
        if entity_ref is None:
            raise ValueError("open_campaign requires the persisted registry entity_ref")
        if set(values) != {"campaign_ref", "envelope_ref", "budget"}:
            raise ValueError("open_campaign requires campaign_ref, envelope_ref and budget only; scope comes from the console")
        return open_claimed_campaign(console, entity_ref, now=at, **values)
    if engine == "cash_position_chain" and operation == "assemble":
        if entity_ref is not None or set(values) - {"period_ref", "as_of", "preparer_ref", "balances", "days_ahead", "documents"} or not {"period_ref", "as_of", "preparer_ref"} <= set(values):
            raise ValueError("assemble requires period_ref, as_of, preparer_ref and balances (optionally days_ahead and documents) only; the entity is cash:<period_ref>")
        return assemble_cash_period(console, str(values["period_ref"]), as_of=str(values["as_of"]), preparer_ref=str(values["preparer_ref"]), balances=values.get("balances", ()), now=at, days_ahead=int(values.get("days_ahead", 30)), documents=values.get("documents", ()))
    if engine == "growth_channel_cohorts":
        if operation not in {"list", "summary", "build"}:
            raise ValueError(f"unsupported cohort operation {operation}")
        return build_channel_cohort_report(console, now=at, attribution=values.get("attribution"))
    if engine == "growth_revenue_model":
        if operation not in {"list", "summary", "build"}:
            raise ValueError(f"unsupported revenue model operation {operation}")
        return build_revenue_model_document(console, now=at, pipeline_forecast=values.get("pipeline_forecast"))
    if engine == "pipeline_coverage":
        if operation not in {"list", "summary", "build"} or "period_ref" not in values or set(values) - {"period_ref", "operating_plan_ref", "revenue_model", "target_amount", "current_sales_heads"}:
            raise ValueError("pipeline coverage takes period_ref and optionally operating_plan_ref, revenue_model, target_amount, current_sales_heads")
        return build_pipeline_coverage_document(console, now=at, **values)
    if engine == "growth_plan_reconciliation":
        if operation not in {"list", "summary", "build"} or "objective" not in values or set(values) - {"objective", "operating_plan_ref", "revenue_model", "assessment"}:
            raise ValueError("objective reconciliation takes objective and optionally operating_plan_ref, revenue_model, assessment")
        return build_objective_plan_document(console, now=at, **values)
    if engine == "growth_channel_allocation":
        if operation not in {"list", "summary", "build"} or "allocation_ref" not in values or set(values) - {"allocation_ref", "funding_gate", "budget_envelope", "attribution"}:
            raise ValueError("channel allocation takes allocation_ref, one of funding_gate or budget_envelope, and optionally attribution")
        return build_channel_allocation_document(console, now=at, **values)
    if engine == "price_catalog" and operation == "draft_from_price_plan":
        if entity_ref is None or not {"price_plan", "version_ref", "drafter_ref", "current_ref"} <= set(values) or set(values) - {"price_plan", "version_ref", "drafter_ref", "current_ref", "item_refs"}:
            raise ValueError("draft_from_price_plan requires the new entity_ref, price_plan, version_ref, drafter_ref, current_ref and optionally item_refs")
        return draft_catalog_from_price_plan(console, entity_ref, now=at, **values)
    if engine == "pipeline_win_loss":
        if operation not in {"list", "summary", "build"} or set(values) - {"facts", "since"}:
            raise ValueError("win/loss takes optional facts and since only")
        return build_win_loss_report(console, now=at, **values)
    if engine == "growth_allocation_outcomes":
        if operation not in {"list", "summary", "build", "score"} or "allocation" not in values or set(values) - {"allocation", "attribution"}:
            raise ValueError("allocation outcomes take the sealed allocation and optionally attribution")
        return score_allocation_document(console, now=at, **values)
    if engine == "growth_operating_review":
        if operation == "list" and not values:
            reviews = persisted_growth_reviews(console)
            return {"schema": "lightbulb.growth_review_inventory.v1", "as_of": at, "reviews": reviews, "count": len(reviews), "provider_effect_executed": False}
        required = {"review_ref", "period_ref", "allocation_ref"}
        if operation not in {"summary", "build", "record"} or not required <= set(values) or set(values) - (required | {"objective", "funding_gate", "budget_envelope", "operating_plan_ref", "current_sales_heads", "attribution", "authorizations", "pipeline_forecast", "assessment", "previous", "carry"}):
            raise ValueError("the growth review takes review_ref, period_ref, allocation_ref, and optionally objective (else the bundle's), funding_gate or budget_envelope (else the latest projected treasury period's), operating_plan_ref, current_sales_heads, attribution, authorizations, pipeline_forecast, assessment, previous, carry; list with no payload returns the persisted reviews")
        built = build_growth_review_document(console, now=at, **values)
        if operation == "record":
            persisted = persist_growth_review(console, _document({key: value for key, value in built.items() if key != "documents_built"}))
            return {**built, "persisted": True, "entity_ref": persisted["entity_ref"]}
        return built
    if engine == "company_adoption":
        if operation == "plan":
            if set(values) != {"sources"}:
                raise ValueError("adoption plan takes sources only")
            return plan_company_adoption(console, now=at, sources=values["sources"])
        if operation == "run":
            if not set(values) <= {"plan", "sources"} or not values:
                raise ValueError("adoption run takes a sealed plan or the sources to plan from")
            return run_company_adoption(console, now=at, plan=values.get("plan"), sources=values.get("sources", ()))
        raise ValueError(f"unsupported adoption operation {operation}")
    if engine == "sales_capacity":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start"}:
            raise ValueError("sales capacity takes an optional window_start only")
        return build_sales_capacity_document(console, now=at, **values)
    if engine == "company_sync":
        if operation == "plan":
            if set(values) != {"sources"}:
                raise ValueError("sync plan takes sources only")
            return plan_company_sync(console, now=at, sources=values["sources"])
        if operation == "run":
            if not set(values) <= {"plan", "sources"} or not values:
                raise ValueError("sync run takes a sealed plan or the sources to plan from")
            return run_company_sync(console, now=at, plan=values.get("plan"), sources=values.get("sources", ()))
        raise ValueError(f"unsupported sync operation {operation}")
    if engine == "product_margin":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("product margin takes an optional window_start and window_end")
        return build_product_margin_document(console, now=at, **values)
    if engine == "product_portfolio":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end", "previous_window_start"}:
            raise ValueError("product portfolio takes an optional window_start, window_end, and previous_window_start")
        return build_product_portfolio_document(console, now=at, **values)
    if engine == "skills_matching":
        if operation not in {"match", "summary", "build"} or not {"jobs", "profiles"} <= set(values) or set(values) - {"jobs", "profiles", "taxonomy"}:
            raise ValueError("skills takes jobs and profiles, and optionally a taxonomy (else the bundle's)")
        return build_skills_match_document(console, now=at, **values)
    if engine == "labour_sourcing":
        if operation not in {"plan", "summary", "build"} or not {"jobs", "profiles"} <= set(values) or set(values) - {"jobs", "profiles", "taxonomy", "match_report"}:
            raise ValueError("sourcing takes jobs and profiles, and optionally a taxonomy and a sealed match report (else they are the bundle's and built now)")
        return build_labour_sourcing_document(console, now=at, **values)
    if engine == "services_margin":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end", "profiles"}:
            raise ValueError("services margin takes an optional window_start, window_end, and profiles")
        return build_services_margin_document(console, now=at, **values)
    if engine == "skills_inventory":
        if operation not in {"list", "summary", "build"} or "profiles" not in values or set(values) - {"profiles", "jobs", "taxonomy", "minimum_depth", "licence_horizon_days"}:
            raise ValueError("skills inventory takes profiles, and optionally jobs, a taxonomy, minimum_depth, and licence_horizon_days")
        return build_skills_inventory_document(console, now=at, **values)
    if engine == "price_probes":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end", "previous_window_start"}:
            raise ValueError("price probes take an optional window_start, window_end, and previous_window_start")
        return build_price_probes_document(console, now=at, **values)
    if engine == "contribution_bridge":
        if operation not in {"list", "summary", "build"} or not {"previous_window_start", "window_start"} <= set(values) or set(values) - {"previous_window_start", "window_start", "window_end"}:
            raise ValueError("the contribution bridge takes previous_window_start and window_start, and optionally window_end")
        return build_contribution_bridge_document(console, now=at, **values)
    if engine == "rate_card":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end", "profiles"}:
            raise ValueError("the rate card takes an optional window_start, window_end, and profiles")
        return build_rate_card_document(console, now=at, **values)
    if engine == "workforce_capacity":
        if operation not in {"list", "summary", "build", "plan"} or not {"profiles", "jobs"} <= set(values) or set(values) - {"profiles", "jobs", "taxonomy", "weeks"}:
            raise ValueError("workforce capacity takes profiles and jobs, and optionally a taxonomy and weeks")
        return build_workforce_capacity_document(console, now=at, **values)
    if engine == "job_quote":
        if operation not in {"quote", "summary", "build"} or not {"job", "profiles"} <= set(values) or set(values) - {"job", "profiles", "offered_price", "taxonomy"}:
            raise ValueError("the job quote takes a job and profiles, and optionally an offered_price and a taxonomy")
        return build_job_quote_document(console, now=at, **values)
    if engine == "customer_profitability":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end", "target_margin_percent", "return_rate_threshold_percent", "core_share_percent"}:
            raise ValueError("customer profitability takes an optional window_start, window_end, target_margin_percent, return_rate_threshold_percent, and core_share_percent")
        return build_customer_profitability_document(console, now=at, **values)
    if engine == "intelligence_review":
        if operation == "list" and not values:
            reviews = persisted_intelligence_reviews(console)
            return {"schema": "lightbulb.intelligence_review_inventory.v1", "as_of": at, "reviews": reviews, "count": len(reviews), "provider_effect_executed": False}
        if operation not in {"build", "summary", "review", "record"} or "review_ref" not in values or set(values) - {"review_ref", "documents", "window_start", "window_end", "previous_window_start", "profiles", "max_age_days", "previous", "carry"}:
            raise ValueError("the intelligence review takes review_ref, and optionally documents, window_start, window_end, previous_window_start, profiles, max_age_days, previous, and carry; list with no payload returns the persisted reviews")
        built = build_intelligence_review_document(console, now=at, **values)
        if operation == "record":
            persisted = persist_intelligence_review(console, _sealed(built))
            return {**built, "persisted": True, "entity_ref": persisted["entity_ref"]}
        return built
    if engine == "supplier_scorecard":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("the supplier scorecard takes an optional window_start and window_end")
        return build_supplier_scorecard_document(console, now=at, **values)
    if engine == "job_costing":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("job costing takes an optional window_start and window_end")
        return build_job_costing_document(console, now=at, **values)
    if engine == "open_to_buy":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end", "previous_window_start", "budget_envelope"}:
            raise ValueError("open to buy takes an optional window_start, window_end, previous_window_start, and budget_envelope")
        return build_open_to_buy_document(console, now=at, **values)
    if engine == "intelligence_history":
        if operation not in {"build", "list", "summary"} or set(values) - {"windows"}:
            raise ValueError("history takes an optional windows list (else every recorded window is assembled)")
        return build_intelligence_history_document(console, now=at, **values)
    if engine == "threshold_calibration":
        if operation not in {"build", "propose", "summary"} or set(values) - {"minimum_observations", "windows"}:
            raise ValueError("calibrate takes an optional minimum_observations (default 6) and windows list")
        return build_threshold_calibration_document(console, now=at, **values)
    if engine == "job_assignment":
        if operation not in {"build", "assign", "summary"} or not {"jobs", "profiles"} <= set(values) or set(values) - {"jobs", "profiles", "taxonomy", "match_report"}:
            raise ValueError("the assignment takes jobs and profiles, and optionally a taxonomy and a match_report (else the bundle's, built now)")
        return build_job_assignment_document(console, now=at, **values)
    if engine == "customer_ledger":
        if operation == "list":
            if values:
                raise ValueError("listing the customer ledgers takes no payload")
            rows = persisted_customer_ledgers(console)
            return {"ledgers": rows, "count": len(rows), "provider_effect_executed": False}
        if operation not in {"build", "record"} or set(values) - {"source", "window_start", "window_end"} or "source" not in values:
            raise ValueError("the customer ledger takes source (the sales invoice read) and an optional window_start and window_end; operations are build, record and list")
        built = build_customer_ledger_document(console, now=at, **values)
        if operation == "record":
            persisted = persist_customer_ledger(console, {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed"}})
            return {**built, "entity_ref": persisted["entity_ref"], "version": int(dict(persisted["record"]["state"])["version"]), "unchanged": persisted["unchanged"]}
        return built
    if engine == "company_scenario":
        if operation == "compare":
            if set(values) != {"scenarios"}:
                raise ValueError("what_if compare takes scenarios: [{scenario_ref, levers}]")
            return compare_scenario_documents(console, now=at, **values)
        if operation not in {"build", "run", "list"} or set(values) != {"scenario_ref", "levers"}:
            raise ValueError("what_if takes scenario_ref and levers (build), or scenarios (compare)")
        return build_scenario_document(console, now=at, **values)
    if engine == "ledger_tie_out":
        if operation not in {"list", "summary", "build"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("the tie-out takes an optional window_start and window_end")
        return build_tie_out_document(console, now=at, **values)
    if engine == "intelligence_readiness":
        if operation not in {"list", "summary", "build"} or set(values) - {"connectors_bound"}:
            raise ValueError("readiness takes an optional connectors_bound list")
        return build_intelligence_readiness_document(console, now=at, **values)
    if engine == "company_questions":
        if operation not in {"ask", "build", "list"} or set(values) - {"question", "limit", "connectors_bound"} or "question" not in values:
            raise ValueError("ask takes a question and an optional limit and connectors_bound list")
        return answer_company_question(console, now=at, **values)
    if engine == "books_cash_forecast":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"horizon_weeks", "receivables_collected_in_days", "payables_paid_in_days", "tax_paid_in_days", "weekly_receipts_at_run_rate"}:
            raise ValueError("the cash calendar takes an optional horizon_weeks, receivables_collected_in_days, payables_paid_in_days, tax_paid_in_days and weekly_receipts_at_run_rate")
        return build_books_cash_forecast_document(console, now=at, **values)
    if engine == "books_snapshot":
        if operation == "list":
            if values:
                raise ValueError("listing the books snapshots takes no payload")
            rows = persisted_books_snapshots(console)
            return {"snapshots": rows, "count": len(rows), "provider_effect_executed": False}
        if operation not in {"build", "record"} or set(values) - {"sources", "window_start", "window_end"} or "sources" not in values:
            raise ValueError("the books take sources (the profit and loss read and, optionally, the balance sheet read) and an optional window_start and window_end; operations are build, record and list")
        built = build_books_snapshot_document(console, now=at, **values)
        if operation == "record":
            persisted = persist_books_snapshot(console, {key: value for key, value in built.items() if key not in {"summary", "provider_effect_executed"}})
            return {**built, "entity_ref": persisted["entity_ref"], "version": int(dict(persisted["record"]["state"])["version"]), "unchanged": persisted["unchanged"]}
        return built
    if engine == "working_capital":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("working capital takes an optional window_start and window_end")
        return build_working_capital_document(console, now=at, **values)
    if engine == "review_outcomes":
        if operation not in {"list", "summary", "build", "score"} or set(values) - {"previous", "current", "previous_ref", "current_ref"}:
            raise ValueError("review outcomes take optional previous and current reviews, or previous_ref and current_ref; with no payload the two latest persisted reviews are scored")
        return build_review_outcomes_document(console, now=at, **values)
    if engine == "break_even":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end", "profiles"}:
            raise ValueError("break-even takes an optional window_start, window_end, and profiles")
        return build_break_even_document(console, now=at, **values)
    if engine == "probe_outcomes":
        if operation not in {"list", "summary", "build", "score"} or "probes" not in values or set(values) - {"probes", "window_start", "window_end", "before", "previous_window_start"}:
            raise ValueError("probe outcomes take the sealed probes, and optionally window_start, window_end, before, and previous_window_start")
        return build_probe_outcomes_document(console, now=at, **values)
    if engine == "skills_development":
        if operation not in {"list", "summary", "build", "plan"} or "profiles" not in values or set(values) - {"profiles", "jobs", "taxonomy", "weeks", "minimum_depth", "licence_horizon_days"}:
            raise ValueError("skills development takes profiles, and optionally jobs, a taxonomy, weeks, minimum_depth, and licence_horizon_days")
        return build_skills_development_document(console, now=at, **values)
    if engine == "customer_cohorts":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("customer cohorts take an optional window_start and window_end")
        return build_customer_cohorts_document(console, now=at, **values)
    if engine == "quote_outcomes":
        if operation not in {"list", "summary", "build", "score"} or "quotes" not in values or set(values) - {"quotes", "window_start", "window_end", "contingency_percent"}:
            raise ValueError("quote outcomes take the sealed quotes, and optionally window_start, window_end, and contingency_percent")
        return build_quote_outcomes_document(console, now=at, **values)
    if engine == "review_decisions":
        if operation == "list" and not values:
            ledgers = persisted_review_decisions(console)
            return {"schema": "lightbulb.review_decisions_inventory.v1", "as_of": at, "ledgers": ledgers, "count": len(ledgers), "provider_effect_executed": False}
        if operation not in {"build", "summary", "decide", "record"} or set(values) - {"decisions", "review_ref", "review"}:
            raise ValueError("review decisions take decisions, and optionally review_ref or a sealed review; list with no payload returns the persisted ledgers")
        built = build_review_decisions_document(console, now=at, **values)
        if operation == "record":
            persisted = persist_review_decisions(console, _sealed(built))
            return {**built, "persisted": True, "entity_ref": persisted["entity_ref"], "version": persisted["version"]}
        return built
    if engine == "stockouts":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("stockouts take an optional window_start and window_end")
        return build_stockouts_document(console, now=at, **values)
    if engine == "returns_ledger":
        if operation not in {"list", "summary", "build", "plan"} or set(values) - {"window_start", "window_end"}:
            raise ValueError("the returns ledger takes an optional window_start and window_end")
        return build_returns_ledger_document(console, now=at, **values)
    if engine == "decision_work_items":
        if operation not in {"list", "summary", "build"} or set(values) - {"review_ref"}:
            raise ValueError("decision work items take an optional review_ref")
        return build_decision_work_items_document(console, now=at, **values)
    if engine == "company_cap_table":
        if operation not in {"list", "summary", "build"}:
            raise ValueError(f"unsupported cap table operation {operation}")
        return build_cap_table_register(console, now=at)
    surface = CompanyOperatorSurface(console)
    runtime = surface.runtime(engine)
    if operation in {"advance", "supply"}:
        if entity_ref is None or "event" not in values:
            raise ValueError("advance requires entity_ref and event")
        return surface.supply(engine, entity_ref, now=at, **values)
    if operation == "open":
        if entity_ref is None:
            raise ValueError("open requires an explicit entity_ref")
        scope = console.bundle.engine_scope(entity_ref)
        state = runtime.spec.open(runtime.plan, scope, receipt=opening_receipt(runtime.spec, scope, values.get("receipt", values)), opened_at=at, actor_ref=console.bundle.actor_ref)
        record = runtime.open(entity_ref, state)
        return {"schema": "lightbulb.company_chain_operation.v1", "engine": engine, "entity_ref": entity_ref, "persisted": True, "state": state.to_dict(), "record": record, "provider_effect_executed": False}
    if operation not in {"list", "summary", "plan"}:
        raise ValueError(f"unsupported chain operation {operation}")
    rows = []
    records = [console.store.get(engine, entity_ref)] if entity_ref else console.store.list(engine=engine, limit=200)
    for record in records:
        if record is None:
            raise LookupError(f"{engine} {entity_ref} is not persisted")
        _, state = runtime.spec.bind(runtime.plan, record["state"])
        _scope(console.bundle, state)
        events = [event for (status, event) in runtime.spec.table if status == state.status]
        rows.append({"entity_ref": state.scope.entity_ref, "status": state.status, "source_digest": state.state_digest, "ledger": state.ledger.to_dict(), "legal_events": [{"event": event, "required_receipt_fields": list(receipt_requirements(runtime.spec, event))} for event in events]})
    report = {"schema": "lightbulb.company_chain_inventory.v1", "verb": verb, "engine": engine, "as_of": at, "plan_digest": runtime.plan.plan_digest, "states": rows, "provider_effect_executed": False}
    return {**report, "report_digest": stable_digest(report)}


__all__ = ["CompanyOperatorSurface", "operate_chain", "open_claimed_campaign"]
