"""Reviewable chain operations over the existing scoped store and approval bridge.

Commands never execute a provider effect. They consume retained observations,
governed execution receipts and human authority proofs through real lifecycles.
"""
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from lightbulb.company_chain_catalog import OPERATOR_CHAIN_MODULES as CHAIN_MODULES, CHAIN_VERBS, opening_receipt, plan_for_chain, receipt_requirements
from lightbulb.company_engine_core import detached, stable_digest, timestamp
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
