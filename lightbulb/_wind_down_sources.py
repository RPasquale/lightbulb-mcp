"""Canonical retained sources for company wind-down; no effect authority."""
from __future__ import annotations
from typing import Any
from lightbulb.company_engine_core import detached, parsed, same_scope, EngineScope

TARGETS = {
    "job_chain": "job_chain",
    "engagement_engine": "engagement_engine",
    "refund_and_dispute_chain": "refund_and_dispute_chain",
    "spend_control_chain": "vendor_commitment",
    "subscription_chain": "subscription_chain",
    "collections_chain": "collections_chain",
    "payables_chain": "payables_chain",
    "disbursement_run": "disbursement_run",
    "employment_chain": "employment_chain",
    "payroll_run_chain": "payroll_run_chain",
    "obligation_paper": "company_standing",
    "compliance_calendar": "compliance_obligation",
    "bank_reconciliation": "bank_reconciliation",
    "finance_close": "finance_close",
    "company_cost_centres": "company_cost_centres",
}

def replay(engine: str, plan: Any, state: Any):
    from lightbulb.company_plan_migration import lifecycle_for
    if engine not in TARGETS or plan is None or state is None:
        raise ValueError("WIND_DOWN_SOURCE_REQUIRED: retain the full canonical source plan and state")
    return lifecycle_for(TARGETS[engine]).spec.bind(plan, state)

def source_facts(engine: str, plan: Any, state: Any) -> dict[str, Any]:
    policy, bound = replay(engine, plan, state)
    ledger = detached(bound.ledger)
    at = bound.transition_history[-1].command.occurred_at
    ref_key = {
        "refund_and_dispute_chain":"refund_ref", "collections_chain":"invoice_ref",
        "payables_chain":"bill_ref", "payroll_run_chain":"run_ref",
        "employment_chain":"payroll_worker_ref", "obligation_paper":"item_ref",
        "compliance_calendar":"obligation_ref", "bank_reconciliation":"account_ref",
        "finance_close":"close_ref", "company_cost_centres":"period_ref",
    }.get(engine)
    facts = dict(engine=engine, entity_ref=ledger.get(ref_key) or bound.scope.entity_ref,
        status=bound.status, state_digest=bound.state_digest, plan_digest=policy.plan_digest,
        currency=bound.scope.currency, settled_at=at)
    amounts = {
        "refund_and_dispute_chain":"cash_out", "spend_control_chain":"amount",
        "subscription_chain":"mrr", "collections_chain":
            "recovered_amount" if bound.status == "recovered" else "write_off_amount" if bound.status == "written_off" else "balance",
        "payables_chain":"applied_amount", "disbursement_run":"settled_total",
        "payroll_run_chain":"net", "bank_reconciliation":"statement_closing",
    }
    if engine in amounts:
        facts["amount"] = ledger[amounts[engine]]
    for key in ("period_start", "period_end", "kind"):
        if ledger.get(key) is not None:
            facts[key] = ledger[key]
    if engine == "employment_chain":
        facts.update(opened_at=ledger.get("offboarding_initiated_at"),
            settled_at=ledger.get("last_working_at"), detail=ledger.get("final_pay_run_ref"))
    if engine == "payroll_run_chain":
        facts["reserved"] = ledger["liabilities_reserved"]
    return facts

def validate_scope(engine: str, plan: Any, state: Any, *, company_ref: str, scope: Any, at: str):
    policy, bound = replay(engine, plan, state)
    company = getattr(policy, "company_ref", None)
    if company is None:
        company = getattr(getattr(policy, "blueprint", None), "company_ref", None)
    # Finance-close blueprints are reusable accounting policy, while the state
    # is always bound to the concrete company execution scope.
    if (company is not None and company != company_ref) or not same_scope(bound.scope, EngineScope.model_validate(detached(scope))):
        raise ValueError("WIND_DOWN_SOURCE_SCOPE_MISMATCH: source belongs to another company or execution scope")
    if parsed(bound.transition_history[-1].command.occurred_at) > parsed(at):
        raise ValueError("WIND_DOWN_SOURCE_IN_FUTURE: source was not available at this wind-down step")
    return bound
