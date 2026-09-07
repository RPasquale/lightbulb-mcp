"""Shared operator routes for the Round 5 lifecycles and their source plans."""
from collections.abc import Mapping
import ast
import inspect
import textwrap
from typing import Any

from lightbulb.company_engine_core import detached

CHAIN_MODULES = {
    "company_cost_centres": "company_cost_centres", "payroll_run_chain": "payroll_run_chain",
    "bank_reconciliation": "bank_reconciliation", "subscription_chain": "subscription_chain",
    "storefront_settlement_chain": "storefront_settlement_chain", "collections_chain": "collections_chain",
    "spend_control_chain": "spend_control_chain", "vendor_commitment": "spend_control_chain",
    "disbursement_run": "disbursement_run", "agreement_chain": "obligation_paper",
    "company_standing": "obligation_paper", "deal_desk_engine": "deal_desk_engine",
    "contact_endpoint": "permission_register", "claim_register": "permission_register",
    "people_engine": "people_engine", "marketplace_seller": "marketplace_supply_engine",
    "marketplace_listing": "marketplace_supply_engine", "marketplace_supply_engine": "marketplace_supply_engine",
    "engagement_engine": "engagement_engine", "wip_billing": "wip_billing",
    "payout_chain": "payout_chain", "custodial_funds": "custodial_funds",
    "refund_and_dispute_chain": "refund_and_dispute_chain",
}
CHAIN_MODULES["content_asset_lifecycle"] = "content_asset_lifecycle"
CHAIN_MODULES.update({"demand_envelope": "growth_paced_envelope", 'company_provisioning': 'company_provisioning', 'employment_chain': 'employment_chain', 'job_chain': 'job_chain', 'wind_down_chain': 'wind_down_chain', 'company_launch': 'launch_plan', 'local_presence_engine': 'local_presence_engine', 'local_presence_review': 'local_presence_engine'})
OPERATOR_CHAIN_MODULES = {**CHAIN_MODULES, "revenue_chain": "revenue_chain", "payables_chain": "payables_chain", "retention_chain": "retention_chain", "compliance_obligation": "compliance_calendar", "exception_case": "exceptions_desk"}
CHAIN_VERBS = {
    "revenue": ("revenue_chain",), "payables": ("payables_chain",), "renewals": ("retention_chain",),
    "obligations": ("compliance_obligation",), "exception_cases": ("exception_case",),
    "costs": ("company_cost_centres",), "coverage": ("company_cost_centres",),
    "payroll": ("payroll_run_chain",), "pay_run": ("payroll_run_chain",),
    "bank": ("bank_reconciliation",), "reconcile_bank": ("bank_reconciliation",),
    "subscriptions": ("subscription_chain",), "dunning": ("subscription_chain",),
    "storefront": ("storefront_settlement_chain",), "settlements": ("storefront_settlement_chain",),
    "authority": ("authority_matrix",), "approvals": ("authority_matrix",),
    "collections": ("collections_chain",), "receivables": ("collections_chain",),
    "spend": ("spend_control_chain",), "vendors": ("vendor_commitment",), "commitments": ("vendor_commitment",),
    "disbursements": ("disbursement_run",), "pay_run_batch": ("disbursement_run",),
    "agreements": ("agreement_chain",), "standing": ("company_standing",), "cover": ("company_standing",),
    "deals": ("deal_desk_engine",), "quotes": ("deal_desk_engine",), "price_book": ("deal_desk_engine",),
    "consent": ("contact_endpoint",), "claims": ("claim_register",), "suppression": ("contact_endpoint",),
    "people": ("people_engine",), "marketplace_supply": ("marketplace_seller", "marketplace_listing", "marketplace_supply_engine"),
    "engagements": ("engagement_engine",), "wip": ("wip_billing",), "payouts": ("payout_chain",),
    "custody": ("custodial_funds",), "refunds": ("refund_and_dispute_chain",),
    "unit_economics": ("company_unit_economics",),
}
CHAIN_VERBS["content_assets"] = ("content_asset_lifecycle",)
CHAIN_VERBS.update({"demand_budget": ("demand_envelope",), 'provisioning': ('company_provisioning',), 'employees': ('employment_chain',), 'people_ops': ('employment_chain',), 'jobs': ('job_chain',), 'wind_down': ('wind_down_chain',), 'closure': ('wind_down_chain',), 'launch': ('company_launch',), 'listings': ('local_presence_engine',), 'reviews': ('local_presence_review',)})
CHAIN_ACTION_KINDS = {"payroll_run_chain": "run_payroll", "disbursement_run": "assemble_disbursement", "spend_control_chain": "code_spend", "bank_reconciliation": "reconcile_bank", "agreement_chain": "advance_obligation", "company_standing": "advance_obligation", "exception_case": "triage_exception"}


def plan_for_chain(bundle: Any, engine: str) -> Any:
    values = {"people_engine": bundle.people_plan, "marketplace_supply_engine": bundle.marketplace_supply_plan,
              "marketplace_seller": bundle.marketplace_supply_plan, "marketplace_listing": bundle.marketplace_supply_plan,
              "engagement_engine": bundle.engagement_plan}
    raw = bundle.supporting_plans.get(engine) or bundle.supporting_plans.get(OPERATOR_CHAIN_MODULES.get(engine, engine)) or values.get(engine)
    if raw is None:
        raise LookupError(f"the bundle carries no sealed plan for {engine}")
    from lightbulb.company_plan_migration import lifecycle_for
    plan = lifecycle_for(engine).plan_model.model_validate(detached(raw))
    if getattr(plan, "company_ref", bundle.company_ref) != bundle.company_ref:
        raise ValueError("SCOPE_MISMATCH: the chain plan must name this company")
    if getattr(plan, "currency", bundle.operating_plan.blueprint.currency) != bundle.operating_plan.blueprint.currency:
        raise ValueError("ENGINE_CURRENCY_MISMATCH: the chain must use the company's currency")
    return plan


def receipt_requirements(spec: Any, event: str) -> tuple[str, ...]:
    """Describe receipt fields read by the actual event branch; guards decide alternatives."""
    names = set()
    visited = set()
    def scan(function: Any, depth: int = 0) -> None:
        if function in visited or depth > 5 or not inspect.isfunction(function) or function.__module__ != spec.apply.__module__:
            return
        visited.add(function)
        tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
        branches = []
        event_branches = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            constants = {part.value for part in ast.walk(node.test) if isinstance(part, ast.Constant) and isinstance(part.value, str)}
            if constants.intersection(spec.events):
                event_branches = True
            if event in constants:
                branches.extend(node.body)
        if not event_branches:
            branches = [tree]
        for branch in branches:
            for part in ast.walk(branch):
                if isinstance(part, ast.Attribute) and isinstance(part.value, ast.Name) and part.value.id in {"r", "receipt"} and part.attr in spec.receipt_model.model_fields:
                    names.add(part.attr)
                if isinstance(part, ast.Call) and isinstance(part.func, ast.Name):
                    called = function.__globals__.get(part.func.id)
                    if inspect.isfunction(called):
                        scan(called, depth + 1)
    scan(spec.apply)
    names -= {"evidence_refs", "entity_scope", "scope_binding", "register_scope"}
    return tuple(sorted(names))[:24]


def opening_receipt(spec: Any, scope: Any, receipt: Mapping[str, Any]) -> dict[str, Any]:
    fields = spec.receipt_model.model_fields
    supplied = dict(detached(receipt))
    for name in ("entity_scope", "scope_binding", "register_scope", "paper_scope", "registry_scope"):
        if name in fields:
            supplied[name] = detached(scope)
    if "entity_ref" in fields:
        supplied["entity_ref"] = detached(scope)["entity_ref"]
    return supplied


__all__ = ["CHAIN_MODULES", "OPERATOR_CHAIN_MODULES", "CHAIN_VERBS", "CHAIN_ACTION_KINDS", "plan_for_chain", "receipt_requirements", "opening_receipt"]


def chain_runtime(bundle: Any, engine: str, store: Any, *, approval_requester: Any = None) -> Any:
    """Use the lifecycle's authoritative approval lane at every operator entry."""
    from lightbulb.company_plan_migration import lifecycle_for
    from lightbulb.company_engine_store import EngineRuntime
    plan = plan_for_chain(bundle, engine)
    if engine == "company_launch":
        from lightbulb.launch_plan import launch_runtime
        return launch_runtime(plan, store, approval_requester=approval_requester)
    lifecycle = lifecycle_for(engine)
    return EngineRuntime(spec=lifecycle.spec, engine=engine, plan=plan, store=store, advance=lifecycle.advance, approval_engine=OPERATOR_CHAIN_MODULES.get(engine, engine), approval_requester=approval_requester)
