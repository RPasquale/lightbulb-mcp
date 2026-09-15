"""The engine golden-loop registry: every loop key the engines and chains declare, joined to what implements it.

Two loop vocabularies grew side by side.  ``reference_golden_loops`` holds
the formally catalogued ``LoopCertificationManifest`` records (eight loops,
each with certification tests, surfaces and budgets).  Every engine and chain
module also declares a ``*_GOLDEN_LOOP`` string such as
``saas.launched_product_to_compounding_revenue@0.1.0`` and files its
lifecycle under it, but nothing collected those keys: the primitive manifest
only knew the catalogued eight, so most primitives carried no loop
membership and the developer reference could not say which lifecycle proves
which loop.

This module reads the keys off the modules themselves (a loop that is not
declared by a module does not exist here), joins them to the registered
lifecycle engines that carry the key, and adds the reviewed, static part: a
title, the business function, the archetypes the loop serves, the primitives
that enter it, and the loop it hands off to.  ``loop_memberships`` feeds the
primitive manifest; ``engine_loops`` feeds the business process map and the
company reference.  Nothing here executes a loop.
"""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, model_validator

from lightbulb.company_engine_core import ShortText, StrictModel, stable_digest

ENGINE_LOOP_REGISTRY_SCHEMA = "lightbulb.engine_golden_loop_registry.v1"
LoopStatus = Literal["modelled", "partial"]

#: Modules that declare a loop key but register no lifecycle in
#: ``company_plan_migration`` (pack loops with their own state machines).
PACK_LOOP_MODULES: tuple[str, ...] = (
    "lightbulb.appointment_business_loop",
    "lightbulb.business_artifact_production",
    "lightbulb.contract_delivery_acceptance",
    "lightbulb.marketplace_business_loop",
    "lightbulb.product_commerce_loop",
    "lightbulb.saas_product_loop",
    "lightbulb.service_business_loop",
    "lightbulb.service_engagement",
    "lightbulb.software_production",
    "lightbulb.subscription_business_loop",
    "lightbulb.company_bring_up",
    "lightbulb.company_cadence_runner",
    "lightbulb.company_front_door",
    "lightbulb.planning_intake",
    "lightbulb.ai_operator",
    "lightbulb.authority_matrix",
    "lightbulb.contract_obligations",
)


class EngineLoopEntry(StrictModel):
    """The reviewed description of one loop key; the engines and modules are read from the code."""

    title: ShortText
    function: ShortText
    archetypes: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    primitive_refs: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=60)
    hands_off_to: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    money_truth: ShortText
    status: LoopStatus = "modelled"


ALL_ARCHETYPES: tuple[str, ...] = ("dtc_commerce", "b2b_saas", "services_firm", "marketplace", "appointment_business", "subscription_business", "saas_product", "product_commerce", "service_business", "marketplace_business")
_ALL = ALL_ARCHETYPES
_SAAS = ("b2b_saas", "saas_product", "subscription_business")
_SERVICES = ("services_firm", "service_business")
_COMMERCE = ("dtc_commerce", "product_commerce", "marketplace", "marketplace_business")

#: The static, reviewed half of the registry.  A key here must be declared by
#: a module; a key declared by a module must be here (the test enforces both).
ENGINE_LOOP_ENTRIES: Mapping[str, EngineLoopEntry] = {
    "company.blueprint_to_governed_operating_cadence@0.1.0": EngineLoopEntry(title="Blueprint to governed operating cadence", function="run_company", archetypes=_ALL, primitive_refs=("blueprint.compile_company_operating_system", "blueprint.compile_workforce", "company.advance_period", "company.assess_health", "company.route_signal", "company.consume_signal", "company.simulate_operating_periods", "company.evaluate_scenario", "company.meter_dispatch", "company.render_approval_inbox", "company.preview_plan_migration", "company.assess_portfolio", "workforce.plan_dispatch", "workforce.advance_worker", "workforce.assess_workforce", "approval.request_decision"), hands_off_to=("company.operating_cadence_unattended@0.1.0",), money_truth="every dollar a period spent is attributed once in the cost register and every approval is a platform decision"),
    "company.operating_cadence_unattended@0.1.0": EngineLoopEntry(title="Operating cadence, unattended", function="run_company", archetypes=_ALL, primitive_refs=("company.advance_cadence", "company.plan_cadence_tick", "company.plan_observation_jobs"), money_truth="a tick commits to the exact bundle digest and records what it dispatched and observed"),
    "company.formed_to_running_cadence@0.1.0": EngineLoopEntry(title="Formed company to running cadence", function="form_company", archetypes=_ALL, primitive_refs=("company.plan_formation", "company.assess_bring_up_readiness"), hands_off_to=("company.operating_cadence_unattended@0.1.0",), money_truth="readiness compares every engine with the OAuth connections the account actually holds"),
    "company.formed_to_instrumented@0.1.0": EngineLoopEntry(title="Formed company to instrumented company", function="form_company", archetypes=_ALL, money_truth="each instrument is proven by a provisioning receipt from the provider, never by a request"),
    "company.idea_to_first_dollar@0.1.0": EngineLoopEntry(title="Idea to first dollar", function="form_company", archetypes=_ALL, hands_off_to=("company.blueprint_to_governed_operating_cadence@0.1.0",), money_truth="the launch gate stays with a human and the first dollar is proven by a settled chain case"),
    "company.decision_to_closed_books@0.1.0": EngineLoopEntry(title="Wind-down decision to closed books", function="wind_down", archetypes=_ALL, money_truth="directors' resolution, headcount proof, and cleared liabilities before the books close"),
    "workforce.roster_to_governed_dispatch@0.1.0": EngineLoopEntry(title="Agent roster to governed dispatch", function="run_company", archetypes=_ALL, primitive_refs=("blueprint.compile_workforce", "workforce.plan_dispatch", "workforce.advance_worker", "workforce.assess_workforce"), money_truth="dispatch cost is metered from the platform's own record and capped per worker and period"),
    "finance.period_close_to_verified_books@0.1.0": EngineLoopEntry(title="Period close to verified books", function="books_and_close", archetypes=_ALL, primitive_refs=("blueprint.compile_finance_close", "finance_close.plan_close_reads", "finance_close.advance_close", "finance_close.assess_close", "finance_close.verify_books", "finance.evaluate_period_close_readiness", "finance.evaluate_period_reconciliation", "finance.prepare_close_evidence_bundle", "finance.prepare_close_workspace", "finance.materialize_ledger_snapshot", "finance.reconcile_stripe_settlements", "finance.build_close_audit_packet"), money_truth="payables, payroll, bank reconciliation, collections, spend control, disbursements and statutory obligations all prove cash against a verified close"),
    "growth.store_truth_to_attributed_revenue@0.1.0": EngineLoopEntry(title="Store truth to attributed revenue", function="grow", archetypes=("dtc_commerce", "product_commerce", "marketplace", "b2b_saas", "services_firm"), primitive_refs=("blueprint.compile_growth_engine", "growth_engine.plan_campaign_portfolio", "growth_engine.advance_campaign", "growth_engine.propose_reallocation", "growth_engine.assess_engine", "growth.build_funnel_snapshot", "growth.build_unit_economics", "growth.diagnose", "growth.plan_launch", "growth.review_profit", "growth.plan_price_move", "growth.assess_objective", "growth.preflight_action", "growth.allocate_incremental_acquisition"), money_truth="attributed revenue is a storefront settlement batch that hit the bank; media spend is invoice-backed"),
    "growth.brief_to_compounding_asset@0.1.0": EngineLoopEntry(title="Brief to compounding content asset", function="content", archetypes=_ALL, primitive_refs=("content.run_creative_experiment_factory", "demand_gen.plan_content_calendar", "demand_gen.plan_audience_growth"), money_truth="an asset's organic life is measured from analytics reads, never asserted"),
    "growth.local_presence_to_booked_demand@0.1.0": EngineLoopEntry(title="Local presence to booked demand", function="local_presence", archetypes=("services_firm", "appointment_business", "service_business"), money_truth="listing and review states come from Business Profile reads with provenance"),
    "revenue.icp_to_qualified_pipeline@0.1.0": EngineLoopEntry(title="ICP to qualified pipeline and settled revenue", function="sell", archetypes=("b2b_saas", "services_firm", "saas_product", "service_business"), primitive_refs=("blueprint.compile_pipeline_engine", "pipeline.evaluate_icp_fit", "pipeline.plan_sequence", "pipeline.advance_prospect", "pipeline.plan_next_touch", "pipeline.forecast_pipeline", "crm.qualify_lead", "crm.orchestrate_profit_aware_lifecycle"), hands_off_to=("commercial.approved_quote_to_executed_agreement_custody@0.1.0",), money_truth="the revenue chain proves a handed-off deal through agreement, invoice, payment, and settlement"),
    "commercial.approved_quote_to_executed_agreement_custody@0.1.0": EngineLoopEntry(title="Approved quote to executed agreement custody", function="contract", archetypes=("b2b_saas", "services_firm", "saas_product", "service_business"), primitive_refs=("commercial.compile_legal_review_packet", "commercial.validate_legal_review_outcome", "commercial.reconcile_executed_agreement", "commercial.evaluate_quote_order_contract_controls", "commercial.propose_operations_transition", "legal.review_contract", "legal.draft_contract"), hands_off_to=("project.work_packet_independent_acceptance@0.1.0",), money_truth="a deal is priced from the price book and executed paper is custody-bound by digest"),
    "saas.launched_product_to_compounding_revenue@0.1.0": EngineLoopEntry(title="Launched product to compounding revenue", function="subscriptions", archetypes=_SAAS, primitive_refs=("blueprint.compile_saas_operating", "saas_ops.observe_usage", "saas_ops.observe_billing", "saas_ops.triage_support", "saas_ops.rank_roadmap", "saas_ops.advance_release", "saas_ops.assess_operating"), money_truth="MRR is read from Stripe invoices, renewals and dunning are proven by the next billing observation"),
    "saas.market_research_to_launched_product@0.1.0": EngineLoopEntry(title="Market research to launched product", function="build_product", archetypes=("saas_product",), primitive_refs=("blueprint.compile_saas_product", "saas.compile_market_research", "saas.evaluate_demand_validation", "saas.project_business_model", "saas.plan_product_artifacts", "saas.verify_artifact_grounding", "saas.advance_product", "saas.assess_product"), hands_off_to=("software.approved_change_to_verified_production@0.1.0", "subscription.trial_to_renewal_business@0.1.0"), money_truth="every number in a generated artifact matches a grounding fact"),
    "subscription.trial_to_renewal_business@0.1.0": EngineLoopEntry(title="Trial to renewal subscription business", function="subscriptions", archetypes=("subscription_business", "saas_product"), primitive_refs=("blueprint.compile_subscription_business", "subscription.advance_account", "subscription.prorate_plan_change", "subscription.assess_portfolio"), money_truth="proration and MRR movements are deterministic from the account ledger"),
    "service.market_to_renewal_business@0.1.0": EngineLoopEntry(title="Market to renewal service business", function="deliver_services", archetypes=_SERVICES, primitive_refs=("blueprint.compile_service_business", "service.advance_business_cycle", "service.assess_business_cycle", "service.open_exception_case", "service.advance_exception_case", "service.assess_exception_portfolio", "service.prepare_productised_assessment"), money_truth="quote, accepted, invoiced, and collected totals link by digest across the cycle"),
    "service.marketing_to_cash_engagement@0.1.0": EngineLoopEntry(title="Engagement from scope to cash", function="deliver_services", archetypes=_SERVICES, primitive_refs=("engagement.compile_engagement", "engagement.advance_engagement", "engagement.assess_engagement", "service.propose_engagement_transition", "service.propose_engagement_invoice"), hands_off_to=("revenue.icp_to_qualified_pipeline@0.1.0",), money_truth="WIP invoices bill only accepted, uninvoiced value"),
    "service.case_intake_to_verified_resolution@0.1.0": EngineLoopEntry(title="Case intake to verified resolution", function="customers_support", archetypes=_ALL, primitive_refs=("blueprint.compile_service_delivery", "service_delivery.advance_case", "service_delivery.assess_delivery", "service.intake_and_classify_case", "service.route_and_escalate_case", "service.submit_resolution_for_verification", "service.evaluate_case_resolution_controls", "service.verify_case_resolution", "customer_success.prevent_returns_and_expand_ltv"), money_truth="refunds and representments are backed by the original sale, an authority decision, and bank rows"),
    "services.lead_to_cash_per_job@0.1.0": EngineLoopEntry(title="Lead to cash per job", function="deliver_services", archetypes=("services_firm", "service_business", "appointment_business"), money_truth="one replay-fenced lifecycle per job from lead to the first dollar settled"),
    "people.offer_to_offboarded_with_proven_pay@0.1.0": EngineLoopEntry(title="Accepted offer to offboarded with proven pay", function="pay_people", archetypes=_ALL, primitive_refs=("hr.onboard_employee", "people.evaluate_worker_lifecycle_controls", "people.propose_operations_transition"), money_truth="gross and net are read off the worker's row of a posted pay run; a name never enters the engine"),
    "people.capacity_to_proven_labour@0.1.0": EngineLoopEntry(title="Team capacity to proven labour", function="pay_people", archetypes=_ALL, primitive_refs=("people.compile_people_engine", "people.advance_people", "people.assess_capacity"), money_truth="paid labour is derived from replayed payroll runs"),
    "marketplace.supply_demand_to_settled_transaction@0.1.0": EngineLoopEntry(title="Supply and demand to settled transaction", function="marketplace", archetypes=("marketplace", "marketplace_business"), primitive_refs=("blueprint.compile_marketplace_business", "marketplace.compile_supply_engine", "marketplace.advance_supply", "marketplace.assess_supply", "marketplace.advance_seller", "marketplace.advance_listing", "marketplace.advance_transaction", "marketplace.assess_marketplace"), hands_off_to=("marketplace.seller_liability_to_reserved_custody@0.1.0",), money_truth="seller liabilities become approved instructions and then bank-cleared payouts"),
    "marketplace.seller_liability_to_reserved_custody@0.1.0": EngineLoopEntry(title="Seller liability to reserved custody", function="marketplace", archetypes=("marketplace", "marketplace_business"), money_truth="custody balance is reconciled against seller liabilities every period"),
    "appointment.booking_to_rebooking_business@0.1.0": EngineLoopEntry(title="Booking to rebooking business", function="appointments", archetypes=("appointment_business",), primitive_refs=("blueprint.compile_appointment_business", "appointment.generate_availability", "appointment.advance_booking", "appointment.assess_schedule"), money_truth="deposits and no-show fees follow the sealed policy"),
    "commerce.product_truth_to_measured_improvement@0.1.0": EngineLoopEntry(title="Product truth to measured improvement", function="sell_products", archetypes=("dtc_commerce", "product_commerce"), primitive_refs=("blueprint.compile_product_commerce", "commerce.compile_product_commercial_identity", "commerce.advance_product_cycle", "commerce.assess_product_cycle", "commerce.compose_personalized_variant", "commerce.plan_channel_publication", "commerce.plan_shopify_storefront", "commerce.govern_inventory_and_fulfillment", "commerce.optimize_storefront_conversion", "commerce.recover_abandoned_revenue", "gtm.plan_omnichannel_product_launch", "gtm.optimize_offer_price_and_margin", "product.discover_profitable_opportunities"), hands_off_to=("growth.store_truth_to_attributed_revenue@0.1.0",), money_truth="contribution margin per SKU is computed from settled batches and standard costs"),
    "documents.governed_business_artifact_production@0.1.0": EngineLoopEntry(title="Governed business artifact production", function="documents", archetypes=_ALL, primitive_refs=("documents.prepare_business_artifact_generation", "documents.generate_business_artifact", "documents.validate_generated_business_artifact", "documents.render_productised_assessment"), money_truth="generated sections are validated against the sealed brief"),
    "project.work_packet_independent_acceptance@0.1.0": EngineLoopEntry(title="Work packet to independent acceptance", function="deliver_software", archetypes=("services_firm", "service_business", "b2b_saas", "saas_product"), primitive_refs=("project.create_work_packet", "project.evaluate_work_packet_artifact", "project.execute_approved_work_packet", "project.compile_contract_delivery_plan", "project.bind_contract_deliverable_to_work_packet", "project.evaluate_contractual_delivery_evidence", "project.compile_customer_acceptance_candidate", "commercial.propose_contract_change_order"), money_truth="accepted value is bound to a deliverable and independently verified before it is invoiced"),
    "software.approved_change_to_verified_production@0.1.0": EngineLoopEntry(title="Approved change to verified production", function="deliver_software", archetypes=("saas_product", "b2b_saas", "services_firm"), primitive_refs=("project.request_software_production", "project.admit_software_production_run", "project.apply_software_production_event", "project.assess_software_production_result", "workflow.evaluate_staging_canary"), money_truth="a run is registered by Spring and every event is a sealed loop command"),
    "legal.approved_contract_obligation_to_verified_fulfillment@0.1.0": EngineLoopEntry(title="Approved contract obligation to verified fulfillment", function="contract", archetypes=("b2b_saas", "services_firm", "saas_product", "service_business"), primitive_refs=("legal.intake_contract_obligations_from_custody", "legal.normalize_contract_obligation_candidates", "legal.compile_contract_obligation_schedule", "legal.evaluate_contract_obligation_fulfillment", "legal.route_contract_obligation_register", "legal.assess_contract_obligation_portfolio", "legal.propose_contract_obligation_transition"), money_truth="obligations are dated from the approved agreement version and fulfilment is verified against custody-bound evidence"),
    "people.headcount_need_to_accepted_offer@0.1.0": EngineLoopEntry(title="Headcount need to accepted offer", function="hire", archetypes=_ALL, hands_off_to=("people.offer_to_offboarded_with_proven_pay@0.1.0",), money_truth="a requisition commits annualised pay against the budget envelope under a people_change authority decision; the accepted offer opens the employment chain"),
    "inventory.demand_signal_to_replenished_stock@0.1.0": EngineLoopEntry(title="Demand signal to replenished stock", function="buy_stock", archetypes=("dtc_commerce", "product_commerce", "marketplace_business"), hands_off_to=("finance.period_close_to_verified_books@0.1.0",), money_truth="stock is cash: landed cost comes from paid payables, COGS from settled storefront batches, and every unit is costed once"),
    "planning.operating_plan_to_reforecast@0.1.0": EngineLoopEntry(title="Operating plan to reforecast", function="plan_and_budget", archetypes=_ALL, hands_off_to=("company.blueprint_to_governed_operating_cadence@0.1.0",), money_truth="actuals bind only from a closed cost register; variance and reforecast are signals to the operating system, never edits to the plan of record"),
    "reliability.detected_incident_to_credited_customer@0.1.0": EngineLoopEntry(title="Detected incident to credited customer", function="reliability", archetypes=_SAAS, hands_off_to=("saas.launched_product_to_compounding_revenue@0.1.0",), money_truth="an SLA credit is a liability computed from the sealed policy and the affected tier's price, settled only by a billing credit observation"),
    "people.expense_claim_to_reimbursed@0.1.0": EngineLoopEntry(title="Expense claim to reimbursed", function="expense_claims", archetypes=_ALL, hands_off_to=("people.offer_to_offboarded_with_proven_pay@0.1.0",), money_truth="a claim is reimbursed only through a paid pay run or a bank-observed transfer for the approved total"),
    "partner.agreement_to_paid_commission@0.1.0": EngineLoopEntry(title="Partner agreement to paid commission", function="partners", archetypes=("b2b_saas", "saas_product", "services_firm", "subscription_business"), hands_off_to=("finance.period_close_to_verified_books@0.1.0",), money_truth="commission accrues only on settled revenue chain cash under an in-force agreement and is paid through a proven disbursement"),
    "commerce.paid_order_to_delivered_customer@0.1.0": EngineLoopEntry(title="Paid order to delivered customer", function="fulfilment", archetypes=("dtc_commerce", "product_commerce", "marketplace_business"), hands_off_to=("inventory.demand_signal_to_replenished_stock@0.1.0", "service.case_intake_to_verified_resolution@0.1.0"), money_truth="an order exists only from a settled storefront read; shipping, delivery, and returns are carrier and store observations, and a return restocks inventory or expects a refund, never both"),
    "people.contractor_engaged_to_paid_work@0.1.0": EngineLoopEntry(title="Contractor engaged to paid work", function="contractors", archetypes=_ALL, hands_off_to=("finance.period_close_to_verified_books@0.1.0",), money_truth="work is recorded from a timesheet read inside the agreement's rate and cap, invoiced through the supplier's replayed payable case, and paid only when that case is paid"),
    "customer.won_deal_to_live_account@0.1.0": EngineLoopEntry(title="Won deal to live account", function="customer_onboarding", archetypes=("b2b_saas", "saas_product", "subscription_business", "services_firm"), hands_off_to=("saas.launched_product_to_compounding_revenue@0.1.0",), money_truth="onboarding opens from a won revenue-chain deal and goes live only on an observed usage row for the account; overdue milestones are signals, never edits"),
    "finance.eligible_activity_to_received_incentive@0.1.0": EngineLoopEntry(title="Eligible activity to received incentive", function="incentives", archetypes=_ALL, hands_off_to=("finance.period_close_to_verified_books@0.1.0",), money_truth="eligible cost binds only from closed cost registers under a registered program, the benefit is computed from the sealed rate and cap, the preparer never lodges, and receipt is a bank read"),
    "commerce.price_book_to_published_prices@0.1.0": EngineLoopEntry(title="Price book to published prices", function="pricing_catalog", archetypes=_ALL, hands_off_to=("commercial.approved_quote_to_executed_agreement_custody@0.1.0", "saas.launched_product_to_compounding_revenue@0.1.0"), money_truth="a catalog version prices only after pricing authority approves it, increases publish only with the notice period served, and one version is in force per catalog at a time"),
    "finance.acquired_asset_to_disposed_asset@0.1.0": EngineLoopEntry(title="Acquired asset to disposed asset", function="fixed_assets", archetypes=_ALL, hands_off_to=("finance.period_close_to_verified_books@0.1.0", "company.decision_to_closed_books@0.1.0"), money_truth="cost comes from the supplier's replayed payable case, depreciation is computed month by month from the sealed class and lands in the cost register once, and proceeds are a bank read"),
    "finance.foreign_balance_to_settled_company_currency@0.1.0": EngineLoopEntry(title="Foreign balance to settled company currency", function="multi_currency", archetypes=_ALL, hands_off_to=("finance.period_close_to_verified_books@0.1.0",), money_truth="an exposure is a balance read valued at a fresh governed rate; a conversion sells exactly the order inside the quote's tolerance, and its cost lands in the cost register once"),
    "capital.round_planned_to_funds_received@0.1.0": EngineLoopEntry(title="Capital round planned to funds received", function="fundraise", archetypes=_ALL, hands_off_to=("finance.observed_balances_to_reviewed_cash_forecast@0.1.0",), money_truth="dilution is computed from the sealed cap table, the closing is a capital authority decision by someone other than the lead, and the round is funded only when every wire is observed for exactly its commitment"),
    "finance.observed_balances_to_reviewed_cash_forecast@0.1.0": EngineLoopEntry(title="Observed balances to reviewed cash forecast", function="cash_and_runway", archetypes=_ALL, hands_off_to=("company.blueprint_to_governed_operating_cadence@0.1.0", "finance.period_close_to_verified_books@0.1.0"), money_truth="cash is the sum of observed account balances; expectations enter once with the replayed state that produced them; the forecast is computed and a floor breach is reviewed by someone other than the preparer"),
    "risk.insured_loss_to_settled_claim@0.1.0": EngineLoopEntry(title="Insured loss to settled claim", function="insurance", archetypes=_ALL, hands_off_to=("finance.observed_balances_to_reviewed_cash_forecast@0.1.0", "finance.period_close_to_verified_books@0.1.0"), money_truth="a loss is a replayed asset or bill under the replayed policy in force on the loss date; claimable is computed from the excess and limit, the settlement is a bank read, and the net loss reaches the cost register once"),
    "governance.board_cycle_to_tracked_resolutions@0.1.0": EngineLoopEntry(title="Board cycle to tracked resolutions", function="governance", archetypes=_ALL, hands_off_to=("company.blueprint_to_governed_operating_cadence@0.1.0",), money_truth="the pack the board saw is the sealed board pack; a resolution is carried by the recorded votes of a quorum; minutes are the secretary's and the chair's; actions close only with evidence"),
    "operations.raised_work_order_to_costed_completion@0.1.0": EngineLoopEntry(title="Raised work order to costed completion", function="regulated_operations", archetypes=("dtc_commerce", "product_commerce", "services_firm", "service_business"), primitive_refs=("compliance.evaluate_regulated_controls",), hands_off_to=("finance.period_close_to_verified_books@0.1.0", "service.case_intake_to_verified_resolution@0.1.0"), money_truth="a job is approved by a non-requester under commitment authority, starts only on a verified satisfied controls result, costs from replayed bills and timesheet reads, and is costed only when the replayed register carries it"),
    "capital.option_grant_to_shares_or_lapse@0.1.0": EngineLoopEntry(title="Option grant to shares or lapse", function="equity", archetypes=_ALL, hands_off_to=("capital.round_planned_to_funds_received@0.1.0", "governance.board_cycle_to_tracked_resolutions@0.1.0"), money_truth="a grant never exceeds the pool and rests on a minuted, carried board resolution; vesting is computed month by month; shares are issued only for cash observed at exactly the strike"),
    "revenue.customer_deposit_to_drawn_down@0.1.0": EngineLoopEntry(title="Customer deposit to drawn down", function="prepayments", archetypes=("services_firm", "service_business", "dtc_commerce", "product_commerce"), hands_off_to=("revenue.icp_to_qualified_pipeline@0.1.0", "finance.observed_balances_to_reviewed_cash_forecast@0.1.0"), money_truth="a deposit is held only when the bank shows exactly what was requested, drawn only against a replayed issued invoice for the same customer once per invoice, and refunded for exactly the balance or forfeited under a named clause"),
}


def _module_loop_keys(module: Any) -> tuple[str, ...]:
    keys = []
    for name, value in inspect.getmembers(module):
        if name.endswith("GOLDEN_LOOP") and isinstance(value, str) and "@" in value:
            keys.append(value)
    return tuple(sorted(set(keys)))


def declared_loop_keys() -> dict[str, tuple[str, ...]]:
    """Loop key -> the modules that declare it, read from the registered lifecycles and the pack loop modules."""

    from lightbulb import company_plan_migration as migration

    migration._register_late_lifecycles()
    modules = {lifecycle.advance.__module__ for lifecycle in migration.ENGINE_LIFECYCLES.values()}
    modules.update(PACK_LOOP_MODULES)
    out: dict[str, set[str]] = {}
    for module_name in sorted(modules):
        module = importlib.import_module(module_name)
        for key in _module_loop_keys(module):
            out.setdefault(key, set()).add(module_name)
    return {key: tuple(sorted(value)) for key, value in sorted(out.items())}


def loop_engines() -> dict[str, tuple[str, ...]]:
    """Loop key -> the registered lifecycle engines whose module declares that key."""

    from lightbulb import company_plan_migration as migration

    migration._register_late_lifecycles()
    out: dict[str, set[str]] = {}
    for engine, lifecycle in migration.ENGINE_LIFECYCLES.items():
        module = importlib.import_module(lifecycle.advance.__module__)
        for key in _module_loop_keys(module):
            out.setdefault(key, set()).add(engine)
    return {key: tuple(sorted(value)) for key, value in sorted(out.items())}


class EngineLoop(StrictModel):
    loop_key: ShortText
    title: ShortText
    function: ShortText
    archetypes: tuple[ShortText, ...]
    engines: tuple[ShortText, ...] = Field(default_factory=tuple)
    modules: tuple[ShortText, ...] = Field(min_length=1)
    primitive_refs: tuple[ShortText, ...] = Field(default_factory=tuple)
    hands_off_to: tuple[ShortText, ...] = Field(default_factory=tuple)
    money_truth: ShortText
    status: LoopStatus

    @model_validator(mode="after")
    def _guard(self) -> "EngineLoop":
        if "@" not in self.loop_key:
            raise ValueError("a loop key carries its version")
        return self


def engine_loops() -> tuple[EngineLoop, ...]:
    """Every declared loop, joined to its engines, modules, and reviewed description; sorted by key."""

    declared = declared_loop_keys()
    engines = loop_engines()
    out = []
    for key, modules in declared.items():
        entry = ENGINE_LOOP_ENTRIES.get(key)
        if entry is None:
            raise LookupError(f"{key} is declared by {modules} but has no registry entry; add it to ENGINE_LOOP_ENTRIES")
        out.append(EngineLoop(loop_key=key, title=entry.title, function=entry.function, archetypes=entry.archetypes, engines=engines.get(key, ()), modules=modules, primitive_refs=entry.primitive_refs, hands_off_to=entry.hands_off_to, money_truth=entry.money_truth, status=entry.status))
    return tuple(out)


def declared_primitive_loops() -> dict[str, str]:
    """Primitive ref -> the ``golden_loop`` its implementation class declares (pack primitives name their loop)."""

    from lightbulb.executable_primitives import default_primitive_registry

    registry = default_primitive_registry()
    out: dict[str, str] = {}
    for entry in registry.catalog():
        ref = str(entry["primitive_ref"])
        declared = getattr(registry.get(ref), "golden_loop", None)
        if isinstance(declared, str) and "@" in declared:
            out[ref] = declared
    return dict(sorted(out.items()))


def loop_memberships() -> dict[str, tuple[str, ...]]:
    """Primitive ref -> the engine loop keys it enters: the reviewed entries plus each primitive's own declaration."""

    out: dict[str, set[str]] = {}
    for loop in engine_loops():
        for ref in loop.primitive_refs:
            out.setdefault(ref, set()).add(loop.loop_key)
    for ref, key in declared_primitive_loops().items():
        out.setdefault(ref, set()).add(key)
    return {ref: tuple(sorted(keys)) for ref, keys in sorted(out.items())}


def engine_loop_registry() -> dict[str, Any]:
    loops = [loop.to_dict() for loop in engine_loops()]
    payload = {"schema": ENGINE_LOOP_REGISTRY_SCHEMA, "loops": loops, "loop_count": len(loops)}
    return {**payload, "registry_digest": stable_digest(payload)}


__all__ = ["ALL_ARCHETYPES", "ENGINE_LOOP_ENTRIES", "ENGINE_LOOP_REGISTRY_SCHEMA", "PACK_LOOP_MODULES", "EngineLoop", "EngineLoopEntry", "declared_loop_keys", "engine_loop_registry", "engine_loops", "loop_engines", "loop_memberships"]
