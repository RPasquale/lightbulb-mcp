"""The business process map: which loop, chain, and primitives run each function of a business, and what is not modelled.

The SDK grew one engine at a time.  Each engine documented itself, and the
question "what does the SDK not do yet?" had to be answered by reading 400
modules.  This map answers it from the code: every business function a
company runs is a row, each row names the engine loops (from
``engine_golden_loops``), the registered lifecycle engines, and the executable
primitives that serve it, and a row whose status is ``not_modelled`` or
``partial`` says so in the generated document rather than hiding it.

The static table is the reviewed part.  The tests hold it to the code: every
loop key must be declared by a module, every engine must be a registered
lifecycle, every primitive must be in the executable registry, and every
declared loop must appear in at least one row.  ``render_business_process_map``
produces ``docs/lightbulb-business-process-map.md``; regenerate it with
``scripts/generate_business_process_map.py`` after adding an engine.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from pydantic import Field

from lightbulb.company_engine_core import ShortText, StrictModel, stable_digest
from lightbulb.engine_golden_loops import ALL_ARCHETYPES, engine_loops

BUSINESS_PROCESS_MAP_SCHEMA = "lightbulb.business_process_map.v1"
FunctionStatus = Literal["modelled", "partial", "not_modelled"]
_ALL = ALL_ARCHETYPES
_SAAS = ("b2b_saas", "saas_product", "subscription_business")
_SERVICES = ("services_firm", "service_business")
_COMMERCE = ("dtc_commerce", "product_commerce", "marketplace_business")


class BusinessFunction(StrictModel):
    key: ShortText
    title: ShortText
    question: ShortText
    archetypes: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    loop_keys: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    engines: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    primitive_refs: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    status: FunctionStatus
    gap: ShortText | None = None


BUSINESS_FUNCTIONS: tuple[BusinessFunction, ...] = (
    BusinessFunction(key="form_company", title="Form and instrument the company", question="Is the company formed, instrumented, and ready to run?", archetypes=_ALL, loop_keys=("company.idea_to_first_dollar@0.1.0", "company.formed_to_instrumented@0.1.0", "company.formed_to_running_cadence@0.1.0"), engines=("company_launch", "company_provisioning"), primitive_refs=("company.plan_formation", "company.assess_bring_up_readiness"), status="modelled"),
    BusinessFunction(key="run_company", title="Run the operating cadence", question="What did each engine do this period, what did it cost, and who approved it?", archetypes=_ALL, loop_keys=("company.blueprint_to_governed_operating_cadence@0.1.0", "company.operating_cadence_unattended@0.1.0", "workforce.roster_to_governed_dispatch@0.1.0"), engines=("company_operating_system", "company_cost_centres", "company_workforce", "company_operating_memory", "exception_case", "agreement_chain", "company_standing", "contact_endpoint", "claim_register"), primitive_refs=("blueprint.compile_company_operating_system", "company.advance_period", "company.assess_health", "company.route_signal", "company.consume_signal", "company.advance_cadence", "company.plan_cadence_tick", "company.render_approval_inbox"), status="modelled"),
    BusinessFunction(key="plan_and_budget", title="Plan, budget, and reforecast", question="Are we on plan, where is the variance, and what did we reforecast?", archetypes=_ALL, loop_keys=("planning.operating_plan_to_reforecast@0.1.0",), engines=("operating_plan",), status="modelled"),
    BusinessFunction(key="sell", title="Find and qualify demand", question="Which prospects fit, what touched them, and what is qualified?", archetypes=("b2b_saas", "services_firm", "saas_product", "service_business"), loop_keys=("revenue.icp_to_qualified_pipeline@0.1.0",), engines=("pipeline_engine", "revenue_chain", "deal_desk_engine"), primitive_refs=("blueprint.compile_pipeline_engine", "pipeline.evaluate_icp_fit", "pipeline.plan_sequence", "pipeline.advance_prospect", "pipeline.forecast_pipeline", "crm.qualify_lead"), status="modelled"),
    BusinessFunction(key="contract", title="Quote, agree, and take custody of paper", question="Is the deal priced from the book and is the executed agreement in custody?", archetypes=("b2b_saas", "services_firm", "saas_product", "service_business"), loop_keys=("commercial.approved_quote_to_executed_agreement_custody@0.1.0", "legal.approved_contract_obligation_to_verified_fulfillment@0.1.0"), engines=("deal_desk_engine", "agreement_chain"), primitive_refs=("commercial.compile_legal_review_packet", "commercial.validate_legal_review_outcome", "commercial.reconcile_executed_agreement", "legal.review_contract", "legal.draft_contract"), status="modelled"),
    BusinessFunction(key="deliver_services", title="Deliver services and bill accepted value", question="What was accepted, what is uninvoiced, and what is collected?", archetypes=_SERVICES, loop_keys=("service.market_to_renewal_business@0.1.0", "service.marketing_to_cash_engagement@0.1.0", "services.lead_to_cash_per_job@0.1.0"), engines=("engagement_engine", "wip_billing", "job_chain"), primitive_refs=("blueprint.compile_service_business", "service.advance_business_cycle", "engagement.advance_engagement", "service.propose_engagement_invoice"), status="modelled"),
    BusinessFunction(key="deliver_software", title="Build and accept software", question="Was the change produced under a registered run and accepted independently?", archetypes=("saas_product", "b2b_saas", "services_firm"), loop_keys=("software.approved_change_to_verified_production@0.1.0", "project.work_packet_independent_acceptance@0.1.0"), primitive_refs=("project.request_software_production", "project.admit_software_production_run", "project.create_work_packet", "project.compile_customer_acceptance_candidate"), status="modelled"),
    BusinessFunction(key="build_product", title="Research, validate, and launch a product", question="Is the thesis grounded and did validation say go?", archetypes=("saas_product",), loop_keys=("saas.market_research_to_launched_product@0.1.0",), primitive_refs=("saas.compile_market_research", "saas.evaluate_demand_validation", "saas.project_business_model", "saas.advance_product"), status="modelled"),
    BusinessFunction(key="sell_products", title="Sell products through storefronts", question="What did each SKU earn after fees, refunds, and standard cost?", archetypes=("dtc_commerce", "product_commerce"), loop_keys=("commerce.product_truth_to_measured_improvement@0.1.0", "growth.store_truth_to_attributed_revenue@0.1.0"), engines=("storefront_settlement_chain", "refund_and_dispute_chain"), primitive_refs=("commerce.compile_product_commercial_identity", "commerce.advance_product_cycle", "commerce.govern_inventory_and_fulfillment", "commerce.recover_abandoned_revenue"), status="modelled"),
    BusinessFunction(key="buy_stock", title="Hold, replenish, and cost inventory", question="What stock do we hold, when do we reorder, and what did the units we sold cost?", archetypes=_COMMERCE, loop_keys=("inventory.demand_signal_to_replenished_stock@0.1.0",), engines=("inventory_chain",), primitive_refs=("supply_chain.evaluate_plan_fulfillment_controls", "procurement.propose_procure_to_pay_transition"), status="modelled"),
    BusinessFunction(key="subscriptions", title="Run subscriptions and renewals", question="What is MRR, who is at risk, and what renewed?", archetypes=_SAAS, loop_keys=("saas.launched_product_to_compounding_revenue@0.1.0", "subscription.trial_to_renewal_business@0.1.0"), engines=("saas_operating_engine", "subscription_chain", "retention_chain"), primitive_refs=("saas_ops.observe_usage", "saas_ops.observe_billing", "saas_ops.assess_operating", "subscription.advance_account", "subscription.assess_portfolio"), status="modelled"),
    BusinessFunction(key="reliability", title="Handle incidents and honour SLAs", question="How long was it down, who was affected, and were the credits settled?", archetypes=_SAAS, loop_keys=("reliability.detected_incident_to_credited_customer@0.1.0",), engines=("incident_chain",), primitive_refs=("saas_ops.triage_support", "saas_ops.advance_release"), status="modelled"),
    BusinessFunction(key="marketplace", title="Run a marketplace", question="Are sellers verified, are listings live, and are payouts and custody reconciled?", archetypes=("marketplace", "marketplace_business"), loop_keys=("marketplace.supply_demand_to_settled_transaction@0.1.0", "marketplace.seller_liability_to_reserved_custody@0.1.0"), engines=("marketplace_seller", "marketplace_listing", "marketplace_supply_engine", "payout_chain", "custodial_funds"), primitive_refs=("marketplace.advance_seller", "marketplace.advance_listing", "marketplace.advance_transaction", "marketplace.assess_marketplace"), status="modelled"),
    BusinessFunction(key="appointments", title="Book and deliver appointments", question="What is booked, what was utilised, and who did not show?", archetypes=("appointment_business",), loop_keys=("appointment.booking_to_rebooking_business@0.1.0",), primitive_refs=("appointment.generate_availability", "appointment.advance_booking", "appointment.assess_schedule"), status="modelled"),
    BusinessFunction(key="customers_support", title="Support customers and resolve cases", question="Was every case resolved inside its SLA and verified by the customer?", archetypes=_ALL, loop_keys=("service.case_intake_to_verified_resolution@0.1.0",), engines=("service_delivery", "refund_and_dispute_chain"), primitive_refs=("service.intake_and_classify_case", "service.route_and_escalate_case", "service.verify_case_resolution", "service_delivery.advance_case"), status="modelled"),
    BusinessFunction(key="hire", title="Plan headcount and hire", question="Is the requisition funded and authorised, who was interviewed, and was the offer accepted?", archetypes=_ALL, loop_keys=("people.headcount_need_to_accepted_offer@0.1.0",), engines=("hiring_chain",), status="modelled"),
    BusinessFunction(key="pay_people", title="Employ, roster, and pay people", question="Was this person hired under authority, rostered, and paid what the pay run says?", archetypes=_ALL, loop_keys=("people.offer_to_offboarded_with_proven_pay@0.1.0", "people.capacity_to_proven_labour@0.1.0"), engines=("employment_chain", "payroll_run_chain", "people_engine"), primitive_refs=("hr.onboard_employee", "people.compile_people_engine", "people.assess_capacity"), status="modelled"),
    BusinessFunction(key="expense_claims", title="Reimburse expense claims", question="Was the claim inside policy, approved by someone else, and actually reimbursed?", archetypes=_ALL, loop_keys=("people.expense_claim_to_reimbursed@0.1.0",), engines=("expense_claim_chain",), status="modelled"),
    BusinessFunction(key="pay_suppliers", title="Buy from suppliers and pay bills", question="Which bills are approved, covered by cash, paid, and cleared?", archetypes=_ALL, loop_keys=("finance.period_close_to_verified_books@0.1.0",), engines=("payables_chain", "spend_control_chain", "vendor_commitment", "disbursement_run"), primitive_refs=("finance.ingest_supplier_invoice", "procurement.evaluate_purchase_to_pay_controls", "procurement.propose_vendor_onboarding_transition"), status="modelled"),
    BusinessFunction(key="partners", title="Run partner and referral programs", question="Which partner earned what on settled cash, and was it paid?", archetypes=("b2b_saas", "saas_product", "services_firm", "subscription_business"), loop_keys=("partner.agreement_to_paid_commission@0.1.0",), engines=("partner_commission_chain",), status="modelled"),
    BusinessFunction(key="books_and_close", title="Keep the books and close the period", question="Do the books balance inside materiality with every reconciliation done?", archetypes=_ALL, loop_keys=("finance.period_close_to_verified_books@0.1.0",), engines=("finance_close", "bank_reconciliation", "collections_chain"), primitive_refs=("finance_close.advance_close", "finance_close.verify_books", "finance.prepare_journal_entry", "finance.post_journal_entry", "finance.reconcile_stripe_settlements"), status="modelled"),
    BusinessFunction(key="tax_and_statutory", title="Reserve, lodge, and pay statutory obligations", question="What is due, reserved, lodged, and paid?", archetypes=_ALL, loop_keys=("finance.period_close_to_verified_books@0.1.0",), engines=("compliance_obligation",), primitive_refs=("accounting.estimate_tax_set_aside",), status="modelled"),
    BusinessFunction(key="cash_and_runway", title="Watch cash and runway", question="How long can we run and what may we spend?", archetypes=_ALL, loop_keys=("finance.observed_balances_to_reviewed_cash_forecast@0.1.0",), engines=("cash_position_chain", "company_cost_centres"), primitive_refs=("cash.build_runway_snapshot", "cash.assess_runway", "cash.derive_budget_envelope", "cash.build_cash_flow_forecast", "accounting.run_cycle", "accounting.assess_default_alive", "accounting.compute_burn_multiple"), status="modelled"),
    BusinessFunction(key="grow", title="Acquire customers profitably", question="Which channel earned attributed revenue and where should the next tranche go?", archetypes=("dtc_commerce", "product_commerce", "b2b_saas", "services_firm", "marketplace"), loop_keys=("growth.store_truth_to_attributed_revenue@0.1.0",), engines=("growth_engine", "demand_envelope"), primitive_refs=("growth_engine.plan_campaign_portfolio", "growth_engine.advance_campaign", "growth_engine.propose_reallocation", "growth.build_funnel_snapshot", "growth.diagnose", "growth.review_profit"), status="modelled"),
    BusinessFunction(key="content", title="Produce and measure content", question="Which assets compound and which creative is fatigued?", archetypes=_ALL, loop_keys=("growth.brief_to_compounding_asset@0.1.0",), engines=("content_asset_lifecycle",), primitive_refs=("content.run_creative_experiment_factory", "demand_gen.plan_content_calendar"), status="modelled"),
    BusinessFunction(key="local_presence", title="Run local presence", question="Are the listings verified and the reviews answered?", archetypes=("services_firm", "appointment_business", "service_business"), loop_keys=("growth.local_presence_to_booked_demand@0.1.0",), engines=("local_presence_engine", "local_presence_review"), status="modelled"),
    BusinessFunction(key="documents", title="Produce governed business documents", question="Was the artifact generated from a sealed brief and validated against it?", archetypes=_ALL, loop_keys=("documents.governed_business_artifact_production@0.1.0",), primitive_refs=("documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact"), status="modelled"),
    BusinessFunction(key="regulated_operations", title="Regulated, manufacturing, supply-chain, and maintenance operations", question="Do the controls hold before work starts, and what did the job actually cost?", archetypes=("dtc_commerce", "product_commerce", "services_firm", "service_business"), loop_keys=("operations.raised_work_order_to_costed_completion@0.1.0",), engines=("work_order_chain",), primitive_refs=("compliance.evaluate_regulated_controls", "compliance.propose_regulated_operations_transition", "manufacturing.advance_execution_lifecycle", "supply_chain.propose_execution_transition", "maintenance.propose_work_order_transition", "product_engineering.propose_lifecycle_transition"), status="modelled"),
    BusinessFunction(key="insurance", title="Insure and claim", question="Was the loss covered, was the insurer told in time, and what did we recover?", archetypes=_ALL, loop_keys=("risk.insured_loss_to_settled_claim@0.1.0",), engines=("insurance_claim_chain", "company_standing"), status="modelled"),
    BusinessFunction(key="prepayments", title="Take deposits and retainers", question="What did customers pay up front, what has it been drawn against, and what is owed back?", archetypes=("services_firm", "service_business", "dtc_commerce", "product_commerce"), loop_keys=("revenue.customer_deposit_to_drawn_down@0.1.0",), engines=("prepayment_chain",), status="modelled"),
    BusinessFunction(key="equity", title="Grant and vest equity", question="What was granted on whose authority, what has vested, and what was exercised for cash?", archetypes=_ALL, loop_keys=("capital.option_grant_to_shares_or_lapse@0.1.0",), engines=("equity_grant_chain",), status="modelled"),
    BusinessFunction(key="governance", title="Run the board", question="Did the board see the sealed pack, resolve with a quorum, and get its actions done?", archetypes=_ALL, loop_keys=("governance.board_cycle_to_tracked_resolutions@0.1.0",), engines=("board_cadence_chain",), status="modelled"),
    BusinessFunction(key="wind_down", title="Wind the company down", question="Are liabilities cleared and the books closed under a directors' resolution?", archetypes=_ALL, loop_keys=("company.decision_to_closed_books@0.1.0",), engines=("wind_down_chain",), status="modelled"),
    BusinessFunction(key="pricing_catalog", title="Version prices and packaging", question="Which price list is in force for whom, and what was grandfathered?", archetypes=_ALL, loop_keys=("commerce.price_book_to_published_prices@0.1.0",), engines=("price_catalog", "deal_desk_engine"), primitive_refs=("growth.plan_price_move", "gtm.optimize_offer_price_and_margin"), status="modelled"),
    BusinessFunction(key="fundraise", title="Raise capital", question="Are we ready to raise, what does the round cost, and did the money arrive?", archetypes=_ALL, loop_keys=("capital.round_planned_to_funds_received@0.1.0",), engines=("fundraise_chain",), primitive_refs=("accounting.assess_default_alive", "accounting.compute_burn_multiple"), status="modelled"),
    BusinessFunction(key="fixed_assets", title="Own and depreciate assets", question="What do we own, what is it worth, and what was disposed?", archetypes=_ALL, loop_keys=("finance.acquired_asset_to_disposed_asset@0.1.0",), engines=("fixed_asset_chain",), status="modelled"),
    BusinessFunction(key="multi_currency", title="Hold and settle in several currencies", question="What is the exposure and what did conversion cost?", archetypes=_ALL, loop_keys=("finance.foreign_balance_to_settled_company_currency@0.1.0",), engines=("fx_exposure_chain",), status="modelled"),
    BusinessFunction(key="customer_onboarding", title="Onboard and implement customers", question="Is each new account activated inside the promised window?", archetypes=_SAAS, loop_keys=("customer.won_deal_to_live_account@0.1.0",), engines=("customer_onboarding_chain",), primitive_refs=("saas_ops.observe_usage",), status="modelled"),
    BusinessFunction(key="fulfilment", title="Ship orders and handle returns", question="Was every paid order shipped, delivered, and any return restocked or refunded?", archetypes=("dtc_commerce", "product_commerce", "marketplace_business"), loop_keys=("commerce.paid_order_to_delivered_customer@0.1.0",), engines=("fulfilment_chain",), status="modelled"),
    BusinessFunction(key="contractors", title="Engage and pay contractors", question="Was the work inside the agreement and paid through the supplier's bill?", archetypes=_ALL, loop_keys=("people.contractor_engaged_to_paid_work@0.1.0",), engines=("contractor_chain",), status="modelled"),
    BusinessFunction(key="incentives", title="Claim grants and R&D incentives", question="Which eligible cost was claimed, lodged by someone else, and received?", archetypes=_ALL, loop_keys=("finance.eligible_activity_to_received_incentive@0.1.0",), engines=("incentive_claim_chain",), primitive_refs=("accounting.match_grants", "accounting.search_grants"), status="modelled"),
)


def _known_engines() -> set[str]:
    from lightbulb import company_plan_migration as migration

    migration._register_late_lifecycles()
    return set(migration.ENGINE_LIFECYCLES)


def _known_primitives() -> set[str]:
    from lightbulb.executable_primitives import default_primitive_registry

    return {entry["primitive_ref"] for entry in default_primitive_registry().catalog()}


def validate_business_process_map() -> list[str]:
    """Every reference in the static table must exist in the code; returns the problems instead of raising."""

    problems: list[str] = []
    loops = {loop.loop_key: loop for loop in engine_loops()}
    engines, primitives = _known_engines(), _known_primitives()
    seen_keys: set[str] = set()
    covered_loops: set[str] = set()
    for row in BUSINESS_FUNCTIONS:
        if row.key in seen_keys:
            problems.append(f"duplicate function {row.key}")
        seen_keys.add(row.key)
        if row.status != "modelled" and not row.gap:
            problems.append(f"{row.key} is {row.status} without naming the gap")
        if row.status == "modelled" and row.gap:
            problems.append(f"{row.key} names a gap but is marked modelled")
        for key in row.loop_keys:
            if key not in loops:
                problems.append(f"{row.key} cites undeclared loop {key}")
            covered_loops.add(key)
        for engine in row.engines:
            if engine not in engines:
                problems.append(f"{row.key} cites unregistered engine {engine}")
        for ref in row.primitive_refs:
            if ref not in primitives:
                problems.append(f"{row.key} cites unknown primitive {ref}")
        for archetype in row.archetypes:
            if archetype not in ALL_ARCHETYPES:
                problems.append(f"{row.key} cites unknown archetype {archetype}")
    for key in loops:
        if key not in covered_loops:
            problems.append(f"declared loop {key} is not on the map")
    return problems


def coverage_summary() -> dict[str, Any]:
    rows = BUSINESS_FUNCTIONS
    counts = {status: sum(1 for row in rows if row.status == status) for status in ("modelled", "partial", "not_modelled")}
    by_archetype: dict[str, dict[str, int]] = {}
    for archetype in ALL_ARCHETYPES:
        mine = [row for row in rows if archetype in row.archetypes]
        by_archetype[archetype] = {status: sum(1 for row in mine if row.status == status) for status in ("modelled", "partial", "not_modelled")}
    return {"functions": len(rows), **counts, "loops": len(engine_loops()), "by_archetype": by_archetype}


def business_process_map() -> dict[str, Any]:
    payload = {"schema": BUSINESS_PROCESS_MAP_SCHEMA, "functions": [row.to_dict() for row in BUSINESS_FUNCTIONS], "loops": [loop.to_dict() for loop in engine_loops()], "summary": coverage_summary()}
    return {**payload, "map_digest": stable_digest(payload)}


def _cell(values: Sequence[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "-"


def render_business_process_map() -> str:
    """The generated document: functions by status, then the loop registry."""

    problems = validate_business_process_map()
    if problems:
        raise ValueError("business process map is inconsistent with the code: " + "; ".join(problems[:5]))
    loops = engine_loops()
    summary = coverage_summary()
    lines = ["# Lightbulb business process map", "", "Generated by `lightbulb-sdk/scripts/generate_business_process_map.py` from `lightbulb.business_process_map` and `lightbulb.engine_golden_loops`. Do not edit by hand.", "",
             f"{summary['functions']} business functions: {summary['modelled']} modelled, {summary['partial']} partial, {summary['not_modelled']} not modelled. {summary['loops']} engine golden loops are declared by the code.", "",
             "A *modelled* function has at least one replay-fenced lifecycle or golden loop carrying it; *partial* means only evaluations or proposals exist; *not modelled* means nothing in the SDK carries the function yet. Status is a claim about SDK source, never about hosted execution or provider certification.", ""]
    for status, heading in (("modelled", "Modelled functions"), ("partial", "Partially modelled functions"), ("not_modelled", "Not modelled")):
        rows = [row for row in BUSINESS_FUNCTIONS if row.status == status]
        if not rows:
            continue
        lines.append(f"## {heading}")
        lines.append("")
        lines.append("| function | question it answers | archetypes | loops | engines | primitives | gap |")
        lines.append("|---|---|---|---|---|---|---|")
        for row in rows:
            lines.append(f"| `{row.key}` {row.title} | {row.question} | {_cell(row.archetypes)} | {_cell(row.loop_keys)} | {_cell(row.engines)} | {_cell(row.primitive_refs)} | {row.gap or '-'} |")
        lines.append("")
    lines.append("## Coverage by archetype")
    lines.append("")
    lines.append("| archetype | modelled | partial | not modelled |")
    lines.append("|---|---|---|---|")
    for archetype, counts in summary["by_archetype"].items():
        lines.append(f"| `{archetype}` | {counts['modelled']} | {counts['partial']} | {counts['not_modelled']} |")
    lines.append("")
    lines.append("## Engine golden loops")
    lines.append("")
    lines.append("| loop | function | engines | modules | primitives | hands off to | money truth |")
    lines.append("|---|---|---|---|---|---|---|")
    for loop in loops:
        lines.append(f"| `{loop.loop_key}` {loop.title} | `{loop.function}` | {_cell(loop.engines)} | {_cell(m.removeprefix('lightbulb.') for m in loop.modules)} | {_cell(loop.primitive_refs)} | {_cell(loop.hands_off_to)} | {loop.money_truth} |")
    lines.append("")
    return "\n".join(lines)


__all__ = ["BUSINESS_FUNCTIONS", "BUSINESS_PROCESS_MAP_SCHEMA", "BusinessFunction", "business_process_map", "coverage_summary", "render_business_process_map", "validate_business_process_map"]
