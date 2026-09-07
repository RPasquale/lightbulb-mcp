"""Executable proposal primitives for the ten-workflow profit flywheel."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)
from lightbulb.profit_workflow_blueprints import (
    PROFIT_WORKFLOW_DEFINITIONS,
    ProfitWorkflowDefinition,
)
from lightbulb.profit_workflow_runtime import (
    PlanProfitWorkflowInput,
    ProfitWorkflowPlan,
    plan_profit_workflow,
)


_EXAMPLE_SOURCE: dict[str, str] = {
    "finance.allocate_launch_portfolio_profit": "host.normalized_profit_ledger",
    "product.discover_profitable_opportunities": "host.market_demand_snapshot",
    "gtm.optimize_offer_price_and_margin": "host.normalized_unit_economics",
    "commerce.govern_inventory_and_fulfillment": "host.inventory_snapshot",
    "commerce.optimize_storefront_conversion": "host.experiment_snapshot",
    "content.run_creative_experiment_factory": "host.experiment_snapshot",
    "growth.allocate_incremental_acquisition": "host.paid_media_spend_snapshot",
    "crm.orchestrate_profit_aware_lifecycle": "host.customer_cohort_snapshot",
    "commerce.recover_abandoned_revenue": "host.checkout_recovery_snapshot",
    "customer_success.prevent_returns_and_expand_ltv": (
        "host.customer_cohort_snapshot"
    ),
}

_EXAMPLE_VALUE: dict[str, str] = {
    "finance.allocate_launch_portfolio_profit": "3750.00",
    "product.discover_profitable_opportunities": "0.720000",
    "gtm.optimize_offer_price_and_margin": "37.50",
    "commerce.govern_inventory_and_fulfillment": "0.030000",
    "commerce.optimize_storefront_conversion": "0.75",
    "content.run_creative_experiment_factory": "37.50",
    "growth.allocate_incremental_acquisition": "3.200000",
    "crm.orchestrate_profit_aware_lifecycle": "7.50",
    "commerce.recover_abandoned_revenue": "3750.00",
    "customer_success.prevent_returns_and_expand_ltv": "240.00",
}

_EXAMPLE_TARGET: dict[str, str] = {
    "finance.allocate_launch_portfolio_profit": "4500.00",
    "product.discover_profitable_opportunities": "0.750000",
    "gtm.optimize_offer_price_and_margin": "42.00",
    "commerce.govern_inventory_and_fulfillment": "0.020000",
    "commerce.optimize_storefront_conversion": "0.90",
    "content.run_creative_experiment_factory": "42.00",
    "growth.allocate_incremental_acquisition": "3.500000",
    "crm.orchestrate_profit_aware_lifecycle": "9.00",
    "commerce.recover_abandoned_revenue": "4500.00",
    "customer_success.prevent_returns_and_expand_ltv": "275.00",
}

_EXAMPLE_EXPOSURE: dict[str, int] = {
    "gtm.optimize_offer_price_and_margin": 100,
    "commerce.optimize_storefront_conversion": 5_000,
    "content.run_creative_experiment_factory": 100_000,
    "crm.orchestrate_profit_aware_lifecycle": 500,
}

_EXAMPLE_ACTION_ACCOUNT: dict[str, tuple[str, str]] = {
    "gtm.optimize_offer_price_and_margin": ("shopify", "shopify-primary"),
    "commerce.govern_inventory_and_fulfillment": ("xero", "xero-primary"),
    "commerce.optimize_storefront_conversion": ("shopify", "shopify-primary"),
}


def _example_ledger() -> dict[str, Any]:
    return {
        "currency": "USD",
        "gross_sales": "10000.00",
        "discounts": "500.00",
        "refunds": "300.00",
        "cogs": "3000.00",
        "fulfillment_cost": "800.00",
        "payment_fees": "250.00",
        "acquisition_cost": "1200.00",
        "service_cost": "200.00",
    }


def _example_inputs(definition: ProfitWorkflowDefinition) -> dict[str, Any]:
    workflow_id = definition.workflow_id
    metric = definition.primary_metric
    evidence: dict[str, Any] = {
        "evidence_ref": "baseline-primary",
        "provider": "host",
        "source_capability": _EXAMPLE_SOURCE[workflow_id],
        "metric": metric,
        "unit": {
            "finance.allocate_launch_portfolio_profit": "money",
            "product.discover_profitable_opportunities": "ratio",
            "gtm.optimize_offer_price_and_margin": "money",
            "commerce.govern_inventory_and_fulfillment": "ratio",
            "commerce.optimize_storefront_conversion": "money",
            "content.run_creative_experiment_factory": "money",
            "growth.allocate_incremental_acquisition": "multiple",
            "crm.orchestrate_profit_aware_lifecycle": "money",
            "commerce.recover_abandoned_revenue": "money",
            "customer_success.prevent_returns_and_expand_ltv": "money",
        }[workflow_id],
        "value": _EXAMPLE_VALUE[workflow_id],
        "sample_size": 1_000,
        "observed_at": "2026-08-19T10:00:00Z",
        "window_start": "2026-08-01T00:00:00Z",
        "window_end": "2026-08-18T23:59:59Z",
        "evidence_digest": "a" * 64,
    }
    if evidence["unit"] == "money":
        evidence["currency"] = "USD"
    if metric in {
        "contribution_profit",
        "contribution_profit_per_contact",
        "contribution_profit_per_order",
        "contribution_profit_per_session",
        "creative_profit_per_thousand_impressions",
        "recovered_contribution_profit",
    }:
        evidence["ledger"] = _example_ledger()
    if workflow_id in _EXAMPLE_EXPOSURE:
        evidence["exposure_count"] = _EXAMPLE_EXPOSURE[workflow_id]

    first_action = definition.action_capabilities[0]
    account = _EXAMPLE_ACTION_ACCOUNT.get(workflow_id)
    candidate: dict[str, Any] = {
        "candidate_ref": "primary-lever",
        "title": f"Pilot {first_action.purpose.lower()}",
        "capability": first_action.capability,
        "rationale": (
            "Run one bounded pilot, preserve a holdout, and stop if verified "
            "contribution profit misses the declared floor."
        ),
        "parameters": [
            {"name": "pilot_scope", "value": "one store, one segment, one tranche"},
            {"name": "stop_loss", "value": "halt on negative contribution profit"},
        ],
        "expected_incremental_revenue": "5000.00",
        "expected_incremental_cost": "1500.00",
        "implementation_cost": "500.00",
        "downside_loss": "500.00",
        "confidence": "0.700000",
        "time_to_value_days": 14,
        "measurement_metric": metric,
        "supported_by_evidence_refs": ["baseline-primary"],
    }
    bindings: list[dict[str, str]] = []
    if account is not None:
        provider, account_ref = account
        bindings.append({"provider": provider, "connector_account_ref": account_ref})
        candidate["target_account_ref"] = account_ref
    return {
        "analysis_as_of": "2026-08-19T12:00:00Z",
        "plan_ref": definition.workflow_id.replace(".", "-").replace("_", "-"),
        "launch_ref": "focus-kit-launch",
        "objective": definition.promise,
        "account_bindings": bindings,
        "baseline": _example_ledger(),
        "evidence": [evidence],
        "candidates": [candidate],
        "policy": {
            "target_metric": metric,
            "target_value": _EXAMPLE_TARGET[workflow_id],
            "max_actions": 3,
            "budget_cap": "10000.00",
            "minimum_expected_profit": "0.00",
            "minimum_confidence": "0.250000",
            "unverified_confidence_haircut": "0.500000",
            "minimum_sample_size": 100,
            "max_observation_age_hours": 720,
            "measurement_window_hours": 168,
            "max_iterations": 3,
        },
        "source_plan_digests": [],
    }


class ProfitWorkflowPrimitive(
    BusinessProcessPrimitive[PlanProfitWorkflowInput, ProfitWorkflowPlan]
):
    """One thin SDK adapter over a code-owned profit workflow blueprint."""

    version = "1.0.0"
    input_model = PlanProfitWorkflowInput
    output_model = ProfitWorkflowPlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def __init__(self, definition: ProfitWorkflowDefinition) -> None:
        self.definition = definition
        self.primitive_ref = definition.workflow_id
        self.title = definition.title
        self.description = f"Profit workflow: {definition.promise}"
        self.example_inputs = _example_inputs(definition)

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["capability_hints"] = list(
            dict.fromkeys(
                (
                    *self.definition.evidence_capabilities,
                    *(item.capability for item in self.definition.action_capabilities),
                )
            )
        )
        contract["profit_blueprint"] = self.definition.model_dump(
            mode="json",
            exclude_none=True,
        )
        contract["capability_hints_are_dispatch_authority"] = False
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PlanProfitWorkflowInput,
    ) -> PrimitiveExecutionResult[ProfitWorkflowPlan]:
        del context
        output = plan_profit_workflow(self.definition.workflow_id, inputs)
        return PrimitiveExecutionResult[ProfitWorkflowPlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=output.summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type=self.definition.emits_event,
                    payload={
                        "workflow_id": output.workflow_id,
                        "launch_ref": output.launch_ref,
                        "plan_digest": output.plan_digest,
                        "selected_action_count": len(output.actions),
                        "optimization_status": output.optimization_status,
                        "live_systems_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="profit_workflow_plan",
                    summary=(
                        "The SDK ranked bounded profit levers and compiled an immutable "
                        "proposal without invoking any external system."
                    ),
                    refs={"plan_sha256": output.plan_digest},
                )
            ],
        )


PROFIT_EXECUTABLE_PRIMITIVES: tuple[ProfitWorkflowPrimitive, ...] = tuple(
    ProfitWorkflowPrimitive(definition) for definition in PROFIT_WORKFLOW_DEFINITIONS
)


def profit_workflow_example_inputs(workflow_id: str) -> dict[str, Any]:
    """Return a defensive copy of one valid, proposal-only example input."""

    for primitive in PROFIT_EXECUTABLE_PRIMITIVES:
        if primitive.primitive_ref == workflow_id:
            return deepcopy(dict(primitive.example_inputs))
    raise KeyError(f"Unknown profit workflow: {workflow_id}")


__all__ = [
    "PROFIT_EXECUTABLE_PRIMITIVES",
    "ProfitWorkflowPrimitive",
    "profit_workflow_example_inputs",
]
