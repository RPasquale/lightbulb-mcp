"""Verified financial context beside customer outcomes, without invented attribution.

Canonical finance reports do not contain customer allocation dimensions. Their
company totals must not be labeled as profit caused by a lifecycle intervention.
"""

from decimal import Decimal, ROUND_DOWN
from typing import Literal
from pydantic import Field, field_validator
from lightbulb.growth_profit import (
    BuildUnitEconomicsInput,
    ContributionMetrics,
    build_unit_economics,
    verify_profit_contribution_evidence,
)
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    stable_digest,
    parsed,
)
from lightbulb.company_customer_events import require


class CustomerFinancialAllocation(StrictModel):
    """Operator-reviewed share of one verified report, not provider customer attribution."""

    evidence_digest: Sha256Digest
    binding_ref: OpaqueRef
    share: Decimal = Field(gt=0, le=1, max_digits=9, decimal_places=8)

    @field_validator("share", mode="before")
    @classmethod
    def decimal_share(cls, value):
        require(
            not isinstance(value, (bool, float)), "CUSTOMER_PROFIT_DECIMAL_REQUIRED"
        )
        return Decimal(value)


class CustomerEstimatedCost(StrictModel):
    estimate_ref: OpaqueRef
    binding_ref: OpaqueRef
    kind: Literal["delivery", "tool"]
    amount: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")

    @field_validator("amount", mode="before")
    @classmethod
    def decimal_amount(cls, value):
        require(
            not isinstance(value, (bool, float)), "CUSTOMER_PROFIT_DECIMAL_REQUIRED"
        )
        return Decimal(value)


class CustomerFinancialAllocationPlan(StrictModel):
    review_ref: OpaqueRef
    reviewed_at: str
    allocations: tuple[CustomerFinancialAllocation, ...] = Field(
        min_length=1, max_length=100
    )
    estimated_costs: tuple[CustomerEstimatedCost, ...] = Field(
        default=(), max_length=100
    )


class CompanyCustomerProfit:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.gateway = lifecycle.events.gateway

    def report(self, inputs, *, allocation_plan=None):
        """Use sealed financial evidence; estimates and invoice balances are not ledgers."""
        inputs = BuildUnitEconomicsInput.model_validate(inputs)
        authority = dict(
            scope=self.gateway.authority_scope, scope_keyring=self.gateway.keyring
        )
        require(
            inputs.currency
            == self.lifecycle.sales.runner.bundle.operating_plan.blueprint.currency,
            "CUSTOMER_PROFIT_CURRENCY_MISMATCH",
        )
        for evidence in inputs.evidence:
            verify_profit_contribution_evidence(evidence, **authority)
        snapshot = build_unit_economics(inputs, **authority)
        # Account-wide reports provide context only. Repeated reports recompute
        # a snapshot; they never append a second cost or refund to a ledger.
        outcomes = []
        for row in self.lifecycle.configuration.enrollments:
            doc = self.lifecycle.events.read(self.lifecycle.ref(row))
            if (
                doc
                and doc.get("outcome")
                and parsed(doc["outcome"]["observed_at"])
                <= parsed(inputs.analysis_as_of)
                and any(
                    parsed(e.window_start)
                    <= parsed(doc["outcome"]["observed_at"])
                    < parsed(e.window_end)
                    for e in snapshot.admitted_evidence
                )
            ):
                outcomes.append(
                    {
                        "enrollment_ref": row.enrollment_ref,
                        "binding_ref": row.binding_ref,
                        "observed_at": doc["outcome"]["observed_at"],
                        "outcome_digest": stable_digest(doc["outcome"]),
                        "kind": doc["outcome"]["kind"],
                        "basis": "observed_after_intervention",
                    }
                )
        allocated = []
        if allocation_plan is not None:
            plan = CustomerFinancialAllocationPlan.model_validate(allocation_plan)
            require(
                parsed(plan.reviewed_at) <= parsed(inputs.analysis_as_of),
                "CUSTOMER_PROFIT_REVIEW_FUTURE",
            )
            rows = {r.binding_ref: r for r in self.lifecycle.configuration.enrollments}
            evidence_by_digest = {e.evidence_digest: e for e in inputs.evidence}
            admitted = {e.evidence_digest for e in snapshot.admitted_evidence}
            shares, identities, grouped = {}, set(), {}
            for allocation in plan.allocations:
                key = (allocation.evidence_digest, allocation.binding_ref)
                require(key not in identities, "CUSTOMER_PROFIT_ALLOCATION_DUPLICATED")
                identities.add(key)
                require(
                    allocation.binding_ref in rows, "CUSTOMER_PROFIT_BINDING_REQUIRED"
                )
                require(
                    allocation.evidence_digest in admitted,
                    "CUSTOMER_PROFIT_ADMITTED_EVIDENCE_REQUIRED",
                )
                shares[allocation.evidence_digest] = (
                    shares.get(allocation.evidence_digest, Decimal(0))
                    + allocation.share
                )
                require(
                    shares[allocation.evidence_digest] <= 1,
                    "CUSTOMER_PROFIT_ALLOCATION_EXCEEDED",
                )
                original = evidence_by_digest[allocation.evidence_digest]
                metrics = {}
                for name, value in original.metrics.model_dump().items():
                    if value is None:
                        continue
                    # Financial context only: fractional customer/order counts
                    # cannot support per-order or lifetime value assertions.
                    if name in {"orders", "units", "new_customers"}:
                        continue
                    metrics[name] = (Decimal(value) * allocation.share).quantize(
                        Decimal("0.01"), rounding=ROUND_DOWN
                    )
                require(bool(metrics), "CUSTOMER_PROFIT_MONEY_EVIDENCE_REQUIRED")
                payload = original.model_dump(
                    mode="python",
                    exclude={"receipt_key_id", "exact_scope_digest", "evidence_hmac"},
                )
                payload.update(
                    metrics=ContributionMetrics(**metrics),
                    evidence_digest=stable_digest(
                        {
                            "source": original.evidence_digest,
                            "allocation": allocation.to_dict(),
                            "review": plan.review_ref,
                        }
                    ),
                )
                grouped.setdefault(allocation.binding_ref, []).append(payload)
            for ref, evidence in grouped.items():
                unverified = build_unit_economics(
                    {
                        "economics_ref": "allocated-customer",
                        "analysis_as_of": inputs.analysis_as_of,
                        "currency": inputs.currency,
                        "evidence": evidence,
                        "staleness_policy": {
                            "require_verified_evidence": False,
                            "max_evidence_age_hours": inputs.staleness_policy.max_evidence_age_hours,
                        },
                    }
                )
                binding = self.lifecycle.sales.progression.binding(ref)
                allocated.append(
                    {
                        "binding_ref": ref,
                        "account_ref": binding.account_ref,
                        "workflow_goal": rows[ref].goal,
                        "allocation_review_ref": plan.review_ref,
                        "allocation_plan_digest": stable_digest(plan.to_dict()),
                        "basis": "operator_reviewed_allocation_of_verified_financial_reports",
                        "provider_verified_customer_attribution": False,
                        "allocations": [
                            a.to_dict()
                            for a in plan.allocations
                            if a.binding_ref == ref
                        ],
                        "outcomes": [
                            o
                            for o in outcomes
                            if o["binding_ref"] == ref
                            and any(
                                parsed(e["window_start"])
                                <= parsed(o["observed_at"])
                                < parsed(e["window_end"])
                                for e in evidence
                            )
                        ],
                        "economics": unverified.model_dump(mode="json"),
                    }
                )
            estimates = set()
            for cost in plan.estimated_costs:
                require(
                    cost.estimate_ref not in estimates,
                    "CUSTOMER_PROFIT_ESTIMATE_DUPLICATED",
                )
                estimates.add(cost.estimate_ref)
                require(
                    cost.binding_ref in grouped,
                    "CUSTOMER_PROFIT_ALLOCATED_BINDING_REQUIRED",
                )
                require(
                    cost.currency == inputs.currency,
                    "CUSTOMER_PROFIT_CURRENCY_MISMATCH",
                )
            for row in allocated:
                costs = [
                    c.to_dict()
                    for c in plan.estimated_costs
                    if c.binding_ref == row["binding_ref"]
                ]
                row["estimated_costs"] = costs
                row["estimated_cost_basis"] = (
                    "operator_estimates_not_deducted_from_observed_contribution"
                )
        return {
            "schema": "lightbulb.customer_profit_context.v1",
            "economics": snapshot.model_dump(mode="json"),
            "outcomes": outcomes,
            "allocated_contribution": allocated,
            "financial_basis": "verified_company_financial_context",
            "customer_profit_attribution_verified": False,
            "causal_profit_uplift_verified": False,
            "estimated_profit": None,
            "execution_authorized": False,
        }
