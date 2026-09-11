"""Order-level cash observations joined to canonical recorded workflow costs.

Checkout evidence joins provider customer, session, charge and refund identities.
Costs retain their original evidence grade; shared attribution requires a review.
This is a recomputed contribution snapshot, never a revenue recognition ledger.
"""

from decimal import Decimal, ROUND_DOWN
from typing import Literal

from pydantic import Field, field_validator

from lightbulb.billing_health import minor_units_to_amount
from lightbulb.company_engine_core import StrictModel, OpaqueRef, detached, parsed, stable_digest
from lightbulb.company_customer_commerce import CustomerOffer
from lightbulb.company_customer_events import require
from lightbulb.company_sales_progression import scoped_receipt
from lightbulb.connector_execution import ConnectorExecutionRequest


class CustomerCostAllocation(StrictModel):
    source_ref: OpaqueRef
    offer_ref: OpaqueRef
    share: Decimal = Field(gt=0, le=1, max_digits=9, decimal_places=8)
    review_ref: OpaqueRef

    @field_validator("share", mode="before")
    @classmethod
    def decimal_share(cls, value):
        require(not isinstance(value, (float, bool)), "CUSTOMER_FINANCIAL_DECIMAL_REQUIRED")
        return Decimal(value)


class CustomerFinancialRequest(StrictModel):
    report_ref: OpaqueRef
    offer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    preparation_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=100)
    cost_allocations: tuple[CustomerCostAllocation, ...] = Field(default=(), max_length=100)


class CheckoutRefundObservation(StrictModel):
    refund_id: str = Field(pattern=r"^re_[A-Za-z0-9]{1,128}$")
    amount_minor: int = Field(gt=0, le=10**12, strict=True)
    status: Literal["succeeded", "pending", "failed", "canceled", "requires_action"]


class CheckoutFinancialObservation(StrictModel):
    schema_id: Literal["lightbulb.stripe_checkout_financials.v1"] = Field(alias="schema")
    session_id: str = Field(pattern=r"^cs_[A-Za-z0-9_]{1,200}$")
    customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{1,128}$")
    offer_ref: OpaqueRef
    payment_intent_id: str = Field(pattern=r"^pi_[A-Za-z0-9]{1,128}$")
    charge_id: str = Field(pattern=r"^ch_[A-Za-z0-9]{1,128}$")
    currency: str = Field(pattern=r"^[a-z]{3}$")
    captured_minor: int = Field(gt=0, le=10**12, strict=True)
    refunded_minor: int = Field(ge=0, le=10**12, strict=True)
    refunds: tuple[CheckoutRefundObservation, ...] = Field(max_length=100)
    refunds_complete: bool
    disputed: bool
    processing_fee_minor: int | None = Field(ge=0, le=10**12, strict=True)
    balance_transaction_id: str | None = Field(pattern=r"^txn_[A-Za-z0-9]{1,128}$")


class CompanyCustomerFinancials:
    def __init__(self, commerce):
        self.commerce, self.sales, self.events = commerce, commerce.sales, commerce.events

    def _observe(self, offer_ref, *, now, fence):
        row = self.events.read(self.commerce.ref(offer_ref))
        require(row and row.get("session_id"), "CUSTOMER_FINANCIAL_CHECKOUT_REQUIRED")
        offer = CustomerOffer.model_validate(row["offer"])
        self.commerce._source(offer)
        request = ConnectorExecutionRequest(
            tool="stripe.get_checkout_financials",
            scope=self.commerce.scope,
            connector_account_ref=row["request"]["connector_account_ref"],
            arguments={**row["request"]["arguments"], "session_id": row["session_id"]},
        )
        fence()
        result = self.sales.executor.execute(request)
        receipt = scoped_receipt(result, request)
        now = self.sales._now(now)
        require(
            0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "CUSTOMER_FINANCIAL_READ_STALE",
        )
        observation = CheckoutFinancialObservation.model_validate(result.output)
        require(
            observation.session_id == row["session_id"]
            and observation.offer_ref == row["request"]["arguments"]["offer_ref"]
            and observation.customer_id == row["request"]["arguments"]["customer_id"]
            and observation.currency == offer.currency
            and observation.captured_minor == offer.amount_total_minor,
            "CUSTOMER_FINANCIAL_IDENTITY_MISMATCH",
        )
        require(
            observation.refunds_complete
            and len({r.refund_id for r in observation.refunds}) == len(observation.refunds)
            and sum(r.amount_minor for r in observation.refunds if r.status == "succeeded")
            == observation.refunded_minor
            <= observation.captured_minor,
            "CUSTOMER_FINANCIAL_REFUND_RECONCILIATION_REQUIRED",
        )
        require(
            (observation.processing_fee_minor is None)
            == (observation.balance_transaction_id is None),
            "CUSTOMER_FINANCIAL_FEE_PROOF_REQUIRED",
        )
        account = request.connector_account_ref
        # A charge can fund exactly one order within this signed company bundle.
        claim_ref = (
            self.events.prefix + "-cash-claim-" + stable_digest([account, observation.charge_id])
        )

        def claim(doc):
            require(
                doc.get("offer_ref", offer_ref) == offer_ref
                and doc.get("commerce_kind", "one_time") == "one_time",
                "CUSTOMER_FINANCIAL_CHARGE_ALREADY_JOINED",
            )
            doc.update(offer_ref=offer_ref, commerce_kind="one_time")

        self.events.change(claim_ref, claim, fence)
        binding = self.sales.progression.binding(offer.binding_ref)
        money = lambda value: minor_units_to_amount(value, observation.currency.upper())
        return {
            "offer_ref": offer_ref,
            "binding_ref": offer.binding_ref,
            "account_ref": binding.account_ref,
            "connector_account_ref": account,
            "currency": observation.currency.upper(),
            "financial_observation": observation.to_dict(),
            "receipt": receipt.to_dict(),
            "captured": str(money(observation.captured_minor)),
            "refunded": str(money(observation.refunded_minor)),
            "net_collected": str(money(observation.captured_minor - observation.refunded_minor)),
            "processing_fee": (
                None
                if observation.processing_fee_minor is None
                else str(money(observation.processing_fee_minor))
            ),
            "recorded_costs": [],
            "estimated_costs": [],
            "provider_customer_join_verified": True,
            "settlement_verified": False,
            "causal_uplift_verified": False,
        }

    def reconcile(self, request, *, now, fence, cost_register=None, cost_plan=None):
        request = CustomerFinancialRequest.model_validate(request)
        require(
            len(set(request.offer_refs)) == len(request.offer_refs),
            "CUSTOMER_FINANCIAL_ORDER_DUPLICATED",
        )
        require(
            len(set(request.preparation_refs)) == len(request.preparation_refs),
            "CUSTOMER_FINANCIAL_PREPARATION_DUPLICATED",
        )
        rows = [self._observe(ref, now=now, fence=fence) for ref in request.offer_refs]
        by_offer = {r["offer_ref"]: r for r in rows}
        unallocated = []
        require(
            (cost_register is None) == (cost_plan is None), "CUSTOMER_FINANCIAL_COST_PLAN_REQUIRED"
        )
        if cost_register is None:
            require(
                not request.cost_allocations and not request.preparation_refs,
                "CUSTOMER_FINANCIAL_COST_REGISTER_REQUIRED",
            )
        else:
            unallocated = self._join_costs(
                request, rows, cost_register, cost_plan, now=now, fence=fence
            )
        for row in rows:
            known_cost = sum((Decimal(c["amount"]) for c in row["recorded_costs"]), Decimal(0))
            row["recorded_cost_total"] = str(known_cost)
            row["contribution_after_recorded_costs"] = (
                None
                if row["processing_fee"] is None or row["financial_observation"]["disputed"]
                else str(
                    Decimal(row["net_collected"]) - Decimal(row["processing_fee"]) - known_cost
                )
            )
            row["cost_coverage_complete"] = False
            row["basis"] = (
                "captured_less_succeeded_refunds_original_processing_fee_and_recorded_costs"
            )
        report = {
            "schema": "lightbulb.customer_financial_reconciliation.v1",
            "report_ref": request.report_ref,
            "orders": list(by_offer.values()),
            "unallocated_cost_sources": unallocated,
            "observed_at": self.sales._now(now),
            "execution_authorized": False,
            "revenue_recognition_performed": False,
        }
        ref = self.events.prefix + "-financial-report-" + stable_digest(request.report_ref)

        def retain(doc):
            require(
                doc.get("request", request.to_dict()) == request.to_dict(),
                "CUSTOMER_FINANCIAL_REPORT_CHANGED",
            )
            doc.update(request=request.to_dict(), report=report)

        self.events.change(ref, retain, fence)
        return report

    def _join_costs(self, request, rows, register, plan, *, now, fence, allocation_kind="one_time"):
        from lightbulb.company_cost_centres import register_summary, CostRegisterLedger

        summary = register_summary(register, source_plan=plan)  # replays original source evidence
        raw = detached(register)
        require(
            all(raw["scope"].get(k) == v for k, v in self.sales.runner.bundle.scope.items()),
            "CUSTOMER_FINANCIAL_COST_SCOPE_MISMATCH",
        )
        require(
            not raw["transition_history"]
            or parsed(raw["transition_history"][-1]["command"]["occurred_at"]) <= parsed(now),
            "CUSTOMER_FINANCIAL_COST_FROM_FUTURE",
        )
        ledger = CostRegisterLedger.model_validate(raw["ledger"])
        require(
            all(r["currency"] == summary["currency"] for r in rows),
            "CUSTOMER_FINANCIAL_COST_CURRENCY_MISMATCH",
        )
        by_offer = {r["offer_ref"]: r for r in rows}
        # Match actual retained domain dispatch traces to canonical metered artifacts.
        traces = {}
        for ref in request.preparation_refs:
            prepared = self.sales.progression.read(ref)
            require(
                prepared and prepared.get("phase") == "complete" and prepared.get("agent_trace_id"),
                "CUSTOMER_FINANCIAL_PREPARATION_REQUIRED",
            )
            matches = [
                r
                for r in rows
                if prepared.get("binding_digest")
                == stable_digest(self.sales.progression.binding(r["binding_ref"]).to_dict())
            ]
            require(len(matches) == 1, "CUSTOMER_FINANCIAL_COST_ORDER_AMBIGUOUS")
            require(prepared["agent_trace_id"] not in traces, "CUSTOMER_FINANCIAL_TRACE_DUPLICATED")
            traces[prepared["agent_trace_id"]] = matches[0]["offer_ref"]
        metered = {}
        for transition in raw["transition_history"]:
            command = transition["command"]
            artifact = command.get("receipt", {}).get("metered_artifact")
            if command["event"] == "record_source" and artifact:
                metered[command["receipt"]["source_ref"]] = artifact["trace_id"]
        allocations = {}
        for declaration in request.cost_allocations:
            require(declaration.offer_ref in by_offer, "CUSTOMER_FINANCIAL_COST_ORDER_REQUIRED")
            allocations.setdefault(declaration.source_ref, []).append(declaration)
        require(
            set(allocations) <= {s.source_ref for s in ledger.sources},
            "CUSTOMER_FINANCIAL_COST_SOURCE_REQUIRED",
        )
        unallocated = []
        for source in ledger.sources:
            if source.spend_amount == 0:
                continue
            parts = allocations.get(source.source_ref, [])
            automatic = traces.get(metered.get(source.source_ref))
            require(not (automatic and parts), "CUSTOMER_FINANCIAL_COST_DOUBLE_ATTRIBUTION")
            if automatic:
                shares = [(automatic, Decimal(1), "recorded_dispatch_trace", None)]
            elif parts:
                require(
                    len({p.offer_ref for p in parts}) == len(parts)
                    and sum(p.share for p in parts) <= 1,
                    "CUSTOMER_FINANCIAL_COST_OVERALLOCATED",
                )
                shares = [
                    (p.offer_ref, p.share, "reviewed_allocation", p.review_ref) for p in parts
                ]
            else:
                unallocated.append(source.source_ref)
                continue
            claim_ref = (
                self.events.prefix + "-cost-claim-" + stable_digest(source.primary_source_ref)
            )
            allocation = sorted(
                [[ref, str(share), basis, review] for ref, share, basis, review in shares]
            )

            def claim(doc):
                require(
                    doc.get("allocation", allocation) == allocation
                    and doc.get(
                        "allocation_kind", "one_time" if "allocation" in doc else allocation_kind
                    )
                    == allocation_kind,
                    "CUSTOMER_FINANCIAL_COST_ALREADY_ALLOCATED",
                )
                doc.update(allocation=allocation, allocation_kind=allocation_kind)

            self.events.change(claim_ref, claim, fence)
            amount = max(Decimal(0), source.spend_amount - source.returned)
            estimated = source.source_kind in {"worker", "metered_dispatch"}
            for offer_ref, share, basis, review in shares:
                by_offer[offer_ref]["estimated_costs" if estimated else "recorded_costs"].append(
                    {
                        "source_ref": source.source_ref,
                        "source_digest": source.source_digest,
                        "amount": str(
                            (amount * share).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
                        ),
                        "basis": basis,
                        "review_ref": review,
                        "evidence_grade": (
                            "platform_metered_estimate"
                            if estimated
                            else "canonical_recorded_source"
                        ),
                    }
                )
            if sum(share for _, share, _, _ in shares) < 1:
                unallocated.append(source.source_ref)
        return unallocated
