"""Recurring customer cash snapshots, with contract run rate and estimates kept separate.

Invoice billing periods are provider invoice periods, not revenue-recognition periods.
Credits and paid-out-of-band invoices never establish captured cash.
"""

from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from lightbulb.billing_health import minor_units_to_amount
from lightbulb.company_engine_core import StrictModel, stable_digest, parsed
from lightbulb.company_customer_events import require
from lightbulb.company_customer_financials import (
    CustomerFinancialRequest,
    CheckoutRefundObservation,
    CompanyCustomerFinancials,
)
from lightbulb.company_customer_subscriptions import CustomerSubscriptionOffer


class SubscriptionPaymentObservation(StrictModel):
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


class SubscriptionInvoiceObservation(StrictModel):
    invoice_id: str = Field(pattern=r"^in_[A-Za-z0-9]{1,128}$")
    currency: str = Field(pattern=r"^[a-z]{3}$")
    status: Literal["draft", "open", "paid", "void", "uncollectible"]
    billing_reason: str = Field(min_length=1, max_length=100)
    period_start: int = Field(ge=0, strict=True)
    period_end: int = Field(ge=0, strict=True)
    paid_at: int | None = Field(ge=0, strict=True)
    amount_due_minor: int = Field(ge=0, le=10**12, strict=True)
    amount_paid_minor: int = Field(ge=0, le=10**12, strict=True)
    amount_remaining_minor: int = Field(ge=0, le=10**12, strict=True)
    pre_payment_credit_notes_amount_minor: int = Field(ge=0, le=10**12, strict=True)
    post_payment_credit_notes_amount_minor: int = Field(ge=0, le=10**12, strict=True)
    starting_balance_minor: int | None = Field(ge=-(10**12), le=10**12, strict=True)
    ending_balance_minor: int | None = Field(ge=-(10**12), le=10**12, strict=True)
    paid_out_of_band: bool
    cash_verified: bool
    payment: SubscriptionPaymentObservation | None


class _SubscriptionSnapshot(StrictModel):
    schema_id: Literal["lightbulb.stripe_customer_subscription.v1"] = Field(alias="schema")
    id: str = Field(pattern=r"^sub_[A-Za-z0-9]{1,128}$")
    customer: str = Field(pattern=r"^cus_[A-Za-z0-9]{1,128}$")
    status: Literal[
        "trialing",
        "active",
        "incomplete",
        "incomplete_expired",
        "past_due",
        "canceled",
        "unpaid",
        "paused",
    ]
    cancel_at_period_end: bool
    item_id: str = Field(pattern=r"^si_[A-Za-z0-9]{1,128}$")
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]{1,128}$")
    quantity: int = Field(ge=1, le=1000, strict=True)
    unit_amount_minor: int = Field(ge=1, le=10**9, strict=True)
    currency: str = Field(pattern=r"^[a-z]{3}$")
    interval: Literal["day", "week", "month", "year"]
    interval_count: int = Field(ge=1, le=12, strict=True)
    current_period_end: int = Field(gt=0, strict=True)
    trial_end: int | None = Field(gt=0, strict=True)
    pending_update: bool
    latest_invoice_id: str | None = Field(pattern=r"^in_[A-Za-z0-9]{1,128}$")
    latest_invoice_paid: bool
    access_authorized: Literal[False]
    access_recommendation: Literal["propose_paid_access", "propose_trial_access", "review_access"]
    subscription_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class SubscriptionFinancialObservation(StrictModel):
    schema_id: Literal["lightbulb.stripe_subscription_financials.v1"] = Field(alias="schema")
    customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{1,128}$")
    subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{1,128}$")
    subscription: dict
    billing_readiness: Literal["ready", "unknown"]
    trial_start: int | None = Field(gt=0, strict=True)
    trial_end: int | None = Field(gt=0, strict=True)
    invoices_complete: bool
    invoices: tuple[SubscriptionInvoiceObservation, ...] = Field(max_length=100)

    @field_validator("subscription")
    @classmethod
    def subscription_snapshot(cls, value):
        return _SubscriptionSnapshot.model_validate(value).model_dump(mode="json", by_alias=True)


class SubscriptionFinancialRequest(CustomerFinancialRequest):
    estimated_remaining_months: Decimal | None = Field(default=None, gt=0, le=120)
    estimate_review_ref: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("estimated_remaining_months", mode="before")
    @classmethod
    def decimal_months(cls, value):
        require(not isinstance(value, (float, bool)), "SUBSCRIPTION_FINANCIAL_DECIMAL_REQUIRED")
        return None if value is None else Decimal(value)


class CompanySubscriptionFinancials:
    def __init__(self, subscriptions):
        self.subscriptions = subscriptions
        self.sales, self.events = subscriptions.sales, subscriptions.events

    @property
    def index_ref(self):
        return self.events.prefix + "-subscription-financial-cadence"

    def register(self, request, *, fence):
        """Register a bounded cash report on the existing leased sales cadence.

        Cost joins remain explicit reconciliations against current canonical source
        artifacts. A cadence request cannot retain a stale cost-register snapshot.
        """
        request = SubscriptionFinancialRequest.model_validate(request)
        require(
            not request.cost_allocations and not request.preparation_refs,
            "SUBSCRIPTION_FINANCIAL_CADENCE_COST_ARTIFACT_REQUIRED",
        )
        require(
            len(request.offer_refs) <= 10
            and len(set(request.offer_refs)) == len(request.offer_refs),
            "SUBSCRIPTION_FINANCIAL_CADENCE_OFFER_LIMIT",
        )
        require(
            (request.estimated_remaining_months is None) == (request.estimate_review_ref is None),
            "SUBSCRIPTION_FINANCIAL_ESTIMATE_REVIEW_REQUIRED",
        )
        for offer_ref in request.offer_refs:
            row = self.events.read(self.subscriptions.ref(offer_ref))
            require(row and row.get("offer"), "SUBSCRIPTION_FINANCIAL_OFFER_REQUIRED")
            self.subscriptions.commerce._source(
                CustomerSubscriptionOffer.model_validate(row["offer"])
            )

        def retain(doc):
            requests = doc.setdefault("requests", {})
            require(
                request.report_ref in requests or len(requests) < 100,
                "SUBSCRIPTION_FINANCIAL_CADENCE_LIMIT",
            )
            require(
                requests.get(request.report_ref, request.to_dict()) == request.to_dict(),
                "SUBSCRIPTION_FINANCIAL_REPORT_CHANGED",
            )
            requests[request.report_ref] = request.to_dict()

        self.events.change(self.index_ref, retain, fence)
        return {"report_ref": request.report_ref, "status": "registered"}

    def unregister(self, report_ref, *, fence):
        def remove(doc):
            doc.setdefault("requests", {}).pop(report_ref, None)

        self.events.change(self.index_ref, remove, fence)
        return {"report_ref": report_ref, "status": "unregistered"}

    def tick(self, *, now, fence, max_reports=1):
        from lightbulb.company_host_journal import HostAuthorityError
        from lightbulb.company_hosted_scheduler import CheckpointConflict

        require(
            type(max_reports) is int and 1 <= max_reports <= 10,
            "SUBSCRIPTION_FINANCIAL_CADENCE_LIMIT",
        )
        fence()
        index = self.events.read(self.index_ref)
        if not index or not index.get("requests"):
            return {"reports": [], "poll_again": False}
        requests = index["requests"]
        require(
            isinstance(requests, dict) and len(requests) <= 100,
            "SUBSCRIPTION_FINANCIAL_CADENCE_INVALID",
        )
        keys = list(requests)
        cursor = index.get("cursor", 0) % len(keys)
        selected = (keys[cursor:] + keys[:cursor])[:max_reports]
        reports = []
        for ref in selected:
            try:
                fence()
                report = self.reconcile(requests[ref], now=now, fence=fence)
                reports.append(
                    {
                        "report_ref": ref,
                        "status": "observed",
                        "cash_coverage_complete": all(
                            r["cash_coverage_complete"] for r in report["subscriptions"]
                        ),
                    }
                )
            except (HostAuthorityError, CheckpointConflict):
                raise
            except Exception:
                reports.append({"report_ref": ref, "status": "reconciliation_required"})

        def advance(doc):
            doc["cursor"] = (cursor + len(selected)) % max(1, len(doc.get("requests", {})))

        self.events.change(self.index_ref, advance, fence)
        return {"reports": reports, "poll_again": True}

    def observe(self, offer_ref, *, now, fence):
        """Fresh, scoped invoice evidence for reconciliation and trial conversion workflows."""
        retained = self.events.read(self.subscriptions.ref(offer_ref))
        require(retained and retained.get("offer"), "SUBSCRIPTION_FINANCIAL_OFFER_REQUIRED")
        offer = CustomerSubscriptionOffer.model_validate(retained["offer"])
        binding, source = self.subscriptions.commerce._source(offer)
        require(
            source.connector_account_ref == retained["request"]["connector_account_ref"]
            and source.arguments["customer_id"] == retained["request"]["arguments"]["customer_id"]
            and binding.account_ref == retained["account_ref"],
            "SUBSCRIPTION_FINANCIAL_BILLING_MAPPING_CHANGED",
        )
        fence()
        current = self.subscriptions.observe(offer_ref, now=now, fence=fence)
        sub = current.get("subscription")
        require(sub is not None, "SUBSCRIPTION_FINANCIAL_ACCEPTANCE_REQUIRED")
        request = self.subscriptions._request(
            "stripe.get_subscription_financials",
            {
                "customer_id": retained["request"]["arguments"]["customer_id"],
                "subscription_id": sub["id"],
            },
            retained["request"]["connector_account_ref"],
        )
        fence()
        raw, receipt, at = self.subscriptions._read(request, now)
        observation = SubscriptionFinancialObservation.model_validate(raw)
        require(
            observation.customer_id == request.arguments["customer_id"]
            and observation.subscription_id == sub["id"],
            "SUBSCRIPTION_FINANCIAL_IDENTITY_MISMATCH",
        )
        self.subscriptions._subscription_output(
            observation.subscription, observation.subscription_id, observation.customer_id
        )
        require(
            observation.subscription.get("currency") == offer.currency,
            "SUBSCRIPTION_FINANCIAL_CURRENCY_MISMATCH",
        )
        require(
            observation.trial_start is None
            or observation.trial_end is not None
            and observation.trial_start <= observation.trial_end,
            "SUBSCRIPTION_FINANCIAL_TRIAL_PERIOD_INVALID",
        )
        seen, charges, refunds = set(), set(), set()
        for invoice in observation.invoices:
            require(
                invoice.invoice_id not in seen
                and invoice.currency == offer.currency
                and invoice.period_start <= invoice.period_end
                and (invoice.paid_at is None or invoice.paid_at <= int(parsed(at).timestamp())),
                "SUBSCRIPTION_FINANCIAL_INVOICE_INVALID",
            )
            seen.add(invoice.invoice_id)
            payment = invoice.payment
            require(
                invoice.cash_verified == (payment is not None),
                "SUBSCRIPTION_FINANCIAL_CASH_PROOF_REQUIRED",
            )
            if payment is None:
                continue
            require(
                not invoice.paid_out_of_band
                and payment.currency == offer.currency
                and payment.charge_id not in charges,
                "SUBSCRIPTION_FINANCIAL_CHARGE_INVALID",
            )
            charges.add(payment.charge_id)
            require(
                payment.refunded_minor <= payment.captured_minor
                and (payment.processing_fee_minor is None)
                == (payment.balance_transaction_id is None),
                "SUBSCRIPTION_FINANCIAL_PAYMENT_INVALID",
            )
            succeeded = 0
            for refund in payment.refunds:
                require(
                    refund.refund_id not in refunds
                    and refund.amount_minor <= payment.captured_minor,
                    "SUBSCRIPTION_FINANCIAL_REFUND_INVALID",
                )
                refunds.add(refund.refund_id)
                if refund.status == "succeeded":
                    succeeded += refund.amount_minor
            require(
                succeeded <= payment.refunded_minor
                and (not payment.refunds_complete or succeeded == payment.refunded_minor),
                "SUBSCRIPTION_FINANCIAL_REFUND_INVALID",
            )
        return {**observation.model_dump(mode="json", by_alias=True), "receipt": receipt}

    def reconcile(self, request, *, now, fence, cost_register=None, cost_plan=None):
        request = SubscriptionFinancialRequest.model_validate(request)
        require(
            len(set(request.offer_refs)) == len(request.offer_refs)
            and len(set(request.preparation_refs)) == len(request.preparation_refs),
            "SUBSCRIPTION_FINANCIAL_DUPLICATE_INPUT",
        )
        require(
            (request.estimated_remaining_months is None) == (request.estimate_review_ref is None),
            "SUBSCRIPTION_FINANCIAL_ESTIMATE_REVIEW_REQUIRED",
        )
        rows = []
        for ref in request.offer_refs:
            evidence = self.observe(ref, now=now, fence=fence)
            retained = self.events.read(self.subscriptions.ref(ref))
            offer = CustomerSubscriptionOffer.model_validate(retained["offer"])
            account = retained["request"]["connector_account_ref"]
            payments = [i["payment"] for i in evidence["invoices"] if i["payment"]]
            for invoice in evidence["invoices"]:
                claim_ref = (
                    self.events.prefix
                    + "-invoice-claim-"
                    + stable_digest([account, invoice["invoice_id"]])
                )
                self._claim(claim_ref, ref, fence)
            for payment in payments:
                self._claim(
                    self.events.prefix
                    + "-cash-claim-"
                    + stable_digest([account, payment["charge_id"]]),
                    ref,
                    fence,
                )
            money = lambda value: minor_units_to_amount(value, offer.currency.upper())
            captured = sum(p["captured_minor"] for p in payments)
            refunded = sum(p["refunded_minor"] for p in payments)
            coverage = evidence["invoices_complete"] and all(
                (i["payment"] is not None or i["amount_paid_minor"] == 0)
                and (not i["payment"] or i["payment"]["refunds_complete"])
                for i in evidence["invoices"]
            )
            fees = sum(p["processing_fee_minor"] or 0 for p in payments)
            fees_known = all(p["processing_fee_minor"] is not None for p in payments)
            sub = evidence["subscription"]
            amount = sub.get("unit_amount_minor")
            quantity, count = sub.get("quantity"), sub.get("interval_count")
            require(
                type(amount) is int
                and amount > 0
                and type(quantity) is int
                and 0 < quantity <= 1000
                and type(count) is int
                and 0 < count <= 12,
                "SUBSCRIPTION_FINANCIAL_TERMS_REQUIRED",
            )
            interval = sub.get("interval")
            require(
                interval in {"day", "week", "month", "year"},
                "SUBSCRIPTION_FINANCIAL_INTERVAL_REQUIRED",
            )
            monthly = money(amount * quantity) / Decimal(count)
            monthly *= {
                "day": Decimal(365) / 12,
                "week": Decimal(52) / 12,
                "month": Decimal(1),
                "year": Decimal(1) / 12,
            }[interval]
            active = (
                sub["status"] == "active"
                and not sub.get("pending_update")
                and sub["current_period_end"] > int(parsed(now).timestamp())
            )
            rows.append(
                {
                    "offer_ref": ref,
                    "binding_ref": offer.binding_ref,
                    "account_ref": retained["account_ref"],
                    "connector_account_ref": account,
                    "subscription_id": evidence["subscription_id"],
                    "currency": offer.currency.upper(),
                    "financial_observation": evidence,
                    "captured": str(money(captured)),
                    "refunded": str(money(refunded)),
                    "net_collected": str(money(captured - refunded)),
                    "processing_fee": str(money(fees)) if fees_known else None,
                    "cash_coverage_complete": coverage,
                    "recorded_costs": [],
                    "estimated_costs": [],
                    "contract_monthly_run_rate": str(monthly) if active else "0",
                    "run_rate_basis": "current_fixed_price_excluding_tax_discount_churn_and_usage",
                    "scheduled_cancellation": sub["cancel_at_period_end"],
                    "estimated_remaining_contract_value": (
                        None
                        if request.estimated_remaining_months is None
                        or not active
                        or sub["cancel_at_period_end"]
                        else {
                            "amount": (
                                str(monthly * request.estimated_remaining_months) if active else "0"
                            ),
                            "assumed_remaining_months": str(request.estimated_remaining_months),
                            "review_ref": request.estimate_review_ref,
                            "evidence_grade": "operator_estimate",
                            "profit_or_cash_verified": False,
                        }
                    ),
                    "settlement_verified": False,
                    "cost_coverage_complete": False,
                }
            )
        require(
            (cost_register is None) == (cost_plan is None),
            "SUBSCRIPTION_FINANCIAL_COST_PLAN_REQUIRED",
        )
        unallocated = []
        if cost_register is None:
            require(
                not request.cost_allocations and not request.preparation_refs,
                "SUBSCRIPTION_FINANCIAL_COST_REGISTER_REQUIRED",
            )
        else:
            unallocated = CompanyCustomerFinancials(self.subscriptions.commerce)._join_costs(
                request,
                rows,
                cost_register,
                cost_plan,
                now=now,
                fence=fence,
                allocation_kind="subscription",
            )
        for row in rows:
            known = sum((Decimal(c["amount"]) for c in row["recorded_costs"]), Decimal(0))
            row["recorded_cost_total"] = str(known)
            disputed = any(
                i["payment"] and i["payment"]["disputed"]
                for i in row["financial_observation"]["invoices"]
            )
            row["contribution_after_recorded_costs"] = (
                None
                if (not row["cash_coverage_complete"] or row["processing_fee"] is None or disputed)
                else str(Decimal(row["net_collected"]) - Decimal(row["processing_fee"]) - known)
            )
        report = {
            "schema": "lightbulb.subscription_financial_reconciliation.v1",
            "report_ref": request.report_ref,
            "subscriptions": rows,
            "unallocated_cost_sources": unallocated,
            "observed_at": self.sales._now(now),
            "revenue_recognition_performed": False,
        }

        def retain(doc):
            require(
                doc.get("request", request.to_dict()) == request.to_dict(),
                "SUBSCRIPTION_FINANCIAL_REPORT_CHANGED",
            )
            doc.update(request=request.to_dict(), report=report)

        self.events.change(
            self.events.prefix
            + "-subscription-financial-report-"
            + stable_digest(request.report_ref),
            retain,
            fence,
        )
        return report

    def _claim(self, claim_ref, offer_ref, fence):
        def claim(doc):
            require(
                doc.get("offer_ref", offer_ref) == offer_ref
                and doc.get("commerce_kind", "one_time" if "offer_ref" in doc else "subscription")
                == "subscription",
                "SUBSCRIPTION_FINANCIAL_ALREADY_JOINED",
            )
            doc.update(offer_ref=offer_ref, commerce_kind="subscription")

        self.events.change(claim_ref, claim, fence)
