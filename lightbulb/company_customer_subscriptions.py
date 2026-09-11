"""Reviewed recurring commerce through canonical governed Stripe Tools.

Provider observations recommend access; destination fulfillment remains a separately
approved operation. Local proration primitives remain estimates, not Stripe quotes.
"""

from typing import Literal
from pydantic import Field
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    parsed,
    stable_digest,
    detached,
)
from lightbulb.company_customer_events import CompanyCustomerEvents, require
from lightbulb.company_customer_commerce import (
    CompanyCustomerCommerce,
    CustomerFulfillmentPlan,
)
from lightbulb.connector_execution import (
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
)


class CustomerSubscriptionAccessPolicy(StrictModel):
    allow_trial_access: bool = False
    allow_paid_invoice_access: bool = True
    revoke_on: tuple[
        Literal["canceled", "unpaid", "incomplete_expired", "paused"], ...
    ] = ("canceled", "unpaid", "incomplete_expired")
    revoke_fulfillment: CustomerFulfillmentPlan | None = None


class CustomerSubscriptionOffer(StrictModel):
    offer_ref: OpaqueRef
    binding_ref: OpaqueRef
    billing_source_ref: OpaqueRef
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]{1,128}$")
    quantity: int = Field(default=1, ge=1, le=1000, strict=True)
    unit_amount_minor: int = Field(ge=1, le=1000000000, strict=True)
    currency: str = Field(pattern=r"^[a-z]{3}$")
    interval: Literal["day", "week", "month", "year"]
    interval_count: int = Field(default=1, ge=1, le=12, strict=True)
    trial_days: int = Field(default=0, ge=0, le=90, strict=True)
    expires_at: str
    success_url: str
    cancel_url: str
    review_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    fulfillment: CustomerFulfillmentPlan | None = None
    access_policy: CustomerSubscriptionAccessPolicy = Field(
        default_factory=CustomerSubscriptionAccessPolicy
    )


class _SubscriptionAccessExecution(CompanyCustomerCommerce):
    def __init__(self, sales, ref):
        super().__init__(sales)
        self.access_ref = ref

    def ref(self, offer_ref):
        return self.access_ref

    def _fulfillment_plan(self, row):
        return CustomerFulfillmentPlan.model_validate(row["access_plan"])

    def status(self, offer_ref):
        row = self.events.read(self.access_ref)
        return {
            "offer_ref": offer_ref,
            "status": row.get("fulfillment", {}).get("phase", "prepared"),
            "fulfillment": row.get("fulfillment", {}),
        }


class CustomerSubscriptionChange(StrictModel):
    change_ref: OpaqueRef
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]{1,128}$")
    quantity: int = Field(ge=1, le=1000, strict=True)
    unit_amount_minor: int = Field(ge=1, le=1000000000, strict=True)
    currency: str = Field(pattern=r"^[a-z]{3}$")
    interval: Literal["day", "week", "month", "year"]
    interval_count: int = Field(default=1, ge=1, le=12, strict=True)


class CompanyCustomerSubscriptions:
    def __init__(self, sales):
        self.sales = sales
        self.commerce = CompanyCustomerCommerce(sales)
        self.events = CompanyCustomerEvents(sales.runner, sales.gateway)

    @property
    def financials(self):
        from lightbulb.company_subscription_financials import CompanySubscriptionFinancials
        return CompanySubscriptionFinancials(self)

    def ref(self, offer_ref):
        return self.events.prefix + "-subscription-" + stable_digest(offer_ref)

    def verify_access(self, offer_ref, *, now, fence):
        """Fresh readback of an existing access effect; never request a new write."""
        control = self.events.read(self.ref(offer_ref) + "-access-control")
        require(control and control.get("active_ref"), "CUSTOMER_SUBSCRIPTION_ACCESS_REQUIRED")
        return _SubscriptionAccessExecution(self.sales, control["active_ref"]).verify_fulfillment(
            offer_ref, now=now, fence=fence)

    @property
    def index_ref(self):
        return self.events.prefix + "-subscription-offers"

    def _request(self, tool, arguments, account, *, key=None):
        write = tool in {
            "stripe.create_subscription_checkout",
            "stripe.change_customer_subscription",
            "stripe.cancel_customer_subscription",
        }
        return ConnectorExecutionRequest(
            tool=tool,
            effect="write" if write else "read",
            approval_required=write,
            scope=self.commerce.scope,
            connector_account_ref=account,
            arguments=arguments,
            idempotency_key=key,
        )

    def _read(self, request, now):
        result = self.sales.executor.execute(request)
        now = self.sales._now(now)
        result, receipt = self.commerce._receipt(result, request, now)
        require(
            result.status.value == "completed"
            and 0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "CUSTOMER_SUBSCRIPTION_READ_REQUIRED",
        )
        require(
            result.output.get("schema")
            != "lightbulb.governed_connector_output_commitment.v1",
            "CUSTOMER_SUBSCRIPTION_OBSERVATION_REQUIRED",
        )
        return detached(result.output), receipt.to_dict(), now

    def prepare(self, offer, *, now, fence):
        from lightbulb.company_payment_recovery_actions import PaymentUpdateRequest
        from lightbulb.observation_runtime import _assert_no_secret_keys

        offer = CustomerSubscriptionOffer.model_validate(offer)
        _assert_no_secret_keys(offer.to_dict())
        require(
            parsed(now) < parsed(offer.expires_at),
            "CUSTOMER_SUBSCRIPTION_OFFER_EXPIRED",
        )
        for value in (offer.success_url, offer.cancel_url):
            PaymentUpdateRequest.approved_destination(value)
        binding, source = self.commerce._source(offer)
        for plan in (offer.fulfillment, offer.access_policy.revoke_fulfillment):
            if plan is None:
                continue
            review = plan.destination_identity_review
            require(
                (
                    review is not None
                    and review.account_ref == binding.account_ref
                    and review.provider_identity == plan.customer_identity_value
                )
                or (
                    review is None
                    and plan.customer_identity_value
                    in {
                        binding.account_ref,
                        str(binding.crm_contact_id),
                        source.arguments["customer_id"],
                    }
                ),
                "CUSTOMER_SUBSCRIPTION_FULFILLMENT_IDENTITY_MISMATCH",
            )
            require(
                plan.expected_fields.get(plan.customer_identity_field)
                == plan.customer_identity_value
                and plan.verification_identity_argument
                not in plan.verification_arguments,
                "CUSTOMER_SUBSCRIPTION_FULFILLMENT_PROOF_REQUIRED",
            )
        state = self.sales.intake._scoped_state(
            self.sales.runner.runtimes["pipeline_engine"], binding.prospect_ref
        )
        require(
            state.ledger.account_ref == binding.account_ref
            and state.status in {"qualified", "meeting_booked", "handed_off"},
            "CUSTOMER_SUBSCRIPTION_QUALIFICATION_REQUIRED",
        )
        arguments = {
            k: v
            for k, v in offer.to_dict().items()
            if k
            not in {
                "binding_ref",
                "billing_source_ref",
                "review_evidence_refs",
                "fulfillment",
                "access_policy",
            }
        }
        arguments.update(
            customer_id=source.arguments["customer_id"],
            offer_ref=self.ref(offer.offer_ref),
            expires_at=int(parsed(offer.expires_at).timestamp()),
        )
        request = self._request(
            "stripe.create_subscription_checkout",
            arguments,
            source.connector_account_ref,
            key=self.ref(offer.offer_ref),
        )

        def retain(doc):
            require(
                not doc.get("offer") or doc["offer"] == offer.to_dict(),
                "CUSTOMER_SUBSCRIPTION_OFFER_CHANGED",
            )
            require(
                not doc.get("request")
                or doc["request"] == request.model_dump(mode="json"),
                "CUSTOMER_SUBSCRIPTION_BINDING_CHANGED",
            )
            if not doc.get("offer"):
                doc.update(
                    offer=offer.to_dict(),
                    request=request.model_dump(mode="json"),
                    account_ref=binding.account_ref,
                    phase="prepared",
                )

        def register(doc):
            offers = doc.setdefault("offers", [])
            if offer.offer_ref not in offers:
                require(len(offers) < 100, "CUSTOMER_SUBSCRIPTION_OFFER_LIMIT")
                offers.append(offer.offer_ref)

        self.events.change(self.index_ref, register, fence)
        return self.events.change(self.ref(offer.offer_ref), retain, fence)

    def tick(self, *, now, fence, max_offers=100):
        """Continue registered offers on the sales host's existing leased cadence.

        This cannot invent an offer or a price/cancellation proposal. It can resume
        exact retained checkout/change/cancellation requests waiting for user approval, observe known sessions,
        and request/reconcile the offer's separately approved access policy.
        """
        from lightbulb.company_host_journal import HostAuthorityError
        from lightbulb.company_hosted_scheduler import CheckpointConflict

        require(
            type(max_offers) is int and 1 <= max_offers <= 100,
            "CUSTOMER_SUBSCRIPTION_TICK_LIMIT",
        )
        fence()
        index = self.events.read(self.index_ref)
        if not index:
            return {"reports": [], "poll_again": False}
        offers = index.get("offers", [])
        require(
            isinstance(offers, list)
            and len(offers) <= 100
            and len(set(offers)) == len(offers),
            "CUSTOMER_SUBSCRIPTION_INDEX_INVALID",
        )
        cursor = index.get("cursor", 0) % max(1, len(offers))
        selected = (offers[cursor:] + offers[:cursor])[:max_offers]
        reports = []
        for offer_ref in selected:
            try:
                fence()
                row = self.events.read(self.ref(offer_ref))
                require(
                    row is not None and row.get("offer"),
                    "CUSTOMER_SUBSCRIPTION_OFFER_REQUIRED",
                )
                write = row.get("writes", {}).get("checkout", {})
                if write.get("phase") == "awaiting_approval":
                    self.checkout(row["offer"], now=self.sales._now(now), fence=fence)
                    row = self.events.read(self.ref(offer_ref))
                if not row.get("session_id"):
                    status = (
                        "checkout_reconciliation_required"
                        if write.get("phase") == "posting"
                        else "awaiting_checkout"
                    )
                    reports.append({"offer_ref": offer_ref, "status": status})
                    continue
                # At most one retained commercial command per offer per tick. The
                # public methods preserve the original proposal's expiry and exact
                # subscription/preview commitments; no automatic quote refresh.
                pending = next(
                    (
                        (operation, value)
                        for operation, value in row.get("writes", {}).items()
                        if operation != "checkout"
                        and value.get("phase") == "awaiting_approval"
                    ),
                    None,
                )
                if pending:
                    operation, command = pending
                    tool = command["request"]["tool"]
                    try:
                        if tool == "stripe.change_customer_subscription":
                            change_ref = operation.removeprefix("change-")
                            proposal = row["changes"][change_ref]
                            self.change(
                                offer_ref,
                                change_ref,
                                expected_digest=stable_digest(proposal),
                                now=self.sales._now(now),
                                fence=fence,
                            )
                        elif tool == "stripe.cancel_customer_subscription":
                            self.cancel_at_period_end(
                                offer_ref,
                                expected_subscription_digest=command["request"][
                                    "arguments"
                                ]["subscription_digest"],
                                now=self.sales._now(now),
                                fence=fence,
                            )
                    except (HostAuthorityError, CheckpointConflict):
                        raise
                    except ValueError:

                        def needs_review(doc):
                            current = doc.get("writes", {}).get(operation, {})
                            if current.get("phase") == "awaiting_approval":
                                current["phase"] = "review_required"

                        self.events.change(self.ref(offer_ref), needs_review, fence)
                        reports.append(
                            {
                                "offer_ref": offer_ref,
                                "status": "subscription_change_review_required",
                            }
                        )
                observation = self.observe(
                    offer_ref, now=self.sales._now(now), fence=fence
                )
                if observation["subscription"] and row["offer"].get("fulfillment"):
                    access = self.synchronize_access(
                        offer_ref, now=self.sales._now(now), fence=fence
                    )
                    reports.append({"offer_ref": offer_ref, "status": access["status"]})
                else:
                    reports.append(
                        {
                            "offer_ref": offer_ref,
                            "status": "subscription_observed"
                            if observation["subscription"]
                            else observation["checkout"]["status"],
                        }
                    )
            except (HostAuthorityError, CheckpointConflict):
                raise
            except Exception:
                # No provider payload, customer identity, private link or error body.
                reports.append(
                    {"offer_ref": offer_ref, "status": "reconciliation_required"}
                )

        def advance(doc):
            doc["cursor"] = (cursor + len(selected)) % max(
                1, len(doc.get("offers", []))
            )

        self.events.change(self.index_ref, advance, fence)
        return {
            "reports": reports,
            "poll_again": any(r["status"] != "expired" for r in reports),
        }

    def checkout(self, offer, *, now, fence):
        row = self.prepare(offer, now=now, fence=fence)
        return self._write(
            self.ref(row["offer"]["offer_ref"]),
            "checkout",
            ConnectorExecutionRequest.model_validate(row["request"]),
            now,
            fence,
        )

    def _write(self, ref, operation, request, now, fence):
        row = self.events.read(ref)
        prior = row.get("writes", {}).get(operation)
        if prior and prior["phase"] not in {"prepared", "awaiting_approval"}:
            return {
                "status": prior["phase"],
                "reconciliation_required": prior["phase"] == "posting",
            }

        def posting(doc):
            writes = doc.setdefault("writes", {})
            previous = writes.get(operation)
            require(
                not previous or previous["request"] == request.model_dump(mode="json"),
                "CUSTOMER_SUBSCRIPTION_WRITE_CHANGED",
            )
            require(
                not previous or previous["phase"] in {"prepared", "awaiting_approval"},
                "CUSTOMER_SUBSCRIPTION_RECONCILIATION_REQUIRED",
            )
            writes[operation] = {
                "request": request.model_dump(mode="json"),
                "phase": "posting",
            }

        self.events.change(ref, posting, fence)
        try:
            result = self.sales.executor.execute(request)
        except Exception:
            return {"status": "posting", "reconciliation_required": True}
        return self.reconcile(
            ref, operation, result, now=self.sales._now(now), fence=fence
        )

    def reconcile(self, ref, operation, result, *, now, fence):
        row = self.events.read(ref)
        require(
            row is not None and operation in row.get("writes", {}),
            "CUSTOMER_SUBSCRIPTION_WRITE_REQUIRED",
        )
        write = row["writes"][operation]
        request = ConnectorExecutionRequest.model_validate(write["request"])
        result = ConnectorExecutionResult.model_validate(detached(result))
        require(result.tool == request.tool, "CUSTOMER_SUBSCRIPTION_TOOL_MISMATCH")
        if result.status.value == "pending_approval":

            def pending(doc):
                require(
                    doc["writes"][operation]["phase"]
                    in {"posting", "awaiting_approval"},
                    "CUSTOMER_SUBSCRIPTION_RESULT_CHANGED",
                )
                doc["writes"][operation].update(
                    phase="awaiting_approval", approval_ref=result.approval_ref
                )

            self.events.change(ref, pending, fence)
            return {"status": "awaiting_approval", "approval_ref": result.approval_ref}
        result, receipt = self.commerce._receipt(result, request, now)
        require(
            result.status.value == "completed",
            "CUSTOMER_SUBSCRIPTION_RESULT_UNCONFIRMED",
        )
        if (
            result.output.get("schema")
            == "lightbulb.governed_connector_output_commitment.v1"
        ):
            return {"status": "posting", "reconciliation_required": True}
        output = detached(result.output)
        require(
            output.get("customer") == request.arguments["customer_id"],
            "CUSTOMER_SUBSCRIPTION_CUSTOMER_MISMATCH",
        )
        private_url = None
        if operation == "checkout":
            self._checkout_output(output, request.arguments)
            private_url = output.pop("url", None)
        else:
            self._subscription_output(
                output,
                request.arguments["subscription_id"],
                request.arguments["customer_id"],
            )
        proof = {
            "phase": "applied",
            "request": write["request"],
            "receipt": receipt.to_dict(),
            "output": output,
        }

        def applied(doc):
            prior = doc["writes"][operation]
            require(
                prior["phase"] != "applied" or prior == proof,
                "CUSTOMER_SUBSCRIPTION_RESULT_CHANGED",
            )
            doc["writes"][operation] = proof
            if operation == "checkout":
                require(
                    not doc.get("session_id") or doc["session_id"] == output["id"],
                    "CUSTOMER_SUBSCRIPTION_SESSION_CHANGED",
                )
                doc.update(session_id=output["id"], phase="checkout_created")

        self.events.change(ref, applied, fence)
        report = {"status": "applied", "output": output, "access_authorized": False}
        if (
            private_url
            and 0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60
            and parsed(now).timestamp() < output["expires_at"]
        ):
            from urllib.parse import urlsplit

            u = urlsplit(private_url)
            require(
                u.scheme == "https"
                and u.hostname == "checkout.stripe.com"
                and u.path.startswith("/c/pay/")
                and u.username is None
                and u.password is None
                and u.port in {None, 443},
                "CUSTOMER_SUBSCRIPTION_URL_INVALID",
            )
            report["private_checkout_url"] = private_url
        return report

    def _checkout_output(self, output, arguments):
        require(
            output.get("schema") == "lightbulb.stripe_subscription_checkout.v1"
            and output.get("customer") == arguments["customer_id"]
            and output.get("access_authorized") is False,
            "CUSTOMER_SUBSCRIPTION_CHECKOUT_INVALID",
        )
        require(
            all(
                output.get(k) == arguments[k]
                for k in (
                    "offer_ref",
                    "price_id",
                    "quantity",
                    "unit_amount_minor",
                    "currency",
                    "interval",
                    "interval_count",
                    "trial_days",
                    "expires_at",
                )
            ),
            "CUSTOMER_SUBSCRIPTION_CHECKOUT_CHANGED",
        )
        require(
            isinstance(output.get("id"), str) and output["id"].startswith("cs_"),
            "CUSTOMER_SUBSCRIPTION_SESSION_INVALID",
        )

    def _subscription_output(self, output, subscription_id, customer_id):
        require(
            output.get("schema") == "lightbulb.stripe_customer_subscription.v1"
            and output.get("id") == subscription_id
            and output.get("customer") == customer_id
            and output.get("access_authorized") is False,
            "CUSTOMER_SUBSCRIPTION_OBSERVATION_INVALID",
        )
        require(
            isinstance(output.get("subscription_digest"), str)
            and len(output["subscription_digest"]) == 64,
            "CUSTOMER_SUBSCRIPTION_DIGEST_REQUIRED",
        )

    def observe(self, offer_ref, *, now, fence, session_id=None):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(row is not None, "CUSTOMER_SUBSCRIPTION_OFFER_REQUIRED")
        session_id = session_id or row.get("session_id")
        require(
            isinstance(session_id, str) and session_id.startswith("cs_"),
            "CUSTOMER_SUBSCRIPTION_SESSION_REQUIRED",
        )
        require(
            not row.get("session_id") or row["session_id"] == session_id,
            "CUSTOMER_SUBSCRIPTION_SESSION_CHANGED",
        )
        request = ConnectorExecutionRequest.model_validate(row["request"])
        checkout, receipt, now = self._read(
            self._request(
                "stripe.get_subscription_checkout",
                {**request.arguments, "session_id": session_id},
                request.connector_account_ref,
            ),
            now,
        )
        self._checkout_output(checkout, request.arguments)
        require(checkout["id"] == session_id, "CUSTOMER_SUBSCRIPTION_SESSION_CHANGED")
        subscription = None
        if checkout.get("subscription_id"):
            require(
                checkout.get("status") == "complete",
                "CUSTOMER_SUBSCRIPTION_ACCEPTANCE_REQUIRED",
            )
            subscription, receipt, now = self._read(
                self._request(
                    "stripe.get_customer_subscription",
                    {
                        "customer_id": request.arguments["customer_id"],
                        "subscription_id": checkout["subscription_id"],
                    },
                    request.connector_account_ref,
                ),
                now,
            )
            self._subscription_output(
                subscription,
                checkout["subscription_id"],
                request.arguments["customer_id"],
            )

        def retain(doc):
            require(
                not doc.get("session_id") or doc["session_id"] == session_id,
                "CUSTOMER_SUBSCRIPTION_SESSION_CHANGED",
            )
            if doc.get("subscription") and subscription:
                require(
                    doc["subscription"]["id"] == subscription["id"],
                    "CUSTOMER_SUBSCRIPTION_ID_CHANGED",
                )
            doc.update(
                session_id=session_id,
                checkout_observation=checkout,
                observed_at=now,
                observation_receipt=receipt,
            )
            if subscription:
                doc.update(subscription=subscription, phase="subscription_observed")

        self.events.change(ref, retain, fence)
        return {
            "checkout": checkout,
            "subscription": subscription,
            "access_authorized": False,
        }

    def preview_change(self, offer_ref, change, *, now, fence):
        change = CustomerSubscriptionChange.model_validate(change)
        observed = self.observe(offer_ref, now=now, fence=fence)
        sub = observed["subscription"]
        require(sub is not None, "CUSTOMER_SUBSCRIPTION_REQUIRED")
        row = self.events.read(self.ref(offer_ref))
        arguments = {k: v for k, v in change.to_dict().items() if k != "change_ref"}
        arguments.update(
            customer_id=sub["customer"],
            subscription_id=sub["id"],
            subscription_digest=sub["subscription_digest"],
            proration_date=int(parsed(self.sales._now(now)).timestamp()),
        )
        preview, receipt, now = self._read(
            self._request(
                "stripe.preview_subscription_change",
                arguments,
                row["request"]["connector_account_ref"],
            ),
            now,
        )
        require(
            preview.get("schema") == "lightbulb.stripe_subscription_preview.v1"
            and all(preview.get(k) == v for k, v in arguments.items()),
            "CUSTOMER_SUBSCRIPTION_PREVIEW_CHANGED",
        )
        require(
            type(preview.get("amount_due_minor")) is int
            and preview["amount_due_minor"] >= 0
            and isinstance(preview.get("preview_digest"), str),
            "CUSTOMER_SUBSCRIPTION_PREVIEW_INVALID",
        )
        proposal = {
            "change": change.to_dict(),
            "arguments": {
                **arguments,
                "amount_due_minor": preview["amount_due_minor"],
                "preview_digest": preview["preview_digest"],
            },
            "preview": preview,
            "receipt": receipt,
            "observed_at": now,
        }

        def retain(doc):
            proposals = doc.setdefault("changes", {})
            require(
                change.change_ref not in proposals
                or proposals[change.change_ref] == proposal,
                "CUSTOMER_SUBSCRIPTION_CHANGE_REF_USED",
            )
            proposals[change.change_ref] = proposal

        self.events.change(self.ref(offer_ref), retain, fence)
        return {
            **proposal,
            "review_digest": stable_digest(proposal),
            "execution_authorized": False,
        }

    def change(self, offer_ref, change_ref, *, expected_digest, now, fence):
        row = self.events.read(self.ref(offer_ref))
        require(
            row is not None and change_ref in row.get("changes", {}),
            "CUSTOMER_SUBSCRIPTION_PREVIEW_REQUIRED",
        )
        proposal = row["changes"][change_ref]
        require(
            stable_digest(proposal) == expected_digest
            and 0
            <= (parsed(now) - parsed(proposal["observed_at"])).total_seconds()
            <= 600,
            "CUSTOMER_SUBSCRIPTION_REVIEW_STALE",
        )
        request = self._request(
            "stripe.change_customer_subscription",
            proposal["arguments"],
            row["request"]["connector_account_ref"],
            key=self.ref(offer_ref) + "-change-" + stable_digest(change_ref),
        )
        return self._write(
            self.ref(offer_ref), "change-" + change_ref, request, now, fence
        )

    def cancel_at_period_end(
        self, offer_ref, *, expected_subscription_digest, now, fence
    ):
        observed = self.observe(offer_ref, now=now, fence=fence)
        sub = observed["subscription"]
        require(
            sub is not None
            and sub["subscription_digest"] == expected_subscription_digest,
            "CUSTOMER_SUBSCRIPTION_REVIEW_CHANGED",
        )
        row = self.events.read(self.ref(offer_ref))
        request = self._request(
            "stripe.cancel_customer_subscription",
            {
                "customer_id": sub["customer"],
                "subscription_id": sub["id"],
                "subscription_digest": expected_subscription_digest,
            },
            row["request"]["connector_account_ref"],
            key=self.ref(offer_ref) + "-cancel-" + expected_subscription_digest,
        )
        return self._write(
            self.ref(offer_ref),
            "cancel-" + expected_subscription_digest,
            request,
            now,
            fence,
        )

    def reconcile_access(self, offer_ref, action, result, *, now, fence):
        require(
            action in {"grant", "revoke"}, "CUSTOMER_SUBSCRIPTION_ACCESS_ACTION_INVALID"
        )
        control = self.events.read(self.ref(offer_ref) + "-access-control")
        require(
            control is not None and control.get("action") == action,
            "CUSTOMER_SUBSCRIPTION_ACCESS_ACTION_CHANGED",
        )
        execution = _SubscriptionAccessExecution(self.sales, control["active_ref"])
        return execution.reconcile_fulfillment(offer_ref, result, now=now, fence=fence)

    def synchronize_access(self, offer_ref, *, now, fence):
        """Observe current billing, then request the separately approved exact access effect.

        Paid invoice includes legitimate credits and out-of-band payment; it is not
        captured/settled cash. Trial access requires explicit offer policy consent.
        Call again from the host cadence after billing changes. A scheduled cancel
        keeps access until the provider actually reaches a terminal status.
        """
        observed = self.observe(offer_ref, now=now, fence=fence)
        row = self.events.read(self.ref(offer_ref))
        offer = CustomerSubscriptionOffer.model_validate(row["offer"])
        sub = observed["subscription"]
        require(sub is not None, "CUSTOMER_SUBSCRIPTION_REQUIRED")
        policy = offer.access_policy
        recommendation = sub.get("access_recommendation")
        terms = (
            "price_id",
            "quantity",
            "unit_amount_minor",
            "currency",
            "interval",
            "interval_count",
        )
        reviewed_terms = [{key: getattr(offer, key) for key in terms}]
        reviewed_terms.extend(
            {key: write["request"]["arguments"][key] for key in terms}
            for write in row.get("writes", {}).values()
            if write.get("phase") == "applied"
            and write.get("request", {}).get("tool")
            == "stripe.change_customer_subscription"
        )
        terms_match = any(
            all(sub.get(key) == value for key, value in reviewed.items())
            for reviewed in reviewed_terms
        )
        if sub["status"] in policy.revoke_on:
            action, plan = "revoke", policy.revoke_fulfillment
        elif (
            recommendation == "propose_paid_access"
            and policy.allow_paid_invoice_access
            and terms_match
            or recommendation == "propose_trial_access"
            and policy.allow_trial_access
            and offer.trial_days > 0
            and terms_match
        ):
            action, plan = "grant", offer.fulfillment
        else:
            return {
                "status": "access_review_required",
                "subscription": sub,
                "access_authorized": False,
            }
        require(plan is not None, "CUSTOMER_SUBSCRIPTION_ACCESS_PLAN_REQUIRED")
        control_ref = self.ref(offer_ref) + "-access-control"
        control = self.events.read(control_ref)
        if control and control.get("active_ref") and control.get("action") != action:
            prior = self.events.read(control["active_ref"])
            if prior and prior.get("fulfillment", {}).get("phase") == "written":
                _SubscriptionAccessExecution(
                    self.sales, control["active_ref"]
                ).verify_fulfillment(offer_ref, now=now, fence=fence)
                prior = self.events.read(control["active_ref"])
            if not prior or prior.get("fulfillment", {}).get("phase") != "verified":
                return {
                    "status": "access_reconciliation_required",
                    "active_action": control["action"],
                    "access_ref": control["active_ref"],
                }

        def allocate(doc):
            require(
                (doc.get("active_ref"), doc.get("action"), doc.get("generation", 0))
                == (
                    control.get("active_ref"),
                    control.get("action"),
                    control.get("generation", 0),
                )
                if control
                else not doc.get("active_ref"),
                "CUSTOMER_SUBSCRIPTION_ACCESS_CONCURRENT_CHANGE",
            )
            if doc.get("action") != action:
                generation = doc.get("generation", 0) + 1
                doc.update(
                    action=action,
                    generation=generation,
                    active_ref=self.ref(offer_ref) + "-access-" + str(generation),
                )

        control = self.events.change(control_ref, allocate, fence)
        ref = control["active_ref"]
        execution = _SubscriptionAccessExecution(self.sales, ref)
        old = self.events.read(ref)
        if old and old.get("fulfillment", {}).get("phase") in {
            "posting",
            "written",
            "verified",
        }:
            if old["fulfillment"]["phase"] in {"written", "verified"}:
                return execution.verify_fulfillment(offer_ref, now=now, fence=fence)
            return execution.status(offer_ref)
        if plan.deadline_at is not None:
            require(
                parsed(self.sales._now(now)) < parsed(plan.deadline_at),
                "CUSTOMER_SUBSCRIPTION_ACCESS_DEADLINE_PASSED",
            )
        request = ConnectorExecutionRequest(
            tool=plan.write_tool,
            effect="write",
            approval_required=True,
            scope=self.commerce.scope,
            connector_account_ref=plan.connector_account_ref,
            arguments=plan.write_arguments,
            idempotency_key=ref,
        )

        def posting(doc):
            previous = doc.get("fulfillment", {})
            require(
                previous.get("phase") in {None, "awaiting_approval"},
                "CUSTOMER_SUBSCRIPTION_ACCESS_RECONCILIATION_REQUIRED",
            )
            require(
                not previous.get("request")
                or previous["request"] == request.model_dump(mode="json"),
                "CUSTOMER_SUBSCRIPTION_ACCESS_REQUEST_CHANGED",
            )
            doc.update(
                access_plan=plan.to_dict(),
                subscription_evidence=sub,
                fulfillment={
                    "phase": "posting",
                    "request": request.model_dump(mode="json"),
                    "payment_digest": stable_digest(observed),
                },
            )

        require(
            0
            <= (
                parsed(self.sales._now(now)) - parsed(row["observed_at"])
            ).total_seconds()
            <= 60,
            "CUSTOMER_SUBSCRIPTION_ACCESS_OBSERVATION_STALE",
        )
        self.events.change(ref, posting, fence)
        try:
            result = self.sales.executor.execute(request)
        except Exception:
            return execution.status(offer_ref)
        return execution.reconcile_fulfillment(
            offer_ref, result, now=self.sales._now(now), fence=fence
        )
