"""Reviewed fixed-price checkout and payment-gated fulfillment on the sales host."""

from typing import Any
from urllib.parse import urlsplit
from pydantic import Field, field_validator
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest, detached
from lightbulb.company_customer_events import CompanyCustomerEvents, require
from lightbulb.company_payment_recovery_actions import PaymentUpdateRequest
from lightbulb.company_sales_progression import scoped_receipt
from lightbulb.connector_execution import (
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ExecutionScope,
)


class CustomerDestinationIdentityReview(StrictModel):
    """Operator-reviewed identity correspondence, not provider proof of the same person."""

    account_ref: OpaqueRef
    provider_identity: str = Field(min_length=1, max_length=254)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)


class CustomerFulfillmentPlan(StrictModel):
    connector_account_ref: OpaqueRef
    write_tool: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    write_arguments: dict[str, Any] = Field(max_length=30)
    verification_tool: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    verification_arguments: dict[str, Any] = Field(max_length=30)
    expected_fields: dict[str, Any] = Field(min_length=1, max_length=20)
    resource_identity_field: OpaqueRef = "id"
    verification_identity_argument: OpaqueRef = "id"
    customer_identity_field: OpaqueRef
    customer_identity_value: str = Field(min_length=1, max_length=254)
    destination_identity_review: CustomerDestinationIdentityReview | None = None
    deadline_at: str | None = None


class CustomerOffer(StrictModel):
    offer_ref: OpaqueRef
    binding_ref: OpaqueRef
    billing_source_ref: OpaqueRef
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]{1,128}$")
    quantity: int = Field(ge=1, le=1000, strict=True)
    amount_total_minor: int = Field(ge=1, le=1000000000000, strict=True)
    currency: str = Field(pattern=r"^[a-z]{3}$")
    success_url: str = Field(max_length=2048)
    cancel_url: str = Field(max_length=2048)
    expires_at: str
    review_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    fulfillment: CustomerFulfillmentPlan

    @field_validator("success_url", "cancel_url")
    @classmethod
    def destination(cls, value):
        return PaymentUpdateRequest.approved_destination(value)

    @field_validator("expires_at")
    @classmethod
    def expiry(cls, value):
        parsed(value)
        return value


class CompanyCustomerCommerce:
    def __init__(self, sales):
        self.sales = sales
        self.events = CompanyCustomerEvents(sales.runner, sales.gateway)
        self.scope = ExecutionScope(
            **sales.runner.bundle.scope, actor_ref=sales.runner.bundle.actor_ref
        )

    @property
    def financials(self):
        from lightbulb.company_customer_financials import CompanyCustomerFinancials
        return CompanyCustomerFinancials(self)

    @property
    def fulfillment(self):
        from lightbulb.company_fulfillment_packages import CompanyCustomerFulfillment
        return CompanyCustomerFulfillment(self)

    def ref(self, offer_ref):
        return self.events.prefix + "-offer-" + stable_digest(offer_ref)

    def _source(self, offer):
        binding = self.sales.progression.binding(offer.binding_ref)
        sources = [
            s
            for s in self.sales.sources
            if s.source_ref == offer.billing_source_ref and s.kind == "invoice_health"
        ]
        require(len(sources) == 1, "CUSTOMER_OFFER_BILLING_SOURCE_REQUIRED")
        source = sources[0]
        customer = source.arguments["customer_id"]
        require(
            source.identity_links.get(customer) == binding.account_ref,
            "CUSTOMER_OFFER_IDENTITY_MISMATCH",
        )
        return binding, source

    def prepare(self, offer, *, now, fence):
        from lightbulb.observation_runtime import _assert_no_secret_keys

        offer = CustomerOffer.model_validate(offer)
        _assert_no_secret_keys(offer.to_dict())
        require(parsed(now) < parsed(offer.expires_at), "CUSTOMER_OFFER_EXPIRED")
        binding, source = self._source(offer)
        state = self.sales.intake._scoped_state(
            self.sales.runner.runtimes["pipeline_engine"], binding.prospect_ref
        )
        require(
            state.ledger.account_ref == binding.account_ref
            and state.status in {"qualified", "meeting_booked", "handed_off"},
            "CUSTOMER_OFFER_QUALIFIED_STATE_REQUIRED",
        )
        args = {
            key: getattr(offer, key)
            for key in (
                "offer_ref",
                "price_id",
                "quantity",
                "amount_total_minor",
                "currency",
                "success_url",
                "cancel_url",
            )
        }
        args["customer_id"] = source.arguments["customer_id"]
        args["offer_ref"] = self.ref(offer.offer_ref)
        args["expires_at"] = int(parsed(offer.expires_at).timestamp())
        identity_review = offer.fulfillment.destination_identity_review
        if identity_review is not None:
            require(
                identity_review.account_ref == binding.account_ref
                and identity_review.provider_identity == offer.fulfillment.customer_identity_value,
                "CUSTOMER_FULFILLMENT_IDENTITY_MISMATCH",
            )
        else:
            require(
                offer.fulfillment.customer_identity_value
                in {binding.account_ref, str(binding.crm_contact_id), args["customer_id"]},
                "CUSTOMER_FULFILLMENT_IDENTITY_MISMATCH",
            )
        if offer.fulfillment.deadline_at is not None:
            parsed(offer.fulfillment.deadline_at)
        require(
            offer.fulfillment.expected_fields.get(offer.fulfillment.customer_identity_field)
            == offer.fulfillment.customer_identity_value,
            "CUSTOMER_FULFILLMENT_CUSTOMER_PROOF_REQUIRED",
        )
        require(
            offer.fulfillment.verification_identity_argument
            not in offer.fulfillment.verification_arguments,
            "CUSTOMER_FULFILLMENT_DYNAMIC_RESOURCE_REQUIRED",
        )
        request = ConnectorExecutionRequest(
            tool="stripe.create_checkout_session",
            effect="write",
            approval_required=True,
            scope=self.scope,
            connector_account_ref=source.connector_account_ref,
            arguments=args,
            idempotency_key=self.ref(offer.offer_ref),
        )

        def retain(doc):
            require(
                not doc.get("offer") or doc["offer"] == offer.to_dict(), "CUSTOMER_OFFER_CHANGED"
            )
            require(
                not doc.get("request") or doc["request"] == request.model_dump(mode="json"),
                "CUSTOMER_OFFER_BINDING_CHANGED",
            )
            if not doc.get("offer"):
                doc.update(
                    offer=offer.to_dict(),
                    request=request.model_dump(mode="json"),
                    phase="prepared",
                    qualification_state_digest=state.state_digest,
                    account_ref=binding.account_ref,
                )

        return self.events.change(self.ref(offer.offer_ref), retain, fence)

    def checkout(self, offer, *, now, fence):
        row = self.prepare(offer, now=now, fence=fence)
        if row["phase"] not in {"prepared", "awaiting_approval"}:
            return self.status(row["offer"]["offer_ref"])
        ref = self.ref(row["offer"]["offer_ref"])
        request = ConnectorExecutionRequest.model_validate(row["request"])

        def posting(doc):
            require(
                doc["phase"] in {"prepared", "awaiting_approval"},
                "CUSTOMER_CHECKOUT_RECONCILIATION_REQUIRED",
            )
            doc["phase"] = "posting"

        self.events.change(ref, posting, fence)
        try:
            result = self.sales.executor.execute(request)
        except Exception:
            return self.status(row["offer"]["offer_ref"])
        return self.reconcile_checkout(
            row["offer"]["offer_ref"], result, now=self.sales._now(now), fence=fence
        )

    def _receipt(self, result, request, now):
        result = ConnectorExecutionResult.model_validate(detached(result))
        receipt = scoped_receipt(result, request)
        require(parsed(receipt.completed_at) <= parsed(now), "CUSTOMER_COMMERCE_FUTURE_RECEIPT")
        if request.effect.value == "write":
            require(
                bool(receipt.approval_ref) and bool(receipt.approval_receipt_digest),
                "CUSTOMER_COMMERCE_APPROVAL_REQUIRED",
            )
        return result, receipt

    def _session(self, output, row, *, now):
        offer = CustomerOffer.model_validate(row["offer"])
        args = row["request"]["arguments"]
        require(
            set(output)
            in (
                {
                    "schema",
                    "id",
                    "customer",
                    "offer_ref",
                    "price_id",
                    "quantity",
                    "amount_total_minor",
                    "currency",
                    "status",
                    "payment_status",
                    "payment_confirmed",
                    "payment_available_for_fulfillment",
                    "created",
                    "expires_at",
                },
                {
                    "schema",
                    "id",
                    "customer",
                    "offer_ref",
                    "price_id",
                    "quantity",
                    "amount_total_minor",
                    "currency",
                    "status",
                    "payment_status",
                    "payment_confirmed",
                    "payment_available_for_fulfillment",
                    "created",
                    "expires_at",
                    "url",
                },
            ),
            "CUSTOMER_CHECKOUT_OUTPUT_INVALID",
        )
        require(
            output.get("expires_at") == args["expires_at"]
            and type(output.get("quantity")) is int
            and type(output.get("amount_total_minor")) is int
            and type(output.get("created")) is int
            and 0 < output["created"] < output["expires_at"]
            and output.get("status") in {"open", "complete", "expired"}
            and output.get("payment_status") in {"paid", "unpaid", "no_payment_required"}
            and output.get("payment_confirmed")
            is (output.get("status") == "complete" and output.get("payment_status") == "paid")
            and type(output.get("payment_available_for_fulfillment")) is bool
            and (not output["payment_available_for_fulfillment"] or output["payment_confirmed"]),
            "CUSTOMER_CHECKOUT_OUTPUT_INVALID",
        )
        require(
            output.get("schema") == "lightbulb.stripe_checkout_session.v1"
            and output.get("customer") == args["customer_id"]
            and all(
                output.get(key) == args[key]
                for key in ("offer_ref", "price_id", "quantity", "amount_total_minor", "currency")
            )
            and isinstance(output.get("id"), str)
            and output["id"].startswith("cs_"),
            "CUSTOMER_CHECKOUT_SESSION_MISMATCH",
        )
        require(
            not row.get("session_id") or row["session_id"] == output["id"],
            "CUSTOMER_CHECKOUT_SESSION_CHANGED",
        )
        return offer

    def reconcile_checkout(self, offer_ref, result, *, now, fence):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(row is not None, "CUSTOMER_OFFER_REQUIRED")
        request = ConnectorExecutionRequest.model_validate(row["request"])
        result = ConnectorExecutionResult.model_validate(detached(result))
        require(result.tool == request.tool, "CUSTOMER_CHECKOUT_TOOL_MISMATCH")
        if result.status.value == "pending_approval":

            def pending(doc):
                require(
                    doc["phase"] in {"posting", "awaiting_approval"},
                    "CUSTOMER_CHECKOUT_RESULT_CHANGED",
                )
                doc.update(phase="awaiting_approval", approval_ref=result.approval_ref)

            self.events.change(ref, pending, fence)
            return self.status(offer_ref)
        result, receipt = self._receipt(result, request, now)
        output = result.output
        if output.get("schema") == "lightbulb.governed_connector_output_commitment.v1":
            # The commitment cannot recover a lost session identifier or authorize another write.
            return {**self.status(offer_ref), "status": "session_identity_reconciliation_required"}
        offer = self._session(output, row, now=now)
        url = urlsplit(output.get("url", ""))
        require(
            url.scheme == "https"
            and url.hostname == "checkout.stripe.com"
            and url.username is None
            and url.password is None
            and url.port in (None, 443)
            and len(output["url"]) <= 4096,
            "CUSTOMER_CHECKOUT_URL_INVALID",
        )
        verified = {"receipt": receipt.to_dict(), "output_digest": stable_digest(output)}

        def complete(doc):
            require(
                not doc.get("created") or doc["created"] == verified,
                "CUSTOMER_CHECKOUT_RESULT_CHANGED",
            )
            if not doc.get("created"):
                doc.update(phase="checkout_created", session_id=output["id"], created=verified)

        self.events.change(ref, complete, fence)
        report = self.status(offer_ref)
        if (
            parsed(now) < parsed(offer.expires_at)
            and 0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 600
        ):
            report.update(private_checkout_url=output["url"], retention="ephemeral_response_only")
        return report

    def recover_checkout(self, offer_ref, session_id, *, now, fence):
        import re

        require(
            isinstance(session_id, str) and re.fullmatch(r"cs_[A-Za-z0-9_]{1,255}", session_id),
            "CUSTOMER_CHECKOUT_SESSION_INVALID",
        )
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(
            row and row["phase"] in {"posting", "checkout_created"},
            "CUSTOMER_CHECKOUT_RECOVERY_NOT_REQUIRED",
        )
        request = ConnectorExecutionRequest(
            tool="stripe.get_checkout_session",
            effect="read",
            scope=self.scope,
            connector_account_ref=row["request"]["connector_account_ref"],
            arguments={**row["request"]["arguments"], "session_id": session_id},
        )
        fence()
        executed = self.sales.executor.execute(request)
        now = self.sales._now(now)
        result, receipt = self._receipt(executed, request, now)
        require(
            0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "CUSTOMER_CHECKOUT_READ_STALE",
        )
        require(result.output.get("id") == session_id, "CUSTOMER_CHECKOUT_SESSION_MISMATCH")
        self._session(result.output, row, now=now)

        def recover(doc):
            require(
                not doc.get("session_id") or doc["session_id"] == session_id,
                "CUSTOMER_CHECKOUT_SESSION_CHANGED",
            )
            doc.update(
                session_id=session_id,
                phase="checkout_created",
                identity_recovery_receipt=receipt.to_dict(),
            )

        self.events.change(ref, recover, fence)
        return self.status(offer_ref)

    def observe_payment(self, offer_ref, *, now, fence):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(row and row.get("session_id"), "CUSTOMER_CHECKOUT_SESSION_REQUIRED")
        self._source(CustomerOffer.model_validate(row["offer"]))
        request = ConnectorExecutionRequest(
            tool="stripe.get_checkout_session",
            effect="read",
            scope=self.scope,
            connector_account_ref=row["request"]["connector_account_ref"],
            arguments={**row["request"]["arguments"], "session_id": row["session_id"]},
        )
        fence()
        executed = self.sales.executor.execute(request)
        now = self.sales._now(now)
        result, receipt = self._receipt(executed, request, now)
        require(
            0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "CUSTOMER_CHECKOUT_READ_STALE",
        )
        self._session(result.output, row, now=now)
        paid = (
            result.output.get("payment_confirmed") is True
            and result.output.get("status") == "complete"
            and result.output.get("payment_status") == "paid"
        )
        evidence = {
            "receipt": receipt.to_dict(),
            "session": detached(result.output),
            "payment_confirmed": paid,
        }

        def retain(doc):
            doc["payment_observation"] = evidence

        self.events.change(ref, retain, fence)
        return evidence

    def fulfill(self, offer_ref, *, now, fence):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(row is not None, "CUSTOMER_OFFER_REQUIRED")
        if row.get("fulfillment", {}).get("phase") in {"posting", "written", "verified"}:
            return (
                self.verify_fulfillment(offer_ref, now=now, fence=fence)
                if row["fulfillment"]["phase"] == "written"
                else self.status(offer_ref)
            )
        paid = self.observe_payment(offer_ref, now=now, fence=fence)
        require(
            paid["payment_confirmed"] and paid["session"]["payment_available_for_fulfillment"],
            "CUSTOMER_FULFILLMENT_PAYMENT_REQUIRED",
        )
        offer = CustomerOffer.model_validate(row["offer"])
        plan = offer.fulfillment
        if plan.deadline_at is not None:
            require(parsed(self.sales._now(now)) < parsed(plan.deadline_at), "CUSTOMER_FULFILLMENT_DEADLINE_PASSED")
        request = ConnectorExecutionRequest(
            tool=plan.write_tool,
            effect="write",
            approval_required=True,
            scope=self.scope,
            connector_account_ref=plan.connector_account_ref,
            arguments=plan.write_arguments,
            idempotency_key=ref + "-fulfillment",
        )

        def posting(doc):
            old = doc.get("fulfillment", {})
            require(
                old.get("phase") in {None, "awaiting_approval"},
                "CUSTOMER_FULFILLMENT_RECONCILIATION_REQUIRED",
            )
            doc["fulfillment"] = {
                "phase": "posting",
                "request": request.model_dump(mode="json"),
                "payment_digest": stable_digest(paid),
            }

        self.events.change(ref, posting, fence)
        try:
            result = self.sales.executor.execute(request)
        except Exception:
            return self.status(offer_ref)
        return self.reconcile_fulfillment(offer_ref, result, now=self.sales._now(now), fence=fence)

    def _fulfillment_plan(self, row):
        return CustomerOffer.model_validate(row["offer"]).fulfillment

    def reconcile_fulfillment(self, offer_ref, result, *, now, fence):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(row and row.get("fulfillment"), "CUSTOMER_FULFILLMENT_REQUEST_REQUIRED")
        request = ConnectorExecutionRequest.model_validate(row["fulfillment"]["request"])
        result = ConnectorExecutionResult.model_validate(detached(result))
        if result.status.value == "pending_approval":
            require(result.tool == request.tool, "CUSTOMER_FULFILLMENT_TOOL_MISMATCH")

            def pending(doc):
                require(
                    doc["fulfillment"]["phase"] in {"posting", "awaiting_approval"},
                    "CUSTOMER_FULFILLMENT_RESULT_CHANGED",
                )
                doc["fulfillment"].update(
                    phase="awaiting_approval", approval_ref=result.approval_ref
                )

            self.events.change(ref, pending, fence)
            return self.status(offer_ref)
        result, receipt = self._receipt(result, request, now)
        plan = self._fulfillment_plan(row)
        resource = result.output.get(plan.resource_identity_field)
        require(
            isinstance(resource, str)
            and 0 < len(resource) <= 200
            and result.output.get(plan.customer_identity_field) == plan.customer_identity_value,
            "CUSTOMER_FULFILLMENT_RESOURCE_PROOF_REQUIRED",
        )

        def written(doc):
            previous = doc["fulfillment"].get("receipt")
            require(
                previous is None or previous == receipt.to_dict(),
                "CUSTOMER_FULFILLMENT_RESULT_CHANGED",
            )
            if previous is None:
                doc["fulfillment"].update(
                    phase="written", receipt=receipt.to_dict(), resource_ref=resource
                )
            else:
                require(
                    doc["fulfillment"].get("resource_ref") == resource,
                    "CUSTOMER_FULFILLMENT_RESULT_CHANGED",
                )

        self.events.change(ref, written, fence)
        return self.verify_fulfillment(offer_ref, now=now, fence=fence)

    def verify_fulfillment(self, offer_ref, *, now, fence):
        ref = self.ref(offer_ref)
        row = self.events.read(ref)
        require(
            row and row.get("fulfillment", {}).get("phase") in {"written", "verified"},
            "CUSTOMER_FULFILLMENT_WRITE_REQUIRED",
        )
        plan = self._fulfillment_plan(row)
        request = ConnectorExecutionRequest(
            tool=plan.verification_tool,
            effect="read",
            scope=self.scope,
            connector_account_ref=plan.connector_account_ref,
            arguments={
                **plan.verification_arguments,
                plan.verification_identity_argument: row["fulfillment"]["resource_ref"],
            },
        )
        fence()
        executed = self.sales.executor.execute(request)
        now = self.sales._now(now)
        result, receipt = self._receipt(executed, request, now)
        require(
            parsed(row["fulfillment"]["receipt"]["completed_at"]) <= parsed(receipt.completed_at)
            and 0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "CUSTOMER_FULFILLMENT_READ_STALE",
        )
        require(
            result.output.get(plan.resource_identity_field) == row["fulfillment"]["resource_ref"]
            and all(result.output.get(k) == v for k, v in plan.expected_fields.items()),
            "CUSTOMER_FULFILLMENT_NOT_OBSERVED",
        )

        def verified(doc):
            doc["fulfillment"].update(
                phase="verified",
                verification_receipt=receipt.to_dict(),
                output_digest=stable_digest(result.output),
            )

        self.events.change(ref, verified, fence)
        return self.status(offer_ref)

    def status(self, offer_ref):
        row = self.events.read(self.ref(offer_ref))
        require(row is not None, "CUSTOMER_OFFER_REQUIRED")
        return {
            "offer_ref": offer_ref,
            "status": row["phase"],
            "session_id": row.get("session_id"),
            "payment_confirmed": row.get("payment_observation", {}).get("payment_confirmed", False),
            "fulfillment_status": row.get("fulfillment", {}).get("phase", "not_started"),
            "automatic_send_authorized": False,
        }
