"""Bounded checkout assistance, with separate ephemeral provider continuation links."""

from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed
from lightbulb.company_sales_progression import require
from lightbulb.connector_execution import ConnectorExecutionRequest


class CheckoutRecoveryRequest(StrictModel):
    recovery_ref: OpaqueRef
    offer_ref: OpaqueRef
    subject: str = Field(min_length=1, max_length=998)
    assistance_body: str = Field(min_length=1, max_length=5000)
    review_ref: OpaqueRef
    minimum_age_seconds: int = Field(default=1800, ge=60, le=86400, strict=True)


class CompanyCheckoutRecovery:
    def __init__(self, progression):
        self.p, self.host = progression, progression.host

    def evaluate(self, request, *, now, fence):
        request = CheckoutRecoveryRequest.model_validate(request)
        commerce = self.p.commerce
        row = commerce.events.read(commerce.ref(request.offer_ref))
        require(row and row.get("session_id"), "CHECKOUT_RECOVERY_SESSION_REQUIRED")
        binding = self.p.binding(row["offer"]["binding_ref"])
        paid = commerce.observe_payment(request.offer_ref, now=now, fence=fence)
        session = paid["session"]
        now = self.host._now(now)
        require(
            not paid["payment_confirmed"]
            and session["status"] == "open"
            and session["payment_status"] == "unpaid",
            "CHECKOUT_RECOVERY_NOT_ABANDONED",
        )
        require(int(parsed(now).timestamp()) < session["expires_at"], "CHECKOUT_RECOVERY_EXPIRED")
        require(
            int(parsed(now).timestamp()) - session["created"] >= request.minimum_age_seconds,
            "CHECKOUT_RECOVERY_TOO_EARLY",
        )
        self.host.intake._permission(binding, now=now)
        thread = self.p.conversations._thread(
            binding, now=now, fence=fence, recovery=True, since=session["created"]
        )
        require(
            not (
                self.host.customer_actions.events.read(self.host.customer_actions.ref(binding))
                or {}
            ).get("hold"),
            "CHECKOUT_RECOVERY_CUSTOMER_OWNED",
        )
        return row, binding, thread

    def prepare(self, request, *, now, fence):
        request = CheckoutRecoveryRequest.model_validate(request)
        require(
            not any(c in request.subject for c in "\r\n\0")
            and "\0" not in request.assistance_body
            and "checkout.stripe.com" not in request.assistance_body,
            "CHECKOUT_RECOVERY_PRIVATE_LINK_NOT_DURABLE",
        )
        row, binding, thread = self.evaluate(request, now=now, fence=fence)
        self.p.no_pending_delivery(binding)
        ref = self.p.ref(binding, "conversation_action", request.recovery_ref)
        old = self.p.read(ref)
        if old:
            require(old["action"]["recovery"] == request.to_dict(), "CHECKOUT_RECOVERY_CHANGED")
            return self.p.conversations._track(binding, ref, old, fence=fence)
        action = dict(
            action_ref=request.recovery_ref,
            binding_ref=binding.binding_ref,
            kind="checkout_recovery",
            subject=request.subject,
            body=request.assistance_body,
            evidence_refs=[self.p.commerce.ref(request.offer_ref)],
            recovery=request.to_dict(),
        )
        return self.p.conversations._freeze(
            binding, action, ref, thread, now=now, fence=fence, recovery=True
        )

    def continuation(self, request, *, now, fence):
        """Return a fresh private link for the reviewed UI; never retain it in a journal."""
        row, binding, _ = self.evaluate(request, now=now, fence=fence)
        commerce = self.p.commerce
        call = ConnectorExecutionRequest(
            tool="stripe.get_checkout_continuation",
            scope=commerce.scope,
            connector_account_ref=row["request"]["connector_account_ref"],
            arguments={**row["request"]["arguments"], "session_id": row["session_id"]},
        )
        fence()
        result = self.host.executor.execute(call)
        result, _ = commerce._receipt(result, call, self.host._now(now))
        commerce._session(result.output, row, now=self.host._now(now))
        from urllib.parse import urlsplit

        url = urlsplit(result.output.get("url", ""))
        require(
            url.scheme == "https"
            and url.hostname == "checkout.stripe.com"
            and url.username is None
            and url.password is None
            and url.port in {None, 443}
            and url.path.startswith("/c/pay/")
            and result.output["status"] == "open"
            and result.output["payment_status"] == "unpaid"
            and result.output["expires_at"] > int(parsed(self.host._now(now)).timestamp()),
            "CHECKOUT_RECOVERY_URL_INVALID",
        )
        return {
            "private_checkout_url": result.output["url"],
            "retention": "ephemeral_response_only",
            "offer_ref": row["offer"]["offer_ref"],
        }

    def step(self, request, *, now, fence):
        spec = CheckoutRecoveryRequest.model_validate(request)
        offer = self.p.commerce.events.read(self.p.commerce.ref(spec.offer_ref))
        require(offer, "CHECKOUT_RECOVERY_SESSION_REQUIRED")
        binding = self.p.binding(offer["offer"]["binding_ref"])
        row = self.p.read(self.p.ref(binding, "conversation_action", spec.recovery_ref))
        if row:
            require(row["action"]["recovery"] == spec.to_dict(), "CHECKOUT_RECOVERY_CHANGED")
        else:
            row = self.prepare(spec, now=now, fence=fence)
        return self.p.conversations.step(
            row["action"]["action_ref"], row["action"]["binding_ref"], now=now, fence=fence
        )
