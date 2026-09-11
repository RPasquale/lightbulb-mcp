"""Reviewed referral attribution and rewards backed by actual customer outcomes."""

from typing import Literal
from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest
from lightbulb.company_customer_events import CompanyCustomerEvents, require


class CustomerReferralProgram(StrictModel):
    program_ref: OpaqueRef
    successful_offer_ref: OpaqueRef
    successful_offer_kind: Literal["one_time", "subscription"] = "one_time"
    review_ref: OpaqueRef
    expires_at: str
    reward_minor: int = Field(gt=0, le=1000000, strict=True)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    reward_hold_days: int = Field(default=14, ge=0, le=90, strict=True)


class CustomerReferralAttribution(StrictModel):
    referral_ref: OpaqueRef
    program_ref: OpaqueRef
    invitation_action_ref: OpaqueRef
    referred_offer_ref: OpaqueRef
    referred_offer_kind: Literal["one_time", "subscription"] = "one_time"
    inbound_event_ref: OpaqueRef
    review_ref: OpaqueRef
    authenticated_event_id: str | None = None
    link_ref: OpaqueRef | None = None


class CompanyCustomerReferrals:
    def __init__(self, progression):
        self.p, self.host = progression, progression.host
        self.events = CompanyCustomerEvents(self.host.runner, self.host.gateway)

    @property
    def acquisition(self):
        from lightbulb.company_referral_acquisition import CompanyReferralAcquisition

        return CompanyReferralAcquisition(self)

    def _offer(self, kind, ref):
        service = self.p.subscriptions if kind == "subscription" else self.p.commerce
        return self.events.read(service.ref(ref))

    def _cash(self, kind, ref, *, now, fence):
        if kind == "one_time":
            return self.p.commerce.financials._observe(ref, now=now, fence=fence)
        evidence = self.p.subscriptions.financials.observe(ref, now=now, fence=fence)
        require(evidence["invoices_complete"], "CUSTOMER_REFERRAL_INCOMPLETE_FINANCIALS")
        invoices = [i for i in evidence["invoices"] if i["payment"]]
        require(
            invoices
            and all(
                i["cash_verified"]
                and i["payment"]["refunds_complete"]
                and not i["paid_out_of_band"]
                for i in invoices
            ),
            "CUSTOMER_REFERRAL_CAPTURE_REQUIRED",
        )
        candidates = [
            i
            for i in invoices
            if i["status"] == "paid"
            and i["paid_at"] is not None
            and i["amount_remaining_minor"] == 0
        ]
        require(candidates, "CUSTOMER_REFERRAL_CAPTURE_REQUIRED")
        invoice = min(candidates, key=lambda i: (i["paid_at"], i["invoice_id"]))
        row = self._offer(kind, ref)
        payment = dict(invoice["payment"])
        payment.update(
            customer_id=evidence["customer_id"],
            subscription_id=evidence["subscription_id"],
            invoice_id=invoice["invoice_id"],
            paid_at=invoice["paid_at"],
            refunded_minor=sum(i["payment"]["refunded_minor"] for i in invoices),
            disputed=any(i["payment"]["disputed"] for i in invoices),
        )
        return dict(
            account_ref=row["account_ref"],
            currency=evidence["subscription"]["currency"].upper(),
            financial_observation=payment,
            subscription_evidence=evidence,
        )

    def _verify(self, kind, ref, *, now, fence):
        if kind == "subscription":
            control = self.events.read(self.p.subscriptions.ref(ref) + "-access-control")
            require(
                control and control.get("action") == "grant", "CUSTOMER_REFERRAL_SUCCESS_REQUIRED"
            )
            return self.p.subscriptions.verify_access(ref, now=now, fence=fence)
        return self.p.commerce.verify_fulfillment(ref, now=now, fence=fence)

    def ref(self, value):
        return self.events.prefix + "-referral-program-" + stable_digest(value)

    def claim_ref(self, value):
        return self.events.prefix + "-referral-claim-" + stable_digest(value)

    def register(self, request, *, now, fence):
        request = CustomerReferralProgram.model_validate(request)
        require(parsed(now) < parsed(request.expires_at), "CUSTOMER_REFERRAL_EXPIRED")
        offer = self._offer(request.successful_offer_kind, request.successful_offer_ref)
        require(
            offer
            and (
                request.successful_offer_kind == "subscription"
                or offer.get("fulfillment", {}).get("phase") == "verified"
            ),
            "CUSTOMER_REFERRAL_SUCCESS_REQUIRED",
        )
        self._verify(
            request.successful_offer_kind, request.successful_offer_ref, now=now, fence=fence
        )
        binding = self.p.binding(offer["offer"]["binding_ref"])

        def retain(doc):
            require(
                not doc.get("request")
                or CustomerReferralProgram.model_validate(doc["request"]).to_dict()
                == request.to_dict(),
                "CUSTOMER_REFERRAL_PROGRAM_CHANGED",
            )
            if not doc.get("request"):
                doc.update(
                    request=request.to_dict(),
                    binding_ref=binding.binding_ref,
                    binding_digest=stable_digest(binding.to_dict()),
                    registered_at=self.host._now(now),
                )

        return self.events.change(self.ref(request.program_ref), retain, fence)

    def evaluate(self, program_ref, *, now, fence):
        row = self.events.read(self.ref(program_ref))
        require(row is not None, "CUSTOMER_REFERRAL_PROGRAM_REQUIRED")
        request = CustomerReferralProgram.model_validate(row["request"])
        binding = self.p.binding(row["binding_ref"])
        require(
            row["binding_digest"] == stable_digest(binding.to_dict()),
            "CUSTOMER_REFERRAL_BINDING_CHANGED",
        )
        financial = self._cash(
            request.successful_offer_kind, request.successful_offer_ref, now=now, fence=fence
        )
        outcome = self._verify(
            request.successful_offer_kind, request.successful_offer_ref, now=now, fence=fence
        )
        now = self.host._now(now)
        cash = financial["financial_observation"]
        require(financial["currency"] == request.currency, "CUSTOMER_REFERRAL_CURRENCY_MISMATCH")
        status = "invitation_eligible"
        if parsed(now) >= parsed(request.expires_at):
            status = "expired"
        elif cash["refunded_minor"] or cash["disputed"]:
            status = "purchase_reversed"
        elif outcome.get("fulfillment_status") != "verified":
            status = "resolution_required"
        else:
            from lightbulb.company_host_journal import HostAuthorityError

            try:
                self.host.intake._permission(binding, now=now)
                contact = (
                    self.host.customer_actions.events.read(self.host.customer_actions.ref(binding))
                    or {}
                )
                hold = contact.get("hold")
                if hold and not (
                    hold["owner_binding_ref"] == binding.binding_ref
                    and hold["disposition"] == "reply"
                    and parsed(hold["observed_at"]) <= parsed(row["registered_at"])
                ):
                    status = "customer_reply_or_suppression"
            except ValueError as error:
                if isinstance(error, HostAuthorityError):
                    raise
                status = "customer_reply_or_suppression"
        return dict(
            program_ref=program_ref,
            binding_ref=binding.binding_ref,
            status=status,
            baseline=int(parsed(row["registered_at"]).timestamp()),
            financial=financial,
            fulfillment_evidence_digest=stable_digest(outcome),
            observed_at=now,
        )

    def prepare_invitation(self, program_ref, message, *, now, fence):
        return self.p.conversations.prepare_program(
            "referral_invitation", program_ref, message, now=now, fence=fence
        )

    def attribute(self, request, *, now, fence):
        request = CustomerReferralAttribution.model_validate(request)
        prior = self.events.read(self.claim_ref(request.referral_ref))
        require(
            not prior or CustomerReferralAttribution.model_validate(prior["request"]).to_dict() == request.to_dict(),
            "CUSTOMER_REFERRAL_ATTRIBUTION_CHANGED",
        )
        program = self.events.read(self.ref(request.program_ref))
        require(program is not None, "CUSTOMER_REFERRAL_PROGRAM_REQUIRED")
        require(parsed(now) < parsed(program["request"]["expires_at"]), "CUSTOMER_REFERRAL_EXPIRED")
        referrer = self.p.binding(program["binding_ref"])
        invitation = self.p.read(
            self.p.ref(referrer, "conversation_action", request.invitation_action_ref)
        )
        require(
            invitation
            and invitation["phase"] == "sent"
            and invitation["action"]["kind"] == "referral_invitation"
            and invitation["action"]["program_ref"] == request.program_ref,
            "CUSTOMER_REFERRAL_SENT_INVITATION_REQUIRED",
        )
        offer = self._offer(request.referred_offer_kind, request.referred_offer_ref)
        require(offer is not None, "CUSTOMER_REFERRAL_ORDER_REQUIRED")
        referred = self.p.binding(offer["offer"]["binding_ref"])
        own_offer = self._offer(
            program["request"].get("successful_offer_kind", "one_time"),
            program["request"]["successful_offer_ref"],
        )
        same_provider_customer = (
            own_offer["request"]["connector_account_ref"],
            own_offer["request"]["arguments"]["customer_id"],
        ) == (
            offer["request"]["connector_account_ref"],
            offer["request"]["arguments"]["customer_id"],
        )
        require(
            referrer.account_ref != referred.account_ref
            and referrer.to_address.lower() != referred.to_address.lower()
            and not same_provider_customer,
            "CUSTOMER_REFERRAL_SELF_REFERRAL",
        )
        state = self.host.intake._scoped_state(
            self.host.runner.runtimes["pipeline_engine"], referred.prospect_ref
        )
        require(
            state.ledger.account_ref == referred.account_ref
            and state.status in {"qualified", "meeting_booked", "handed_off"},
            "CUSTOMER_REFERRAL_QUALIFICATION_REQUIRED",
        )
        event = self.events.read(request.inbound_event_ref)
        require(
            event
            and event.get("event", {}).get("account_ref") == referred.account_ref
            and event["event"]["kind"] in {"demo_requested", "inquiry_received", "referral_claimed"}
            and parsed(invitation["effect"]["completed_at"])
            <= parsed(event["event"]["occurred_at"])
            <= parsed(now),
            "CUSTOMER_REFERRAL_INBOUND_EVIDENCE_REQUIRED",
        )
        if event["event"]["kind"] == "referral_claimed":
            link = (
                self.events.read(self.acquisition.link_ref(request.link_ref))
                if request.link_ref
                else None
            )
            proof = event.get("proof", {})
            source = proof.get("source", {})
            require(
                link
                and proof.get("source_kind") == "authenticated_referral_intake"
                and source.get("id") == request.authenticated_event_id
                and source.get("referral_code") == link["result"]["referral_code"]
                and link["request"]["program_ref"] == request.program_ref,
                "CUSTOMER_REFERRAL_AUTHENTICATED_EVENT_MISMATCH",
            )
        # This is a reviewed correspondence, not an assertion that the provider supplied a referral code.
        identity = stable_digest(
            [
                offer["request"]["connector_account_ref"],
                offer["request"]["arguments"]["customer_id"],
            ]
        )

        def unique(doc):
            require(
                doc.get("referral_ref", request.referral_ref) == request.referral_ref,
                "CUSTOMER_REFERRAL_ALREADY_ATTRIBUTED",
            )
            doc["referral_ref"] = request.referral_ref

        self.events.change(self.events.prefix + "-referred-customer-" + identity, unique, fence)

        def retain(doc):
            require(
                not doc.get("request")
                or CustomerReferralAttribution.model_validate(doc["request"]).to_dict()
                == request.to_dict(),
                "CUSTOMER_REFERRAL_ATTRIBUTION_CHANGED",
            )
            if not doc.get("request"):
                doc.update(
                    request=request.to_dict(),
                    referred_account_ref=referred.account_ref,
                    qualified_state_digest=state.state_digest,
                    inbound_evidence_digest=stable_digest(event),
                    inbound_occurred_at=event["event"]["occurred_at"],
                    attribution_basis="operator_reviewed_correspondence",
                    created_at=self.host._now(now),
                )

        result = self.events.change(self.claim_ref(request.referral_ref), retain, fence)

        def register(doc):
            refs = doc.setdefault("claims", [])
            if request.referral_ref not in refs:
                require(len(refs) < 100, "CUSTOMER_REFERRAL_CLAIM_CAPACITY")
                refs.append(request.referral_ref)

        self.events.change(self.events.prefix + "-referral-claims", register, fence)
        return result

    def tick(self, *, now, fence, max_claims=1):
        from lightbulb.company_host_journal import HostAuthorityError
        from lightbulb.company_sales_host import _code

        require(type(max_claims) is int and 1 <= max_claims <= 10, "CUSTOMER_REFERRAL_TICK_LIMIT")
        ref = self.events.prefix + "-referral-claims"
        index = self.events.read(ref) or {}
        refs = index.get("claims", [])
        cursor = index.get("cursor", 0) % max(1, len(refs))
        selected = (refs[cursor:] + refs[:cursor])[:max_claims]
        reports = []
        for claim in selected:
            try:
                self.prepare_reward(claim, now=now, fence=fence)
                reports.append(self.acquisition.tick_claim(claim, now=now, fence=fence))
            except (ValueError, LookupError) as error:
                if isinstance(error, HostAuthorityError):
                    raise
                reports.append(dict(referral_ref=claim, status="blocked", code=_code(error)))
        if selected:
            self.events.change(
                ref, lambda doc: doc.update(cursor=(cursor + len(selected)) % len(refs)), fence
            )
        return dict(reports=reports, poll_again=bool(refs))

    def prepare_reward(self, referral_ref, *, now, fence):
        claim = self.events.read(self.claim_ref(referral_ref))
        require(claim is not None, "CUSTOMER_REFERRAL_ATTRIBUTION_REQUIRED")
        request = CustomerReferralAttribution.model_validate(claim["request"])
        program = self.events.read(self.ref(request.program_ref))
        spec = CustomerReferralProgram.model_validate(program["request"])
        original = self._cash(
            spec.successful_offer_kind, spec.successful_offer_ref, now=now, fence=fence
        )
        purchase = self._cash(
            request.referred_offer_kind, request.referred_offer_ref, now=now, fence=fence
        )
        if request.referred_offer_kind == "subscription":
            purchased_at = purchase["financial_observation"]["paid_at"]
        else:
            payment = self.p.commerce.observe_payment(
                request.referred_offer_ref, now=now, fence=fence
            )
            purchased_at = payment["session"]["created"]
        require(
            purchased_at >= parsed(claim["inbound_occurred_at"]).timestamp(),
            "CUSTOMER_REFERRAL_PURCHASE_PREDATES_INBOUND",
        )
        require(
            original["currency"] == purchase["currency"] == spec.currency,
            "CUSTOMER_REFERRAL_CURRENCY_MISMATCH",
        )
        valid = all(
            row["financial_observation"]["captured_minor"] >= spec.reward_minor
            and not row["financial_observation"]["refunded_minor"]
            and not row["financial_observation"]["disputed"]
            for row in (original, purchase)
        )
        now = self.host._now(now)

        def retain(doc):
            if valid and not doc.get("first_collected_at"):
                doc["first_collected_at"] = now
            ready = (
                valid
                and (parsed(now) - parsed(doc["first_collected_at"])).total_seconds()
                >= spec.reward_hold_days * 86400
            )
            doc["reward"] = dict(
                status="review_required" if ready else "holding" if valid else "ineligible",
                amount_minor=spec.reward_minor,
                currency=spec.currency,
                recipient_account_ref=original["account_ref"],
                referral_ref=referral_ref,
                purchase_evidence_digest=stable_digest(purchase),
                observed_at=now,
                execution_authorized=False,
                payout_performed=False,
            )
            doc["reward"]["proposal_digest"] = stable_digest(doc["reward"])

        result = self.events.change(self.claim_ref(referral_ref), retain, fence)
        return result["reward"]
