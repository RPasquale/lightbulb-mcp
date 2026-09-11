"""Referral capture and reviewed billing credits on canonical authenticated paths."""

from typing import Literal
from urllib.parse import urlsplit, urlencode
from uuid import UUID

from pydantic import Field

from lightbulb.company_engine_core import StrictModel, OpaqueRef, stable_digest, parsed
from lightbulb.company_customer_events import CustomerEvent, require
from lightbulb.company_customer_referrals import (
    CustomerReferralAttribution,
    CustomerReferralProgram,
)
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult


class CustomerReferralLink(StrictModel):
    link_ref: OpaqueRef
    program_ref: OpaqueRef
    destination_url: str = Field(max_length=2048)
    review_ref: OpaqueRef


class ReferralCreditObservation(StrictModel):
    schema_id: Literal["lightbulb.stripe_referral_credit.v1"] = Field(alias="schema")
    id: str = Field(pattern=r"^cbtxn_[A-Za-z0-9]{1,128}$")
    customer: str = Field(pattern=r"^cus_[A-Za-z0-9]{1,128}$")
    currency: str = Field(pattern=r"^[a-z]{3}$")
    created: int = Field(gt=0, strict=True)
    livemode: bool
    referral_ref: OpaqueRef
    amount_minor: int = Field(ge=-1000000, le=1000000, strict=True)
    reversal_of: str | None = Field(pattern=r"^cbtxn_[A-Za-z0-9]{1,128}$")
    payout_performed: Literal[False]


class CompanyReferralAcquisition:
    def __init__(self, referrals):
        self.referrals = referrals
        self.p, self.host, self.events = referrals.p, referrals.host, referrals.events

    def link_ref(self, ref):
        return self.events.prefix + "-referral-link-" + stable_digest(ref)

    def create_link(self, request, *, now, fence):
        request = CustomerReferralLink.model_validate(request)
        report = self.referrals.evaluate(request.program_ref, now=now, fence=fence)
        require(report["status"] == "invitation_eligible", "CUSTOMER_REFERRAL_NOT_ELIGIBLE")
        url = urlsplit(request.destination_url)
        require(
            url.scheme == "https"
            and url.hostname
            and url.username is None
            and url.password is None
            and url.port in {None, 443}
            and not url.query
            and not url.fragment,
            "CUSTOMER_REFERRAL_DESTINATION_INVALID",
        )
        code = "lbr_" + stable_digest([self.events.prefix, request.to_dict()])[:32]
        result = dict(
            referral_code=code,
            url=request.destination_url + "?" + urlencode({"ref": code}),
            program_ref=request.program_ref,
            link_ref=request.link_ref,
        )

        def retain(doc):
            require(
                doc.get("request", request.to_dict()) == request.to_dict(),
                "CUSTOMER_REFERRAL_LINK_CHANGED",
            )
            doc.update(
                request=request.to_dict(),
                result=result,
                linked_at=doc.get("linked_at", self.host._now(now)),
            )

        self.events.change(self.link_ref(request.link_ref), retain, fence)
        return result

    def event_ref(self, event_id):
        authority = self.events.gateway.authority_scope.model_dump(mode="json")
        scope = {k: str(authority[k]) for k in ("tenant_id", "company_id", "user_id")}
        scope["project_id"] = str(self.host.runner.bundle.scope["project_id"])
        return self.events.prefix + "-event-" + stable_digest([scope, str(UUID(event_id))])

    def attribute_authenticated(self, request, *, client, now, fence):
        request = CustomerReferralAttribution.model_validate(request)
        require(
            request.authenticated_event_id and request.link_ref,
            "CUSTOMER_REFERRAL_AUTHENTICATED_EVENT_REQUIRED",
        )
        event_id = str(UUID(request.authenticated_event_id))
        link = self.events.read(self.link_ref(request.link_ref))
        require(
            link and link["request"]["program_ref"] == request.program_ref,
            "CUSTOMER_REFERRAL_LINK_REQUIRED",
        )
        offer = self.referrals._offer(request.referred_offer_kind, request.referred_offer_ref)
        require(offer, "CUSTOMER_REFERRAL_ORDER_REQUIRED")
        binding = self.p.binding(offer["offer"]["binding_ref"])
        authority = self.events.gateway.authority_scope.model_dump(mode="json")
        expected = {k: str(authority[k]) for k in ("tenant_id", "company_id", "user_id")}
        expected["project_id"] = str(self.host.runner.bundle.scope["project_id"])
        fence()
        received = client.get_customer_referral_event(
            expected["project_id"], event_id, company_id=expected["company_id"]
        )
        require(
            received.get("schema") == "lightbulb.customer_referral_intake.v1"
            and all(received.get(k) == v for k, v in expected.items())
            and received.get("id") == event_id
            and received.get("referral_code") == link["result"]["referral_code"]
            and received.get("identity_digest") == stable_digest(str(binding.crm_contact_id))
            and parsed(link["linked_at"])
            <= parsed(received["occurred_at"])
            <= parsed(received["recorded_at"])
            <= parsed(now),
            "CUSTOMER_REFERRAL_AUTHENTICATED_EVENT_MISMATCH",
        )
        event = CustomerEvent(
            event_ref=stable_digest([expected, event_id]),
            account_ref=binding.account_ref,
            kind="referral_claimed",
            occurred_at=received["occurred_at"],
            source_ref="authenticated-referral-intake",
            provider_event_digest=stable_digest(received),
            identity_digest=received["identity_digest"],
        )
        journal_ref = self.events.prefix + "-event-" + event.event_ref
        require(
            request.inbound_event_ref == journal_ref, "CUSTOMER_REFERRAL_EVENT_REFERENCE_MISMATCH"
        )
        self.events._retain(
            event, {"source_kind": "authenticated_referral_intake", "source": received}, fence
        )
        return self.referrals.attribute(request, now=now, fence=fence)

    def _write_ref(self, referral_ref, operation):
        return self.referrals.claim_ref(referral_ref) + "-" + operation

    def _credit_arguments(self, referral_ref, *, now, fence):
        claim = self.events.read(self.referrals.claim_ref(referral_ref))
        request = CustomerReferralAttribution.model_validate(claim["request"])
        spec = CustomerReferralProgram.model_validate(
            self.events.read(self.referrals.ref(request.program_ref))["request"]
        )
        original = self.referrals._cash(
            spec.successful_offer_kind, spec.successful_offer_ref, now=now, fence=fence
        )
        purchase = self.referrals._cash(
            request.referred_offer_kind, request.referred_offer_ref, now=now, fence=fence
        )
        source = self.referrals._offer(spec.successful_offer_kind, spec.successful_offer_ref)[
            "request"
        ]
        destination = self.referrals._offer(
            request.referred_offer_kind, request.referred_offer_ref
        )["request"]
        require(
            source["connector_account_ref"] == destination["connector_account_ref"],
            "CUSTOMER_REFERRAL_BILLING_ACCOUNT_MISMATCH",
        )
        cash = purchase["financial_observation"]
        arguments = dict(
            referral_ref=self.referrals.claim_ref(referral_ref),
            customer_id=source["arguments"]["customer_id"],
            referred_customer_id=destination["arguments"]["customer_id"],
            referrer_charge_id=original["financial_observation"]["charge_id"],
            referred_charge_id=cash["charge_id"],
            currency=spec.currency.lower(),
            amount_minor=spec.reward_minor,
            referred_invoice_id=cash.get("invoice_id"),
            referred_subscription_id=cash.get("subscription_id"),
        )
        return arguments, source["connector_account_ref"]

    def prepare_credit(self, referral_ref, *, expected_reward_digest, now, fence):
        claim = self.events.read(self.referrals.claim_ref(referral_ref))
        require(
            claim
            and claim.get("reward", {}).get("status") == "review_required"
            and claim["reward"]["proposal_digest"] == expected_reward_digest,
            "CUSTOMER_REFERRAL_REWARD_REVIEW_REQUIRED",
        )
        reward = self.referrals.prepare_reward(referral_ref, now=now, fence=fence)
        require(reward["status"] == "review_required", "CUSTOMER_REFERRAL_REWARD_NOT_ELIGIBLE")
        arguments, account = self._credit_arguments(referral_ref, now=now, fence=fence)
        return self._prepare(
            referral_ref, "credit", "stripe.create_referral_credit", arguments, account, fence
        )

    def prepare_reversal(self, referral_ref, *, expected_credit_digest, now, fence):
        original = self.events.read(self._write_ref(referral_ref, "credit"))
        require(
            original
            and original.get("phase") == "applied"
            and stable_digest(original["observation"]) == expected_credit_digest,
            "CUSTOMER_REFERRAL_CREDIT_REVIEW_REQUIRED",
        )
        reward = self.referrals.prepare_reward(referral_ref, now=now, fence=fence)
        require(reward["status"] == "ineligible", "CUSTOMER_REFERRAL_REVERSAL_NOT_REQUIRED")
        args = original["request"]["arguments"]
        arguments = {
            k: args[k] for k in ("referral_ref", "customer_id", "currency", "amount_minor")
        }
        arguments["transaction_id"] = original["observation"]["id"]
        return self._prepare(
            referral_ref,
            "reversal",
            "stripe.reverse_referral_credit",
            arguments,
            original["request"]["connector_account_ref"],
            fence,
        )

    def _prepare(self, referral_ref, operation, tool, arguments, account, fence):
        ref = self._write_ref(referral_ref, operation)
        request = ConnectorExecutionRequest(
            tool=tool,
            effect="write",
            approval_required=True,
            scope=self.p.commerce.scope,
            connector_account_ref=account,
            arguments=arguments,
            idempotency_key=ref,
        )
        raw = request.model_dump(mode="json")

        def retain(doc):
            require(doc.get("request", raw) == raw, "CUSTOMER_REFERRAL_CREDIT_CHANGED")
            doc.setdefault("request", raw)
            doc.setdefault("phase", "prepared")

        return self.events.change(ref, retain, fence)

    def execute(self, referral_ref, operation, *, now, fence):
        require(operation in {"credit", "reversal"}, "CUSTOMER_REFERRAL_OPERATION_INVALID")
        ref = self._write_ref(referral_ref, operation)
        row = self.events.read(ref)
        require(row and row.get("request"), "CUSTOMER_REFERRAL_CREDIT_REQUIRED")
        if row["phase"] not in {"prepared", "awaiting_approval"}:
            return dict(
                referral_ref=referral_ref,
                status=row["phase"],
                reconciliation_required=row["phase"] == "posting",
            )
        reward = self.referrals.prepare_reward(referral_ref, now=now, fence=fence)
        require(
            reward["status"] == ("review_required" if operation == "credit" else "ineligible"),
            "CUSTOMER_REFERRAL_REWARD_CHANGED",
        )
        if operation == "credit":
            args, account = self._credit_arguments(referral_ref, now=now, fence=fence)
            require(
                args == row["request"]["arguments"]
                and account == row["request"]["connector_account_ref"],
                "CUSTOMER_REFERRAL_CREDIT_CHANGED",
            )
        request = ConnectorExecutionRequest.model_validate(row["request"])

        def posting(doc):
            require(
                doc.get("phase") in {"prepared", "awaiting_approval"},
                "CUSTOMER_REFERRAL_CREDIT_PHASE_INVALID",
            )
            doc["phase"] = "posting"

        self.events.change(ref, posting, fence)
        try:
            result = self.host.executor.execute(request)
        except Exception:
            return dict(referral_ref=referral_ref, status="posting", reconciliation_required=True)
        return self.reconcile(referral_ref, operation, result, now=now, fence=fence)

    def reconcile(self, referral_ref, operation, result, *, now, fence):
        require(operation in {"credit", "reversal"}, "CUSTOMER_REFERRAL_OPERATION_INVALID")
        ref = self._write_ref(referral_ref, operation)
        row = self.events.read(ref)
        require(row and row.get("request"), "CUSTOMER_REFERRAL_CREDIT_REQUIRED")
        request = ConnectorExecutionRequest.model_validate(row["request"])
        result = ConnectorExecutionResult.model_validate(result)
        if result.status.value == "pending_approval":
            require(result.tool == request.tool, "CUSTOMER_REFERRAL_TOOL_MISMATCH")

            def pending(doc):
                require(
                    doc.get("phase") in {"posting", "awaiting_approval"},
                    "CUSTOMER_REFERRAL_CREDIT_PHASE_INVALID",
                )
                doc.update(phase="awaiting_approval", approval_ref=result.approval_ref)

            self.events.change(ref, pending, fence)
            return dict(
                referral_ref=referral_ref,
                status="awaiting_approval",
                approval_ref=result.approval_ref,
            )
        result, receipt = self.p.commerce._receipt(result, request, self.host._now(now))
        require(result.status.value == "completed", "CUSTOMER_REFERRAL_CREDIT_UNCONFIRMED")
        observation = ReferralCreditObservation.model_validate(result.output)
        a = request.arguments
        require(
            observation.customer == a["customer_id"]
            and observation.currency == a["currency"]
            and observation.referral_ref == a["referral_ref"]
            and observation.amount_minor
            == a["amount_minor"] * (1 if operation == "reversal" else -1)
            and observation.reversal_of
            == (a["transaction_id"] if operation == "reversal" else None),
            "CUSTOMER_REFERRAL_CREDIT_IDENTITY_MISMATCH",
        )

        def retain(doc):
            require(
                doc.get("phase") in {"posting", "awaiting_approval", "applied"},
                "CUSTOMER_REFERRAL_CREDIT_PHASE_INVALID",
            )
            require(
                not doc.get("observation")
                or doc["observation"] == observation.model_dump(mode="json", by_alias=True),
                "CUSTOMER_REFERRAL_CREDIT_CHANGED",
            )
            doc.update(
                phase="applied",
                observation=observation.model_dump(mode="json", by_alias=True),
                receipt=receipt.to_dict(),
            )

        self.events.change(ref, retain, fence)
        return dict(
            referral_ref=referral_ref, status="applied", operation=operation, payout_performed=False
        )

    def observe_credit(self, referral_ref, operation, transaction_id, *, now, fence):
        """Locate a possible provider effect without inventing its approved execution receipt."""
        require(operation in {"credit", "reversal"}, "CUSTOMER_REFERRAL_OPERATION_INVALID")
        row = self.events.read(self._write_ref(referral_ref, operation))
        require(row and row.get("request"), "CUSTOMER_REFERRAL_CREDIT_REQUIRED")
        a = row["request"]["arguments"]
        arguments = {
            key: a[key] for key in ("referral_ref", "customer_id", "currency", "amount_minor")
        }
        arguments["transaction_id"] = transaction_id
        request = ConnectorExecutionRequest(
            tool="stripe.get_referral_credit",
            scope=self.p.commerce.scope,
            connector_account_ref=row["request"]["connector_account_ref"],
            arguments=arguments,
        )
        fence()
        raw, receipt, _ = self.p.subscriptions._read(request, now)
        observation = ReferralCreditObservation.model_validate(raw)
        require(
            observation.id == transaction_id
            and observation.customer == a["customer_id"]
            and observation.currency == a["currency"]
            and observation.referral_ref == a["referral_ref"]
            and observation.amount_minor
            == a["amount_minor"] * (1 if operation == "reversal" else -1)
            and observation.reversal_of
            == (a["transaction_id"] if operation == "reversal" else None),
            "CUSTOMER_REFERRAL_CREDIT_IDENTITY_MISMATCH",
        )
        return {
            "observation": observation.model_dump(mode="json", by_alias=True),
            "receipt": receipt,
            "status": "provider_observed",
            "approved_write_receipt_required": row["phase"] != "applied",
        }

    def tick_claim(self, referral_ref, *, now, fence):
        credit = self.events.read(self._write_ref(referral_ref, "credit"))
        if not credit:
            return self.events.read(self.referrals.claim_ref(referral_ref))["reward"]
        reversal = self.events.read(self._write_ref(referral_ref, "reversal"))
        if reversal:
            return self.execute(referral_ref, "reversal", now=now, fence=fence)
        reward = self.events.read(self.referrals.claim_ref(referral_ref))["reward"]
        if credit["phase"] == "applied" and reward["status"] == "ineligible":
            return dict(
                referral_ref=referral_ref,
                status="reversal_review_required",
                credit_digest=stable_digest(credit["observation"]),
            )
        return self.execute(referral_ref, "credit", now=now, fence=fence)
