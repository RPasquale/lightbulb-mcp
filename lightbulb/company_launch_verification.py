"""Executable, resumable launch checks against the actual configured company host.

These checks never simulate a provider success or approve their own requests.
Billing test mode is provider-observed; destination test isolation is reviewed setup.
"""

from typing import Literal
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    stable_digest,
    parsed,
)
from lightbulb.company_customer_events import CompanyCustomerEvents, require
from lightbulb.company_launch_packages import BusinessLaunchPackageProposal
from lightbulb.connector_execution import ConnectorExecutionRequest


class BusinessLaunchVerificationRequest(StrictModel):
    verification_ref: OpaqueRef
    package_digest: Sha256Digest
    offer_ref: OpaqueRef
    destination_test_review_ref: OpaqueRef
    finalization: Literal["refund", "scheduled_cancellation"]
    deadline_at: str


class CompanyBusinessLaunchVerification:
    def __init__(self, packages):
        self.packages = packages

    def check_guard(self, proposal, request, scenario, *, host, now, fence):
        """Execute a negative guard against a test-mode, reviewed launch configuration.

        State-dependent checks report missing setup rather than manufacturing an
        unpaid/refunded customer or a failed provider effect. No provider write is
        permitted by this diagnostic; exact guarded reads still use the executor.
        """
        require(
            scenario
            in {
                "foreign_customer_rejected",
                "unpaid_has_no_fulfillment",
                "delivery_deadline_blocks_new_write",
                "refund_before_fulfillment_blocks_delivery",
            },
            "LAUNCH_VERIFICATION_GUARD_UNSUPPORTED",
        )
        self.run(proposal, request, host=host, now=now, fence=fence)
        proposal = BusinessLaunchPackageProposal.model_validate(proposal)
        request = BusinessLaunchVerificationRequest.model_validate(request)
        offers = [o for o in proposal.package.offers if o.offer_ref == request.offer_ref]
        require(len(offers) == 1, "LAUNCH_VERIFICATION_ONE_TIME_GUARD_REQUIRED")
        offer = offers[0]
        commerce = host.progression.commerce
        old = commerce.events.read(commerce.ref(offer.offer_ref))
        if scenario != "foreign_customer_rejected":
            if not old or not old.get("session_id") or old.get("fulfillment", {}).get("phase"):
                return dict(
                    scenario=scenario, status="blocked", reason="unfulfilled_test_checkout_required"
                )
            payment = commerce.observe_payment(offer.offer_ref, now=now, fence=fence)
            if scenario == "unpaid_has_no_fulfillment" and payment["payment_confirmed"]:
                return dict(
                    scenario=scenario, status="blocked", reason="unpaid_test_checkout_required"
                )
            if scenario == "refund_before_fulfillment_blocks_delivery":
                if not payment["payment_confirmed"]:
                    return dict(
                        scenario=scenario,
                        status="blocked",
                        reason="refunded_test_checkout_required",
                    )
                cash = commerce.financials._observe(offer.offer_ref, now=now, fence=fence)
                if not cash["financial_observation"]["refunded_minor"]:
                    return dict(
                        scenario=scenario,
                        status="blocked",
                        reason="refunded_test_checkout_required",
                    )
            if scenario == "delivery_deadline_blocks_new_write" and (
                not offer.fulfillment.deadline_at
                or parsed(now) < parsed(offer.fulfillment.deadline_at)
                or not payment["session"]["payment_available_for_fulfillment"]
            ):
                return dict(
                    scenario=scenario,
                    status="blocked",
                    reason="paid_checkout_with_elapsed_delivery_deadline_required",
                )
        delegate = host.executor

        class ReadOnlyProbe:
            attempted_write = False

            def execute(self, call):
                if call.effect.value == "write":
                    self.attempted_write = True
                    raise RuntimeError("LAUNCH_NEGATIVE_GUARD_ATTEMPTED_WRITE")
                return delegate.execute(call)

        probe = ReadOnlyProbe()
        host.executor = probe
        try:
            try:
                if scenario == "foreign_customer_rejected":
                    from lightbulb.company_customer_commerce import CustomerOffer

                    raw = offer.to_dict()
                    raw["fulfillment"]["customer_identity_value"] = "different-customer"
                    commerce.prepare(CustomerOffer.model_validate(raw), now=now, fence=fence)
                else:
                    commerce.fulfill(offer.offer_ref, now=now, fence=fence)
            except ValueError as error:
                from lightbulb.company_host_journal import HostAuthorityError

                if isinstance(error, HostAuthorityError):
                    raise
                expected = {
                    "foreign_customer_rejected": "CUSTOMER_FULFILLMENT_IDENTITY_MISMATCH",
                    "unpaid_has_no_fulfillment": "CUSTOMER_FULFILLMENT_PAYMENT_REQUIRED",
                    "refund_before_fulfillment_blocks_delivery": "CUSTOMER_FULFILLMENT_PAYMENT_REQUIRED",
                    "delivery_deadline_blocks_new_write": "CUSTOMER_FULFILLMENT_DEADLINE_PASSED",
                }[scenario]
                require(
                    str(error) == expected and not probe.attempted_write,
                    "LAUNCH_VERIFICATION_GUARD_FAILED",
                )
                return dict(
                    scenario=scenario,
                    status="passed",
                    observed_guard=expected,
                    provider_write_attempted=False,
                    observed_at=host._now(now),
                )
            require(False, "LAUNCH_VERIFICATION_GUARD_FAILED")
        finally:
            host.executor = delegate

    def run(self, proposal, request, *, host, now, fence, advance=False):
        """Read evidence; optionally request the next exact governed sandbox operation.

        Reinvoke after the user approves, the customer completes checkout, or a test
        refund is recorded. Unknown effects remain reconciliation tasks. Refund
        execution is deliberately owned by the existing governed finance workflow.
        """
        require(type(advance) is bool, "LAUNCH_VERIFICATION_ADVANCE_INVALID")
        proposal = BusinessLaunchPackageProposal.model_validate(proposal)
        request = BusinessLaunchVerificationRequest.model_validate(request)
        require(
            request.package_digest == proposal.proposal_digest,
            "LAUNCH_VERIFICATION_PACKAGE_CHANGED",
        )
        configuration = self.packages.materialize_reviewed(
            proposal, expected_digest=request.package_digest
        )
        from lightbulb.company_cadence_runner import build_bundle

        expected_bundle = build_bundle(proposal.package.configuration.bundle)
        require(
            host.runner.bundle.plan_digest == expected_bundle.plan_digest
            and host.runner.bundle.scope == proposal.package.configuration.bundle["scope"]
            and host.configuration.to_dict() == proposal.package.configuration.sales_config,
            "LAUNCH_VERIFICATION_HOST_SCOPE_MISMATCH",
        )
        require(
            [s.to_dict() for s in host.sources] == list(proposal.package.configuration.sources),
            "LAUNCH_VERIFICATION_SOURCES_CHANGED",
        )
        candidates = [
            (False, o) for o in proposal.package.offers if o.offer_ref == request.offer_ref
        ]
        candidates += [
            (True, o)
            for o in proposal.package.subscription_offers
            if o.offer_ref == request.offer_ref
        ]
        require(len(candidates) == 1, "LAUNCH_VERIFICATION_OFFER_REQUIRED")
        recurring, offer = candidates[0]
        require(
            recurring == (request.finalization == "scheduled_cancellation"),
            "LAUNCH_VERIFICATION_FINALIZATION_MISMATCH",
        )
        commerce = host.progression.commerce
        service = host.progression.subscriptions if recurring else commerce
        binding, source = commerce._source(offer)
        events = CompanyCustomerEvents(host.runner, host.gateway)
        ref = events.prefix + "-launch-verification-" + stable_digest(request.verification_ref)

        def register(doc):
            require(
                not doc.get("request") or doc["request"] == request.to_dict(),
                "LAUNCH_VERIFICATION_CHANGED",
            )
            doc.setdefault("request", request.to_dict())

        events.change(ref, register, fence)
        call = ConnectorExecutionRequest(
            tool="stripe.get_commerce_environment",
            scope=commerce.scope,
            connector_account_ref=source.connector_account_ref,
            arguments={},
        )
        fence()
        result = host.executor.execute(call)
        result, receipt = commerce._receipt(result, call, host._now(now))
        now = host._now(now)
        require(
            0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60,
            "LAUNCH_VERIFICATION_ENVIRONMENT_STALE",
        )
        require(
            result.output
            == {"schema": "lightbulb.stripe_commerce_environment.v1", "livemode": False},
            "LAUNCH_VERIFICATION_TEST_MODE_REQUIRED",
        )
        can_advance = advance and parsed(now) < parsed(request.deadline_at)
        steps = {
            "connections": dict(status="passed", evidence_digest=stable_digest(configuration)),
            "billing_test_mode": dict(status="passed", evidence_digest=receipt.receipt_digest),
        }
        state = host.runner.store.get("pipeline_engine", binding.prospect_ref)
        if state is None and can_advance:
            selected = [
                c
                for c in host.configuration.intake_candidates
                if c.binding.binding_ref == binding.binding_ref
            ]
            if len(selected) == 1:
                host.intake.ingest(selected[0], now=now, fence=fence)
            state = host.runner.store.get("pipeline_engine", binding.prospect_ref)
        if state:
            scoped = host.intake._scoped_state(
                host.runner.runtimes["pipeline_engine"], binding.prospect_ref
            )
            require(
                scoped.ledger.account_ref == binding.account_ref,
                "LAUNCH_VERIFICATION_CUSTOMER_MISMATCH",
            )
            steps["intake"] = dict(status="passed", evidence_digest=scoped.state_digest)
        else:
            steps["intake"] = dict(status="blocked", reason="customer_intake_required")
        old = events.read(service.ref(offer.offer_ref))
        if can_advance and state:
            service.checkout(offer, now=now, fence=fence)
            old = events.read(service.ref(offer.offer_ref))
        steps["checkout"] = dict(
            status="passed" if old and old.get("session_id") else "blocked",
            reason=None if old and old.get("session_id") else "approved_checkout_required",
        )
        steps["approval"] = dict(status="blocked", reason="approved_write_receipt_required")
        steps["payment"] = dict(status="blocked", reason="customer_payment_required")
        steps["delivery"] = dict(status="blocked", reason="approved_delivery_and_readback_required")
        steps["finalization"] = dict(
            status="blocked", reason="test_refund_or_cancellation_required"
        )
        if old and old.get("session_id"):
            # The canonical checkout writer validates the provider's approved write
            # receipt before retaining its created/session result.
            approval_evidence = (
                old.get("created") if not recurring else old.get("writes", {}).get("checkout")
            )
            approval_receipt = (approval_evidence or {}).get("receipt", {})
            approved = (
                approval_receipt.get("approval_ref")
                and approval_receipt.get("approval_receipt_digest")
                and (
                    not recurring
                    or approval_evidence.get("phase") == "applied"
                    and approval_evidence.get("output", {}).get("id") == old["session_id"]
                )
            )
            if approved:
                steps["approval"] = dict(
                    status="passed", evidence_digest=stable_digest(approval_evidence)
                )
            if recurring:
                observed = service.observe(offer.offer_ref, now=now, fence=fence)
                financial = service.financials.observe(offer.offer_ref, now=now, fence=fence)
                paid = any(
                    i["cash_verified"]
                    and i["payment"]
                    and i["payment"]["captured_minor"] > 0
                    and not i["payment"]["disputed"]
                    for i in financial["invoices"]
                )
                if paid:
                    steps["payment"] = dict(
                        status="passed", evidence_digest=stable_digest(financial)
                    )
                if can_advance and paid:
                    service.synchronize_access(offer.offer_ref, now=now, fence=fence)
                control = events.read(service.ref(offer.offer_ref) + "-access-control") or {}
                access = events.read(control["active_ref"]) if control.get("active_ref") else None
                if (
                    access
                    and control.get("action") == "grant"
                    and access.get("fulfillment", {}).get("phase") == "verified"
                ):
                    service.verify_access(offer.offer_ref, now=now, fence=fence)
                    access = events.read(control["active_ref"])
                    steps["delivery"] = dict(
                        status="passed", evidence_digest=stable_digest(access["fulfillment"])
                    )
                sub = observed.get("subscription")
                if (
                    sub
                    and can_advance
                    and steps["delivery"]["status"] == "passed"
                    and not sub["cancel_at_period_end"]
                ):
                    service.cancel_at_period_end(
                        offer.offer_ref,
                        expected_subscription_digest=sub["subscription_digest"],
                        now=now,
                        fence=fence,
                    )
                    sub = service.observe(offer.offer_ref, now=now, fence=fence).get("subscription")
                if sub and sub["cancel_at_period_end"]:
                    steps["finalization"] = dict(
                        status="passed",
                        evidence_digest=stable_digest(sub),
                        kind="scheduled_cancellation",
                    )
            else:
                payment = commerce.observe_payment(offer.offer_ref, now=now, fence=fence)
                if payment["payment_confirmed"]:
                    steps["payment"] = dict(status="passed", evidence_digest=stable_digest(payment))
                if can_advance and payment["session"]["payment_available_for_fulfillment"]:
                    commerce.fulfill(offer.offer_ref, now=now, fence=fence)
                current = events.read(commerce.ref(offer.offer_ref))
                if current.get("fulfillment", {}).get("phase") in {"written", "verified"}:
                    status = commerce.verify_fulfillment(offer.offer_ref, now=now, fence=fence)
                    if status["fulfillment_status"] == "verified":
                        steps["delivery"] = dict(
                            status="passed",
                            evidence_digest=stable_digest(
                                events.read(commerce.ref(offer.offer_ref))["fulfillment"]
                            ),
                        )
                if payment["payment_confirmed"]:
                    financial = commerce.financials._observe(offer.offer_ref, now=now, fence=fence)
                    if financial["financial_observation"]["refunded_minor"] > 0:
                        steps["finalization"] = dict(
                            status="passed",
                            evidence_digest=stable_digest(financial),
                            kind="observed_refund",
                        )
        report = dict(
            schema="lightbulb.business_launch_verification.v1",
            verification_ref=request.verification_ref,
            package_digest=request.package_digest,
            observed_at=host._now(now),
            steps=steps,
            journey_verified=all(s["status"] == "passed" for s in steps.values()),
            destination_isolation_basis="operator_reviewed_test_target",
            execution_authorized=False,
            deadline_passed=parsed(now) >= parsed(request.deadline_at),
            unexecuted_scenarios=list(proposal.sandbox_scenarios),
            sandbox_validated=False,
        )
        # A successful positive journey is not certification of the failure scenarios.
        events.change(ref, lambda doc: doc.update(report=report), fence)
        return report
