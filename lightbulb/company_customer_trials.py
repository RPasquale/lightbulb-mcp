"""Trial conversion evidence and approved assistance on the existing sales cadence."""

from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest
from lightbulb.company_customer_events import CompanyCustomerEvents, require


class CustomerTrialEnrollment(StrictModel):
    enrollment_ref: OpaqueRef
    offer_ref: OpaqueRef
    activation_source_ref: OpaqueRef
    review_ref: OpaqueRef
    assistance_hours_before_end: int = Field(default=72, ge=1, le=720, strict=True)
    max_source_age_seconds: int = Field(default=172800, ge=60, le=604800, strict=True)


class CompanyCustomerTrials:
    def __init__(self, progression):
        self.p, self.host = progression, progression.host
        self.events = CompanyCustomerEvents(self.host.runner, self.host.gateway)

    def ref(self, enrollment_ref):
        return self.events.prefix + "-customer-trial-" + stable_digest(enrollment_ref)

    @property
    def index_ref(self):
        return self.events.prefix + "-customer-trials"

    def enroll(self, request, *, now, fence):
        request = CustomerTrialEnrollment.model_validate(request)
        offer = self.events.read(self.p.subscriptions.ref(request.offer_ref))
        require(offer and offer["offer"]["trial_days"] > 0, "CUSTOMER_TRIAL_OFFER_REQUIRED")
        binding = self.p.binding(offer["offer"]["binding_ref"])
        sources = [s for s in self.host.sources if s.source_ref == request.activation_source_ref]
        require(
            len(sources) == 1
            and sources[0].kind == "customer_events"
            and binding.account_ref in sources[0].identity_links.values()
            and any(m["kind"] == "activated" for m in sources[0].event_bindings.values()),
            "CUSTOMER_TRIAL_ACTIVATION_SOURCE_REQUIRED",
        )

        def retain(doc):
            require(
                not doc.get("request") or doc["request"] == request.to_dict(),
                "CUSTOMER_TRIAL_CHANGED",
            )
            if not doc.get("request"):
                doc.update(
                    request=request.to_dict(),
                    binding_ref=binding.binding_ref,
                    binding_digest=stable_digest(binding.to_dict()),
                    source_digest=stable_digest(sources[0].to_dict()),
                    enrolled_at=self.host._now(now),
                )

        result = self.events.change(self.ref(request.enrollment_ref), retain, fence)

        def register(doc):
            refs = doc.setdefault("enrollments", [])
            if request.enrollment_ref not in refs:
                require(len(refs) < 100, "CUSTOMER_TRIAL_CAPACITY")
                refs.append(request.enrollment_ref)

        self.events.change(self.index_ref, register, fence)
        return result

    def evaluate(self, enrollment_ref, *, now, fence):
        from lightbulb.company_subscription_financials import CompanySubscriptionFinancials

        row = self.events.read(self.ref(enrollment_ref))
        require(row is not None, "CUSTOMER_TRIAL_UNKNOWN")
        request = CustomerTrialEnrollment.model_validate(row["request"])
        binding = self.p.binding(row["binding_ref"])
        require(
            row["binding_digest"] == stable_digest(binding.to_dict()),
            "CUSTOMER_TRIAL_BINDING_CHANGED",
        )
        financials = CompanySubscriptionFinancials(self.p.subscriptions).observe(
            request.offer_ref, now=now, fence=fence
        )
        now = self.host._now(now)
        start, end = financials.get("trial_start"), financials.get("trial_end")
        require(
            type(start) is int and type(end) is int and start < end,
            "CUSTOMER_TRIAL_PROVIDER_DATES_REQUIRED",
        )
        current = int(parsed(now).timestamp())
        require(start <= current, "CUSTOMER_TRIAL_NOT_STARTED")
        paid = [
            i
            for i in financials["invoices"]
            if i.get("cash_verified")
            and i.get("paid_at") is not None
            and end <= i["paid_at"] <= current
            and i.get("billing_reason") in {"subscription_cycle", "subscription_create"}
            and i["payment"]["captured_minor"] > i["payment"]["refunded_minor"]
            and not i["payment"]["disputed"]
            and i["payment"]["refunds_complete"]
        ]
        sub = financials["subscription"]
        source = next(
            (s for s in self.host.sources if s.source_ref == request.activation_source_ref), None
        )
        require(source is not None, "CUSTOMER_TRIAL_ACTIVATION_SOURCE_REQUIRED")
        require(
            stable_digest(source.to_dict()) == row["source_digest"], "CUSTOMER_TRIAL_SOURCE_CHANGED"
        )
        self.events.validate_source_revision(source)
        account = self.events.account(binding.account_ref) or {}
        activated = account.get("kinds", {}).get("activated")
        activated = (
            activated
            if activated
            and activated["event"]["source_ref"] == source.source_ref
            and start <= parsed(activated["event"]["occurred_at"]).timestamp() <= current
            else None
        )
        coverage = self.events.read(
            self.events.prefix + "-source-" + stable_digest(source.source_ref)
        )
        covered = bool(
            coverage
            and coverage.get("binding_digest") == stable_digest(source.to_dict())
            and parsed(coverage.get("covered_from", coverage["window_start"])).timestamp() <= start
            and 0
            <= current - parsed(coverage["through"]).timestamp()
            <= request.max_source_age_seconds
        )
        status = "assistance_eligible"
        if not financials["invoices_complete"]:
            status = "billing_coverage_required"
        elif paid:
            status = "converted"
        elif sub["cancel_at_period_end"] or sub["status"] in {
            "canceled",
            "unpaid",
            "incomplete_expired",
            "paused",
        }:
            status = "canceled"
        elif current >= end:
            status = "trial_ended"
        elif current < end - request.assistance_hours_before_end * 3600:
            status = "conversion_window_not_open"
        elif not covered:
            status = "instrumentation_required"
        else:
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
                    and parsed(hold["observed_at"]) <= parsed(row["enrolled_at"])
                ):
                    status = "customer_reply_or_suppression"
            except ValueError as error:
                from lightbulb.company_host_journal import HostAuthorityError

                if isinstance(error, HostAuthorityError):
                    raise
                status = "customer_reply_or_suppression"
        first = min(paid, key=lambda i: (i["paid_at"], i["invoice_id"])) if paid else None
        result = dict(
            enrollment_ref=enrollment_ref,
            binding_ref=binding.binding_ref,
            status=status,
            baseline=int(parsed(row["enrolled_at"]).timestamp()),
            trial_start=start,
            trial_end=end,
            activation_observed=activated is not None,
            activation_evidence=activated,
            billing_readiness=financials.get("billing_readiness", "unknown"),
            recommended_action=(
                "review_billing_readiness" if activated else "offer_activation_assistance"
            ),
            first_collected_invoice=first,
            financial_evidence_digest=stable_digest(financials),
            observed_at=now,
            causal_uplift_verified=False,
        )
        self.events.change(
            self.ref(enrollment_ref), lambda doc: doc.update(observation=result), fence
        )
        return result

    def prepare_assistance(self, enrollment_ref, message, *, now, fence):
        return self.p.conversations.prepare_program(
            "trial_assistance", enrollment_ref, message, now=now, fence=fence
        )

    def tick(self, *, now, fence, max_enrollments=1):
        from lightbulb.company_host_journal import HostAuthorityError
        from lightbulb.company_sales_host import _code

        index = self.events.read(self.index_ref) or {}
        require(
            type(max_enrollments) is int and 1 <= max_enrollments <= 10, "CUSTOMER_TRIAL_TICK_LIMIT"
        )
        refs = index.get("enrollments", [])
        cursor = index.get("cursor", 0) % max(1, len(refs))
        selected = (refs[cursor:] + refs[:cursor])[:max_enrollments]
        rows = []
        for ref in selected:
            try:
                rows.append(self.evaluate(ref, now=now, fence=fence))
            except (ValueError, LookupError) as error:
                if isinstance(error, HostAuthorityError):
                    raise
                rows.append(dict(enrollment_ref=ref, status="blocked", code=_code(error)))
        if selected:
            self.events.change(
                self.index_ref,
                lambda doc: doc.update(cursor=(cursor + len(selected)) % len(refs)),
                fence,
            )
        return {
            "reports": rows,
            "poll_again": len(refs) > len(selected)
            or any(r["status"] not in {"converted", "canceled", "trial_ended"} for r in rows),
        }
