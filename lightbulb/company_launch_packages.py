"""Reviewed launch compositions, including commerce and concrete destination readiness."""

from typing import Literal, Any
from pydantic import Field, model_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    stable_digest,
    detached,
)
from lightbulb.company_business_launch import BusinessLaunchRequest, BusinessLaunchProposal
from lightbulb.company_customer_commerce import CustomerOffer
from lightbulb.company_customer_subscriptions import CustomerSubscriptionOffer
from lightbulb.company_customer_events import require
from lightbulb.company_sales_configuration import CompanySalesConfiguration


class BusinessLaunchPackage(StrictModel):
    package_ref: OpaqueRef
    kind: Literal["saas", "service", "digital_product"]
    configuration: BusinessLaunchRequest
    offers: tuple[CustomerOffer, ...] = Field(default=(), max_length=100)
    subscription_offers: tuple[CustomerSubscriptionOffer, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def coherent(self):
        all_offers = (*self.offers, *self.subscription_offers)
        require(bool(all_offers), "LAUNCH_PACKAGE_OFFER_REQUIRED")
        require(
            len({o.offer_ref for o in all_offers}) == len(all_offers),
            "LAUNCH_PACKAGE_DUPLICATE_OFFER",
        )
        expected = {
            "saas": {"github.provision_repository_access", "postgresql.apply_customer_workspace"},
            "service": {"notion.create_service_onboarding"},
            "digital_product": {"drive.deliver_file_access"},
        }[self.kind]
        require(
            all(
                getattr(o, "fulfillment", None) is not None and o.fulfillment.write_tool in expected
                for o in all_offers
            ),
            "LAUNCH_PACKAGE_DESTINATION_MISMATCH",
        )
        require(self.configuration.sales_config is not None, "LAUNCH_PACKAGE_SALES_REQUIRED")
        bindings = {
            b.binding_ref
            for b in CompanySalesConfiguration.model_validate(
                self.configuration.sales_config
            ).all_bindings()
        }
        sources = {s["source_ref"]: s for s in self.configuration.sources}
        for offer in all_offers:
            require(offer.binding_ref in bindings, "LAUNCH_PACKAGE_BINDING_REQUIRED")
            require(
                sources.get(offer.billing_source_ref, {}).get("kind") == "invoice_health",
                "LAUNCH_PACKAGE_BILLING_REQUIRED",
            )
        if self.kind == "saas":
            require(bool(self.subscription_offers), "LAUNCH_PACKAGE_SUBSCRIPTION_REQUIRED")
            require(
                all(
                    o.access_policy.revoke_fulfillment is not None for o in self.subscription_offers
                ),
                "LAUNCH_PACKAGE_REVOCATION_REQUIRED",
            )
            require(
                any(s.get("kind") == "customer_events" for s in self.configuration.sources),
                "LAUNCH_PACKAGE_PRODUCT_EVENTS_REQUIRED",
            )
            require(
                self.configuration.customer_lifecycle is not None,
                "LAUNCH_PACKAGE_LIFECYCLE_REQUIRED",
            )
        return self


class BusinessLaunchPackageProposal(StrictModel):
    package: BusinessLaunchPackage
    configuration_proposal: BusinessLaunchProposal
    commerce_routes: tuple[dict[str, Any], ...]
    sandbox_scenarios: tuple[str, ...]
    proposal_digest: Sha256Digest
    execution_authorized: Literal[False] = False


class CompanyBusinessLaunchPackages:
    def __init__(self, assistant):
        self.assistant = assistant

    @property
    def verification(self):
        from lightbulb.company_launch_verification import CompanyBusinessLaunchVerification

        return CompanyBusinessLaunchVerification(self)

    def prepare(self, package, *, probe_sources=True):
        package = BusinessLaunchPackage.model_validate(package)
        proposal = self.assistant.prepare(package.configuration, probe_sources=probe_sources)
        package = BusinessLaunchPackage.model_validate(
            {**package.to_dict(), "configuration": proposal.request.to_dict()}
        )
        routes = self._routes(package)
        scenarios = (
            "approval_denied_has_no_effect",
            "foreign_customer_rejected",
            "unpaid_has_no_fulfillment",
            "paid_destination_write_then_exact_readback",
            "lost_write_ack_requires_receipt_reconciliation",
            "delivery_deadline_blocks_new_write",
            "refund_before_fulfillment_blocks_delivery",
        )
        if package.subscription_offers:
            scenarios = tuple(
                s
                for s in scenarios
                if s
                not in {"unpaid_has_no_fulfillment", "refund_before_fulfillment_blocks_delivery"}
            ) + (
                "trial_access_requires_explicit_policy",
                "scheduled_cancellation_retains_current_access",
                "unpaid_subscription_proposes_approved_revocation",
                "reactivation_requires_new_reviewed_offer",
            )
        body = {
            "package": package.to_dict(),
            "configuration_proposal": proposal.to_dict(),
            "commerce_routes": routes,
            "sandbox_scenarios": scenarios,
        }
        return BusinessLaunchPackageProposal(**body, proposal_digest=stable_digest(body))

    def _routes(self, package):
        project = str(package.configuration.bundle["scope"]["project_id"])
        sources = {s["source_ref"]: s for s in package.configuration.sources}
        wanted = set()
        for offer in package.offers:
            billing = sources[offer.billing_source_ref]["connector_account_ref"]
            wanted.update(
                [
                    (billing, "stripe.create_checkout_session"),
                    (billing, "stripe.get_checkout_session"),
                    (offer.fulfillment.connector_account_ref, offer.fulfillment.write_tool),
                    (offer.fulfillment.connector_account_ref, offer.fulfillment.verification_tool),
                ]
            )
        for offer in package.subscription_offers:
            billing = sources[offer.billing_source_ref]["connector_account_ref"]
            wanted.update(
                (billing, tool)
                for tool in (
                    "stripe.create_subscription_checkout",
                    "stripe.get_subscription_checkout",
                    "stripe.get_customer_subscription",
                    "stripe.preview_subscription_change",
                    "stripe.change_customer_subscription",
                    "stripe.cancel_customer_subscription",
                )
            )
            revoke = offer.access_policy.revoke_fulfillment
            if revoke is not None:
                wanted.update(
                    [
                        (revoke.connector_account_ref, revoke.write_tool),
                        (revoke.connector_account_ref, revoke.verification_tool),
                    ]
                )
            wanted.update(
                [
                    (offer.fulfillment.connector_account_ref, offer.fulfillment.write_tool),
                    (offer.fulfillment.connector_account_ref, offer.fulfillment.verification_tool),
                ]
            )
        rows = []
        active = {
            r["connectorAccountRef"]
            for r in self.assistant.client.list_project_connector_accounts(
                project, company_id=self.assistant.company_id
            )
            if r.get("status") == "active"
        }
        for account, tool in sorted(wanted):
            require(account in active, "LAUNCH_PACKAGE_ACTIVE_DESTINATION_REQUIRED")
            descriptor = self.assistant.client.get_project_connector_route_descriptor(
                project, account, tool, company_id=self.assistant.company_id
            )
            require(isinstance(descriptor, dict) and descriptor, "LAUNCH_PACKAGE_ROUTE_REQUIRED")
            rows.append(
                {
                    "connector_account_ref": account,
                    "tool": tool,
                    "descriptor_digest": stable_digest(descriptor),
                }
            )
        return rows

    def materialize_reviewed(self, proposal, *, expected_digest):
        proposal = BusinessLaunchPackageProposal.model_validate(proposal)
        body = {
            k: detached(getattr(proposal, k))
            for k in ("package", "configuration_proposal", "commerce_routes", "sandbox_scenarios")
        }
        require(
            stable_digest(body) == proposal.proposal_digest == expected_digest,
            "LAUNCH_PACKAGE_REVIEW_CHANGED",
        )
        require(
            detached(proposal.package.configuration)
            == detached(proposal.configuration_proposal.request),
            "LAUNCH_PACKAGE_CONFIGURATION_CHANGED",
        )
        require(
            self._routes(proposal.package) == list(proposal.commerce_routes),
            "LAUNCH_PACKAGE_ROUTES_CHANGED",
        )
        configuration = self.assistant.materialize_reviewed(
            proposal.configuration_proposal,
            expected_digest=proposal.configuration_proposal.proposal_digest,
        )
        return {
            "worker_configuration": configuration,
            "offers": [o.to_dict() for o in proposal.package.offers],
            "subscription_offers": [o.to_dict() for o in proposal.package.subscription_offers],
            "sandbox_scenarios": list(proposal.sandbox_scenarios),
            "sandbox_validated": False,
            "reviewed_package_digest": expected_digest,
            "execution_authorized": False,
            "account_provisioning_scope": (
                "explicit application workspace or existing GitHub identity repository access"
                if proposal.package.kind == "saas"
                else None
            ),
        }
