"""Reviewed deal/invoice links with scoped CRM and retained billing observations."""
from decimal import Decimal

from pydantic import Field

from lightbulb.company_billing_recovery import CompanyBillingRecovery
from lightbulb.company_engine_core import OpaqueRef, StrictModel, detached, parsed, stable_digest
from lightbulb.company_sales_progression import require, scoped_receipt
from lightbulb.connector_execution import ConnectorExecutionRequest


class SalesDealInvoiceLink(StrictModel):
    deal_ref: OpaqueRef
    crm_connector_account_ref: OpaqueRef
    pipeline_ref: OpaqueRef
    won_stage_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    proposal_ref: OpaqueRef
    invoice_source_ref: OpaqueRef
    invoice_ref: OpaqueRef
    review_ref: OpaqueRef


class CompanySalesPayments:
    def __init__(self, progression):
        self.progression, self.host = progression, progression.host

    def _deal(self, link, *, now, fence):
        request = ConnectorExecutionRequest(tool="crm.get_deal", scope=self.host.scope,
            connector_account_ref=link.crm_connector_account_ref, arguments={"deal_id": link.deal_ref})
        fence()
        result = self.host.executor.execute(request)
        receipt = scoped_receipt(result, request)
        now = self.host._now(now)
        require(0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60, "SALES_DEAL_READ_STALE")
        output = result.output
        require(output.get("id") == link.deal_ref and output.get("archived") is False, "SALES_DEAL_IDENTITY_MISMATCH")
        properties = output.get("properties", {})
        require(properties.get("pipeline") == link.pipeline_ref and isinstance(properties.get("dealstage"), str)
                and bool(properties["dealstage"]), "SALES_DEAL_PIPELINE_MISMATCH")
        currency = self.host.runner.bundle.operating_plan.blueprint.currency
        require(properties.get("deal_currency_code") == currency, "SALES_DEAL_CURRENCY_MISMATCH")
        amount = Decimal(properties.get("amount", "NaN"))
        require(amount.is_finite() and 0 <= amount <= 10**12, "SALES_DEAL_AMOUNT_INVALID")
        return {"deal_ref": link.deal_ref, "stage": properties["dealstage"], "amount": str(amount),
                "currency": currency, "receipt": receipt.to_dict()}

    def _source(self, link, binding):
        sources = [source for source in self.host.sources if source.source_ref == link.invoice_source_ref]
        require(len(sources) == 1 and sources[0].kind == "invoice_health", "SALES_INVOICE_SOURCE_REQUIRED")
        source = sources[0]
        require(source.identity_links.get(source.arguments["customer_id"]) == binding.account_ref, "SALES_INVOICE_ACCOUNT_MISMATCH")
        return source

    def link(self, binding_ref, declaration, *, now, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        p.no_pending_delivery(binding)
        require(binding.purpose != "billing_recovery", "SALES_BILLING_NOT_DEAL_HANDOFF")
        link = SalesDealInvoiceLink.model_validate(detached(declaration))
        source = self._source(link, binding)
        ref = p.ref(binding, "deal_invoice", link.invoice_ref)
        old = p.read(ref)
        require(old is None or old["link"] == link.to_dict(), "SALES_DEAL_INVOICE_LINK_CHANGED")
        # Shared across prospects in this authenticated host, not global attribution.
        claim_ref = "sales-invoice-link-" + stable_digest({"authority": self.host.authority_scope,
            "account": source.connector_account_ref, "invoice": link.invoice_ref})
        claim = p.read(claim_ref)
        require(claim is None or claim["link_ref"] == ref, "SALES_INVOICE_ALREADY_ATTRIBUTED")
        if old is None:
            state = self.host._state(binding)
            require(state.status in {"meeting_booked", "handed_off"}, "SALES_MEETING_BEFORE_DEAL_REQUIRED")
            require(state.status != "handed_off" or state.ledger.deal_ref == link.deal_ref, "SALES_DEAL_CHANGED")
            deal = self._deal(link, now=now, fence=fence)
            if claim is None:
                p.write(claim_ref, {"link_ref": ref}, None, fence)
            old = p.write(ref, {"link": link.to_dict(), "deal": deal, "binding_digest": stable_digest(binding.to_dict()),
                "handoff_required": state.status != "handed_off", "mapping_verification": "operator_attested"}, None, fence)
        if old["handoff_required"]:
            p.apply(binding, identity=ref, event="hand_off", receipt={"deal_ref": link.deal_ref,
                "deal_value": old["deal"]["amount"], "evidence_refs": [link.review_ref, old["deal"]["receipt"]["journal_ref"]]}, now=now, fence=fence)
        return old

    def observe(self, binding_ref, invoice_ref, *, now, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        ref = p.ref(binding, "deal_invoice", invoice_ref)
        retained = p.read(ref)
        require(retained and retained["binding_digest"] == stable_digest(binding.to_dict()), "SALES_DEAL_INVOICE_LINK_REQUIRED")
        link = SalesDealInvoiceLink.model_validate(retained["link"])
        state = self.host._state(binding)
        require(state.status == "handed_off" and state.ledger.deal_ref == link.deal_ref, "SALES_DEAL_HANDOFF_REQUIRED")
        source = self._source(link, binding)
        snapshot = CompanyBillingRecovery(self.host.runner, self.host.gateway, source).invoice_snapshot(invoice_ref)
        require(snapshot and snapshot["present"], "SALES_INVOICE_NOT_OBSERVED")
        deal = self._deal(link, now=now, fence=fence)
        now = self.host._now(now)
        require(0 <= (parsed(now) - parsed(snapshot["observation"]["observed_at"])).total_seconds() <= 86400, "SALES_INVOICE_OBSERVATION_STALE")
        row = snapshot["invoice"]
        require(row["currency"] == deal["currency"], "SALES_PAYMENT_CURRENCY_MISMATCH")
        report = {"prospect_ref": binding.prospect_ref, "playbook_ref": binding.playbook_ref,
            "deal_ref": link.deal_ref, "proposal_ref": link.proposal_ref, "invoice_ref": invoice_ref,
            "deal_stage": deal["stage"], "deal_won_under_reviewed_mapping": deal["stage"] in link.won_stage_refs,
            "invoice_status": row["status"], "observed_paid_minor": row["amount_paid_minor"],
            "remaining_minor": row["amount_remaining_minor"], "currency": row["currency"],
            "payment_observed_at": snapshot["observation"]["observed_at"],
            "invoice_observation_digest": snapshot["observation"]["observation_digest"],
            "deal_execution_digest": deal["receipt"]["execution_digest"], "mapping_verification": "operator_attested",
            "causal_attribution_verified": False, "settlement_verified": False, "revenue_verified": False}
        report_ref = p.ref(binding, "payment_observation", invoice_ref)
        old = p.read(report_ref)
        if old is None or old["report"] != report:
            p.write(report_ref, {"report": report, "binding_digest": stable_digest(binding.to_dict())}, old, fence)
        return report
