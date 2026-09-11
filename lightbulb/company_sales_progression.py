"""Durable reviewed reply and qualification transitions for company sales.

Classification is a proposal. Reviews are explicit operator evidence; neither
they nor SDK state changes grant provider-write authority.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from lightbulb.company_engine_core import OpaqueRef, Sha256Digest, StrictModel, detached, parsed, stable_digest, timestamp
from lightbulb.company_execution_bridge import execution_receipt_from_connector
from lightbulb.company_sales_observations import sales_thread_observation, _addresses
from lightbulb.connector_execution import ConnectorExecutionRequest
from lightbulb.executable_primitives import ClassifyReplyPrimitive
from lightbulb.primitive_runtime import PrimitiveExecutionContext


class SalesProgressionError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise SalesProgressionError(code)


def scoped_receipt(result, request):
    receipt = execution_receipt_from_connector(result, request)
    require(receipt.project_id == str(request.scope.project_id)
            and receipt.connector_account_ref == request.connector_account_ref,
            "SALES_EXECUTION_SCOPE_MISMATCH")
    require(receipt.route_digest != "0" * 64 and receipt.receipt_digest != "0" * 64,
            "SALES_EXECUTION_UNSEALED")
    return receipt


class SalesReplyReview(StrictModel):
    proposal_ref: OpaqueRef
    proposal_digest: Sha256Digest
    review_ref: OpaqueRef
    disposition: Literal["positive", "objection", "not_now", "negative", "out_of_office", "wrong_person", "unsubscribe", "uncertain"]


class SalesQualificationReview(StrictModel):
    review_ref: OpaqueRef
    expected_state_digest: Sha256Digest
    scores: dict[str, int] = Field(max_length=5)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)


class CompanySalesProgression:
    """Use through ``CompanySalesHost.progression`` under the host's lease fence."""
    def __init__(self, host):
        self.host, self.runner, self.gateway = host, host.runner, host.gateway

    @property
    def subscriptions(self):
        from lightbulb.company_customer_subscriptions import CompanyCustomerSubscriptions
        return CompanyCustomerSubscriptions(self.host)

    @property
    def trials(self):
        from lightbulb.company_customer_trials import CompanyCustomerTrials
        return CompanyCustomerTrials(self)

    @property
    def allocation(self):
        from lightbulb.company_customer_allocation import CompanyCustomerAllocation
        return CompanyCustomerAllocation(self)

    @property
    def referrals(self):
        from lightbulb.company_customer_referrals import CompanyCustomerReferrals
        return CompanyCustomerReferrals(self)

    @property
    def support(self):
        from lightbulb.company_customer_support import CompanyCustomerSupport
        return CompanyCustomerSupport(self)

    @property
    def checkout_recovery(self):
        from lightbulb.company_checkout_recovery import CompanyCheckoutRecovery
        return CompanyCheckoutRecovery(self)

    @property
    def conversations(self):
        from lightbulb.company_customer_conversations import CompanyCustomerConversations
        return CompanyCustomerConversations(self)

    @property
    def commerce(self):
        from lightbulb.company_customer_commerce import CompanyCustomerCommerce
        return CompanyCustomerCommerce(self.host)

    @property
    def customer_profit(self):
        from lightbulb.company_customer_profit import CompanyCustomerProfit
        return CompanyCustomerProfit(self.host.customer_lifecycle)

    @property
    def preparation(self):
        from lightbulb.company_sales_preparation import CompanySalesPreparation
        return CompanySalesPreparation(self)

    @property
    def research(self):
        from lightbulb.company_sales_research import CompanySalesResearch
        return CompanySalesResearch(self)

    @property
    def meetings(self):
        from lightbulb.company_sales_meetings import CompanySalesMeetings
        return CompanySalesMeetings(self)

    @property
    def payments(self):
        from lightbulb.company_sales_payments import CompanySalesPayments
        return CompanySalesPayments(self)

    def payment_recovery(self, policy_ref):
        from lightbulb.company_payment_recovery_actions import CompanyPaymentRecoveryActions
        require(policy_ref in self.host.billing, "SALES_BILLING_POLICY_UNKNOWN")
        return CompanyPaymentRecoveryActions(self.host.billing[policy_ref], self.host.executor)

    def binding(self, binding_ref):
        rows = [row for row in self.host.configuration.all_bindings() if row.binding_ref == binding_ref]
        require(len(rows) == 1, "SALES_BINDING_UNKNOWN")
        return rows[0]

    def ref(self, binding, kind, identity):
        return "sales-progress-" + stable_digest({"authority": self.host.authority_scope,
            "bundle": self.runner.bundle.plan_digest, "prospect": binding.prospect_ref, "kind": kind, "identity": identity})

    def read(self, ref):
        row = self.gateway.get(ref)
        if row:
            require(row.get("schema") == "lightbulb.sales_progression.v1"
                    and row.get("authority_scope") == self.host.authority_scope
                    and row.get("bundle_digest") == self.runner.bundle.plan_digest, "SALES_PROGRESSION_SCOPE_MISMATCH")
        return row

    def write(self, ref, value, old, fence):
        value = {**detached(value), "schema": "lightbulb.sales_progression.v1", "status": "COMPLETED", "resume_at": None,
                 "authority_scope": self.host.authority_scope, "bundle_digest": self.runner.bundle.plan_digest}
        require(len(json.dumps(value).encode()) < 400_000, "SALES_PROGRESSION_CAPACITY")
        if getattr(self.host, "capability_waits", None):
            self.host.capability_waits.outcomes.track_sales_source(ref, value, old, fence=fence)
        fence()
        return self.gateway.put(ref, value, expected_revision=old["revision"] if old else 0)

    def no_pending_delivery(self, binding):
        from lightbulb.company_sales_host import CONTROL_SCHEMA
        control = self.host._read(self.host._ref(binding), CONTROL_SCHEMA)
        require(not control or not control.get("active_ref"), "SALES_DELIVERY_RECONCILIATION_REQUIRED")

    def apply(self, binding, *, identity, event, receipt, now, fence, engine="pipeline_engine", entity=None, reason=None):
        """Freeze before mutation and recover a lost state-write acknowledgement."""
        ref = self.ref(binding, engine + ":" + event, identity)
        retained = self.read(ref)
        intent = stable_digest({"event": event, "receipt": receipt, "reason": reason, "entity": entity})
        runtime = self.runner.runtimes[engine]
        entity = entity or binding.prospect_ref
        state = self.host.intake._scoped_state(runtime, entity)
        if retained is None:
            command = runtime.command(state, event=event, transition_ref=ref, idempotency_key=ref,
                occurred_at=timestamp(now, field_name="now"), actor_ref=self.runner.bundle.actor_ref,
                receipt=receipt, reason=reason)
            predicted = runtime.advance(runtime.plan, state, command)
            require(predicted.candidate_validated, "SALES_PROGRESS_TRANSITION_REFUSED")
            retained = self.write(ref, {"intent": intent, "command": detached(command)}, None, fence)
        require(retained["intent"] == intent, "SALES_PROGRESS_REVIEW_CHANGED")
        command = retained["command"]
        matches = [item for item in state.transition_history if item.command.idempotency_key == ref]
        if not matches:
            require(state.state_digest == command["expected_state_digest"], "SALES_PROGRESS_STATE_CHANGED")
            fence()
            result = runtime.advance_and_persist(entity, command)
            require(result.persisted, "SALES_PROGRESS_TRANSITION_REFUSED")
            state = self.host.intake._scoped_state(runtime, entity)
            matches = [item for item in state.transition_history if item.command.idempotency_key == ref]
        require(len(matches) == 1 and detached(matches[0].command) == command, "SALES_PROGRESS_REPLAY_MISMATCH")
        return state

    def propose_reply(self, binding_ref, *, now, fence):
        binding = self.binding(binding_ref)
        self.no_pending_delivery(binding)
        request = ConnectorExecutionRequest(tool="gmail.get_thread", arguments={"thread_id": binding.thread_ref, "max_messages": 10},
            scope=self.host.scope, connector_account_ref=binding.connector_account_ref)
        fence()
        result = self.host.executor.execute(request)
        now = self.host._now(now)
        scoped_receipt(result, request)
        observation = sales_thread_observation(request, result, binding=binding,
            scope=self.host.scope.model_dump(mode="json"), now=now)
        require(observation.disposition == "reply", "SALES_UNAMBIGUOUS_REPLY_REQUIRED")
        anchored, inbound = False, []
        for row in result.output["messages"]:
            headers = {key.lower(): value for key, value in row["headers"].items()}
            if headers.get("messageid") == binding.parent_message_id:
                anchored = True
                continue
            if anchored and _addresses(headers.get("from")) == (binding.to_address.lower(),):
                inbound.append(row)
        require(bool(inbound), "SALES_REPLY_MISSING")
        message = inbound[-1]
        text = message.get("body")
        require(isinstance(text, str) and 0 < len(text) <= 20_000, "SALES_REPLY_TEXT_REQUIRED")
        identity = stable_digest({"binding": stable_digest(binding.to_dict()), "message_id": message["id"]})
        ref = self.ref(binding, "reply", identity)
        old = self.read(ref)
        # A provider message changing content is an integrity error, not a new review.
        content_digest = stable_digest({"message": message})
        if old:
            require(old["content_digest"] == content_digest, "SALES_REPLY_CONTENT_CHANGED")
            return old
        classified = ClassifyReplyPrimitive().execute(PrimitiveExecutionContext(scope=self.host.scope,
            connectors=self.host.executor), {"reply_text": text})
        require(classified.output is not None, "SALES_REPLY_CLASSIFICATION_FAILED")
        proposal = {"proposal_ref": ref, "binding_digest": stable_digest(binding.to_dict()), "message_identity": identity,
            "content_digest": content_digest, "observation": observation.to_dict(),
            "read_receipt": scoped_receipt(result, request).to_dict(),
            "classification": classified.output.model_dump(mode="json"), "review_required": True,
            "owner": "finance_agent" if binding.purpose == "billing_recovery" else "crm_agent"}
        proposal["proposal_digest"] = stable_digest(proposal)
        return self.write(ref, proposal, None, fence)

    def review_reply(self, binding_ref, review, *, now, fence):
        now = self.host._now(now)
        binding = self.binding(binding_ref)
        self.no_pending_delivery(binding)
        review = SalesReplyReview.model_validate(detached(review))
        proposal = self.read(review.proposal_ref)
        require(proposal is not None and proposal["binding_digest"] == stable_digest(binding.to_dict())
                and proposal["proposal_digest"] == review.proposal_digest, "SALES_REPLY_REVIEW_MISMATCH")
        require(parsed(proposal["observation"]["observed_at"]) <= parsed(now), "SALES_REVIEW_FROM_FUTURE")
        applied_ref = self.ref(binding, "pipeline_engine:" + ("suppress" if review.disposition == "unsubscribe" else "reply"),
                               proposal["message_identity"])
        if self.read(applied_ref) is None:
            current = self.propose_reply(binding_ref, now=now, fence=fence)
            require(current["proposal_ref"] == review.proposal_ref, "SALES_REPLY_REVIEW_SUPERSEDED")
            now = self.host._now(now)
        if review.disposition == "uncertain" or (binding.purpose == "billing_recovery" and review.disposition != "unsubscribe"):
            return {"status": "needs_review", "owner": proposal["owner"], "proposal_ref": review.proposal_ref}
        receipt = {"reply_ref": review.proposal_ref, "disposition": review.disposition,
                   "evidence_refs": [review.review_ref]}
        if review.disposition == "unsubscribe":
            from lightbulb.company_sales_host import CONTROL_SCHEMA
            control_ref = self.host._ref(binding)
            control = self.host._read(control_ref, CONTROL_SCHEMA)
            if control:
                self.host._write(control_ref, {**control, "stopped": True, "stop_reason": "SALES_REVIEWED_UNSUBSCRIBE"}, control, fence)
            # The permission register requires an actual normalized platform
            # consent observation. A whole-thread receipt is not that evidence.
            hold_ref = self.ref(binding, "permission_withdrawal", proposal["message_identity"])
            hold = self.read(hold_ref)
            if hold is None:
                self.write(hold_ref, {"proposal_ref": review.proposal_ref, "review_ref": review.review_ref,
                    "action": "withdraw_permission", "state": "normalized_platform_observation_required"}, None, fence)
            return self.apply(binding, identity=proposal["message_identity"], event="suppress", receipt={"evidence_refs": [review.review_ref]},
                reason="reviewed unsubscribe", now=now, fence=fence)
        return self.apply(binding, identity=proposal["message_identity"], event="reply", receipt=receipt, now=now, fence=fence)

    def withdraw_permission(self, binding_ref, proposal_ref, observation, *, now, fence):
        """Complete the register transition only from its canonical platform evidence."""
        from lightbulb.permission_register import withdrawal_receipt
        binding = self.binding(binding_ref)
        proposal = self.read(proposal_ref)
        require(proposal and proposal["binding_digest"] == stable_digest(binding.to_dict()), "SALES_REPLY_REVIEW_MISMATCH")
        hold_ref = self.ref(binding, "permission_withdrawal", proposal["message_identity"])
        hold = self.read(hold_ref)
        require(hold is not None, "SALES_UNSUBSCRIBE_REVIEW_REQUIRED")
        receipt = withdrawal_receipt(observation)
        facts = receipt["source"]["payload"]
        require(facts["company_ref"] == self.runner.bundle.company_ref and facts["endpoint_digest"] == binding.endpoint_digest
                and facts["key_ref"] == binding.endpoint_key_ref and facts["channel"] == "email", "SALES_WITHDRAWAL_ENDPOINT_MISMATCH")
        state = self.apply(binding, identity=proposal["message_identity"], event="withdraw", receipt=receipt,
            engine="contact_endpoint", entity=binding.permission_entity_ref, now=now, fence=fence)
        self.write(hold_ref, {**hold, "state": "withdrawn"}, hold, fence)
        return state

    def qualify(self, binding_ref, review, *, now, fence):
        binding = self.binding(binding_ref)
        require(binding.purpose != "billing_recovery", "SALES_BILLING_NOT_QUALIFICATION")
        self.no_pending_delivery(binding)
        review = SalesQualificationReview.model_validate(detached(review))
        state = self.host._state(binding)
        ref = self.ref(binding, "pipeline_engine:qualify", review.review_ref)
        retained = self.read(ref)
        expected = retained["command"]["expected_state_digest"] if retained else state.state_digest
        require(expected == review.expected_state_digest, "SALES_QUALIFICATION_STATE_CHANGED")
        require(all(type(score) is int and 0 <= score <= 100 for score in review.scores.values()), "SALES_RUBRIC_SCORE_INVALID")
        return self.apply(binding, identity=review.review_ref, event="qualify",
            receipt={"scores": review.scores, "evidence_refs": list(review.evidence_refs)}, now=now, fence=fence)

    def qualification_requirements(self, binding_ref, scores=None):
        """List missing rubric evidence for the CRM agent; never invent answers."""
        binding = self.binding(binding_ref)
        require(binding.purpose != "billing_recovery", "SALES_BILLING_NOT_QUALIFICATION")
        state = self.host._state(binding)
        rubric = self.runner.runtimes["pipeline_engine"].plan.blueprint.rubric
        supplied = scores or {}
        require(isinstance(supplied, dict) and set(supplied) <= {item.dimension for item in rubric}
                and all(type(value) is int and 0 <= value <= 100 for value in supplied.values()), "SALES_RUBRIC_SCORE_INVALID")
        return {"state_digest": state.state_digest, "missing_dimensions": [item.dimension for item in rubric if item.dimension not in supplied],
                "rubric": [item.to_dict() for item in rubric], "review_required": True, "owner": "crm_agent"}
