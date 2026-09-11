"""Retained CRM-agent preparation with capability-gap handoffs."""
from lightbulb.company_engine_core import stable_digest
from lightbulb.company_sales_progression import require, scoped_receipt
from lightbulb.company_sales_observations import sales_thread_observation, _addresses
from lightbulb.connector_execution import ConnectorExecutionRequest
from lightbulb.sdk_capability_gap import SalesAgentDecision, SalesAgentPreparationRequest, SalesAgentScope, sdk_gap_project_package


class CompanySalesPreparation:
    def __init__(self, progression):
        self.progression, self.host = progression, progression.host

    def _conversation(self, binding, *, now, fence):
        request = ConnectorExecutionRequest(tool="gmail.get_thread", scope=self.host.scope,
            connector_account_ref=binding.connector_account_ref,
            arguments={"thread_id": binding.thread_ref, "max_messages": 10})
        fence()
        result = self.host.executor.execute(request)
        scoped_receipt(result, request)
        observation = sales_thread_observation(request, result, binding=binding,
            scope=self.host.scope.model_dump(mode="json"), now=self.host._now(now))
        require(observation.disposition in {"reply", "no_reply"}, "SDK_SALES_CONVERSATION_HELD")
        text, anchored = "", False
        for row in result.output["messages"]:
            headers = {key.lower(): value for key, value in row["headers"].items()}
            if headers.get("messageid") == binding.parent_message_id:
                anchored = True
            elif anchored and _addresses(headers.get("from")) == (binding.to_address.lower(),):
                text = row.get("body")
                require(isinstance(text, str) and 0 < len(text) <= 20000, "SDK_SALES_REPLY_TEXT_REQUIRED")
        require(observation.disposition != "reply" or bool(text), "SDK_SALES_REPLY_TEXT_REQUIRED")
        return text, stable_digest({"binding": binding.to_dict(), "messages": result.output["messages"]})

    def run(self, binding_ref, brief_ref, *, request_ref, client, now, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        p.no_pending_delivery(binding)
        ref = p.ref(binding, "agent_preparation", request_ref)
        old = p.read(ref)
        if old:
            require(old["brief_ref"] == brief_ref and old["binding_digest"] == stable_digest(binding.to_dict()), "SDK_SALES_REQUEST_CHANGED")
            require(old["phase"] == "complete", "SDK_SALES_AGENT_RECONCILIATION_REQUIRED")
            if old.get("decision", {}).get("gap") and getattr(self.host, "capability_waits", None):
                self.host.capability_waits.development.discover_sales(binding_ref, request_ref, now=now, fence=fence)
            return old
        context = p.research.drafting_context(binding_ref, brief_ref, now=now)
        brief = p.read(brief_ref)
        p.research._workspace(client, brief["request"]["workspace_id"])
        text, conversation_digest = self._conversation(binding, now=now, fence=fence)
        request = SalesAgentPreparationRequest(request_ref=request_ref,
            scope=SalesAgentScope(**{key: self.host.authority_scope[key] for key in
                ("tenant_id", "company_id", "user_id", "project_id")}), research_context=context, reply_text=text)
        # Freeze a single dispatch before invoking the agent. Raw customer text
        # stays ephemeral; only its commitment is retained in this journal.
        old = p.write(ref, {"phase": "dispatching", "brief_ref": brief_ref, "request_ref": request_ref,
            "context_digest": context["context_digest"], "conversation_digest": conversation_digest,
            "binding_digest": stable_digest(binding.to_dict())}, None, fence)
        result = client.dispatch("crm", action="outbound_messaging", company_id=str(request.scope.company_id),
            project_id=str(request.scope.project_id), inputs={"sdk_sales_preparation": request.to_dict()})
        p.research._workspace(client, brief["request"]["workspace_id"])
        output = result.outputs
        require(output.get("scope") == request.scope.to_dict() and output.get("request_ref") == request_ref
                and output.get("context_digest") == context["context_digest"], "SDK_SALES_AGENT_RESPONSE_MISMATCH")
        decision = SalesAgentDecision.model_validate(output["decision"])
        _, current = self._conversation(binding, now=now, fence=fence)
        require(current == conversation_digest, "SDK_SALES_REPLY_CHANGED")
        require(p.research.drafting_context(binding_ref, brief_ref, now=self.host._now(now))["context_digest"]
                == context["context_digest"], "SDK_SALES_CONTEXT_CHANGED")
        prepared = None
        if decision.preparation:
            require(decision.preparation.preparation_ref == request_ref, "SDK_SALES_REQUEST_CHANGED")
            prepared = p.research.prepare(binding_ref, brief_ref, decision.preparation, now=self.host._now(now), fence=fence)
        if decision.gap and getattr(self.host, "capability_waits", None):
            self.host.capability_waits.development.discover_sales(binding_ref, request_ref, now=now, fence=fence)
        return p.write(ref, {**old, "phase": "complete", "decision": decision.to_dict(),
            "prepared": prepared, "agent_trace_id": result.trace_id,
            "review_required": True, "execution_authorized": False}, old, fence)

    def propose_gap(self, binding_ref, preparation_ref, *, implementation_budget_usd, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        preparation = p.read(p.ref(binding, "agent_preparation", preparation_ref))
        require(preparation and preparation.get("binding_digest") == stable_digest(binding.to_dict())
                and preparation["phase"] == "complete", "SDK_GAP_PREPARATION_REQUIRED")
        decision = SalesAgentDecision.model_validate(preparation["decision"])
        require(decision.gap is not None, "SDK_GAP_NOT_OBSERVED")
        package = sdk_gap_project_package(decision.gap, scope=self.host.scope,
            source_context_digest=preparation["context_digest"], implementation_budget_usd=implementation_budget_usd)
        ref = p.ref(binding, "capability_gap", preparation_ref)
        old = p.read(ref)
        if old:
            require(old["package"] == package, "SDK_GAP_REQUEST_CHANGED")
            return old
        return p.write(ref, {"gap_ref": ref, "phase": "proposed", "package": package,
            "preparation_ref": preparation_ref, "binding_digest": stable_digest(binding.to_dict())}, None, fence)

    def submit_gap(self, binding_ref, gap_ref, *, client, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        gap = p.read(gap_ref)
        require(gap and gap.get("binding_digest") == stable_digest(binding.to_dict()), "SDK_GAP_SCOPE_MISMATCH")
        if gap["phase"] == "submitted":
            return gap
        require(gap["phase"] == "proposed", "SDK_GAP_SUBMISSION_RECONCILIATION_REQUIRED")
        scope = SalesAgentScope(**{key: self.host.authority_scope[key] for key in
            ("tenant_id", "company_id", "user_id", "project_id")})
        preparation = p.read(p.ref(binding, "agent_preparation", gap["preparation_ref"]))
        brief = p.read(preparation["brief_ref"])
        p.research._workspace(client, brief["request"]["workspace_id"])
        gap = p.write(gap_ref, {**gap, "phase": "submitting"}, gap, fence)
        result = client.dispatch("crm", action="outbound_messaging", company_id=str(scope.company_id),
            project_id=str(scope.project_id), inputs={"sdk_capability_handoff": {"scope": scope.to_dict(), "package": gap["package"]}})
        p.research._workspace(client, brief["request"]["workspace_id"])
        output = result.outputs
        require(output.get("scope") == scope.to_dict() and output.get("package_digest") == gap["package"]["package_digest"]
                and str(output.get("handoff", {}).get("projectId")) == str(scope.project_id), "SDK_GAP_RESPONSE_MISMATCH")
        return p.write(gap_ref, {**gap, "phase": "submitted", "handoff": output["handoff"],
            "implementation_started": False, "coding_handoff_authorized": False,
            "approval_required": True, "next_step": "user_review_and_coding_handoff_approval"}, gap, fence)

    def resume_gap(self, binding_ref, gap_ref, *, task_id, connection_id, brief_ref, client, now, fence):
        """Re-enter preparation after exact dependency availability; existing dispatch and effect gates still apply.

        The host supplies its configured runtime connection, never a model-selected environment.
        A fresh research brief is allowed; the original gap remains bound to its original context.
        """
        from uuid import UUID
        from datetime import datetime, timezone
        from lightbulb.native_coding import NativeDeliveryStatus
        p, binding = self.progression, self.progression.binding(binding_ref)
        gap = p.read(gap_ref)
        require(gap and gap.get("phase") == "submitted" and gap.get("binding_digest") == stable_digest(binding.to_dict()),
                "SDK_GAP_SUBMITTED_SCOPE_REQUIRED")
        packet = gap["package"]["work_packets"][0]
        channel = client.native_coding(self.host.authority_scope["project_id"])
        fence()
        status = NativeDeliveryStatus.model_validate(channel.delivery(task_id, packet["packet_digest"]))
        require(str(status.project_id) == self.host.authority_scope["project_id"] and status.task_id == UUID(str(task_id))
                and status.connection_id == UUID(str(connection_id)), "SDK_GAP_RUNTIME_SCOPE_MISMATCH")
        require(status.available and status.stage == "installed" and status.evidence_digest
                and status.gap_packet_digest == packet["packet_digest"]
                and status.source_context_digest == packet["source_context_digest"]
                and status.capability_ref == packet["capability_gap"]["capability_ref"], "SDK_GAP_DELIVERY_NOT_AVAILABLE")
        require(status.expires_at and datetime.fromisoformat(status.expires_at.replace("Z", "+00:00")) > datetime.now(timezone.utc),
                "SDK_GAP_INSTALLATION_EVIDENCE_EXPIRED")
        # One retained request identity per blocked gap and native task. run() freezes
        # dispatch before I/O and holds uncertain dispatches for reconciliation.
        request_ref = "resume-" + stable_digest({"gap_ref": gap_ref, "task_id": str(task_id)})
        prepared = self.run(binding_ref, brief_ref, request_ref=request_ref, client=client, now=now, fence=fence)
        return {"task_id": str(task_id), "gap_ref": gap_ref, "evidence_digest": status.evidence_digest,
                "phase": "prepared_for_review" if prepared.get("prepared") else "capability_still_missing", "preparation": prepared,
                "review_required": True, "execution_authorized": False}
