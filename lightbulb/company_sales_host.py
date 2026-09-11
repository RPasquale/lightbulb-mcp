"""Durable follow-up over real prospect, permission and communication records.

Spring owns approval, exact CRM identity, atomic admission and delivery. This
host freezes each proposal before requesting it and applies only verified
communication effects. Gmail reads are fresh and retained only as commitments.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from lightbulb.company_engine_core import detached, parsed, stable_digest, timestamp
from lightbulb.company_engine_store import EngineStateConflictError
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway, HostAuthorityError
from lightbulb.company_sales_configuration import validate_sales_configuration
from lightbulb.company_sales_intake import CompanySalesIntake
from lightbulb.company_sales_observations import sales_thread_observation
from lightbulb.company_sales_workflow import sales_workflow_handoff
from lightbulb.connector_execution import ConnectorExecutionRequest, ExecutionScope
from lightbulb.permission_register import verify_eligibility
from lightbulb.pipeline_execution import TouchRequest, plan_next_touch


CONTROL_SCHEMA = "lightbulb.company_sales_followup.v1"
TOUCH_SCHEMA = "lightbulb.company_sales_touch.v1"
MAX_DOCUMENT_BYTES = 512 * 1024
# Completion repeats at most the original touch's receipt fields. Its command
# envelope, bounded typed effect and status metadata fit within this allowance.
COMPLETION_METADATA_BYTES = 16 * 1024


class SalesHostError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise SalesHostError(code)


def _code(error):
    code = getattr(error, "code", "SALES_VALIDATION_FAILED")
    return code if isinstance(code, str) and code.isupper() and code.replace("_", "").isalnum() and len(code) <= 100 else "SALES_VALIDATION_FAILED"


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class CompanySalesHost:
    @property
    def progression(self):
        from lightbulb.company_sales_progression import CompanySalesProgression
        return CompanySalesProgression(self)

    def __init__(self, runner, gateway, executor, communication, configuration, sources=(), *, clock=_utc_now):
        _require(isinstance(gateway, AuthenticatedCheckpointGateway), "AUTHENTICATED_HOST_JOURNAL_REQUIRED")
        _require(gateway.bundle_digest == runner.bundle.plan_digest, "SALES_JOURNAL_BUNDLE_MISMATCH")
        self.runner, self.gateway = runner, gateway
        self.executor, self.communication = executor, communication
        self.clock = clock
        from lightbulb.company_customer_lifecycle import CompanyCustomerLifecycle
        self.sources = tuple(sources)
        self.configuration = validate_sales_configuration(configuration, bundle=runner.bundle, sources=self.sources)
        self.intake = CompanySalesIntake(runner, gateway, self.configuration.playbooks)
        self.customer_lifecycle = CompanyCustomerLifecycle(self)
        from lightbulb.company_customer_actions import CompanyCustomerActions
        self.customer_actions = CompanyCustomerActions(self)
        self.scope = ExecutionScope(**runner.bundle.scope, actor_ref=runner.bundle.actor_ref)
        self.authority_scope = {**gateway.authority_scope.model_dump(mode="json"),
                                "project_id": runner.bundle.scope["project_id"]}
        self.billing = {}
        if self.configuration.billing_policies:
            from lightbulb.billing_followup import CompanyBillingFollowupCoordinator
            from lightbulb.company_billing_recovery import CompanyBillingRecovery
            source_map = {source.source_ref: source for source in self.sources}
            for policy in self.configuration.billing_policies:
                recovery = CompanyBillingRecovery(runner, gateway, source_map[policy.source_ref])
                self.billing[policy.policy_ref] = CompanyBillingFollowupCoordinator(recovery, policy)

    def _now(self, started):
        return max((timestamp(started, field_name="now"), timestamp(self.clock(), field_name="clock")), key=parsed)

    def _ref(self, binding):
        # Renaming a configuration row cannot reset a recipient's stopped run.
        return "company-sales-" + stable_digest({"bundle": self.runner.bundle.plan_digest,
            "scope": self.runner.bundle.scope, "prospect_ref": binding.prospect_ref})

    def _read(self, ref, schema):
        record = self.gateway.get(ref)
        if record is not None:
            _require(record.get("schema") == schema and record.get("bundle_digest") == self.runner.bundle.plan_digest
                     and record.get("scope") == self.runner.bundle.scope, "SALES_JOURNAL_SCOPE_MISMATCH")
        return record

    def _write(self, ref, document, prior, fence):
        document = {**document, "bundle_digest": self.runner.bundle.plan_digest,
                    "scope": detached(self.runner.bundle.scope), "resume_at": None}
        _require(len(json.dumps(detached(document), ensure_ascii=True).encode("utf-8")) + 4096 <= MAX_DOCUMENT_BYTES,
                 "SALES_JOURNAL_TOO_LARGE")
        fence()
        return self.gateway.put(ref, document, expected_revision=prior["revision"] if prior else 0)

    def _completion_capacity(self, document):
        retained = {**document, "bundle_digest": self.runner.bundle.plan_digest,
                    "scope": detached(self.runner.bundle.scope), "resume_at": None}
        size = lambda value: len(json.dumps(detached(value), ensure_ascii=True).encode("utf-8"))
        _require(size(retained) + size(document["touch"]) + COMPLETION_METADATA_BYTES + 4096 <= MAX_DOCUMENT_BYTES,
                 "SALES_COMPLETION_CAPACITY_REQUIRED")

    def _state(self, binding):
        state = self.intake._scoped_state(self.runner.runtimes["pipeline_engine"], binding.prospect_ref)
        _require(state.ledger.account_ref == binding.account_ref
                 and state.ledger.sequence_plan == binding.sequence.to_dict(), "SALES_PROSPECT_BINDING_MISMATCH")
        return state

    def _inventory(self):
        runtime = self.runner.runtimes["pipeline_engine"]
        rows = self.runner.store.list_all(engine="pipeline_engine")
        result = []
        for row in rows:
            # Refuse mixed retained plans rather than relabel their provenance.
            _require(row["plan_digest"] == runtime.plan.plan_digest, "SALES_INVENTORY_PLAN_MISMATCH")
            state = runtime.spec.State.model_validate(row["state"], context={runtime.spec.plan_context_key: runtime.plan})
            _require(state.scope.to_dict() == self.runner.bundle.engine_scope(row["entity_ref"]), "SALES_INVENTORY_SCOPE_MISMATCH")
            result.append({"source_plan": runtime.plan.to_dict(), "state": state.to_dict()})
        return result

    def _observe(self, binding, *, now, fence):
        request = ConnectorExecutionRequest(tool="gmail.get_thread", effect="read", scope=self.scope,
            connector_account_ref=binding.connector_account_ref,
            arguments={"thread_id": binding.thread_ref, "max_messages": 10})
        fence()
        result = self.executor.execute(request)
        return sales_thread_observation(request, result, binding=binding,
                                       scope=self.scope.model_dump(mode="json"), now=self._now(now))

    def _guard(self, binding, state, touch_record, *, now, fence):
        if self.customer_lifecycle:
            self.customer_lifecycle.guard(binding, now=now, fence=fence)
        _require(state.status in {"sequenced", "engaged"}, "SALES_PROSPECT_NOT_CONTACTABLE")
        _, permission = self.intake._permission(binding, now=now)
        if touch_record:
            touch = TouchRequest.model_validate(touch_record["touch"])
            _require(state.state_digest == touch_record["source_state"]["state_digest"], "SALES_PROPOSAL_STATE_CHANGED")
            verify_eligibility(touch.eligibility_receipt, suppression_digest=touch.suppression_digest,
                channel="email", at=now, endpoints=[binding.endpoint_digest],
                company_ref=self.runner.bundle.company_ref, expected_scope=state.scope)
        billing_decision = None
        if binding.billing_guard:
            guard = binding.billing_guard
            coordinator = self.billing[guard.policy_ref]
            if touch_record:
                billing_decision = coordinator.validate_current(touch_record["billing_decision"], now=now)
            else:
                billing_decision = coordinator.evaluate(guard.invoice_ref, now=now, fence=fence)
                _require(billing_decision.disposition == "eligible", "SALES_BILLING_" + billing_decision.disposition.upper())
            _require(billing_decision.account_ref == binding.account_ref, "SALES_BILLING_ACCOUNT_MISMATCH")
        observation = self._observe(binding, now=now, fence=fence)
        self.customer_actions.observe(binding, observation, fence=fence)
        if observation.disposition != "no_reply":
            if binding.billing_guard and observation.disposition == "reply":
                self.billing[binding.billing_guard.policy_ref].record_reply(binding.billing_guard.invoice_ref,
                    evidence_ref=observation.execution_digest, now=now, fence=fence)
        return permission, observation, billing_decision

    def _prepare(self, binding, book, state, permission, observation, billing_decision, *, now, fence):
        message = book.message_for(state.ledger.next_step)
        touch = plan_next_touch(book.pipeline_plan, state, binding.sequence, now=now,
            to_address=binding.to_address, subject=message.subject, body=message.body,
            claim_refs=message.claim_refs, thread_ref=binding.thread_ref, eligibility_receipt=permission,
            suppression_digest=permission.suppression_digest, endpoint_digest=binding.endpoint_digest,
            channel_sources=self._inventory())
        ref = self._ref(binding) + "-" + str(touch.step)
        prior = self._read(ref, TOUCH_SCHEMA)
        if prior is not None:
            _require(prior["binding"] == binding.to_dict() and prior["playbook_digest"] == book.playbook_digest,
                     "SALES_PROPOSAL_CHANGED")
            return ref, prior
        document = {"schema": TOUCH_SCHEMA, "status": "RUNNING", "phase": "prepared",
            "binding": binding.to_dict(), "playbook_digest": book.playbook_digest,
            "touch": touch.to_dict(), "source_state": state.to_dict(), "prepared_at": now,
            "observation": observation.to_dict(), "billing_decision": billing_decision.to_dict() if billing_decision else None}
        self._completion_capacity(document)
        return ref, self._write(ref, document, None, fence)

    def _apply(self, binding, ref, record, result, *, now, fence):
        from lightbulb.company_sales_communication import sales_touch_receipt
        runtime = self.runner.runtimes["pipeline_engine"]
        if record.get("command") is None:
            touch = TouchRequest.model_validate(record["touch"])
            receipt = sales_touch_receipt(touch, result, binding=binding, scope=self.authority_scope)
            # Only closed, validated execution fields belong in the durable
            # result. Unrelated response extensions cannot exhaust its reserve.
            from lightbulb.company_sales_communication import SalesTouchEffect
            effect = SalesTouchEffect.model_validate(result["effect"]).to_dict()
            result = {"schema": "lightbulb.communication_sales_touch_result.v1", "status": "sent",
                      **{key: effect[key] for key in ("source_ref", "run_ref", "completed_at", "touch_request_digest")},
                      "effect": effect}
            _require(parsed(result["completed_at"]) <= parsed(now), "SALES_EFFECT_FROM_FUTURE")
            original = runtime.spec.State.model_validate(record["source_state"], context={runtime.spec.plan_context_key: runtime.plan})
            command = runtime.command(original, event="touch", transition_ref=ref, idempotency_key=touch.idempotency_key,
                occurred_at=result["completed_at"], actor_ref=self.runner.bundle.actor_ref, receipt=receipt)
            predicted = runtime.advance(runtime.plan, original, command)
            _require(predicted.candidate_validated, "SALES_EFFECT_TRANSITION_REFUSED")
            record = self._write(ref, {**record, "phase": "effect_observed", "command": command,
                "result_digest": predicted.state.state_digest, "effect": detached(result)}, record, fence)
        command = record["command"]
        state = self._state(binding)
        retained = [item for item in state.transition_history if item.command.idempotency_key == command["idempotency_key"]]
        if not retained:
            _require(state.state_digest == record["source_state"]["state_digest"], "SALES_EFFECT_RECONCILIATION_REQUIRED")
            fence()
            try:
                outcome = runtime.advance_and_persist(binding.prospect_ref, command)
                _require(outcome.persisted, "SALES_EFFECT_TRANSITION_REFUSED")
            except EngineStateConflictError:
                pass
            state = self._state(binding)
            retained = [item for item in state.transition_history if item.command.idempotency_key == command["idempotency_key"]]
        _require(len(retained) == 1 and detached(retained[0].command) == command,
                 "SALES_EFFECT_RECONCILIATION_REQUIRED")
        if record["phase"] != "applied":
            self._write(ref, {**record, "phase": "applied", "status": "COMPLETED", "applied_at": now}, record, fence)
        self.customer_actions.complete(binding, ref, fence=fence)
        return state

    def _binding_step(self, binding, *, now, fence):
        book = self.intake.playbooks[binding.playbook_ref]
        ref = self._ref(binding)
        control = self._read(ref, CONTROL_SCHEMA)
        if control is None:
            control = self._write(ref, {"schema": CONTROL_SCHEMA, "status": "RUNNING",
                "binding_digest": stable_digest(binding.to_dict()), "playbook_digest": book.playbook_digest,
                "active_ref": None, "stopped": False}, None, fence)
        _require(control["binding_digest"] == stable_digest(binding.to_dict())
                 and control["playbook_digest"] == book.playbook_digest, "SALES_BINDING_CHANGED")
        active_ref = control["active_ref"]
        record = self._read(active_ref, TOUCH_SCHEMA) if active_ref else None
        _require(active_ref is None or record is not None, "SALES_ACTIVE_PROPOSAL_MISSING")
        state = self._state(binding)
        if record and record.get("command"):
            state = self._apply(binding, active_ref, record, record["effect"], now=now, fence=fence)
            control = self._write(ref, {**control, "active_ref": None, "last_result": "sent"}, control, fence)
            return {"status": "sent", "prospect_ref": binding.prospect_ref}
        reason = control.get("stop_reason") if control["stopped"] else None
        observation = None
        if not reason:
            if state.ledger.next_step > len(binding.sequence.touches) and record is None:
                return {"status": "sequence_complete", "prospect_ref": binding.prospect_ref}
            try:
                permission, observation, billing_decision = self._guard(binding, state, record, now=now, fence=fence)
                if observation.disposition != "no_reply":
                    reason = "SALES_THREAD_" + observation.disposition.upper()
                    control = self._write(ref, {**control, "stopped": True, "stop_reason": reason,
                        "observation": observation.to_dict(), "stopped_at": now}, control, fence)
            except ValueError as error:
                if isinstance(error, HostAuthorityError):
                    raise
                reason = _code(error)
        now = self._now(now)
        if record is None and reason:
            return {"status": "stopped" if control["stopped"] else "blocked", "code": reason, "prospect_ref": binding.prospect_ref}
        if record is None:
            active_ref, record = self._prepare(binding, book, state, permission, observation, billing_decision, now=now, fence=fence)
            control = self._write(ref, {**control, "active_ref": active_ref}, control, fence)
        if reason is None:
            # A lost pointer acknowledgement can recover an older frozen
            # proposal. Check again after reads and durable writes, using the
            # host's current clock rather than the start of a long cycle.
            now = self._now(now)
            try:
                touch = TouchRequest.model_validate(record["touch"])
                self._completion_capacity(record)
                _require(self._state(binding).state_digest == record["source_state"]["state_digest"], "SALES_PROPOSAL_STATE_CHANGED")
                self.intake._permission(binding, now=now)
                _require(observation is not None and 0 <= (parsed(now) - parsed(observation.observed_at)).total_seconds() <= 60,
                         "SALES_THREAD_READ_STALE")
                verify_eligibility(touch.eligibility_receipt, suppression_digest=touch.suppression_digest,
                    channel="email", at=now, endpoints=[binding.endpoint_digest],
                    company_ref=self.runner.bundle.company_ref, expected_scope=state.scope)
                if binding.billing_guard:
                    self.billing[binding.billing_guard.policy_ref].validate_current(record["billing_decision"], now=now)
            except ValueError as error:
                if isinstance(error, HostAuthorityError):
                    raise
                reason = _code(error)
        if reason is None and self.customer_lifecycle:
            try:
                self.customer_lifecycle.guard(binding, now=self._now(now), fence=fence)
                self.customer_lifecycle.reserve_touch(binding, state, fence=fence)
                self.customer_actions.reserve(binding, active_ref, now=self._now(now), fence=fence)
                now = self._now(now)
                self.customer_lifecycle.guard(binding, now=now, fence=fence)
                self.intake._permission(binding, now=now)
                current_touch = TouchRequest.model_validate(record["touch"])
                verify_eligibility(current_touch.eligibility_receipt, suppression_digest=current_touch.suppression_digest,
                    channel="email", at=now, endpoints=[binding.endpoint_digest],
                    company_ref=self.runner.bundle.company_ref, expected_scope=state.scope)
            except ValueError as error:
                if isinstance(error,HostAuthorityError):raise
                reason=_code(error)
        fence()
        result = self.communication.step(binding, TouchRequest.model_validate(record["touch"]),
            state=record["source_state"], now=now, allow_dispatch=reason is None)
        status = result.get("status")
        _require(status in {"pending_approval", "admitted", "pending", "sent", "blocked", "stopped"}, "SALES_COMMUNICATION_STATUS_INVALID")
        if status == "sent":
            self._apply(binding, active_ref, record, result, now=self._now(now), fence=fence)
            control = self._write(ref, {**control, "active_ref": None, "last_result": "sent"}, control, fence)
        else:
            safe = {key: result[key] for key in ("status", "source_ref", "run_ref") if key in result}
            provider_reason = result.get("reason")
            if isinstance(provider_reason, str) and len(provider_reason) <= 100 and provider_reason.replace("_", "").isalnum():
                safe["reason"] = provider_reason
            if reason:
                safe["hold_code"] = reason
            if record.get("communication") != safe:
                self._write(active_ref, {**record, "communication": safe}, record, fence)
        return {"prospect_ref": binding.prospect_ref, "status": status, **({"code": reason} if reason else {})}

    def step(self, *, now, fence):
        now = timestamp(now, field_name="now")
        reports, admitted = [], {binding.binding_ref for binding in self.configuration.bindings}
        if self.customer_lifecycle:
            admitted -= self.customer_lifecycle.guarded_bindings()
            eligible, lifecycle_reports = self.customer_lifecycle.admit(now=now,fence=fence)
            admitted.update(eligible)
            reports.extend(lifecycle_reports)
        for candidate in self.configuration.intake_candidates:
            try:
                self.intake.ingest(candidate, now=now, fence=fence)
                admitted.add(candidate.binding.binding_ref)
            except ValueError as error:
                if isinstance(error, HostAuthorityError):
                    raise
                reports.append({"candidate_ref": candidate.candidate_ref, "status": "blocked", "code": _code(error)})
        for binding in self.customer_actions.ordered(self.configuration.all_bindings()):
            try:
                report = self.progression.conversations.advance_pending(binding, now=self._now(now), fence=fence)
                if report is None:
                    if binding.binding_ref not in admitted:
                        continue
                    report = self._binding_step(binding, now=self._now(now), fence=fence)
            except (ValueError, LookupError) as error:
                if isinstance(error, HostAuthorityError):
                    raise
                report = {"prospect_ref": binding.prospect_ref, "status": "blocked", "code": _code(error)}
            reports.append(report)
            ref = self._ref(binding)
            control = self._read(ref, CONTROL_SCHEMA)
            if control and control.get("last_report") != report:
                control = self._write(ref, {**control, "last_report": report}, control, fence)
            if (control and control.get("stop_reason") == "SALES_THREAD_REPLY"
                    and not control.get("active_ref") and not control.get("reply_review_ref")):
                try:
                    proposal = self.progression.propose_reply(binding.binding_ref, now=self._now(now), fence=fence)
                    self._write(ref, {**control, "reply_review_ref": proposal["proposal_ref"]}, control, fence)
                except ValueError as error:
                    if isinstance(error, HostAuthorityError):
                        raise
                    reports.append({"prospect_ref": binding.prospect_ref, "status": "blocked", "code": _code(error)})
        if self.customer_lifecycle:
            self.customer_lifecycle.observe(now=now,fence=fence)
        subscription_continuation = self.progression.subscriptions.tick(now=self._now(now), fence=fence)
        trial_conversion = self.progression.trials.tick(now=self._now(now), fence=fence)
        recurring_financials = self.progression.subscriptions.financials.tick(now=self._now(now), fence=fence)
        customer_referrals = self.progression.referrals.tick(now=self._now(now), fence=fence)
        customer_allocation = self.progression.allocation.tick(now=self._now(now), fence=fence)
        support_resolution = self.progression.support.tick(client=getattr(self.communication, "client", None), now=self._now(now), fence=fence)
        return {"subscription_continuation": subscription_continuation, "trial_conversion": trial_conversion, "recurring_financials": recurring_financials, "customer_referrals": customer_referrals, "customer_allocation": customer_allocation, "support_resolution": support_resolution, "reports": reports, "pending": sum(row["status"] in {"pending_approval", "admitted", "pending"} for row in reports),
                "sent": sum(row["status"] == "sent" for row in reports),
                "poll_again": subscription_continuation["poll_again"] or trial_conversion["poll_again"] or support_resolution["poll_again"] or recurring_financials["poll_again"] or customer_referrals["poll_again"] or customer_allocation["poll_again"] or any(row["status"] not in {"stopped", "sequence_complete"} for row in reports)}

    def report(self):
        rows = []
        for binding in self.configuration.all_bindings():
            control = self._read(self._ref(binding), CONTROL_SCHEMA)
            record = self._read(control["active_ref"], TOUCH_SCHEMA) if control and control.get("active_ref") else None
            raw = self.runner.store.get("pipeline_engine", binding.prospect_ref)
            state = self._state(binding) if raw else None
            communication = (record or {}).get("communication", {})
            row = {"binding_ref": binding.binding_ref, "purpose": binding.purpose,
                "status": "stopped" if control and control["stopped"] else (control or {}).get("last_report", {}).get("status", communication.get("status", "ready" if state else "not_intaken")),
                "review_reason": (control or {}).get("last_report", {}).get("code") or communication.get("hold_code") or communication.get("reason"),
                "stop_reason": (control or {}).get("stop_reason"), "prospect_status": state.status if state else None,
                "sent_touches": state.ledger.touches if state else 0, "recorded_replies": state.ledger.replies if state else 0,
                "meeting_recorded": bool(state and state.ledger.meeting_ref), "revenue_verified": False,
                "reply_review_ref": (control or {}).get("reply_review_ref")}
            row["workflow"] = sales_workflow_handoff(prospect_status=row["prospect_status"],
                status=row["status"], reason=row["review_reason"] or row["stop_reason"], purpose=binding.purpose,
                active_proposal=bool(control and control.get("active_ref")),
                sequence_complete=bool(state and state.ledger.next_step > len(binding.sequence.touches)))
            row["meeting_workflow"] = self.progression.meetings.status(binding.binding_ref)
            row["customer_conversation"] = self.progression.conversations.status(binding)
            if row["meeting_workflow"] and row["workflow"]["action"] == "arrange_meeting":
                row["workflow"] = dict(row["meeting_workflow"])
            row["workflow"]["evidence_digest"] = stable_digest({"scope": self.runner.bundle.scope,
                "authority_scope": self.authority_scope,
                "bundle_digest": self.runner.bundle.plan_digest, "binding_digest": stable_digest(binding.to_dict()),
                "state_digest": state.state_digest if state else None,
                "control_revision": (control or {}).get("revision"), "proposal_revision": (record or {}).get("revision"),
                "handoff": row["workflow"]})
            rows.append(row)
        return rows


__all__ = ["CompanySalesHost", "SalesHostError"]
