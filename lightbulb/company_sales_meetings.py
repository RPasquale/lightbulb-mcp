"""Host-calendar slot proposals and governed, agreement-bound sales bookings."""
from datetime import datetime, timedelta
from dataclasses import replace

from pydantic import Field

from lightbulb.company_engine_core import OpaqueRef, StrictModel, detached, parsed, stable_digest, timestamp
from lightbulb.company_sales_progression import require, scoped_receipt
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult
from lightbulb.executable_primitives import ScheduleMeetingPrimitive
from lightbulb.primitive_runtime import PrimitiveExecutionContext


class SalesMeetingRequest(StrictModel):
    request_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    title: str = Field(min_length=1, max_length=200)
    agenda: str = Field(default="", max_length=2000)
    candidate_starts: tuple[str, ...] = Field(min_length=1, max_length=10)
    duration_minutes: int = Field(default=30, ge=5, le=120)


class _Capture:
    def __init__(self, executor):
        self.executor = executor
        self.request = self.result = None

    def execute(self, request):
        self.request = request
        self.result = self.executor.execute(request)
        return self.result


def _provider_time(value):
    require(isinstance(value, str) and len(value) <= 80, "SALES_CALENDAR_TIME_INVALID")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.utcoffset() is not None, "SALES_CALENDAR_TIME_INVALID")
    return result


class CompanySalesMeetings:
    def __init__(self, progression):
        self.progression, self.host = progression, progression.host

    def status(self, binding_ref, proposal_ref=None):
        """Inspect retained booking work without provider reads or journal writes."""
        p, binding = self.progression, self.progression.binding(binding_ref)
        if proposal_ref is None:
            claim = p.read(p.ref(binding, "meeting_admission", "one"))
            if claim is None:
                return None
            proposal_ref = claim["proposal_ref"]
        proposal = p.read(proposal_ref)
        require(proposal and proposal.get("binding_digest") == stable_digest(binding.to_dict()),
                "SALES_MEETING_BINDING_MISMATCH")
        phase = proposal["phase"]
        pending = proposal.get("pending", {})
        if phase == "posting":
            action, owner, evidence = "reconcile_meeting", "calendar_runtime", ("original_hosted_execution_result",)
        elif phase == "awaiting_approval":
            if pending.get("status") == "pending_approval":
                action, owner, evidence = "review_meeting_approval", "human_reviewer", ("exact_calendar_approval",)
            else:
                action, owner, evidence = "review_meeting_hold", "operator", ("resolved_calendar_hold", "current_permission")
        elif phase == "booked":
            state = self.host._state(binding)
            recorded = state and state.ledger.meeting_ref == proposal["verified"]["event_ref"]
            action = "meeting_recorded" if recorded else "finalize_meeting_state"
            owner, evidence = "crm_agent", () if recorded else ("retained_verified_calendar_result",)
        else:
            require(phase == "proposed", "SALES_MEETING_PHASE_INVALID")
            action = "review_meeting_agreement" if proposal["slots"] else "propose_other_meeting_slots"
            owner, evidence = "crm_agent", ("customer_agreed_time",) if proposal["slots"] else ("new_candidate_times", "new_request_ref")
        return {"proposal_ref": proposal_ref, "phase": phase, "action": action, "owner": owner,
            "required_evidence": evidence, "automatic": False, "execution_authorized": False,
            "approval_ref": pending.get("approval_ref"), "approval_receipt_digest": pending.get("approval_receipt_digest"),
            "selected_start": proposal.get("booking", {}).get("start"),
            "event_ref": proposal.get("verified", {}).get("event_ref"),
            "evidence_digest": stable_digest({"authority": self.host.authority_scope,
                "proposal": proposal, "action": action})}

    def _available(self, binding, spec, starts, *, now, fence):
        starts = tuple(timestamp(start, field_name="candidate_start") for start in starts)
        require(len(set(starts)) == len(starts), "SALES_MEETING_DUPLICATE_SLOT")
        window = self.host.runner.runtimes["pipeline_engine"].plan.blueprint.meeting_window_days
        require(all(parsed(now) < parsed(start) <= parsed(now) + timedelta(days=window) for start in starts), "SALES_MEETING_WINDOW")
        end = (max(map(parsed, starts)) + timedelta(minutes=spec.duration_minutes)).isoformat().replace("+00:00", "Z")
        request = ConnectorExecutionRequest(tool="calendar.get_availability", scope=self.host.scope,
            connector_account_ref=spec.connector_account_ref,
            arguments={"calendar_id": "primary", "time_min": min(starts, key=parsed), "time_max": end})
        fence()
        result = self.host.executor.execute(request)
        now = self.host._now(now)
        receipt = scoped_receipt(result, request)
        require(0 <= (parsed(now) - parsed(receipt.completed_at)).total_seconds() <= 60, "SALES_CALENDAR_STALE")
        output = result.output
        require(output.get("calendar_id") == "primary" and output.get("time_min") == request.arguments["time_min"]
                and output.get("time_max") == end, "SALES_CALENDAR_SCOPE_MISMATCH")
        availability = output.get("availability", {})
        require(isinstance(availability, dict) and not availability.get("errors")
                and isinstance(availability.get("busy"), list) and len(availability["busy"]) <= 1000,
                "SALES_CALENDAR_INCOMPLETE")
        intervals = []
        for busy in availability["busy"]:
            require(isinstance(busy, dict) and set(busy) == {"start", "end"}, "SALES_CALENDAR_INTERVAL_INVALID")
            start, stop = _provider_time(busy["start"]), _provider_time(busy["end"])
            require(start < stop, "SALES_CALENDAR_INTERVAL_INVALID")
            intervals.append((start, stop))
        available = [start for start in starts if not any(parsed(start) < stop
            and parsed(start) + timedelta(minutes=spec.duration_minutes) > begin for begin, stop in intervals)]
        return available, receipt

    def propose(self, binding_ref, request, *, now, fence):
        p = self.progression
        binding, spec = p.binding(binding_ref), SalesMeetingRequest.model_validate(detached(request))
        p.no_pending_delivery(binding)
        require(binding.purpose != "billing_recovery" and self.host._state(binding).status == "qualified", "SALES_QUALIFIED_PROSPECT_REQUIRED")
        ref = p.ref(binding, "meeting", spec.request_ref)
        old = p.read(ref)
        if old:
            require(old["request"] == spec.to_dict(), "SALES_MEETING_REQUEST_CHANGED")
            return old
        slots, receipt = self._available(binding, spec, spec.candidate_starts, now=now, fence=fence)
        proposal = {"proposal_ref": ref, "binding_digest": stable_digest(binding.to_dict()), "request": spec.to_dict(),
            "state_digest": self.host._state(binding).state_digest, "slots": slots,
            "availability_receipt": receipt.to_dict(), "attendee_availability_verified": False,
            "customer_agreement_required": True, "phase": "proposed"}
        proposal["proposal_digest"] = stable_digest(proposal)
        return p.write(ref, proposal, None, fence)

    def book(self, binding_ref, proposal_ref, *, start, agreement_ref, approval_ref=None, now, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        p.no_pending_delivery(binding)
        proposal = p.read(proposal_ref)
        require(proposal and proposal.get("binding_digest") == stable_digest(binding.to_dict()), "SALES_MEETING_BINDING_MISMATCH")
        start = timestamp(start, field_name="start")
        # Agreement is explicit reviewed customer evidence, never inferred from an open slot.
        require(isinstance(agreement_ref, str) and 0 < len(agreement_ref) <= 200 and start in proposal["slots"], "SALES_MEETING_AGREEMENT_REQUIRED")
        intent = {"start": start, "agreement_ref": agreement_ref}
        require("booking" not in proposal or proposal["booking"] == intent, "SALES_MEETING_AGREEMENT_CHANGED")
        if proposal["phase"] == "booked":
            return self._apply(binding, proposal, now=now, fence=fence)
        require(proposal["phase"] != "posting", "SALES_MEETING_RECONCILIATION_REQUIRED")
        require(self.host._state(binding).state_digest == proposal["state_digest"], "SALES_MEETING_STATE_CHANGED")
        claim_ref = p.ref(binding, "meeting_admission", "one")
        claim = p.read(claim_ref)
        require(claim is None or claim["proposal_ref"] == proposal_ref, "SALES_MEETING_ALREADY_RESERVED")
        if claim is None:
            p.write(claim_ref, {"proposal_ref": proposal_ref}, None, fence)
        self.host.intake._permission(binding, now=now)
        spec = SalesMeetingRequest.model_validate(proposal["request"])
        slots, _ = self._available(binding, spec, [start], now=now, fence=fence)
        require(start in slots, "SALES_MEETING_SLOT_NO_LONGER_AVAILABLE")
        require(parsed(start) > parsed(self.host._now(now)), "SALES_MEETING_SLOT_EXPIRED")
        capture = _Capture(self.host.executor)
        context = PrimitiveExecutionContext(scope=self.host.scope, connectors=capture, preview_only=False,
            idempotency_key=proposal_ref, approval_refs={"calendar.schedule_meeting": approval_ref} if approval_ref else {},
            connector_account_refs={"calendar": spec.connector_account_ref, "calendar.create_event": spec.connector_account_ref})
        # Retain the exact request before even attempting network IO.
        class JournalledCapture:
            def execute(self, request):
                nonlocal proposal
                dispatch_now = p.host._now(now)
                p.host.intake._permission(binding, now=dispatch_now)
                require(parsed(start) > parsed(dispatch_now), "SALES_MEETING_SLOT_EXPIRED")
                proposal = p.write(proposal_ref, {**proposal, "phase": "posting", "booking": intent,
                    "connector_request": request.model_dump(mode="json")}, proposal, fence)
                return capture.execute(request)
        context = replace(context, connectors=JournalledCapture())
        try:
            ScheduleMeetingPrimitive().execute(context, {"attendees": [binding.to_address], "title": spec.title,
                "agenda": spec.agenda, "start_time": start, "duration_minutes": spec.duration_minutes, "create_invite": True})
        except Exception:
            if capture.request is None:
                raise
            return {"status": "reconciliation_required", "proposal_ref": proposal_ref}
        require(capture.request is not None, "SALES_MEETING_REQUEST_NOT_EXECUTED")
        result = capture.result
        if result is None or result.status.value == "failed":
            return {"status": "reconciliation_required", "proposal_ref": proposal_ref}
        if result.status.value != "completed":
            pending = {"status": result.status.value, "proposal_ref": proposal_ref,
                       "approval_ref": result.approval_ref, "approval_receipt_digest": result.approval_receipt_digest}
            p.write(proposal_ref, {**proposal, "phase": "awaiting_approval", "pending": pending}, proposal, fence)
            return pending
        return self.reconcile(binding_ref, proposal_ref, result, now=now, fence=fence)

    def reconcile(self, binding_ref, proposal_ref, result, *, now, fence):
        p, binding = self.progression, self.progression.binding(binding_ref)
        proposal = p.read(proposal_ref)
        require(proposal and proposal.get("binding_digest") == stable_digest(binding.to_dict())
                and "connector_request" in proposal, "SALES_MEETING_BINDING_MISMATCH")
        request = ConnectorExecutionRequest.model_validate(proposal["connector_request"])
        result = ConnectorExecutionResult.model_validate(detached(result))
        receipt = scoped_receipt(result, request)
        now = self.host._now(now)
        require(parsed(receipt.completed_at) <= parsed(now), "SALES_MEETING_RESULT_FROM_FUTURE")
        output = result.output
        spec = SalesMeetingRequest.model_validate(proposal["request"])
        start = proposal["booking"]["start"]
        require(output.get("status") == "confirmed" and isinstance(output.get("id"), str)
                and 0 < len(output["id"]) <= 200, "SALES_MEETING_EVENT_UNCONFIRMED")
        require(_provider_time(output.get("start", {}).get("dateTime")) == parsed(start)
                and _provider_time(output.get("end", {}).get("dateTime")) == parsed(start) + timedelta(minutes=spec.duration_minutes)
                and output.get("summary") == spec.title, "SALES_MEETING_EVENT_MISMATCH")
        attendees = output.get("attendees", [])
        require(isinstance(attendees, list) and len(attendees) == 1
                and attendees[0].get("email", "").lower() == binding.to_address.lower(), "SALES_MEETING_ATTENDEE_MISMATCH")
        verified = {"event_ref": output["id"], "receipt": receipt.to_dict()}
        require("verified" not in proposal or proposal["verified"] == verified, "SALES_MEETING_RECEIPT_CHANGED")
        proposal = p.write(proposal_ref, {**proposal, "phase": "booked", "verified": verified}, proposal, fence)
        return self._apply(binding, proposal, now=now, fence=fence)

    def _apply(self, binding, proposal, *, now, fence):
        verified = proposal["verified"]
        return self.progression.apply(binding, identity=proposal["proposal_ref"], event="book_meeting",
            receipt={"meeting_ref": verified["event_ref"], "meeting_at": proposal["booking"]["start"],
                "evidence_refs": [verified["receipt"]["journal_ref"], proposal["booking"]["agreement_ref"]]},
            now=verified["receipt"]["completed_at"], fence=fence)
