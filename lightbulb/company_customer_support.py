"""Conversation escalation through a real specialist and hosted service resolution."""

from datetime import timedelta
from typing import Literal

from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest
from lightbulb.company_sales_progression import require
from lightbulb.sdk_capability_gap import SalesAgentPreparationRequest, SalesAgentDecision
from lightbulb.golden_loop_projections import ServiceCaseResolutionStart, ServiceCaseResolutionRun


class CustomerSupportAssignment(StrictModel):
    case_ref: OpaqueRef
    binding_ref: OpaqueRef
    escalation_action_ref: OpaqueRef
    brief_ref: OpaqueRef
    specialist: Literal["crm"] = "crm"
    owner_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    ticket_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    requester_ref: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    identity_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=10)
    acknowledgment_minutes: int = Field(default=30, ge=1, le=1440)
    resolution_hours: int = Field(default=48, ge=1, le=720)
    review_ref: OpaqueRef


class CustomerSupportRequest(SalesAgentPreparationRequest):
    schema_version: Literal["lightbulb.customer_support_request.v1"] = (
        "lightbulb.customer_support_request.v1"
    )
    case_ref: OpaqueRef
    owner_ref: OpaqueRef


class CompanyCustomerSupport:
    """SDK coordinates; the domain agent diagnoses; Spring approves and verifies effects.

    CRM is the supported customer-facing specialist. Freshservice owns the actual
    ticket, confirmation and closure. An acknowledged agent dispatch is not a
    human acknowledgment or a verified resolution.
    """

    def __init__(self, progression):
        self.p, self.host = progression, progression.host

    @property
    def application_fixes(self):
        from lightbulb.company_application_fixes import CompanyApplicationFixes

        return CompanyApplicationFixes(self)

    def tick(self, *, client, now, fence):
        """Observe or dispatch one retained case per binding on the host lease."""
        reports = []
        for binding in self.host.configuration.all_bindings():
            pointer = self.p.read(self.p.ref(binding, "active_support", "one"))
            if not pointer:
                continue
            case_ref = pointer["case_ref"]
            if client is None:
                reports.append({"case_ref": case_ref, "phase": "client_required"})
                continue
            try:
                _, _, row = self._load(binding.binding_ref, case_ref)
                if row["phase"] == "assigned" and parsed(now) < parsed(
                    row["acknowledgment_deadline"]
                ):
                    self.dispatch(
                        binding.binding_ref, case_ref, client=client, now=now, fence=fence
                    )
                elif row["phase"] == "submitting_resolution":
                    self.submit_resolution(
                        binding.binding_ref,
                        case_ref,
                        row["candidate"],
                        client=client,
                        now=now,
                        fence=fence,
                    )
                reports.append(
                    self.observe(binding.binding_ref, case_ref, client=client, now=now, fence=fence)
                )
                if row.get("application_fix_refs"):
                    reports[-1]["application_fixes"] = self.application_fixes.tick(
                        binding.binding_ref, case_ref, client=client, now=now, fence=fence
                    )
            except ValueError as error:
                from lightbulb.company_host_journal import HostAuthorityError

                if isinstance(error, HostAuthorityError):
                    raise
                reports.append(
                    {
                        "case_ref": case_ref,
                        "phase": "review_required",
                        "reason": type(error).__name__,
                    }
                )
        return {
            "reports": reports,
            "poll_again": any(not r.get("terminal", False) for r in reports),
        }

    def _load(self, binding_ref, case_ref):
        binding = self.p.binding(binding_ref)
        ref = self.p.ref(binding, "customer_support", case_ref)
        row = self.p.read(ref)
        require(
            row and row["binding_digest"] == stable_digest(binding.to_dict()),
            "CUSTOMER_SUPPORT_SCOPE_MISMATCH",
        )
        return binding, ref, row

    def _client(self, row, client):
        brief = self.p.read(row["assignment"]["brief_ref"])
        require(brief is not None, "CUSTOMER_SUPPORT_BRIEF_REQUIRED")
        self.p.research._workspace(client, brief["request"]["workspace_id"])

    def assign(self, assignment, *, now, fence):
        spec = CustomerSupportAssignment.model_validate(assignment)
        binding = self.p.binding(spec.binding_ref)
        escalation = self.p.read(
            self.p.ref(binding, "conversation_action", spec.escalation_action_ref)
        )
        require(
            escalation
            and escalation.get("phase") == "escalated"
            and escalation.get("owner_ref") == spec.owner_ref
            and escalation.get("binding_digest") == stable_digest(binding.to_dict()),
            "CUSTOMER_SUPPORT_ESCALATION_REQUIRED",
        )
        self.p.research.drafting_context(spec.binding_ref, spec.brief_ref, now=now)
        identity_evidence = {
            evidence: self.p.read(evidence) for evidence in spec.identity_evidence_refs
        }
        require(
            all(
                value and value.get("binding_digest") == stable_digest(binding.to_dict())
                for value in identity_evidence.values()
            ),
            "CUSTOMER_SUPPORT_IDENTITY_EVIDENCE_REQUIRED",
        )
        ref = self.p.ref(binding, "customer_support", spec.case_ref)
        pointer_ref = self.p.ref(binding, "active_support", "one")
        pointer = self.p.read(pointer_ref)
        if pointer and pointer["case_ref"] != spec.case_ref:
            _, _, prior = self._load(binding.binding_ref, pointer["case_ref"])
            require(prior.get("terminal") is True, "CUSTOMER_SUPPORT_OWNER_BUSY")
        old = self.p.read(ref)
        if old:
            require(old["assignment"] == spec.to_dict(), "CUSTOMER_SUPPORT_ASSIGNMENT_CHANGED")
            return old
        current = parsed(now)
        # Register first so a lost checkpoint never leaves an undiscoverable case.
        self.p.write(
            pointer_ref,
            {"case_ref": spec.case_ref, "binding_digest": stable_digest(binding.to_dict())},
            pointer,
            fence,
        )
        return self.p.write(
            ref,
            {
                "assignment": spec.to_dict(),
                "binding_digest": stable_digest(binding.to_dict()),
                "phase": "assigned",
                "assigned_at": now,
                "escalation_digest": stable_digest(escalation),
                "identity_evidence_digest": stable_digest(identity_evidence),
                "acknowledgment_deadline": (
                    current + timedelta(minutes=spec.acknowledgment_minutes)
                )
                .isoformat()
                .replace("+00:00", "Z"),
                "resolution_deadline": (current + timedelta(hours=spec.resolution_hours))
                .isoformat()
                .replace("+00:00", "Z"),
                "execution_authorized": False,
            },
            None,
            fence,
        )

    def dispatch(self, binding_ref, case_ref, *, client, now, fence):
        binding, ref, row = self._load(binding_ref, case_ref)
        if row["phase"] == "acknowledged":
            return row
        require(row["phase"] == "assigned", "CUSTOMER_SUPPORT_DISPATCH_RECONCILIATION_REQUIRED")
        require(
            parsed(now) < parsed(row["acknowledgment_deadline"]),
            "CUSTOMER_SUPPORT_ACKNOWLEDGMENT_OVERDUE",
        )
        spec = row["assignment"]
        brief = self.p.read(spec["brief_ref"])
        self.p.research._workspace(client, brief["request"]["workspace_id"])
        context = self.p.research.drafting_context(binding_ref, spec["brief_ref"], now=now)
        text, thread = self.p.preparation._conversation(binding, now=now, fence=fence)
        request_ref = "support-" + stable_digest({"case": ref, "assignment": spec})
        request = CustomerSupportRequest(
            request_ref=request_ref,
            case_ref=case_ref,
            owner_ref=spec["owner_ref"],
            scope={
                k: self.host.authority_scope[k]
                for k in ("tenant_id", "company_id", "project_id", "user_id")
            },
            research_context=context,
            reply_text=text,
        )
        row = self.p.write(
            ref,
            {
                **row,
                "phase": "dispatching",
                "context_digest": context["context_digest"],
                "thread_digest": thread,
                "request_ref": request_ref,
            },
            row,
            fence,
        )
        fence()
        result = client.dispatch(
            "crm",
            action="outbound_messaging",
            company_id=str(request.scope.company_id),
            project_id=str(request.scope.project_id),
            inputs={"sdk_customer_support": request.to_dict()},
        )
        self.p.research._workspace(client, brief["request"]["workspace_id"])
        output = result.outputs
        require(
            output.get("scope") == request.scope.to_dict()
            and output.get("request_ref") == request_ref
            and output.get("case_ref") == case_ref
            and output.get("owner_ref") == spec["owner_ref"]
            and output.get("context_digest") == context["context_digest"],
            "CUSTOMER_SUPPORT_ACKNOWLEDGMENT_MISMATCH",
        )
        decision = SalesAgentDecision.model_validate(output["decision"])
        require(
            self.p.preparation._conversation(binding, now=now, fence=fence)[1] == thread,
            "CUSTOMER_SUPPORT_REPLY_CHANGED",
        )
        prepared = None
        if decision.preparation:
            require(
                decision.preparation.preparation_ref == request_ref,
                "CUSTOMER_SUPPORT_PREPARATION_CHANGED",
            )
            prepared = self.p.research.prepare(
                binding_ref, spec["brief_ref"], decision.preparation, now=now, fence=fence
            )
        # Retain canonical preparation so existing approved gap proposal/submission
        # and conversation preparation consume precisely the specialist's output.
        prep_ref = self.p.ref(binding, "agent_preparation", request_ref)
        self.p.write(
            prep_ref,
            {
                "phase": "complete",
                "request_ref": request_ref,
                "brief_ref": spec["brief_ref"],
                "binding_digest": stable_digest(binding.to_dict()),
                "context_digest": context["context_digest"],
                "conversation_digest": thread,
                "decision": decision.to_dict(),
                "prepared": prepared,
                "agent_trace_id": result.trace_id,
                "review_required": True,
                "execution_authorized": False,
            },
            None,
            fence,
        )
        return self.p.write(
            ref,
            {
                **row,
                "phase": "acknowledged",
                "acknowledged_at": now,
                "acknowledgment_kind": "domain_agent_response",
                "agent_trace_id": result.trace_id,
                "decision_digest": stable_digest(decision.to_dict()),
                "preparation_ref": prep_ref,
            },
            row,
            fence,
        )

    def propose_coding(self, binding_ref, case_ref, *, implementation_budget_usd, fence):
        _, _, row = self._load(binding_ref, case_ref)
        require(row["phase"] == "acknowledged", "CUSTOMER_SUPPORT_ACKNOWLEDGMENT_REQUIRED")
        return self.p.preparation.propose_gap(
            binding_ref,
            row["request_ref"],
            implementation_budget_usd=implementation_budget_usd,
            fence=fence,
        )

    def submit_coding(self, binding_ref, case_ref, *, implementation_budget_usd, client, fence):
        """Stage the exact Project proposal; the user approves the coding handoff in Spring."""
        proposal = self.propose_coding(
            binding_ref, case_ref, implementation_budget_usd=implementation_budget_usd, fence=fence
        )
        return self.p.preparation.submit_gap(
            binding_ref, proposal["gap_ref"], client=client, fence=fence
        )

    def submit_resolution(self, binding_ref, case_ref, candidate, *, client, now, fence):
        """Start/recover an exact Freshservice run; its existing two approvals remain mandatory."""
        binding, ref, row = self._load(binding_ref, case_ref)
        candidate = ServiceCaseResolutionStart.model_validate(candidate)
        self._client(row, client)
        require(
            stable_digest(
                {
                    evidence: self.p.read(evidence)
                    for evidence in row["assignment"]["identity_evidence_refs"]
                }
            )
            == row["identity_evidence_digest"],
            "CUSTOMER_SUPPORT_IDENTITY_EVIDENCE_CHANGED",
        )
        require(
            row["phase"]
            in {"acknowledged", "submitting_resolution", "resolution_running", "resolved"},
            "CUSTOMER_SUPPORT_ACKNOWLEDGMENT_REQUIRED",
        )
        prep = self.p.read(row["preparation_ref"])
        decision = SalesAgentDecision.model_validate(prep["decision"])
        require(
            decision.preparation
            and candidate.reply_body == decision.preparation.response_draft
            and candidate.resolution_sha256 == row["decision_digest"]
            and candidate.routing_sha256 == stable_digest(row["assignment"])
            and candidate.classification_sha256 == row["escalation_digest"],
            "CUSTOMER_SUPPORT_RESOLUTION_EVIDENCE_CHANGED",
        )
        require(candidate.candidate_ref == case_ref, "CUSTOMER_SUPPORT_CANDIDATE_CHANGED")
        require(
            all(
                getattr(candidate, k) == row["assignment"][k]
                for k in ("connector_account_ref", "ticket_ref", "requester_ref")
            ),
            "CUSTOMER_SUPPORT_DESTINATION_CHANGED",
        )
        if row.get("candidate_digest"):
            require(
                row["candidate_digest"] == stable_digest(candidate.to_dict()),
                "CUSTOMER_SUPPORT_CANDIDATE_CHANGED",
            )
        else:
            require(
                parsed(now) < parsed(row["resolution_deadline"]),
                "CUSTOMER_SUPPORT_RESOLUTION_OVERDUE",
            )
            require(
                self.p.preparation._conversation(binding, now=now, fence=fence)[1]
                == row["thread_digest"],
                "CUSTOMER_SUPPORT_REPLY_CHANGED",
            )
            require(
                self.p.research.drafting_context(
                    binding_ref, row["assignment"]["brief_ref"], now=now
                )["context_digest"]
                == row["context_digest"],
                "CUSTOMER_SUPPORT_CONTEXT_CHANGED",
            )
            row = self.p.write(
                ref,
                {
                    **row,
                    "phase": "submitting_resolution",
                    "candidate_digest": stable_digest(candidate.to_dict()),
                    "candidate_sha256": candidate.candidate_sha256,
                    "candidate": candidate.to_dict(),
                },
                row,
                fence,
            )
        scope = self.host.authority_scope
        # Spring owns durable idempotency of this exact start, including lost responses.
        fence()
        run = client.start_service_case_resolution(
            scope["project_id"], candidate, company_id=scope["company_id"]
        )
        return self._retain_run(ref, row, run, fence)

    def _retain_run(self, ref, row, run, fence):
        run = ServiceCaseResolutionRun.model_validate(run)
        scope = self.host.authority_scope
        require(
            all(
                getattr(run, k) == scope[k]
                for k in ("tenant_id", "company_id", "project_id", "user_id")
            )
            and run.candidate_ref == row["assignment"]["case_ref"]
            and run.candidate_sha256 == row["candidate_sha256"]
            and run.resolution_sha256 == row["decision_digest"],
            "CUSTOMER_SUPPORT_RUN_SCOPE_MISMATCH",
        )
        require(
            not row.get("run_ref") or row["run_ref"] == run.run_ref, "CUSTOMER_SUPPORT_RUN_CHANGED"
        )
        return self.p.write(
            ref,
            {
                **row,
                "phase": "resolved" if run.state == "CLOSED_VERIFIED" else "resolution_running",
                "run_ref": run.run_ref,
                "hosted_state": run.state,
                "terminal": run.terminal,
                "resolution_verified": run.state == "CLOSED_VERIFIED",
                "resolution_receipt_sha256": run.resolution_receipt_sha256,
            },
            row,
            fence,
        )

    def observe(self, binding_ref, case_ref, *, client, now, fence):
        _, ref, row = self._load(binding_ref, case_ref)
        if row.get("run_ref"):
            self._client(row, client)
            fence()
            run = client.get_service_case_resolution(
                self.host.authority_scope["project_id"],
                row["run_ref"],
                company_id=self.host.authority_scope["company_id"],
            )
            row = self._retain_run(ref, row, run, fence)
        deadline = (
            row["acknowledgment_deadline"]
            if row["phase"] in {"assigned", "dispatching"}
            else row["resolution_deadline"]
        )
        return {**row, "overdue": row["phase"] != "resolved" and parsed(now) >= parsed(deadline)}
