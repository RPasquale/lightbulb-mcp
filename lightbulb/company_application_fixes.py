"""Customer application fixes through existing Project approval and independent evidence."""

from pathlib import PurePosixPath
from typing import Literal
from uuid import UUID
from pydantic import Field, field_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    stable_digest,
    parsed,
)
from lightbulb.company_sales_progression import require
from lightbulb.growth_primitives import CreateWorkPacketPrimitive
from lightbulb.primitive_runtime import PrimitiveExecutionContext
from lightbulb.connector_execution import InMemoryConnectorExecutor
from lightbulb.native_coding import NativeCodingTask, NativeDeliveryStatus
from lightbulb.golden_loop_projections import (
    ServiceCaseResolutionStart,
    ServiceCaseResolutionRun,
)


class CustomerApplicationFix(StrictModel):
    fix_ref: OpaqueRef
    repository_connection_id: str = Field(
        pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
    )
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
    deployment_target_ref: OpaqueRef
    summary: str = Field(min_length=1, max_length=2000)
    reproduction_steps: tuple[str, ...] = Field(min_length=2, max_length=20)
    acceptance_criteria: tuple[str, ...] = Field(min_length=2, max_length=20)
    target_files: tuple[str, ...] = Field(min_length=1, max_length=50)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    review_ref: OpaqueRef
    implementation_budget_usd: int = Field(ge=1, le=1000, strict=True)

    @field_validator("summary")
    @classmethod
    def bounded_summary(cls, value):
        require(
            value == value.strip() and not any(ord(c) < 32 for c in value),
            "APPLICATION_FIX_BOUNDED_EVIDENCE_REQUIRED",
        )
        return value

    @field_validator("reproduction_steps", "acceptance_criteria")
    @classmethod
    def bounded_steps(cls, values):
        require(
            len(set(values)) == len(values)
            and all(
                0 < len(v) <= 2000 and v == v.strip() and not any(ord(c) < 32 for c in v)
                for v in values
            ),
            "APPLICATION_FIX_BOUNDED_EVIDENCE_REQUIRED",
        )
        return values

    @field_validator("target_files")
    @classmethod
    def relative_targets(cls, values):
        for value in values:
            require(
                0 < len(value) <= 300
                and not value.startswith("/")
                and "\\" not in value
                and ":" not in value
                and all(
                    p and p not in {".", ".."} and p.lower() != ".git" for p in value.split("/")
                )
                and not PurePosixPath(value).is_absolute()
                and not any(ord(c) < 32 for c in value),
                "APPLICATION_FIX_TARGET_OUTSIDE_REPOSITORY",
            )
        return values


class _ApplicationFixContract(StrictModel):
    schema_id: Literal["lightbulb.customer_application_fix.v1"] = Field(
        default="lightbulb.customer_application_fix.v1", alias="schema"
    )
    fix: CustomerApplicationFix
    case_ref: OpaqueRef
    support_case_digest: Sha256Digest
    source_context_digest: Sha256Digest


class ApplicationFixVerificationRequest(StrictModel):
    preparation_ref: OpaqueRef
    contact_policy_decision_ref: OpaqueRef
    contact_policy_sha256: Sha256Digest
    contact_policy_expires_at: str
    review_ref: OpaqueRef

    @field_validator("contact_policy_expires_at")
    @classmethod
    def canonical_expiry(cls, value):
        return parsed(value).isoformat().replace("+00:00", "Z")


def application_fix_package(fix, *, scope, case_ref, support_case_digest, source_context_digest):
    fix = CustomerApplicationFix.model_validate(fix)
    contract = _ApplicationFixContract(
        fix=fix,
        case_ref=case_ref,
        support_case_digest=support_case_digest,
        source_context_digest=source_context_digest,
    ).to_dict()
    result = CreateWorkPacketPrimitive().execute(
        PrimitiveExecutionContext(scope=scope, connectors=InMemoryConnectorExecutor()),
        {
            "title": "Resolve application issue " + fix.fix_ref,
            "implementation_objective": fix.summary,
            "scope": [
                "Implement only in the explicitly connected repository " + fix.repository,
                "Reproduce the reported issue and preserve its regression tests.",
                "Return a reviewable PR. User approval is required for coding; do not merge or deploy.",
                "Independent release/deployment observation and later customer confirmation are required for resolution.",
            ],
            "acceptance_criteria": list(fix.acceptance_criteria),
            "target_files": list(fix.target_files),
            "submit_for_approval": False,
        },
    )
    digest = stable_digest(contract)
    requirement = "application-fix-requirement-" + digest
    packet = result.output.model_dump(mode="json")
    packet.update(
        application_fix=contract,
        packet_digest=digest,
        id="application-fix-" + digest,
        packet_type="coding",
        source_requirement_ids=[requirement],
        status="draft",
        approval_required=True,
        budget_authorized=False,
        implementation_approval_required=True,
        independent_acceptance_required=True,
    )
    package = {
        "requirements": [
            {
                "id": requirement,
                "title": packet["title"],
                "description": fix.summary,
                "status": "draft",
            }
        ],
        "work_packets": [packet],
    }
    package["package_digest"] = stable_digest(package)
    return package


class CompanyApplicationFixes:
    """No SDK assertion or coding result authorizes a release or resolves a customer issue."""

    def __init__(self, support):
        self.support, self.p, self.host = support, support.p, support.host

    def _load(self, binding_ref, case_ref, fix_ref):
        binding, _, case = self.support._load(binding_ref, case_ref)
        ref = self.p.ref(binding, "application_fix", fix_ref)
        row = self.p.read(ref)
        require(
            row
            and row["binding_digest"] == stable_digest(binding.to_dict())
            and row["case_ref"] == case_ref,
            "APPLICATION_FIX_SCOPE_MISMATCH",
        )
        return binding, case, ref, row

    def propose(self, binding_ref, case_ref, fix, *, now, fence):
        binding, _, case = self.support._load(binding_ref, case_ref)
        require(case.get("phase") == "acknowledged", "APPLICATION_FIX_SPECIALIST_REQUIRED")
        fix = CustomerApplicationFix.model_validate(fix)
        evidence = {ref: self.p.read(ref) for ref in fix.evidence_refs}
        require(
            case["preparation_ref"] in evidence
            and all(
                v and v.get("binding_digest") == stable_digest(binding.to_dict())
                for v in evidence.values()
            ),
            "APPLICATION_FIX_SUPPORT_EVIDENCE_REQUIRED",
        )
        context = stable_digest(
            {
                "assignment": case["assignment"],
                "decision_digest": case["decision_digest"],
                "thread_digest": case["thread_digest"],
            }
        )
        package = application_fix_package(
            fix,
            scope=self.host.scope,
            case_ref=case_ref,
            support_case_digest=context,
            source_context_digest=stable_digest(evidence),
        )
        ref = self.p.ref(binding, "application_fix", fix.fix_ref)
        old = self.p.read(ref)
        if old:
            require(old["package"] == package, "APPLICATION_FIX_CHANGED")
            self._register(binding_ref, case_ref, fix.fix_ref, fence)
            return old
        require(len(case.get("application_fix_refs", [])) < 5, "APPLICATION_FIX_CASE_LIMIT")
        row = self.p.write(
            ref,
            {
                "case_ref": case_ref,
                "binding_digest": stable_digest(binding.to_dict()),
                "package": package,
                "phase": "proposed",
                "created_at": self.host._now(now),
                "execution_authorized": False,
            },
            None,
            fence,
        )
        self._register(binding_ref, case_ref, fix.fix_ref, fence)
        return row

    def _register(self, binding_ref, case_ref, fix_ref, fence):
        _, ref, case = self.support._load(binding_ref, case_ref)
        refs = case.get("application_fix_refs", [])
        if fix_ref not in refs:
            require(len(refs) < 5, "APPLICATION_FIX_CASE_LIMIT")
            self.p.write(ref, {**case, "application_fix_refs": [*refs, fix_ref]}, case, fence)

    def tick(self, binding_ref, case_ref, *, client, now, fence):
        """Continue only handoffs the caller already requested on a pinned connection."""
        _, _, case = self.support._load(binding_ref, case_ref)
        reports = []
        for fix_ref in case.get("application_fix_refs", []):
            try:
                _, _, _, row = self._load(binding_ref, case_ref, fix_ref)
                if row.get("connection_id") and not row.get("task_id"):
                    row = self.request_handoff(
                        binding_ref,
                        case_ref,
                        fix_ref,
                        connection_id=row["connection_id"],
                        client=client,
                        fence=fence,
                    )
                if row.get("task_id"):
                    if row.get("verification", {}).get("phase") == "submitting":
                        row = self.submit_verification(
                            binding_ref,
                            case_ref,
                            fix_ref,
                            client=client,
                            now=now,
                            fence=fence,
                        )
                    else:
                        row = self.observe(
                            binding_ref,
                            case_ref,
                            fix_ref,
                            client=client,
                            now=now,
                            fence=fence,
                        )
                reports.append(
                    {
                        "fix_ref": fix_ref,
                        "phase": row["phase"],
                        **row.get("observation", {}),
                    }
                )
            except ValueError as error:
                from lightbulb.company_host_journal import HostAuthorityError

                if isinstance(error, HostAuthorityError):
                    raise
                reports.append(
                    {
                        "fix_ref": fix_ref,
                        "phase": "review_required",
                        "reason": type(error).__name__,
                    }
                )
        return reports

    def submit(self, binding_ref, case_ref, fix_ref, *, client, fence):
        _, case, ref, row = self._load(binding_ref, case_ref, fix_ref)
        self.support._client(case, client)
        if row["phase"] != "proposed":
            require(
                row["phase"] != "submitting",
                "APPLICATION_FIX_SUBMISSION_RECONCILIATION_REQUIRED",
            )
            return row
        scope = {
            k: self.host.authority_scope[k]
            for k in ("tenant_id", "company_id", "user_id", "project_id")
        }
        row = self.p.write(ref, {**row, "phase": "submitting"}, row, fence)
        fence()
        result = client.dispatch(
            "crm",
            action="outbound_messaging",
            company_id=scope["company_id"],
            project_id=scope["project_id"],
            inputs={"sdk_application_fix": {"scope": scope, "package": row["package"]}},
        )
        self.support._client(case, client)
        output = result.outputs
        require(
            output.get("scope") == scope
            and output.get("package_digest") == row["package"]["package_digest"]
            and str(output.get("handoff", {}).get("projectId")) == scope["project_id"],
            "APPLICATION_FIX_HANDOFF_SCOPE_MISMATCH",
        )
        return self.p.write(
            ref,
            {
                **row,
                "phase": "submitted",
                "project_handoff": output["handoff"],
                "approval_required": True,
            },
            row,
            fence,
        )

    def request_handoff(self, binding_ref, case_ref, fix_ref, *, connection_id, client, fence):
        _, case, ref, row = self._load(binding_ref, case_ref, fix_ref)
        require(
            row["phase"] in {"submitted", "awaiting_user_approval", "task_created"},
            "APPLICATION_FIX_SUBMITTED_REQUIRED",
        )
        self.support._client(case, client)
        connection_id = str(UUID(str(connection_id)))
        require(
            not row.get("connection_id") or row["connection_id"] == connection_id,
            "APPLICATION_FIX_CONNECTION_CHANGED",
        )
        if row.get("task_id"):
            return row
        row = self.p.write(ref, {**row, "connection_id": connection_id}, row, fence)
        packet = row["package"]["work_packets"][0]
        fence()
        response = client.native_coding(self.host.authority_scope["project_id"]).prepare(
            connection_id,
            row.get("proposal_digest"),
            expected_gap_packet_digest=packet["packet_digest"],
        )
        if isinstance(response, NativeCodingTask):
            require(
                str(response.connection_id) == connection_id
                and response.proposal_digest == row.get("proposal_digest"),
                "APPLICATION_FIX_APPROVED_TASK_CHANGED",
            )
            return self.p.write(
                ref,
                {
                    **row,
                    "phase": "task_created",
                    "task_id": str(response.id),
                    "harness": response.harness,
                    "approval_task_id": str(response.approval_task_id),
                    "coding_status": response.status,
                },
                row,
                fence,
            )
        dependencies = response.get("review_payload", {}).get("application_fix_dependencies", [])
        require(
            any(
                d.get("gap_packet_digest") == packet["packet_digest"]
                and d.get("repository") == packet["application_fix"]["fix"]["repository"]
                for d in dependencies
            ),
            "APPLICATION_FIX_APPROVAL_PACKET_CHANGED",
        )
        require(
            not row.get("proposal_digest") or row["proposal_digest"] == response["proposal_digest"],
            "APPLICATION_FIX_APPROVAL_CHANGED",
        )
        return self.p.write(
            ref,
            {
                **row,
                "phase": "awaiting_user_approval",
                "proposal_digest": response["proposal_digest"],
                "approval_task_id": response["approval_task_id"],
                "approval_required": True,
            },
            row,
            fence,
        )

    def observe(self, binding_ref, case_ref, fix_ref, *, client, now, fence):
        _, case, ref, row = self._load(binding_ref, case_ref, fix_ref)
        self.support._client(case, client)
        require(row.get("task_id"), "APPLICATION_FIX_TASK_REQUIRED")
        packet = row["package"]["work_packets"][0]
        fix = packet["application_fix"]["fix"]
        channel = client.native_coding(self.host.authority_scope["project_id"])
        fence()
        task = channel.get(row["task_id"])
        require(
            str(task.connection_id) == row["connection_id"]
            and task.proposal_digest == row["proposal_digest"],
            "APPLICATION_FIX_TASK_CHANGED",
        )
        fence()
        status = NativeDeliveryStatus.model_validate(
            channel.delivery(row["task_id"], packet["packet_digest"])
        )
        require(
            str(status.connection_id) == row["connection_id"]
            and status.proposal_digest == row["proposal_digest"],
            "APPLICATION_FIX_DELIVERY_CHANGED",
        )
        deployed = bool(
            status.available
            and status.stage == "installed"
            and status.gap_packet_digest == packet["packet_digest"]
            and status.capability_ref == "support.application_fix"
            and status.source_context_digest == packet["application_fix"]["source_context_digest"]
            and status.acceptance_digest == stable_digest(fix["acceptance_criteria"])
            and status.repository == fix["repository"]
            and status.deployment_target_ref == fix["deployment_target_ref"]
            and status.evidence_digest
            and status.issued_at
            and status.expires_at
            and parsed(status.expires_at) > parsed(now)
        )
        observation = dict(
            stage=status.stage,
            independent_deployment_verified=deployed,
            customer_resolution_verified=False,
            coding_status=task.status,
            delivery=status.model_dump(mode="json", by_alias=True, exclude_none=True),
            observed_at=self.host._now(now),
            execution_authorized=False,
        )
        verification = row.get("verification")
        if verification and verification.get("run_ref"):
            fence()
            run = client.get_service_case_resolution(
                self.host.authority_scope["project_id"],
                verification["run_ref"],
                company_id=self.host.authority_scope["company_id"],
            )
            self._resolution_run(verification, run)
            observation["customer_resolution_state"] = run.state
            observation["customer_resolution_verified"] = bool(
                deployed
                and run.state == "CLOSED_VERIFIED"
                and self._same_deployment(
                    verification["deployment"], status.model_dump(mode="json")
                )
            )
            observation["customer_resolution_receipt_sha256"] = run.resolution_receipt_sha256
        retained = self.p.write(ref, {**row, "observation": observation}, row, fence)
        if observation["customer_resolution_verified"]:
            _, case_journal_ref, current_case = self.support._load(binding_ref, case_ref)
            if current_case["phase"] == "acknowledged" and not current_case.get("run_ref"):
                self.p.write(
                    case_journal_ref,
                    {
                        **current_case,
                        "phase": "resolved",
                        "terminal": True,
                        "resolution_verified": True,
                        "resolution_receipt_sha256": observation[
                            "customer_resolution_receipt_sha256"
                        ],
                        "application_fix_resolution_ref": fix_ref,
                    },
                    current_case,
                    fence,
                )
        return retained

    @staticmethod
    def _same_deployment(left, right):
        return all(
            left.get(k) == right.get(k)
            for k in (
                "artifact_sha256",
                "source_commit",
                "repository",
                "deployment_target_ref",
                "acceptance_digest",
            )
        )

    def _resolution_run(self, verification, run):
        run = ServiceCaseResolutionRun.model_validate(run)
        candidate = verification["candidate"]
        require(
            all(
                getattr(run, k) == self.host.authority_scope[k]
                for k in ("tenant_id", "company_id", "user_id", "project_id")
            )
            and run.candidate_ref == candidate["candidate_ref"]
            and run.candidate_sha256 == candidate["candidate_sha256"]
            and parsed(run.created_at) >= parsed(verification["deployment"]["issued_at"])
            and (
                not run.terminal_at
                or parsed(run.terminal_at) >= parsed(verification["deployment"]["issued_at"])
            ),
            "APPLICATION_FIX_CUSTOMER_VERIFICATION_MISMATCH",
        )
        require(
            not verification.get("run_ref") or run.run_ref == verification["run_ref"],
            "APPLICATION_FIX_VERIFICATION_RUN_CHANGED",
        )
        if run.state == "CLOSED_VERIFIED":
            receipt = run.resolution_receipt
            require(
                parsed(receipt["customer_confirmation_observed_at"]) >= parsed(run.created_at)
                and parsed(receipt["closure_observed_at"])
                >= parsed(receipt["customer_confirmation_observed_at"]),
                "APPLICATION_FIX_POST_DEPLOYMENT_CONFIRMATION_REQUIRED",
            )
        return run

    def prepare_verification(self, binding_ref, case_ref, fix_ref, request, *, client, now, fence):
        """Bind a fresh response and customer confirmation to independently observed deployment."""
        import hashlib

        request = ApplicationFixVerificationRequest.model_validate(request)
        row = self.observe(binding_ref, case_ref, fix_ref, client=client, now=now, fence=fence)
        binding, case, ref, _ = self._load(binding_ref, case_ref, fix_ref)
        if row.get("verification"):
            require(
                row["verification"]["request"] == request.to_dict(),
                "APPLICATION_FIX_VERIFICATION_CHANGED",
            )
            return row
        require(
            row["observation"]["independent_deployment_verified"],
            "APPLICATION_FIX_DEPLOYMENT_REQUIRED",
        )
        deployment = row["observation"]["delivery"]
        prepared = self.p.read(request.preparation_ref)
        require(
            prepared
            and prepared.get("binding_digest") == stable_digest(binding.to_dict())
            and prepared.get("review_required") is True,
            "APPLICATION_FIX_RESOLUTION_PREPARATION_REQUIRED",
        )
        context = self.p.research.drafting_context(binding_ref, prepared["brief_ref"], now=now)
        require(
            context["context_digest"] == prepared["context_digest"],
            "APPLICATION_FIX_RESOLUTION_CONTEXT_CHANGED",
        )
        brief = self.p.read(prepared["brief_ref"])
        require(
            parsed(brief["completed_at"]) >= parsed(deployment["issued_at"]),
            "APPLICATION_FIX_POST_DEPLOYMENT_CONTEXT_REQUIRED",
        )
        body = prepared.get("preparation", {}).get("response_draft")
        require(
            isinstance(body, str) and 0 < len(body) <= 5000,
            "APPLICATION_FIX_RESPONSE_REQUIRED",
        )
        mapping = case["assignment"]
        identity = dict(
            schema="lightbulb.service_case_resolution_candidate.v1",
            candidate_ref="appfix-" + row["package"]["package_digest"],
            connector_account_ref=mapping["connector_account_ref"],
            ticket_ref=mapping["ticket_ref"],
            requester_ref=mapping["requester_ref"],
            classification_sha256=case["escalation_digest"],
            routing_sha256=stable_digest(mapping),
            resolution_sha256=stable_digest(
                {
                    "package": row["package"]["package_digest"],
                    "deployment": deployment["evidence_digest"],
                    "preparation": stable_digest(prepared),
                    "review_ref": request.review_ref,
                }
            ),
            contact_policy_decision_ref=request.contact_policy_decision_ref,
            contact_policy_sha256=request.contact_policy_sha256,
            contact_policy_expires_at=request.contact_policy_expires_at,
            reply_body_sha256=hashlib.sha256(body.encode()).hexdigest(),
        )
        candidate = ServiceCaseResolutionStart(
            **{k: v for k, v in identity.items() if k != "reply_body_sha256"},
            candidate_sha256=stable_digest(identity),
            reply_body=body,
            idempotency_key="appfix:" + row["package"]["package_digest"]
        )
        _, thread = self.p.preparation._conversation(binding, now=now, fence=fence)
        return self.p.write(
            ref,
            {
                **row,
                "verification": {
                    "request": request.to_dict(),
                    "candidate": candidate.to_dict(),
                    "deployment": deployment,
                    "thread_digest": thread,
                    "phase": "prepared",
                },
            },
            row,
            fence,
        )

    def submit_verification(self, binding_ref, case_ref, fix_ref, *, client, now, fence):
        row = self.observe(binding_ref, case_ref, fix_ref, client=client, now=now, fence=fence)
        binding, _, ref, _ = self._load(binding_ref, case_ref, fix_ref)
        verification = row.get("verification")
        require(
            verification is not None,
            "APPLICATION_FIX_VERIFICATION_PREPARATION_REQUIRED",
        )
        if verification.get("run_ref"):
            return row
        require(
            row["observation"]["independent_deployment_verified"]
            and self._same_deployment(verification["deployment"], row["observation"]["delivery"]),
            "APPLICATION_FIX_DEPLOYMENT_CHANGED",
        )
        if verification["phase"] == "prepared":
            require(
                self.p.preparation._conversation(binding, now=now, fence=fence)[1]
                == verification["thread_digest"],
                "APPLICATION_FIX_CUSTOMER_REPLY_CHANGED",
            )
            verification = {**verification, "phase": "submitting"}
            row = self.p.write(ref, {**row, "verification": verification}, row, fence)
        fence()
        run = client.start_service_case_resolution(
            self.host.authority_scope["project_id"],
            verification["candidate"],
            company_id=self.host.authority_scope["company_id"],
        )
        run = self._resolution_run(verification, run)
        return self.p.write(
            ref,
            {
                **row,
                "verification": {
                    **verification,
                    "phase": "customer_confirmation_pending",
                    "run_ref": run.run_ref,
                },
            },
            row,
            fence,
        )
