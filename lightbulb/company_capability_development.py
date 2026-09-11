"""Retained SDK gap proposals on the existing company checkpoint and Project approval path."""
from __future__ import annotations

from datetime import timedelta
from pydantic import BaseModel, ConfigDict, Field
from lightbulb.company_capability_waits import CapabilityWait
from lightbulb.company_engine_core import parsed, stable_digest
from lightbulb.company_host_journal import HostAuthorityError
from lightbulb.native_coding import NativeCodingTask
from lightbulb.sdk_capability_gap import sdk_gap_project_package


class CapabilityDevelopmentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    implementation_budget_usd: int = Field(ge=1, le=1000, strict=True)
    deadline_hours: int = Field(default=168, ge=1, le=720, strict=True)
    max_open_requests: int = Field(default=8, ge=1, le=16, strict=True)


class CompanyCapabilityDevelopment:
    """Proposes work; Spring asks the user and alone authorizes the selected harness."""
    def __init__(self, waits, policy=None):
        self.waits = waits
        self.policy = CapabilityDevelopmentPolicy.model_validate(policy) if policy is not None else None

    def _rows(self):
        return (self.waits._read() or {}).get("handoffs", {})

    def _put(self, key, value, fence, *, create=False):
        def change(doc):
            rows = dict(doc.get("handoffs", {}))
            old = rows.get(key)
            if old and old["phase"] in {"registered", "cancelled", "needs_review", "expired"}:
                return
            if create and old:
                if old["request_digest"] != value["request_digest"]:
                    raise ValueError("CAPABILITY_HANDOFF_CHANGED")
                return
            if old is None and (len(rows) >= 128 or sum(r["phase"] not in {"registered", "cancelled", "needs_review", "expired"} for r in rows.values()) >= self.policy.max_open_requests):
                raise ValueError("CAPABILITY_HANDOFF_CAPACITY")
            rows[key] = {**(old or {}), **value}
            doc["handoffs"] = rows
        return self.waits._change(change, fence).get("handoffs", {}).get(key)

    def discover_sales(self, binding_ref, preparation_ref, *, now, fence):
        if self.policy is None:
            return
        identity = stable_digest({"binding_ref": binding_ref, "preparation_ref": preparation_ref})
        def register(doc):
            rows = dict(doc.get("gap_discoveries", {}))
            if identity in rows:
                return
            if len(rows) >= 128:
                raise ValueError("CAPABILITY_DISCOVERY_CAPACITY")
            rows[identity] = {"binding_ref": binding_ref, "preparation_ref": preparation_ref, "created_at": now, "phase": "pending"}
            doc["gap_discoveries"] = rows
        self.waits._change(register, fence)

    def request(self, domain, target_ref, gap, *, source_context_digest, now, fence, inputs=None):
        if self.policy is None or not self.waits.connection_id:
            raise ValueError("CAPABILITY_DEVELOPMENT_POLICY_REQUIRED")
        w = self.waits
        from lightbulb.connector_execution import ExecutionScope
        package = sdk_gap_project_package(gap, scope=ExecutionScope(**w.runner.bundle.scope, actor_ref=w.runner.bundle.actor_ref),
            source_context_digest=source_context_digest, implementation_budget_usd=self.policy.implementation_budget_usd)
        target_digest = w.target_digest(domain, target_ref, inputs)
        key = w._key(domain, target_ref)
        request = {"domain": domain, "target_ref": target_ref, "target_digest": target_digest,
            "inputs": inputs or {}, "package": package, "connection_id": w.connection_id}
        # Validate the owner contract before retaining anything. The task UUID is assigned by Spring later.
        packet = package["work_packets"][0]
        deadline = (parsed(now) + timedelta(hours=self.policy.deadline_hours)).isoformat().replace("+00:00", "Z")
        CapabilityWait(wait_ref="auto-" + stable_digest(key), domain=domain, target_ref=target_ref, target_digest=target_digest,
            inputs=inputs or {}, expires_at=deadline, dependencies=[dict(task_id="00000000-0000-0000-0000-000000000001",
                gap_packet_digest=packet["packet_digest"], source_context_digest=source_context_digest, capability_ref=packet["capability_gap"]["capability_ref"])])
        previous = self._rows().get(key)
        if previous:
            if previous["request_digest"] != stable_digest(request):
                raise ValueError("CAPABILITY_HANDOFF_CHANGED")
            return previous
        return self._put(key, {**request, "request_digest": stable_digest(request), "phase": "pending_submission",
            "created_at": now, "expires_at": deadline, "reason": "project_proposal_pending"}, fence, create=True)

    def blocks(self, domain, target_ref):
        row = self._rows().get(self.waits._key(domain, target_ref))
        return row is not None and row["phase"] != "registered"

    def cancel(self, domain, target_ref, *, fence):
        key = self.waits._key(domain, target_ref)
        row = self._rows().get(key)
        if row is None:
            raise LookupError(target_ref)
        if row["phase"] == "registered":
            return self.waits.cancel(domain, target_ref, fence=fence)
        return self._put(key, {"phase": "cancelled", "reason": "business_resumption_cancelled_coding_task_unchanged"}, fence)

    def _discover(self, *, now, fence):
        w = self.waits
        pending = [(identity, source) for identity, source in (w._read() or {}).get("gap_discoveries", {}).items() if source["phase"] == "pending"]
        cursor = int((w._read() or {}).get("discovery_cursor", 0)) % max(1, len(pending))
        for identity, source in (pending[cursor:] + pending[:cursor])[:8]:
            phase = "registered"
            try:
                if parsed(source["created_at"]) + timedelta(hours=self.policy.deadline_hours) <= w._now(now):
                    raise ValueError("CAPABILITY_DISCOVERY_EXPIRED")
                p = w.sales.progression
                binding = p.binding(source["binding_ref"])
                preparation = p.read(p.ref(binding, "agent_preparation", source["preparation_ref"]))
                if not preparation or preparation.get("phase") != "complete":
                    continue
                gap = p.preparation.propose_gap(source["binding_ref"], source["preparation_ref"],
                    implementation_budget_usd=self.policy.implementation_budget_usd, fence=fence)
                packet = gap["package"]["work_packets"][0]
                self.request("sales", gap["gap_ref"], packet["capability_gap"], source_context_digest=packet["source_context_digest"],
                    inputs={"binding_ref": source["binding_ref"], "brief_ref": preparation["brief_ref"]}, now=now, fence=fence)
            except HostAuthorityError:
                raise
            except (ValueError, LookupError, KeyError):
                phase = "needs_review"
            def done(doc):
                doc["gap_discoveries"] = {**doc["gap_discoveries"], identity: {**source, "phase": phase}}
            w._change(done, fence)
        if pending:
            w._change(lambda doc: doc.update(discovery_cursor=(cursor + 8) % len(pending)), fence)

    def step(self, *, now, fence):
        if self.policy is None or not self.waits.connection_id:
            return {"poll_again": bool(self._rows())}
        w = self.waits
        if w.sales:
            self._discover(now=now, fence=fence)
        active = [(key, row) for key, row in self._rows().items() if row["phase"] not in {"registered", "cancelled", "needs_review", "expired"}]
        cursor = int((w._read() or {}).get("handoff_cursor", 0)) % max(1, len(active))
        parent_fence = fence
        for key, row in (active[cursor:] + active[:cursor])[:8]:
            def guarded():
                parent_fence()
                latest = self._rows().get(key)
                cadence = w.runner.store.get("company_cadence", w.runner.bundle.company_ref + ":cadence")
                if (not latest or latest["phase"] in {"cancelled", "needs_review", "expired"}
                        or latest["connection_id"] != w.connection_id or not cadence or cadence.get("status") != "running"):
                    raise ValueError("CAPABILITY_HANDOFF_HELD")
            fence = guarded
            try:
                if parsed(row["expires_at"]) <= w._now(now):
                    self._put(key, {"phase": "expired", "reason": "task_deadline_passed"}, fence)
                    continue
                if row["connection_id"] != w.connection_id or w.target_digest(row["domain"], row["target_ref"], row["inputs"]) != row["target_digest"]:
                    raise ValueError("CAPABILITY_HANDOFF_TARGET_CHANGED")
                if row["phase"] == "submitting":
                    raise ValueError("CAPABILITY_HANDOFF_RECONCILIATION_REQUIRED")
                if row["phase"] == "pending_submission":
                    if row["domain"] == "sales":
                        w.sales.progression.preparation.submit_gap(row["inputs"]["binding_ref"], row["target_ref"], client=w.client, fence=fence)
                    else:
                        self._put(key, {"phase": "submitting"}, fence)
                        scope = {**w.gateway.authority_scope.model_dump(mode="json"), "project_id": w.runner.bundle.scope["project_id"]}
                        scope = {k: scope[k] for k in ("tenant_id", "company_id", "user_id", "project_id")}
                        fence()
                        result = w.client.dispatch("crm", action="outbound_messaging", company_id=scope["company_id"], project_id=scope["project_id"],
                            inputs={"sdk_capability_handoff": {"scope": scope, "package": row["package"]}})
                        output = result.outputs
                        if output.get("scope") != scope or output.get("package_digest") != row["package"]["package_digest"] or str(output.get("handoff", {}).get("projectId")) != scope["project_id"]:
                            raise ValueError("CAPABILITY_HANDOFF_SCOPE_MISMATCH")
                    row = self._put(key, {"phase": "awaiting_packet", "reason": "user_handoff_approval_required"}, fence)
                packet = row["package"]["work_packets"][0]
                fence()
                result = w.client.native_coding(w.runner.bundle.scope["project_id"]).prepare(w.connection_id,
                    row.get("proposal_digest"), expected_gap_packet_digest=packet["packet_digest"])
                if isinstance(result, NativeCodingTask):
                    expected = {"gap_packet_digest": packet["packet_digest"], "source_context_digest": packet["source_context_digest"], "capability_ref": packet["capability_gap"]["capability_ref"]}
                    if (str(result.project_id) != w.runner.bundle.scope["project_id"] or str(result.connection_id) != w.connection_id
                            or result.proposal_digest != row.get("proposal_digest") or result.status in {"failed", "cancelled"}):
                        raise ValueError("CAPABILITY_HANDOFF_TASK_MISMATCH")
                    def receipt(doc):
                        rows = dict(doc["handoffs"])
                        rows[key] = {**rows[key], "task_id": str(result.id), "approval_task_id": str(result.approval_task_id)}
                        doc["handoffs"] = rows
                    w._change(receipt, parent_fence)
                    w.enqueue(CapabilityWait(wait_ref="auto-" + stable_digest(key), domain=row["domain"], target_ref=row["target_ref"],
                        target_digest=row["target_digest"], inputs=row["inputs"], expires_at=row["expires_at"],
                        dependencies=[{**expected, "task_id": result.id}]), now=now, fence=fence)
                    self._put(key, {"phase": "registered", "task_id": str(result.id), "reason": "waiting_for_verified_installation"}, fence)
                else:
                    expected = {"gap_packet_digest": packet["packet_digest"], "source_context_digest": packet["source_context_digest"], "capability_ref": packet["capability_gap"]["capability_ref"]}
                    dependencies = result.get("review_payload", {}).get("sdk_capability_dependencies", [])
                    if not any(isinstance(d, dict) and all(d.get(k) == v for k, v in expected.items()) for d in dependencies):
                        raise ValueError("CAPABILITY_HANDOFF_DEPENDENCY_MISMATCH")
                    def approval_receipt(doc):
                        rows = dict(doc["handoffs"])
                        rows[key] = {**rows[key], "approval_task_id": result["approval_task_id"]}
                        doc["handoffs"] = rows
                    w._change(approval_receipt, parent_fence)
                    if result.get("status") in {"rejected", "expired", "cancelled"}:
                        raise ValueError("CAPABILITY_HANDOFF_APPROVAL_HELD")
                    self._put(key, {"phase": "awaiting_approval", "proposal_digest": result["proposal_digest"],
                        "approval_task_id": result["approval_task_id"], "reason": "user_handoff_approval_required"}, fence)
            except HostAuthorityError:
                raise
            except (ValueError, KeyError, LookupError):
                self._put(key, {"phase": "needs_review", "reason": "handoff_or_owner_requires_review"}, parent_fence)
            except Exception as error:
                code = getattr(error, "status_code", None)
                if code in {400, 401, 403, 404} or (code == 409 and row.get("proposal_digest")):
                    self._put(key, {"phase": "needs_review", "reason": "project_permission_or_packet_requires_review"}, parent_fence)
                    continue
                # A transport failure on idempotent approval polling may retry the same digest;
                # a dispatched Project submission remains submitting and requires reconciliation.
                self._put(key, {"reason": "project_packet_not_ready" if code == 409 else "handoff_transport_unavailable"}, parent_fence)
        if active:
            w._change(lambda doc: doc.update(handoff_cursor=(cursor + 8) % len(active)), parent_fence)
        return {"poll_again": any(r["phase"] not in {"registered", "cancelled", "needs_review", "expired"} for r in self._rows().values())
            or any(r["phase"] == "pending" for r in (w._read() or {}).get("gap_discoveries", {}).values())}

    def report(self):
        return [{"domain": r["domain"], "target_ref": r["target_ref"], "status": r["phase"], "reason": r["reason"],
            "approval_task_id": r.get("approval_task_id"), "task_id": r.get("task_id"),
            "cancellation_scope": "business_resumption_only", "coding_execution_may_continue": bool(r.get("task_id")) or r["phase"] == "cancelled",
            "execution_authorized": False} for r in self._rows().values()] + [
                {"status": "discovery_needs_review", "reason": "original_sales_preparation_requires_review", "execution_authorized": False}
                for r in (self.waits._read() or {}).get("gap_discoveries", {}).values() if r["phase"] == "needs_review"]
