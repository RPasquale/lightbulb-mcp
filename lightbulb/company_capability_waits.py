"""Capability dependency gates on the existing authenticated company cadence.

This module neither dispatches arbitrary agents nor grants execution authority.
Owners re-enter their existing, journaled paths under the current cadence lease.
"""
from __future__ import annotations

import json
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator
from lightbulb.company_engine_core import stable_digest, parsed, timestamp
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway, HostAuthorityError
from lightbulb.company_hosted_scheduler import CheckpointConflict
from lightbulb.native_coding import NativeDeliveryStatus

SCHEMA = "lightbulb.company_capability_waits.v1"
TERMINAL = {"resumed", "cancelled", "expired", "needs_review"}


class CapabilityDependency(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    task_id: UUID
    gap_packet_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_context_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    capability_ref: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


class CapabilityWait(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    wait_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,119}$")
    domain: Literal["sales", "finance", "marketing", "operations"]
    target_ref: str = Field(min_length=1, max_length=160)
    target_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    dependencies: tuple[CapabilityDependency, ...] = Field(min_length=1, max_length=4)
    expires_at: str
    inputs: dict[str, str] = Field(default_factory=dict, max_length=2)

    @model_validator(mode="after")
    def contract(self):
        timestamp(self.expires_at, field_name="expires_at")
        if len({(d.task_id, d.gap_packet_digest) for d in self.dependencies}) != len(self.dependencies):
            raise ValueError("CAPABILITY_DEPENDENCIES_DUPLICATED")
        expected = {"binding_ref", "brief_ref"} if self.domain == "sales" else set()
        if set(self.inputs) != expected or any(not 1 <= len(v) <= 160 for v in self.inputs.values()):
            raise ValueError("CAPABILITY_WAIT_INPUTS_INVALID")
        if self.domain == "sales" and len(self.dependencies) != 1:
            raise ValueError("SALES_WAIT_REQUIRES_ORIGINAL_GAP")
        return self


def validate_capability_waits(values):
    if not isinstance(values, (tuple, list)) or len(values) > 64:
        raise ValueError("CAPABILITY_WAIT_CONFIGURATION_INVALID")
    waits = tuple(CapabilityWait.model_validate(v) for v in values)
    if len({(w.domain, w.target_ref) for w in waits}) != len(waits):
        raise ValueError("CAPABILITY_WAIT_TARGET_DUPLICATED")
    return waits


class CompanyCapabilityWaits:
    def __init__(self, runner, gateway, client, *, connection_id, clock, sales=None, growth=None, signals=None, configured=(), signal_sources=(), development_policy=None):
        if not isinstance(gateway, AuthenticatedCheckpointGateway):
            raise HostAuthorityError("AUTHENTICATED_HOST_JOURNAL_REQUIRED")
        self.runner, self.gateway, self.client = runner, gateway, client
        self.connection_id = str(UUID(str(connection_id))) if connection_id else None
        self.clock, self.sales, self.growth, self.signals = clock, sales, growth, signals
        self.signal_sources = signal_sources
        self.configured = validate_capability_waits(configured)
        self.ref = "company-capability-waits-" + stable_digest(runner.bundle.scope)
        from lightbulb.company_capability_development import CompanyCapabilityDevelopment
        from lightbulb.company_capability_outcomes import CompanyCapabilityOutcomes
        self.development = CompanyCapabilityDevelopment(self, development_policy)
        self.outcomes = CompanyCapabilityOutcomes(self)
        from lightbulb.company_capability_learning import CompanyCapabilityLearning
        self.learning = CompanyCapabilityLearning(self)
        if sales is not None:
            sales.capability_waits = self

    def _now(self, now):
        return max(parsed(timestamp(now, field_name="now")), parsed(timestamp(self.clock(), field_name="clock")))

    def _read(self):
        old = self.gateway.get(self.ref)
        if old and (old.get("schema") != SCHEMA or old.get("bundle_digest") != self.runner.bundle.plan_digest
                    or old.get("scope") != self.runner.bundle.scope):
            raise HostAuthorityError("CAPABILITY_WAIT_SCOPE_MISMATCH")
        return old

    def _change(self, change, fence):
        for _ in range(3):
            old = self._read()
            doc = {**(old or {}), "schema": SCHEMA, "bundle_digest": self.runner.bundle.plan_digest,
                   "scope": dict(self.runner.bundle.scope), "resume_at": None,
                   "entries": dict((old or {}).get("entries", {}))}
            change(doc)
            if len(json.dumps(doc, ensure_ascii=True).encode()) > 480 * 1024:
                raise ValueError("CAPABILITY_WAIT_JOURNAL_FULL")
            fence()
            try:
                return self.gateway.put(self.ref, doc, expected_revision=old["revision"] if old else 0)
            except CheckpointConflict:
                continue
        raise CheckpointConflict("capability waits changed; original request retained")

    @staticmethod
    def _key(domain, target):
        return domain + ":" + target

    def target_digest(self, domain, target_ref, inputs=None):
        inputs = inputs or {}
        if domain in {"finance", "marketing"} and self.growth:
            field = "periods" if domain == "finance" else "reallocations"
            spec = next((s for s in self.growth.configuration.get(field, ()) if s["ref"] == target_ref), None)
            if spec is not None:
                return stable_digest(spec)
        if domain == "operations" and self.signals:
            journal = self.signals._journal(target_ref)
            if journal:
                return stable_digest(journal["signal"])
            from lightbulb.company_operating_system import CompanySignal
            for raw in self.signal_sources:
                signal = CompanySignal.model_validate(raw)
                if self.signals._identity(signal) == target_ref:
                    return stable_digest(signal.to_dict())
        if domain == "sales" and self.sales:
            p = self.sales.progression
            binding = p.binding(inputs["binding_ref"])
            gap = p.read(target_ref)
            if gap and gap.get("phase") in {"proposed", "submitted"} and gap.get("binding_digest") == stable_digest(binding.to_dict()):
                return stable_digest({"package": gap["package"], "binding_digest": gap["binding_digest"], "inputs": inputs})
        raise ValueError("CAPABILITY_WAIT_TARGET_NOT_CURRENT")

    def enqueue(self, request, *, now, fence):
        wait = CapabilityWait.model_validate(request)
        key = self._key(wait.domain, wait.target_ref)
        body = wait.model_dump(mode="json")
        existing = (self._read() or {}).get("entries", {}).get(key)
        if existing:
            if existing["request"] != body:
                raise ValueError("CAPABILITY_WAIT_TARGET_CHANGED")
            return existing
        def insert(doc):
            previous = doc["entries"].get(key)
            if previous:
                if previous["request"] != body:
                    raise ValueError("CAPABILITY_WAIT_TARGET_CHANGED")
                return
            if len(doc["entries"]) >= 128:
                raise ValueError("CAPABILITY_WAIT_QUEUE_FULL")
            if not self.connection_id or parsed(wait.expires_at) <= self._now(now):
                raise ValueError("CAPABILITY_WAIT_CONNECTION_OR_DEADLINE_REQUIRED")
            if self.target_digest(wait.domain, wait.target_ref, wait.inputs) != wait.target_digest:
                raise ValueError("CAPABILITY_WAIT_TARGET_CHANGED")
            doc["entries"][key] = {"request": body, "connection_id": self.connection_id, "worker_probe_required": self.development.policy is not None or key in doc.get("handoffs", {}),
                "phase": "waiting", "reason": "capability_unavailable", "started": False, "evidence": []}
        return self._change(insert, fence)["entries"][key]

    def _update(self, key, values, fence):
        def update(doc):
            if doc["entries"][key]["phase"] == "resumed" or (doc["entries"][key]["phase"] in TERMINAL and values.get("phase") != "cancelled"):
                return
            doc["entries"][key] = {**doc["entries"][key], **values}
        return self._change(update, fence)["entries"][key]

    def cancel(self, domain, target_ref, *, fence):
        key = self._key(domain, target_ref)
        row = (self._read() or {}).get("entries", {}).get(key)
        if row is None:
            raise LookupError(target_ref)
        if row["phase"] == "resumed":
            return row  # Completion cannot be undone or presented as cancellation.
        return self._update(key, {"phase": "cancelled", "reason": "cancelled_by_operator"}, fence)

    def refresh(self, *, now, fence):
        development_pending = self.development.step(now=now, fence=fence).get("poll_again", False)
        # Registration happens under the same cadence lease as owner execution.
        for wait in self.configured:
            self.enqueue(wait, now=now, fence=fence)
        old = self._read()
        if not old:
            return {"poll_again": development_pending}
        keys = [k for k, row in old["entries"].items() if row["phase"] not in TERMINAL]
        cursor = int(old.get("cursor", 0)) % max(1, len(keys))
        selected = (keys[cursor:] + keys[:cursor])[:16]
        for key in selected:
            row = (self._read() or {})["entries"][key]
            wait = CapabilityWait.model_validate(row["request"])
            if parsed(wait.expires_at) <= self._now(now):
                self._update(key, {"phase": "expired", "reason": "task_deadline_passed"}, fence)
                continue
            try:
                if self.target_digest(wait.domain, wait.target_ref, wait.inputs) != wait.target_digest:
                    raise ValueError("CAPABILITY_WAIT_TARGET_CHANGED")
                if self.connection_id != row["connection_id"]:
                    raise ValueError("CAPABILITY_WAIT_RUNTIME_CHANGED")
                evidence = []
                for dependency in wait.dependencies:
                    fence()
                    value = self.client.native_coding(self.runner.bundle.scope["project_id"]).delivery(dependency.task_id, dependency.gap_packet_digest)
                    status = NativeDeliveryStatus.model_validate(value)
                    if (str(status.project_id) != self.runner.bundle.scope["project_id"] or status.task_id != dependency.task_id
                            or str(status.connection_id) != self.connection_id
                            or (status.gap_packet_digest is not None and status.gap_packet_digest != dependency.gap_packet_digest)
                            or (status.source_context_digest is not None and status.source_context_digest != dependency.source_context_digest)
                            or (status.capability_ref is not None and status.capability_ref != dependency.capability_ref)):
                        raise ValueError("CAPABILITY_WAIT_EVIDENCE_SCOPE_MISMATCH")
                    if (not status.available or status.stage != "installed" or status.gap_packet_digest != dependency.gap_packet_digest
                            or status.source_context_digest != dependency.source_context_digest or status.capability_ref != dependency.capability_ref or not status.evidence_digest or not status.expires_at or parsed(status.expires_at) <= self._now(now)):
                        break
                    from lightbulb.sdk_capability_assessment import refresh_worker_capability
                    if not refresh_worker_capability(self, wait.domain, status, fence=fence, required=row.get("worker_probe_required", False) or key in (self._read() or {}).get("handoffs", {})):
                        evidence = []
                        break
                    evidence.append({"digest": status.evidence_digest, "expires_at": status.expires_at})
                ready = len(evidence) == len(wait.dependencies)
                self._update(key, {"phase": "ready" if ready else "waiting", "reason": None if ready else "capability_unavailable",
                                   "evidence": evidence if ready else [], "checked_at": self._now(now).isoformat()}, fence)
            except HostAuthorityError:
                raise
            except (ValueError, LookupError):
                self._update(key, {"phase": "needs_review", "reason": "target_or_scope_changed", "evidence": []}, fence)
            except Exception:
                # Transport failures never mean availability; each other wait can still progress.
                self._update(key, {"phase": "waiting", "reason": "availability_check_failed", "evidence": []}, fence)
        if keys:
            self._change(lambda doc: doc.update(cursor=(cursor + len(selected)) % len(keys)), fence)
        return {"poll_again": development_pending or any(row["phase"] not in TERMINAL for row in (self._read() or {}).get("entries", {}).values())}

    def begin(self, domain, target_ref, target_digest, *, now, fence):
        key = self._key(domain, target_ref)
        row = (self._read() or {}).get("entries", {}).get(key)
        if self.development.blocks(domain, target_ref):
            return False
        if row is None or row["phase"] == "resumed":
            return True
        wait = CapabilityWait.model_validate(row["request"])
        if wait.target_digest != target_digest or self.connection_id != row["connection_id"]:
            self._update(key, {"phase": "needs_review", "reason": "target_or_runtime_changed"}, fence)
            return False
        if parsed(wait.expires_at) <= self._now(now):
            self._update(key, {"phase": "expired", "reason": "task_deadline_passed"}, fence)
            return False
        if row["phase"] != "ready" or not row["evidence"] or any(parsed(e["expires_at"]) <= self._now(now) for e in row["evidence"]):
            return False
        cadence = self.runner.store.get("company_cadence", self.runner.bundle.company_ref + ":cadence")
        if cadence is None or cadence.get("status") != "running":
            return False
        fence()
        begun = self._update(key, {"phase": "resuming", "started": True, "started_at": row.get("started_at") or now, "reason": "owner_rechecking_current_policy"}, fence)
        return begun["phase"] == "resuming"

    def owner_fence(self, domain, target_ref, *, now, fence):
        def guarded():
            fence()
            row = (self._read() or {}).get("entries", {}).get(self._key(domain, target_ref))
            if row is None or row["phase"] == "resumed":
                return
            cadence = self.runner.store.get("company_cadence", self.runner.bundle.company_ref + ":cadence")
            if (row["phase"] != "resuming" or not cadence or cadence.get("status") != "running"
                    or parsed(row["request"]["expires_at"]) <= self._now(now)
                    or not row["evidence"] or any(parsed(e["expires_at"]) <= self._now(now) for e in row["evidence"])):
                raise ValueError("CAPABILITY_WAIT_OWNER_HELD")
        return guarded

    def finish(self, domain, target_ref, *, complete=False, terminal=False, reason=None, fence):
        key = self._key(domain, target_ref)
        row = (self._read() or {}).get("entries", {}).get(key)
        if row is None or row["phase"] in TERMINAL:
            return
        phase = "resumed" if complete else "needs_review" if terminal else "owner_pending"
        self._update(key, {"phase": phase, "completed_at": self.clock() if complete else None,
            "reason": reason or (None if complete else "owner_approval_or_recovery_pending")}, fence)

    def run_sales(self, *, now, fence):
        if self.sales is None:
            return
        for row in list((self._read() or {}).get("entries", {}).values()):
            wait = CapabilityWait.model_validate(row["request"])
            if wait.domain != "sales" or row["phase"] != "ready":
                continue
            dependency = wait.dependencies[0]
            try:
                if not self.begin("sales", wait.target_ref, self.target_digest("sales", wait.target_ref, wait.inputs), now=now, fence=fence):
                    continue
                result = self.sales.progression.preparation.resume_gap(wait.inputs["binding_ref"], wait.target_ref,
                    task_id=dependency.task_id, connection_id=self.connection_id, brief_ref=wait.inputs["brief_ref"],
                    client=self.client, now=now, fence=self.owner_fence("sales", wait.target_ref, now=now, fence=fence))
                self.finish("sales", wait.target_ref, complete=result["phase"] == "prepared_for_review",
                            terminal=result["phase"] != "prepared_for_review", reason="draft_requires_review", fence=fence)
            except HostAuthorityError:
                raise
            except Exception:
                self.finish("sales", wait.target_ref, terminal=True, reason="sales_preparation_requires_reconciliation", fence=fence)

    def report(self):
        return [{"wait_ref": row["request"]["wait_ref"], "domain": row["request"]["domain"],
                 "target_ref": row["request"]["target_ref"], "status": row["phase"], "reason": row.get("reason"),
                 "started": row["started"], "execution_authorized": False}
                for row in (self._read() or {}).get("entries", {}).values()]
