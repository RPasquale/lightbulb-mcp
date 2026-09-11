"""Typed domain diagnosis and refreshed worker capability contracts; no execution authority."""
from typing import Literal, Annotated
from pydantic import BaseModel, ConfigDict, Field, model_validator
from lightbulb.sdk_capability_gap import SalesAgentScope, SdkCapabilityGap


class UnsupportedOwnerOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    engine: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=100)
    satisfied_by: tuple[Annotated[str, Field(max_length=160)], ...] = Field(default=(), max_length=6)
    requires_consent: bool = False
    requires_approval: bool = False


class CapabilityAssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scope: SalesAgentScope
    domain: Literal["sales", "finance", "marketing", "operations"]
    target_ref: str = Field(min_length=1, max_length=160)
    target_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    report_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    blocker_kind: Literal["permission", "configuration", "data", "approval", "recovery", "unsupported_behavior"]
    observed_codes: tuple[Annotated[str, Field(max_length=120)], ...] = Field(max_length=12)
    unsupported_operations: tuple[UnsupportedOwnerOperation, ...] = Field(default=(), max_length=12)


class CapabilityAssessmentDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    disposition: Literal["permission", "configuration", "data", "approval", "recovery", "capability_gap", "needs_review"]
    gap: SdkCapabilityGap | None = None

    @model_validator(mode="after")
    def exact(self):
        if (self.disposition == "capability_gap") != (self.gap is not None):
            raise ValueError("CAPABILITY_DIAGNOSIS_GAP_MISMATCH")
        return self


class CapabilityProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scope: SalesAgentScope
    capability_ref: str = Field(pattern=r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
    package_version: str = Field(min_length=1, max_length=80)
    installation_evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


DOMAIN_AGENT = {"sales": "crm", "finance": "finance", "marketing": "content", "operations": "it_ops"}


def diagnose_owner_blocker(waits, domain, target_ref, report, *, now, fence):
    from lightbulb.company_host_journal import HostAuthorityError
    try:
        return _diagnose_owner_blocker(waits, domain, target_ref, report, now=now, fence=fence)
    except HostAuthorityError:
        raise
    except (ValueError, KeyError, TimeoutError):
        fence()
        return {"phase": "needs_review", "reason": "diagnosis_incomplete"}


def _diagnose_owner_blocker(waits, domain, target_ref, report, *, now, fence):
    if waits.development.policy is None:
        return None
    from lightbulb.company_engine_core import stable_digest
    # Exact owner facts take precedence over model judgment. Unknown errors are recovery, not new code.
    codes = [str(report.get(k, ""))[:120] for k in ("status", "execution_status", "error_code") if report.get(k)]
    if report.get("missing_sources"):
        kind = "data"
    elif any("APPROVAL" in c for c in codes):
        kind = "approval"
    elif any("PERMISSION" in c or "SCOPE" in c or "AUTH" in c for c in codes):
        kind = "permission"
    elif report.get("deferred_intents") or report.get("deferred_commands") or any(c in {"SDK_CAPABILITY_UNAVAILABLE", "UNSUPPORTED_INTENT"} for c in codes):
        kind = "unsupported_behavior"
    elif any("CONFIGURATION" in c or "REQUIRED" in c for c in codes):
        kind = "configuration"
    else:
        kind = "recovery"
    target_digest = waits.target_digest(domain, target_ref)
    report_digest = stable_digest(report)
    identity = stable_digest({"domain": domain, "target": target_ref, "report": report_digest})
    old = (waits._read() or {}).get("capability_diagnoses", {}).get(identity)
    if old:
        return old  # Dispatching means reconcile this exact diagnosis; never a second model request.
    scope = waits.gateway.authority_scope.model_dump(mode="json")
    scope = {k: scope[k] for k in ("tenant_id", "company_id", "user_id")}
    scope["project_id"] = waits.runner.bundle.scope["project_id"]
    request = CapabilityAssessmentRequest(scope=scope, domain=domain, target_ref=target_ref, target_digest=target_digest,
        report_digest=report_digest, blocker_kind=kind, observed_codes=codes,
        unsupported_operations=[{"engine": row["engine"], "operation": row.get("kind", row.get("event")),
            "satisfied_by": row.get("satisfied_by", ()), "requires_consent": row.get("requires_consent", False),
            "requires_approval": row.get("requires_approval", False)}
            for row in [*report.get("deferred_intents", ()), *report.get("deferred_commands", ())][:12]])
    def retain(phase, decision=None):
        def write(doc):
            rows = dict(doc.get("capability_diagnoses", {}))
            if len(rows) >= 128 and identity not in rows:
                raise ValueError("CAPABILITY_DIAGNOSIS_CAPACITY")
            previous = rows.get(identity)
            if previous and phase == "dispatching":
                raise ValueError("CAPABILITY_DIAGNOSIS_ALREADY_DISPATCHED")
            if previous and previous.get("phase") == "complete":
                return
            rows[identity] = {"domain": domain, "target_ref": target_ref, "target_digest": target_digest,
                "report_digest": report_digest, "phase": phase, "decision": decision, "observed_at": now}
            doc["capability_diagnoses"] = rows
        return waits._change(write, fence)["capability_diagnoses"][identity]
    if kind != "unsupported_behavior":
        return retain("complete", {"disposition": kind, "gap": None})
    retain("dispatching")
    fence()
    result = waits.client.dispatch(DOMAIN_AGENT[domain], action="chat", company_id=scope["company_id"], project_id=scope["project_id"],
        inputs={"sdk_capability_assessment": request.model_dump(mode="json")})
    output = result.outputs
    if output.get("scope") != scope or output.get("report_digest") != report_digest or output.get("target_digest") != target_digest:
        raise ValueError("CAPABILITY_DIAGNOSIS_SCOPE_MISMATCH")
    decision = CapabilityAssessmentDecision.model_validate(output["decision"])
    if decision.gap:
        if waits.target_digest(domain, target_ref) != target_digest:
            raise ValueError("CAPABILITY_DIAGNOSIS_OWNER_CHANGED")
        fence()
        waits.development.request(domain, target_ref, decision.gap.model_dump(mode="json"), source_context_digest=report_digest, now=now, fence=fence)
    return retain("complete", decision.model_dump(mode="json"))


def refresh_worker_capability(waits, domain, status, *, fence, required=False):
    """A fresh agent invocation must see and validate the installed capability before resuming."""
    if not required and waits.development.policy is None:
        return True
    from lightbulb.company_engine_core import stable_digest
    from lightbulb.native_coding import NativeDeliveryStatus
    status = NativeDeliveryStatus.model_validate(status)
    if not status.package_version or not status.evidence_digest:
        return False
    scope = waits.gateway.authority_scope.model_dump(mode="json")
    scope = {k: scope[k] for k in ("tenant_id", "company_id", "user_id")}
    scope["project_id"] = waits.runner.bundle.scope["project_id"]
    request = CapabilityProbeRequest(scope=scope, capability_ref=status.capability_ref, package_version=status.package_version,
        installation_evidence_digest=status.evidence_digest)
    identity = stable_digest({"domain": domain, "task_id": str(status.task_id), "capability_ref": status.capability_ref})
    # Probe every refresh; a process restart or package change cannot reuse an old worker inventory.
    fence()
    result = waits.client.dispatch(DOMAIN_AGENT[domain], action="chat", company_id=scope["company_id"], project_id=scope["project_id"],
        inputs={"sdk_capability_probe": request.model_dump(mode="json")})
    output = result.outputs
    ready = (output.get("scope") == scope and output.get("capability_ref") == status.capability_ref
        and output.get("installation_evidence_digest") == status.evidence_digest and output.get("package_version") == status.package_version
        and output.get("ready") is True and output.get("acceptance_basis") == "imported_primitive_contract"
        and isinstance(output.get("inventory_digest"), str) and len(output["inventory_digest"]) == 64)
    def store(doc):
        rows = dict(doc.get("worker_capability_probes", {}))
        if identity not in rows and len(rows) >= 128:
            rows.pop(next(iter(rows)))
        rows[identity] = {"domain": domain, "capability_ref": status.capability_ref, "ready": ready,
            "inventory_digest": output.get("inventory_digest") if ready else None, "reason": None if ready else "worker_restart_or_capability_contract_required"}
        doc["worker_capability_probes"] = rows
    waits._change(store, fence)
    return ready


def capability_runtime_report(waits):
    doc = waits._read() or {}
    return {"assessments": [{"domain": row["domain"], "target_ref": row["target_ref"], "phase": row["phase"],
        "disposition": (row.get("decision") or {}).get("disposition")} for row in doc.get("capability_diagnoses", {}).values()],
        "worker_probes": list(doc.get("worker_capability_probes", {}).values()), "execution_authorized": False}
