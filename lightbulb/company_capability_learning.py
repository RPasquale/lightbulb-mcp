"""Existing growth-learning ledger backed by the company's authenticated checkpoint."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from lightbulb.company_engine_core import stable_digest, parsed, timestamp
from lightbulb.growth_learnings import GrowthLearningsLedger, GrowthLearningsConflictError


def implementation_contract(gap):
    return stable_digest({"capability_ref": gap["capability_ref"], "missing_behavior": gap["missing_behavior"],
        "acceptance_criteria": sorted(gap["acceptance_criteria"]), "target_files": sorted(gap["target_files"])})


class CapabilityImplementationReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    review_ref: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    actual_effort_minutes: int = Field(ge=1, le=1000000, strict=True)
    actual_cost_minor: int = Field(ge=0, le=10**12, strict=True)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    evidence_digests: tuple[str, ...] = Field(min_length=1, max_length=10)


class _CheckpointLearningStore:
    def __init__(self, waits, fence):
        self.waits, self.fence = waits, fence

    def load(self):
        doc = self.waits._read() or {}
        return doc.get("learning_revision", 0), tuple(doc.get("growth_learning_entries", ()))

    def save(self, *, expected_revision, entries):
        if len(entries) > 128:
            raise ValueError("CAPABILITY_LEARNING_CAPACITY")
        def save(doc):
            if doc.get("learning_revision", 0) != expected_revision:
                raise GrowthLearningsConflictError("Reload the original learning chain")
            doc.update(learning_revision=expected_revision+1, growth_learning_entries=list(entries))
        self.waits._change(save, self.fence)
        return expected_revision+1


class CompanyCapabilityLearning:
    def __init__(self, waits):
        self.waits = waits

    def ledger(self, fence):
        return GrowthLearningsLedger(_CheckpointLearningStore(self.waits, fence),
            scope=self.waits.gateway.authority_scope, scope_keyring=self.waits.gateway.keyring)

    def review(self, domain, target_ref, review, *, now, fence):
        review = CapabilityImplementationReview.model_validate(review)
        if any(len(d) != 64 or any(c not in "0123456789abcdef" for c in d) for d in review.evidence_digests):
            raise ValueError("CAPABILITY_COST_EVIDENCE_INVALID")
        timestamp(now, field_name="now")
        w, key = self.waits, self.waits._key(domain, target_ref)
        doc = w._read() or {}
        handoff, wait = doc.get("handoffs", {}).get(key), doc.get("entries", {}).get(key)
        if not handoff or not wait or wait["phase"] != "resumed":
            raise ValueError("CAPABILITY_COMPLETED_WORK_REQUIRED")
        body = {"review": review.model_dump(mode="json"), "recorded_at": now,
            "contract_digest": implementation_contract(handoff["package"]["work_packets"][0]["capability_gap"]),
            "estimate": doc.get("value_estimates", {}).get(key), "basis": "operator_attested_cost"}
        def retain(current):
            rows = dict(current.get("implementation_reviews", {}))
            old = rows.get(key)
            if old and old != body:
                raise ValueError("CAPABILITY_IMPLEMENTATION_REVIEW_CHANGED")
            rows[key] = body
            current["implementation_reviews"] = rows
        w._change(retain, fence)
        return body

    def sync(self, *, now, fence):
        """Record each completed step once; observed usage never becomes causal revenue."""
        w, ledger = self.waits, self.ledger(fence)
        doc = w._read() or {}
        known = {entry.entry_ref for entry in ledger.entries()}
        added = 0
        for key, row in doc.get("entries", {}).items():
            if row["phase"] != "resumed" or key not in doc.get("handoffs", {}):
                continue
            handoff = doc["handoffs"][key]
            contract = implementation_contract(handoff["package"]["work_packets"][0]["capability_gap"])
            entry_ref = "cap-"+stable_digest({"key": key, "task": row["request"]["dependencies"]})[:48]
            if entry_ref in known:
                continue
            if added >= 8:
                break
            try:
                ledger.record_observational_learning(entry_ref=entry_ref, lever="sdk-capability-use", metric_name="workflow_completion",
                    claim="The owning business workflow completed a step after verified capability installation; no conversion or revenue uplift is inferred.",
                    recorded_at=now, evidence_digests=[stable_digest(row), contract])
            except ValueError as error:
                if str(error) not in {"CAPABILITY_LEARNING_CAPACITY", "CAPABILITY_WAIT_JOURNAL_FULL"}:
                    raise
                return {"added": added, "pending": True, "reason": "learning_archive_required"}
            known.add(entry_ref)
            added += 1
        return {"added": added, "pending": added == 8}

    def record_experiment(self, domain, target_ref, *, design, readout, now, fence):
        key, w = self.waits._key(domain, target_ref), self.waits
        doc = w._read() or {}
        row = doc.get("handoffs", {}).get(key)
        wait = doc.get("entries", {}).get(key)
        if not row or not wait or wait["phase"] != "resumed":
            raise ValueError("CAPABILITY_HANDOFF_REQUIRED")
        ledger = self.ledger(fence)
        # Existing ledger verifies exact-scope seals and matching causal readout/design.
        contract = implementation_contract(row["package"]["work_packets"][0]["capability_gap"])
        from lightbulb.growth_experiments import verify_growth_experiment_design, verify_growth_experiment_readout
        d = verify_growth_experiment_design(design, scope=w.gateway.authority_scope, scope_keyring=w.gateway.keyring)
        r = verify_growth_experiment_readout(readout, scope=w.gateway.authority_scope, scope_keyring=w.gateway.keyring)
        if not wait.get("started_at") or parsed(d.exposure_start) < parsed(wait["started_at"]):
            raise ValueError("CAPABILITY_EXPERIMENT_PREDATES_USE")
        if parsed(now) < parsed(r.analysis_as_of):
            raise ValueError("CAPABILITY_LEARNING_FROM_FUTURE")
        ref = "exp-"+stable_digest({"contract": contract, "readout": r.readout_digest})[:48]
        existing = next((e for e in ledger.entries() if e.entry_ref == ref), None)
        entry = existing or ledger.record_experiment_learning(design=d, readout=r, entry_ref=ref, lever="sdk-capability-use",
            claim="Scoped experiment readout associated with this reviewed SDK capability change.", recorded_at=now)
        def link(doc):
            rows = dict(doc.get("capability_experiments", {}))
            if len(rows) >= 128 and entry.entry_digest not in rows:
                raise ValueError("CAPABILITY_EXPERIMENT_CAPACITY")
            rows[entry.entry_digest] = {"contract_digest": contract, "mapping_basis": "operator_attested"}
            doc["capability_experiments"] = rows
        w._change(link, fence)
        return entry

    def history(self, contract_digest):
        doc = self.waits._read() or {}
        reviews = [r for r in doc.get("implementation_reviews", {}).values() if r["contract_digest"] == contract_digest]
        links = doc.get("capability_experiments", {})
        experiments = [e for e in self.ledger(lambda: None).entries() if links.get(e.entry_digest, {}).get("contract_digest") == contract_digest]
        uses = [e for e in self.ledger(lambda: None).entries() if e.grade == "observational" and contract_digest in e.evidence_digests]
        return {"completed_uses": len(uses), "reviewed_effort_minutes": max((r["review"]["actual_effort_minutes"] for r in reviews), default=None),
            "cost_basis": "operator_attested", "experimental_findings": [{"entry_digest": e.entry_digest, "recorded_at": e.recorded_at,
                "metric_name": e.metric_name, "effect_estimate": str(e.effect_estimate), "ci_low": str(e.ci_low), "ci_high": str(e.ci_high),
                "mapping_basis": "operator_attested"} for e in experiments]}

    def report(self):
        doc = self.waits._read() or {}
        rows = []
        for key, review in doc.get("implementation_reviews", {}).items():
            estimate = review.get("estimate")
            rows.append({"contract_digest": review["contract_digest"], "actual_effort_minutes": review["review"]["actual_effort_minutes"],
                "actual_cost_minor": review["review"]["actual_cost_minor"], "currency": review["review"]["currency"],
                "estimated_effort_minutes": estimate.get("effort_minutes") if estimate else None,
                "estimated_value_minor": estimate.get("expected_value_minor") if estimate else None,
                "estimated_currency": estimate.get("currency") if estimate else None,
                "basis": "operator_attested_cost", "observed_revenue_uplift": None})
        return {"schema": "lightbulb.capability_learning.v1", "implementation_reviews": rows,
            "learning_entries": len(self.ledger(lambda: None).entries()), "causal_revenue_assumed": False}
