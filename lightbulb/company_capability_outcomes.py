"""Observed owner results linked to resumed work, without causal revenue claims."""
from __future__ import annotations

from lightbulb.company_engine_core import parsed, stable_digest


class CompanyCapabilityOutcomes:
    def __init__(self, waits):
        self.waits = waits

    def track_sales_source(self, ref, value, old, *, fence):
        """Retain the pointer before the owner commits, so replay cannot lose the link."""
        w = self.waits
        if not w.sales:
            return
        kind = None
        occurred = None
        if value.get("phase") == "booked" and value.get("verified") and (old or {}).get("phase") != "booked":
            kind, occurred = "meeting_booked", value["verified"]["receipt"]["completed_at"]
        elif value.get("report", {}).get("invoice_observation_digest"):
            kind, occurred = "payment_observed", value["report"]["payment_observed_at"]
        if kind is None:
            return
        binding_digest = value.get("binding_digest")
        if not binding_digest:
            return
        matches = []
        for key, row in (w._read() or {}).get("entries", {}).items():
            request = row["request"]
            if request["domain"] != "sales" or not row.get("started_at") or parsed(occurred) < parsed(row["started_at"]):
                continue
            binding = w.sales.progression.binding(request["inputs"]["binding_ref"])
            if stable_digest(binding.to_dict()) == binding_digest:
                matches.append(key)
        if not matches:
            return
        def track(doc):
            sources = dict(doc.get("outcome_sources", {}))
            identity = stable_digest({"kind": kind, "source_ref": ref})
            if identity not in sources and len(sources) >= 256:
                raise ValueError("CAPABILITY_OUTCOME_CAPACITY")
            prior = sources.get(identity, {})
            sources[identity] = {"kind": kind, "source_ref": ref, "binding_digest": binding_digest,
                "wait_keys": sorted(set(prior.get("wait_keys", [])) | set(matches))}
            doc["outcome_sources"] = sources
        w._change(track, fence)

    def report(self):
        w = self.waits
        doc = w._read() or {}
        observations = []
        for key, row in doc.get("entries", {}).items():
            if row["phase"] == "resumed":
                observations.append({"observation_ref": stable_digest({"wait": key, "kind": "owner_step_completed"}),
                    "kind": "draft_prepared" if row["request"]["domain"] == "sales" else "workflow_step_completed",
                    "wait_refs": [row["request"]["wait_ref"]], "domain": row["request"]["domain"],
                    "observed_at": row.get("completed_at"), "count": 1, "causal_attribution_verified": False})
        if w.sales:
            for identity, pointer in doc.get("outcome_sources", {}).items():
                source = w.sales.progression.read(pointer["source_ref"])
                if not source or source.get("binding_digest") != pointer["binding_digest"]:
                    continue
                linked = [doc["entries"][k] for k in pointer["wait_keys"] if k in doc.get("entries", {}) and doc["entries"][k]["phase"] == "resumed"]
                if not linked:
                    continue
                item = {"observation_ref": identity, "kind": pointer["kind"], "domain": "sales",
                    "wait_refs": sorted(r["request"]["wait_ref"] for r in linked), "causal_attribution_verified": False,
                    "evidence_digest": stable_digest(source)}
                if pointer["kind"] == "meeting_booked" and source.get("phase") == "booked":
                    item.update(count=1, observed_at=source["verified"]["receipt"]["completed_at"])
                elif pointer["kind"] == "payment_observed" and "report" in source:
                    report = source["report"]
                    item.update(observed_paid_minor=report["observed_paid_minor"], currency=report["currency"],
                        observed_at=report["payment_observed_at"], revenue_verified=False, settlement_verified=False,
                        measure="latest_cumulative_invoice_observation")
                else:
                    continue
                # A source pointer may precede an unsuccessful owner CAS. Compare the committed
                # observation time again so old evidence cannot be linked to a newer resume.
                item["wait_refs"] = sorted(r["request"]["wait_ref"] for r in linked
                    if r.get("started_at") and parsed(item["observed_at"]) >= parsed(r["started_at"]))
                if item["wait_refs"]:
                    observations.append(item)
        # One source observation may link several capabilities, but appears only once.
        return {"schema": "lightbulb.capability_outcomes.v1", "observations": observations,
            "causal_attribution_verified": False, "estimated_time_saved_is_observed": False}
