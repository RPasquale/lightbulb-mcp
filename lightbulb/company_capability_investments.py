"""Transparent prioritization over explicitly accessible company journals."""
from __future__ import annotations

from collections import defaultdict
from pydantic import BaseModel, ConfigDict, Field, field_validator
from lightbulb.company_engine_core import stable_digest, parsed, timestamp


class CapabilityValueEstimate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    opportunity_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,119}$")
    review_ref: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,119}$")
    expected_value_minor: int = Field(ge=0, le=10**12, strict=True)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    effort_minutes: int = Field(ge=1, le=1000000, strict=True)
    confidence_bps: int = Field(ge=0, le=10000, strict=True)
    urgency: int = Field(default=1, ge=1, le=3, strict=True)
    expires_at: str

    @field_validator("expires_at")
    @classmethod
    def deadline(cls, value):
        return timestamp(value, field_name="expires_at")


def estimate_capability(waits, domain, target_ref, estimate, *, fence):
    value = CapabilityValueEstimate.model_validate(estimate)
    parsed(value.expires_at)
    key = waits._key(domain, target_ref)
    def retain(doc):
        if key not in doc.get("handoffs", {}):
            raise ValueError("CAPABILITY_ESTIMATE_HANDOFF_REQUIRED")
        rows = dict(doc.get("value_estimates", {}))
        rows[key] = value.model_dump(mode="json")
        doc["value_estimates"] = rows
    waits._change(retain, fence)
    return value


def rank_capability_investments(workers, *, now):
    """No company discovery, data fetch outside each scoped gateway, or build authority.

    Compatible means exact matching implementation requirements, not semantic equivalence.
    Scores are confidence-adjusted estimated value per hour with an explicit urgency factor.
    """
    if not isinstance(workers, (tuple, list)) or not 1 <= len(workers) <= 64:
        raise ValueError("CAPABILITY_PORTFOLIO_BOUNDED_WORKERS_REQUIRED")
    identities, groups, seen_workers = set(), defaultdict(list), set()
    histories = defaultdict(list)
    for waits in workers:
        from lightbulb.company_capability_waits import CompanyCapabilityWaits
        if not isinstance(waits, CompanyCapabilityWaits):
            raise ValueError("AUTHENTICATED_CAPABILITY_WORKER_REQUIRED")
        authority = waits.gateway.authority_scope
        identities.add((str(authority.tenant_id), str(authority.user_id)))
        if len(identities) != 1:
            raise ValueError("CAPABILITY_PORTFOLIO_ACTOR_SCOPE_MISMATCH")
        # Each gateway performs its existing authenticated company/project read.
        doc = waits._read() or {}
        worker_identity = stable_digest({"scope": waits.runner.bundle.scope, "authority": authority.model_dump(mode="json")})
        if worker_identity in seen_workers:
            continue
        seen_workers.add(worker_identity)
        from lightbulb.company_capability_learning import implementation_contract
        contracts = {implementation_contract(r["package"]["work_packets"][0]["capability_gap"]) for r in doc.get("handoffs", {}).values()}
        for contract in contracts:
            histories[contract].append(waits.learning.history(contract))
        for key, row in doc.get("handoffs", {}).items():
            if row["phase"] in {"cancelled", "expired", "needs_review"} or parsed(row["expires_at"]) <= parsed(now):
                continue
            wait = doc.get("entries", {}).get(key)
            if wait and wait["phase"] in {"resumed", "cancelled", "expired", "needs_review"}:
                continue
            gap = row["package"]["work_packets"][0]["capability_gap"]
            contract = stable_digest({"capability_ref": gap["capability_ref"], "missing_behavior": gap["missing_behavior"],
                "acceptance_criteria": sorted(gap["acceptance_criteria"]), "target_files": sorted(gap["target_files"])})
            estimate = doc.get("value_estimates", {}).get(key)
            if estimate and parsed(estimate["expires_at"]) <= parsed(now):
                estimate = None
            groups[(gap["capability_ref"], contract, estimate["currency"] if estimate else None)].append((str(authority.company_id), key, estimate))
    ranking = []
    for (capability, contract, currency), rows in groups.items():
        opportunities = {}
        conflicts = False
        for company, _, estimate in rows:
            if estimate:
                key = (company, estimate["opportunity_ref"])
                if key in opportunities and opportunities[key] != estimate:
                    conflicts = True
                else:
                    opportunities[key] = estimate
        estimates = list(opportunities.values())
        # Conflicting claims about the same opportunity require review, never choose the optimistic value.
        effort_floor = max((h["reviewed_effort_minutes"] or 0 for h in histories[contract]), default=0)
        effective_effort = max([effort_floor, *(e["effort_minutes"] for e in estimates)])
        score = None if not estimates or conflicts else round(sum(e["expected_value_minor"] * e["confidence_bps"] * e["urgency"] for e in estimates) * 60 / (10000 * effective_effort), 4)
        ranking.append({"capability_ref": capability, "implementation_contract_digest": contract,
            "business_count": len({r[0] for r in rows}), "blocked_work_count": len(rows), "currency": currency,
            "estimated_value_minor": sum(e["expected_value_minor"] for e in estimates) if not conflicts and estimates else None,
            "estimated_effort_minutes": max(e["effort_minutes"] for e in estimates) if estimates else None,
            "estimated_opportunity_count": len(estimates),
            "effective_effort_minutes": effective_effort or None,
            "completed_uses": sum(h["completed_uses"] for h in histories[contract]),
            "experimental_findings": [e for h in histories[contract] for e in h["experimental_findings"]],
            "learning_basis": "reviewed_effort_floor_no_assumed_revenue_uplift",
            "confidence_bps_range": [min(e["confidence_bps"] for e in estimates), max(e["confidence_bps"] for e in estimates)] if estimates else None,
            "maximum_urgency": max(e["urgency"] for e in estimates) if estimates else None,
            "priority_score": score, "score_basis": "confidence_adjusted_estimated_minor_per_hour_times_urgency",
            "review_required": True, "estimate_conflict": conflicts, "execution_authorized": False})
    return {"schema": "lightbulb.capability_investments.v1", "currency_comparison": "separate_no_fx_conversion",
        "recommendations": sorted(ranking, key=lambda r: (r["currency"] or "~", r["priority_score"] is None, -(r["priority_score"] or 0), r["capability_ref"], r["implementation_contract_digest"]))}
