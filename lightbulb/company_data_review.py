"""Company source census and append-only historical correction holds.

Only the trusted host writes through AuthenticatedCheckpointGateway. These
records neither grant provider authority nor attest external completeness.
Corrections invalidate future budget use before replacement work begins.
"""
from __future__ import annotations

from typing import Literal
from pydantic import Field, model_validator, field_validator
from lightbulb.company_engine_core import StrictModel, OpaqueRef, Sha256Digest, timestamp, stable_digest, detached
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway


class CompanySourceAccount(StrictModel):
    account_ref: OpaqueRef
    category: Literal["bank", "payments", "advertising", "payroll", "vendor", "custody", "customer_history", "other"]
    source_refs: tuple[OpaqueRef, ...] = ()
    reconciliation: Literal["unknown", "missing", "partial", "reconciled"] = "unknown"
    evidence_refs: tuple[OpaqueRef, ...] = ()

    @model_validator(mode="after")
    def evidence(self):
        if self.reconciliation == "reconciled" and not self.evidence_refs:
            raise ValueError("RECONCILIATION_EVIDENCE_REQUIRED")
        if len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("SOURCE_REPEATED")
        return self


class CompanySourceCensus(StrictModel):
    census_ref: OpaqueRef
    period_start: str
    period_end: str
    accounts: tuple[CompanySourceAccount, ...] = Field(min_length=1, max_length=1000)
    operator_attests_account_inventory: bool = False
    attestation_evidence_ref: OpaqueRef | None = None

    @field_validator("period_start", "period_end")
    @classmethod
    def stamps(cls, value):
        return timestamp(value, field_name="census_window")

    @model_validator(mode="after")
    def bound(self):
        from lightbulb.company_engine_core import parsed
        if parsed(self.period_start) >= parsed(self.period_end):
            raise ValueError("CENSUS_WINDOW_INVALID")
        if len({a.account_ref for a in self.accounts}) != len(self.accounts):
            raise ValueError("CENSUS_ACCOUNT_REPEATED")
        if self.operator_attests_account_inventory and not self.attestation_evidence_ref:
            raise ValueError("OPERATOR_ATTESTATION_EVIDENCE_REQUIRED")
        return self


def assess_source_census(census, *, configured_source_refs):
    """Separate operator assertions, declared coverage and independent proof."""
    census = CompanySourceCensus.model_validate(detached(census))
    declared = {s for a in census.accounts for s in a.source_refs}
    configured = set(configured_source_refs)
    unresolved = [a.account_ref for a in census.accounts if a.reconciliation != "reconciled"]
    return {"schema": "lightbulb.company_source_coverage.v1", "census_digest": stable_digest(census.to_dict()),
            "operator_attests_account_inventory": census.operator_attests_account_inventory,
            "external_liabilities_proven_complete": False, "reconciliation_basis": "operator_evidence_references",
            "unresolved_accounts": unresolved, "unconfigured_sources": sorted(declared - configured),
            "unregistered_sources": sorted(configured - declared),
            "declared_coverage_reviewed": not unresolved and declared == configured and census.operator_attests_account_inventory}


class HistoricalCorrection(StrictModel):
    correction_ref: OpaqueRef
    affected_period_ref: OpaqueRef
    replacement_period_ref: OpaqueRef
    kind: Literal["late_events", "provider_revision", "identity_mapping", "cost_reversal"]
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    original_configuration_digest: Sha256Digest
    replacement_configuration_digest: Sha256Digest
    recorded_at: str

    @field_validator("recorded_at")
    @classmethod
    def stamp(cls, value):
        return timestamp(value, field_name="recorded_at")

    @model_validator(mode="after")
    def distinct(self):
        if self.affected_period_ref == self.replacement_period_ref or self.original_configuration_digest == self.replacement_configuration_digest:
            raise ValueError("CORRECTION_REQUIRES_NEW_OPERATION")
        return self


def _trusted(gateway):
    if not isinstance(gateway, AuthenticatedCheckpointGateway):
        raise ValueError("AUTHENTICATED_HOST_JOURNAL_REQUIRED")


def record_source_census(gateway, census, *, configured_source_refs):
    """Retain an immutable operator census under the authenticated host scope."""
    _trusted(gateway)
    census = CompanySourceCensus.model_validate(detached(census))
    assessment = assess_source_census(census, configured_source_refs=configured_source_refs)
    ref = "company-source-census-" + census.census_ref
    old = gateway.get(ref)
    if old is not None:
        if old.get("census") != census.to_dict() or old.get("assessment") != assessment:
            raise ValueError("CENSUS_CHANGED_USE_NEW_REFERENCE")
        return old
    return gateway.put(ref, {"schema": "lightbulb.company_source_census_checkpoint.v1", "status": "completed", "resume_at": None,
                             "census": census.to_dict(), "assessment": assessment}, expected_revision=0)


def correction_hold(gateway, period_ref):
    """Read the exact-scope hold; never trust caller-provided readiness flags."""
    _trusted(gateway)
    return gateway.get("company-period-correction-" + period_ref)


def record_correction(gateway, correction):
    """Atomically retain a permanent hold before recomputation; replay is exact.

The replacement runs normal source ingestion and period acceptance under a new
configuration identity. Original observations, approvals and effects remain.
"""
    _trusted(gateway)
    correction = HistoricalCorrection.model_validate(detached(correction))
    document = correction.to_dict()
    ref = "company-period-correction-" + correction.affected_period_ref
    old = gateway.get(ref)
    if old is not None:
        if old.get("correction") != document:
            raise ValueError("CORRECTION_ALREADY_RECORDED")
        return old
    period = gateway.get("company-growth-period-" + correction.affected_period_ref)
    if period is None or period.get("configuration_digest") != correction.original_configuration_digest:
        raise ValueError("CORRECTION_SOURCE_MISMATCH")
    return gateway.put(ref, {"schema": "lightbulb.company_period_correction.v1", "status": "blocked", "resume_at": None,
                           "correction": document, "eligible_for_budget_decisions": False}, expected_revision=0)
