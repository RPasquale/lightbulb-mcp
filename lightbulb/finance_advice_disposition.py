"""Non-replacement case outcomes, proposed by one person and approved by another.

Retaining a product requires a complete, sealed stay comparison. Referral and
deferral preserve unresolved questions without turning them into a recommendation.
Every outcome has a follow-up date and an attributable supporting document.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel
from lightbulb.finance_advice_decision import AdviceDecision
from lightbulb.finance_advice_engine import AdvicePlan, ClientState


class AdviceDisposition(AdviceIdentityModel):
    schema_id: Literal["lightbulb.finance_advice_disposition.v1"] = Field(default="lightbulb.finance_advice_disposition.v1", alias="schema")
    case_ref: OpaqueRef
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    client_ref: OpaqueRef
    verification_digest: Sha256Digest
    outcome: Literal["retain_current", "refer", "defer"]
    decision_digest: Sha256Digest | None = None
    reason: str = Field(min_length=8, max_length=1200)
    referral_ref: OpaqueRef | None = None
    evidence_ref: OpaqueRef
    follow_up_at: str
    prepared_at: str
    prepared_by_ref: OpaqueRef
    disposition_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _validate(self, info: ValidationInfo) -> AdviceDisposition:
        if parsed(timestamp(self.follow_up_at, field_name="follow_up_at")) <= parsed(timestamp(self.prepared_at, field_name="prepared_at")):
            raise ValueError("FOLLOW_UP_INVALID: follow-up must be after this proposal")
        if self.outcome == "refer" and not self.referral_ref:
            raise ValueError("REFERRAL_ABSENT: identify the referral by an opaque reference")
        if self.outcome == "retain_current" and not self.decision_digest:
            raise ValueError("RETAIN_EVIDENCE_ABSENT: retaining requires a complete stay comparison")
        if not skip_digests(info) and self.disposition_digest != sealed_digest(AdviceDisposition, self, "disposition_digest"):
            raise ValueError("DISPOSITION_SEAL_INVALID: the disposition must match its seal")
        return self


def prepare_disposition(*, case_ref: str, plan: AdvicePlan, state: ClientState,
                        outcome: str, reason: str, evidence_ref: str, follow_up_at: str,
                        prepared_at: str, prepared_by_ref: str, verification_digest: str, referral_ref: str | None = None,
                        decision: Mapping[str, Any] | None = None) -> AdviceDisposition:
    decision_digest = None
    if outcome == "retain_current":
        comparison = AdviceDecision.model_validate(decision or {})
        if (comparison.case_ref, comparison.plan_digest, comparison.state_digest, comparison.outcome) != (
                case_ref, plan.plan_digest, state.state_digest, "retain_current") or comparison.missing:
            raise ValueError("RETAIN_EVIDENCE_MISMATCH: retaining requires this case's complete stay comparison")
        decision_digest = comparison.decision_digest
    return seal(AdviceDisposition, dict(case_ref=case_ref, plan_digest=plan.plan_digest,
                state_digest=state.state_digest, client_ref=state.client_ref, verification_digest=verification_digest, outcome=outcome, decision_digest=decision_digest,
                reason=reason, evidence_ref=evidence_ref, follow_up_at=follow_up_at,
                prepared_at=prepared_at, prepared_by_ref=prepared_by_ref, referral_ref=referral_ref), "disposition_digest")


def propose_disposition(runtime: Any, disposition: AdviceDisposition) -> Any:
    from lightbulb.finance_advice_cases import advance_case
    current = runtime.load(disposition.case_ref)
    if (current.plan_digest != disposition.plan_digest or current.ledger.client_ref != disposition.client_ref
            or (current.ledger.state_digest is not None and current.ledger.state_digest != disposition.state_digest)):
        raise ValueError("DISPOSITION_STALE: the client's current facts and plan must match")
    if current.status == "disposition_pending" and current.ledger.disposition_digest == disposition.disposition_digest:
        return current
    return advance_case(runtime, disposition.case_ref, event="propose_disposition", receipt={
        "disposition_digest": disposition.disposition_digest, "state_digest": disposition.state_digest, "client_ref": disposition.client_ref,
        "disposition_outcome": disposition.outcome, "next_review_due_at": disposition.follow_up_at,
        "evidence_refs": [disposition.evidence_ref]}, occurred_at=disposition.prepared_at,
        actor_ref=disposition.prepared_by_ref, reason=disposition.reason)


def request_disposition_approval(runtime: Any, disposition: AdviceDisposition, *, authority: Any,
                                 verification: Mapping[str, Any]) -> Any:
    from lightbulb.finance_advice_cases import advance_case
    from lightbulb.finance_advice_licence import AuthorityVerification
    proof = AuthorityVerification.model_validate(dict(detached(verification)))
    current = runtime.load(disposition.case_ref)
    if (current.ledger.disposition_digest != disposition.disposition_digest
            or current.ledger.state_digest != disposition.state_digest
            or proof.verification_digest != disposition.verification_digest
            or proof.verdict != "verified" or proof.authority_ref_sha256 != authority.authority_ref_sha256):
        raise ValueError("DISPOSITION_APPROVAL_MISMATCH: this exact disposition requires verified authority")
    return advance_case(runtime, disposition.case_ref, event="resolve_disposition", receipt={
        "disposition_digest": disposition.disposition_digest, "verification_digest": proof.verification_digest,
        "adviser_ref": authority.holder_ref, "authority_kind": authority.kind,
        "authority_ref_sha256": authority.authority_ref_sha256, "approved_at": disposition.prepared_at,
        "evidence_refs": [disposition.evidence_ref]}, occurred_at=disposition.prepared_at,
        actor_ref=disposition.prepared_by_ref, summary=f"Adviser approval to {disposition.outcome.replace('_', ' ')}: {disposition.case_ref}")
