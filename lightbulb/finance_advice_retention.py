"""Retention: how long an advice record and the evidence under it are kept, as a sealed policy the store applies.

Advice records are kept for years after the advice is given; the exact period is the operator's
obligation under their licence and is set here as an operator-confirmed number, not a claim the
SDK makes about the law. The default is seven years for both jurisdictions, which is the period
Australian and Canadian operators commonly work to; the operator confirms it with counsel and
changes it per jurisdiction if their obligation differs. Nothing in the advice store deletes a
record, an approval, a quote capture or an observation; the policy says when a record may leave
active retention, and the platform's operator does the leaving, by hand, after that date.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, StrictModel, parsed, seal, sealed_digest, skip_digests, timestamp

RETENTION_SCHEMA = "lightbulb.finance_advice_retention_policy.v1"
DEFAULT_RETENTION_YEARS: dict[str, int] = {"AU": 7, "CA": 7}
DEFAULT_BASIS = "operator-confirmed default; the operator confirms the statutory period for their licence with counsel"
RETAINED_KINDS: tuple[str, ...] = ("advice_case", "adviser_approval", "record_of_advice_evidence", "advice_document", "quote_capture", "observation", "proposed_change_decision", "check_receipt", "fact_change_event", "engagement_pack", "acknowledgement", "fee_arrangement", "risk_profile", "strategy_plan", "serviceability", "compliance_checklist", "authority_verification", "remuneration_schedule", "conflicts_register", "remuneration_disclosure", "prose_draft", "client_explanation", "grounded_answer", "application_pack", "provider_write_proposal", "provider_outcome", "terms_reconciliation", "state_diff", "review_assessment", "review_calendar", "holistic_plan", "case_run")


RETAINED_KINDS = (*RETAINED_KINDS, "tax_estimate", "retirement_projection", "supervision_file", "complaint_file", "advice_decision")


class RetentionPolicy(StrictModel):
    """One jurisdiction's retention period and the kinds it applies to, sealed."""

    schema_id: Literal["lightbulb.finance_advice_retention_policy.v1"] = RETENTION_SCHEMA
    jurisdiction: Literal["AU", "CA"]
    years: int = Field(ge=1, le=50)
    basis: str = Field(min_length=1)
    retained_kinds: tuple[str, ...] = RETAINED_KINDS
    deletion: Literal["never_by_the_platform"] = "never_by_the_platform"
    confirmed_by_ref: str | None = None
    confirmed_at: str | None = None
    policy_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> RetentionPolicy:
        if not skip_digests(info) and self.policy_digest != sealed_digest(RetentionPolicy, self, "policy_digest"):
            raise ValueError("policy_digest does not match the policy")
        return self


def retention_policy(jurisdiction: str, *, years: int | None = None, basis: str | None = None, confirmed_by_ref: str | None = None, confirmed_at: str | None = None) -> RetentionPolicy:
    """The policy for a jurisdiction: the default years unless the operator sets and confirms another number."""
    if jurisdiction not in DEFAULT_RETENTION_YEARS:
        raise ValueError(f"no default retention for {jurisdiction}")
    return seal(RetentionPolicy, {"jurisdiction": jurisdiction, "years": years if years is not None else DEFAULT_RETENTION_YEARS[jurisdiction], "basis": basis or DEFAULT_BASIS, "confirmed_by_ref": confirmed_by_ref, "confirmed_at": timestamp(confirmed_at, field_name="confirmed_at") if confirmed_at else None}, "policy_digest")


def retain_until(prepared_at: str, policy: RetentionPolicy | Mapping[str, Any]) -> str:
    """The date active retention ends: the record's date plus the policy's years, as an ISO date."""
    p = policy if isinstance(policy, RetentionPolicy) else RetentionPolicy.model_validate(dict(policy))
    when = parsed(timestamp(prepared_at, field_name="prepared_at"))
    year = when.year + p.years
    try:
        end = date(year, when.month, when.day)
    except ValueError:
        end = date(year, when.month, 28)
    return end.isoformat()


def retention_label(record: Mapping[str, Any] | Any, policy: RetentionPolicy | Mapping[str, Any]) -> dict[str, Any]:
    """What the store writes beside a record: the policy digest and the date active retention ends."""
    p = policy if isinstance(policy, RetentionPolicy) else RetentionPolicy.model_validate(dict(policy))
    prepared_at = record["prepared_at"] if isinstance(record, Mapping) else getattr(record, "prepared_at")
    return {"policy_digest": p.policy_digest, "jurisdiction": p.jurisdiction, "years": p.years, "retain_until": retain_until(prepared_at, p), "deletion": p.deletion}


RETENTION_MANIFEST: dict[str, Any] = {
    "schema": RETENTION_SCHEMA,
    "default_years": dict(DEFAULT_RETENTION_YEARS),
    "basis": DEFAULT_BASIS,
    "retained_kinds": list(RETAINED_KINDS),
    "deletion": "the platform exposes no delete path for advice records; leaving retention is the operator's act after the date",
    "not_claimed": "the years are the operator's confirmed number, not the SDK's reading of the law",
}

__all__ = ["DEFAULT_BASIS", "DEFAULT_RETENTION_YEARS", "RETAINED_KINDS", "RETENTION_MANIFEST", "RETENTION_SCHEMA", "RetentionPolicy", "retain_until", "retention_label", "retention_policy"]
