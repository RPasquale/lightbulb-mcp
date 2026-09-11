"""Coordinate billing reminders without owning email or Stripe settings.

Policies are trusted business configuration. Stripe dashboard setup is an
operator attestation, never provider verification. The common follow-up host
must validate a decision again before requesting the exact governed send.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from lightbulb.company_engine_core import (
    CurrencyCode, OpaqueRef, Sha256Digest, StrictModel, detached, parsed,
    reject_secret_like_payload, stable_digest, timestamp,
)
from lightbulb.company_hosted_scheduler import CheckpointConflict

DECISION_SCHEMA = "lightbulb.billing_followup_decision.v1"
STOP_SCHEMA = "lightbulb.billing_followup_stop.v1"


class BillingFollowupError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise BillingFollowupError(code)


def _safe_ref(value: str) -> str:
    _require(not any(char in value for char in ("/", "@"))
             and not value.lower().startswith(("http:", "https:", "javascript:", "data:")),
             "BILLING_FOLLOWUP_REFERENCE_INVALID")
    reject_secret_like_payload(value)
    return value


class StripeReminderSetupAttestation(StrictModel):
    """Operator-reviewed dashboard coverage, including custom Billing automations."""
    attestation_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    attested_by: OpaqueRef
    attested_at: str
    expires_at: str
    failed_payment_emails: bool
    unpaid_invoice_reminders: bool
    custom_billing_automations: bool

    @field_validator("attestation_ref", "connector_account_ref", "attested_by")
    @classmethod
    def _refs(cls, value):
        return _safe_ref(value)

    @field_validator("attested_at", "expires_at")
    @classmethod
    def _times(cls, value, info):
        return timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _bounded(self):
        seconds = (parsed(self.expires_at) - parsed(self.attested_at)).total_seconds()
        _require(0 < seconds <= 90 * 86400, "BILLING_SETUP_ATTESTATION_WINDOW_INVALID")
        return self

    @property
    def native_reminders_enabled(self):
        return self.failed_payment_emails or self.unpaid_invoice_reminders or self.custom_billing_automations


class BillingRecoveryPolicy(StrictModel):
    schema_id: Literal["lightbulb.billing_recovery_policy.v1"] = Field(default="lightbulb.billing_recovery_policy.v1", alias="schema")
    policy_ref: OpaqueRef
    source_ref: OpaqueRef
    reminder_owner: Literal["stripe_native", "lightbulb_approved"]
    setup_attestation: StripeReminderSetupAttestation | None = None
    max_observation_age_seconds: int = Field(default=86400, ge=60, le=604800)

    @field_validator("policy_ref", "source_ref")
    @classmethod
    def _refs(cls, value):
        return _safe_ref(value)


class BillingFollowupDecision(StrictModel):
    schema_id: Literal["lightbulb.billing_followup_decision.v1"] = Field(default=DECISION_SCHEMA, alias="schema")
    followup_ref: OpaqueRef
    billing_binding_digest: Sha256Digest
    policy_ref: OpaqueRef
    policy_digest: Sha256Digest
    source_ref: OpaqueRef
    invoice_ref: OpaqueRef
    account_ref: OpaqueRef | None = None
    disposition: Literal["eligible", "native_owned", "blocked", "stopped"]
    reason: str = Field(min_length=1, max_length=100)
    evaluated_at: str
    observed_at: str | None = None
    observation_digest: Sha256Digest | None = None
    amount_remaining_minor: int | None = Field(default=None, ge=0)
    currency: CurrencyCode | None = None
    setup_verification: Literal["operator_attested", "not_attested"]
    provider_settings_verified: Literal[False] = False
    customer_action: Literal["use_original_stripe_invoice_email"] = "use_original_stripe_invoice_email"
    payment_link_status: Literal["unavailable_governed_tool"] = "unavailable_governed_tool"
    requires_approval: Literal[True] = True
    provider_effect_executed: Literal[False] = False


class CompanyBillingFollowupCoordinator:
    """Durable eligibility and irreversible stops over the existing billing journal.

    This coordinator does not send email, change settings, create payment
    links, or approve a send. Reply inputs come from the common host after its
    fresh scoped reply observation; recording one can only stop follow-up.
    """
    def __init__(self, recovery, policy):
        self.recovery = recovery
        self.policy = BillingRecoveryPolicy.model_validate(detached(policy))
        _require(self.policy.source_ref == recovery.source.source_ref, "BILLING_FOLLOWUP_SOURCE_MISMATCH")
        self.policy_digest = stable_digest(self.policy.to_dict())

    def _identity(self, invoice_ref):
        from pydantic import TypeAdapter
        invoice_ref = _safe_ref(TypeAdapter(OpaqueRef).validate_python(invoice_ref))
        return stable_digest({"binding": self.recovery.binding_digest, "invoice_ref": invoice_ref})

    def _read(self, ref, schema, invoice_ref):
        record = self.recovery.gateway.get(ref)
        if record is not None:
            _require(record.get("schema") == schema and record.get("binding") == self.recovery.binding
                     and record.get("invoice_ref") == invoice_ref, "BILLING_FOLLOWUP_JOURNAL_MISMATCH")
        return record

    def _stop(self, invoice_ref):
        return self._read("billing-followup-stop-" + self._identity(invoice_ref), STOP_SCHEMA, invoice_ref)

    def _record_stop(self, invoice_ref, *, reason, evidence_ref, now, fence):
        ref = "billing-followup-stop-" + self._identity(invoice_ref)
        prior = self._stop(invoice_ref)
        if prior is not None:
            return prior
        document = {"schema": STOP_SCHEMA, "status": "COMPLETED", "binding": self.recovery.binding,
                    "invoice_ref": invoice_ref, "reason": reason, "evidence_ref": evidence_ref, "stopped_at": now}
        try:
            return self.recovery._write(ref, document, None, fence)
        except CheckpointConflict:
            prior = self._stop(invoice_ref)
            if prior is None:
                raise
            return prior

    def record_reply(self, invoice_ref, *, evidence_ref, now, fence):
        """Persist a monotone stop after the common host's scoped reply check."""
        from pydantic import TypeAdapter
        evidence_ref = _safe_ref(TypeAdapter(OpaqueRef).validate_python(evidence_ref))
        at = timestamp(now, field_name="now")
        return self._record_stop(invoice_ref, reason="reply_received", evidence_ref=evidence_ref, now=at, fence=fence)

    def _facts(self, invoice_ref, now):
        snapshot = self.recovery.invoice_snapshot(invoice_ref)
        stop = self._stop(invoice_ref)
        if stop is not None:
            return snapshot, "stopped", stop["reason"]
        if snapshot is None:
            return None, "blocked", "invoice_not_observed"
        if not snapshot["present"]:
            return snapshot, "blocked", "invoice_absent_from_latest_page"
        row, observation = snapshot["invoice"], snapshot["observation"]
        if row["status"] in {"paid", "void", "uncollectible"}:
            return snapshot, "stopped", "invoice_" + row["status"]
        age = (parsed(now) - parsed(observation["observed_at"])).total_seconds()
        if age < 0 or age > self.policy.max_observation_age_seconds:
            return snapshot, "blocked", "invoice_observation_stale"
        if (row["status"] != "open" or row["amount_remaining_minor"] <= 0 or row.get("due_at") is None
                or parsed(row["due_at"]) >= parsed(observation["observed_at"])):
            return snapshot, "blocked", "invoice_not_overdue"
        setup = self.policy.setup_attestation
        if setup is None:
            return snapshot, "blocked", "reminder_coverage_unattested"
        if setup.connector_account_ref != snapshot["connector_account_ref"]:
            return snapshot, "blocked", "reminder_account_mismatch"
        if not parsed(setup.attested_at) <= parsed(now) < parsed(setup.expires_at):
            return snapshot, "blocked", "reminder_attestation_expired"
        if self.policy.reminder_owner == "stripe_native":
            return (snapshot, "native_owned", "stripe_native_reminders") if setup.native_reminders_enabled else (snapshot, "blocked", "native_reminders_not_enabled")
        if setup.native_reminders_enabled:
            return snapshot, "blocked", "native_reminders_still_enabled"
        return snapshot, "eligible", "lightbulb_followup_requires_approval"

    def evaluate(self, invoice_ref, *, now, fence):
        """Freeze a current invoice-bound proposal or a reason that prevents it."""
        at = timestamp(now, field_name="now")
        ref = "billing-followup-" + self._identity(invoice_ref)
        snapshot, disposition, reason = self._facts(invoice_ref, at)
        if disposition == "stopped" and self._stop(invoice_ref) is None:
            self._record_stop(invoice_ref, reason=reason, evidence_ref=snapshot["observation"]["observation_digest"], now=at, fence=fence)
        observation = snapshot["observation"] if snapshot else None
        row = snapshot["invoice"] if snapshot else None
        decision = BillingFollowupDecision(followup_ref=ref, billing_binding_digest=self.recovery.binding_digest,
            policy_ref=self.policy.policy_ref, policy_digest=self.policy_digest, source_ref=self.policy.source_ref,
            invoice_ref=invoice_ref, account_ref=snapshot["account_ref"] if snapshot else None,
            disposition=disposition, reason=reason, evaluated_at=at,
            observed_at=observation["observed_at"] if observation else None,
            observation_digest=observation["observation_digest"] if observation else None,
            amount_remaining_minor=row["amount_remaining_minor"] if row else None,
            currency=row["currency"] if row else None,
            setup_verification="operator_attested" if self.policy.setup_attestation else "not_attested")
        prior = self._read(ref, DECISION_SCHEMA, invoice_ref)
        comparison = decision.model_dump(exclude={"evaluated_at"})
        def matches(record):
            return record is not None and BillingFollowupDecision.model_validate(record["decision"]).model_dump(exclude={"evaluated_at"}) == comparison
        if matches(prior):
            return BillingFollowupDecision.model_validate(prior["decision"])
        document = {"schema": DECISION_SCHEMA, "status": "COMPLETED", "binding": self.recovery.binding,
                    "invoice_ref": invoice_ref, "policy": self.policy.to_dict(), "decision": decision.to_dict()}
        try:
            written = self.recovery._write(ref, document, prior, fence)
        except CheckpointConflict:
            written = self._read(ref, DECISION_SCHEMA, invoice_ref)
            if not matches(written):
                raise
        return BillingFollowupDecision.model_validate(written["decision"])

    def validate_current(self, decision, *, now):
        """Recheck the retained proposal immediately before an exact governed send."""
        decision = BillingFollowupDecision.model_validate(detached(decision))
        at = timestamp(now, field_name="now")
        _require(decision.policy_digest == self.policy_digest and decision.billing_binding_digest == self.recovery.binding_digest,
                 "BILLING_FOLLOWUP_POLICY_CHANGED")
        ref = "billing-followup-" + self._identity(decision.invoice_ref)
        _require(decision.followup_ref == ref, "BILLING_FOLLOWUP_IDENTITY_MISMATCH")
        prior = self._read(ref, DECISION_SCHEMA, decision.invoice_ref)
        _require(prior is not None and prior["decision"] == decision.to_dict(), "BILLING_FOLLOWUP_PROPOSAL_CHANGED")
        snapshot, disposition, _ = self._facts(decision.invoice_ref, at)
        _require(decision.disposition == disposition == "eligible", "BILLING_FOLLOWUP_NOT_ELIGIBLE")
        _require(snapshot["observation"]["observation_digest"] == decision.observation_digest
                 and snapshot["account_ref"] == decision.account_ref, "BILLING_FOLLOWUP_OBSERVATION_CHANGED")
        return decision


__all__ = ["StripeReminderSetupAttestation", "BillingRecoveryPolicy", "BillingFollowupDecision",
           "BillingFollowupError", "CompanyBillingFollowupCoordinator"]
