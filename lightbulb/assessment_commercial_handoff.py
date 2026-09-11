"""Bind a selected assessment offer to the existing pending-quote lifecycle.

Configuration validation and command-bound attestations must be supplied. This
module prepares the exact evidence challenge before those attestations exist;
it never manufactures evidence, approves a quote, taxes a sale or activates an
account. Commercial and optional engagement results remain SDK candidates.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from lightbulb.commercial_controls import CommercialConfigurationSnapshot, CommercialQuoteSnapshot
from lightbulb.commercial_operations_lifecycle import (
    GENESIS_SNAPSHOT_DIGEST,
    CommercialLifecycleScope,
    CommercialOperationsLifecycleInput,
    CommercialOperationsLifecycleResult,
    _exact_difference,
    _exact_sum,
    _money_product,
    _normalize_unordered_collections,
    _stable_digest,
    materialize_commercial_operations_candidate,
    seal_commercial_command,
)
from lightbulb.primitive_runtime import PrimitiveEvidenceRef
from lightbulb.productised_assessment import AssessmentBlocker, ProductisedAssessmentDossier
from lightbulb.service_engagement import (
    OpaqueRef,
    ServiceEngagementScope,
    ServiceEngagementSnapshot,
    ServiceEngagementTransitionInput,
    ServiceEngagementTransitionResult,
    Sha256Digest,
    _StrictModel,
    _detached,
    _parsed_timestamp,
    _timestamp,
    materialize_service_engagement_transition,
    genesis_engagement_state_digest,
    seal_service_engagement_command,
)


class AssessmentCommercialHandoffInput(_StrictModel):
    dossier: ProductisedAssessmentDossier
    offer_ref: OpaqueRef
    requested_by_ref: OpaqueRef
    prepared_at: str
    product_ref: OpaqueRef | None = None
    configuration: CommercialConfigurationSnapshot | None = None
    configuration_scope: CommercialLifecycleScope | None = None
    quote_ref: OpaqueRef | None = None
    configured_by_ref: OpaqueRef | None = None
    transition_ref: OpaqueRef | None = None
    idempotency_key: OpaqueRef | None = None
    configuration_evidence_ref: OpaqueRef | None = None
    pricing_evidence_ref: OpaqueRef | None = None
    tax_basis: Literal["exclusive", "inclusive", "unknown"] = "unknown"
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(default_factory=tuple, max_length=20)
    engagement_snapshot: ServiceEngagementSnapshot | None = None
    engagement_expected_version: int | None = Field(default=None, ge=0)
    engagement_expected_state_digest: Sha256Digest | None = None
    engagement_transition_ref: OpaqueRef | None = None
    engagement_idempotency_key: OpaqueRef | None = None

    @field_validator("prepared_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _identity(self) -> "AssessmentCommercialHandoffInput":
        source = self.dossier.inputs
        if self.requested_by_ref != source.requested_by_ref:
            raise ValueError("requesting actor must match the selected assessment dossier")
        if self.configuration is not None:
            if self.configuration.account_ref != source.scope.customer_ref:
                raise ValueError("configuration customer must match the assessment customer")
            if self.configuration.currency != source.scope.currency:
                raise ValueError("configuration currency must match the assessment currency")
        if self.configuration_scope is not None:
            for field in ("tenant_ref", "company_ref", "project_ref", "project_id", "customer_ref", "currency"):
                if str(getattr(self.configuration_scope, field)) != str(getattr(source.scope, field)):
                    raise ValueError("configuration scope must match the exact assessment company, project and customer")
            if self.product_ref is not None and self.configuration_scope.product_ref != self.product_ref:
                raise ValueError("configuration scope must match the explicitly selected product")
        if self.engagement_snapshot is not None and self.engagement_snapshot.scope != source.scope:
            raise ValueError("engagement snapshot must match the exact assessment scope")
        if len({item.evidence_ref for item in self.evidence_refs}) != len(self.evidence_refs):
            raise ValueError("attestation evidence references must be unique")
        return self


class AssessmentQuoteEvidenceChallenge(_StrictModel):
    """Unsigned command content for external attestation, never an executable input."""

    schema_id: Literal["lightbulb.assessment_quote_evidence_challenge.v1"] = Field(default="lightbulb.assessment_quote_evidence_challenge.v1", alias="schema")
    scope: CommercialLifecycleScope
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    requested_by_ref: OpaqueRef
    occurred_at: str
    configuration: CommercialConfigurationSnapshot
    quote: CommercialQuoteSnapshot
    configured_by_ref: OpaqueRef
    configuration_evidence_ref: OpaqueRef
    pricing_evidence_ref: OpaqueRef
    evidence_sha256: Sha256Digest
    executable: Literal[False] = False

    def command_content(self) -> dict[str, Any]:
        return _normalize_unordered_collections({
            "schema": "lightbulb.commercial_propose_quote_command.v1", "kind": "propose_quote",
            "scope": self.scope.to_dict(), "transition_ref": self.transition_ref,
            "idempotency_key": self.idempotency_key, "requested_by_ref": self.requested_by_ref,
            "expected_version": 0, "expected_snapshot_digest": GENESIS_SNAPSHOT_DIGEST,
            "occurred_at": self.occurred_at, "host_outcome_report": "reported_certain",
            "configuration": self.configuration.to_dict(), "quote": self.quote.to_dict(),
            "configured_by_ref": self.configured_by_ref,
            "configuration_evidence_ref": self.configuration_evidence_ref,
            "pricing_evidence_ref": self.pricing_evidence_ref,
        })

    @model_validator(mode="after")
    def _commitment(self) -> "AssessmentQuoteEvidenceChallenge":
        if self.evidence_sha256 != _stable_digest(self.command_content()):
            raise ValueError("evidence_sha256 must commit the exact normalized command content")
        if self.quote.status != "pending_approval" or self.quote.approval_status != "pending" or not self.quote.approval_required or self.quote.approved_by_ref is not None:
            raise ValueError("an assessment quote challenge must remain pending approval")
        return self


class AssessmentCommercialHandoff(_StrictModel):
    schema_id: Literal["lightbulb.assessment_commercial_handoff.v1"] = Field(default="lightbulb.assessment_commercial_handoff.v1", alias="schema")
    dossier_digest: Sha256Digest
    offer_ref: OpaqueRef
    offer_digest: Sha256Digest
    offer_kind: Literal["assessment", "implementation", "managed_monitoring", "software_access"]
    billing_period: Literal["one_off", "month", "year"]
    terms_ref: OpaqueRef | None = None
    scope: ServiceEngagementScope
    prepared_at: str
    status: Literal["blocked", "awaiting_attestations", "ready_for_commercial_review"]
    blockers: tuple[AssessmentBlocker, ...] = Field(default_factory=tuple, max_length=1600)
    evidence_challenge: AssessmentQuoteEvidenceChallenge | None = None
    commercial_input: CommercialOperationsLifecycleInput | None = None
    commercial_result: CommercialOperationsLifecycleResult | None = None
    engagement_input: ServiceEngagementTransitionInput | None = None
    engagement_result: ServiceEngagementTransitionResult | None = None
    primitive_ref: Literal["commercial.propose_operations_transition"] = "commercial.propose_operations_transition"
    engagement_primitive_ref: Literal["service.propose_engagement_transition"] = "service.propose_engagement_transition"
    persisted: Literal[False] = False
    quote_approved: Literal[False] = False
    tax_calculated: Literal[False] = False
    payment_collected: Literal[False] = False
    access_activated: Literal[False] = False
    handoff_digest: Sha256Digest

    @model_validator(mode="after")
    def _exact(self) -> "AssessmentCommercialHandoff":
        payload = self.to_dict()
        payload.pop("handoff_digest")
        if self.handoff_digest != _stable_digest(payload):
            raise ValueError("handoff_digest must commit the exact handoff")
        expected_status = "ready_for_commercial_review" if not self.blockers else "awaiting_attestations" if self.evidence_challenge is not None and self.commercial_input is None else "blocked"
        if self.status != expected_status:
            raise ValueError("status must reflect the exact blockers and executable input readiness")
        for scoped in (self.evidence_challenge, self.commercial_input):
            if scoped is not None:
                for field in ("tenant_ref", "company_ref", "project_ref", "project_id", "customer_ref", "currency"):
                    if str(getattr(scoped.scope, field)) != str(getattr(self.scope, field)):
                        raise ValueError("canonical quote scope must match the exact handoff scope")
        if (self.commercial_input is None) != (self.commercial_result is None):
            raise ValueError("canonical commercial input and result must be retained together")
        if (self.engagement_input is None) != (self.engagement_result is None):
            raise ValueError("canonical engagement input and result must be retained together")
        if self.commercial_input is not None:
            if self.commercial_input.command.kind != "propose_quote" or self.commercial_input.current_snapshot is not None:
                raise ValueError("the handoff may propose only the initial pending quote")
            if self.commercial_result.to_dict() != materialize_commercial_operations_candidate(self.commercial_input).to_dict():
                raise ValueError("commercial result must match its exact canonical input")
        if self.engagement_input is not None:
            if self.engagement_input.command.kind != "link_quote":
                raise ValueError("the handoff may only link an unapproved quote")
            if self.engagement_result.to_dict() != materialize_service_engagement_transition(self.engagement_input).to_dict():
                raise ValueError("engagement result must match its exact canonical input")
        return self


def _challenge(inputs: AssessmentCommercialHandoffInput, offer: Any) -> AssessmentQuoteEvidenceChallenge:
    configuration = inputs.configuration
    scope = CommercialLifecycleScope.model_validate({
        **{key: getattr(inputs.dossier.inputs.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "customer_ref", "currency")},
        "product_ref": inputs.product_ref,
    })
    quote = CommercialQuoteSnapshot.model_validate({
        "quote_ref": inputs.quote_ref or offer.pricing.quote_ref,
        "revision": 1, "configuration_ref": configuration.configuration_ref,
        "account_ref": scope.customer_ref, "status": "pending_approval", "currency": scope.currency,
        "valid_until": offer.pricing.valid_until, "subtotal": str(offer.pricing.total), "tax_total": "0", "total": str(offer.pricing.total),
        "approval_required": True, "approval_status": "pending", "prepared_by_ref": inputs.configured_by_ref,
        "lines": [{
            "quote_line_ref": "quote-line:" + _stable_digest({"quote_ref": inputs.quote_ref or offer.pricing.quote_ref, "configuration_line_ref": line.configuration_line_ref})[:32],
            "configuration_line_ref": line.configuration_line_ref, "product_ref": line.product_ref,
            "quantity": str(line.quantity), "unit_price": str(line.configured_unit_price),
            "line_total": str(_money_product(line.quantity, line.configured_unit_price)),
        } for line in configuration.lines],
        "evidence_refs": [inputs.pricing_evidence_ref],
    })
    payload = {
        "scope": scope.to_dict(), "transition_ref": inputs.transition_ref, "idempotency_key": inputs.idempotency_key,
        "requested_by_ref": inputs.requested_by_ref, "occurred_at": inputs.prepared_at,
        "configuration": configuration.to_dict(), "quote": quote.to_dict(), "configured_by_ref": inputs.configured_by_ref,
        "configuration_evidence_ref": inputs.configuration_evidence_ref, "pricing_evidence_ref": inputs.pricing_evidence_ref,
    }
    content = {
        **payload, "schema": "lightbulb.commercial_propose_quote_command.v1", "kind": "propose_quote",
        "expected_version": 0, "expected_snapshot_digest": GENESIS_SNAPSHOT_DIGEST, "host_outcome_report": "reported_certain",
    }
    payload["evidence_sha256"] = _stable_digest(_normalize_unordered_collections(content))
    return AssessmentQuoteEvidenceChallenge.model_validate(payload)


def _validation_blockers(exc: ValidationError, field: str) -> list[AssessmentBlocker]:
    return [AssessmentBlocker(code="CANONICAL_INPUT_INVALID", field=field, message=error["msg"][:500]) for error in exc.errors(include_input=False, include_url=False)[:20]]


def prepare_assessment_commercial_handoff(inputs: AssessmentCommercialHandoffInput | Mapping[str, Any]) -> AssessmentCommercialHandoff:
    """Prepare a pending quote after exact declared pricing and supplied attestations."""
    parsed = AssessmentCommercialHandoffInput.model_validate(_detached(inputs))
    source = parsed.dossier.inputs
    offer = next((item for item in source.offers if item.offer_ref == parsed.offer_ref), None)
    if offer is None:
        raise ValueError("offer_ref must select an offer from the exact assessment dossier")
    blockers = [AssessmentBlocker(code="ASSESSMENT_INCOMPLETE", field="dossier." + item.field, message=item.message, related_refs=item.related_refs) for item in parsed.dossier.blockers]

    def block(code: str, field: str, message: str) -> None:
        blockers.append(AssessmentBlocker(code=code, field=field, message=message))

    for field in ("product_ref", "configuration", "configuration_scope", "configured_by_ref", "transition_ref", "idempotency_key", "configuration_evidence_ref", "pricing_evidence_ref"):
        if getattr(parsed, field) is None:
            block("MISSING_INPUT", field, f"Supply {field.replace('_', ' ')} for the canonical quote proposal.")
    if parsed.quote_ref is None and (offer.pricing is None or offer.pricing.quote_ref is None):
        block("MISSING_INPUT", "quote_ref", "Supply the exact quote reference to propose.")
    if parsed.tax_basis != "exclusive":
        block("TAX_BASIS_REQUIRED", "tax_basis", "Confirm that the selected offer amount is tax-exclusive. The canonical SDK projection leaves tax calculation to Spring.")
    if parsed.configuration_evidence_ref is not None and parsed.configuration_evidence_ref == parsed.pricing_evidence_ref:
        block("ATTESTATION_REFS_NOT_DISTINCT", "pricing_evidence_ref", "Configuration and pricing require distinct evidence references with their exact evidence kinds.")
    if offer.pricing is None or offer.pricing.valid_until is None:
        block("PRICING_REQUIRED", "dossier.inputs.offers", "The selected offer requires explicit pricing and a quote validity cutoff.")
    if parsed.quote_ref is not None and offer.pricing is not None and offer.pricing.quote_ref not in {None, parsed.quote_ref}:
        block("QUOTE_REF_MISMATCH", "quote_ref", "The proposed quote reference must match the selected offer's declared quote reference.")
    if offer.pricing is not None and offer.pricing.quote_revision not in {None, 1}:
        block("QUOTE_REVISION_UNSUPPORTED", "dossier.inputs.offers", "This bridge prepares an initial revision-one quote; existing quote revisions require the canonical revision workflow.")
    at = _parsed_timestamp(parsed.prepared_at)
    if at < _parsed_timestamp(source.prepared_at):
        block("HANDOFF_PREDATES_ASSESSMENT", "prepared_at", "The commercial handoff cannot predate its source assessment.")
    if any(_parsed_timestamp(item.valid_until) <= at for item in (*source.evidence, *source.findings)):
        block("ASSESSMENT_STALE", "dossier", "Refresh the assessment evidence and findings before preparing this quote.")
    if offer.pricing is not None and offer.pricing.valid_until is not None and _parsed_timestamp(offer.pricing.valid_until) <= at:
        block("PRICE_EXPIRED", "prepared_at", "The selected offer price has expired at the handoff timestamp.")

    configuration = parsed.configuration
    if configuration is not None:
        if configuration.configuration_ref == (parsed.quote_ref or (offer.pricing.quote_ref if offer.pricing is not None else None)):
            block("ARTIFACT_REFS_NOT_DISTINCT", "quote_ref", "Configuration and quote require distinct primary references.")
        if configuration.status != "validated":
            block("CONFIGURATION_VALIDATION_REQUIRED", "configuration.status", "Supply the validated configuration; the assessment cannot validate a price-book configuration itself.")
        if configuration.revision != 1:
            block("CONFIGURATION_REVISION_UNSUPPORTED", "configuration.revision", "The canonical initial quote requires configuration revision one.")
        if any(line.product_ref != parsed.product_ref for line in configuration.lines):
            block("PRODUCT_MISMATCH", "configuration.lines", "Every supplied configuration line must belong to the explicitly selected product.")
        if _parsed_timestamp(configuration.effective_at) > at or (configuration.expires_at is not None and _parsed_timestamp(configuration.expires_at) <= at):
            block("CONFIGURATION_NOT_CURRENT", "configuration", "The configuration must be effective at the commercial handoff timestamp.")
        if configuration.expires_at is not None and offer.pricing is not None and offer.pricing.valid_until is not None and _parsed_timestamp(offer.pricing.valid_until) > _parsed_timestamp(configuration.expires_at):
            block("CONFIGURATION_EXPIRES_BEFORE_QUOTE", "configuration.expires_at", "The validated configuration must cover the complete proposed quote validity period.")
        if set(configuration.evidence_refs) != {parsed.configuration_evidence_ref, parsed.pricing_evidence_ref}:
            block("CONFIGURATION_EVIDENCE_MISMATCH", "configuration.evidence_refs", "The configuration must retain exactly the selected configuration and pricing evidence references.")
        if offer.pricing is not None:
            configured_lines = [(line.quantity, line.configured_unit_price, _money_product(line.quantity, line.configured_unit_price)) for line in configuration.lines]
            if _exact_sum([line[2] for line in configured_lines]) != offer.pricing.total:
                block("OFFER_PRICE_MISMATCH", "configuration.lines", "The configured quote subtotal must exactly equal the selected offer's declared tax-exclusive amount.")
            if offer.pricing.lines and Counter((line.quantity, line.unit_price, line.line_total) for line in offer.pricing.lines) != Counter(configured_lines):
                block("OFFER_LINES_MISMATCH", "configuration.lines", "Configured quantities and prices must exactly cover every declared offer line, not merely match its total.")
        for line in configuration.lines:
            if line.configured_unit_price != _money_product(line.list_unit_price, _exact_difference(1, line.discount_ratio)):
                block("CONFIGURATION_PRICE_INVALID", "configuration.lines", "The supplied configured price must exactly equal its declared list price after discount.")

    requested_link = any(value is not None for value in (parsed.engagement_snapshot, parsed.engagement_transition_ref, parsed.engagement_idempotency_key, parsed.engagement_expected_version, parsed.engagement_expected_state_digest))
    if requested_link:
        for field in ("engagement_expected_version", "engagement_expected_state_digest", "engagement_transition_ref", "engagement_idempotency_key"):
            if getattr(parsed, field) is None:
                block("MISSING_INPUT", field, "Linking the quote requires exact expected engagement version/digest fences and explicit transition and idempotency references.")
        expected_version = parsed.engagement_snapshot.version if parsed.engagement_snapshot is not None else 0
        expected_digest = parsed.engagement_snapshot.state_digest if parsed.engagement_snapshot is not None else genesis_engagement_state_digest(source.scope)
        if parsed.engagement_expected_version not in {None, expected_version} or parsed.engagement_expected_state_digest not in {None, expected_digest}:
            block("ENGAGEMENT_FENCE_MISMATCH", "engagement_expected_state_digest", "The engagement fences must exactly match the supplied snapshot, or explicit genesis when no snapshot exists.")
        if parsed.engagement_snapshot is not None and _parsed_timestamp(parsed.engagement_snapshot.transition_history[-1].command.occurred_at) > at:
            block("FUTURE_ENGAGEMENT_SNAPSHOT", "engagement_snapshot", "The engagement snapshot must exist at the handoff timestamp.")

    challenge = None
    commercial_input = commercial_result = engagement_input = engagement_result = None
    if not blockers:
        challenge = _challenge(parsed, offer)
        evidence_by_ref = {item.evidence_ref: item for item in parsed.evidence_refs}
        for ref, kind in ((parsed.configuration_evidence_ref, "cpq_configuration"), (parsed.pricing_evidence_ref, "pricing")):
            evidence = evidence_by_ref.get(ref)
            if evidence is None:
                block("ATTESTATION_REQUIRED", "evidence_refs", f"Supply externally attested {kind} evidence for the exact challenge commitment.")
            elif evidence.sha256 != challenge.evidence_sha256:
                block("ATTESTATION_DIGEST_MISMATCH", "evidence_refs", "Supplied evidence must already commit the exact proposed command; the SDK never repairs its digest.")
        if parsed.evidence_refs and set(evidence_by_ref) - {parsed.configuration_evidence_ref, parsed.pricing_evidence_ref}:
            block("UNEXPECTED_ATTESTATION", "evidence_refs", "Supply only the two selected command-bound configuration and pricing attestations.")
        if not blockers:
            try:
                command = seal_commercial_command({**challenge.command_content(), "evidence_refs": [_detached(item) for item in parsed.evidence_refs]})
                commercial_input = CommercialOperationsLifecycleInput.model_validate({"scope": challenge.scope, "command": command})
                commercial_result = materialize_commercial_operations_candidate(commercial_input)
                if not commercial_result.candidate_validated:
                    block("COMMERCIAL_PROPOSAL_REJECTED", "commercial_input", commercial_result.transition_receipt.recovery.instructions or "The canonical commercial lifecycle rejected the quote proposal.")
            except ValidationError as exc:
                commercial_input = commercial_result = None
                blockers.extend(_validation_blockers(exc, "evidence_refs"))
    if not blockers and commercial_result is not None and requested_link:
        snapshot = commercial_result.snapshot
        engagement_command = seal_service_engagement_command({
            "kind": "link_quote", "scope": source.scope, "transition_ref": parsed.engagement_transition_ref,
            "idempotency_key": parsed.engagement_idempotency_key, "expected_version": parsed.engagement_expected_version,
            "expected_state_digest": parsed.engagement_expected_state_digest, "occurred_at": parsed.prepared_at,
            "requested_by_ref": parsed.requested_by_ref,
            "package": {"kind": "link_quote", "quote_ref": snapshot.quote.quote_ref, "quote_revision": snapshot.quote.revision,
                        "commercial_snapshot_digest": snapshot.state_digest, "total": str(snapshot.quote.total)},
        })
        engagement_input = ServiceEngagementTransitionInput.model_validate({"scope": source.scope, "command": engagement_command, "current_snapshot": parsed.engagement_snapshot})
        engagement_result = materialize_service_engagement_transition(engagement_input)
        if not engagement_result.candidate_validated:
            block("ENGAGEMENT_LINK_REJECTED", "engagement_snapshot", engagement_result.transition_receipt.recovery.instructions or "The canonical engagement cannot link this quote from its current state.")
    status = "ready_for_commercial_review" if not blockers else "awaiting_attestations" if challenge is not None and commercial_input is None else "blocked"
    payload = {
        "schema": "lightbulb.assessment_commercial_handoff.v1", "dossier_digest": parsed.dossier.dossier_digest,
        "offer_ref": parsed.offer_ref, "offer_digest": _stable_digest(offer.to_dict()), "offer_kind": offer.kind,
        "billing_period": offer.billing_period, **({"terms_ref": offer.terms_ref} if offer.terms_ref is not None else {}),
        "scope": source.scope.to_dict(), "prepared_at": parsed.prepared_at,
        "status": status, "blockers": [_detached(item) for item in blockers],
        **({"evidence_challenge": challenge.to_dict()} if challenge is not None else {}),
        **({"commercial_input": commercial_input.to_dict(), "commercial_result": commercial_result.to_dict()} if commercial_input is not None else {}),
        **({"engagement_input": engagement_input.to_dict(), "engagement_result": engagement_result.to_dict()} if engagement_input is not None else {}),
        "primitive_ref": "commercial.propose_operations_transition", "engagement_primitive_ref": "service.propose_engagement_transition",
        "persisted": False, "quote_approved": False, "tax_calculated": False, "payment_collected": False, "access_activated": False,
    }
    payload["handoff_digest"] = _stable_digest(payload)
    return AssessmentCommercialHandoff.model_validate(payload)


__all__ = ["AssessmentCommercialHandoff", "AssessmentCommercialHandoffInput", "AssessmentQuoteEvidenceChallenge", "prepare_assessment_commercial_handoff"]
