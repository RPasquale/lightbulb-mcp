"""Compile an evidence-backed assessment and commercial options for review.

This is a deterministic composition of the service-business loop, engagement
assessment and business-artifact contracts. It has no durable lifecycle and
performs no publication, acceptance, billing or software-access effects. Scope
references identify the intended company; Spring still authorizes every hosted
operation, including when the requesting user is a tenant administrator.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.business_artifact_production import BrandContext, CommercialContext, CustomerContext
from lightbulb.service_business_loop import SERVICE_BUSINESS_GOLDEN_LOOP
from lightbulb.service_engagement import (
    BoundedText,
    OpaqueRef,
    ServiceEngagementAssessment,
    ServiceEngagementScope,
    ServiceEngagementSnapshot,
    Sha256Digest,
    ShortText,
    _StrictModel,
    _detached,
    _digest_without,
    _parsed_timestamp,
    _timestamp,
    assess_service_engagement,
)


ASSESSMENT_INPUT_SCHEMA = "lightbulb.productised_assessment_input.v1"
ASSESSMENT_DOSSIER_SCHEMA = "lightbulb.productised_assessment_dossier.v1"
_GENESIS_DIGEST = "0" * 64
OfferKind = Literal["assessment", "implementation", "managed_monitoring", "software_access"]


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, _GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_productised_assessment_digests": True})
    return _digest_without(parsed.to_dict(), field)


class AssessmentGoal(_StrictModel):
    goal_ref: OpaqueRef
    description: BoundedText
    success_criteria: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)


class AssessmentEvidence(_StrictModel):
    """A declared evidence reference, not a claim that its bytes were fetched."""

    evidence_ref: OpaqueRef
    scope: ServiceEngagementScope
    digest: Sha256Digest
    observed_at: str
    valid_until: str
    summary: BoundedText

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _time(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _window(self) -> "AssessmentEvidence":
        if _parsed_timestamp(self.valid_until) <= _parsed_timestamp(self.observed_at):
            raise ValueError("evidence valid_until must follow observed_at")
        return self


class AssessmentFinding(_StrictModel):
    finding_ref: OpaqueRef
    title: ShortText
    observation: BoundedText
    recommendation: BoundedText
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=30)
    goal_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    assessed_at: str
    valid_until: str

    @field_validator("assessed_at", "valid_until")
    @classmethod
    def _time(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _window(self) -> "AssessmentFinding":
        _unique(self.evidence_refs, "finding evidence references")
        _unique(self.goal_refs, "finding goal references")
        if _parsed_timestamp(self.valid_until) <= _parsed_timestamp(self.assessed_at):
            raise ValueError("finding valid_until must follow assessed_at")
        return self


class AssessmentOffer(_StrictModel):
    """An unapproved commercial option with explicitly supplied prices."""

    offer_ref: OpaqueRef
    kind: OfferKind
    title: ShortText
    outcome: BoundedText
    scope_of_work: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    exclusions: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    pricing: CommercialContext | None = None
    billing_period: Literal["one_off", "month", "year"]
    acceptance_criteria: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    terms_ref: OpaqueRef | None = None
    finding_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @model_validator(mode="after")
    def _commercial_shape(self) -> "AssessmentOffer":
        _unique(self.finding_refs, "offer finding references")
        if self.kind in {"assessment", "implementation"} and self.billing_period != "one_off":
            raise ValueError("assessment and implementation offers must have one-off pricing")
        if self.kind in {"managed_monitoring", "software_access"} and self.billing_period == "one_off":
            raise ValueError("ongoing offers must declare monthly or annual pricing")
        if self.pricing is not None:
            for line in self.pricing.lines:
                if (line.quantity * line.unit_price).quantize(Decimal("0.000001")) != line.line_total:
                    raise ValueError("commercial line total must equal quantity times unit price")
        return self


class ProductisedAssessmentInput(_StrictModel):
    schema_id: Literal["lightbulb.productised_assessment_input.v1"] = Field(default=ASSESSMENT_INPUT_SCHEMA, alias="schema")
    scope: ServiceEngagementScope
    requested_by_ref: OpaqueRef
    assessment_ref: OpaqueRef
    prepared_at: str
    title: ShortText
    executive_summary: BoundedText | None = None
    brand: BrandContext | None = None
    customer: CustomerContext | None = None
    goals: tuple[AssessmentGoal, ...] = Field(default_factory=tuple, max_length=30)
    evidence: tuple[AssessmentEvidence, ...] = Field(default_factory=tuple, max_length=100)
    findings: tuple[AssessmentFinding, ...] = Field(default_factory=tuple, max_length=100)
    offers: tuple[AssessmentOffer, ...] = Field(default_factory=tuple, max_length=20)
    engagement_snapshot: ServiceEngagementSnapshot | None = None
    input_digest: Sha256Digest = _GENESIS_DIGEST

    @model_validator(mode="before")
    @classmethod
    def _seal_fresh_input(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and "input_digest" not in value:
            raw = dict(_detached(value))
            raw["input_digest"] = _sealed_digest(cls, raw, "input_digest")
            return raw
        return value

    @field_validator("prepared_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _scope_and_seal(self, info: ValidationInfo) -> "ProductisedAssessmentInput":
        for field, ref in (("goals", "goal_ref"), ("evidence", "evidence_ref"), ("findings", "finding_ref"), ("offers", "offer_ref")):
            _unique(tuple(getattr(item, ref) for item in getattr(self, field)), field)
        if sum(offer.kind == "assessment" for offer in self.offers) > 1:
            raise ValueError("declare exactly one initial assessment offer, with optional later offers")
        if self.customer is not None and self.customer.customer_ref != self.scope.customer_ref:
            raise ValueError("customer must match the exact assessment customer scope")
        for evidence in self.evidence:
            if evidence.scope != self.scope:
                raise ValueError("evidence scope must exactly match the assessment scope")
        if self.engagement_snapshot is not None and self.engagement_snapshot.scope != self.scope:
            raise ValueError("engagement snapshot scope must exactly match the assessment scope")
        if any(offer.pricing is not None and offer.pricing.currency != self.scope.currency for offer in self.offers):
            raise ValueError("offer pricing currency must match the assessment scope currency")
        if not (info.context or {}).get("skip_productised_assessment_digests"):
            if self.input_digest != _sealed_digest(ProductisedAssessmentInput, self, "input_digest"):
                raise ValueError("input_digest must commit the exact assessment input")
        return self


class AssessmentBlocker(_StrictModel):
    code: ShortText
    field: ShortText
    message: BoundedText
    related_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)


class AssessmentNextAction(_StrictModel):
    action_ref: OpaqueRef
    kind: Literal["supply_input", "review", "canonical_primitive"]
    primitive_ref: ShortText | None = None
    input_fields: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=1500)
    reason: BoundedText
    execution_boundary: Literal["input_only", "human_review", "hosted_governed"]


class ProductisedAssessmentDossier(_StrictModel):
    schema_id: Literal["lightbulb.productised_assessment_dossier.v1"] = Field(default=ASSESSMENT_DOSSIER_SCHEMA, alias="schema")
    inputs: ProductisedAssessmentInput
    golden_loop: Literal["service.market_to_renewal_business@0.1.0"] = SERVICE_BUSINESS_GOLDEN_LOOP
    status: Literal["blocked", "ready_for_review"]
    disposition: Literal["draft_for_review"] = "draft_for_review"
    blockers: tuple[AssessmentBlocker, ...] = Field(default_factory=tuple, max_length=1500)
    next_actions: tuple[AssessmentNextAction, ...] = Field(min_length=1, max_length=10)
    continuation_offer_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    engagement_assessment: ServiceEngagementAssessment
    persisted: Literal[False] = False
    published: Literal[False] = False
    approved: Literal[False] = False
    paid: Literal[False] = False
    access_activated: Literal[False] = False
    dossier_digest: Sha256Digest = _GENESIS_DIGEST

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "ProductisedAssessmentDossier":
        expected = _assemble_dossier(self.inputs)
        for field in ("status", "blockers", "next_actions", "continuation_offer_refs", "engagement_assessment"):
            if _detached(getattr(self, field)) != _detached(expected[field]):
                raise ValueError(f"{field} must be derived from the exact assessment input")
        if not (info.context or {}).get("skip_productised_assessment_digests"):
            if self.dossier_digest != _sealed_digest(ProductisedAssessmentDossier, self, "dossier_digest"):
                raise ValueError("dossier_digest must commit the exact assessment dossier")
        return self


def seal_productised_assessment_input(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize fresh input; an existing seal is always checked, never repaired."""
    raw = dict(_detached(inputs))
    if "input_digest" not in raw:
        raw["input_digest"] = _sealed_digest(ProductisedAssessmentInput, raw, "input_digest")
    return ProductisedAssessmentInput.model_validate(raw).to_dict()


def _assemble_dossier(inputs: ProductisedAssessmentInput) -> dict[str, Any]:
    blockers: list[AssessmentBlocker] = []

    def block(code: str, field: str, message: str, *refs: str) -> None:
        blockers.append(AssessmentBlocker(code=code, field=field, message=message, related_refs=refs))

    for field in ("brand", "customer", "executive_summary", "goals", "evidence", "findings"):
        if not getattr(inputs, field):
            block("missing_input", field, f"Supply {field.replace('_', ' ')} for the assessment.")
    if not any(offer.kind == "assessment" for offer in inputs.offers):
        block("missing_assessment_offer", "offers", "Declare the initial assessment offer, including its scope, acceptance criteria and price.")
    for index, goal in enumerate(inputs.goals):
        if not goal.success_criteria:
            block("missing_success_criteria", f"goals[{index}].success_criteria", "State how the customer will judge this goal.", goal.goal_ref)

    prepared = _parsed_timestamp(inputs.prepared_at)
    evidence_by_ref = {item.evidence_ref: item for item in inputs.evidence}
    goal_refs = {item.goal_ref for item in inputs.goals}
    finding_refs = {item.finding_ref for item in inputs.findings}
    for index, evidence in enumerate(inputs.evidence):
        if _parsed_timestamp(evidence.observed_at) > prepared:
            block("future_evidence", f"evidence[{index}].observed_at", "Evidence cannot be observed after the assessment timestamp.", evidence.evidence_ref)
        if _parsed_timestamp(evidence.valid_until) <= prepared:
            block("stale_evidence", f"evidence[{index}].valid_until", "Refresh this evidence before using the assessment.", evidence.evidence_ref)
    for index, finding in enumerate(inputs.findings):
        path = f"findings[{index}]"
        if not finding.evidence_refs:
            block("unsupported_finding", f"{path}.evidence_refs", "Attach evidence supporting this finding.", finding.finding_ref)
        unknown = set(finding.evidence_refs) - evidence_by_ref.keys()
        if unknown:
            block("unknown_evidence", f"{path}.evidence_refs", "Every finding evidence reference must be supplied in this assessment.", *sorted(unknown))
        if not finding.goal_refs:
            block("unlinked_finding", f"{path}.goal_refs", "Link this finding to a customer goal.", finding.finding_ref)
        if set(finding.goal_refs) - goal_refs:
            block("unknown_goal", f"{path}.goal_refs", "Every finding goal reference must be supplied in this assessment.", *sorted(set(finding.goal_refs) - goal_refs))
        assessed = _parsed_timestamp(finding.assessed_at)
        if assessed > prepared:
            block("future_finding", f"{path}.assessed_at", "A finding cannot be assessed after the assessment timestamp.", finding.finding_ref)
        if _parsed_timestamp(finding.valid_until) <= prepared:
            block("stale_finding", f"{path}.valid_until", "Reassess this finding before using the assessment.", finding.finding_ref)
        newer_evidence = [ref for ref in finding.evidence_refs if ref in evidence_by_ref and _parsed_timestamp(evidence_by_ref[ref].observed_at) > assessed]
        if newer_evidence:
            block("finding_predates_evidence", f"{path}.assessed_at", "Reassess the finding against the supplied newer evidence.", *newer_evidence)

    covered_goals = {ref for finding in inputs.findings for ref in finding.goal_refs}
    for index, goal in enumerate(inputs.goals):
        if goal.goal_ref not in covered_goals:
            block("unassessed_goal", f"goals[{index}]", "Supply an evidence-backed finding for this customer goal, including an explicit finding when no change is needed.", goal.goal_ref)

    if inputs.engagement_snapshot is not None:
        latest_transition = inputs.engagement_snapshot.transition_history[-1].command
        if _parsed_timestamp(latest_transition.occurred_at) > prepared:
            block("future_engagement_snapshot", "engagement_snapshot", "Refresh the assessment timestamp or supply the engagement snapshot that existed at that time.")

    for index, offer in enumerate(inputs.offers):
        path = f"offers[{index}]"
        for field in ("scope_of_work", "acceptance_criteria", "terms_ref", "pricing"):
            if not getattr(offer, field):
                block("incomplete_offer", f"{path}.{field}", f"Supply {field.replace('_', ' ')} for this proposed offer.", offer.offer_ref)
        if offer.pricing is not None:
            if offer.pricing.valid_until is None:
                block("missing_price_validity", f"{path}.pricing.valid_until", "Declare how long this price remains valid.", offer.offer_ref)
            elif _parsed_timestamp(offer.pricing.valid_until) <= prepared:
                block("expired_price", f"{path}.pricing.valid_until", "Refresh expired commercial pricing.", offer.offer_ref)
        if offer.kind != "assessment" and not offer.finding_refs:
            block("unlinked_offer", f"{path}.finding_refs", "Link the proposed follow-on work to assessment findings.", offer.offer_ref)
        unknown = set(offer.finding_refs) - finding_refs
        if unknown:
            block("unknown_finding", f"{path}.finding_refs", "Every offer finding reference must be supplied in this assessment.", *sorted(unknown))

    actions: list[AssessmentNextAction] = []
    if blockers:
        actions.append(AssessmentNextAction(
            action_ref="complete_assessment_inputs", kind="supply_input", input_fields=tuple(dict.fromkeys(item.field for item in blockers)),
            reason="Resolve all listed prerequisites, then compile the assessment again.", execution_boundary="input_only",
        ))
    else:
        actions.append(AssessmentNextAction(
            action_ref="review_assessment_and_offers", kind="review",
            reason="Review the evidence, findings and separately priced offers before any customer delivery.", execution_boundary="human_review",
        ))
        actions.append(AssessmentNextAction(
            action_ref="prepare_governed_artifact", kind="canonical_primitive", primitive_ref="documents.prepare_business_artifact_generation",
            reason="Use the reviewed assessment as source material in the existing governed artifact workflow.", execution_boundary="hosted_governed",
        ))
    actions.append(AssessmentNextAction(
        action_ref="inspect_canonical_engagement", kind="canonical_primitive", primitive_ref="service.assess_engagement",
        reason="Read the exact engagement of record before proposing agreement, delivery, acceptance, invoice or collection work.", execution_boundary="hosted_governed",
    ))
    return {
        "inputs": inputs,
        "status": "blocked" if blockers else "ready_for_review",
        "blockers": tuple(blockers),
        "next_actions": tuple(actions),
        "continuation_offer_refs": tuple(offer.offer_ref for offer in inputs.offers if offer.kind in {"managed_monitoring", "software_access"}),
        "engagement_assessment": assess_service_engagement({"scope": inputs.scope, "snapshot": inputs.engagement_snapshot, "requested_by_ref": inputs.requested_by_ref}),
    }


def compile_productised_assessment(inputs: ProductisedAssessmentInput | Mapping[str, Any]) -> ProductisedAssessmentDossier:
    """Compile all readiness gaps and exact draft content without any effects."""
    parsed = ProductisedAssessmentInput.model_validate(seal_productised_assessment_input(_detached(inputs)))
    payload = _assemble_dossier(parsed)
    payload["dossier_digest"] = _sealed_digest(ProductisedAssessmentDossier, payload, "dossier_digest")
    return ProductisedAssessmentDossier.model_validate(payload)


def example_productised_assessment_input() -> dict[str, Any]:
    """Return synthetic demo inputs, never defaults for a real customer.

    Replace every identity, observation, evidence digest, scope and price with
    supplied business facts before proposing any actual customer work.
    """
    scope = {
        "tenant_ref": "tenant:example", "company_ref": "22222222-2222-4222-8222-222222222222", "project_ref": "project:example-assessment",
        "project_id": "11111111-1111-4111-8111-111111111111", "engagement_ref": "engagement:example",
        "customer_ref": "customer:example", "currency": "USD",
    }
    specifications = {
        "assessment": {
            "outcome": "A documented onboarding assessment with evidence-linked findings and separately priced options.",
            "scope_of_work": ["Review the customer-supplied onboarding process and handoff log.", "Deliver the assessment report and hold one customer review meeting."],
            "exclusions": ["Production implementation, recurring monitoring and software subscriptions."],
            "acceptance_criteria": ["The report covers the agreed onboarding handoff and links every finding to supplied evidence.", "The customer confirms the report meets the documented scope."],
        },
        "implementation": {
            "outcome": "An approved onboarding handoff change delivered against agreed acceptance criteria.",
            "scope_of_work": ["Prepare a bounded work packet for one onboarding handoff automation.", "Implement and test the approved change, then submit the evidence for customer acceptance."],
            "exclusions": ["Production changes before hosted approval, unrelated integrations and ongoing operation."],
            "acceptance_criteria": ["Agreed handoff tests pass and the customer accepts the delivered change.", "An evaluator other than the builder accepts any software delivery evidence."],
        },
        "managed_monitoring": {
            "outcome": "The provider reviews the onboarding handoff each month and reports exceptions needing a decision.",
            "scope_of_work": ["Perform one monthly review of customer-supplied onboarding evidence.", "Deliver an exceptions report and request approval for any proposed corrective work."],
            "exclusions": ["Automatic production changes, implementation fees and round-the-clock incident response."],
            "acceptance_criteria": ["The monthly report states the evidence reviewed, exceptions found and requested customer decisions."],
        },
        "software_access": {
            "outcome": "The customer and their agents operate the assessment workflow in their authorized workspace.",
            "scope_of_work": ["Proposed monthly access for three named customer users through the SDK and agent interfaces.", "Include workflow documentation and email support for using the assessment tools."],
            "exclusions": ["Consulting delivery, provider-operated monitoring and implementation services.", "Access activation before the existing hosted agreement, billing and entitlement checks."],
            "acceptance_criteria": ["After hosted activation, authorized customer users can prepare and review their own scoped assessment drafts.", "Customer data and actions remain within the authorized tenant, company and project."],
        },
    }
    offers = []
    for kind, title, amount, period in (
        ("assessment", "Initial assessment", "900", "one_off"),
        ("implementation", "Implementation option", "4000", "one_off"),
        ("managed_monitoring", "Managed monitoring option", "200", "month"),
        ("software_access", "Software access option", "79", "month"),
    ):
        offers.append({
            "offer_ref": f"offer:example-{kind}", "kind": kind, "title": title,
            **specifications[kind],
            "pricing": {"currency": "USD", "total": amount, "valid_until": "2026-10-01T00:00:00Z"},
            "billing_period": period,
            "terms_ref": f"terms:example-{kind}", "finding_refs": [] if kind == "assessment" else ["finding:example-handoff"],
        })
    return {
        "scope": scope, "requested_by_ref": "user:example-owner", "assessment_ref": "assessment:example",
        "prepared_at": "2026-09-07T12:00:00Z", "title": "Illustrative onboarding assessment",
        "executive_summary": "Synthetic example: the supplied sample process shows a manual handoff. Replace these sample claims, evidence and prices before customer use.",
        "brand": {"brand_ref": "brand:example", "brand_name": "Example Services"},
        "customer": {"customer_ref": "customer:example", "customer_display_name": "Example Customer"},
        "goals": [{"goal_ref": "goal:example-handoff", "description": "Document the onboarding handoff", "success_criteria": ["Customer accepts the documented handoff process."]}],
        "evidence": [{
            "evidence_ref": "evidence:example-process", "scope": dict(scope), "digest": "a" * 64,
            "observed_at": "2026-09-06T09:00:00Z", "valid_until": "2026-10-06T09:00:00Z",
            "summary": "Synthetic sample process description; not fetched customer evidence.",
        }],
        "findings": [{
            "finding_ref": "finding:example-handoff", "title": "Illustrative manual handoff",
            "observation": "The sample process contains a manual handoff.",
            "recommendation": "Review the documented inputs before proposing automation.",
            "evidence_refs": ["evidence:example-process"], "goal_refs": ["goal:example-handoff"],
            "assessed_at": "2026-09-07T09:00:00Z", "valid_until": "2026-10-06T09:00:00Z",
        }],
        "offers": offers,
    }


__all__ = [
    "ASSESSMENT_DOSSIER_SCHEMA", "ASSESSMENT_INPUT_SCHEMA", "AssessmentBlocker", "AssessmentEvidence", "AssessmentFinding",
    "AssessmentGoal", "AssessmentNextAction", "AssessmentOffer", "ProductisedAssessmentDossier", "ProductisedAssessmentInput",
    "compile_productised_assessment", "example_productised_assessment_input", "seal_productised_assessment_input",
]
