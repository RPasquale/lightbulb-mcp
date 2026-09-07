"""Intake and routing that bind contract obligations to an executed agreement.

This module is the seam between the commercial-legal handoff and the
contract-obligation loop.  It turns the ``ObligationFulfillmentProjection``
derived from an ``ExecutedCommercialAgreementCustodyCandidate`` plus the
legal/commercial agent's typed completions (criteria, due rules, parties,
policies) into the exact ``ContractObligationNormalizationInput`` the
obligation loop consumes, and it routes a normalized register's obligations
toward the domain loops that fulfil them:

* customer commitments → project/service delivery;
* billing and payment terms → contract-to-cash;
* supplier commitments → procurement;
* compliance, restriction, and data obligations → compliance controls;
* notice deadlines → legal review.

Routing is a deterministic proposal.  It never starts a downstream loop,
persists anything, or decides legal meaning; Spring and the target loops own
their own admission.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, Field, ValidationInfo, field_validator, model_validator

from lightbulb.commercial_legal_handoff import ObligationFulfillmentProjection
from lightbulb.contract_obligations import (
    GENESIS_STATE_DIGEST,
    MAX_REGISTER_DEFINITIONS,
    ActivationCondition,
    ContractObligationNormalizationInput,
    ContractObligationScope,
    DueRule,
    EscalationPolicy,
    FulfillmentCriterion,
    Materiality,
    MonetaryTerms,
    ObligationDefinition,
    ObligationRegister,
    OpaqueRef,
    Sha256Digest,
    _StrictModel,
    _timestamp,
)


OBLIGATION_INTAKE_SCHEMA = "lightbulb.contract_obligation_intake_input.v1"
OBLIGATION_ROUTING_SCHEMA = "lightbulb.contract_obligation_routing_plan.v1"

CounterpartyRole = Literal["customer", "supplier", "partner"]
ObligationRoute = Literal[
    "project_service_delivery",
    "contract_to_cash",
    "procurement",
    "compliance_controls",
    "legal_review",
]
ROUTE_TARGET_LOOPS: dict[str, str] = {
    "project_service_delivery": "project/service delivery and milestone acceptance",
    "contract_to_cash": "commercial operations lifecycle (subscription, billing, collection)",
    "procurement": "procure-to-pay and vendor lifecycle",
    "compliance_controls": "compliance controls and regulated-operations lifecycle",
    "legal_review": "legal review and notice handling",
}


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _controlled_projection(value: Any) -> Any:
    return ObligationFulfillmentProjection.model_validate(_detached(value))


ControlledProjection = Annotated[ObligationFulfillmentProjection, BeforeValidator(_controlled_projection)]


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ObligationCandidateCompletion(_StrictModel):
    """Agent-supplied mechanics for one proposed obligation from the custody projection."""

    obligation_ref: OpaqueRef
    criteria: tuple[FulfillmentCriterion, ...] = Field(min_length=1, max_length=40)
    responsible_party_ref: OpaqueRef
    due_rule: DueRule
    activation: ActivationCondition = Field(default_factory=ActivationCondition)
    dependencies: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    notice_lead_days: int | None = Field(default=None, ge=0, le=730)
    evidence_lead_days: int = Field(default=0, ge=0, le=365)
    evidence_freshness_days: int = Field(default=365, ge=1, le=3650)
    materiality: Materiality = "medium"
    escalation_policy: EscalationPolicy
    monetary: MonetaryTerms | None = None
    supersedes_obligation_ref: OpaqueRef | None = None
    proposed_by_ref: OpaqueRef
    proposal_evidence_ref: OpaqueRef


class ContractObligationIntakeInput(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_intake_input.v1"] = Field(
        default=OBLIGATION_INTAKE_SCHEMA, alias="schema"
    )
    scope: ContractObligationScope
    projection: ControlledProjection
    custody_candidate_digest: Sha256Digest
    custody_approval_evidence_ref: OpaqueRef
    custody_approved_at: str
    completions: tuple[ObligationCandidateCompletion, ...] = Field(
        min_length=1, max_length=MAX_REGISTER_DEFINITIONS
    )
    prior_register: ObligationRegister | None = None
    requested_by_ref: OpaqueRef

    @field_validator("custody_approved_at")
    @classmethod
    def _approved(cls, value: str) -> str:
        return _timestamp(value, field_name="custody_approved_at")

    @model_validator(mode="after")
    def _intake_is_exact(self) -> "ContractObligationIntakeInput":
        projection = self.projection
        if projection.custody_candidate_digest != self.custody_candidate_digest:
            raise ValueError("projection must derive from the cited custody candidate")
        if projection.agreement_ref != self.scope.agreement_ref:
            raise ValueError("projection agreement must match the scoped agreement")
        if projection.counterparty_role != "customer":
            raise ValueError("custody projections describe customer agreements")
        proposed = {item.obligation_ref for item in projection.proposed_obligations}
        completed = [item.obligation_ref for item in self.completions]
        if len(completed) != len(set(completed)):
            raise ValueError("completions must be unique per obligation")
        missing = sorted(proposed - set(completed))
        extra = sorted(set(completed) - proposed)
        if missing or extra:
            raise ValueError(
                "completions must cover exactly the projected obligations "
                f"(missing={missing}, extra={extra})"
            )
        if self.prior_register is not None:
            if self.prior_register.scope != self.scope:
                raise ValueError("prior register must share the exact scope")
            if projection.agreement_version <= self.prior_register.agreement.version:
                raise ValueError("an amendment projection must advance the agreement version")
        return self


def build_contract_obligation_normalization_input(
    inputs: ContractObligationIntakeInput | Mapping[str, Any],
) -> ContractObligationNormalizationInput:
    """Bind projected obligations and agent completions into normalization input."""

    parsed = ContractObligationIntakeInput.model_validate(_detached(inputs))
    projection = parsed.projection
    prior = parsed.prior_register
    agreement: dict[str, Any] = {
        "agreement_ref": projection.agreement_ref,
        "version": projection.agreement_version,
        "agreement_digest": projection.agreement_digest,
        "approval_evidence_ref": parsed.custody_approval_evidence_ref,
        "approved_at": parsed.custody_approved_at,
        "effective_at": projection.effective_at,
        "expires_at": projection.expires_at,
    }
    if prior is not None:
        agreement["supersedes_version"] = prior.agreement.version
    proposed = {item.obligation_ref: item for item in projection.proposed_obligations}
    candidates = []
    for completion in sorted(parsed.completions, key=lambda item: item.obligation_ref):
        source = proposed[completion.obligation_ref]
        payload = completion.to_dict()
        payload.update(
            {
                "candidate_ref": f"candidate:{source.obligation_ref}",
                "clause_ref": source.clause_ref,
                "clause_text_digest": source.clause_text_digest,
                "kind": source.kind,
                "direction": source.direction,
                "title": source.title,
                "counterparty_ref": projection.counterparty_ref,
            }
        )
        candidates.append(payload)
    normalization: dict[str, Any] = {
        "scope": parsed.scope.to_dict(),
        "agreement": agreement,
        "clause_index": [
            {
                "clause_ref": item.clause_ref,
                "heading": None,
                "clause_text_digest": item.clause_text_digest,
                "source_evidence_ref": item.source_evidence_ref,
            }
            for item in projection.clause_index
        ],
        "candidates": candidates,
        "requested_by_ref": parsed.requested_by_ref,
    }
    if prior is not None:
        normalization["prior_register"] = prior.to_dict()
    return ContractObligationNormalizationInput.model_validate(normalization)


def route_for(
    definition: ObligationDefinition, *, counterparty_role: CounterpartyRole
) -> tuple[ObligationRoute, str]:
    """Deterministic routing of one obligation toward the loop that fulfils it."""

    kind = definition.kind
    owed_by_company = definition.direction == "owed_by_company"
    if kind == "notice":
        return "legal_review", "notice deadlines are handled through legal review"
    if kind == "monetary":
        if owed_by_company and counterparty_role == "supplier":
            return "procurement", "payment owed to a supplier flows through procure-to-pay"
        return "contract_to_cash", "monetary terms flow through the commercial billing and collection lifecycle"
    if kind in {"compliance", "restriction"}:
        return "compliance_controls", f"{kind} obligations are evidenced through compliance controls"
    if kind in {"delivery", "service", "acceptance"}:
        if not owed_by_company and counterparty_role == "supplier":
            return "procurement", "supplier commitments are tracked through procurement"
        return "project_service_delivery", f"{kind} commitments are fulfilled through project/service delivery"
    # reporting
    if owed_by_company and counterparty_role == "customer":
        return "project_service_delivery", "customer reporting commitments are delivered as service outputs"
    return "compliance_controls", "reporting owed by or to non-customers is evidenced through compliance controls"


class ObligationRouteAssignment(_StrictModel):
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    kind: str
    direction: str
    route: ObligationRoute
    target_loop: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=1, max_length=500)


class ObligationRoutingPlan(_StrictModel):
    schema_id: Literal["lightbulb.contract_obligation_routing_plan.v1"] = Field(
        default=OBLIGATION_ROUTING_SCHEMA, alias="schema"
    )
    scope: ContractObligationScope
    register_digest: Sha256Digest
    counterparty_role: CounterpartyRole
    assignments: tuple[ObligationRouteAssignment, ...] = Field(
        default_factory=tuple, max_length=MAX_REGISTER_DEFINITIONS
    )
    route_counts: dict[str, int]
    routing_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("route_counts", mode="before")
    @classmethod
    def _counts(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): value[key] for key in sorted(value)}
        return value

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "ObligationRoutingPlan":
        refs = [item.obligation_ref for item in self.assignments]
        if refs != sorted(refs) or len(refs) != len(set(refs)):
            raise ValueError("assignments must be unique and sorted by obligation_ref")
        counts: dict[str, int] = {}
        for item in self.assignments:
            counts[item.route] = counts.get(item.route, 0) + 1
        if self.route_counts != counts:
            raise ValueError("route_counts must be derived from assignments")
        if (info.context or {}).get("skip_obligation_digests"):
            return self
        if self.routing_digest != obligation_routing_digest(self):
            raise ValueError("routing_digest must commit the exact plan")
        return self


def obligation_routing_digest(plan: ObligationRoutingPlan | Mapping[str, Any]) -> str:
    raw = dict(_detached(plan))
    raw.setdefault("routing_digest", GENESIS_STATE_DIGEST)
    parsed = ObligationRoutingPlan.model_validate(raw, context={"skip_obligation_digests": True})
    payload = parsed.to_dict()
    payload.pop("routing_digest", None)
    return _stable_digest(payload)


class ContractObligationRoutingInput(_StrictModel):
    scope: ContractObligationScope
    obligation_register: ObligationRegister
    counterparty_role: CounterpartyRole = "customer"
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractObligationRoutingInput":
        if self.obligation_register.scope != self.scope:
            raise ValueError("register scope must exactly match routing scope")
        return self


def route_contract_obligation_register(
    inputs: ContractObligationRoutingInput | Mapping[str, Any],
) -> ObligationRoutingPlan:
    """Propose one deterministic downstream route per registered obligation."""

    parsed = ContractObligationRoutingInput.model_validate(_detached(inputs))
    assignments = []
    for definition in parsed.obligation_register.definitions:
        route, rationale = route_for(definition, counterparty_role=parsed.counterparty_role)
        assignments.append(
            ObligationRouteAssignment(
                obligation_ref=definition.obligation_ref,
                definition_digest=definition.definition_digest,
                kind=definition.kind,
                direction=definition.direction,
                route=route,
                target_loop=ROUTE_TARGET_LOOPS[route],
                rationale=rationale,
            )
        )
    counts: dict[str, int] = {}
    for item in assignments:
        counts[item.route] = counts.get(item.route, 0) + 1
    plan = {
        "scope": parsed.scope.to_dict(),
        "register_digest": parsed.obligation_register.register_digest,
        "counterparty_role": parsed.counterparty_role,
        "assignments": [item.to_dict() for item in assignments],
        "route_counts": counts,
    }
    plan["routing_digest"] = obligation_routing_digest(plan)
    return ObligationRoutingPlan.model_validate(plan)


__all__ = [
    "OBLIGATION_INTAKE_SCHEMA",
    "OBLIGATION_ROUTING_SCHEMA",
    "ROUTE_TARGET_LOOPS",
    "ContractObligationIntakeInput",
    "ContractObligationRoutingInput",
    "CounterpartyRole",
    "ObligationCandidateCompletion",
    "ObligationRoute",
    "ObligationRouteAssignment",
    "ObligationRoutingPlan",
    "build_contract_obligation_normalization_input",
    "obligation_routing_digest",
    "route_contract_obligation_register",
    "route_for",
]
