"""Contract-bound project delivery and independently verified customer acceptance.

This module bridges three existing contracts rather than adding a project
runtime:

* the executed agreement custody candidate, its service-delivery and
  contract-to-cash projections, and the normalized obligation register
  (``lightbulb.commercial_legal_handoff``, ``lightbulb.contract_obligations``);
* the Dynamic Workflow acceptance contracts — immutable
  ``AcceptanceCriterion``, ``BuilderResult``, and fresh-context
  ``EvaluatorVerdict`` (``lightbulb.dynamic_workflows``);
* the existing ``project.create_work_packet`` packet record
  (``lightbulb.growth_primitives``).

It compiles deliverable obligations into a bounded contract delivery plan
with invoice allocation, binds each deliverable to a work packet and its
immutable acceptance contract, checks whether retained builder evidence
addresses the contractual criteria (non-authoritatively; it cannot accept),
converts an independent evaluator verdict or verified customer sign-off into
an ``AcceptedValueBinding`` candidate for contract-to-cash, and proposes a
change order when delivery reveals a contractual variance.

Invariants: every deliverable stays bound to its exact agreement, version,
digest, obligation, order lines, and acceptance criteria; the builder cannot
accept its own work; project completion and provider upload are not
acceptance; acceptance criteria cannot change after binding without an
approved change order; partial acceptance yields only the contractually
allocated accepted amount; rejected work is never invoice-eligible; an
expired or superseded agreement generates no new work; a change order never
rewrites prior work, evidence, acceptance, or invoices; only Spring persists
customer acceptance or authorizes invoicing.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.commercial_legal_handoff import (
    ContractToCashProjection,
    ExecutedCommercialAgreementCustodyCandidate,
    ServiceDeliveryProjection,
)
from lightbulb.contract_obligation_intake import ObligationRoutingPlan
from lightbulb.contract_obligations import ObligationRegister
from lightbulb.dynamic_workflows import (
    AcceptanceCriterion,
    BuilderOutcome,
    BuilderResult,
    DynamicWorkflowScope,
    EvaluatorDecision,
    EvaluatorVerdict,
)
from lightbulb.growth_primitives import CreateWorkPacketOutput
from lightbulb.primitive_runtime import (
    PrimitiveEvidenceClassification,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


CONTRACT_DELIVERY_GOLDEN_LOOP = "project.work_packet_independent_acceptance@0.1.0"
CONTRACT_DELIVERY_LOOP_EXTENSION = "contract_bound_delivery_and_customer_acceptance"
DELIVERY_SCOPE_SCHEMA = "lightbulb.contract_delivery_scope.v1"
DELIVERY_PLAN_SCHEMA = "lightbulb.contract_delivery_plan.v1"
DELIVERY_PLAN_RESULT_SCHEMA = "lightbulb.contract_delivery_plan_result.v1"
DELIVERABLE_BINDING_SCHEMA = "lightbulb.contract_deliverable_binding.v1"
DELIVERABLE_BINDING_RESULT_SCHEMA = "lightbulb.contract_deliverable_binding_result.v1"
DELIVERY_EVIDENCE_ASSESSMENT_SCHEMA = "lightbulb.contractual_delivery_evidence_assessment.v1"
ACCEPTED_VALUE_BINDING_SCHEMA = "lightbulb.accepted_value_binding.v1"
ACCEPTANCE_CANDIDATE_RESULT_SCHEMA = "lightbulb.customer_acceptance_candidate_result.v1"
CHANGE_ORDER_PROPOSAL_SCHEMA = "lightbulb.contract_change_order_proposal.v1"

GENESIS_DIGEST = "0" * 64
MAX_DELIVERABLES = 500
MAX_CRITERIA_PER_DELIVERABLE = 50

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_MONEY_QUANTUM = Decimal("0.000001")

_SECRET_LIKE_KEYS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "client_secret",
)
_IDENTITY_KEYS = frozenset({"tenant_id", "company_id", "user_id"})
_WORKFLOW_SCOPE_KEYS = frozenset({"tenant_id", "company_id", "user_id", "project_ref"})
_SECRET_LIKE_VALUE_PATTERNS = (
    re.compile(r"^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^(xox[abprs]-|ghp_|gho_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^(Bearer|Basic) [A-Za-z0-9._~+/=-]{8,}$", re.IGNORECASE),
)


def _reject_secret_like_text(value: str, *, label: str) -> None:
    for pattern in _SECRET_LIKE_VALUE_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"{label} must not carry credential-like material")


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, Mapping):
        # The Dynamic Workflow scope is the one existing contract that spells
        # identity with *_id keys.  It is recognised by its exact four-key shape
        # and compared for consistency only; it never grants authority here.
        is_workflow_scope = set(str(key) for key in value) == _WORKFLOW_SCOPE_KEYS
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            # Usage counters (input_tokens/output_tokens) on workflow contracts are
            # not credentials.
            credential_like = any(marker in lowered for marker in _SECRET_LIKE_KEYS) and not (
                lowered.endswith("_tokens")
            )
            if credential_like or (lowered in _IDENTITY_KEYS and not is_workflow_scope):
                raise ValueError(
                    f"{path}.{key_text} is a credential-like or authority-like field "
                    "and is never accepted"
                )
            _reject_secret_like_payload(item, path=f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _reject_secret_like_text(value, label=path)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    _reject_secret_like_text(value, label="reference")
    return value


OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN), AfterValidator(_visible_ref)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]

DeliverableKind = Literal["delivery", "service", "acceptance", "reporting"]
EvidenceCoverage = Literal["complete", "partial", "none"]
AcceptanceSource = Literal["independent_evaluator", "customer_signoff"]
AcceptanceState = Literal["accepted_full", "accepted_partial", "rejected"]
VarianceClassification = Literal[
    "clarification_no_change",
    "internal_delivery_correction",
    "schedule_only_change",
    "scope_change",
    "price_change",
    "acceptance_criteria_change",
    "regulatory_legal_change",
    "customer_requested_cancellation",
    "supplier_dependency_variance",
]
ChangeOrderDisposition = Literal[
    "no_contract_change",
    "internal_correction",
    "change_order_required",
    "cancellation_review_required",
]
ChangeOrderPath = Literal[
    "none",
    "internal_delivery_correction",
    "commercial_then_legal_amendment",
    "customer_cancellation_review",
]
DeliveryBlockerCode = Literal[
    "CUSTODY_DIGEST_MISMATCH",
    "AGREEMENT_EXPIRED",
    "AGREEMENT_NOT_YET_EFFECTIVE",
    "AGREEMENT_SUPERSEDED",
    "PROJECTION_NOT_BOUND_TO_CUSTODY",
    "REGISTER_NOT_BOUND_TO_AGREEMENT",
    "ROUTING_NOT_BOUND_TO_REGISTER",
    "UNASSIGNED_DELIVERABLE",
    "NOT_A_DELIVERY_OBLIGATION",
    "UNKNOWN_MILESTONE",
    "UNKNOWN_ORDER_LINE",
    "DEADLINE_OUTSIDE_AGREEMENT",
    "ALLOCATION_MISMATCH",
    "DEPENDENCY_UNRESOLVED",
    "DEPENDENCY_CYCLE",
    "DELIVERABLE_NOT_IN_PLAN",
    "ACCEPTANCE_CRITERIA_CHANGED",
    "WORK_PACKET_CRITERIA_MISMATCH",
    "BOUND_BEFORE_EFFECTIVE",
    "WORKFLOW_SCOPE_MISMATCH",
    "RUN_MISMATCH",
    "PLAN_DIGEST_MISMATCH",
    "BUILDER_NOT_COMPLETED",
    "EVIDENCE_ASSESSMENT_MISMATCH",
    "VERDICT_BUILDER_RESULT_MISMATCH",
    "BUILDER_SELF_ACCEPTANCE",
    "UNKNOWN_CRITERION",
    "ACCEPTED_CRITERION_WITHOUT_BUILDER_EVIDENCE",
    "SIGNOFF_EVIDENCE_INVALID",
    "ACCEPTANCE_BEFORE_WORK",
    "CLASSIFICATION_INCONSISTENT",
    "UNKNOWN_DELIVERABLE",
]

_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_secret_like_payload(value)
        return {
            str(key): (tuple(item) if isinstance(item, list) else item)
            for key, item in value.items()
        }

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _controlled(model: type[BaseModel]) -> Any:
    def validate(value: Any) -> Any:
        return model.model_validate(_detached(value))

    return BeforeValidator(validate)


ControlledCustody = Annotated[
    ExecutedCommercialAgreementCustodyCandidate, _controlled(ExecutedCommercialAgreementCustodyCandidate)
]
ControlledServiceDelivery = Annotated[ServiceDeliveryProjection, _controlled(ServiceDeliveryProjection)]
ControlledContractToCash = Annotated[ContractToCashProjection, _controlled(ContractToCashProjection)]
ControlledRegister = Annotated[ObligationRegister, _controlled(ObligationRegister)]
ControlledRouting = Annotated[ObligationRoutingPlan, _controlled(ObligationRoutingPlan)]
ControlledWorkflowScope = Annotated[DynamicWorkflowScope, _controlled(DynamicWorkflowScope)]
ControlledCriterion = Annotated[AcceptanceCriterion, _controlled(AcceptanceCriterion)]
ControlledWorkPacket = Annotated[CreateWorkPacketOutput, _controlled(CreateWorkPacketOutput)]
ControlledBuilderResult = Annotated[BuilderResult, _controlled(BuilderResult)]
ControlledEvaluatorVerdict = Annotated[EvaluatorVerdict, _controlled(EvaluatorVerdict)]
ControlledEvidenceRef = Annotated[PrimitiveEvidenceRef, _controlled(PrimitiveEvidenceRef)]


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string or integer")
    if isinstance(value, Decimal):
        parsed = value
    elif isinstance(value, int):
        parsed = Decimal(value)
    elif isinstance(value, str):
        if value != value.strip() or not value:
            raise ValueError(f"{field_name} must be a canonical decimal string")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} must be a canonical decimal string") from exc
    else:
        raise ValueError(f"{field_name} must be a decimal string or integer")
    if not parsed.is_finite():
        raise ValueError(f"{field_name} must be finite")
    if parsed.as_tuple().exponent < -6:
        raise ValueError(f"{field_name} supports at most six decimal places")
    if parsed < 0 and not allow_negative:
        raise ValueError(f"{field_name} cannot be negative")
    return parsed.quantize(_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest_without(payload: Mapping[str, Any], *fields: str) -> str:
    return _stable_digest({key: value for key, value in payload.items() if key not in fields})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sorted_unique_tuple(value: Any, *, label: str) -> Any:
    if not isinstance(value, (tuple, list)):
        return value
    items = tuple(value)
    _unique(list(items), label=label)
    return tuple(sorted(items))


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_delivery_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_delivery_digests": True})
    return _digest_without(parsed.to_dict(), field)


def _criteria_digest(criteria: Sequence[AcceptanceCriterion]) -> str:
    return _stable_digest([criterion.digest for criterion in criteria])


class DeliveryBlocker(_StrictModel):
    code: DeliveryBlockerCode
    detail: BoundedText
    refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="blocker refs")


class ContractDeliveryEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    builder_self_acceptance: Literal[False] = False
    project_completion_treated_as_acceptance: Literal[False] = False
    provider_upload_treated_as_acceptance: Literal[False] = False
    customer_acceptance_recorded: Literal[False] = False
    invoice_authorized: Literal[False] = False
    scope_mutated: Literal[False] = False
    prior_work_rewritten: Literal[False] = False
    persistence_written: Literal[False] = False
    connector_effect_executed: Literal[False] = False


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


class ContractDeliveryScope(_StrictModel):
    """Exact identity fence: commercial scope, executed agreement, workflow scope."""

    schema_id: Literal["lightbulb.contract_delivery_scope.v1"] = Field(
        default=DELIVERY_SCOPE_SCHEMA, alias="schema"
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    agreement_ref: OpaqueRef
    custody_candidate_digest: Sha256Digest
    workflow_scope: ControlledWorkflowScope
    evidence_custody_ref: OpaqueRef
    authorized_evidence_issuer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        from uuid import UUID

        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return value

    @field_validator("authorized_evidence_issuer_refs", mode="before")
    @classmethod
    def _issuers(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="authorized evidence issuers")


# --------------------------------------------------------------------------- #
# Delivery plan
# --------------------------------------------------------------------------- #


class CriterionAllocation(_StrictModel):
    criterion_id: ShortText
    amount: Decimal

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return _decimal(value, field_name="amount")


class DeliverableAssignment(_StrictModel):
    obligation_ref: OpaqueRef
    milestone_ref: OpaqueRef
    accountable_role_ref: OpaqueRef
    deadline_at: str
    order_line_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    acceptance_criteria: tuple[ControlledCriterion, ...] = Field(
        min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE
    )
    criterion_allocations: tuple[CriterionAllocation, ...] = Field(
        min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE
    )
    allocated_amount: Decimal
    depends_on_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("deadline_at")
    @classmethod
    def _deadline(cls, value: str) -> str:
        return _timestamp(value, field_name="deadline_at")

    @field_validator("allocated_amount", mode="before")
    @classmethod
    def _allocated(cls, value: Any) -> Any:
        return _decimal(value, field_name="allocated_amount")

    @field_validator("order_line_refs", "depends_on_obligation_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique_tuple(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _assignment_is_exact(self) -> "DeliverableAssignment":
        ids = [item.criterion_id for item in self.acceptance_criteria]
        _unique(ids, label="acceptance criterion ids")
        allocations = {item.criterion_id: item.amount for item in self.criterion_allocations}
        _unique([item.criterion_id for item in self.criterion_allocations], label="criterion allocations")
        if set(allocations) != set(ids):
            raise ValueError("criterion allocations must cover exactly the acceptance criteria")
        if sum(allocations.values(), Decimal(0)) != self.allocated_amount:
            raise ValueError("criterion allocations must sum to the deliverable allocation")
        if self.obligation_ref in self.depends_on_obligation_refs:
            raise ValueError("a deliverable cannot depend on itself")
        return self


class ContractDeliveryPlanInput(_StrictModel):
    scope: ContractDeliveryScope
    custody_candidate: ControlledCustody
    service_delivery: ControlledServiceDelivery
    contract_to_cash: ControlledContractToCash
    obligation_register: ControlledRegister
    routing_plan: ControlledRouting
    assignments: tuple[DeliverableAssignment, ...] = Field(min_length=1, max_length=MAX_DELIVERABLES)
    superseded_by_agreement_version: int | None = Field(default=None, ge=2, le=10_000)
    as_of: str
    requested_by_ref: OpaqueRef

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractDeliveryPlanInput":
        custody = self.custody_candidate
        commercial = custody.scope.commercial
        if (
            commercial.tenant_ref != self.scope.tenant_ref
            or commercial.company_ref != self.scope.company_ref
            or commercial.project_ref != self.scope.project_ref
            or str(commercial.project_id) != self.scope.project_id
        ):
            raise ValueError("custody candidate scope must exactly match delivery scope")
        if custody.contract_ref != self.scope.agreement_ref:
            raise ValueError("custody candidate contract must be the scoped agreement")
        _unique([item.obligation_ref for item in self.assignments], label="deliverable assignments")
        return self


class DeliveryMilestoneRef(_StrictModel):
    milestone_ref: OpaqueRef
    description: BoundedText
    due_at: str
    acceptance_required: bool

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return _timestamp(value, field_name="due_at")


class ContractDeliverable(_StrictModel):
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    kind: DeliverableKind
    direction: Literal["owed_by_company", "owed_to_company"]
    title: ShortText
    agreement_ref: OpaqueRef
    agreement_version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest
    milestone_ref: OpaqueRef
    milestone_due_at: str
    accountable_role_ref: OpaqueRef
    deadline_at: str
    order_line_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    acceptance_criteria: tuple[ControlledCriterion, ...] = Field(
        min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE
    )
    acceptance_contract_digest: Sha256Digest
    evidence_requirements: tuple[ShortText, ...] = Field(min_length=1, max_length=200)
    criterion_allocations: tuple[CriterionAllocation, ...] = Field(min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    allocated_amount: Decimal
    currency: CurrencyCode
    depends_on_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("milestone_due_at", "deadline_at")
    @classmethod
    def _timestamps(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @field_validator("allocated_amount", mode="before")
    @classmethod
    def _allocated(cls, value: Any) -> Any:
        return _decimal(value, field_name="allocated_amount")

    @model_validator(mode="after")
    def _deliverable_is_exact(self) -> "ContractDeliverable":
        if self.acceptance_contract_digest != _criteria_digest(self.acceptance_criteria):
            raise ValueError("acceptance_contract_digest must commit the exact immutable criteria")
        expected = tuple(sorted({kind for item in self.acceptance_criteria for kind in item.required_evidence}))
        if self.evidence_requirements != expected:
            raise ValueError("evidence_requirements must be derived from the acceptance criteria")
        if sum((item.amount for item in self.criterion_allocations), Decimal(0)) != self.allocated_amount:
            raise ValueError("criterion allocations must sum to the deliverable allocation")
        return self


class ContractDeliveryPlan(_StrictModel):
    schema_id: Literal["lightbulb.contract_delivery_plan.v1"] = Field(
        default=DELIVERY_PLAN_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    agreement_ref: OpaqueRef
    agreement_version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest
    customer_ref: OpaqueRef
    effective_at: str
    expires_at: str
    currency: CurrencyCode
    total_allocated: Decimal
    milestones: tuple[DeliveryMilestoneRef, ...] = Field(default_factory=tuple, max_length=100)
    deliverables: tuple[ContractDeliverable, ...] = Field(min_length=1, max_length=MAX_DELIVERABLES)
    as_of: str
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("effective_at", "expires_at", "as_of")
    @classmethod
    def _timestamps(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @field_validator("total_allocated", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        return _decimal(value, field_name="total_allocated")

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "ContractDeliveryPlan":
        refs = [item.obligation_ref for item in self.deliverables]
        _unique(refs, label="plan deliverables")
        if refs != sorted(refs):
            raise ValueError("deliverables must be sorted by obligation_ref")
        if self.custody_candidate_digest != self.scope.custody_candidate_digest:
            raise ValueError("plan must bind the scoped custody candidate")
        for item in self.deliverables:
            if (
                item.agreement_ref != self.agreement_ref
                or item.agreement_version != self.agreement_version
                or item.agreement_digest != self.agreement_digest
                or item.custody_candidate_digest != self.custody_candidate_digest
                or item.currency != self.currency
            ):
                raise ValueError("every deliverable must bind the plan's exact agreement")
        if sum((item.allocated_amount for item in self.deliverables), Decimal(0)) != self.total_allocated:
            raise ValueError("total_allocated must equal the sum of deliverable allocations")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(ContractDeliveryPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


class ContractDeliveryPlanResult(_StrictModel):
    schema_id: Literal["lightbulb.contract_delivery_plan_result.v1"] = Field(
        default=DELIVERY_PLAN_RESULT_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    plan: ContractDeliveryPlan | None = None
    blockers: tuple[DeliveryBlocker, ...] = Field(default_factory=tuple, max_length=200)
    effect_boundary: ContractDeliveryEffectBoundary = Field(default_factory=ContractDeliveryEffectBoundary)
    result_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _result_is_coherent(self, info: ValidationInfo) -> "ContractDeliveryPlanResult":
        if (self.plan is None) == (not self.blockers):
            raise ValueError("a plan result carries exactly a plan or blockers")
        if _skip(info):
            return self
        if self.result_digest != _sealed_digest(ContractDeliveryPlanResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact result")
        return self


def _dependency_cycles(edges: Mapping[str, Sequence[str]]) -> set[str]:
    state: dict[str, int] = {}
    in_cycle: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in sorted(edges.get(node, ())):
            if target not in edges:
                continue
            if state.get(target) == 1:
                in_cycle.update(stack[stack.index(target):])
            elif state.get(target) is None:
                visit(target)
        stack.pop()
        state[node] = 2

    for node in sorted(edges):
        if state.get(node) is None:
            visit(node)
    return in_cycle


def _agreement_blockers(
    custody: ExecutedCommercialAgreementCustodyCandidate,
    *,
    at: str,
    superseded_by: int | None,
    scope: ContractDeliveryScope,
) -> list[DeliveryBlocker]:
    blockers: list[DeliveryBlocker] = []
    moment = _parsed_timestamp(at)
    if custody.custody_candidate_digest != scope.custody_candidate_digest:
        blockers.append(
            DeliveryBlocker(
                code="CUSTODY_DIGEST_MISMATCH",
                detail="custody candidate does not match the scoped custody digest",
            )
        )
    if superseded_by is not None:
        blockers.append(
            DeliveryBlocker(
                code="AGREEMENT_SUPERSEDED",
                detail=f"agreement version {custody.agreement_version} was superseded by version {superseded_by}; new work requires the successor agreement",
            )
        )
    if moment >= _parsed_timestamp(custody.expires_at):
        blockers.append(
            DeliveryBlocker(code="AGREEMENT_EXPIRED", detail="an expired agreement cannot generate new work")
        )
    if moment < _parsed_timestamp(custody.effective_at):
        blockers.append(
            DeliveryBlocker(
                code="AGREEMENT_NOT_YET_EFFECTIVE",
                detail="work cannot be planned before the agreement becomes effective",
            )
        )
    return blockers


def compile_contract_delivery_plan(
    inputs: ContractDeliveryPlanInput | Mapping[str, Any],
) -> ContractDeliveryPlanResult:
    """Map executed-agreement deliverable obligations into a bounded delivery plan."""

    parsed = ContractDeliveryPlanInput.model_validate(_detached(inputs))
    custody = parsed.custody_candidate
    scope = parsed.scope
    blockers = _agreement_blockers(
        custody, at=parsed.as_of, superseded_by=parsed.superseded_by_agreement_version, scope=scope
    )

    def block(code: DeliveryBlockerCode, detail: str, refs: Sequence[str] = ()) -> None:
        blockers.append(DeliveryBlocker(code=code, detail=detail, refs=tuple(sorted(set(refs)))))

    digest = custody.custody_candidate_digest
    if parsed.service_delivery.custody_candidate_digest != digest or (
        parsed.contract_to_cash.custody_candidate_digest != digest
    ):
        block("PROJECTION_NOT_BOUND_TO_CUSTODY", "projections must derive from the same custody candidate")
    register = parsed.obligation_register
    if (
        register.agreement.agreement_ref != custody.contract_ref
        or register.agreement.version != custody.agreement_version
        or register.agreement.agreement_digest != custody.executed_agreement_digest
    ):
        block("REGISTER_NOT_BOUND_TO_AGREEMENT", "obligation register must bind the executed agreement version and digest")
    if parsed.routing_plan.register_digest != register.register_digest:
        block("ROUTING_NOT_BOUND_TO_REGISTER", "routing plan must derive from the exact register")
    definitions = {item.obligation_ref: item for item in register.definitions}
    routed = {
        item.obligation_ref
        for item in parsed.routing_plan.assignments
        if item.route == "project_service_delivery"
    }
    assigned = {item.obligation_ref: item for item in parsed.assignments}
    missing = sorted(routed - set(assigned))
    if missing:
        block("UNASSIGNED_DELIVERABLE", "every obligation routed to delivery needs an assignment", missing)
    extra = sorted(set(assigned) - routed)
    if extra:
        block("NOT_A_DELIVERY_OBLIGATION", "assignments may only target obligations routed to delivery", extra)
    milestones = {item.milestone_ref: item for item in parsed.service_delivery.delivery.milestones}
    order_lines = {line.order_line_ref for line in parsed.contract_to_cash.order.lines}
    effective = _parsed_timestamp(custody.effective_at)
    expires = _parsed_timestamp(custody.expires_at)
    for assignment in parsed.assignments:
        if assignment.milestone_ref not in milestones:
            block("UNKNOWN_MILESTONE", "assignment cites a milestone outside the service-delivery projection", [assignment.obligation_ref, assignment.milestone_ref])
        unknown_lines = sorted(set(assignment.order_line_refs) - order_lines)
        if unknown_lines:
            block("UNKNOWN_ORDER_LINE", "assignment cites order lines outside the executed order", [assignment.obligation_ref, *unknown_lines])
        deadline = _parsed_timestamp(assignment.deadline_at)
        if deadline < effective or deadline > expires:
            block("DEADLINE_OUTSIDE_AGREEMENT", "deliverable deadline must fall inside the agreement term", [assignment.obligation_ref])
        unresolved = sorted(dep for dep in assignment.depends_on_obligation_refs if dep not in assigned)
        if unresolved:
            block("DEPENDENCY_UNRESOLVED", "deliverable dependencies must be planned deliverables", [assignment.obligation_ref, *unresolved])
    cycles = _dependency_cycles({ref: list(item.depends_on_obligation_refs) for ref, item in assigned.items()})
    if cycles:
        block("DEPENDENCY_CYCLE", "deliverable dependencies form a cycle", sorted(cycles))
    total = sum((item.allocated_amount for item in parsed.assignments), Decimal(0))
    billing_total = Decimal(parsed.contract_to_cash.billing.total).quantize(_MONEY_QUANTUM)
    if total != billing_total or parsed.contract_to_cash.billing.currency != parsed.contract_to_cash.contract.currency:
        block(
            "ALLOCATION_MISMATCH",
            f"deliverable allocations ({total}) must equal the contracted billing total ({billing_total})",
        )

    if blockers:
        result = {
            "scope": scope.to_dict(),
            "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
        }
        result["result_digest"] = _sealed_digest(ContractDeliveryPlanResult, result, "result_digest")
        return ContractDeliveryPlanResult.model_validate(result)

    currency = parsed.contract_to_cash.billing.currency
    deliverables = []
    for ref in sorted(assigned):
        assignment = assigned[ref]
        definition = definitions[ref]
        milestone = milestones[assignment.milestone_ref]
        criteria = tuple(assignment.acceptance_criteria)
        deliverables.append(
            {
                "obligation_ref": ref,
                "definition_digest": definition.definition_digest,
                "kind": definition.kind,
                "direction": definition.direction,
                "title": definition.title,
                "agreement_ref": custody.contract_ref,
                "agreement_version": custody.agreement_version,
                "agreement_digest": custody.executed_agreement_digest,
                "custody_candidate_digest": digest,
                "milestone_ref": milestone.milestone_ref,
                "milestone_due_at": milestone.due_at,
                "accountable_role_ref": assignment.accountable_role_ref,
                "deadline_at": assignment.deadline_at,
                "order_line_refs": list(assignment.order_line_refs),
                "acceptance_criteria": [item.model_dump(mode="json") for item in criteria],
                "acceptance_contract_digest": _criteria_digest(criteria),
                "evidence_requirements": sorted({kind for item in criteria for kind in item.required_evidence}),
                "criterion_allocations": [
                    item.to_dict() for item in sorted(assignment.criterion_allocations, key=lambda item: item.criterion_id)
                ],
                "allocated_amount": str(assignment.allocated_amount),
                "currency": currency,
                "depends_on_obligation_refs": list(assignment.depends_on_obligation_refs),
            }
        )
    plan = {
        "scope": scope.to_dict(),
        "agreement_ref": custody.contract_ref,
        "agreement_version": custody.agreement_version,
        "agreement_digest": custody.executed_agreement_digest,
        "custody_candidate_digest": digest,
        "customer_ref": custody.customer_ref,
        "effective_at": custody.effective_at,
        "expires_at": custody.expires_at,
        "currency": currency,
        "total_allocated": str(total),
        "milestones": [
            {
                "milestone_ref": item.milestone_ref,
                "description": item.description,
                "due_at": item.due_at,
                "acceptance_required": item.acceptance_required,
            }
            for item in sorted(parsed.service_delivery.delivery.milestones, key=lambda item: item.milestone_ref)
        ],
        "deliverables": deliverables,
        "as_of": parsed.as_of,
    }
    plan["plan_digest"] = _sealed_digest(ContractDeliveryPlan, plan, "plan_digest")
    result = {"scope": scope.to_dict(), "plan": plan, "blockers": []}
    result["result_digest"] = _sealed_digest(ContractDeliveryPlanResult, result, "result_digest")
    return ContractDeliveryPlanResult.model_validate(result)


# --------------------------------------------------------------------------- #
# Deliverable ↔ work packet binding
# --------------------------------------------------------------------------- #


class ContractDeliverableBindingInput(_StrictModel):
    scope: ContractDeliveryScope
    plan: ContractDeliveryPlan
    obligation_ref: OpaqueRef
    work_packet: ControlledWorkPacket
    workflow_run_ref: OpaqueRef
    planner_plan_digest: Sha256Digest
    retained_acceptance_criteria: tuple[ControlledCriterion, ...] = Field(
        min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE
    )
    superseded_by_agreement_version: int | None = Field(default=None, ge=2, le=10_000)
    bound_at: str
    requested_by_ref: OpaqueRef

    @field_validator("bound_at")
    @classmethod
    def _bound(cls, value: str) -> str:
        return _timestamp(value, field_name="bound_at")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractDeliverableBindingInput":
        if self.plan.scope != self.scope:
            raise ValueError("plan scope must exactly match binding scope")
        return self


class ContractDeliverableBinding(_StrictModel):
    schema_id: Literal["lightbulb.contract_deliverable_binding.v1"] = Field(
        default=DELIVERABLE_BINDING_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    plan_digest: Sha256Digest
    deliverable: ContractDeliverable
    packet_ref: OpaqueRef
    work_packet_digest: Sha256Digest
    work_packet_state: Literal["draft", "pending_approval", "approved"]
    workflow_run_ref: OpaqueRef
    planner_plan_digest: Sha256Digest
    acceptance_contract_digest: Sha256Digest
    criterion_ids: tuple[ShortText, ...] = Field(min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    bound_at: str
    binding_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("bound_at")
    @classmethod
    def _bound(cls, value: str) -> str:
        return _timestamp(value, field_name="bound_at")

    @model_validator(mode="after")
    def _binding_is_exact(self, info: ValidationInfo) -> "ContractDeliverableBinding":
        if self.acceptance_contract_digest != self.deliverable.acceptance_contract_digest:
            raise ValueError("binding must retain the deliverable's exact acceptance contract")
        if self.criterion_ids != tuple(item.criterion_id for item in self.deliverable.acceptance_criteria):
            raise ValueError("criterion_ids must mirror the deliverable's acceptance criteria")
        if _skip(info):
            return self
        if self.binding_digest != _sealed_digest(ContractDeliverableBinding, self, "binding_digest"):
            raise ValueError("binding_digest must commit the exact binding")
        return self


class ContractDeliverableBindingResult(_StrictModel):
    schema_id: Literal["lightbulb.contract_deliverable_binding_result.v1"] = Field(
        default=DELIVERABLE_BINDING_RESULT_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    binding: ContractDeliverableBinding | None = None
    blockers: tuple[DeliveryBlocker, ...] = Field(default_factory=tuple, max_length=200)
    change_order_required: bool = False
    effect_boundary: ContractDeliveryEffectBoundary = Field(default_factory=ContractDeliveryEffectBoundary)
    result_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _result_is_coherent(self, info: ValidationInfo) -> "ContractDeliverableBindingResult":
        if (self.binding is None) == (not self.blockers):
            raise ValueError("a binding result carries exactly a binding or blockers")
        if self.change_order_required and self.binding is not None:
            raise ValueError("a bound deliverable cannot also require a change order")
        if _skip(info):
            return self
        if self.result_digest != _sealed_digest(ContractDeliverableBindingResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact result")
        return self


def work_packet_digest(packet: CreateWorkPacketOutput | Mapping[str, Any]) -> str:
    parsed = CreateWorkPacketOutput.model_validate(_detached(packet))
    return _stable_digest(parsed.model_dump(mode="json"))


def bind_contract_deliverable_to_work_packet(
    inputs: ContractDeliverableBindingInput | Mapping[str, Any],
) -> ContractDeliverableBindingResult:
    """Bind one contractual deliverable to a work packet and its immutable acceptance contract."""

    parsed = ContractDeliverableBindingInput.model_validate(_detached(inputs))
    plan = parsed.plan
    blockers: list[DeliveryBlocker] = []
    change_order = False

    def block(code: DeliveryBlockerCode, detail: str, refs: Sequence[str] = ()) -> None:
        blockers.append(DeliveryBlocker(code=code, detail=detail, refs=tuple(sorted(set(refs)))))

    deliverable = next((item for item in plan.deliverables if item.obligation_ref == parsed.obligation_ref), None)
    if deliverable is None:
        block("DELIVERABLE_NOT_IN_PLAN", "obligation is not a deliverable of the cited plan", [parsed.obligation_ref])
    bound_at = _parsed_timestamp(parsed.bound_at)
    if parsed.superseded_by_agreement_version is not None:
        block("AGREEMENT_SUPERSEDED", "a superseded agreement cannot generate new work")
    if bound_at >= _parsed_timestamp(plan.expires_at):
        block("AGREEMENT_EXPIRED", "an expired agreement cannot generate new work")
    if bound_at < _parsed_timestamp(plan.effective_at):
        block("BOUND_BEFORE_EFFECTIVE", "work cannot be bound before the agreement is effective")
    if deliverable is not None:
        retained = _criteria_digest(parsed.retained_acceptance_criteria)
        if retained != deliverable.acceptance_contract_digest:
            change_order = True
            block(
                "ACCEPTANCE_CRITERIA_CHANGED",
                "retained acceptance criteria differ from the contractual acceptance contract; an approved change order is required",
                [parsed.obligation_ref],
            )
        packet_criteria = set(parsed.work_packet.acceptance_criteria)
        missing = [item.criterion_id for item in deliverable.acceptance_criteria if item.description not in packet_criteria]
        if missing:
            block(
                "WORK_PACKET_CRITERIA_MISMATCH",
                "work packet must carry every contractual acceptance criterion verbatim",
                [parsed.obligation_ref, *missing],
            )

    if blockers:
        result = {
            "scope": parsed.scope.to_dict(),
            "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
            "change_order_required": change_order,
        }
        result["result_digest"] = _sealed_digest(ContractDeliverableBindingResult, result, "result_digest")
        return ContractDeliverableBindingResult.model_validate(result)

    assert deliverable is not None
    binding = {
        "scope": parsed.scope.to_dict(),
        "plan_digest": plan.plan_digest,
        "deliverable": deliverable.to_dict(),
        "packet_ref": parsed.work_packet.packet_ref,
        "work_packet_digest": work_packet_digest(parsed.work_packet),
        "work_packet_state": parsed.work_packet.state,
        "workflow_run_ref": parsed.workflow_run_ref,
        "planner_plan_digest": parsed.planner_plan_digest,
        "acceptance_contract_digest": deliverable.acceptance_contract_digest,
        "criterion_ids": [item.criterion_id for item in deliverable.acceptance_criteria],
        "bound_at": parsed.bound_at,
    }
    binding["binding_digest"] = _sealed_digest(ContractDeliverableBinding, binding, "binding_digest")
    result = {"scope": parsed.scope.to_dict(), "binding": binding, "blockers": [], "change_order_required": False}
    result["result_digest"] = _sealed_digest(ContractDeliverableBindingResult, result, "result_digest")
    return ContractDeliverableBindingResult.model_validate(result)


# --------------------------------------------------------------------------- #
# Contractual delivery evidence (non-authoritative)
# --------------------------------------------------------------------------- #


class CriterionEvidenceCoverage(_StrictModel):
    criterion_id: ShortText
    required_evidence: tuple[ShortText, ...] = Field(min_length=1, max_length=50)
    covered_kinds: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    missing_kinds: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    evidence_sha256: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=1000)
    coverage: EvidenceCoverage


class ContractualDeliveryEvidenceInput(_StrictModel):
    scope: ContractDeliveryScope
    binding: ContractDeliverableBinding
    builder_result: ControlledBuilderResult
    evaluated_at: str
    requested_by_ref: OpaqueRef

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractualDeliveryEvidenceInput":
        if self.binding.scope != self.scope:
            raise ValueError("binding scope must exactly match evidence scope")
        return self


class ContractualDeliveryEvidenceAssessment(_StrictModel):
    schema_id: Literal["lightbulb.contractual_delivery_evidence_assessment.v1"] = Field(
        default=DELIVERY_EVIDENCE_ASSESSMENT_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    binding_digest: Sha256Digest
    obligation_ref: OpaqueRef
    packet_ref: OpaqueRef
    acceptance_contract_digest: Sha256Digest
    builder_result_digest: Sha256Digest
    builder_context_id: str = Field(min_length=1, max_length=300)
    builder_session_id: str = Field(min_length=1, max_length=300)
    builder_outcome: Literal["completed", "failed", "blocked"]
    coverage_summary: EvidenceCoverage
    criteria: tuple[CriterionEvidenceCoverage, ...] = Field(min_length=1, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    acceptance_status: Literal["not_accepted_pending_independent_evaluation"] = (
        "not_accepted_pending_independent_evaluation"
    )
    blockers: tuple[DeliveryBlocker, ...] = Field(default_factory=tuple, max_length=200)
    evaluated_at: str
    effect_boundary: ContractDeliveryEffectBoundary = Field(default_factory=ContractDeliveryEffectBoundary)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ContractualDeliveryEvidenceAssessment":
        ids = [item.criterion_id for item in self.criteria]
        _unique(ids, label="criterion coverage")
        statuses = {item.coverage for item in self.criteria}
        expected: EvidenceCoverage
        if self.blockers or statuses == {"none"}:
            expected = "none"
        elif statuses == {"complete"}:
            expected = "complete"
        else:
            expected = "partial"
        if self.coverage_summary != expected:
            raise ValueError("coverage_summary must be derived from criterion coverage and blockers")
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ContractualDeliveryEvidenceAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def evaluate_contractual_delivery_evidence(
    inputs: ContractualDeliveryEvidenceInput | Mapping[str, Any],
) -> ContractualDeliveryEvidenceAssessment:
    """Check whether retained builder evidence addresses the contractual criteria; never accept."""

    parsed = ContractualDeliveryEvidenceInput.model_validate(_detached(inputs))
    binding = parsed.binding
    result = parsed.builder_result
    blockers: list[DeliveryBlocker] = []
    if result.scope != parsed.scope.workflow_scope:
        blockers.append(DeliveryBlocker(code="WORKFLOW_SCOPE_MISMATCH", detail="builder result belongs to a different dynamic workflow scope"))
    if result.run_ref != binding.workflow_run_ref:
        blockers.append(DeliveryBlocker(code="RUN_MISMATCH", detail="builder result belongs to a different workflow run", refs=(result.run_ref,)))
    if result.plan_digest != binding.planner_plan_digest:
        blockers.append(DeliveryBlocker(code="PLAN_DIGEST_MISMATCH", detail="builder result was produced against a different planner plan"))
    if result.outcome != BuilderOutcome.COMPLETED:
        blockers.append(DeliveryBlocker(code="BUILDER_NOT_COMPLETED", detail=f"builder outcome is {result.outcome.value}; evidence cannot address the criteria"))
    evidence_by_kind: dict[str, list[str]] = {}
    for item in result.evidence_refs:
        evidence_by_kind.setdefault(item.kind, []).append(item.sha256)
    criteria = []
    for criterion in binding.deliverable.acceptance_criteria:
        covered = tuple(sorted(kind for kind in criterion.required_evidence if kind in evidence_by_kind))
        missing = tuple(sorted(kind for kind in criterion.required_evidence if kind not in evidence_by_kind))
        if blockers or not covered:
            coverage: EvidenceCoverage = "none"
        elif missing:
            coverage = "partial"
        else:
            coverage = "complete"
        criteria.append(
            CriterionEvidenceCoverage(
                criterion_id=criterion.criterion_id,
                required_evidence=tuple(criterion.required_evidence),
                covered_kinds=covered if not blockers else (),
                missing_kinds=missing if not blockers else tuple(criterion.required_evidence),
                evidence_sha256=tuple(sorted({sha for kind in covered for sha in evidence_by_kind[kind]})) if not blockers else (),
                coverage=coverage,
            )
        )
    statuses = {item.coverage for item in criteria}
    summary: EvidenceCoverage = "none" if blockers or statuses == {"none"} else ("complete" if statuses == {"complete"} else "partial")
    assessment = {
        "scope": parsed.scope.to_dict(),
        "binding_digest": binding.binding_digest,
        "obligation_ref": binding.deliverable.obligation_ref,
        "packet_ref": binding.packet_ref,
        "acceptance_contract_digest": binding.acceptance_contract_digest,
        "builder_result_digest": result.digest,
        "builder_context_id": result.builder_context_id,
        "builder_session_id": result.builder_session_id,
        "builder_outcome": result.outcome.value,
        "coverage_summary": summary,
        "criteria": [item.to_dict() for item in criteria],
        "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
        "evaluated_at": parsed.evaluated_at,
    }
    assessment["assessment_digest"] = _sealed_digest(ContractualDeliveryEvidenceAssessment, assessment, "assessment_digest")
    return ContractualDeliveryEvidenceAssessment.model_validate(assessment)


# --------------------------------------------------------------------------- #
# Customer acceptance candidate → AcceptedValueBinding
# --------------------------------------------------------------------------- #


class CustomerSignoff(_StrictModel):
    signoff_ref: OpaqueRef
    accepted_by_party_ref: OpaqueRef
    accepted_criterion_ids: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    rejected_criterion_ids: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    signed_at: str
    evidence: ControlledEvidenceRef

    @field_validator("signed_at")
    @classmethod
    def _signed(cls, value: str) -> str:
        return _timestamp(value, field_name="signed_at")

    @field_validator("accepted_criterion_ids", "rejected_criterion_ids", mode="before")
    @classmethod
    def _ids(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique_tuple(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _signoff_is_exact(self) -> "CustomerSignoff":
        if set(self.accepted_criterion_ids) & set(self.rejected_criterion_ids):
            raise ValueError("a criterion cannot be both accepted and rejected")
        if self.evidence.kind != "customer_acceptance":
            raise ValueError("customer sign-off evidence must be a customer_acceptance reference")
        return self


class CustomerAcceptanceCandidateInput(_StrictModel):
    scope: ContractDeliveryScope
    binding: ContractDeliverableBinding
    evidence_assessment: ContractualDeliveryEvidenceAssessment
    evaluator_verdict: ControlledEvaluatorVerdict | None = None
    customer_signoff: CustomerSignoff | None = None
    accepted_at: str
    requested_by_ref: OpaqueRef

    @field_validator("accepted_at")
    @classmethod
    def _accepted(cls, value: str) -> str:
        return _timestamp(value, field_name="accepted_at")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "CustomerAcceptanceCandidateInput":
        if self.binding.scope != self.scope or self.evidence_assessment.scope != self.scope:
            raise ValueError("binding and evidence assessment must share the exact scope")
        if (self.evaluator_verdict is None) == (self.customer_signoff is None):
            raise ValueError("exactly one of evaluator_verdict or customer_signoff is required")
        return self


class AcceptedValueBinding(_StrictModel):
    """Candidate accepted value for contract-to-cash; Spring records the authoritative acceptance."""

    schema_id: Literal["lightbulb.accepted_value_binding.v1"] = Field(
        default=ACCEPTED_VALUE_BINDING_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    agreement_ref: OpaqueRef
    agreement_version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest
    obligation_ref: OpaqueRef
    definition_digest: Sha256Digest
    binding_digest: Sha256Digest
    packet_ref: OpaqueRef
    order_line_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    acceptance_source: AcceptanceSource
    acceptance_reference: str = Field(min_length=1, max_length=300)
    builder_result_digest: Sha256Digest
    accepted_criterion_ids: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    rejected_criterion_ids: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_CRITERIA_PER_DELIVERABLE)
    allocated_amount: Decimal
    accepted_amount: Decimal
    currency: CurrencyCode
    acceptance_state: AcceptanceState
    invoice_eligible: bool
    accepted_at: str
    authoritative: Literal[False] = False
    spring_acceptance_required: Literal[True] = True
    accepted_value_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("accepted_at")
    @classmethod
    def _accepted(cls, value: str) -> str:
        return _timestamp(value, field_name="accepted_at")

    @field_validator("allocated_amount", "accepted_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _decimal(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _binding_is_coherent(self, info: ValidationInfo) -> "AcceptedValueBinding":
        if set(self.accepted_criterion_ids) & set(self.rejected_criterion_ids):
            raise ValueError("a criterion cannot be both accepted and rejected")
        if self.accepted_amount > self.allocated_amount:
            raise ValueError("accepted amount cannot exceed the contractual allocation")
        if self.acceptance_state == "rejected":
            if self.accepted_amount != 0 or self.invoice_eligible:
                raise ValueError("rejected work carries no accepted value and is never invoice-eligible")
        elif self.acceptance_state == "accepted_full":
            if self.accepted_amount != self.allocated_amount or self.rejected_criterion_ids:
                raise ValueError("full acceptance requires every criterion and the full allocation")
        else:
            if not self.accepted_criterion_ids or not self.rejected_criterion_ids:
                raise ValueError("partial acceptance requires both accepted and rejected criteria")
        if self.invoice_eligible != (self.acceptance_state != "rejected" and self.accepted_amount > 0):
            raise ValueError("invoice eligibility must follow accepted value")
        if _skip(info):
            return self
        if self.accepted_value_digest != _sealed_digest(AcceptedValueBinding, self, "accepted_value_digest"):
            raise ValueError("accepted_value_digest must commit the exact binding")
        return self


class CustomerAcceptanceCandidateResult(_StrictModel):
    schema_id: Literal["lightbulb.customer_acceptance_candidate_result.v1"] = Field(
        default=ACCEPTANCE_CANDIDATE_RESULT_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    candidate: AcceptedValueBinding | None = None
    blockers: tuple[DeliveryBlocker, ...] = Field(default_factory=tuple, max_length=200)
    effect_boundary: ContractDeliveryEffectBoundary = Field(default_factory=ContractDeliveryEffectBoundary)
    result_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _result_is_coherent(self, info: ValidationInfo) -> "CustomerAcceptanceCandidateResult":
        if (self.candidate is None) == (not self.blockers):
            raise ValueError("an acceptance result carries exactly a candidate or blockers")
        if _skip(info):
            return self
        if self.result_digest != _sealed_digest(CustomerAcceptanceCandidateResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact result")
        return self


def compile_customer_acceptance_candidate(
    inputs: CustomerAcceptanceCandidateInput | Mapping[str, Any],
) -> CustomerAcceptanceCandidateResult:
    """Convert an independent verdict or verified customer sign-off into an AcceptedValueBinding candidate."""

    parsed = CustomerAcceptanceCandidateInput.model_validate(_detached(inputs))
    binding = parsed.binding
    assessment = parsed.evidence_assessment
    deliverable = binding.deliverable
    blockers: list[DeliveryBlocker] = []

    def block(code: DeliveryBlockerCode, detail: str, refs: Sequence[str] = ()) -> None:
        blockers.append(DeliveryBlocker(code=code, detail=detail, refs=tuple(sorted(set(refs)))))

    if assessment.binding_digest != binding.binding_digest:
        block("EVIDENCE_ASSESSMENT_MISMATCH", "evidence assessment does not belong to this binding")
    if assessment.blockers:
        block("EVIDENCE_ASSESSMENT_MISMATCH", "evidence assessment carries blockers; work was not evaluable", [item.code for item in assessment.blockers])
    criterion_ids = set(binding.criterion_ids)
    coverage = {item.criterion_id: item.coverage for item in assessment.criteria}
    accepted: list[str] = []
    rejected: list[str] = []
    source: AcceptanceSource
    reference: str
    decisive_accept = False

    if parsed.evaluator_verdict is not None:
        verdict = parsed.evaluator_verdict
        source = "independent_evaluator"
        reference = verdict.digest
        if verdict.scope != parsed.scope.workflow_scope:
            block("WORKFLOW_SCOPE_MISMATCH", "evaluator verdict belongs to a different dynamic workflow scope")
        if verdict.run_ref != binding.workflow_run_ref:
            block("RUN_MISMATCH", "evaluator verdict belongs to a different workflow run", [verdict.run_ref])
        if verdict.plan_digest != binding.planner_plan_digest:
            block("PLAN_DIGEST_MISMATCH", "evaluator verdict was produced against a different planner plan")
        if verdict.builder_result_digest != assessment.builder_result_digest:
            block("VERDICT_BUILDER_RESULT_MISMATCH", "evaluator verdict does not judge the assessed builder result")
        if (
            verdict.evaluator_context_id == assessment.builder_context_id
            or verdict.evaluator_session_id == assessment.builder_session_id
        ):
            block("BUILDER_SELF_ACCEPTANCE", "the builder cannot accept its own work; a fresh evaluator context is required")
        unknown = sorted({item.criterion_id for item in verdict.criterion_results} - criterion_ids)
        if unknown:
            block("UNKNOWN_CRITERION", "verdict evaluates criteria outside the acceptance contract", unknown)
        decisive_accept = verdict.decision == EvaluatorDecision.ACCEPT and verdict.accepted
        results = {item.criterion_id: item for item in verdict.criterion_results}
        for criterion_id in binding.criterion_ids:
            evaluation = results.get(criterion_id)
            if decisive_accept and evaluation is not None and evaluation.accepted:
                accepted.append(criterion_id)
            else:
                rejected.append(criterion_id)
    else:
        signoff = parsed.customer_signoff
        assert signoff is not None
        source = "customer_signoff"
        reference = signoff.evidence.evidence_ref
        evidence = signoff.evidence
        if (
            evidence.subject_ref != binding.binding_digest
            or evidence.issuer_ref not in parsed.scope.authorized_evidence_issuer_refs
            or _GRADE_RANK[evidence.verification_grade] < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.VERIFIED]
            or evidence.classification == PrimitiveEvidenceClassification.PUBLIC
        ):
            block("SIGNOFF_EVIDENCE_INVALID", "customer sign-off evidence must be verified, issuer-authorized, and bound to the binding digest", [evidence.evidence_ref])
        if _parsed_timestamp(signoff.signed_at) < _parsed_timestamp(assessment.evaluated_at):
            block("ACCEPTANCE_BEFORE_WORK", "customer sign-off predates the assessed builder evidence")
        unknown = sorted((set(signoff.accepted_criterion_ids) | set(signoff.rejected_criterion_ids)) - criterion_ids)
        if unknown:
            block("UNKNOWN_CRITERION", "sign-off cites criteria outside the acceptance contract", unknown)
        decisive_accept = bool(signoff.accepted_criterion_ids)
        for criterion_id in binding.criterion_ids:
            if criterion_id in signoff.accepted_criterion_ids:
                accepted.append(criterion_id)
            else:
                rejected.append(criterion_id)

    uncovered = sorted(criterion_id for criterion_id in accepted if coverage.get(criterion_id) == "none")
    if uncovered:
        block(
            "ACCEPTED_CRITERION_WITHOUT_BUILDER_EVIDENCE",
            "a criterion cannot be accepted when no retained builder evidence addresses it",
            uncovered,
        )

    if blockers:
        result = {
            "scope": parsed.scope.to_dict(),
            "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
        }
        result["result_digest"] = _sealed_digest(CustomerAcceptanceCandidateResult, result, "result_digest")
        return CustomerAcceptanceCandidateResult.model_validate(result)

    allocations = {item.criterion_id: item.amount for item in deliverable.criterion_allocations}
    if not decisive_accept:
        state: AcceptanceState = "rejected"
        accepted = []
        rejected = list(binding.criterion_ids)
        accepted_amount = Decimal(0)
    elif not rejected:
        state = "accepted_full"
        accepted_amount = deliverable.allocated_amount
    else:
        state = "accepted_partial"
        accepted_amount = sum((allocations[criterion_id] for criterion_id in accepted), Decimal(0))
    candidate = {
        "scope": parsed.scope.to_dict(),
        "agreement_ref": deliverable.agreement_ref,
        "agreement_version": deliverable.agreement_version,
        "agreement_digest": deliverable.agreement_digest,
        "custody_candidate_digest": deliverable.custody_candidate_digest,
        "obligation_ref": deliverable.obligation_ref,
        "definition_digest": deliverable.definition_digest,
        "binding_digest": binding.binding_digest,
        "packet_ref": binding.packet_ref,
        "order_line_refs": list(deliverable.order_line_refs),
        "acceptance_source": source,
        "acceptance_reference": reference,
        "builder_result_digest": assessment.builder_result_digest,
        "accepted_criterion_ids": sorted(accepted),
        "rejected_criterion_ids": sorted(rejected),
        "allocated_amount": str(deliverable.allocated_amount),
        "accepted_amount": str(accepted_amount.quantize(_MONEY_QUANTUM)),
        "currency": deliverable.currency,
        "acceptance_state": state,
        "invoice_eligible": state != "rejected" and accepted_amount > 0,
        "accepted_at": parsed.accepted_at,
    }
    candidate["accepted_value_digest"] = _sealed_digest(AcceptedValueBinding, candidate, "accepted_value_digest")
    result = {"scope": parsed.scope.to_dict(), "candidate": candidate, "blockers": []}
    result["result_digest"] = _sealed_digest(CustomerAcceptanceCandidateResult, result, "result_digest")
    return CustomerAcceptanceCandidateResult.model_validate(result)


# --------------------------------------------------------------------------- #
# Change-order proposal
# --------------------------------------------------------------------------- #


class DeliveryVariance(_StrictModel):
    variance_ref: OpaqueRef
    discovered_at: str
    discovered_by_ref: OpaqueRef
    classification: VarianceClassification
    description: BoundedText
    affected_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("discovered_at")
    @classmethod
    def _discovered(cls, value: str) -> str:
        return _timestamp(value, field_name="discovered_at")

    @field_validator("affected_obligation_refs", "evidence_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique_tuple(value, label=str(info.field_name))


class AcceptanceCriteriaChange(_StrictModel):
    obligation_ref: OpaqueRef
    criterion_id: ShortText | None = None
    proposed_description: BoundedText
    reason: BoundedText


class ChangeImpact(_StrictModel):
    schedule_days_delta: int = Field(default=0, ge=-3650, le=3650)
    price_delta: Decimal = Decimal(0)
    currency: CurrencyCode
    scope_delta: BoundedText | None = None
    acceptance_criteria_changes: tuple[AcceptanceCriteriaChange, ...] = Field(default_factory=tuple, max_length=100)
    assumption_changes: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("price_delta", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Any:
        return _decimal(value, field_name="price_delta", allow_negative=True)

    @property
    def is_contractual(self) -> bool:
        return bool(
            self.schedule_days_delta
            or self.price_delta != 0
            or self.scope_delta
            or self.acceptance_criteria_changes
            or self.assumption_changes
        )


class ContractChangeOrderInput(_StrictModel):
    scope: ContractDeliveryScope
    plan: ContractDeliveryPlan
    variance: DeliveryVariance
    impact: ChangeImpact
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ContractChangeOrderInput":
        if self.plan.scope != self.scope:
            raise ValueError("plan scope must exactly match change-order scope")
        if self.impact.currency != self.plan.currency:
            raise ValueError("impact currency must match the plan currency")
        return self


class ContractChangeOrderProposal(_StrictModel):
    schema_id: Literal["lightbulb.contract_change_order_proposal.v1"] = Field(
        default=CHANGE_ORDER_PROPOSAL_SCHEMA, alias="schema"
    )
    scope: ContractDeliveryScope
    agreement_ref: OpaqueRef
    agreement_version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest
    plan_digest: Sha256Digest
    variance: DeliveryVariance
    impact: ChangeImpact
    disposition: ChangeOrderDisposition
    required_path: ChangeOrderPath
    minimum_agreement_version: int | None = Field(default=None, ge=2, le=10_000)
    affected_deliverables: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    blockers: tuple[DeliveryBlocker, ...] = Field(default_factory=tuple, max_length=200)
    prior_work_preserved: Literal[True] = True
    prior_evidence_preserved: Literal[True] = True
    prior_acceptance_rewritten: Literal[False] = False
    prior_invoices_rewritten: Literal[False] = False
    scope_mutated: Literal[False] = False
    effect_boundary: ContractDeliveryEffectBoundary = Field(default_factory=ContractDeliveryEffectBoundary)
    proposal_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _proposal_is_coherent(self, info: ValidationInfo) -> "ContractChangeOrderProposal":
        expected_path = {
            "no_contract_change": "none",
            "internal_correction": "internal_delivery_correction",
            "change_order_required": "commercial_then_legal_amendment",
            "cancellation_review_required": "customer_cancellation_review",
        }[self.disposition]
        if self.required_path != expected_path:
            raise ValueError("required_path must follow the disposition")
        if (self.minimum_agreement_version is not None) != (
            self.disposition in {"change_order_required", "cancellation_review_required"}
        ):
            raise ValueError("a minimum agreement version exists exactly for contractual changes")
        if self.minimum_agreement_version is not None and self.minimum_agreement_version <= self.agreement_version:
            raise ValueError("a change order must target a later agreement version")
        if _skip(info):
            return self
        if self.proposal_digest != _sealed_digest(ContractChangeOrderProposal, self, "proposal_digest"):
            raise ValueError("proposal_digest must commit the exact proposal")
        return self


_CONTRACTUAL_CLASSIFICATIONS = frozenset(
    {
        "schedule_only_change",
        "scope_change",
        "price_change",
        "acceptance_criteria_change",
        "regulatory_legal_change",
    }
)


def propose_contract_change_order(
    inputs: ContractChangeOrderInput | Mapping[str, Any],
) -> ContractChangeOrderProposal:
    """Classify a delivery variance and route contractual changes back through commercial and legal review."""

    parsed = ContractChangeOrderInput.model_validate(_detached(inputs))
    plan = parsed.plan
    variance = parsed.variance
    impact = parsed.impact
    blockers: list[DeliveryBlocker] = []
    deliverables = {item.obligation_ref for item in plan.deliverables}
    unknown = sorted(set(variance.affected_obligation_refs) - deliverables)
    if unknown:
        blockers.append(DeliveryBlocker(code="UNKNOWN_DELIVERABLE", detail="variance cites obligations outside the plan", refs=tuple(unknown)))
    changed_criteria = sorted({item.obligation_ref for item in impact.acceptance_criteria_changes} - deliverables)
    if changed_criteria:
        blockers.append(DeliveryBlocker(code="UNKNOWN_DELIVERABLE", detail="criteria changes cite obligations outside the plan", refs=tuple(changed_criteria)))

    classification = variance.classification
    inconsistent: str | None = None
    if classification in {"clarification_no_change", "internal_delivery_correction"} and impact.is_contractual:
        inconsistent = f"{classification} cannot carry schedule, price, scope, criteria, or assumption changes"
    elif classification == "schedule_only_change" and (
        impact.schedule_days_delta == 0 or impact.price_delta != 0 or impact.scope_delta or impact.acceptance_criteria_changes
    ):
        inconsistent = "schedule_only_change must carry exactly a non-zero schedule delta"
    elif classification == "price_change" and impact.price_delta == 0:
        inconsistent = "price_change must carry a non-zero price delta"
    elif classification == "scope_change" and not impact.scope_delta:
        inconsistent = "scope_change must describe the scope delta"
    elif classification == "acceptance_criteria_change" and not impact.acceptance_criteria_changes:
        inconsistent = "acceptance_criteria_change must list the proposed criteria changes"
    if inconsistent:
        blockers.append(DeliveryBlocker(code="CLASSIFICATION_INCONSISTENT", detail=inconsistent))

    if classification == "clarification_no_change":
        disposition: ChangeOrderDisposition = "no_contract_change"
    elif classification == "internal_delivery_correction":
        disposition = "internal_correction"
    elif classification == "customer_requested_cancellation":
        disposition = "cancellation_review_required"
    elif classification in _CONTRACTUAL_CLASSIFICATIONS or impact.is_contractual:
        disposition = "change_order_required"
    else:
        disposition = "internal_correction"
    if blockers:
        # An inconsistent or unknown variance is never silently downgraded.
        disposition = "change_order_required"
    required_path: ChangeOrderPath = {
        "no_contract_change": "none",
        "internal_correction": "internal_delivery_correction",
        "change_order_required": "commercial_then_legal_amendment",
        "cancellation_review_required": "customer_cancellation_review",
    }[disposition]
    proposal = {
        "scope": parsed.scope.to_dict(),
        "agreement_ref": plan.agreement_ref,
        "agreement_version": plan.agreement_version,
        "agreement_digest": plan.agreement_digest,
        "custody_candidate_digest": plan.custody_candidate_digest,
        "plan_digest": plan.plan_digest,
        "variance": variance.to_dict(),
        "impact": impact.to_dict(),
        "disposition": disposition,
        "required_path": required_path,
        "minimum_agreement_version": (
            plan.agreement_version + 1
            if disposition in {"change_order_required", "cancellation_review_required"}
            else None
        ),
        "affected_deliverables": sorted(set(variance.affected_obligation_refs) & deliverables),
        "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
    }
    proposal["proposal_digest"] = _sealed_digest(ContractChangeOrderProposal, proposal, "proposal_digest")
    return ContractChangeOrderProposal.model_validate(proposal)


__all__ = [
    "ACCEPTANCE_CANDIDATE_RESULT_SCHEMA",
    "ACCEPTED_VALUE_BINDING_SCHEMA",
    "CHANGE_ORDER_PROPOSAL_SCHEMA",
    "CONTRACT_DELIVERY_GOLDEN_LOOP",
    "CONTRACT_DELIVERY_LOOP_EXTENSION",
    "DELIVERABLE_BINDING_RESULT_SCHEMA",
    "DELIVERABLE_BINDING_SCHEMA",
    "DELIVERY_EVIDENCE_ASSESSMENT_SCHEMA",
    "DELIVERY_PLAN_RESULT_SCHEMA",
    "DELIVERY_PLAN_SCHEMA",
    "DELIVERY_SCOPE_SCHEMA",
    "GENESIS_DIGEST",
    "AcceptanceCriteriaChange",
    "AcceptedValueBinding",
    "ChangeImpact",
    "ContractChangeOrderInput",
    "ContractChangeOrderProposal",
    "ContractDeliverable",
    "ContractDeliverableBinding",
    "ContractDeliverableBindingInput",
    "ContractDeliverableBindingResult",
    "ContractDeliveryEffectBoundary",
    "ContractDeliveryPlan",
    "ContractDeliveryPlanInput",
    "ContractDeliveryPlanResult",
    "ContractDeliveryScope",
    "ContractualDeliveryEvidenceAssessment",
    "ContractualDeliveryEvidenceInput",
    "CriterionAllocation",
    "CriterionEvidenceCoverage",
    "CustomerAcceptanceCandidateInput",
    "CustomerAcceptanceCandidateResult",
    "CustomerSignoff",
    "DeliverableAssignment",
    "DeliveryBlocker",
    "DeliveryMilestoneRef",
    "DeliveryVariance",
    "bind_contract_deliverable_to_work_packet",
    "compile_contract_delivery_plan",
    "compile_customer_acceptance_candidate",
    "evaluate_contractual_delivery_evidence",
    "propose_contract_change_order",
    "work_packet_digest",
]
