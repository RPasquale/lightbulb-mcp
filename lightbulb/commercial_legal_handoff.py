"""Deterministic commercial-to-legal handoff and executed-agreement reconciliation.

This module connects the existing commercial operations lifecycle (approved
quote → contract/order review → subscription → billing) to legal review
without creating a second quote, order, or contract lifecycle.  It defines:

* a typed **legal review packet** compiled from a ``quote_proposed`` commercial
  snapshot plus the approved quote, draft order, draft contract, agreement
  package, commercial term sheet, playbooks, negotiation boundaries, required
  reviewers and approvals, and source artifact references;
* a typed **legal review outcome** authored by the legal agent, and a
  deterministic validation of that outcome against the packet's boundaries;
* a deterministic **executed-agreement reconciliation** whose only successful
  terminal is an exact, evidence-bound
  ``ExecutedCommercialAgreementCustodyCandidate`` eligible for Spring custody,
  with separate projections for contract-to-cash (the existing
  ``review_contract_order`` stage), project/service delivery, and
  contract-obligation fulfillment.

Ownership: Sales decides the commercial objective; Legal decides legal
interpretation and negotiation posture; these primitives define the typed
handoff and reconciliation; Spring authorizes approvals and retains executed
agreement custody; workflows observe signature, delivery, obligation, invoice,
and collection outcomes; MCP exposes the same governed operations.

Invariants enforced here: a legal change to price, quantity, currency, scope,
term, billing, renewal, or termination economics forces a new commercial
revision; legal findings never mutate sales artifacts; sales cannot discard
unresolved legal deviations; a signed agreement must match the reviewed
agreement digests and required signers.  Nothing here authenticates an actor,
approves anything, signs anything, persists anything, or invokes a connector.
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

from lightbulb.commercial_controls import (
    CommercialContractSnapshot,
    CommercialOrderSnapshot,
    CommercialQuoteSnapshot,
)
from lightbulb.commercial_operations_lifecycle import (
    CommercialLifecycleScope,
    CommercialOperationsLifecycleSnapshot,
)
from lightbulb.primitive_runtime import (
    PrimitiveEvidenceClassification,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP = (
    "commercial.approved_quote_to_executed_agreement_custody@0.1.0"
)
HANDOFF_SCOPE_SCHEMA = "lightbulb.commercial_legal_handoff_scope.v1"
LEGAL_REVIEW_PACKET_SCHEMA = "lightbulb.commercial_legal_review_packet.v1"
LEGAL_REVIEW_OUTCOME_SCHEMA = "lightbulb.commercial_legal_review_outcome.v1"
LEGAL_REVIEW_VALIDATION_SCHEMA = "lightbulb.commercial_legal_review_outcome_validation.v1"
EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA = (
    "lightbulb.commercial_legal_handoff_custody_candidate.v1"
)
CONTRACT_TO_CASH_PROJECTION_SCHEMA = "lightbulb.contract_to_cash_projection.v1"
SERVICE_DELIVERY_PROJECTION_SCHEMA = "lightbulb.service_delivery_projection.v1"
OBLIGATION_FULFILLMENT_PROJECTION_SCHEMA = "lightbulb.obligation_fulfillment_projection.v1"
EXECUTED_AGREEMENT_RECONCILIATION_SCHEMA = (
    "lightbulb.executed_agreement_reconciliation.v1"
)

GENESIS_DIGEST = "0" * 64
MAX_AGREEMENT_DOCUMENTS = 20
MAX_FINDINGS = 500
MAX_PROPOSED_OBLIGATIONS = 500
MAX_SIGNERS = 100

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

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
    "tenant_id",
    "company_id",
    "user_id",
)
# Embedded document bodies are rejected by exact key; digests and refs of a
# clause or document are the intended way to cite content.
_DOCUMENT_BODY_KEYS = frozenset(
    {"document_text", "document_body", "clause_text", "body", "full_text", "content"}
)
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
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS) or (
                lowered in _DOCUMENT_BODY_KEYS
            ):
                raise ValueError(
                    f"{path}.{key_text} is a credential-, authority-, or document-body "
                    "field and is never accepted; pass source artifact references"
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


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]

AgreementDocumentKind = Literal["nda", "msa", "sow", "order_form", "dpa", "amendment"]
CommercialTermPath = Literal[
    "price",
    "quantity",
    "currency",
    "scope",
    "term",
    "billing",
    "renewal",
    "termination",
    "notice",
    "delivery",
    "acceptance",
    "entitlement",
    "liability",
    "indemnity",
    "ip",
    "data_protection",
    "confidentiality",
    "sla",
    "other",
]
ECONOMIC_TERM_PATHS: frozenset[str] = frozenset(
    {"price", "quantity", "currency", "scope", "term", "billing", "renewal", "termination"}
)
NegotiationBoundaryKind = Literal["fixed", "negotiable_within_policy", "escalate_for_change"]
ApprovalKind = Literal["legal", "finance", "security", "executive", "commercial"]
FindingSeverity = Literal["low", "medium", "high", "critical"]
ReviewDisposition = Literal[
    "approved",
    "revision_required",
    "commercial_reapproval_required",
    "rejected",
]
SignatureReadiness = Literal["ready", "blocked"]
UnresolvedAction = Literal[
    "counterparty_response",
    "commercial_reapproval",
    "executive_approval",
    "legal_escalation",
]
ProposedObligationKind = Literal[
    "monetary",
    "service",
    "notice",
    "reporting",
    "compliance",
    "delivery",
    "acceptance",
    "restriction",
]
ObligationDirection = Literal["owed_by_company", "owed_to_company"]
ReconciliationDisposition = Literal[
    "executed_custody_candidate",
    "commercial_revision_required",
    "legal_revision_required",
    "signature_incomplete",
    "rejected",
]
OutcomeViolationCode = Literal[
    "PACKET_DIGEST_MISMATCH",
    "REQUIRED_DOCUMENT_NOT_REVIEWED",
    "REVIEWED_DOCUMENT_UNKNOWN",
    "DOCUMENT_VERSION_REGRESSED",
    "REVIEWER_NOT_REQUIRED",
    "REVIEW_EVIDENCE_INVALID",
    "DEVIATION_ON_FIXED_TERM",
    "DEVIATION_PLAYBOOK_NOT_AUTHORIZED",
    "DEVIATION_REQUIRES_ESCALATION_APPROVAL",
    "APPROVED_WITH_UNRESOLVED_DEVIATIONS",
    "ECONOMIC_CHANGE_WITHOUT_COMMERCIAL_REAPPROVAL",
    "SIGNATURE_READY_WITHOUT_APPROVAL",
    "APPROVED_BUT_SIGNATURE_BLOCKED",
    "REQUIRED_SIGNER_DROPPED",
    "OBLIGATION_DOCUMENT_NOT_REVIEWED",
    "FINDING_DOCUMENT_NOT_REVIEWED",
]
ReconciliationBlockerCode = Literal[
    "OUTCOME_VALIDATION_NOT_ACCEPTED",
    "STALE_COMMERCIAL_SNAPSHOT",
    "OUTCOME_REJECTED",
    "LEGAL_REVISION_REQUIRED",
    "COMMERCIAL_REAPPROVAL_REQUIRED",
    "ECONOMIC_TERMS_CHANGED",
    "UNRESOLVED_DEVIATIONS_RETAINED",
    "SIGNATURE_NOT_READY",
    "EXECUTED_DOCUMENT_MISSING",
    "EXECUTED_DOCUMENT_UNKNOWN",
    "AGREEMENT_DIGEST_MISMATCH",
    "SIGNATURE_MISSING",
    "SIGNATURE_UNEXPECTED",
    "SIGNATURE_DIGEST_MISMATCH",
    "SIGNATURE_AFTER_RECONCILIATION",
    "CLAUSE_DIGEST_CONFLICT",
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
    """Detach and revalidate a reused commercial contract at this boundary."""

    def validate(value: Any) -> Any:
        return model.model_validate(_detached(value))

    return BeforeValidator(validate)


ControlledCommercialScope = Annotated[CommercialLifecycleScope, _controlled(CommercialLifecycleScope)]
ControlledCommercialSnapshot = Annotated[
    CommercialOperationsLifecycleSnapshot, _controlled(CommercialOperationsLifecycleSnapshot)
]
ControlledQuote = Annotated[CommercialQuoteSnapshot, _controlled(CommercialQuoteSnapshot)]
ControlledOrder = Annotated[CommercialOrderSnapshot, _controlled(CommercialOrderSnapshot)]
ControlledContract = Annotated[CommercialContractSnapshot, _controlled(CommercialContractSnapshot)]
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


def _decimal(value: Any, *, field_name: str) -> Decimal:
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
    return parsed


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
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


def _skip_digests(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_handoff_digests"))


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


class CommercialLegalHandoffScope(_StrictModel):
    """Exact portable identity fence around one commercial lifecycle scope."""

    schema_id: Literal["lightbulb.commercial_legal_handoff_scope.v1"] = Field(
        default=HANDOFF_SCOPE_SCHEMA, alias="schema"
    )
    commercial: ControlledCommercialScope
    opportunity_ref: OpaqueRef
    evidence_custody_ref: OpaqueRef
    authorized_evidence_issuer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)

    @field_validator("authorized_evidence_issuer_refs", mode="before")
    @classmethod
    def _issuers(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="authorized evidence issuers")


def commercial_legal_handoff_scope_digest(
    scope: CommercialLegalHandoffScope | Mapping[str, Any],
) -> str:
    return _stable_digest(CommercialLegalHandoffScope.model_validate(_detached(scope)).to_dict())


# --------------------------------------------------------------------------- #
# Agreement package and commercial term sheet
# --------------------------------------------------------------------------- #


class AgreementPackageItem(_StrictModel):
    document_kind: AgreementDocumentKind
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    version: int = Field(ge=1, le=10_000)
    required: bool = True


class EntitlementTerm(_StrictModel):
    order_line_ref: OpaqueRef
    product_ref: OpaqueRef
    quantity: Decimal
    unit_price: Decimal

    @field_validator("quantity", "unit_price", mode="before")
    @classmethod
    def _decimals(cls, value: Any, info: ValidationInfo) -> Any:
        parsed = _decimal(value, field_name=str(info.field_name))
        if parsed < 0 or (info.field_name == "quantity" and parsed <= 0):
            raise ValueError(f"{info.field_name} must be positive")
        return parsed


class DeliveryMilestone(_StrictModel):
    milestone_ref: OpaqueRef
    description: BoundedText
    due_at: str
    acceptance_required: bool = True

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return _timestamp(value, field_name="due_at")


class DeliveryTerm(_StrictModel):
    delivery_model: Literal["saas", "managed_service", "professional_services", "physical", "hybrid"]
    start_at: str
    milestones: tuple[DeliveryMilestone, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("start_at")
    @classmethod
    def _start(cls, value: str) -> str:
        return _timestamp(value, field_name="start_at")

    @model_validator(mode="after")
    def _milestones_are_ordered(self) -> "DeliveryTerm":
        _unique([item.milestone_ref for item in self.milestones], label="milestone refs")
        start = _parsed_timestamp(self.start_at)
        for milestone in self.milestones:
            if _parsed_timestamp(milestone.due_at) < start:
                raise ValueError("milestones cannot be due before delivery starts")
        return self


class AcceptanceTerm(_StrictModel):
    acceptance_window_days: int = Field(ge=0, le=365)
    deemed_acceptance: bool = False
    criteria_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("criteria_refs", mode="before")
    @classmethod
    def _criteria(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="acceptance criteria refs")


class BillingTerm(_StrictModel):
    billing_model: Literal["flat", "seat", "usage", "hybrid"]
    frequency: Literal["one_time", "monthly", "quarterly", "annually"]
    payment_terms_days: int = Field(ge=0, le=365)
    currency: CurrencyCode
    total: Decimal
    invoicing_trigger: Literal["signature", "delivery", "acceptance", "period_start"]

    @field_validator("total", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        parsed = _decimal(value, field_name="total")
        if parsed < 0:
            raise ValueError("total cannot be negative")
        return parsed


class RenewalTerm(_StrictModel):
    auto_renew: bool
    term_months: int = Field(ge=1, le=240)
    notice_days: int = Field(ge=0, le=365)
    price_change_cap_ratio: Decimal | None = None

    @field_validator("price_change_cap_ratio", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> Any:
        if value is None:
            return None
        parsed = _decimal(value, field_name="price_change_cap_ratio")
        if not 0 <= parsed <= 1:
            raise ValueError("price_change_cap_ratio must lie within [0, 1]")
        return parsed


class TerminationTerm(_StrictModel):
    for_convenience: bool
    notice_days: int = Field(ge=0, le=365)
    cure_days: int = Field(ge=0, le=365)


class NoticeTerm(_StrictModel):
    channel: Literal["email", "portal", "registered_mail", "counsel"]
    address_ref: OpaqueRef


class CommercialTermSheet(_StrictModel):
    entitlements: tuple[EntitlementTerm, ...] = Field(min_length=1, max_length=5_000)
    delivery: DeliveryTerm
    acceptance: AcceptanceTerm
    billing: BillingTerm
    renewal: RenewalTerm
    termination: TerminationTerm
    notice: NoticeTerm

    @model_validator(mode="after")
    def _terms_are_coherent(self) -> "CommercialTermSheet":
        _unique([item.order_line_ref for item in self.entitlements], label="entitlement order lines")
        if self.renewal.notice_days > self.renewal.term_months * 31:
            raise ValueError("renewal notice cannot exceed the renewal term")
        return self


class NegotiationBoundary(_StrictModel):
    term_path: CommercialTermPath
    boundary: NegotiationBoundaryKind
    policy_ref: OpaqueRef | None = None

    @model_validator(mode="after")
    def _policy_matches_boundary(self) -> "NegotiationBoundary":
        if (self.boundary == "negotiable_within_policy") != (self.policy_ref is not None):
            raise ValueError("policy_ref is required exactly for negotiable_within_policy")
        return self


class ApprovalRequirement(_StrictModel):
    approval_kind: ApprovalKind
    approver_role_ref: OpaqueRef
    reason: BoundedText


# --------------------------------------------------------------------------- #
# Legal review packet
# --------------------------------------------------------------------------- #


def _quote_lines_payload(quote: CommercialQuoteSnapshot) -> list[dict[str, Any]]:
    return sorted(
        (
            {
                "quote_line_ref": line.quote_line_ref,
                "product_ref": line.product_ref,
                "quantity": str(line.quantity),
                "unit_price": str(line.unit_price),
                "line_total": str(line.line_total),
            }
            for line in quote.lines
        ),
        key=lambda item: item["quote_line_ref"],
    )


def approved_commercial_terms_digest(
    quote: CommercialQuoteSnapshot | Mapping[str, Any],
    order: CommercialOrderSnapshot | Mapping[str, Any],
    contract: CommercialContractSnapshot | Mapping[str, Any],
    terms: CommercialTermSheet | Mapping[str, Any],
) -> str:
    """Digest the exact approved commercial economics legal is asked to review."""

    parsed_quote = CommercialQuoteSnapshot.model_validate(_detached(quote))
    parsed_order = CommercialOrderSnapshot.model_validate(_detached(order))
    parsed_contract = CommercialContractSnapshot.model_validate(_detached(contract))
    parsed_terms = CommercialTermSheet.model_validate(_detached(terms))
    return _stable_digest(
        {
            "quote_ref": parsed_quote.quote_ref,
            "quote_revision": parsed_quote.revision,
            "quote_total": str(parsed_quote.total),
            "quote_lines": _quote_lines_payload(parsed_quote),
            "order_ref": parsed_order.order_ref,
            "order_revision": parsed_order.revision,
            "order_total": str(parsed_order.total),
            "contract_ref": parsed_contract.contract_ref,
            "contract_revision": parsed_contract.revision,
            "contract_value": str(parsed_contract.contract_value),
            "currency": parsed_contract.currency,
            "effective_at": parsed_contract.effective_at,
            "expires_at": parsed_contract.expires_at,
            "required_signer_refs": sorted(parsed_contract.required_signer_refs),
            "terms": parsed_terms.to_dict(),
        }
    )


class LegalReviewPacketInput(_StrictModel):
    scope: CommercialLegalHandoffScope
    commercial_snapshot: ControlledCommercialSnapshot
    approved_quote: ControlledQuote
    draft_order: ControlledOrder
    draft_contract: ControlledContract
    agreement_package: tuple[AgreementPackageItem, ...] = Field(
        min_length=1, max_length=MAX_AGREEMENT_DOCUMENTS
    )
    commercial_terms: CommercialTermSheet
    jurisdiction_ref: OpaqueRef
    required_playbook_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    negotiation_boundaries: tuple[NegotiationBoundary, ...] = Field(
        default_factory=tuple, max_length=50
    )
    required_reviewer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    required_approvals: tuple[ApprovalRequirement, ...] = Field(
        default_factory=tuple, max_length=50
    )
    requested_completion_at: str
    source_artifact_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=200)
    requested_by_ref: OpaqueRef

    @field_validator("requested_completion_at")
    @classmethod
    def _completion(cls, value: str) -> str:
        return _timestamp(value, field_name="requested_completion_at")

    @field_validator(
        "required_playbook_refs", "required_reviewer_refs", "source_artifact_refs", mode="before"
    )
    @classmethod
    def _sorted_refs(cls, value: Any, info: ValidationInfo) -> Any:
        return _sorted_unique_tuple(value, label=str(info.field_name))

    @model_validator(mode="after")
    def _packet_input_is_exact(self) -> "LegalReviewPacketInput":
        scope = self.scope.commercial
        snapshot = self.commercial_snapshot
        if snapshot.scope != scope:
            raise ValueError("commercial snapshot scope must exactly match handoff scope")
        if snapshot.status != "quote_proposed":
            raise ValueError(
                "legal review packets are compiled from a quote_proposed commercial snapshot; "
                "later stages already carry an executed contract"
            )
        quote = self.approved_quote
        proposed = snapshot.quote
        if quote.quote_ref != proposed.quote_ref or quote.configuration_ref != proposed.configuration_ref:
            raise ValueError("approved quote must be the proposed quote")
        if quote.revision <= proposed.revision:
            raise ValueError("approved quote revision must advance the proposed revision")
        if quote.status not in {"approved", "accepted"} or quote.approval_status != "approved":
            raise ValueError("approved quote must be approved and accepted")
        if quote.approved_by_ref is None or quote.approved_by_ref == quote.prepared_by_ref:
            raise ValueError("quote approval requires an approver distinct from the preparer")
        if _quote_lines_payload(quote) != _quote_lines_payload(proposed) or (
            quote.total != proposed.total or quote.currency != proposed.currency
        ):
            raise ValueError("approved quote economics must equal the proposed quote economics")
        if quote.currency != scope.currency:
            raise ValueError("quote currency must match the commercial scope currency")
        order = self.draft_order
        if order.quote_ref != quote.quote_ref or order.account_ref != quote.account_ref:
            raise ValueError("draft order must bind the approved quote and account")
        if order.status not in {"draft", "pending"}:
            raise ValueError("draft order must be draft or pending before legal review")
        if order.currency != quote.currency or order.total != quote.total:
            raise ValueError("draft order total and currency must equal the approved quote")
        quote_lines = {line.quote_line_ref: line for line in quote.lines}
        if len(order.lines) != len(quote_lines) or any(
            line.quote_line_ref not in quote_lines
            or quote_lines[line.quote_line_ref].product_ref != line.product_ref
            or quote_lines[line.quote_line_ref].quantity != line.quantity
            or quote_lines[line.quote_line_ref].unit_price != line.unit_price
            for line in order.lines
        ):
            raise ValueError("draft order lines must map one-to-one onto approved quote lines")
        contract = self.draft_contract
        if (
            contract.quote_ref != quote.quote_ref
            or contract.order_ref != order.order_ref
            or contract.account_ref != quote.account_ref
            or order.contract_ref != contract.contract_ref
        ):
            raise ValueError("draft contract must bind the approved quote and draft order")
        if contract.status not in {"draft", "pending_signature"}:
            raise ValueError("draft contract must be unexecuted before legal review")
        if contract.signature_status not in {"not_required", "pending"} or contract.completed_signer_refs:
            raise ValueError("draft contract cannot carry completed signatures")
        if not contract.required_signer_refs:
            raise ValueError("draft contract must name its required signers")
        if contract.amendment_pending:
            raise ValueError("draft contract with a pending amendment cannot enter review")
        if contract.currency != quote.currency or contract.contract_value != order.total:
            raise ValueError("draft contract value and currency must equal the draft order")
        terms = self.commercial_terms
        if terms.billing.currency != quote.currency or terms.billing.total != contract.contract_value:
            raise ValueError("billing terms must equal the contract value and currency")
        order_lines = {line.order_line_ref: line for line in order.lines}
        if len(terms.entitlements) != len(order_lines) or any(
            item.order_line_ref not in order_lines
            or order_lines[item.order_line_ref].product_ref != item.product_ref
            or order_lines[item.order_line_ref].quantity != item.quantity
            or order_lines[item.order_line_ref].unit_price != item.unit_price
            for item in terms.entitlements
        ):
            raise ValueError("entitlement terms must map one-to-one onto draft order lines")
        if _parsed_timestamp(terms.delivery.start_at) < _parsed_timestamp(contract.effective_at):
            raise ValueError("delivery cannot start before the contract becomes effective")
        _unique(
            [f"{item.document_kind}:{item.artifact_ref}" for item in self.agreement_package],
            label="agreement package documents",
        )
        _unique([item.artifact_ref for item in self.agreement_package], label="agreement artifacts")
        kinds = {item.document_kind for item in self.agreement_package if item.required}
        if not kinds & {"msa", "order_form", "sow"}:
            raise ValueError("agreement package requires an MSA, order form, or SOW")
        _unique(
            [item.term_path for item in self.negotiation_boundaries],
            label="negotiation boundary term paths",
        )
        _unique(
            [f"{item.approval_kind}:{item.approver_role_ref}" for item in self.required_approvals],
            label="required approvals",
        )
        for boundary in self.negotiation_boundaries:
            if boundary.policy_ref is not None and boundary.policy_ref not in self.required_playbook_refs:
                raise ValueError("negotiation policies must be among the required playbooks")
        return self


class LegalReviewPacket(_StrictModel):
    schema_id: Literal["lightbulb.commercial_legal_review_packet.v1"] = Field(
        default=LEGAL_REVIEW_PACKET_SCHEMA, alias="schema"
    )
    scope: CommercialLegalHandoffScope
    opportunity_ref: OpaqueRef
    customer_ref: OpaqueRef
    project_ref: OpaqueRef
    quote_ref: OpaqueRef
    quote_revision: int = Field(ge=1)
    order_ref: OpaqueRef
    order_revision: int = Field(ge=1)
    contract_ref: OpaqueRef
    contract_revision: int = Field(ge=1)
    commercial_snapshot_digest: Sha256Digest
    commercial_terms_digest: Sha256Digest
    approved_quote: ControlledQuote
    draft_order: ControlledOrder
    draft_contract: ControlledContract
    agreement_package: tuple[AgreementPackageItem, ...] = Field(
        min_length=1, max_length=MAX_AGREEMENT_DOCUMENTS
    )
    commercial_terms: CommercialTermSheet
    jurisdiction_ref: OpaqueRef
    required_playbook_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    negotiation_boundaries: tuple[NegotiationBoundary, ...] = Field(
        default_factory=tuple, max_length=50
    )
    required_reviewer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    required_approvals: tuple[ApprovalRequirement, ...] = Field(
        default_factory=tuple, max_length=50
    )
    required_signer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=MAX_SIGNERS)
    requested_completion_at: str
    source_artifact_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=200)
    packet_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("requested_completion_at")
    @classmethod
    def _completion(cls, value: str) -> str:
        return _timestamp(value, field_name="requested_completion_at")

    @model_validator(mode="after")
    def _packet_is_exact(self, info: ValidationInfo) -> "LegalReviewPacket":
        if self.commercial_terms_digest != approved_commercial_terms_digest(
            self.approved_quote, self.draft_order, self.draft_contract, self.commercial_terms
        ):
            raise ValueError("commercial_terms_digest must commit the exact approved economics")
        if tuple(sorted(self.draft_contract.required_signer_refs)) != self.required_signer_refs:
            raise ValueError("packet signers must equal the draft contract's required signers")
        if _skip_digests(info):
            return self
        if self.packet_digest != legal_review_packet_digest(self):
            raise ValueError("packet_digest must commit the exact packet")
        return self


def legal_review_packet_digest(packet: LegalReviewPacket | Mapping[str, Any]) -> str:
    raw = dict(_detached(packet))
    raw.setdefault("packet_digest", GENESIS_DIGEST)
    parsed = LegalReviewPacket.model_validate(raw, context={"skip_handoff_digests": True})
    return _digest_without(parsed.to_dict(), "packet_digest")


def compile_legal_review_packet(
    inputs: LegalReviewPacketInput | Mapping[str, Any],
) -> LegalReviewPacket:
    """Bind approved commercial economics into one sealed legal review packet."""

    parsed = LegalReviewPacketInput.model_validate(_detached(inputs))
    packet = {
        "scope": parsed.scope.to_dict(),
        "opportunity_ref": parsed.scope.opportunity_ref,
        "customer_ref": parsed.scope.commercial.customer_ref,
        "project_ref": parsed.scope.commercial.project_ref,
        "quote_ref": parsed.approved_quote.quote_ref,
        "quote_revision": parsed.approved_quote.revision,
        "order_ref": parsed.draft_order.order_ref,
        "order_revision": parsed.draft_order.revision,
        "contract_ref": parsed.draft_contract.contract_ref,
        "contract_revision": parsed.draft_contract.revision,
        "commercial_snapshot_digest": parsed.commercial_snapshot.state_digest,
        "commercial_terms_digest": approved_commercial_terms_digest(
            parsed.approved_quote, parsed.draft_order, parsed.draft_contract, parsed.commercial_terms
        ),
        "approved_quote": parsed.approved_quote.to_dict(),
        "draft_order": parsed.draft_order.to_dict(),
        "draft_contract": parsed.draft_contract.to_dict(),
        "agreement_package": [
            item.to_dict()
            for item in sorted(
                parsed.agreement_package, key=lambda item: (item.document_kind, item.artifact_ref)
            )
        ],
        "commercial_terms": parsed.commercial_terms.to_dict(),
        "jurisdiction_ref": parsed.jurisdiction_ref,
        "required_playbook_refs": list(parsed.required_playbook_refs),
        "negotiation_boundaries": [
            item.to_dict()
            for item in sorted(parsed.negotiation_boundaries, key=lambda item: item.term_path)
        ],
        "required_reviewer_refs": list(parsed.required_reviewer_refs),
        "required_approvals": [
            item.to_dict()
            for item in sorted(
                parsed.required_approvals,
                key=lambda item: (item.approval_kind, item.approver_role_ref),
            )
        ],
        "required_signer_refs": sorted(parsed.draft_contract.required_signer_refs),
        "requested_completion_at": parsed.requested_completion_at,
        "source_artifact_refs": list(parsed.source_artifact_refs),
    }
    packet["packet_digest"] = legal_review_packet_digest(packet)
    return LegalReviewPacket.model_validate(packet)


# --------------------------------------------------------------------------- #
# Legal review outcome
# --------------------------------------------------------------------------- #


class ReviewedDocument(_StrictModel):
    document_kind: AgreementDocumentKind
    artifact_ref: OpaqueRef
    version: int = Field(ge=1, le=10_000)
    artifact_digest: Sha256Digest


class ClauseFinding(_StrictModel):
    finding_ref: OpaqueRef
    document_kind: AgreementDocumentKind
    clause_ref: OpaqueRef
    clause_text_digest: Sha256Digest
    source_evidence_ref: OpaqueRef
    category: CommercialTermPath
    severity: FindingSeverity
    description: BoundedText


class AcceptedDeviation(_StrictModel):
    deviation_ref: OpaqueRef
    finding_ref: OpaqueRef
    term_path: CommercialTermPath
    playbook_ref: OpaqueRef | None = None
    accepted_by_ref: OpaqueRef
    rationale: BoundedText


class UnresolvedDeviation(_StrictModel):
    deviation_ref: OpaqueRef
    finding_ref: OpaqueRef
    term_path: CommercialTermPath
    required_action: UnresolvedAction
    detail: BoundedText


class CommercialTermChange(_StrictModel):
    term_path: CommercialTermPath
    finding_ref: OpaqueRef
    prior_value: BoundedText
    proposed_value: BoundedText
    reason: BoundedText


class ProposedContractObligation(_StrictModel):
    obligation_ref: OpaqueRef
    document_kind: AgreementDocumentKind
    clause_ref: OpaqueRef
    clause_text_digest: Sha256Digest
    source_evidence_ref: OpaqueRef
    kind: ProposedObligationKind
    direction: ObligationDirection
    title: ShortText
    summary: BoundedText


class LegalReviewOutcome(_StrictModel):
    schema_id: Literal["lightbulb.commercial_legal_review_outcome.v1"] = Field(
        default=LEGAL_REVIEW_OUTCOME_SCHEMA, alias="schema"
    )
    packet_digest: Sha256Digest
    reviewed_documents: tuple[ReviewedDocument, ...] = Field(
        min_length=1, max_length=MAX_AGREEMENT_DOCUMENTS
    )
    findings: tuple[ClauseFinding, ...] = Field(default_factory=tuple, max_length=MAX_FINDINGS)
    accepted_deviations: tuple[AcceptedDeviation, ...] = Field(
        default_factory=tuple, max_length=MAX_FINDINGS
    )
    unresolved_deviations: tuple[UnresolvedDeviation, ...] = Field(
        default_factory=tuple, max_length=MAX_FINDINGS
    )
    changed_commercial_terms: tuple[CommercialTermChange, ...] = Field(
        default_factory=tuple, max_length=50
    )
    additional_approvals: tuple[ApprovalRequirement, ...] = Field(
        default_factory=tuple, max_length=50
    )
    signature_readiness: SignatureReadiness
    required_signer_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=MAX_SIGNERS)
    proposed_obligations: tuple[ProposedContractObligation, ...] = Field(
        default_factory=tuple, max_length=MAX_PROPOSED_OBLIGATIONS
    )
    disposition: ReviewDisposition
    reviewed_by_ref: OpaqueRef
    reviewed_at: str
    review_evidence: ControlledEvidenceRef
    outcome_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reviewed_at")
    @classmethod
    def _reviewed(cls, value: str) -> str:
        return _timestamp(value, field_name="reviewed_at")

    @field_validator("required_signer_refs", mode="before")
    @classmethod
    def _signers(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="required signers")

    @model_validator(mode="after")
    def _outcome_is_well_formed(self, info: ValidationInfo) -> "LegalReviewOutcome":
        _unique(
            [f"{item.document_kind}:{item.artifact_ref}" for item in self.reviewed_documents],
            label="reviewed documents",
        )
        finding_refs = [item.finding_ref for item in self.findings]
        _unique(finding_refs, label="finding refs")
        known = set(finding_refs)
        deviation_refs = [item.deviation_ref for item in self.accepted_deviations] + [
            item.deviation_ref for item in self.unresolved_deviations
        ]
        _unique(deviation_refs, label="deviation refs")
        for deviation in (*self.accepted_deviations, *self.unresolved_deviations):
            if deviation.finding_ref not in known:
                raise ValueError("every deviation must cite a retained finding")
        accepted_findings = {item.finding_ref for item in self.accepted_deviations}
        unresolved_findings = {item.finding_ref for item in self.unresolved_deviations}
        if accepted_findings & unresolved_findings:
            raise ValueError("a finding cannot be both accepted and unresolved")
        for change in self.changed_commercial_terms:
            if change.finding_ref not in known:
                raise ValueError("every commercial term change must cite a retained finding")
        _unique([item.term_path for item in self.changed_commercial_terms], label="changed term paths")
        _unique([item.obligation_ref for item in self.proposed_obligations], label="proposed obligations")
        _unique(
            [f"{item.approval_kind}:{item.approver_role_ref}" for item in self.additional_approvals],
            label="additional approvals",
        )
        if self.review_evidence.subject_ref != self.packet_digest:
            raise ValueError("review evidence must bind the exact packet digest")
        if self.review_evidence.kind != "legal_review":
            raise ValueError("review evidence must be a legal_review evidence reference")
        if _parsed_timestamp(self.review_evidence.observed_at) > _parsed_timestamp(self.reviewed_at):
            raise ValueError("review evidence cannot be observed after the review")
        if _skip_digests(info):
            return self
        if self.outcome_digest != legal_review_outcome_digest(self):
            raise ValueError("outcome_digest must commit the exact outcome")
        return self


def legal_review_outcome_digest(outcome: LegalReviewOutcome | Mapping[str, Any]) -> str:
    raw = dict(_detached(outcome))
    raw.setdefault("outcome_digest", GENESIS_DIGEST)
    parsed = LegalReviewOutcome.model_validate(raw, context={"skip_handoff_digests": True})
    return _digest_without(parsed.to_dict(), "outcome_digest")


def seal_legal_review_outcome(outcome: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(outcome))
    raw["outcome_digest"] = legal_review_outcome_digest(raw)
    return LegalReviewOutcome.model_validate(raw).to_dict()


class OutcomeViolation(_StrictModel):
    code: OutcomeViolationCode
    detail: BoundedText
    refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="violation refs")


class CommercialLegalHandoffEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    legal_determination_made: Literal[False] = False
    negotiation_position_decided: Literal[False] = False
    commercial_artifact_mutated: Literal[False] = False
    deviation_discarded: Literal[False] = False
    signature_performed: Literal[False] = False
    custody_recorded: Literal[False] = False
    approval_recorded: Literal[False] = False
    persistence_written: Literal[False] = False
    connector_effect_executed: Literal[False] = False


class LegalReviewOutcomeValidation(_StrictModel):
    schema_id: Literal["lightbulb.commercial_legal_review_outcome_validation.v1"] = Field(
        default=LEGAL_REVIEW_VALIDATION_SCHEMA, alias="schema"
    )
    packet_digest: Sha256Digest
    outcome_digest: Sha256Digest
    accepted: bool
    effective_disposition: ReviewDisposition | None = None
    economic_terms_changed: tuple[CommercialTermPath, ...] = Field(
        default_factory=tuple, max_length=50
    )
    commercial_revision_required: bool
    outstanding_approvals: tuple[ApprovalRequirement, ...] = Field(
        default_factory=tuple, max_length=100
    )
    violations: tuple[OutcomeViolation, ...] = Field(default_factory=tuple, max_length=200)
    effect_boundary: CommercialLegalHandoffEffectBoundary = Field(
        default_factory=CommercialLegalHandoffEffectBoundary
    )
    validation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _validation_is_exact(self, info: ValidationInfo) -> "LegalReviewOutcomeValidation":
        if self.accepted != (not self.violations):
            raise ValueError("accepted must be true exactly when no violation was found")
        if self.accepted != (self.effective_disposition is not None):
            raise ValueError("effective disposition exists exactly for accepted outcomes")
        if _skip_digests(info):
            return self
        if self.validation_digest != legal_review_validation_digest(self):
            raise ValueError("validation_digest must commit the exact validation")
        return self


def legal_review_validation_digest(
    validation: LegalReviewOutcomeValidation | Mapping[str, Any],
) -> str:
    raw = dict(_detached(validation))
    raw.setdefault("validation_digest", GENESIS_DIGEST)
    parsed = LegalReviewOutcomeValidation.model_validate(
        raw, context={"skip_handoff_digests": True}
    )
    return _digest_without(parsed.to_dict(), "validation_digest")


class LegalReviewOutcomeValidationInput(_StrictModel):
    scope: CommercialLegalHandoffScope
    packet: LegalReviewPacket
    outcome: LegalReviewOutcome
    requested_by_ref: OpaqueRef

    @model_validator(mode="after")
    def _input_is_exact(self) -> "LegalReviewOutcomeValidationInput":
        if self.packet.scope != self.scope:
            raise ValueError("packet scope must exactly match validation scope")
        return self


def validate_legal_review_outcome(
    inputs: LegalReviewOutcomeValidationInput | Mapping[str, Any],
) -> LegalReviewOutcomeValidation:
    """Check a legal outcome against the packet's boundaries; never re-decide law."""

    parsed = LegalReviewOutcomeValidationInput.model_validate(_detached(inputs))
    packet = parsed.packet
    outcome = parsed.outcome
    violations: list[OutcomeViolation] = []

    def violate(code: OutcomeViolationCode, detail: str, refs: Sequence[str] = ()) -> None:
        violations.append(OutcomeViolation(code=code, detail=detail, refs=tuple(sorted(set(refs)))))

    if outcome.packet_digest != packet.packet_digest:
        violate("PACKET_DIGEST_MISMATCH", "outcome does not cite the exact packet digest")
    reviewed = {item.artifact_ref: item for item in outcome.reviewed_documents}
    package = {item.artifact_ref: item for item in packet.agreement_package}
    for artifact_ref, item in package.items():
        if item.required and artifact_ref not in reviewed:
            violate("REQUIRED_DOCUMENT_NOT_REVIEWED", "required agreement document was not reviewed", [artifact_ref])
    for artifact_ref, item in reviewed.items():
        source = package.get(artifact_ref)
        if source is None or source.document_kind != item.document_kind:
            violate("REVIEWED_DOCUMENT_UNKNOWN", "reviewed document is not in the packet", [artifact_ref])
        elif item.version < source.version:
            violate("DOCUMENT_VERSION_REGRESSED", "reviewed version precedes the packet version", [artifact_ref])
    if outcome.reviewed_by_ref not in packet.required_reviewer_refs:
        violate("REVIEWER_NOT_REQUIRED", "reviewer is not one of the packet's required reviewers", [outcome.reviewed_by_ref])
    evidence = outcome.review_evidence
    if (
        evidence.issuer_ref not in packet.scope.authorized_evidence_issuer_refs
        or _GRADE_RANK[evidence.verification_grade] < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
        or evidence.classification == PrimitiveEvidenceClassification.PUBLIC
    ):
        violate("REVIEW_EVIDENCE_INVALID", "review evidence issuer, grade, or classification is not acceptable", [evidence.evidence_ref])
    reviewed_kinds = {item.document_kind for item in outcome.reviewed_documents}
    for finding in outcome.findings:
        if finding.document_kind not in reviewed_kinds:
            violate("FINDING_DOCUMENT_NOT_REVIEWED", "finding cites a document kind that was not reviewed", [finding.finding_ref])
    boundaries = {item.term_path: item for item in packet.negotiation_boundaries}
    escalation_kinds = {item.approval_kind for item in outcome.additional_approvals}
    for deviation in outcome.accepted_deviations:
        boundary = boundaries.get(deviation.term_path)
        if boundary is None:
            continue
        if boundary.boundary == "fixed":
            violate("DEVIATION_ON_FIXED_TERM", "accepted deviation touches a fixed term", [deviation.deviation_ref])
        elif boundary.boundary == "negotiable_within_policy":
            if deviation.playbook_ref is None or deviation.playbook_ref != boundary.policy_ref:
                violate("DEVIATION_PLAYBOOK_NOT_AUTHORIZED", "accepted deviation must cite the boundary's playbook", [deviation.deviation_ref])
        elif not escalation_kinds & {"executive", "legal"}:
            violate("DEVIATION_REQUIRES_ESCALATION_APPROVAL", "escalate-for-change terms require an executive or legal approval requirement", [deviation.deviation_ref])
    economic = tuple(
        sorted(item.term_path for item in outcome.changed_commercial_terms if item.term_path in ECONOMIC_TERM_PATHS)
    )
    if outcome.disposition == "approved":
        if outcome.unresolved_deviations:
            violate("APPROVED_WITH_UNRESOLVED_DEVIATIONS", "approved outcomes cannot retain unresolved deviations", [item.deviation_ref for item in outcome.unresolved_deviations])
        if outcome.signature_readiness != "ready":
            violate("APPROVED_BUT_SIGNATURE_BLOCKED", "approved outcomes must be signature-ready")
    if economic and outcome.disposition not in {"commercial_reapproval_required", "rejected"}:
        violate("ECONOMIC_CHANGE_WITHOUT_COMMERCIAL_REAPPROVAL", "changed economic terms require commercial re-approval", list(economic))
    if outcome.signature_readiness == "ready" and outcome.disposition != "approved":
        violate("SIGNATURE_READY_WITHOUT_APPROVAL", "only approved outcomes can be signature-ready")
    dropped = [ref for ref in packet.required_signer_refs if ref not in outcome.required_signer_refs]
    if dropped:
        violate("REQUIRED_SIGNER_DROPPED", "legal may add signers but cannot drop contract-required signers", dropped)
    for obligation in outcome.proposed_obligations:
        if obligation.document_kind not in reviewed_kinds:
            violate("OBLIGATION_DOCUMENT_NOT_REVIEWED", "proposed obligation cites an unreviewed document kind", [obligation.obligation_ref])

    accepted = not violations
    validation = {
        "packet_digest": packet.packet_digest,
        "outcome_digest": outcome.outcome_digest,
        "accepted": accepted,
        "effective_disposition": outcome.disposition if accepted else None,
        "economic_terms_changed": list(economic),
        "commercial_revision_required": bool(economic) or outcome.disposition == "commercial_reapproval_required",
        "outstanding_approvals": [
            item.to_dict()
            for item in sorted(
                {
                    f"{item.approval_kind}:{item.approver_role_ref}": item
                    for item in (*packet.required_approvals, *outcome.additional_approvals)
                }.values(),
                key=lambda item: (item.approval_kind, item.approver_role_ref),
            )
        ],
        "violations": [
            item.to_dict() for item in sorted(violations, key=lambda item: (item.code, item.refs))
        ],
    }
    validation["validation_digest"] = legal_review_validation_digest(validation)
    return LegalReviewOutcomeValidation.model_validate(validation)


# --------------------------------------------------------------------------- #
# Executed-agreement reconciliation
# --------------------------------------------------------------------------- #


class SignatureRecord(_StrictModel):
    signer_ref: OpaqueRef
    signed_at: str
    document_kind: AgreementDocumentKind
    artifact_digest: Sha256Digest
    evidence: ControlledEvidenceRef

    @field_validator("signed_at")
    @classmethod
    def _signed(cls, value: str) -> str:
        return _timestamp(value, field_name="signed_at")

    @model_validator(mode="after")
    def _signature_evidence_is_exact(self) -> "SignatureRecord":
        if self.evidence.kind != "contract_signature":
            raise ValueError("signature evidence must be a contract_signature reference")
        if _GRADE_RANK[self.evidence.verification_grade] < _GRADE_RANK[
            PrimitiveEvidenceVerificationGrade.VERIFIED
        ]:
            raise ValueError("signature evidence must be verified")
        if _parsed_timestamp(self.evidence.observed_at) < _parsed_timestamp(self.signed_at):
            raise ValueError("signature evidence cannot be observed before signing")
        return self


class ExecutedDocument(_StrictModel):
    document_kind: AgreementDocumentKind
    artifact_ref: OpaqueRef
    version: int = Field(ge=1, le=10_000)
    artifact_digest: Sha256Digest
    executed_at: str

    @field_validator("executed_at")
    @classmethod
    def _executed(cls, value: str) -> str:
        return _timestamp(value, field_name="executed_at")


class ReconciliationBlocker(_StrictModel):
    code: ReconciliationBlockerCode
    detail: BoundedText
    refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="blocker refs")


class RequiredCommercialRevision(_StrictModel):
    quote_ref: OpaqueRef
    minimum_quote_revision: int = Field(ge=1)
    changed_term_paths: tuple[CommercialTermPath, ...] = Field(default_factory=tuple, max_length=50)
    reason: BoundedText


class CustodySignature(_StrictModel):
    signer_ref: OpaqueRef
    signed_at: str
    document_kind: AgreementDocumentKind
    evidence_ref: OpaqueRef

    @field_validator("signed_at")
    @classmethod
    def _signed(cls, value: str) -> str:
        return _timestamp(value, field_name="signed_at")


class ExecutedCommercialAgreementCustodyCandidate(_StrictModel):
    """The only successful handoff terminal; Spring decides whether it enters custody."""

    schema_id: Literal["lightbulb.commercial_legal_handoff_custody_candidate.v1"] = Field(
        default=EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA, alias="schema"
    )
    scope: CommercialLegalHandoffScope
    opportunity_ref: OpaqueRef
    customer_ref: OpaqueRef
    contract_ref: OpaqueRef
    contract_revision: int = Field(ge=1)
    agreement_version: int = Field(ge=1, le=10_000)
    quote_ref: OpaqueRef
    quote_revision: int = Field(ge=1)
    order_ref: OpaqueRef
    order_revision: int = Field(ge=1)
    jurisdiction_ref: OpaqueRef
    executed_documents: tuple[ExecutedDocument, ...] = Field(
        min_length=1, max_length=MAX_AGREEMENT_DOCUMENTS
    )
    executed_agreement_digest: Sha256Digest
    signatures: tuple[CustodySignature, ...] = Field(min_length=1, max_length=MAX_SIGNERS)
    executed_at: str
    effective_at: str
    expires_at: str
    packet_digest: Sha256Digest
    outcome_digest: Sha256Digest
    validation_digest: Sha256Digest
    commercial_terms_digest: Sha256Digest
    commercial_snapshot_digest: Sha256Digest
    custody_candidate_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("executed_at", "effective_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _candidate_is_exact(self, info: ValidationInfo) -> "ExecutedCommercialAgreementCustodyCandidate":
        _unique([item.artifact_ref for item in self.executed_documents], label="executed documents")
        _unique([item.signer_ref for item in self.signatures], label="custody signers")
        if self.executed_agreement_digest != executed_agreement_digest(self.executed_documents):
            raise ValueError("executed_agreement_digest must commit the exact executed documents")
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.effective_at):
            raise ValueError("agreement expiry must follow effectiveness")
        if _skip_digests(info):
            return self
        if self.custody_candidate_digest != custody_candidate_digest(self):
            raise ValueError("custody_candidate_digest must commit the exact candidate")
        return self


def executed_agreement_digest(documents: Sequence[ExecutedDocument | Mapping[str, Any]]) -> str:
    parsed = [ExecutedDocument.model_validate(_detached(item)) for item in documents]
    return _stable_digest(
        [
            {
                "document_kind": item.document_kind,
                "artifact_ref": item.artifact_ref,
                "version": item.version,
                "artifact_digest": item.artifact_digest,
            }
            for item in sorted(parsed, key=lambda item: (item.document_kind, item.artifact_ref))
        ]
    )


def custody_candidate_digest(
    candidate: ExecutedCommercialAgreementCustodyCandidate | Mapping[str, Any],
) -> str:
    raw = dict(_detached(candidate))
    raw.setdefault("custody_candidate_digest", GENESIS_DIGEST)
    parsed = ExecutedCommercialAgreementCustodyCandidate.model_validate(
        raw, context={"skip_handoff_digests": True}
    )
    return _digest_without(parsed.to_dict(), "custody_candidate_digest")


class ContractToCashProjection(_StrictModel):
    """Inputs for the existing commercial ``review_contract_order`` stage."""

    schema_id: Literal["lightbulb.contract_to_cash_projection.v1"] = Field(
        default=CONTRACT_TO_CASH_PROJECTION_SCHEMA, alias="schema"
    )
    custody_candidate_digest: Sha256Digest
    next_commercial_command: Literal["review_contract_order"] = "review_contract_order"
    reviewed_quote: ControlledQuote
    order: ControlledOrder
    contract: ControlledContract
    billing: BillingTerm
    renewal: RenewalTerm
    contract_signature_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=MAX_SIGNERS)
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("contract_signature_evidence_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="signature evidence refs")

    @model_validator(mode="after")
    def _projection_is_exact(self, info: ValidationInfo) -> "ContractToCashProjection":
        if self.contract.status != "executed" or self.contract.signature_status != "completed":
            raise ValueError("contract-to-cash projection requires an executed, fully signed contract")
        if set(self.contract.completed_signer_refs) != set(self.contract.required_signer_refs):
            raise ValueError("executed contract must carry every required signature")
        if self.order.status != "confirmed":
            raise ValueError("contract-to-cash projection requires a confirmed order")
        if _skip_digests(info):
            return self
        if self.projection_digest != _projection_digest(ContractToCashProjection, self):
            raise ValueError("projection_digest must commit the exact projection")
        return self


class ServiceDeliveryProjection(_StrictModel):
    schema_id: Literal["lightbulb.service_delivery_projection.v1"] = Field(
        default=SERVICE_DELIVERY_PROJECTION_SCHEMA, alias="schema"
    )
    custody_candidate_digest: Sha256Digest
    contract_ref: OpaqueRef
    customer_ref: OpaqueRef
    delivery: DeliveryTerm
    acceptance: AcceptanceTerm
    entitlements: tuple[EntitlementTerm, ...] = Field(min_length=1, max_length=5_000)
    delivery_obligation_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("delivery_obligation_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="delivery obligation refs")

    @model_validator(mode="after")
    def _projection_is_exact(self, info: ValidationInfo) -> "ServiceDeliveryProjection":
        if _skip_digests(info):
            return self
        if self.projection_digest != _projection_digest(ServiceDeliveryProjection, self):
            raise ValueError("projection_digest must commit the exact projection")
        return self


class ClauseIndexEntry(_StrictModel):
    clause_ref: OpaqueRef
    document_kind: AgreementDocumentKind
    clause_text_digest: Sha256Digest
    source_evidence_ref: OpaqueRef


class ObligationFulfillmentProjection(_StrictModel):
    """Exact agreement identity and clause index for the obligation loop."""

    schema_id: Literal["lightbulb.obligation_fulfillment_projection.v1"] = Field(
        default=OBLIGATION_FULFILLMENT_PROJECTION_SCHEMA, alias="schema"
    )
    custody_candidate_digest: Sha256Digest
    agreement_ref: OpaqueRef
    agreement_version: int = Field(ge=1, le=10_000)
    agreement_digest: Sha256Digest
    executed_at: str
    effective_at: str
    expires_at: str
    counterparty_ref: OpaqueRef
    counterparty_role: Literal["customer"] = "customer"
    clause_index: tuple[ClauseIndexEntry, ...] = Field(default_factory=tuple, max_length=2000)
    proposed_obligations: tuple[ProposedContractObligation, ...] = Field(
        default_factory=tuple, max_length=MAX_PROPOSED_OBLIGATIONS
    )
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("executed_at", "effective_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _projection_is_exact(self, info: ValidationInfo) -> "ObligationFulfillmentProjection":
        _unique([item.clause_ref for item in self.clause_index], label="clause index refs")
        indexed = {item.clause_ref: item.clause_text_digest for item in self.clause_index}
        for obligation in self.proposed_obligations:
            if indexed.get(obligation.clause_ref) != obligation.clause_text_digest:
                raise ValueError("every proposed obligation must cite an indexed clause digest")
        if _skip_digests(info):
            return self
        if self.projection_digest != _projection_digest(ObligationFulfillmentProjection, self):
            raise ValueError("projection_digest must commit the exact projection")
        return self


def _projection_digest(model: type[_StrictModel], projection: Any) -> str:
    raw = dict(_detached(projection))
    raw.setdefault("projection_digest", GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_handoff_digests": True})
    return _digest_without(parsed.to_dict(), "projection_digest")


class ExecutedAgreementReconciliationInput(_StrictModel):
    scope: CommercialLegalHandoffScope
    packet: LegalReviewPacket
    outcome: LegalReviewOutcome
    validation: LegalReviewOutcomeValidation
    current_commercial_snapshot: ControlledCommercialSnapshot
    executed_documents: tuple[ExecutedDocument, ...] = Field(
        default_factory=tuple, max_length=MAX_AGREEMENT_DOCUMENTS
    )
    signatures: tuple[SignatureRecord, ...] = Field(default_factory=tuple, max_length=MAX_SIGNERS)
    reconciled_at: str
    requested_by_ref: OpaqueRef

    @field_validator("reconciled_at")
    @classmethod
    def _reconciled(cls, value: str) -> str:
        return _timestamp(value, field_name="reconciled_at")

    @model_validator(mode="after")
    def _input_is_exact(self) -> "ExecutedAgreementReconciliationInput":
        if self.packet.scope != self.scope:
            raise ValueError("packet scope must exactly match reconciliation scope")
        if self.current_commercial_snapshot.scope != self.scope.commercial:
            raise ValueError("commercial snapshot scope must exactly match reconciliation scope")
        if self.validation.packet_digest != self.packet.packet_digest:
            raise ValueError("validation must bind the exact packet digest")
        if self.validation.outcome_digest != self.outcome.outcome_digest:
            raise ValueError("validation must bind the exact outcome digest")
        _unique([item.artifact_ref for item in self.executed_documents], label="executed documents")
        _unique([item.signer_ref for item in self.signatures], label="signatures")
        _unique([item.evidence.evidence_ref for item in self.signatures], label="signature evidence")
        for signature in self.signatures:
            if signature.evidence.issuer_ref not in self.scope.authorized_evidence_issuer_refs:
                raise ValueError("signature evidence issuer is not authorized by scope")
            if signature.evidence.subject_ref != self.packet.contract_ref:
                raise ValueError("signature evidence must bind the exact contract reference")
        return self


class ExecutedAgreementReconciliation(_StrictModel):
    schema_id: Literal["lightbulb.executed_agreement_reconciliation.v1"] = Field(
        default=EXECUTED_AGREEMENT_RECONCILIATION_SCHEMA, alias="schema"
    )
    scope: CommercialLegalHandoffScope
    packet_digest: Sha256Digest
    outcome_digest: Sha256Digest
    disposition: ReconciliationDisposition
    blockers: tuple[ReconciliationBlocker, ...] = Field(default_factory=tuple, max_length=200)
    required_commercial_revision: RequiredCommercialRevision | None = None
    custody_candidate: ExecutedCommercialAgreementCustodyCandidate | None = None
    contract_to_cash: ContractToCashProjection | None = None
    service_delivery: ServiceDeliveryProjection | None = None
    obligation_fulfillment: ObligationFulfillmentProjection | None = None
    effect_boundary: CommercialLegalHandoffEffectBoundary = Field(
        default_factory=CommercialLegalHandoffEffectBoundary
    )
    reconciliation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _reconciliation_is_coherent(self, info: ValidationInfo) -> "ExecutedAgreementReconciliation":
        executed = self.disposition == "executed_custody_candidate"
        projections = (self.custody_candidate, self.contract_to_cash, self.service_delivery, self.obligation_fulfillment)
        if executed:
            if self.blockers or any(item is None for item in projections):
                raise ValueError("an executed custody candidate carries all projections and no blocker")
            assert self.custody_candidate is not None
            digest = self.custody_candidate.custody_candidate_digest
            for projection in projections[1:]:
                assert projection is not None
                if projection.custody_candidate_digest != digest:
                    raise ValueError("every projection must bind the exact custody candidate")
        else:
            if not self.blockers or any(item is not None for item in projections):
                raise ValueError("a non-executed reconciliation carries blockers and no projection")
        if (self.disposition == "commercial_revision_required") != (
            self.required_commercial_revision is not None
        ):
            raise ValueError("required commercial revision exists exactly for that disposition")
        if _skip_digests(info):
            return self
        if self.reconciliation_digest != executed_agreement_reconciliation_digest(self):
            raise ValueError("reconciliation_digest must commit the exact reconciliation")
        return self


def executed_agreement_reconciliation_digest(
    reconciliation: ExecutedAgreementReconciliation | Mapping[str, Any],
) -> str:
    raw = dict(_detached(reconciliation))
    raw.setdefault("reconciliation_digest", GENESIS_DIGEST)
    parsed = ExecutedAgreementReconciliation.model_validate(
        raw, context={"skip_handoff_digests": True}
    )
    return _digest_without(parsed.to_dict(), "reconciliation_digest")


def reconcile_executed_agreement(
    inputs: ExecutedAgreementReconciliationInput | Mapping[str, Any],
) -> ExecutedAgreementReconciliation:
    """Reconcile sales, legal, and signature facts into one custody candidate or a blocker set."""

    parsed = ExecutedAgreementReconciliationInput.model_validate(_detached(inputs))
    packet = parsed.packet
    outcome = parsed.outcome
    validation = parsed.validation
    blockers: list[ReconciliationBlocker] = []
    disposition: ReconciliationDisposition | None = None
    revision: RequiredCommercialRevision | None = None

    def block(code: ReconciliationBlockerCode, detail: str, refs: Sequence[str] = ()) -> None:
        blockers.append(ReconciliationBlocker(code=code, detail=detail, refs=tuple(sorted(set(refs)))))

    def settle(candidate: ReconciliationDisposition) -> None:
        nonlocal disposition
        order = ("rejected", "commercial_revision_required", "legal_revision_required", "signature_incomplete")
        if disposition is None or order.index(candidate) < order.index(disposition):
            disposition = candidate

    if not validation.accepted:
        block("OUTCOME_VALIDATION_NOT_ACCEPTED", "legal outcome validation retained violations", [item.code for item in validation.violations])
        settle("rejected")
    if parsed.current_commercial_snapshot.state_digest != packet.commercial_snapshot_digest:
        block("STALE_COMMERCIAL_SNAPSHOT", "commercial lifecycle advanced since the packet was compiled; recompile the packet")
        revision = revision or RequiredCommercialRevision(
            quote_ref=packet.quote_ref,
            minimum_quote_revision=packet.quote_revision,
            reason="commercial snapshot changed after packet compilation; recompile from the current snapshot",
        )
        settle("commercial_revision_required")
    if outcome.disposition == "rejected":
        block("OUTCOME_REJECTED", "legal rejected the agreement package")
        settle("rejected")
    elif outcome.disposition == "revision_required":
        block("LEGAL_REVISION_REQUIRED", "legal requires a revised agreement package")
        settle("legal_revision_required")
    elif outcome.disposition == "commercial_reapproval_required" or validation.economic_terms_changed:
        changed = validation.economic_terms_changed
        block(
            "COMMERCIAL_REAPPROVAL_REQUIRED" if not changed else "ECONOMIC_TERMS_CHANGED",
            "legal changed commercial economics; sales must issue a new quote revision and packet",
            list(changed),
        )
        revision = RequiredCommercialRevision(
            quote_ref=packet.quote_ref,
            minimum_quote_revision=packet.quote_revision + 1,
            changed_term_paths=changed,
            reason="legal findings changed price, quantity, currency, scope, term, billing, renewal, or termination economics",
        )
        settle("commercial_revision_required")
    if outcome.unresolved_deviations:
        block("UNRESOLVED_DEVIATIONS_RETAINED", "sales cannot discard unresolved legal deviations", [item.deviation_ref for item in outcome.unresolved_deviations])
        settle("legal_revision_required")
    if outcome.signature_readiness != "ready":
        block("SIGNATURE_NOT_READY", "legal has not declared the package signature-ready")
        settle("legal_revision_required")

    reviewed = {item.artifact_ref: item for item in outcome.reviewed_documents}
    executed = {item.artifact_ref: item for item in parsed.executed_documents}
    required_artifacts = {item.artifact_ref for item in packet.agreement_package if item.required}
    for artifact_ref in sorted(required_artifacts | set(reviewed)):
        document = executed.get(artifact_ref)
        review = reviewed.get(artifact_ref)
        if document is None:
            block("EXECUTED_DOCUMENT_MISSING", "a reviewed or required document has no executed counterpart", [artifact_ref])
            settle("signature_incomplete")
        elif review is None:
            block("EXECUTED_DOCUMENT_UNKNOWN", "executed document was never reviewed", [artifact_ref])
            settle("rejected")
        elif document.artifact_digest != review.artifact_digest or document.version != review.version or document.document_kind != review.document_kind:
            block("AGREEMENT_DIGEST_MISMATCH", "signed document does not match the reviewed document version and digest", [artifact_ref])
            settle("rejected")
    for artifact_ref in sorted(set(executed) - set(reviewed)):
        block("EXECUTED_DOCUMENT_UNKNOWN", "executed document was never reviewed", [artifact_ref])
        settle("rejected")

    executed_digests = {item.artifact_digest for item in parsed.executed_documents}
    signatures = {item.signer_ref: item for item in parsed.signatures}
    required_signers = sorted(set(packet.required_signer_refs) | set(outcome.required_signer_refs))
    reconciled_at = _parsed_timestamp(parsed.reconciled_at)
    for signer_ref in required_signers:
        signature = signatures.get(signer_ref)
        if signature is None:
            block("SIGNATURE_MISSING", "required signer has no verified signature", [signer_ref])
            settle("signature_incomplete")
            continue
        if signature.artifact_digest not in executed_digests:
            block("SIGNATURE_DIGEST_MISMATCH", "signature covers a digest that is not an executed document", [signer_ref])
            settle("rejected")
        if _parsed_timestamp(signature.signed_at) > reconciled_at:
            block("SIGNATURE_AFTER_RECONCILIATION", "signature is dated after reconciliation", [signer_ref])
            settle("rejected")
    for signer_ref in sorted(set(signatures) - set(required_signers)):
        block("SIGNATURE_UNEXPECTED", "signature from a signer the agreement does not require", [signer_ref])
        settle("rejected")

    clause_index: dict[str, ClauseIndexEntry] = {}
    for source in (*outcome.findings, *outcome.proposed_obligations):
        entry = ClauseIndexEntry(
            clause_ref=source.clause_ref,
            document_kind=source.document_kind,
            clause_text_digest=source.clause_text_digest,
            source_evidence_ref=source.source_evidence_ref,
        )
        existing = clause_index.get(source.clause_ref)
        if existing is None:
            clause_index[source.clause_ref] = entry
        elif existing.clause_text_digest != entry.clause_text_digest:
            block("CLAUSE_DIGEST_CONFLICT", "findings and obligations cite different digests for one clause", [source.clause_ref])
            settle("rejected")

    base = {
        "scope": parsed.scope.to_dict(),
        "packet_digest": packet.packet_digest,
        "outcome_digest": outcome.outcome_digest,
    }
    if disposition is not None:
        result = {
            **base,
            "disposition": disposition,
            "blockers": [item.to_dict() for item in sorted(blockers, key=lambda item: (item.code, item.refs))],
            "required_commercial_revision": (
                revision.to_dict() if disposition == "commercial_revision_required" and revision else None
            ),
        }
        result["reconciliation_digest"] = executed_agreement_reconciliation_digest(result)
        return ExecutedAgreementReconciliation.model_validate(result)

    executed_documents = sorted(parsed.executed_documents, key=lambda item: (item.document_kind, item.artifact_ref))
    executed_at = max(_parsed_timestamp(item.signed_at) for item in parsed.signatures)
    executed_at_text = executed_at.isoformat().replace("+00:00", "Z")
    candidate = {
        "scope": parsed.scope.to_dict(),
        "opportunity_ref": packet.opportunity_ref,
        "customer_ref": packet.customer_ref,
        "contract_ref": packet.contract_ref,
        "contract_revision": packet.contract_revision,
        "agreement_version": 1,
        "quote_ref": packet.quote_ref,
        "quote_revision": packet.quote_revision,
        "order_ref": packet.order_ref,
        "order_revision": packet.order_revision,
        "jurisdiction_ref": packet.jurisdiction_ref,
        "executed_documents": [item.to_dict() for item in executed_documents],
        "executed_agreement_digest": executed_agreement_digest(executed_documents),
        "signatures": [
            CustodySignature(
                signer_ref=item.signer_ref,
                signed_at=item.signed_at,
                document_kind=item.document_kind,
                evidence_ref=item.evidence.evidence_ref,
            ).to_dict()
            for item in sorted(parsed.signatures, key=lambda item: item.signer_ref)
        ],
        "executed_at": executed_at_text,
        "effective_at": packet.draft_contract.effective_at,
        "expires_at": packet.draft_contract.expires_at,
        "packet_digest": packet.packet_digest,
        "outcome_digest": outcome.outcome_digest,
        "validation_digest": validation.validation_digest,
        "commercial_terms_digest": packet.commercial_terms_digest,
        "commercial_snapshot_digest": packet.commercial_snapshot_digest,
    }
    candidate["custody_candidate_digest"] = custody_candidate_digest(candidate)
    custody = ExecutedCommercialAgreementCustodyCandidate.model_validate(candidate)
    signature_evidence_refs = sorted(item.evidence.evidence_ref for item in parsed.signatures)
    executed_contract = {
        **packet.draft_contract.to_dict(),
        "status": "executed",
        "signature_status": "completed",
        "required_signer_refs": required_signers,
        "completed_signer_refs": required_signers,
        "evidence_refs": signature_evidence_refs,
    }
    confirmed_order = {**packet.draft_order.to_dict(), "status": "confirmed"}
    contract_to_cash = {
        "custody_candidate_digest": custody.custody_candidate_digest,
        "reviewed_quote": packet.approved_quote.to_dict(),
        "order": confirmed_order,
        "contract": executed_contract,
        "billing": packet.commercial_terms.billing.to_dict(),
        "renewal": packet.commercial_terms.renewal.to_dict(),
        "contract_signature_evidence_refs": signature_evidence_refs,
    }
    contract_to_cash["projection_digest"] = _projection_digest(ContractToCashProjection, contract_to_cash)
    service_delivery = {
        "custody_candidate_digest": custody.custody_candidate_digest,
        "contract_ref": packet.contract_ref,
        "customer_ref": packet.customer_ref,
        "delivery": packet.commercial_terms.delivery.to_dict(),
        "acceptance": packet.commercial_terms.acceptance.to_dict(),
        "entitlements": [item.to_dict() for item in packet.commercial_terms.entitlements],
        "delivery_obligation_refs": sorted(
            item.obligation_ref
            for item in outcome.proposed_obligations
            if item.kind in {"delivery", "acceptance", "service"}
        ),
    }
    service_delivery["projection_digest"] = _projection_digest(ServiceDeliveryProjection, service_delivery)
    obligation_projection = {
        "custody_candidate_digest": custody.custody_candidate_digest,
        "agreement_ref": packet.contract_ref,
        "agreement_version": 1,
        "agreement_digest": custody.executed_agreement_digest,
        "executed_at": executed_at_text,
        "effective_at": custody.effective_at,
        "expires_at": custody.expires_at,
        "counterparty_ref": packet.customer_ref,
        "clause_index": [clause_index[key].to_dict() for key in sorted(clause_index)],
        "proposed_obligations": [
            item.to_dict() for item in sorted(outcome.proposed_obligations, key=lambda item: item.obligation_ref)
        ],
    }
    obligation_projection["projection_digest"] = _projection_digest(
        ObligationFulfillmentProjection, obligation_projection
    )
    result = {
        **base,
        "disposition": "executed_custody_candidate",
        "blockers": [],
        "custody_candidate": custody.to_dict(),
        "contract_to_cash": contract_to_cash,
        "service_delivery": service_delivery,
        "obligation_fulfillment": obligation_projection,
    }
    result["reconciliation_digest"] = executed_agreement_reconciliation_digest(result)
    return ExecutedAgreementReconciliation.model_validate(result)


__all__ = [
    "COMMERCIAL_LEGAL_HANDOFF_GOLDEN_LOOP",
    "CONTRACT_TO_CASH_PROJECTION_SCHEMA",
    "ECONOMIC_TERM_PATHS",
    "EXECUTED_AGREEMENT_CUSTODY_CANDIDATE_SCHEMA",
    "EXECUTED_AGREEMENT_RECONCILIATION_SCHEMA",
    "GENESIS_DIGEST",
    "HANDOFF_SCOPE_SCHEMA",
    "LEGAL_REVIEW_OUTCOME_SCHEMA",
    "LEGAL_REVIEW_PACKET_SCHEMA",
    "LEGAL_REVIEW_VALIDATION_SCHEMA",
    "OBLIGATION_FULFILLMENT_PROJECTION_SCHEMA",
    "SERVICE_DELIVERY_PROJECTION_SCHEMA",
    "AcceptanceTerm",
    "AcceptedDeviation",
    "AgreementPackageItem",
    "ApprovalRequirement",
    "BillingTerm",
    "ClauseFinding",
    "ClauseIndexEntry",
    "CommercialLegalHandoffEffectBoundary",
    "CommercialLegalHandoffScope",
    "CommercialTermChange",
    "CommercialTermSheet",
    "ContractToCashProjection",
    "CustodySignature",
    "DeliveryMilestone",
    "DeliveryTerm",
    "EntitlementTerm",
    "ExecutedAgreementReconciliation",
    "ExecutedAgreementReconciliationInput",
    "ExecutedCommercialAgreementCustodyCandidate",
    "ExecutedDocument",
    "LegalReviewOutcome",
    "LegalReviewOutcomeValidation",
    "LegalReviewOutcomeValidationInput",
    "LegalReviewPacket",
    "LegalReviewPacketInput",
    "NegotiationBoundary",
    "NoticeTerm",
    "ObligationFulfillmentProjection",
    "OutcomeViolation",
    "ProposedContractObligation",
    "ReconciliationBlocker",
    "RenewalTerm",
    "RequiredCommercialRevision",
    "ReviewedDocument",
    "ServiceDeliveryProjection",
    "SignatureRecord",
    "TerminationTerm",
    "UnresolvedDeviation",
    "approved_commercial_terms_digest",
    "commercial_legal_handoff_scope_digest",
    "compile_legal_review_packet",
    "custody_candidate_digest",
    "executed_agreement_digest",
    "executed_agreement_reconciliation_digest",
    "legal_review_outcome_digest",
    "legal_review_packet_digest",
    "legal_review_validation_digest",
    "reconcile_executed_agreement",
    "seal_legal_review_outcome",
    "validate_legal_review_outcome",
]
