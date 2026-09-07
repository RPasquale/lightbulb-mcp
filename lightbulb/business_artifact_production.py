"""Governed business-artifact production: context assembly, policy, delegation, validation.

The capability has four deterministic stages that surround a model-powered
(or template-powered) generation step:

1. **Assemble** brand, commercial, legal-template, customer, and engagement
   context into one sealed ``ArtifactGenerationBrief`` with explicit
   generation constraints and the approvals the artifact will need.
2. **Prepare** an ``ArtifactGenerationRequest`` for an
   ``ArtifactGenerationExecutor``.  The executor interface is protocol
   agnostic: an in-process template executor renders deterministically; a
   deferred host executor returns a ``HostGenerationTicket`` that the
   connected model host (Claude Code, Codex, ChatGPT, …) fulfils and submits
   back.  No MCP protocol operation is baked into this domain.
3. **Validate** the produced content against the brief: required sections,
   forbidden content (secrets, prices outside the commercial context, legal
   clauses outside the approved template), length bounds, and template clause
   retention for legal documents.
4. **Bind** provenance, versioning, approval requirements, and engagement
   linkage into a ``GeneratedBusinessArtifact`` candidate whose file write
   still goes through the existing ``documents.generate_business_artifact``
   primitive and Spring approval.

Legal-document policy here targets ordinary professionals: approved
templates, jurisdiction, risk classification, and mandatory review.  The SDK
never asserts that a document is legally sufficient; it only decides whether
the policy allows the draft to proceed and who must review it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.growth_primitives import GenerateBusinessArtifactInput


BUSINESS_ARTIFACT_GOLDEN_LOOP = "documents.governed_business_artifact_production@0.1.0"
ARTIFACT_BRIEF_SCHEMA = "lightbulb.business_artifact_generation_brief.v1"
ARTIFACT_REQUEST_SCHEMA = "lightbulb.business_artifact_generation_request.v1"
HOST_TICKET_SCHEMA = "lightbulb.business_artifact_host_generation_ticket.v1"
ARTIFACT_SUBMISSION_SCHEMA = "lightbulb.business_artifact_generation_submission.v1"
GENERATED_ARTIFACT_SCHEMA = "lightbulb.generated_business_artifact.v1"
LEGAL_POLICY_SCHEMA = "lightbulb.legal_document_policy.v1"

GENESIS_DIGEST = "0" * 64
MAX_CONTENT_BYTES = 1_000_000
MAX_SECTIONS = 60

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
_SECRET_LIKE_VALUE_PATTERNS = (
    re.compile(r"(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(xox[abprs]-|ghp_|gho_|github_pat_|glpat-)[A-Za-z0-9_-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(Bearer|Basic) [A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
)
_MONEY_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:USD|EUR|GBP|AUD|CAD|\$|€|£)\s?([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)")


def _reject_secret_like_text(value: str, *, label: str) -> None:
    for pattern in _SECRET_LIKE_VALUE_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"{label} must not carry credential-like material")


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS) and not lowered.endswith("_tokens"):
                raise ValueError(
                    f"{path}.{key} is a credential-like or authority-like field and is never accepted"
                )
            _reject_secret_like_payload(item, path=f"{path}.{key}")
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
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]

ArtifactKind = Literal[
    "proposal",
    "quote_summary",
    "estimate",
    "statement_of_work",
    "contract",
    "invoice",
    "brochure",
    "presentation",
    "one_pager",
    "case_study",
    "cover_letter",
]
ArtifactFormat = Literal["docx", "pdf", "xlsx", "pptx", "markdown"]
GenerationMode = Literal["host_model", "template"]
LegalRiskClass = Literal["none", "low", "standard", "elevated", "restricted"]
ApprovalKind = Literal["brand", "commercial", "legal", "finance", "executive"]
ArtifactState = Literal["validated", "review_required", "blocked"]
ValidationCode = Literal[
    "REQUIRED_SECTION_MISSING",
    "FORBIDDEN_SECTION_PRESENT",
    "CREDENTIAL_LIKE_CONTENT",
    "AMOUNT_OUTSIDE_COMMERCIAL_CONTEXT",
    "TEMPLATE_CLAUSE_MISSING",
    "CONTENT_TOO_LARGE",
    "CONTENT_EMPTY",
    "BRIEF_DIGEST_MISMATCH",
    "TICKET_DIGEST_MISMATCH",
    "TICKET_EXPIRED",
    "GENERATOR_NOT_DECLARED",
    "LEGAL_TEMPLATE_REQUIRED",
    "JURISDICTION_NOT_APPROVED",
    "RISK_CLASS_BLOCKED",
    "BRAND_CLAIM_FORBIDDEN",
]
LEGAL_ARTIFACT_KINDS: frozenset[str] = frozenset({"contract", "statement_of_work"})
COMMERCIAL_ARTIFACT_KINDS: frozenset[str] = frozenset({"proposal", "quote_summary", "estimate", "invoice"})
MARKETING_ARTIFACT_KINDS: frozenset[str] = frozenset({"brochure", "presentation", "one_pager", "case_study", "cover_letter"})

REQUIRED_SECTIONS: dict[str, tuple[str, ...]] = {
    "proposal": ("executive_summary", "scope", "pricing", "timeline", "next_steps"),
    "quote_summary": ("summary", "pricing", "validity"),
    "estimate": ("assumptions", "pricing", "exclusions"),
    "statement_of_work": ("scope", "deliverables", "acceptance", "schedule", "fees"),
    "contract": ("parties", "term", "fees", "liability", "termination", "governing_law"),
    "invoice": ("bill_to", "line_items", "total", "payment_terms"),
    "brochure": ("headline", "value_proposition", "call_to_action"),
    "presentation": ("agenda", "problem", "solution", "next_steps"),
    "one_pager": ("headline", "value_proposition", "proof_points", "call_to_action"),
    "case_study": ("challenge", "solution", "outcome"),
    "cover_letter": ("greeting", "purpose", "closing"),
}
ALLOWED_FORMATS: dict[str, tuple[str, ...]] = {
    "proposal": ("docx", "pdf", "markdown"),
    "quote_summary": ("docx", "pdf", "markdown"),
    "estimate": ("xlsx", "docx", "pdf", "markdown"),
    "statement_of_work": ("docx", "pdf", "markdown"),
    "contract": ("docx", "pdf"),
    "invoice": ("pdf", "docx", "xlsx"),
    "brochure": ("pdf", "docx"),
    "presentation": ("pptx", "pdf"),
    "one_pager": ("pdf", "docx", "markdown"),
    "case_study": ("docx", "pdf", "markdown"),
    "cover_letter": ("docx", "pdf", "markdown"),
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
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

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
    try:
        parsed = Decimal(value) if not isinstance(value, Decimal) else value
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a canonical decimal string") from exc
    if not parsed.is_finite() or parsed < 0 or parsed.as_tuple().exponent < -6:
        raise ValueError(f"{field_name} must be a finite non-negative decimal with at most six places")
    return parsed.quantize(Decimal("0.000001"))


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
    return bool((info.context or {}).get("skip_artifact_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_artifact_digests": True})
    return _digest_without(parsed.to_dict(), field)


# --------------------------------------------------------------------------- #
# Scope and context inputs
# --------------------------------------------------------------------------- #


class ArtifactProductionScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    engagement_ref: OpaqueRef | None = None
    customer_ref: OpaqueRef | None = None

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


class BrandContext(_StrictModel):
    """Brand facts by reference and short descriptors; no assets are embedded."""

    brand_ref: OpaqueRef
    brand_name: ShortText
    tone: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    palette_ref: OpaqueRef | None = None
    logo_asset_ref: OpaqueRef | None = None
    boilerplate_ref: OpaqueRef | None = None
    approved_claims: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=50)
    forbidden_claims: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=50)
    brand_approver_role_ref: OpaqueRef | None = None

    @field_validator("tone", mode="before")
    @classmethod
    def _tone(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="tone descriptors")


class CommercialLine(_StrictModel):
    line_ref: OpaqueRef
    description: ShortText
    quantity: Decimal
    unit_price: Decimal
    line_total: Decimal

    @field_validator("quantity", "unit_price", "line_total", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _decimal(value, field_name=str(info.field_name))


class CommercialContext(_StrictModel):
    """Exact commercial facts the artifact may quote; nothing else may appear as a price."""

    quote_ref: OpaqueRef | None = None
    quote_revision: int | None = Field(default=None, ge=1)
    order_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    commercial_terms_digest: Sha256Digest | None = None
    currency: CurrencyCode
    total: Decimal
    lines: tuple[CommercialLine, ...] = Field(default_factory=tuple, max_length=500)
    payment_terms_days: int | None = Field(default=None, ge=0, le=365)
    valid_until: str | None = None

    @field_validator("total", mode="before")
    @classmethod
    def _total(cls, value: Any) -> Any:
        return _decimal(value, field_name="total")

    @field_validator("valid_until")
    @classmethod
    def _valid(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="valid_until")

    @model_validator(mode="after")
    def _lines_sum(self) -> "CommercialContext":
        _unique([item.line_ref for item in self.lines], label="commercial lines")
        if self.lines and sum((item.line_total for item in self.lines), Decimal(0)) != self.total:
            raise ValueError("commercial line totals must sum to the total")
        return self

    def allowed_amounts(self) -> frozenset[Decimal]:
        amounts = {self.total}
        for line in self.lines:
            amounts.update({line.unit_price, line.line_total})
        return frozenset(amounts)


class ApprovedLegalTemplate(_StrictModel):
    template_ref: OpaqueRef
    template_digest: Sha256Digest
    document_kind: Literal["contract", "statement_of_work"]
    jurisdiction_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    required_clause_markers: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)
    risk_class: LegalRiskClass = "standard"
    version: int = Field(ge=1, le=10_000)

    @field_validator("jurisdiction_refs", mode="before")
    @classmethod
    def _jurisdictions(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="template jurisdictions")


class LegalDocumentPolicy(_StrictModel):
    """Legal-document guard rails for ordinary professionals, not a lawyer-only workflow."""

    schema_id: Literal["lightbulb.legal_document_policy.v1"] = Field(default=LEGAL_POLICY_SCHEMA, alias="schema")
    policy_ref: OpaqueRef
    approved_templates: tuple[ApprovedLegalTemplate, ...] = Field(default_factory=tuple, max_length=200)
    approved_jurisdiction_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    review_required_from_risk_class: LegalRiskClass = "elevated"
    blocked_risk_classes: tuple[LegalRiskClass, ...] = Field(default=("restricted",), max_length=5)
    legal_reviewer_role_ref: OpaqueRef
    allow_untemplated_legal_documents: bool = False
    contract_value_review_threshold: Decimal | None = None
    currency: CurrencyCode | None = None

    @field_validator("approved_jurisdiction_refs", mode="before")
    @classmethod
    def _jurisdictions(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="approved jurisdictions")

    @field_validator("contract_value_review_threshold", mode="before")
    @classmethod
    def _threshold(cls, value: Any) -> Any:
        return None if value is None else _decimal(value, field_name="contract_value_review_threshold")

    @model_validator(mode="after")
    def _policy_is_coherent(self) -> "LegalDocumentPolicy":
        _unique([f"{item.template_ref}:{item.version}" for item in self.approved_templates], label="approved templates")
        if (self.contract_value_review_threshold is None) != (self.currency is None):
            raise ValueError("a value review threshold requires its currency")
        return self


class LegalTemplateContext(_StrictModel):
    policy: LegalDocumentPolicy
    template_ref: OpaqueRef | None = None
    template_version: int | None = Field(default=None, ge=1, le=10_000)
    jurisdiction_ref: OpaqueRef
    counterparty_ref: OpaqueRef
    requested_deviations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=50)


class CustomerContext(_StrictModel):
    customer_ref: OpaqueRef
    customer_display_name: ShortText
    industry: ShortText | None = None
    contact_role_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    preferences: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    relationship_summary: BoundedText | None = None


class EngagementContext(_StrictModel):
    engagement_ref: OpaqueRef
    stage: ShortText
    linked_artifact_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=50)
    custody_candidate_digest: Sha256Digest | None = None
    delivery_plan_digest: Sha256Digest | None = None


# --------------------------------------------------------------------------- #
# Risk classification and brief assembly
# --------------------------------------------------------------------------- #


_RISK_RANK: dict[str, int] = {"none": 0, "low": 1, "standard": 2, "elevated": 3, "restricted": 4}


class LegalRiskAssessment(_StrictModel):
    risk_class: LegalRiskClass
    template_ref: OpaqueRef | None = None
    template_digest: Sha256Digest | None = None
    template_version: int | None = None
    mandatory_legal_review: bool
    blocked: bool
    reasons: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    required_clause_markers: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)


def classify_legal_artifact_risk(
    kind: ArtifactKind,
    legal: LegalTemplateContext | None,
    commercial: CommercialContext | None,
) -> LegalRiskAssessment:
    """Decide whether policy allows a legal draft and who must review it; never a legal opinion."""

    if kind not in LEGAL_ARTIFACT_KINDS:
        return LegalRiskAssessment(risk_class="none", mandatory_legal_review=False, blocked=False)
    if legal is None:
        return LegalRiskAssessment(
            risk_class="restricted",
            mandatory_legal_review=True,
            blocked=True,
            reasons=("legal artifacts require a legal template context and policy",),
        )
    policy = legal.policy
    reasons: list[str] = []
    blocked = False
    template: ApprovedLegalTemplate | None = None
    if legal.template_ref is not None:
        template = next(
            (
                item
                for item in policy.approved_templates
                if item.template_ref == legal.template_ref
                and (legal.template_version is None or item.version == legal.template_version)
                and item.document_kind == kind
            ),
            None,
        )
        if template is None:
            reasons.append("cited template is not an approved template for this document kind")
            blocked = True
    elif not policy.allow_untemplated_legal_documents:
        reasons.append("policy requires an approved template for legal documents")
        blocked = True
    if legal.jurisdiction_ref not in policy.approved_jurisdiction_refs:
        reasons.append("jurisdiction is not approved by the legal policy")
        blocked = True
    if template is not None and legal.jurisdiction_ref not in template.jurisdiction_refs:
        reasons.append("approved template does not cover the requested jurisdiction")
        blocked = True
    risk = template.risk_class if template is not None else "elevated"
    if legal.requested_deviations:
        risk = "elevated" if _RISK_RANK[risk] < _RISK_RANK["elevated"] else risk
        reasons.append("requested deviations from the approved template require legal review")
    if (
        commercial is not None
        and policy.contract_value_review_threshold is not None
        and policy.currency == commercial.currency
        and commercial.total >= policy.contract_value_review_threshold
    ):
        risk = "elevated" if _RISK_RANK[risk] < _RISK_RANK["elevated"] else risk
        reasons.append("contract value meets the policy review threshold")
    if risk in policy.blocked_risk_classes:
        reasons.append(f"risk class {risk} is blocked by policy")
        blocked = True
    mandatory_review = blocked or _RISK_RANK[risk] >= _RISK_RANK[policy.review_required_from_risk_class] or bool(
        legal.requested_deviations
    )
    return LegalRiskAssessment(
        risk_class=risk,
        template_ref=template.template_ref if template else None,
        template_digest=template.template_digest if template else None,
        template_version=template.version if template else None,
        mandatory_legal_review=mandatory_review,
        blocked=blocked,
        reasons=tuple(reasons),
        required_clause_markers=template.required_clause_markers if template else (),
    )


class ApprovalRequirement(_StrictModel):
    approval_kind: ApprovalKind
    approver_role_ref: OpaqueRef
    reason: BoundedText


class GenerationConstraints(_StrictModel):
    required_sections: tuple[ShortText, ...] = Field(min_length=1, max_length=MAX_SECTIONS)
    forbidden_sections: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_SECTIONS)
    max_words: int = Field(default=4000, ge=50, le=50_000)
    amounts_must_match_commercial_context: bool = True
    template_clauses_must_be_retained: bool = False
    forbidden_claims: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=50)
    language: ShortText = "en"
    tone: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)


class ArtifactGenerationInput(_StrictModel):
    scope: ArtifactProductionScope
    artifact_kind: ArtifactKind
    artifact_format: ArtifactFormat
    title: ShortText
    purpose: BoundedText
    generation_mode: GenerationMode = "host_model"
    brand: BrandContext | None = None
    commercial: CommercialContext | None = None
    legal: LegalTemplateContext | None = None
    customer: CustomerContext | None = None
    engagement: EngagementContext | None = None
    source_artifact_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    prior_version: tuple[OpaqueRef, int, Sha256Digest] | None = None
    max_words: int = Field(default=4000, ge=50, le=50_000)
    language: ShortText = "en"
    requested_at: str
    requested_by_ref: OpaqueRef

    @field_validator("requested_at")
    @classmethod
    def _requested(cls, value: str) -> str:
        return _timestamp(value, field_name="requested_at")

    @field_validator("source_artifact_refs", mode="before")
    @classmethod
    def _sources(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="source artifact refs")

    @model_validator(mode="after")
    def _input_is_coherent(self) -> "ArtifactGenerationInput":
        if self.artifact_format not in ALLOWED_FORMATS[self.artifact_kind]:
            raise ValueError(f"{self.artifact_kind} cannot be produced as {self.artifact_format}")
        if self.artifact_kind in COMMERCIAL_ARTIFACT_KINDS and self.commercial is None:
            raise ValueError(f"{self.artifact_kind} requires a commercial context")
        if self.engagement is not None and self.scope.engagement_ref not in {None, self.engagement.engagement_ref}:
            raise ValueError("engagement context must match the scoped engagement")
        if self.customer is not None and self.scope.customer_ref not in {None, self.customer.customer_ref}:
            raise ValueError("customer context must match the scoped customer")
        if self.artifact_kind in MARKETING_ARTIFACT_KINDS and self.brand is None:
            raise ValueError(f"{self.artifact_kind} requires a brand context")
        return self


class ArtifactGenerationBrief(_StrictModel):
    """Sealed, prompt-ready assembly of every context the generator may rely on."""

    schema_id: Literal["lightbulb.business_artifact_generation_brief.v1"] = Field(default=ARTIFACT_BRIEF_SCHEMA, alias="schema")
    scope: ArtifactProductionScope
    artifact_kind: ArtifactKind
    artifact_format: ArtifactFormat
    title: ShortText
    purpose: BoundedText
    brand: BrandContext | None = None
    commercial: CommercialContext | None = None
    legal_assessment: LegalRiskAssessment
    customer: CustomerContext | None = None
    engagement: EngagementContext | None = None
    constraints: GenerationConstraints
    required_approvals: tuple[ApprovalRequirement, ...] = Field(default_factory=tuple, max_length=10)
    source_artifact_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    prior_version: tuple[OpaqueRef, int, Sha256Digest] | None = None
    next_version: int = Field(ge=1, le=10_000)
    requested_at: str
    requested_by_ref: OpaqueRef
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _brief_is_exact(self, info: ValidationInfo) -> "ArtifactGenerationBrief":
        if _skip(info):
            return self
        if self.brief_digest != _sealed_digest(ArtifactGenerationBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self

    def prompt_sections(self) -> dict[str, Any]:
        """Structured, model-facing rendering of the brief (no secrets, refs only)."""

        sections: dict[str, Any] = {
            "artifact": {
                "kind": self.artifact_kind,
                "format": self.artifact_format,
                "title": self.title,
                "purpose": self.purpose,
                "language": self.constraints.language,
                "required_sections": list(self.constraints.required_sections),
                "forbidden_sections": list(self.constraints.forbidden_sections),
                "max_words": self.constraints.max_words,
            },
            "rules": [
                "Use only the commercial amounts listed; never invent prices, discounts, or totals.",
                "Do not include credentials, identifiers, or internal system references.",
                "Do not assert legal conclusions; legal documents follow the approved template exactly.",
                "Return every required section under its exact section key.",
            ],
        }
        if self.brand is not None:
            sections["brand"] = {
                "name": self.brand.brand_name,
                "tone": list(self.brand.tone),
                "approved_claims": list(self.brand.approved_claims),
                "forbidden_claims": list(self.brand.forbidden_claims),
            }
        if self.commercial is not None:
            sections["commercial"] = {
                "currency": self.commercial.currency,
                "total": str(self.commercial.total),
                "lines": [
                    {"description": line.description, "quantity": str(line.quantity), "unit_price": str(line.unit_price), "line_total": str(line.line_total)}
                    for line in self.commercial.lines
                ],
                "payment_terms_days": self.commercial.payment_terms_days,
                "valid_until": self.commercial.valid_until,
            }
        if self.legal_assessment.risk_class != "none":
            sections["legal"] = {
                "template_ref": self.legal_assessment.template_ref,
                "required_clause_markers": list(self.legal_assessment.required_clause_markers),
                "risk_class": self.legal_assessment.risk_class,
                "mandatory_legal_review": self.legal_assessment.mandatory_legal_review,
            }
        if self.customer is not None:
            sections["customer"] = {
                "name": self.customer.customer_display_name,
                "industry": self.customer.industry,
                "preferences": list(self.customer.preferences),
                "relationship_summary": self.customer.relationship_summary,
            }
        if self.engagement is not None:
            sections["engagement"] = {"engagement_ref": self.engagement.engagement_ref, "stage": self.engagement.stage}
        return sections


def assemble_artifact_generation_brief(
    inputs: ArtifactGenerationInput | Mapping[str, Any],
) -> ArtifactGenerationBrief:
    parsed = ArtifactGenerationInput.model_validate(_detached(inputs))
    kind = parsed.artifact_kind
    assessment = classify_legal_artifact_risk(kind, parsed.legal, parsed.commercial)
    approvals: list[ApprovalRequirement] = []
    if parsed.brand is not None and parsed.brand.brand_approver_role_ref is not None and kind not in LEGAL_ARTIFACT_KINDS:
        approvals.append(ApprovalRequirement(approval_kind="brand", approver_role_ref=parsed.brand.brand_approver_role_ref, reason="customer-facing material produced under a brand context requires brand approval"))
    if kind in COMMERCIAL_ARTIFACT_KINDS | LEGAL_ARTIFACT_KINDS:
        approvals.append(ApprovalRequirement(approval_kind="commercial", approver_role_ref="role-commercial-approver", reason="commercial terms must be approved before the artifact leaves the company"))
    if kind == "invoice":
        approvals.append(ApprovalRequirement(approval_kind="finance", approver_role_ref="role-finance-approver", reason="invoices are issued only through the governed finance path"))
    if assessment.mandatory_legal_review and parsed.legal is not None:
        approvals.append(ApprovalRequirement(approval_kind="legal", approver_role_ref=parsed.legal.policy.legal_reviewer_role_ref, reason="; ".join(assessment.reasons) or "legal policy requires review"))
    constraints = GenerationConstraints(
        required_sections=REQUIRED_SECTIONS[kind],
        forbidden_sections=("pricing", "fees", "total") if kind in MARKETING_ARTIFACT_KINDS else (),
        max_words=parsed.max_words,
        amounts_must_match_commercial_context=parsed.commercial is not None,
        template_clauses_must_be_retained=bool(assessment.required_clause_markers),
        forbidden_claims=parsed.brand.forbidden_claims if parsed.brand else (),
        language=parsed.language,
        tone=parsed.brand.tone if parsed.brand else (),
    )
    brief = {
        "scope": parsed.scope.to_dict(),
        "artifact_kind": kind,
        "artifact_format": parsed.artifact_format,
        "title": parsed.title,
        "purpose": parsed.purpose,
        "brand": parsed.brand.to_dict() if parsed.brand else None,
        "commercial": parsed.commercial.to_dict() if parsed.commercial else None,
        "legal_assessment": assessment.to_dict(),
        "customer": parsed.customer.to_dict() if parsed.customer else None,
        "engagement": parsed.engagement.to_dict() if parsed.engagement else None,
        "constraints": constraints.to_dict(),
        "required_approvals": [item.to_dict() for item in approvals],
        "source_artifact_refs": list(parsed.source_artifact_refs),
        "prior_version": list(parsed.prior_version) if parsed.prior_version else None,
        "next_version": (parsed.prior_version[1] + 1) if parsed.prior_version else 1,
        "requested_at": parsed.requested_at,
        "requested_by_ref": parsed.requested_by_ref,
    }
    brief["brief_digest"] = _sealed_digest(ArtifactGenerationBrief, brief, "brief_digest")
    return ArtifactGenerationBrief.model_validate(brief)


# --------------------------------------------------------------------------- #
# Execution interface: template executor and deferred host executor
# --------------------------------------------------------------------------- #


class HostGenerationTicket(_StrictModel):
    """A protocol-agnostic request for the connected model host to produce content."""

    schema_id: Literal["lightbulb.business_artifact_host_generation_ticket.v1"] = Field(default=HOST_TICKET_SCHEMA, alias="schema")
    ticket_ref: OpaqueRef
    brief_digest: Sha256Digest
    prompt_sections: dict[str, Any]
    response_contract: dict[str, Any]
    issued_at: str
    expires_at: str
    ticket_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ticket_is_exact(self, info: ValidationInfo) -> "HostGenerationTicket":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.issued_at):
            raise ValueError("ticket expiry must follow issuance")
        if _skip(info):
            return self
        if self.ticket_digest != _sealed_digest(HostGenerationTicket, self, "ticket_digest"):
            raise ValueError("ticket_digest must commit the exact ticket")
        return self


class ArtifactGenerationRequest(_StrictModel):
    schema_id: Literal["lightbulb.business_artifact_generation_request.v1"] = Field(default=ARTIFACT_REQUEST_SCHEMA, alias="schema")
    brief: ArtifactGenerationBrief
    generation_mode: GenerationMode
    host_ticket: HostGenerationTicket | None = None
    blocked_reasons: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    request_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _request_is_exact(self, info: ValidationInfo) -> "ArtifactGenerationRequest":
        if (self.generation_mode == "host_model") != (self.host_ticket is not None) and not self.blocked_reasons:
            raise ValueError("host_model requests carry exactly one host ticket")
        if _skip(info):
            return self
        if self.request_digest != _sealed_digest(ArtifactGenerationRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self


class GenerationProvenance(_StrictModel):
    generator_kind: Literal["host_model", "template"]
    host_ref: OpaqueRef | None = None
    model_ref: OpaqueRef | None = None
    host_session_ref: OpaqueRef | None = None
    ticket_digest: Sha256Digest | None = None
    generated_at: str

    @field_validator("generated_at")
    @classmethod
    def _generated(cls, value: str) -> str:
        return _timestamp(value, field_name="generated_at")

    @model_validator(mode="after")
    def _provenance_is_declared(self) -> "GenerationProvenance":
        if self.generator_kind == "host_model" and (self.host_ref is None or self.ticket_digest is None):
            raise ValueError("host-model provenance requires host_ref and ticket_digest")
        return self


class ArtifactGenerationSubmission(_StrictModel):
    """What comes back from an executor: sectioned content plus provenance."""

    schema_id: Literal["lightbulb.business_artifact_generation_submission.v1"] = Field(default=ARTIFACT_SUBMISSION_SCHEMA, alias="schema")
    brief_digest: Sha256Digest
    sections: dict[str, str]
    provenance: GenerationProvenance

    @field_validator("sections", mode="before")
    @classmethod
    def _sections(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): value[key] for key in sorted(value)}
        return value


class ArtifactGenerationExecutor(Protocol):
    """Protocol-agnostic execution interface; MCP, CLI, or in-process hosts implement it."""

    executor_kind: str

    def generate(self, request: ArtifactGenerationRequest) -> ArtifactGenerationSubmission | HostGenerationTicket: ...


class TemplateArtifactGenerationExecutor:
    """Deterministic in-process executor: renders the brief into required sections."""

    executor_kind = "template"

    def generate(self, request: ArtifactGenerationRequest) -> ArtifactGenerationSubmission:
        brief = request.brief
        sections: dict[str, str] = {}
        for section in brief.constraints.required_sections:
            sections[section] = _render_template_section(brief, section)
        return ArtifactGenerationSubmission(
            brief_digest=brief.brief_digest,
            sections=sections,
            provenance=GenerationProvenance(generator_kind="template", generated_at=brief.requested_at),
        )


class DeferredHostGenerationExecutor:
    """Returns the host ticket; the connected model host produces and submits content later."""

    executor_kind = "deferred_host"

    def generate(self, request: ArtifactGenerationRequest) -> HostGenerationTicket:
        if request.host_ticket is None:
            raise ValueError("deferred host generation requires a host ticket")
        return request.host_ticket


def _render_template_section(brief: ArtifactGenerationBrief, section: str) -> str:
    customer = brief.customer.customer_display_name if brief.customer else "the customer"
    brand = brief.brand.brand_name if brief.brand else "our company"
    commercial = brief.commercial
    if section in {"pricing", "fees", "total", "line_items"} and commercial is not None:
        lines = "; ".join(
            f"{line.description}: {line.quantity} x {commercial.currency} {line.unit_price} = {commercial.currency} {line.line_total}"
            for line in commercial.lines
        )
        return f"{lines or 'Total'} — total {commercial.currency} {commercial.total}."
    if section == "payment_terms" and commercial is not None:
        return f"Payment due within {commercial.payment_terms_days or 30} days of invoice."
    if section == "validity" and commercial is not None:
        return f"Valid until {commercial.valid_until or 'the stated date'}."
    if section == "governing_law":
        return "[[clause:governing_law]] This agreement is governed by the approved jurisdiction."
    if section in {"parties", "bill_to", "greeting"}:
        return f"{brand} and {customer}."
    if section in {"liability", "termination", "term"} and brief.legal_assessment.template_ref:
        markers = " ".join(f"[[clause:{marker}]]" for marker in brief.legal_assessment.required_clause_markers if marker.startswith(section))
        return f"{markers} Per approved template {brief.legal_assessment.template_ref}.".strip()
    return f"{section.replace('_', ' ').capitalize()} for {customer}: {brief.purpose}"


def prepare_business_artifact_generation(
    inputs: ArtifactGenerationInput | Mapping[str, Any],
    *,
    ticket_ref: str | None = None,
    ticket_ttl_hours: int = 24,
) -> ArtifactGenerationRequest:
    """Assemble the brief and produce the executor request (ticket for host generation)."""

    parsed = ArtifactGenerationInput.model_validate(_detached(inputs))
    brief = assemble_artifact_generation_brief(parsed)
    blocked: list[str] = []
    if brief.legal_assessment.blocked:
        blocked.extend(brief.legal_assessment.reasons)
    ticket: dict[str, Any] | None = None
    if parsed.generation_mode == "host_model" and not blocked:
        issued = _parsed_timestamp(brief.requested_at)
        from datetime import timedelta

        expires = issued + timedelta(hours=max(1, min(ticket_ttl_hours, 168)))
        ticket = {
            "ticket_ref": ticket_ref or f"artifact-ticket:{brief.brief_digest[:16]}",
            "brief_digest": brief.brief_digest,
            "prompt_sections": brief.prompt_sections(),
            "response_contract": {
                "schema": ARTIFACT_SUBMISSION_SCHEMA,
                "sections": {key: "string" for key in brief.constraints.required_sections},
                "provenance": {"generator_kind": "host_model", "host_ref": "<host>", "model_ref": "<model>", "ticket_digest": "<ticket_digest>", "generated_at": "<utc timestamp>"},
                "instruction": "Return every required section verbatim under its key; do not add prices, credentials, or legal conclusions.",
            },
            "issued_at": brief.requested_at,
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        }
        ticket["ticket_digest"] = _sealed_digest(HostGenerationTicket, ticket, "ticket_digest")
    request = {
        "brief": brief.to_dict(),
        "generation_mode": parsed.generation_mode,
        "host_ticket": ticket,
        "blocked_reasons": blocked,
    }
    request["request_digest"] = _sealed_digest(ArtifactGenerationRequest, request, "request_digest")
    return ArtifactGenerationRequest.model_validate(request)


# --------------------------------------------------------------------------- #
# Validation and binding
# --------------------------------------------------------------------------- #


class ValidationFinding(_StrictModel):
    code: ValidationCode
    detail: BoundedText
    section: ShortText | None = None


class GeneratedBusinessArtifact(_StrictModel):
    """Validated artifact candidate with provenance, version, approvals, and engagement linkage."""

    schema_id: Literal["lightbulb.generated_business_artifact.v1"] = Field(default=GENERATED_ARTIFACT_SCHEMA, alias="schema")
    scope: ArtifactProductionScope
    artifact_ref: OpaqueRef
    version: int = Field(ge=1, le=10_000)
    prior_version_digest: Sha256Digest | None = None
    artifact_kind: ArtifactKind
    artifact_format: ArtifactFormat
    title: ShortText
    brief_digest: Sha256Digest
    request_digest: Sha256Digest
    sections: dict[str, str]
    content_digest: Sha256Digest
    word_count: int = Field(ge=0)
    provenance: GenerationProvenance
    legal_assessment: LegalRiskAssessment
    required_approvals: tuple[ApprovalRequirement, ...] = Field(default_factory=tuple, max_length=10)
    engagement_ref: OpaqueRef | None = None
    engagement_stage: ShortText | None = None
    linked_artifact_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=50)
    state: ArtifactState
    findings: tuple[ValidationFinding, ...] = Field(default_factory=tuple, max_length=100)
    authoritative: Literal[False] = False
    external_write_performed: Literal[False] = False
    artifact_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("sections", mode="before")
    @classmethod
    def _sections(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): value[key] for key in sorted(value)}
        return value

    @model_validator(mode="after")
    def _artifact_is_exact(self, info: ValidationInfo) -> "GeneratedBusinessArtifact":
        if self.content_digest != _stable_digest(self.sections):
            raise ValueError("content_digest must commit the exact sections")
        if self.state == "blocked" and not self.findings:
            raise ValueError("a blocked artifact carries findings")
        if self.state == "validated" and (self.findings or self.required_approvals):
            raise ValueError("a validated artifact has no findings and no outstanding approvals")
        if self.state == "review_required" and not (self.required_approvals or self.legal_assessment.mandatory_legal_review):
            raise ValueError("review_required needs an approval or mandatory review")
        if _skip(info):
            return self
        if self.artifact_digest != _sealed_digest(GeneratedBusinessArtifact, self, "artifact_digest"):
            raise ValueError("artifact_digest must commit the exact artifact")
        return self

    def to_generate_business_artifact_input(self, *, destination: str = "", create: bool = False) -> GenerateBusinessArtifactInput:
        """Project into the existing governed file-write primitive's input."""

        return GenerateBusinessArtifactInput(
            artifact_type=self.artifact_format,
            title=self.title,
            content={
                "artifact_ref": self.artifact_ref,
                "version": self.version,
                "artifact_digest": self.artifact_digest,
                "sections": dict(self.sections),
            },
            destination=destination,
            create=create,
        )


class ArtifactValidationInput(_StrictModel):
    request: ArtifactGenerationRequest
    submission: ArtifactGenerationSubmission
    artifact_ref: OpaqueRef
    validated_at: str
    requested_by_ref: OpaqueRef

    @field_validator("validated_at")
    @classmethod
    def _validated(cls, value: str) -> str:
        return _timestamp(value, field_name="validated_at")


def _amounts_in_text(text: str) -> set[Decimal]:
    found: set[Decimal] = set()
    for match in _MONEY_PATTERN.finditer(text):
        raw = match.group(1).replace(",", "")
        try:
            found.add(Decimal(raw).quantize(Decimal("0.000001")))
        except InvalidOperation:
            continue
    return found


def validate_generated_business_artifact(
    inputs: ArtifactValidationInput | Mapping[str, Any],
) -> GeneratedBusinessArtifact:
    """Validate submitted content against the brief and bind provenance, version, approvals, engagement."""

    parsed = ArtifactValidationInput.model_validate(_detached(inputs))
    request = parsed.request
    brief = request.brief
    submission = parsed.submission
    findings: list[ValidationFinding] = []

    def find(code: ValidationCode, detail: str, section: str | None = None) -> None:
        findings.append(ValidationFinding(code=code, detail=detail, section=section))

    if submission.brief_digest != brief.brief_digest:
        find("BRIEF_DIGEST_MISMATCH", "submission does not cite the exact brief")
    if request.blocked_reasons:
        for reason in request.blocked_reasons:
            find("RISK_CLASS_BLOCKED" if "risk class" in reason else ("JURISDICTION_NOT_APPROVED" if "jurisdiction" in reason else "LEGAL_TEMPLATE_REQUIRED"), reason)
    provenance = submission.provenance
    if request.generation_mode == "host_model":
        if provenance.generator_kind != "host_model":
            find("GENERATOR_NOT_DECLARED", "host-model requests must declare host-model provenance")
        elif request.host_ticket is not None:
            if provenance.ticket_digest != request.host_ticket.ticket_digest:
                find("TICKET_DIGEST_MISMATCH", "provenance cites a different host ticket")
            if _parsed_timestamp(provenance.generated_at) > _parsed_timestamp(request.host_ticket.expires_at):
                find("TICKET_EXPIRED", "content was generated after the ticket expired")
    elif provenance.generator_kind != "template":
        find("GENERATOR_NOT_DECLARED", "template requests must declare template provenance")

    sections = submission.sections
    rendered = json.dumps(sections, ensure_ascii=True)
    if len(rendered.encode("utf-8")) > MAX_CONTENT_BYTES:
        find("CONTENT_TOO_LARGE", "artifact content exceeds the bounded size")
    if not any(text.strip() for text in sections.values()):
        find("CONTENT_EMPTY", "artifact content is empty")
    for section in brief.constraints.required_sections:
        if not sections.get(section, "").strip():
            find("REQUIRED_SECTION_MISSING", f"required section {section} is missing or empty", section)
    for section in brief.constraints.forbidden_sections:
        if sections.get(section, "").strip():
            find("FORBIDDEN_SECTION_PRESENT", f"section {section} is not allowed in this artifact kind", section)
    for section, text in sections.items():
        for pattern in _SECRET_LIKE_VALUE_PATTERNS:
            if pattern.search(text):
                find("CREDENTIAL_LIKE_CONTENT", "section carries credential-like material", section)
                break
        if brief.brand is not None:
            for claim in brief.brand.forbidden_claims:
                if claim.lower() in text.lower():
                    find("BRAND_CLAIM_FORBIDDEN", f"section repeats a forbidden brand claim: {claim}", section)
    if brief.constraints.amounts_must_match_commercial_context and brief.commercial is not None:
        allowed = brief.commercial.allowed_amounts()
        for section, text in sections.items():
            stray = sorted(str(amount) for amount in _amounts_in_text(text) - allowed)
            if stray:
                find("AMOUNT_OUTSIDE_COMMERCIAL_CONTEXT", f"amounts not in the commercial context: {', '.join(stray)}", section)
    if brief.constraints.template_clauses_must_be_retained:
        joined = "\n".join(sections.values())
        for marker in brief.legal_assessment.required_clause_markers:
            if f"[[clause:{marker}]]" not in joined:
                find("TEMPLATE_CLAUSE_MISSING", f"approved template clause {marker} is not retained")

    word_count = sum(len(text.split()) for text in sections.values())
    approvals = tuple(brief.required_approvals)
    if findings:
        state: ArtifactState = "blocked"
    elif approvals or brief.legal_assessment.mandatory_legal_review:
        state = "review_required"
    else:
        state = "validated"
    artifact = {
        "scope": brief.scope.to_dict(),
        "artifact_ref": parsed.artifact_ref,
        "version": brief.next_version,
        "prior_version_digest": brief.prior_version[2] if brief.prior_version else None,
        "artifact_kind": brief.artifact_kind,
        "artifact_format": brief.artifact_format,
        "title": brief.title,
        "brief_digest": brief.brief_digest,
        "request_digest": request.request_digest,
        "sections": dict(sections),
        "content_digest": _stable_digest({key: sections[key] for key in sorted(sections)}),
        "word_count": word_count,
        "provenance": provenance.to_dict(),
        "legal_assessment": brief.legal_assessment.to_dict(),
        "required_approvals": [item.to_dict() for item in approvals],
        "engagement_ref": brief.engagement.engagement_ref if brief.engagement else None,
        "engagement_stage": brief.engagement.stage if brief.engagement else None,
        "linked_artifact_digests": list(brief.engagement.linked_artifact_digests) if brief.engagement else [],
        "state": state,
        "findings": [item.to_dict() for item in findings],
    }
    artifact["artifact_digest"] = _sealed_digest(GeneratedBusinessArtifact, artifact, "artifact_digest")
    return GeneratedBusinessArtifact.model_validate(artifact)


def generate_business_artifact_with_executor(
    inputs: ArtifactGenerationInput | Mapping[str, Any],
    executor: ArtifactGenerationExecutor,
    *,
    artifact_ref: str,
    validated_at: str,
    requested_by_ref: str,
) -> GeneratedBusinessArtifact | HostGenerationTicket:
    """Prepare, execute through the given executor, and validate when content is available."""

    request = prepare_business_artifact_generation(inputs)
    if request.blocked_reasons:
        submission = ArtifactGenerationSubmission(
            brief_digest=request.brief.brief_digest,
            sections={},
            provenance=GenerationProvenance(generator_kind="template", generated_at=request.brief.requested_at),
        )
        return validate_generated_business_artifact(
            {"request": request.to_dict(), "submission": submission.to_dict(), "artifact_ref": artifact_ref, "validated_at": validated_at, "requested_by_ref": requested_by_ref}
        )
    produced = executor.generate(request)
    if isinstance(produced, HostGenerationTicket):
        return produced
    return validate_generated_business_artifact(
        {"request": request.to_dict(), "submission": produced.to_dict(), "artifact_ref": artifact_ref, "validated_at": validated_at, "requested_by_ref": requested_by_ref}
    )


__all__ = [
    "ALLOWED_FORMATS",
    "ARTIFACT_BRIEF_SCHEMA",
    "ARTIFACT_REQUEST_SCHEMA",
    "ARTIFACT_SUBMISSION_SCHEMA",
    "BUSINESS_ARTIFACT_GOLDEN_LOOP",
    "COMMERCIAL_ARTIFACT_KINDS",
    "GENERATED_ARTIFACT_SCHEMA",
    "HOST_TICKET_SCHEMA",
    "LEGAL_ARTIFACT_KINDS",
    "LEGAL_POLICY_SCHEMA",
    "MARKETING_ARTIFACT_KINDS",
    "REQUIRED_SECTIONS",
    "ApprovalRequirement",
    "ApprovedLegalTemplate",
    "ArtifactGenerationBrief",
    "ArtifactGenerationExecutor",
    "ArtifactGenerationInput",
    "ArtifactGenerationRequest",
    "ArtifactGenerationSubmission",
    "ArtifactProductionScope",
    "ArtifactValidationInput",
    "BrandContext",
    "CommercialContext",
    "CommercialLine",
    "CustomerContext",
    "DeferredHostGenerationExecutor",
    "EngagementContext",
    "GeneratedBusinessArtifact",
    "GenerationConstraints",
    "GenerationProvenance",
    "HostGenerationTicket",
    "LegalDocumentPolicy",
    "LegalRiskAssessment",
    "LegalTemplateContext",
    "TemplateArtifactGenerationExecutor",
    "ValidationFinding",
    "assemble_artifact_generation_brief",
    "classify_legal_artifact_risk",
    "generate_business_artifact_with_executor",
    "prepare_business_artifact_generation",
    "validate_generated_business_artifact",
]
