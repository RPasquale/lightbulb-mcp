"""SaaS product research, thesis, validation, business model, funding ask, and artifact grounding.

A SaaS *product* is more than an app.  Before a line of code is written a
company needs evidence-backed market research, a product thesis and pricing
hypothesis, demand validation, a business model with projections, a funding
ask, and the materials that carry all of it: pitch deck, one-pager, financial
summary, marketing site copy, launch brief.  This module types those objects
and the mechanics between them so every number in a deck traces back to a
sealed research, projection, or funding fact.

Rules:
- Every market claim is either **evidence-backed** (refs) or a typed
  **assumption** with a confidence; the confidence score is derived, never
  asserted.
- TAM ≥ SAM ≥ SOM, each with its basis and assumptions.
- Validation verdicts come from thresholds the blueprint sets, not from a
  model's opinion.
- Projections are deterministic arithmetic over declared assumptions.
- Use of funds sums to the ask; runway after the raise is derived.
- ``verify_artifact_grounding`` rejects numbers in generated materials that do
  not match a grounding fact.

Nothing here calls a model, a data provider, or a file store.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_validator


RESEARCH_DOSSIER_SCHEMA = "lightbulb.saas_market_research_dossier.v1"
PRODUCT_THESIS_SCHEMA = "lightbulb.saas_product_thesis.v1"
PRICING_HYPOTHESIS_SCHEMA = "lightbulb.saas_pricing_hypothesis.v1"
VALIDATION_VERDICT_SCHEMA = "lightbulb.saas_demand_validation_verdict.v1"
BUSINESS_MODEL_SCHEMA = "lightbulb.saas_business_model.v1"
PROJECTION_SCHEMA = "lightbulb.saas_financial_projection.v1"
FUNDING_ASK_SCHEMA = "lightbulb.saas_funding_ask.v1"
ARTIFACT_PLAN_SCHEMA = "lightbulb.saas_product_artifact_plan.v1"
GROUNDING_REPORT_SCHEMA = "lightbulb.saas_artifact_grounding_report.v1"
GENESIS_DIGEST = "0" * 64
MAX_PROJECTION_MONTHS = 60

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id")
_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
)
_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.0001")

OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

Confidence = Literal["evidence_backed", "assumption_high", "assumption_medium", "assumption_low"]
SizingBasis = Literal["top_down", "bottom_up", "analogue"]
CompetitorKind = Literal["direct", "adjacent", "substitute", "status_quo"]
ValidationMethod = Literal["customer_interview", "landing_page_smoke_test", "waitlist", "letter_of_intent", "pilot", "presale", "survey"]
Verdict = Literal["go", "pivot", "no_go", "insufficient_evidence"]
RoundType = Literal["bootstrapped", "pre_seed", "seed", "series_a", "revenue_based", "grant"]
ArtifactKind = Literal["pitch_deck", "one_pager", "financial_summary", "marketing_site_copy", "launch_campaign_brief", "investor_faq", "product_requirements_document"]
_CONFIDENCE_WEIGHT: dict[str, Decimal] = {"evidence_backed": Decimal("1"), "assumption_high": Decimal("0.7"), "assumption_medium": Decimal("0.4"), "assumption_low": Decimal("0.15")}


# --------------------------------------------------------------------------- #
# Strict model and helpers
# --------------------------------------------------------------------------- #


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential- or identity-like field and is never accepted")
            _reject_secret_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

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
        return {str(key): _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z") from exc
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp_or_none(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def _decimal(value: Any, *, field_name: str, allow_negative: bool = False, quantum: Decimal = _MONEY_QUANTUM) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or (parsed < 0 and not allow_negative) or abs(parsed) > Decimal("1000000000000000"):
        raise ValueError(f"{field_name} must be a finite {'bounded' if allow_negative else 'non-negative bounded'} decimal")
    return parsed.quantize(quantum)


def _rate(value: Any, *, field_name: str) -> Decimal:
    parsed = _decimal(value, field_name=field_name, quantum=_RATE_QUANTUM)
    if parsed > 1:
        raise ValueError(f"{field_name} must be a rate between 0 and 1")
    return parsed


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_saas_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_saas_digests": True})
    return _stable_digest({key: value for key, value in parsed.to_dict().items() if key != field})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _seal(model: type[_StrictModel], payload: Mapping[str, Any], field: str) -> Any:
    raw = dict(_detached(payload))
    raw[field] = _sealed_digest(model, raw, field)
    return model.model_validate(raw)


# --------------------------------------------------------------------------- #
# Market research dossier
# --------------------------------------------------------------------------- #


class Claim(_StrictModel):
    """A statement about the market: evidence-backed or a typed assumption."""

    claim_id: OpaqueRef
    text: ShortText
    confidence: Confidence
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @model_validator(mode="after")
    def _evidence_matches_confidence(self) -> "Claim":
        if self.confidence == "evidence_backed" and not self.evidence_refs:
            raise ValueError(f"claim {self.claim_id} is marked evidence-backed without evidence references")
        return self


class MarketSegment(_StrictModel):
    segment_ref: OpaqueRef
    name: ShortText
    description: BoundedText
    buyer_role: ShortText
    pain_points: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    current_alternatives: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    estimated_accounts: int = Field(ge=0, le=1_000_000_000)
    willingness_to_pay_monthly: Decimal | None = None
    claim_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("willingness_to_pay_monthly", mode="before")
    @classmethod
    def _wtp(cls, value: Any) -> Any:
        return None if value is None else _decimal(value, field_name="willingness_to_pay_monthly")


class Competitor(_StrictModel):
    competitor_ref: OpaqueRef
    name: ShortText
    kind: CompetitorKind
    positioning: ShortText
    pricing_note: ShortText | None = None
    strengths: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    gaps: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)


class MarketSizing(_StrictModel):
    currency: CurrencyCode
    tam_annual: Decimal
    sam_annual: Decimal
    som_annual: Decimal
    basis: SizingBasis
    assumptions: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    claim_ids: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("tam_annual", "sam_annual", "som_annual", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _nested(self) -> "MarketSizing":
        if not (self.som_annual <= self.sam_annual <= self.tam_annual):
            raise ValueError("market sizing must satisfy SOM <= SAM <= TAM")
        if self.tam_annual <= 0:
            raise ValueError("TAM must be positive")
        return self


class InterviewEvidence(_StrictModel):
    interview_ref: OpaqueRef
    segment_ref: OpaqueRef
    role: ShortText
    problem_confirmed: bool
    would_pay: bool
    quote_summary: ShortText | None = None
    evidence_ref: OpaqueRef


class RegulatoryConstraint(_StrictModel):
    constraint_ref: OpaqueRef
    description: ShortText
    applies_to_segments: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=10)


class MarketResearchDossier(_StrictModel):
    schema_id: Literal["lightbulb.saas_market_research_dossier.v1"] = Field(default=RESEARCH_DOSSIER_SCHEMA, alias="schema")
    dossier_ref: OpaqueRef
    product_ref: OpaqueRef
    problem_statement: BoundedText
    claims: tuple[Claim, ...] = Field(min_length=1, max_length=200)
    segments: tuple[MarketSegment, ...] = Field(min_length=1, max_length=20)
    competitors: tuple[Competitor, ...] = Field(min_length=1, max_length=50)
    sizing: MarketSizing
    interviews: tuple[InterviewEvidence, ...] = Field(default_factory=tuple, max_length=500)
    regulatory_constraints: tuple[RegulatoryConstraint, ...] = Field(default_factory=tuple, max_length=50)
    researched_at: str
    research_confidence_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    evidence_backed_claims: int = Field(default=0, ge=0)
    assumption_claims: int = Field(default=0, ge=0)
    dossier_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("researched_at")
    @classmethod
    def _researched(cls, value: str) -> str:
        return _timestamp(value, field_name="researched_at")

    @field_validator("research_confidence_percent", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="research_confidence_percent")

    @model_validator(mode="after")
    def _dossier_is_exact(self, info: ValidationInfo) -> "MarketResearchDossier":
        claim_ids = [item.claim_id for item in self.claims]
        _unique(claim_ids, label="claim ids")
        _unique([item.segment_ref for item in self.segments], label="segment refs")
        _unique([item.competitor_ref for item in self.competitors], label="competitor refs")
        known_claims, known_segments = set(claim_ids), {item.segment_ref for item in self.segments}
        for segment in self.segments:
            unknown = [claim for claim in segment.claim_ids if claim not in known_claims]
            if unknown:
                raise ValueError(f"segment {segment.segment_ref} cites unknown claims {unknown}")
        unknown_sizing = [claim for claim in self.sizing.claim_ids if claim not in known_claims]
        if unknown_sizing:
            raise ValueError(f"market sizing cites unknown claims {unknown_sizing}")
        for interview in self.interviews:
            if interview.segment_ref not in known_segments:
                raise ValueError(f"interview {interview.interview_ref} belongs to an unknown segment")
        for constraint in self.regulatory_constraints:
            unknown = [segment for segment in constraint.applies_to_segments if segment not in known_segments]
            if unknown:
                raise ValueError(f"constraint {constraint.constraint_ref} applies to unknown segments {unknown}")
        expected_confidence, backed, assumed = research_confidence(self.claims, self.interviews)
        if self.research_confidence_percent != expected_confidence or self.evidence_backed_claims != backed or self.assumption_claims != assumed:
            raise ValueError("research confidence and claim counts are derived from the claims and interviews")
        if _skip(info):
            return self
        if self.dossier_digest != _sealed_digest(MarketResearchDossier, self, "dossier_digest"):
            raise ValueError("dossier_digest must commit the exact dossier")
        return self

    def segment(self, segment_ref: str) -> MarketSegment | None:
        return next((item for item in self.segments if item.segment_ref == segment_ref), None)

    def competitor_gaps(self) -> tuple[str, ...]:
        return tuple(gap for item in self.competitors for gap in item.gaps)


def research_confidence(claims: Sequence[Claim], interviews: Sequence[InterviewEvidence]) -> tuple[Decimal, int, int]:
    """Derived confidence: claim-weighted evidence share, lifted by confirmed interviews (capped)."""

    backed = sum(1 for item in claims if item.confidence == "evidence_backed")
    assumed = len(claims) - backed
    weighted = sum((_CONFIDENCE_WEIGHT[item.confidence] for item in claims), Decimal("0")) / Decimal(max(len(claims), 1))
    confirmed = sum(1 for item in interviews if item.problem_confirmed)
    interview_lift = min(Decimal(confirmed) / Decimal(20), Decimal("0.2"))
    score = min(weighted * Decimal("0.8") + interview_lift, Decimal("1")) * Decimal(100)
    return score.quantize(_MONEY_QUANTUM), backed, assumed


def compile_market_research_dossier(dossier: Mapping[str, Any]) -> MarketResearchDossier:
    raw = dict(_detached(dossier))
    claims = [Claim.model_validate(item) for item in raw.get("claims", ())]
    interviews = [InterviewEvidence.model_validate(item) for item in raw.get("interviews", ())]
    confidence, backed, assumed = research_confidence(claims, interviews)
    raw.update({"research_confidence_percent": str(confidence), "evidence_backed_claims": backed, "assumption_claims": assumed})
    return _seal(MarketResearchDossier, raw, "dossier_digest")


# --------------------------------------------------------------------------- #
# Product thesis and pricing hypothesis
# --------------------------------------------------------------------------- #


class SuccessMetric(_StrictModel):
    metric_ref: OpaqueRef
    name: ShortText
    target: ShortText
    horizon_months: int = Field(ge=1, le=60)


class ProductRequirement(_StrictModel):
    """A must-have capability with acceptance criteria; feeds a software-production request."""

    requirement_ref: OpaqueRef
    title: ShortText
    user_story: BoundedText
    acceptance_criteria: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    priority: Literal["must", "should", "could"] = "must"
    segment_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    addresses_pain_points: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)


class ProductThesis(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_thesis.v1"] = Field(default=PRODUCT_THESIS_SCHEMA, alias="schema")
    thesis_ref: OpaqueRef
    dossier_digest: Sha256Digest
    product_ref: OpaqueRef
    product_name: ShortText
    target_segment_ref: OpaqueRef
    positioning: BoundedText
    value_proposition: BoundedText
    differentiators: tuple[ShortText, ...] = Field(min_length=1, max_length=10)
    competitor_gaps_addressed: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    requirements: tuple[ProductRequirement, ...] = Field(min_length=1, max_length=100)
    success_metrics: tuple[SuccessMetric, ...] = Field(min_length=1, max_length=20)
    defined_at: str
    thesis_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("defined_at")
    @classmethod
    def _defined(cls, value: str) -> str:
        return _timestamp(value, field_name="defined_at")

    @model_validator(mode="after")
    def _thesis_is_exact(self, info: ValidationInfo) -> "ProductThesis":
        _unique([item.requirement_ref for item in self.requirements], label="requirement refs")
        _unique([item.metric_ref for item in self.success_metrics], label="metric refs")
        if not any(item.priority == "must" for item in self.requirements):
            raise ValueError("a thesis needs at least one must-have requirement")
        if _skip(info):
            return self
        if self.thesis_digest != _sealed_digest(ProductThesis, self, "thesis_digest"):
            raise ValueError("thesis_digest must commit the exact thesis")
        return self


def derive_product_thesis(dossier: MarketResearchDossier | Mapping[str, Any], thesis: Mapping[str, Any]) -> ProductThesis:
    """Seal a thesis against its dossier: the segment exists, gaps addressed are real competitor gaps, pain points are the segment's."""

    parsed = MarketResearchDossier.model_validate(_detached(dossier))
    raw = dict(_detached(thesis))
    raw["dossier_digest"] = parsed.dossier_digest
    raw.setdefault("product_ref", parsed.product_ref)
    segment = parsed.segment(str(raw.get("target_segment_ref", "")))
    if segment is None:
        raise ValueError("the target segment must be one of the dossier's segments")
    gaps = set(parsed.competitor_gaps())
    unknown_gaps = [gap for gap in raw.get("competitor_gaps_addressed", ()) if gap not in gaps]
    if unknown_gaps:
        raise ValueError(f"competitor gaps addressed must come from the dossier's competitors: {unknown_gaps}")
    pain_points = set(segment.pain_points)
    for requirement in raw.get("requirements", ()):
        unknown_pain = [pain for pain in requirement.get("addresses_pain_points", ()) if pain not in pain_points]
        if unknown_pain:
            raise ValueError(f"requirement {requirement.get('requirement_ref')} addresses pain points the segment does not have: {unknown_pain}")
    return _seal(ProductThesis, raw, "thesis_digest")


class PricingPlan(_StrictModel):
    plan_ref: OpaqueRef
    name: ShortText
    monthly_price: Decimal
    billing_model: Literal["flat", "seat", "usage", "hybrid"]
    included_seats: int = Field(default=1, ge=1, le=100_000)
    target_segment_ref: OpaqueRef
    expected_mix_percent: Decimal

    @field_validator("monthly_price", "expected_mix_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class PricingHypothesis(_StrictModel):
    schema_id: Literal["lightbulb.saas_pricing_hypothesis.v1"] = Field(default=PRICING_HYPOTHESIS_SCHEMA, alias="schema")
    pricing_ref: OpaqueRef
    thesis_digest: Sha256Digest
    currency: CurrencyCode
    plans: tuple[PricingPlan, ...] = Field(min_length=1, max_length=10)
    trial_days: int = Field(default=14, ge=0, le=90)
    blended_arpa_monthly: Decimal = Field(default=Decimal("0"), validate_default=True)
    anchored_to_willingness_to_pay: bool = False
    subscription_profile_suggestion: Literal["saas_self_serve", "saas_sales_led"] = "saas_self_serve"
    pricing_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("blended_arpa_monthly", mode="before")
    @classmethod
    def _arpa(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="blended_arpa_monthly")

    @model_validator(mode="after")
    def _pricing_is_exact(self, info: ValidationInfo) -> "PricingHypothesis":
        _unique([item.plan_ref for item in self.plans], label="plan refs")
        mix = sum((item.expected_mix_percent for item in self.plans), Decimal("0"))
        if mix != Decimal("100"):
            raise ValueError(f"plan mix must sum to 100 percent, got {mix}")
        expected = sum((item.monthly_price * Decimal(item.included_seats) * item.expected_mix_percent / Decimal(100) for item in self.plans), Decimal("0")).quantize(_MONEY_QUANTUM)
        if self.blended_arpa_monthly != expected:
            raise ValueError("blended ARPA is derived from the plan mix")
        if _skip(info):
            return self
        if self.pricing_digest != _sealed_digest(PricingHypothesis, self, "pricing_digest"):
            raise ValueError("pricing_digest must commit the exact hypothesis")
        return self


def derive_pricing_hypothesis(dossier: MarketResearchDossier | Mapping[str, Any], thesis: ProductThesis | Mapping[str, Any], pricing: Mapping[str, Any]) -> PricingHypothesis:
    parsed_dossier = MarketResearchDossier.model_validate(_detached(dossier))
    parsed_thesis = ProductThesis.model_validate(_detached(thesis))
    if parsed_thesis.dossier_digest != parsed_dossier.dossier_digest:
        raise ValueError("the thesis belongs to a different dossier")
    raw = dict(_detached(pricing))
    raw["thesis_digest"] = parsed_thesis.thesis_digest
    plans = [PricingPlan.model_validate(item) for item in raw.get("plans", ())]
    for plan in plans:
        if parsed_dossier.segment(plan.target_segment_ref) is None:
            raise ValueError(f"plan {plan.plan_ref} targets a segment the dossier does not describe")
    raw["blended_arpa_monthly"] = str(sum((item.monthly_price * Decimal(item.included_seats) * item.expected_mix_percent / Decimal(100) for item in plans), Decimal("0")).quantize(_MONEY_QUANTUM))
    anchored = all(parsed_dossier.segment(plan.target_segment_ref).willingness_to_pay_monthly is not None and plan.monthly_price <= parsed_dossier.segment(plan.target_segment_ref).willingness_to_pay_monthly * Decimal("1.5") for plan in plans)  # type: ignore[union-attr]
    raw["anchored_to_willingness_to_pay"] = anchored
    raw["subscription_profile_suggestion"] = "saas_sales_led" if any(plan.monthly_price * Decimal(plan.included_seats) >= Decimal("1000") for plan in plans) else "saas_self_serve"
    return _seal(PricingHypothesis, raw, "pricing_digest")


# --------------------------------------------------------------------------- #
# Demand validation
# --------------------------------------------------------------------------- #


class ValidationThresholds(_StrictModel):
    min_interviews: int = Field(default=10, ge=0, le=1000)
    min_problem_confirmation_rate: Decimal = Field(default=Decimal("0.6"), validate_default=True)
    min_would_pay_rate: Decimal = Field(default=Decimal("0.3"), validate_default=True)
    min_landing_conversion_rate: Decimal = Field(default=Decimal("0.03"), validate_default=True)
    min_waitlist_signups: int = Field(default=50, ge=0, le=1_000_000)
    min_committed_value: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("min_problem_confirmation_rate", "min_would_pay_rate", "min_landing_conversion_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _rate(value, field_name=str(info.field_name))

    @field_validator("min_committed_value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="min_committed_value")


class ValidationEvidence(_StrictModel):
    evidence_ref: OpaqueRef
    method: ValidationMethod
    segment_ref: OpaqueRef
    observed_at: str
    participants: int = Field(default=0, ge=0)
    problem_confirmed: int = Field(default=0, ge=0)
    would_pay: int = Field(default=0, ge=0)
    visitors: int = Field(default=0, ge=0)
    signups: int = Field(default=0, ge=0)
    committed_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    currency: CurrencyCode = "USD"

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("committed_value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="committed_value")

    @model_validator(mode="after")
    def _counts(self) -> "ValidationEvidence":
        if self.problem_confirmed > self.participants or self.would_pay > self.participants or self.signups > self.visitors:
            raise ValueError("confirmations cannot exceed participants and signups cannot exceed visitors")
        return self


class DemandValidationVerdict(_StrictModel):
    schema_id: Literal["lightbulb.saas_demand_validation_verdict.v1"] = Field(default=VALIDATION_VERDICT_SCHEMA, alias="schema")
    thesis_digest: Sha256Digest
    verdict: Verdict
    interviews: int = Field(ge=0)
    problem_confirmation_rate: Decimal | None = None
    would_pay_rate: Decimal | None = None
    landing_conversion_rate: Decimal | None = None
    waitlist_signups: int = Field(ge=0)
    committed_value: Decimal
    checks: dict[str, bool] = Field(default_factory=dict)
    reasons: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    evidence_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=200)
    evaluated_at: str
    verdict_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("problem_confirmation_rate", "would_pay_rate", "landing_conversion_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _rate(value, field_name=str(info.field_name))

    @field_validator("committed_value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="committed_value")

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def _verdict_is_exact(self, info: ValidationInfo) -> "DemandValidationVerdict":
        if _skip(info):
            return self
        if self.verdict_digest != _sealed_digest(DemandValidationVerdict, self, "verdict_digest"):
            raise ValueError("verdict_digest must commit the exact verdict")
        return self


def evaluate_demand_validation(thesis: ProductThesis | Mapping[str, Any], evidence: Sequence[ValidationEvidence | Mapping[str, Any]], thresholds: ValidationThresholds | Mapping[str, Any] | None = None, *, evaluated_at: str) -> DemandValidationVerdict:
    """Threshold-driven go / pivot / no-go from validation evidence for the thesis's target segment."""

    parsed_thesis = ProductThesis.model_validate(_detached(thesis))
    parsed = [ValidationEvidence.model_validate(_detached(item)) for item in evidence]
    limits = ValidationThresholds.model_validate(_detached(thresholds) if thresholds is not None else {})
    on_segment = [item for item in parsed if item.segment_ref == parsed_thesis.target_segment_ref]
    off_segment = len(parsed) - len(on_segment)
    interviews = sum(item.participants for item in on_segment if item.method in {"customer_interview", "survey"})
    confirmed = sum(item.problem_confirmed for item in on_segment if item.method in {"customer_interview", "survey"})
    would_pay = sum(item.would_pay for item in on_segment if item.method in {"customer_interview", "survey"})
    visitors = sum(item.visitors for item in on_segment if item.method in {"landing_page_smoke_test", "waitlist"})
    signups = sum(item.signups for item in on_segment if item.method in {"landing_page_smoke_test", "waitlist"})
    committed = sum((item.committed_value for item in on_segment if item.method in {"letter_of_intent", "pilot", "presale"}), Decimal("0")).quantize(_MONEY_QUANTUM)
    confirmation_rate = (Decimal(confirmed) / Decimal(interviews)).quantize(_RATE_QUANTUM) if interviews else None
    pay_rate = (Decimal(would_pay) / Decimal(interviews)).quantize(_RATE_QUANTUM) if interviews else None
    conversion = (Decimal(signups) / Decimal(visitors)).quantize(_RATE_QUANTUM) if visitors else None
    checks = {
        "enough_interviews": interviews >= limits.min_interviews,
        "problem_confirmed": confirmation_rate is not None and confirmation_rate >= limits.min_problem_confirmation_rate,
        "willingness_to_pay": pay_rate is not None and pay_rate >= limits.min_would_pay_rate,
        "landing_conversion": (conversion is not None and conversion >= limits.min_landing_conversion_rate) if visitors else limits.min_landing_conversion_rate == 0,
        "waitlist": signups >= limits.min_waitlist_signups,
        "committed_value": committed >= limits.min_committed_value,
    }
    reasons: list[str] = []
    if off_segment:
        reasons.append(f"{off_segment} evidence item(s) ignored: not the target segment")
    if not on_segment or (interviews == 0 and visitors == 0 and committed == 0):
        verdict = "insufficient_evidence"
        reasons.append("no evidence on the target segment")
    elif all(checks.values()):
        verdict = "go"
    elif checks["problem_confirmed"] and not checks["willingness_to_pay"]:
        verdict = "pivot"
        reasons.append("the problem is real but buyers will not pay at the tested price; revisit pricing or segment")
    elif not checks["enough_interviews"]:
        verdict = "insufficient_evidence"
        reasons.append(f"{interviews} interview(s) below the {limits.min_interviews} minimum")
    elif not checks["problem_confirmed"]:
        verdict = "no_go"
        reasons.append("buyers did not confirm the problem")
    else:
        verdict = "pivot"
        reasons.extend(f"{name} below threshold" for name, passed in checks.items() if not passed)
    payload = {"thesis_digest": parsed_thesis.thesis_digest, "verdict": verdict, "interviews": interviews, "problem_confirmation_rate": None if confirmation_rate is None else str(confirmation_rate), "would_pay_rate": None if pay_rate is None else str(pay_rate), "landing_conversion_rate": None if conversion is None else str(conversion), "waitlist_signups": signups, "committed_value": str(committed), "checks": checks, "reasons": reasons, "evidence_digests": [_stable_digest(item.to_dict()) for item in parsed], "evaluated_at": evaluated_at}
    return _seal(DemandValidationVerdict, payload, "verdict_digest")


# --------------------------------------------------------------------------- #
# Business model, projection, funding ask
# --------------------------------------------------------------------------- #


class ModelAssumptions(_StrictModel):
    """Declared assumptions; every derived figure traces to these and the pricing hypothesis."""

    currency: CurrencyCode
    gross_margin_rate: Decimal
    monthly_churn_rate: Decimal
    customer_acquisition_cost: Decimal
    new_accounts_month_one: int = Field(ge=0, le=1_000_000)
    monthly_new_account_growth_rate: Decimal
    fixed_monthly_costs: Decimal
    variable_cost_per_account_monthly: Decimal
    starting_cash: Decimal
    months: int = Field(default=36, ge=1, le=MAX_PROJECTION_MONTHS)
    claim_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("gross_margin_rate", "monthly_churn_rate", "monthly_new_account_growth_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name), quantum=_RATE_QUANTUM)
        if info.field_name != "monthly_new_account_growth_rate" and parsed > 1:
            raise ValueError(f"{info.field_name} must be a rate between 0 and 1")
        if parsed > 5:
            raise ValueError(f"{info.field_name} is implausible")
        return parsed

    @field_validator("customer_acquisition_cost", "fixed_monthly_costs", "variable_cost_per_account_monthly", "starting_cash", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class UnitEconomics(_StrictModel):
    arpa_monthly: Decimal
    gross_margin_rate: Decimal
    monthly_churn_rate: Decimal
    customer_acquisition_cost: Decimal
    contribution_per_account_monthly: Decimal
    payback_months: Decimal | None = None
    lifetime_months: Decimal | None = None
    lifetime_value: Decimal | None = None
    ltv_to_cac: Decimal | None = None

    @field_validator("arpa_monthly", "customer_acquisition_cost", "contribution_per_account_monthly", "payback_months", "lifetime_months", "lifetime_value", "ltv_to_cac", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("gross_margin_rate", "monthly_churn_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _rate(value, field_name=str(info.field_name))


class ProjectionMonth(_StrictModel):
    month: int = Field(ge=1, le=MAX_PROJECTION_MONTHS)
    new_accounts: int = Field(ge=0)
    churned_accounts: int = Field(ge=0)
    active_accounts: int = Field(ge=0)
    mrr: Decimal
    revenue: Decimal
    cost_of_revenue: Decimal
    acquisition_cost: Decimal
    fixed_costs: Decimal
    net_cash_flow: Decimal
    cash_balance: Decimal

    @field_validator("mrr", "revenue", "cost_of_revenue", "acquisition_cost", "fixed_costs", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("net_cash_flow", "cash_balance", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name), allow_negative=True)


class FinancialProjection(_StrictModel):
    schema_id: Literal["lightbulb.saas_financial_projection.v1"] = Field(default=PROJECTION_SCHEMA, alias="schema")
    projection_ref: OpaqueRef
    business_model_digest: Sha256Digest
    currency: CurrencyCode
    months: tuple[ProjectionMonth, ...] = Field(min_length=1, max_length=MAX_PROJECTION_MONTHS)
    ending_mrr: Decimal
    ending_arr: Decimal
    ending_active_accounts: int = Field(ge=0)
    total_revenue: Decimal
    cash_low_point: Decimal
    cash_low_month: int = Field(ge=1)
    runway_months_from_start: int | None = Field(default=None, ge=0)
    breakeven_month: int | None = Field(default=None, ge=1)
    projection_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("ending_mrr", "ending_arr", "total_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("cash_low_point", mode="before")
    @classmethod
    def _signed(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="cash_low_point", allow_negative=True)

    @model_validator(mode="after")
    def _projection_is_exact(self, info: ValidationInfo) -> "FinancialProjection":
        if [item.month for item in self.months] != list(range(1, len(self.months) + 1)):
            raise ValueError("projection months must be contiguous from 1")
        if _skip(info):
            return self
        if self.projection_digest != _sealed_digest(FinancialProjection, self, "projection_digest"):
            raise ValueError("projection_digest must commit the exact projection")
        return self


class BusinessModel(_StrictModel):
    schema_id: Literal["lightbulb.saas_business_model.v1"] = Field(default=BUSINESS_MODEL_SCHEMA, alias="schema")
    model_ref: OpaqueRef
    thesis_digest: Sha256Digest
    pricing_digest: Sha256Digest
    assumptions: ModelAssumptions
    unit_economics: UnitEconomics
    health_findings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    model_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _model_is_exact(self, info: ValidationInfo) -> "BusinessModel":
        if _skip(info):
            return self
        if self.model_digest != _sealed_digest(BusinessModel, self, "model_digest"):
            raise ValueError("model_digest must commit the exact model")
        return self


def build_business_model(pricing: PricingHypothesis | Mapping[str, Any], assumptions: ModelAssumptions | Mapping[str, Any], *, model_ref: str) -> BusinessModel:
    parsed_pricing = PricingHypothesis.model_validate(_detached(pricing))
    parsed = ModelAssumptions.model_validate(_detached(assumptions))
    if parsed.currency != parsed_pricing.currency:
        raise ValueError("model assumptions and pricing must share a currency")
    arpa = parsed_pricing.blended_arpa_monthly
    contribution = (arpa * parsed.gross_margin_rate - parsed.variable_cost_per_account_monthly).quantize(_MONEY_QUANTUM)
    payback = (parsed.customer_acquisition_cost / contribution).quantize(_MONEY_QUANTUM) if contribution > 0 else None
    lifetime = (Decimal(1) / parsed.monthly_churn_rate).quantize(_MONEY_QUANTUM) if parsed.monthly_churn_rate > 0 else None
    ltv = (contribution * lifetime).quantize(_MONEY_QUANTUM) if lifetime is not None else None
    ltv_to_cac = (ltv / parsed.customer_acquisition_cost).quantize(_MONEY_QUANTUM) if ltv is not None and parsed.customer_acquisition_cost > 0 else None
    findings: list[str] = []
    if contribution <= 0:
        findings.append("each account loses money before acquisition cost; pricing or variable cost must change")
    if payback is not None and payback > 18:
        findings.append(f"CAC payback of {payback} months exceeds 18")
    if ltv_to_cac is not None and ltv_to_cac < 3:
        findings.append(f"LTV to CAC of {ltv_to_cac} is below 3")
    if lifetime is None:
        findings.append("zero churn assumed; lifetime value is unbounded and not credible")
    economics = {"arpa_monthly": str(arpa), "gross_margin_rate": str(parsed.gross_margin_rate), "monthly_churn_rate": str(parsed.monthly_churn_rate), "customer_acquisition_cost": str(parsed.customer_acquisition_cost), "contribution_per_account_monthly": str(contribution), "payback_months": None if payback is None else str(payback), "lifetime_months": None if lifetime is None else str(lifetime), "lifetime_value": None if ltv is None else str(ltv), "ltv_to_cac": None if ltv_to_cac is None else str(ltv_to_cac)}
    return _seal(BusinessModel, {"model_ref": model_ref, "thesis_digest": parsed_pricing.thesis_digest, "pricing_digest": parsed_pricing.pricing_digest, "assumptions": parsed.to_dict(), "unit_economics": economics, "health_findings": findings}, "model_digest")


def project_financials(model: BusinessModel | Mapping[str, Any], *, projection_ref: str, cash_injection: Any = "0", injection_month: int = 1) -> FinancialProjection:
    """Deterministic monthly projection from the model's assumptions; optional cash injection models a raise."""

    parsed = BusinessModel.model_validate(_detached(model))
    a, arpa = parsed.assumptions, parsed.unit_economics.arpa_monthly
    injection = _decimal(cash_injection, field_name="cash_injection")
    if injection_month < 1 or injection_month > a.months:
        raise ValueError("injection_month must fall inside the projection")
    months: list[dict[str, Any]] = []
    active, cash, new_rate = 0, a.starting_cash, Decimal(a.new_accounts_month_one)
    total_revenue = Decimal("0")
    low_point, low_month, runway, breakeven = a.starting_cash, 1, None, None
    for month in range(1, a.months + 1):
        new_accounts = int(new_rate.to_integral_value(rounding="ROUND_HALF_UP")) if month > 1 else a.new_accounts_month_one
        churned = int((Decimal(active) * a.monthly_churn_rate).to_integral_value(rounding="ROUND_HALF_UP"))
        active = max(active + new_accounts - churned, 0)
        mrr = (arpa * Decimal(active)).quantize(_MONEY_QUANTUM)
        cost_of_revenue = (mrr * (Decimal(1) - a.gross_margin_rate) + a.variable_cost_per_account_monthly * Decimal(active)).quantize(_MONEY_QUANTUM)
        acquisition = (a.customer_acquisition_cost * Decimal(new_accounts)).quantize(_MONEY_QUANTUM)
        net = (mrr - cost_of_revenue - acquisition - a.fixed_monthly_costs).quantize(_MONEY_QUANTUM)
        if month == injection_month:
            cash += injection
        cash = (cash + net).quantize(_MONEY_QUANTUM)
        total_revenue += mrr
        if cash < low_point:
            low_point, low_month = cash, month
        if runway is None and cash < 0:
            runway = month - 1
        if breakeven is None and net >= 0 and mrr > 0:
            breakeven = month
        months.append({"month": month, "new_accounts": new_accounts, "churned_accounts": churned, "active_accounts": active, "mrr": str(mrr), "revenue": str(mrr), "cost_of_revenue": str(cost_of_revenue), "acquisition_cost": str(acquisition), "fixed_costs": str(a.fixed_monthly_costs), "net_cash_flow": str(net), "cash_balance": str(cash)})
        new_rate = new_rate * (Decimal(1) + a.monthly_new_account_growth_rate)
    last = months[-1]
    payload = {"projection_ref": projection_ref, "business_model_digest": parsed.model_digest, "currency": a.currency, "months": months, "ending_mrr": last["mrr"], "ending_arr": str((Decimal(last["mrr"]) * 12).quantize(_MONEY_QUANTUM)), "ending_active_accounts": last["active_accounts"], "total_revenue": str(total_revenue.quantize(_MONEY_QUANTUM)), "cash_low_point": str(low_point), "cash_low_month": low_month, "runway_months_from_start": runway if runway is not None else a.months, "breakeven_month": breakeven}
    return _seal(FinancialProjection, payload, "projection_digest")


class UseOfFunds(_StrictModel):
    category: Literal["product_engineering", "sales_marketing", "operations", "working_capital", "compliance", "other"]
    amount: Decimal
    rationale: ShortText

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="amount")


class FundingMilestone(_StrictModel):
    milestone_ref: OpaqueRef
    description: ShortText
    target_month: int = Field(ge=1, le=MAX_PROJECTION_MONTHS)
    metric_ref: OpaqueRef | None = None


class FundingAsk(_StrictModel):
    schema_id: Literal["lightbulb.saas_funding_ask.v1"] = Field(default=FUNDING_ASK_SCHEMA, alias="schema")
    ask_ref: OpaqueRef
    business_model_digest: Sha256Digest
    projection_digest: Sha256Digest
    round_type: RoundType
    currency: CurrencyCode
    amount: Decimal
    use_of_funds: tuple[UseOfFunds, ...] = Field(default_factory=tuple, max_length=10)
    milestones: tuple[FundingMilestone, ...] = Field(default_factory=tuple, max_length=20)
    runway_months_without_raise: int = Field(ge=0)
    runway_months_with_raise: int = Field(ge=0)
    findings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    ask_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="amount")

    @model_validator(mode="after")
    def _ask_is_exact(self, info: ValidationInfo) -> "FundingAsk":
        if self.round_type != "bootstrapped":
            if self.amount <= 0:
                raise ValueError("a funding round needs a positive ask")
            total = sum((item.amount for item in self.use_of_funds), Decimal("0"))
            if total != self.amount:
                raise ValueError(f"use of funds ({total}) must equal the ask ({self.amount})")
        elif self.amount != 0 or self.use_of_funds:
            raise ValueError("a bootstrapped plan has no ask")
        _unique([item.milestone_ref for item in self.milestones], label="milestone refs")
        if _skip(info):
            return self
        if self.ask_digest != _sealed_digest(FundingAsk, self, "ask_digest"):
            raise ValueError("ask_digest must commit the exact ask")
        return self


def compose_funding_ask(model: BusinessModel | Mapping[str, Any], projection: FinancialProjection | Mapping[str, Any], ask: Mapping[str, Any]) -> FundingAsk:
    """Bind an ask to the model and projection; derive runway with and without the raise and flag a short runway."""

    parsed_model = BusinessModel.model_validate(_detached(model))
    parsed_projection = FinancialProjection.model_validate(_detached(projection))
    if parsed_projection.business_model_digest != parsed_model.model_digest:
        raise ValueError("the projection belongs to a different business model")
    raw = dict(_detached(ask))
    raw.update({"business_model_digest": parsed_model.model_digest, "projection_digest": parsed_projection.projection_digest, "currency": parsed_model.assumptions.currency})
    amount = _decimal(raw.get("amount", "0"), field_name="amount")
    without = parsed_projection.runway_months_from_start if parsed_projection.runway_months_from_start is not None else parsed_model.assumptions.months
    with_raise = project_financials(parsed_model, projection_ref=f"{raw.get('ask_ref', 'ask')}:with-raise", cash_injection=amount).runway_months_from_start if amount > 0 else without
    findings: list[str] = []
    if raw.get("round_type", "bootstrapped") != "bootstrapped" and (with_raise or 0) < 18 and (with_raise or 0) < parsed_model.assumptions.months:
        findings.append(f"runway after the raise is {with_raise} months; investors expect 18 or more")
    if parsed_model.health_findings:
        findings.append("unit economics carry open findings; address them before pitching")
    for milestone in raw.get("milestones", ()):
        if int(milestone.get("target_month", 0)) > parsed_model.assumptions.months:
            raise ValueError(f"milestone {milestone.get('milestone_ref')} falls outside the projection")
    raw.update({"runway_months_without_raise": int(without or 0), "runway_months_with_raise": int(with_raise or 0), "findings": findings})
    return _seal(FundingAsk, raw, "ask_digest")


# --------------------------------------------------------------------------- #
# Artifact plan and grounding
# --------------------------------------------------------------------------- #


class GroundingFact(_StrictModel):
    fact_id: OpaqueRef
    label: ShortText
    value: ShortText
    source: Literal["dossier", "thesis", "pricing", "validation", "business_model", "projection", "funding_ask"]
    source_digest: Sha256Digest


class ArtifactRequirement(_StrictModel):
    kind: ArtifactKind
    required_sections: tuple[ShortText, ...] = Field(min_length=1, max_length=30)
    grounding_fact_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    audience: ShortText
    format: Literal["pptx", "pdf", "docx", "markdown"]
    approval_kinds: tuple[Literal["brand", "commercial", "legal", "finance", "executive"], ...] = Field(default_factory=tuple, max_length=5)


class ProductArtifactPlan(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_artifact_plan.v1"] = Field(default=ARTIFACT_PLAN_SCHEMA, alias="schema")
    plan_ref: OpaqueRef
    product_ref: OpaqueRef
    facts: tuple[GroundingFact, ...] = Field(min_length=1, max_length=200)
    artifacts: tuple[ArtifactRequirement, ...] = Field(min_length=1, max_length=10)
    generation_primitive_refs: tuple[ShortText, ...] = Field(default=("documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "documents.generate_business_artifact"))
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "ProductArtifactPlan":
        _unique([item.fact_id for item in self.facts], label="fact ids")
        _unique([item.kind for item in self.artifacts], label="artifact kinds")
        known = {item.fact_id for item in self.facts}
        for artifact in self.artifacts:
            unknown = [fact for fact in artifact.grounding_fact_ids if fact not in known]
            if unknown:
                raise ValueError(f"{artifact.kind} cites unknown grounding facts {unknown}")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(ProductArtifactPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def fact(self, fact_id: str) -> GroundingFact | None:
        return next((item for item in self.facts if item.fact_id == fact_id), None)


def _money_text(value: Decimal) -> str:
    return f"{value.quantize(_MONEY_QUANTUM):,.2f}"


def plan_product_artifacts(dossier: MarketResearchDossier | Mapping[str, Any], thesis: ProductThesis | Mapping[str, Any], pricing: PricingHypothesis | Mapping[str, Any], verdict: DemandValidationVerdict | Mapping[str, Any] | None, model: BusinessModel | Mapping[str, Any], projection: FinancialProjection | Mapping[str, Any], ask: FundingAsk | Mapping[str, Any] | None, *, plan_ref: str) -> ProductArtifactPlan:
    """Assemble grounding facts from every sealed object and the artifact set a SaaS product needs."""

    d = MarketResearchDossier.model_validate(_detached(dossier))
    t = ProductThesis.model_validate(_detached(thesis))
    p = PricingHypothesis.model_validate(_detached(pricing))
    m = BusinessModel.model_validate(_detached(model))
    f = FinancialProjection.model_validate(_detached(projection))
    v = DemandValidationVerdict.model_validate(_detached(verdict)) if verdict is not None else None
    a = FundingAsk.model_validate(_detached(ask)) if ask is not None else None
    if t.dossier_digest != d.dossier_digest or p.thesis_digest != t.thesis_digest or m.pricing_digest != p.pricing_digest or f.business_model_digest != m.model_digest:
        raise ValueError("dossier, thesis, pricing, model, and projection must form one chain")
    if v is not None and v.thesis_digest != t.thesis_digest:
        raise ValueError("the validation verdict belongs to a different thesis")
    if a is not None and a.projection_digest != f.projection_digest:
        raise ValueError("the funding ask belongs to a different projection")
    segment = d.segment(t.target_segment_ref)
    facts: list[dict[str, Any]] = [
        {"fact_id": "tam_annual", "label": "Total addressable market (annual)", "value": _money_text(d.sizing.tam_annual), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "sam_annual", "label": "Serviceable addressable market (annual)", "value": _money_text(d.sizing.sam_annual), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "som_annual", "label": "Serviceable obtainable market (annual)", "value": _money_text(d.sizing.som_annual), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "research_confidence", "label": "Research confidence percent", "value": str(d.research_confidence_percent), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "target_segment_accounts", "label": "Target segment accounts", "value": str(segment.estimated_accounts if segment else 0), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "competitor_count", "label": "Competitors analysed", "value": str(len(d.competitors)), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "interview_count", "label": "Customer interviews", "value": str(len(d.interviews)), "source": "dossier", "source_digest": d.dossier_digest},
        {"fact_id": "blended_arpa", "label": "Blended monthly ARPA", "value": _money_text(p.blended_arpa_monthly), "source": "pricing", "source_digest": p.pricing_digest},
        {"fact_id": "gross_margin_rate", "label": "Gross margin rate", "value": str(m.unit_economics.gross_margin_rate), "source": "business_model", "source_digest": m.model_digest},
        {"fact_id": "monthly_churn_rate", "label": "Monthly churn rate", "value": str(m.unit_economics.monthly_churn_rate), "source": "business_model", "source_digest": m.model_digest},
        {"fact_id": "cac", "label": "Customer acquisition cost", "value": _money_text(m.unit_economics.customer_acquisition_cost), "source": "business_model", "source_digest": m.model_digest},
        {"fact_id": "ending_arr", "label": f"ARR at month {len(f.months)}", "value": _money_text(f.ending_arr), "source": "projection", "source_digest": f.projection_digest},
        {"fact_id": "ending_accounts", "label": f"Active accounts at month {len(f.months)}", "value": str(f.ending_active_accounts), "source": "projection", "source_digest": f.projection_digest},
        {"fact_id": "projection_months", "label": "Projection horizon (months)", "value": str(len(f.months)), "source": "projection", "source_digest": f.projection_digest},
    ]
    for key, label in (("payback_months", "CAC payback (months)"), ("lifetime_value", "Lifetime value"), ("ltv_to_cac", "LTV to CAC")):
        value = getattr(m.unit_economics, key)
        if value is not None:
            facts.append({"fact_id": key, "label": label, "value": _money_text(value) if key == "lifetime_value" else str(value), "source": "business_model", "source_digest": m.model_digest})
    if f.breakeven_month is not None:
        facts.append({"fact_id": "breakeven_month", "label": "Breakeven month", "value": str(f.breakeven_month), "source": "projection", "source_digest": f.projection_digest})
    if v is not None:
        facts.append({"fact_id": "validation_verdict", "label": "Demand validation verdict", "value": v.verdict, "source": "validation", "source_digest": v.verdict_digest})
        facts.append({"fact_id": "waitlist_signups", "label": "Waitlist signups", "value": str(v.waitlist_signups), "source": "validation", "source_digest": v.verdict_digest})
        if v.problem_confirmation_rate is not None:
            facts.append({"fact_id": "problem_confirmation_rate", "label": "Problem confirmation rate", "value": str(v.problem_confirmation_rate), "source": "validation", "source_digest": v.verdict_digest})
    if a is not None:
        facts.append({"fact_id": "funding_ask", "label": f"{a.round_type} ask", "value": _money_text(a.amount), "source": "funding_ask", "source_digest": a.ask_digest})
        facts.append({"fact_id": "runway_with_raise", "label": "Runway after raise (months)", "value": str(a.runway_months_with_raise), "source": "funding_ask", "source_digest": a.ask_digest})
    fact_ids = [item["fact_id"] for item in facts]
    market_facts = [fid for fid in ("tam_annual", "sam_annual", "som_annual", "target_segment_accounts", "research_confidence", "competitor_count", "interview_count", "problem_confirmation_rate", "waitlist_signups") if fid in fact_ids]
    economics_facts = [fid for fid in ("blended_arpa", "gross_margin_rate", "monthly_churn_rate", "cac", "payback_months", "ltv_to_cac", "ending_arr", "ending_accounts", "breakeven_month") if fid in fact_ids]
    artifacts: list[dict[str, Any]] = [
        {"kind": "pitch_deck", "required_sections": ["problem", "solution", "market", "product", "business_model", "traction", "competition", "go_to_market", "financials", "team", "ask"], "grounding_fact_ids": market_facts + economics_facts + ([fid for fid in ("funding_ask", "runway_with_raise") if fid in fact_ids]), "audience": "investors", "format": "pptx", "approval_kinds": ["executive", "finance"]},
        {"kind": "one_pager", "required_sections": ["problem", "solution", "market", "traction", "ask"], "grounding_fact_ids": [fid for fid in ("tam_annual", "som_annual", "blended_arpa", "ending_arr", "funding_ask") if fid in fact_ids], "audience": "investors", "format": "pdf", "approval_kinds": ["executive"]},
        {"kind": "financial_summary", "required_sections": ["assumptions", "unit_economics", "projection", "use_of_funds"], "grounding_fact_ids": economics_facts + ["projection_months"] + ([fid for fid in ("funding_ask", "runway_with_raise") if fid in fact_ids]), "audience": "investors", "format": "pdf", "approval_kinds": ["finance"]},
        {"kind": "marketing_site_copy", "required_sections": ["hero", "problem", "how_it_works", "benefits", "pricing", "call_to_action"], "grounding_fact_ids": ["blended_arpa"], "audience": t.target_segment_ref, "format": "markdown", "approval_kinds": ["brand", "legal"]},
        {"kind": "launch_campaign_brief", "required_sections": ["objective", "audience", "channels", "message", "offer", "timeline", "success_metrics"], "grounding_fact_ids": ["target_segment_accounts", "blended_arpa"], "audience": "marketing", "format": "docx", "approval_kinds": ["brand", "commercial"]},
        {"kind": "investor_faq", "required_sections": ["why_now", "why_us", "risks", "competition", "unit_economics", "use_of_funds"], "grounding_fact_ids": economics_facts + market_facts, "audience": "investors", "format": "docx", "approval_kinds": ["executive", "legal"]},
        {"kind": "product_requirements_document", "required_sections": ["overview", "target_users", "requirements", "acceptance_criteria", "non_goals", "success_metrics"], "grounding_fact_ids": ["target_segment_accounts", "interview_count"], "audience": "engineering", "format": "markdown", "approval_kinds": []},
    ]
    return _seal(ProductArtifactPlan, {"plan_ref": plan_ref, "product_ref": d.product_ref, "facts": facts, "artifacts": artifacts}, "plan_digest")


_NUMBER_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?:\$|€|£)?\d[\d,]*(?:\.\d+)?%?(?:\s?[kKmMbB](?![A-Za-z]))?")


def _normalize_number(token: str) -> Decimal | None:
    text = token.strip().lstrip("$€£").rstrip("%").replace(",", "").strip()
    multiplier = Decimal(1)
    if text and text[-1] in "kKmMbB":
        multiplier = {"k": Decimal(1000), "m": Decimal(1_000_000), "b": Decimal(1_000_000_000)}[text[-1].lower()]
        text = text[:-1].strip()
    try:
        return (Decimal(text) * multiplier).quantize(_MONEY_QUANTUM)
    except (InvalidOperation, ValueError):
        return None


class GroundingFinding(_StrictModel):
    section: ShortText
    number: ShortText
    code: Literal["UNGROUNDED_NUMBER", "MISSING_SECTION", "FACT_NOT_CITED"]
    message: ShortText


class ArtifactGroundingReport(_StrictModel):
    schema_id: Literal["lightbulb.saas_artifact_grounding_report.v1"] = Field(default=GROUNDING_REPORT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    kind: ArtifactKind
    status: Literal["grounded", "review_required", "blocked"]
    numbers_checked: int = Field(ge=0)
    grounded_numbers: int = Field(ge=0)
    findings: tuple[GroundingFinding, ...] = Field(default_factory=tuple, max_length=200)
    content_digest: Sha256Digest
    report_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _report_is_exact(self, info: ValidationInfo) -> "ArtifactGroundingReport":
        if _skip(info):
            return self
        if self.report_digest != _sealed_digest(ArtifactGroundingReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self


def verify_artifact_grounding(plan: ProductArtifactPlan | Mapping[str, Any], kind: str, sections: Mapping[str, str], *, allowed_unlabelled: Sequence[str] = ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "12", "24", "36", "100")) -> ArtifactGroundingReport:
    """Every number in the generated sections must match a grounding fact (or be a trivial ordinal); every required section must exist."""

    parsed = ProductArtifactPlan.model_validate(_detached(plan))
    requirement = next((item for item in parsed.artifacts if item.kind == kind), None)
    if requirement is None:
        raise ValueError(f"the plan has no {kind} artifact")
    allowed_values: set[Decimal] = set()
    for fact_id in requirement.grounding_fact_ids:
        fact = parsed.fact(fact_id)
        if fact is not None:
            value = _normalize_number(fact.value)
            if value is not None:
                allowed_values.add(value)
                allowed_values.add((value / Decimal(1000)).quantize(_MONEY_QUANTUM))
                allowed_values.add((value / Decimal(1_000_000)).quantize(_MONEY_QUANTUM))
                if value <= 1:
                    allowed_values.add((value * Decimal(100)).quantize(_MONEY_QUANTUM))
    trivial = {Decimal(item).quantize(_MONEY_QUANTUM) for item in allowed_unlabelled}
    findings: list[dict[str, str]] = []
    checked = grounded = 0
    normalized_sections = {str(key): str(value) for key, value in sections.items()}
    for section in requirement.required_sections:
        if section not in normalized_sections or not normalized_sections[section].strip():
            findings.append({"section": section, "number": "-", "code": "MISSING_SECTION", "message": f"required section {section} is missing"})
    cited_fact_ids: set[str] = set()
    for section, text in normalized_sections.items():
        for match in _NUMBER_RE.finditer(text):
            token = match.group(0)
            value = _normalize_number(token)
            if value is None:
                continue
            checked += 1
            if value in allowed_values:
                grounded += 1
                cited_fact_ids.update(fact_id for fact_id in requirement.grounding_fact_ids if (fact := parsed.fact(fact_id)) is not None and _normalize_number(fact.value) in {value, (value * Decimal(1000)).quantize(_MONEY_QUANTUM), (value * Decimal(1_000_000)).quantize(_MONEY_QUANTUM), (value / Decimal(100)).quantize(_MONEY_QUANTUM)})
            elif value in trivial:
                grounded += 1
            else:
                findings.append({"section": section, "number": token.strip()[:300], "code": "UNGROUNDED_NUMBER", "message": f"{token.strip()} in {section} matches no grounding fact"})
    for fact_id in requirement.grounding_fact_ids:
        fact = parsed.fact(fact_id)
        if fact is not None and fact.source in {"dossier", "projection", "funding_ask"} and fact_id in {"tam_annual", "ending_arr", "funding_ask"} and fact_id not in cited_fact_ids:
            findings.append({"section": "-", "number": fact.value, "code": "FACT_NOT_CITED", "message": f"{fact.label} is a required fact for {kind} and is not cited"})
    ungrounded = sum(1 for item in findings if item["code"] == "UNGROUNDED_NUMBER")
    missing = sum(1 for item in findings if item["code"] == "MISSING_SECTION")
    status = "blocked" if ungrounded or missing else ("review_required" if findings else "grounded")
    payload = {"plan_digest": parsed.plan_digest, "kind": kind, "status": status, "numbers_checked": checked, "grounded_numbers": grounded, "findings": findings, "content_digest": _stable_digest(normalized_sections)}
    return _seal(ArtifactGroundingReport, payload, "report_digest")


__all__ = [
    "ARTIFACT_PLAN_SCHEMA",
    "BUSINESS_MODEL_SCHEMA",
    "FUNDING_ASK_SCHEMA",
    "GROUNDING_REPORT_SCHEMA",
    "MAX_PROJECTION_MONTHS",
    "PRICING_HYPOTHESIS_SCHEMA",
    "PRODUCT_THESIS_SCHEMA",
    "PROJECTION_SCHEMA",
    "RESEARCH_DOSSIER_SCHEMA",
    "VALIDATION_VERDICT_SCHEMA",
    "ArtifactGroundingReport",
    "ArtifactRequirement",
    "BusinessModel",
    "Claim",
    "Competitor",
    "DemandValidationVerdict",
    "FinancialProjection",
    "FundingAsk",
    "FundingMilestone",
    "GroundingFact",
    "GroundingFinding",
    "InterviewEvidence",
    "MarketResearchDossier",
    "MarketSegment",
    "MarketSizing",
    "ModelAssumptions",
    "PricingHypothesis",
    "PricingPlan",
    "ProductArtifactPlan",
    "ProductRequirement",
    "ProductThesis",
    "ProjectionMonth",
    "RegulatoryConstraint",
    "SuccessMetric",
    "UnitEconomics",
    "UseOfFunds",
    "ValidationEvidence",
    "ValidationThresholds",
    "build_business_model",
    "compile_market_research_dossier",
    "compose_funding_ask",
    "derive_pricing_hypothesis",
    "derive_product_thesis",
    "evaluate_demand_validation",
    "plan_product_artifacts",
    "project_financials",
    "research_confidence",
    "verify_artifact_grounding",
]
