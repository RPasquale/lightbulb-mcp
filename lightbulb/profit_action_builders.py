"""Typed candidate builders that make existing profit workflows executable.

These builders do not execute connectors.  They convert closed, provider-typed
arguments into a ``ProfitLeverCandidate`` whose immutable intent contains only a
SHA-256 connector-payload commitment.  The shared profit materializer later
requires the exact payload, approval, account, scope, project, and server
provenance before any effect can receive a receipt.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lightbulb.profit_materializer import (
    EcommerceUpdateProductArguments,
    FacebookPublishPostArguments,
    GmailSendEmailArguments,
    InstagramPublishPostArguments,
    LinkedInPublishPostArguments,
    canonical_profit_connector_arguments,
    profit_connector_arguments_digest,
)
from lightbulb.profit_workflow_runtime import (
    ProfitActionParameter,
    ProfitLeverCandidate,
)


MaterializableCapability = Literal[
    "ecommerce.create_discount",
    "ecommerce.update_product",
    "facebook.publish_post",
    "gmail.send_email",
    "instagram.publish_post",
    "linkedin.publish_post",
]


class MaterializableCandidateEconomics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    expected_incremental_revenue: Decimal = Field(ge=0, le=1_000_000_000_000)
    expected_incremental_cost: Decimal = Field(ge=0, le=1_000_000_000_000)
    implementation_cost: Decimal = Field(default=Decimal("0.00"), ge=0)
    downside_loss: Decimal = Field(default=Decimal("0.00"), ge=0)
    confidence: Decimal = Field(gt=0, le=1)
    time_to_value_days: int = Field(ge=0, le=3_650)

    @field_validator(
        "expected_incremental_revenue",
        "expected_incremental_cost",
        "implementation_cost",
        "downside_loss",
        "confidence",
        mode="before",
    )
    @classmethod
    def _decimal(cls, value: Any) -> Decimal:
        if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
            raise ValueError("economics values must be decimal strings or JSON numbers")
        parsed = Decimal(str(value))
        if not parsed.is_finite():
            raise ValueError("economics values must be finite")
        return parsed


def build_materializable_connector_candidate(
    *,
    candidate_ref: str,
    title: str,
    capability: MaterializableCapability,
    connector_account_ref: str,
    connector_arguments: Mapping[str, Any] | BaseModel,
    rationale: str,
    economics: MaterializableCandidateEconomics | Mapping[str, Any],
    measurement_metric: str,
    supported_by_evidence_refs: Sequence[str],
    depends_on: Sequence[str] = (),
    mutually_exclusive_group: str | None = None,
) -> ProfitLeverCandidate:
    """Build a profit candidate committed to one closed connector payload."""

    canonical_profit_connector_arguments(capability, connector_arguments)
    arguments_digest = profit_connector_arguments_digest(
        capability,
        connector_arguments,
    )
    economic_model = MaterializableCandidateEconomics.model_validate(economics)
    return ProfitLeverCandidate(
        candidate_ref=candidate_ref,
        title=title,
        capability=capability,
        target_account_ref=connector_account_ref,
        rationale=rationale,
        parameters=(
            ProfitActionParameter(
                name="connector_arguments_digest",
                value=arguments_digest,
            ),
        ),
        expected_incremental_revenue=economic_model.expected_incremental_revenue,
        expected_incremental_cost=economic_model.expected_incremental_cost,
        implementation_cost=economic_model.implementation_cost,
        downside_loss=economic_model.downside_loss,
        confidence=economic_model.confidence,
        time_to_value_days=economic_model.time_to_value_days,
        measurement_metric=measurement_metric,
        supported_by_evidence_refs=tuple(supported_by_evidence_refs),
        depends_on=tuple(depends_on),
        mutually_exclusive_group=mutually_exclusive_group,
    )


def build_offer_product_update_candidate(
    *,
    candidate_ref: str,
    connector_account_ref: str,
    arguments: EcommerceUpdateProductArguments | Mapping[str, Any],
    economics: MaterializableCandidateEconomics | Mapping[str, Any],
    supported_by_evidence_refs: Sequence[str],
) -> ProfitLeverCandidate:
    """Create an executable offer/margin or storefront product-update candidate."""

    return build_materializable_connector_candidate(
        candidate_ref=candidate_ref,
        title="Apply one reviewed product offer update",
        capability="ecommerce.update_product",
        connector_account_ref=connector_account_ref,
        connector_arguments=arguments,
        rationale=(
            "Apply only the reviewed product/variant fields whose exact payload is "
            "content-bound to the plan and a separate approval."
        ),
        economics=economics,
        measurement_metric="contribution_profit_per_order",
        supported_by_evidence_refs=supported_by_evidence_refs,
    )


def build_creative_publish_candidate(
    *,
    candidate_ref: str,
    capability: Literal[
        "facebook.publish_post",
        "instagram.publish_post",
        "linkedin.publish_post",
    ],
    connector_account_ref: str,
    arguments: (
        FacebookPublishPostArguments
        | InstagramPublishPostArguments
        | LinkedInPublishPostArguments
        | Mapping[str, Any]
    ),
    economics: MaterializableCandidateEconomics | Mapping[str, Any],
    supported_by_evidence_refs: Sequence[str],
) -> ProfitLeverCandidate:
    """Create an exact, separately-approved social experiment cell."""

    return build_materializable_connector_candidate(
        candidate_ref=candidate_ref,
        title="Publish one reviewed creative experiment cell",
        capability=capability,
        connector_account_ref=connector_account_ref,
        connector_arguments=arguments,
        rationale=(
            "Publish one channel-native cell after review, then rank it on downstream "
            "contribution profit rather than engagement alone."
        ),
        economics=economics,
        measurement_metric="creative_profit_per_thousand_impressions",
        supported_by_evidence_refs=supported_by_evidence_refs,
    )


def build_lifecycle_email_candidate(
    *,
    candidate_ref: str,
    connector_account_ref: str,
    arguments: GmailSendEmailArguments | Mapping[str, Any],
    economics: MaterializableCandidateEconomics | Mapping[str, Any],
    measurement_metric: Literal[
        "contribution_profit_per_contact",
        "recovered_contribution_profit",
    ],
    supported_by_evidence_refs: Sequence[str],
    depends_on: Sequence[str] = (),
) -> ProfitLeverCandidate:
    """Create a consent-reviewed Gmail lifecycle or recovery candidate."""

    return build_materializable_connector_candidate(
        candidate_ref=candidate_ref,
        title="Send one reviewed lifecycle message",
        capability="gmail.send_email",
        connector_account_ref=connector_account_ref,
        connector_arguments=arguments,
        rationale=(
            "Send only after the owning workflow verifies identity, consent, "
            "suppression, dedupe, and frequency policy."
        ),
        economics=economics,
        measurement_metric=measurement_metric,
        supported_by_evidence_refs=supported_by_evidence_refs,
        depends_on=depends_on,
    )


__all__ = [
    "MaterializableCandidateEconomics",
    "MaterializableCapability",
    "build_creative_publish_candidate",
    "build_lifecycle_email_candidate",
    "build_materializable_connector_candidate",
    "build_offer_product_update_candidate",
]
