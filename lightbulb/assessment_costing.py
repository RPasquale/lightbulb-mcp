"""Private, declared offer-cost scenarios; never ledger profit or pricing authority."""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP, localcontext
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from lightbulb.productised_assessment import ProductisedAssessmentDossier, AssessmentBlocker
from lightbulb.service_engagement import (
    _StrictModel, _detached, _digest_without, _parsed_timestamp, _timestamp,
    ServiceEngagementScope, OpaqueRef, Sha256Digest, BoundedText,
)


def _amount(value: Any) -> Decimal:
    if isinstance(value, (bool, float)):
        raise ValueError("use decimal strings or integers, not floats or booleans")
    try:
        result = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("a finite non-negative decimal is required") from exc
    if not result.is_finite() or result < 0 or result > Decimal('1e12') or result.as_tuple().exponent < -6:
        raise ValueError("amount must be non-negative, at most 1e12, with at most six decimal places")
    return result


class AssessmentOfferCost(_StrictModel):
    """All amounts apply to exactly one quoted billing period, in scope currency.

    Explicit zero is permitted; omitting a category is not a claim of zero cost.
    Own time is costed even when it is not a cash payment.
    """
    scope: ServiceEngagementScope
    offer_ref: OpaqueRef
    billing_period: Literal['one_off', 'month', 'year']
    own_hours: Decimal
    own_hourly_cost: Decimal
    contractor_cost: Decimal
    software_api_cost: Decimal
    other_delivery_cost: Decimal
    allocated_overhead: Decimal
    payment_fixed_cost: Decimal
    payment_rate: Decimal
    minimum_margin: Decimal
    valid_until: str
    assumptions: BoundedText

    @field_validator('own_hours', 'own_hourly_cost', 'contractor_cost', 'software_api_cost',
                     'other_delivery_cost', 'allocated_overhead', 'payment_fixed_cost',
                     'payment_rate', 'minimum_margin', mode='before')
    @classmethod
    def _numeric(cls, value: Any) -> Decimal:
        return _amount(value)

    @field_validator('valid_until')
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, field_name='valid_until')

    @model_validator(mode='after')
    def _rates(self):
        if self.payment_rate >= 1 or self.minimum_margin >= 1:
            raise ValueError('rates must be below one')
        if self.payment_rate + self.minimum_margin >= 1:
            raise ValueError('payment rate plus minimum margin must be below one')
        return self


class AssessmentCostingInput(_StrictModel):
    dossier: ProductisedAssessmentDossier
    as_of: str
    requested_by_ref: OpaqueRef
    tax_basis: Literal['exclusive', 'inclusive', 'unknown'] = 'unknown'
    costs: tuple[AssessmentOfferCost, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator('as_of')
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, field_name='as_of')

    @model_validator(mode='after')
    def _scope(self):
        source = self.dossier.inputs
        if self.requested_by_ref != source.requested_by_ref:
            raise ValueError('costing actor must match the assessment actor')
        if _parsed_timestamp(self.as_of) < _parsed_timestamp(source.prepared_at):
            raise ValueError('costing cannot precede the assessment')
        offers = {offer.offer_ref: offer for offer in source.offers}
        if len({cost.offer_ref for cost in self.costs}) != len(self.costs):
            raise ValueError('costs must be unique per offer')
        for cost in self.costs:
            if cost.scope != source.scope:
                raise ValueError('costs must match the exact tenant/company/project/customer and currency')
            if cost.offer_ref not in offers:
                raise ValueError('costs must select an existing assessment offer')
            if cost.billing_period != offers[cost.offer_ref].billing_period:
                raise ValueError('costs must cover the exact quoted billing period')
        return self


class AssessmentOfferEconomics(_StrictModel):
    offer_ref: OpaqueRef
    billing_period: Literal['one_off', 'month', 'year']
    currency: str
    status: Literal['incomplete', 'below_margin_floor', 'meets_margin_floor']
    quoted_price: Decimal | None = None
    declared_cost: Decimal | None = None
    own_time_cost: Decimal | None = None
    estimated_surplus: Decimal | None = None
    estimated_margin: Decimal | None = None
    minimum_price: Decimal | None = None
    discount_headroom: Decimal | None = None
    price_shortfall: Decimal | None = None
    blockers: tuple[AssessmentBlocker, ...] = ()


    @field_validator('quoted_price', 'declared_cost', 'own_time_cost', 'estimated_surplus',
                     'estimated_margin', 'minimum_price', 'discount_headroom', 'price_shortfall', mode='before')
    @classmethod
    def _decimal_output(cls, value):
        if value is None:
            return None
        if isinstance(value, (bool, float)):
            raise ValueError('derived amounts require exact decimal values')
        try:
            result = Decimal(value)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError('derived amount must be finite') from exc
        if not result.is_finite():
            raise ValueError('derived amount must be finite')
        return result


class AssessmentCostingReview(_StrictModel):
    schema_id: Literal['lightbulb.assessment_costing_review.v1'] = Field(default='lightbulb.assessment_costing_review.v1', alias='schema')
    inputs: AssessmentCostingInput
    offers: tuple[AssessmentOfferEconomics, ...]
    basis: Literal['caller_declared_estimates'] = 'caller_declared_estimates'
    audience: Literal['internal_operator'] = 'internal_operator'
    actual_profit_verified: Literal[False] = False
    price_changed: Literal[False] = False
    approved: Literal[False] = False
    review_digest: Sha256Digest

    @model_validator(mode='after')
    def _exact(self):
        if self.offers != _compare(self.inputs):
            raise ValueError('offer economics must be derived from the exact declared inputs')
        if self.review_digest != _digest_without(self.to_dict(), 'review_digest'):
            raise ValueError('review digest must commit the exact costing review')
        return self


def _compare(inputs: AssessmentCostingInput) -> tuple[AssessmentOfferEconomics, ...]:
    costs = {cost.offer_ref: cost for cost in inputs.costs}
    rows = []
    at = _parsed_timestamp(inputs.as_of)
    for offer in inputs.dossier.inputs.offers:
        blockers = list(inputs.dossier.blockers)
        def block(code, message):
            blockers.append(AssessmentBlocker(code=code, field='costs', message=message, related_refs=(offer.offer_ref,)))
        cost = costs.get(offer.offer_ref)
        if cost is None:
            block('missing_costs', 'Declare every cost category, including your time; use explicit zero where appropriate.')
        elif _parsed_timestamp(cost.valid_until) <= at:
            block('stale_costs', 'Refresh the cost estimates before relying on this comparison.')
        if inputs.tax_basis != 'exclusive':
            block('tax_basis_required', 'Confirm tax-exclusive quoted prices and costs; tax treatment is not inferred.')
        if offer.pricing is None or offer.pricing.valid_until is None:
            block('missing_price', 'Supply a price and its validity cutoff.')
        elif offer.pricing.total <= 0:
            block('non_positive_price', 'Supply a positive price to evaluate a selling margin.')
        elif _parsed_timestamp(offer.pricing.valid_until) <= at:
            block('stale_price', 'Refresh the offer price before relying on this comparison.')
        row = dict(offer_ref=offer.offer_ref, billing_period=offer.billing_period,
                   currency=inputs.dossier.inputs.scope.currency, status='incomplete', blockers=tuple(blockers))
        if not blockers:
            with localcontext() as context:
                context.prec = 80
                price = offer.pricing.total
                own_time = cost.own_hours * cost.own_hourly_cost
                fixed = own_time + cost.contractor_cost + cost.software_api_cost + cost.other_delivery_cost + cost.allocated_overhead + cost.payment_fixed_cost
                total = fixed + price * cost.payment_rate
                surplus = price - total
                minimum = max(Decimal('.000001'), (fixed / (1 - cost.payment_rate - cost.minimum_margin)).quantize(Decimal('.000001'), rounding=ROUND_CEILING))
                # Compare exact money, not a rounded ratio at the policy boundary.
                meets = price > 0 and surplus >= price * cost.minimum_margin
                row.update(status='meets_margin_floor' if meets else 'below_margin_floor',
                           quoted_price=price, declared_cost=total, own_time_cost=own_time,
                           estimated_surplus=surplus,
                           estimated_margin=(surplus / price).quantize(Decimal('.000001'), rounding=ROUND_HALF_UP) if price else None,
                           minimum_price=minimum, discount_headroom=max(Decimal(0), price-minimum),
                           price_shortfall=max(Decimal(0), minimum-price))
        rows.append(AssessmentOfferEconomics(**row))
    return tuple(rows)


def review_assessment_offer_costs(inputs: AssessmentCostingInput | Mapping[str, Any]) -> AssessmentCostingReview:
    """Compare declared costs without changing offers or claiming earned profit.

    Margins are per quoted billing period. There is no demand, renewal, tax,
    revenue or delivery-capacity forecast. Actuals belong to growth_profit's
    existing ledger-evidence contracts, never this estimate.
    """
    parsed = AssessmentCostingInput.model_validate(_detached(inputs))
    payload = dict(inputs=parsed.to_dict(), offers=[row.to_dict() for row in _compare(parsed)],
                   schema='lightbulb.assessment_costing_review.v1', basis='caller_declared_estimates',
                   audience='internal_operator', actual_profit_verified=False, price_changed=False, approved=False)
    payload['review_digest'] = _digest_without(payload, 'review_digest')
    return AssessmentCostingReview.model_validate(payload)
