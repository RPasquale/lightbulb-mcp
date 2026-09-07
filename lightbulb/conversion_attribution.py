"""Portfolio attribution from retained conversion identities and non-monetary touches.

A provider's aggregate conversion count is not a conversion identity. It cannot
enter this ledger or create revenue. Commerce conversions replay their source
lifecycle; attribution chooses one eligible touch per authoritative conversion.
"""
from __future__ import annotations
from decimal import Decimal
from datetime import timedelta
from typing import Any, Literal, Mapping, Sequence
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import (StrictModel, EngineScope, OpaqueRef, Sha256Digest,
    GENESIS_DIGEST, decimal_value, detached, parsed, timestamp, stable_digest, seal,
    sealed_digest, skip_digests, same_scope)

Basis = Literal["platform_reported", "site_measured", "crm_recorded", "commerce_recorded"]
BASIS_PRIORITY = {"platform_reported": 0, "site_measured": 1, "crm_recorded": 2, "commerce_recorded": 3}

from lightbulb.growth_engine_loop import Channel
AttributionChannel = Channel | Literal["local_presence"]

class AttributionError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AttributionError(code, message)

class ConversionCommitment(StrictModel):
    schema_id: Literal["lightbulb.conversion_commitment.v1"] = Field(default="lightbulb.conversion_commitment.v1", alias="schema")
    identity_commitment: Sha256Digest
    unit_commitment: Sha256Digest
    company_ref: OpaqueRef
    scope: EngineScope
    basis: Basis
    occurred_at: str
    value: Decimal
    source_state: dict[str, Any]
    source_plan: dict[str, Any]
    conversion_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("value", mode="before")
    @classmethod
    def money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")

    @field_validator("occurred_at")
    @classmethod
    def stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo) -> ConversionCommitment:
        if not skip_digests(info) and self.conversion_digest != sealed_digest(type(self), self, "conversion_digest"):
            raise ValueError("conversion_digest must commit the complete retained conversion")
        return self


def conversion_from_revenue(state: Any, *, source_plan: Any) -> ConversionCommitment:
    """A settled economic source supplies one identity, scope and monetary value."""
    from lightbulb.company_cost_centres import chain_revenue_receipt, _bound, _primary_source
    plan, source = _bound(state, source_plan)
    receipt = chain_revenue_receipt(source, source_plan=plan, centre_ref="attribution")
    raw = source.to_dict()
    customer = raw["ledger"].get("customer_ref") or raw["ledger"].get("account_ref")
    require(bool(customer), "IDENTITY_UNCOMMITTED", "the revenue source must retain a customer identity for touch matching")
    # The join is a commitment, never a raw person identifier in the touch lane.
    import re
    unit = str(customer) if re.fullmatch(r"[0-9a-f]{64}", str(customer)) else stable_digest({"customer_ref": customer})
    company = getattr(plan, "company_ref", None)
    require(company is not None, "SOURCE_SCOPE_MISMATCH", "the revenue plan must identify its logical company")
    return seal(ConversionCommitment, {
        "identity_commitment": stable_digest({"economic_source": _primary_source(raw, receipt["source_kind"])}),
        "unit_commitment": unit, "company_ref": company, "scope": source.scope.to_dict(),
        "basis": "commerce_recorded", "occurred_at": receipt["occurred_at"], "value": receipt["amount"],
        "source_state": raw, "source_plan": plan.to_dict()}, "conversion_digest")


def verify_conversion(value: Any) -> ConversionCommitment:
    conversion = ConversionCommitment.model_validate(detached(value))
    expected = conversion_from_revenue(conversion.source_state, source_plan=conversion.source_plan)
    require(conversion.conversion_digest == expected.conversion_digest, "BASIS_CONFLICT", "conversion identity, basis and value must be reproduced from their source")
    return conversion

class TouchClaim(StrictModel):
    schema_id: Literal["lightbulb.touch_claim.v1"] = Field(default="lightbulb.touch_claim.v1", alias="schema")
    touch_ref: OpaqueRef
    company_ref: OpaqueRef
    scope: EngineScope
    unit_commitment: Sha256Digest
    channel: AttributionChannel
    asset_commitment: Sha256Digest | None = None
    occurred_at: str
    basis: Basis
    claim_source: OpaqueRef
    provenance_digest: Sha256Digest
    source_evidence: dict[str, Any] | None = None
    # This is a non-monetary claim. It cannot be used as observed revenue.
    touch_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo) -> TouchClaim:
        if not skip_digests(info) and self.touch_digest != sealed_digest(type(self), self, "touch_digest"):
            raise ValueError("touch_digest must commit the complete touch claim")
        return self


def touch_claim(payload: Mapping[str, Any]) -> TouchClaim:
    return seal(TouchClaim, payload, "touch_digest")

class AttributionCredit(StrictModel):
    identity_commitment: Sha256Digest
    conversion_digest: Sha256Digest
    touch_digest: Sha256Digest
    channel: AttributionChannel
    value: Decimal
    conversion_weight: Decimal = Field(default=Decimal(1), ge=0, le=1)

    @field_validator("conversion_weight", mode="before")
    @classmethod
    def weight(cls, value):
        return Decimal(str(value))

    @field_validator("value", mode="before")
    @classmethod
    def money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")

class AttributionLedger(StrictModel):
    schema_id: Literal["lightbulb.attribution_ledger.v1"] = Field(default="lightbulb.attribution_ledger.v1", alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    portfolio_digest: Sha256Digest
    window_start: str
    window_end: str
    attribution_window_days: int = Field(ge=1, le=366)
    method: Literal["last_eligible_touch", "first_eligible_touch", "linear_eligible_touches"] = "last_eligible_touch"
    conversions: tuple[ConversionCommitment, ...] = Field(max_length=2000)
    touches: tuple[TouchClaim, ...] = Field(max_length=10000)
    holdout_units: tuple[Sha256Digest, ...] = Field(default=(), max_length=10000)
    credits: tuple[AttributionCredit, ...] = Field(max_length=20000)
    unmatched: tuple[Sha256Digest, ...] = Field(max_length=2000)
    observed_total: Decimal
    attributed_total: Decimal
    ledger_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("observed_total", "attributed_total", mode="before")
    @classmethod
    def money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("window_start", "window_end")
    @classmethod
    def stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo) -> AttributionLedger:
        require(parsed(self.window_start) < parsed(self.window_end), "WINDOW_INVALID", "attribution requires a positive window")
        require(sum((credit.value for credit in self.credits), Decimal(0)) == self.attributed_total <= self.observed_total,
                "PORTFOLIO_ATTRIBUTION_EXCEEDS_OBSERVED", "portfolio credits must conserve authoritative observed revenue")
        if not skip_digests(info) and self.ledger_digest != sealed_digest(type(self), self, "ledger_digest"):
            raise ValueError("ledger_digest must commit the complete attribution inputs and result")
        return self


def attribute_conversions(*, company_ref: str, scope: Any, portfolio_digest: str,
                          window_start: str, window_end: str, attribution_window_days: int,
                          conversions: Sequence[Any], touches: Sequence[Any], holdout_units: Sequence[str] = (),
                          method: str = "last_eligible_touch") -> AttributionLedger:
    require(method in {"last_eligible_touch", "first_eligible_touch", "linear_eligible_touches"}, "ATTRIBUTION_MODEL_UNKNOWN", "use a declared attribution model")
    scoped = EngineScope.model_validate(detached(scope))
    start, end = parsed(window_start), parsed(window_end)
    require(start < end, "WINDOW_INVALID", "attribution requires a positive window")
    require(1 <= attribution_window_days <= 366, "WINDOW_INVALID", "attribution lookback must be bounded")
    require(len(conversions) <= 2000 and len(touches) <= 10000, "INPUT_LIMIT", "split oversized windows before attribution")
    observed = [verify_conversion(value) for value in conversions]
    claims = [TouchClaim.model_validate(detached(value)) for value in touches]
    identities: set[str] = set()
    touch_ids: set[str] = set()
    for conversion in observed:
        require(conversion.company_ref == company_ref and same_scope(scoped, conversion.scope), "SOURCE_SCOPE_MISMATCH", "conversion belongs to another execution scope")
        require(start <= parsed(conversion.occurred_at) < end, "CONVERSION_OUTSIDE_WINDOW", "conversion belongs to another accounting window")
        require(conversion.identity_commitment not in identities, "CONVERSION_ALREADY_CREDITED", "one economic conversion may occur only once across the entire portfolio")
        identities.add(conversion.identity_commitment)
    for claim in claims:
        require(claim.company_ref == company_ref and same_scope(scoped, claim.scope), "SOURCE_SCOPE_MISMATCH", "touch belongs to another execution scope")
        from lightbulb.trusted_touch_sources import current_touch_verifier
        verifier = current_touch_verifier()
        require(verifier is not None, "TOUCH_SOURCE_UNVERIFIED", "the host must install its scoped touch-source verifier before attribution")
        verifier.verify(claim)
        require(claim.touch_ref not in touch_ids, "TOUCH_ALREADY_RECORDED", "a touch cannot be renamed across channels")
        touch_ids.add(claim.touch_ref)
        require(start - timedelta(days=attribution_window_days) <= parsed(claim.occurred_at) < end,
                "TOUCH_OUTSIDE_WINDOW", "touch lies outside the portfolio window and its lookback")
        require(claim.unit_commitment not in holdout_units, "HOLDOUT_CONTAMINATED", "a live holdout unit cannot receive treatment credit")
    credits, unmatched = [], []
    for conversion in observed:
        eligible = [claim for claim in claims if claim.unit_commitment == conversion.unit_commitment
                    and timedelta(0) <= parsed(conversion.occurred_at) - parsed(claim.occurred_at) <= timedelta(days=attribution_window_days)]
        if not eligible or conversion.unit_commitment in holdout_units:
            unmatched.append(conversion.identity_commitment)
            continue
        ordered = sorted(eligible, key=lambda claim: (parsed(claim.occurred_at), BASIS_PRIORITY[claim.basis], claim.touch_digest))
        chosen = ordered if method == "linear_eligible_touches" else [min(eligible, key=lambda claim: (parsed(claim.occurred_at), -BASIS_PRIORITY[claim.basis], claim.touch_digest)) if method == "first_eligible_touch" else ordered[-1]]
        require(len(credits) + len(chosen) <= 20000, "CREDIT_LIMIT", "split attribution windows before generating excessive credit rows")
        from lightbulb.company_engine_core import MONEY_QUANTUM
        cents = conversion.value / MONEY_QUANTUM
        require(cents == cents.to_integral_value(), "MONEY_PRECISION_INVALID", "conversion money must use the accounting quantum")
        quotient, remainder = divmod(int(cents), len(chosen))
        weight = Decimal(1) / len(chosen)
        for index, touch in enumerate(chosen):
            credits.append({"identity_commitment": conversion.identity_commitment, "conversion_digest": conversion.conversion_digest,
                            "touch_digest": touch.touch_digest, "channel": touch.channel,
                            "value": Decimal(quotient + (index < remainder)) * MONEY_QUANTUM,
                            "conversion_weight": weight if index < len(chosen)-1 else Decimal(1)-weight*(len(chosen)-1)})
    return seal(AttributionLedger, {"company_ref": company_ref, "scope": scoped.to_dict(), "portfolio_digest": portfolio_digest,
        "window_start": window_start, "window_end": window_end, "attribution_window_days": attribution_window_days, "method": method,
        "conversions": [value.to_dict() for value in observed], "touches": [value.to_dict() for value in claims],
        "holdout_units": list(holdout_units), "credits": credits, "unmatched": unmatched,
        "observed_total": sum((value.value for value in observed), Decimal(0)),
        "attributed_total": sum((value["value"] for value in credits), Decimal(0))}, "ledger_digest")


def verify_attribution(value: Any) -> AttributionLedger:
    ledger = AttributionLedger.model_validate(detached(value))
    expected = attribute_conversions(**{key: ledger.to_dict()[key] for key in
        ("company_ref", "scope", "portfolio_digest", "window_start", "window_end", "attribution_window_days", "conversions", "touches", "holdout_units", "method")})
    require(expected.ledger_digest == ledger.ledger_digest, "ATTRIBUTION_SOURCE_MISMATCH", "credits must reproduce the retained source evidence")
    return ledger


CONVERSION_ATTRIBUTION_MANIFEST = {"kind": "conversion_attribution", "schema": "lightbulb.conversion_attribution_manifest.v1",
    "measurement_basis": list(BASIS_PRIORITY), "methods": ["last_eligible_touch", "first_eligible_touch", "linear_eligible_touches"], "aggregate_metrics_create_revenue": False,
    "effect_boundary": {"sdk_candidate_only": True, "provider_write": False}}

__all__ = ["AttributionError", "ConversionCommitment", "TouchClaim", "AttributionCredit", "AttributionLedger",
           "conversion_from_revenue", "verify_conversion", "touch_claim", "attribute_conversions", "verify_attribution",
           "BASIS_PRIORITY", "CONVERSION_ATTRIBUTION_MANIFEST"]
