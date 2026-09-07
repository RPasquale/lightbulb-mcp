"""Marketplace Business Golden Operating Loop and Company Blueprint profiles.

Two-sided businesses (services, goods, rentals, B2B) share one loop::

    Onboard supply -> List -> Acquire demand -> Match -> Transact (escrow)
                   -> Fulfil -> Review / dispute -> Settle (fees, payout) -> Learn

and the branches that come with it: sellers that fail verification or get
suspended, listings that need review or sell out, transactions that are
cancelled, disputed, refunded in full or in part, and payouts that wait for
the dispute window.  This pack types the marketplace policy (take rate,
buyer fee, escrow, KYC level, listing review, dispute window, refund policy,
prohibited categories, listing limits), three replay-fenced entity
lifecycles (seller, listing, transaction) with policy-derived money, and a
marketplace assessment (GMV, take revenue, liquidity, dispute and refund
rates, repeat buyers, escrow exposure).

Nothing here verifies a person, moves money, or publishes a listing; those
are Spring-authorized effects executed through ``finance.*``,
``compliance.evaluate_regulated_controls``, and the payment connectors.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_validator


MARKETPLACE_BUSINESS_GOLDEN_LOOP = "marketplace.supply_demand_to_settled_transaction@0.1.0"
MARKETPLACE_BUSINESS_ARCHETYPE = "marketplace_business"
BLUEPRINT_SCHEMA = "lightbulb.marketplace_business_blueprint.v1"
PLAN_SCHEMA = "lightbulb.marketplace_business_loop_plan.v1"
COMMAND_SCHEMA = "lightbulb.marketplace_command.v1"
STATE_SCHEMA = "lightbulb.marketplace_entity_state.v1"
RESULT_SCHEMA = "lightbulb.marketplace_transition_result.v1"
ASSESSMENT_SCHEMA = "lightbulb.marketplace_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_TRANSITIONS = 80

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id", "card_number", "cvc", "iban", "routing_number", "date_of_birth", "national_id", "passport")
_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"(?<![0-9A-Za-z-])\d{13,19}(?![0-9A-Za-z-])"),
)
_MONEY_QUANTUM = Decimal("0.01")

OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

BlueprintProfile = Literal["services_marketplace", "goods_marketplace", "rental_marketplace", "b2b_marketplace", "custom"]
KycLevel = Literal["none", "basic", "verified", "enhanced"]
_KYC_RANK: dict[str, int] = {"none": 0, "basic": 1, "verified": 2, "enhanced": 3}
RefundPolicy = Literal["full_refund", "partial_refund", "no_refund", "case_by_case"]
Resolution = Literal["release_to_seller", "refund_buyer", "partial_refund"]
Entity = Literal["seller", "listing", "transaction"]
SellerStatus = Literal["applied", "verified", "active", "suspended", "offboarded", "rejected"]
ListingStatus = Literal["draft", "under_review", "live", "paused", "sold_out", "delisted", "rejected"]
TransactionStatus = Literal["matched", "funded", "in_fulfilment", "delivered", "accepted", "disputed", "resolved", "settled", "closed", "cancelled"]
EntityStatus = Literal[
    "applied", "verified", "active", "suspended", "offboarded", "rejected",
    "draft", "under_review", "live", "paused", "sold_out", "delisted",
    "matched", "funded", "in_fulfilment", "delivered", "accepted", "disputed", "resolved", "settled", "closed", "cancelled",
]
MarketplaceEvent = Literal[
    "apply", "verify", "reject", "activate", "suspend", "reinstate", "offboard",
    "draft", "submit", "approve", "reject_listing", "pause", "resume", "update_price", "delist", "mark_sold_out",
    "match", "fund", "start_fulfilment", "deliver", "accept", "dispute", "resolve", "settle", "close", "cancel",
]
LoopStage = Literal["onboard_supply", "list", "acquire_demand", "match", "transact", "fulfil", "review", "settle", "learn"]
STAGE_ORDER: tuple[str, ...] = ("onboard_supply", "list", "acquire_demand", "match", "transact", "fulfil", "review", "settle", "learn")
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]

_STATUSES: dict[str, frozenset[str]] = {
    "seller": frozenset(SellerStatus.__args__),  # type: ignore[attr-defined]
    "listing": frozenset(ListingStatus.__args__),  # type: ignore[attr-defined]
    "transaction": frozenset(TransactionStatus.__args__),  # type: ignore[attr-defined]
}
_EVENTS: dict[str, frozenset[str]] = {
    "seller": frozenset({"apply", "verify", "reject", "activate", "suspend", "reinstate", "offboard"}),
    "listing": frozenset({"draft", "submit", "approve", "reject_listing", "pause", "resume", "update_price", "delist", "mark_sold_out"}),
    "transaction": frozenset({"match", "fund", "start_fulfilment", "deliver", "accept", "dispute", "resolve", "settle", "close", "cancel"}),
}
TERMINAL_STATUSES: dict[str, frozenset[str]] = {
    "seller": frozenset({"offboarded", "rejected"}),
    "listing": frozenset({"sold_out", "delisted", "rejected"}),
    "transaction": frozenset({"closed", "cancelled"}),
}
_OPENING_EVENT: dict[str, str] = {"seller": "apply", "listing": "draft", "transaction": "match"}
_REASON_EVENTS = frozenset({"reject", "suspend", "offboard", "reject_listing", "delist", "dispute", "cancel"})
_TABLES: dict[str, dict[tuple[str, str], str]] = {
    "seller": {
        ("new", "apply"): "applied", ("applied", "verify"): "verified", ("applied", "reject"): "rejected", ("verified", "activate"): "active", ("verified", "reject"): "rejected",
        ("active", "suspend"): "suspended", ("suspended", "reinstate"): "active", ("active", "offboard"): "offboarded", ("suspended", "offboard"): "offboarded",
    },
    "listing": {
        ("new", "draft"): "draft", ("draft", "submit"): "live", ("under_review", "approve"): "live", ("under_review", "reject_listing"): "rejected",
        ("live", "pause"): "paused", ("paused", "resume"): "live", ("live", "update_price"): "live", ("paused", "update_price"): "paused",
        ("live", "delist"): "delisted", ("paused", "delist"): "delisted", ("live", "mark_sold_out"): "sold_out",
    },
    "transaction": {
        ("new", "match"): "matched", ("matched", "fund"): "funded", ("matched", "cancel"): "cancelled", ("funded", "start_fulfilment"): "in_fulfilment", ("funded", "cancel"): "cancelled",
        ("in_fulfilment", "deliver"): "delivered", ("delivered", "accept"): "accepted", ("delivered", "dispute"): "disputed", ("disputed", "resolve"): "resolved",
        ("accepted", "settle"): "settled", ("resolved", "settle"): "settled", ("settled", "close"): "closed",
    },
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_marketplace_business", "marketplace.advance_seller", "marketplace.advance_listing", "marketplace.advance_transaction", "marketplace.assess_marketplace",
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead", "communication.write_email", "communication.plan_crm_conversation_turn",
        "finance.create_invoice", "finance.collect_payment", "service.intake_and_classify_case", "service.verify_case_resolution",
        "growth.build_funnel_snapshot", "growth.review_customer_value", "growth.build_unit_economics", "learning.plan_optimization_sweep", "compliance.evaluate_regulated_controls",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset({"stripe.create_invoice", "stripe.create_refund", "stripe.list_payouts", "stripe.list_charges", "airwallex.create_payment", "airwallex.list_payouts", "hubspot.create_workflow", "shopify.list_fulfillment_orders"})


# --------------------------------------------------------------------------- #
# Strict model and helpers
# --------------------------------------------------------------------------- #


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like, card-like, or identity-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential-, bank-, or personal-identity field and is never accepted")
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


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or (parsed < 0 and not allow_negative) or abs(parsed) > Decimal("1000000000000"):
        raise ValueError(f"{field_name} must be a finite {'bounded' if allow_negative else 'non-negative bounded'} decimal")
    return parsed.quantize(_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_marketplace_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_marketplace_digests": True})
    return _stable_digest({key: value for key, value in parsed.to_dict().items() if key != field})


def _seal(model: type[_StrictModel], payload: Mapping[str, Any], field: str) -> Any:
    raw = dict(_detached(payload))
    raw[field] = _sealed_digest(model, raw, field)
    return model.model_validate(raw)


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _pct(amount: Decimal, percent: Decimal) -> Decimal:
    return (amount * percent / Decimal(100)).quantize(_MONEY_QUANTUM)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class ListingCategory(_StrictModel):
    category_ref: OpaqueRef
    name: ShortText
    take_rate_percent: Decimal | None = None
    requires_review: bool = False
    quantity_tracked: bool = False

    @field_validator("take_rate_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        parsed = _decimal(value, field_name="take_rate_percent")
        if parsed > 100:
            raise ValueError("take_rate_percent must be between 0 and 100")
        return parsed


class MarketplaceBusinessBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_business_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    categories: tuple[ListingCategory, ...] = Field(min_length=1, max_length=200)
    take_rate_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    buyer_fee_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    payout_delay_days: int = Field(default=2, ge=0, le=90)
    escrow_required: bool = True
    kyc_level: KycLevel = "basic"
    listing_review_required: bool = False
    dispute_window_days: int = Field(default=14, ge=0, le=90)
    refund_policy: RefundPolicy = "case_by_case"
    prohibited_categories: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    max_active_listings_per_seller: int = Field(default=100, ge=1, le=100000)
    min_seller_rating: Decimal = Field(default=Decimal("3"), validate_default=True)
    target_liquidity_percent: Decimal = Field(default=Decimal("30"), validate_default=True)
    max_dispute_rate_percent: Decimal = Field(default=Decimal("3"), validate_default=True)
    target_repeat_buyer_rate_percent: Decimal = Field(default=Decimal("30"), validate_default=True)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("take_rate_percent", "buyer_fee_percent", "target_liquidity_percent", "max_dispute_rate_percent", "target_repeat_buyer_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name))
        if parsed > 100:
            raise ValueError(f"{info.field_name} must be between 0 and 100")
        return parsed

    @field_validator("min_seller_rating", mode="before")
    @classmethod
    def _rating(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="min_seller_rating")
        if parsed > 5:
            raise ValueError("min_seller_rating must be between 0 and 5")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "MarketplaceBusinessBlueprint":
        _unique([item.category_ref for item in self.categories], label="category refs")
        _unique(list(self.prohibited_categories), label="prohibited categories")
        offered = {item.category_ref for item in self.categories}
        if offered & set(self.prohibited_categories):
            raise ValueError("a prohibited category cannot also be offered")
        if self.take_rate_percent + self.buyer_fee_percent > 100:
            raise ValueError("take rate plus buyer fee cannot exceed 100 percent")
        if self.escrow_required and self.kyc_level == "none":
            raise ValueError("escrow needs verified payees; set a KYC level")
        if self.refund_policy == "no_refund" and self.dispute_window_days > 0:
            raise ValueError("a no-refund policy cannot open a dispute window")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(MarketplaceBusinessBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def category(self, category_ref: str) -> ListingCategory | None:
        return next((item for item in self.categories if item.category_ref == category_ref), None)

    def take_rate_for(self, category_ref: str) -> Decimal:
        category = self.category(category_ref)
        return category.take_rate_percent if category is not None and category.take_rate_percent is not None else self.take_rate_percent


def seal_marketplace_business_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(MarketplaceBusinessBlueprint, raw, "blueprint_digest")
    return MarketplaceBusinessBlueprint.model_validate(raw).to_dict()


MARKETPLACE_BUSINESS_PROFILES: dict[str, dict[str, Any]] = {
    "services_marketplace": {"profile": "services_marketplace", "name": "Services marketplace", "categories": [{"category_ref": "home-services", "name": "Home services"}, {"category_ref": "professional-services", "name": "Professional services", "take_rate_percent": "12"}, {"category_ref": "creative", "name": "Creative work"}], "take_rate_percent": "15", "buyer_fee_percent": "5", "payout_delay_days": 2, "escrow_required": True, "kyc_level": "basic", "listing_review_required": False, "dispute_window_days": 14, "refund_policy": "case_by_case", "prohibited_categories": ["regulated-medical", "weapons"], "max_active_listings_per_seller": 20, "min_seller_rating": "3", "target_liquidity_percent": "40", "max_dispute_rate_percent": "3", "target_repeat_buyer_rate_percent": "30", "notes": "Escrow funds at match; release after the buyer accepts or the window closes."},
    "goods_marketplace": {"profile": "goods_marketplace", "name": "Goods marketplace", "categories": [{"category_ref": "electronics", "name": "Electronics", "requires_review": True, "quantity_tracked": True}, {"category_ref": "home", "name": "Home and garden", "quantity_tracked": True}, {"category_ref": "fashion", "name": "Fashion", "take_rate_percent": "8", "quantity_tracked": True}], "take_rate_percent": "10", "buyer_fee_percent": "0", "payout_delay_days": 3, "escrow_required": True, "kyc_level": "basic", "listing_review_required": True, "dispute_window_days": 30, "refund_policy": "full_refund", "prohibited_categories": ["weapons", "counterfeit", "recalled"], "max_active_listings_per_seller": 500, "min_seller_rating": "4", "target_liquidity_percent": "25", "max_dispute_rate_percent": "2", "target_repeat_buyer_rate_percent": "35", "notes": "Every listing reviewed; full refunds inside thirty days."},
    "rental_marketplace": {"profile": "rental_marketplace", "name": "Rental marketplace", "categories": [{"category_ref": "stays", "name": "Stays", "requires_review": True}, {"category_ref": "vehicles", "name": "Vehicles", "requires_review": True, "take_rate_percent": "15"}, {"category_ref": "equipment", "name": "Equipment"}], "take_rate_percent": "12", "buyer_fee_percent": "8", "payout_delay_days": 1, "escrow_required": True, "kyc_level": "verified", "listing_review_required": True, "dispute_window_days": 7, "refund_policy": "partial_refund", "prohibited_categories": ["unlicensed-lodging"], "max_active_listings_per_seller": 10, "min_seller_rating": "4", "target_liquidity_percent": "50", "max_dispute_rate_percent": "4", "target_repeat_buyer_rate_percent": "25", "notes": "Verified hosts; payout the day after check-in; partial refunds on disputes."},
    "b2b_marketplace": {"profile": "b2b_marketplace", "name": "B2B marketplace", "categories": [{"category_ref": "raw-materials", "name": "Raw materials", "quantity_tracked": True}, {"category_ref": "components", "name": "Components", "quantity_tracked": True}, {"category_ref": "logistics", "name": "Logistics services"}], "take_rate_percent": "5", "buyer_fee_percent": "0", "payout_delay_days": 30, "escrow_required": False, "kyc_level": "enhanced", "listing_review_required": True, "dispute_window_days": 45, "refund_policy": "case_by_case", "prohibited_categories": ["sanctioned-goods"], "max_active_listings_per_seller": 1000, "min_seller_rating": "3", "target_liquidity_percent": "20", "max_dispute_rate_percent": "2", "target_repeat_buyer_rate_percent": "50", "notes": "Invoice terms instead of escrow; enhanced due diligence on both sides."},
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    events: tuple[MarketplaceEvent, ...] = Field(default_factory=tuple, max_length=12)
    gate: Literal["none", "spring_approval", "platform_policy"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class MarketplaceBusinessLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_business_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["marketplace.supply_demand_to_settled_transaction@0.1.0"] = MARKETPLACE_BUSINESS_GOLDEN_LOOP
    archetype: Literal["marketplace_business"] = MARKETPLACE_BUSINESS_ARCHETYPE
    blueprint: MarketplaceBusinessBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=9, max_length=9)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "MarketplaceBusinessLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(MarketplaceBusinessLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(blueprint: MarketplaceBusinessBlueprint) -> list[dict[str, Any]]:
    kyc: tuple[str, ...] = ("compliance.evaluate_regulated_controls",) if blueprint.kyc_level != "none" else ()
    review: tuple[str, ...] = ("compliance.evaluate_regulated_controls",) if blueprint.listing_review_required or any(item.requires_review for item in blueprint.categories) else ()
    payment_tools: tuple[str, ...] = ("stripe.create_invoice", "stripe.list_charges") if blueprint.escrow_required else ("stripe.create_invoice",)
    return [
        {"stage": "onboard_supply", "title": "Onboard and verify sellers", "primitive_refs": ("crm.qualify_lead", "marketplace.advance_seller") + kyc, "events": ("apply", "verify", "reject", "activate", "suspend", "reinstate", "offboard"), "gate": "platform_policy" if kyc else "none"},
        {"stage": "list", "title": "List supply" + (" under review" if review else ""), "primitive_refs": ("marketplace.advance_listing",) + review, "events": ("draft", "submit", "approve", "reject_listing", "pause", "resume", "update_price", "delist", "mark_sold_out"), "gate": "platform_policy" if review else "none"},
        {"stage": "acquire_demand", "title": "Acquire buyers", "primitive_refs": ("demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "communication.write_email"), "connector_tools": ("hubspot.create_workflow",), "gate": "spring_approval"},
        {"stage": "match", "title": "Match demand to supply", "primitive_refs": ("marketplace.advance_transaction", "communication.plan_crm_conversation_turn"), "events": ("match", "cancel"), "gate": "none"},
        {"stage": "transact", "title": "Fund" + (" into escrow" if blueprint.escrow_required else " on invoice terms"), "primitive_refs": ("finance.create_invoice", "finance.collect_payment", "marketplace.advance_transaction"), "connector_tools": payment_tools, "events": ("fund", "cancel"), "gate": "spring_approval"},
        {"stage": "fulfil", "title": "Fulfil and deliver", "primitive_refs": ("marketplace.advance_transaction",), "connector_tools": ("shopify.list_fulfillment_orders",) if any(item.quantity_tracked for item in blueprint.categories) else (), "events": ("start_fulfilment", "deliver"), "gate": "none"},
        {"stage": "review", "title": f"Accept or dispute inside {blueprint.dispute_window_days} day(s)", "primitive_refs": ("marketplace.advance_transaction", "service.intake_and_classify_case", "service.verify_case_resolution"), "events": ("accept", "dispute", "resolve"), "gate": "platform_policy"},
        {"stage": "settle", "title": f"Settle fees and pay out after {blueprint.payout_delay_days} day(s)", "primitive_refs": ("marketplace.advance_transaction", "finance.collect_payment"), "connector_tools": ("stripe.create_refund", "stripe.list_payouts", "airwallex.create_payment", "airwallex.list_payouts"), "events": ("settle", "close"), "gate": "spring_approval"},
        {"stage": "learn", "title": "Learn: GMV, liquidity, disputes, repeat buyers", "primitive_refs": ("marketplace.assess_marketplace", "growth.build_funnel_snapshot", "growth.review_customer_value", "growth.build_unit_economics", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_marketplace_business_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> MarketplaceBusinessLoopPlan:
    if isinstance(profile, str):
        if profile not in MARKETPLACE_BUSINESS_PROFILES:
            raise ValueError(f"unknown marketplace business profile {profile!r}; choose one of {sorted(MARKETPLACE_BUSINESS_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(MARKETPLACE_BUSINESS_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = MarketplaceBusinessBlueprint.model_validate(seal_marketplace_business_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = _sealed_digest(MarketplaceBusinessLoopPlan, payload, "plan_digest")
    return MarketplaceBusinessLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Commands, ledgers, and transitions
# --------------------------------------------------------------------------- #


class MarketplaceScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    entity_ref: OpaqueRef
    currency: CurrencyCode

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


class MarketplaceReceipt(_StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    kyc_ref: OpaqueRef | None = None
    kyc_level: KycLevel | None = None
    payout_account_ref: OpaqueRef | None = None
    rating: Decimal | None = None
    category_ref: OpaqueRef | None = None
    title: ShortText | None = None
    unit_price: Decimal | None = None
    quantity: int | None = Field(default=None, ge=0, le=1_000_000)
    seller_ref: OpaqueRef | None = None
    buyer_ref: OpaqueRef | None = None
    listing_ref: OpaqueRef | None = None
    review_ref: OpaqueRef | None = None
    seller_state_digest: Sha256Digest | None = None
    listing_state_digest: Sha256Digest | None = None
    payment_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    delivery_ref: OpaqueRef | None = None
    case_ref: OpaqueRef | None = None
    resolution: Resolution | None = None
    refund_amount: Decimal | None = None
    payout_ref: OpaqueRef | None = None
    buyer_rating: int | None = Field(default=None, ge=1, le=5)
    seller_rating: int | None = Field(default=None, ge=1, le=5)

    @field_validator("unit_price", "amount", "refund_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("rating", mode="before")
    @classmethod
    def _rating(cls, value: Any) -> Any:
        if value is None:
            return None
        parsed = _decimal(value, field_name="rating")
        if parsed > 5:
            raise ValueError("rating must be between 0 and 5")
        return parsed


class MarketplaceCommand(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_command.v1"] = Field(default=COMMAND_SCHEMA, alias="schema")
    entity: Entity
    event: MarketplaceEvent
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: MarketplaceReceipt = Field(default_factory=MarketplaceReceipt)
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "MarketplaceCommand":
        if self.event not in _EVENTS[self.entity]:
            raise ValueError(f"{self.event} is not a {self.entity} event")
        if self.event in _REASON_EVENTS and self.reason is None:
            raise ValueError(f"{self.event} requires a reason")
        if _skip(info):
            return self
        if self.request_digest != marketplace_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def marketplace_command_digest(command: MarketplaceCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(MarketplaceCommand, command, "request_digest")


def seal_marketplace_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = marketplace_command_digest(raw)
    return MarketplaceCommand.model_validate(raw).to_dict()


class MarketplaceLedger(_StrictModel):
    kyc_ref: OpaqueRef | None = None
    kyc_level: KycLevel | None = None
    payout_account_ref: OpaqueRef | None = None
    rating: Decimal | None = None
    strikes: int = Field(default=0, ge=0)
    suspension_reason: ShortText | None = None
    category_ref: OpaqueRef | None = None
    title: ShortText | None = None
    unit_price: Decimal = Field(default=Decimal("0"), validate_default=True)
    quantity: int | None = Field(default=None, ge=0)
    seller_ref: OpaqueRef | None = None
    buyer_ref: OpaqueRef | None = None
    listing_ref: OpaqueRef | None = None
    review_ref: OpaqueRef | None = None
    seller_state_digest: Sha256Digest | None = None
    listing_state_digest: Sha256Digest | None = None
    price_changes: int = Field(default=0, ge=0)
    item_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    buyer_fee: Decimal = Field(default=Decimal("0"), validate_default=True)
    take_fee: Decimal = Field(default=Decimal("0"), validate_default=True)
    gross: Decimal = Field(default=Decimal("0"), validate_default=True)
    escrow_held: bool = False
    payment_ref: OpaqueRef | None = None
    delivered_at: str | None = None
    acceptance_deadline: str | None = None
    accepted_at: str | None = None
    acceptance: Literal["buyer", "window_elapsed"] | None = None
    dispute_case_ref: OpaqueRef | None = None
    resolution: Resolution | None = None
    refund_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    seller_payout: Decimal = Field(default=Decimal("0"), validate_default=True)
    platform_revenue: Decimal = Field(default=Decimal("0"), validate_default=True)
    payout_available_at: str | None = None
    payout_ref: OpaqueRef | None = None
    buyer_rating: int | None = Field(default=None, ge=1, le=5)
    seller_rating: int | None = Field(default=None, ge=1, le=5)
    outcome: Literal["completed", "refunded", "partially_refunded", "cancelled"] | None = None

    @field_validator("unit_price", "item_total", "buyer_fee", "take_fee", "gross", "refund_amount", "seller_payout", "platform_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("rating", mode="before")
    @classmethod
    def _rating(cls, value: Any) -> Any:
        return None if value is None else _decimal(value, field_name="rating")


class MarketplaceTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: EntityStatus
    transition_digest: Sha256Digest
    command: MarketplaceCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "MarketplaceTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: MarketplaceCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, entity: str, scope: MarketplaceScope, history: Sequence[MarketplaceTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "entity": entity, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _require(condition: bool, code: str, instructions: str, recovery: RecoveryDisposition = "correct_input") -> None:
    if not condition:
        raise _Rejected(code, instructions, recovery)


def _apply_seller(bp: MarketplaceBusinessBlueprint, event: str, ledger: MarketplaceLedger, r: MarketplaceReceipt, command: MarketplaceCommand, data: dict[str, Any]) -> None:
    if event == "verify":
        if bp.kyc_level != "none":
            _require(r.kyc_ref is not None and r.kyc_level is not None, "KYC_MISSING", f"verification links the KYC evidence at level {bp.kyc_level} or above")
            _require(_KYC_RANK[str(r.kyc_level)] >= _KYC_RANK[bp.kyc_level], "KYC_INSUFFICIENT", f"blueprint requires KYC level {bp.kyc_level}; got {r.kyc_level}")
        data.update({"kyc_ref": r.kyc_ref, "kyc_level": r.kyc_level or "none"})
    elif event == "activate":
        _require(r.payout_account_ref is not None, "PAYOUT_ACCOUNT_MISSING", "activation links the seller's payout account reference (never bank details)")
        data["payout_account_ref"] = r.payout_account_ref
        if r.rating is not None:
            data["rating"] = str(r.rating)
    elif event == "suspend":
        data.update({"strikes": ledger.strikes + 1, "suspension_reason": str(command.reason)[:300]})
    elif event == "reinstate":
        data["suspension_reason"] = None
    if r.rating is not None and event in {"reinstate", "suspend"}:
        data["rating"] = str(r.rating)


def _apply_listing(bp: MarketplaceBusinessBlueprint, event: str, ledger: MarketplaceLedger, r: MarketplaceReceipt, data: dict[str, Any]) -> str | None:
    if event == "draft":
        _require(r.category_ref is not None and r.title is not None and r.unit_price is not None and r.seller_ref is not None, "LISTING_INCOMPLETE", "a listing names its category, title, unit price, and seller")
        _require(str(r.category_ref) not in bp.prohibited_categories, "CATEGORY_PROHIBITED", f"{r.category_ref} is prohibited on this marketplace", "manual_reconciliation")
        category = bp.category(str(r.category_ref))
        _require(category is not None, "CATEGORY_UNKNOWN", f"{r.category_ref} is not a category on this marketplace")
        _require(r.unit_price is not None and r.unit_price > 0, "PRICE_INVALID", "unit price must be positive")
        assert category is not None
        if category.quantity_tracked:
            _require(r.quantity is not None and r.quantity >= 1, "QUANTITY_MISSING", f"{category.category_ref} listings track quantity; supply at least one unit")
        data.update({"category_ref": category.category_ref, "title": r.title, "unit_price": str(r.unit_price), "quantity": r.quantity if category.quantity_tracked else None, "seller_ref": r.seller_ref, "seller_state_digest": r.seller_state_digest})
        return None
    if event == "submit":
        category = bp.category(str(ledger.category_ref))
        return "under_review" if bp.listing_review_required or (category is not None and category.requires_review) else "live"
    if event == "approve":
        _require(r.review_ref is not None, "REVIEW_MISSING", "approval links the listing review")
        data["review_ref"] = r.review_ref
    elif event == "update_price":
        _require(r.unit_price is not None and r.unit_price > 0, "PRICE_INVALID", "unit price must be positive")
        data.update({"unit_price": str(r.unit_price), "price_changes": ledger.price_changes + 1})
    elif event == "mark_sold_out":
        _require(ledger.quantity is not None, "QUANTITY_NOT_TRACKED", "only quantity-tracked listings sell out")
        data["quantity"] = 0
    return None


def _apply_transaction(bp: MarketplaceBusinessBlueprint, event: str, ledger: MarketplaceLedger, r: MarketplaceReceipt, command: MarketplaceCommand, data: dict[str, Any]) -> None:
    at = _parsed(command.occurred_at)
    if event == "match":
        _require(r.listing_ref is not None and r.seller_ref is not None and r.buyer_ref is not None and r.unit_price is not None and r.category_ref is not None, "TRANSACTION_INCOMPLETE", "a match names the listing, seller, buyer, category, and unit price")
        _require(r.buyer_ref != r.seller_ref, "SELF_DEALING", "a seller cannot buy their own listing", "manual_reconciliation")
        _require(bp.category(str(r.category_ref)) is not None, "CATEGORY_UNKNOWN", f"{r.category_ref} is not a category on this marketplace")
        quantity = r.quantity if r.quantity is not None else 1
        _require(quantity >= 1 and r.unit_price is not None and r.unit_price > 0, "PRICE_INVALID", "quantity and unit price must be positive")
        assert r.unit_price is not None
        item_total = (r.unit_price * quantity).quantize(_MONEY_QUANTUM)
        buyer_fee, take_fee = _pct(item_total, bp.buyer_fee_percent), _pct(item_total, bp.take_rate_for(str(r.category_ref)))
        data.update({"listing_ref": r.listing_ref, "seller_ref": r.seller_ref, "buyer_ref": r.buyer_ref, "category_ref": r.category_ref, "unit_price": str(r.unit_price), "quantity": quantity, "item_total": str(item_total), "buyer_fee": str(buyer_fee), "take_fee": str(take_fee), "gross": str(item_total + buyer_fee), "listing_state_digest": r.listing_state_digest})
    elif event == "fund":
        _require(r.payment_ref is not None and r.amount == ledger.gross, "PAYMENT_MISMATCH", f"funding must carry the payment reference for exactly {ledger.gross}")
        data.update({"payment_ref": r.payment_ref, "escrow_held": bp.escrow_required})
    elif event == "deliver":
        _require(r.delivery_ref is not None, "DELIVERY_MISSING", "delivery links the delivery or check-in evidence")
        data.update({"delivered_at": command.occurred_at, "acceptance_deadline": _iso(at + timedelta(days=bp.dispute_window_days))})
    elif event == "accept":
        deadline = _parsed(str(ledger.acceptance_deadline))
        data.update({"accepted_at": command.occurred_at, "acceptance": "window_elapsed" if at > deadline else "buyer", "seller_payout": str(ledger.item_total - ledger.take_fee), "platform_revenue": str(ledger.take_fee + ledger.buyer_fee), "payout_available_at": _iso(at + timedelta(days=bp.payout_delay_days)), "outcome": "completed"})
    elif event == "dispute":
        _require(bp.dispute_window_days > 0, "DISPUTES_NOT_OFFERED", "this marketplace has no dispute window", "manual_reconciliation")
        _require(at <= _parsed(str(ledger.acceptance_deadline)), "DISPUTE_WINDOW_CLOSED", f"disputes close at {ledger.acceptance_deadline}", "manual_reconciliation")
        _require(r.case_ref is not None, "CASE_MISSING", "a dispute links the intake case")
        data["dispute_case_ref"] = r.case_ref
    elif event == "resolve":
        _require(r.resolution is not None, "RESOLUTION_MISSING", "a resolution names release_to_seller, refund_buyer, or partial_refund")
        allowed = {"no_refund": {"release_to_seller"}, "full_refund": {"release_to_seller", "refund_buyer"}, "partial_refund": {"release_to_seller", "partial_refund"}, "case_by_case": {"release_to_seller", "refund_buyer", "partial_refund"}}[bp.refund_policy]
        _require(str(r.resolution) in allowed, "REFUND_POLICY_VIOLATION", f"{r.resolution} is outside the {bp.refund_policy} policy", "manual_reconciliation")
        if r.resolution == "release_to_seller":
            refund, payout, revenue, outcome = Decimal("0"), ledger.item_total - ledger.take_fee, ledger.take_fee + ledger.buyer_fee, "completed"
        elif r.resolution == "refund_buyer":
            refund, payout, revenue, outcome = ledger.gross, Decimal("0"), Decimal("0"), "refunded"
        else:
            _require(r.refund_amount is not None and Decimal("0") < r.refund_amount < ledger.gross, "REFUND_AMOUNT_INVALID", f"a partial refund is more than 0 and less than {ledger.gross}")
            assert r.refund_amount is not None
            refund, payout, revenue, outcome = r.refund_amount, max(ledger.item_total - ledger.take_fee - r.refund_amount, Decimal("0")), ledger.take_fee + ledger.buyer_fee, "partially_refunded"
        data.update({"resolution": r.resolution, "refund_amount": str(refund), "seller_payout": str(payout.quantize(_MONEY_QUANTUM)), "platform_revenue": str(revenue), "payout_available_at": _iso(at + timedelta(days=bp.payout_delay_days)), "outcome": outcome})
    elif event == "settle":
        _require(at >= _parsed(str(ledger.payout_available_at)), "PAYOUT_NOT_AVAILABLE", f"payout opens at {ledger.payout_available_at}", "manual_reconciliation")
        if ledger.seller_payout > 0:
            _require(r.payout_ref is not None and r.amount == ledger.seller_payout, "PAYOUT_MISMATCH", f"settlement must carry the payout reference for exactly {ledger.seller_payout}")
            data["payout_ref"] = r.payout_ref
        data["escrow_held"] = False
    elif event == "close":
        data.update({"buyer_rating": r.buyer_rating, "seller_rating": r.seller_rating})
    elif event == "cancel":
        refund = ledger.gross if ledger.payment_ref is not None else Decimal("0")
        data.update({"refund_amount": str(refund), "seller_payout": "0", "platform_revenue": "0", "escrow_held": False, "outcome": "cancelled"})


def _apply(plan: MarketplaceBusinessLoopPlan, entity: str, status: str, ledger: MarketplaceLedger, command: MarketplaceCommand) -> tuple[str, MarketplaceLedger]:
    if status in TERMINAL_STATUSES[entity]:
        raise _Rejected(f"{entity.upper()}_TERMINAL", f"{entity} is {status}; no further transitions", "do_not_replay")
    next_status = _TABLES[entity].get((status, command.event))
    if next_status is None:
        raise _Rejected("ILLEGAL_TRANSITION", f"{command.event} is not a legal {entity} transition from {status}", "correct_input")
    data = ledger.to_dict()
    bp, r = plan.blueprint, command.receipt
    if entity == "seller":
        _apply_seller(bp, command.event, ledger, r, command, data)
    elif entity == "listing":
        override = _apply_listing(bp, command.event, ledger, r, data)
        next_status = override or next_status
    else:
        _apply_transaction(bp, command.event, ledger, r, command, data)
    return next_status, MarketplaceLedger.model_validate({key: value for key, value in data.items() if value is not None})


class MarketplaceState(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_entity_state.v1"] = Field(default=STATE_SCHEMA, alias="schema")
    entity: Entity
    plan_digest: Sha256Digest
    scope: MarketplaceScope
    status: EntityStatus
    version: int = Field(ge=1, le=MAX_TRANSITIONS)
    transition_history: tuple[MarketplaceTransition, ...] = Field(min_length=1, max_length=MAX_TRANSITIONS)
    ledger: MarketplaceLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "MarketplaceState":
        history = self.transition_history
        if self.status not in _STATUSES[self.entity]:
            raise ValueError(f"{self.status} is not a {self.entity} status")
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("entity version must equal a contiguous transition history")
        if any(item.command.entity != self.entity for item in history) or history[0].command.event != _OPENING_EVENT[self.entity]:
            raise ValueError("transition history must open the entity with its opening event")
        if self.status != history[-1].to_status:
            raise ValueError("entity status must equal the last retained transition status")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        prefix: tuple[MarketplaceTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.entity, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.entity, self.scope, history):
            raise ValueError("state_digest must commit the exact entity state")
        plan: MarketplaceBusinessLoopPlan | None = (info.context or {}).get("marketplace_plan")
        if plan is not None:
            if plan.plan_digest != self.plan_digest:
                raise ValueError("entity belongs to a different loop plan")
            status, ledger = "new", MarketplaceLedger()
            for transition in history:
                try:
                    status, ledger = _apply(plan, self.entity, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the transition table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("entity status and ledger must be derived from history")
        return self


class MarketplaceRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "MarketplaceRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class MarketplaceTransitionReceipt(_StrictModel):
    entity: Entity
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: MarketplaceEvent
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: EntityStatus
    to_status: EntityStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: MarketplaceRecovery


class MarketplaceEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    identity_verified: Literal[False] = False
    listing_published: Literal[False] = False
    funds_moved: Literal[False] = False
    payout_sent: Literal[False] = False
    refund_issued: Literal[False] = False


class MarketplaceTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_transition_result.v1"] = Field(default=RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: MarketplaceState | None = None
    receipt: MarketplaceTransitionReceipt
    effect_boundary: MarketplaceEffectBoundary = Field(default_factory=MarketplaceEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "MarketplaceTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], state: MarketplaceState | Mapping[str, Any]) -> tuple[MarketplaceBusinessLoopPlan, MarketplaceState]:
    parsed_plan = MarketplaceBusinessLoopPlan.model_validate(_detached(plan))
    unbound = MarketplaceState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("entity belongs to a different loop plan")
    return parsed_plan, MarketplaceState.model_validate(unbound.to_dict(), context={"marketplace_plan": parsed_plan})


def _open(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], entity: str, scope: MarketplaceScope | Mapping[str, Any], *, requested_at: str, actor_ref: str, receipt: Mapping[str, Any]) -> MarketplaceState:
    parsed_plan = MarketplaceBusinessLoopPlan.model_validate(_detached(plan))
    parsed_scope = MarketplaceScope.model_validate(_detached(scope))
    if parsed_scope.currency != parsed_plan.blueprint.currency:
        raise ValueError("entity currency must match the blueprint currency")
    event = _OPENING_EVENT[entity]
    genesis = _state_digest(parsed_plan.plan_digest, entity, parsed_scope, ())
    command = MarketplaceCommand.model_validate(seal_marketplace_command({"entity": entity, "event": event, "transition_ref": f"{event}:{parsed_scope.entity_ref}", "idempotency_key": f"{parsed_scope.entity_ref}:{event}", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": requested_at, "actor_ref": actor_ref, "receipt": _detached(receipt)}))
    try:
        status, ledger = _apply(parsed_plan, entity, "new", MarketplaceLedger(), command)
    except _Rejected as exc:
        raise ValueError(f"{exc.code}: {exc.instructions}") from exc
    transition = MarketplaceTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return MarketplaceState.model_validate({"entity": entity, "plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, entity, parsed_scope, (transition,))}, context={"marketplace_plan": parsed_plan})


def _same_marketplace(scope: MarketplaceScope, other: MarketplaceScope) -> bool:
    return (scope.tenant_ref, scope.company_ref, scope.project_ref, scope.project_id, scope.currency) == (other.tenant_ref, other.company_ref, other.project_ref, other.project_id, other.currency)


def open_seller(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], scope: MarketplaceScope | Mapping[str, Any], *, requested_at: str, actor_ref: str, receipt: MarketplaceReceipt | Mapping[str, Any] | None = None) -> MarketplaceState:
    """Open a seller application; the scope's entity_ref is the seller reference."""

    return _open(plan, "seller", scope, requested_at=requested_at, actor_ref=actor_ref, receipt=_detached(receipt or {}))


def open_listing(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], scope: MarketplaceScope | Mapping[str, Any], *, requested_at: str, actor_ref: str, receipt: MarketplaceReceipt | Mapping[str, Any], seller: MarketplaceState | Mapping[str, Any], active_listings: int = 0) -> MarketplaceState:
    """Open a listing draft for an active seller; the seller state is linked by digest."""

    parsed_plan, parsed_seller = _validate_plan_state(plan, seller)
    parsed_scope = MarketplaceScope.model_validate(_detached(scope))
    raw = dict(_detached(receipt))
    if parsed_seller.entity != "seller" or not _same_marketplace(parsed_scope, parsed_seller.scope):
        raise ValueError("SELLER_NOT_BOUND: the seller must belong to this marketplace scope")
    if raw.get("seller_ref") != parsed_seller.scope.entity_ref:
        raise ValueError("SELLER_REF_MISMATCH: the listing's seller_ref must be the seller state's entity_ref")
    if parsed_seller.status != "active":
        raise ValueError(f"SELLER_NOT_ACTIVE: seller is {parsed_seller.status}")
    if active_listings >= parsed_plan.blueprint.max_active_listings_per_seller:
        raise ValueError(f"LISTING_LIMIT: sellers may hold {parsed_plan.blueprint.max_active_listings_per_seller} active listing(s)")
    raw["seller_state_digest"] = parsed_seller.state_digest
    return _open(parsed_plan, "listing", parsed_scope, requested_at=requested_at, actor_ref=actor_ref, receipt=raw)


def open_transaction(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], scope: MarketplaceScope | Mapping[str, Any], *, requested_at: str, actor_ref: str, receipt: MarketplaceReceipt | Mapping[str, Any], listing: MarketplaceState | Mapping[str, Any]) -> MarketplaceState:
    """Match a buyer to a live listing; price, seller, and category come from the listing."""

    parsed_plan, parsed_listing = _validate_plan_state(plan, listing)
    parsed_scope = MarketplaceScope.model_validate(_detached(scope))
    raw = dict(_detached(receipt))
    if parsed_listing.entity != "listing" or not _same_marketplace(parsed_scope, parsed_listing.scope):
        raise ValueError("LISTING_NOT_BOUND: the listing must belong to this marketplace scope")
    if raw.get("listing_ref") != parsed_listing.scope.entity_ref:
        raise ValueError("LISTING_REF_MISMATCH: the transaction's listing_ref must be the listing state's entity_ref")
    if parsed_listing.status != "live":
        raise ValueError(f"LISTING_NOT_LIVE: listing is {parsed_listing.status}")
    quantity = int(raw.get("quantity") or 1)
    if parsed_listing.ledger.quantity is not None and quantity > parsed_listing.ledger.quantity:
        raise ValueError(f"QUANTITY_UNAVAILABLE: listing has {parsed_listing.ledger.quantity} unit(s)")
    if raw.get("unit_price") is not None and _decimal(raw["unit_price"], field_name="unit_price") != parsed_listing.ledger.unit_price:
        raise ValueError(f"PRICE_MISMATCH: listing price is {parsed_listing.ledger.unit_price}")
    raw.update({"seller_ref": parsed_listing.ledger.seller_ref, "category_ref": parsed_listing.ledger.category_ref, "unit_price": str(parsed_listing.ledger.unit_price), "quantity": quantity, "listing_state_digest": parsed_listing.state_digest})
    return _open(parsed_plan, "transaction", parsed_scope, requested_at=requested_at, actor_ref=actor_ref, receipt=raw)


def advance_marketplace_entity(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], state: MarketplaceState | Mapping[str, Any], command: MarketplaceCommand | Mapping[str, Any]) -> MarketplaceTransitionResult:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = MarketplaceCommand.model_validate(_detached(command))
    entity, from_version, from_status, from_digest = parsed_state.entity, parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> MarketplaceTransitionResult:
        receipt = MarketplaceTransitionReceipt(entity=entity, transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=MarketplaceRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return MarketplaceTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        if parsed_command.entity != entity:
            raise _Rejected("ENTITY_MISMATCH", f"command targets a {parsed_command.entity}; state is a {entity}", "correct_input")
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if _parsed(parsed_command.occurred_at) < _parsed(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the entity reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_plan, entity, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = MarketplaceTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = MarketplaceState.model_validate({"entity": entity, "plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, entity, parsed_state.scope, history)}, context={"marketplace_plan": parsed_plan})
    receipt = MarketplaceTransitionReceipt(entity=entity, transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=MarketplaceRecovery(disposition="not_required"))
    return MarketplaceTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


# --------------------------------------------------------------------------- #
# Marketplace assessment
# --------------------------------------------------------------------------- #


class MarketplaceAssessment(_StrictModel):
    schema_id: Literal["lightbulb.marketplace_assessment.v1"] = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["marketplace.supply_demand_to_settled_transaction@0.1.0"] = MARKETPLACE_BUSINESS_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    sellers: int = Field(ge=0)
    active_sellers: int = Field(ge=0)
    sellers_by_status: dict[str, int] = Field(default_factory=dict)
    listings: int = Field(ge=0)
    live_listings: int = Field(ge=0)
    listings_by_status: dict[str, int] = Field(default_factory=dict)
    transactions: int = Field(ge=0)
    transactions_by_status: dict[str, int] = Field(default_factory=dict)
    funded_transactions: int = Field(ge=0)
    gmv: Decimal
    take_revenue: Decimal
    refunds: Decimal
    escrow_held: Decimal
    pending_payouts: Decimal
    average_order_value: Decimal | None = None
    liquidity_percent: Decimal | None = None
    dispute_rate_percent: Decimal | None = None
    refund_rate_percent: Decimal | None = None
    repeat_buyer_rate_percent: Decimal | None = None
    average_seller_rating: Decimal | None = None
    learnings: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("gmv", "take_revenue", "refunds", "escrow_held", "pending_payouts", "average_order_value", "liquidity_percent", "dispute_rate_percent", "refund_rate_percent", "repeat_buyer_rate_percent", "average_seller_rating", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "MarketplaceAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(MarketplaceAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def _ratio(numerator: int, denominator: int) -> Decimal | None:
    return None if denominator == 0 else (Decimal(numerator) * 100 / Decimal(denominator)).quantize(_MONEY_QUANTUM)


def assess_marketplace(plan: MarketplaceBusinessLoopPlan | Mapping[str, Any], sellers: Sequence[MarketplaceState | Mapping[str, Any]], listings: Sequence[MarketplaceState | Mapping[str, Any]], transactions: Sequence[MarketplaceState | Mapping[str, Any]], *, assessed_at: str) -> MarketplaceAssessment:
    parsed_plan = MarketplaceBusinessLoopPlan.model_validate(_detached(plan))
    blueprint = parsed_plan.blueprint

    def bound(items: Sequence[MarketplaceState | Mapping[str, Any]], entity: str) -> list[MarketplaceState]:
        parsed = [_validate_plan_state(parsed_plan, item)[1] for item in items]
        if any(item.entity != entity for item in parsed):
            raise ValueError(f"every item in {entity}s must be a {entity} state")
        return parsed

    seller_states, listing_states, transaction_states = bound(sellers, "seller"), bound(listings, "listing"), bound(transactions, "transaction")
    counts = lambda items: {status: sum(1 for item in items if item.status == status) for status in sorted({item.status for item in items})}  # noqa: E731
    funded = [item for item in transaction_states if item.ledger.payment_ref is not None]
    gmv = sum((item.ledger.item_total for item in funded), Decimal("0"))
    take_revenue = sum((item.ledger.platform_revenue for item in transaction_states if item.status in {"settled", "closed"}), Decimal("0"))
    refunds = sum((item.ledger.refund_amount for item in transaction_states), Decimal("0"))
    escrow_held = sum((item.ledger.gross for item in transaction_states if item.ledger.escrow_held), Decimal("0"))
    pending_payouts = sum((item.ledger.seller_payout for item in transaction_states if item.status in {"accepted", "resolved"}), Decimal("0"))
    transacted_listings = {item.ledger.listing_ref for item in funded}
    listed = [item for item in listing_states if item.status not in {"draft", "under_review", "rejected"}]
    buyers: dict[str, int] = {}
    for item in funded:
        buyers[str(item.ledger.buyer_ref)] = buyers.get(str(item.ledger.buyer_ref), 0) + 1
    disputed = sum(1 for item in funded if item.ledger.dispute_case_ref is not None)
    refunded = sum(1 for item in funded if item.ledger.refund_amount > 0)
    ratings = [item.ledger.rating for item in seller_states if item.ledger.rating is not None]
    liquidity = _ratio(len(transacted_listings), len(listed))
    dispute_rate, refund_rate = _ratio(disputed, len(funded)), _ratio(refunded, len(funded))
    repeat_rate = _ratio(sum(1 for count in buyers.values() if count >= 2), len(buyers))
    quantum = _MONEY_QUANTUM
    learnings: list[str] = []
    recommendations: list[str] = []
    if liquidity is not None and liquidity < blueprint.target_liquidity_percent:
        learnings.append(f"liquidity {liquidity}% is below the {blueprint.target_liquidity_percent.quantize(quantum)}% target")
        recommendations.append("concentrate demand acquisition on the categories with unsold supply")
    if dispute_rate is not None and dispute_rate > blueprint.max_dispute_rate_percent:
        learnings.append(f"dispute rate {dispute_rate}% exceeds the {blueprint.max_dispute_rate_percent.quantize(quantum)}% ceiling")
        recommendations.append("tighten listing review and delivery evidence before release")
    if repeat_rate is not None and repeat_rate < blueprint.target_repeat_buyer_rate_percent:
        learnings.append(f"repeat-buyer rate {repeat_rate}% is below the {blueprint.target_repeat_buyer_rate_percent.quantize(quantum)}% target")
        recommendations.append("follow up settled transactions with a rebuy or rebook offer")
    if escrow_held > 0:
        learnings.append(f"{escrow_held} {blueprint.currency} held in escrow")
    if pending_payouts > 0:
        learnings.append(f"{pending_payouts} {blueprint.currency} awaiting payout")
        recommendations.append("settle payouts as soon as the delay elapses to keep sellers active")
    suspended = sum(1 for item in seller_states if item.status == "suspended")
    if suspended:
        learnings.append(f"{suspended} seller(s) suspended")
    if not learnings:
        learnings.append("marketplace is inside blueprint targets")
    payload = {
        "profile": blueprint.profile, "currency": blueprint.currency,
        "sellers": len(seller_states), "active_sellers": sum(1 for item in seller_states if item.status == "active"), "sellers_by_status": counts(seller_states),
        "listings": len(listing_states), "live_listings": sum(1 for item in listing_states if item.status == "live"), "listings_by_status": counts(listing_states),
        "transactions": len(transaction_states), "transactions_by_status": counts(transaction_states), "funded_transactions": len(funded),
        "gmv": str(gmv), "take_revenue": str(take_revenue), "refunds": str(refunds), "escrow_held": str(escrow_held), "pending_payouts": str(pending_payouts),
        "average_order_value": None if not funded else str((gmv / Decimal(len(funded))).quantize(quantum)),
        "liquidity_percent": None if liquidity is None else str(liquidity), "dispute_rate_percent": None if dispute_rate is None else str(dispute_rate), "refund_rate_percent": None if refund_rate is None else str(refund_rate), "repeat_buyer_rate_percent": None if repeat_rate is None else str(repeat_rate),
        "average_seller_rating": None if not ratings else str((sum(ratings, Decimal("0")) / Decimal(len(ratings))).quantize(quantum)),
        "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at,
    }
    return _seal(MarketplaceAssessment, payload, "assessment_digest")


MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": MARKETPLACE_BUSINESS_ARCHETYPE,
    "title": "Marketplace business",
    "golden_loop": MARKETPLACE_BUSINESS_GOLDEN_LOOP,
    "composed_with": ["crm.qualify_lead", "compliance.evaluate_regulated_controls (KYC, listing review)", "finance.create_invoice", "finance.collect_payment", "communication.write_email", "service.* dispute cases", "growth.* funnel, customer value, unit economics"],
    "profiles": sorted(MARKETPLACE_BUSINESS_PROFILES),
    "entities": {"seller": list(SellerStatus.__args__), "listing": list(ListingStatus.__args__), "transaction": list(TransactionStatus.__args__)},  # type: ignore[attr-defined]
    "events": list(MarketplaceEvent.__args__),  # type: ignore[attr-defined]
    "economic_spine": {"acquire_demand": "acquire_demand", "create_offer": "list", "agree_purchase": "match / transact", "deliver_value": "fulfil", "accept_value": "review (accept or dispute)", "monetize": "settle (take rate, buyer fee, payout)", "learn": "learn"},
    "composable_with": ["service_business", "product_commerce", "subscription_business", "saas_product", "appointment_business"],
    "explicit_inputs_never_invented": ["KYC evidence and level", "listing review outcomes", "payments, refunds, and payouts", "dispute cases and resolutions", "platform policy (prohibited categories, refund policy)"],
}

__all__ = [
    "MARKETPLACE_BUSINESS_ARCHETYPE",
    "MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST",
    "MARKETPLACE_BUSINESS_GOLDEN_LOOP",
    "MARKETPLACE_BUSINESS_PROFILES",
    "MAX_TRANSITIONS",
    "STAGE_ORDER",
    "TERMINAL_STATUSES",
    "ListingCategory",
    "MarketplaceAssessment",
    "MarketplaceBusinessBlueprint",
    "MarketplaceBusinessLoopPlan",
    "MarketplaceCommand",
    "MarketplaceEffectBoundary",
    "MarketplaceLedger",
    "MarketplaceReceipt",
    "MarketplaceRecovery",
    "MarketplaceScope",
    "MarketplaceState",
    "MarketplaceTransition",
    "MarketplaceTransitionReceipt",
    "MarketplaceTransitionResult",
    "StageBinding",
    "advance_marketplace_entity",
    "assess_marketplace",
    "compile_marketplace_business_blueprint",
    "marketplace_command_digest",
    "open_listing",
    "open_seller",
    "open_transaction",
    "seal_marketplace_business_blueprint",
    "seal_marketplace_command",
]
