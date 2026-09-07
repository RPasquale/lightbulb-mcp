"""Marketplace supply on the shared lifecycle runtime.

The canonical marketplace blueprint and seller/listing/transaction tables are
reused. Platform observations prove business facts; completed governed effects
prove publication and refunds. Settlement divides received cash into company
take revenue and an unpaid seller liability. A seller payout is a separate
payout-chain effect. This module performs no I/O or identity verification.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb import marketplace_business_loop as canonical
from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec,
    OpaqueRef, Rejected, Sha256Digest, ShortText, StrictModel, decimal_value,
    detached, iso, parsed, pct, seal, sealed_digest, skip_digests,
    stable_digest, timestamp, unique,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance

MARKETPLACE_SUPPLY_KIND = "marketplace_supply_engine"
MARKETPLACE_SUPPLY_GOLDEN_LOOP = canonical.MARKETPLACE_BUSINESS_GOLDEN_LOOP
MARKETPLACE_SUPPLY_PLAN_SCHEMA = "lightbulb.marketplace_supply_plan.v1"
MARKETPLACE_SUPPLY_PROFILES = {"two_sided_marketplace": {"source_profile": "services_marketplace"}}
SELLER_STATUSES = tuple(sorted(canonical._STATUSES["seller"]))
LISTING_STATUSES = tuple(sorted(canonical._STATUSES["listing"]))
TRANSACTION_STATUSES = tuple(sorted(canonical._STATUSES["transaction"]))
SELLER_EVENTS = tuple(sorted(canonical._EVENTS["seller"]))
LISTING_EVENTS = tuple(sorted(canonical._EVENTS["listing"]))
TRANSACTION_EVENTS = tuple(sorted(canonical._EVENTS["transaction"]))

MARKETPLACE_SUPPLY_CODES = (
    "SOURCE_NOT_EVIDENCED", "SCOPE_MISMATCH", "SOURCE_FROM_FUTURE", "OPERATING_PLAN_MISMATCH",
    "KYC_MISSING", "KYC_INSUFFICIENT", "PAYOUT_ACCOUNT_MISSING", "SELLER_NOT_ACTIVE",
    "SELLER_NOT_BOUND", "SELLER_REF_MISMATCH", "LISTING_LIMIT", "LISTING_INCOMPLETE",
    "CATEGORY_PROHIBITED", "CATEGORY_UNKNOWN", "PRICE_INVALID", "QUANTITY_MISSING",
    "REVIEW_MISSING", "QUANTITY_NOT_TRACKED", "LISTING_NOT_BOUND", "LISTING_NOT_LIVE",
    "LISTING_REF_MISMATCH", "TRANSACTION_INCOMPLETE", "SELF_DEALING", "PRICE_MISMATCH",
    "QUANTITY_UNAVAILABLE", "PAYMENT_MISMATCH", "DELIVERY_MISSING", "ACCEPTANCE_MISSING",
    "DISPUTES_NOT_OFFERED", "DISPUTE_WINDOW_CLOSED", "CASE_MISSING", "RESOLUTION_MISSING",
    "REFUND_POLICY_VIOLATION", "REFUND_AMOUNT_INVALID", "REFUND_NOT_PROVEN",
    "PAYOUT_NOT_AVAILABLE", "SETTLEMENT_MISMATCH", "TRANSACTION_NOT_SETTLED",
)


class MarketplaceSupplyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise MarketplaceSupplyError(code, message)


def _parse(model: Any, value: Any, code: str = "SOURCE_NOT_EVIDENCED") -> Any:
    try:
        return model.model_validate(detached(value))
    except (ValueError, TypeError) as exc:
        raise MarketplaceSupplyError(code, f"valid retained {model.__name__} evidence is required") from exc


def _money(value: Any, field: str) -> Decimal:
    return decimal_value(value, field_name=field).quantize(MONEY_QUANTUM)


class MarketplaceSupplyPlan(StrictModel):
    schema_id: Literal["lightbulb.marketplace_supply_plan.v1"] = Field(default=MARKETPLACE_SUPPLY_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    profile: Literal["two_sided_marketplace"] = "two_sided_marketplace"
    currency: CurrencyCode
    source_operating_plan: dict[str, Any]
    source_marketplace_plan: canonical.MarketplaceBusinessLoopPlan
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @property
    def blueprint(self) -> canonical.MarketplaceBusinessBlueprint:
        return self.source_marketplace_plan.blueprint

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketplaceSupplyPlan:
        from lightbulb.company_operating_system import CompanyOperatingPlan
        operating = CompanyOperatingPlan.model_validate(self.source_operating_plan)
        source = canonical.MarketplaceBusinessLoopPlan.model_validate(self.source_marketplace_plan.to_dict())
        binding = operating.blueprint.engine(MARKETPLACE_SUPPLY_KIND)
        if binding is None or binding.profile != self.profile or self.currency != operating.blueprint.currency or self.currency != source.blueprint.currency:
            raise ValueError("OPERATING_PLAN_MISMATCH: supply profile and currency must match the sealed operating envelope")
        if not skip_digests(info) and self.plan_digest != sealed_digest(MarketplaceSupplyPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact marketplace supply policy")
        return self


def compile_marketplace_supply_engine(company_ref: str, *, operating_plan: Any, profile: str = "two_sided_marketplace", overrides: Mapping[str, Any] | None = None) -> MarketplaceSupplyPlan:
    from lightbulb.company_operating_system import CompanyOperatingPlan
    operating = _parse(CompanyOperatingPlan, operating_plan, "OPERATING_PLAN_MISMATCH")
    _require(profile in MARKETPLACE_SUPPLY_PROFILES, "OPERATING_PLAN_MISMATCH", "unknown marketplace supply profile")
    policy = dict(detached(overrides or {}))
    _require("currency" not in policy or policy["currency"] == operating.blueprint.currency, "OPERATING_PLAN_MISMATCH", "marketplace currency must inherit the operating envelope")
    source = canonical.compile_marketplace_business_blueprint(MARKETPLACE_SUPPLY_PROFILES[profile]["source_profile"], {**policy, "currency": operating.blueprint.currency})
    return seal(MarketplaceSupplyPlan, {"company_ref": company_ref, "profile": profile, "currency": operating.blueprint.currency, "source_operating_plan": operating.to_dict(), "source_marketplace_plan": source}, "plan_digest")


class MarketplaceFacts(StrictModel):
    """Normalized, redacted output committed by its platform provenance."""
    schema_id: Literal["lightbulb.marketplace_source_record.v1"] = Field(default="lightbulb.marketplace_source_record.v1", alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    event: ShortText
    occurred_at: str
    disposition: Literal["applied", "verified", "active", "passed", "paid", "delivered", "accepted", "open", "resolved", "settled", "refunded", "recorded", "complete"]
    seller_ref: OpaqueRef | None = None
    buyer_ref: OpaqueRef | None = None
    listing_ref: OpaqueRef | None = None
    category_ref: OpaqueRef | None = None
    title: ShortText | None = None
    unit_price: Decimal | None = None
    quantity: int | None = Field(default=None, ge=0, le=1_000_000)
    kyc_ref: OpaqueRef | None = None
    kyc_level: Literal["none", "basic", "verified", "enhanced"] | None = None
    payout_account_ref: OpaqueRef | None = None
    rating: Decimal | None = None
    review_ref: OpaqueRef | None = None
    reviewer_ref: OpaqueRef | None = None
    active_listing_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=10000)
    complete: bool = False
    payment_ref: OpaqueRef | None = None
    correlation_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    delivery_ref: OpaqueRef | None = None
    case_ref: OpaqueRef | None = None
    resolution: Literal["release_to_seller", "refund_buyer", "partial_refund"] | None = None
    refund_amount: Decimal | None = None
    settlement_ref: OpaqueRef | None = None
    buyer_rating: int | None = Field(default=None, ge=1, le=5)
    seller_rating: int | None = Field(default=None, ge=1, le=5)

    @field_validator("occurred_at")
    @classmethod
    def _at(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")

    @field_validator("unit_price", "amount", "refund_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _money(value, str(info.field_name))

    @field_validator("rating", mode="before")
    @classmethod
    def _rating(cls, value: Any) -> Any:
        result = None if value is None else decimal_value(value, field_name="rating")
        if result is not None and result > 5:
            raise ValueError("rating cannot exceed five")
        return result

    @model_validator(mode="after")
    def _unique(self) -> MarketplaceFacts:
        unique(self.active_listing_refs, label="active listing references")
        return self


class MarketplaceObservation(StrictModel):
    schema_id: Literal["lightbulb.marketplace_supply_observation.v1"] = Field(default="lightbulb.marketplace_supply_observation.v1", alias="schema")
    provenance: ObservationProvenance
    output: dict[str, Any]
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketplaceObservation:
        if self.provenance.schema_id != "lightbulb.engine_observation_provenance.v1" or self.provenance.provenance_digest == GENESIS_DIGEST or self.provenance.output_digest != stable_digest(self.output):
            raise ValueError("observation provenance must commit the exact output and schema")
        if not skip_digests(info) and self.observation_digest != sealed_digest(MarketplaceObservation, self, "observation_digest"):
            raise ValueError("observation_digest must commit its source")
        return self


class MarketplaceExecution(StrictModel):
    schema_id: Literal["lightbulb.marketplace_supply_execution.v1"] = Field(default="lightbulb.marketplace_supply_execution.v1", alias="schema")
    execution: ExecutionReceipt
    output: dict[str, Any]
    effect_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketplaceExecution:
        if self.execution.schema_id != "lightbulb.engine_execution_receipt.v1" or self.execution.effect != "write" or self.execution.output_digest != stable_digest(self.output):
            raise ValueError("a governed completed write must commit the exact marketplace output")
        if any(getattr(self.execution, key) == GENESIS_DIGEST for key in ("request_digest", "receipt_digest", "route_digest", "approval_receipt_digest")):
            raise ValueError("write evidence cannot use genesis provenance")
        if not skip_digests(info) and self.effect_digest != sealed_digest(MarketplaceExecution, self, "effect_digest"):
            raise ValueError("effect_digest must commit the governed output")
        return self


def marketplace_observation(provenance: Any, output: Mapping[str, Any]) -> MarketplaceObservation:
    return seal(MarketplaceObservation, {"provenance": detached(provenance), "output": dict(detached(output))}, "observation_digest")


def marketplace_execution(execution: Any, output: Mapping[str, Any]) -> MarketplaceExecution:
    return seal(MarketplaceExecution, {"execution": detached(execution), "output": dict(detached(output))}, "effect_digest")


def observation_receipt(observation: Any) -> dict[str, Any]:
    return {"observation": _parse(MarketplaceObservation, observation).to_dict()}


def execution_receipt(execution: Any) -> dict[str, Any]:
    return {"execution": _parse(MarketplaceExecution, execution).to_dict()}


class MarketplaceSource(StrictModel):
    kind: Literal["seller", "listing", "transaction"]
    source_plan: MarketplaceSupplyPlan
    state: dict[str, Any]


class SupplyReceipt(StrictModel):
    register_scope: EngineScope | None = None
    observation: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    seller_source: MarketplaceSource | None = None
    listing_source: MarketplaceSource | None = None
    capacity: dict[str, Any] | None = None


class SupplyLedger(StrictModel):
    register_scope: EngineScope | None = None
    entity_ref: OpaqueRef | None = None
    kyc_ref: OpaqueRef | None = None
    kyc_level: Literal["none", "basic", "verified", "enhanced"] | None = None
    payout_account_ref: OpaqueRef | None = None
    rating: Decimal | None = None
    strikes: int = Field(default=0, ge=0)
    suspension_reason: ShortText | None = None
    category_ref: OpaqueRef | None = None
    title: ShortText | None = None
    unit_price: Decimal = Decimal("0.00")
    quantity: int | None = Field(default=None, ge=0)
    seller_ref: OpaqueRef | None = None
    buyer_ref: OpaqueRef | None = None
    listing_ref: OpaqueRef | None = None
    review_ref: OpaqueRef | None = None
    seller_state_digest: Sha256Digest | None = None
    listing_state_digest: Sha256Digest | None = None
    price_changes: int = Field(default=0, ge=0)
    item_total: Decimal = Decimal("0.00")
    buyer_fee: Decimal = Decimal("0.00")
    take_fee: Decimal = Decimal("0.00")
    gross: Decimal = Decimal("0.00")
    funded_amount: Decimal = Decimal("0.00")
    payment_ref: OpaqueRef | None = None
    correlation_ref: OpaqueRef | None = None
    funded_at: str | None = None
    delivered_at: str | None = None
    acceptance_deadline: str | None = None
    accepted_at: str | None = None
    acceptance: Literal["buyer", "window_elapsed"] | None = None
    dispute_case_ref: OpaqueRef | None = None
    resolution: Literal["release_to_seller", "refund_buyer", "partial_refund"] | None = None
    refund_amount: Decimal = Decimal("0.00")
    seller_liability: Decimal = Decimal("0.00")
    company_take_revenue: Decimal = Decimal("0.00")
    cash_settled: Decimal = Decimal("0.00")
    payout_available_at: str | None = None
    settlement_ref: OpaqueRef | None = None
    settled_at: str | None = None
    last_event_at: str | None = None
    buyer_rating: int | None = Field(default=None, ge=1, le=5)
    seller_rating: int | None = Field(default=None, ge=1, le=5)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=160)
    outcome: Literal["completed", "refunded", "partially_refunded", "cancelled"] | None = None

    @field_validator("rating", mode="before")
    @classmethod
    def _rating(cls, value: Any) -> Any:
        return None if value is None else decimal_value(value, field_name="rating")

    @field_validator("unit_price", "item_total", "buyer_fee", "take_fee", "gross", "funded_amount", "refund_amount", "seller_liability", "company_take_revenue", "cash_settled", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("funded_at", "delivered_at", "acceptance_deadline", "accepted_at", "payout_available_at", "settled_at", "last_event_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> Any:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class MarketplaceEffectBoundary(StrictModel):
    hosted_execution_performed: Literal[False] = False
    external_effect_authorized: Literal[False] = False
    seller_payout_performed: Literal[False] = False
    approval_granted: Literal[False] = False


_READ_TOOLS = {"host.marketplace_register", "host.marketplace_review", "stripe.list_charges", "stripe.list_payouts", "airwallex.list_transactions", "shopify.list_fulfillment_orders"}
_WRITE_TOOLS = {"submit": {"shopify.publish_product"}, "approve": {"shopify.publish_product"}, "resume": {"shopify.publish_product"}, "pause": {"shopify.update_product"}, "delist": {"shopify.update_product"}, "update_price": {"shopify.update_product"}, "refund": {"stripe.create_refund"}}


def _scope_equal(a: Any, b: Any, *, entity: bool = True) -> bool:
    a, b = detached(a), detached(b)
    keys = ("tenant_ref", "company_ref", "project_ref", "project_id", "currency") + (("entity_ref",) if entity else ())
    return all(a.get(key) == b.get(key) for key in keys)


def _facts(value: Any, *, plan: MarketplaceSupplyPlan, scope: Any, event: str, at: str, code: str = "SOURCE_NOT_EVIDENCED", write: bool = False) -> tuple[MarketplaceFacts, Any]:
    evidence = _parse(MarketplaceExecution if write else MarketplaceObservation, value, code)
    facts = _parse(MarketplaceFacts, evidence.output, code)
    if write:
        source_time, tool = evidence.execution.completed_at, evidence.execution.tool
        _require(tool in _WRITE_TOOLS.get(event, set()) and evidence.execution.project_id == facts.scope.project_id, code, "the execution tool and authenticated project must prove this effect")
    else:
        source_time, tool = evidence.provenance.completed_at, evidence.provenance.source_tool
        _require(tool in _READ_TOOLS and (evidence.provenance.lane == "host_read") == tool.startswith("host."), code, "the source must use its admitted observation lane")
        if event in {"fund", "settle"}:
            permitted = {"stripe.list_charges"} if event == "fund" else {"stripe.list_payouts", "airwallex.list_transactions"}
            _require(tool in permitted, code, "cash facts must come from the payment provider observation")
        else:
            _require(tool.startswith("host.marketplace") or (event == "deliver" and tool == "shopify.list_fulfillment_orders"), code, "a cash report cannot attest marketplace review or delivery")
    _require(facts.company_ref == plan.company_ref and _scope_equal(facts.scope, scope), "SCOPE_MISMATCH", "evidence must retain the exact authenticated marketplace scope")
    _require(facts.event == event, code, "the committed source proves another event")
    _require(parsed(facts.occurred_at) <= parsed(source_time) <= parsed(at), "SOURCE_FROM_FUTURE", "evidence must be observed after the event and before it is recorded")
    return facts, evidence


def _remember(data: dict[str, Any], evidence: Any) -> None:
    digest = getattr(evidence, "observation_digest", None) or evidence.effect_digest
    _require(digest not in data.get("source_digests", ()), "SOURCE_NOT_EVIDENCED", "one provider result cannot satisfy multiple transitions")
    data["source_digests"] = [*data.get("source_digests", ()), digest]


def _chronology(data: dict[str, Any], facts: MarketplaceFacts | None, at: str) -> None:
    event_at = facts.occurred_at if facts is not None else at
    _require(data.get("last_event_at") is None or parsed(event_at) >= parsed(data["last_event_at"]), "SOURCE_NOT_EVIDENCED", "the observed business event cannot precede the previous retained event")
    data["last_event_at"] = event_at


def marketplace_source(state: Any, *, source_plan: Any, kind: str) -> MarketplaceSource:
    source = _parse(MarketplaceSource, {"kind": kind, "source_plan": detached(source_plan), "state": detached(state)})
    _, proven = _spec(kind).bind(source.source_plan, source.state)
    _require(_scope_equal(proven.scope, proven.ledger.register_scope), "SCOPE_MISMATCH", "replayed opening scope must equal the retained state scope")
    return MarketplaceSource(kind=kind, source_plan=source.source_plan, state=proven.to_dict())


def _source(value: Any, *, kind: str, plan: MarketplaceSupplyPlan, scope: Any, at: str, code: str) -> Any:
    source = _parse(MarketplaceSource, value, code)
    _require(source.kind == kind, code, f"a retained {kind} source is required")
    try:
        source = marketplace_source(source.state, source_plan=source.source_plan, kind=kind)
        _, state = _spec(kind).bind(source.source_plan, source.state)
    except (ValueError, TypeError) as exc:
        raise MarketplaceSupplyError(code, "the source state and ledger must replay against their retained plan") from exc
    _require(source.source_plan.plan_digest == plan.plan_digest and _scope_equal(scope, state.scope, entity=False), code, "the source must belong to this marketplace and execution scope")
    _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "a source state cannot come from the future")
    return state


def _opening(plan: MarketplaceSupplyPlan, data: dict[str, Any], command: Any) -> EngineScope:
    scope = _parse(EngineScope, command.receipt.register_scope, "SCOPE_MISMATCH")
    _require(scope.currency == plan.currency, "SCOPE_MISMATCH", "opening scope must retain the plan currency")
    data.update(register_scope=scope.to_dict(), entity_ref=scope.entity_ref)
    return scope


def _apply_seller(plan: MarketplaceSupplyPlan, nxt: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        scope = _opening(plan, data, command) if event == "apply" else data["register_scope"]
        code = {"verify": "KYC_MISSING", "activate": "PAYOUT_ACCOUNT_MISSING"}.get(event, "SOURCE_NOT_EVIDENCED")
        facts, source = _facts(r.observation, plan=plan, scope=scope, event=event, at=at, code=code)
        _require(facts.disposition == {"apply": "applied", "verify": "verified", "activate": "active", "reinstate": "active"}.get(event, "recorded"), code, "the source disposition does not prove this seller transition")
        if event == "verify":
            _require(facts.kyc_ref is not None and facts.kyc_level is not None, "KYC_MISSING", "KYC evidence must name its review and level")
            _require(canonical._KYC_RANK[facts.kyc_level] >= canonical._KYC_RANK[plan.blueprint.kyc_level], "KYC_INSUFFICIENT", "the observed KYC level is below policy")
            data.update(kyc_ref=facts.kyc_ref, kyc_level=facts.kyc_level)
        elif event == "activate":
            _require(facts.payout_account_ref is not None, "PAYOUT_ACCOUNT_MISSING", "activation requires a platform-held payout account reference")
            data.update(payout_account_ref=facts.payout_account_ref, rating=facts.rating)
        elif event == "suspend":
            data.update(strikes=data.get("strikes", 0) + 1, suspension_reason=str(command.reason)[:300])
        elif event == "reinstate":
            data["suspension_reason"] = None
        if facts.rating is not None and event in {"suspend", "reinstate"}:
            data["rating"] = facts.rating
        _chronology(data, facts, at)
        _remember(data, source)
    except MarketplaceSupplyError as exc:
        raise Rejected(exc.code, exc.message, "correct_input") from exc
    return nxt, data


def _apply_listing(plan: MarketplaceSupplyPlan, nxt: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at, bp = command.receipt, command.event, command.occurred_at, plan.blueprint
    try:
        scope = _opening(plan, data, command) if event == "draft" else data["register_scope"]
        category = bp.category(data.get("category_ref", ""))
        needs_review = bp.listing_review_required or bool(category is not None and category.requires_review)
        write = event in _WRITE_TOOLS and not (event == "submit" and needs_review)
        code = "REVIEW_MISSING" if event == "approve" else "SOURCE_NOT_EVIDENCED"
        facts, evidence = _facts(r.execution if write else r.observation, plan=plan, scope=scope, event=event, at=at, code=code, write=write)
        _require(facts.disposition == ("passed" if event == "approve" else "recorded"), code, "the committed output does not prove the listing transition")
        if event == "draft":
            _require(facts.category_ref is not None and facts.title is not None and facts.unit_price is not None and facts.seller_ref is not None, "LISTING_INCOMPLETE", "draft facts must name category, title, price and seller")
            seller = _source(r.seller_source, kind="seller", plan=plan, scope=scope, at=at, code="SELLER_NOT_BOUND")
            _require(seller.scope.entity_ref == facts.seller_ref, "SELLER_REF_MISMATCH", "the listing must name its retained seller")
            _require(seller.status == "active", "SELLER_NOT_ACTIVE", "only an active seller may list supply")
            capacity, cap_source = _facts(r.capacity, plan=plan, scope=seller.scope, event="capacity", at=at, code="LISTING_LIMIT")
            _require(capacity.complete and capacity.disposition == "complete" and len(capacity.active_listing_refs) < bp.max_active_listings_per_seller and scope.entity_ref not in capacity.active_listing_refs, "LISTING_LIMIT", "a complete platform inventory must leave capacity for this new listing")
            _require(facts.category_ref not in bp.prohibited_categories, "CATEGORY_PROHIBITED", "the listing category is prohibited")
            category = bp.category(facts.category_ref)
            _require(category is not None, "CATEGORY_UNKNOWN", "the listing category is not offered")
            _require(facts.unit_price > 0, "PRICE_INVALID", "listing prices must be positive")
            _require(not category.quantity_tracked or (facts.quantity is not None and facts.quantity >= 1), "QUANTITY_MISSING", "a tracked listing must have available quantity")
            data.update(category_ref=category.category_ref, title=facts.title, unit_price=facts.unit_price, quantity=facts.quantity if category.quantity_tracked else None, seller_ref=facts.seller_ref, seller_state_digest=seller.state_digest, payout_account_ref=seller.ledger.payout_account_ref)
            _remember(data, cap_source)
        elif event == "submit":
            category = bp.category(data["category_ref"])
            nxt = "under_review" if bp.listing_review_required or category.requires_review else "live"
        elif event == "approve":
            _require(facts.review_ref is not None and facts.reviewer_ref is not None and facts.reviewer_ref != command.actor_ref and facts.disposition == "passed", "REVIEW_MISSING", "listing publication requires an independent approved review in the governed output")
            data["review_ref"] = facts.review_ref
        elif event == "update_price":
            _require(facts.unit_price is not None and facts.unit_price > 0, "PRICE_INVALID", "listing prices must be positive")
            data.update(unit_price=facts.unit_price, price_changes=data.get("price_changes", 0) + 1)
        elif event == "mark_sold_out":
            _require(data.get("quantity") is not None, "QUANTITY_NOT_TRACKED", "only tracked listings sell out")
            _require(facts.quantity == 0, "QUANTITY_UNAVAILABLE", "the source inventory must show no remaining units")
            data["quantity"] = 0
        _chronology(data, facts, at)
        _remember(data, evidence)
    except MarketplaceSupplyError as exc:
        raise Rejected(exc.code, exc.message, "correct_input") from exc
    return nxt, data


def _allocation(data: dict[str, Any], refund: Decimal, at: str, delay: int) -> None:
    remaining = Decimal(data["gross"]) - refund
    liability = max(Decimal(data["item_total"]) - Decimal(data["take_fee"]) - refund, Decimal("0.00"))
    data.update(refund_amount=refund, seller_liability=liability, company_take_revenue=remaining - liability, payout_available_at=iso(parsed(at) + timedelta(days=delay)))


def _refund(plan: MarketplaceSupplyPlan, data: dict[str, Any], value: Any, amount: Decimal, at: str) -> None:
    facts, effect = _facts(value, plan=plan, scope=data["register_scope"], event="refund", at=at, code="REFUND_NOT_PROVEN", write=True)
    _require(facts.disposition == "refunded" and facts.amount == amount and facts.payment_ref == data.get("payment_ref") and facts.correlation_ref == data.get("correlation_ref"), "REFUND_NOT_PROVEN", "refund execution must match this exact payment, correlation and amount")
    _require(parsed(facts.occurred_at) >= parsed(data["funded_at"]), "REFUND_NOT_PROVEN", "a refund cannot precede funding")
    _remember(data, effect)


def _apply_transaction(plan: MarketplaceSupplyPlan, nxt: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at, bp = command.receipt, command.event, command.occurred_at, plan.blueprint
    try:
        scope = _opening(plan, data, command) if event == "match" else data["register_scope"]
        codes = {"fund": "PAYMENT_MISMATCH", "deliver": "DELIVERY_MISSING", "accept": "ACCEPTANCE_MISSING", "dispute": "CASE_MISSING", "resolve": "RESOLUTION_MISSING", "settle": "SETTLEMENT_MISMATCH"}
        # Expired acceptance is a deterministic clock event, not a claimed buyer action.
        facts = evidence = None
        if event != "accept" or r.observation is not None or parsed(at) <= parsed(data["acceptance_deadline"]):
            facts, evidence = _facts(r.observation, plan=plan, scope=scope, event=event, at=at, code=codes.get(event, "SOURCE_NOT_EVIDENCED"))
        if event == "match":
            _require(facts.listing_ref is not None and facts.buyer_ref is not None, "TRANSACTION_INCOMPLETE", "a match must identify its observed listing and buyer")
            listing = _source(r.listing_source, kind="listing", plan=plan, scope=scope, at=at, code="LISTING_NOT_BOUND")
            _require(facts.listing_ref == listing.scope.entity_ref, "LISTING_REF_MISMATCH", "the match must name the retained listing")
            _require(listing.status == "live", "LISTING_NOT_LIVE", "a match requires live supply")
            seller = _source(r.seller_source, kind="seller", plan=plan, scope=scope, at=at, code="SELLER_NOT_BOUND")
            _require(seller.scope.entity_ref == listing.ledger.seller_ref, "SELLER_REF_MISMATCH", "the current seller must own this listing")
            _require(seller.status == "active", "SELLER_NOT_ACTIVE", "suspended or offboarded sellers cannot receive matches")
            _require((facts.seller_ref is None or facts.seller_ref == seller.scope.entity_ref) and (facts.category_ref is None or facts.category_ref == listing.ledger.category_ref), "SOURCE_NOT_EVIDENCED", "the match cannot substitute the listing's seller or category")
            _require(facts.buyer_ref != seller.scope.entity_ref, "SELF_DEALING", "a seller cannot buy their own listing")
            quantity = facts.quantity if facts.quantity is not None else 1
            _require(quantity >= 1, "PRICE_INVALID", "matched quantity must be positive")
            _require(listing.ledger.quantity is None or quantity <= listing.ledger.quantity, "QUANTITY_UNAVAILABLE", "the retained listing cannot supply this quantity")
            _require(facts.unit_price is None or facts.unit_price == listing.ledger.unit_price, "PRICE_MISMATCH", "the observed match price differs from the retained listing")
            item_total = (listing.ledger.unit_price * quantity).quantize(MONEY_QUANTUM)
            buyer_fee, take_fee = pct(item_total, bp.buyer_fee_percent), pct(item_total, bp.take_rate_for(listing.ledger.category_ref))
            data.update(listing_ref=listing.scope.entity_ref, seller_ref=seller.scope.entity_ref, buyer_ref=facts.buyer_ref, category_ref=listing.ledger.category_ref, unit_price=listing.ledger.unit_price, quantity=quantity, listing_state_digest=listing.state_digest, seller_state_digest=seller.state_digest, payout_account_ref=seller.ledger.payout_account_ref, item_total=item_total, buyer_fee=buyer_fee, take_fee=take_fee, gross=item_total + buyer_fee, correlation_ref="LB-MK-" + command.expected_state_digest[:24])
        elif event == "fund":
            _require(facts.disposition == "paid" and facts.payment_ref is not None and facts.amount == Decimal(data["gross"]) and facts.correlation_ref == data["correlation_ref"], "PAYMENT_MISMATCH", "funding must prove the exact gross amount and marketplace correlation")
            data.update(payment_ref=facts.payment_ref, funded_amount=facts.amount, funded_at=facts.occurred_at)
        elif event == "deliver":
            _require(facts.disposition == "delivered" and facts.delivery_ref is not None, "DELIVERY_MISSING", "a delivered result must name its completion evidence")
            _require(parsed(facts.occurred_at) >= parsed(data["funded_at"]), "DELIVERY_MISSING", "delivery cannot precede funding")
            data.update(delivered_at=facts.occurred_at, acceptance_deadline=iso(parsed(facts.occurred_at) + timedelta(days=bp.dispute_window_days)))
        elif event == "accept":
            elapsed = parsed(at) > parsed(data["acceptance_deadline"])
            if not elapsed:
                _require(facts is not None and facts.disposition == "accepted" and facts.buyer_ref == data["buyer_ref"] and parsed(facts.occurred_at) >= parsed(data["delivered_at"]), "ACCEPTANCE_MISSING", "early acceptance must be observed from the matched buyer")
            data.update(accepted_at=at, acceptance="window_elapsed" if elapsed else "buyer", outcome="completed")
            _allocation(data, Decimal("0.00"), at, bp.payout_delay_days)
        elif event == "dispute":
            _require(bp.dispute_window_days > 0, "DISPUTES_NOT_OFFERED", "this policy has no dispute window")
            _require(parsed(at) <= parsed(data["acceptance_deadline"]), "DISPUTE_WINDOW_CLOSED", "the dispute window is closed")
            _require(facts.case_ref is not None and facts.disposition == "open" and facts.buyer_ref == data["buyer_ref"] and parsed(facts.occurred_at) >= parsed(data["delivered_at"]), "CASE_MISSING", "the buyer dispute must bind a current intake case")
            data["dispute_case_ref"] = facts.case_ref
        elif event == "resolve":
            _require(facts.resolution is not None and facts.disposition == "resolved" and facts.case_ref == data["dispute_case_ref"] and facts.reviewer_ref is not None and facts.reviewer_ref != command.actor_ref, "RESOLUTION_MISSING", "resolution requires the independently reviewed case")
            allowed = {"no_refund": {"release_to_seller"}, "full_refund": {"release_to_seller", "refund_buyer"}, "partial_refund": {"release_to_seller", "partial_refund"}, "case_by_case": {"release_to_seller", "refund_buyer", "partial_refund"}}[bp.refund_policy]
            _require(facts.resolution in allowed, "REFUND_POLICY_VIOLATION", "the case resolution is outside the refund policy")
            refund = Decimal("0.00") if facts.resolution == "release_to_seller" else Decimal(data["gross"]) if facts.resolution == "refund_buyer" else facts.refund_amount
            _require(refund is not None and (facts.resolution != "partial_refund" or Decimal("0.00") < refund < Decimal(data["gross"])), "REFUND_AMOUNT_INVALID", "partial refunds must fall strictly inside the funded gross")
            if refund > 0:
                _refund(plan, data, r.execution, refund, at)
            _allocation(data, refund, at, bp.payout_delay_days)
            data.update(resolution=facts.resolution, outcome={"release_to_seller": "completed", "refund_buyer": "refunded", "partial_refund": "partially_refunded"}[facts.resolution])
        elif event == "settle":
            _require(parsed(at) >= parsed(data["payout_available_at"]), "PAYOUT_NOT_AVAILABLE", "settlement allocation remains inside the payout hold period")
            expected = Decimal(data["gross"]) - Decimal(data["refund_amount"])
            _require(facts.disposition == "settled" and facts.settlement_ref is not None and facts.amount == expected and facts.payment_ref == data["payment_ref"] and facts.correlation_ref == data["correlation_ref"], "SETTLEMENT_MISMATCH", "cash settlement must match the funded payment, refunds and correlation")
            _require(parsed(facts.occurred_at) >= parsed(data["payout_available_at"]), "PAYOUT_NOT_AVAILABLE", "provider settlement precedes the allocation hold release")
            _require(expected == Decimal(data["seller_liability"]) + Decimal(data["company_take_revenue"]), "SETTLEMENT_MISMATCH", "settled cash must conserve company revenue and seller liability")
            data.update(cash_settled=expected, settled_at=facts.occurred_at, settlement_ref=facts.settlement_ref)
        elif event == "close":
            data.update(buyer_rating=facts.buyer_rating, seller_rating=facts.seller_rating)
        elif event == "cancel":
            refund = Decimal(data["funded_amount"])
            if refund > 0:
                _refund(plan, data, r.execution, refund, at)
            data.update(refund_amount=refund, seller_liability=Decimal("0.00"), company_take_revenue=Decimal("0.00"), outcome="cancelled")
        if event in {"match", "start_fulfilment", "close", "cancel"}:
            _require(facts.disposition == "recorded", "SOURCE_NOT_EVIDENCED", "the observed business event is not recorded")
        _chronology(data, facts, at)
        if evidence is not None:
            _remember(data, evidence)
    except MarketplaceSupplyError as exc:
        raise Rejected(exc.code, exc.message, "correct_input") from exc
    return nxt, data


class _SupplyLifecycle(LifecycleSpec):
    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.register_scope is None or not _scope_equal(self.scope, self.ledger.register_scope):
                    raise ValueError("SCOPE_MISMATCH: replayed opening scope must equal state scope")
                return self
        ScopedState.__name__ = self.State.__name__
        self.State = ScopedState


def _lifecycle(kind: str, apply: Any) -> LifecycleSpec:
    return _SupplyLifecycle(entity=kind, schema_prefix="marketplace_supply_" + kind, statuses=tuple(sorted(canonical._STATUSES[kind])), terminal=canonical.TERMINAL_STATUSES[kind], events=tuple(sorted(canonical._EVENTS[kind])), table=dict(canonical._TABLES[kind]), opening_event=canonical._OPENING_EVENT[kind], reason_events=tuple(canonical._REASON_EVENTS & canonical._EVENTS[kind]), apply=apply, ledger_model=SupplyLedger, receipt_model=SupplyReceipt, effect_boundary_model=MarketplaceEffectBoundary, plan_model=MarketplaceSupplyPlan, max_transitions=80)


SELLER_LIFECYCLE = _lifecycle("seller", _apply_seller)
LISTING_LIFECYCLE = _lifecycle("listing", _apply_listing)
TRANSACTION_LIFECYCLE = _lifecycle("transaction", _apply_transaction)
SellerState, ListingState, TransactionState = SELLER_LIFECYCLE.State, LISTING_LIFECYCLE.State, TRANSACTION_LIFECYCLE.State


def _spec(kind: str) -> LifecycleSpec:
    return {"seller": SELLER_LIFECYCLE, "listing": LISTING_LIFECYCLE, "transaction": TRANSACTION_LIFECYCLE}[kind]


def _open(kind: str, plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    scope = _parse(EngineScope, scope, "SCOPE_MISMATCH")
    return _spec(kind).open(plan, scope, receipt={**detached(receipt), "register_scope": scope.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def open_seller(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    return _open("seller", plan, scope, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref)


def open_listing(plan: Any, scope: Any, *, receipt: Any, seller: Any, capacity: Any, opened_at: str, actor_ref: str) -> Any:
    source = marketplace_source(seller, source_plan=plan, kind="seller")
    return _open("listing", plan, scope, receipt={**detached(receipt), "seller_source": source.to_dict(), "capacity": _parse(MarketplaceObservation, capacity).to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def open_transaction(plan: Any, scope: Any, *, receipt: Any, listing: Any, seller: Any, opened_at: str, actor_ref: str) -> Any:
    listing_source = marketplace_source(listing, source_plan=plan, kind="listing")
    seller_source = marketplace_source(seller, source_plan=plan, kind="seller")
    return _open("transaction", plan, scope, receipt={**detached(receipt), "listing_source": listing_source.to_dict(), "seller_source": seller_source.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_seller(plan: Any, state: Any, command: Any) -> Any:
    return SELLER_LIFECYCLE.advance(plan, state, command)


def advance_listing(plan: Any, state: Any, command: Any) -> Any:
    return LISTING_LIFECYCLE.advance(plan, state, command)


def advance_transaction(plan: Any, state: Any, command: Any) -> Any:
    return TRANSACTION_LIFECYCLE.advance(plan, state, command)


class MarketplaceSettlement(StrictModel):
    schema_id: Literal["lightbulb.marketplace_settlement.v1"] = Field(default="lightbulb.marketplace_settlement.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    scope: EngineScope
    transaction_ref: OpaqueRef
    seller_ref: OpaqueRef
    buyer_ref: OpaqueRef
    payout_account_ref: OpaqueRef
    payment_ref: OpaqueRef
    settlement_ref: OpaqueRef
    correlation_ref: OpaqueRef
    gross: Decimal
    refund_amount: Decimal
    cash_settled: Decimal
    seller_liability: Decimal
    company_take_revenue: Decimal
    settled_at: str
    payout_available_at: str
    source: MarketplaceSource
    source_digest: Sha256Digest
    settlement_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("gross", "refund_amount", "cash_settled", "seller_liability", "company_take_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("settled_at", "payout_available_at")
    @classmethod
    def _at(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MarketplaceSettlement:
        state = verify_settled_transaction(self.source.state, source_plan=self.source.source_plan, company_ref=self.company_ref, currency=self.currency, expected_scope=self.scope)
        expected = _settlement_fields(state, self.source.source_plan)
        if any(detached(getattr(self, key)) != detached(value) for key, value in expected.items()):
            raise ValueError("settlement fields must be derived from the replayed transaction")
        if self.source.kind != "transaction":
            raise ValueError("settlement must retain a transaction source")
        if not skip_digests(info) and self.settlement_digest != sealed_digest(MarketplaceSettlement, self, "settlement_digest"):
            raise ValueError("settlement_digest must commit the derived ownership allocation")
        return self


def verify_settled_transaction(state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    source = marketplace_source(state, source_plan=source_plan, kind="transaction")
    plan, proven = TRANSACTION_LIFECYCLE.bind(source.source_plan, source.state)
    _require(proven.status in {"settled", "closed"} and proven.ledger.settled_at is not None, "TRANSACTION_NOT_SETTLED", "seller liabilities require a settled transaction")
    _require((company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency), "SCOPE_MISMATCH", "settlement belongs to another company or currency")
    _require(expected_scope is None or _scope_equal(expected_scope, proven.scope, entity=False), "SCOPE_MISMATCH", "settlement belongs to another authenticated scope")
    if at is not None:
        _require(parsed(proven.transition_history[-1].command.occurred_at) <= parsed(timestamp(at, field_name="at")), "SOURCE_FROM_FUTURE", "settlement state cannot come from the future")
    _require(proven.ledger.cash_settled == proven.ledger.gross - proven.ledger.refund_amount == proven.ledger.seller_liability + proven.ledger.company_take_revenue, "SETTLEMENT_MISMATCH", "settled cash must conserve seller and company ownership")
    return proven


def _settlement_fields(state: Any, plan: MarketplaceSupplyPlan) -> dict[str, Any]:
    keys = ("seller_ref", "buyer_ref", "payout_account_ref", "payment_ref", "settlement_ref", "correlation_ref", "gross", "refund_amount", "cash_settled", "seller_liability", "company_take_revenue", "settled_at", "payout_available_at")
    return {"company_ref": plan.company_ref, "currency": plan.currency, "scope": state.scope, "transaction_ref": state.scope.entity_ref, "source_digest": state.state_digest, **{key: getattr(state.ledger, key) for key in keys}}


def transaction_settlement(state: Any, *, source_plan: Any) -> MarketplaceSettlement:
    source = marketplace_source(state, source_plan=source_plan, kind="transaction")
    proven = verify_settled_transaction(source.state, source_plan=source.source_plan)
    return seal(MarketplaceSettlement, {**_settlement_fields(proven, source.source_plan), "source": source}, "settlement_digest")


def period_evidence_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.company_operating_system import PeriodReceipt
    settlement = transaction_settlement(state, source_plan=source_plan)
    source_digests = list(dict.fromkeys([settlement.source_digest, *settlement.source.state["ledger"]["source_digests"]]))
    return PeriodReceipt.model_validate({"engine": MARKETPLACE_SUPPLY_KIND, "entity_ref": settlement.transaction_ref, "spend": "0.00", "revenue": str(settlement.company_take_revenue), "revenue_only": True, "evidence_ref": f"marketplace:{settlement.source_digest[:24]}", "source_kind": MARKETPLACE_SUPPLY_KIND, "source_digest": settlement.source_digest, "source_digests": source_digests}).to_dict()


def marketplace_summary(state: Any, *, source_plan: Any, kind: str) -> dict[str, Any]:
    source = marketplace_source(state, source_plan=source_plan, kind=kind)
    return {"kind": kind, "status": source.state["status"], "entity_ref": source.state["scope"]["entity_ref"], "state_digest": source.state["state_digest"], **source.state["ledger"]}


MARKETPLACE_SUPPLY_MANIFEST = {
    "schema": "lightbulb.company_engine_manifest.v1", "engine": MARKETPLACE_SUPPLY_KIND, "golden_loop": MARKETPLACE_SUPPLY_GOLDEN_LOOP,
    "stages": list(canonical.STAGE_ORDER), "statuses": list(dict.fromkeys(SELLER_STATUSES + LISTING_STATUSES + TRANSACTION_STATUSES)), "events": list(dict.fromkeys(SELLER_EVENTS + LISTING_EVENTS + TRANSACTION_EVENTS)),
    "hops": {"settled": "payout_chain.accrue / custodial_funds.record_liability", "company_take": "company_cost_centres / company_operating_system.record_evidence"},
    "required_connectors": ["stripe.list_charges", "stripe.list_payouts", "stripe.create_refund", "shopify.publish_product", "shopify.update_product"],
    "hard_rules": ["GMV and unpaid seller balances are never company revenue", "seller and listing sources replay against retained plans", "settlement does not authorize or confirm a seller payout"],
}

__all__ = ["MARKETPLACE_SUPPLY_KIND", "MARKETPLACE_SUPPLY_GOLDEN_LOOP", "MARKETPLACE_SUPPLY_PLAN_SCHEMA", "MARKETPLACE_SUPPLY_PROFILES", "MARKETPLACE_SUPPLY_CODES", "MARKETPLACE_SUPPLY_MANIFEST", "SELLER_STATUSES", "LISTING_STATUSES", "TRANSACTION_STATUSES", "SELLER_EVENTS", "LISTING_EVENTS", "TRANSACTION_EVENTS", "MarketplaceSupplyError", "MarketplaceSupplyPlan", "MarketplaceFacts", "MarketplaceObservation", "MarketplaceExecution", "MarketplaceSource", "MarketplaceSettlement", "MarketplaceEffectBoundary", "SupplyReceipt", "SupplyLedger", "SellerState", "ListingState", "TransactionState", "SELLER_LIFECYCLE", "LISTING_LIFECYCLE", "TRANSACTION_LIFECYCLE", "compile_marketplace_supply_engine", "marketplace_observation", "marketplace_execution", "observation_receipt", "execution_receipt", "marketplace_source", "open_seller", "open_listing", "open_transaction", "advance_seller", "advance_listing", "advance_transaction", "verify_settled_transaction", "transaction_settlement", "period_evidence_receipt", "marketplace_summary"]
