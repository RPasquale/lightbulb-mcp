"""Subscription Business Golden Operating Loop and Company Blueprint profiles.

Recurring-revenue businesses (SaaS, memberships, subscription boxes, sales-led
enterprise subscriptions) share one loop::

    Acquire -> Trial -> Activate -> Bill -> Collect -> Serve
            -> Retain (dunning, pause, save offers) -> Expand (plan change, usage)
            -> Renew -> Learn (MRR, churn, NRR, LTV)

The commercial lifecycle on ``main`` already types subscription activation,
recurring and usage billing proposals, and renewal preparation
(``commercial.propose_operations_transition``); this pack composes them into a
per-account lifecycle with the branches every subscription business hits:
trials that convert or lapse, failed payments and a finite dunning schedule,
pauses, upgrades and downgrades with deterministic proration, usage overage,
cancellation at period end with bounded save offers, renewal, and involuntary
expiry.  Portfolio assessment derives MRR, ARR, gross churn, net revenue
retention, trial conversion, ARPA, and LTV from account ledgers.

Nothing here charges a card, sends a reminder, grants a discount, or changes
a provider subscription; those are Spring-authorized effects executed by the
bound primitives and connectors (``finance.create_invoice``,
``finance.collect_payment``, ``finance.reconcile_stripe_settlements``,
``communication.write_email``).
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


SUBSCRIPTION_BUSINESS_GOLDEN_LOOP = "subscription.trial_to_renewal_business@0.1.0"
SUBSCRIPTION_BUSINESS_ARCHETYPE = "subscription_business"
BLUEPRINT_SCHEMA = "lightbulb.subscription_business_blueprint.v1"
PLAN_SCHEMA = "lightbulb.subscription_business_loop_plan.v1"
ACCOUNT_COMMAND_SCHEMA = "lightbulb.subscription_account_command.v1"
ACCOUNT_STATE_SCHEMA = "lightbulb.subscription_account_state.v1"
ACCOUNT_RESULT_SCHEMA = "lightbulb.subscription_account_transition_result.v1"
PRORATION_SCHEMA = "lightbulb.subscription_proration_candidate.v1"
PORTFOLIO_SCHEMA = "lightbulb.subscription_portfolio_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_ACCOUNT_TRANSITIONS = 400

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id", "card_number", "cvc")
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

BlueprintProfile = Literal["saas_self_serve", "saas_sales_led", "membership", "subscription_box", "custom"]
BillingInterval = Literal["monthly", "quarterly", "annual"]
BillingModel = Literal["flat", "seat", "usage", "hybrid"]
PaymentMethod = Literal["card", "invoice", "direct_debit"]
AccountStatus = Literal["lead", "trialing", "active", "past_due", "paused", "cancel_scheduled", "cancelled", "expired"]
TERMINAL_ACCOUNT_STATUSES: frozenset[str] = frozenset({"cancelled", "expired"})
AccountEvent = Literal["start_trial", "convert_trial", "activate", "bill", "record_payment", "payment_failed", "retry_payment", "pause", "resume", "change_plan", "record_usage", "request_cancel", "save", "cancel", "renew", "expire"]
LoopStage = Literal["acquire", "trial", "activate", "bill", "collect", "serve", "retain", "expand", "renew", "learn"]
STAGE_ORDER: tuple[str, ...] = ("acquire", "trial", "activate", "bill", "collect", "serve", "retain", "expand", "renew", "learn")
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]
_MONTHS_PER_INTERVAL: dict[str, Decimal] = {"monthly": Decimal(1), "quarterly": Decimal(3), "annual": Decimal(12)}
_TABLE: dict[tuple[str, str], str] = {
    ("lead", "start_trial"): "trialing", ("lead", "activate"): "active",
    ("trialing", "convert_trial"): "active", ("trialing", "expire"): "expired", ("trialing", "cancel"): "cancelled",
    ("active", "bill"): "active", ("active", "record_payment"): "active", ("active", "payment_failed"): "past_due", ("active", "pause"): "paused", ("active", "change_plan"): "active", ("active", "record_usage"): "active", ("active", "request_cancel"): "cancel_scheduled", ("active", "renew"): "active", ("active", "expire"): "expired",
    ("past_due", "retry_payment"): "past_due", ("past_due", "record_payment"): "active", ("past_due", "request_cancel"): "cancel_scheduled", ("past_due", "cancel"): "cancelled", ("past_due", "expire"): "expired",
    ("paused", "resume"): "active", ("paused", "request_cancel"): "cancel_scheduled", ("paused", "expire"): "expired",
    ("cancel_scheduled", "save"): "active", ("cancel_scheduled", "cancel"): "cancelled", ("cancel_scheduled", "bill"): "cancel_scheduled", ("cancel_scheduled", "record_payment"): "cancel_scheduled",
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_subscription_business", "subscription.advance_account", "subscription.prorate_plan_change", "subscription.assess_portfolio",
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead", "communication.plan_crm_conversation_turn", "communication.write_email",
        "commercial.evaluate_quote_order_contract_controls", "commercial.propose_operations_transition", "finance.create_invoice", "finance.collect_payment",
        "finance.reconcile_stripe_settlements", "finance.discover_stripe_settlement_movements", "accounting.assess_receivables", "service.intake_and_classify_case", "service.verify_case_resolution",
        "growth.review_customer_value", "growth.build_customer_value", "growth.plan_price_move", "growth.build_unit_economics", "growth.review_profit", "learning.plan_optimization_sweep",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset({"stripe.create_invoice", "stripe.list_invoices", "stripe.list_charges", "stripe.create_refund", "stripe.list_customers", "stripe.list_balance_transactions", "hubspot.create_workflow", "xero.create_invoice", "xero.create_payment"})


# --------------------------------------------------------------------------- #
# Strict model and helpers
# --------------------------------------------------------------------------- #


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like or card-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential-, card-, or identity-like field and is never accepted")
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
    return bool((info.context or {}).get("skip_subscription_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_subscription_digests": True})
    return _stable_digest({key: value for key, value in parsed.to_dict().items() if key != field})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def monthly_recurring(price: Decimal, seats: int, interval: str, discount_percent: Decimal) -> Decimal:
    """Monthly-normalized recurring revenue for one account."""

    gross = (price * Decimal(max(seats, 1)) / _MONTHS_PER_INTERVAL[interval])
    return (gross * (Decimal(100) - discount_percent) / Decimal(100)).quantize(_MONEY_QUANTUM)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class SubscriptionBusinessBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.subscription_business_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    billing_interval: BillingInterval
    billing_model: BillingModel
    payment_method: PaymentMethod
    trial_days: int = Field(default=0, ge=0, le=365)
    trial_requires_payment_method: bool = False
    pause_allowed: bool = False
    max_pause_days: int = Field(default=0, ge=0, le=365)
    cancel_at_period_end: bool = True
    dunning_retry_days: tuple[int, ...] = Field(default=(3, 5, 7), max_length=8)
    grace_period_days: int = Field(default=14, ge=0, le=120)
    proration_on_plan_change: bool = True
    save_offer_max_discount_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    max_save_offers: int = Field(default=1, ge=0, le=5)
    renewal_notice_days: int = Field(default=30, ge=0, le=180)
    target_monthly_gross_churn_percent: Decimal = Field(default=Decimal("3"), validate_default=True)
    min_trial_conversion_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    min_net_revenue_retention_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("save_offer_max_discount_percent", "target_monthly_gross_churn_percent", "min_trial_conversion_percent", "min_net_revenue_retention_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name))
        if parsed > Decimal(1000):
            raise ValueError(f"{info.field_name} is out of range")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "SubscriptionBusinessBlueprint":
        days = list(self.dunning_retry_days)
        if any(day < 1 for day in days) or days != sorted(days) or len(set(days)) != len(days):
            raise ValueError("dunning retry days must be positive and strictly increasing")
        if days and self.grace_period_days < days[-1]:
            raise ValueError("the grace period must cover the last dunning retry")
        if self.pause_allowed != (self.max_pause_days > 0):
            raise ValueError("pause_allowed and max_pause_days must agree")
        if self.trial_requires_payment_method and self.trial_days == 0:
            raise ValueError("a trial payment-method requirement needs a trial")
        if self.max_save_offers == 0 and self.save_offer_max_discount_percent > 0:
            raise ValueError("no save offers means no save discount")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(SubscriptionBusinessBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self


def seal_subscription_business_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(SubscriptionBusinessBlueprint, raw, "blueprint_digest")
    return SubscriptionBusinessBlueprint.model_validate(raw).to_dict()


SUBSCRIPTION_BUSINESS_PROFILES: dict[str, dict[str, Any]] = {
    "saas_self_serve": {"profile": "saas_self_serve", "name": "Self-serve SaaS", "billing_interval": "monthly", "billing_model": "seat", "payment_method": "card", "trial_days": 14, "trial_requires_payment_method": False, "pause_allowed": False, "max_pause_days": 0, "cancel_at_period_end": True, "dunning_retry_days": [3, 5, 7], "grace_period_days": 14, "proration_on_plan_change": True, "save_offer_max_discount_percent": "20", "max_save_offers": 1, "renewal_notice_days": 0, "target_monthly_gross_churn_percent": "3", "min_trial_conversion_percent": "15", "min_net_revenue_retention_percent": "100", "notes": "Card-billed monthly seats with a free trial, smart-retry dunning, and one save offer at cancellation."},
    "saas_sales_led": {"profile": "saas_sales_led", "name": "Sales-led SaaS", "billing_interval": "annual", "billing_model": "hybrid", "payment_method": "invoice", "trial_days": 0, "trial_requires_payment_method": False, "pause_allowed": False, "max_pause_days": 0, "cancel_at_period_end": True, "dunning_retry_days": [7, 21, 45], "grace_period_days": 60, "proration_on_plan_change": True, "save_offer_max_discount_percent": "10", "max_save_offers": 2, "renewal_notice_days": 60, "target_monthly_gross_churn_percent": "1", "min_trial_conversion_percent": "0", "min_net_revenue_retention_percent": "110", "notes": "Annual invoiced contracts with usage overage, notice-based renewal, and a save desk."},
    "membership": {"profile": "membership", "name": "Membership (gym, club, community)", "billing_interval": "monthly", "billing_model": "flat", "payment_method": "direct_debit", "trial_days": 7, "trial_requires_payment_method": True, "pause_allowed": True, "max_pause_days": 60, "cancel_at_period_end": True, "dunning_retry_days": [3, 7], "grace_period_days": 21, "proration_on_plan_change": False, "save_offer_max_discount_percent": "25", "max_save_offers": 1, "renewal_notice_days": 0, "target_monthly_gross_churn_percent": "4", "min_trial_conversion_percent": "40", "min_net_revenue_retention_percent": "95", "notes": "Flat monthly membership with freezes, a paid-method trial, and direct-debit dunning."},
    "subscription_box": {"profile": "subscription_box", "name": "Subscription box", "billing_interval": "monthly", "billing_model": "flat", "payment_method": "card", "trial_days": 0, "trial_requires_payment_method": False, "pause_allowed": True, "max_pause_days": 90, "cancel_at_period_end": True, "dunning_retry_days": [2, 4, 8], "grace_period_days": 10, "proration_on_plan_change": False, "save_offer_max_discount_percent": "30", "max_save_offers": 2, "renewal_notice_days": 0, "target_monthly_gross_churn_percent": "8", "min_trial_conversion_percent": "0", "min_net_revenue_retention_percent": "90", "notes": "Recurring physical shipments with skips, short dunning, and two win-back offers."},
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    account_events: tuple[AccountEvent, ...] = Field(default_factory=tuple, max_length=8)
    gate: Literal["none", "spring_approval", "customer_consent"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class SubscriptionBusinessLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.subscription_business_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["subscription.trial_to_renewal_business@0.1.0"] = SUBSCRIPTION_BUSINESS_GOLDEN_LOOP
    archetype: Literal["subscription_business"] = SUBSCRIPTION_BUSINESS_ARCHETYPE
    blueprint: SubscriptionBusinessBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=10, max_length=10)
    composed_golden_loops: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "SubscriptionBusinessLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(SubscriptionBusinessLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _billing_tools(blueprint: SubscriptionBusinessBlueprint) -> tuple[str, ...]:
    return ("stripe.create_invoice", "stripe.list_invoices") if blueprint.payment_method == "card" else ("xero.create_invoice",)


def _collect_tools(blueprint: SubscriptionBusinessBlueprint) -> tuple[str, ...]:
    return ("stripe.list_charges", "stripe.list_balance_transactions") if blueprint.payment_method == "card" else ("xero.create_payment",)


def _stage_bindings(blueprint: SubscriptionBusinessBlueprint) -> list[dict[str, Any]]:
    trial_refs: tuple[str, ...] = ("crm.qualify_lead", "communication.plan_crm_conversation_turn") if blueprint.trial_days else ("crm.qualify_lead", "commercial.evaluate_quote_order_contract_controls")
    usage_refs: tuple[str, ...] = ("commercial.propose_operations_transition",) if blueprint.billing_model in {"usage", "hybrid"} else ()
    return [
        {"stage": "acquire", "title": "Acquire demand", "primitive_refs": ("demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead"), "gate": "none"},
        {"stage": "trial", "title": "Trial" if blueprint.trial_days else "Evaluate", "primitive_refs": trial_refs, "account_events": ("start_trial", "convert_trial", "expire"), "gate": "customer_consent" if blueprint.trial_requires_payment_method else "none"},
        {"stage": "activate", "title": "Activate the subscription", "primitive_refs": ("commercial.propose_operations_transition",), "account_events": ("activate", "convert_trial"), "gate": "spring_approval"},
        {"stage": "bill", "title": f"Bill ({blueprint.billing_interval}, {blueprint.billing_model})", "primitive_refs": ("commercial.propose_operations_transition", "finance.create_invoice"), "connector_tools": _billing_tools(blueprint), "account_events": ("bill", "record_usage"), "gate": "spring_approval"},
        {"stage": "collect", "title": "Collect and recover failed payments", "primitive_refs": ("finance.collect_payment", "finance.reconcile_stripe_settlements", "communication.write_email", "accounting.assess_receivables"), "connector_tools": _collect_tools(blueprint), "account_events": ("record_payment", "payment_failed", "retry_payment", "expire"), "gate": "spring_approval"},
        {"stage": "serve", "title": "Serve and support", "primitive_refs": ("service.intake_and_classify_case", "service.verify_case_resolution"), "account_events": ("pause", "resume") if blueprint.pause_allowed else (), "gate": "none"},
        {"stage": "retain", "title": "Retain: cancellation, save offers", "primitive_refs": ("growth.review_customer_value", "communication.write_email"), "account_events": ("request_cancel", "save", "cancel"), "gate": "spring_approval"},
        {"stage": "expand", "title": "Expand: plan changes and usage", "primitive_refs": ("subscription.prorate_plan_change", "growth.plan_price_move") + usage_refs, "account_events": ("change_plan", "record_usage"), "gate": "spring_approval"},
        {"stage": "renew", "title": "Renew", "primitive_refs": ("commercial.propose_operations_transition", "communication.write_email"), "account_events": ("renew", "expire"), "gate": "spring_approval"},
        {"stage": "learn", "title": "Learn: MRR, churn, NRR, LTV", "primitive_refs": ("subscription.assess_portfolio", "growth.build_customer_value", "growth.build_unit_economics", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_subscription_business_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> SubscriptionBusinessLoopPlan:
    if isinstance(profile, str):
        if profile not in SUBSCRIPTION_BUSINESS_PROFILES:
            raise ValueError(f"unknown subscription business profile {profile!r}; choose one of {sorted(SUBSCRIPTION_BUSINESS_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(SUBSCRIPTION_BUSINESS_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = SubscriptionBusinessBlueprint.model_validate(seal_subscription_business_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint), "composed_golden_loops": ["commercial.operations_lifecycle (activate_subscription, propose_recurring_billing, propose_usage_billing, prepare_renewal)"]}
    payload["plan_digest"] = _sealed_digest(SubscriptionBusinessLoopPlan, payload, "plan_digest")
    return SubscriptionBusinessLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Proration
# --------------------------------------------------------------------------- #


class ProrationCandidate(_StrictModel):
    schema_id: Literal["lightbulb.subscription_proration_candidate.v1"] = Field(default=PRORATION_SCHEMA, alias="schema")
    old_plan_ref: OpaqueRef
    new_plan_ref: OpaqueRef
    old_period_amount: Decimal
    new_period_amount: Decimal
    period_start: str
    period_end: str
    change_at: str
    unused_fraction: Decimal
    credit_for_unused: Decimal
    charge_for_remaining: Decimal
    net_amount: Decimal
    direction: Literal["upgrade", "downgrade", "lateral"]
    currency: CurrencyCode
    proration_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("old_period_amount", "new_period_amount", "credit_for_unused", "charge_for_remaining", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("net_amount", mode="before")
    @classmethod
    def _net(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="net_amount", allow_negative=True)

    @field_validator("unused_fraction", mode="before")
    @classmethod
    def _fraction(cls, value: Any) -> Decimal:
        parsed = Decimal(str(value))
        if parsed < 0 or parsed > 1:
            raise ValueError("unused_fraction must be between 0 and 1")
        return parsed.quantize(Decimal("0.000001"))

    @model_validator(mode="after")
    def _proration_is_exact(self, info: ValidationInfo) -> "ProrationCandidate":
        if _skip(info):
            return self
        if self.proration_digest != _sealed_digest(ProrationCandidate, self, "proration_digest"):
            raise ValueError("proration_digest must commit the exact proration")
        return self


def prorate_plan_change(*, old_plan_ref: str, new_plan_ref: str, old_price: Any, new_price: Any, old_seats: int, new_seats: int, period_start: str, period_end: str, change_at: str, currency: str) -> ProrationCandidate:
    """Deterministic mid-period proration: credit the unused old amount, charge the remaining new amount."""

    start, end, at = _parsed(_timestamp(period_start, field_name="period_start")), _parsed(_timestamp(period_end, field_name="period_end")), _parsed(_timestamp(change_at, field_name="change_at"))
    if end <= start:
        raise ValueError("the period must end after it starts")
    if at < start or at > end:
        raise ValueError("the change must fall inside the period")
    old_amount = _decimal(old_price, field_name="old_price") * Decimal(max(old_seats, 1))
    new_amount = _decimal(new_price, field_name="new_price") * Decimal(max(new_seats, 1))
    total_seconds = Decimal((end - start).total_seconds())
    unused = (Decimal((end - at).total_seconds()) / total_seconds).quantize(Decimal("0.000001"))
    credit = (old_amount * unused).quantize(_MONEY_QUANTUM)
    charge = (new_amount * unused).quantize(_MONEY_QUANTUM)
    direction = "upgrade" if new_amount > old_amount else ("downgrade" if new_amount < old_amount else "lateral")
    payload = {"old_plan_ref": old_plan_ref, "new_plan_ref": new_plan_ref, "old_period_amount": str(old_amount.quantize(_MONEY_QUANTUM)), "new_period_amount": str(new_amount.quantize(_MONEY_QUANTUM)), "period_start": _iso(start), "period_end": _iso(end), "change_at": _iso(at), "unused_fraction": str(unused), "credit_for_unused": str(credit), "charge_for_remaining": str(charge), "net_amount": str((charge - credit).quantize(_MONEY_QUANTUM)), "direction": direction, "currency": currency}
    payload["proration_digest"] = _sealed_digest(ProrationCandidate, payload, "proration_digest")
    return ProrationCandidate.model_validate(payload)


# --------------------------------------------------------------------------- #
# Account lifecycle
# --------------------------------------------------------------------------- #


class SubscriptionScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    account_ref: OpaqueRef
    customer_ref: OpaqueRef
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


class AccountReceipt(_StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    plan_ref: OpaqueRef | None = None
    plan_price: Decimal | None = None
    seats: int | None = Field(default=None, ge=1, le=100_000)
    payment_method_on_file: bool | None = None
    term_start: str | None = None
    term_end: str | None = None
    subscription_snapshot_digest: Sha256Digest | None = None
    subscription_status: Literal["pending", "provisioning", "active", "suspended", "cancelled", "expired"] | None = None
    billing_proposal_digest: Sha256Digest | None = None
    invoice_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    payment_ref: OpaqueRef | None = None
    failure_code: ShortText | None = None
    pause_days: int | None = Field(default=None, ge=1, le=365)
    new_plan_ref: OpaqueRef | None = None
    new_plan_price: Decimal | None = None
    new_seats: int | None = Field(default=None, ge=1, le=100_000)
    proration_digest: Sha256Digest | None = None
    usage_billing_digest: Sha256Digest | None = None
    usage_total: Decimal | None = None
    cancel_reason: ShortText | None = None
    save_offer_ref: OpaqueRef | None = None
    discount_percent: Decimal | None = None
    renewal_snapshot_digest: Sha256Digest | None = None
    renewal_status: Literal["not_due", "planned", "pending_review", "approved", "renewed", "declined"] | None = None
    renewal_total: Decimal | None = None

    @field_validator("plan_price", "amount", "new_plan_price", "usage_total", "discount_percent", "renewal_total", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("term_start", "term_end")
    @classmethod
    def _terms(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else _timestamp(value, field_name=str(info.field_name))


class SubscriptionAccountCommand(_StrictModel):
    schema_id: Literal["lightbulb.subscription_account_command.v1"] = Field(default=ACCOUNT_COMMAND_SCHEMA, alias="schema")
    event: AccountEvent
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_ACCOUNT_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: AccountReceipt = Field(default_factory=AccountReceipt)
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "SubscriptionAccountCommand":
        if self.event in {"cancel", "expire"} and self.reason is None:
            raise ValueError(f"{self.event} requires a reason")
        if _skip(info):
            return self
        if self.request_digest != account_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def account_command_digest(command: SubscriptionAccountCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(SubscriptionAccountCommand, command, "request_digest")


def seal_account_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = account_command_digest(raw)
    return SubscriptionAccountCommand.model_validate(raw).to_dict()


class AccountLedger(_StrictModel):
    plan_ref: OpaqueRef | None = None
    plan_price: Decimal = Field(default=Decimal("0"), validate_default=True)
    seats: int = Field(default=1, ge=1)
    discount_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    starting_mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    trial_end: str | None = None
    converted_from_trial: bool | None = None
    term_start: str | None = None
    term_end: str | None = None
    terms_completed: int = Field(default=0, ge=0)
    invoiced_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    open_invoice_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    open_invoice_ref: OpaqueRef | None = None
    pending_usage_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    first_failure_at: str | None = None
    dunning_retries_used: int = Field(default=0, ge=0)
    pause_days_used: int = Field(default=0, ge=0)
    paused_at: str | None = None
    save_offers_used: int = Field(default=0, ge=0)
    cancel_reason: ShortText | None = None
    cancel_effective_at: str | None = None
    expansion_mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    contraction_mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    subscription_snapshot_digest: Sha256Digest | None = None
    renewal_snapshot_digest: Sha256Digest | None = None

    @field_validator("plan_price", "discount_percent", "starting_mrr", "invoiced_total", "paid_total", "open_invoice_amount", "pending_usage_total", "expansion_mrr", "contraction_mrr", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class AccountTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_ACCOUNT_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: AccountStatus
    transition_digest: Sha256Digest
    command: SubscriptionAccountCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "AccountTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: SubscriptionAccountCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, scope: SubscriptionScope, history: Sequence[AccountTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


def genesis_account_state_digest(plan_digest: str, scope: SubscriptionScope | Mapping[str, Any]) -> str:
    return _state_digest(plan_digest, SubscriptionScope.model_validate(_detached(scope)), ())


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _expected_bill(blueprint: SubscriptionBusinessBlueprint, ledger: AccountLedger) -> Decimal:
    recurring = ledger.plan_price * Decimal(ledger.seats if blueprint.billing_model in {"seat", "hybrid"} else 1)
    discounted = (recurring * (Decimal(100) - ledger.discount_percent) / Decimal(100)).quantize(_MONEY_QUANTUM)
    return (discounted + ledger.pending_usage_total).quantize(_MONEY_QUANTUM)


def _mrr(blueprint: SubscriptionBusinessBlueprint, ledger: AccountLedger) -> Decimal:
    return monthly_recurring(ledger.plan_price, ledger.seats if blueprint.billing_model in {"seat", "hybrid"} else 1, blueprint.billing_interval, ledger.discount_percent)


def _activate(blueprint: SubscriptionBusinessBlueprint, data: dict[str, Any], r: AccountReceipt, *, from_trial: bool) -> None:
    if r.plan_ref is None or r.plan_price is None or r.plan_price <= 0 or r.term_start is None or r.term_end is None:
        raise _Rejected("PLAN_MISSING", "activation links the plan, a positive price, and the term", "correct_input")
    if r.subscription_snapshot_digest is None or r.subscription_status != "active":
        raise _Rejected("SUBSCRIPTION_NOT_ACTIVE", "activation links an active commercial subscription snapshot (commercial.propose_operations_transition activate_subscription)", "correct_input")
    if _parsed(r.term_end) <= _parsed(r.term_start):
        raise _Rejected("TERM_INVALID", "the term must end after it starts", "correct_input")
    if blueprint.billing_model in {"seat", "hybrid"} and r.seats is None:
        raise _Rejected("SEATS_MISSING", "seat-based billing needs the seat count", "correct_input")
    data.update({"plan_ref": r.plan_ref, "plan_price": str(r.plan_price), "seats": r.seats or 1, "term_start": r.term_start, "term_end": r.term_end, "subscription_snapshot_digest": r.subscription_snapshot_digest, "converted_from_trial": from_trial})
    data["starting_mrr"] = str(monthly_recurring(r.plan_price, (r.seats or 1) if blueprint.billing_model in {"seat", "hybrid"} else 1, blueprint.billing_interval, Decimal("0")))


def _apply(plan: SubscriptionBusinessLoopPlan, status: str, ledger: AccountLedger, command: SubscriptionAccountCommand) -> tuple[str, AccountLedger]:
    if status in TERMINAL_ACCOUNT_STATUSES:
        raise _Rejected("ACCOUNT_TERMINAL", f"account is {status}; no further transitions", "do_not_replay")
    event = command.event
    next_status = _TABLE.get((status, event))
    if next_status is None:
        raise _Rejected("ILLEGAL_TRANSITION", f"{event} is not a legal transition from {status}", "correct_input")
    blueprint = plan.blueprint
    r = command.receipt
    data = ledger.to_dict()
    at = _parsed(command.occurred_at)
    if event == "start_trial":
        if blueprint.trial_days == 0:
            raise _Rejected("TRIAL_NOT_OFFERED", "this blueprint has no trial; activate directly", "correct_input")
        if blueprint.trial_requires_payment_method and r.payment_method_on_file is not True:
            raise _Rejected("PAYMENT_METHOD_REQUIRED", "the trial requires a payment method on file", "correct_input")
        data["trial_end"] = _iso(at + timedelta(days=blueprint.trial_days))
    elif event == "convert_trial":
        _activate(blueprint, data, r, from_trial=True)
    elif event == "activate":
        _activate(blueprint, data, r, from_trial=False)
    elif event == "bill":
        if r.billing_proposal_digest is None or r.invoice_ref is None or r.amount is None:
            raise _Rejected("BILLING_PROPOSAL_MISSING", "billing links the recurring billing proposal digest, the invoice, and the amount", "correct_input")
        if Decimal(data["open_invoice_amount"]) > 0:
            raise _Rejected("INVOICE_ALREADY_OPEN", "an invoice is already open; collect it before billing again", "correct_input")
        expected = _expected_bill(blueprint, ledger)
        if r.amount != expected:
            raise _Rejected("BILL_AMOUNT_MISMATCH", f"expected {expected} for the current plan, seats, discount, and pending usage; got {r.amount}", "correct_input")
        data.update({"invoiced_total": str(ledger.invoiced_total + r.amount), "open_invoice_amount": str(r.amount), "open_invoice_ref": r.invoice_ref, "pending_usage_total": "0"})
    elif event == "record_payment":
        if r.payment_ref is None or r.amount is None or r.amount <= 0:
            raise _Rejected("PAYMENT_MISSING", "a payment links the payment reference and a positive amount", "correct_input")
        if ledger.open_invoice_amount <= 0:
            raise _Rejected("NO_OPEN_INVOICE", "nothing is open to pay", "correct_input")
        if r.amount != ledger.open_invoice_amount:
            raise _Rejected("PAYMENT_AMOUNT_MISMATCH", f"open invoice is {ledger.open_invoice_amount}; got {r.amount}", "correct_input")
        data.update({"paid_total": str(ledger.paid_total + r.amount), "open_invoice_amount": "0", "open_invoice_ref": None, "first_failure_at": None, "dunning_retries_used": 0})
    elif event == "payment_failed":
        if ledger.open_invoice_amount <= 0:
            raise _Rejected("NO_OPEN_INVOICE", "a payment can only fail against an open invoice", "correct_input")
        if r.failure_code is None:
            raise _Rejected("FAILURE_CODE_MISSING", "a failed payment carries the provider failure code", "correct_input")
        data.update({"first_failure_at": command.occurred_at, "dunning_retries_used": 0})
    elif event == "retry_payment":
        used = ledger.dunning_retries_used
        if used >= len(blueprint.dunning_retry_days):
            raise _Rejected("DUNNING_EXHAUSTED", "every retry was used; cancel, expire, or take a manual payment", "manual_reconciliation")
        due = _parsed(str(ledger.first_failure_at)) + timedelta(days=blueprint.dunning_retry_days[used])
        if at < due:
            raise _Rejected("RETRY_TOO_EARLY", f"retry {used + 1} is due at {_iso(due)}", "correct_input")
        if r.failure_code is None:
            raise _Rejected("FAILURE_CODE_MISSING", "a failed retry carries the provider failure code", "correct_input")
        data["dunning_retries_used"] = used + 1
    elif event == "pause":
        if not blueprint.pause_allowed:
            raise _Rejected("PAUSE_NOT_ALLOWED", "this blueprint does not allow pauses", "correct_input")
        if r.pause_days is None or ledger.pause_days_used + r.pause_days > blueprint.max_pause_days:
            raise _Rejected("PAUSE_LIMIT", f"pause days are limited to {blueprint.max_pause_days} per account", "correct_input")
        if ledger.open_invoice_amount > 0:
            raise _Rejected("INVOICE_OPEN", "settle the open invoice before pausing", "correct_input")
        data.update({"paused_at": command.occurred_at, "pause_days_used": ledger.pause_days_used + r.pause_days})
    elif event == "resume":
        paused_days = max((at - _parsed(str(ledger.paused_at))).days, 0)
        data.update({"paused_at": None, "term_end": _iso(_parsed(str(ledger.term_end)) + timedelta(days=paused_days))})
    elif event == "change_plan":
        if r.new_plan_ref is None or r.new_plan_price is None or r.new_plan_price <= 0:
            raise _Rejected("NEW_PLAN_MISSING", "a plan change links the new plan and a positive price", "correct_input")
        seats = r.new_seats or ledger.seats
        if blueprint.proration_on_plan_change and r.proration_digest is None:
            raise _Rejected("PRORATION_REQUIRED", "this blueprint prorates plan changes; link the proration candidate digest", "correct_input")
        old_mrr, new_mrr = _mrr(blueprint, ledger), monthly_recurring(r.new_plan_price, seats if blueprint.billing_model in {"seat", "hybrid"} else 1, blueprint.billing_interval, ledger.discount_percent)
        data.update({"plan_ref": r.new_plan_ref, "plan_price": str(r.new_plan_price), "seats": seats})
        if new_mrr > old_mrr:
            data["expansion_mrr"] = str(ledger.expansion_mrr + (new_mrr - old_mrr))
        elif new_mrr < old_mrr:
            data["contraction_mrr"] = str(ledger.contraction_mrr + (old_mrr - new_mrr))
    elif event == "record_usage":
        if blueprint.billing_model not in {"usage", "hybrid"}:
            raise _Rejected("USAGE_NOT_BILLABLE", "this blueprint has no usage component", "correct_input")
        if r.usage_billing_digest is None or r.usage_total is None:
            raise _Rejected("USAGE_BILLING_MISSING", "usage links the validated usage billing snapshot digest and total", "correct_input")
        data["pending_usage_total"] = str(ledger.pending_usage_total + r.usage_total)
    elif event == "request_cancel":
        if r.cancel_reason is None:
            raise _Rejected("CANCEL_REASON_MISSING", "a cancellation request records the customer's reason", "correct_input")
        effective = str(ledger.term_end) if blueprint.cancel_at_period_end and ledger.term_end else command.occurred_at
        data.update({"cancel_reason": r.cancel_reason, "cancel_effective_at": effective})
    elif event == "save":
        if r.save_offer_ref is None or r.discount_percent is None:
            raise _Rejected("SAVE_OFFER_MISSING", "a save links the offer reference and discount percent", "correct_input")
        if ledger.save_offers_used + 1 > blueprint.max_save_offers:
            raise _Rejected("SAVE_OFFER_LIMIT", f"policy allows {blueprint.max_save_offers} save offer(s)", "manual_reconciliation")
        if r.discount_percent > blueprint.save_offer_max_discount_percent:
            raise _Rejected("DISCOUNT_EXCEEDS_POLICY", f"discount {r.discount_percent}% exceeds the {blueprint.save_offer_max_discount_percent}% limit", "await_approval")
        data.update({"save_offers_used": ledger.save_offers_used + 1, "discount_percent": str(r.discount_percent), "cancel_reason": None, "cancel_effective_at": None})
    elif event == "cancel":
        if status == "cancel_scheduled" and ledger.cancel_effective_at and at < _parsed(ledger.cancel_effective_at):
            raise _Rejected("CANCEL_NOT_EFFECTIVE_YET", f"cancellation takes effect at {ledger.cancel_effective_at}", "correct_input")
        if status == "past_due" and ledger.dunning_retries_used < len(blueprint.dunning_retry_days):
            raise _Rejected("DUNNING_NOT_EXHAUSTED", "retry the payment schedule before cancelling for non-payment", "correct_input")
        data["cancel_effective_at"] = data.get("cancel_effective_at") or command.occurred_at
    elif event == "renew":
        if r.renewal_snapshot_digest is None or r.renewal_status != "renewed" or r.term_start is None or r.term_end is None or r.renewal_total is None:
            raise _Rejected("RENEWAL_MISSING", "renewal links a renewed commercial renewal snapshot (prepare_renewal), the new term, and the renewal total", "correct_input")
        if r.term_start != ledger.term_end:
            raise _Rejected("TERM_NOT_CONTIGUOUS", "the new term starts when the current term ends", "correct_input")
        if _parsed(r.term_end) <= _parsed(r.term_start):
            raise _Rejected("TERM_INVALID", "the term must end after it starts", "correct_input")
        data.update({"term_start": r.term_start, "term_end": r.term_end, "terms_completed": ledger.terms_completed + 1, "renewal_snapshot_digest": r.renewal_snapshot_digest})
        if r.plan_price is not None:
            data["plan_price"] = str(r.plan_price)
    elif event == "expire":
        if status == "trialing":
            if ledger.trial_end and at < _parsed(ledger.trial_end):
                raise _Rejected("TRIAL_NOT_ENDED", f"the trial runs until {ledger.trial_end}", "correct_input")
        elif status == "past_due":
            if not ledger.first_failure_at or at < _parsed(ledger.first_failure_at) + timedelta(days=blueprint.grace_period_days):
                raise _Rejected("GRACE_PERIOD_ACTIVE", f"the grace period runs {blueprint.grace_period_days} days from the first failure", "correct_input")
        elif status == "paused":
            if not ledger.paused_at or at < _parsed(ledger.paused_at) + timedelta(days=blueprint.max_pause_days):
                raise _Rejected("PAUSE_NOT_EXHAUSTED", "a paused account expires only after the maximum pause", "correct_input")
        elif ledger.term_end and at < _parsed(ledger.term_end) + timedelta(days=blueprint.grace_period_days):
            raise _Rejected("TERM_NOT_ENDED", "an active account expires only after its term plus grace passes without renewal", "correct_input")
    return next_status, AccountLedger.model_validate(data)


class SubscriptionAccountState(_StrictModel):
    schema_id: Literal["lightbulb.subscription_account_state.v1"] = Field(default=ACCOUNT_STATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    scope: SubscriptionScope
    status: AccountStatus
    version: int = Field(ge=1, le=MAX_ACCOUNT_TRANSITIONS)
    transition_history: tuple[AccountTransition, ...] = Field(min_length=1, max_length=MAX_ACCOUNT_TRANSITIONS)
    ledger: AccountLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "SubscriptionAccountState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("account version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        prefix: tuple[AccountTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.scope, history):
            raise ValueError("state_digest must commit the exact account state")
        plan: SubscriptionBusinessLoopPlan | None = (info.context or {}).get("subscription_plan")
        if plan is not None:
            if plan.plan_digest != self.plan_digest:
                raise ValueError("account belongs to a different loop plan")
            status, ledger = "lead", AccountLedger()
            for transition in history:
                try:
                    status, ledger = _apply(plan, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the account table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("account status and ledger must be derived from history")
        return self

    def mrr(self, plan: SubscriptionBusinessLoopPlan) -> Decimal:
        return _mrr(plan.blueprint, self.ledger) if self.status in {"active", "past_due", "cancel_scheduled"} else Decimal("0")


class AccountRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "AccountRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class AccountTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: AccountEvent
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: AccountStatus
    to_status: AccountStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: AccountRecovery


class AccountEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    card_charged: Literal[False] = False
    provider_subscription_changed: Literal[False] = False
    reminder_sent: Literal[False] = False
    discount_granted: Literal[False] = False


class AccountTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.subscription_account_transition_result.v1"] = Field(default=ACCOUNT_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: SubscriptionAccountState | None = None
    receipt: AccountTransitionReceipt
    effect_boundary: AccountEffectBoundary = Field(default_factory=AccountEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "AccountTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: SubscriptionBusinessLoopPlan | Mapping[str, Any], state: SubscriptionAccountState | Mapping[str, Any]) -> tuple[SubscriptionBusinessLoopPlan, SubscriptionAccountState]:
    parsed_plan = SubscriptionBusinessLoopPlan.model_validate(_detached(plan))
    unbound = SubscriptionAccountState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("account belongs to a different loop plan")
    return parsed_plan, SubscriptionAccountState.model_validate(unbound.to_dict(), context={"subscription_plan": parsed_plan})


def open_subscription_account(plan: SubscriptionBusinessLoopPlan | Mapping[str, Any], scope: SubscriptionScope | Mapping[str, Any], *, opened_at: str, actor_ref: str, event: Literal["start_trial", "activate"] = "start_trial", receipt: AccountReceipt | Mapping[str, Any] | None = None) -> SubscriptionAccountState:
    """Open an account from a lead: start its trial, or activate directly for blueprints without trials."""

    parsed_plan = SubscriptionBusinessLoopPlan.model_validate(_detached(plan))
    parsed_scope = SubscriptionScope.model_validate(_detached(scope))
    if parsed_scope.currency != parsed_plan.blueprint.currency:
        raise ValueError("account currency must match the blueprint currency")
    genesis = _state_digest(parsed_plan.plan_digest, parsed_scope, ())
    command = SubscriptionAccountCommand.model_validate(seal_account_command({"event": event, "transition_ref": f"{event}:{parsed_scope.account_ref}", "idempotency_key": f"{parsed_scope.account_ref}:{event}", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": _detached(receipt) if receipt is not None else {}}))
    try:
        status, ledger = _apply(parsed_plan, "lead", AccountLedger(), command)
    except _Rejected as exc:
        raise ValueError(f"{exc.code}: {exc.instructions}") from exc
    transition = AccountTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return SubscriptionAccountState.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={"subscription_plan": parsed_plan})


def advance_subscription_account(plan: SubscriptionBusinessLoopPlan | Mapping[str, Any], state: SubscriptionAccountState | Mapping[str, Any], command: SubscriptionAccountCommand | Mapping[str, Any]) -> AccountTransitionResult:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = SubscriptionAccountCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> AccountTransitionResult:
        receipt = AccountTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=AccountRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return AccountTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if _parsed(parsed_command.occurred_at) < _parsed(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_ACCOUNT_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the account reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_plan, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = AccountTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = SubscriptionAccountState.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={"subscription_plan": parsed_plan})
    receipt = AccountTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=AccountRecovery(disposition="not_required"))
    return AccountTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


# --------------------------------------------------------------------------- #
# Portfolio assessment
# --------------------------------------------------------------------------- #


class SubscriptionPortfolioAssessment(_StrictModel):
    schema_id: Literal["lightbulb.subscription_portfolio_assessment.v1"] = Field(default=PORTFOLIO_SCHEMA, alias="schema")
    golden_loop: Literal["subscription.trial_to_renewal_business@0.1.0"] = SUBSCRIPTION_BUSINESS_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    accounts: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    mrr: Decimal
    arr: Decimal
    arpa: Decimal | None = None
    starting_mrr: Decimal
    expansion_mrr: Decimal
    contraction_mrr: Decimal
    churned_mrr: Decimal
    net_revenue_retention_percent: Decimal | None = None
    gross_churn_percent: Decimal | None = None
    trial_conversion_percent: Decimal | None = None
    ltv: Decimal | None = None
    past_due_exposure: Decimal
    open_invoices: Decimal
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    effect_boundary: AccountEffectBoundary = Field(default_factory=AccountEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("mrr", "arr", "arpa", "starting_mrr", "expansion_mrr", "contraction_mrr", "churned_mrr", "net_revenue_retention_percent", "gross_churn_percent", "trial_conversion_percent", "ltv", "past_due_exposure", "open_invoices", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "SubscriptionPortfolioAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(SubscriptionPortfolioAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_subscription_portfolio(plan: SubscriptionBusinessLoopPlan | Mapping[str, Any], accounts: Sequence[SubscriptionAccountState | Mapping[str, Any]], *, assessed_at: str) -> SubscriptionPortfolioAssessment:
    """Effect-dark portfolio metrics from account ledgers: MRR, ARR, ARPA, NRR, gross churn, trial conversion, LTV, exposure."""

    parsed_plan = SubscriptionBusinessLoopPlan.model_validate(_detached(plan))
    parsed = [_validate_plan_state(parsed_plan, item)[1] for item in accounts]
    blueprint = parsed_plan.blueprint
    quantum = _MONEY_QUANTUM
    by_status: dict[str, int] = {}
    for account in parsed:
        by_status[account.status] = by_status.get(account.status, 0) + 1
    live = [account for account in parsed if account.status in {"active", "past_due", "cancel_scheduled", "paused"}]
    ever_active = [account for account in parsed if account.ledger.plan_ref is not None]
    mrr = sum((account.mrr(parsed_plan) for account in parsed), Decimal("0")).quantize(quantum)
    starting = sum((account.ledger.starting_mrr for account in ever_active), Decimal("0")).quantize(quantum)
    expansion = sum((account.ledger.expansion_mrr for account in ever_active), Decimal("0")).quantize(quantum)
    contraction = sum((account.ledger.contraction_mrr for account in ever_active), Decimal("0")).quantize(quantum)
    churned_accounts = [account for account in ever_active if account.status in TERMINAL_ACCOUNT_STATUSES]
    churned_mrr = sum((_mrr(blueprint, account.ledger) for account in churned_accounts), Decimal("0")).quantize(quantum)
    retained_mrr = sum((account.mrr(parsed_plan) for account in ever_active if account.status not in TERMINAL_ACCOUNT_STATUSES), Decimal("0"))
    nrr = (retained_mrr / starting * Decimal(100)).quantize(quantum) if starting > 0 else None
    gross_churn = (Decimal(len(churned_accounts)) / Decimal(len(ever_active)) * Decimal(100)).quantize(quantum) if ever_active else None
    trials = [account for account in parsed if account.ledger.converted_from_trial is True or (account.ledger.trial_end is not None and account.status in {"expired", "cancelled"} and account.ledger.plan_ref is None)]
    converted = sum(1 for account in trials if account.ledger.converted_from_trial is True)
    trial_conversion = (Decimal(converted) / Decimal(len(trials)) * Decimal(100)).quantize(quantum) if trials else None
    arpa = (mrr / Decimal(len(live))).quantize(quantum) if live and mrr > 0 else None
    ltv = (arpa / (gross_churn / Decimal(100))).quantize(quantum) if arpa is not None and gross_churn is not None and gross_churn > 0 else None
    past_due = sum((account.ledger.open_invoice_amount for account in parsed if account.status == "past_due"), Decimal("0")).quantize(quantum)
    open_invoices = sum((account.ledger.open_invoice_amount for account in parsed), Decimal("0")).quantize(quantum)
    learnings: list[str] = []
    recommendations: list[str] = []
    if gross_churn is not None and gross_churn > blueprint.target_monthly_gross_churn_percent:
        learnings.append(f"gross churn {gross_churn}% exceeds the {blueprint.target_monthly_gross_churn_percent.quantize(quantum)}% target")
        recommendations.append("review cancel reasons and add a save offer or pause option before the cancel takes effect")
    if nrr is not None and nrr < blueprint.min_net_revenue_retention_percent:
        learnings.append(f"net revenue retention {nrr}% is below the {blueprint.min_net_revenue_retention_percent.quantize(quantum)}% floor")
        recommendations.append("drive expansion through seat growth or usage tiers; contraction and churn outweigh expansion")
    if trial_conversion is not None and trial_conversion < blueprint.min_trial_conversion_percent:
        learnings.append(f"trial conversion {trial_conversion}% is below the {blueprint.min_trial_conversion_percent.quantize(quantum)}% floor")
        recommendations.append("shorten time-to-value in the trial and require a payment method only if conversion holds")
    if past_due > 0:
        learnings.append(f"{past_due} {blueprint.currency} is past due across {by_status.get('past_due', 0)} account(s)")
        recommendations.append("run the dunning schedule to completion and reconcile provider settlements before expiring accounts")
    if not learnings:
        learnings.append("portfolio is inside blueprint targets")
    payload = {"profile": blueprint.profile, "currency": blueprint.currency, "accounts": len(parsed), "by_status": dict(sorted(by_status.items())), "mrr": str(mrr), "arr": str((mrr * 12).quantize(quantum)), "arpa": None if arpa is None else str(arpa), "starting_mrr": str(starting), "expansion_mrr": str(expansion), "contraction_mrr": str(contraction), "churned_mrr": str(churned_mrr), "net_revenue_retention_percent": None if nrr is None else str(nrr), "gross_churn_percent": None if gross_churn is None else str(gross_churn), "trial_conversion_percent": None if trial_conversion is None else str(trial_conversion), "ltv": None if ltv is None else str(ltv), "past_due_exposure": str(past_due), "open_invoices": str(open_invoices), "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at}
    payload["assessment_digest"] = _sealed_digest(SubscriptionPortfolioAssessment, payload, "assessment_digest")
    return SubscriptionPortfolioAssessment.model_validate(payload)


SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": SUBSCRIPTION_BUSINESS_ARCHETYPE,
    "title": "Subscription business",
    "golden_loop": SUBSCRIPTION_BUSINESS_GOLDEN_LOOP,
    "composed_with": ["commercial.propose_operations_transition (activate_subscription, propose_recurring_billing, propose_usage_billing, prepare_renewal)", "finance.create_invoice", "finance.collect_payment", "finance.reconcile_stripe_settlements", "growth.* customer value, price moves, unit economics"],
    "profiles": sorted(SUBSCRIPTION_BUSINESS_PROFILES),
    "account_statuses": list(AccountStatus.__args__),  # type: ignore[attr-defined]
    "account_events": list(AccountEvent.__args__),  # type: ignore[attr-defined]
    "economic_spine": {"acquire_demand": "acquire", "create_offer": "trial", "agree_purchase": "activate", "deliver_value": "serve", "accept_value": "convert_trial / renew", "monetize": "bill+collect", "learn": "learn"},
    "composable_with": ["service_business", "product_commerce", "saas_product", "appointment_business", "marketplace_business"],
}

__all__ = [
    "ACCOUNT_COMMAND_SCHEMA",
    "ACCOUNT_RESULT_SCHEMA",
    "ACCOUNT_STATE_SCHEMA",
    "BLUEPRINT_SCHEMA",
    "MAX_ACCOUNT_TRANSITIONS",
    "PLAN_SCHEMA",
    "PORTFOLIO_SCHEMA",
    "PRORATION_SCHEMA",
    "STAGE_ORDER",
    "SUBSCRIPTION_BUSINESS_ARCHETYPE",
    "SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST",
    "SUBSCRIPTION_BUSINESS_GOLDEN_LOOP",
    "SUBSCRIPTION_BUSINESS_PROFILES",
    "TERMINAL_ACCOUNT_STATUSES",
    "AccountEffectBoundary",
    "AccountLedger",
    "AccountReceipt",
    "AccountRecovery",
    "AccountTransition",
    "AccountTransitionReceipt",
    "AccountTransitionResult",
    "ProrationCandidate",
    "StageBinding",
    "SubscriptionAccountCommand",
    "SubscriptionAccountState",
    "SubscriptionBusinessBlueprint",
    "SubscriptionBusinessLoopPlan",
    "SubscriptionPortfolioAssessment",
    "SubscriptionScope",
    "account_command_digest",
    "advance_subscription_account",
    "assess_subscription_portfolio",
    "compile_subscription_business_blueprint",
    "genesis_account_state_digest",
    "monthly_recurring",
    "open_subscription_account",
    "prorate_plan_change",
    "seal_account_command",
    "seal_subscription_business_blueprint",
]
