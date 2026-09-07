"""Shared evidence, economics, planning, and evaluation runtime for profit workflows."""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Iterable, Literal, Mapping

from pydantic import Field, ValidationError, field_validator, model_validator

from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.profit_workflow_blueprints import (
    PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA,
    PROFIT_FLYWHEEL_PLAN_SCHEMA,
    PROFIT_OUTCOME_EVIDENCE_SCHEMA,
    PROFIT_WORKFLOW_DEFINITIONS,
    PROFIT_WORKFLOW_EVALUATION_SCHEMA,
    PROFIT_WORKFLOW_PLAN_SCHEMA,
    CapabilityAvailability,
    CapabilityRef,
    CurrencyCode,
    ExecutionKind,
    LongText,
    MetricUnit,
    PortableRef,
    ProfitCapabilityContract,
    ProfitEffect,
    ProfitMetric,
    ProfitScopeKeyRing,
    ProfitWorkflowDefinition,
    ProfitWorkflowId,
    ProfitWorkflowValidationError,
    Provider,
    Sha256Digest,
    ShortText,
    TargetDirection,
    _DEFINITIONS_BY_ID,
    _FORBIDDEN_PARAMETER_PARTS,
    _MAX_CANDIDATES,
    _MAX_EVIDENCE,
    _MAX_PARAMETERS,
    _MAX_WORKFLOW_BYTES,
    _METRIC_UNITS,
    _MONEY_QUANTUM,
    _PROFIT_ACCOUNT_HMAC_DOMAIN,
    _PROFIT_ACTION_EXECUTION_HMAC_DOMAIN,
    _PROFIT_EVALUATION_HMAC_DOMAIN,
    _PROFIT_METRIC_HMAC_DOMAIN,
    _PROFIT_OUTCOME_HMAC_DOMAIN,
    _PROFIT_PLAN_HMAC_DOMAIN,
    _RATE_QUANTUM,
    _SCORE_QUANTUM,
    _StrictModel,
    _decimal,
    _immutable_sequence,
    _normalized_timestamp,
    _parse_timestamp,
    _serialized_size,
    _stable_digest,
)


_SOURCE_CAPABILITIES: dict[str, tuple[Provider, frozenset[str]]] = {
    "shopify.analytics_query": (
        "shopify",
        frozenset(
            {
                "add_to_cart_rate",
                "average_order_value",
                "checkout_completion_rate",
                "contribution_margin_rate",
                "contribution_profit",
                "contribution_profit_per_order",
                "contribution_profit_per_session",
                "customer_lifetime_value",
                "refund_rate",
                "repeat_purchase_rate",
                "return_rate",
                "segment_conversion_rate",
                "storefront_conversion_rate",
            }
        ),
    ),
    "shopify.list_abandoned_checkouts": (
        "shopify",
        frozenset(
            {
                "checkout_completion_rate",
                "recovered_contribution_profit",
                "contribution_margin_rate",
            }
        ),
    ),
    "shopify.list_refunds": (
        "shopify",
        frozenset({"refund_rate", "return_rate", "contribution_profit"}),
    ),
    "shopify.list_fulfillment_orders": (
        "shopify",
        frozenset({"return_rate", "refund_rate"}),
    ),
    "stripe.list_balance_transactions": (
        "stripe",
        frozenset(
            {
                "contribution_profit",
                "contribution_margin_rate",
                "cash_conversion_cycle_days",
            }
        ),
    ),
    "xero.profit_loss_report": (
        "xero",
        frozenset(
            {
                "contribution_profit",
                "contribution_margin_rate",
                "contribution_profit_per_order",
            }
        ),
    ),
    "xero.list_purchase_orders": (
        "xero",
        frozenset(
            {
                "stockout_rate",
                "forecast_error_rate",
                "inventory_turnover",
                "cash_conversion_cycle_days",
            }
        ),
    ),
    "ecommerce.get_inventory": (
        "shopify",
        frozenset({"stockout_rate", "inventory_turnover", "forecast_error_rate"}),
    ),
    "crm.search_deals": (
        "hubspot",
        frozenset(
            {
                "qualified_demand_score",
                "segment_conversion_rate",
                "contribution_profit_per_contact",
            }
        ),
    ),
    "salesforce.pipeline_report": (
        "salesforce",
        frozenset(
            {
                "qualified_demand_score",
                "segment_conversion_rate",
                "contribution_profit_per_contact",
            }
        ),
    ),
    "facebook.fetch_metrics": (
        "facebook",
        frozenset(
            {
                "click_through_rate",
                "creative_profit_per_thousand_impressions",
                "marginal_roas",
                "customer_acquisition_cost",
            }
        ),
    ),
    "instagram.fetch_metrics": (
        "instagram",
        frozenset(
            {
                "click_through_rate",
                "creative_profit_per_thousand_impressions",
                "marginal_roas",
                "customer_acquisition_cost",
            }
        ),
    ),
    "linkedin.fetch_metrics": (
        "linkedin",
        frozenset(
            {
                "click_through_rate",
                "creative_profit_per_thousand_impressions",
                "marginal_roas",
                "customer_acquisition_cost",
                "qualified_demand_score",
            }
        ),
    ),
    "google_analytics.fetch_metrics": (
        "google_analytics",
        frozenset(
            {
                "storefront_conversion_rate",
                "add_to_cart_rate",
                "checkout_completion_rate",
                "click_through_rate",
                "contribution_profit_per_session",
            }
        ),
    ),
    "host.normalized_profit_ledger": (
        "host",
        frozenset(_METRIC_UNITS),
    ),
    "host.market_demand_snapshot": (
        "host",
        frozenset(
            {
                "qualified_demand_score",
                "competitive_saturation_rate",
                "contribution_margin_rate",
                "refund_rate",
            }
        ),
    ),
    "host.normalized_unit_economics": (
        "host",
        frozenset(
            {
                "contribution_profit_per_order",
                "contribution_margin_rate",
                "average_order_value",
                "refund_rate",
            }
        ),
    ),
    "host.experiment_snapshot": (
        "host",
        frozenset(_METRIC_UNITS),
    ),
    "host.inventory_snapshot": (
        "host",
        frozenset(
            {
                "stockout_rate",
                "forecast_error_rate",
                "inventory_turnover",
                "cash_conversion_cycle_days",
            }
        ),
    ),
    "host.paid_media_spend_snapshot": (
        "host",
        frozenset(
            {
                "marginal_roas",
                "customer_acquisition_cost",
                "contribution_profit",
                "customer_lifetime_value",
            }
        ),
    ),
    "host.customer_cohort_snapshot": (
        "host",
        frozenset(
            {
                "contribution_profit_per_contact",
                "segment_conversion_rate",
                "repeat_purchase_rate",
                "customer_lifetime_value",
                "churn_rate",
                "return_rate",
                "refund_rate",
                "contribution_profit",
            }
        ),
    ),
    "host.checkout_recovery_snapshot": (
        "host",
        frozenset(
            {
                "recovered_contribution_profit",
                "checkout_completion_rate",
                "contribution_margin_rate",
                "refund_rate",
            }
        ),
    ),
    "host.support_outcome_snapshot": (
        "host",
        frozenset(
            {
                "customer_lifetime_value",
                "return_rate",
                "refund_rate",
                "repeat_purchase_rate",
                "churn_rate",
            }
        ),
    ),
}

_ACTION_PROVIDER: dict[str, Provider] = {
    "gmail.send_email": "gmail",
    "ecommerce.create_discount": "shopify",
    "shopify.create_price_rule": "shopify",
    "ecommerce.update_product": "shopify",
    "xero.create_purchase_order": "xero",
    "shopify.upsert_theme_files": "shopify",
    "facebook.publish_post": "facebook",
    "instagram.publish_post": "instagram",
    "linkedin.publish_post": "linkedin",
    "hubspot.create_workflow": "hubspot",
    "stripe.create_refund": "stripe",
}

_DERIVED_CONTRIBUTION_METRICS = frozenset(
    {
        "contribution_profit",
        "contribution_profit_per_contact",
        "contribution_profit_per_order",
        "contribution_profit_per_session",
        "creative_profit_per_thousand_impressions",
        "recovered_contribution_profit",
    }
)


def get_profit_workflow_definition(
    workflow_id: ProfitWorkflowId | str,
) -> ProfitWorkflowDefinition:
    try:
        return _DEFINITIONS_BY_ID[str(workflow_id)]
    except KeyError as exc:
        raise KeyError(f"Unknown profit workflow: {workflow_id}") from exc


class ProfitConnectorAccountBinding(_StrictModel):
    provider: Provider
    connector_account_ref: ShortText
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    account_hmac: Sha256Digest | None = None

    @model_validator(mode="after")
    def _connector_provider_only(self) -> "ProfitConnectorAccountBinding":
        if self.provider == "host":
            raise ValueError("host evidence does not use a connector account binding")
        binding = (self.receipt_key_id, self.exact_scope_digest, self.account_hmac)
        if any(item is not None for item in binding) and not all(
            item is not None for item in binding
        ):
            raise ValueError(
                "connector account attestation fields must be supplied together"
            )
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"account_hmac"},
            exclude_none=True,
        )


class ProfitContributionLedger(_StrictModel):
    currency: CurrencyCode
    gross_sales: Decimal = Field(ge=0, le=1_000_000_000_000)
    discounts: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    refunds: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    cogs: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    fulfillment_cost: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    payment_fees: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    acquisition_cost: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)
    service_cost: Decimal = Field(default=Decimal("0"), ge=0, le=1_000_000_000_000)

    @field_validator(
        "gross_sales",
        "discounts",
        "refunds",
        "cogs",
        "fulfillment_cost",
        "payment_fees",
        "acquisition_cost",
        "service_cost",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @property
    def contribution_profit(self) -> Decimal:
        return (
            self.gross_sales
            - self.discounts
            - self.refunds
            - self.cogs
            - self.fulfillment_cost
            - self.payment_fees
            - self.acquisition_cost
            - self.service_cost
        ).quantize(_MONEY_QUANTUM)

    @property
    def net_revenue(self) -> Decimal:
        return (self.gross_sales - self.discounts - self.refunds).quantize(
            _MONEY_QUANTUM
        )


class ProfitMetricEvidence(_StrictModel):
    evidence_ref: PortableRef
    provider: Provider
    connector_account_ref: ShortText | None = None
    subject_account_refs: tuple[ShortText, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    source_capability: CapabilityRef
    metric: ProfitMetric
    unit: MetricUnit
    value: Decimal
    currency: CurrencyCode | None = None
    exposure_count: int | None = Field(default=None, ge=1, le=10_000_000_000)
    sample_size: int = Field(ge=0, le=10_000_000_000)
    observed_at: str
    window_start: str
    window_end: str
    ledger: ProfitContributionLedger | None = None
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    snapshot_hmac: Sha256Digest | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _metric_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _closed_evidence(self) -> "ProfitMetricEvidence":
        expected_unit = _METRIC_UNITS[self.metric]
        if self.unit != expected_unit:
            raise ValueError(f"{self.metric} must use {expected_unit} units")
        try:
            source_provider, allowed_metrics = _SOURCE_CAPABILITIES[
                self.source_capability
            ]
        except KeyError as exc:
            raise ValueError(
                "source_capability is not an allowed evidence source"
            ) from exc
        if source_provider != self.provider or self.metric not in allowed_metrics:
            raise ValueError(
                "evidence provider or metric does not match source capability"
            )
        if self.provider == "host" and self.connector_account_ref is not None:
            raise ValueError("host evidence must not claim a connector account")
        if self.provider != "host" and self.connector_account_ref is None:
            raise ValueError("connector evidence requires connector_account_ref")
        if self.provider != "host" and self.subject_account_refs:
            raise ValueError(
                "connector evidence already has an exact account reference"
            )
        if len(self.subject_account_refs) != len(set(self.subject_account_refs)):
            raise ValueError("host evidence subject account references must be unique")
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede window_end")
        if self.unit == "money":
            if self.currency is None:
                raise ValueError("money evidence requires currency")
            if self.value != self.value.quantize(_MONEY_QUANTUM):
                raise ValueError("money evidence supports at most two decimal places")
            object.__setattr__(self, "value", self.value.quantize(_MONEY_QUANTUM))
        elif self.currency is not None:
            raise ValueError("only money evidence may declare currency")
        if self.unit == "ratio" and not Decimal("0") <= self.value <= Decimal("1"):
            raise ValueError("ratio evidence must be between zero and one")
        if self.unit in {"count", "days", "multiple"} and self.value < 0:
            raise ValueError(f"{self.unit} evidence must not be negative")
        if self.metric in _DERIVED_CONTRIBUTION_METRICS:
            if self.ledger is None:
                raise ValueError("contribution metrics require a component ledger")
            if self.currency != self.ledger.currency:
                raise ValueError("metric and contribution ledger currencies must match")
            expected = self.ledger.contribution_profit
            if self.metric in {
                "contribution_profit_per_contact",
                "contribution_profit_per_order",
                "contribution_profit_per_session",
            }:
                if self.exposure_count is None:
                    raise ValueError(
                        "per-unit contribution metrics require exposure_count"
                    )
                expected = (expected / Decimal(self.exposure_count)).quantize(
                    _MONEY_QUANTUM,
                    rounding=ROUND_HALF_UP,
                )
            elif self.metric == "creative_profit_per_thousand_impressions":
                if self.exposure_count is None:
                    raise ValueError(
                        "creative profit requires impression exposure_count"
                    )
                expected = (
                    expected * Decimal("1000") / Decimal(self.exposure_count)
                ).quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)
            if self.value != expected:
                raise ValueError(
                    "contribution metric must be derived from ledger components"
                )
        elif self.ledger is not None:
            raise ValueError("ledger is accepted only for derived contribution metrics")
        binding = (self.receipt_key_id, self.exact_scope_digest, self.snapshot_hmac)
        if any(item is not None for item in binding) and not all(
            item is not None for item in binding
        ):
            raise ValueError("evidence attestation fields must be supplied together")
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"snapshot_hmac"},
            exclude_none=True,
        )


class ProfitActionParameter(_StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    value: str = Field(min_length=1, max_length=2_000)

    @field_validator("name")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        normalized = value.casefold()
        parts = set(re.split(r"[^a-z0-9]+", normalized))
        if any(forbidden in normalized for forbidden in _FORBIDDEN_PARAMETER_PARTS) or (
            parts.intersection(_FORBIDDEN_PARAMETER_PARTS)
        ):
            raise ValueError(
                "parameter name may not contain authority or secret fields"
            )
        return value

    @field_validator("value")
    @classmethod
    def _bounded_value(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("parameter value must not contain surrounding whitespace")
        return value


class ProfitLeverCandidate(_StrictModel):
    candidate_ref: PortableRef
    title: ShortText
    capability: CapabilityRef
    target_account_ref: ShortText | None = None
    rationale: LongText
    parameters: tuple[ProfitActionParameter, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_PARAMETERS,
    )
    expected_incremental_revenue: Decimal = Field(ge=0, le=1_000_000_000_000)
    expected_incremental_cost: Decimal = Field(ge=0, le=1_000_000_000_000)
    implementation_cost: Decimal = Field(ge=0, le=1_000_000_000_000)
    downside_loss: Decimal = Field(ge=0, le=1_000_000_000_000)
    confidence: Decimal = Field(ge=0, le=1)
    time_to_value_days: int = Field(ge=0, le=3_650)
    measurement_metric: ProfitMetric
    supported_by_evidence_refs: tuple[PortableRef, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    depends_on: tuple[PortableRef, ...] = Field(default_factory=tuple, max_length=10)
    mutually_exclusive_group: PortableRef | None = None

    @field_validator(
        "expected_incremental_revenue",
        "expected_incremental_cost",
        "implementation_cost",
        "downside_loss",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator(
        "parameters",
        "supported_by_evidence_refs",
        "depends_on",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_candidate_parts(self) -> "ProfitLeverCandidate":
        parameter_names = [item.name for item in self.parameters]
        if len(parameter_names) != len(set(parameter_names)):
            raise ValueError("candidate parameter names must be unique")
        if len(self.supported_by_evidence_refs) != len(
            set(self.supported_by_evidence_refs)
        ):
            raise ValueError("supported evidence references must be unique")
        if self.candidate_ref in self.depends_on:
            raise ValueError("candidate cannot depend on itself")
        return self


class ProfitOptimizationPolicy(_StrictModel):
    target_metric: ProfitMetric
    target_value: Decimal
    max_actions: int = Field(default=3, ge=1, le=10)
    budget_cap: Decimal = Field(default=Decimal("10000"), ge=0, le=1_000_000_000_000)
    minimum_expected_profit: Decimal = Field(
        default=Decimal("0"), ge=0, le=1_000_000_000_000
    )
    minimum_confidence: Decimal = Field(default=Decimal("0.25"), ge=0, le=1)
    unverified_confidence_haircut: Decimal = Field(default=Decimal("0.50"), gt=0, le=1)
    minimum_sample_size: int = Field(default=100, ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(default=720, ge=1, le=8_760)
    measurement_window_hours: int = Field(default=168, ge=1, le=2_160)
    max_iterations: int = Field(default=3, ge=1, le=4)

    @field_validator("target_value", mode="before")
    @classmethod
    def _target_value(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("budget_cap", "minimum_expected_profit", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator(
        "minimum_confidence",
        "unverified_confidence_haircut",
        mode="before",
    )
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value)


class PlanProfitWorkflowInput(_StrictModel):
    analysis_as_of: str
    plan_ref: PortableRef
    launch_ref: PortableRef
    objective: LongText
    account_bindings: tuple[ProfitConnectorAccountBinding, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    baseline: ProfitContributionLedger
    evidence: tuple[ProfitMetricEvidence, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_EVIDENCE,
    )
    candidates: tuple[ProfitLeverCandidate, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    policy: ProfitOptimizationPolicy
    source_plan_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "account_bindings",
        "evidence",
        "candidates",
        "source_plan_digests",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _closed_input_graph(self) -> "PlanProfitWorkflowInput":
        bindings = {
            (item.provider, item.connector_account_ref)
            for item in self.account_bindings
        }
        if len(bindings) != len(self.account_bindings):
            raise ValueError("account bindings must be unique")
        bound_account_refs = {
            item.connector_account_ref for item in self.account_bindings
        }
        if len(bound_account_refs) != len(self.account_bindings):
            raise ValueError("connector account references must be globally unique")
        evidence_refs: set[str] = set()
        for item in self.evidence:
            if item.evidence_ref in evidence_refs:
                raise ValueError("evidence_ref values must be unique")
            evidence_refs.add(item.evidence_ref)
            if (
                item.provider != "host"
                and (
                    item.provider,
                    item.connector_account_ref,
                )
                not in bindings
            ):
                raise ValueError("evidence connector account is not declared")
            if any(
                account_ref not in bound_account_refs
                for account_ref in item.subject_account_refs
            ):
                raise ValueError("host evidence subject account is not declared")
            if item.currency is not None and item.currency != self.baseline.currency:
                raise ValueError("all money evidence must use the baseline currency")
        known_candidates: set[str] = set()
        for candidate in self.candidates:
            if candidate.candidate_ref in known_candidates:
                raise ValueError("candidate_ref values must be unique")
            if any(
                dependency not in known_candidates
                for dependency in candidate.depends_on
            ):
                raise ValueError(
                    "candidate dependencies must reference earlier candidates"
                )
            if any(
                evidence_ref not in evidence_refs
                for evidence_ref in candidate.supported_by_evidence_refs
            ):
                raise ValueError("candidate references unknown evidence")
            known_candidates.add(candidate.candidate_ref)
        if len(self.source_plan_digests) != len(set(self.source_plan_digests)):
            raise ValueError("source_plan_digests must be unique")
        return self


class ProfitEvidenceScope(_StrictModel):
    status: Literal["caller_supplied_unverified", "host_hmac_verified"]
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _complete_binding(self) -> "ProfitEvidenceScope":
        expected = self.status == "host_hmac_verified"
        actual = self.receipt_key_id is not None and self.exact_scope_digest is not None
        if expected != actual:
            raise ValueError(
                "verified evidence scope requires a complete keyed binding"
            )
        return self


EvidenceEligibility = Literal[
    "eligible",
    "context_only",
    "future_observation",
    "insufficient_sample",
    "scope_unverified",
    "stale",
]


class ProfitMetricFinding(_StrictModel):
    evidence_ref: PortableRef
    provider: Provider
    connector_account_ref: ShortText | None = None
    subject_account_refs: tuple[ShortText, ...] = Field(default_factory=tuple)
    metric: ProfitMetric
    value: Decimal
    unit: MetricUnit
    status: EvidenceEligibility
    age_hours: int = Field(ge=0, le=1_000_000)
    primary_metric: bool
    reason: ShortText

    @field_validator("value", mode="before")
    @classmethod
    def _decimal_value(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("subject_account_refs", mode="before")
    @classmethod
    def _immutable_accounts(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _canonical_value(self) -> "ProfitMetricFinding":
        quantum = _MONEY_QUANTUM if self.unit == "money" else _RATE_QUANTUM
        object.__setattr__(self, "value", self.value.quantize(quantum))
        return self


class ProfitBaselineSummary(_StrictModel):
    currency: CurrencyCode
    gross_sales: Decimal
    net_revenue: Decimal
    total_attributable_cost: Decimal
    contribution_profit: Decimal
    contribution_margin_rate: Decimal | None = None

    @field_validator(
        "gross_sales",
        "net_revenue",
        "total_attributable_cost",
        "contribution_profit",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("contribution_margin_rate", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal | None:
        return None if value is None else _decimal(value)


CandidateDisposition = Literal[
    "selected",
    "below_confidence_floor",
    "below_profit_floor",
    "blocked_capability",
    "budget_exceeded",
    "dependency_not_selected",
    "mutually_exclusive",
    "selection_limit",
]


class ProfitCandidateDecision(_StrictModel):
    candidate_ref: PortableRef
    rank: int = Field(ge=1, le=_MAX_CANDIDATES)
    disposition: CandidateDisposition
    declared_confidence: Decimal = Field(ge=0, le=1)
    effective_confidence: Decimal = Field(ge=0, le=1)
    gross_incremental_profit: Decimal
    risk_adjusted_profit: Decimal
    cash_required: Decimal = Field(ge=0)
    priority_score: Decimal
    evidence_verified: bool
    reason: ShortText

    @field_validator("declared_confidence", "effective_confidence", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator(
        "gross_incremental_profit",
        "risk_adjusted_profit",
        "cash_required",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("priority_score", mode="before")
    @classmethod
    def _score(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_SCORE_QUANTUM)


OperationDisposition = Literal["proposal", "blocked_capability"]


class GovernedProfitAction(_StrictModel):
    ordinal: int = Field(ge=1, le=10)
    operation_ref: str = Field(
        min_length=1,
        max_length=180,
        pattern=r"^[a-z][a-z0-9_.:-]{0,179}$",
    )
    candidate_ref: PortableRef
    title: ShortText
    capability: CapabilityRef
    execution_kind: ExecutionKind
    effect: ProfitEffect
    availability: CapabilityAvailability
    disposition: OperationDisposition
    target_account_ref: ShortText | None = None
    exact_scope_digest: Sha256Digest | None = None
    intent_parameters: tuple[ProfitActionParameter, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_PARAMETERS,
    )
    depends_on: tuple[str, ...] = Field(default_factory=tuple, max_length=10)
    expected_risk_adjusted_profit: Decimal
    approval_required: bool
    approval_unit: str | None = Field(default=None, min_length=1, max_length=500)
    dispatchable_by_planner: Literal[False] = False
    operation_digest: Sha256Digest = "0" * 64

    @field_validator("intent_parameters", "depends_on", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("expected_risk_adjusted_profit", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _seal_operation(self) -> "GovernedProfitAction":
        if self.effect == "WRITE" and not self.approval_required:
            raise ValueError("external writes require a content-bound approval unit")
        if self.effect == "DRAFT" and self.approval_required:
            raise ValueError("local draft proposals do not request write approval")
        payload = self.model_dump(
            mode="json",
            exclude={"operation_digest", "approval_unit"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        expected_approval = (
            f"profit-action#{self.operation_ref}#{expected_digest}"
            if self.approval_required
            else None
        )
        if self.operation_digest not in {"0" * 64, expected_digest}:
            raise ValueError("operation_digest does not match action content")
        if self.approval_unit not in {None, expected_approval}:
            raise ValueError("approval_unit does not match action content")
        object.__setattr__(self, "operation_digest", expected_digest)
        object.__setattr__(self, "approval_unit", expected_approval)
        return self


class ProfitCapabilityGap(_StrictModel):
    code: ShortText
    capability: CapabilityRef
    severity: Literal["info", "blocking"]
    message: LongText


class ProfitEvaluationLoop(_StrictModel):
    target_metric: ProfitMetric
    target_unit: MetricUnit
    target_direction: TargetDirection
    target_value: Decimal
    minimum_sample_size: int = Field(ge=1)
    max_observation_age_hours: int = Field(ge=1)
    measurement_window_hours: int = Field(ge=1)
    max_iterations: int = Field(ge=1, le=4)
    stages: tuple[
        Literal[
            "approve",
            "materialize",
            "observe",
            "evaluate",
            "revise",
        ],
        ...,
    ]
    stop_conditions: tuple[
        Literal[
            "target_met",
            "iteration_limit_reached",
            "approval_revoked",
            "evidence_missing",
            "stop_loss_triggered",
        ],
        ...,
    ]

    @field_validator("target_value", mode="before")
    @classmethod
    def _target(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("stages", "stop_conditions", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _canonical_target(self) -> "ProfitEvaluationLoop":
        quantum = _MONEY_QUANTUM if self.target_unit == "money" else _RATE_QUANTUM
        object.__setattr__(self, "target_value", self.target_value.quantize(quantum))
        return self


class ProfitEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    domain_actions: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    external_systems_changed: Literal[False] = False
    materialization_supported: Literal[False] = False


OptimizationStatus = Literal[
    "assumption_ranked",
    "partially_evidence_informed",
    "evidence_optimized",
]


class ProfitWorkflowPlan(_StrictModel):
    schema_id: Literal["lightbulb.profit_workflow_plan.v1"] = Field(
        default=PROFIT_WORKFLOW_PLAN_SCHEMA,
        alias="schema",
    )
    workflow_id: ProfitWorkflowId
    workflow_ordinal: int = Field(ge=1, le=10)
    blueprint_digest: Sha256Digest
    plan_ref: PortableRef
    launch_ref: PortableRef
    analysis_as_of: str
    objective: LongText
    source_plan_digests: tuple[Sha256Digest, ...]
    account_bindings: tuple[ProfitConnectorAccountBinding, ...]
    evidence_scope: ProfitEvidenceScope
    optimization_status: OptimizationStatus
    baseline: ProfitBaselineSummary
    metric_findings: tuple[ProfitMetricFinding, ...]
    candidate_decisions: tuple[ProfitCandidateDecision, ...]
    actions: tuple[GovernedProfitAction, ...]
    capability_gaps: tuple[ProfitCapabilityGap, ...]
    evaluation_loop: ProfitEvaluationLoop
    estimated_incremental_profit: Decimal
    estimated_post_plan_contribution_profit: Decimal
    estimates_are_assumptions: Literal[True] = True
    estimates_are_non_additive_across_workflows: Literal[True] = True
    effect_boundary: ProfitEffectBoundary = Field(default_factory=ProfitEffectBoundary)
    summary: LongText
    receipt_key_id: str | None = Field(default=None, min_length=8, max_length=80)
    exact_scope_digest: Sha256Digest | None = None
    plan_hmac: Sha256Digest | None = None
    plan_digest: Sha256Digest = "0" * 64

    @field_validator(
        "source_plan_digests",
        "account_bindings",
        "metric_findings",
        "candidate_decisions",
        "actions",
        "capability_gaps",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("analysis_as_of")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "estimated_incremental_profit",
        "estimated_post_plan_contribution_profit",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _seal_plan(self) -> "ProfitWorkflowPlan":
        definition = get_profit_workflow_definition(self.workflow_id)
        if self.workflow_ordinal != definition.ordinal:
            raise ValueError("workflow ordinal does not match blueprint")
        expected_blueprint_digest = _stable_digest(
            definition.model_dump(mode="json", exclude_none=True)
        )
        if self.blueprint_digest != expected_blueprint_digest:
            raise ValueError("blueprint_digest does not match code-owned blueprint")
        declared_bindings = {
            (item.provider, item.connector_account_ref)
            for item in self.account_bindings
        }
        if len(declared_bindings) != len(self.account_bindings):
            raise ValueError("plan connector account bindings must be unique")
        if len({item.connector_account_ref for item in self.account_bindings}) != len(
            self.account_bindings
        ):
            raise ValueError(
                "plan connector account references must be globally unique"
            )
        if [item.rank for item in self.candidate_decisions] != list(
            range(1, len(self.candidate_decisions) + 1)
        ):
            raise ValueError("candidate decision ranks must be contiguous")
        selected_refs = {
            item.candidate_ref
            for item in self.candidate_decisions
            if item.disposition == "selected"
        }
        if {item.candidate_ref for item in self.actions} != selected_refs:
            raise ValueError("actions must match selected candidate decisions")
        known_operations: set[str] = set()
        for ordinal, action in enumerate(self.actions, 1):
            if action.ordinal != ordinal:
                raise ValueError("action ordinals must be contiguous")
            if any(
                dependency not in known_operations for dependency in action.depends_on
            ):
                raise ValueError("action dependencies must reference earlier actions")
            known_operations.add(action.operation_ref)
            if action.exact_scope_digest != self.exact_scope_digest:
                raise ValueError("action scope binding does not match plan scope")
            provider = _ACTION_PROVIDER.get(action.capability)
            if (
                provider is not None
                and (provider, action.target_account_ref) not in declared_bindings
            ):
                raise ValueError("action account is not declared by the plan")
        selected_profit = sum(
            (
                item.risk_adjusted_profit
                for item in self.candidate_decisions
                if item.disposition == "selected"
            ),
            Decimal("0"),
        ).quantize(_MONEY_QUANTUM)
        if self.estimated_incremental_profit != selected_profit:
            raise ValueError("estimated profit must equal selected candidate decisions")
        expected_post = (
            self.baseline.contribution_profit + self.estimated_incremental_profit
        ).quantize(_MONEY_QUANTUM)
        if self.estimated_post_plan_contribution_profit != expected_post:
            raise ValueError("post-plan contribution profit does not reconcile")
        binding = (self.receipt_key_id, self.exact_scope_digest, self.plan_hmac)
        if self.evidence_scope.status == "host_hmac_verified":
            if not all(item is not None for item in binding):
                raise ValueError("host-bound plan requires a complete HMAC binding")
            if (
                self.receipt_key_id != self.evidence_scope.receipt_key_id
                or self.exact_scope_digest != self.evidence_scope.exact_scope_digest
            ):
                raise ValueError("plan HMAC binding must match evidence scope")
            if any(
                item.exact_scope_digest != self.exact_scope_digest
                or item.receipt_key_id != self.receipt_key_id
                or item.account_hmac is None
                for item in self.account_bindings
            ):
                raise ValueError(
                    "host-bound plan requires exact-scope connector account bindings"
                )
        elif any(item is not None for item in binding):
            raise ValueError("unverified plan cannot carry a host HMAC binding")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest", "plan_hmac"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.plan_digest not in {"0" * 64, expected_digest}:
            raise ValueError("plan_digest does not match canonical plan content")
        object.__setattr__(self, "plan_digest", expected_digest)
        if (
            _serialized_size(self.model_dump(mode="json", by_alias=True))
            > _MAX_WORKFLOW_BYTES
        ):
            raise ValueError("profit workflow plan exceeds its serialized byte budget")
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_hmac"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _parse_plan_input(
    value: PlanProfitWorkflowInput | Mapping[str, Any],
) -> PlanProfitWorkflowInput:
    try:
        payload = (
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, PlanProfitWorkflowInput)
            else value
        )
        return PlanProfitWorkflowInput.model_validate(payload)
    except ValidationError:
        raise ProfitWorkflowValidationError(
            "Profit workflow input failed closed-world validation"
        ) from None


def _workflow_input_contract(
    definition: ProfitWorkflowDefinition,
    inputs: PlanProfitWorkflowInput,
    *,
    evidence_scope: ProfitEvidenceScope,
    scope_keyring: ProfitScopeKeyRing | None,
) -> dict[str, ProfitCapabilityContract]:
    if inputs.policy.target_metric != definition.primary_metric:
        raise ProfitWorkflowValidationError(
            "policy target_metric must match the workflow primary metric"
        )
    target_unit = _METRIC_UNITS[inputs.policy.target_metric]
    if target_unit == "ratio" and not Decimal(
        "0"
    ) <= inputs.policy.target_value <= Decimal("1"):
        raise ProfitWorkflowValidationError(
            "ratio targets must be between zero and one"
        )
    if target_unit == "money" and (
        inputs.policy.target_value
        != inputs.policy.target_value.quantize(_MONEY_QUANTUM)
    ):
        raise ProfitWorkflowValidationError(
            "money targets support at most two decimals"
        )
    allowed_sources = set(definition.evidence_capabilities)
    if any(item.source_capability not in allowed_sources for item in inputs.evidence):
        raise ProfitWorkflowValidationError(
            "evidence source is not allowed by the selected workflow blueprint"
        )
    if any(item.metric not in definition.supported_metrics for item in inputs.evidence):
        raise ProfitWorkflowValidationError(
            "evidence metric is not supported by the selected workflow blueprint"
        )
    capabilities = {
        contract.capability: contract for contract in definition.action_capabilities
    }
    bindings = {
        (item.provider, item.connector_account_ref) for item in inputs.account_bindings
    }
    if evidence_scope.status == "host_hmac_verified" and any(
        not _account_binding_attestation_matches(
            item,
            evidence_scope=evidence_scope,
            scope_keyring=scope_keyring,
        )
        for item in inputs.account_bindings
    ):
        raise ProfitWorkflowValidationError(
            "verified planning requires every connector account binding to be "
            "HMAC-bound to the authenticated scope"
        )
    for candidate in inputs.candidates:
        try:
            contract = capabilities[candidate.capability]
        except KeyError as exc:
            raise ProfitWorkflowValidationError(
                "candidate capability is not allowed by the workflow blueprint"
            ) from exc
        if candidate.measurement_metric not in definition.supported_metrics:
            raise ProfitWorkflowValidationError(
                "candidate measurement metric is not supported by the workflow"
            )
        provider = _ACTION_PROVIDER.get(candidate.capability)
        if (
            provider is not None
            and (
                provider,
                candidate.target_account_ref,
            )
            not in bindings
        ):
            raise ProfitWorkflowValidationError(
                "connector action candidate requires a declared matching account"
            )
        if provider is None and contract.execution_kind in {
            "sdk_primitive",
            "host_service",
        }:
            if candidate.target_account_ref is not None:
                raise ProfitWorkflowValidationError(
                    "SDK and host action intents must not accept connector accounts"
                )
    return capabilities


def _evidence_scope(
    *,
    verified_scope: DynamicWorkflowScope | Mapping[str, Any] | None,
    scope_keyring: ProfitScopeKeyRing | None,
    scope_key_id: str | None,
) -> ProfitEvidenceScope:
    if verified_scope is None and scope_keyring is None and scope_key_id is None:
        return ProfitEvidenceScope(status="caller_supplied_unverified")
    if verified_scope is None or scope_keyring is None:
        raise ValueError("verified_scope and scope_keyring are both required")
    scope = (
        verified_scope
        if isinstance(verified_scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(verified_scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    return ProfitEvidenceScope(
        status="host_hmac_verified",
        receipt_key_id=key_id,
        exact_scope_digest=scope_keyring.exact_scope_digest(
            key_id=key_id,
            scope=scope,
        ),
    )


def mint_profit_connector_account_binding(
    value: ProfitConnectorAccountBinding | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    scope_key_id: str | None = None,
) -> ProfitConnectorAccountBinding:
    """Seal one opaque connector-account reference to an exact host scope."""

    binding = ProfitConnectorAccountBinding.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, ProfitConnectorAccountBinding)
        else value
    )
    if any(
        item is not None
        for item in (
            binding.receipt_key_id,
            binding.exact_scope_digest,
            binding.account_hmac,
        )
    ):
        raise ValueError("connector account binding is already attested")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    draft = ProfitConnectorAccountBinding(
        provider=binding.provider,
        connector_account_ref=binding.connector_account_ref,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        account_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _PROFIT_ACCOUNT_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    payload = draft.model_dump(mode="python", exclude_none=True)
    payload["account_hmac"] = signature
    return ProfitConnectorAccountBinding.model_validate(payload)


def _account_binding_attestation_matches(
    binding: ProfitConnectorAccountBinding,
    *,
    evidence_scope: ProfitEvidenceScope,
    scope_keyring: ProfitScopeKeyRing | None,
) -> bool:
    if evidence_scope.status != "host_hmac_verified" or scope_keyring is None:
        return False
    if (
        binding.receipt_key_id != evidence_scope.receipt_key_id
        or binding.exact_scope_digest != evidence_scope.exact_scope_digest
        or binding.account_hmac is None
    ):
        return False
    expected = scope_keyring.sign(
        binding.receipt_key_id,
        _PROFIT_ACCOUNT_HMAC_DOMAIN,
        binding.hmac_payload(),
    ).hex()
    return hmac.compare_digest(binding.account_hmac, expected)


def mint_profit_metric_evidence(
    value: ProfitMetricEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    scope_key_id: str | None = None,
) -> ProfitMetricEvidence:
    """Seal one host-verified metric observation with its exact workflow scope."""

    evidence = ProfitMetricEvidence.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, ProfitMetricEvidence)
        else value
    )
    if any(
        item is not None
        for item in (
            evidence.receipt_key_id,
            evidence.exact_scope_digest,
            evidence.snapshot_hmac,
        )
    ):
        raise ValueError("profit metric evidence is already attested")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    payload = evidence.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "snapshot_hmac": "0" * 64,
        }
    )
    draft = ProfitMetricEvidence.model_validate(payload)
    signature = scope_keyring.sign(
        key_id,
        _PROFIT_METRIC_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["snapshot_hmac"] = signature
    return ProfitMetricEvidence.model_validate(sealed)


def _evidence_attestation_matches(
    evidence: ProfitMetricEvidence,
    *,
    evidence_scope: ProfitEvidenceScope,
    scope_keyring: ProfitScopeKeyRing | None,
) -> bool:
    if evidence_scope.status != "host_hmac_verified" or scope_keyring is None:
        return False
    if (
        evidence.receipt_key_id != evidence_scope.receipt_key_id
        or evidence.exact_scope_digest != evidence_scope.exact_scope_digest
        or evidence.snapshot_hmac is None
    ):
        return False
    expected = scope_keyring.sign(
        evidence.receipt_key_id,
        _PROFIT_METRIC_HMAC_DOMAIN,
        evidence.hmac_payload(),
    ).hex()
    return hmac.compare_digest(evidence.snapshot_hmac, expected)


def _metric_findings(
    definition: ProfitWorkflowDefinition,
    inputs: PlanProfitWorkflowInput,
    *,
    evidence_scope: ProfitEvidenceScope,
    scope_keyring: ProfitScopeKeyRing | None,
) -> tuple[ProfitMetricFinding, ...]:
    analysis_at = _parse_timestamp(inputs.analysis_as_of)
    findings: list[ProfitMetricFinding] = []
    for item in inputs.evidence:
        window_end = _parse_timestamp(item.window_end)
        observed_at = _parse_timestamp(item.observed_at)
        age_seconds = max(0.0, (analysis_at - window_end).total_seconds())
        age_hours = int(age_seconds // 3_600)
        if window_end > analysis_at or observed_at > analysis_at:
            status: EvidenceEligibility = "future_observation"
            reason = "Observation occurs after analysis_as_of."
        elif not _evidence_attestation_matches(
            item,
            evidence_scope=evidence_scope,
            scope_keyring=scope_keyring,
        ):
            status = "scope_unverified"
            reason = "Observation is not HMAC-bound to the authenticated scope."
        elif age_seconds > inputs.policy.max_observation_age_hours * 3_600:
            status = "stale"
            reason = "Measured window is older than the configured freshness limit."
        elif item.sample_size < inputs.policy.minimum_sample_size:
            status = "insufficient_sample"
            reason = "Observation does not meet the configured sample floor."
        elif item.metric in definition.required_metrics:
            status = "eligible"
            reason = "Verified, fresh, required workflow evidence."
        else:
            status = "context_only"
            reason = "Verified supporting evidence outside the required KPI set."
        findings.append(
            ProfitMetricFinding(
                evidence_ref=item.evidence_ref,
                provider=item.provider,
                connector_account_ref=item.connector_account_ref,
                subject_account_refs=item.subject_account_refs,
                metric=item.metric,
                value=item.value,
                unit=item.unit,
                status=status,
                age_hours=age_hours,
                primary_metric=item.metric == definition.primary_metric,
                reason=reason,
            )
        )
    return tuple(findings)


def _baseline_summary(ledger: ProfitContributionLedger) -> ProfitBaselineSummary:
    attributable_cost = (
        ledger.cogs
        + ledger.fulfillment_cost
        + ledger.payment_fees
        + ledger.acquisition_cost
        + ledger.service_cost
    ).quantize(_MONEY_QUANTUM)
    margin = None
    if ledger.net_revenue > 0:
        margin = (ledger.contribution_profit / ledger.net_revenue).quantize(
            _RATE_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
    return ProfitBaselineSummary(
        currency=ledger.currency,
        gross_sales=ledger.gross_sales,
        net_revenue=ledger.net_revenue,
        total_attributable_cost=attributable_cost,
        contribution_profit=ledger.contribution_profit,
        contribution_margin_rate=margin,
    )


class _ScoredCandidate(_StrictModel):
    candidate_ref: PortableRef
    gross_incremental_profit: Decimal
    risk_adjusted_profit: Decimal
    cash_required: Decimal
    effective_confidence: Decimal
    priority_score: Decimal
    evidence_verified: bool
    preliminary_disposition: CandidateDisposition | None = None

    @field_validator(
        "gross_incremental_profit",
        "risk_adjusted_profit",
        "cash_required",
        mode="before",
    )
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("effective_confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("priority_score", mode="before")
    @classmethod
    def _priority(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_SCORE_QUANTUM)


def _score_candidates(
    inputs: PlanProfitWorkflowInput,
    *,
    capabilities: Mapping[str, ProfitCapabilityContract],
    findings: tuple[ProfitMetricFinding, ...],
) -> tuple[tuple[ProfitCandidateDecision, ...], set[str]]:
    finding_by_ref = {item.evidence_ref: item for item in findings}
    candidates = {item.candidate_ref: item for item in inputs.candidates}
    scored: dict[str, _ScoredCandidate] = {}
    for candidate in inputs.candidates:
        support = [finding_by_ref[ref] for ref in candidate.supported_by_evidence_refs]
        target_provider = _ACTION_PROVIDER.get(candidate.capability)
        account_consistent = (
            all(
                (
                    candidate.target_account_ref in finding.subject_account_refs
                    if finding.provider == "host"
                    else finding.provider != target_provider
                    or finding.connector_account_ref == candidate.target_account_ref
                )
                for finding in support
            )
            if target_provider is not None
            else True
        )
        evidence_verified = (
            bool(support)
            and all(
                finding.status in {"eligible", "context_only"} for finding in support
            )
            and account_consistent
        )
        effective_confidence = candidate.confidence
        if not evidence_verified:
            effective_confidence = (
                effective_confidence * inputs.policy.unverified_confidence_haircut
            ).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)
        gross = (
            candidate.expected_incremental_revenue - candidate.expected_incremental_cost
        ).quantize(_MONEY_QUANTUM)
        risk_adjusted = (
            effective_confidence * gross
            - (Decimal("1") - effective_confidence) * candidate.downside_loss
            - candidate.implementation_cost
        ).quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)
        cash = (
            candidate.expected_incremental_cost + candidate.implementation_cost
        ).quantize(_MONEY_QUANTUM)
        denominator = max(cash, Decimal("1"))
        time_discount = Decimal("30") / Decimal(30 + candidate.time_to_value_days)
        priority = (risk_adjusted / denominator * time_discount).quantize(
            _SCORE_QUANTUM,
            rounding=ROUND_HALF_UP,
        )
        contract = capabilities[candidate.capability]
        preliminary: CandidateDisposition | None = None
        if contract.availability == "host_service_missing":
            preliminary = "blocked_capability"
        elif effective_confidence < inputs.policy.minimum_confidence:
            preliminary = "below_confidence_floor"
        elif risk_adjusted < inputs.policy.minimum_expected_profit:
            preliminary = "below_profit_floor"
        scored[candidate.candidate_ref] = _ScoredCandidate(
            candidate_ref=candidate.candidate_ref,
            gross_incremental_profit=gross,
            risk_adjusted_profit=risk_adjusted,
            cash_required=cash,
            effective_confidence=effective_confidence,
            priority_score=priority,
            evidence_verified=evidence_verified,
            preliminary_disposition=preliminary,
        )

    ranked_refs = sorted(
        candidates,
        key=lambda ref: (
            -scored[ref].risk_adjusted_profit,
            -scored[ref].priority_score,
            ref,
        ),
    )
    ordered_refs = tuple(candidate.candidate_ref for candidate in inputs.candidates)
    remaining_profit: list[Decimal] = [Decimal("0")] * (len(ordered_refs) + 1)
    for index in range(len(ordered_refs) - 1, -1, -1):
        item = scored[ordered_refs[index]]
        remaining_profit[index] = remaining_profit[index + 1] + (
            max(item.risk_adjusted_profit, Decimal("0"))
            if item.preliminary_disposition is None
            else Decimal("0")
        )

    best_selected: tuple[str, ...] = ()
    best_profit = Decimal("0")
    best_priority = Decimal("0")
    best_cash = Decimal("0")

    def is_better(
        refs: tuple[str, ...],
        profit: Decimal,
        priority: Decimal,
        cash: Decimal,
    ) -> bool:
        nonlocal best_selected, best_profit, best_priority, best_cash
        score = (profit, priority, -cash, -Decimal(len(refs)))
        best_score = (
            best_profit,
            best_priority,
            -best_cash,
            -Decimal(len(best_selected)),
        )
        return score > best_score or (
            score == best_score and tuple(sorted(refs)) < tuple(sorted(best_selected))
        )

    def search(
        index: int,
        refs: tuple[str, ...],
        selected_refs: frozenset[str],
        selected_groups: frozenset[str],
        cash: Decimal,
        profit: Decimal,
        priority: Decimal,
    ) -> None:
        nonlocal best_selected, best_profit, best_priority, best_cash
        if profit + remaining_profit[index] < best_profit:
            return
        if index == len(ordered_refs):
            if is_better(refs, profit, priority, cash):
                best_selected = refs
                best_profit = profit
                best_priority = priority
                best_cash = cash
            return

        ref = ordered_refs[index]
        candidate = candidates[ref]
        item = scored[ref]
        search(
            index + 1,
            refs,
            selected_refs,
            selected_groups,
            cash,
            profit,
            priority,
        )
        group = candidate.mutually_exclusive_group
        if (
            item.preliminary_disposition is not None
            or len(refs) >= inputs.policy.max_actions
            or any(
                dependency not in selected_refs for dependency in candidate.depends_on
            )
            or (group is not None and group in selected_groups)
            or cash + item.cash_required > inputs.policy.budget_cap
        ):
            return
        search(
            index + 1,
            (*refs, ref),
            selected_refs.union({ref}),
            selected_groups.union({group}) if group is not None else selected_groups,
            cash + item.cash_required,
            profit + item.risk_adjusted_profit,
            priority + item.priority_score,
        )

    search(
        0,
        (),
        frozenset(),
        frozenset(),
        Decimal("0"),
        Decimal("0"),
        Decimal("0"),
    )
    selected = set(best_selected)
    selected_groups = {
        candidates[ref].mutually_exclusive_group
        for ref in selected
        if candidates[ref].mutually_exclusive_group is not None
    }
    used_budget = sum(
        (scored[ref].cash_required for ref in selected),
        Decimal("0"),
    )

    decisions: list[ProfitCandidateDecision] = []
    for rank, ref in enumerate(ranked_refs, 1):
        candidate = candidates[ref]
        item = scored[ref]
        if ref in selected:
            disposition: CandidateDisposition = "selected"
            reason = (
                "Selected inside confidence, profit, budget, and dependency bounds."
            )
        else:
            disposition = item.preliminary_disposition
            if disposition is None:
                if any(
                    dependency not in selected for dependency in candidate.depends_on
                ):
                    disposition = "dependency_not_selected"
                elif (
                    candidate.mutually_exclusive_group is not None
                    and candidate.mutually_exclusive_group in selected_groups
                ):
                    disposition = "mutually_exclusive"
                elif used_budget + item.cash_required > inputs.policy.budget_cap:
                    disposition = "budget_exceeded"
                else:
                    disposition = "selection_limit"
            reason = {
                "below_confidence_floor": "Effective confidence is below policy floor.",
                "below_profit_floor": "Risk-adjusted profit is below policy floor.",
                "blocked_capability": "Required materialization capability does not exist.",
                "budget_exceeded": "Candidate would exceed the bounded cash envelope.",
                "dependency_not_selected": "A required predecessor was not selected.",
                "mutually_exclusive": "A stronger mutually exclusive candidate was selected.",
                "selection_limit": "A stronger set filled the bounded action limit.",
                "selected": "Selected.",
            }[disposition]
        decisions.append(
            ProfitCandidateDecision(
                candidate_ref=ref,
                rank=rank,
                disposition=disposition,
                declared_confidence=candidate.confidence,
                effective_confidence=item.effective_confidence,
                gross_incremental_profit=item.gross_incremental_profit,
                risk_adjusted_profit=item.risk_adjusted_profit,
                cash_required=item.cash_required,
                priority_score=item.priority_score,
                evidence_verified=item.evidence_verified,
                reason=reason,
            )
        )
    return tuple(decisions), selected


def _actions(
    definition: ProfitWorkflowDefinition,
    inputs: PlanProfitWorkflowInput,
    decisions: tuple[ProfitCandidateDecision, ...],
    selected: set[str],
    *,
    capabilities: Mapping[str, ProfitCapabilityContract],
    evidence_scope: ProfitEvidenceScope,
) -> tuple[GovernedProfitAction, ...]:
    decision_by_ref = {item.candidate_ref: item for item in decisions}
    operation_refs: dict[str, str] = {}
    actions: list[GovernedProfitAction] = []
    for candidate in inputs.candidates:
        if candidate.candidate_ref not in selected:
            continue
        contract = capabilities[candidate.capability]
        seed = _stable_digest(
            {
                "workflow_id": definition.workflow_id,
                "plan_ref": inputs.plan_ref,
                "candidate": candidate.model_dump(mode="json", exclude_none=True),
            }
        )
        operation_ref = (
            f"{definition.workflow_id.replace('.', '_')}."
            f"{candidate.candidate_ref}.{seed[:16]}"
        )
        operation_refs[candidate.candidate_ref] = operation_ref
        actions.append(
            GovernedProfitAction(
                ordinal=len(actions) + 1,
                operation_ref=operation_ref,
                candidate_ref=candidate.candidate_ref,
                title=candidate.title,
                capability=candidate.capability,
                execution_kind=contract.execution_kind,
                effect=contract.effect,
                availability=contract.availability,
                disposition=(
                    "blocked_capability"
                    if contract.availability == "host_service_missing"
                    else "proposal"
                ),
                target_account_ref=candidate.target_account_ref,
                exact_scope_digest=evidence_scope.exact_scope_digest,
                intent_parameters=candidate.parameters,
                depends_on=tuple(
                    operation_refs[dependency] for dependency in candidate.depends_on
                ),
                expected_risk_adjusted_profit=decision_by_ref[
                    candidate.candidate_ref
                ].risk_adjusted_profit,
                approval_required=contract.effect == "WRITE",
            )
        )
    return tuple(actions)


def _capability_gaps(
    definition: ProfitWorkflowDefinition,
    findings: tuple[ProfitMetricFinding, ...],
) -> tuple[ProfitCapabilityGap, ...]:
    gaps: list[ProfitCapabilityGap] = []
    eligible_metrics = {
        finding.metric for finding in findings if finding.status == "eligible"
    }
    for metric in definition.required_metrics:
        if metric not in eligible_metrics:
            matching_source = next(
                (
                    capability
                    for capability in definition.evidence_capabilities
                    if metric
                    in _SOURCE_CAPABILITIES.get(
                        capability,
                        ("host", frozenset()),
                    )[1]
                ),
                definition.evidence_capabilities[0],
            )
            gaps.append(
                ProfitCapabilityGap(
                    code="verified_metric_missing",
                    capability=matching_source,
                    severity="blocking",
                    message=(
                        f"No fresh, sufficiently sampled, exact-scope evidence was "
                        f"available for required metric {metric}."
                    ),
                )
            )
    for contract in definition.action_capabilities:
        if contract.availability in {
            "sdk_available",
            "trusted_host_materializer_available",
        }:
            continue
        gaps.append(
            ProfitCapabilityGap(
                code=f"materializer_{contract.availability}",
                capability=contract.capability,
                severity=(
                    "blocking"
                    if contract.availability == "host_service_missing"
                    else "info"
                ),
                message=contract.notes,
            )
        )
    return tuple(gaps)


def plan_profit_workflow(
    workflow_id: ProfitWorkflowId | str,
    value: PlanProfitWorkflowInput | Mapping[str, Any],
    *,
    verified_scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ProfitScopeKeyRing | None = None,
    scope_key_id: str | None = None,
) -> ProfitWorkflowPlan:
    """Compile one deterministic, risk-adjusted, proposal-only profit workflow."""

    definition = get_profit_workflow_definition(workflow_id)
    inputs = _parse_plan_input(value)
    evidence_scope = _evidence_scope(
        verified_scope=verified_scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )
    capabilities = _workflow_input_contract(
        definition,
        inputs,
        evidence_scope=evidence_scope,
        scope_keyring=scope_keyring,
    )
    findings = _metric_findings(
        definition,
        inputs,
        evidence_scope=evidence_scope,
        scope_keyring=scope_keyring,
    )
    decisions, selected = _score_candidates(
        inputs,
        capabilities=capabilities,
        findings=findings,
    )
    actions = _actions(
        definition,
        inputs,
        decisions,
        selected,
        capabilities=capabilities,
        evidence_scope=evidence_scope,
    )
    gaps = _capability_gaps(definition, findings)
    eligible_metrics = {item.metric for item in findings if item.status == "eligible"}
    if set(definition.required_metrics).issubset(eligible_metrics):
        optimization_status: OptimizationStatus = "evidence_optimized"
    elif findings:
        optimization_status = "partially_evidence_informed"
    else:
        optimization_status = "assumption_ranked"
    baseline = _baseline_summary(inputs.baseline)
    estimated_profit = sum(
        (
            item.risk_adjusted_profit
            for item in decisions
            if item.disposition == "selected"
        ),
        Decimal("0"),
    ).quantize(_MONEY_QUANTUM)
    summary = (
        f"Planned {len(actions)} of {len(inputs.candidates)} bounded profit action(s) "
        f"for {definition.title}. Estimated risk-adjusted incremental contribution "
        f"profit is {inputs.baseline.currency} {estimated_profit}; estimates remain "
        "assumptions until the signed post-action measurement loop completes. No "
        "connector, domain action, SDK primitive, or live system was invoked."
    )
    plan_fields: dict[str, Any] = {
        "workflow_id": definition.workflow_id,
        "workflow_ordinal": definition.ordinal,
        "blueprint_digest": _stable_digest(
            definition.model_dump(mode="json", exclude_none=True)
        ),
        "plan_ref": inputs.plan_ref,
        "launch_ref": inputs.launch_ref,
        "analysis_as_of": inputs.analysis_as_of,
        "objective": inputs.objective,
        "source_plan_digests": inputs.source_plan_digests,
        "account_bindings": inputs.account_bindings,
        "evidence_scope": evidence_scope,
        "optimization_status": optimization_status,
        "baseline": baseline,
        "metric_findings": findings,
        "candidate_decisions": decisions,
        "actions": actions,
        "capability_gaps": gaps,
        "evaluation_loop": ProfitEvaluationLoop(
            target_metric=definition.primary_metric,
            target_unit=_METRIC_UNITS[definition.primary_metric],
            target_direction=definition.target_direction,
            target_value=inputs.policy.target_value,
            minimum_sample_size=inputs.policy.minimum_sample_size,
            max_observation_age_hours=inputs.policy.max_observation_age_hours,
            measurement_window_hours=inputs.policy.measurement_window_hours,
            max_iterations=inputs.policy.max_iterations,
            stages=("approve", "materialize", "observe", "evaluate", "revise"),
            stop_conditions=(
                "target_met",
                "iteration_limit_reached",
                "approval_revoked",
                "evidence_missing",
                "stop_loss_triggered",
            ),
        ),
        "estimated_incremental_profit": estimated_profit,
        "estimated_post_plan_contribution_profit": (
            baseline.contribution_profit + estimated_profit
        ).quantize(_MONEY_QUANTUM),
        "summary": summary,
    }
    if evidence_scope.status == "host_hmac_verified":
        assert scope_keyring is not None
        plan_fields.update(
            {
                "receipt_key_id": evidence_scope.receipt_key_id,
                "exact_scope_digest": evidence_scope.exact_scope_digest,
                "plan_hmac": "0" * 64,
            }
        )
        draft = ProfitWorkflowPlan.model_validate(plan_fields)
        signature = scope_keyring.sign(
            evidence_scope.receipt_key_id,
            _PROFIT_PLAN_HMAC_DOMAIN,
            draft.hmac_payload(),
        ).hex()
        plan_fields = draft.model_dump(mode="python", by_alias=True, exclude_none=True)
        plan_fields["plan_hmac"] = signature
    try:
        return ProfitWorkflowPlan.model_validate(plan_fields)
    except ValidationError:
        raise ProfitWorkflowValidationError(
            "Profit workflow plan failed immutable output validation"
        ) from None


def verify_profit_workflow_plan(
    value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitWorkflowPlan:
    """Revalidate and authenticate a host-bound plan before trusted use."""

    plan = ProfitWorkflowPlan.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, ProfitWorkflowPlan)
        else value
    )
    if (
        plan.evidence_scope.status != "host_hmac_verified"
        or plan.receipt_key_id is None
        or plan.exact_scope_digest is None
        or plan.plan_hmac is None
    ):
        raise ValueError("trusted profit workflow use requires a host-HMAC plan")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    expected_scope = scope_keyring.exact_scope_digest(
        key_id=plan.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(plan.exact_scope_digest, expected_scope):
        raise ValueError(
            "profit workflow plan scope does not match authenticated scope"
        )
    expected_hmac = scope_keyring.sign(
        plan.receipt_key_id,
        _PROFIT_PLAN_HMAC_DOMAIN,
        plan.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(plan.plan_hmac, expected_hmac):
        raise ValueError("profit workflow plan HMAC is invalid")
    if any(
        not _account_binding_attestation_matches(
            binding,
            evidence_scope=plan.evidence_scope,
            scope_keyring=scope_keyring,
        )
        for binding in plan.account_bindings
    ):
        raise ValueError("profit workflow connector account binding HMAC is invalid")
    return plan


class ProfitActionExecutionReceipt(_StrictModel):
    """Host-sealed proof that one exact planned action completed."""

    schema_id: Literal["lightbulb.profit_action_execution_receipt.v1"] = Field(
        default=PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA,
        alias="schema",
    )
    workflow_id: ProfitWorkflowId
    plan_digest: Sha256Digest
    run_ref: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    )
    iteration: int = Field(ge=1, le=4)
    operation_ref: str = Field(
        min_length=1,
        max_length=180,
        pattern=r"^[a-z][a-z0-9_.:-]{0,179}$",
    )
    operation_digest: Sha256Digest
    capability: CapabilityRef
    target_account_ref: ShortText | None = None
    approval_unit: str | None = Field(default=None, min_length=1, max_length=500)
    approval_receipt_digest: Sha256Digest | None = None
    completed_at: str
    effect_receipt_digest: Sha256Digest
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: Sha256Digest
    execution_hmac: Sha256Digest
    execution_digest: Sha256Digest = "0" * 64

    @field_validator("completed_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _seal_execution(self) -> "ProfitActionExecutionReceipt":
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"execution_hmac", "execution_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.execution_digest not in {"0" * 64, expected}:
            raise ValueError(
                "execution_digest does not match canonical action receipt content"
            )
        object.__setattr__(self, "execution_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"execution_hmac"},
            exclude_none=True,
        )


class ProfitOutcomeEvidence(_StrictModel):
    schema_id: Literal["lightbulb.profit_outcome_evidence.v1"] = Field(
        default=PROFIT_OUTCOME_EVIDENCE_SCHEMA,
        alias="schema",
    )
    workflow_id: ProfitWorkflowId
    plan_digest: Sha256Digest
    run_ref: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    )
    iteration: int = Field(ge=1, le=4)
    commitment_ref: str = Field(min_length=1, max_length=420)
    action_receipts: tuple[ProfitActionExecutionReceipt, ...] = Field(
        min_length=1,
        max_length=10,
    )
    observation: ProfitMetricEvidence
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: Sha256Digest
    outcome_hmac: Sha256Digest
    outcome_digest: Sha256Digest = "0" * 64

    @field_validator("action_receipts", mode="before")
    @classmethod
    def _immutable_receipts(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _seal_outcome(self) -> "ProfitOutcomeEvidence":
        expected_commitment = (
            f"profit-outcome:{self.workflow_id}:{self.plan_digest}:"
            f"{self.run_ref}:i{self.iteration}"
        )
        if self.commitment_ref != expected_commitment:
            raise ValueError("outcome commitment_ref does not match plan/run/iteration")
        operation_refs = [item.operation_ref for item in self.action_receipts]
        if len(operation_refs) != len(set(operation_refs)):
            raise ValueError("outcome action receipt operation refs must be unique")
        if any(
            item.workflow_id != self.workflow_id
            or item.plan_digest != self.plan_digest
            or item.run_ref != self.run_ref
            or item.iteration != self.iteration
            or item.receipt_key_id != self.receipt_key_id
            or item.exact_scope_digest != self.exact_scope_digest
            for item in self.action_receipts
        ):
            raise ValueError(
                "outcome action receipts do not match the outcome envelope"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"outcome_hmac", "outcome_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.outcome_digest not in {"0" * 64, expected}:
            raise ValueError("outcome_digest does not match canonical outcome content")
        object.__setattr__(self, "outcome_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"outcome_hmac"},
            exclude_none=True,
        )


EvaluationDecision = Literal[
    "target_met",
    "revise_plan",
    "iteration_limit_reached",
]


class ProfitWorkflowEvaluation(_StrictModel):
    schema_id: Literal["lightbulb.profit_workflow_evaluation.v1"] = Field(
        default=PROFIT_WORKFLOW_EVALUATION_SCHEMA,
        alias="schema",
    )
    workflow_id: ProfitWorkflowId
    plan_digest: Sha256Digest
    run_ref: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    )
    iteration: int = Field(ge=1, le=4)
    evaluated_at: str
    metric: ProfitMetric
    unit: MetricUnit
    observed_value: Decimal
    target_value: Decimal
    target_direction: TargetDirection
    decision: EvaluationDecision
    next_iteration: int | None = Field(default=None, ge=2, le=4)
    previous_evaluation_digest: Sha256Digest | None = None
    outcome_digest: Sha256Digest
    summary: LongText
    receipt_key_id: str = Field(min_length=8, max_length=80)
    exact_scope_digest: Sha256Digest
    evaluation_hmac: Sha256Digest
    evaluation_digest: Sha256Digest = "0" * 64

    @field_validator("evaluated_at")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("observed_value", "target_value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _seal_evaluation(self) -> "ProfitWorkflowEvaluation":
        quantum = _MONEY_QUANTUM if self.unit == "money" else _RATE_QUANTUM
        object.__setattr__(
            self, "observed_value", self.observed_value.quantize(quantum)
        )
        object.__setattr__(self, "target_value", self.target_value.quantize(quantum))
        if (self.decision == "revise_plan") != (self.next_iteration is not None):
            raise ValueError("only revise_plan evaluations may name a next iteration")
        if self.iteration == 1 and self.previous_evaluation_digest is not None:
            raise ValueError("iteration one must not name a previous evaluation")
        if self.iteration > 1 and self.previous_evaluation_digest is None:
            raise ValueError("later iterations require the previous evaluation digest")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_hmac", "evaluation_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.evaluation_digest not in {"0" * 64, expected}:
            raise ValueError(
                "evaluation_digest does not match canonical evaluation content"
            )
        object.__setattr__(self, "evaluation_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_hmac"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def mint_profit_action_execution_receipt(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    *,
    operation_ref: str,
    effect_receipt_digest: str,
    approval_receipt_digest: str | None = None,
    completed_at: datetime,
    run_ref: str,
    iteration: int,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitActionExecutionReceipt:
    """Mint trusted proof from one governed action result or local artifact."""

    plan = verify_profit_workflow_plan(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    if completed_at.tzinfo is None or completed_at.utcoffset() is None:
        raise ValueError("completed_at must include a UTC offset")
    try:
        action = next(
            item for item in plan.actions if item.operation_ref == operation_ref
        )
    except StopIteration:
        raise ValueError(
            "operation_ref is not part of the authenticated plan"
        ) from None
    if action.disposition != "proposal":
        raise ValueError("blocked actions cannot receive completion receipts")
    if action.approval_required and approval_receipt_digest is None:
        raise ValueError(
            "WRITE action execution requires a governed approval receipt digest"
        )
    if not action.approval_required and approval_receipt_digest is not None:
        raise ValueError("DRAFT action execution must not consume a write approval")
    if iteration < 1 or iteration > plan.evaluation_loop.max_iterations:
        raise ValueError("execution receipt iteration exceeds the bounded plan loop")
    draft = ProfitActionExecutionReceipt(
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        run_ref=run_ref,
        iteration=iteration,
        operation_ref=action.operation_ref,
        operation_digest=action.operation_digest,
        capability=action.capability,
        target_account_ref=action.target_account_ref,
        approval_unit=action.approval_unit,
        approval_receipt_digest=approval_receipt_digest,
        completed_at=completed_at.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        effect_receipt_digest=effect_receipt_digest,
        receipt_key_id=plan.receipt_key_id,
        exact_scope_digest=plan.exact_scope_digest,
        execution_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        draft.receipt_key_id,
        _PROFIT_ACTION_EXECUTION_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    payload = draft.model_dump(mode="python", by_alias=True)
    payload["execution_hmac"] = signature
    return ProfitActionExecutionReceipt.model_validate(payload)


def _verify_profit_action_execution_receipt(
    value: ProfitActionExecutionReceipt | Mapping[str, Any],
    *,
    plan: ProfitWorkflowPlan,
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitActionExecutionReceipt:
    receipt = ProfitActionExecutionReceipt.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, ProfitActionExecutionReceipt)
        else value
    )
    try:
        action = next(
            item for item in plan.actions if item.operation_ref == receipt.operation_ref
        )
    except StopIteration:
        raise ValueError("action execution receipt is not part of the plan") from None
    if (
        receipt.workflow_id != plan.workflow_id
        or receipt.plan_digest != plan.plan_digest
        or receipt.operation_digest != action.operation_digest
        or receipt.capability != action.capability
        or receipt.target_account_ref != action.target_account_ref
        or receipt.approval_unit != action.approval_unit
        or receipt.receipt_key_id != plan.receipt_key_id
        or receipt.exact_scope_digest != plan.exact_scope_digest
    ):
        raise ValueError(
            "action execution receipt does not match the authenticated plan"
        )
    if action.approval_required != (receipt.approval_receipt_digest is not None):
        raise ValueError("action execution receipt approval proof is incomplete")
    expected_hmac = scope_keyring.sign(
        receipt.receipt_key_id,
        _PROFIT_ACTION_EXECUTION_HMAC_DOMAIN,
        receipt.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(receipt.execution_hmac, expected_hmac):
        raise ValueError("profit action execution receipt HMAC is invalid")
    return receipt


def verify_profit_action_execution_receipt(
    value: ProfitActionExecutionReceipt | Mapping[str, Any],
    *,
    plan: ProfitWorkflowPlan | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitActionExecutionReceipt:
    """Verify one action receipt against the current scope and authenticated plan."""

    verified_plan = verify_profit_workflow_plan(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    return _verify_profit_action_execution_receipt(
        value,
        plan=verified_plan,
        scope_keyring=scope_keyring,
    )


def mint_profit_outcome_evidence(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    observation_value: ProfitMetricEvidence | Mapping[str, Any],
    *,
    action_receipts: Iterable[ProfitActionExecutionReceipt | Mapping[str, Any]],
    run_ref: str,
    iteration: int,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitOutcomeEvidence:
    """Bind one verified post-action observation to an exact plan/run/iteration."""

    plan = verify_profit_workflow_plan(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    observation = ProfitMetricEvidence.model_validate(
        observation_value.model_dump(mode="python")
        if isinstance(observation_value, ProfitMetricEvidence)
        else observation_value
    )
    if observation.metric != plan.evaluation_loop.target_metric:
        raise ValueError("outcome observation must measure the plan target metric")
    if observation.unit != plan.evaluation_loop.target_unit:
        raise ValueError("outcome observation unit does not match the plan target")
    if not _evidence_attestation_matches(
        observation,
        evidence_scope=plan.evidence_scope,
        scope_keyring=scope_keyring,
    ):
        raise ValueError("outcome observation is not authenticated for plan scope")
    definition = get_profit_workflow_definition(plan.workflow_id)
    if observation.source_capability not in definition.evidence_capabilities:
        raise ValueError("outcome observation source is not allowed by the workflow")
    if observation.metric not in definition.supported_metrics:
        raise ValueError("outcome observation metric is not supported by the workflow")
    if (
        observation.currency is not None
        and observation.currency != plan.baseline.currency
    ):
        raise ValueError("outcome observation currency does not match plan baseline")
    declared_bindings = {
        (item.provider, item.connector_account_ref) for item in plan.account_bindings
    }
    if (
        observation.provider != "host"
        and (observation.provider, observation.connector_account_ref)
        not in declared_bindings
    ):
        raise ValueError("outcome observation connector account is not in the plan")
    if not plan.actions:
        raise ValueError("post-action evaluation requires at least one planned action")
    target_accounts = {
        item.target_account_ref for item in plan.actions if item.target_account_ref
    }
    target_bindings = {
        (_ACTION_PROVIDER[item.capability], item.target_account_ref)
        for item in plan.actions
        if item.capability in _ACTION_PROVIDER and item.target_account_ref is not None
    }
    if observation.provider == "host" and not target_accounts.issubset(
        observation.subject_account_refs
    ):
        raise ValueError(
            "host outcome evidence is not bound to every targeted connector account"
        )
    if (
        observation.provider != "host"
        and target_bindings
        and target_bindings
        != {(observation.provider, observation.connector_account_ref)}
    ):
        raise ValueError(
            "connector outcome cannot cover actions targeting another provider account; "
            "use host-normalized evidence bound to every target account"
        )
    if iteration < 1 or iteration > plan.evaluation_loop.max_iterations:
        raise ValueError("outcome iteration exceeds the bounded plan loop")
    parsed_receipts: list[ProfitActionExecutionReceipt] = []
    for raw_receipt in action_receipts:
        if len(parsed_receipts) >= len(plan.actions):
            raise ValueError("too many action materialization receipts")
        receipt = _verify_profit_action_execution_receipt(
            raw_receipt,
            plan=plan,
            scope_keyring=scope_keyring,
        )
        if receipt.run_ref != run_ref or receipt.iteration != iteration:
            raise ValueError("action materialization receipt run or iteration mismatch")
        parsed_receipts.append(receipt)
    if {item.operation_ref for item in parsed_receipts} != {
        item.operation_ref for item in plan.actions
    }:
        raise ValueError(
            "post-action outcome requires one verified materialization receipt "
            "for every planned action"
        )
    latest_completion = max(
        _parse_timestamp(item.completed_at) for item in parsed_receipts
    )
    if _parse_timestamp(observation.window_start) < latest_completion:
        raise ValueError("outcome window must start after every action completed")
    draft = ProfitOutcomeEvidence(
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        run_ref=run_ref,
        iteration=iteration,
        commitment_ref=(
            f"profit-outcome:{plan.workflow_id}:{plan.plan_digest}:"
            f"{run_ref}:i{iteration}"
        ),
        action_receipts=tuple(parsed_receipts),
        observation=observation,
        receipt_key_id=plan.receipt_key_id,
        exact_scope_digest=plan.exact_scope_digest,
        outcome_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        draft.receipt_key_id,
        _PROFIT_OUTCOME_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    payload = draft.model_dump(mode="python", by_alias=True)
    payload["outcome_hmac"] = signature
    return ProfitOutcomeEvidence.model_validate(payload)


def _verify_profit_outcome(
    value: ProfitOutcomeEvidence | Mapping[str, Any],
    *,
    plan: ProfitWorkflowPlan,
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitOutcomeEvidence:
    outcome = ProfitOutcomeEvidence.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, ProfitOutcomeEvidence)
        else value
    )
    if (
        outcome.workflow_id != plan.workflow_id
        or outcome.plan_digest != plan.plan_digest
        or outcome.receipt_key_id != plan.receipt_key_id
        or outcome.exact_scope_digest != plan.exact_scope_digest
    ):
        raise ValueError("outcome evidence does not match the authenticated plan")
    expected_hmac = scope_keyring.sign(
        outcome.receipt_key_id,
        _PROFIT_OUTCOME_HMAC_DOMAIN,
        outcome.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(outcome.outcome_hmac, expected_hmac):
        raise ValueError("profit outcome HMAC is invalid")
    if not _evidence_attestation_matches(
        outcome.observation,
        evidence_scope=plan.evidence_scope,
        scope_keyring=scope_keyring,
    ):
        raise ValueError("nested profit observation HMAC is invalid")
    definition = get_profit_workflow_definition(plan.workflow_id)
    if outcome.observation.source_capability not in definition.evidence_capabilities:
        raise ValueError("outcome observation source is not allowed by the workflow")
    if outcome.observation.metric != plan.evaluation_loop.target_metric:
        raise ValueError("outcome observation does not measure the plan target")
    if (
        outcome.observation.currency is not None
        and outcome.observation.currency != plan.baseline.currency
    ):
        raise ValueError("outcome observation currency does not match plan baseline")
    declared_bindings = {
        (item.provider, item.connector_account_ref) for item in plan.account_bindings
    }
    if (
        outcome.observation.provider != "host"
        and (
            outcome.observation.provider,
            outcome.observation.connector_account_ref,
        )
        not in declared_bindings
    ):
        raise ValueError("outcome observation connector account is not in the plan")
    target_accounts = {
        item.target_account_ref for item in plan.actions if item.target_account_ref
    }
    target_bindings = {
        (_ACTION_PROVIDER[item.capability], item.target_account_ref)
        for item in plan.actions
        if item.capability in _ACTION_PROVIDER and item.target_account_ref is not None
    }
    if outcome.observation.provider == "host" and not target_accounts.issubset(
        outcome.observation.subject_account_refs
    ):
        raise ValueError(
            "host outcome evidence is not bound to every targeted connector account"
        )
    if (
        outcome.observation.provider != "host"
        and target_bindings
        and target_bindings
        != {
            (
                outcome.observation.provider,
                outcome.observation.connector_account_ref,
            )
        }
    ):
        raise ValueError(
            "connector outcome cannot cover actions targeting another provider account"
        )
    verified_receipts = tuple(
        _verify_profit_action_execution_receipt(
            receipt,
            plan=plan,
            scope_keyring=scope_keyring,
        )
        for receipt in outcome.action_receipts
    )
    if {item.operation_ref for item in verified_receipts} != {
        item.operation_ref for item in plan.actions
    }:
        raise ValueError("outcome is missing a planned action execution receipt")
    if any(
        item.run_ref != outcome.run_ref or item.iteration != outcome.iteration
        for item in verified_receipts
    ):
        raise ValueError("outcome action receipt run or iteration mismatch")
    latest_completion = max(
        _parse_timestamp(item.completed_at) for item in verified_receipts
    )
    if _parse_timestamp(outcome.observation.window_start) < latest_completion:
        raise ValueError("outcome window predates an action execution receipt")
    return outcome


def verify_profit_workflow_evaluation(
    value: ProfitWorkflowEvaluation | Mapping[str, Any],
    *,
    plan: ProfitWorkflowPlan | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
) -> ProfitWorkflowEvaluation:
    verified_plan = verify_profit_workflow_plan(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    evaluation = ProfitWorkflowEvaluation.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, ProfitWorkflowEvaluation)
        else value
    )
    if (
        evaluation.workflow_id != verified_plan.workflow_id
        or evaluation.plan_digest != verified_plan.plan_digest
        or evaluation.receipt_key_id != verified_plan.receipt_key_id
        or evaluation.exact_scope_digest != verified_plan.exact_scope_digest
    ):
        raise ValueError("evaluation does not match the authenticated plan")
    expected_hmac = scope_keyring.sign(
        evaluation.receipt_key_id,
        _PROFIT_EVALUATION_HMAC_DOMAIN,
        evaluation.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(evaluation.evaluation_hmac, expected_hmac):
        raise ValueError("profit evaluation HMAC is invalid")
    return evaluation


def evaluate_profit_workflow_iteration(
    plan_value: ProfitWorkflowPlan | Mapping[str, Any],
    outcome_value: ProfitOutcomeEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ProfitScopeKeyRing,
    evaluated_at: datetime,
    previous_evaluation: ProfitWorkflowEvaluation | Mapping[str, Any] | None = None,
) -> ProfitWorkflowEvaluation:
    """Evaluate one fresh KPI window and authorize at most one next revision."""

    plan = verify_profit_workflow_plan(
        plan_value,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    outcome = _verify_profit_outcome(
        outcome_value,
        plan=plan,
        scope_keyring=scope_keyring,
    )
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must include a UTC offset")
    evaluated = evaluated_at.astimezone(timezone.utc)
    observation = outcome.observation
    window_start = _parse_timestamp(observation.window_start)
    window_end = _parse_timestamp(observation.window_end)
    observed_at = _parse_timestamp(observation.observed_at)
    if window_end > evaluated or observed_at > evaluated:
        raise ValueError("outcome observation cannot occur after evaluation")
    window_hours = (window_end - window_start).total_seconds() / 3_600
    if window_hours < plan.evaluation_loop.measurement_window_hours:
        raise ValueError("outcome measurement window is shorter than policy")
    if (
        evaluated - window_end
    ).total_seconds() > plan.evaluation_loop.max_observation_age_hours * 3_600:
        raise ValueError("outcome measurement window is stale")
    if observation.sample_size < plan.evaluation_loop.minimum_sample_size:
        raise ValueError("outcome sample is below the configured floor")
    if window_start < _parse_timestamp(plan.analysis_as_of):
        raise ValueError("outcome window must start after the planning cutoff")

    prior: ProfitWorkflowEvaluation | None = None
    if outcome.iteration == 1:
        if previous_evaluation is not None:
            raise ValueError("iteration one must not provide a previous evaluation")
    else:
        if previous_evaluation is None:
            raise ValueError("later iterations require a previous evaluation")
        prior = verify_profit_workflow_evaluation(
            previous_evaluation,
            plan=plan,
            scope=scope,
            scope_keyring=scope_keyring,
        )
        if (
            prior.run_ref != outcome.run_ref
            or prior.decision != "revise_plan"
            or prior.next_iteration != outcome.iteration
        ):
            raise ValueError("previous evaluation does not authorize this iteration")
        if window_start < _parse_timestamp(prior.evaluated_at):
            raise ValueError(
                "revised iteration requires fresh post-evaluation evidence"
            )

    target_met = (
        observation.value >= plan.evaluation_loop.target_value
        if plan.evaluation_loop.target_direction == "maximize"
        else observation.value <= plan.evaluation_loop.target_value
    )
    if target_met:
        decision: EvaluationDecision = "target_met"
        next_iteration = None
    elif outcome.iteration >= plan.evaluation_loop.max_iterations:
        decision = "iteration_limit_reached"
        next_iteration = None
    else:
        decision = "revise_plan"
        next_iteration = outcome.iteration + 1
    summary = (
        f"Iteration {outcome.iteration} measured {observation.metric}="
        f"{observation.value} against {plan.evaluation_loop.target_direction} target "
        f"{plan.evaluation_loop.target_value}; decision={decision}."
    )
    draft = ProfitWorkflowEvaluation(
        workflow_id=plan.workflow_id,
        plan_digest=plan.plan_digest,
        run_ref=outcome.run_ref,
        iteration=outcome.iteration,
        # Evaluation output is intentionally deterministic for one immutable
        # outcome. ``evaluated_at`` above remains the host freshness clock, while
        # the signed artifact uses the observation admission timestamp.
        evaluated_at=observation.observed_at,
        metric=observation.metric,
        unit=observation.unit,
        observed_value=observation.value,
        target_value=plan.evaluation_loop.target_value,
        target_direction=plan.evaluation_loop.target_direction,
        decision=decision,
        next_iteration=next_iteration,
        previous_evaluation_digest=(
            prior.evaluation_digest if prior is not None else None
        ),
        outcome_digest=outcome.outcome_digest,
        summary=summary,
        receipt_key_id=plan.receipt_key_id,
        exact_scope_digest=plan.exact_scope_digest,
        evaluation_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        draft.receipt_key_id,
        _PROFIT_EVALUATION_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    payload = draft.model_dump(mode="python", by_alias=True)
    payload["evaluation_hmac"] = signature
    return ProfitWorkflowEvaluation.model_validate(payload)


class ProfitFlywheelEdge(_StrictModel):
    source: str = Field(min_length=3, max_length=160)
    target: str = Field(min_length=3, max_length=160)
    handoff: ShortText
    feedback: bool = False


class ProfitFlywheelNode(_StrictModel):
    workflow_id: ProfitWorkflowId
    plan_ref: PortableRef
    plan_digest: Sha256Digest
    optimization_status: OptimizationStatus
    selected_action_count: int = Field(ge=0, le=10)
    blocking_gap_count: int = Field(ge=0, le=100)


_FLYWHEEL_EDGES: tuple[ProfitFlywheelEdge, ...] = (
    ProfitFlywheelEdge(
        source="finance.allocate_launch_portfolio_profit",
        target="product.discover_profitable_opportunities",
        handoff="Bounded capital envelope and portfolio stop-loss",
    ),
    ProfitFlywheelEdge(
        source="product.discover_profitable_opportunities",
        target="gtm.optimize_offer_price_and_margin",
        handoff="Ranked product, segment, store, and pilot thesis",
    ),
    ProfitFlywheelEdge(
        source="gtm.optimize_offer_price_and_margin",
        target="commerce.govern_inventory_and_fulfillment",
        handoff="Margin floor, price, bundle, and demand range",
    ),
    ProfitFlywheelEdge(
        source="gtm.optimize_offer_price_and_margin",
        target="commerce.optimize_storefront_conversion",
        handoff="Reviewed offer and experiment guardrails",
    ),
    ProfitFlywheelEdge(
        source="gtm.optimize_offer_price_and_margin",
        target="content.run_creative_experiment_factory",
        handoff="Offer, audience, margin floor, and claims guardrails",
    ),
    ProfitFlywheelEdge(
        source="commerce.govern_inventory_and_fulfillment",
        target="gtm.plan_omnichannel_product_launch",
        handoff="Inventory and fulfillment readiness gate",
    ),
    ProfitFlywheelEdge(
        source="commerce.optimize_storefront_conversion",
        target="gtm.plan_omnichannel_product_launch",
        handoff="Reviewed landing variant and conversion measurement contract",
    ),
    ProfitFlywheelEdge(
        source="content.run_creative_experiment_factory",
        target="gtm.plan_omnichannel_product_launch",
        handoff="Reviewed channel-native creative cells",
    ),
    ProfitFlywheelEdge(
        source="gtm.plan_omnichannel_product_launch",
        target="growth.allocate_incremental_acquisition",
        handoff="Verified live landing and launch receipts",
    ),
    ProfitFlywheelEdge(
        source="gtm.plan_omnichannel_product_launch",
        target="crm.orchestrate_profit_aware_lifecycle",
        handoff="Campaign, product, and audience correlation",
    ),
    ProfitFlywheelEdge(
        source="gtm.plan_omnichannel_product_launch",
        target="commerce.recover_abandoned_revenue",
        handoff="Verified live checkout, offer, and launch correlation",
    ),
    ProfitFlywheelEdge(
        source="gtm.plan_omnichannel_product_launch",
        target="customer_success.prevent_returns_and_expand_ltv",
        handoff="Product promise, order, and fulfillment context",
    ),
    ProfitFlywheelEdge(
        source="growth.allocate_incremental_acquisition",
        target="customer_success.prevent_returns_and_expand_ltv",
        handoff="Acquisition cohort, promise, spend, and payback context",
    ),
    ProfitFlywheelEdge(
        source="crm.orchestrate_profit_aware_lifecycle",
        target="customer_success.prevent_returns_and_expand_ltv",
        handoff="Consent-safe customer history and lifecycle outcome",
    ),
    ProfitFlywheelEdge(
        source="commerce.recover_abandoned_revenue",
        target="customer_success.prevent_returns_and_expand_ltv",
        handoff="Recovery intervention, discount, and holdout outcome",
    ),
    ProfitFlywheelEdge(
        source="growth.allocate_incremental_acquisition",
        target="finance.allocate_launch_portfolio_profit",
        handoff="Signed marginal acquisition outcome",
        feedback=True,
    ),
    ProfitFlywheelEdge(
        source="commerce.recover_abandoned_revenue",
        target="finance.allocate_launch_portfolio_profit",
        handoff="Holdout-measured recovered contribution profit",
        feedback=True,
    ),
    ProfitFlywheelEdge(
        source="customer_success.prevent_returns_and_expand_ltv",
        target="finance.allocate_launch_portfolio_profit",
        handoff="Net LTV, return cost, and root-cause outcome",
        feedback=True,
    ),
)


class ProfitFlywheelPlan(_StrictModel):
    schema_id: Literal["lightbulb.profit_flywheel_plan.v1"] = Field(
        default=PROFIT_FLYWHEEL_PLAN_SCHEMA,
        alias="schema",
    )
    launch_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode
    nodes: tuple[ProfitFlywheelNode, ...]
    edges: tuple[ProfitFlywheelEdge, ...]
    external_workflow_refs: tuple[str, ...] = ("gtm.plan_omnichannel_product_launch",)
    execution_order: tuple[str, ...]
    estimates_are_non_additive: Literal[True] = True
    materialization_supported: Literal[False] = False
    summary: LongText
    flywheel_digest: Sha256Digest = "0" * 64

    @field_validator("analysis_as_of")
    @classmethod
    def _timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "nodes",
        "edges",
        "external_workflow_refs",
        "execution_order",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _seal_manifest(self) -> "ProfitFlywheelPlan":
        expected_ids = tuple(
            definition.workflow_id for definition in PROFIT_WORKFLOW_DEFINITIONS
        )
        if tuple(node.workflow_id for node in self.nodes) != expected_ids:
            raise ValueError("flywheel manifest must contain the exact ten workflows")
        if len({node.plan_ref for node in self.nodes}) != len(self.nodes):
            raise ValueError("flywheel plan_ref values must be unique")
        if len({node.plan_digest for node in self.nodes}) != len(self.nodes):
            raise ValueError("flywheel plan digests must be unique")
        if self.execution_order != expected_ids:
            raise ValueError("flywheel execution order must match blueprint ordinals")
        if self.external_workflow_refs != ("gtm.plan_omnichannel_product_launch",):
            raise ValueError(
                "flywheel must name the existing launch planner as its hub"
            )
        if self.edges != _FLYWHEEL_EDGES:
            raise ValueError("flywheel handoffs must match the code-owned graph")
        declared_edges = {
            (definition.workflow_id, target)
            for definition in PROFIT_WORKFLOW_DEFINITIONS
            for target in definition.feeds
        }
        manifest_declared_edges = {
            (edge.source, edge.target)
            for edge in self.edges
            if edge.source in expected_ids
        }
        if manifest_declared_edges != declared_edges:
            raise ValueError("flywheel edges must match every blueprint follow-up")
        external_edges = {
            (edge.source, edge.target)
            for edge in self.edges
            if edge.source not in expected_ids
        }
        if external_edges != {
            ("gtm.plan_omnichannel_product_launch", workflow_id)
            for workflow_id in (
                "growth.allocate_incremental_acquisition",
                "crm.orchestrate_profit_aware_lifecycle",
                "commerce.recover_abandoned_revenue",
                "customer_success.prevent_returns_and_expand_ltv",
            )
        }:
            raise ValueError("flywheel external launch-hub edges are incomplete")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"flywheel_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.flywheel_digest not in {"0" * 64, expected}:
            raise ValueError("flywheel_digest does not match canonical manifest")
        object.__setattr__(self, "flywheel_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def compile_profit_flywheel(
    inputs_by_workflow: Mapping[
        ProfitWorkflowId | str,
        PlanProfitWorkflowInput | Mapping[str, Any],
    ],
    *,
    verified_scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ProfitScopeKeyRing | None = None,
    scope_key_id: str | None = None,
) -> ProfitFlywheelPlan:
    """Compile all ten workflows and return a compact, content-addressed manifest."""

    expected = tuple(
        definition.workflow_id for definition in PROFIT_WORKFLOW_DEFINITIONS
    )
    if set(inputs_by_workflow) != set(expected):
        raise ProfitWorkflowValidationError(
            "profit flywheel requires exactly one input for each of ten workflows"
        )
    plans = tuple(
        plan_profit_workflow(
            workflow_id,
            inputs_by_workflow[workflow_id],
            verified_scope=verified_scope,
            scope_keyring=scope_keyring,
            scope_key_id=scope_key_id,
        )
        for workflow_id in expected
    )
    launch_refs = {plan.launch_ref for plan in plans}
    analysis_times = {plan.analysis_as_of for plan in plans}
    currencies = {plan.baseline.currency for plan in plans}
    if len(launch_refs) != 1 or len(analysis_times) != 1 or len(currencies) != 1:
        raise ProfitWorkflowValidationError(
            "flywheel plans must share launch_ref, analysis_as_of, and currency"
        )
    nodes = tuple(
        ProfitFlywheelNode(
            workflow_id=plan.workflow_id,
            plan_ref=plan.plan_ref,
            plan_digest=plan.plan_digest,
            optimization_status=plan.optimization_status,
            selected_action_count=len(plan.actions),
            blocking_gap_count=sum(
                gap.severity == "blocking" for gap in plan.capability_gaps
            ),
        )
        for plan in plans
    )
    return ProfitFlywheelPlan(
        launch_ref=plans[0].launch_ref,
        analysis_as_of=plans[0].analysis_as_of,
        currency=plans[0].baseline.currency,
        nodes=nodes,
        edges=_FLYWHEEL_EDGES,
        execution_order=expected,
        summary=(
            "Compiled the exact ten-workflow profit flywheel around the existing "
            "omnichannel launch planner. Node estimates are deliberately non-additive; "
            "the manifest dispatches no operation and changes no live system."
        ),
    )


__all__ = [
    "PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA",
    "PROFIT_FLYWHEEL_PLAN_SCHEMA",
    "PROFIT_OUTCOME_EVIDENCE_SCHEMA",
    "PROFIT_WORKFLOW_EVALUATION_SCHEMA",
    "PROFIT_WORKFLOW_PLAN_SCHEMA",
    "GovernedProfitAction",
    "PlanProfitWorkflowInput",
    "ProfitActionExecutionReceipt",
    "ProfitActionParameter",
    "ProfitBaselineSummary",
    "ProfitCandidateDecision",
    "ProfitCapabilityGap",
    "ProfitConnectorAccountBinding",
    "ProfitContributionLedger",
    "ProfitEffectBoundary",
    "ProfitEvaluationLoop",
    "ProfitEvidenceScope",
    "ProfitFlywheelEdge",
    "ProfitFlywheelNode",
    "ProfitFlywheelPlan",
    "ProfitLeverCandidate",
    "ProfitMetricEvidence",
    "ProfitMetricFinding",
    "ProfitOptimizationPolicy",
    "ProfitOutcomeEvidence",
    "ProfitWorkflowEvaluation",
    "ProfitWorkflowPlan",
    "compile_profit_flywheel",
    "evaluate_profit_workflow_iteration",
    "get_profit_workflow_definition",
    "mint_profit_action_execution_receipt",
    "mint_profit_connector_account_binding",
    "mint_profit_metric_evidence",
    "mint_profit_outcome_evidence",
    "plan_profit_workflow",
    "verify_profit_workflow_evaluation",
    "verify_profit_action_execution_receipt",
    "verify_profit_workflow_plan",
]
