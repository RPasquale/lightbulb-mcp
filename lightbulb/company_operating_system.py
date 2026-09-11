"""Company Operating System Golden Operating Loop: blueprint to governed operating cadence.

The top of the stack.  A company blueprint names an archetype, a jurisdiction
(Australia or Canada, the two the platform forms companies in today), an
operating budget and the engines it runs; the operating system compiles that
into an operating plan (budget envelopes per engine, a period cadence, typed
cross-loop signal routes, and a formation plan), then runs each operating
period as a replay-fenced lifecycle::

    Form company (through the user's account) -> Bind engines -> Plan period
      -> Dispatch engines -> Collect evidence -> Reconcile -> Replan -> Learn

Engines are the other Golden Operating Loops (growth, pipeline, SaaS
operating, finance close, service delivery).  Signals are the typed events
that flow between them (attributed revenue, qualified pipeline, churn risk,
expansion candidates, rolled-back releases, exhausted envelopes).

Nothing here forms a company, moves budget, dispatches an agent, or reads a
provider.  Formation runs through ``LightbulbClient.create_company`` under the
user's credential; Spring authorizes every dispatch, reallocation, and spend.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    percent_value,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)
from lightbulb.company_formation import EXPECTED_RESIDENCY_REGION, SUPPORTED_FORMATION_COUNTRIES, normalize_formation_country

COMPANY_OS_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
COMPANY_OS_KIND = "company_operating_system"
BLUEPRINT_SCHEMA = "lightbulb.company_operating_blueprint.v1"
PLAN_SCHEMA = "lightbulb.company_operating_plan.v1"
ROUTING_SCHEMA = "lightbulb.company_signal_routing.v1"
ASSESSMENT_SCHEMA = "lightbulb.company_health_assessment.v1"
MAX_PERIOD_TRANSITIONS = 120

Archetype = Literal["dtc_commerce", "b2b_saas", "services_firm", "marketplace", "founder_led_saas", "local_services", "two_sided_marketplace", "custom"]
EngineKind = Literal["growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery", "people_engine", "marketplace_supply_engine", "engagement_engine"]
ENGINE_KINDS: tuple[str, ...] = ("growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery", "people_engine", "marketplace_supply_engine", "engagement_engine")
LoopStage = Literal["form_company", "bind_engines", "plan_period", "dispatch", "collect_evidence", "reconcile", "replan", "learn"]
STAGE_ORDER: tuple[str, ...] = ("form_company", "bind_engines", "plan_period", "dispatch", "collect_evidence", "reconcile", "replan", "learn")

PeriodStatus = Literal["planned", "dispatched", "evidenced", "reconciled", "replanned", "closed", "halted"]
PERIOD_STATUSES: tuple[str, ...] = ("planned", "dispatched", "evidenced", "reconciled", "replanned", "closed", "halted")
TERMINAL_PERIOD_STATUSES: frozenset[str] = frozenset({"closed", "halted"})
PeriodEvent = Literal["open", "dispatch", "record_evidence", "reconcile", "replan", "close", "halt"]
PERIOD_EVENTS: tuple[str, ...] = ("open", "dispatch", "record_evidence", "reconcile", "replan", "close", "halt")
_PERIOD_TABLE: dict[tuple[str, str], str] = {
    ("new", "open"): "planned",
    ("planned", "dispatch"): "dispatched",
    ("planned", "halt"): "halted",
    ("dispatched", "dispatch"): "dispatched",
    ("dispatched", "record_evidence"): "evidenced",
    ("dispatched", "halt"): "halted",
    ("evidenced", "dispatch"): "evidenced",
    ("evidenced", "record_evidence"): "evidenced",
    ("evidenced", "reconcile"): "reconciled",
    ("evidenced", "halt"): "halted",
    ("reconciled", "replan"): "replanned",
    ("reconciled", "close"): "closed",
    ("reconciled", "halt"): "halted",
    ("replanned", "close"): "closed",
    ("replanned", "halt"): "halted",
}

ENGINE_LOOPS: Mapping[str, str] = {
    "growth_engine": "growth.store_truth_to_attributed_revenue@0.1.0",
    "pipeline_engine": "revenue.icp_to_qualified_pipeline@0.1.0",
    "saas_operating_engine": "saas.launched_product_to_compounding_revenue@0.1.0",
    "finance_close": "finance.period_close_to_verified_books@0.1.0",
    "service_delivery": "service.case_intake_to_verified_resolution@0.1.0",
    "people_engine": "people.capacity_to_proven_labour@0.1.0",
    "marketplace_supply_engine": "marketplace.seller_to_settled_transaction@0.1.0",
    "engagement_engine": "services.scope_to_proven_delivery@0.1.0",
}
ENGINE_ENTRY_PRIMITIVES: Mapping[str, tuple[str, ...]] = {
    "growth_engine": ("blueprint.compile_growth_engine", "growth_engine.plan_campaign_portfolio", "growth_engine.advance_campaign", "growth_engine.propose_reallocation", "growth_engine.assess_engine"),
    "pipeline_engine": ("blueprint.compile_pipeline_engine", "pipeline.evaluate_icp_fit", "pipeline.plan_sequence", "pipeline.advance_prospect", "pipeline.forecast_pipeline"),
    "saas_operating_engine": ("blueprint.compile_saas_operating", "saas_ops.observe_usage", "saas_ops.triage_support", "saas_ops.rank_roadmap", "saas_ops.advance_release", "saas_ops.assess_operating"),
    "finance_close": ("finance.evaluate_period_close_readiness", "finance.evaluate_period_reconciliation", "finance.prepare_close_evidence_bundle"),
    "service_delivery": ("service.intake_and_classify_case", "service.verify_case_resolution"),
    "people_engine": ("people.compile_people_engine", "people.advance_people", "people.assess_capacity"),
    "marketplace_supply_engine": ("marketplace.compile_supply_engine", "marketplace.advance_supply", "marketplace.assess_supply"),
    "engagement_engine": ("engagement.compile_engagement", "engagement.advance_engagement", "engagement.assess_engagement"),
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {"blueprint.compile_company_operating_system", "company.plan_formation", "company.advance_period", "company.route_signal", "company.assess_health", "approval.request_decision", "learning.plan_optimization_sweep", "compliance.evaluate_regulated_controls", "communication.write_email"}
    | {ref for refs in ENGINE_ENTRY_PRIMITIVES.values() for ref in refs}
)


def _dec(value: Any, *, field_name: str, minimum: Decimal | None = None, maximum: Decimal | None = None) -> Decimal:
    result = decimal_value(value, field_name=field_name, allow_negative=True)
    if minimum is not None and result < minimum:
        raise ValueError(f"{field_name} must be at least {minimum}")
    if maximum is not None and result > maximum:
        raise ValueError(f"{field_name} must be at most {maximum}")
    return result


class SignalSpec(StrictModel):
    name: str = Field(pattern=r"^signals\.[a-z_]{3,60}$")
    producer: EngineKind | Literal["company_operating_system", "subscription_chain", "payout_chain", "custodial_funds", "refund_and_dispute_chain", "obligation_paper", "spend_control_chain", "job_chain"]
    consumers: tuple[EngineKind | Literal["company_operating_system"], ...] = Field(min_length=1, max_length=9)
    required_keys: tuple[ShortText, ...] = Field(min_length=1, max_length=8)
    advisory: BoundedText

    @model_validator(mode="after")
    def _guard(self) -> SignalSpec:
        unique(list(self.consumers), label="signal consumers")
        unique(list(self.required_keys), label="signal keys")
        if self.producer in self.consumers:
            raise ValueError("a signal producer does not consume its own signal")
        return self


SIGNAL_SPECS: Mapping[str, SignalSpec] = {
    spec.name: spec
    for spec in (
        SignalSpec(name="signals.job_settled", producer="job_chain", consumers=("company_operating_system", "finance_close"), required_keys=("job_ref", "settled_amount", "currency", "source_digest"), advisory="Record the replayed paid job in the protected company cost register; settlement alone does not establish marketing attribution."),
        SignalSpec(name="signals.attributed_revenue", producer="growth_engine", consumers=("company_operating_system", "finance_close"), required_keys=("channel", "attributed_revenue", "spend", "window_end"), advisory="Book attributed revenue against the period envelope; reconcile spend at close."),
        SignalSpec(name="signals.envelope_exhausted", producer="growth_engine", consumers=("company_operating_system",), required_keys=("envelope_ref", "spend", "budget"), advisory="No further launches on this envelope until replan; reallocation needs approval above the threshold."),
        SignalSpec(name="signals.qualified_pipeline", producer="pipeline_engine", consumers=("company_operating_system", "saas_operating_engine", "service_delivery"), required_keys=("prospect_ref", "deal_value", "meeting_at"), advisory="Reserve onboarding or delivery capacity for the booked meeting; forecast carries the deal at stage weight."),
        SignalSpec(name="signals.churn_risk", producer="saas_operating_engine", consumers=("pipeline_engine", "growth_engine", "service_delivery", "company_operating_system"), required_keys=("account_ref", "mrr_at_risk", "inactive_days"), advisory="Suppress acquisition spend on look-alikes of the at-risk account; queue a retention play, never an unsolicited message."),
        SignalSpec(name="signals.payment_overdue", producer="finance_close", consumers=("service_delivery", "company_operating_system"), required_keys=("invoice_ref", "account_ref", "amount_remaining", "currency", "days_overdue", "due_at", "source_digest"), advisory="Review the evidenced overdue invoice through a service case; its remaining balance is not MRR, payment authority, or a reason to suppress acquisition."),
        SignalSpec(name="signals.expansion_candidate", producer="saas_operating_engine", consumers=("pipeline_engine", "company_operating_system"), required_keys=("account_ref", "suggested_plan_ref"), advisory="Open an expansion opportunity only with the customer's consent on record."),
        SignalSpec(name="signals.release_rolled_back", producer="saas_operating_engine", consumers=("growth_engine", "company_operating_system"), required_keys=("release_ref", "reason"), advisory="Pause new campaign launches that promote the rolled-back capability until the release is verified again."),
        SignalSpec(name="signals.books_verified", producer="finance_close", consumers=("company_operating_system",), required_keys=("period_end", "gross_margin_percent"), advisory="Reconcile the operating period against verified books before replanning envelopes."),
        SignalSpec(name="signals.case_resolved", producer="service_delivery", consumers=("saas_operating_engine", "company_operating_system"), required_keys=("case_ref", "resolution_verified"), advisory="Count verified resolutions toward SLA attainment; unverified resolutions do not close."),
        SignalSpec(name="signals.subscription_settled", producer="subscription_chain", consumers=("saas_operating_engine", "finance_close", "company_operating_system"), required_keys=("account_ref", "settled_amount", "source_digest"), advisory="Record only cash proven by the settled subscription and its source digest."),
        SignalSpec(name="signals.capability_lapsed", producer="obligation_paper", consumers=("people_engine", "growth_engine", "company_operating_system"), required_keys=("holder_ref", "paper_ref", "source_digest"), advisory="Suspend work and claims that require the lapsed capability until fresh paper is verified."),
        SignalSpec(name="signals.capacity_shortfall", producer="people_engine", consumers=("service_delivery", "company_operating_system"), required_keys=("required_hours", "available_hours", "source_digest"), advisory="Replan delivery capacity using the observed staffing shortfall."),
        SignalSpec(name="signals.supply_shortfall", producer="marketplace_supply_engine", consumers=("growth_engine", "company_operating_system"), required_keys=("required_supply", "available_supply", "source_digest"), advisory="Balance demand acquisition with verified available supply."),
        SignalSpec(name="signals.dispute_rate_breach", producer="refund_and_dispute_chain", consumers=("service_delivery", "company_operating_system"), required_keys=("dispute_rate", "source_digest"), advisory="Review disputed transactions and their evidence before releasing funds."),
        SignalSpec(name="signals.payout_blocked", producer="payout_chain", consumers=("marketplace_supply_engine", "finance_close", "company_operating_system"), required_keys=("payout_ref", "reason", "source_digest"), advisory="Resolve the evidenced payout hold before a fresh authorized instruction."),
        SignalSpec(name="signals.custody_shortfall", producer="custodial_funds", consumers=("marketplace_supply_engine", "finance_close", "company_operating_system"), required_keys=("liability", "custody_balance", "source_digest"), advisory="Custodial liabilities are unavailable for operating spend; stop releases when coverage fails."),
        SignalSpec(name="signals.commitment_expiring", producer="spend_control_chain", consumers=("company_operating_system",), required_keys=("commitment_ref", "merchant_ref", "renews_at", "notice_due_at", "amount", "currency", "state_digest"), advisory="Review the recurring commitment before its notice deadline."),
        SignalSpec(name="signals.company_formed", producer="company_operating_system", consumers=ENGINE_KINDS, required_keys=("company_ref", "country", "region"), advisory="Engines bind to the formed company's scope; nothing dispatches before formation."),
    )
}


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class EngineBinding(StrictModel):
    engine: EngineKind
    profile: ShortText
    budget_share_percent: Decimal
    cadence_days: int = Field(ge=1, le=92)

    @model_validator(mode="after")
    def _profile_exists(self) -> EngineBinding:
        from lightbulb.growth_engine_loop import GROWTH_ENGINE_PROFILES
        from lightbulb.pipeline_engine_loop import PIPELINE_ENGINE_PROFILES
        from lightbulb.saas_operating_loop import SAAS_OPERATING_PROFILES
        from lightbulb.finance_close_engine import FINANCE_CLOSE_PROFILES
        from lightbulb.service_delivery_engine import SERVICE_DELIVERY_PROFILES
        from lightbulb.people_engine import PEOPLE_PROFILES
        from lightbulb.marketplace_supply_engine import MARKETPLACE_SUPPLY_PROFILES
        from lightbulb.engagement_engine import ENGAGEMENT_PROFILES

        profiles = {"growth_engine": GROWTH_ENGINE_PROFILES, "pipeline_engine": PIPELINE_ENGINE_PROFILES,
                    "saas_operating_engine": SAAS_OPERATING_PROFILES, "finance_close": FINANCE_CLOSE_PROFILES,
                    "service_delivery": SERVICE_DELIVERY_PROFILES,
                    "people_engine": PEOPLE_PROFILES, "marketplace_supply_engine": MARKETPLACE_SUPPLY_PROFILES,
                    "engagement_engine": ENGAGEMENT_PROFILES}
        if self.profile not in profiles[self.engine]:
            raise ValueError(f"UNKNOWN_ENGINE_PROFILE: {self.engine}.{self.profile}")
        return self

    @field_validator("budget_share_percent", mode="before")
    @classmethod
    def _share(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="budget_share_percent")

    @property
    def golden_loop(self) -> str:
        return ENGINE_LOOPS[self.engine]

    @property
    def entry_primitives(self) -> tuple[str, ...]:
        return ENGINE_ENTRY_PRIMITIVES[self.engine]


class OperatingTargets(StrictModel):
    revenue_per_period: Decimal
    gross_margin_percent: Decimal
    min_cash_runway_months: int = Field(default=6, ge=1, le=60)

    @field_validator("revenue_per_period", mode="before")
    @classmethod
    def _revenue(cls, value: Any) -> Decimal:
        return _dec(value, field_name="revenue_per_period", minimum=Decimal("0"))

    @field_validator("gross_margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="gross_margin_percent")


class FormationPolicy(StrictModel):
    industry: ShortText
    purpose: BoundedText
    contact_email_required: bool = True


class CompanyOperatingBlueprint(StrictModel):
    schema_id: str = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    archetype: Archetype
    name: ShortText
    country: str = Field(min_length=2, max_length=80)
    currency: CurrencyCode
    operating_budget_per_period: Decimal
    period_days: int = Field(default=7, ge=1, le=92)
    engines: tuple[EngineBinding, ...] = Field(min_length=1, max_length=len(ENGINE_KINDS))
    signals: tuple[str, ...] = Field(min_length=1, max_length=len(SIGNAL_SPECS))
    max_shift_percent_per_replan: Decimal = Field(default=Decimal("30"), validate_default=True)
    approval_threshold_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    formation: FormationPolicy
    targets: OperatingTargets
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("country")
    @classmethod
    def _country(cls, value: str) -> str:
        return normalize_formation_country(value)

    @field_validator("operating_budget_per_period", mode="before")
    @classmethod
    def _budget(cls, value: Any) -> Decimal:
        return _dec(value, field_name="operating_budget_per_period", minimum=Decimal("0.01"))

    @field_validator("max_shift_percent_per_replan", "approval_threshold_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: Any) -> Decimal:
        return percent_value(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CompanyOperatingBlueprint:
        unique([item.engine for item in self.engines], label="engines")
        unique(list(self.signals), label="signals")
        if sum(item.budget_share_percent for item in self.engines) != Decimal("100"):
            raise ValueError("engine budget shares must sum to 100")
        for name in self.signals:
            if name not in SIGNAL_SPECS:
                raise ValueError(f"unknown signal {name}; known: {sorted(SIGNAL_SPECS)}")
        if self.approval_threshold_percent > self.max_shift_percent_per_replan:
            raise ValueError("approval threshold cannot exceed the maximum shift per replan")
        for item in self.engines:
            # Labour can run fortnightly inside weekly operating periods.
            if item.cadence_days > self.period_days and item.engine != "people_engine":
                raise ValueError(f"{item.engine} cadence {item.cadence_days}d exceeds the operating period {self.period_days}d")
            if item.engine in ("finance_close", "service_delivery"):
                from lightbulb.finance_close_engine import FINANCE_CLOSE_PROFILES
                from lightbulb.service_delivery_engine import SERVICE_DELIVERY_PROFILES
                profile = (FINANCE_CLOSE_PROFILES if item.engine == "finance_close" else SERVICE_DELIVERY_PROFILES)[item.profile]
                if profile["currency"] != self.currency:
                    raise ValueError(f"ENGINE_CURRENCY_MISMATCH: {item.engine}.{item.profile} is {profile['currency']}, company is {self.currency}")
        if not skip_digests(info) and self.blueprint_digest != sealed_digest(CompanyOperatingBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def engine(self, kind: str) -> EngineBinding | None:
        return next((item for item in self.engines if item.engine == kind), None)

    @property
    def engine_kinds(self) -> tuple[str, ...]:
        return tuple(item.engine for item in self.engines)

    @property
    def country_name(self) -> str:
        return SUPPORTED_FORMATION_COUNTRIES[self.country]


_COMMON_SIGNALS = ["signals.company_formed", "signals.attributed_revenue", "signals.envelope_exhausted", "signals.books_verified"]
COMPANY_OS_ARCHETYPES: Mapping[str, dict[str, Any]] = {'dtc_commerce': {'archetype': 'dtc_commerce',
                  'name': 'Direct-to-consumer commerce company',
                  'country': 'AU',
                  'currency': 'AUD',
                  'operating_budget_per_period': '12000',
                  'period_days': 7,
                  'engines': [{'engine': 'growth_engine',
                               'profile': 'dtc_shopify',
                               'budget_share_percent': '55',
                               'cadence_days': 1},
                              {'engine': 'service_delivery',
                               'profile': 'commerce_support',
                               'budget_share_percent': '15',
                               'cadence_days': 1},
                              {'engine': 'finance_close',
                               'profile': 'dtc_weekly_close',
                               'budget_share_percent': '20',
                               'cadence_days': 7},
                              {'engine': 'people_engine',
                               'profile': 'small_team',
                               'budget_share_percent': '10',
                               'cadence_days': 14}],
                  'signals': ['signals.company_formed',
                              'signals.attributed_revenue',
                              'signals.envelope_exhausted',
                              'signals.books_verified',
                              'signals.case_resolved'],
                  'formation': {'industry': 'Retail',
                                'purpose': 'Sell a curated product range online with automated marketing and fulfilment.',
                                'contact_email_required': True},
                  'targets': {'revenue_per_period': '40000', 'gross_margin_percent': '55', 'min_cash_runway_months': 6}},
 'b2b_saas': {'archetype': 'b2b_saas',
              'name': 'B2B SaaS company',
              'country': 'CA',
              'currency': 'CAD',
              'operating_budget_per_period': '30000',
              'period_days': 7,
              'engines': [{'engine': 'growth_engine',
                           'profile': 'b2b_saas',
                           'budget_share_percent': '27',
                           'cadence_days': 1},
                          {'engine': 'pipeline_engine',
                           'profile': 'b2b_saas_outbound',
                           'budget_share_percent': '22',
                           'cadence_days': 1},
                          {'engine': 'saas_operating_engine',
                           'profile': 'sales_assisted',
                           'budget_share_percent': '31',
                           'cadence_days': 1},
                          {'engine': 'finance_close',
                           'profile': 'weekly_close',
                           'budget_share_percent': '10',
                           'cadence_days': 7},
                          {'engine': 'people_engine',
                           'profile': 'small_team',
                           'budget_share_percent': '10',
                           'cadence_days': 14}],
              'signals': ['signals.company_formed',
                          'signals.attributed_revenue',
                          'signals.envelope_exhausted',
                          'signals.books_verified',
                          'signals.qualified_pipeline',
                          'signals.churn_risk',
                          'signals.expansion_candidate',
                          'signals.release_rolled_back'],
              'formation': {'industry': 'Software',
                            'purpose': 'Sell and operate a subscription software product for business customers.',
                            'contact_email_required': True},
              'targets': {'revenue_per_period': '60000', 'gross_margin_percent': '75', 'min_cash_runway_months': 12}},
 'services_firm': {'archetype': 'services_firm',
                   'name': 'Professional services firm',
                   'country': 'AU',
                   'currency': 'AUD',
                   'operating_budget_per_period': '8000',
                   'period_days': 14,
                   'engines': [{'engine': 'pipeline_engine',
                                'profile': 'agency_outbound',
                                'budget_share_percent': '35',
                                'cadence_days': 2},
                               {'engine': 'growth_engine',
                                'profile': 'local_services',
                                'budget_share_percent': '25',
                                'cadence_days': 2},
                               {'engine': 'service_delivery',
                                'profile': 'engagement_delivery',
                                'budget_share_percent': '25',
                                'cadence_days': 1},
                               {'engine': 'finance_close',
                                'profile': 'fortnightly_close',
                                'budget_share_percent': '15',
                                'cadence_days': 14}],
                   'signals': ['signals.company_formed',
                               'signals.attributed_revenue',
                               'signals.envelope_exhausted',
                               'signals.books_verified',
                               'signals.qualified_pipeline',
                               'signals.case_resolved'],
                   'formation': {'industry': 'Professional services',
                                 'purpose': 'Win and deliver client engagements with governed outreach and verified '
                                            'delivery.',
                                 'contact_email_required': True},
                   'targets': {'revenue_per_period': '30000', 'gross_margin_percent': '45', 'min_cash_runway_months': 4}},
 'marketplace': {'archetype': 'marketplace',
                 'name': 'Two-sided marketplace',
                 'country': 'CA',
                 'currency': 'CAD',
                 'operating_budget_per_period': '20000',
                 'period_days': 7,
                 'engines': [{'engine': 'growth_engine',
                              'profile': 'marketplace_demand',
                              'budget_share_percent': '50',
                              'cadence_days': 1},
                             {'engine': 'pipeline_engine',
                              'profile': 'partner_channel',
                              'budget_share_percent': '30',
                              'cadence_days': 1},
                             {'engine': 'finance_close',
                              'profile': 'weekly_close',
                              'budget_share_percent': '20',
                              'cadence_days': 7}],
                 'signals': ['signals.company_formed',
                             'signals.attributed_revenue',
                             'signals.envelope_exhausted',
                             'signals.books_verified',
                             'signals.qualified_pipeline'],
                 'formation': {'industry': 'Marketplace',
                               'purpose': 'Match supply and demand with governed demand generation and partner sourcing.',
                               'contact_email_required': True},
                 'targets': {'revenue_per_period': '25000', 'gross_margin_percent': '30', 'min_cash_runway_months': 9}},
 'founder_led_saas': {'archetype': 'founder_led_saas',
                      'name': 'Founder-led SaaS company',
                      'country': 'CA',
                      'currency': 'CAD',
                      'operating_budget_per_period': '4000',
                      'period_days': 30,
                      'engines': [{'engine': 'growth_engine',
                                   'profile': 'plg_self_serve',
                                   'budget_share_percent': '30',
                                   'cadence_days': 1},
                                  {'engine': 'saas_operating_engine',
                                   'profile': 'plg_self_serve',
                                   'budget_share_percent': '40',
                                   'cadence_days': 1},
                                  {'engine': 'finance_close',
                                   'profile': 'monthly_close_cad',
                                   'budget_share_percent': '20',
                                   'cadence_days': 30},
                                  {'engine': 'people_engine',
                                   'profile': 'small_team',
                                   'budget_share_percent': '10',
                                   'cadence_days': 14}],
                      'signals': ['signals.company_formed',
                                  'signals.attributed_revenue',
                                  'signals.envelope_exhausted',
                                  'signals.books_verified',
                                  'signals.churn_risk',
                                  'signals.expansion_candidate',
                                  'signals.subscription_settled'],
                      'formation': {'industry': 'Software',
                                    'purpose': 'Build a self-serve subscription business with founder pay inside its '
                                               'operating budget.',
                                    'contact_email_required': True},
                      'targets': {'revenue_per_period': '83333', 'gross_margin_percent': '80', 'min_cash_runway_months': 9}},
 'local_services': {'archetype': 'local_services',
                    'name': 'Local services company',
                    'country': 'AU',
                    'currency': 'AUD',
                    'operating_budget_per_period': '6000',
                    'period_days': 14,
                    'engines': [{'engine': 'growth_engine',
                                 'profile': 'local_services',
                                 'budget_share_percent': '30',
                                 'cadence_days': 1},
                                {'engine': 'service_delivery',
                                 'profile': 'local_aftercare',
                                 'budget_share_percent': '25',
                                 'cadence_days': 1},
                                {'engine': 'people_engine',
                                 'profile': 'small_team',
                                 'budget_share_percent': '25',
                                 'cadence_days': 14},
                                {'engine': 'finance_close',
                                 'profile': 'fortnightly_close',
                                 'budget_share_percent': '20',
                                 'cadence_days': 14}],
                    'signals': ['signals.company_formed',
                                'signals.attributed_revenue',
                                'signals.envelope_exhausted',
                                'signals.books_verified',
                                'signals.capability_lapsed',
                                'signals.capacity_shortfall',
                                'signals.case_resolved'],
                    'formation': {'industry': 'Local services',
                                  'purpose': 'Book and deliver services with verified capabilities, aftercare and proven '
                                             'labour costs.',
                                  'contact_email_required': True},
                    'targets': {'revenue_per_period': '18000', 'gross_margin_percent': '45', 'min_cash_runway_months': 3}},
 'two_sided_marketplace': {'archetype': 'two_sided_marketplace',
                           'name': 'Two-sided marketplace with custodial controls',
                           'country': 'CA',
                           'currency': 'CAD',
                           'operating_budget_per_period': '20000',
                           'period_days': 7,
                           'engines': [{'engine': 'marketplace_supply_engine',
                                        'profile': 'two_sided_marketplace',
                                        'budget_share_percent': '35',
                                        'cadence_days': 1},
                                       {'engine': 'growth_engine',
                                        'profile': 'marketplace_demand',
                                        'budget_share_percent': '35',
                                        'cadence_days': 1},
                                       {'engine': 'service_delivery',
                                        'profile': 'marketplace_disputes',
                                        'budget_share_percent': '15',
                                        'cadence_days': 1},
                                       {'engine': 'finance_close',
                                        'profile': 'weekly_close',
                                        'budget_share_percent': '15',
                                        'cadence_days': 7}],
                           'signals': ['signals.company_formed',
                                       'signals.attributed_revenue',
                                       'signals.envelope_exhausted',
                                       'signals.books_verified',
                                       'signals.supply_shortfall',
                                       'signals.dispute_rate_breach',
                                       'signals.payout_blocked',
                                       'signals.custody_shortfall'],
                           'formation': {'industry': 'Marketplace',
                                         'purpose': 'Match verified supply and demand; measure company take revenue and '
                                                    'reserve seller funds.',
                                         'contact_email_required': True},
                           'targets': {'revenue_per_period': '5000',
                                       'gross_margin_percent': '30',
                                       'min_cash_runway_months': 9}}}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[str, ...] = Field(min_length=1, max_length=10)
    engines: tuple[EngineKind, ...] = Field(default_factory=tuple, max_length=len(ENGINE_KINDS))
    gate: ShortText | None = None

    @field_validator("primitive_refs")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for ref in value:
            if ref not in _KNOWN_PRIMITIVE_REFS:
                raise ValueError(f"unknown primitive ref {ref}")
        return value


class EngineEnvelope(StrictModel):
    engine: EngineKind
    golden_loop: ShortText
    profile: ShortText
    budget: Decimal
    budget_share_percent: Decimal
    cadence_days: int = Field(ge=1, le=92)
    dispatches_per_period: int = Field(ge=1, le=92)

    @field_validator("budget", mode="before")
    @classmethod
    def _budget(cls, value: Any) -> Decimal:
        return _dec(value, field_name="budget", minimum=Decimal("0"))

    @field_validator("budget_share_percent", mode="before")
    @classmethod
    def _share(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="budget_share_percent")


class SignalRoute(StrictModel):
    name: ShortText
    producer: ShortText
    consumers: tuple[ShortText, ...] = Field(min_length=1, max_length=9)
    required_keys: tuple[ShortText, ...] = Field(min_length=1, max_length=8)


class FormationPlan(StrictModel):
    country: str
    country_name: ShortText
    expected_region: ShortText
    request_preview: dict[str, str]
    client_method: Literal["LightbulbClient.create_company"] = "LightbulbClient.create_company"
    endpoint: Literal["POST /api/companies/guided"] = "POST /api/companies/guided"
    requires_signed_in_account_admin: Literal[True] = True
    scope_from_signed_in_account: Literal[True] = True
    executes_nothing: Literal[True] = True

    @field_validator("country")
    @classmethod
    def _country(cls, value: str) -> str:
        return normalize_formation_country(value)


class CompanyOperatingPlan(StrictModel):
    schema_id: str = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["company.blueprint_to_governed_operating_cadence@0.1.0"] = COMPANY_OS_GOLDEN_LOOP
    blueprint: CompanyOperatingBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=len(STAGE_ORDER), max_length=len(STAGE_ORDER))
    envelopes: tuple[EngineEnvelope, ...] = Field(min_length=1, max_length=len(ENGINE_KINDS))
    signal_routes: tuple[SignalRoute, ...] = Field(min_length=1, max_length=len(SIGNAL_SPECS))
    formation: FormationPlan
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CompanyOperatingPlan:
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("stages must follow the loop order")
        if tuple(item.engine for item in self.envelopes) != self.blueprint.engine_kinds:
            raise ValueError("envelopes must mirror the blueprint engines in order")
        total = sum(item.budget for item in self.envelopes)
        if abs(total - self.blueprint.operating_budget_per_period) > MONEY_QUANTUM * len(self.envelopes):
            raise ValueError("envelope budgets must sum to the operating budget")
        if tuple(item.name for item in self.signal_routes) != self.blueprint.signals:
            raise ValueError("signal routes must mirror the blueprint signals")
        if self.formation.country != self.blueprint.country:
            raise ValueError("formation plan must target the blueprint country")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CompanyOperatingPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)

    def envelope(self, engine: str) -> EngineEnvelope | None:
        return next((item for item in self.envelopes if item.engine == engine), None)

    def route(self, name: str) -> SignalRoute | None:
        return next((item for item in self.signal_routes if item.name == name), None)


def _stages(bp: CompanyOperatingBlueprint) -> tuple[StageBinding, ...]:
    kinds = bp.engine_kinds
    entry = tuple(dict.fromkeys(ENGINE_ENTRY_PRIMITIVES[kind][0] for kind in kinds))
    assess = tuple(dict.fromkeys(ENGINE_ENTRY_PRIMITIVES[kind][-1] for kind in kinds))
    return (
        StageBinding(stage="form_company", title=f"Form the company in {bp.country_name} through the user's Lightbulb account", primitive_refs=("company.plan_formation",), gate="authenticated_tenant_admin"),
        StageBinding(stage="bind_engines", title=f"Bind {len(kinds)} engine(s) to the formed company's scope", primitive_refs=("blueprint.compile_company_operating_system", *entry[:9]), engines=kinds),
        StageBinding(stage="plan_period", title=f"Open a {bp.period_days}-day operating period with {bp.currency} {bp.operating_budget_per_period} across envelopes", primitive_refs=("company.advance_period",)),
        StageBinding(stage="dispatch", title="Dispatch every bound engine inside its envelope", primitive_refs=("company.advance_period", "approval.request_decision"), engines=kinds, gate="spring_authorized_dispatch"),
        StageBinding(stage="collect_evidence", title="Collect engine evidence and route typed signals", primitive_refs=("company.advance_period", "company.route_signal"), engines=kinds),
        StageBinding(stage="reconcile", title="Reconcile spend and revenue against envelopes and verified books", primitive_refs=("company.advance_period", "compliance.evaluate_regulated_controls"), gate="books_verified"),
        StageBinding(stage="replan", title=f"Replan envelopes (max shift {bp.max_shift_percent_per_replan}%, approval above {bp.approval_threshold_percent}%)", primitive_refs=("company.advance_period", "approval.request_decision"), gate="human_approval_above_threshold"),
        StageBinding(stage="learn", title="Assess company health against targets", primitive_refs=("company.assess_health", *assess[:8], "learning.plan_optimization_sweep")[:10]),
    )


def _envelopes(bp: CompanyOperatingBlueprint) -> tuple[EngineEnvelope, ...]:
    rows = []
    allocated = Decimal("0")
    for index, item in enumerate(bp.engines):
        budget = (bp.operating_budget_per_period * item.budget_share_percent / Decimal("100")).quantize(MONEY_QUANTUM)
        if index == len(bp.engines) - 1:
            budget = (bp.operating_budget_per_period - allocated).quantize(MONEY_QUANTUM)
        allocated += budget
        rows.append(EngineEnvelope(engine=item.engine, golden_loop=item.golden_loop, profile=item.profile, budget=budget, budget_share_percent=item.budget_share_percent, cadence_days=item.cadence_days, dispatches_per_period=max(1, bp.period_days // item.cadence_days)))
    return tuple(rows)


def _routes(bp: CompanyOperatingBlueprint) -> tuple[SignalRoute, ...]:
    enabled = set(bp.engine_kinds) | {"company_operating_system"}
    supporting = {"engagement_engine": {"job_chain"}, "saas_operating_engine": {"subscription_chain"}, "people_engine": {"obligation_paper"},
                  "finance_close": {"spend_control_chain"},
                  "service_delivery": {"job_chain", "refund_and_dispute_chain"},
                  "marketplace_supply_engine": {"payout_chain", "custodial_funds"}}
    producers = enabled | {name for engine, names in supporting.items() if engine in enabled for name in names}
    routes = []
    for name in bp.signals:
        spec = SIGNAL_SPECS[name]
        if spec.producer not in producers:
            raise ValueError(f"{name} is produced by {spec.producer}, which this blueprint does not run")
        consumers = tuple(item for item in spec.consumers if item in enabled)
        if not consumers:
            raise ValueError(f"{name} has no enabled consumer in this blueprint")
        routes.append(SignalRoute(name=name, producer=spec.producer, consumers=consumers, required_keys=spec.required_keys))
    return tuple(routes)


def _formation(bp: CompanyOperatingBlueprint) -> FormationPlan:
    return FormationPlan(country=bp.country, country_name=bp.country_name, expected_region=EXPECTED_RESIDENCY_REGION[bp.country], request_preview={"name": bp.name, "country": bp.country, "industry": bp.formation.industry, "purpose": bp.formation.purpose})


def compile_company_operating_blueprint(blueprint: str | CompanyOperatingBlueprint | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> CompanyOperatingPlan:
    """Compile an archetype name or a full blueprint (plus overrides) into an operating plan."""

    if isinstance(blueprint, str):
        if blueprint not in COMPANY_OS_ARCHETYPES:
            raise ValueError(f"unknown company archetype {blueprint!r}; known: {sorted(COMPANY_OS_ARCHETYPES)}")
        raw: dict[str, Any] = dict(COMPANY_OS_ARCHETYPES[blueprint])
    elif isinstance(blueprint, CompanyOperatingBlueprint):
        raw = blueprint.to_dict()
        raw.pop("blueprint_digest", None)
    else:
        raw = dict(detached(blueprint))
    if overrides:
        if any(key in ("schema", "blueprint_digest") for key in overrides):
            raise ValueError("overrides cannot set schema or digest fields")
        raw.update(detached(overrides))
    raw["blueprint_digest"] = sealed_digest(CompanyOperatingBlueprint, raw, "blueprint_digest")
    bp = CompanyOperatingBlueprint.model_validate(raw)
    return seal(CompanyOperatingPlan, {"blueprint": bp, "stages": _stages(bp), "envelopes": _envelopes(bp), "signal_routes": _routes(bp), "formation": _formation(bp)}, "plan_digest")


# --------------------------------------------------------------------------- #
# Operating period lifecycle
# --------------------------------------------------------------------------- #


class EnvelopeShift(StrictModel):
    engine: EngineKind
    delta_percent: Decimal

    @field_validator("delta_percent", mode="before")
    @classmethod
    def _delta(cls, value: Any) -> Decimal:
        return _dec(value, field_name="delta_percent", minimum=Decimal("-100"), maximum=Decimal("100"))


class PeriodReceipt(StrictModel):
    entity_scope: dict[str, Any] | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    entity_ref: OpaqueRef | None = None
    period_start: str | None = None
    period_end: str | None = None
    engine: EngineKind | None = None
    dispatch_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=92)
    evidence_ref: OpaqueRef | None = None
    source_digest: Sha256Digest | None = None
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=512)
    source_kind: ShortText | None = None
    revenue_only: bool | None = None
    spend: Decimal | None = None
    revenue: Decimal | None = None
    signals: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    reconciliation_ref: OpaqueRef | None = None
    books_verified: bool | None = None
    close_state_digest: Sha256Digest | None = None
    shifts: tuple[EnvelopeShift, ...] = Field(default_factory=tuple, max_length=len(ENGINE_KINDS))
    approval_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None

    @field_validator("source_digests", mode="before")
    @classmethod
    def _sources(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else timestamp(value, field_name=info.field_name)

    @field_validator("spend", "revenue", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal | None:
        return None if value is None else _dec(value, field_name=info.field_name, minimum=Decimal("0"))


class PeriodLedger(StrictModel):
    entity_scope: dict[str, Any] | None = None
    entity_ref: OpaqueRef | None = None
    period_start: str | None = None
    period_end: str | None = None
    budget_total: Decimal = Decimal("0.00")
    dispatched_engines: tuple[EngineKind, ...] = Field(default_factory=tuple)
    dispatch_count: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    evidence_source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)
    spend_by_engine: dict[str, Decimal] = Field(default_factory=dict)
    revenue_by_engine: dict[str, Decimal] = Field(default_factory=dict)
    signals_received: tuple[str, ...] = Field(default_factory=tuple)
    total_spend: Decimal = Decimal("0.00")
    total_revenue: Decimal = Decimal("0.00")
    reconciliation_ref: str | None = None
    books_verified: bool = False
    close_state_digest: str | None = None
    shifts_applied: tuple[EnvelopeShift, ...] = Field(default_factory=tuple)
    approval_ref: str | None = None
    authorization_proof_digest: Sha256Digest | None = None
    halt_reason: str | None = None
    outcome: Literal["open", "closed", "halted"] = "open"

    @field_validator("budget_total", "total_spend", "total_revenue", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _dec(value, field_name=info.field_name, minimum=Decimal("0"))

    @field_validator("spend_by_engine", "revenue_by_engine", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: Any) -> dict[str, Decimal]:
        return {str(key): _dec(item, field_name=info.field_name, minimum=Decimal("0")) for key, item in dict(value or {}).items()}


class PeriodEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    company_formed: Literal[False] = False
    engine_dispatched: Literal[False] = False
    budget_moved: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def replan_authority_amount(plan: Any, shifts: Any) -> Decimal:
    """Money moved once: positive percentage points of the company budget."""
    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    values = tuple(EnvelopeShift.model_validate(detached(item)) for item in shifts)
    return (parsed_plan.blueprint.operating_budget_per_period * sum((max(item.delta_percent, Decimal("0")) for item in values), Decimal("0")) / Decimal("100")).quantize(MONEY_QUANTUM)


def _apply_period(plan: CompanyOperatingPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    bp, r, event = plan.blueprint, command.receipt, command.event
    if event == "open":
        if r.entity_scope is not None:
            from lightbulb.company_engine_core import EngineScope
            scope = EngineScope.model_validate(r.entity_scope)
            require(command.expected_state_digest == PERIOD_LIFECYCLE.state_digest(plan.plan_digest, scope, ()), "SCOPE_MISMATCH", "the period retains its actual execution scope")
            data["entity_scope"] = r.entity_scope
        require(r.period_start is not None and r.period_end is not None, "PERIOD_MISSING", "an operating period opens with period_start and period_end")
        assert r.period_start is not None and r.period_end is not None
        require(parsed(r.period_end) > parsed(r.period_start), "PERIOD_INVERTED", "period_end is after period_start")
        require(parsed(r.period_end) <= parsed(add_days(r.period_start, bp.period_days)), "PERIOD_TOO_LONG", f"the operating period is at most {bp.period_days} day(s)")
        data.update({"entity_ref": r.entity_ref, "period_start": r.period_start, "period_end": r.period_end, "budget_total": str(bp.operating_budget_per_period)})
    elif event == "dispatch":
        require(r.engine is not None, "ENGINE_MISSING", "a dispatch names its engine")
        envelope = plan.envelope(str(r.engine))
        require(envelope is not None, "ENGINE_NOT_BOUND", f"{r.engine} is not bound in this operating plan")
        require(str(r.engine) not in data.get("dispatched_engines", ()), "ENGINE_ALREADY_DISPATCHED", f"{r.engine} was already dispatched this period")
        require(len(r.dispatch_refs) > 0, "DISPATCH_REFS_MISSING", "a dispatch carries the Spring-authorized dispatch refs")
        assert envelope is not None
        require(len(r.dispatch_refs) <= envelope.dispatches_per_period, "DISPATCH_CADENCE_EXCEEDED", f"{r.engine} runs at most {envelope.dispatches_per_period} dispatch(es) per period")
        require(parsed(command.occurred_at) <= parsed(str(data["period_end"])), "PERIOD_ELAPSED", "dispatches happen inside the period")
        data.update({"dispatched_engines": (*data.get("dispatched_engines", ()), r.engine), "dispatch_count": int(data.get("dispatch_count", 0)) + len(r.dispatch_refs)})
    elif event == "record_evidence":
        if r.source_state is not None or r.source_plan is not None:
            require(r.source_state is not None and r.source_plan is not None, "EVIDENCE_SOURCE_MISSING", "retain both source state and source plan")
            from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE, period_evidence_receipt
            try:
                source_plan, source = COST_REGISTER_LIFECYCLE.bind(r.source_plan, r.source_state)
                derived = period_evidence_receipt(source, source_plan=source_plan, engine=r.engine, period_ref=data.get("entity_ref"))
            except (ValueError, TypeError) as exc:
                require(False, getattr(exc, "code", "EVIDENCE_SOURCE_INVALID"), str(exc))
            scope = data.get("entity_scope") or {}
            require(all(getattr(source.scope, key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "cost evidence belongs to this company execution scope")
            require(source.ledger.period_start == data.get("period_start") and source.ledger.period_end == data.get("period_end"), "PERIOD_MISMATCH", "the cost register covers this exact operating period")
            for key in ("source_digest", "source_digests", "spend", "revenue", "revenue_only", "source_kind"):
                expected = derived.get(key)
                actual = getattr(r, key)
                require(expected is None or detached(actual) == detached(PeriodReceipt.model_validate(derived).__getattribute__(key)), "EVIDENCE_SOURCE_MISMATCH", "period money and source digests must reproduce the cost register")
        require(r.engine is not None and r.evidence_ref is not None, "EVIDENCE_MISSING", "evidence names its engine and evidence_ref")
        require(str(r.engine) in data.get("dispatched_engines", ()), "EVIDENCE_BEFORE_DISPATCH", f"{r.engine} has not been dispatched this period")
        envelope = plan.envelope(str(r.engine))
        assert envelope is not None
        spend = r.spend if r.spend is not None else Decimal("0")
        revenue = r.revenue if r.revenue is not None else Decimal("0")
        sources = tuple(dict.fromkeys((*(r.source_digests or ()), *((r.source_digest,) if r.source_digest else ()))))
        if r.source_digest is not None or r.source_kind is not None or r.revenue_only is not None or r.source_digests:
            require(r.source_digest is not None, "EVIDENCE_SOURCE_MISSING", "artifact-backed evidence carries its source_digest")
            require(r.spend is not None and r.spend >= 0, "EVIDENCE_SPEND_MISSING", "artifact-backed evidence states its non-negative spend")
            require(spend > 0 or revenue == 0 or r.revenue_only is True, "ZERO_SPEND_WITH_REVENUE", "zero-spend revenue explicitly names itself revenue-only")
        require(r.evidence_ref not in data.get("evidence_refs", ()) and not set(sources).intersection(data.get("evidence_source_digests", ())), "EVIDENCE_ALREADY_RECORDED", "this evidence reference or source digest was already recorded", "do_not_replay")
        spend_map = dict(data.get("spend_by_engine", {}))
        revenue_map = dict(data.get("revenue_by_engine", {}))
        new_spend = Decimal(str(spend_map.get(str(r.engine), "0"))) + spend
        require(new_spend <= envelope.budget, "ENVELOPE_OVERSPEND", f"{r.engine} spend {new_spend} exceeds its envelope {envelope.budget}", "manual_reconciliation")
        for name in r.signals:
            require(plan.route(name) is not None, "SIGNAL_UNKNOWN", f"{name} is not routed in this operating plan")
            route = plan.route(name)
            assert route is not None
            require(route.producer == r.engine, "SIGNAL_NOT_PRODUCED_BY_ENGINE", f"{name} is produced by {route.producer}, not {r.engine}")
        spend_map[str(r.engine)] = str(new_spend.quantize(MONEY_QUANTUM))
        revenue_map[str(r.engine)] = str((Decimal(str(revenue_map.get(str(r.engine), "0"))) + revenue).quantize(MONEY_QUANTUM))
        data.update({"evidence_refs": (*data.get("evidence_refs", ()), r.evidence_ref), "evidence_source_digests": (*data.get("evidence_source_digests", ()), *sources)})
        data.update({"evidence_count": int(data.get("evidence_count", 0)) + 1, "spend_by_engine": spend_map, "revenue_by_engine": revenue_map, "signals_received": (*data.get("signals_received", ()), *r.signals), "total_spend": str(sum(Decimal(v) for v in spend_map.values()).quantize(MONEY_QUANTUM)), "total_revenue": str(sum(Decimal(v) for v in revenue_map.values()).quantize(MONEY_QUANTUM))})
    elif event == "reconcile":
        missing = [kind for kind in bp.engine_kinds if kind not in data.get("spend_by_engine", {})]
        require(not missing, "EVIDENCE_INCOMPLETE", f"every bound engine records evidence before reconciliation; missing {missing}")
        require(r.reconciliation_ref is not None, "RECONCILIATION_MISSING", "reconciliation carries the reconciliation_ref from the finance close")
        require(r.books_verified is True, "BOOKS_NOT_VERIFIED", "the period reconciles only against verified books", "await_approval")
        if "finance_close" in bp.engine_kinds:
            require(r.close_state_digest is not None, "BOOKS_PROOF_MISSING", "this company runs the finance close engine; reconciliation carries the close_state_digest from finance_close.verify_books", "await_approval")
        data.update({"reconciliation_ref": r.reconciliation_ref, "books_verified": True, "close_state_digest": r.close_state_digest})
    elif event == "replan":
        require(len(r.shifts) > 0, "SHIFTS_MISSING", "a replan carries envelope shifts")
        unique([item.engine for item in r.shifts], label="shift engines")
        for shift in r.shifts:
            require(plan.envelope(shift.engine) is not None, "ENGINE_NOT_BOUND", f"{shift.engine} is not bound in this operating plan")
            require(abs(shift.delta_percent) <= bp.max_shift_percent_per_replan, "SHIFT_TOO_LARGE", f"{shift.engine} shift {shift.delta_percent}% exceeds the {bp.max_shift_percent_per_replan}% maximum")
        require(sum(item.delta_percent for item in r.shifts) == Decimal("0"), "SHIFT_NOT_NEUTRAL", "shifts move budget between envelopes; they never change the operating budget")
        needs_approval = any(abs(item.delta_percent) > bp.approval_threshold_percent for item in r.shifts)
        proof = None
        if needs_approval:
            from lightbulb.authority_matrix import require_authorization_proof

            amount = replan_authority_amount(plan, r.shifts)
            proof = require_authorization_proof(r.authorization_proof, category="replan", amount=amount, currency=bp.currency, command=command, plan_digest=plan.plan_digest, entity_ref=data.get("entity_ref"))
        data.update({"shifts_applied": tuple(item.to_dict() for item in r.shifts), "approval_ref": proof.approval_task_id if proof else None, "authorization_proof_digest": proof.proof_digest if proof else None})
    elif event == "close":
        data.update({"outcome": "closed"})
    elif event == "halt":
        data.update({"halt_reason": command.reason, "outcome": "halted"})
    return next_status, data


PERIOD_LIFECYCLE = LifecycleSpec(entity="operating_period", schema_prefix="company_operating_period", statuses=PERIOD_STATUSES, terminal=TERMINAL_PERIOD_STATUSES, events=PERIOD_EVENTS, table=_PERIOD_TABLE, opening_event="open", reason_events=("halt",), apply=_apply_period, ledger_model=PeriodLedger, receipt_model=PeriodReceipt, effect_boundary_model=PeriodEffectBoundary, plan_model=CompanyOperatingPlan, max_transitions=MAX_PERIOD_TRANSITIONS)
PeriodCommand = PERIOD_LIFECYCLE.Command
PeriodState = PERIOD_LIFECYCLE.State
PeriodTransitionResult = PERIOD_LIFECYCLE.TransitionResult
seal_period_command = PERIOD_LIFECYCLE.seal_command
period_command_digest = PERIOD_LIFECYCLE.command_digest


def open_period(plan: CompanyOperatingPlan | Mapping[str, Any], scope: Mapping[str, Any] | Any, *, period_start: str, opened_at: str, actor_ref: str, period_end: str | None = None) -> Any:
    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    end = period_end or add_days(period_start, parsed_plan.blueprint.period_days)
    return PERIOD_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={"entity_scope": detached(scope), "entity_ref": dict(detached(scope))["entity_ref"], "period_start": period_start, "period_end": end})


def advance_period(plan: CompanyOperatingPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PERIOD_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Signal routing
# --------------------------------------------------------------------------- #


class CompanySignal(StrictModel):
    name: str = Field(pattern=r"^signals\.[a-z_]{3,60}$")
    producer: EngineKind | Literal["company_operating_system", "subscription_chain", "payout_chain", "custodial_funds", "refund_and_dispute_chain", "obligation_paper", "spend_control_chain", "job_chain"]
    emitted_at: str
    payload: dict[str, str | int | bool] = Field(default_factory=dict)

    @field_validator("emitted_at")
    @classmethod
    def _emitted(cls, value: str) -> str:
        return timestamp(value, field_name="emitted_at")

    @model_validator(mode="after")
    def _guard(self) -> CompanySignal:
        if len(self.payload) > 16:
            raise ValueError("signal payload carries at most 16 keys")
        return self


class SignalRouting(StrictModel):
    schema_id: str = Field(default=ROUTING_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    signal: CompanySignal
    consumers: tuple[ShortText, ...] = Field(min_length=1, max_length=6)
    advisory: BoundedText
    executes_nothing: Literal[True] = True
    routing_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> SignalRouting:
        if not skip_digests(info) and self.routing_digest != sealed_digest(SignalRouting, self, "routing_digest"):
            raise ValueError("routing_digest must commit the exact routing")
        return self


def route_signal(plan: CompanyOperatingPlan | Mapping[str, Any], signal: CompanySignal | Mapping[str, Any]) -> SignalRouting:
    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    parsed_signal = CompanySignal.model_validate(detached(signal))
    route = parsed_plan.route(parsed_signal.name)
    if route is None:
        raise ValueError(f"SIGNAL_UNKNOWN: {parsed_signal.name} is not routed in this operating plan")
    if route.producer != parsed_signal.producer:
        raise ValueError(f"SIGNAL_PRODUCER_MISMATCH: {parsed_signal.name} is produced by {route.producer}, not {parsed_signal.producer}")
    missing = [key for key in route.required_keys if key not in parsed_signal.payload]
    if missing:
        raise ValueError(f"SIGNAL_PAYLOAD_INCOMPLETE: {parsed_signal.name} requires {missing}")
    return seal(SignalRouting, {"plan_digest": parsed_plan.plan_digest, "signal": parsed_signal, "consumers": route.consumers, "advisory": SIGNAL_SPECS[parsed_signal.name].advisory}, "routing_digest")


# --------------------------------------------------------------------------- #
# Health assessment (learn stage)
# --------------------------------------------------------------------------- #


class EngineHealth(StrictModel):
    engine: EngineKind
    budget: Decimal
    spend: Decimal
    revenue: Decimal
    utilisation_percent: Decimal
    return_on_spend: Decimal | None = None

    @field_validator("budget", "spend", "revenue", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _dec(value, field_name=info.field_name, minimum=Decimal("0"))

    @field_validator("utilisation_percent", mode="before")
    @classmethod
    def _util(cls, value: Any) -> Decimal:
        return _dec(value, field_name="utilisation_percent", minimum=Decimal("0"))

    @field_validator("return_on_spend", mode="before")
    @classmethod
    def _ros(cls, value: Any) -> Decimal | None:
        return None if value is None else _dec(value, field_name="return_on_spend", minimum=Decimal("0"))


class CompanyHealthAssessment(StrictModel):
    schema_id: str = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    assessed_at: str
    periods: int = Field(ge=0)
    closed: int = Field(ge=0)
    halted: int = Field(ge=0)
    budget_total: Decimal
    total_spend: Decimal
    total_revenue: Decimal
    revenue_target: Decimal
    revenue_attainment_percent: Decimal | None = None
    spend_utilisation_percent: Decimal | None = None
    runway_months: Decimal | None = None
    engines: tuple[EngineHealth, ...] = Field(default_factory=tuple, max_length=5)
    signals_by_name: dict[str, int] = Field(default_factory=dict)
    learnings: tuple[BoundedText, ...] = Field(min_length=1, max_length=12)
    recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=12)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @field_validator("budget_total", "total_spend", "total_revenue", "revenue_target", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _dec(value, field_name=info.field_name, minimum=Decimal("0"))

    @field_validator("revenue_attainment_percent", "spend_utilisation_percent", "runway_months", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: Any) -> Decimal | None:
        return None if value is None else _dec(value, field_name=info.field_name, minimum=Decimal("0"))

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> CompanyHealthAssessment:
        if not skip_digests(info) and self.assessment_digest != sealed_digest(CompanyHealthAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    if denominator <= 0:
        return None
    return (numerator / denominator * Decimal("100")).quantize(Decimal("0.01"))


def assess_company_health(plan: CompanyOperatingPlan | Mapping[str, Any], periods: Sequence[Any], *, assessed_at: str, cash_on_hand: Any = None, monthly_burn: Any = None, prior_plans: Sequence[CompanyOperatingPlan | Mapping[str, Any]] = ()) -> CompanyHealthAssessment:
    """Assess periods run under plan; prior_plans admits earlier generations of the same lineage (replans)."""

    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    lineage: dict[str, CompanyOperatingPlan] = {parsed_plan.plan_digest: parsed_plan}
    for prior in prior_plans:
        parsed_prior = CompanyOperatingPlan.model_validate(detached(prior))
        if parsed_prior.blueprint.engine_kinds != bp.engine_kinds or parsed_prior.blueprint.currency != bp.currency:
            raise ValueError("PLAN_LINEAGE_MISMATCH: prior plans must run the same engines in the same currency")
        lineage.setdefault(parsed_prior.plan_digest, parsed_prior)
    bound = []
    for item in periods:
        unbound = PERIOD_LIFECYCLE.State.model_validate(detached(item))
        generation = lineage.get(unbound.plan_digest)
        if generation is None:
            raise ValueError("operating_period belongs to a different loop plan")
        bound.append(PERIOD_LIFECYCLE.bind(generation, unbound)[1])
    budget_total = sum((item.ledger.budget_total for item in bound), Decimal("0"))
    total_spend = sum((item.ledger.total_spend for item in bound), Decimal("0"))
    total_revenue = sum((item.ledger.total_revenue for item in bound), Decimal("0"))
    revenue_target = (bp.targets.revenue_per_period * len(bound)).quantize(MONEY_QUANTUM)
    engines = []
    for envelope in parsed_plan.envelopes:
        budget = sum((lineage[item.plan_digest].envelope(envelope.engine).budget for item in bound), Decimal("0"))  # type: ignore[union-attr]
        spend = sum((Decimal(str(item.ledger.spend_by_engine.get(envelope.engine, "0"))) for item in bound), Decimal("0"))
        revenue = sum((Decimal(str(item.ledger.revenue_by_engine.get(envelope.engine, "0"))) for item in bound), Decimal("0"))
        engines.append(EngineHealth(engine=envelope.engine, budget=budget, spend=spend, revenue=revenue, utilisation_percent=_pct(spend, budget) or Decimal("0"), return_on_spend=(revenue / spend).quantize(Decimal("0.01")) if spend > 0 else None))
    signals: dict[str, int] = {}
    for item in bound:
        for name in item.ledger.signals_received:
            signals[name] = signals.get(name, 0) + 1
    runway = None
    if cash_on_hand is not None and monthly_burn is not None:
        cash = _dec(cash_on_hand, field_name="cash_on_hand", minimum=Decimal("0"))
        burn = _dec(monthly_burn, field_name="monthly_burn", minimum=Decimal("0"))
        runway = (cash / burn).quantize(Decimal("0.01")) if burn > 0 else None
    attainment = _pct(total_revenue, revenue_target)
    utilisation = _pct(total_spend, budget_total)
    learnings: list[str] = []
    recommendations: list[str] = []
    halted = sum(1 for item in bound if item.status == "halted")
    if not bound:
        learnings.append("no operating periods yet; form the company and open the first period")
    if attainment is not None and attainment < Decimal("100"):
        learnings.append(f"revenue attainment {attainment}% is below target across {len(bound)} period(s)")
        recommendations.append("shift budget toward the engine with the highest return on spend, inside the replan limits")
    if utilisation is not None and utilisation < Decimal("60"):
        learnings.append(f"only {utilisation}% of the operating budget was deployed")
        recommendations.append("raise dispatch cadence before adding budget")
    if halted:
        learnings.append(f"{halted} period(s) halted: {', '.join(sorted({item.ledger.halt_reason or 'unstated' for item in bound if item.status == 'halted'}))}")
    if runway is not None and runway < bp.targets.min_cash_runway_months:
        learnings.append(f"cash runway {runway} month(s) is below the {bp.targets.min_cash_runway_months}-month floor")
        recommendations.append("cut discretionary envelopes before the next period opens; do not defer the finance close")
    if signals.get("signals.release_rolled_back"):
        recommendations.append("hold growth launches that promote rolled-back capabilities until re-verified")
    if signals.get("signals.churn_risk"):
        recommendations.append("route churn-risk accounts to retention plays; suppress acquisition look-alikes")
    for row in engines:
        if row.spend > 0 and row.revenue == 0:
            learnings.append(f"{row.engine} spent {row.spend} with no attributed revenue")
    if not learnings:
        learnings.append("company is operating inside blueprint targets")
    return seal(CompanyHealthAssessment, dict(plan_digest=parsed_plan.plan_digest, assessed_at=assessed_at, periods=len(bound), closed=sum(1 for item in bound if item.status == "closed"), halted=halted, budget_total=budget_total, total_spend=total_spend, total_revenue=total_revenue, revenue_target=revenue_target, revenue_attainment_percent=attainment, spend_utilisation_percent=utilisation, runway_months=runway, engines=tuple(engines), signals_by_name=signals, learnings=tuple(learnings[:12]), recommendations=tuple(recommendations[:12])), "assessment_digest")


COMPANY_OS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": COMPANY_OS_KIND,
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "stages": list(STAGE_ORDER),
    "archetypes": sorted(COMPANY_OS_ARCHETYPES),
    "formation_countries": dict(SUPPORTED_FORMATION_COUNTRIES),
    "engines": {kind: {"golden_loop": ENGINE_LOOPS[kind], "entry_primitives": list(ENGINE_ENTRY_PRIMITIVES[kind])} for kind in ENGINE_KINDS},
    "signals": {name: {"producer": spec.producer, "consumers": list(spec.consumers), "required_keys": list(spec.required_keys)} for name, spec in SIGNAL_SPECS.items()},
    "period_statuses": list(PERIOD_STATUSES),
    "period_events": list(PERIOD_EVENTS),
    "required_connectors": ["lightbulb.account", "stripe", "xero", "quickbooks", "hubspot", "shopify", "slack"],
    "hard_rules": ["formation runs through the user's own Lightbulb account in Australia or Canada only", "engines dispatch only inside their envelope and cadence", "reconciliation needs verified books", "replans are budget-neutral, capped, and approved above the threshold", "signals are typed, routed only to enabled consumers, and never executed here"],
}

__all__ = [
    "COMPANY_OS_ARCHETYPES",
    "COMPANY_OS_GOLDEN_LOOP",
    "COMPANY_OS_KIND",
    "COMPANY_OS_MANIFEST",
    "ENGINE_ENTRY_PRIMITIVES",
    "ENGINE_KINDS",
    "ENGINE_LOOPS",
    "PERIOD_EVENTS",
    "PERIOD_LIFECYCLE",
    "PERIOD_STATUSES",
    "SIGNAL_SPECS",
    "STAGE_ORDER",
    "TERMINAL_PERIOD_STATUSES",
    "CompanyHealthAssessment",
    "CompanyOperatingBlueprint",
    "CompanyOperatingPlan",
    "CompanySignal",
    "EngineBinding",
    "EngineEnvelope",
    "EngineHealth",
    "EnvelopeShift",
    "FormationPlan",
    "FormationPolicy",
    "OperatingTargets",
    "PeriodCommand",
    "PeriodEffectBoundary",
    "PeriodLedger",
    "PeriodReceipt",
    "PeriodState",
    "PeriodTransitionResult",
    "SignalRoute",
    "SignalRouting",
    "SignalSpec",
    "StageBinding",
    "advance_period",
    "assess_company_health",
    "compile_company_operating_blueprint",
    "open_period",
    "period_command_digest",
    "route_signal",
    "seal_period_command",
    "skip_digests",
    "sealed_digest",
]
