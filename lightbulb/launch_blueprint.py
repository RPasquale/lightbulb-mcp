"""The front door's second seam: an operator's intent plus sealed planning runs compiled into a launch blueprint.

A company that does not exist yet has no observations, so a blueprint can only
stand on two things: what a person explicitly declared, and what the platform's
planning agents already produced and ``planning_intake`` sealed.  This module
keeps those two apart and makes the difference legible.

* ``OperatorIntent`` is the explicit, self-naming operator input - archetype,
  country, region, currency, offers with prices, channels, budget, cash, the
  paper, licences and insurance the operator says the business needs.  It is a
  ``StrictModel``, so it can never carry a tenant, company, or user identifier,
  and it is sealed with ``build_intent`` before anything compiles from it.
* ``compile_launch_blueprint`` merges that intent with a ``PlanningIntake`` into
  a ``LaunchBlueprint`` in which **every compiled field names where it came
  from**: a ``FieldProvenance`` row citing the run's source, trace and outputs
  digest, or ``operator`` when a person declared it.  A field nothing proved
  does not get a fabricated value; it gets a ``Blocker`` that says who resolves
  it - the operator, another platform run, or a human acting in the world.

Nothing here forms a company, dispatches an agent, or spends money.  The
compiler refuses outright only where a number would otherwise be a lie: a
planning run too old to describe the present, an incorporation package for a
different country, priced evidence in a different currency.  Everything softer
is a blocker, and a blueprint carrying blockers still compiles and still renders
- it simply cannot become a ``CadenceBundle`` until they are gone.

``suggest_requirements`` offers the registrations, licences and insurance a
jurisdiction usually asks of a trade.  Suggestions are **never** promoted into
the blueprint: each one the operator has neither declared nor dismissed becomes
a ``REQUIREMENT_SUGGESTION_UNCONFIRMED`` blocker, and every row carries
``not_legal_advice``.  ``draft_intent`` likewise only drafts - it turns a
sentence into an unsealed mapping the operator edits and seals themselves.

What this hands on: ``to_cadence_bundle`` turns a ready blueprint into the
``CadenceBundle`` that ``company_cadence_runner`` and the existing engines
already run on, and ``render_blueprint`` renders the whole thing as markdown a
person can argue with before a dollar moves.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, ValidationInfo, field_validator, model_validator

from lightbulb.company_cadence_runner import CadenceBundle, complete_company_bundle_plans
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    percent_value,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)
from lightbulb.company_formation import UnsupportedFormationCountryError, normalize_formation_country
from lightbulb.company_operating_system import (
    COMPANY_OS_ARCHETYPES,
    Archetype,
    CompanyOperatingBlueprint,
    compile_company_operating_blueprint,
)
from lightbulb.company_workforce import STANDARD_ROSTERS, compile_workforce, standard_roster
from lightbulb.compliance_calendar import compile_compliance_calendar
from lightbulb.finance_close_engine import compile_finance_close_blueprint
from lightbulb.growth_engine_loop import (
    GROWTH_ENGINE_PROFILES,
    PAID_CHANNELS,
    Channel,
    compile_growth_engine_blueprint,
)
from lightbulb.pipeline_engine_loop import (
    PIPELINE_ENGINE_PROFILES,
    OutreachChannel,
    compile_pipeline_engine_blueprint,
)
from lightbulb.planning_intake import ObservedPrice, PlanningIntake, PlanningRunReceipt, PlanningSource
from lightbulb.saas_operating_loop import compile_saas_operating_blueprint
from lightbulb.service_delivery_engine import compile_service_delivery_blueprint

BLUEPRINT_SCHEMA = "lightbulb.launch_blueprint.v1"
INTENT_SCHEMA = "lightbulb.operator_launch_intent.v1"
LAUNCH_GOLDEN_LOOP = "company.idea_to_first_dollar@0.1.0"
# The intake already refuses a run older than 30 days at sealing; this is the blueprint's own,
# looser bound, so a blueprint recompiled from an older sealed intake still says when it went stale.
MAX_RUN_AGE_DAYS = 90
COUNTRY_CURRENCY: Mapping[str, str] = {"AU": "AUD", "CA": "CAD"}
RegionCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$")]

ARCHETYPE_PROFILES: Mapping[str, Mapping[str, str | None]] = {
    "services_firm": {"growth": "local_services", "pipeline": "agency_outbound", "service_delivery": "engagement_delivery", "finance_close": "fortnightly_close", "saas": None},
    "dtc_commerce": {"growth": "dtc_shopify", "pipeline": None, "service_delivery": "commerce_support", "finance_close": "weekly_close", "saas": None},
    "b2b_saas": {"growth": "b2b_saas", "pipeline": "b2b_saas_outbound", "service_delivery": "saas_support", "finance_close": "weekly_close", "saas": "sales_assisted"},
    "marketplace": {"growth": "marketplace_demand", "pipeline": "partner_channel", "service_delivery": None, "finance_close": "weekly_close", "saas": None},
    "founder_led_saas": {"growth": "plg_self_serve", "pipeline": None, "service_delivery": None, "finance_close": "monthly_close_cad", "saas": "plg_self_serve"},
    "local_services": {"growth": "local_services", "pipeline": None, "service_delivery": "local_aftercare", "finance_close": "fortnightly_close", "saas": None},
    "two_sided_marketplace": {"growth": "marketplace_demand", "pipeline": None, "service_delivery": "marketplace_disputes", "finance_close": "weekly_close", "saas": None},

}

PaperKind = Literal["service_agreement", "employment_agreement", "nda", "partnership_agreement", "sales_agreement", "incorporation", "hr_onboarding"]
# kind -> the platform action that drafts it.  Only the three that planning_intake seals are
# PlanningSource members; the rest name a run the platform can make but the SDK cannot yet read.
PACKET_ACTIONS: Mapping[str, str] = {
    "service_agreement": "legal.service_agreement_packet",
    "employment_agreement": "legal.employment_agreement_packet",
    "incorporation": "legal.incorporation_document_package",
    "nda": "legal.nda_packet",
    "partnership_agreement": "legal.partnership_agreement_packet",
    "sales_agreement": "legal.sales_agreement_packet",
    "hr_onboarding": "legal.hr_onboarding_packet",
}
_BLOCKING_BEFORE = ("formation", "first_hire", "first_job")

PROVENANCED_FIELDS: tuple[str, ...] = (
    "operating_blueprint.name",
    "operating_blueprint.country",
    "operating_blueprint.currency",
    "operating_blueprint.operating_budget_per_period",
    "operating_blueprint.targets.revenue_per_period",
    "operating_blueprint.targets.gross_margin_percent",
    "growth_overrides.channels",
    "offers",
    "required_paper",
    "licences",
    "insurance",
)
MAX_PROVENANCE_ROWS = 120
MAX_BLOCKERS = 40
MAX_FINDINGS = 40
# A finding is a ``ShortText``.  Findings quote operator strings (an offer name is itself a
# 300-character ShortText), so an unbounded one turns a legitimate compile into a pydantic
# error about a field the operator never named.  Say less rather than refuse.
FINDING_MAX_CHARS = 300


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class BlueprintCompileError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BlueprintCompileError(code, message)


def _money(value: Any, *, field_name: str) -> Decimal:
    return decimal_value(value, field_name=field_name)


def _q(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANTUM)


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _finding(text: str) -> str:
    """Keep a finding inside ``ShortText``; a long quoted name shortens the sentence, never the compile."""

    return text if len(text) <= FINDING_MAX_CHARS else text[: FINDING_MAX_CHARS - 1].rstrip() + "…"


def _within_cap(blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A blueprint exists to say who owns every gap, so the ones past the cap are counted, not dropped."""

    if len(blockers) <= MAX_BLOCKERS:
        return blockers
    kept = blockers[: MAX_BLOCKERS - 1]
    dropped = blockers[MAX_BLOCKERS - 1 :]
    codes = ", ".join(sorted({str(item["code"]) for item in dropped}))
    return [
        *kept,
        {
            "code": "BLOCKERS_TRUNCATED",
            "detail": f"{len(dropped)} further blockers ({codes}) are not listed; a blueprint carries at most {MAX_BLOCKERS}. Resolve the listed ones and recompile to see the rest.",
            "resolves_by": "operator_input",
            "platform_action": None,
        },
    ]


# --------------------------------------------------------------------------- #
# Draft helpers: unsealed, the operator confirms
# --------------------------------------------------------------------------- #

TRADE_ARCHETYPES: Mapping[str, str] = {
    "plumbing": "services_firm",
    "electrical": "services_firm",
    "hvac": "services_firm",
    "cleaning": "services_firm",
    "landscaping": "services_firm",
    "painting": "services_firm",
    "carpentry": "services_firm",
    "bookkeeping": "services_firm",
    "accounting": "services_firm",
    "consulting": "services_firm",
    "marketing_agency": "services_firm",
    "legal_practice": "services_firm",
    "clinic": "services_firm",
    "online_store": "dtc_commerce",
    "ecommerce": "dtc_commerce",
    "dtc": "dtc_commerce",
    "saas": "b2b_saas",
    "software": "b2b_saas",
    "marketplace": "marketplace",
}

CITY_JURISDICTIONS: Mapping[str, tuple[str, str]] = {
    "brisbane": ("AU", "AU-QLD"),
    "gold coast": ("AU", "AU-QLD"),
    "sunshine coast": ("AU", "AU-QLD"),
    "sydney": ("AU", "AU-NSW"),
    "newcastle": ("AU", "AU-NSW"),
    "melbourne": ("AU", "AU-VIC"),
    "geelong": ("AU", "AU-VIC"),
    "perth": ("AU", "AU-WA"),
    "adelaide": ("AU", "AU-SA"),
    "hobart": ("AU", "AU-TAS"),
    "darwin": ("AU", "AU-NT"),
    "canberra": ("AU", "AU-ACT"),
    "toronto": ("CA", "CA-ON"),
    "ottawa": ("CA", "CA-ON"),
    "vancouver": ("CA", "CA-BC"),
    "victoria": ("CA", "CA-BC"),
    "montreal": ("CA", "CA-QC"),
    "quebec city": ("CA", "CA-QC"),
    "calgary": ("CA", "CA-AB"),
    "edmonton": ("CA", "CA-AB"),
    "winnipeg": ("CA", "CA-MB"),
    "halifax": ("CA", "CA-NS"),
}

# Outreach phrases are matched first and cut out of the sentence, so "cold email" never
# also reads as the growth channel "email".
CHANNEL_ALIASES: Mapping[str, Mapping[str, str]] = {
    "outreach": {
        "cold email": "email",
        "outbound": "email",
        "linkedin outreach": "linkedin",
        "cold call": "voice",
        "phone": "voice",
    },
    "growth": {
        "google ads": "paid_search_google",
        "paid search": "paid_search_google",
        "ppc": "paid_search_google",
        "facebook": "paid_social_meta",
        "meta": "paid_social_meta",
        "instagram ads": "paid_social_meta",
        "paid social": "paid_social_meta",
        "tiktok": "paid_social_tiktok",
        "organic social": "organic_social",
        "instagram": "organic_social",
        "linkedin": "organic_social",
        "social": "organic_social",
        "seo": "seo_content",
        "content": "seo_content",
        "blog": "seo_content",
        "email": "email_lifecycle",
        "newsletter": "email_lifecycle",
        "sms": "sms_lifecycle",
        "text": "sms_lifecycle",
        "referral": "affiliate",
        "affiliate": "affiliate",
        "partner": "affiliate",
    },
}


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])")


def _longest_first(table: Mapping[str, Any]) -> list[str]:
    return sorted(table, key=lambda phrase: (-len(phrase), phrase))


def _first_phrase(text: str, table: Mapping[str, Any]) -> str | None:
    for phrase in _longest_first(table):
        if _phrase_pattern(phrase.replace("_", " ")).search(text) or _phrase_pattern(phrase).search(text):
            return phrase
    return None


def _matched_values(text: str, table: Mapping[str, str]) -> tuple[list[str], str]:
    """Every alias the sentence names, in table order, plus the sentence with those phrases cut out."""

    found: list[str] = []
    remainder = text
    for phrase in _longest_first(table):
        pattern = _phrase_pattern(phrase)
        if pattern.search(remainder):
            remainder = pattern.sub(" ", remainder)
            value = table[phrase]
            if value not in found:
                found.append(value)
    ordered = list(dict.fromkeys(table.values()))
    return [value for value in ordered if value in found], remainder


def draft_intent(utterance: str, *, declared_by_ref: str, declared_at: str, **declarations: Any) -> dict[str, Any]:
    """Draft - never seal - an intent from one sentence; the operator edits it and calls ``build_intent``."""

    text = " ".join(str(utterance or "").split())
    lowered = text.lower()
    draft: dict[str, Any] = {"schema": INTENT_SCHEMA, "declared_by_ref": declared_by_ref, "declared_at": declared_at, "idea": text or "unstated"}

    trade = _first_phrase(lowered, TRADE_ARCHETYPES)
    if trade is None and "archetype" not in declarations:
        raise ValueError(f"TRADE_UNKNOWN: nothing in {text!r} names a trade this draft knows; declare archetype= yourself. Known: {sorted(TRADE_ARCHETYPES)}")
    if trade is not None:
        draft["trade"] = trade.replace("_", " ")
        draft["archetype"] = TRADE_ARCHETYPES[trade]

    city = _first_phrase(lowered, CITY_JURISDICTIONS)
    if city is None and "country" not in declarations:
        raise ValueError(f"CITY_UNKNOWN: nothing in {text!r} names a city this draft knows; declare country= and region_code= yourself. Known: {sorted(CITY_JURISDICTIONS)}")
    if city is not None:
        country, region_code = CITY_JURISDICTIONS[city]
        draft.update({"country": country, "region_code": region_code, "currency": COUNTRY_CURRENCY[country], "region": city.title()})

    outreach, remainder = _matched_values(lowered, CHANNEL_ALIASES["outreach"])
    growth, _ = _matched_values(remainder, CHANNEL_ALIASES["growth"])
    if growth:
        draft["channels"] = growth[:8]
    if outreach:
        draft["outreach_channels"] = outreach[:4]
    draft.update(declarations)
    return draft


# --------------------------------------------------------------------------- #
# Requirement suggestions: never promoted, never legal advice
# --------------------------------------------------------------------------- #

RequirementKind = Literal["registration", "tax_registration", "trade_licence", "insurance", "workers_compensation"]
RequirementCondition = Literal["always", "has_payroll", "revenue_over_gst_threshold"]

REQUIREMENT_DEFAULTS: Mapping[tuple[str, str, str], tuple[dict[str, str], ...]] = {
    ("AU", "*", "*"): (
        {"kind": "registration", "name": "ABN", "authority": "Australian Business Register", "condition": "always"},
        {"kind": "tax_registration", "name": "GST registration", "authority": "Australian Taxation Office", "condition": "revenue_over_gst_threshold"},
        {"kind": "insurance", "name": "public_liability", "authority": "insurer", "condition": "always"},
        {"kind": "workers_compensation", "name": "WorkCover", "authority": "state workers compensation regulator", "condition": "has_payroll"},
    ),
    ("AU", "AU-QLD", "plumbing"): ({"kind": "trade_licence", "name": "QBCC plumbing and drainage licence", "authority": "Queensland Building and Construction Commission", "condition": "always"},),
    ("AU", "AU-NSW", "plumbing"): ({"kind": "trade_licence", "name": "NSW Fair Trading plumbing licence", "authority": "NSW Fair Trading", "condition": "always"},),
    ("AU", "*", "electrical"): ({"kind": "trade_licence", "name": "State electrical licence", "authority": "state electrical safety regulator", "condition": "always"},),
    ("CA", "*", "*"): (
        {"kind": "registration", "name": "CRA business number", "authority": "Canada Revenue Agency", "condition": "always"},
        {"kind": "tax_registration", "name": "GST/HST account", "authority": "Canada Revenue Agency", "condition": "revenue_over_gst_threshold"},
        {"kind": "insurance", "name": "commercial general liability", "authority": "insurer", "condition": "always"},
        {"kind": "workers_compensation", "name": "provincial workers compensation", "authority": "provincial workers compensation board", "condition": "has_payroll"},
    ),
    ("CA", "CA-ON", "plumbing"): ({"kind": "trade_licence", "name": "Skilled Trades Ontario plumber certificate", "authority": "Skilled Trades Ontario", "condition": "always"},),
}
GST_THRESHOLDS: Mapping[str, str] = {"AU": "AUD 75,000 a year", "CA": "CAD 30,000 a year"}


class SuggestedRequirement(StrictModel):
    """A registration, licence or policy the jurisdiction usually asks of this trade; a prompt, not advice."""

    kind: RequirementKind
    name: ShortText
    authority: ShortText
    condition: RequirementCondition
    not_legal_advice: Literal[True] = True


def suggest_requirements(intent: OperatorIntent | Mapping[str, Any]) -> tuple[SuggestedRequirement, ...]:
    """The default requirements for this country, region and trade; the operator confirms or dismisses each."""

    parsed_intent = _intent(intent)
    rows: list[SuggestedRequirement] = []
    for (country, region, trade), entries in REQUIREMENT_DEFAULTS.items():
        if country != parsed_intent.country:
            continue
        if region != "*" and region != parsed_intent.region_code:
            continue
        if trade != "*" and trade != (parsed_intent.trade or ""):
            continue
        for entry in entries:
            if entry["condition"] == "has_payroll" and not parsed_intent.has_payroll:
                continue
            if entry["condition"] == "revenue_over_gst_threshold" and not parsed_intent.registered_for_gst:
                continue
            rows.append(SuggestedRequirement.model_validate(entry))
    return tuple(rows)


def _declared_tokens(intent: OperatorIntent) -> set[str]:
    tokens = {item.kind.casefold() for item in intent.licences}
    tokens |= {item.kind.casefold() for item in intent.insurance}
    tokens |= {item.kind.casefold() for item in intent.required_paper}
    return tokens


def unconfirmed_requirements(intent: OperatorIntent | Mapping[str, Any]) -> tuple[SuggestedRequirement, ...]:
    """Suggestions the operator has neither declared nor dismissed; each becomes a blocker."""

    parsed_intent = _intent(intent)
    tokens = _declared_tokens(parsed_intent)
    dismissed = {item.casefold() for item in parsed_intent.dismissed_suggestions}
    return tuple(
        row for row in suggest_requirements(parsed_intent)
        if row.name.casefold() not in tokens and row.kind.casefold() not in tokens and row.name.casefold() not in dismissed
    )


# --------------------------------------------------------------------------- #
# The operator's intent
# --------------------------------------------------------------------------- #


class Offer(StrictModel):
    """One thing the business sells, at the price the operator declared."""

    name: ShortText
    unit: Literal["hour", "job", "month", "unit", "project"]
    price: Decimal
    cost_of_delivery: Decimal
    currency: CurrencyCode
    description: BoundedText | None = None

    @field_validator("price", "cost_of_delivery", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _priced(self) -> Offer:
        if self.price <= 0:
            raise ValueError("OFFER_PRICE_INVALID: an offer price must be greater than zero")
        return self

    @property
    def margin(self) -> Decimal:
        return self.price - self.cost_of_delivery


class PaperRequirement(StrictModel):
    """A document the operator says must exist before a milestone."""

    kind: PaperKind
    counterparty_role: ShortText
    required_before: Literal["formation", "first_hire", "first_job", "first_dollar"]


class LicenceRequirement(StrictModel):
    """A licence the operator says the business needs, and whether they hold it."""

    kind: ShortText
    authority: ShortText
    required_before: Literal["formation", "first_job", "first_dollar"]
    status: Literal["not_applied", "applied", "held"]
    evidence_ref: OpaqueRef | None = None

    @model_validator(mode="after")
    def _held_is_evidenced(self) -> LicenceRequirement:
        if self.status == "held" and self.evidence_ref is None:
            raise ValueError(f"LICENCE_EVIDENCE_MISSING: {self.kind} is declared held; name the evidence_ref that proves it")
        return self


class InsuranceRequirement(StrictModel):
    """A policy the operator says the business needs, and whether it is bound."""

    kind: Literal["public_liability", "professional_indemnity", "workers_compensation", "product_liability", "cyber", "vehicle"]
    minimum_cover: Decimal
    required_before: Literal["formation", "first_hire", "first_job", "first_dollar"]
    status: Literal["not_bound", "quoted", "bound"]
    evidence_ref: OpaqueRef | None = None

    @field_validator("minimum_cover", mode="before")
    @classmethod
    def _cover(cls, value: Any) -> Decimal:
        return _money(value, field_name="minimum_cover")

    @model_validator(mode="after")
    def _bound_is_evidenced(self) -> InsuranceRequirement:
        if self.status == "bound" and self.evidence_ref is None:
            raise ValueError(f"INSURANCE_EVIDENCE_MISSING: {self.kind} is declared bound; name the evidence_ref that proves it")
        return self


class OperatorIntent(StrictModel):
    """What a person declared they want to build.  Every field here is an operator input, not a model output."""

    schema_id: Literal["lightbulb.operator_launch_intent.v1"] = Field(default=INTENT_SCHEMA, alias="schema")
    declared_by_ref: OpaqueRef
    declared_at: str
    idea: BoundedText
    name: ShortText
    archetype: Archetype
    country: str
    region: ShortText
    region_code: RegionCode
    currency: CurrencyCode
    trade: ShortText | None = None
    industry: ShortText
    purpose: BoundedText
    offers: tuple[Offer, ...] = Field(min_length=1, max_length=12)
    channels: tuple[Channel, ...] = Field(min_length=1, max_length=8)
    outreach_channels: tuple[OutreachChannel, ...] = Field(default=(), max_length=4)
    operating_budget_per_period: Decimal
    period_days: int = Field(default=7, ge=1, le=92)
    starting_cash: Decimal
    fixed_costs_per_period: Decimal
    required_paper: tuple[PaperRequirement, ...] = Field(default=(), max_length=12)
    licences: tuple[LicenceRequirement, ...] = Field(default=(), max_length=20)
    insurance: tuple[InsuranceRequirement, ...] = Field(default=(), max_length=12)
    dismissed_suggestions: tuple[ShortText, ...] = Field(default=(), max_length=20)
    has_payroll: bool = False
    registered_for_gst: bool = False
    revenue_per_period_target: Decimal | None = None
    intent_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("declared_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="declared_at")

    @field_validator("archetype")
    @classmethod
    def _archetype(cls, value: str) -> str:
        if value not in ARCHETYPE_PROFILES:
            raise ValueError(f"ARCHETYPE_UNSUPPORTED: {value!r} has no launch profile; choose one of {sorted(ARCHETYPE_PROFILES)}")
        return value

    @field_validator("country", mode="before")
    @classmethod
    def _country(cls, value: Any) -> str:
        try:
            return normalize_formation_country(value)
        except UnsupportedFormationCountryError as exc:
            raise ValueError(f"COUNTRY_UNSUPPORTED: the front door forms companies in {sorted(COUNTRY_CURRENCY)} only; got {value!r}") from exc

    @field_validator("operating_budget_per_period", "starting_cash", "fixed_costs_per_period", "revenue_per_period_target", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _money(value, field_name=str(info.field_name))

    @field_validator("offers", "channels", "outreach_channels", "required_paper", "licences", "insurance", "dismissed_suggestions", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorIntent:
        if self.region_code[:2] != self.country:
            raise ValueError(f"REGION_COUNTRY_MISMATCH: region_code {self.region_code} is not in {self.country}")
        expected = COUNTRY_CURRENCY[self.country]
        if self.currency != expected:
            raise ValueError(f"CURRENCY_COUNTRY_MISMATCH: {self.country} operates in {expected}, not {self.currency}")
        unique([item.name for item in self.offers], label="offer names")
        unique(list(self.channels), label="channels")
        unique(list(self.outreach_channels), label="outreach channels")
        for offer in self.offers:
            if offer.currency != self.currency:
                raise ValueError(f"OFFER_CURRENCY_MISMATCH: offer {offer.name} is priced in {offer.currency}, the company operates in {self.currency}")
            if offer.margin <= 0:
                raise ValueError(f"OFFER_MARGIN_NEGATIVE: offer {offer.name} costs {offer.cost_of_delivery} to deliver and sells for {offer.price}")
        if self.operating_budget_per_period < Decimal("0.01"):
            raise ValueError("operating_budget_per_period must be at least 0.01")
        if not skip_digests(info) and self.intent_digest != sealed_digest(OperatorIntent, self, "intent_digest"):
            raise ValueError("intent_digest must commit the exact intent")
        return self

    @property
    def monthly_budget(self) -> Decimal:
        return _q(self.operating_budget_per_period * Decimal(30) / Decimal(self.period_days))


def build_intent(intent: Mapping[str, Any]) -> OperatorIntent:
    """Seal what the operator declared; nothing compiles from an unsealed intent."""

    return seal(OperatorIntent, dict(detached(intent)), "intent_digest")


def _intent(value: OperatorIntent | Mapping[str, Any]) -> OperatorIntent:
    if isinstance(value, OperatorIntent):
        return value
    raw = dict(detached(value))
    if raw.get("intent_digest") in (None, GENESIS_DIGEST):
        return build_intent(raw)
    return OperatorIntent.model_validate(raw)


def _intake(value: PlanningIntake | Mapping[str, Any] | None) -> PlanningIntake | None:
    if value is None or isinstance(value, PlanningIntake):
        return value
    return PlanningIntake.model_validate(dict(detached(value)))


# --------------------------------------------------------------------------- #
# The blueprint
# --------------------------------------------------------------------------- #


class FieldProvenance(StrictModel):
    """Where one compiled field came from: a planning run and the path inside it, or the operator."""

    field: ShortText
    source: PlanningSource | Literal["operator"] = "operator"
    trace_ref: OpaqueRef | None = None
    outputs_digest: Sha256Digest | None = None
    path: ShortText | None = None
    confidence: Literal["extracted", "fallback", "operator_declared"] = "operator_declared"


class Blocker(StrictModel):
    """Something the blueprint could not prove, and who resolves it."""

    code: ShortText
    detail: BoundedText
    resolves_by: Literal["operator_input", "platform_run", "human_action"]
    platform_action: ShortText | None = None


class PaperPlan(StrictModel):
    """One required document: whether a platform run has drafted it, and what proves the draft."""

    kind: PaperKind
    counterparty_role: ShortText
    required_before: Literal["formation", "first_hire", "first_job", "first_dollar"]
    packet_source: PlanningSource | None = None
    document_ref: OpaqueRef | None = None
    content_sha256: Sha256Digest | None = None
    registrar: ShortText | None = None
    filing_steps: tuple[ShortText, ...] = Field(default=(), max_length=12)
    requires_review: Literal[True] = True
    status: Literal["not_drafted", "drafted"] = "not_drafted"

    @field_validator("filing_steps", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


PriceEvidence = ObservedPrice


class LaunchBlueprint(StrictModel):
    """A compiled launch plan in which every field names its run or its declarer, and every gap names its owner."""

    schema_id: Literal["lightbulb.launch_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    intent_digest: Sha256Digest
    intake_digest: Sha256Digest | None = None
    compiled_at: str
    archetype: Archetype
    country: str
    region: ShortText
    region_code: RegionCode
    currency: CurrencyCode
    operating_blueprint: CompanyOperatingBlueprint
    growth_profile: ShortText
    growth_overrides: dict[str, Any] = Field(default_factory=dict)
    pipeline_profile: ShortText | None = None
    pipeline_overrides: dict[str, Any] = Field(default_factory=dict)
    service_delivery_profile: ShortText | None = None
    finance_close_profile: ShortText
    saas_profile: ShortText | None = None
    offers: tuple[Offer, ...] = Field(min_length=1, max_length=12)
    price_evidence: tuple[PriceEvidence, ...] = Field(default=(), max_length=50)
    required_paper: tuple[PaperPlan, ...] = Field(default=(), max_length=12)
    licences: tuple[LicenceRequirement, ...] = Field(default=(), max_length=20)
    insurance: tuple[InsuranceRequirement, ...] = Field(default=(), max_length=12)
    compliance_plan_digest: Sha256Digest
    obligation_kinds: tuple[ShortText, ...] = Field(default=(), max_length=12)
    formation_preview: dict[str, str] = Field(default_factory=dict)
    provenance: tuple[FieldProvenance, ...] = Field(min_length=1, max_length=MAX_PROVENANCE_ROWS)
    blockers: tuple[Blocker, ...] = Field(default=(), max_length=40)
    findings: tuple[ShortText, ...] = Field(default=(), max_length=40)
    ready_to_plan: bool = False
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("compiled_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="compiled_at")

    @field_validator("offers", "price_evidence", "required_paper", "licences", "insurance", "obligation_kinds", "provenance", "blockers", "findings", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchBlueprint:
        if self.ready_to_plan != (len(self.blockers) == 0):
            raise ValueError("ready_to_plan must say exactly whether the blueprint carries blockers")
        named = {row.field for row in self.provenance}
        required = PROVENANCED_FIELDS + (("pipeline_overrides.icp",) if self.pipeline_profile is not None else ())
        for field in required:
            if field not in named:
                raise ValueError(f"FIELD_WITHOUT_PROVENANCE: {field}")
        if not skip_digests(info) and self.blueprint_digest != sealed_digest(LaunchBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def blocker(self, code: str) -> Blocker | None:
        return next((item for item in self.blockers if item.code == code), None)

    def rows_for(self, field: str) -> tuple[FieldProvenance, ...]:
        return tuple(row for row in self.provenance if row.field == field)

    def paper(self, kind: str) -> PaperPlan | None:
        return next((item for item in self.required_paper if item.kind == kind), None)

    @property
    def blocker_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.blockers)

    @property
    def finding_codes(self) -> tuple[str, ...]:
        return tuple(item.split(":", 1)[0] for item in self.findings)


# --------------------------------------------------------------------------- #
# The compiler
# --------------------------------------------------------------------------- #


def _row(field: str, *, receipt: PlanningRunReceipt | None = None, path: str | None = None, confidence: str | None = None) -> dict[str, Any]:
    if receipt is None:
        return {"field": field, "source": "operator", "path": path, "confidence": confidence or "operator_declared"}
    return {
        "field": field,
        "source": receipt.source,
        "trace_ref": receipt.trace_ref,
        "outputs_digest": receipt.outputs_digest,
        "path": path,
        "confidence": confidence or "extracted",
    }


def _nearest_cpa(profile_channels: Sequence[Mapping[str, Any]], cap: Decimal) -> str | None:
    """The target CPA of the profile's paid channel whose budget cap sits closest to this one."""

    candidates = [row for row in profile_channels if row.get("channel") in PAID_CHANNELS and row.get("target_cpa") is not None]
    if not candidates:
        return None
    nearest = min(candidates, key=lambda row: abs(_money(row["monthly_budget_cap"], field_name="monthly_budget_cap") - cap))
    return str(nearest["target_cpa"])


def _trimmed_sequences(sequences: Sequence[Mapping[str, Any]], kept: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sequence in sequences:
        steps = [dict(step) for step in sequence.get("steps", ()) if step.get("channel") in kept]
        if not steps:
            continue
        for index, step in enumerate(steps, start=1):
            step["step"] = index
        out.append({**{key: value for key, value in sequence.items() if key != "steps"}, "steps": steps})
    return out


def compile_launch_blueprint(
    intent: OperatorIntent | Mapping[str, Any],
    intake: PlanningIntake | Mapping[str, Any] | None = None,
    *,
    compiled_at: str,
    max_run_age_days: int = MAX_RUN_AGE_DAYS,
) -> LaunchBlueprint:
    """Compile an operator's intent and the sealed planning runs into a blueprint that names every source."""

    declared = _intent(intent)
    sealed_intake = _intake(intake)
    when = timestamp(compiled_at, field_name="compiled_at")
    receipts = sealed_intake.receipts if sealed_intake is not None else ()

    for receipt in receipts:
        # Staleness is only half of it: a blueprint stamped before the runs it cites would claim
        # provenance from work that had not happened, and compiled_at anchors the whole calendar.
        _require(
            parsed(receipt.generated_at) <= parsed(when),
            "PLANNING_RUN_IN_FUTURE",
            f"{receipt.source} completed {receipt.generated_at}, after the compile stamp {when}; a blueprint cannot cite a run that has not happened",
        )
        fresh = parsed(when) <= parsed(add_days(receipt.generated_at, max_run_age_days))
        _require(fresh, "PLANNING_RUN_STALE", f"{receipt.source} completed {receipt.generated_at}, more than {max_run_age_days} days before {when}; run it again")
    by_source = {receipt.source: receipt for receipt in receipts}

    incorporation = by_source.get("legal.incorporation_document_package")
    if incorporation is not None and incorporation.facts.country is not None:
        _require(
            incorporation.facts.country == declared.country,
            "INTAKE_COUNTRY_CONFLICT",
            f"the incorporation package was drafted for {incorporation.facts.country}, the intent declares {declared.country}",
        )

    pricing = by_source.get("product.pricing_intelligence")
    price_evidence = tuple(pricing.facts.observed_prices or ()) if pricing is not None else ()
    for observed in price_evidence:
        _require(
            observed.currency.upper() == declared.currency,
            "INTAKE_CURRENCY_CONFLICT",
            f"observed prices for {observed.subject} are in {observed.currency}, the intent declares {declared.currency}",
        )

    provenance: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    findings: list[str] = []
    profiles = ARCHETYPE_PROFILES[declared.archetype]
    archetype_raw = _copy(dict(COMPANY_OS_ARCHETYPES[declared.archetype]))

    # ---- targets ------------------------------------------------------- #
    forecast = by_source.get("finance.finance_forecasting")
    points = tuple(forecast.facts.forecast_points or ()) if forecast is not None else ()
    monthly_revenue: Decimal | None = None
    if points:
        monthly_revenue = _q(sum((point.predicted_value for point in points), Decimal(0)) / Decimal(len(points)))
        revenue = _q(monthly_revenue * Decimal(declared.period_days) / Decimal(30))
        provenance.append(_row("operating_blueprint.targets.revenue_per_period", receipt=forecast, path="forecasts[].predicted_value"))
    elif declared.revenue_per_period_target is not None:
        revenue = declared.revenue_per_period_target
        monthly_revenue = _q(revenue * Decimal(30) / Decimal(declared.period_days))
        provenance.append(_row("operating_blueprint.targets.revenue_per_period", path="intent.revenue_per_period_target"))
    else:
        revenue = _money(archetype_raw["targets"]["revenue_per_period"], field_name="revenue_per_period")
        provenance.append(_row("operating_blueprint.targets.revenue_per_period", path=f"COMPANY_OS_ARCHETYPES.{declared.archetype}.targets.revenue_per_period", confidence="fallback"))
        blockers.append({
            "code": "REVENUE_TARGET_UNDECLARED",
            "detail": "no revenue forecast was sealed and the intent declares no revenue_per_period_target; the archetype default stands in and proves nothing",
            "resolves_by": "platform_run",
            "platform_action": "finance.finance_forecasting",
        })

    gross = sum((offer.margin for offer in declared.offers), Decimal(0))
    turnover = sum((offer.price for offer in declared.offers), Decimal(0))
    margin_percent = percent_value(_q(gross * Decimal(100) / turnover), field_name="gross_margin_percent")
    provenance.append(_row("operating_blueprint.targets.gross_margin_percent", path="intent.offers[].price - cost_of_delivery"))

    runway_months = int(archetype_raw["targets"]["min_cash_runway_months"])
    # A cadence longer than the operating period is not runnable; the operator's period wins.
    # It is still a number this module rewrote, so it says so rather than moving it quietly.
    engines = [{**binding, "cadence_days": min(int(binding["cadence_days"]), declared.period_days)} for binding in archetype_raw["engines"]]
    clamped = [str(binding["engine"]) for binding in archetype_raw["engines"] if int(binding["cadence_days"]) > declared.period_days]
    if clamped:
        findings.append(f"ENGINE_CADENCE_CLAMPED: the {declared.archetype} archetype runs {', '.join(clamped)} less often than the {declared.period_days}d period the operator declared; their cadence is pulled back to it")
    operating_raw = {
        **archetype_raw,
        "name": declared.name,
        "country": declared.country,
        "currency": declared.currency,
        "operating_budget_per_period": str(declared.operating_budget_per_period),
        "period_days": declared.period_days,
        "engines": engines,
        "formation": {"industry": declared.industry, "purpose": declared.purpose, "contact_email_required": True},
        "targets": {"revenue_per_period": str(revenue), "gross_margin_percent": str(margin_percent), "min_cash_runway_months": runway_months},
    }
    operating_blueprint = seal(CompanyOperatingBlueprint, operating_raw, "blueprint_digest")
    for field, path in (
        ("operating_blueprint.name", "intent.name"),
        ("operating_blueprint.country", "intent.country"),
        ("operating_blueprint.currency", "intent.currency"),
        ("operating_blueprint.operating_budget_per_period", "intent.operating_budget_per_period"),
    ):
        provenance.append(_row(field, path=path))

    # ---- growth --------------------------------------------------------- #
    growth_profile = str(profiles["growth"])
    profile_channels = _copy(GROWTH_ENGINE_PROFILES[growth_profile]["channels"])
    by_channel = {row["channel"]: row for row in profile_channels}
    growth_share = next((Decimal(str(binding["budget_share_percent"])) for binding in engines if binding["engine"] == "growth_engine"), Decimal(100))
    per_channel_cap = _q(declared.monthly_budget * growth_share / Decimal(100) / Decimal(len(declared.channels)))
    channel_rows: list[dict[str, Any]] = []
    for channel in declared.channels:
        known = by_channel.get(channel)
        if known is not None:
            channel_rows.append(known)
            continue
        row: dict[str, Any] = {"channel": channel, "monthly_budget_cap": str(per_channel_cap), "approval_threshold": str(_q(per_channel_cap / Decimal(2)))}
        if channel in PAID_CHANNELS:
            cpa = _nearest_cpa(profile_channels, per_channel_cap)
            if cpa is None:
                blockers.append({
                    "code": "PAID_CHANNEL_TARGET_MISSING",
                    "detail": f"{channel} is a paid channel the {growth_profile} profile does not carry, and no paid channel in that profile publishes a target CPA to borrow",
                    "resolves_by": "operator_input",
                    "platform_action": None,
                })
            else:
                row["target_cpa"] = cpa
        channel_rows.append(row)
    provenance.append(_row("growth_overrides.channels", path="intent.channels"))

    claims = _copy(GROWTH_ENGINE_PROFILES[growth_profile].get("approved_claims", []))
    licensed = any(item.status == "held" for item in declared.licences) and any(item.kind == "public_liability" and item.status == "bound" for item in declared.insurance)
    if not licensed and any(claim.get("claim_ref") == "claim-licensed" for claim in claims):
        claims = [claim for claim in claims if claim.get("claim_ref") != "claim-licensed"]
        findings.append("CLAIM_LICENSED_UNSUPPORTED: no licence is held and no public liability policy is bound, so the profile's 'licensed and insured' claim is withdrawn")
    growth_overrides: dict[str, Any] = {"channels": channel_rows, "approved_claims": claims, "currency": declared.currency}

    # ---- pipeline ------------------------------------------------------- #
    pipeline_profile = profiles["pipeline"]
    pipeline_overrides: dict[str, Any] = {}
    if pipeline_profile is not None:
        profile_raw = _copy(PIPELINE_ENGINE_PROFILES[pipeline_profile])
        profile_icp = profile_raw["icp"]
        icp_receipt = by_source.get("crm.icp_intelligence")
        gtm_receipt = by_source.get("gtm.go_to_market_plan")
        icp_facts = icp_receipt.facts if icp_receipt is not None else None
        gtm_facts = gtm_receipt.facts if gtm_receipt is not None else None
        missing: list[str] = []

        if icp_facts is not None and icp_facts.icp_industries:
            industries = list(icp_facts.icp_industries)
            provenance.append(_row("pipeline_overrides.icp", receipt=icp_receipt, path="analysis.icp_definition.industries"))
        elif gtm_facts is not None and gtm_facts.target_industry:
            industries = [gtm_facts.target_industry]
            provenance.append(_row("pipeline_overrides.icp", receipt=gtm_receipt, path="plan.target_market.industry"))
        else:
            industries = [declared.industry]
            provenance.append(_row("pipeline_overrides.icp", path="intent.industry"))

        observed_regions = set(icp_facts.icp_regions or ()) if icp_facts is not None else set()
        regions = sorted({declared.region_code[:2]} | observed_regions)
        provenance.append(_row("pipeline_overrides.icp", path="intent.region_code"))
        if observed_regions:
            provenance.append(_row("pipeline_overrides.icp", receipt=icp_receipt, path="analysis.icp_definition.regions"))

        if icp_facts is not None and icp_facts.icp_buyer_titles:
            buyer_titles = list(icp_facts.icp_buyer_titles)
            provenance.append(_row("pipeline_overrides.icp", receipt=icp_receipt, path="analysis.icp_definition.buyer_titles"))
        elif gtm_facts is not None and gtm_facts.target_persona:
            buyer_titles = [gtm_facts.target_persona]
            provenance.append(_row("pipeline_overrides.icp", receipt=gtm_receipt, path="plan.target_market.persona"))
        else:
            buyer_titles = list(profile_icp["buyer_titles"])
            missing.append("buyer_titles")
            provenance.append(_row("pipeline_overrides.icp", path=f"PIPELINE_ENGINE_PROFILES.{pipeline_profile}.icp.buyer_titles", confidence="fallback"))

        signals = list(icp_facts.icp_required_signals) if icp_facts is not None and icp_facts.icp_required_signals else list(profile_icp.get("required_signals", []))
        disqualifiers = list(icp_facts.icp_disqualifiers) if icp_facts is not None and icp_facts.icp_disqualifiers else list(profile_icp.get("disqualifiers", []))
        pipeline_overrides["icp"] = {
            "industries": industries[:40],
            "min_employees": int(profile_icp.get("min_employees", 1)),
            "max_employees": int(profile_icp.get("max_employees", 1_000_000)),
            "regions": regions[:40],
            "buyer_titles": buyer_titles[:40],
            "required_signals": signals[:20],
            "disqualifiers": disqualifiers[:20],
            "fit_threshold": int(profile_icp.get("fit_threshold", 60)),
        }
        if missing:
            blockers.append({
                "code": "ICP_INCOMPLETE",
                "detail": f"this archetype runs the pipeline engine but nothing proved {', '.join(missing)}; the profile default stands in",
                "resolves_by": "platform_run",
                "platform_action": "crm.icp_intelligence",
            })
        if declared.outreach_channels:
            available = {row["channel"] for row in profile_raw["channels"]}
            kept = {channel for channel in declared.outreach_channels if channel in available}
            sequences = _trimmed_sequences(profile_raw["sequences"], kept)
            # A sequence that cannot run is worse than a channel the operator did not name, so the
            # filter only applies when at least one of the profile's sequences survives it.
            if kept and sequences:
                pipeline_overrides["channels"] = [row for row in profile_raw["channels"] if row["channel"] in kept]
                pipeline_overrides["sequences"] = sequences
                running = kept
            else:
                running = available
            # Whichever way it lands, an operator who declared outreach channels is told when the
            # plan will not run exactly those; a silently substituted channel is not a plan they chose.
            if running != set(declared.outreach_channels):
                findings.append(
                    f"OUTREACH_CHANNELS_NOT_AS_DECLARED: the {pipeline_profile} profile will run {', '.join(sorted(running))}, "
                    f"not the declared {', '.join(declared.outreach_channels)}; it carries no runnable sequence for the rest"
                )

    if gtm_fallback := by_source.get("gtm.go_to_market_plan"):
        if gtm_fallback.facts.plan_source == "fallback":
            blockers.append({
                "code": "GTM_FALLBACK_PLAN",
                "detail": "the go-to-market run fell back to a template plan; nothing in it is evidence of this market",
                "resolves_by": "operator_input",
                "platform_action": "gtm.go_to_market_plan",
            })

    # ---- paper, licences, insurance ------------------------------------- #
    paper: list[dict[str, Any]] = []
    for requirement in declared.required_paper:
        action = PACKET_ACTIONS[requirement.kind]
        receipt = by_source.get(action)
        plan: dict[str, Any] = {"kind": requirement.kind, "counterparty_role": requirement.counterparty_role, "required_before": requirement.required_before, "requires_review": True, "status": "not_drafted"}
        if receipt is not None:
            plan.update({"status": "drafted", "packet_source": receipt.source})
            if receipt.facts.document_ref is not None:
                plan["document_ref"] = receipt.facts.document_ref
            if receipt.facts.content_sha256 is not None:
                plan["content_sha256"] = receipt.facts.content_sha256
            if requirement.kind == "incorporation":
                if receipt.facts.registrar is not None:
                    plan["registrar"] = receipt.facts.registrar
                if receipt.facts.filing_steps:
                    plan["filing_steps"] = list(receipt.facts.filing_steps)
            provenance.append(_row("required_paper", receipt=receipt, path="document_id"))
        elif requirement.required_before in _BLOCKING_BEFORE:
            blockers.append({
                "code": "PAPER_NOT_DRAFTED",
                "detail": f"{requirement.kind} is required before {requirement.required_before} and no packet run has drafted it",
                "resolves_by": "platform_run",
                "platform_action": action,
            })
        paper.append(plan)
    provenance.append(_row("required_paper", path="intent.required_paper"))

    for licence in declared.licences:
        if licence.required_before != "first_dollar" and licence.status != "held":
            blockers.append({
                "code": "LICENCE_NOT_HELD",
                "detail": f"{licence.kind} from {licence.authority} is required before {licence.required_before} and is {licence.status}",
                "resolves_by": "human_action",
                "platform_action": None,
            })
    provenance.append(_row("licences", path="intent.licences"))

    for policy in declared.insurance:
        if policy.required_before != "first_dollar" and policy.status != "bound":
            blockers.append({
                "code": "INSURANCE_NOT_BOUND",
                "detail": f"{policy.kind} cover is required before {policy.required_before} and is {policy.status}",
                "resolves_by": "human_action",
                "platform_action": None,
            })
    if declared.has_payroll and not any(policy.kind == "workers_compensation" for policy in declared.insurance):
        blockers.append({
            "code": "WORKERS_COMP_REQUIRED",
            "detail": "the intent declares payroll and no workers' compensation cover; a person must arrange it before the first hire",
            "resolves_by": "human_action",
            "platform_action": None,
        })
    provenance.append(_row("insurance", path="intent.insurance"))

    committed = _q(declared.operating_budget_per_period * Decimal(30) / Decimal(declared.period_days) * Decimal(runway_months))
    if committed > declared.starting_cash:
        blockers.append({
            "code": "BUDGET_EXCEEDS_CASH",
            "detail": f"{committed} of operating budget over the {runway_months} month runway exceeds the declared starting cash of {declared.starting_cash}",
            "resolves_by": "operator_input",
            "platform_action": None,
        })

    for suggestion in unconfirmed_requirements(declared):
        threshold = f" (applies above {GST_THRESHOLDS[declared.country]})" if suggestion.condition == "revenue_over_gst_threshold" else ""
        blockers.append({
            "code": "REQUIREMENT_SUGGESTION_UNCONFIRMED",
            "detail": f"{suggestion.name} ({suggestion.authority}) is a usual {suggestion.kind} in {declared.region_code}{threshold}; declare it or dismiss it. This is not legal advice.",
            "resolves_by": "operator_input",
            "platform_action": None,
        })

    # ---- offers, evidence, findings -------------------------------------- #
    provenance.append(_row("offers", path="intent.offers"))
    if price_evidence:
        # The evidence names the run it came from; the prices stay the operator's.  This row is
        # deliberately NOT filed against `offers`: a declared price citing an agent run is a lie,
        # and the hard rule is that no agent output is ever promoted into one.
        provenance.append(_row("price_evidence", receipt=pricing, path="discrepancies[].prices[]"))
    spreads: dict[str, tuple[Decimal, Decimal]] = {}
    for observed in price_evidence:
        low, high = spreads.get(observed.subject.casefold(), (observed.min_price, observed.max_price))
        spreads[observed.subject.casefold()] = (min(low, observed.min_price), max(high, observed.max_price))
    for offer in declared.offers:
        spread = spreads.get(offer.name.casefold())
        if spread is not None and not (spread[0] <= offer.price <= spread[1]):
            findings.append(f"PRICE_OUTSIDE_EVIDENCE: {offer.name} is priced {offer.price}, outside the observed {spread[0]}-{spread[1]}")
    if incorporation is not None:
        findings.append("INCORPORATION_GUIDE_ONLY: the incorporation package is a guide the operator lodges themselves; the platform files nothing")
    if declared.archetype not in STANDARD_ROSTERS:
        findings.append(f"NO_STANDARD_ROSTER: {declared.archetype} has no standard agent roster; pass one to to_cadence_bundle or run without a workforce plan")

    # ---- obligations ------------------------------------------------------ #
    if monthly_revenue is None:
        monthly_revenue = _q(revenue * Decimal(30) / Decimal(declared.period_days))
    calendar = compile_compliance_calendar(
        "blueprint",
        jurisdiction=declared.country,
        currency=declared.currency,
        start_at=when,
        horizon_months=12,
        estimated_revenue_per_month=str(monthly_revenue),
        estimated_payroll_per_month="0",
        has_payroll=declared.has_payroll,
        registered_for_gst=declared.registered_for_gst,
    )

    payload: dict[str, Any] = {
        "intent_digest": declared.intent_digest,
        "intake_digest": sealed_intake.intake_digest if sealed_intake is not None else None,
        "compiled_at": when,
        "archetype": declared.archetype,
        "country": declared.country,
        "region": declared.region,
        "region_code": declared.region_code,
        "currency": declared.currency,
        "operating_blueprint": operating_blueprint.to_dict(),
        "growth_profile": growth_profile,
        "growth_overrides": growth_overrides,
        "pipeline_profile": pipeline_profile,
        "pipeline_overrides": pipeline_overrides,
        "service_delivery_profile": profiles["service_delivery"],
        "finance_close_profile": str(profiles["finance_close"]),
        "saas_profile": profiles["saas"],
        "offers": [offer.to_dict() for offer in declared.offers],
        "price_evidence": [observed.to_dict() for observed in price_evidence],
        "required_paper": paper,
        "licences": [item.to_dict() for item in declared.licences],
        "insurance": [item.to_dict() for item in declared.insurance],
        "compliance_plan_digest": calendar.plan_digest,
        "obligation_kinds": sorted({row.kind for row in calendar.schedule}),
        "formation_preview": {"name": declared.name, "country": declared.country, "industry": declared.industry, "purpose": declared.purpose},
        "provenance": provenance[:MAX_PROVENANCE_ROWS],
        "blockers": _within_cap(blockers),
        "findings": [_finding(item) for item in findings[:MAX_FINDINGS]],
        "ready_to_plan": not blockers,
    }
    return seal(LaunchBlueprint, payload, "blueprint_digest")


# --------------------------------------------------------------------------- #
# The bundle
# --------------------------------------------------------------------------- #


def to_cadence_bundle(
    blueprint: LaunchBlueprint,
    *,
    company_ref: str,
    scope: Mapping[str, str],
    actor_ref: str,
    start_at: str,
    roster: Any = None,
    ledger_ref: str = "ledger",
    preparer_ref: str | None = None,
) -> CadenceBundle:
    """Turn a blueprint with no blockers into the bundle the cadence runner and the engines already run on."""

    _require(
        not blueprint.blockers,
        "BLUEPRINT_NOT_READY",
        f"the blueprint carries {len(blueprint.blockers)} blockers ({', '.join(sorted(set(blueprint.blocker_codes)))}); resolve them before planning",
    )
    operating_plan = compile_company_operating_blueprint(blueprint.operating_blueprint)
    currency = blueprint.operating_blueprint.currency
    period_days = blueprint.operating_blueprint.period_days

    bundle: dict[str, Any] = {
        "company_ref": company_ref,
        "scope": dict(scope),
        "actor_ref": actor_ref,
        "operating_plan": operating_plan.to_dict(),
        "growth_plan": compile_growth_engine_blueprint(blueprint.growth_profile, {**blueprint.growth_overrides, "require_permission_register": True, "permission_company_ref": company_ref, "claim_jurisdiction": blueprint.country, "claim_product_ref": company_ref, "require_demand_registry": True}).to_dict(),
        "finance_close_plan": compile_finance_close_blueprint(blueprint.finance_close_profile, {"currency": currency, "period_days": period_days}).to_dict(),
        "ledger_ref": ledger_ref,
        "start_at": start_at,
    }
    if blueprint.pipeline_profile is not None:
        bundle["pipeline_plan"] = compile_pipeline_engine_blueprint(blueprint.pipeline_profile, {**blueprint.pipeline_overrides, "currency": currency, "require_permission_register": True, "permission_company_ref": company_ref}).to_dict()
    if blueprint.service_delivery_profile is not None:
        bundle["service_delivery_plan"] = compile_service_delivery_blueprint(blueprint.service_delivery_profile, {"currency": currency, "company_ref": company_ref}).to_dict()
    if blueprint.saas_profile is not None:
        bundle["saas_plan"] = compile_saas_operating_blueprint(blueprint.saas_profile, {"currency": currency}).to_dict()
    if preparer_ref is not None:
        bundle["preparer_ref"] = preparer_ref

    if roster is not None:
        bundle["workforce_plan"] = compile_workforce(operating_plan, roster).to_dict()
    elif blueprint.archetype in STANDARD_ROSTERS:
        bundle["workforce_plan"] = compile_workforce(operating_plan, standard_roster(blueprint.archetype)).to_dict()
    return complete_company_bundle_plans(bundle)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _cite(row: FieldProvenance) -> str:
    if row.source == "operator":
        return f"operator{f' ({row.path})' if row.path else ''}"
    trace = f" {row.trace_ref}" if row.trace_ref else ""
    path = f" path {row.path}" if row.path else ""
    marker = " [fallback]" if row.confidence == "fallback" else ""
    return f"{row.source}{trace}{path}{marker}"


def render_blueprint(blueprint: LaunchBlueprint) -> str:
    """Markdown: one line per compiled field with its provenance, then the blockers and findings."""

    bp = blueprint.operating_blueprint
    lines = [
        f"# Launch blueprint: {bp.name}",
        f"{blueprint.archetype} in {blueprint.region} ({blueprint.region_code}), {blueprint.currency}; "
        f"{'ready to plan' if blueprint.ready_to_plan else f'{len(blueprint.blockers)} blockers'}",
        "",
        "## Compiled fields",
    ]
    labels = {
        "operating_blueprint.name": bp.name,
        "operating_blueprint.country": bp.country,
        "operating_blueprint.currency": bp.currency,
        "operating_blueprint.operating_budget_per_period": f"{blueprint.currency} {bp.operating_budget_per_period}/period ({bp.period_days}d)",
        "operating_blueprint.targets.revenue_per_period": f"revenue target {blueprint.currency} {bp.targets.revenue_per_period}/period",
        "operating_blueprint.targets.gross_margin_percent": f"gross margin {bp.targets.gross_margin_percent}%",
        "growth_overrides.channels": ", ".join(str(row["channel"]) for row in blueprint.growth_overrides.get("channels", ())),
        "required_paper": ", ".join(f"{item.kind} ({item.status})" for item in blueprint.required_paper) or "none",
        "licences": ", ".join(f"{item.kind} ({item.status})" for item in blueprint.licences) or "none",
        "insurance": ", ".join(f"{item.kind} ({item.status})" for item in blueprint.insurance) or "none",
        "pipeline_overrides.icp": ", ".join(str(value) for value in blueprint.pipeline_overrides.get("icp", {}).get("industries", ())),
        "price_evidence": f"{len(blueprint.price_evidence)} observed price spreads (evidence only; no offer is priced from them)",
    }
    seen: set[str] = set()
    valued: set[str] = set()
    for row in blueprint.provenance:
        if row.field == "offers":
            continue
        key = f"{row.field}|{_cite(row)}"
        if key in seen:
            continue
        seen.add(key)
        # A field assembled from several runs prints its value once.  Repeating it beside every
        # citation would read as if each run had produced the whole thing, which is the one thing
        # this render exists to prevent; the later rows show only what each run contributed.
        value = "" if row.field in valued else labels.get(row.field, "")
        valued.add(row.field)
        lines.append(f"- {row.field}{f': {value}' if value else ''} <- {_cite(row)}")
    for offer in blueprint.offers:
        spread = [item for item in blueprint.price_evidence if item.subject.casefold() == offer.name.casefold()]
        evidence = f"; evidence: {len(spread)} observed prices {min(item.min_price for item in spread)}-{max(item.max_price for item in spread)}" if spread else ""
        lines.append(f"- offer {offer.name} {blueprint.currency} {offer.price}/{offer.unit} <- operator{evidence}")

    if blueprint.blockers:
        lines += ["", "## Blockers"]
        for resolver in ("operator_input", "platform_run", "human_action"):
            rows = [item for item in blueprint.blockers if item.resolves_by == resolver]
            if not rows:
                continue
            lines.append(f"### {resolver}")
            for item in rows:
                action = f" [{item.platform_action}]" if item.platform_action else ""
                lines.append(f"- {item.code}{action}: {item.detail}")
    if blueprint.findings:
        lines += ["", "## Findings"] + [f"- {item}" for item in blueprint.findings]
    return "\n".join(lines)


LAUNCH_BLUEPRINT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "launch_blueprint",
    "golden_loop": LAUNCH_GOLDEN_LOOP,
    "stages": ["declare_intent", "seal_intake", "derive_with_provenance", "find_blockers", "seal", "compile_bundle"],
    "archetype_profiles": {name: dict(profile) for name, profile in ARCHETYPE_PROFILES.items()},
    "provenanced_fields": list(PROVENANCED_FIELDS),
    "required_connectors": ["lightbulb.domain_agents", "lightbulb.workflow_instances"],
    "hard_rules": [
        "every compiled number names the run it came from or the operator who declared it",
        "the operator declares price, archetype, licences and insurance; no agent output is promoted to any of them",
        "requirement defaults are suggestions the operator confirms or dismisses; they are not legal advice",
        "a blueprint with blockers compiles but cannot become a bundle",
        "nothing here forms, dispatches, or spends",
    ],
}


__all__ = [
    "ARCHETYPE_PROFILES",
    "BLUEPRINT_SCHEMA",
    "CHANNEL_ALIASES",
    "CITY_JURISDICTIONS",
    "COUNTRY_CURRENCY",
    "GST_THRESHOLDS",
    "INTENT_SCHEMA",
    "LAUNCH_BLUEPRINT_MANIFEST",
    "LAUNCH_GOLDEN_LOOP",
    "MAX_RUN_AGE_DAYS",
    "PACKET_ACTIONS",
    "PROVENANCED_FIELDS",
    "REQUIREMENT_DEFAULTS",
    "TRADE_ARCHETYPES",
    "Blocker",
    "BlueprintCompileError",
    "FieldProvenance",
    "InsuranceRequirement",
    "LaunchBlueprint",
    "LicenceRequirement",
    "Offer",
    "OperatorIntent",
    "PaperPlan",
    "PaperRequirement",
    "PriceEvidence",
    "RegionCode",
    "SuggestedRequirement",
    "build_intent",
    "compile_launch_blueprint",
    "draft_intent",
    "render_blueprint",
    "suggest_requirements",
    "to_cadence_bundle",
    "unconfirmed_requirements",
]
