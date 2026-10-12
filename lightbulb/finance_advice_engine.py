"""Advice engine: a client's state, a licensed adviser, and the product that fits, with every hop evidenced.

The general shape of an advice business: a client discloses a *state*, an adviser reasons over a
universe of regulated providers, and a product, policy or plan is recommended and implemented.
This engine holds that loop for any vertical the catalog knows (retail banking, credit, insurance,
investments, superannuation, payments, and by the same formula any consulting domain with a
provider universe) and refuses the hops that get advice businesses into trouble:

* a recommendation is never made outside the authority the plan holds for that vertical, and a
  business without one runs in ``general_information`` mode, which compares facts and recommends
  nothing;
* nothing is ranked on a price the catalog cannot support with a source, and a catalog older than
  the plan allows or a capped register sample is disclosed, never hidden;
* the client's personal data never enters the SDK; the state carries a commitment to it and only
  the structured decision facts (amounts, bands, residency, preferences) travel in clear;
* the adviser who approves is a person with an authority the plan names, is not the client, and
  approves exactly the recommendation that was prepared; presentation follows approval and
  implementation follows presentation.

The SDK reads nothing and writes nothing. Catalogs arrive from ``finance_advice_catalog``; the record of
advice, the client acknowledgement and the application are platform artifacts that arrive here
as digests.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import engine_eligible
from lightbulb.finance_advice_catalog import (
    Completeness,
    Confidence,
    PricingFact,
    Product,
    ProductCatalog,
    VerticalRegistry,
    load_vertical_registry,
)
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel

ADVICE_KIND = "lightbulb.finance_advice_engine"
ADVICE_PLAN_SCHEMA = "lightbulb.finance_advice_plan.v1"
CLIENT_STATE_SCHEMA = "lightbulb.finance_advice_client_state.v1"
SHORTLIST_SCHEMA = "lightbulb.finance_advice_shortlist.v1"
RECOMMENDATION_SCHEMA = "lightbulb.finance_advice_recommendation.v1"
COMPARISON_SCHEMA = "lightbulb.finance_advice_comparison.v1"
MAX_CASE_TRANSITIONS = 40
MAX_SHORTLIST = 50

AdviceMode = Literal["personal_recommendation", "general_information"]
AuthorityKind = Literal[
    "afs_licence",
    "australian_credit_licence",
    "provincial_mortgage_broker_licence",
    "provincial_insurance_licence",
    "provincial_securities_registration",
    "provincial_credit_licence",
    "provincial_deposit_advice_registration",
    "fintrac_msb_registration",
]
from lightbulb.finance_advice_projection import project_cost

Residency = Literal["citizen", "permanent_resident", "temporary_resident", "non_resident", "unstated"]
Direction = Literal["lower_is_better", "higher_is_better"]
SuitabilityOutcome = Literal["eligible", "ineligible", "unassessed"]
RecommendationBasis = Literal["ranked_on_supported_pricing", "adviser_judgement"]

_CONFIDENCE_ORDER = {"unverified": 0, "single_source": 1, "verified": 2}
_PII_KEYS = frozenset({"name", "first_name", "last_name", "full_name", "email", "phone", "mobile", "address", "street", "date_of_birth", "dob", "tax_file_number", "tfn", "sin", "social_insurance_number", "passport", "drivers_licence", "account_number", "iban"})
_NUMBER = re.compile(r"-?[0-9][0-9,]*(?:\.[0-9]+)?")
_STANDARD_DISCLOSURES = (
    "This shortlist is prepared from a sourced product catalog; the adviser's own assessment of the client's circumstances governs.",
    "Product pricing is point-in-time as retrieved from the provider and changes without notice; confirm current terms before implementation.",
)


class AdviceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceError(code, message)


def parse_money(value: Any) -> Decimal | None:
    """The first number in a stated amount (``"AUD 250,000"``, ``250000``, ``{"value": ...}``)."""

    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, Mapping):
        return parse_money(value.get("value") if "value" in value else value.get("minimum", value.get("amount")))
    if isinstance(value, (list, tuple)):
        parsed_values = [parse_money(item) for item in value]
        parsed_values = [item for item in parsed_values if item is not None]
        return min(parsed_values) if parsed_values else None
    match = _NUMBER.search(str(value))
    if match is None:
        return None
    try:
        return Decimal(match.group(0).replace(",", ""))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# The plan: what this advice business is authorised to do, and how it ranks
# --------------------------------------------------------------------------- #


class Authority(StrictModel):
    """A licence or registration the business holds, as commitments; the number itself never enters the SDK."""

    kind: AuthorityKind
    holder_ref: OpaqueRef
    authority_ref_sha256: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    scope_verticals: tuple[str, ...] = Field(default_factory=tuple, min_length=1)
    verified_at: str
    expires_at: str | None = None

    @field_validator("scope_verticals", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("verified_at", "expires_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class RankingWeight(StrictModel):
    decision_field: ShortText
    pricing_items: tuple[str, ...] = Field(min_length=1)
    direction: Direction = "lower_is_better"
    weight: Decimal = Field(gt=0, le=1)

    @field_validator("pricing_items", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("weight", mode="before")
    @classmethod
    def _weight(cls, value: Any) -> Decimal:
        return Decimal(str(value))


class AdvicePlan(StrictModel):
    schema_id: str = Field(default=ADVICE_PLAN_SCHEMA, alias="schema")
    business_ref: OpaqueRef
    jurisdiction: Literal["AU", "CA"]
    mode: AdviceMode
    verticals: tuple[str, ...] = Field(min_length=1)
    authorities: tuple[Authority, ...] = Field(default_factory=tuple)
    ranking: tuple[RankingWeight, ...] = Field(default_factory=tuple)
    max_catalog_age_days: int = Field(default=45, ge=1, le=365)
    minimum_confidence: Confidence = "single_source"
    include_unclassified: bool = False
    remuneration_disclosure: BoundedText
    require_adviser_approval: Literal[True] = True
    review_after_days: int = Field(default=365, ge=30, le=1095)
    project_costs: bool = False
    projection_horizon_years: int | None = Field(default=None, ge=1, le=40)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("verticals", "authorities", "ranking", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> AdvicePlan:
        if len(set(self.verticals)) != len(self.verticals):
            raise ValueError("verticals must be unique")
        total = sum((item.weight for item in self.ranking), Decimal("0"))
        if self.ranking and abs(total - Decimal("1")) > Decimal("0.0001"):
            raise ValueError("ranking weights must sum to 1")
        for authority in self.authorities:
            if authority.jurisdiction != self.jurisdiction:
                raise ValueError("an authority belongs to the plan's jurisdiction")
        if not skip_digests(info) and self.plan_digest != sealed_digest(AdvicePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def authority_for(self, vertical_id: str, kind: str) -> Authority | None:
        for authority in self.authorities:
            if authority.kind == kind and vertical_id in authority.scope_verticals:
                return authority
        return None


_DEFAULT_RANKING: dict[str, tuple[RankingWeight, ...]] = {
    "credit": (
        RankingWeight(decision_field="cost of credit", pricing_items=("comparison rate", "revert comparison rate", "interest/comparison rate", "APR", "current_apr", "posted_apr", "annual percentage rate", "revert variable rate", "revert rate", "revert interest rate", "interest rate", "interest_rate", "current_interest_rate", "variable interest rate", "Mortgage interest rate", "mortgage_interest_rate", "mortgage interest rate", "purchase interest rate", "purchase rate"), direction="lower_is_better", weight=Decimal("0.7")),
        RankingWeight(decision_field="ongoing fees", pricing_items=("monthly fee", "annual fee", "annual package fee", "monthly account fee"), direction="lower_is_better", weight=Decimal("0.3")),
    ),
    "deposits": (
        RankingWeight(decision_field="return", pricing_items=("interest rate", "base interest rate", "bonus interest rate", "total interest rate"), direction="higher_is_better", weight=Decimal("0.6")),
        RankingWeight(decision_field="ongoing fees", pricing_items=("monthly fee", "monthly account fee", "annual fee"), direction="lower_is_better", weight=Decimal("0.4")),
    ),
    "insurance": (
        RankingWeight(decision_field="premium", pricing_items=("premium", "annual premium", "monthly premium", "base premium", "indicative premium", "premium per month", "premium per year", "premium rate"), direction="lower_is_better", weight=Decimal("0.6")),
        RankingWeight(decision_field="excess", pricing_items=("excess", "standard excess", "basic excess", "deductible"), direction="lower_is_better", weight=Decimal("0.2")),
        RankingWeight(decision_field="cover", pricing_items=("maximum cover", "maximum sum insured", "sum insured maximum", "cover limit"), direction="higher_is_better", weight=Decimal("0.2")),
    ),
    "investments": (
        RankingWeight(decision_field="ongoing cost", pricing_items=("management fee", "MER", "management expense ratio", "indirect cost ratio", "total fees and costs", "administration fee", "account fee", "annual fee"), direction="lower_is_better", weight=Decimal("0.6")),
        RankingWeight(decision_field="transaction cost", pricing_items=("buy/sell spread", "buy-sell spread", "brokerage", "trading fee", "trading commission", "switching fee"), direction="lower_is_better", weight=Decimal("0.4")),
    ),
}

SectorFamily = Literal["credit", "deposits", "insurance", "investments"]


def sector_family(sector: str) -> SectorFamily:
    """Which ranking and suitability family a roadmap sector belongs to; credit is the conservative default."""

    lower = sector.lower()
    if "insurance" in lower or "funeral" in lower or "annuit" in lower:
        return "insurance"
    if any(word in lower for word in ("investment", "retirement", "superannuation", "registered", "brokerage")):
        return "investments"
    if "deposit" in lower or "saving" in lower or "banking" in lower:
        return "deposits"
    return "credit"


def default_ranking(sector: str) -> tuple[RankingWeight, ...]:
    return _DEFAULT_RANKING[sector_family(sector)]


def compile_advice_plan(business_ref: str, *, jurisdiction: str, mode: str, verticals: Sequence[str], authorities: Sequence[Mapping[str, Any] | Authority] = (), ranking: Sequence[Mapping[str, Any] | RankingWeight] | None = None, remuneration_disclosure: str, overrides: Mapping[str, Any] | None = None, registry: VerticalRegistry | None = None) -> AdvicePlan:
    """A plan is compiled against the vertical registry: a personal recommendation needs the authority each vertical requires."""

    registry = registry or load_vertical_registry()
    parsed_authorities = tuple(item if isinstance(item, Authority) else Authority.model_validate(dict(detached(item))) for item in authorities)
    for vertical_id in verticals:
        vertical = registry.vertical(vertical_id)
        _require(vertical.jurisdiction == jurisdiction, "VERTICAL_JURISDICTION_MISMATCH", f"{vertical_id} is a {vertical.jurisdiction} vertical")
        if mode == "personal_recommendation":
            required = vertical.authority_for_recommendation
            held = any(item.kind == required and vertical_id in item.scope_verticals for item in parsed_authorities)
            _require(held, "SCOPE_UNLICENSED", f"a personal recommendation in {vertical_id} ({vertical.name}) requires {required}; run general_information or add the authority")
    if ranking is None:
        first = registry.vertical(verticals[0])
        ranking = default_ranking(first.sector)
    payload: dict[str, Any] = {"business_ref": business_ref, "jurisdiction": jurisdiction, "mode": mode, "verticals": list(verticals), "authorities": [item.to_dict() for item in parsed_authorities], "ranking": [item.to_dict() if isinstance(item, RankingWeight) else dict(item) for item in ranking], "remuneration_disclosure": remuneration_disclosure}
    payload.update(dict(overrides or {}))
    return seal(AdvicePlan, payload, "plan_digest")


# --------------------------------------------------------------------------- #
# The client's state: decision facts in clear, personal data as a commitment
# --------------------------------------------------------------------------- #


class ClientState(StrictModel):
    schema_id: str = Field(default=CLIENT_STATE_SCHEMA, alias="schema")
    client_ref: OpaqueRef
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str
    objective: BoundedText
    amount: Decimal | None = Field(default=None, ge=0)
    lvr_percent: Decimal | None = Field(default=None, ge=0, le=100)
    term_years: int | None = Field(default=None, ge=1, le=50)
    residency: Residency = "unstated"
    age_band: str | None = None
    income_band: str | None = None
    purpose: str | None = None
    region: str | None = None
    preferences: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    facts: dict[str, Any] = Field(default_factory=dict)
    personal_data_sha256: Sha256Digest
    fact_find_complete: bool = False
    disclosed_at: str
    state_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="before")
    @classmethod
    def _identity_keys(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and isinstance(value.get("facts"), Mapping):
            if any(str(key).lower() in _PII_KEYS for key in value["facts"]):
                raise ValueError("FACT_PII_FORBIDDEN: the state carries decision facts and identity commitments only")
        return value

    @field_validator("amount", "lvr_percent", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value))

    @field_validator("preferences", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("disclosed_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="disclosed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ClientState:
        for key in self.facts:
            if key.lower() in _PII_KEYS:
                raise ValueError(f"FACT_PII_FORBIDDEN: {key} is personal data; the state carries only its commitment")
        if not skip_digests(info) and self.state_digest != sealed_digest(ClientState, self, "state_digest"):
            raise ValueError("state_digest must commit the exact state")
        return self


def client_state(client_ref: str, *, jurisdiction: str, vertical_id: str, objective: str, personal_data_sha256: str, disclosed_at: str, fact_find_complete: bool = False, **facts: Any) -> ClientState:
    payload: dict[str, Any] = {"client_ref": client_ref, "jurisdiction": jurisdiction, "vertical_id": vertical_id, "objective": objective, "personal_data_sha256": personal_data_sha256, "disclosed_at": disclosed_at, "fact_find_complete": fact_find_complete}
    known = {"amount", "lvr_percent", "term_years", "residency", "age_band", "income_band", "purpose", "region", "preferences", "facts"}
    for key, value in facts.items():
        if key in known:
            payload[key] = value
        else:
            payload.setdefault("facts", {})[key] = value
    return seal(ClientState, payload, "state_digest")


# --------------------------------------------------------------------------- #
# Suitability: structured checks where the catalog states structure, otherwise unassessed
# --------------------------------------------------------------------------- #


class SuitabilityVerdict(StrictModel):
    product_ref: OpaqueRef
    outcome: SuitabilityOutcome
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    checked_terms: tuple[str, ...] = Field(default_factory=tuple)
    restrictions: tuple[str, ...] = Field(default_factory=tuple)
    unconfirmed: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("reasons", "checked_terms", "restrictions", "unconfirmed", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


_MIN_AMOUNT_TERMS = ("minimum loan amount", "minimum new loan amount", "minimum_loan_amount", "minimum amount", "minimum credit limit", "minimum opening deposit", "minimum investment", "minimum initial investment", "minimum opening balance", "minimum contribution", "minimum sum insured", "minimum cover", "opening minimum")
_MAX_AMOUNT_TERMS = ("maximum loan amount", "maximum_loan_amount", "maximum amount", "maximum credit limit", "maximum investment", "maximum sum insured", "maximum cover", "maximum contribution")
_MIN_AGE_TERMS = ("minimum entry age", "minimum age", "entry age minimum", "minimum issue age", "issue age minimum", "minimum age at entry")
_MAX_AGE_TERMS = ("maximum entry age", "maximum age", "entry age maximum", "maximum issue age", "issue age maximum", "maximum age at entry")
_RISK_TERMS = ("standard risk measure", "risk band", "risk level", "risk rating", "risk_rating", "srm", "risk label")
_HORIZON_TERMS = ("minimum suggested timeframe", "minimum investment timeframe", "suggested minimum investment period", "minimum investment horizon", "investment horizon", "suggested investment timeframe", "minimum suggested investment timeframe")
_RISK_LABELS = {"very low": 1, "low": 2, "low to medium": 3, "medium": 4, "medium to high": 5, "high": 6, "very high": 7}
_RISK_PROFILE_MAX = {"conservative": 3, "cautious": 3, "moderate": 4, "moderately conservative": 4, "balanced": 5, "moderately aggressive": 6, "growth": 6, "high_growth": 7, "high growth": 7, "aggressive": 7}


def age_bounds(state: "ClientState") -> tuple[int | None, int | None]:
    """The client's age as a band: an exact age fact, else the state's age band such as 35-44, 65+ or under 18."""

    exact = state.facts.get("age")
    if isinstance(exact, int) and not isinstance(exact, bool) and 0 < exact < 130:
        return exact, exact
    band = (state.age_band or "").strip().lower().replace("–", "-")
    if not band:
        return None, None
    match = re.match(r"^(\d{1,3})\s*-\s*(\d{1,3})$", band)
    if match:
        return int(match.group(1)), int(match.group(2))
    match = re.match(r"^(\d{1,3})\s*\+$", band) or re.match(r"^(\d{1,3})\s*(?:and|or) (?:over|older|above)$", band)
    if match:
        return int(match.group(1)), None
    match = re.match(r"^under\s*(\d{1,3})$", band) or re.match(r"^<\s*(\d{1,3})$", band)
    if match:
        return None, int(match.group(1)) - 1
    return None, None


def risk_score(value: Any) -> int | None:
    """A product's stated risk on the 1..7 scale: a number as stated, or a label such as 'high'."""

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        number = int(value)
        return number if 1 <= number <= 7 else None
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in _RISK_LABELS:
        return _RISK_LABELS[text]
    match = re.search(r"\b([1-7])\b", text)
    if match:
        return int(match.group(1))
    for label, score in sorted(_RISK_LABELS.items(), key=lambda item: -len(item[0])):
        if label in text:
            return score
    return None


def _age_from_prose(statement: str) -> tuple[int | None, int | None]:
    lower = statement.lower().replace("–", "-")
    if not any(word in lower for word in ("age", "aged", "years", "turn", "older", "under", "younger", "over", "+")):
        return None, None
    match = re.search(r"\b(?:aged?|ages|between)\s*(\d{1,2})\s*(?:to|-|and)\s*(\d{1,2})\b", lower)
    if match:
        return int(match.group(1)), int(match.group(2))
    low = None
    high = None
    match = re.search(r"\b(?:aged?\s*)?(\d{1,2})\s*(?:years?\s*)?(?:or|and)\s*(?:under|younger|below)\b", lower)
    if match:
        high = int(match.group(1))
    match = re.search(r"\bover\s*(\d{2})s?\b|\b(\d{2})\s*\+|\baged\s*(\d{2})\s*plus\b", lower)
    if match and low is None:
        low = int(next(group for group in match.groups() if group))
    match = re.search(r"\b(\d{2})\s*years?\s*(?:of age\s*)?(?:or|and)\s*(?:older|over|above)\b|\bat least\s*(\d{2})\s*years\b|\baged\s*(\d{2})\s*(?:or|and)\s*(?:over|older)\b|\bminimum (?:entry |issue )?age (?:of |is )?(\d{2})\b", lower)
    if match:
        low = int(next(group for group in match.groups() if group))
    match = re.search(r"\bunder (?:the age of )?(\d{2})\b|\bup to (?:the )?age (?:of )?(\d{2})\b|\byear (?:you|they|the member) turns? (\d{2})\b|\bbefore (?:you|they) turn (\d{2})\b|\bmaximum (?:entry |issue )?age (?:of |is )?(\d{2})\b|\bup to age (\d{2})\b", lower)
    if match:
        high = int(next(group for group in match.groups() if group))
        if "year" in lower and "turn" in lower and "before" not in lower:
            high = high  # contributions allowed through the year the client turns this age
    return low, high
_MAX_LVR_TERMS = ("maximum LVR", "maximum LVR shown", "maximum_lvr", "maximum ltv", "maximum LTV")
_MAX_TERM_TERMS = ("maximum loan term", "loan term", "maximum_amortization_years", "term_years")
# In Canada a mortgage "term" is the rate-commitment period (1-10 years); the loan life is the amortization,
# which is what the client's term_years states there. A Canadian term never bounds the client's loan life.
_CONTRACT_TERM_NAMES = frozenset({"term_years", "term_years_range", "terms_years", "term_months", "term_options_years", "term_options_months"})
_CONTRACT_TERM_JURISDICTIONS = frozenset({"CA"})

# Prose eligibility the fact find can settle. A hard restriction the state does not confirm keeps the
# product unranked (it stays on the list, unassessed); a joinable condition is recorded and leaves ranking alone.
RestrictionKind = Literal["hard", "condition"]

_RESTRICTIONS: tuple[tuple[str, RestrictionKind, tuple[str, ...]], ...] = (
    ("investment_only", "hard", ("investment lending only", "investment purposes only", "investment properties only", "investment property only", "investors only", "investor only", "for investment only", "for investors", "first-time investor", "first time investor", "investors who", "residential investment", "investment lending")),
    ("owner_occupied_only", "hard", ("owner occupied only", "owner-occupied only", "owner occupiers only", "owner-occupiers only", "principal place of residence only", "must live in the property", "must occupy the property")),
    ("first_home_buyer", "hard", ("first home", "first-home", "first-time home buyer", "first-time homebuyer", "first time home buyer", "first-time buyer", "first time buyer")),
    ("pensioner_or_concession", "hard", ("age pension", "aged pension", "pensioner", "pension card", "concession card", "seniors card", "seniors health card", "self-funded retiree", "self funded retiree", "superannuation pension", "disability support pension", "receive a pension", "in receipt of a pension", "mature age allowance", "retirees only", "for retirees")),
    ("youth_or_student", "hard", ("full-time student", "full time student", "students only", "for students", "student account", "apprentice", "trainee", "for kids", "for children", "youth account", "young people", "under 18s", "under-18s")),
    ("construction", "hard", ("construction loan only", "construction purposes only", "building a new home", "land and construction", "construction of a")),
    ("refinance_only", "hard", ("refinance only", "refinancing only", "refinances only", "available only when refinancing")),
    ("energy_efficient_property", "hard", ("energy efficient", "energy-efficient", "green home", "nathers", "green building", "sustainable home", "climate active", "energy rating")),
    ("affinity_group", "hard", ("defence force", "australian defence force", "adf member", "dhoas", "defence home ownership", "employees of", "employee of", "police officer", "police force", "union member", "members of the union", "medical practitioner", "health professional", "teachers", "veteran", "serving member", "reservist", "essential worker", "key worker", "frontline", "emergency services", "nurses", "nurse", "paramedic", "firefighter", "first responder")),
    ("wholesale_investor_only", "hard", ("wholesale clients only", "wholesale client only", "wholesale investors only", "sophisticated investors only", "accredited investors only", "available to wholesale clients", "wholesale clients as defined")),
    ("non_smoker_only", "hard", ("non-smokers only", "non smokers only", "non-smoker rates only", "available to non-smokers only")),
    ("occupation_class", "condition", ("occupation class", "occupation category", "eligible occupations", "occupation rating")),
    ("pre_existing_conditions", "condition", ("pre-existing condition", "pre-existing medical", "pre existing condition")),
    ("membership", "condition", ("membership", "must be a member", "become a member", "members only", "member of the", "shareholder")),
    ("new_customers_only", "condition", ("new customers only", "new to bank", "new lending only", "new borrowings only", "new home loan customers")),
)

# The taxonomy class states purpose and segment as structure; a class-derived tag is settled like the prose tag.
_CLASS_RESTRICTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("investment_only", ("investment", "rental_property")),
    ("pensioner_or_concession", ("pensioner", "concession", "senior", "retiree")),
    ("youth_or_student", ("youth", "student", "kids", "children", "junior")),
)
_REFINANCE_TRANSACTIONS = frozenset({"refinance", "refinancing", "top_up", "top-up", "increase", "switch"})
_PENSION_WORDS = ("pension", "pensioner", "concession", "senior", "retiree", "retired")
_AGE_PENSION_FLOOR = 55

_REGIONS: dict[str, str] = {
    "new south wales": "NSW", "victoria": "VIC", "queensland": "QLD", "south australia": "SA", "western australia": "WA", "tasmania": "TAS", "australian capital territory": "ACT", "northern territory": "NT",
    "alberta": "AB", "british columbia": "BC", "manitoba": "MB", "new brunswick": "NB", "newfoundland and labrador": "NL", "nova scotia": "NS", "ontario": "ON", "prince edward island": "PE", "quebec": "QC", "québec": "QC", "saskatchewan": "SK", "yukon": "YT", "northwest territories": "NT", "nunavut": "NU",
}
_REGION_CODES = {code for code in _REGIONS.values()}


def region_code(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.upper() in _REGION_CODES:
        return text.upper()
    return _REGIONS.get(text.lower())


def restriction_tags(product: Product) -> tuple[tuple[str, RestrictionKind, str], ...]:
    """Every restriction phrase found in the provider's eligibility statements: (tag, kind, statement)."""

    found: list[tuple[str, RestrictionKind, str]] = []
    seen: set[str] = set()
    age_low: int | None = None
    age_high: int | None = None
    age_statement: str | None = None
    for statement in product.eligibility:
        lower = statement.lower()
        for tag, kind, phrases in _RESTRICTIONS:
            if tag not in seen and any(phrase in lower for phrase in phrases):
                seen.add(tag)
                found.append((tag, kind, statement))
        if " only" in lower or "only " in lower:
            for name, code in _REGIONS.items():
                tag = f"region:{code}"
                if tag not in seen and name in lower:
                    seen.add(tag)
                    found.append((tag, "hard", statement))
        low, high = _age_from_prose(statement)
        if low is not None and (age_low is None or low > age_low):
            age_low, age_statement = low, age_statement or statement
        if high is not None and (age_high is None or high < age_high):
            age_high, age_statement = high, age_statement or statement
    cls = (product.taxonomy_class or "").lower().replace("-", "_")
    for tag, words in _CLASS_RESTRICTIONS:
        if tag not in seen and any(word in cls for word in words):
            seen.add(tag)
            found.append((tag, "hard", f"taxonomy class {product.taxonomy_class}"))
    if age_low is not None or age_high is not None:
        # An adult floor alone is a condition every fact find already implies; a ceiling or a higher floor is a restriction.
        kind: RestrictionKind = "condition" if (age_high is None and (age_low or 0) <= 18) else "hard"
        found.append((f"age:{'' if age_low is None else age_low}-{'' if age_high is None else age_high}", kind, age_statement or ""))
    return tuple(found)


def _settle(tag: str, kind: RestrictionKind, statement: str, state: ClientState) -> tuple[str, str]:
    """(status, reason) with status satisfied | contradicted | unconfirmed | noted."""

    facts = state.facts
    purpose = (state.purpose or "").strip().lower() or None

    def by_purpose(wanted: str) -> tuple[str, str]:
        if purpose is None:
            return "unconfirmed", f"{tag}: the fact find does not state the purpose; the provider says {statement[:100]!r}"
        if purpose == wanted:
            return "satisfied", f"{tag} satisfied by purpose {purpose}"
        return "contradicted", f"{tag}: the client's purpose is {purpose}; the provider says {statement[:100]!r}"

    def by_flag(key: str) -> tuple[str, str]:
        value = facts.get(key)
        if value is None:
            return "unconfirmed", f"{tag}: the fact find does not state {key}; the provider says {statement[:100]!r}"
        if value is True:
            return "satisfied", f"{tag} satisfied by {key}"
        return "contradicted", f"{tag}: the fact find states {key} is {value}; the provider says {statement[:100]!r}"

    if tag == "investment_only":
        return by_purpose("investment")
    if tag == "owner_occupied_only":
        if purpose is None:
            return "unconfirmed", f"{tag}: the fact find does not state the purpose; the provider says {statement[:100]!r}"
        if purpose == "owner_occupied":
            return "satisfied", f"{tag} satisfied by purpose {purpose}"
        if purpose == "investment":
            return "contradicted", f"{tag}: the client's purpose is investment; the provider says {statement[:100]!r}"
        return "unconfirmed", f"{tag}: purpose {purpose} does not settle owner occupation; the adviser confirms it"
    if tag == "construction":
        return by_purpose("construction")
    if tag == "refinance_only":
        return by_purpose("refinance")
    if tag == "first_home_buyer":
        transaction = str(facts.get("transaction") or "").strip().lower()
        if purpose in _REFINANCE_TRANSACTIONS or transaction in _REFINANCE_TRANSACTIONS:
            return "contradicted", f"{tag}: the client is refinancing ({transaction or purpose}), not buying a first home; the provider says {statement[:100]!r}"
        return by_flag("first_home_buyer")
    if tag == "pensioner_or_concession":
        flag = facts.get("pension_or_concession")
        groups = facts.get("affinity_groups")
        if isinstance(groups, str):
            groups = [groups]
        if flag is True or any(any(word in str(group).lower() for word in _PENSION_WORDS) for group in (groups or ())):
            return "satisfied", f"{tag} satisfied: the fact find states a pension or concession"
        if flag is False:
            return "contradicted", f"{tag}: the fact find states no pension or concession; the provider says {statement[:100]!r}"
        client_low, client_high = age_bounds(state)
        lower_statement = statement.lower()
        if client_high is not None and client_high < _AGE_PENSION_FLOOR and not any(word in lower_statement for word in ("disability", "carer", "veteran", "concession card", "health care card")):
            return "contradicted", f"{tag}: the client's age band is under {_AGE_PENSION_FLOOR} and the provider names an age or retirement pension: {statement[:100]!r}"
        return "unconfirmed", f"{tag}: the fact find does not state a pension or concession; the provider says {statement[:100]!r}"
    if tag == "youth_or_student":
        student = facts.get("student")
        if student is True:
            return "satisfied", f"{tag} satisfied: the fact find states the client is a student"
        client_low, client_high = age_bounds(state)
        if student is False and "student" in statement.lower() and not any(word in statement.lower() for word in ("kids", "children", "youth", "under 18", "junior")):
            return "contradicted", f"{tag}: the fact find states the client is not a student; the provider says {statement[:100]!r}"
        if client_low is not None and client_low >= 25 and student is not True:
            return "contradicted", f"{tag}: the client's age band starts at {client_low} and the fact find does not state a student; the provider says {statement[:100]!r}"
        return "unconfirmed", f"{tag}: the fact find does not settle the youth or student segment; the provider says {statement[:100]!r}"
    if tag == "energy_efficient_property":
        return by_flag("energy_efficient_property")
    if tag == "affinity_group":
        groups = facts.get("affinity_groups")
        if isinstance(groups, str):
            groups = [groups]
        if not groups:
            return "unconfirmed", f"{tag}: the fact find names no affinity group; the provider says {statement[:100]!r}"
        lower = statement.lower()
        if any(str(group).strip().lower() in lower for group in groups):
            return "satisfied", f"{tag} satisfied by a named affinity group"
        return "unconfirmed", f"{tag}: none of the named groups appears in the provider's statement; the adviser confirms it"
    if tag.startswith("region:"):
        wanted = tag.split(":", 1)[1]
        have = region_code(state.region)
        if have is None:
            return "unconfirmed", f"{tag}: the fact find does not state the property region; the provider says {statement[:100]!r}"
        if have == wanted:
            return "satisfied", f"{tag} satisfied by region {have}"
        return "contradicted", f"{tag}: the property is in {have}; the provider says {statement[:100]!r}"
    if tag == "wholesale_investor_only":
        classification = str(facts.get("investor_classification") or "").strip().lower()
        if not classification:
            return "unconfirmed", f"{tag}: the fact find does not classify the investor; the provider says {statement[:100]!r}"
        if classification in ("wholesale", "sophisticated", "accredited", "professional"):
            return "satisfied", f"{tag} satisfied by investor classification {classification}"
        return "contradicted", f"{tag}: the client is a {classification} investor; the provider says {statement[:100]!r}"
    if tag == "non_smoker_only":
        smoker = facts.get("smoker")
        if smoker is None:
            return "unconfirmed", f"{tag}: the fact find does not state smoker status; the provider says {statement[:100]!r}"
        if smoker is False:
            return "satisfied", f"{tag} satisfied: the fact find states non-smoker"
        return "contradicted", f"{tag}: the fact find states smoker; the provider says {statement[:100]!r}"
    if tag.startswith("age:"):
        low_text, high_text = tag[4:].split("-", 1)
        low = int(low_text) if low_text else None
        high = int(high_text) if high_text else None
        client_low, client_high = age_bounds(state)
        if client_low is None and client_high is None:
            if kind == "condition":
                return "noted", f"{tag}: {statement[:100]!r}"
            return "unconfirmed", f"{tag}: the fact find does not state an age band; the provider says {statement[:100]!r}"
        if low is not None and client_high is not None and client_high < low:
            return "contradicted", f"{tag}: the client is under {low}; the provider says {statement[:100]!r}"
        if high is not None and client_low is not None and client_low > high:
            return "contradicted", f"{tag}: the client is over {high}; the provider says {statement[:100]!r}"
        exact = client_low is not None and client_low == client_high
        if exact or ((low is None or (client_low is not None and client_low >= low)) and (high is None or (client_high is not None and client_high <= high))):
            return "satisfied", f"{tag} satisfied by the client's age band"
        return "unconfirmed", f"{tag}: the client's age band straddles the limit; the adviser confirms the exact age"
    if tag == "new_customers_only":
        existing = facts.get("existing_customer")
        if existing is True:
            return "contradicted", f"{tag}: the client is an existing customer; the provider says {statement[:100]!r}"
        return "noted", f"{tag}: {statement[:100]!r}"
    if kind == "condition":
        return "noted", f"{tag}: {statement[:100]!r}"
    return "unconfirmed", f"{tag}: the adviser confirms {statement[:100]!r} against the fact find"


def _amount_range(value: Any) -> tuple[Decimal, Decimal] | None:
    """A stated range of amounts such as 'AUD 3,000 to AUD 50,000' or '$5k - $100k' as (low, high)."""
    if not isinstance(value, str):
        return None
    parts = re.split(r"\s+(?:to|and)\s+|\s*[-–]\s*", value.strip().lower(), maxsplit=1)
    if len(parts) != 2:
        return None
    low, high = parse_money(parts[0]), parse_money(parts[1])
    if low is None or high is None or high < low:
        return None
    return low, high


def evaluate_suitability(product: Product, state: ClientState) -> SuitabilityVerdict:
    """Deterministic checks on the structured terms the provider states; prose eligibility stays with the adviser."""

    reasons: list[str] = []
    checked: list[str] = []
    failed = False
    for term in product.key_terms:
        name = term.term
        lower = name.lower()
        bounds = _amount_range(term.value) if state.amount is not None and "amount" in lower and lower not in {t.lower() for t in _MIN_AMOUNT_TERMS} and lower not in {t.lower() for t in _MAX_AMOUNT_TERMS} else None
        if bounds is not None:
            low_bound, high_bound = bounds
            checked.append(name)
            if state.amount < low_bound:
                failed = True
                reasons.append(f"{name} {low_bound} to {high_bound} is above the client's {state.amount}")
            elif state.amount > high_bound:
                failed = True
                reasons.append(f"{name} {low_bound} to {high_bound} is below the client's {state.amount}")
            continue
        if state.amount is not None and lower in {t.lower() for t in _MIN_AMOUNT_TERMS}:
            minimum = parse_money(term.value)
            if minimum is not None:
                checked.append(name)
                if state.amount < minimum:
                    failed = True
                    reasons.append(f"{name} {minimum} exceeds the client's {state.amount}")
        elif state.amount is not None and lower in {t.lower() for t in _MAX_AMOUNT_TERMS}:
            maximum = parse_money(term.value)
            if maximum is not None:
                checked.append(name)
                if state.amount > maximum:
                    failed = True
                    reasons.append(f"{name} {maximum} is below the client's {state.amount}")
        elif state.lvr_percent is not None and lower in {t.lower() for t in _MAX_LVR_TERMS}:
            maximum = parse_money(term.value)
            if maximum is not None:
                checked.append(name)
                if state.lvr_percent > maximum:
                    failed = True
                    reasons.append(f"{name} {maximum}% is below the client's {state.lvr_percent}%")
        elif state.term_years is not None and lower in {t.lower() for t in _MAX_TERM_TERMS} and not (state.jurisdiction in _CONTRACT_TERM_JURISDICTIONS and lower in _CONTRACT_TERM_NAMES):
            maximum = parse_money(term.value)
            if maximum is not None and isinstance(term.value, (int, float, str, list, tuple)):
                checked.append(name)
                if Decimal(state.term_years) > maximum:
                    failed = True
                    reasons.append(f"{name} {maximum} years is below the client's {state.term_years}")
    client_low, client_high = age_bounds(state)
    horizon = state.facts.get("horizon_years")
    profile = str(state.facts.get("risk_profile") or "").strip().lower()
    tolerated = _RISK_PROFILE_MAX.get(profile)
    for term in product.key_terms:
        name = term.term
        lower = name.lower()
        if lower in _MIN_AGE_TERMS and (client_low is not None or client_high is not None):
            minimum = parse_money(term.value)
            if minimum is not None:
                checked.append(name)
                if client_high is not None and Decimal(client_high) < minimum:
                    failed = True
                    reasons.append(f"{name} {minimum} exceeds the client's age band")
        elif lower in _MAX_AGE_TERMS and (client_low is not None or client_high is not None):
            maximum = parse_money(term.value)
            if maximum is not None:
                checked.append(name)
                if client_low is not None and Decimal(client_low) > maximum:
                    failed = True
                    reasons.append(f"{name} {maximum} is below the client's age band")
        elif lower in _RISK_TERMS and tolerated is not None:
            score = risk_score(term.value)
            if score is not None:
                checked.append(name)
                if score > tolerated:
                    failed = True
                    reasons.append(f"{name} {score} of 7 exceeds the {profile} profile's tolerance of {tolerated}")
        elif lower in _HORIZON_TERMS and isinstance(horizon, (int, float, Decimal)) and not isinstance(horizon, bool):
            minimum = parse_money(term.value)
            if minimum is not None:
                checked.append(name)
                if Decimal(str(horizon)) < minimum:
                    failed = True
                    reasons.append(f"{name} {minimum} years is longer than the client's {horizon} year horizon")
    if state.residency in ("temporary_resident", "non_resident"):
        for statement in product.eligibility:
            lower = statement.lower()
            if "permanent resident" in lower or "citizen" in lower or "australian resident" in lower or "canadian resident" in lower:
                checked.append("residency (from the provider's eligibility statement)")
                failed = True
                reasons.append(f"eligibility states: {statement[:120]}")
                break
    restrictions: list[str] = []
    unconfirmed: list[str] = []
    for tag, kind, statement in restriction_tags(product):
        restrictions.append(tag)
        status, reason = _settle(tag, kind, statement, state)
        if status == "contradicted":
            failed = True
            checked.append(tag)
            reasons.append(reason)
        elif status == "satisfied":
            checked.append(tag)
            reasons.append(reason)
        elif status == "unconfirmed":
            unconfirmed.append(tag)
            reasons.append(reason)
        else:
            reasons.append(reason)
    kwargs = {"product_ref": product.product_ref, "checked_terms": tuple(dict.fromkeys(checked)), "restrictions": tuple(restrictions), "unconfirmed": tuple(unconfirmed)}
    if failed:
        return SuitabilityVerdict(outcome="ineligible", reasons=tuple(reasons), **kwargs)
    if unconfirmed:
        return SuitabilityVerdict(outcome="unassessed", reasons=tuple(reasons), **kwargs)
    if not checked:
        return SuitabilityVerdict(outcome="unassessed", reasons=("eligibility is stated in prose only; the adviser confirms it against the fact find", *reasons), **kwargs)
    structured = tuple(f"{name} satisfied" for name in dict.fromkeys(checked) if name not in restrictions)
    return SuitabilityVerdict(outcome="eligible", reasons=structured + tuple(reasons), **kwargs)


# --------------------------------------------------------------------------- #
# Shortlist: filter on the plan, rank only on supported pricing
# --------------------------------------------------------------------------- #


class ShortlistEntry(StrictModel):
    product_ref: OpaqueRef
    provider_ref: OpaqueRef
    product_name: str
    provider_name: str
    taxonomy_class: str
    suitability: SuitabilityVerdict
    score: Decimal | None = None
    score_basis: tuple[str, ...] = Field(default_factory=tuple)
    rankable: bool
    pricing_kind: str
    confidence: Confidence
    gaps: tuple[str, ...] = Field(default_factory=tuple)
    projected_cost: Decimal | None = None
    projection_horizon_years: int | None = None

    @field_validator("score_basis", "gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("score", "projected_cost", mode="before")
    @classmethod
    def _score(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value))


class Shortlist(StrictModel):
    schema_id: str = Field(default=SHORTLIST_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    catalog_digest: Sha256Digest
    vertical_id: str
    catalog_completeness: Completeness
    catalog_age_days: int = Field(ge=0)
    prepared_at: str
    entries: tuple[ShortlistEntry, ...] = Field(default_factory=tuple, max_length=MAX_SHORTLIST)
    excluded: dict[str, int] = Field(default_factory=dict)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    shortlist_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Shortlist:
        if not skip_digests(info) and self.shortlist_digest != sealed_digest(Shortlist, self, "shortlist_digest"):
            raise ValueError("shortlist_digest must commit the exact shortlist")
        return self

    @property
    def ranked(self) -> tuple[ShortlistEntry, ...]:
        return tuple(item for item in self.entries if item.rankable and item.score is not None)


def _fact_for(product: Product, items: Sequence[str]) -> PricingFact | None:
    """The supported fact for a decision field: the items are in priority order (an all-in comparison rate before a headline rate), the lowest value within the first item that has one."""
    wanted = [item.lower() for item in items]

    def priority(fact: PricingFact) -> int | None:
        name = fact.item.lower()
        for index, item in enumerate(wanted):
            if name == item or name.startswith(item):
                return index
        return None

    ranked = [(priority(fact), fact) for fact in product.rankable_pricing]
    candidates = [(index, fact) for index, fact in ranked if index is not None]
    if not candidates:
        return None
    best = min(index for index, _ in candidates)
    return min((fact for index, fact in candidates if index == best), key=lambda fact: (fact.value if fact.value is not None else Decimal("0")))


_INTRODUCTORY_WORDS = ("introductory", "intro rate", "honeymoon", "discounted for the first", "for the first year", "for the first 2 years", "for the first two years")
_COMPARISON_RATE_ITEMS = ("comparison rate", "revert comparison rate", "interest/comparison rate", "apr", "current_apr", "posted_apr", "annual percentage rate")


def introductory_without_comparison(product: Product) -> bool:
    """A product that names an introductory or honeymoon rate and states no comparison rate, APR or revert rate: its headline is temporary and nothing states the whole cost."""
    words = " ".join([product.product_name, *(fact.item for fact in product.pricing), *(term.term for term in product.key_terms)]).lower()
    if not any(word in words for word in _INTRODUCTORY_WORDS):
        return False
    stated = {fact.item.lower() for fact in product.rankable_pricing}
    if any(name == item or name.startswith(item) for name in stated for item in _COMPARISON_RATE_ITEMS):
        return False
    return not any("revert" in fact.item.lower() for fact in product.rankable_pricing)


def shortlist_products(plan: AdvicePlan | Mapping[str, Any], state: ClientState | Mapping[str, Any], catalog: ProductCatalog | Mapping[str, Any], *, as_of: str, limit: int = 10, registry: VerticalRegistry | None = None) -> Shortlist:
    """Every product the plan admits, with a suitability verdict, ranked only where supported pricing exists."""

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    stamp = timestamp(as_of, field_name="as_of")
    _require(s.vertical_id in p.verticals, "SCOPE_OUT_OF_PLAN", f"{s.vertical_id} is not a vertical this plan covers")
    _require(s.jurisdiction == p.jurisdiction == c.jurisdiction, "JURISDICTION_MISMATCH", "plan, client state and catalog share one jurisdiction")
    _require(c.vertical_id == s.vertical_id, "CATALOG_VERTICAL_MISMATCH", f"the catalog is {c.vertical_id}, the client needs {s.vertical_id}")
    _require(s.fact_find_complete, "FACT_FIND_INCOMPLETE", "a shortlist needs a complete fact find")
    age_days = (parsed(stamp) - parsed(f"{c.run_date}T00:00:00Z" if len(c.run_date) == 10 else c.run_date)).days
    _require(age_days <= p.max_catalog_age_days, "CATALOG_STALE", f"the catalog is {age_days} days old; the plan allows {p.max_catalog_age_days}")
    _require(c.completeness != "identity_only", "CATALOG_IDENTITY_ONLY", "the catalog holds provider identities and no products yet")
    registry = registry or load_vertical_registry()
    vertical = registry.vertical(s.vertical_id)

    excluded: dict[str, int] = {}
    entries: list[ShortlistEntry] = []
    minimum = _CONFIDENCE_ORDER[p.minimum_confidence]
    family = sector_family(vertical.sector)
    currency = "AUD" if c.jurisdiction == "AU" else "CAD"
    overrides: dict[str, dict[str, Decimal]] = {}
    for product in c.products:
        if not product.classified and not p.include_unclassified:
            excluded["unclassified"] = excluded.get("unclassified", 0) + 1
            continue
        if _CONFIDENCE_ORDER[product.confidence] < minimum:
            excluded["below_minimum_confidence"] = excluded.get("below_minimum_confidence", 0) + 1
            continue
        if product.availability_status and product.availability_status.lower() in ("withdrawn", "closed", "not_available", "unavailable"):
            excluded["not_available"] = excluded.get("not_available", 0) + 1
            continue
        if not engine_eligible(product, c):
            excluded["not_engine_eligible"] = excluded.get("not_engine_eligible", 0) + 1
            continue
        verdict = evaluate_suitability(product, s)
        if verdict.outcome == "ineligible":
            excluded["ineligible"] = excluded.get("ineligible", 0) + 1
            continue
        basis: list[str] = []
        components: list[tuple[RankingWeight, PricingFact]] = []
        for weight in p.ranking:
            fact = _fact_for(product, weight.pricing_items)
            if fact is not None:
                components.append((weight, fact))
                basis.append(f"{weight.decision_field}: {fact.item} {fact.value} {fact.unit or ''} ({product.confidence}, {fact.support})".strip())
        projection = None
        if p.project_costs:
            projection = project_cost(product, s, family=family, horizon_years=p.projection_horizon_years, currency=currency)
            if projection.rankable:
                primary = p.ranking[0]
                overrides[product.product_ref] = {primary.decision_field: -projection.total if primary.direction == "higher_is_better" else projection.total}
                basis.append(f"projected {family} cost over {projection.horizon_years} years: {projection.total} {currency} from " + ", ".join(item.label for item in projection.components) + (" (assumptions: " + "; ".join(projection.assumptions) + ")" if projection.assumptions else ""))
            else:
                basis.append("projection not ranked: missing " + ", ".join(projection.missing))
        projected = projection is not None and projection.rankable
        intro_unstated = family == "credit" and introductory_without_comparison(product)
        rankable = (projected or (bool(components) and sum((w.weight for w, _ in components), Decimal("0")) >= Decimal("0.5"))) and product.pricing_kind in ("list", "quoted") and not verdict.unconfirmed and not intro_unstated
        used = next((fact for weight, fact in components if weight.decision_field == "cost of credit"), None) if family == "credit" else None
        if rankable and used is not None:
            basis.append(f"cost of credit read from the provider's {used.item} ({used.value}{' ' + used.unit if used.unit else ''})" + ("; the comparison rate is the all-in figure on the regulator's standard loan and covers fees and any introductory period" if any(used.item.lower() == item or used.item.lower().startswith(item) for item in _COMPARISON_RATE_ITEMS) else "; no comparison rate is stated, so the headline rate stands"))
        if not rankable:
            if intro_unstated:
                basis.append("not ranked: an introductory rate with no comparison rate, APR or revert rate stated; the headline is temporary and nothing states the whole cost")
            elif verdict.unconfirmed:
                basis.append("not ranked: eligibility restriction " + ", ".join(verdict.unconfirmed) + " is not confirmed by the fact find")
            else:
                basis.append("not ranked: " + ("pricing is quote dependent" if product.pricing_kind == "quote_required" else "no supported pricing fact for the plan's decision fields"))
        entries.append(ShortlistEntry(product_ref=product.product_ref, provider_ref=product.provider_ref, product_name=product.product_name, provider_name=product.provider_name, taxonomy_class=product.taxonomy_class, suitability=verdict, score=None, score_basis=tuple(basis), rankable=rankable, pricing_kind=product.pricing_kind, confidence=product.confidence, gaps=product.gaps[:6], projected_cost=projection.total if projection is not None and projection.rankable else None, projection_horizon_years=projection.horizon_years if projection is not None and projection.rankable else None))

    # Normalise each decision field across the rankable candidates, then weight.
    rankable_entries = [entry for entry in entries if entry.rankable]
    scored: dict[str, Decimal] = {}
    if rankable_entries:
        per_field: dict[str, dict[str, Decimal]] = {}
        for entry in rankable_entries:
            product = c.product(entry.product_ref)
            for weight in p.ranking:
                fact = _fact_for(product, weight.pricing_items)
                value = overrides.get(entry.product_ref, {}).get(weight.decision_field, fact.value if fact is not None else None)
                if value is not None:
                    per_field.setdefault(weight.decision_field, {})[entry.product_ref] = value
        for entry in rankable_entries:
            total = Decimal("0")
            covered = Decimal("0")
            for weight in p.ranking:
                values = per_field.get(weight.decision_field, {})
                value = values.get(entry.product_ref)
                if value is None:
                    continue
                low, high = min(values.values()), max(values.values())
                if high == low:
                    continue  # every candidate states the same figure: the field separates nothing and scores nothing
                normalised = (value - low) / (high - low)
                if weight.direction == "lower_is_better":
                    normalised = Decimal("1") - normalised
                total += normalised * weight.weight
                covered += weight.weight
            scored[entry.product_ref] = (total / covered * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) if covered > 0 else Decimal("0")
    finished = [entry.model_copy(update={"score": scored.get(entry.product_ref)}) if entry.rankable else entry for entry in entries]
    finished.sort(key=lambda entry: (0 if entry.rankable else 1, -(entry.score or Decimal("0")), entry.product_name))
    disclosures = list(_STANDARD_DISCLOSURES)
    if c.completeness != "census_complete":
        disclosures.append(f"The catalog is a {c.completeness.replace('_', ' ')}: {c.coverage.providers_captured or 0} of {c.coverage.providers_on_register or 'an unstated number of'} providers on the register section were reviewed; products from unreviewed providers are not represented.")
    if any(not entry.rankable for entry in finished):
        disclosures.append("Some candidates are listed unranked because their pricing is quote dependent, lacks a supported source, or carries an eligibility restriction the fact find has not confirmed; they are not inferior, only unranked.")
    if family == "credit" and any(entry.rankable for entry in entries):
        disclosures.append("Cost of credit is ranked on the provider's comparison rate or APR where one is stated (the regulator's all-in figure on a standard loan, which covers fees and any introductory period) and on the headline rate only where none is; an introductory rate with no comparison rate is listed unranked.")
    disclosures.append(p.remuneration_disclosure)
    if excluded.get("not_engine_eligible"):
        disclosures = [*disclosures, f"{excluded['not_engine_eligible']} product record(s) are marked not advice-engine eligible by the pack that carries them ({c.coverage.phase or 'phase unstated'}); they stay visible in the market table and never rank until a fresh research pass revalidates them"]
    not_fresh: dict[str, int] = {}
    for product in c.products:
        for fact in product.pricing:
            if fact.value is not None and fact.support != "unsupported" and (fact.freshness not in ("fresh", "unstated") or fact.hold):
                state = "held" if fact.hold else fact.freshness
                not_fresh[state] = not_fresh.get(state, 0) + 1
    if not_fresh:
        disclosures = [*disclosures, "pricing facts that did not rank because they are not fresh at " + stamp[:10] + ": " + ", ".join(f"{count} {state}" for state, count in sorted(not_fresh.items())) + (f" (published view as of {c.coverage.published_as_of})" if c.coverage.published_as_of else "")]
    return seal(Shortlist, {"plan_digest": p.plan_digest, "state_digest": s.state_digest, "catalog_digest": c.catalog_digest, "vertical_id": s.vertical_id, "catalog_completeness": c.completeness, "catalog_age_days": age_days, "prepared_at": stamp, "entries": [entry.to_dict() for entry in finished[:limit]], "excluded": dict(sorted(excluded.items())), "disclosures": disclosures}, "shortlist_digest")


# --------------------------------------------------------------------------- #
# Recommendation and comparison
# --------------------------------------------------------------------------- #


class Recommendation(StrictModel):
    schema_id: str = Field(default=RECOMMENDATION_SCHEMA, alias="schema")
    shortlist_digest: Sha256Digest
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    vertical_id: str
    primary_product_ref: OpaqueRef
    alternatives: tuple[str, ...] = Field(default_factory=tuple, max_length=3)
    basis: RecommendationBasis
    rationale: tuple[str, ...] = Field(min_length=1)
    disclosures: tuple[str, ...] = Field(min_length=1)
    prepared_at: str
    prepared_by_ref: OpaqueRef
    recommendation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("alternatives", "rationale", "disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Recommendation:
        if self.primary_product_ref in self.alternatives:
            raise ValueError("the primary product is not also an alternative")
        if not skip_digests(info) and self.recommendation_digest != sealed_digest(Recommendation, self, "recommendation_digest"):
            raise ValueError("recommendation_digest must commit the exact recommendation")
        return self


def prepare_recommendation(plan: AdvicePlan | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any], *, prepared_at: str, prepared_by_ref: str, primary_product_ref: str | None = None, rationale: Sequence[str] = ()) -> Recommendation:
    """A recommendation only in personal_recommendation mode, only from the shortlist, only for an eligible or unassessed product."""

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    _require(p.mode == "personal_recommendation", "GENERAL_INFORMATION_NO_RECOMMENDATION", "this plan runs in general_information mode; it compares facts and recommends nothing")
    _require(sl.plan_digest == p.plan_digest, "SHORTLIST_PLAN_MISMATCH", "the shortlist was prepared under a different plan")
    _require(bool(sl.entries), "SHORTLIST_EMPTY", "nothing to recommend from an empty shortlist")
    by_ref = {entry.product_ref: entry for entry in sl.entries}
    if primary_product_ref is None:
        ranked = sl.ranked
        _require(bool(ranked), "RECOMMENDATION_UNRANKED_REQUIRES_ADVISER", "no candidate is ranked on supported pricing; the adviser names the primary product and the basis is adviser_judgement")
        primary = ranked[0]
        basis: RecommendationBasis = "ranked_on_supported_pricing"
    else:
        primary = by_ref.get(primary_product_ref)  # type: ignore[assignment]
        _require(primary is not None, "PRODUCT_NOT_SHORTLISTED", f"{primary_product_ref} is not on the shortlist")
        assert primary is not None
        basis = "ranked_on_supported_pricing" if (sl.ranked and primary.product_ref == sl.ranked[0].product_ref) else "adviser_judgement"
    assert primary is not None
    _require(primary.suitability.outcome != "ineligible", "PRIMARY_INELIGIBLE", "the primary product failed a structured suitability check")
    alternatives = tuple(entry.product_ref for entry in sl.ranked if entry.product_ref != primary.product_ref)[:3]
    reasons = list(rationale) or [f"{primary.product_name} by {primary.provider_name}: " + ("; ".join(primary.score_basis) if primary.score_basis else "named by the adviser")]
    if primary.suitability.outcome == "unassessed":
        reasons.append("eligibility is stated in prose only; the adviser confirms it before approval")
    return seal(Recommendation, {"shortlist_digest": sl.shortlist_digest, "plan_digest": p.plan_digest, "state_digest": sl.state_digest, "vertical_id": sl.vertical_id, "primary_product_ref": primary.product_ref, "alternatives": list(alternatives), "basis": basis, "rationale": reasons, "disclosures": list(sl.disclosures), "prepared_at": timestamp(prepared_at, field_name="prepared_at"), "prepared_by_ref": prepared_by_ref}, "recommendation_digest")


def comparison_table(shortlist: Shortlist | Mapping[str, Any], catalog: ProductCatalog | Mapping[str, Any]) -> dict[str, Any]:
    """General information: the shortlisted products' stated facts side by side, and no recommendation."""

    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    _require(c.catalog_digest == sl.catalog_digest, "CATALOG_MISMATCH", "the comparison uses the catalog the shortlist was prepared from")
    rows = []
    for entry in sl.entries:
        product = c.product(entry.product_ref)
        rows.append({"product_ref": entry.product_ref, "provider": entry.provider_name, "product": entry.product_name, "class": entry.taxonomy_class, "pricing": [{"item": fact.item, "value": None if fact.value is None else str(fact.value), "unit": fact.unit, "support": fact.support} for fact in product.pricing], "key_terms": [{"term": term.term, "value": term.value} for term in product.key_terms], "eligibility": list(product.eligibility), "confidence": product.confidence, "gaps": list(product.gaps), "sources": [{"url": source.url, "retrieved_at": source.retrieved_at} for source in product.sources]})
    return {"schema": COMPARISON_SCHEMA, "vertical_id": sl.vertical_id, "catalog_digest": sl.catalog_digest, "shortlist_digest": sl.shortlist_digest, "rows": rows, "disclosures": list(sl.disclosures), "recommendation": None}


# --------------------------------------------------------------------------- #
# The advice case lifecycle
# --------------------------------------------------------------------------- #


class AdviceCaseReceipt(StrictModel):
    client_ref: OpaqueRef | None = None
    vertical_id: str | None = None
    objective: BoundedText | None = None
    state_digest: Sha256Digest | None = None
    personal_data_sha256: Sha256Digest | None = None
    fact_find_complete: bool | None = None
    shortlist_digest: Sha256Digest | None = None
    catalog_digest: Sha256Digest | None = None
    catalog_completeness: Completeness | None = None
    catalog_age_days: int | None = Field(default=None, ge=0)
    entry_count: int | None = Field(default=None, ge=0)
    recommendation_digest: Sha256Digest | None = None
    primary_product_ref: OpaqueRef | None = None
    basis: RecommendationBasis | None = None
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    approval_ref: OpaqueRef | None = None
    adviser_ref: OpaqueRef | None = None
    authority_kind: AuthorityKind | None = None
    authority_ref_sha256: Sha256Digest | None = None
    approved_at: str | None = None
    statement_digest: Sha256Digest | None = None
    client_acknowledgement_ref: OpaqueRef | None = None
    implementation_ref: OpaqueRef | None = None
    product_ref: OpaqueRef | None = None
    review_outcome: ShortText | None = None
    fact_find_gaps: tuple[str, ...] = Field(default_factory=tuple)
    event_ref: OpaqueRef | None = None
    changed_fields: tuple[str, ...] = Field(default_factory=tuple)
    changed_product_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    # bindings to the adviser's file: every one a digest or an opaque ref, every one optional
    engagement_digest: Sha256Digest | None = None
    predecessor_case_ref: OpaqueRef | None = None
    checklist_digest: Sha256Digest | None = None
    verification_digest: Sha256Digest | None = None
    document_digest: Sha256Digest | None = None
    explanation_digest: Sha256Digest | None = None
    outcome_digest: Sha256Digest | None = None
    reconciliation_digest: Sha256Digest | None = None
    reconciliation_verdict: Literal["as_recommended", "differs", "unassessed"] | None = None
    differences_acknowledged_ref: OpaqueRef | None = None
    review_digest: Sha256Digest | None = None
    successor_case_ref: OpaqueRef | None = None
    implementation_digest: Sha256Digest | None = None
    next_review_due_at: str | None = None
    disposition_digest: Sha256Digest | None = None
    disposition_outcome: Literal["retain_current", "refer", "defer"] | None = None

    @field_validator("fact_find_gaps", mode="before")
    @classmethod
    def _gap_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=12)

    @field_validator("disclosures", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class AdviceCaseLedger(StrictModel):
    client_ref: OpaqueRef | None = None
    vertical_id: str | None = None
    objective: str | None = None
    state_digest: Sha256Digest | None = None
    personal_data_sha256: Sha256Digest | None = None
    shortlist_digest: Sha256Digest | None = None
    catalog_digest: Sha256Digest | None = None
    catalog_completeness: str | None = None
    recommendation_digest: Sha256Digest | None = None
    primary_product_ref: OpaqueRef | None = None
    basis: str | None = None
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    approval_ref: OpaqueRef | None = None
    adviser_ref: OpaqueRef | None = None
    authority_kind: str | None = None
    approved_at: str | None = None
    statement_digest: Sha256Digest | None = None
    presented_at: str | None = None
    implementation_ref: OpaqueRef | None = None
    implemented_product_ref: OpaqueRef | None = None
    review_due_at: str | None = None
    review_outcome: str | None = None
    review_required: bool = False
    review_required_reason: str | None = None
    fact_changes: tuple[str, ...] = Field(default_factory=tuple)
    decline_reason: str | None = None
    outcome: Literal["open", "implemented", "reviewed", "declined", "withdrawn", "resolved"] = "open"
    disposition_digest: Sha256Digest | None = None
    disposition_outcome: Literal["retain_current", "refer", "defer"] | None = None
    engagement_digest: Sha256Digest | None = None
    predecessor_case_ref: OpaqueRef | None = None
    state_digest_at_advice: Sha256Digest | None = None
    checklist_digest: Sha256Digest | None = None
    verification_digest: Sha256Digest | None = None
    document_digest: Sha256Digest | None = None
    explanation_digest: Sha256Digest | None = None
    outcome_digest: Sha256Digest | None = None
    reconciliation_digest: Sha256Digest | None = None
    reconciliation_verdict: str | None = None
    review_digest: Sha256Digest | None = None
    successor_case_ref: OpaqueRef | None = None

    @field_validator("disclosures", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class AdviceCaseEffectBoundary(StrictModel):
    personal_data_read: bool = False
    recommendation_made: bool = False
    statement_issued: bool = False
    product_applied_for: bool = False
    message_sent: bool = False


def _add_days(stamp: str, days: int) -> str:
    from datetime import timedelta

    return (parsed(stamp) + timedelta(days=days)).isoformat().replace("+00:00", "Z")


def _apply_case(plan: AdvicePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event = command.receipt, command.event
    if event == "open":
        require(r.client_ref is not None and r.vertical_id is not None and r.objective is not None, "INTAKE_INCOMPLETE", "intake names the client commitment, the vertical and the objective")
        require(r.vertical_id in plan.verticals, "SCOPE_OUT_OF_PLAN", f"{r.vertical_id} is not a vertical this plan covers")
        data.update({"client_ref": r.client_ref, "vertical_id": r.vertical_id, "objective": r.objective, "engagement_digest": r.engagement_digest, "predecessor_case_ref": r.predecessor_case_ref})
    elif event == "complete_fact_find":
        require(r.state_digest is not None and r.personal_data_sha256 is not None, "FACT_FIND_MISSING", "the fact find carries the state digest and the personal-data commitment")
        require(not r.fact_find_gaps, "FACT_FIND_GAPS", "the fact find still lacks " + ", ".join(r.fact_find_gaps) + "; collect them before the shortlist", "correct_input")
        require(r.fact_find_complete is True, "FACT_FIND_INCOMPLETE", "the fact find is not complete")
        data.update({"state_digest": r.state_digest, "personal_data_sha256": r.personal_data_sha256})
    elif event == "shortlist":
        require(r.shortlist_digest is not None and r.catalog_digest is not None and r.catalog_completeness is not None and r.catalog_age_days is not None, "SHORTLIST_MISSING", "the shortlist carries its digest, catalog digest, completeness and age")
        require(r.state_digest == data.get("state_digest"), "STATE_DRIFT", "the shortlist was prepared for a different client state; complete the fact find again")
        require(r.catalog_age_days <= plan.max_catalog_age_days, "CATALOG_STALE", f"the catalog is {r.catalog_age_days} days old; the plan allows {plan.max_catalog_age_days}")
        require((r.entry_count or 0) >= 1, "SHORTLIST_EMPTY", "an empty shortlist is not a shortlist; widen the catalog or the plan", "correct_input")
        data.update({"shortlist_digest": r.shortlist_digest, "catalog_digest": r.catalog_digest, "catalog_completeness": r.catalog_completeness, "recommendation_digest": None, "primary_product_ref": None})
    elif event == "recommend":
        require(plan.mode == "personal_recommendation", "GENERAL_INFORMATION_NO_RECOMMENDATION", "this plan runs in general_information mode; it compares facts and recommends nothing")
        require(r.recommendation_digest is not None and r.primary_product_ref is not None and r.basis is not None, "RECOMMENDATION_MISSING", "a recommendation carries its digest, the primary product and its basis")
        require(r.shortlist_digest == data.get("shortlist_digest"), "SHORTLIST_MISMATCH", "the recommendation was prepared from a different shortlist")
        require(any(plan.remuneration_disclosure == text for text in r.disclosures), "DISCLOSURE_MISSING", "the recommendation carries the plan's remuneration disclosure")
        if data.get("catalog_completeness") != "census_complete":
            require(any("partial" in text.lower() or "identity" in text.lower() or "not represented" in text.lower() for text in r.disclosures), "COVERAGE_UNDISCLOSED", "a recommendation from a partial catalog discloses the coverage")
        data.update({"recommendation_digest": r.recommendation_digest, "primary_product_ref": r.primary_product_ref, "basis": r.basis, "disclosures": tuple(r.disclosures), "checklist_digest": r.checklist_digest, "state_digest_at_advice": data.get("state_digest")})
    elif event == "approve":
        require(r.adviser_ref is not None and r.authority_kind is not None and r.authority_ref_sha256 is not None and r.approved_at is not None, "ADVISER_APPROVAL_MISSING", "approval names the adviser, the authority and the time")
        require(r.approval_ref is not None, "ADVISER_APPROVAL_REQUIRED", "the licensed adviser approves this recommendation as a platform approval decided by someone other than the requester; the case waits for that decision", "await_approval")
        require(r.approval_ref is not None and r.adviser_ref is not None and r.authority_kind is not None and r.authority_ref_sha256 is not None and r.approved_at is not None, "ADVISER_APPROVAL_MISSING", "approval names the approval, the adviser, the authority kind and commitment, and the time")
        require(r.recommendation_digest == data.get("recommendation_digest"), "APPROVAL_STALE", "the adviser approves exactly the recommendation that was prepared; re-recommend after any change")
        require(r.adviser_ref != data.get("client_ref"), "SELF_ADVICE", "the adviser is not the client")
        authority = plan.authority_for(str(data.get("vertical_id")), str(r.authority_kind))
        require(authority is not None, "ADVISER_UNAUTHORISED", f"the plan holds no {r.authority_kind} covering {data.get('vertical_id')}")
        assert authority is not None
        require(authority.authority_ref_sha256 == r.authority_ref_sha256, "AUTHORITY_MISMATCH", "the approving authority is not the one the plan holds")
        require(authority.expires_at is None or parsed(authority.expires_at) > parsed(str(r.approved_at)), "AUTHORITY_EXPIRED", "the authority had expired at approval time")
        if data.get("checklist_digest") is not None:
            # a recommendation that carried a compliance checklist is approved against that exact checklist and a verified licence
            require(r.checklist_digest == data.get("checklist_digest"), "APPROVAL_CHECKLIST_MISMATCH", "the adviser approves against the compliance checklist the recommendation carried; a different or missing checklist is not that approval")
            require(r.verification_digest is not None, "AUTHORITY_UNVERIFIED", "the adviser's authority is verified against a register snapshot before the approval; the approval cites that verification")
        data.update({"approval_ref": r.approval_ref, "adviser_ref": r.adviser_ref, "authority_kind": r.authority_kind, "approved_at": r.approved_at, "verification_digest": r.verification_digest})
    elif event == "propose_disposition":
        require(r.disposition_digest is not None and r.disposition_outcome is not None and bool(command.reason), "DISPOSITION_MISSING", "the proposed outcome, exact evidence and reason are required")
        require(r.state_digest is not None and r.client_ref == data.get("client_ref") and data.get("state_digest") in (None, r.state_digest), "DISPOSITION_STALE", "the proposal must bind the current client facts")
        require(r.next_review_due_at is not None and parsed(r.next_review_due_at) > parsed(command.occurred_at), "FOLLOW_UP_INVALID", "the case outcome carries a future follow-up date")
        data.update({"disposition_digest": r.disposition_digest, "disposition_outcome": r.disposition_outcome, "review_due_at": r.next_review_due_at, "state_digest": r.state_digest})
    elif event == "resolve_disposition":
        require(r.disposition_digest is not None and r.disposition_digest == data.get("disposition_digest"), "DISPOSITION_STALE", "approval binds the exact proposed disposition")
        require(r.verification_digest is not None and r.adviser_ref is not None and r.approved_at is not None, "AUTHORITY_UNVERIFIED", "the disposition requires a licensed adviser and retained verification")
        require(r.approval_ref is not None, "ADVISER_APPROVAL_REQUIRED", "a different person must approve the disposition", "await_approval")
        authority = plan.authority_for(str(data.get("vertical_id")), str(r.authority_kind))
        require(authority is not None and authority.authority_ref_sha256 == r.authority_ref_sha256, "AUTHORITY_MISMATCH", "the approving authority must be the plan's authority")
        require(r.adviser_ref != data.get("client_ref"), "SELF_ADVICE", "the adviser is not the client")
        require(authority.expires_at is None or parsed(authority.expires_at) > parsed(str(r.approved_at)), "AUTHORITY_EXPIRED", "the authority must remain valid")
        data.update({"approval_ref": r.approval_ref, "adviser_ref": r.adviser_ref, "authority_kind": r.authority_kind, "approved_at": r.approved_at, "verification_digest": r.verification_digest, "outcome": "resolved"})
    elif event == "present":
        require(not data.get("review_required"), "REVIEW_REQUIRED", "changed facts require review before presentation", "await_approval")
        require(r.statement_digest is not None and r.client_acknowledgement_ref is not None, "STATEMENT_MISSING", "presentation carries the record-of-advice digest and the client's acknowledgement")
        data.update({"statement_digest": r.statement_digest, "presented_at": command.occurred_at, "document_digest": r.document_digest, "explanation_digest": r.explanation_digest})
    elif event == "implement":
        require(not data.get("review_required"), "REVIEW_REQUIRED", "changed facts require review before implementation", "await_approval")
        require(r.implementation_ref is not None and r.product_ref is not None, "IMPLEMENTATION_MISSING", "implementation names the application evidence and the product")
        require(r.product_ref == data.get("primary_product_ref"), "PRODUCT_NOT_RECOMMENDED", "only the recommended product is implemented under this case; a different product is a new recommendation")
        require(not (r.reconciliation_verdict == "differs" and r.differences_acknowledged_ref is None), "TERMS_DIFFER_UNACKNOWLEDGED", "the provider's stated terms differ from the recommendation; the adviser acknowledges the differences before the case is implemented", "await_approval")
        data.update({"implementation_ref": r.implementation_ref, "implemented_product_ref": r.product_ref, "review_due_at": _add_days(command.occurred_at, plan.review_after_days), "outcome": "implemented", "outcome_digest": r.outcome_digest, "reconciliation_digest": r.reconciliation_digest, "reconciliation_verdict": r.reconciliation_verdict})
    elif event == "review":
        require(r.review_outcome is not None, "REVIEW_OUTCOME_MISSING", "a review names its outcome")
        if status == "resolved":
            require(r.successor_case_ref is not None, "SUCCESSOR_REQUIRED", "disposition follow-up opens a linked case for fresh work")
        data.update({"review_outcome": r.review_outcome, "outcome": "reviewed", "review_digest": r.review_digest, "successor_case_ref": r.successor_case_ref})
    elif event == "decline":
        require(bool((command.reason or "").strip()), "DECLINE_UNEXPLAINED", "a decline names its reason")
        data.update({"decline_reason": command.reason, "outcome": "declined"})
    elif event == "withdraw":
        require(bool((command.reason or "").strip()), "WITHDRAWAL_UNEXPLAINED", "a withdrawal names its reason")
        data.update({"outcome": "withdrawn"})
    elif event == "facts_changed":
        require(r.event_ref is not None, "FACT_CHANGE_UNNAMED", "a fact change names the event that carried it")
        if r.state_digest is not None:
            require(r.client_ref == data.get("client_ref"), "REVISION_CLIENT_MISMATCH", "revised facts must identify this case's client")
            data["state_digest"] = r.state_digest
        note = f"{r.event_ref}: {', '.join(r.changed_fields) or 'facts'} changed for {len(r.changed_product_refs) or 'some'} product(s) at {command.occurred_at}"
        history = tuple(data.get("fact_changes") or ()) + (note,)
        if status in ("adviser_approved", "presented", "resolved"):
            # advice already approved or presented is never silently reverted: it is flagged for the adviser's review
            data.update({"fact_changes": history, "review_required": True, "review_required_reason": note})
        else:
            data.update({"fact_changes": history, "shortlist_digest": None, "catalog_digest": None, "catalog_completeness": None, "recommendation_digest": None, "primary_product_ref": None, "basis": None, "review_required": False})
    return next_status, data


ADVICE_CASE_STATUSES: tuple[str, ...] = ("intake", "fact_find_complete", "shortlisted", "recommended", "adviser_approved", "presented", "implemented", "reviewed", "declined", "withdrawn", "disposition_pending", "resolved")
TERMINAL_CASE_STATUSES = frozenset({"reviewed", "declined", "withdrawn"})
ADVICE_CASE_EVENTS: tuple[str, ...] = ("open", "complete_fact_find", "shortlist", "recommend", "approve", "present", "implement", "review", "decline", "withdraw", "facts_changed", "propose_disposition", "resolve_disposition")
_CASE_TABLE = {
    ("new", "open"): "intake",
    ("intake", "complete_fact_find"): "fact_find_complete",
    ("fact_find_complete", "complete_fact_find"): "fact_find_complete",
    ("fact_find_complete", "shortlist"): "shortlisted",
    ("shortlisted", "shortlist"): "shortlisted",
    ("shortlisted", "recommend"): "recommended",
    ("recommended", "shortlist"): "shortlisted",
    ("recommended", "recommend"): "recommended",
    ("recommended", "approve"): "adviser_approved",
    ("adviser_approved", "present"): "presented",
    ("presented", "implement"): "implemented",
    ("implemented", "review"): "reviewed",
    ("adviser_approved", "review"): "reviewed",
    ("presented", "review"): "reviewed",
    ("recommended", "decline"): "declined",
    ("adviser_approved", "decline"): "declined",
    ("presented", "decline"): "declined",
    **{(status, "withdraw"): "withdrawn" for status in ("intake", "fact_find_complete", "shortlisted", "recommended", "adviser_approved", "presented")},
    # a published fact change sends a shortlisted or recommended case back to its fact find; an approved or presented case keeps its status and is flagged
    ("shortlisted", "facts_changed"): "fact_find_complete",
    ("fact_find_complete", "facts_changed"): "fact_find_complete",
    ("recommended", "facts_changed"): "fact_find_complete",
    ("adviser_approved", "facts_changed"): "adviser_approved",
    ("presented", "facts_changed"): "presented",
    **{(status, "propose_disposition"): "disposition_pending" for status in ("intake", "fact_find_complete", "shortlisted", "recommended", "disposition_pending")},
    ("disposition_pending", "resolve_disposition"): "resolved",
    ("disposition_pending", "decline"): "declined",
    ("disposition_pending", "facts_changed"): "fact_find_complete",
    ("resolved", "facts_changed"): "resolved",
    ("resolved", "review"): "reviewed",
}

ADVICE_CASE_LIFECYCLE = LifecycleSpec(entity="advice_case", schema_prefix="finance_advice_engine", legacy_schema_prefixes=(ADVICE_KIND,), statuses=ADVICE_CASE_STATUSES, terminal=TERMINAL_CASE_STATUSES, events=ADVICE_CASE_EVENTS, table=_CASE_TABLE, opening_event="open", reason_events=("decline", "withdraw"), apply=_apply_case, ledger_model=AdviceCaseLedger, receipt_model=AdviceCaseReceipt, effect_boundary_model=AdviceCaseEffectBoundary, plan_model=AdvicePlan, max_transitions=MAX_CASE_TRANSITIONS)
AdviceCaseState = ADVICE_CASE_LIFECYCLE.State


def open_advice_case(plan: AdvicePlan, scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return ADVICE_CASE_LIFECYCLE.open(plan, scope, receipt=receipt, opened_at=opened_at, actor_ref=actor_ref)


def advance_advice_case(plan: AdvicePlan, state: Any, command: Any) -> Any:
    return ADVICE_CASE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the artifacts this engine binds
# --------------------------------------------------------------------------- #


def fact_find_receipt(state: ClientState | Mapping[str, Any]) -> dict[str, Any]:
    """The receipt the case lifecycle binds: digests, the personal-data commitment, and the required facts still missing for the vertical."""

    from lightbulb.finance_advice_fact_find import fact_find_gaps

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    gaps = fact_find_gaps(s)
    return {"state_digest": s.state_digest, "personal_data_sha256": s.personal_data_sha256, "fact_find_complete": s.fact_find_complete, "fact_find_gaps": list(gaps.required_missing), "evidence_refs": [f"client_state:{s.disclosed_at[:10]}", f"fact_find_gaps:{gaps.gaps_digest[:16]}"]}


def shortlist_receipt(shortlist: Shortlist | Mapping[str, Any]) -> dict[str, Any]:
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    return {"shortlist_digest": sl.shortlist_digest, "catalog_digest": sl.catalog_digest, "catalog_completeness": sl.catalog_completeness, "catalog_age_days": sl.catalog_age_days, "entry_count": len(sl.entries), "state_digest": sl.state_digest, "evidence_refs": [f"shortlist:{sl.prepared_at[:10]}", f"catalog:{sl.vertical_id}:{sl.catalog_completeness}"]}


def recommendation_receipt(recommendation: Recommendation | Mapping[str, Any], *, checklist_digest: str | None = None) -> dict[str, Any]:
    rec = recommendation if isinstance(recommendation, Recommendation) else Recommendation.model_validate(dict(detached(recommendation)))
    receipt = {"recommendation_digest": rec.recommendation_digest, "shortlist_digest": rec.shortlist_digest, "primary_product_ref": rec.primary_product_ref, "basis": rec.basis, "disclosures": list(rec.disclosures), "evidence_refs": [f"recommendation:{rec.prepared_at[:10]}:{rec.basis}"]}
    if checklist_digest is not None:
        receipt["checklist_digest"] = checklist_digest
    return receipt


def approval_receipt(*, approval_ref: str | None, adviser_ref: str, authority: Authority | Mapping[str, Any], approved_at: str, recommendation_digest: str, checklist_digest: str | None = None, verification_digest: str | None = None) -> dict[str, Any]:
    a = authority if isinstance(authority, Authority) else Authority.model_validate(dict(detached(authority)))
    receipt = {"approval_ref": approval_ref, "adviser_ref": adviser_ref, "authority_kind": a.kind, "authority_ref_sha256": a.authority_ref_sha256, "approved_at": timestamp(approved_at, field_name="approved_at"), "recommendation_digest": recommendation_digest, "evidence_refs": [f"approval:{approval_ref}"]}
    if checklist_digest is not None:
        receipt["checklist_digest"] = checklist_digest
    if verification_digest is not None:
        receipt["verification_digest"] = verification_digest
    return receipt


def advice_case_summary(state: Any) -> dict[str, Any]:
    ledger = state.ledger
    return {"case_ref": str(state.scope.entity_ref), "status": state.status, "vertical_id": ledger.vertical_id, "objective": ledger.objective, "catalog_completeness": ledger.catalog_completeness, "primary_product_ref": ledger.primary_product_ref, "basis": ledger.basis, "adviser_ref": ledger.adviser_ref, "authority_kind": ledger.authority_kind, "presented_at": ledger.presented_at, "implemented_product_ref": ledger.implemented_product_ref, "review_due_at": ledger.review_due_at, "outcome": ledger.outcome, "review_required": bool(getattr(ledger, "review_required", False)), "fact_changes": list(getattr(ledger, "fact_changes", ()) or ()), "engagement_digest": ledger.engagement_digest, "predecessor_case_ref": ledger.predecessor_case_ref, "state_digest_at_advice": ledger.state_digest_at_advice, "recommendation_digest": ledger.recommendation_digest, "checklist_digest": ledger.checklist_digest, "verification_digest": ledger.verification_digest, "document_digest": ledger.document_digest, "explanation_digest": ledger.explanation_digest, "outcome_digest": ledger.outcome_digest, "reconciliation_verdict": ledger.reconciliation_verdict, "review_digest": ledger.review_digest, "successor_case_ref": ledger.successor_case_ref, "approval_ref": ledger.approval_ref}


ADVICE_ENGINE_MANIFEST: dict[str, Any] = {
    "kind": ADVICE_KIND,
    "schemas": [ADVICE_PLAN_SCHEMA, CLIENT_STATE_SCHEMA, SHORTLIST_SCHEMA, RECOMMENDATION_SCHEMA, COMPARISON_SCHEMA],
    "lifecycle": {"entity": "advice_case", "statuses": list(ADVICE_CASE_STATUSES), "events": list(ADVICE_CASE_EVENTS)},
    "modes": ["personal_recommendation", "general_information"],
    "hard_rules": [
        "a recommendation is never made outside the authority the plan holds for that vertical; without one the business runs general_information and recommends nothing",
        "nothing is ranked on a price the catalog cannot support with a source",
        "a catalog older than the plan allows is refused; a partial register sample is disclosed, never hidden",
        "personal data never enters the SDK: the state carries its commitment and only decision facts travel in clear",
        "the approving adviser is a person with an authority the plan names, is not the client, and approves exactly the recommendation prepared",
        "presentation follows approval, implementation follows presentation, and only the recommended product is implemented under the case",
        "a general-information comparison carries facts, sources and gaps side by side and no recommendation",
    ],
}

__all__ = [
    "ADVICE_CASE_EVENTS",
    "ADVICE_CASE_LIFECYCLE",
    "ADVICE_CASE_STATUSES",
    "ADVICE_ENGINE_MANIFEST",
    "ADVICE_KIND",
    "ADVICE_PLAN_SCHEMA",
    "CLIENT_STATE_SCHEMA",
    "COMPARISON_SCHEMA",
    "RECOMMENDATION_SCHEMA",
    "SHORTLIST_SCHEMA",
    "AdviceCaseLedger",
    "AdviceCaseReceipt",
    "AdviceCaseState",
    "AdviceError",
    "AdvicePlan",
    "Authority",
    "ClientState",
    "RankingWeight",
    "Recommendation",
    "Shortlist",
    "ShortlistEntry",
    "SuitabilityVerdict",
    "advance_advice_case",
    "advice_case_summary",
    "approval_receipt",
    "client_state",
    "comparison_table",
    "compile_advice_plan",
    "default_ranking",
    "engine_eligible",
    "evaluate_suitability",
    "age_bounds",
    "region_code",
    "restriction_tags",
    "risk_score",
    "sector_family",
    "fact_find_receipt",
    "open_advice_case",
    "parse_money",
    "prepare_recommendation",
    "recommendation_receipt",
    "shortlist_products",
    "shortlist_receipt",
]
