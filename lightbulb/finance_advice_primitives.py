"""Executable primitives for the advice loop: provider map, shortlist, recommendation, market report, research queue, and the adviser's file.

All previews. Each takes inputs the caller already holds (research packs, a sealed
plan, a client state that carries only a commitment to the personal data, a sealed
catalog) and returns a sealed artifact. Nothing here reads a register, calls a
provider, or gives personal financial advice: a recommendation is prepared for a
licensed adviser, whose approval the case lifecycle demands before anyone presents it.

The rest of the adviser's file (engagement, strategy, remuneration, the compliance
checklist, the licence verification, the client explanation, the application pack,
the review assessment and one whole case run) previews under a second golden loop,
``ADVICE_FULL_LOOP``, so every manifest that already names the first one keeps its
meaning. All of them stay read-only: the SDK writes to no provider, sends nothing to
a client, requests no approval from a preview, and runs no model.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator

from lightbulb.finance_advice_catalog import AdviceCatalogError, ResearchModel, ingest_catalog_pack, provider_ref
from lightbulb.finance_advice_observations import published_catalog
from lightbulb.finance_advice_engine import ADVICE_CASE_LIFECYCLE, AdviceError, AdvicePlan, Recommendation, Shortlist, advance_advice_case, client_state, compile_advice_plan, fact_find_receipt, open_advice_case, prepare_recommendation, shortlist_products
from lightbulb.finance_advice_record import RecordOfAdviceEvidence, record_of_advice_evidence
from lightbulb.finance_advice_market import AdviceMarketError, MarketReport, market_report
from lightbulb.finance_advice_provider_map import AdviceProviderMapError, ProviderMap, build_provider_map
from lightbulb.finance_advice_research import AdviceResearchError, ResearchQueue, queue_from_map
from lightbulb.finance_advice_case_runner import CaseRun, run_case
from lightbulb.finance_advice_cases import advice_case_runtime
from lightbulb.finance_advice_compliance import AdviceComplianceError, ComplianceChecklist, approval_pack, compliance_checklist, verification_for
from lightbulb.finance_advice_engagement import AdviceEngagementError, EngagementPack, engagement_gaps, engagement_pack, engagement_receipt
from lightbulb.finance_advice_implementation import AdviceImplementationError, ApplicationPack, application_pack, implementation_receipt, reconcile_terms
from lightbulb.finance_advice_licence import AuthorityVerification, licence_register, verify_authority
from lightbulb.finance_advice_prose import AdviceProseError, ClientExplanation, deterministic_explanation, explanation_document
from lightbulb.finance_advice_remuneration import AdviceRemunerationError, RemunerationDisclosure, conflicts_register, remuneration_disclosure, remuneration_schedule
from lightbulb.finance_advice_review import AdviceReviewError, ReviewAssessment, review_assessment, review_receipt
from lightbulb.finance_advice_strategy import AdviceStrategyError, StrategyPlan, serviceability, strategy_plan
from lightbulb.company_engine_core import OpaqueRef, ShortText, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_engine_store import InMemoryEngineStateStore
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveBlocker, PrimitiveExecutionContext, PrimitiveExecutionResult

ADVICE_GOLDEN_LOOP = "finance_advice.client_state_to_adviser_approved_recommendation@0.1.0"
ADVICE_FULL_LOOP = "finance_advice.engagement_to_reviewed_case@0.1.0"
ADVICE_STAGES: tuple[str, ...] = ("map_providers", "fact_find", "shortlist", "recommend", "adviser_approve", "present", "implement", "review")
AdviceCaseState = ADVICE_CASE_LIFECYCLE.State
AdviceCaseCommand = ADVICE_CASE_LIFECYCLE.Command
AdviceCaseTransition = ADVICE_CASE_LIFECYCLE.TransitionResult
_PROFILES = ("mortgage_broker", "financial_adviser", "insurance_broker", "product_comparison_service")
_ERRORS = (AdviceError, AdviceCatalogError, AdviceProviderMapError, AdviceResearchError, AdviceMarketError, AdviceStrategyError, AdviceComplianceError, AdviceRemunerationError, AdviceEngagementError, AdviceProseError, AdviceImplementationError, AdviceReviewError)
_AUTHORITY_BOUNDARY = {"agent": "gathers packs and the fact find, relays the shortlist", "sdk": "types, seals and fences every artifact; never advises", "spring": "stores catalogs, records the adviser's approval with separation of duties", "connectors": "no provider read or write here"}
_FILE_BOUNDARY = {"agent": "gathers the disclosures, the fact find and the provider's answer; relays what the file says is owed", "sdk": "types, seals and binds every artifact by digest; never advises, never sends, never writes", "spring": "stores the sealed artifacts and records the licensed adviser's approval with separation of duties", "connectors": "no provider read or write here; a provider write is a stored proposal the platform executes under approval"}


class PackFile(ResearchModel):
    file_name: ShortText
    payload: dict[str, Any]


class BuildProviderMapInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    packs: tuple[PackFile, ...] = Field(min_length=1, max_length=200)
    built_at: str

    @field_validator("built_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="built_at")


class ShortlistInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    client_state: dict[str, Any]
    catalog: dict[str, Any]
    as_of: str
    limit: int = Field(default=10, ge=1, le=50)
    observations: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=5000)
    knowledge_at: str | None = None
    apply_freshness: bool = False

    @field_validator("observations", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


class RecommendInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    shortlist: dict[str, Any]
    prepared_at: str
    prepared_by_ref: OpaqueRef
    primary_product_ref: str | None = None
    rationale: tuple[str, ...] = Field(default_factory=tuple, max_length=12)

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class MarketReportInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    catalog: dict[str, Any]
    include_product_cited: bool = True


class ResearchQueueInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    provider_map: dict[str, Any]
    catalogs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    as_of: str
    max_age_days: int = Field(default=45, ge=1, le=365)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


class OpenCaseInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    entity_ref: ShortText
    receipt: dict[str, Any]
    opened_at: str

    @field_validator("opened_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="opened_at")


class AdvanceCaseInput(ResearchModel):
    plan: dict[str, Any]
    state: dict[str, Any]
    command: dict[str, Any]


class RecordEvidenceInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    client_state: dict[str, Any]
    shortlist: dict[str, Any]
    catalog: dict[str, Any]
    recommendation: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    fact_find_gaps: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    switching: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    needs: dict[str, Any] | None = None
    benefit_fit: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    rule_disclosures: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    remuneration: dict[str, Any] | None = None
    strategy: dict[str, Any] | None = None
    serviceability: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    prepared_at: str

    @field_validator("switching", "benefit_fit", "rule_disclosures", "serviceability", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class StrategyPlanInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    client_ref: ShortText
    client_state: dict[str, Any]
    prepared_at: str
    as_of: str
    horizon_years: int = Field(default=5, ge=1, le=40)
    assumptions: dict[str, Any] = Field(default_factory=dict)
    products: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    family: str = "credit"

    @field_validator("products", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of", "prepared_at")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))


class ComplianceChecklistInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    client_state: dict[str, Any]
    shortlist: dict[str, Any]
    catalog: dict[str, Any]
    as_of: str
    recommendation: dict[str, Any] | None = None
    record: dict[str, Any] | None = None
    switching: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=50)
    verifications: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    remuneration: dict[str, Any] | None = None
    engagement: dict[str, Any] | None = None
    serviceability: dict[str, Any] | None = None
    needs: dict[str, Any] | None = None
    fact_find_gaps: tuple[str, ...] = Field(default_factory=tuple, max_length=40)

    @field_validator("switching", "verifications", "fact_find_gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


class RemunerationDisclosureInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    schedule: dict[str, Any]
    recommendation: dict[str, Any]
    shortlist: dict[str, Any]
    family: str
    prepared_at: str
    conflicts_register: dict[str, Any] | None = None
    client_state: dict[str, Any] | None = None
    horizon_years: int = Field(default=1, ge=1, le=40)
    amount: str | None = None

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class EngagementPackInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    client_ref: ShortText
    personal_data_sha256: str
    jurisdiction: str
    family: str
    verticals: tuple[str, ...] = Field(min_length=1, max_length=20)
    objectives: dict[str, str]
    given: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=40)
    consent: dict[str, Any]
    prepared_at: str
    fee_arrangement: dict[str, Any] | None = None
    risk_profile: dict[str, Any] | None = None
    scope_exclusions: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    vertical_id: str | None = None

    @field_validator("verticals", "given", "scope_exclusions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class ClientExplanationInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    record: dict[str, Any]
    prepared_at: str
    jurisdiction_terms: dict[str, str] = Field(default_factory=dict)
    retain_until: str | None = None

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class ApplicationPackInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    recommendation: dict[str, Any]
    record: dict[str, Any]
    client_state: dict[str, Any]
    prepared_at: str
    prepared_by_ref: OpaqueRef
    approval: dict[str, Any] | None = None
    items: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=60)
    write_proposals: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    holdings: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    case_ref: str | None = None
    provider_ref: str | None = None
    outcome: dict[str, Any] | None = None
    differences_acknowledged_ref: str | None = None

    @field_validator("items", "write_proposals", "holdings", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")


class ReviewAssessmentInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: dict[str, Any]
    case_summary: dict[str, Any]
    record: dict[str, Any]
    state_at_advice: dict[str, Any]
    state_now: dict[str, Any]
    catalog_now: dict[str, Any]
    as_of: str
    needs_now: dict[str, Any] | None = None
    serviceability_now: dict[str, Any] | None = None
    engagement: dict[str, Any] | None = None
    verifications: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    quotes: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    impacts: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    reconciliation: dict[str, Any] | None = None
    life_events: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    outcome_note: str | None = None
    successor_case_ref: str | None = None

    @field_validator("verifications", "quotes", "impacts", "life_events", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


class VerifyAuthorityInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    authority: dict[str, Any]
    snapshot: dict[str, Any]
    as_of: str
    vertical_id: str | None = None
    family: str | None = None
    max_register_age_hours: int = Field(default=840, ge=1, le=8760)
    expiring_soon_days: int = Field(default=30, ge=1, le=365)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


class RunCaseInput(ResearchModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    entity_ref: ShortText
    plan: dict[str, Any]
    engagement: dict[str, Any]
    client_state: dict[str, Any]
    catalog: dict[str, Any]
    as_of: str
    prepared_by_ref: OpaqueRef
    mode: Literal["prepare_only"] = "prepare_only"
    observations: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=5000)
    quote_profiles: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    holdings: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    remuneration_schedule: dict[str, Any] | None = None
    conflicts_register: dict[str, Any] | None = None
    licence_snapshots: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    adviser_ref: str | None = None
    authority: dict[str, Any] | None = None
    horizon_years: int = Field(default=5, ge=1, le=40)
    knowledge_at: str | None = None

    @field_validator("observations", "quote_profiles", "holdings", "licence_snapshots", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")


_AUTHORITY = {"kind": "australian_credit_licence", "holder_ref": "holder-example", "authority_ref_sha256": "a1" * 32, "jurisdiction": "AU", "scope_verticals": ["AU-05"], "verified_at": "2026-09-01T00:00:00Z"}
_RUN_DATE = "2026-09-05"


def _product(product_name: str, taxonomy_class: str, rate_item: str, rate: str, *, annual_fee: str = "0", comparison_rate: str | None = None) -> dict[str, Any]:
    pricing = [{"item": rate_item, "value": rate, "unit": "% p.a.", "source_ids": ["s1"]}, {"item": "annual fee", "value": annual_fee, "unit": "AUD/year", "source_ids": ["s1"]}]
    if comparison_rate is not None:
        pricing.append({"item": "comparison rate", "value": comparison_rate, "unit": "% p.a.", "source_ids": ["s1"]})
    return {"provider_name": "Example Bank Ltd", "product_name": product_name, "taxonomy_class": taxonomy_class, "pricing_kind": "list", "confidence": "single_source", "eligibility": ["Applicant must be 18 years or older and an Australian permanent resident."], "pricing": pricing, "key_terms": [{"term": "maximum LVR", "value": "80", "source_ids": ["s1"]}], "sources": [{"source_id": "s1", "url": "https://example.test/rates", "retrieved_at": _RUN_DATE, "document_title": "Example rates and fees", "quote": f"{rate}% p.a."}]}


def _pack(vertical_id: str, product_name: str, taxonomy_class: str, rate_item: str, rate: str) -> dict[str, Any]:
    return {
        "registers": [{"register_name": "List of registered authorised deposit-taking institutions", "authority": "APRA", "jurisdiction": "Australia", "url": "https://www.apra.gov.au/registers", "retrieved_at": _RUN_DATE, "entry_count_calculated": 67}],
        "providers": [{"legal_name": "Example Bank Ltd", "trading_names": ["Example"], "provider_register_id": "123456", "register_id_type": "Australian credit licence", "registration_status": "registered", "product_discovery_status": "current_in_scope_products_extracted"}],
        "products": [{"provider_name": "Example Bank Ltd", "product_name": product_name, "taxonomy_class": taxonomy_class, "pricing_kind": "list", "confidence": "single_source", "eligibility": ["Applicant must be 18 years or older and an Australian permanent resident."], "pricing": [{"item": rate_item, "value": rate, "unit": "% p.a.", "source_ids": ["s1"]}, {"item": "annual fee", "value": "0", "unit": "AUD/year", "source_ids": ["s1"]}], "key_terms": [{"term": "maximum LVR", "value": "80", "source_ids": ["s1"]}], "sources": [{"source_id": "s1", "url": "https://example.test/rates", "retrieved_at": _RUN_DATE, "document_title": "Example rates and fees", "quote": f"{rate}% p.a."}]}],
        "coverage": {"vertical_id": vertical_id, "jurisdiction": "Australia", "run_date": _RUN_DATE, "providers_on_register": 67, "providers_captured": 1},
    }


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        home_loans = _pack("AU-05", "Example Variable Home Loan", "variable_home_loan", "variable interest rate", "5.99")
        cards = _pack("AU-04", "Example Low Rate Card", "low_rate_credit_card", "purchase interest rate", "12.99")
        packs = [("australia_residential_home_loans_batch_01_catalog_2026-09-05.json", home_loans), ("australia_credit_cards_batch_01_catalog_2026-09-05.json", cards)]
        provider_map, catalogs = build_provider_map(packs, built_at="2026-09-06T00:00:00Z")
        catalog = ingest_catalog_pack(home_loans)
        plan = compile_advice_plan("example-broker", jurisdiction="AU", mode="personal_recommendation", verticals=["AU-05"], authorities=[_AUTHORITY], remuneration_disclosure="The broker is paid a lender commission disclosed in the credit proposal.")
        state = client_state("client-example", jurisdiction="AU", vertical_id="AU-05", objective="An owner-occupied variable home loan at 70% LVR", personal_data_sha256="b2" * 32, disclosed_at="2026-09-05T00:00:00Z", fact_find_complete=True, amount="500000", lvr_percent="70", term_years=30, residency="citizen", purpose="owner_occupied", region="NSW")
        shortlist = shortlist_products(plan, state, catalog, as_of="2026-09-06T00:00:00Z")
        recommendation = prepare_recommendation(plan, shortlist, prepared_at="2026-09-06T01:00:00Z", prepared_by_ref="agent-advice-example")
        case = open_advice_case(plan, {**EXAMPLE_SCOPE, "entity_ref": "advice-case-example"}, receipt={"client_ref": "client-example", "vertical_id": "AU-05", "objective": "An owner-occupied variable home loan at 70% LVR"}, opened_at="2026-09-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = ADVICE_CASE_LIFECYCLE.seal_command({"event": "complete_fact_find", "transition_ref": f"complete_fact_find:{case.version}", "idempotency_key": f"complete_fact_find:{case.version}", "expected_version": case.version, "expected_state_digest": case.state_digest, "occurred_at": "2026-09-05T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": fact_find_receipt(state), "reason": None})
        base = {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR}
        built: dict[str, Any] = {
            "map": {**base, "packs": [{"file_name": name, "payload": payload} for name, payload in packs], "built_at": "2026-09-06T00:00:00Z"},
            "shortlist": {**base, "plan": plan.to_dict(), "client_state": state.to_dict(), "catalog": catalog.to_dict(), "as_of": "2026-09-06T00:00:00Z", "limit": 10},
            "recommend": {**base, "plan": plan.to_dict(), "shortlist": shortlist.to_dict(), "prepared_at": "2026-09-06T01:00:00Z", "prepared_by_ref": "agent-advice-example", "rationale": []},
            "market": {**base, "catalog": catalog.to_dict(), "include_product_cited": True},
            "queue": {**base, "provider_map": provider_map.to_dict(), "catalogs": {vertical_id: item.to_dict() for vertical_id, item in catalogs.items()}, "as_of": "2026-09-06T00:00:00Z", "max_age_days": 45},
            "open": {**base, "plan": plan.to_dict(), "entity_ref": "advice-case-example", "receipt": {"client_ref": "client-example", "vertical_id": "AU-05", "objective": "An owner-occupied variable home loan at 70% LVR"}, "opened_at": "2026-09-05T00:00:00Z"},
            "advance": {"plan": plan.to_dict(), "state": case.to_dict(), "command": command},
            "record": {**base, "plan": plan.to_dict(), "client_state": state.to_dict(), "shortlist": shortlist.to_dict(), "catalog": catalog.to_dict(), "recommendation": recommendation.to_dict(), "approval": {"approval_ref": "approval-example", "adviser_ref": "adviser-example", "authority_kind": "australian_credit_licence", "approved_at": "2026-09-06T02:00:00Z"}, "fact_find_gaps": [], "prepared_at": "2026-09-06T03:00:00Z"},
        }
        built.update(self._file(base, plan, home_loans))
        self._built = built
        return self._built

    def _file(self, base: dict[str, Any], plan: AdvicePlan, home_loans: dict[str, Any]) -> dict[str, Any]:
        """The rest of the adviser's file on the same AU-05 story: the same client and plan, a fuller fact find, and the pack's second loan as the alternative the record must consider."""

        products = [_product("Example Variable Home Loan", "variable_home_loan", "variable interest rate", "5.99", comparison_rate="6.02"), _product("Example Offset Home Loan", "variable_home_loan", "variable interest rate", "6.24", annual_fee="395", comparison_rate="6.41")]
        catalog = ingest_catalog_pack({**home_loans, "products": products})
        state = client_state("client-example", jurisdiction="AU", vertical_id="AU-05", objective="An owner-occupied variable home loan at 70% LVR", personal_data_sha256="b2" * 32, disclosed_at="2026-09-05T00:00:00Z", fact_find_complete=True, amount="500000", lvr_percent="70", term_years=30, residency="citizen", purpose="owner_occupied", region="NSW", income_band="150-200k", income="180000", income_basis="net", expenses="90000", debts="0", savings="45000", dependants=1, transaction="purchase")
        shortlist = shortlist_products(plan, state, catalog, as_of="2026-09-06T00:00:00Z")
        recommendation = prepare_recommendation(plan, shortlist, prepared_at="2026-09-06T01:00:00Z", prepared_by_ref="agent-advice-example")
        approval = {"approval_ref": "approval-example", "adviser_ref": "adviser-example", "authority_kind": "australian_credit_licence", "approved_at": "2026-09-06T02:00:00Z", "recommendation_digest": recommendation.recommendation_digest}
        product = next(item for item in catalog.products if item.product_ref == recommendation.primary_product_ref)
        verdict = serviceability(state, product, family="credit", as_of="2026-09-06T00:00:00Z")
        strategy = strategy_plan("client-example", state, prepared_at="2026-09-06T01:00:00Z", horizon_years=5, serviceability_verdicts=[verdict])
        given = [{"kind": kind, "document_digest": "d0" * 32, "given_at": "2026-09-04T00:00:00Z", "channel": "portal"} for kind in ("credit_guide", "privacy_collection_notice", "complaints_information")]
        consent = {"scope": ["advice_process", "data_collection"], "consented_at": "2026-09-04T00:00:00Z", "channel": "portal", "statement": "The client consented to the advice process and to the collection of the facts it needs."}
        engagement = engagement_pack("client-example", personal_data_sha256="b2" * 32, jurisdiction="AU", family="credit", verticals=["AU-05"], objectives={"AU-05": "An owner-occupied variable home loan at 70% LVR"}, given=given, consent=consent, prepared_at="2026-09-04T01:00:00Z")
        lender = provider_ref("AU", "Example Bank Ltd")
        source = {"source_id": "s1", "url": "https://example.test/broker-schedule", "retrieved_at": _RUN_DATE, "document_title": "Example broker remuneration schedule", "quote": "Upfront commission 0.65% of the settled amount"}
        schedule = remuneration_schedule("example-broker", jurisdiction="AU", lines=[{"provider_ref": lender, "kind": "upfront_commission", "rate_percent": "0.65", "payer": "provider", "basis": "of the settled amount", "source": source}, {"provider_ref": lender, "kind": "trail_commission", "rate_percent": "0.15", "payer": "provider", "basis": "of the balance each year", "source": source}], as_of="2026-09-06T00:00:00Z")
        register = conflicts_register("example-broker", [{"conflict_ref": "conflict-example", "kind": "referral_arrangement", "counterparty_ref": "counterparty-example", "applies_to_provider_refs": [lender], "disclosure_text": "The licensee receives referrals from an aggregator that also distributes this lender.", "management": "Disclosed in the credit guide; remuneration is not linked to volume.", "recorded_at": "2026-09-04T00:00:00Z"}], recorded_at="2026-09-06T00:00:00Z")
        remuneration = remuneration_disclosure(schedule, recommendation, shortlist, register=register, state=state, family="credit", horizon_years=1, prepared_at="2026-09-06T01:30:00Z")
        record = record_of_advice_evidence(plan, state, shortlist, catalog, recommendation=recommendation, approval=approval, prepared_at="2026-09-06T03:00:00Z", remuneration=remuneration.to_dict(), strategy=strategy.to_dict(), serviceability=[verdict.to_dict()])
        entry = {"kind": "australian_credit_licence", "jurisdiction": "AU", "licence_ref_sha256": "a1" * 32, "holder_name_as_stated": "Example Broking Pty Ltd", "status": "current", "authorisations": ["Engage in credit activities as a credit provider"], "expires_on": "2028-06-30", "source_url": "https://connectonline.asic.gov.au/", "quote": "Current"}
        snapshot = licence_register("ASIC professional registers", jurisdiction="AU", retrieved_at="2026-09-05T00:00:00Z", entries=[entry])
        verification = verify_authority(_AUTHORITY, snapshot, as_of="2026-09-06T00:00:00Z", vertical_id="AU-05", family="credit")
        summary = {"case_ref": "advice-case-example", "status": "implemented", "vertical_id": "AU-05", "objective": state.objective, "catalog_completeness": shortlist.catalog_completeness, "primary_product_ref": recommendation.primary_product_ref, "basis": recommendation.basis, "adviser_ref": "adviser-example", "authority_kind": "australian_credit_licence", "presented_at": "2026-09-07T00:00:00Z", "implemented_product_ref": recommendation.primary_product_ref, "review_due_at": "2027-09-08T00:00:00Z", "outcome": "implemented", "review_required": False, "fact_changes": []}
        return {
            "strategy": {**base, "client_ref": "client-example", "client_state": state.to_dict(), "prepared_at": "2026-09-06T01:00:00Z", "as_of": "2026-09-06T00:00:00Z", "horizon_years": 5, "products": [product.to_dict()], "family": "credit"},
            "engagement": {**base, "client_ref": "client-example", "personal_data_sha256": "b2" * 32, "jurisdiction": "AU", "family": "credit", "verticals": ["AU-05"], "objectives": {"AU-05": "An owner-occupied variable home loan at 70% LVR"}, "given": given, "consent": consent, "prepared_at": "2026-09-04T01:00:00Z", "vertical_id": "AU-05"},
            "remuneration": {**base, "schedule": schedule.to_dict(), "recommendation": recommendation.to_dict(), "shortlist": shortlist.to_dict(), "conflicts_register": register.to_dict(), "client_state": state.to_dict(), "family": "credit", "horizon_years": 1, "prepared_at": "2026-09-06T01:30:00Z"},
            "checklist": {**base, "plan": plan.to_dict(), "client_state": state.to_dict(), "shortlist": shortlist.to_dict(), "catalog": catalog.to_dict(), "recommendation": recommendation.to_dict(), "record": record.to_dict(), "verifications": [verification.to_dict()], "remuneration": remuneration.to_dict(), "engagement": engagement.to_dict(), "serviceability": verdict.to_dict(), "fact_find_gaps": [], "as_of": "2026-09-06T02:00:00Z"},
            "verify": {**base, "authority": dict(_AUTHORITY), "snapshot": snapshot.to_dict(), "as_of": "2026-09-06T00:00:00Z", "vertical_id": "AU-05", "family": "credit"},
            "record": {**base, "plan": plan.to_dict(), "client_state": state.to_dict(), "shortlist": shortlist.to_dict(), "catalog": catalog.to_dict(), "recommendation": recommendation.to_dict(), "approval": dict(approval), "fact_find_gaps": [], "remuneration": remuneration.to_dict(), "strategy": strategy.to_dict(), "serviceability": [verdict.to_dict()], "prepared_at": "2026-09-06T03:00:00Z"},
            "explanation": {**base, "record": record.to_dict(), "prepared_at": "2026-09-06T04:00:00Z"},
            "application": {**base, "recommendation": recommendation.to_dict(), "record": record.to_dict(), "client_state": state.to_dict(), "prepared_at": "2026-09-08T00:00:00Z", "prepared_by_ref": "agent-advice-example", "approval": approval, "case_ref": "advice-case-example"},
            "review": {**base, "plan": plan.to_dict(), "case_summary": summary, "record": record.to_dict(), "state_at_advice": state.to_dict(), "state_now": state.to_dict(), "catalog_now": catalog.to_dict(), "verifications": [verification.to_dict()], "serviceability_now": verdict.to_dict(), "engagement": engagement.to_dict(), "as_of": "2027-09-06T00:00:00Z"},
            "run": {**base, "entity_ref": "advice-case-run-example", "plan": plan.to_dict(), "engagement": engagement.to_dict(), "client_state": state.to_dict(), "catalog": catalog.to_dict(), "as_of": "2026-09-06T00:00:00Z", "prepared_by_ref": "agent-advice-example", "mode": "prepare_only", "remuneration_schedule": schedule.to_dict(), "conflicts_register": register.to_dict(), "licence_snapshots": [snapshot.to_dict()], "adviser_ref": "adviser-example", "authority": dict(_AUTHORITY)},
        }


_EXAMPLES = _Examples()


def example_advice_inputs() -> dict[str, Any]:
    return dict(_EXAMPLES.get())


def _blocked_code(exc: Exception) -> str:
    return str(getattr(exc, "code", None) or "ADVICE_INPUT_INVALID")


_EMBEDDED_CODE = re.compile(r"^\s*(?:Value error, )?([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+):", re.MULTILINE)


def _input_code(exc: Exception, fallback: str) -> str:
    """The refusal code a module raised as a plain ValueError (its own or through pydantic), so a fence refusal never flattens into a generic input error."""

    found = _EMBEDDED_CODE.search(str(exc))
    return found.group(1) if found else fallback


def _checklist_gaps(run: CaseRun) -> list[str]:
    """The labels of the checklist items the run left missing; empty when the run carried no checklist or answered every item."""

    checklist = run.artifacts.get("compliance_checklist") if isinstance(run.artifacts, Mapping) else None
    if not isinstance(checklist, Mapping) or checklist.get("complete") is not False:
        return []
    return [str(item.get("label") or item.get("key")) for item in checklist.get("items") or () if isinstance(item, Mapping) and item.get("status") == "missing"]


class BuildProviderMapPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.build_provider_map"
    version = "0.1.0"
    title = "Build the provider map from research packs"
    description = "Fold register-ordered research packs and census reconciliations into one sealed provider map: one identity per legal entity per jurisdiction, trading names as aliases, name collisions as candidates a person confirms, the merged catalog per vertical, and coverage against every register the packs name. Rebuilt from the packs, never edited."
    input_model = BuildProviderMapInput
    output_model = ProviderMap
    risk_level = "low"
    operation_spec = read_spec("finance_advice_build_provider_map", "sdk.finance_advice.build_provider_map")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "map")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_provider_map"
    loop_stages = ("map_providers",)
    profiles = _PROFILES
    hard_rules = {"identities_merge_only_on_legal_name_or_census_confirmation": True, "trading_names_are_aliases_never_entities": True, "rebuilt_from_packs_never_edited": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: BuildProviderMapInput) -> PrimitiveExecutionResult[ProviderMap]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            provider_map, catalogs = build_provider_map([(pack.file_name, pack.payload) for pack in inputs.packs], built_at=inputs.built_at)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="PACK_INVALID", message=str(exc))
        pending = sum(1 for item in provider_map.providers for candidate in item.candidate_matches if not candidate.confirmed)
        return self.preview(output=provider_map, digest=digest, external_refs={"map_digest": provider_map.map_digest, **{f"catalog_digest:{vertical_id}": catalog.catalog_digest for vertical_id, catalog in catalogs.items()}}, event_type="finance_advice.provider_map_built", event_payload={"packs": len(provider_map.packs), "providers": len(provider_map.providers), "verticals": [item.vertical_id for item in provider_map.verticals], "pending_name_matches": pending}, evidence_kind="finance_advice_provider_map", evidence_summary="Sealed provider map from the packs given; no register read here.", summary=f"{len(provider_map.providers)} legal entit{'y' if len(provider_map.providers) == 1 else 'ies'} across {len(provider_map.verticals)} vertical(s) from {len(provider_map.packs)} pack(s); {pending} name match(es) for a person to confirm.")


class ShortlistPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.shortlist"
    version = "0.1.0"
    title = "Shortlist products for a client state"
    description = "Every product the plan admits for one client state with a suitability verdict from the provider's structured terms and quoted eligibility, ranked only where supported list pricing exists; an eligibility restriction the fact find has not confirmed keeps a product listed but unranked. The catalog must be fresh and the fact find complete."
    input_model = ShortlistInput
    output_model = Shortlist
    risk_level = "low"
    operation_spec = read_spec("finance_advice_shortlist", "sdk.finance_advice.shortlist")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "shortlist")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_engine"
    loop_stages = ("fact_find", "shortlist")
    profiles = _PROFILES
    hard_rules = {"ranks_only_on_supported_list_pricing": True, "unconfirmed_restriction_stays_unranked": True, "stale_or_identity_only_catalog_refused": True, "client_state_carries_no_personal_data": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ShortlistInput) -> PrimitiveExecutionResult[Shortlist]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        view: Any = inputs.catalog
        if inputs.observations or inputs.apply_freshness:
            view = published_catalog(inputs.catalog, list(inputs.observations), as_of=inputs.as_of, knowledge_at=inputs.knowledge_at)
        try:
            shortlist = shortlist_products(inputs.plan, inputs.client_state, view, as_of=inputs.as_of, limit=inputs.limit)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="ADVICE_INPUT_INVALID", message=str(exc))
        return self.preview(output=shortlist, digest=digest, external_refs={"shortlist_digest": shortlist.shortlist_digest, "plan_digest": shortlist.plan_digest, "state_digest": shortlist.state_digest, "catalog_digest": shortlist.catalog_digest}, event_type="finance_advice.shortlisted", event_payload={"entries": len(shortlist.entries), "ranked": len(shortlist.ranked), "excluded": dict(shortlist.excluded), "catalog_completeness": shortlist.catalog_completeness}, evidence_kind="advice_shortlist", evidence_summary="Shortlist with suitability verdicts and disclosures; not a recommendation.", summary=f"{len(shortlist.entries)} candidate(s), {len(shortlist.ranked)} ranked, {sum(shortlist.excluded.values())} excluded; catalog {shortlist.catalog_completeness.replace('_', ' ')}.")


class PrepareRecommendationPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.prepare_recommendation"
    version = "0.1.0"
    title = "Prepare a recommendation for the adviser"
    description = "From a sealed shortlist, prepare the recommendation record a licensed adviser approves: in general-information mode it carries no product; in personal-recommendation mode it names the primary product only from the shortlist and only for an eligible or unassessed product, and an unranked shortlist needs the adviser to name the product and the rationale. Approval and presentation happen in the case lifecycle, never here."
    input_model = RecommendInput
    output_model = Recommendation
    risk_level = "medium"
    operation_spec = read_spec("finance_advice_prepare_recommendation", "sdk.finance_advice.prepare_recommendation")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "recommend")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_engine"
    loop_stages = ("recommend",)
    profiles = _PROFILES
    hard_rules = {"no_recommendation_outside_the_plans_authority": True, "primary_product_only_from_the_shortlist": True, "adviser_approval_required_before_presentation": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: RecommendInput) -> PrimitiveExecutionResult[Recommendation]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            recommendation = prepare_recommendation(inputs.plan, inputs.shortlist, prepared_at=inputs.prepared_at, prepared_by_ref=inputs.prepared_by_ref, primary_product_ref=inputs.primary_product_ref, rationale=list(inputs.rationale))
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="ADVICE_INPUT_INVALID", message=str(exc))
        return self.preview(output=recommendation, digest=digest, external_refs={"recommendation_digest": recommendation.recommendation_digest, "shortlist_digest": recommendation.shortlist_digest}, event_type="finance_advice.recommendation_prepared", event_payload={"basis": recommendation.basis, "primary_product_ref": recommendation.primary_product_ref, "alternatives": len(recommendation.alternatives)}, evidence_kind="advice_recommendation", evidence_summary="Prepared for the adviser's approval; nothing presented.", summary=f"Recommendation prepared on basis {recommendation.basis}" + (f" for {recommendation.primary_product_ref}" if recommendation.primary_product_ref else "") + "; awaits the adviser's approval.")


class MarketReportPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.market_report"
    version = "0.1.0"
    title = "Place every cited price on the market scale"
    description = "One market table per decision field the sector ranks on, built from a sealed catalog: every cited list figure on one scale with its support level and confidence, min, quartiles, median and max, and what was dropped because it was quote-dependent, unsupported, a range or another unit. Describes prices; never recommends."
    input_model = MarketReportInput
    output_model = MarketReport
    risk_level = "low"
    operation_spec = read_spec("finance_advice_market_report", "sdk.finance_advice.market_report")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "market")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_market"
    loop_stages = ("shortlist",)
    profiles = _PROFILES
    hard_rules = {"describes_prices_never_recommends": True, "quote_dependent_pricing_never_tabulated": True, "product_level_citations_labelled_never_promoted": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: MarketReportInput) -> PrimitiveExecutionResult[MarketReport]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            report = market_report(inputs.catalog, include_product_cited=inputs.include_product_cited)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="CATALOG_INVALID", message=str(exc))
        return self.preview(output=report, digest=digest, external_refs={"report_digest": report.report_digest, "catalog_digest": report.catalog_digest}, event_type="finance_advice.market_reported", event_payload={"tables": [{"label": table.label, "count": table.count, "lenders": table.lenders, "median": None if table.median is None else str(table.median)} for table in report.tables]}, evidence_kind="advice_market_report", evidence_summary="Cited list prices on one scale; no live price read.", summary=f"{len(report.tables)} table(s) over {report.vertical_id}: " + "; ".join(f"{table.label} {table.count} figure(s) from {table.lenders} lender(s)" for table in report.tables) + ".")


class ResearchQueuePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.research_queue"
    version = "0.1.0"
    title = "Queue the research the map still owes"
    description = "From a sealed provider map and its catalogs, the register-ordered batches the packs still owe each vertical: entities the map knows from other verticals but never ran, census identities with no product review, and providers whose products have gone stale, each with the pack brief and the extraction requests a research run is handed. A person hands a batch to the research run; nothing is called here."
    input_model = ResearchQueueInput
    output_model = ResearchQueue
    risk_level = "low"
    operation_spec = read_spec("finance_advice_research_queue", "sdk.finance_advice.research_queue")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "queue")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_research"
    loop_stages = ("map_providers",)
    profiles = _PROFILES
    hard_rules = {"register_order_never_web_search": True, "batch_cap_fifteen": True, "no_tool_called_here": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ResearchQueueInput) -> PrimitiveExecutionResult[ResearchQueue]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            queue = queue_from_map(inputs.provider_map, inputs.catalogs, as_of=inputs.as_of, max_age_days=inputs.max_age_days)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="MAP_INVALID", message=str(exc))
        return self.preview(output=queue, digest=digest, external_refs={"queue_digest": queue.queue_digest, "map_digest": queue.map_digest}, event_type="finance_advice.research_queued", event_payload={"batches": len(queue.batches), "providers_queued": queue.providers_queued, "kinds": sorted({batch.kind for batch in queue.batches})}, evidence_kind="advice_research_queue", evidence_summary="Batches and briefs for a research run; nothing executed.", summary=f"{len(queue.batches)} batch(es), {queue.providers_queued} provider run(s) queued as of {queue.as_of[:10]}.")


class OpenCasePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.open_case"
    version = "0.1.0"
    title = "Open an advice case"
    description = "Open the sealed advice case the lifecycle carries from intake to review: the client commitment, the vertical and the objective under a compiled plan. The case is what the platform persists and what every later transition (fact find, shortlist, recommendation, adviser approval, presentation, implementation, review) binds to."
    input_model = OpenCaseInput
    output_model = AdviceCaseState
    risk_level = "low"
    operation_spec = read_spec("finance_advice_open_case", "sdk.finance_advice.open_case")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "open")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_engine"
    loop_stages = ("fact_find",)
    profiles = _PROFILES
    hard_rules = {"intake_names_client_commitment_vertical_and_objective": True, "vertical_inside_the_plan": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: OpenCaseInput) -> PrimitiveExecutionResult[Any]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = AdvicePlan.model_validate(dict(inputs.plan))
            state = open_advice_case(plan, {**inputs.scope.to_dict(), "entity_ref": inputs.entity_ref}, receipt=inputs.receipt, opened_at=inputs.opened_at, actor_ref=inputs.requested_by_ref)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="CASE_INTAKE_INVALID", message=str(exc))
        return self.preview(output=state, digest=digest, external_refs={"entity_ref": inputs.entity_ref, "state_digest": state.state_digest, "plan_digest": plan.plan_digest}, event_type="finance_advice.case_opened", event_payload={"status": state.status, "vertical_id": state.ledger.vertical_id}, evidence_kind="finance_advice_case", evidence_summary="Advice case opened; nothing advised.", summary=f"Advice case {inputs.entity_ref} opened in {state.ledger.vertical_id}; status {state.status}.")


class AdvanceCasePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.advance_case"
    version = "0.1.0"
    title = "Advance an advice case by one transition"
    description = "Materialise one replay-fenced advice case transition with its receipt: complete the fact find (refused while required facts are missing), shortlist, recommend (refused outside the plan's authority or from a stale catalog), record the licensed adviser's approval (refused when stale, self-advised or unauthorised), present, implement the recommended product only, review, decline or withdraw."
    input_model = AdvanceCaseInput
    output_model = AdviceCaseTransition
    risk_level = "medium"
    operation_spec = read_spec("finance_advice_advance_case", "sdk.finance_advice.advance_case")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_engine"
    loop_stages = ("fact_find", "shortlist", "recommend", "adviser_approve", "present", "implement", "review")
    profiles = _PROFILES
    hard_rules = {"fact_find_gaps_refused": True, "recommendation_only_inside_the_plans_authority": True, "adviser_approval_binds_the_exact_recommendation": True, "only_the_recommended_product_is_implemented": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceCaseInput) -> PrimitiveExecutionResult[Any]:
        digest = request_digest(inputs.to_dict())
        scope_raw = dict(inputs.state.get("scope") or {})
        try:
            scope = RequestScope.model_validate({key: scope_raw.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")})
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_SCOPE_INVALID", message=str(exc))
        actor = str(inputs.command.get("actor_ref") or "")
        if not scope_matches(scope, actor, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the case scope and the command.")
        try:
            plan = AdvicePlan.model_validate(dict(inputs.plan))
            state = AdviceCaseState.model_validate(dict(inputs.state), context={ADVICE_CASE_LIFECYCLE.plan_context_key: plan})
            result = advance_advice_case(plan, state, inputs.command)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=str(scope_raw.get("entity_ref") or ""), event_prefix="finance_advice")


class RecordEvidencePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.record_evidence"
    version = "0.1.0"
    title = "Assemble the record-of-advice evidence"
    description = "Assemble everything the adviser's record of advice must draw on, sealed: scope, objectives and the decision facts, every alternative with its suitability and basis, the recommended product's facts cited to the provider's own documents, disclosures, remuneration, authority and approval, checked against the jurisdiction's requirement list. Evidence for the document, never the document, and no compliance claim."
    input_model = RecordEvidenceInput
    output_model = RecordOfAdviceEvidence
    risk_level = "low"
    operation_spec = read_spec("finance_advice_record_evidence", "sdk.finance_advice.record_evidence")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "record")
    golden_loop = ADVICE_GOLDEN_LOOP
    engine = "finance_advice_record"
    loop_stages = ("recommend", "adviser_approve", "present")
    profiles = _PROFILES
    hard_rules = {"evidence_never_the_document": True, "every_fact_cited_to_the_providers_document": True, "inputs_bound_by_digest": True}
    authority_boundary = _AUTHORITY_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: RecordEvidenceInput) -> PrimitiveExecutionResult[RecordOfAdviceEvidence]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            record = record_of_advice_evidence(inputs.plan, inputs.client_state, inputs.shortlist, inputs.catalog, recommendation=inputs.recommendation, approval=inputs.approval, fact_find_gaps=inputs.fact_find_gaps, prepared_at=inputs.prepared_at, switching=inputs.switching, needs=inputs.needs, benefit_fit=inputs.benefit_fit, rule_disclosures=inputs.rule_disclosures, remuneration=inputs.remuneration, strategy=inputs.strategy, serviceability=inputs.serviceability)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=str(exc).split(":", 1)[0] if str(exc).startswith("RECORD_") else "RECORD_INPUT_INVALID", message=str(exc))
        return self.preview(output=record, digest=digest, external_refs={"record_digest": record.record_digest, "shortlist_digest": record.shortlist_digest}, event_type="finance_advice.record_evidence_prepared", event_payload={"complete": record.complete, "missing": list(record.missing()), "requirements": len(record.requirements)}, evidence_kind="finance_advice_record_evidence", evidence_summary="Evidence for the adviser's record; the adviser writes and signs the document.", summary=("Record evidence complete" if record.complete else "Record evidence missing: " + ", ".join(record.missing())) + f" ({record.jurisdiction} {record.vertical_id}).")


class StrategyPlanPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.strategy_plan"
    version = "0.1.0"
    title = "Project the client's cash flow, goals and serviceability"
    description = "From the disclosed income, expenses, debts and savings: a year-by-year cash flow whose every default is written into the assumptions, emergency-fund and debt-free verdicts, a debt paydown order, the insurance sufficiency the facts support, and a serviceability verdict per product at the contract rate plus the jurisdiction's buffer, named as not yet confirmed by the operator while the rule row is unconfirmed. Arithmetic on stated facts; a missing fact is listed, never estimated, and nothing here recommends."
    input_model = StrategyPlanInput
    output_model = StrategyPlan
    risk_level = "low"
    operation_spec = read_spec("finance_advice_strategy_plan", "sdk.finance_advice.strategy_plan")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "strategy")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_strategy"
    loop_stages = ("fact_find", "shortlist")
    profiles = _PROFILES
    hard_rules = {"every_default_is_written_into_the_assumptions": True, "a_missing_fact_is_listed_never_estimated": True, "the_buffer_is_a_cited_rule_row_marked_unconfirmed": True, "verdicts_are_arithmetic_never_advice": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: StrategyPlanInput) -> PrimitiveExecutionResult[StrategyPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            verdicts = [serviceability(inputs.client_state, product, family=inputs.family, as_of=inputs.as_of) for product in inputs.products]
            plan = strategy_plan(inputs.client_ref, inputs.client_state, prepared_at=inputs.prepared_at, horizon_years=inputs.horizon_years, assumptions=dict(inputs.assumptions) or None, serviceability_verdicts=verdicts)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "STRATEGY_INPUT_INVALID"), message=str(exc))
        goals = {item.goal: item.status for item in plan.cashflow.goals}
        return self.preview(output=plan, digest=digest, external_refs={"strategy_digest": plan.strategy_digest, "state_digest": plan.state_digest, "projection_digest": plan.cashflow.projection_digest}, event_type="finance_advice.strategy_planned", event_payload={"horizon_years": plan.horizon_years, "goals": goals, "serviceability": [item.verdict for item in plan.serviceability], "assumptions": len(plan.assumptions), "missing": list(plan.missing)}, evidence_kind="finance_advice_strategy_plan", evidence_summary="Cash flow, goals and serviceability from the stated facts; every assumption named, nothing recommended.", summary=f"{plan.horizon_years}-year projection with {len(plan.assumptions)} assumption(s)" + (f" and {len(plan.missing)} missing fact(s)" if plan.missing else "") + "; goals " + ", ".join(f"{goal} {status}" for goal, status in sorted(goals.items())) + ".")


class ComplianceChecklistPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.compliance_checklist"
    version = "0.1.0"
    title = "Evaluate the case's compliance checklist and its approval pack"
    description = "The operator's own steps for the case's jurisdiction and family, answered only from the sealed objects the case already produced: each item evidenced, missing, not applicable, or a confirmation only the licensed adviser can make, each naming the digest it read. An evaluated checklist, never a regulatory determination. When the checklist carries a recommendation and a record, the approval pack names exactly the four digests the adviser's approval request binds; a refused or mismatched licence verification is refused here rather than reaching the adviser."
    input_model = ComplianceChecklistInput
    output_model = ComplianceChecklist
    risk_level = "low"
    operation_spec = read_spec("finance_advice_compliance_checklist", "sdk.finance_advice.compliance_checklist")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "checklist")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_compliance"
    loop_stages = ("recommend", "adviser_approve")
    profiles = _PROFILES
    hard_rules = {"every_item_names_the_sealed_object_it_read": True, "evidence_never_a_compliance_claim": True, "a_refused_verification_never_enters_an_approval_pack": True, "the_adviser_confirms_what_the_platform_cannot": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ComplianceChecklistInput) -> PrimitiveExecutionResult[ComplianceChecklist]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            checklist = compliance_checklist(inputs.plan, inputs.client_state, inputs.shortlist, inputs.catalog, recommendation=inputs.recommendation, record=inputs.record, switching=list(inputs.switching), verifications=list(inputs.verifications), remuneration=inputs.remuneration, engagement=inputs.engagement, serviceability=inputs.serviceability, needs=inputs.needs, fact_find_gaps=list(inputs.fact_find_gaps), as_of=inputs.as_of)
            pack: dict[str, Any] | None = None
            if checklist.recommendation_digest is not None and checklist.record_digest is not None:
                verification = verification_for(inputs.plan, list(inputs.verifications), vertical_id=checklist.vertical_id, as_of=inputs.as_of)
                pack = approval_pack(checklist, verification=verification)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "CHECKLIST_INPUT_INVALID"), message=str(exc))
        refs = {"checklist_digest": checklist.checklist_digest, "plan_digest": checklist.plan_digest, "state_digest": checklist.state_digest, "shortlist_digest": checklist.shortlist_digest}
        blocker = None
        if pack is not None:
            refs.update({key: str(pack[key]) for key in ("recommendation_digest", "record_digest") if pack.get(key)})
            if pack.get("verification_digest"):
                refs["verification_digest"] = str(pack["verification_digest"])
            if not checklist.complete:
                blocker = PrimitiveBlocker(code="CHECKLIST_INCOMPLETE", message=("the compliance checklist still lacks " + ", ".join(checklist.missing()))[:500], retryable=False)
        return self.preview(blocker=blocker, output=checklist, digest=digest, external_refs=refs, event_type="finance_advice.compliance_checklist_evaluated", event_payload={"complete": checklist.complete, "evidenced": checklist.evidenced, "missing": list(checklist.missing()), "confirmations": list(checklist.confirmations()), "approval_pack": pack is not None, "regimes": sorted({item.regime for item in checklist.items})}, evidence_kind="finance_advice_compliance_checklist", evidence_summary="The operator's own steps evaluated from sealed objects; the licensed adviser confirms it, and it is not a regulatory determination.", summary=(f"{checklist.evidenced} of {len(checklist.items)} item(s) evidenced" + ("" if checklist.complete else "; still missing " + ", ".join(checklist.missing()))) + f" ({checklist.jurisdiction} {checklist.vertical_id}).")


class RemunerationDisclosurePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.remuneration_disclosure"
    version = "0.1.0"
    title = "State in figures what the adviser is paid on the recommendation"
    description = "From the licensee's own remuneration schedule, cited line by line to its own document: what the adviser earns on the recommended product and on each alternative the shortlist carried, the conflicts register entries that reach the recommended provider or product, and the findings a checklist reads (no schedule line for the recommended product, a recommendation that pays more than every alternative, a conflicted kind for the family, an undisclosed conflict, a commission over an unconfirmed cap). Figures and findings, never a decision."
    input_model = RemunerationDisclosureInput
    output_model = RemunerationDisclosure
    risk_level = "low"
    operation_spec = read_spec("finance_advice_remuneration_disclosure", "sdk.finance_advice.remuneration_disclosure")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "remuneration")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_remuneration"
    loop_stages = ("recommend",)
    profiles = _PROFILES
    hard_rules = {"every_line_cited_to_the_licensees_own_document": True, "counterparties_are_opaque_refs_never_names": True, "describes_and_flags_never_decides": True, "caps_stay_unconfirmed_until_the_operator_confirms_them": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: RemunerationDisclosureInput) -> PrimitiveExecutionResult[RemunerationDisclosure]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            disclosure = remuneration_disclosure(inputs.schedule, inputs.recommendation, inputs.shortlist, register=inputs.conflicts_register, state=inputs.client_state, family=inputs.family, horizon_years=inputs.horizon_years, amount=inputs.amount, prepared_at=inputs.prepared_at)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "REMUNERATION_INPUT_INVALID"), message=str(exc))
        return self.preview(output=disclosure, digest=digest, external_refs={"disclosure_digest": disclosure.disclosure_digest, "schedule_digest": disclosure.schedule_digest, "recommendation_digest": disclosure.recommendation_digest, "shortlist_digest": disclosure.shortlist_digest}, event_type="finance_advice.remuneration_disclosed", event_payload={"clear": disclosure.clear, "findings": list(disclosure.findings), "alternatives": len(disclosure.alternatives), "conflicts": len(disclosure.conflicts), "statements": len(disclosure.statements)}, evidence_kind="finance_advice_remuneration_disclosure", evidence_summary="What the adviser is paid, cited to the licensee's own schedule; the disclosure describes and flags, it decides nothing.", summary=("No finding beyond the fee basis" if disclosure.clear else "Findings: " + ", ".join(disclosure.findings)) + f"; {len(disclosure.alternatives)} alternative(s) priced, {len(disclosure.conflicts)} conflict(s) carried.")


class EngagementPackPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.engagement_pack"
    version = "0.1.0"
    title = "Assemble the pre-advice engagement file and name its gaps"
    description = "What the client was given before advice and consented to: the disclosure kinds the jurisdiction and family require, each recorded by document digest, channel and date, the consent and its scope, the fee arrangement with its renewal date, and the scored risk profile where investments need one. The SDK holds no document text and no signature, only digests and opaque refs; a pack with a gap is returned with the gap named and refused as an opening receipt."
    input_model = EngagementPackInput
    output_model = EngagementPack
    risk_level = "low"
    operation_spec = read_spec("finance_advice_engagement_pack", "sdk.finance_advice.engagement_pack")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "engagement")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_engagement"
    loop_stages = ("fact_find",)
    profiles = _PROFILES
    hard_rules = {"the_sdk_holds_the_documents_digest_never_its_text": True, "consent_carries_no_signature_or_contact_data": True, "a_case_never_opens_past_an_engagement_gap": True, "nothing_is_sent_to_the_client_here": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: EngagementPackInput) -> PrimitiveExecutionResult[EngagementPack]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            pack = engagement_pack(inputs.client_ref, personal_data_sha256=inputs.personal_data_sha256, jurisdiction=inputs.jurisdiction, family=inputs.family, verticals=list(inputs.verticals), objectives=dict(inputs.objectives), given=list(inputs.given), consent=inputs.consent, fee_arrangement=inputs.fee_arrangement, risk_profile=inputs.risk_profile, scope_exclusions=list(inputs.scope_exclusions), prepared_at=inputs.prepared_at)
            gaps = engagement_gaps(pack, vertical_id=inputs.vertical_id)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "ENGAGEMENT_INPUT_INVALID"), message=str(exc))
        blocker = None
        if gaps:
            blocker = PrimitiveBlocker(code="ENGAGEMENT_INCOMPLETE", message=("the engagement lacks " + "; ".join(gaps))[:500], retryable=False)
        else:
            engagement_receipt(pack)
        return self.preview(output=pack, digest=digest, external_refs={"engagement_digest": pack.engagement_digest}, event_type="finance_advice.engagement_assembled", event_payload={"complete": pack.complete, "required": list(pack.required), "missing": list(pack.missing), "gaps": list(gaps), "risk_band": None if pack.risk_profile is None else pack.risk_profile.band}, evidence_kind="finance_advice_engagement_pack", evidence_summary="What the client was given and consented to before advice, by digest; no document text and no signature enter the SDK.", summary=(f"{len(pack.given)} disclosure(s) recorded; engagement complete" if not gaps else f"{len(pack.given)} disclosure(s) recorded; the engagement lacks " + "; ".join(gaps)) + ".", blocker=blocker)


class ClientExplanationPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.client_explanation"
    version = "0.1.0"
    title = "Write the client's explanation from the record alone"
    description = "The plain-words explanation of the record: what is recommended, why, what it costs, what changes, what the client must do, the risks and warnings, and how the adviser is paid. Every paragraph cites a fact reference from the record, every number appears in a cited fact, and every product named is in the record; the default path is the template renderer, so no model runs. A record with no recommendation is refused, never filled in, and the rendered document carries the explanation watermark until the adviser approves what it explains."
    input_model = ClientExplanationInput
    output_model = ClientExplanation
    risk_level = "low"
    operation_spec = read_spec("finance_advice_client_explanation", "sdk.finance_advice.client_explanation")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "explanation")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_prose"
    loop_stages = ("adviser_approve", "present")
    profiles = _PROFILES
    hard_rules = {"every_paragraph_cites_the_record": True, "every_number_is_a_cited_figure": True, "no_model_runs_on_the_default_path": True, "nothing_is_explained_that_the_record_does_not_say": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ClientExplanationInput) -> PrimitiveExecutionResult[ClientExplanation]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            explanation = deterministic_explanation(inputs.record, prepared_at=inputs.prepared_at, jurisdiction_terms=dict(inputs.jurisdiction_terms) or None)
            document = explanation_document(explanation, prepared_at=inputs.prepared_at, retain_until=inputs.retain_until)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "EXPLANATION_INPUT_INVALID"), message=str(exc))
        return self.preview(output=explanation, digest=digest, external_refs={"explanation_digest": explanation.explanation_digest, "record_digest": explanation.record_digest, "draft_digest": explanation.draft_digest, "validation_digest": explanation.validation_digest, "document_digest": document.document_digest}, event_type="finance_advice.client_explanation_written", event_payload={"drafter": explanation.drafter, "paragraphs": len(explanation.paragraphs), "footnotes": len(explanation.footnotes), "document_complete": document.complete}, evidence_kind="finance_advice_client_explanation", evidence_summary="The record explained in plain words, every sentence cited to it; not advice until the licensed adviser approves the recommendation it explains.", summary=f"{len(explanation.paragraphs)} paragraph(s) citing {len(explanation.footnotes)} record fact(s), written by the {explanation.drafter} renderer.")


class ApplicationPackPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.application_pack"
    version = "0.1.0"
    title = "Assemble the application pack for the approved recommendation"
    description = "After the adviser's approval of exactly this recommendation: the provider's application items, the documents the client must sign, the steps that belong to the adviser and to the provider, the recommended product's terms each citing the record, and any provider write kept as a proposal the SDK never executes. Decision facts only, identity keys refused, identity verification an adviser step performed outside. Given the provider's outcome, the pack reconciles the terms as stated against the terms the recommendation rested on; an incomplete outcome, an unacknowledged material difference or a ranked figure that moved is refused rather than implemented quietly."
    input_model = ApplicationPackInput
    output_model = ApplicationPack
    risk_level = "medium"
    operation_spec = read_spec("finance_advice_application_pack", "sdk.finance_advice.application_pack")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "application")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_implementation"
    loop_stages = ("implement",)
    profiles = _PROFILES
    hard_rules = {"only_the_recommended_product_under_an_approval_of_that_recommendation": True, "the_sdk_never_writes_to_a_provider": True, "decision_facts_only_no_identity_keys": True, "material_term_differences_need_the_advisers_acknowledgement": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ApplicationPackInput) -> PrimitiveExecutionResult[ApplicationPack]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        reconciliation: Any = None
        receipt: dict[str, Any] | None = None
        blocker = None
        try:
            pack = application_pack(inputs.recommendation, inputs.record, inputs.client_state, prepared_at=inputs.prepared_at, prepared_by_ref=inputs.prepared_by_ref, items=list(inputs.items), write_proposals=list(inputs.write_proposals), approval=inputs.approval, holdings=list(inputs.holdings), case_ref=inputs.case_ref, provider_ref=inputs.provider_ref)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "APPLICATION_INPUT_INVALID"), message=str(exc))
        if inputs.outcome is not None:
            try:
                reconciliation = reconcile_terms(pack, inputs.outcome, inputs.record)
                receipt = implementation_receipt(pack, inputs.outcome, reconciliation=reconciliation, differences_acknowledged_ref=inputs.differences_acknowledged_ref)
            except _ERRORS as exc:
                blocker = PrimitiveBlocker(code=_blocked_code(exc), message=str(exc)[:500], retryable=False)
            except ValueError as exc:
                blocker = PrimitiveBlocker(code=_input_code(exc, "IMPLEMENTATION_INPUT_INVALID"), message=str(exc)[:500], retryable=False)
        refs = {"pack_digest": pack.pack_digest, "recommendation_digest": pack.recommendation_digest, "record_digest": pack.record_digest, "product_ref": pack.product_ref}
        if receipt is not None:
            refs.update({"implementation_digest": str(receipt["implementation_digest"]), "reconciliation_digest": str(receipt.get("reconciliation_digest") or "")})
        elif reconciliation is not None:
            refs["reconciliation_digest"] = str(reconciliation.reconciliation_digest)
        outstanding = [item.label for item in pack.items if item.required and item.status == "pending"]
        differences = [] if reconciliation is None else [{"item": item.item, "recommended": item.recommended_value, "implemented": item.implemented_value, "material": item.material} for item in reconciliation.differences]
        verdict = receipt.get("reconciliation_verdict") if receipt is not None else (None if reconciliation is None else reconciliation.verdict)
        return self.preview(blocker=blocker, output=pack, digest=digest, external_refs={key: value for key, value in refs.items() if value}, event_type="finance_advice.application_pack_prepared", event_payload={"items": len(pack.items), "signatures_required": list(pack.signatures_required), "write_proposals": len(pack.write_proposals), "outstanding": outstanding, "reconciliation_verdict": verdict, "differences": differences}, evidence_kind="finance_advice_application_pack", evidence_summary="What the client, the adviser and the provider must each do; a provider write is a stored proposal, never executed here.", summary=f"{len(pack.items)} item(s), {len(pack.signatures_required)} signature(s) required, {len(pack.write_proposals)} stored write proposal(s) for {pack.product_ref}" + ("" if blocker is None else f"; the outcome is refused: {blocker.code}") + ".")


class ReviewAssessmentPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.review_assessment"
    version = "0.1.0"
    title = "Assess whether the advice already given still holds"
    description = "What changed since the advice and what it means: the diff of the client's decision facts with the ranked fields flagged, the triggers (review due, a flagged case, a pending fact impact, an expiring authority, a fee consent renewal, an expired quote, a declared life event), and the rechecks of the implemented product's cited facts, its suitability, the serviceability and the disclosures. The outcome is advice holds, the adviser confirms, the client re-discloses, or re-advice; re-advice is a successor case named on the receipt, because the advice already given is never rewritten."
    input_model = ReviewAssessmentInput
    output_model = ReviewAssessment
    risk_level = "low"
    operation_spec = read_spec("finance_advice_review_assessment", "sdk.finance_advice.review_assessment")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "review")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_review"
    loop_stages = ("review",)
    profiles = _PROFILES
    hard_rules = {"advice_already_given_is_never_rewritten": True, "re_advice_opens_a_successor_case": True, "every_recheck_names_the_cited_fact_it_read": True, "the_assessment_asks_the_adviser_it_never_decides": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: ReviewAssessmentInput) -> PrimitiveExecutionResult[ReviewAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = review_assessment(inputs.plan, dict(inputs.case_summary), inputs.record, state_at_advice=inputs.state_at_advice, state_now=inputs.state_now, catalog_now=inputs.catalog_now, needs_now=inputs.needs_now, serviceability_now=inputs.serviceability_now, engagement=inputs.engagement, verifications=list(inputs.verifications), quotes=list(inputs.quotes), impacts=list(inputs.impacts), reconciliation=inputs.reconciliation, life_events=list(inputs.life_events), as_of=inputs.as_of)
            receipt = review_receipt(assessment, outcome_note=inputs.outcome_note, successor_case_ref=inputs.successor_case_ref)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "REVIEW_INPUT_INVALID"), message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest, "record_digest": assessment.record_digest, "diff_digest": assessment.diff.diff_digest, "recommendation_digest": assessment.recommendation_digest}, event_type="finance_advice.review_assessed", event_payload={"outcome": assessment.outcome, "triggers": [item.kind for item in assessment.triggers], "checks_not_holding": [item.key for item in assessment.checks if item.status != "holds"], "next_review_due_at": receipt["next_review_due_at"], "successor_case_ref": receipt["successor_case_ref"]}, evidence_kind="finance_advice_review_assessment", evidence_summary="What changed and what still holds, read from the sealed record and the current catalog; the advice already given is untouched.", summary=f"{assessment.outcome}: {len(assessment.triggers)} trigger(s), {len([item for item in assessment.checks if item.status != 'holds'])} check(s) not holding.")


class VerifyAuthorityPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.verify_authority"
    version = "0.1.0"
    title = "Verify the adviser's authority against a register snapshot"
    description = "One authority checked against one register snapshot the caller already captured: the commitment matches an entry, the entry's status is current, its authorisations reach the vertical's family, and the snapshot is fresh enough. The verdict is verified, refused or unassessed with every finding named; the authority and the holder stay opaque refs and commitments. No register is read here, and a verdict other than verified is returned with the refusal, never treated as an authority."
    input_model = VerifyAuthorityInput
    output_model = AuthorityVerification
    risk_level = "low"
    operation_spec = read_spec("finance_advice_verify_authority", "sdk.finance_advice.verify_authority")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "verify")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_licence"
    loop_stages = ("adviser_approve",)
    profiles = _PROFILES
    hard_rules = {"no_register_is_read_here": True, "identities_are_commitments_never_names": True, "a_stale_snapshot_never_verifies": True, "only_a_verified_authority_reaches_an_approval": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: VerifyAuthorityInput) -> PrimitiveExecutionResult[AuthorityVerification]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            verification = verify_authority(inputs.authority, inputs.snapshot, as_of=inputs.as_of, vertical_id=inputs.vertical_id, family=inputs.family, max_register_age_hours=inputs.max_register_age_hours, expiring_soon_days=inputs.expiring_soon_days)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "VERIFICATION_INPUT_INVALID"), message=str(exc))
        blocker = None if verification.verified else PrimitiveBlocker(code="AUTHORITY_UNVERIFIED", message=(f"the authority is {verification.verdict}: " + ", ".join(verification.reasons or verification.findings))[:500], retryable=False)
        return self.preview(output=verification, digest=digest, external_refs={"verification_digest": verification.verification_digest, "authority_ref_sha256": verification.authority_ref_sha256}, event_type="finance_advice.authority_verified", event_payload={"verdict": verification.verdict, "findings": list(verification.findings), "register_name": verification.register_name, "expires_on": verification.expires_on}, evidence_kind="finance_advice_authority_verification", evidence_summary="One authority against one captured register snapshot; no register was read here.", summary=f"{verification.authority_kind} {verification.verdict}" + (f": {', '.join(verification.findings)}" if verification.findings else "") + ".", blocker=blocker)


class RunCasePrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_advice.run_case"
    version = "0.1.0"
    title = "Run one advice case from engagement to the adviser's file"
    description = "The whole file composed in order over a caller-held case store: the engagement gate, the fact find (stopping with the questions still owed), strategy and serviceability, the published-view shortlist with any matched quotes, stay-or-switch, needs and jurisdiction rules, a recommendation whose rationale is composed only from sealed basis strings, the record with its remuneration disclosure, the licence verification, the compliance checklist, the document and the template explanation. This preview prepares only: it opens no approval request, calls no model and touches no provider, and every stop is a typed code on the run rather than an exception."
    input_model = RunCaseInput
    output_model = CaseRun
    risk_level = "medium"
    operation_spec = read_spec("finance_advice_run_case", "sdk.finance_advice.run_case")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "run")
    golden_loop = ADVICE_FULL_LOOP
    engine = "finance_advice_case_runner"
    loop_stages = ADVICE_STAGES
    profiles = _PROFILES
    hard_rules = {"prepare_only_no_approval_is_requested_from_a_preview": True, "no_model_anywhere_in_the_runner": True, "the_recommendation_still_waits_for_the_advisers_platform_approval": True, "every_stage_is_bound_to_the_previous_one_by_digest": True}
    authority_boundary = _FILE_BOUNDARY

    def _execute(self, context: PrimitiveExecutionContext, inputs: RunCaseInput) -> PrimitiveExecutionResult[CaseRun]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = AdvicePlan.model_validate(dict(inputs.plan))
            runtime = advice_case_runtime(plan, InMemoryEngineStateStore())
            run = run_case(plan, runtime=runtime, entity_ref=inputs.entity_ref, scope=inputs.scope.to_dict(), engagement=inputs.engagement, state=inputs.client_state, catalog=inputs.catalog, as_of=inputs.as_of, actor_ref=inputs.requested_by_ref, prepared_by_ref=inputs.prepared_by_ref, observations=list(inputs.observations), quote_profiles=list(inputs.quote_profiles), holdings=list(inputs.holdings), remuneration_schedule=inputs.remuneration_schedule, conflicts_register=inputs.conflicts_register, licence_snapshots=list(inputs.licence_snapshots), adviser_ref=inputs.adviser_ref, authority=inputs.authority, mode="prepare_only", horizon_years=inputs.horizon_years, knowledge_at=inputs.knowledge_at)
        except _ERRORS as exc:
            return self.blocked(digest=digest, code=_blocked_code(exc), message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code=_input_code(exc, "RUN_INPUT_INVALID"), message=str(exc))
        blocker = None
        if run.refusal:
            blocker = PrimitiveBlocker(code=str(run.refusal.get("code") or "RUN_REFUSED"), message=(str(run.refusal.get("message") or "") or f"the case run stopped at {run.stage_reached}")[:500], retryable=run.stop == "needs_input")
        # prepare_only returns before the case's own checklist gate, so a run that reached the
        # approval request with an incomplete checklist (an unverified authority above all) would
        # otherwise preview as cleanly prepared. Name it here, keeping the run it could seal.
        outstanding = _checklist_gaps(run)
        if blocker is None and outstanding:
            blocker = PrimitiveBlocker(code="CHECKLIST_INCOMPLETE", message=("the case is prepared but its compliance checklist still lacks " + "; ".join(outstanding))[:500], retryable=False)
        refs = {key: str(getattr(run, key)) for key in ("run_digest", "engagement_digest", "state_digest", "strategy_digest", "shortlist_digest", "recommendation_digest", "record_digest", "remuneration_digest", "verification_digest", "checklist_digest", "document_digest", "explanation_digest") if getattr(run, key, None)}
        return self.preview(output=run, digest=digest, external_refs={"entity_ref": run.entity_ref, **refs}, event_type="finance_advice.case_run_prepared", event_payload={"stop": run.stop, "stage_reached": run.stage_reached, "status": run.status, "artifacts": sorted(run.artifacts), "questions_owed": [item["fact"] for item in run.questions_owed], "refusal": run.refusal.get("code") if run.refusal else None, "checklist_missing": outstanding, "authority_verified": bool(getattr(run, "verification_digest", None))}, evidence_kind="finance_advice_case_run", evidence_summary="One case prepared over a caller-held store; nothing was presented, implemented or approved here.", summary=f"Case {run.entity_ref} stopped at {run.stage_reached} ({run.stop})" + (f": {run.refusal.get('code')}" if run.refusal else "") + (f"; the checklist still lacks {'; '.join(outstanding)}" if outstanding and not run.refusal else "") + ".", blocker=blocker)


ADVICE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (BuildProviderMapPrimitive(), ShortlistPrimitive(), PrepareRecommendationPrimitive(), MarketReportPrimitive(), ResearchQueuePrimitive(), OpenCasePrimitive(), AdvanceCasePrimitive(), RecordEvidencePrimitive(), EngagementPackPrimitive(), StrategyPlanPrimitive(), RemunerationDisclosurePrimitive(), ComplianceChecklistPrimitive(), VerifyAuthorityPrimitive(), ClientExplanationPrimitive(), ApplicationPackPrimitive(), ReviewAssessmentPrimitive(), RunCasePrimitive())

ADVICE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "finance_advice",
    "golden_loop": ADVICE_GOLDEN_LOOP,
    "golden_loops": [ADVICE_GOLDEN_LOOP, ADVICE_FULL_LOOP],
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "finance_advice_engine", "golden_loop": ADVICE_GOLDEN_LOOP, "stages": list(ADVICE_STAGES), "required_connectors": ["deep_research", "lightbulb.approvals"]},
    "modules": {"catalog": "lightbulb.finance_advice_catalog", "engine": "lightbulb.finance_advice_engine", "research": "lightbulb.finance_advice_research", "provider_map": "lightbulb.finance_advice_provider_map", "market": "lightbulb.finance_advice_market", "projection": "lightbulb.finance_advice_projection", "fact_find": "lightbulb.finance_advice_fact_find", "record": "lightbulb.finance_advice_record", "primitives": "lightbulb.finance_advice_primitives", "core": "lightbulb.company_engine_core", "engagement": "lightbulb.finance_advice_engagement", "strategy": "lightbulb.finance_advice_strategy", "remuneration": "lightbulb.finance_advice_remuneration", "compliance": "lightbulb.finance_advice_compliance", "licence": "lightbulb.finance_advice_licence", "prose": "lightbulb.finance_advice_prose", "implementation": "lightbulb.finance_advice_implementation", "review": "lightbulb.finance_advice_review", "cases": "lightbulb.finance_advice_cases", "case_runner": "lightbulb.finance_advice_case_runner"},
    "reuses": ["company_engine_core lifecycle and sealing", "deep_research.research_query as the extraction tool", "MCP list_engine_approvals / decide_engine_approval for the adviser's approval"],
    "required_connectors": ["deep_research", "lightbulb.approvals"],
    "primitive_refs": [item.primitive_ref for item in ADVICE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no personal financial advice from the platform", "no register read or provider call here", "no provider write performed by the SDK", "no model on the advice path", "no certification or production-readiness claim"],
}

__all__ = [
    "ADVICE_EXECUTABLE_PRIMITIVES",
    "ADVICE_FULL_LOOP",
    "ADVICE_GOLDEN_LOOP",
    "ADVICE_INTEGRATION_MANIFEST",
    "ADVICE_STAGES",
    "AdvanceCaseInput",
    "AdvanceCasePrimitive",
    "ApplicationPackInput",
    "ApplicationPackPrimitive",
    "BuildProviderMapInput",
    "BuildProviderMapPrimitive",
    "ClientExplanationInput",
    "ClientExplanationPrimitive",
    "ComplianceChecklistInput",
    "ComplianceChecklistPrimitive",
    "EngagementPackInput",
    "EngagementPackPrimitive",
    "MarketReportInput",
    "MarketReportPrimitive",
    "OpenCaseInput",
    "OpenCasePrimitive",
    "PackFile",
    "PrepareRecommendationPrimitive",
    "RecommendInput",
    "RecordEvidenceInput",
    "RecordEvidencePrimitive",
    "RemunerationDisclosureInput",
    "RemunerationDisclosurePrimitive",
    "ResearchQueueInput",
    "ResearchQueuePrimitive",
    "ReviewAssessmentInput",
    "ReviewAssessmentPrimitive",
    "RunCaseInput",
    "RunCasePrimitive",
    "ShortlistInput",
    "ShortlistPrimitive",
    "StrategyPlanInput",
    "StrategyPlanPrimitive",
    "VerifyAuthorityInput",
    "VerifyAuthorityPrimitive",
    "example_advice_inputs",
]
