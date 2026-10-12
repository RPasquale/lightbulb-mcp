"""The compliance file: a per-case checklist of the operator's own steps, answered from the sealed objects the case produced.

An adviser's file has to show that the steps the business set for itself were taken: the client's
objectives and situation were identified and the gaps chased, the subject matter was scoped, the
investigation was reasonable, the judgement rested on the client's circumstances, the adviser's
own interest came second, replacements and remuneration were disclosed, the authority was current,
and the record is complete. In Australia the credit steps are shaped differently (an inquiry into
requirements and financial situation and an assessment that the product is not unsuitable); in
Canada the steps are know-your-client, know-your-product, a suitability determination, the cost of
borrowing for credit, and the mortgage broker's lender comparison and disclosure.

This module keeps those steps as static tables per regime and answers each one from what the
case already sealed: the plan, the client state, the shortlist, the catalog, the recommendation,
the record of advice evidence, the switching analyses, the licence verifications, the remuneration
disclosure, the engagement pack, the serviceability verdict and the needs assessment. Every item
names the object it read by digest. Items the SDK cannot answer are handed to the adviser as a
confirmation, never assumed. The result is a sealed checklist with a disclaimer and an approval
pack that names exactly the digests the adviser's approval binds to.

It is evidence. It certifies nothing and it is not a regulatory determination; the licensed
adviser confirms it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, ShortText, StrictModel, detached, parsed, reject_secret_like_payload, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_catalog import ProductCatalog, load_vertical_registry
from lightbulb.finance_advice_engine import AdvicePlan, ClientState, Recommendation, Shortlist, ShortlistEntry, sector_family
from lightbulb.finance_advice_fact_find import fact_find_gaps
from lightbulb.finance_advice_licence import DEFAULT_REGISTER_MAX_AGE_HOURS

COMPLIANCE_SCHEMA = "lightbulb.finance_advice_compliance_checklist.v1"
APPROVAL_PACK_SCHEMA = "lightbulb.finance_advice_approval_pack.v1"
VERIFICATION_MAX_AGE_DAYS = DEFAULT_REGISTER_MAX_AGE_HOURS // 24
DISCLAIMER = "An evaluated checklist of the operator's own steps; the licensed adviser confirms it. It is not a regulatory determination."
FORBIDDEN_EVIDENCE_KEYS = frozenset({"name", "first_name", "last_name", "full_name", "email", "phone", "mobile", "address", "street", "date_of_birth", "dob", "account_number", "policy_number", "member_number", "licence_number", "license_number", "licence_no", "registration_number", "abn", "acn", "tax_file_number", "tfn", "sin", "social_insurance_number", "national_id", "passport", "drivers_licence", "signature", "signature_image", "ip_address", "bsb", "iban", "card_number", "tenant_id", "company_id", "user_id"})
_INFORMATIONAL_FINDINGS = frozenset({"fee_for_service_only"})

Regime = Literal["au_best_interests", "au_credit_not_unsuitable", "ca_kyc_suitability", "ca_cost_of_borrowing", "ca_mortgage_broker", "common"]
ChecklistStatus = Literal["evidenced", "missing", "not_applicable", "adviser_confirms"]

_REF = re.compile(r"^[a-z_]+:\S.*$")
_SUITABLE = frozenset({"eligible", "unassessed"})
_APR_ITEMS = ("apr", "annual percentage rate", "comparison rate", "current_apr", "posted_apr")
_HOLDING_KEYS = ("holdings", "existing_products")


class AdviceComplianceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class ChecklistSpec(StrictModel):
    """One step the case must answer: the operator's own label, never a statutory section; the operator's mapping lives in ``note``."""

    key: str = Field(min_length=1)
    label: ShortText
    regime: Regime
    note: ShortText | None = None


class ChecklistItem(StrictModel):
    """One step answered: its status, the sealed objects it read (by digest-prefixed ref) and what the adviser confirms when the SDK cannot."""

    key: str = Field(min_length=1)
    label: ShortText
    regime: Regime
    status: ChecklistStatus
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    basis: ShortText
    adviser_action: ShortText | None = None

    @field_validator("evidence", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self) -> ChecklistItem:
        for ref in self.evidence:
            if not _REF.match(ref):
                raise ValueError(f"an evidence ref is '<kind>:<digest or opaque ref>', not {ref!r}")
        if self.status == "adviser_confirms" and not self.adviser_action:
            raise ValueError("an item the adviser confirms names what the adviser confirms")
        return self


class ComplianceChecklist(StrictModel):
    """Every step of every regime the case falls under, answered and sealed against the case's digests."""

    schema_id: str = Field(default=COMPLIANCE_SCHEMA, alias="schema")
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str
    family: str
    mode: str
    regimes: tuple[Regime, ...] = Field(min_length=1)
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    shortlist_digest: Sha256Digest
    recommendation_digest: Sha256Digest | None = None
    record_digest: Sha256Digest | None = None
    verification_digest: Sha256Digest | None = None
    items: tuple[ChecklistItem, ...] = Field(min_length=1)
    evidenced: int = Field(ge=0)
    missing_count: int = Field(ge=0)
    complete: bool
    disclaimer: str = DISCLAIMER
    as_of: str
    checklist_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("regimes", "items", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ComplianceChecklist:
        missing = sum(1 for item in self.items if item.status == "missing")
        evidenced = sum(1 for item in self.items if item.status == "evidenced")
        if self.missing_count != missing or self.evidenced != evidenced:
            raise ValueError("the counts must agree with the items")
        if self.complete != (missing == 0):
            raise ValueError("a checklist is complete exactly when no item is missing")
        if not skip_digests(info) and self.checklist_digest != sealed_digest(ComplianceChecklist, self, "checklist_digest"):
            raise ValueError("checklist_digest must commit the exact checklist")
        return self

    def missing(self) -> tuple[str, ...]:
        return tuple(item.label for item in self.items if item.status == "missing")

    def confirmations(self) -> tuple[str, ...]:
        return tuple(item.adviser_action for item in self.items if item.status == "adviser_confirms" and item.adviser_action)

    def item(self, key: str) -> ChecklistItem | None:
        return next((item for item in self.items if item.key == key), None)


# --------------------------------------------------------------------------- #
# The tables: the operator's steps per regime; labels carry no section numbers
# --------------------------------------------------------------------------- #

_TABLES: dict[str, tuple[tuple[str, str], ...]] = {
    "au_best_interests": (
        ("objectives_identified", "The client's objectives are identified"),
        ("situation_identified", "The client's situation is identified: the decision facts suitability rests on are present"),
        ("needs_identified", "The client's needs are identified"),
        ("subject_matter_scoped", "The subject matter of the advice is scoped to the plan"),
        ("incomplete_information_inquired", "Where information was incomplete, further inquiry was made"),
        ("expertise_within_authority", "The advice sits within the authority the plan holds and a current verification of it"),
        ("reasonable_investigation", "A reasonable investigation of products was made and its limits disclosed"),
        ("judgement_on_circumstances", "The judgement rests on the client's circumstances: every product carries a suitability verdict"),
        ("client_priority_over_adviser", "The client's interest is put ahead of the adviser's remuneration"),
        ("replacement_product_disclosed", "A replacement of a product the client holds is compared with its costs and lost features named"),
        ("fees_and_remuneration_disclosed", "Fees, remuneration and conflicts are disclosed in figures"),
        ("incomplete_information_warning", "The record warns where the catalog is a partial sample"),
        ("record_evidence_complete", "The record of advice evidence is complete"),
        ("disclosures_given_before_advice", "The pre-advice disclosures were given before the advice"),
    ),
    "au_credit_not_unsuitable": (
        ("requirements_and_objectives_inquired", "The client's requirements and objectives for the credit were inquired into"),
        ("financial_situation_inquired", "The client's financial situation was inquired into: income and expenses"),
        ("financial_situation_verified", "The client's financial situation was verified"),
        ("not_unsuitable_assessment", "The credit product is assessed as not unsuitable: serviceable and eligible"),
        ("credit_guide_given", "The credit guide was given before the advice"),
        ("preliminary_assessment_available", "The preliminary assessment is available: the record of advice evidence is complete"),
    ),
    "ca_kyc_suitability": (
        ("kyc_collected", "Know your client: the decision facts and, for investments, the risk profile are collected"),
        ("kyp_product_understood", "Know your product: the recommended product's facts are cited to the provider's own documents"),
        ("suitability_determination", "A suitability determination is made for the recommended product"),
        ("client_interest_first", "The client's interest is put first ahead of the adviser's remuneration"),
        ("conflicts_addressed", "Conflicts of interest are identified and addressed"),
        ("relationship_disclosure_given", "The relationship disclosure was given before the advice"),
    ),
    "ca_cost_of_borrowing": (
        ("apr_disclosed", "The annual percentage rate or comparison figure is cited"),
        ("cost_of_borrowing_stated", "The cost of borrowing over the horizon is stated"),
    ),
    "ca_mortgage_broker": (
        ("lenders_compared", "At least three lenders were compared"),
        ("broker_disclosure_given", "The mortgage broker's key facts sheet was given"),
    ),
    "common": (
        ("authority_verified", "The authority the advice is given under is verified against a current register snapshot"),
        ("approval_separation_declared", "The plan declares that a licensed adviser other than the requester approves"),
        ("retention_labelled", "The record carries its retention date"),
    ),
}
_PERSONAL_ONLY = frozenset({"expertise_within_authority", "judgement_on_circumstances", "client_priority_over_adviser", "not_unsuitable_assessment", "kyp_product_understood", "suitability_determination", "apr_disclosed", "cost_of_borrowing_stated", "authority_verified"})


def _regimes(jurisdiction: str, family: str, authority_kind: str) -> tuple[str, ...]:
    out: list[str] = []
    if jurisdiction == "AU":
        out.append("au_credit_not_unsuitable" if authority_kind == "australian_credit_licence" else "au_best_interests")
    else:
        out.append("ca_kyc_suitability")
        if family == "credit":
            out.append("ca_cost_of_borrowing")
        if authority_kind == "provincial_mortgage_broker_licence":
            out.append("ca_mortgage_broker")
    out.append("common")
    return tuple(out)


def checklist_items_for(jurisdiction: str, family: str, mode: str, *, vertical_id: str) -> tuple[ChecklistSpec, ...]:
    """The steps the case must answer, in order: a table chosen by jurisdiction, family and the vertical's authority kind, not a rule engine."""

    vertical = load_vertical_registry().vertical(vertical_id)
    if vertical.jurisdiction != jurisdiction:
        raise AdviceComplianceError("VERTICAL_JURISDICTION_MISMATCH", f"{vertical_id} is a {vertical.jurisdiction} vertical")
    fam = family or sector_family(vertical.sector)
    specs: list[ChecklistSpec] = []
    for regime in _regimes(jurisdiction, fam, vertical.authority_for_recommendation):
        for key, label in _TABLES[regime]:
            if mode == "general_information" and key in _PERSONAL_ONLY:
                continue
            specs.append(ChecklistSpec(key=key, label=label, regime=regime))
    return tuple(specs)


# --------------------------------------------------------------------------- #
# Reading the sealed objects
# --------------------------------------------------------------------------- #


def _short(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


def _mapping(value: Any) -> dict[str, Any] | None:
    return None if value is None else dict(detached(value))


def _refuse_personal(value: Any, label: str) -> None:
    """A duck-typed input never went through a StrictModel here, so it gets the same guard: no personal, tenant or credential field anywhere in it, and no secret-like value."""

    try:
        reject_secret_like_payload(value, path=label)
    except ValueError as exc:
        raise AdviceComplianceError("PERSONAL_DATA_REFUSED", str(exc)) from exc
    _refuse_personal_keys(value, label)


def _refuse_personal_keys(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_EVIDENCE_KEYS:
                raise AdviceComplianceError("PERSONAL_DATA_REFUSED", f"{label} carries {key}; the checklist reads decision facts and digests only")
            _refuse_personal_keys(item, label)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _refuse_personal_keys(item, label)


def _kinds_given(engagement: Mapping[str, Any] | None) -> set[str]:
    if not engagement:
        return set()
    return {str(item.get("kind")) for item in engagement.get("given") or () if isinstance(item, Mapping)}


def _requirement_status(record: Mapping[str, Any] | None) -> dict[str, str]:
    if not record:
        return {}
    return {str(item.get("key")): str(item.get("status")) for item in record.get("requirements") or () if isinstance(item, Mapping)}


def _present(value: Any) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return value is not None and value != ""


def verification_for(plan: AdvicePlan | Mapping[str, Any], verifications: Sequence[Mapping[str, Any]], *, vertical_id: str, as_of: str) -> Mapping[str, Any] | None:
    """The 'verified' receipt for the authority the vertical requires, held by the plan, verified within VERIFICATION_MAX_AGE_DAYS of as_of; the latest such receipt, else None. A refused receipt is never returned."""

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    now = parsed(timestamp(as_of, field_name="as_of"))
    vertical = load_vertical_registry().vertical(vertical_id)
    kind = vertical.authority_for_recommendation
    family = sector_family(vertical.sector)
    held = p.authority_for(vertical_id, kind)
    if held is None:
        return None
    best: tuple[Any, dict[str, Any]] | None = None
    for raw in verifications:
        v = dict(detached(raw))
        if v.get("verdict") != "verified" or v.get("authority_kind") != kind or v.get("jurisdiction") != p.jurisdiction:
            continue
        if v.get("authority_ref_sha256") != held.authority_ref_sha256 or v.get("vertical_id") not in (None, vertical_id) or v.get("family") not in (None, family):
            continue
        stamp = v.get("verified_at")
        if not isinstance(stamp, str):
            continue
        try:
            when = parsed(timestamp(stamp, field_name="verified_at"))
        except ValueError:
            continue
        age = now - when
        if age < timedelta(0) or age > timedelta(days=VERIFICATION_MAX_AGE_DAYS):
            continue
        if best is None or when > best[0]:
            best = (when, v)
    return best[1] if best else None


class _Case:
    """Everything the evaluators read, parsed once; no field of it is a person."""

    def __init__(self, plan: AdvicePlan, state: ClientState, shortlist: Shortlist, catalog: ProductCatalog, recommendation: Recommendation | None, record: dict[str, Any] | None, *, switching: Sequence[dict[str, Any]], verifications: Sequence[dict[str, Any]], verification: dict[str, Any] | None, remuneration: dict[str, Any] | None, engagement: dict[str, Any] | None, serviceability: dict[str, Any] | None, needs: dict[str, Any] | None, fact_find_gaps: Sequence[str], family: str) -> None:
        self.plan = plan
        self.state = state
        self.shortlist = shortlist
        self.catalog = catalog
        self.recommendation = recommendation
        self.record = record
        self.switching = list(switching)
        self.verifications = list(verifications)
        self.verification = verification
        self.remuneration = remuneration
        self.engagement = engagement
        self.needs = needs
        self.declared_gaps = list(fact_find_gaps)
        self.family = family
        self.personal = plan.mode == "personal_recommendation"
        gaps = _fact_find_gaps_of(state)
        self.required_missing = list(gaps.required_missing)
        self.recommended_missing = list(gaps.recommended_missing)
        self.entry: ShortlistEntry | None = None
        if recommendation is not None:
            self.entry = next((item for item in shortlist.entries if item.product_ref == recommendation.primary_product_ref), None)
        self.serviceability = serviceability
        if serviceability is not None and recommendation is not None and serviceability.get("product_ref") not in (None, recommendation.primary_product_ref):
            self.serviceability = None
            self.serviceability_note = f"the serviceability verdict is for {serviceability.get('product_ref')}, not the recommended product"
        else:
            self.serviceability_note = None
        self.requirements = _requirement_status(record)
        self.refs = {
            "plan": f"plan:{plan.plan_digest}",
            "state": f"state:{state.state_digest}",
            "shortlist": f"shortlist:{shortlist.shortlist_digest}",
            "recommendation": f"recommendation:{recommendation.recommendation_digest}" if recommendation else None,
            "record": f"record:{record.get('record_digest')}" if record and record.get("record_digest") else None,
            "verification": f"verification:{verification.get('verification_digest')}" if verification and verification.get("verification_digest") else None,
            "remuneration": f"remuneration:{remuneration.get('disclosure_digest')}" if remuneration and remuneration.get("disclosure_digest") else None,
            "engagement": f"engagement:{engagement.get('engagement_digest')}" if engagement and engagement.get("engagement_digest") else None,
            "serviceability": f"serviceability:{self.serviceability.get('serviceability_digest')}" if self.serviceability and self.serviceability.get("serviceability_digest") else None,
        }

    def ref(self, *names: str) -> list[str]:
        return [self.refs[name] for name in names if self.refs.get(name)]

    def recommended_facts(self) -> list[dict[str, Any]]:
        """The recommended product's facts: from the record when there is one, else from the catalog product itself."""
        if self.recommendation is None:
            return []
        if self.record and isinstance(self.record.get("recommended"), Mapping):
            return [dict(item) for item in self.record["recommended"].get("facts") or () if isinstance(item, Mapping)]
        product = self.catalog.product(self.recommendation.primary_product_ref)
        return [{"item": fact.item, "value": None if fact.value is None else str(fact.value), "unit": fact.unit, "support": fact.support} for fact in product.pricing]

    def fact_refs(self, facts: Sequence[Mapping[str, Any]]) -> list[str]:
        assert self.recommendation is not None
        return [f"fact:{self.recommendation.primary_product_ref}#{' '.join(str(fact.get('item')).split()) or 'unnamed'}" for fact in facts]

    def holdings(self) -> Any:
        for key in _HOLDING_KEYS:
            value = self.state.facts.get(key)
            if _present(value):
                return value
        return None


def _fact_find_gaps_of(state: ClientState) -> Any:
    return fact_find_gaps(state)


Answer = tuple[str, list[str], str, str | None]


def _ok(evidence: list[str], basis: str) -> Answer:
    return "evidenced", evidence, basis, None


def _missing(basis: str, evidence: list[str] | None = None) -> Answer:
    return "missing", evidence or [], basis, None


def _na(basis: str, evidence: list[str] | None = None) -> Answer:
    return "not_applicable", evidence or [], basis, None


def _confirm(action: str, basis: str, evidence: list[str] | None = None) -> Answer:
    return "adviser_confirms", evidence or [], basis, action


def _no_recommendation(case: _Case) -> Answer:
    if not case.personal:
        return _na("a general-information plan recommends nothing")
    return _missing("no recommendation has been prepared")


# --- au_best_interests ------------------------------------------------------ #


def _objectives_identified(case: _Case) -> Answer:
    if not case.state.objective.strip() or "objective" in case.declared_gaps:
        return _missing("no objective is stated in the client state", case.ref("state"))
    count = len(case.state.facts) + sum(1 for key in ("amount", "lvr_percent", "term_years", "purpose") if getattr(case.state, key) is not None)
    return _ok(case.ref("state"), f"objective stated: '{case.state.objective[:80]}'; {count} decision fact(s) disclosed")


def _situation_identified(case: _Case) -> Answer:
    gaps = list(dict.fromkeys([*case.required_missing, *case.declared_gaps]))
    if gaps:
        return _missing("required decision facts missing: " + ", ".join(gaps), case.ref("state"))
    return _ok(case.ref("state"), "every required decision fact for the vertical is present" + ("; recommended facts not given: " + ", ".join(case.recommended_missing) if case.recommended_missing else ""))


def _needs_identified(case: _Case) -> Answer:
    if case.family == "insurance":
        if case.needs is None:
            return _missing("no needs assessment was supplied for an insurance line")
        kind = str(case.needs.get("kind") or "cover")
        if case.needs.get("need") is None:
            return _missing(f"the {kind} needs assessment is incomplete: missing " + ", ".join(str(item) for item in case.needs.get("missing") or ("facts",)))
        return _ok([*case.ref("state"), f"needs:{kind}"], f"assessed {kind} need {case.needs.get('need')} {case.needs.get('unit') or ''} from " + ", ".join(str(key) for key in (case.needs.get("components") or {})))
    if case.required_missing:
        return _missing("the fact find is incomplete: " + ", ".join(case.required_missing), case.ref("state"))
    return _ok(case.ref("state"), "needs read from the objective and the decision facts of the fact find")


def _subject_matter_scoped(case: _Case) -> Answer:
    if case.state.vertical_id in case.plan.verticals:
        return _ok(case.ref("plan", "state"), f"{case.state.vertical_id} is one of the plan's verticals; mode {case.plan.mode}")
    return _missing(f"{case.state.vertical_id} is not among the plan's verticals", case.ref("plan"))


def _incomplete_information_inquired(case: _Case) -> Answer:
    if case.declared_gaps:
        return _missing("open fact-find gaps still to inquire into: " + ", ".join(case.declared_gaps), case.ref("state"))
    return _ok(case.ref("state"), "no open fact-find gap is declared" + ("; recommended facts not given: " + ", ".join(case.recommended_missing) if case.recommended_missing else ""))


def _expertise_within_authority(case: _Case) -> Answer:
    kind = load_vertical_registry().vertical(case.state.vertical_id).authority_for_recommendation
    if case.plan.authority_for(case.state.vertical_id, kind) is None:
        return _missing(f"the plan holds no {kind} scoped to {case.state.vertical_id}", case.ref("plan"))
    if case.verification is None:
        return _missing(f"no verified {kind} for {case.state.vertical_id} within {VERIFICATION_MAX_AGE_DAYS} days of as_of", case.ref("plan"))
    return _ok(case.ref("plan", "verification"), f"the plan holds {kind} for {case.state.vertical_id}; verified against {case.verification.get('register_name')} at {case.verification.get('verified_at')}")


def _reasonable_investigation(case: _Case) -> Answer:
    sl = case.shortlist
    lowered = [text.lower() for text in sl.disclosures]
    disclosed = sl.catalog_completeness == "census_complete" or any(word in text for text in lowered for word in ("partial", "sample", "census"))
    ranked = len(sl.ranked)
    explained = any(word in text for text in lowered for word in ("unranked", "not ranked"))
    summary = f"{len(sl.entries)} entr(ies), {ranked} ranked, from a {sl.catalog_completeness.replace('_', ' ')} catalog of {len(case.catalog.products)} product(s) and {len(case.catalog.providers)} provider(s)"
    if not disclosed:
        return _missing(summary + "; the catalog's completeness is not disclosed on the shortlist", case.ref("shortlist"))
    if ranked >= 2 or explained:
        return _ok(case.ref("shortlist"), summary + ("; the shortlist discloses why entries are unranked" if ranked < 2 else ""))
    return _missing(summary + "; fewer than two ranked entries and no disclosure names why", case.ref("shortlist"))


def _judgement_on_circumstances(case: _Case) -> Answer:
    if case.recommendation is None or case.entry is None:
        return _no_recommendation(case) if case.recommendation is None else _missing("the recommended product is not on the shortlist", case.ref("recommendation"))
    verdict = case.entry.suitability
    if verdict.outcome == "ineligible":
        return _missing("the recommended product is ineligible: " + "; ".join(verdict.reasons), case.ref("shortlist", "recommendation"))
    if verdict.unconfirmed:
        return _confirm("confirm with the client: " + ", ".join(verdict.unconfirmed), f"the recommended product's restrictions are not settled by the fact find: {', '.join(verdict.unconfirmed)}", case.ref("shortlist", "recommendation"))
    if verdict.outcome == "unassessed":
        return _confirm("confirm the provider's eligibility statements against the client's circumstances; the provider states no structured terms", "every entry carries a suitability verdict; the recommended product is unassessed", case.ref("shortlist", "recommendation"))
    return _ok(case.ref("shortlist", "recommendation"), "every entry carries a suitability verdict; the recommended product is eligible on " + (", ".join(verdict.checked_terms) or "the provider's statements"))


def _client_priority_over_adviser(case: _Case) -> Answer:
    if case.remuneration is None:
        return _missing("no remuneration disclosure was supplied")
    findings = [str(item) for item in case.remuneration.get("findings") or ()]
    substantive = [item for item in findings if item not in _INFORMATIONAL_FINDINGS]
    if case.remuneration.get("clear") is True and not substantive:
        return _ok(case.ref("remuneration"), "the remuneration disclosure is clear" + ("; findings: " + ", ".join(findings) if findings else ""))
    if case.remuneration.get("clear") is True:
        return _missing("the remuneration disclosure says clear but names findings: " + ", ".join(substantive), case.ref("remuneration"))
    return _missing("the remuneration disclosure is not clear: " + (", ".join(findings) or "no findings named"), case.ref("remuneration"))


def _replacement_product_disclosed(case: _Case) -> Answer:
    holdings = case.holdings()
    if holdings is None:
        return _na("the client state names no holding to replace", case.ref("state"))
    named = [item for item in case.switching if "one_off_costs" in item and "features_lost" in item]
    if not named:
        return _missing("the client holds a product and no switching analysis with one-off costs and features lost was supplied", case.ref("state"))
    refs = [f"switch:{item.get('analysis_digest') or item.get('holding_ref') or 'unsealed'}" for item in named]
    return _ok([*case.ref("state"), *refs], "; ".join(f"{item.get('candidate_product_name')}: {item.get('verdict')}, {len(item.get('one_off_costs') or ())} one-off cost(s), features lost {list(item.get('features_lost') or ())}" for item in named))


def _fees_and_remuneration_disclosed(case: _Case) -> Answer:
    if case.record is None:
        return _missing("no record of advice evidence was supplied")
    satisfied = case.requirements.get("remuneration") == "satisfied"
    statements = [str(item) for item in (case.remuneration or {}).get("statements") or ()]
    if satisfied and statements:
        return _ok(case.ref("record", "remuneration"), f"the record carries the plan's remuneration disclosure and the remuneration disclosure states {len(statements)} sentence(s) in figures")
    if satisfied:
        return _missing("the record carries the plan's sentence; no remuneration disclosure in figures was supplied", case.ref("record"))
    return _missing("the record's remuneration requirement is " + (case.requirements.get("remuneration") or "absent"), case.ref("record"))


def _incomplete_information_warning(case: _Case) -> Answer:
    if case.shortlist.catalog_completeness == "census_complete":
        return _na("the catalog is a complete census; no partial-sample warning is owed", case.ref("shortlist"))
    if case.record is None:
        return _missing("no record of advice evidence was supplied")
    warned = any("partial" in str(text).lower() or "not represented" in str(text).lower() for text in case.record.get("disclosures") or ())
    if warned:
        return _ok(case.ref("record"), f"the record's disclosures warn that the catalog is a {case.shortlist.catalog_completeness.replace('_', ' ')}")
    return _missing("the record's disclosures do not warn that the catalog is a partial sample", case.ref("record"))


def _record_evidence_complete(case: _Case) -> Answer:
    """The record is complete for the checklist when every requirement but the adviser's approval is satisfied: the checklist is what the approval is decided on, so the approval itself cannot be a precondition of it."""
    record = case.record or {}
    if not record:
        return _missing("no record of advice evidence was prepared", case.ref("record"))
    if record.get("complete") is True:
        return _ok(case.ref("record"), "the record of advice evidence is complete")
    requirements = [dict(item) for item in record.get("requirements") or ()]
    outstanding = [str(item.get("label") or item.get("key")) for item in requirements if item.get("status") == "missing" and item.get("key") != "approval"]
    if requirements and not outstanding:
        return _ok(case.ref("record"), "the record of advice evidence is complete but for the adviser's approval, which this checklist is decided on")
    missing = outstanding or [str(item) for item in record.get("missing") or ()] or ["unstated"]
    return _missing("the record is not complete: " + "; ".join(missing), case.ref("record"))



def _disclosures_given_before_advice(case: _Case) -> Answer:
    if case.engagement is None:
        return _missing("no engagement pack was supplied")
    if case.engagement.get("complete") is True:
        return _ok(case.ref("engagement"), "the engagement pack is complete: given " + ", ".join(sorted(_kinds_given(case.engagement))))
    return _missing("the engagement pack is missing " + ", ".join(str(item) for item in case.engagement.get("missing") or ("required disclosures",)), case.ref("engagement"))


# --- au_credit_not_unsuitable ------------------------------------------------ #


def _requirements_and_objectives_inquired(case: _Case) -> Answer:
    named = [key for key in ("amount", "purpose", "term_years") if getattr(case.state, key) is not None]
    if case.state.objective.strip() and named:
        return _ok(case.ref("state"), f"objective stated; requirements: {', '.join(named)}")
    return _missing("the objective or the requirements (amount, purpose, term) are not stated", case.ref("state"))


def _financial_situation_inquired(case: _Case) -> Answer:
    absent = [key for key in ("income", "expenses") if not _present(case.state.facts.get(key))]
    if absent:
        return _missing("financial situation facts missing: " + ", ".join(absent), case.ref("state"))
    return _ok(case.ref("state"), "income and expenses are disclosed" + ("; debts disclosed" if _present(case.state.facts.get("debts")) else "; debts not disclosed"))


def _financial_situation_verified(case: _Case) -> Answer:
    return _confirm("verify the disclosed income and expenses against the client's documents outside the SDK", "the SDK holds the disclosed figures and no documents; verification is the adviser's step", case.ref("state"))


def _not_unsuitable_assessment(case: _Case) -> Answer:
    if case.recommendation is None:
        return _no_recommendation(case)
    suitable = case.entry is not None and case.entry.suitability.outcome in _SUITABLE
    sv = case.serviceability
    if sv is not None and sv.get("verdict") == "serviceable" and suitable:
        return _ok(case.ref("serviceability", "recommendation"), f"serviceable at {sv.get('assessed_rate_percent')}% with buffer {sv.get('buffer_percent')}% ({sv.get('buffer_source')}); the recommended product is {case.entry.suitability.outcome}")
    if sv is not None and sv.get("verdict") == "not_serviceable":
        return _missing("the serviceability verdict is not_serviceable: " + "; ".join(str(item) for item in sv.get("reasons") or ()), case.ref("serviceability", "recommendation"))
    if not suitable:
        return _missing("the recommended product is not eligible on the provider's terms", case.ref("recommendation"))
    why = case.serviceability_note or ("the serviceability verdict is unassessed: " + "; ".join(str(item) for item in sv.get("missing") or ("facts",)) if sv is not None else "no serviceability verdict was supplied")
    return _confirm("assess serviceability by hand and record the figures: " + why, why, case.ref("recommendation", "serviceability"))


def _credit_guide_given(case: _Case) -> Answer:
    return _kind_given(case, "credit_guide")


def _kind_given(case: _Case, kind: str) -> Answer:
    if case.engagement is None:
        return _missing("no engagement pack was supplied")
    if kind in _kinds_given(case.engagement):
        given = next(item for item in case.engagement.get("given") or () if isinstance(item, Mapping) and item.get("kind") == kind)
        return _ok(case.ref("engagement"), f"{kind} given {given.get('given_at')} by {given.get('channel')}, document {str(given.get('document_digest'))[:16]}")
    return _missing(f"the engagement pack does not record a {kind}", case.ref("engagement"))


def _preliminary_assessment_available(case: _Case) -> Answer:
    return _record_evidence_complete(case)


# --- ca_kyc_suitability ------------------------------------------------------ #


def _kyc_collected(case: _Case) -> Answer:
    gaps = list(case.required_missing)
    if case.family == "investments" and not _present(case.state.facts.get("risk_profile")):
        gaps.append("risk_profile")
    if gaps:
        return _missing("know-your-client facts missing: " + ", ".join(dict.fromkeys(gaps)), case.ref("state"))
    return _ok(case.ref("state"), "every required decision fact is present" + (f"; risk profile {case.state.facts.get('risk_profile')}" if case.family == "investments" else ""))


def _kyp_product_understood(case: _Case) -> Answer:
    if case.recommendation is None:
        return _no_recommendation(case)
    cited = [fact for fact in case.recommended_facts() if fact.get("support") == "fact_cited"]
    if len(cited) >= 3:
        return _ok([*case.ref("recommendation", "record"), *case.fact_refs(cited)], f"{len(cited)} fact(s) of the recommended product cite the provider's own document: " + ", ".join(str(fact.get("item")) for fact in cited[:6]))
    return _missing(f"{len(cited)} cited fact(s) on the recommended product; three are needed", case.ref("recommendation"))


def _suitability_determination(case: _Case) -> Answer:
    if case.recommendation is None:
        return _no_recommendation(case)
    if case.entry is None or case.entry.suitability.outcome == "ineligible":
        return _missing("the recommended product is ineligible or not on the shortlist", case.ref("recommendation"))
    outcome = case.entry.suitability.outcome
    if case.family == "credit":
        sv = case.serviceability
        if sv is not None and sv.get("verdict") == "serviceable":
            return _ok(case.ref("recommendation", "serviceability"), f"the recommended product is {outcome} and serviceable at {sv.get('assessed_rate_percent')}%")
        if sv is not None and sv.get("verdict") == "not_serviceable":
            return _missing("the serviceability verdict is not_serviceable", case.ref("recommendation", "serviceability"))
        return _confirm("determine suitability by hand: no serviceable verdict is on file", case.serviceability_note or "no serviceability verdict, or an unassessed one", case.ref("recommendation"))
    if case.family == "insurance":
        if case.needs is not None and case.needs.get("need") is not None:
            return _ok([*case.ref("recommendation"), f"needs:{case.needs.get('kind') or 'cover'}"], f"the recommended product is {outcome} against an assessed need of {case.needs.get('need')} {case.needs.get('unit') or ''}")
        return _confirm("determine suitability by hand: the need is not assessed", "no complete needs assessment is on file", case.ref("recommendation"))
    if outcome == "eligible":
        return _ok(case.ref("recommendation", "shortlist"), "the recommended product is eligible on " + (", ".join(case.entry.suitability.checked_terms) or "the provider's statements") + (f"; risk profile {case.state.facts.get('risk_profile')}" if _present(case.state.facts.get("risk_profile")) else ""))
    return _confirm("determine suitability by hand: the provider states no structured terms to check", "the recommended product is unassessed", case.ref("recommendation"))


def _client_interest_first(case: _Case) -> Answer:
    return _client_priority_over_adviser(case)


def _conflicts_addressed(case: _Case) -> Answer:
    if case.remuneration is None:
        return _missing("no remuneration disclosure was supplied")
    if not case.remuneration.get("register_digest"):
        return _missing("the remuneration disclosure consulted no conflicts register", case.ref("remuneration"))
    conflicts = list(case.remuneration.get("conflicts") or ())
    return _ok(case.ref("remuneration"), f"the conflicts register was consulted; {len(conflicts)} conflict(s) reach the recommended provider or product and are disclosed")


def _relationship_disclosure_given(case: _Case) -> Answer:
    return _kind_given(case, "relationship_disclosure")


# --- ca_cost_of_borrowing ----------------------------------------------------- #


def _apr_disclosed(case: _Case) -> Answer:
    if case.recommendation is None:
        return _no_recommendation(case)
    facts = [fact for fact in case.recommended_facts() if any(word in str(fact.get("item")).lower() for word in _APR_ITEMS) and fact.get("support") == "fact_cited"]
    if facts:
        return _ok([*case.ref("recommendation"), *case.fact_refs(facts)], "; ".join(f"{fact.get('item')} {fact.get('value')} {fact.get('unit') or ''}".strip() for fact in facts))
    return _missing("no cited annual percentage rate or comparison figure on the recommended product", case.ref("recommendation"))


def _cost_of_borrowing_stated(case: _Case) -> Answer:
    if case.recommendation is None:
        return _no_recommendation(case)
    if case.requirements.get("cost_of_borrowing") == "satisfied":
        return _ok(case.ref("record", "recommendation"), "the record's cost-of-borrowing requirement is satisfied")
    if case.entry is not None and case.entry.projected_cost is not None:
        return _ok(case.ref("shortlist", "recommendation"), f"projected cost {case.entry.projected_cost} over {case.entry.projection_horizon_years} year(s)")
    return _missing("no projected cost over the horizon and no satisfied cost-of-borrowing requirement", case.ref("recommendation"))


# --- ca_mortgage_broker ------------------------------------------------------- #


def _lenders_compared(case: _Case) -> Answer:
    providers = sorted({entry.provider_ref for entry in case.shortlist.entries})
    if len(providers) >= 3:
        return _ok(case.ref("shortlist"), f"{len(providers)} lender(s) compared on the shortlist")
    return _missing(f"{len(providers)} lender(s) on the shortlist; three are needed; catalog {case.shortlist.catalog_completeness.replace('_', ' ')}", case.ref("shortlist"))


def _broker_disclosure_given(case: _Case) -> Answer:
    return _kind_given(case, "key_facts_sheet")


# --- common ------------------------------------------------------------------- #


def _authority_verified(case: _Case) -> Answer:
    if case.verification is not None:
        return _ok(case.ref("verification"), f"{case.verification.get('authority_kind')} verified against {case.verification.get('register_name')} at {case.verification.get('verified_at')}")
    refused = [f"{item.get('authority_kind')}: {', '.join(str(f) for f in item.get('findings') or ())}" for item in case.verifications if item.get("verdict") == "refused"]
    stale = [str(item.get("verified_at")) for item in case.verifications if item.get("verdict") == "verified"]
    detail = ("; refused: " + "; ".join(refused) if refused else "") + (f"; verified receipts outside {VERIFICATION_MAX_AGE_DAYS} days or for another authority: {', '.join(stale)}" if stale else "")
    return _missing("no current verified receipt for the authority the vertical requires" + detail, case.ref("plan"))


def _approval_separation_declared(case: _Case) -> Answer:
    if case.plan.require_adviser_approval:
        return _ok(case.ref("plan"), "the plan requires a licensed adviser's approval bound to the recommendation; the lifecycle refuses self-advice")
    return _missing("the plan does not require an adviser approval", case.ref("plan"))


def _retention_labelled(case: _Case) -> Answer:
    if case.record is not None and _present(case.record.get("retain_until")):
        return _ok(case.ref("record"), f"retain until {case.record.get('retain_until')}")
    return _na("the record carries no retention date; retention is labelled when the store files it", case.ref("record"))


_EVALUATORS: dict[str, Callable[[_Case], Answer]] = {
    "objectives_identified": _objectives_identified,
    "situation_identified": _situation_identified,
    "needs_identified": _needs_identified,
    "subject_matter_scoped": _subject_matter_scoped,
    "incomplete_information_inquired": _incomplete_information_inquired,
    "expertise_within_authority": _expertise_within_authority,
    "reasonable_investigation": _reasonable_investigation,
    "judgement_on_circumstances": _judgement_on_circumstances,
    "client_priority_over_adviser": _client_priority_over_adviser,
    "replacement_product_disclosed": _replacement_product_disclosed,
    "fees_and_remuneration_disclosed": _fees_and_remuneration_disclosed,
    "incomplete_information_warning": _incomplete_information_warning,
    "record_evidence_complete": _record_evidence_complete,
    "disclosures_given_before_advice": _disclosures_given_before_advice,
    "requirements_and_objectives_inquired": _requirements_and_objectives_inquired,
    "financial_situation_inquired": _financial_situation_inquired,
    "financial_situation_verified": _financial_situation_verified,
    "not_unsuitable_assessment": _not_unsuitable_assessment,
    "credit_guide_given": _credit_guide_given,
    "preliminary_assessment_available": _preliminary_assessment_available,
    "kyc_collected": _kyc_collected,
    "kyp_product_understood": _kyp_product_understood,
    "suitability_determination": _suitability_determination,
    "client_interest_first": _client_interest_first,
    "conflicts_addressed": _conflicts_addressed,
    "relationship_disclosure_given": _relationship_disclosure_given,
    "apr_disclosed": _apr_disclosed,
    "cost_of_borrowing_stated": _cost_of_borrowing_stated,
    "lenders_compared": _lenders_compared,
    "broker_disclosure_given": _broker_disclosure_given,
    "authority_verified": _authority_verified,
    "approval_separation_declared": _approval_separation_declared,
    "retention_labelled": _retention_labelled,
}


# --------------------------------------------------------------------------- #
# The checklist
# --------------------------------------------------------------------------- #


def compliance_checklist(plan: AdvicePlan | Mapping[str, Any], state: ClientState | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any], catalog: ProductCatalog | Mapping[str, Any], *, recommendation: Recommendation | Mapping[str, Any] | None = None, record: Mapping[str, Any] | None = None, switching: Sequence[Mapping[str, Any]] = (), verifications: Sequence[Mapping[str, Any]] = (), remuneration: Mapping[str, Any] | None = None, engagement: Mapping[str, Any] | None = None, serviceability: Mapping[str, Any] | None = None, needs: Mapping[str, Any] | None = None, fact_find_gaps: Sequence[str] = (), as_of: str) -> ComplianceChecklist:
    """Answer every step of the case's regimes from the sealed objects and seal the answers.

    The record, switching analyses, verifications, remuneration disclosure, engagement pack,
    serviceability verdict and needs assessment are read as plain mappings by the fields their
    modules seal, so this module imports none of them. A record whose digests disagree with the
    shortlist or the recommendation is refused (RECORD_MISMATCH); a mapping carrying a personal
    field is refused (PERSONAL_DATA_REFUSED).
    """

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    rec = None if recommendation is None else (recommendation if isinstance(recommendation, Recommendation) else Recommendation.model_validate(dict(detached(recommendation))))
    stamp = timestamp(as_of, field_name="as_of")
    if sl.plan_digest != p.plan_digest or sl.state_digest != s.state_digest or sl.catalog_digest != c.catalog_digest:
        raise AdviceComplianceError("INPUTS_MISMATCH", "the shortlist was prepared from a different plan, state or catalog")
    if rec is not None and rec.shortlist_digest != sl.shortlist_digest:
        raise AdviceComplianceError("INPUTS_MISMATCH", "the recommendation was prepared from a different shortlist")
    r = _mapping(record)
    if r is not None:
        expected = {"plan_digest": p.plan_digest, "state_digest": s.state_digest, "shortlist_digest": sl.shortlist_digest, "recommendation_digest": rec.recommendation_digest if rec else None}
        for key, value in expected.items():
            if r.get(key) != value:
                raise AdviceComplianceError("RECORD_MISMATCH", f"the record's {key} disagrees with the case")
    inputs: dict[str, Any] = {"state facts": s.facts, "record": r, "remuneration": remuneration, "engagement": engagement, "serviceability": serviceability, "needs": needs}
    for label, value in inputs.items():
        _refuse_personal(_mapping(value), label)
    sw = [dict(detached(item)) for item in switching]
    vs = [dict(detached(item)) for item in verifications]
    for label, items in (("switching", sw), ("verifications", vs)):
        _refuse_personal(items, label)
    vertical = load_vertical_registry().vertical(s.vertical_id)
    family = sector_family(vertical.sector)
    specs = checklist_items_for(p.jurisdiction, family, p.mode, vertical_id=s.vertical_id)
    verification = _mapping(verification_for(p, vs, vertical_id=s.vertical_id, as_of=stamp))
    case = _Case(p, s, sl, c, rec, r, switching=sw, verifications=vs, verification=verification, remuneration=_mapping(remuneration), engagement=_mapping(engagement), serviceability=_mapping(serviceability), needs=_mapping(needs), fact_find_gaps=fact_find_gaps, family=family)
    items: list[dict[str, Any]] = []
    for spec in specs:
        status, evidence, basis, action = _EVALUATORS[spec.key](case)
        items.append({"key": spec.key, "label": spec.label, "regime": spec.regime, "status": status, "evidence": list(dict.fromkeys(evidence)), "basis": _short(basis or "read from the case"), "adviser_action": None if action is None else _short(action)})
    missing = sum(1 for item in items if item["status"] == "missing")
    return seal(ComplianceChecklist, {
        "jurisdiction": p.jurisdiction, "vertical_id": s.vertical_id, "family": family, "mode": p.mode, "regimes": list(dict.fromkeys(spec.regime for spec in specs)),
        "plan_digest": p.plan_digest, "state_digest": s.state_digest, "shortlist_digest": sl.shortlist_digest, "recommendation_digest": rec.recommendation_digest if rec else None,
        "record_digest": r.get("record_digest") if r else None, "verification_digest": verification.get("verification_digest") if verification else None,
        "items": items, "evidenced": sum(1 for item in items if item["status"] == "evidenced"), "missing_count": missing, "complete": missing == 0, "as_of": stamp,
    }, "checklist_digest")


def approval_pack(checklist: ComplianceChecklist | Mapping[str, Any], *, verification: Mapping[str, Any] | None) -> dict[str, Any]:
    """Exactly the digests the adviser's approval request carries: recommendation, record, checklist and verification; the worker copies them into the request's contextData."""

    c = checklist if isinstance(checklist, ComplianceChecklist) else ComplianceChecklist.model_validate(dict(detached(checklist)))
    if c.recommendation_digest is None:
        raise AdviceComplianceError("RECOMMENDATION_MISSING", "an approval binds a recommendation; the checklist carries none")
    if c.record_digest is None:
        raise AdviceComplianceError("RECORD_MISSING", "an approval binds the record of advice evidence; the checklist carries none")
    v = _mapping(verification)
    if v is not None:
        if v.get("verdict") != "verified":
            raise AdviceComplianceError("VERIFICATION_REFUSED", "a refused verification never enters an approval pack: " + ", ".join(str(item) for item in v.get("findings") or ()))
        if c.verification_digest is None:
            raise AdviceComplianceError("VERIFICATION_MISMATCH", "the checklist was evaluated without a current verification; evaluate it again with this receipt before packing the approval")
        if v.get("verification_digest") != c.verification_digest:
            raise AdviceComplianceError("VERIFICATION_MISMATCH", "the verification is not the one the checklist was evaluated against")
    return {
        "schema": APPROVAL_PACK_SCHEMA,
        "recommendation_digest": c.recommendation_digest,
        "record_digest": c.record_digest,
        "checklist_digest": c.checklist_digest,
        "verification_digest": v.get("verification_digest") if v else c.verification_digest,
        "checklist_complete": c.complete,
        "missing": list(c.missing()),
        "confirmations": list(c.confirmations()),
        "binds": "the adviser approves exactly these digests",
    }


_MARKS = {"evidenced": "[x]", "missing": "[ ]", "not_applicable": "[–]", "adviser_confirms": "[?]"}


def checklist_markdown(checklist: ComplianceChecklist | Mapping[str, Any]) -> str:
    """The checklist laid out by regime with every item's status, basis and evidence; then what is missing and what the adviser confirms."""

    c = checklist if isinstance(checklist, ComplianceChecklist) else ComplianceChecklist.model_validate(dict(detached(checklist)))
    lines = [f"# Checklist — {c.vertical_id} ({c.jurisdiction}, {c.family}, {c.mode})", "", f"As of {c.as_of}; checklist digest {c.checklist_digest[:16]}…; {c.evidenced} evidenced, {c.missing_count} missing, {len(c.confirmations())} for the adviser to confirm.", "", c.disclaimer, ""]
    for regime in c.regimes:
        lines.append(f"## {regime.replace('_', ' ')}")
        lines.append("")
        for item in c.items:
            if item.regime != regime:
                continue
            tail = f" — adviser confirms: {item.adviser_action}" if item.status == "adviser_confirms" else ""
            evidence = f" (evidence: {', '.join(ref[:32] for ref in item.evidence)})" if item.evidence else ""
            lines.append(f"- {_MARKS[item.status]} {item.label} — {item.basis}{tail}{evidence}")
        lines.append("")
    lines += ["## Still missing", ""]
    lines += [f"- {label}" for label in c.missing()] or ["- nothing"]
    lines += ["", "## The adviser confirms", ""]
    lines += [f"- {action}" for action in c.confirmations()] or ["- nothing"]
    return "\n".join(lines)


COMPLIANCE_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_compliance.v1",
    "schemas": {"checklist": COMPLIANCE_SCHEMA, "approval_pack": APPROVAL_PACK_SCHEMA},
    "regimes": {regime: [key for key, _ in rows] for regime, rows in _TABLES.items()},
    "regime_selection": "AU credit verticals answer au_credit_not_unsuitable, other AU verticals au_best_interests; every CA vertical answers ca_kyc_suitability, CA credit adds ca_cost_of_borrowing and the mortgage-broker vertical adds ca_mortgage_broker; common applies everywhere",
    "statuses": ["evidenced", "missing", "not_applicable", "adviser_confirms"],
    "evidence_ref_kinds": ["plan", "state", "shortlist", "recommendation", "record", "verification", "switch", "remuneration", "engagement", "serviceability", "needs", "fact", "requirement"],
    "verification_max_age_days": VERIFICATION_MAX_AGE_DAYS,
    "rules": [
        "every item names the sealed object it read by digest; an item the SDK cannot answer is handed to the adviser as a confirmation, never assumed",
        "the checklist is complete when no item is missing; confirmations stay on it for the adviser",
        "the approval pack names exactly the recommendation, record, checklist and verification digests; a refused verification never enters it",
        "the record's digests must agree with the shortlist and the recommendation; personal, tenant and credential fields and secret-like values in any input are refused",
        "a remuneration disclosure evidences the client's priority only when it is clear and names no finding beyond the informational fee_for_service_only; a clear flag that contradicts its findings is missing, not trusted",
        "an approval pack binds only the verification the checklist was evaluated against; a checklist evaluated without one is evaluated again before it is packed",
        "labels are the operator's own words and carry no statutory section numbers; the operator's mapping lives in the spec note",
        "deterministic tables; nothing ranks, nothing recommends, no model",
    ],
    "non_goals": ["compliance certified", "regulatory determination"],
    "not_claimed": "an evaluated checklist of the operator's own steps with a disclaimer; the licensed adviser confirms it and nothing here advances a case",
}

__all__ = [
    "APPROVAL_PACK_SCHEMA",
    "COMPLIANCE_MANIFEST",
    "COMPLIANCE_SCHEMA",
    "DISCLAIMER",
    "FORBIDDEN_EVIDENCE_KEYS",
    "VERIFICATION_MAX_AGE_DAYS",
    "AdviceComplianceError",
    "ChecklistItem",
    "ChecklistSpec",
    "ChecklistStatus",
    "ComplianceChecklist",
    "Regime",
    "approval_pack",
    "checklist_items_for",
    "checklist_markdown",
    "compliance_checklist",
    "verification_for",
]
