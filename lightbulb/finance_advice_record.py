"""The record-of-advice evidence: what the adviser's document must contain, assembled from sealed artifacts.

Advisers in both jurisdictions owe the client a record of what was recommended and why: the scope
of the advice, the client's objectives and situation, the alternatives considered, the costs and
how they were sourced, the adviser's remuneration and conflicts, the authority the advice is given
under, and the warnings where the picture is incomplete. This module assembles that evidence from
the plan, the client state, the shortlist, the recommendation and the catalog, cites every product
fact to the provider's own document, and checks the assembled record against a per-jurisdiction
requirement list. It produces the evidence and the checklist, never the legal document, and it
claims no compliance: the licensed adviser owns the document and signs it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.finance_advice_catalog import Product, ProductCatalog
from lightbulb.finance_advice_engine import AdvicePlan, ClientState, Recommendation, Shortlist, sector_family
from lightbulb.finance_advice_catalog import load_vertical_registry
from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, detached, seal, sealed_digest, skip_digests
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel

RECORD_SCHEMA = "lightbulb.finance_advice_record_evidence.v1"
RequirementStatus = Literal["satisfied", "missing", "not_applicable"]


class CitedFact(StrictModel):
    item: str
    value: str | None = None
    unit: str | None = None
    support: str
    source_url: str | None = None
    retrieved_at: str | None = None
    document_title: str | None = None
    quote: str | None = None


class ProductEvidence(StrictModel):
    product_ref: OpaqueRef
    provider_name: str
    product_name: str
    taxonomy_class: str
    confidence: str
    pricing_kind: str
    suitability: str
    score: Decimal | None = None
    projected_cost: Decimal | None = None
    projection_horizon_years: int | None = None
    basis: tuple[str, ...] = Field(default_factory=tuple)
    facts: tuple[CitedFact, ...] = Field(default_factory=tuple)
    eligibility: tuple[str, ...] = Field(default_factory=tuple)
    gaps: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("basis", "facts", "eligibility", "gaps", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("score", "projected_cost", mode="before")
    @classmethod
    def _decimals(cls, value: Any) -> Decimal | None:
        return None if value is None else (value if isinstance(value, Decimal) else Decimal(str(value)))


class RecordRequirement(StrictModel):
    key: str
    label: str
    status: RequirementStatus
    evidence: str


class RecordOfAdviceEvidence(StrictModel):
    """Everything the adviser's record must draw on, sealed, with the requirement checklist for the jurisdiction."""

    schema_id: str = Field(default=RECORD_SCHEMA, alias="schema")
    jurisdiction: str
    vertical_id: str
    vertical_name: str
    family: str
    mode: str
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    shortlist_digest: Sha256Digest
    recommendation_digest: Sha256Digest | None = None
    catalog_digest: Sha256Digest
    catalog_completeness: str
    objective: str
    fact_find: dict[str, Any] = Field(default_factory=dict)
    fact_find_gaps: tuple[str, ...] = Field(default_factory=tuple)
    authorities: tuple[str, ...] = Field(default_factory=tuple)
    recommended: ProductEvidence | None = None
    alternatives: tuple[ProductEvidence, ...] = Field(default_factory=tuple)
    rationale: tuple[str, ...] = Field(default_factory=tuple)
    disclosures: tuple[str, ...] = Field(default_factory=tuple)
    remuneration_disclosure: str
    approval: dict[str, Any] = Field(default_factory=dict)
    requirements: tuple[RecordRequirement, ...] = Field(default_factory=tuple)
    outline: tuple[str, ...] = Field(default_factory=tuple)
    switching: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    needs: dict[str, Any] = Field(default_factory=dict)
    benefit_fit: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    rule_disclosures: tuple[str, ...] = Field(default_factory=tuple)
    remuneration: dict[str, Any] = Field(default_factory=dict)
    strategy: dict[str, Any] = Field(default_factory=dict)
    serviceability: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    complete: bool
    prepared_at: str
    record_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("fact_find_gaps", "authorities", "alternatives", "rationale", "disclosures", "requirements", "outline", "switching", "benefit_fit", "rule_disclosures", "serviceability", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RecordOfAdviceEvidence:
        if self.complete and any(item.status == "missing" for item in self.requirements):
            raise ValueError("a record with a missing requirement is not complete")
        from lightbulb.finance_advice_retirement import RetirementProjection, TaxEstimate

        for key, model in (("tax", TaxEstimate), ("retirement", RetirementProjection)):
            if self.strategy.get(key):
                evidence = model.model_validate(self.strategy[key])
                if evidence.state_digest != self.state_digest or evidence.jurisdiction != self.jurisdiction:
                    raise ValueError("tax and retirement evidence must belong to the record's exact state and jurisdiction")
        if not skip_digests(info) and self.record_digest != sealed_digest(RecordOfAdviceEvidence, self, "record_digest"):
            raise ValueError("record_digest must commit the exact record")
        return self

    def missing(self) -> tuple[str, ...]:
        return tuple(item.label for item in self.requirements if item.status == "missing")


def _cited_facts(product: Product) -> list[CitedFact]:
    by_id = {source.source_id: source for source in product.sources if source.source_id}
    first = product.sources[0] if product.sources else None
    facts: list[CitedFact] = []
    for fact in product.pricing:
        source = next((by_id[sid] for sid in fact.source_ids if sid in by_id), None) or (first if fact.support == "product_cited" else None)
        facts.append(CitedFact(item=fact.item, value=None if fact.value is None else str(fact.value), unit=fact.unit, support=fact.support, source_url=source.url if source else None, retrieved_at=source.retrieved_at if source else None, document_title=source.document_title if source else None, quote=(fact.quote or (source.quote if source else None))))
    return facts


def _evidence(entry: Any, product: Product) -> ProductEvidence:
    return ProductEvidence(product_ref=product.product_ref, provider_name=product.provider_name, product_name=product.product_name, taxonomy_class=product.taxonomy_class, confidence=product.confidence, pricing_kind=product.pricing_kind, suitability=entry.suitability.outcome, score=entry.score, projected_cost=getattr(entry, "projected_cost", None), projection_horizon_years=getattr(entry, "projection_horizon_years", None), basis=entry.score_basis, facts=_cited_facts(product), eligibility=product.eligibility, gaps=product.gaps[:6])


def _fact_find(state: ClientState) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("amount", "lvr_percent", "term_years", "residency", "age_band", "income_band", "purpose", "region"):
        value = getattr(state, key)
        if value not in (None, "", "unstated"):
            out[key] = str(value) if isinstance(value, Decimal) else value
    for key, value in sorted(state.facts.items()):
        out[key] = value
    if state.preferences:
        out["preferences"] = list(state.preferences)
    return out


def _requirements(jurisdiction: str, family: str, mode: str, *, fact_find: Mapping[str, Any], gaps: Sequence[str], authorities: Sequence[str], recommended: ProductEvidence | None, alternatives: Sequence[ProductEvidence], rationale: Sequence[str], disclosures: Sequence[str], remuneration: str, approval: Mapping[str, Any], completeness: str, existing_products: bool) -> list[RecordRequirement]:
    def req(key: str, label: str, ok: bool, evidence: str, applicable: bool = True) -> RecordRequirement:
        return RecordRequirement(key=key, label=label, status="not_applicable" if not applicable else ("satisfied" if ok else "missing"), evidence=evidence[:400])

    cited = recommended is not None and all(fact.source_url for fact in recommended.facts) and bool(recommended.facts)
    facts_named = [key for key in ("amount", "purpose", "term_years", "lvr_percent", "income_band", "age_band", "risk_profile", "horizon_years") if key in fact_find]
    personal = mode == "personal_recommendation"
    rows = [
        req("scope", "Scope of the advice: jurisdiction, vertical and mode stated", True, f"{jurisdiction} {family}; {mode}"),
        req("objectives", "Client objectives recorded", bool(fact_find) and "objective" not in gaps, "objective and decision facts from the fact find"),
        req("situation", "Client situation recorded: the decision facts suitability and cost rest on", bool(facts_named) and not gaps, "facts: " + ", ".join(facts_named) + (f"; missing: {', '.join(gaps)}" if gaps else "")),
        req("alternatives", "Alternatives considered and why they were not chosen", len(alternatives) >= 1, f"{len(alternatives)} alternative(s) on the shortlist with suitability and basis"),
        req("costs", "Costs and fees of the recommended product cited to the provider's own documents", cited, "every pricing fact carries a source URL" if cited else "a recommended product fact lacks a source", applicable=personal),
        req("remuneration", "Remuneration, commissions and conflicts disclosed", bool(remuneration.strip()) and remuneration in disclosures, "plan remuneration disclosure carried into the disclosures"),
        req("authority", "Authority under which the advice is given", bool(authorities), "authorities: " + ", ".join(authorities) if authorities else "the plan holds no authority", applicable=personal),
        req("rationale", "Basis of the recommendation in the adviser's words", bool(rationale), f"{len(rationale)} rationale line(s)", applicable=personal),
        req("coverage_warning", "Warning where the catalog is a partial sample or facts are incomplete", completeness == "census_complete" or any("partial" in item.lower() or "not represented" in item.lower() for item in disclosures), f"catalog {completeness}"),
        req("approval", "Licensed adviser's approval bound to this exact recommendation", bool(approval.get("approval_ref")) and bool(approval.get("adviser_ref")), "approval " + str(approval.get("approval_ref") or "(none)"), applicable=personal),
        req("replacement", "Replacement product comparison where the client already holds a product", bool(fact_find.get("existing_products_compared")), "existing products named in the fact find" if existing_products else "no existing product named", applicable=existing_products),
    ]
    if family == "credit":
        rows.append(req("not_unsuitable", "Assessment that the credit product is not unsuitable: structured checks on amount, term, LVR and eligibility", recommended is not None and recommended.suitability in ("eligible", "unassessed"), f"suitability {recommended.suitability if recommended else 'n/a'}", applicable=personal))
        rows.append(req("cost_of_credit", "Cost of credit stated: rate, fees and a projected cost over the horizon", recommended is not None and (recommended.projected_cost is not None or any("rate" in fact.item.lower() for fact in recommended.facts)), "projected cost " + str(recommended.projected_cost) if recommended and recommended.projected_cost is not None else "rate facts only", applicable=personal))
    if family in ("investments", "insurance"):
        rows.append(req("know_your_product", "Product facts known: fees, risk or premium basis and key terms cited", recommended is not None and bool(recommended.facts), f"{len(recommended.facts) if recommended else 0} cited fact(s)", applicable=personal))
        rows.append(req("suitability_determination", "Suitability determination against risk profile, horizon, age and cover", recommended is not None and recommended.suitability != "ineligible", f"suitability {recommended.suitability if recommended else 'n/a'}", applicable=personal))
    if jurisdiction == "CA" and family == "credit":
        rows.append(req("cost_of_borrowing", "Cost of borrowing disclosure: rate, fees and total cost figure", recommended is not None and recommended.projected_cost is not None, "projected cost over the horizon" if recommended and recommended.projected_cost is not None else "no projected cost", applicable=personal))
    return rows


_OUTLINE = {
    "AU": ("Scope of advice", "About you: objectives and situation", "What we considered", "Our recommendation and why", "Costs, fees and how we are paid", "Risks and warnings", "Authority and approval", "Next steps"),
    "CA": ("Scope and registration", "Know your client: objectives and situation", "Products compared", "Suitability determination and recommendation", "Cost of borrowing / fees and compensation", "Conflicts of interest", "Approval and acknowledgement", "Next steps"),
}


def record_of_advice_evidence(plan: AdvicePlan | Mapping[str, Any], state: ClientState | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any], catalog: ProductCatalog | Mapping[str, Any], *, recommendation: Recommendation | Mapping[str, Any] | None = None, approval: Mapping[str, Any] | None = None, fact_find_gaps: Sequence[str] = (), prepared_at: str, switching: Sequence[Mapping[str, Any]] = (), needs: Mapping[str, Any] | None = None, benefit_fit: Sequence[Mapping[str, Any]] = (), rule_disclosures: Sequence[str] = (), remuneration: Mapping[str, Any] | None = None, strategy: Mapping[str, Any] | None = None, serviceability: Sequence[Mapping[str, Any]] = ()) -> RecordOfAdviceEvidence:
    """Assemble the evidence and the checklist; the adviser writes and signs the document."""

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    rec = None if recommendation is None else (recommendation if isinstance(recommendation, Recommendation) else Recommendation.model_validate(dict(detached(recommendation))))
    if sl.plan_digest != p.plan_digest or sl.state_digest != s.state_digest or sl.catalog_digest != c.catalog_digest:
        raise ValueError("RECORD_INPUTS_MISMATCH: the shortlist was prepared from a different plan, state or catalog")
    if rec is not None and rec.shortlist_digest != sl.shortlist_digest:
        raise ValueError("RECORD_INPUTS_MISMATCH: the recommendation was prepared from a different shortlist")
    vertical = load_vertical_registry().vertical(s.vertical_id)
    family = sector_family(vertical.sector)
    by_ref = {entry.product_ref: entry for entry in sl.entries}
    recommended = None
    alternatives: list[ProductEvidence] = []
    if rec is not None:
        recommended = _evidence(by_ref[rec.primary_product_ref], c.product(rec.primary_product_ref))
        for ref in rec.alternatives:
            if ref in by_ref:
                alternatives.append(_evidence(by_ref[ref], c.product(ref)))
    for entry in sl.entries:
        if (rec is None or entry.product_ref != rec.primary_product_ref) and all(item.product_ref != entry.product_ref for item in alternatives):
            alternatives.append(_evidence(entry, c.product(entry.product_ref)))
    fact_find = _fact_find(s)
    disclosures = list(dict.fromkeys([*(rec.disclosures if rec else ()), *sl.disclosures]))
    if p.remuneration_disclosure not in disclosures:
        disclosures.append(p.remuneration_disclosure)
    authorities = [f"{item.kind} ({item.holder_ref})" for item in p.authorities if s.vertical_id in item.scope_verticals]
    approval_view = dict(approval or {})
    existing = bool(s.facts.get("existing_products"))
    rationale: list[str] = list(rec.rationale) if rec else []
    for item in switching:
        analysis = dict(detached(item))
        rationale.append(f"stay or switch ({analysis.get('candidate_product_name')}): {analysis.get('verdict')}; " + "; ".join(str(reason) for reason in analysis.get("reasons") or ()))
    if needs:
        assessed = dict(detached(needs))
        if assessed.get("need") is not None:
            rationale.append(f"assessed need ({assessed.get('kind')}): {assessed.get('need')} {assessed.get('unit')} from " + ", ".join(f"{k} {v}" for k, v in (assessed.get("components") or {}).items()) + ("; assumptions: " + "; ".join(assessed.get("assumptions") or ()) if assessed.get("assumptions") else ""))
        else:
            rationale.append("assessed need: incomplete; missing " + ", ".join(assessed.get("missing") or ("facts",)))
    for item in benefit_fit:
        fit = dict(detached(item))
        rationale.append(f"benefit fit ({fit.get('product_name')}): {fit.get('fit')}" + ("; " + "; ".join(str(note) for note in fit.get("notes") or ()) if fit.get("notes") else ""))
    disclosures = [*disclosures, *rule_disclosures]
    if strategy:
        plan_view = dict(detached(strategy))
        from lightbulb.finance_advice_retirement import RetirementProjection, TaxEstimate

        for key, model in (("tax", TaxEstimate), ("retirement", RetirementProjection)):
            if plan_view.get(key):
                evidence = model.model_validate(plan_view[key])
                if evidence.state_digest != s.state_digest or evidence.jurisdiction != s.jurisdiction:
                    raise ValueError("STRATEGY_STATE_MISMATCH: tax and retirement evidence must belong to the record's state")
                disclosures.extend(line for line in evidence.disclosures if line not in disclosures)
        for line in plan_view.get("goal_lines") or ():
            rationale.append(f"strategy: {line}")
    for item in serviceability:
        view = dict(detached(item))
        rationale.append(f"serviceability ({view.get('product_name') or view.get('product_ref')}): {view.get('verdict')}" + ("; " + "; ".join(str(reason) for reason in view.get("reasons") or ()) if view.get("reasons") else ""))
    if remuneration:
        pay = dict(detached(remuneration))
        for line in pay.get("statements") or ():
            if line not in disclosures:
                disclosures.append(str(line))
    requirements = _requirements(p.jurisdiction, family, p.mode, fact_find=fact_find, gaps=list(fact_find_gaps), authorities=authorities, recommended=recommended, alternatives=alternatives, rationale=rationale, disclosures=disclosures, remuneration=p.remuneration_disclosure, approval=approval_view, completeness=sl.catalog_completeness, existing_products=existing)
    complete = not any(item.status == "missing" for item in requirements)
    return seal(RecordOfAdviceEvidence, {
        "jurisdiction": p.jurisdiction, "vertical_id": s.vertical_id, "vertical_name": vertical.name, "family": family, "mode": p.mode, "plan_digest": p.plan_digest, "state_digest": s.state_digest, "shortlist_digest": sl.shortlist_digest,
        "recommendation_digest": rec.recommendation_digest if rec else None, "catalog_digest": c.catalog_digest, "catalog_completeness": sl.catalog_completeness, "objective": s.objective, "fact_find": fact_find, "fact_find_gaps": list(fact_find_gaps),
        "authorities": authorities, "recommended": recommended.to_dict() if recommended else None, "alternatives": [item.to_dict() for item in alternatives[:12]], "rationale": rationale, "disclosures": disclosures,
        "remuneration_disclosure": p.remuneration_disclosure, "approval": approval_view, "requirements": [item.to_dict() for item in requirements], "switching": [dict(detached(item)) for item in switching], "needs": dict(detached(needs)) if needs else {}, "benefit_fit": [dict(detached(item)) for item in benefit_fit], "rule_disclosures": list(rule_disclosures), "remuneration": dict(detached(remuneration)) if remuneration else {}, "strategy": dict(detached(strategy)) if strategy else {}, "serviceability": [dict(detached(item)) for item in serviceability], "outline": list(_OUTLINE.get(p.jurisdiction, _OUTLINE["AU"])), "complete": complete, "prepared_at": prepared_at,
    }, "record_digest")


def record_markdown(record: RecordOfAdviceEvidence | Mapping[str, Any]) -> str:
    """The evidence laid out under the document outline, for the adviser to write from."""

    r = record if isinstance(record, RecordOfAdviceEvidence) else RecordOfAdviceEvidence.model_validate(dict(detached(record)))
    lines = [f"# Record of advice evidence — {r.vertical_name} ({r.jurisdiction})", "", f"Mode {r.mode}; prepared {r.prepared_at}; catalog {r.catalog_completeness.replace('_', ' ')}; record digest {r.record_digest[:16]}…", "", "This is the evidence for the adviser's record, not the record; the licensed adviser writes and signs the document.", ""]
    lines += ["## Checklist", ""]
    for item in r.requirements:
        mark = {"satisfied": "[x]", "missing": "[ ]", "not_applicable": "[–]"}[item.status]
        lines.append(f"- {mark} {item.label} — {item.evidence}")
    lines.append("")
    for section in r.outline:
        lines.append(f"## {section}")
        lines.append("")
    lines += ["## Objective and fact find", "", f"Objective: {r.objective}", ""]
    for key, value in r.fact_find.items():
        lines.append(f"- {key}: {value}")
    if r.fact_find_gaps:
        lines.append(f"- still missing: {', '.join(r.fact_find_gaps)}")
    lines.append("")
    if r.recommended:
        lines += ["## Recommended product", "", f"{r.recommended.provider_name} — {r.recommended.product_name} ({r.recommended.taxonomy_class}, {r.recommended.confidence}, suitability {r.recommended.suitability})", ""]
        for fact in r.recommended.facts:
            lines.append(f"- {fact.item}: {fact.value or '—'} {fact.unit or ''} [{fact.support}] {fact.source_url or ''} {('retrieved ' + fact.retrieved_at) if fact.retrieved_at else ''} {('“' + fact.quote[:120] + '”') if fact.quote else ''}".rstrip())
        lines.append("")
    if r.alternatives:
        lines += ["## Alternatives considered", ""]
        for item in r.alternatives:
            lines.append(f"- {item.provider_name} — {item.product_name}: suitability {item.suitability}; " + (f"score {item.score}; " if item.score is not None else "") + (f"projected cost {item.projected_cost} over {item.projection_horizon_years} years; " if item.projected_cost is not None else "") + "; ".join(item.basis[:2]))
        lines.append("")
    lines += ["## Disclosures", ""]
    for item in r.disclosures:
        lines.append(f"- {item}")
    if r.switching:
        lines.append("")
        lines.append("## Stay or switch")
        for item in r.switching:
            lines.append(f"- {item.get('candidate_product_name')}: stay {item.get('stay_total')} against switch {item.get('switch_total')} over {item.get('horizon_years')} years; {item.get('verdict')}. " + " ".join(str(reason) for reason in item.get('reasons') or ()))
    if r.needs:
        lines.append("")
        lines.append("## Needs assessment")
        lines.append(f"- {r.needs.get('kind')}: {r.needs.get('need')} {r.needs.get('unit')}" if r.needs.get("need") is not None else "- incomplete: " + ", ".join(r.needs.get("missing") or ()))
        for key, value in (r.needs.get("components") or {}).items():
            lines.append(f"  - {key}: {value}")
        for item in r.needs.get("assumptions") or ():
            lines.append(f"  - assumption: {item}")
    for item in r.benefit_fit:
        lines.append(f"- benefit fit, {item.get('product_name')}: {item.get('fit')}" + ("; " + "; ".join(str(note) for note in item.get('notes') or ()) if item.get('notes') else ""))
    if r.rule_disclosures:
        lines.append("")
        lines.append("## The jurisdiction's rules applied")
        for item in r.rule_disclosures:
            lines.append(f"- {item}")
    if r.strategy:
        lines.append("")
        lines.append("## Cash flow and goals")
        for item in r.strategy.get("goal_lines") or ():
            lines.append(f"- {item}")
        for item in r.strategy.get("assumptions") or ():
            lines.append(f"  - assumption: {item}")
        tax = r.strategy.get("tax")
        if tax:
            lines.extend(["", "## Tax illustration", "", f"- {tax.get('status')}: bracket tax before reliefs {tax.get('bracket_tax_before_reliefs', 'unassessed')}; this is not total tax."])
            lines.extend(f"- Missing: {item}" for item in tax.get("missing") or ())
            lines.extend(f"- {item}" for item in tax.get("disclosures") or ())
        retirement = r.strategy.get("retirement")
        if retirement:
            lines.extend(["", "## Retirement illustration", "", f"- {retirement.get('status')}; bounded scenario before personal withdrawal tax, not an adequacy determination."])
            for row in retirement.get("rows") or ():
                lines.append(f"- Year {row['year']}, age {row['end_age']}, {row['phase']}: closing balance {row['closing_balance']}, paid draw {row['paid_draw']}, unfunded draw {row['unfunded_draw']}.")
            lines.extend(f"- {item['scheme']}: {item['status']}; {item['basis']}" for item in retirement.get("contribution_checks") or ())
            lines.extend(f"- Missing: {item}" for item in retirement.get("missing") or ())
            lines.extend(f"- {item}" for item in retirement.get("disclosures") or ())
    if r.serviceability:
        lines.append("")
        lines.append("## Serviceability")
        for item in r.serviceability:
            lines.append(f"- {item.get('product_name') or item.get('product_ref')}: {item.get('verdict')}" + ("; " + "; ".join(str(reason) for reason in item.get('reasons') or ()) if item.get('reasons') else ""))
    if r.remuneration:
        lines.append("")
        lines.append("## How we are paid")
        for item in r.remuneration.get("statements") or ():
            lines.append(f"- {item}")
    return "\n".join(lines)


FINANCE_ADVICE_RECORD_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_record.v1",
    "schemas": [RECORD_SCHEMA],
    "hard_rules": [
        "the record is evidence for the adviser's document, never the document; no compliance is claimed",
        "every product fact in the record cites the provider's own document with URL, retrieval date and quote where the catalog carries them",
        "the record binds the exact plan, state, shortlist, recommendation and catalog digests; a mismatch is refused",
        "the checklist names what is missing; a record with a missing requirement is not complete",
    ],
}

__all__ = [
    "CitedFact",
    "FINANCE_ADVICE_RECORD_MANIFEST",
    "ProductEvidence",
    "RECORD_SCHEMA",
    "RecordOfAdviceEvidence",
    "RecordRequirement",
    "record_markdown",
    "record_of_advice_evidence",
]
