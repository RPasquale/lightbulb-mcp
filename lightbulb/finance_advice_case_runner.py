"""The case runner: one client's advice case from engagement to the adviser's approval request, then on to presentation, implementation and review.

Everything an adviser's back office does to assemble a file happens here in one deterministic
composition over the SDK's own modules: the engagement gate, the fact find (stopping with the
questions still owed), the strategy and serviceability, the published-view shortlist with quotes,
the stay-or-switch, needs and rules judgement, a recommendation whose rationale is composed only
from sealed basis strings, the record of advice with its remuneration disclosure, the licence
verification, the compliance checklist, the document, the template explanation, and the approval
request bound to all of it. Every stop is a typed state on the run, never an exception across the
boundary; every artifact is sealed and bound to the one before it by digest.

Nothing here decides. The recommendation waits for the licensed adviser's approval, a platform
decision by someone other than the requester, bound to the recommendation, the checklist and the
licence verification. No model runs anywhere in the runner.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, Sha256Digest, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.company_engine_store import EngineAdvanceOutcome, EngineRuntime
from lightbulb.company_execution_bridge import BridgeError
from lightbulb.finance_advice_cases import case_summary, implement_case, open_case, open_successor_case, present_case, request_adviser_approval, resume_with_adviser_approval, review_case
from lightbulb.finance_advice_catalog import ProductCatalog, VerticalRegistry, load_vertical_registry
from lightbulb.finance_advice_compliance import compliance_checklist, verification_for
from lightbulb.finance_advice_document import advice_document
from lightbulb.finance_advice_decision import AdviceDecision, replacement_decision
from lightbulb.finance_advice_engagement import engagement_gaps
from lightbulb.finance_advice_engine import AdviceError, AdvicePlan, ClientState, Shortlist, ShortlistEntry, fact_find_receipt, prepare_recommendation, recommendation_receipt, sector_family, shortlist_products, shortlist_receipt
from lightbulb.finance_advice_fact_find import fact_find_gaps, fact_find_questions
from lightbulb.finance_advice_licence import verifications_for_plan
from lightbulb.finance_advice_needs import assess_needs, benefit_fit, needs_kind
from lightbulb.finance_advice_observations import published_catalog
from lightbulb.finance_advice_prose import deterministic_explanation
from lightbulb.finance_advice_quotes import catalog_with_quotes
from lightbulb.finance_advice_record import record_of_advice_evidence
from lightbulb.finance_advice_remuneration import remuneration_disclosure
from lightbulb.finance_advice_rules import apply_rules
from lightbulb.finance_advice_strategy import goal_lines, serviceability, strategy_plan
from lightbulb.finance_advice_retirement import AdviceRetirementError
from lightbulb.finance_advice_supervision import ComplaintFile, supervision_file

CASE_RUN_SCHEMA = "lightbulb.finance_advice_case_run.v1"
RUN_STAGES: tuple[str, ...] = ("engage", "fact_find", "strategy", "shortlist", "judgement", "decision", "recommend", "record", "remuneration", "verify_licence", "compliance", "document", "explanation", "approval_request", "approved", "presented", "implemented", "reviewed")
CaseStop = Literal["needs_input", "prepared", "awaiting_approval", "refused", "completed"]
RunMode = Literal["prepare_only", "request_approval"]
_INSURANCE_KINDS = frozenset({"life", "income_protection", "tpd", "trauma"})


class CaseRun(StrictModel):
    """Where one case run stopped, with every digest it bound and every sealed artifact it produced."""

    schema_id: Literal["lightbulb.finance_advice_case_run.v1"] = CASE_RUN_SCHEMA
    entity_ref: str = Field(min_length=1)
    vertical_id: str | None = None
    plan_digest: Sha256Digest
    status: str | None = None
    stop: CaseStop
    stage_reached: str
    engagement_digest: Sha256Digest | None = None
    state_digest: Sha256Digest | None = None
    strategy_digest: Sha256Digest | None = None
    tax_digest: Sha256Digest | None = None
    retirement_digest: Sha256Digest | None = None
    supervision_digest: Sha256Digest | None = None
    shortlist_digest: Sha256Digest | None = None
    decision_digest: Sha256Digest | None = None
    recommendation_digest: Sha256Digest | None = None
    record_digest: Sha256Digest | None = None
    remuneration_digest: Sha256Digest | None = None
    verification_digest: Sha256Digest | None = None
    checklist_digest: Sha256Digest | None = None
    document_digest: Sha256Digest | None = None
    explanation_digest: Sha256Digest | None = None
    approval_request_ref: str | None = None
    refusal: dict[str, Any] = Field(default_factory=dict)
    questions_owed: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    notes: tuple[str, ...] = Field(default_factory=tuple)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    prepared_at: str
    run_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("questions_owed", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> CaseRun:
        if self.decision_digest is not None or self.artifacts.get("advice_decision") is not None:
            decision = AdviceDecision.model_validate(self.artifacts.get("advice_decision"))
            if (decision.decision_digest, decision.case_ref, decision.plan_digest, decision.state_digest, decision.shortlist_digest) != (self.decision_digest, self.entity_ref, self.plan_digest, self.state_digest, self.shortlist_digest):
                raise ValueError("the decision must be bound to this case run and its evidence")
        if not skip_digests(info) and self.run_digest != sealed_digest(CaseRun, self, "run_digest"):
            raise ValueError("run_digest does not match the run")
        return self

    def artifact(self, kind: str) -> Any:
        return self.artifacts.get(kind)


class _Run:
    """The mutable working set of one run; sealed into a CaseRun at every stop."""

    def __init__(self, entity_ref: str, plan: AdvicePlan, prepared_at: str) -> None:
        self.entity_ref = entity_ref
        self.plan = plan
        self.prepared_at = prepared_at
        self.stage = "engage"
        self.digests: dict[str, str | None] = {}
        self.artifacts: dict[str, Any] = {}
        self.notes: list[str] = []
        self.status: str | None = None
        self.vertical_id: str | None = None

    def keep(self, kind: str, obj: Any, digest_field: str | None = None, digest_key: str | None = None) -> Any:
        self.artifacts[kind] = dict(detached(obj)) if not isinstance(obj, (str, int, float)) else obj
        if digest_field is not None:
            self.digests[digest_key or digest_field] = str(getattr(obj, digest_field))
        return obj

    def stop(self, stop: CaseStop, *, refusal: Mapping[str, Any] | None = None, questions: Sequence[Mapping[str, Any]] = ()) -> CaseRun:
        payload = {
            "entity_ref": self.entity_ref, "vertical_id": self.vertical_id, "plan_digest": self.plan.plan_digest, "status": self.status, "stop": stop, "stage_reached": self.stage,
            "engagement_digest": self.digests.get("engagement_digest"), "state_digest": self.digests.get("state_digest"), "strategy_digest": self.digests.get("strategy_digest"), "shortlist_digest": self.digests.get("shortlist_digest"), "recommendation_digest": self.digests.get("recommendation_digest"), "record_digest": self.digests.get("record_digest"), "remuneration_digest": self.digests.get("remuneration_digest"), "verification_digest": self.digests.get("verification_digest"), "checklist_digest": self.digests.get("checklist_digest"), "document_digest": self.digests.get("document_digest"), "explanation_digest": self.digests.get("explanation_digest"), "approval_request_ref": self.digests.get("approval_request_ref"),
            "refusal": dict(refusal) if refusal else {}, "questions_owed": [dict(q) for q in questions], "notes": list(dict.fromkeys(self.notes)), "artifacts": self.artifacts, "prepared_at": self.prepared_at,
        }
        for key in ("tax_digest", "retirement_digest", "decision_digest"):
            payload[key] = self.digests.get(key)
        _refresh_supervision(payload, as_of=self.prepared_at)
        return seal(CaseRun, payload, "run_digest")


def _refresh_supervision(payload: dict[str, Any], *, as_of: str) -> None:
    artifacts = payload["artifacts"]
    if artifacts.get("record_evidence") and artifacts.get("compliance_checklist"):
        file = supervision_file(case_ref=payload["entity_ref"], record=artifacts["record_evidence"], checklist=artifacts["compliance_checklist"], stage=payload["stage_reached"], complaints=artifacts.get("complaint_files") or (), as_of=as_of)
        artifacts["supervision_file"] = file.to_dict()
        payload["supervision_digest"] = file.supervision_digest


def _refusal_of(outcome: EngineAdvanceOutcome) -> dict[str, Any] | None:
    receipt = getattr(outcome.result, "receipt", None)
    code = getattr(receipt, "rejection_code", None)
    if outcome.persisted or code is None:
        return None
    recovery = getattr(receipt, "recovery", None)
    return {"code": str(code), "message": str(getattr(receipt, "rejection_reason", None) or getattr(receipt, "rejection_message", None) or getattr(receipt, "message", None) or code), "disposition": str(getattr(recovery, "disposition", None) or "")}


def _status_of(outcome: EngineAdvanceOutcome, fallback: str | None) -> str | None:
    if outcome.record is not None and outcome.record.get("status"):
        return str(outcome.record["status"])
    return fallback


def _current_status(runtime: EngineRuntime, entity_ref: str) -> str | None:
    try:
        return str(case_summary(runtime, entity_ref).get("status") or "") or None
    except (LookupError, KeyError, ValueError):
        return None


def _rationale_from(entry: ShortlistEntry, shortlist: Shortlist, plan: AdvicePlan, *, strategy: Mapping[str, Any] | None, switching: Sequence[Mapping[str, Any]], needs: Mapping[str, Any] | None, benefit: Mapping[str, Any] | None = None, serviceability_view: Mapping[str, Any] | None = None) -> tuple[str, ...]:
    """Every rationale line is a sealed basis string, a shortlist disclosure, a goal line, a switching verdict, a needs-fit line or the plan's remuneration disclosure; never free text."""
    lines: list[str] = [str(item) for item in entry.score_basis]
    lines.extend(str(item) for item in shortlist.disclosures if "partial" in item.lower() or "not represented" in item.lower() or "identity" in item.lower())
    if strategy:
        lines.extend(f"strategy: {item}" for item in dict(detached(strategy)).get("goal_lines") or ())
    for item in switching:
        view = dict(detached(item))
        lines.append(f"stay or switch ({view.get('candidate_product_name')}): {view.get('verdict')}; " + "; ".join(str(reason) for reason in view.get("reasons") or ()))
    if needs and benefit:
        fit = dict(detached(benefit))
        lines.append(f"benefit fit: {fit.get('fit')}" + ("; " + "; ".join(str(note) for note in fit.get("notes") or ()) if fit.get("notes") else ""))
    if serviceability_view:
        view = dict(detached(serviceability_view))
        lines.append(f"serviceability: {view.get('verdict')}" + ("; " + "; ".join(str(reason) for reason in view.get("reasons") or ()) if view.get("reasons") else ""))
    lines.append(plan.remuneration_disclosure)
    return tuple(dict.fromkeys(line for line in lines if line))


def run_case(plan: AdvicePlan | Mapping[str, Any], *, runtime: EngineRuntime, entity_ref: str, scope: Mapping[str, Any], engagement: Mapping[str, Any], state: ClientState | Mapping[str, Any], catalog: ProductCatalog | Mapping[str, Any], as_of: str, actor_ref: str, prepared_by_ref: str, observations: Sequence[Mapping[str, Any]] = (), quote_profiles: Sequence[Mapping[str, Any]] = (), holdings: Sequence[Mapping[str, Any]] = (), remuneration_schedule: Mapping[str, Any] | None = None, conflicts_register: Mapping[str, Any] | None = None, licence_snapshots: Sequence[Mapping[str, Any]] = (), adviser_ref: str | None = None, authority: Mapping[str, Any] | None = None, mode: RunMode = "request_approval", horizon_years: int = 5, knowledge_at: str | None = None, registry: VerticalRegistry | None = None) -> CaseRun:
    """Run one case from engagement to the approval request; stop early, by typed state, wherever the file is not ready."""

    p = plan if isinstance(plan, AdvicePlan) else AdvicePlan.model_validate(dict(detached(plan)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    c = catalog if isinstance(catalog, ProductCatalog) else ProductCatalog.model_validate(dict(detached(catalog)))
    reg = registry or load_vertical_registry()
    stamp = timestamp(as_of, field_name="as_of")
    run = _Run(entity_ref, p, stamp)
    run.vertical_id = s.vertical_id
    vertical = reg.vertical(s.vertical_id)
    family = sector_family(vertical.sector) if vertical is not None else "credit"

    # engage: the disclosures, the consent and the risk profile the regulator asks for first
    run.stage = "engage"
    pack = dict(detached(engagement))
    gaps = engagement_gaps(pack, vertical_id=s.vertical_id)
    run.keep("engagement_pack", pack)
    run.digests["engagement_digest"] = pack.get("engagement_digest")
    if gaps:
        return run.stop("needs_input", refusal={"code": "ENGAGEMENT_INCOMPLETE", "message": "the engagement lacks " + ", ".join(gaps)}, questions=[{"fact": gap, "kind": "engagement", "required": True, "why": "required before advice under the plan's jurisdiction"} for gap in gaps])
    status = _current_status(runtime, entity_ref)
    if status is None:
        opened = open_case(runtime, entity_ref=entity_ref, scope=scope, receipt={"client_ref": s.client_ref, "vertical_id": s.vertical_id, "objective": s.objective, "evidence_refs": [f"engagement:{str(pack.get('engagement_digest'))[:16]}"]}, opened_at=stamp, actor_ref=actor_ref, engagement=pack)
        status = str(opened.get("status") if isinstance(opened, Mapping) else getattr(opened, "status", "intake")) or "intake"
    run.status = status

    # fact find: stop with the questions still owed
    run.stage = "fact_find"
    gap_view = fact_find_gaps(s, registry=reg)
    run.keep("client_state", s, "state_digest")
    run.keep("fact_find_gaps", gap_view)
    if not gap_view.complete or not s.fact_find_complete:
        missing = set(gap_view.required_missing)
        questions = [q for q in fact_find_questions(s.vertical_id, registry=reg) if q.get("fact") in missing] or [{"fact": key, "required": True, "why": "required by the vertical's fact find"} for key in sorted(missing)]
        if not s.fact_find_complete and not missing:
            questions = [{"fact": "fact_find_complete", "required": True, "why": "the client confirms the fact find is complete"}]
        return run.stop("needs_input", refusal={"code": "FACT_FIND_GAPS", "message": "the fact find still lacks " + ", ".join(sorted(missing) or ["the client's confirmation"])}, questions=questions)
    if status == "intake":
        outcome = _advance(runtime, entity_ref, "complete_fact_find", fact_find_receipt(s), stamp, actor_ref)
        refusal = _refusal_of(outcome)
        if refusal:
            return run.stop("refused", refusal=refusal)
        run.status = status = _status_of(outcome, "fact_find_complete")

    # strategy: cash flow, goals, debt order, emergency fund; serviceability follows the shortlist
    run.stage = "strategy"
    try:
        strategy = strategy_plan(s.client_ref, s, prepared_at=stamp, horizon_years=horizon_years)
    except AdviceRetirementError as exc:
        return run.stop("refused", refusal={"code": exc.code, "message": str(exc)})
    run.keep("strategy_plan", strategy, "strategy_digest")
    if strategy.tax:
        run.keep("tax_estimate", strategy.tax, "tax_digest")
    if strategy.retirement:
        run.keep("retirement_projection", strategy.retirement, "retirement_digest")
    strategy_view = dict(detached(strategy))
    strategy_view["goal_lines"] = list(goal_lines(strategy.cashflow))
    run.artifacts["strategy_plan"] = strategy_view
    if gap_view.recommended_missing:
        run.notes.append("recommended facts still unstated: " + ", ".join(gap_view.recommended_missing) + "; the strategy names the defaults it used for them")

    # shortlist on the published view, with the client's matched quotes
    run.stage = "shortlist"
    view = published_catalog(c, observations, as_of=stamp, knowledge_at=knowledge_at) if observations else c
    if quote_profiles:
        view, match, quote_notes = catalog_with_quotes(view, observations, state=s, profiles=quote_profiles, as_of=stamp, knowledge_at=knowledge_at)
        run.notes.extend(str(note) for note in quote_notes)
        if match is not None:
            run.keep("quote_profile_match", match)
    try:
        shortlist = shortlist_products(p, s, view, as_of=stamp, registry=reg)
    except AdviceError as exc:
        return run.stop("refused", refusal={"code": exc.code, "message": str(exc)})
    run.keep("shortlist", shortlist, "shortlist_digest")
    if status in ("fact_find_complete", "shortlisted", "recommended"):
        outcome = _advance(runtime, entity_ref, "shortlist", shortlist_receipt(shortlist), stamp, actor_ref)
        refusal = _refusal_of(outcome)
        if refusal:
            return run.stop("refused", refusal=refusal)
        run.status = status = _status_of(outcome, "shortlisted")
    ranked = [entry for entry in shortlist.entries if entry.rankable]
    if not ranked:
        run.notes.append("no product ranks on the published view; the shortlist is prepared and the adviser chooses by judgement")
        return run.stop("prepared")
    primary_entry = ranked[0]
    primary = view.product(primary_entry.product_ref)

    # judgement: stay or switch, needs and fit, the jurisdiction's rules, serviceability
    run.stage = "judgement"
    decision = replacement_decision(case_ref=entity_ref, plan=p, state=s, shortlist=shortlist, candidate=primary, holdings=holdings, family=family, horizon_years=horizon_years, prepared_at=stamp)
    switch_views = [item.to_dict() for item in decision.comparisons] if decision is not None else []
    run.artifacts["switching"] = switch_views
    if decision is not None:
        run.keep("advice_decision", decision, "decision_digest")
        if decision.outcome != "replacement_supported":
            run.stage = "decision"
            run.notes.extend(decision.reasons)
            return run.stop("prepared")
    needs_view = None
    fit_view = None
    if family == "insurance" and needs_kind(s.vertical_id) in _INSURANCE_KINDS:
        needs_obj = assess_needs(s)
        needs_view = run.keep("needs_assessment", needs_obj)
        fit_obj = benefit_fit(primary, needs_obj)
        fit_view = run.keep("benefit_fit", fit_obj)
    adjustments, rule_lines = apply_rules(s, primary, vertical_id=s.vertical_id, horizon_years=horizon_years)
    run.artifacts["rules"] = {"adjustments": [dict(detached(item)) for item in adjustments], "disclosures": list(rule_lines)}
    service_view = None
    if family == "credit":
        service_obj = serviceability(s, primary, family=family, as_of=stamp)
        service_view = run.keep("serviceability", service_obj)

    # recommend: rationale from sealed basis strings only; the engine refuses a general-information plan by code
    run.stage = "recommend"
    rationale = _rationale_from(primary_entry, shortlist, p, strategy=run.artifacts.get("strategy_plan"), switching=switch_views, needs=needs_view and dict(detached(needs_view)), benefit=fit_view and dict(detached(fit_view)), serviceability_view=service_view and dict(detached(service_view)))
    try:
        recommendation = prepare_recommendation(p, shortlist, prepared_at=stamp, prepared_by_ref=prepared_by_ref, primary_product_ref=primary_entry.product_ref, rationale=rationale)
    except AdviceError as exc:
        return run.stop("refused", refusal={"code": exc.code, "message": str(exc)})
    run.keep("recommendation", recommendation, "recommendation_digest")

    # remuneration, then the record that carries it
    run.stage = "remuneration"
    remuneration_view = None
    if remuneration_schedule is not None:
        disclosure = remuneration_disclosure(remuneration_schedule, recommendation, shortlist, register=conflicts_register, state=s, family=family, horizon_years=horizon_years, prepared_at=stamp)
        remuneration_view = dict(detached(run.keep("remuneration_disclosure", disclosure, "disclosure_digest", "remuneration_digest")))
    else:
        run.notes.append("no remuneration schedule supplied; the plan's remuneration disclosure stands alone and the compliance checklist names the gap")

    run.stage = "record"
    record = record_of_advice_evidence(p, s, shortlist, view, recommendation=recommendation, fact_find_gaps=(), prepared_at=stamp, switching=switch_views, needs=needs_view and dict(detached(needs_view)), benefit_fit=[dict(detached(fit_view))] if fit_view else (), rule_disclosures=list(rule_lines), remuneration=remuneration_view, strategy=strategy_view, serviceability=[dict(detached(service_view))] if service_view else ())
    run.keep("record_evidence", record, "record_digest")

    # the licence, verified against the register snapshot by commitment
    run.stage = "verify_licence"
    verification_view = None
    if authority is not None and licence_snapshots:
        verifications = verifications_for_plan([authority], licence_snapshots, as_of=stamp, vertical_id=s.vertical_id, family=family)
        run.artifacts["authority_verifications"] = [dict(detached(item)) for item in verifications]
        chosen = verification_for(p, [dict(detached(item)) for item in verifications], vertical_id=s.vertical_id, as_of=stamp)
        if chosen is not None:
            verification_view = dict(chosen)
            run.artifacts["authority_verification"] = verification_view
            run.digests["verification_digest"] = verification_view.get("verification_digest")
    elif authority is not None:
        run.notes.append("no licence register snapshot supplied; the authority is not verified and the compliance checklist names the gap")

    # the compliance file
    run.stage = "compliance"
    checklist = compliance_checklist(p, s, shortlist, view, recommendation=recommendation, record=dict(detached(record)), switching=switch_views, verifications=[verification_view] if verification_view else (), remuneration=remuneration_view, engagement=pack, serviceability=service_view and dict(detached(service_view)), needs=needs_view and dict(detached(needs_view)), fact_find_gaps=list(gap_view.recommended_missing), as_of=stamp)
    run.keep("compliance_checklist", checklist, "checklist_digest")
    if status in ("shortlisted", "recommended"):
        outcome = _advance(runtime, entity_ref, "recommend", recommendation_receipt(recommendation, checklist_digest=checklist.checklist_digest), stamp, actor_ref)
        refusal = _refusal_of(outcome)
        if refusal:
            return run.stop("refused", refusal=refusal)
        run.status = status = _status_of(outcome, "recommended")

    # the document and the template explanation
    run.stage = "document"
    document = advice_document(record, prepared_at=stamp)
    run.keep("advice_document", document, "document_digest")
    run.stage = "explanation"
    try:
        explanation = deterministic_explanation(record, prepared_at=stamp)
        run.keep("client_explanation", explanation, "explanation_digest")
    except (ValueError, AdviceError) as exc:
        run.notes.append(f"template explanation not produced: {exc}")

    # the approval request, bound to the recommendation, the checklist and the verification
    run.stage = "approval_request"
    if mode == "prepare_only":
        return run.stop("prepared")
    if adviser_ref is None or authority is None:
        run.notes.append("no adviser and authority named; the file is prepared and waits for the approval request")
        return run.stop("prepared")
    if not checklist.complete:
        return run.stop("refused", refusal={"code": "CHECKLIST_INCOMPLETE", "message": "the compliance checklist still lacks " + ", ".join(checklist.missing() if hasattr(checklist, "missing") else [str(checklist.missing_count) + " item(s)"])})
    try:
        outcome = request_adviser_approval(runtime, entity_ref, adviser_ref=adviser_ref, authority=authority, approved_at=stamp, recommendation_digest=recommendation.recommendation_digest, actor_ref=actor_ref, occurred_at=stamp, checklist=dict(detached(checklist)), verification=verification_view)
    except ValueError as exc:
        code, _, message = str(exc).partition(": ")
        return run.stop("refused", refusal={"code": code or "APPROVAL_REFUSED", "message": message or str(exc)})
    if outcome.awaiting_approval and outcome.approval_request is not None:
        request = outcome.approval_request
        run.artifacts["approval_request"] = dict(detached(request))
        run.digests["approval_request_ref"] = str(getattr(request, "request_ref", None) or getattr(request, "idempotency_key", None) or getattr(request, "request_digest", None) or "pending")
        run.status = status
        return run.stop("awaiting_approval")
    refusal = _refusal_of(outcome)
    if refusal:
        return run.stop("refused", refusal=refusal)
    run.status = _status_of(outcome, status)
    run.stage = "approved"
    return run.stop("prepared")


def _advance(runtime: EngineRuntime, entity_ref: str, event: str, receipt: Mapping[str, Any], occurred_at: str, actor_ref: str) -> EngineAdvanceOutcome:
    from lightbulb.finance_advice_cases import advance_case

    return advance_case(runtime, entity_ref, event=event, receipt=receipt, occurred_at=occurred_at, actor_ref=actor_ref)


def _carry(run: CaseRun, *, status: str | None, stop: CaseStop, stage: str, extra_digests: Mapping[str, str | None] | None = None, artifacts: Mapping[str, Any] | None = None, notes: Sequence[str] = (), refusal: Mapping[str, Any] | None = None, as_of: str | None = None) -> CaseRun:
    raw = run.to_dict()
    raw.update({"status": status if status is not None else run.status, "stop": stop, "stage_reached": stage, "refusal": dict(refusal) if refusal else {}, "notes": [*run.notes, *notes], "artifacts": {**run.artifacts, **(dict(artifacts) if artifacts else {})}})
    for key, value in (extra_digests or {}).items():
        raw[key] = value
    raw.pop("run_digest", None)
    stamp = as_of or (raw["artifacts"].get("supervision_file") or {}).get("as_of") or run.prepared_at
    _refresh_supervision(raw, as_of=stamp)
    return seal(CaseRun, raw, "run_digest")


def resume_after_approval(run: CaseRun | Mapping[str, Any], *, runtime: EngineRuntime, task: Mapping[str, Any], occurred_at: str, catalog: ProductCatalog | Mapping[str, Any] | None = None) -> CaseRun:
    """Bind the platform's decision to the waiting approval; on approval the record, the document and the checklist are re-sealed with it."""

    r = run if isinstance(run, CaseRun) else CaseRun.model_validate(dict(detached(run)))
    blocked = _blocked_replacement(r)
    if blocked is not None:
        return blocked
    stamp = timestamp(occurred_at, field_name="occurred_at")
    try:
        outcome = resume_with_adviser_approval(runtime, r.entity_ref, task, occurred_at=stamp)
    except LookupError as exc:
        return _carry(r, status=None, stop="refused", stage="approval_request", refusal={"code": "NO_PENDING_APPROVAL", "message": str(exc)})
    except (BridgeError, ValueError) as exc:
        text = str(exc)
        code, _, message = text.partition(": ")
        return _carry(r, status=None, stop="refused", stage="approval_request", refusal={"code": code if code.isupper() else "APPROVAL_NOT_BOUND", "message": message or text})
    refusal = _refusal_of(outcome)
    if refusal:
        return _carry(r, status=None, stop="refused", stage="approval_request", refusal=refusal)
    if not outcome.persisted:
        return _carry(r, status=None, stop="refused", stage="approval_request", refusal={"code": "APPROVAL_NOT_GRANTED", "message": "the platform decision did not approve the recommendation"})
    status = _status_of(outcome, "adviser_approved")
    ledger = dict(detached(runtime.load(r.entity_ref).ledger))
    approval = {"approval_ref": ledger.get("approval_ref"), "adviser_ref": ledger.get("adviser_ref"), "authority_kind": ledger.get("authority_kind"), "approved_at": ledger.get("approved_at"), "recommendation_digest": ledger.get("recommendation_digest") or r.recommendation_digest, "checklist_digest": ledger.get("checklist_digest"), "verification_digest": ledger.get("verification_digest")}
    artifacts: dict[str, Any] = {"approval": approval}
    digests: dict[str, str | None] = {}
    notes: list[str] = []
    if catalog is not None and all(approval.values()):
        record_view = r.artifacts.get("record_evidence") or {}
        plan_view = None
        try:
            plan_view = runtime.plan  # type: ignore[attr-defined]
        except AttributeError:
            plan_view = None
        if plan_view is not None and r.artifacts.get("client_state") and r.artifacts.get("shortlist") and r.artifacts.get("recommendation"):
            record = record_of_advice_evidence(plan_view, r.artifacts["client_state"], r.artifacts["shortlist"], catalog, recommendation=r.artifacts["recommendation"], approval=approval, prepared_at=stamp, switching=r.artifacts.get("switching") or (), needs=r.artifacts.get("needs_assessment"), benefit_fit=[r.artifacts["benefit_fit"]] if r.artifacts.get("benefit_fit") else (), rule_disclosures=list((r.artifacts.get("rules") or {}).get("disclosures") or ()), remuneration=r.artifacts.get("remuneration_disclosure"), strategy=r.artifacts.get("strategy_plan"), serviceability=[r.artifacts["serviceability"]] if r.artifacts.get("serviceability") else ())
            document = advice_document(record, prepared_at=stamp)
            artifacts.update({"record_evidence": dict(detached(record)), "advice_document": dict(detached(document))})
            digests.update({"record_digest": record.record_digest, "document_digest": document.document_digest})
            try:
                explanation = deterministic_explanation(record, prepared_at=stamp)
                artifacts["client_explanation"] = dict(detached(explanation))
                digests["explanation_digest"] = explanation.explanation_digest
            except (ValueError, AdviceError) as exc:
                notes.append(f"template explanation not re-written for the approved record: {exc}")
            notes.append(f"record and document re-sealed with the approval {approval['approval_ref']}; the evidence record {record_view.get('record_digest', '')[:16]} is superseded by {record.record_digest[:16]}")
    else:
        notes.append("the approval is bound; the record and document are re-sealed when the catalog is supplied to the resume")
    return _carry(r, status=status, stop="prepared", stage="approved", extra_digests=digests, artifacts=artifacts, notes=notes, as_of=stamp)


def present_case_run(run: CaseRun | Mapping[str, Any], *, runtime: EngineRuntime, acknowledgement: Mapping[str, Any], explanation: Mapping[str, Any] | None = None, occurred_at: str, actor_ref: str) -> CaseRun:
    """Present the approved document; the acknowledgement names that document and the explanation, if any, explains that record."""

    r = run if isinstance(run, CaseRun) else CaseRun.model_validate(dict(detached(run)))
    blocked = _blocked_replacement(r)
    if blocked is not None:
        return blocked
    document = r.artifacts.get("advice_document")
    if not document:
        return _carry(r, status=None, stop="refused", stage="presented", refusal={"code": "DOCUMENT_MISSING", "message": "the run carries no document to present"})
    if explanation is not None and dict(detached(explanation)).get("record_digest") not in (None, document.get("record_digest")):
        return _carry(r, status=None, stop="refused", stage="presented", refusal={"code": "EXPLANATION_NOT_FOR_THIS_RECORD", "message": "the explanation was written for a different record"})
    try:
        outcome = present_case(runtime, r.entity_ref, document=document, acknowledgement=acknowledgement, explanation=explanation, occurred_at=occurred_at, actor_ref=actor_ref)
    except ValueError as exc:
        code, _, message = str(exc).partition(": ")
        return _carry(r, status=None, stop="refused", stage="presented", refusal={"code": code, "message": message or str(exc)})
    refusal = _refusal_of(outcome)
    if refusal:
        return _carry(r, status=None, stop="refused", stage="presented", refusal=refusal)
    return _carry(r, status=_status_of(outcome, "presented"), stop="prepared", stage="presented", artifacts={"acknowledgement": dict(detached(acknowledgement)), **({"client_explanation": dict(detached(explanation))} if explanation is not None else {})}, extra_digests={"explanation_digest": dict(detached(explanation)).get("explanation_digest") if explanation is not None else r.explanation_digest}, as_of=occurred_at)


def implement_case_run(run: CaseRun | Mapping[str, Any], *, runtime: EngineRuntime, pack: Mapping[str, Any], outcome: Mapping[str, Any], occurred_at: str, actor_ref: str, reconciliation: Mapping[str, Any] | None = None, differences_acknowledged_ref: str | None = None) -> CaseRun:
    """Implement the recommended product from its application pack and the provider's outcome."""

    r = run if isinstance(run, CaseRun) else CaseRun.model_validate(dict(detached(run)))
    blocked = _blocked_replacement(r)
    if blocked is not None:
        return blocked
    result = implement_case(runtime, r.entity_ref, pack=pack, outcome=outcome, reconciliation=reconciliation, differences_acknowledged_ref=differences_acknowledged_ref, occurred_at=occurred_at, actor_ref=actor_ref)
    refusal = _refusal_of(result)
    if refusal:
        return _carry(r, status=None, stop="refused", stage="implemented", refusal=refusal)
    return _carry(r, status=_status_of(result, "implemented"), stop="prepared", stage="implemented", artifacts={"application_pack": dict(detached(pack)), "provider_outcome": dict(detached(outcome)), **({"terms_reconciliation": dict(detached(reconciliation))} if reconciliation is not None else {})}, as_of=occurred_at)


def review_case_run(run: CaseRun | Mapping[str, Any], *, runtime: EngineRuntime, assessment: Mapping[str, Any], occurred_at: str, actor_ref: str, successor_entity_ref: str | None = None, scope: Mapping[str, Any] | None = None, state_now: Mapping[str, Any] | None = None, engagement: Mapping[str, Any] | None = None) -> CaseRun:
    """Close the case with its review; a re-advice opens the successor case first so the review names it."""

    r = run if isinstance(run, CaseRun) else CaseRun.model_validate(dict(detached(run)))
    view = dict(detached(assessment))
    successor_ref = None
    notes: list[str] = []
    if str(view.get("outcome") or "") in {"readvice_required", "adviser_confirms", "client_re_disclosure_required"}:
        if successor_entity_ref and scope is not None and state_now is not None:
            open_successor_case(runtime, predecessor_ref=r.entity_ref, entity_ref=successor_entity_ref, scope=scope, state_now=state_now, opened_at=occurred_at, actor_ref=actor_ref, engagement=engagement)
            successor_ref = successor_entity_ref
        else:
            notes.append("the review calls for re-advice and no successor case was opened; open one with the current state before advising again")
    result = review_case(runtime, r.entity_ref, assessment=view, successor_case_ref=successor_ref, occurred_at=occurred_at, actor_ref=actor_ref)
    refusal = _refusal_of(result)
    if refusal:
        return _carry(r, status=None, stop="refused", stage="reviewed", refusal=refusal, notes=notes)
    return _carry(r, status=_status_of(result, "reviewed"), stop="completed", stage="reviewed", artifacts={"review_assessment": view, **({"successor_case_ref": successor_ref} if successor_ref else {})}, notes=notes, as_of=occurred_at)


def refresh_case_supervision(run: CaseRun | Mapping[str, Any], *, as_of: str) -> CaseRun:
    """Reassess retained supervision evidence at a new time without changing the case lifecycle."""
    r = CaseRun.model_validate(dict(detached(run)))
    return _carry(r, status=r.status, stop=r.stop, stage=r.stage_reached, as_of=timestamp(as_of, field_name="as_of"))


def record_case_complaint(run: CaseRun | Mapping[str, Any], complaint: ComplaintFile | Mapping[str, Any], *, as_of: str) -> CaseRun:
    """Attach an append-only complaint revision and refresh the supervisor's file; persist through Spring."""
    r = CaseRun.model_validate(dict(detached(run)))
    c = ComplaintFile.model_validate(dict(detached(complaint)))
    if c.case_ref != r.entity_ref:
        raise ValueError("COMPLAINT_CASE_MISMATCH: the complaint belongs to another case")
    files = [ComplaintFile.model_validate(item) for item in r.artifacts.get("complaint_files") or ()]
    existing = next((item for item in files if item.complaint_ref == c.complaint_ref), None)
    if existing:
        immutable = ("record_digest", "jurisdiction", "regime", "region", "category")
        if any(getattr(c, key) != getattr(existing, key) for key in immutable) or c.events[:len(existing.events)] != existing.events or len(c.events) < len(existing.events):
            raise ValueError("COMPLAINT_HISTORY_REWRITE: retain the existing complaint metadata and chronology")
    files = [item for item in files if item.complaint_ref != c.complaint_ref] + [c]
    return _carry(r, status=r.status, stop=r.stop, stage=r.stage_reached, artifacts={"complaint_file": c.to_dict(), "complaint_files": [item.to_dict() for item in sorted(files, key=lambda item: item.complaint_ref)]}, as_of=timestamp(as_of, field_name="as_of"))


def _blocked_replacement(run: CaseRun) -> CaseRun | None:
    decision = run.artifacts.get("advice_decision")
    if decision is None:
        return None
    evidence = AdviceDecision.model_validate(decision)
    if evidence.outcome == "replacement_supported":
        return None
    return _carry(run, status=run.status, stop="refused", stage="decision", refusal={"code": "REPLACEMENT_NOT_SUPPORTED", "message": "the current sealed disposition requires adviser review before a replacement proposal; no replacement approval or implementation can be resumed"})


def case_run_summary(run: CaseRun | Mapping[str, Any]) -> dict[str, Any]:
    r = run if isinstance(run, CaseRun) else CaseRun.model_validate(dict(detached(run)))
    return {"entity_ref": r.entity_ref, "vertical_id": r.vertical_id, "status": r.status, "stop": r.stop, "stage_reached": r.stage_reached, "refusal": dict(r.refusal), "questions_owed": [dict(q.get("fact") and {"fact": q.get("fact"), "required": q.get("required")} or q) for q in r.questions_owed], "digests": {key: getattr(r, key) for key in ("engagement_digest", "state_digest", "strategy_digest", "tax_digest", "retirement_digest", "supervision_digest", "shortlist_digest", "decision_digest", "recommendation_digest", "record_digest", "remuneration_digest", "verification_digest", "checklist_digest", "document_digest", "explanation_digest")}, "approval_request_ref": r.approval_request_ref, "artifacts": sorted(r.artifacts), "notes": list(r.notes), "prepared_at": r.prepared_at, "run_digest": r.run_digest}


CASE_RUNNER_MANIFEST: dict[str, Any] = {
    "schema": CASE_RUN_SCHEMA,
    "stages": list(RUN_STAGES),
    "stops": ["needs_input", "prepared", "awaiting_approval", "refused", "completed"],
    "composition": "engagement gate, fact find with the questions owed, strategy and serviceability, published-view shortlist with quotes, stay-or-switch with a sealed replacement disposition, needs, rules, recommendation from sealed basis strings, record with remuneration, licence verification, compliance checklist, document, template explanation, approval request bound to the checklist and the verification",
    "not_claimed": "nothing here decides; the licensed adviser approves as a platform decision by someone other than the requester; no model runs in the runner",
}

__all__ = ["CASE_RUNNER_MANIFEST", "CASE_RUN_SCHEMA", "RUN_STAGES", "CaseRun", "case_run_summary", "implement_case_run", "present_case_run", "record_case_complaint", "refresh_case_supervision", "resume_after_approval", "review_case_run", "run_case"]
