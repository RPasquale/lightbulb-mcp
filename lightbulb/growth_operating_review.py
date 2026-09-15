"""The weekly growth review: the six seam documents read together, once, into an ordered list of decisions.

The revenue model says what cash sales and marketing are holding, the
cohort table what each channel earns back, the coverage assessment whether
the pipeline covers the plan, the reconciliation whether the plan delivers
the objective, and the allocation where the deployable spend should go.
Each is sealed on its own; nothing read them together.  ``build_growth_review``
does: it refuses documents that disagree about the company, the currency,
or each other's digests, refuses stale ones, and seals one review with the
headline numbers and the decisions in the order a founder would take them:
protect runway first, then the plan (reforecast), then the pipeline (heads
or sourcing), then the channels (budget moves), each with the authority it
needs and, when mandate receipts are supplied, whether it was authorized.
Nothing here reads a provider, persists anything, or decides for anyone:
the review is the consequence of the documents it read.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

GROWTH_REVIEW_SCHEMA = "lightbulb.growth_review.v1"
DECISION_KINDS: tuple[str, ...] = ("protect_runway", "reforecast_revenue", "requisition_heads", "source_prospects", "fix_conversion", "adjust_channel_budget", "hold")
REVIEW_VERDICTS: tuple[str, ...] = ("on_plan", "act", "protect_runway")
DecisionKind = Literal["protect_runway", "reforecast_revenue", "requisition_heads", "source_prospects", "fix_conversion", "adjust_channel_budget", "hold"]
DecisionAuthority = Literal["none", "replan", "people_change", "growth_mandate"]
DecisionStatus = Literal["proposed", "authorized", "escalate", "refused"]
ReviewVerdict = Literal["on_plan", "act", "protect_runway"]


class GrowthReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GrowthReviewError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class ReviewDecision(StrictModel):
    order: int = Field(ge=1, le=40)
    kind: DecisionKind
    summary: ShortText
    amount: Decimal | None = None
    authority: DecisionAuthority
    basis: ShortText
    basis_digest: Sha256Digest
    status: DecisionStatus = "proposed"
    mandate_receipt_digest: Sha256Digest | None = None
    subject: ShortText | None = None
    carried_from: OpaqueRef | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="amount")


class GrowthReview(StrictModel):
    schema_id: str = Field(default=GROWTH_REVIEW_SCHEMA, alias="schema")
    review_ref: OpaqueRef
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    documents: dict[str, str] = Field(default_factory=dict)
    mrr_now: Decimal
    expected_next_month: Decimal
    expected_over_horizon: Decimal
    coverage_verdict: ShortText
    coverage_period_ref: ShortText
    pipeline_gap: Decimal
    reconciliation_verdict: ShortText
    revenue_shortfall_ahead: Decimal
    allocation_verdict: ShortText
    deployable_monthly: Decimal
    allocated_monthly: Decimal
    top_channel: ShortText | None = None
    decisions: tuple[ReviewDecision, ...] = Field(default_factory=tuple, max_length=40)
    verdict: ReviewVerdict
    previous_review_ref: OpaqueRef | None = None
    previous_review_digest: Sha256Digest | None = None
    carried: int = Field(default=0, ge=0)
    cleared: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    review_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("decisions", "cleared", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("mrr_now", "expected_next_month", "expected_over_horizon", "pipeline_gap", "revenue_shortfall_ahead", "deployable_monthly", "allocated_monthly", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GrowthReview":
        if [item.order for item in self.decisions] != list(range(1, len(self.decisions) + 1)):
            raise ValueError("decisions are numbered in order")
        if self.carried != sum(1 for item in self.decisions if item.carried_from is not None):
            raise ValueError("carried must count the decisions carried from the previous review")
        if not skip_digests(info) and self.review_digest != sealed_digest(GrowthReview, self, "review_digest"):
            raise ValueError("review_digest must commit the exact review")
        return self

    def render(self) -> str:
        lines = [f"**Growth review {self.review_ref}** for {self.company_ref} as of {self.as_of[:10]}: {self.verdict}; MRR {self.mrr_now}, {self.expected_next_month} {self.currency} expected next month; pipeline {self.coverage_verdict} for {self.coverage_period_ref} (gap {self.pipeline_gap}); plan {self.reconciliation_verdict} (shortfall {self.revenue_shortfall_ahead}); allocation {self.allocation_verdict} ({self.allocated_monthly} of {self.deployable_monthly} a month)."]
        for item in self.decisions:
            amount = "" if item.amount is None else f" {item.amount} {self.currency}"
            carried = "" if item.carried_from is None else f"; carried from {item.carried_from}"
            lines.append(f"{item.order}. [{item.kind}]{amount} {item.summary} (authority: {item.authority}; {item.status}{carried})")
        if self.cleared:
            lines.append(f"- cleared since {self.previous_review_ref}: {', '.join(self.cleared)}")
        return "\n".join(lines)


def _fresh(name: str, stamp: str, as_of: str, max_age_days: int) -> None:
    age = (parsed(as_of) - parsed(stamp)).days
    _require(age <= max_age_days, "STALE_DOCUMENT", f"the {name} is {age} day(s) old; the review accepts {max_age_days}")
    _require(age >= 0, "DOCUMENT_FROM_FUTURE", f"the {name} is dated after the review")


def build_growth_review(*, review_ref: str, as_of: str, revenue_model: Mapping[str, Any] | Any, cohorts: Mapping[str, Any] | Any, coverage: Mapping[str, Any] | Any, reconciliation: Mapping[str, Any] | Any, allocation: Mapping[str, Any] | Any, authorizations: Sequence[Mapping[str, Any] | Any] = (), max_age_days: int = 7, previous: Mapping[str, Any] | Any | None = None) -> GrowthReview:
    """The sealed review from five sealed documents and the mandate receipts (if any) for the allocation's actions; ``previous`` is last week's review, whose still-open decisions are carried and whose resolved ones are listed as cleared."""

    from lightbulb.growth_channel_allocation import allocation_actions, verify_channel_allocation
    from lightbulb.growth_channel_cohorts import ChannelCohortReport
    from lightbulb.growth_plan_reconciliation import verify_reconciliation
    from lightbulb.growth_revenue_model import verify_revenue_model
    from lightbulb.pipeline_coverage import verify_pipeline_coverage

    at = timestamp(as_of, field_name="as_of")
    model = verify_revenue_model(revenue_model)
    table = cohorts if isinstance(cohorts, ChannelCohortReport) else ChannelCohortReport.model_validate(dict(detached(cohorts)))
    cover = verify_pipeline_coverage(coverage)
    recon = verify_reconciliation(reconciliation)
    alloc = verify_channel_allocation(allocation)
    company = model.company_ref
    currency = model.currency
    for name, doc in (("cohort table", table), ("coverage assessment", cover), ("reconciliation", recon), ("allocation", alloc)):
        _require(doc.company_ref == company and doc.currency == currency, "REVIEW_SCOPE_MISMATCH", f"the {name} names another company or currency")
    for name, stamp in (("revenue model", model.as_of), ("cohort table", table.as_of), ("coverage assessment", cover.as_of), ("reconciliation", recon.as_of), ("allocation", alloc.as_of)):
        _fresh(name, stamp, at, max_age_days)
    if cover.target_basis == "revenue_model":
        _require(cover.target_digest == model.model_digest, "REVIEW_INCOHERENT", "the coverage assessment targets another revenue model")
    if recon.revenue_model_digest is not None:
        _require(recon.revenue_model_digest == model.model_digest, "REVIEW_INCOHERENT", "the reconciliation read another revenue model")
    _require(alloc.cohort_report_digest == table.report_digest, "REVIEW_INCOHERENT", "the allocation read another cohort table")
    receipts = {}
    for item in authorizations:
        raw = dict(detached(item))
        if str(raw.get("plan_digest")) == alloc.allocation_digest:
            receipts[str(raw.get("action_ref"))] = raw
    decisions: list[dict[str, Any]] = []

    def decide(kind: str, summary: str, *, amount: Decimal | None, authority: str, basis: str, basis_digest: str, status: str = "proposed", mandate_receipt_digest: str | None = None, subject: str | None = None) -> None:
        decisions.append({"order": len(decisions) + 1, "kind": kind, "summary": summary[:200], "amount": None if amount is None else str(amount), "authority": authority, "basis": basis, "basis_digest": basis_digest, "status": status, "mandate_receipt_digest": mandate_receipt_digest, "subject": subject, "carried_from": None})

    if alloc.verdict == "nothing_deployable":
        decide("protect_runway", f"nothing is deployable ({alloc.deployable_basis}); zero-cost levers only until the runway clears the floor", amount=None, authority="none", basis="allocation", basis_digest=alloc.allocation_digest, subject="runway")
    if recon.verdict in {"plan_below_objective", "plan_below_objective_and_model_below_plan"}:
        decide("reforecast_revenue", f"{recon.periods_short} of {recon.periods_ahead} period(s) ahead fall short of objective {recon.objective_ref}; lift the revenue lines by {recon.total_revenue_shortfall_ahead} in total or restate the objective", amount=recon.total_revenue_shortfall_ahead, authority="replan", basis="reconciliation", basis_digest=recon.reconciliation_digest, subject=recon.objective_ref)
    elif recon.verdict in {"model_below_plan", "plan_below_objective_and_model_below_plan"}:
        decide("reforecast_revenue", f"the revenue model falls below the plan in {recon.periods_model_below_plan} period(s) ahead; reforecast the revenue lines to what sales is holding", amount=None, authority="replan", basis="reconciliation", basis_digest=recon.reconciliation_digest, subject=recon.objective_ref)
    if cover.verdict == "uncovered":
        if cover.expected_value_per_prospect <= 0:
            decide("fix_conversion", f"the meeting rate for {cover.period_ref} is zero; fix conversion before sourcing", amount=None, authority="none", basis="coverage", basis_digest=cover.coverage_digest, subject=cover.period_ref)
        elif cover.additional_heads > 0:
            decide("requisition_heads", f"requisition {cover.additional_heads} sales head(s) to source {cover.prospects_needed} prospect(s) for {cover.period_ref} (gap {cover.pipeline_gap})", amount=cover.pipeline_gap, authority="people_change", basis="coverage", basis_digest=cover.coverage_digest, subject=cover.period_ref)
        else:
            decide("source_prospects", f"source {cover.prospects_needed} prospect(s) inside the ICP for {cover.period_ref} with the current team (gap {cover.pipeline_gap})", amount=cover.pipeline_gap, authority="none", basis="coverage", basis_digest=cover.coverage_digest, subject=cover.period_ref)
    elif cover.verdict == "thin":
        decide("source_prospects", f"open pipeline for {cover.period_ref} is under {cover.assumptions.get('coverage_multiple', '?')}x; keep sourcing before the period starts", amount=None, authority="none", basis="coverage", basis_digest=cover.coverage_digest, subject=cover.period_ref)
    if alloc.verdict == "allocated":
        for action in allocation_actions(alloc):
            receipt = receipts.get(str(action["action_ref"]))
            status = "proposed"
            if receipt is not None:
                status = {"authorized": "authorized", "escalate": "escalate", "refused": "refused"}.get(str(receipt.get("verdict")), "proposed")
            digest = None if receipt is None else receipt.get("authorization_digest")
            decide("adjust_channel_budget", action["description"], amount=_money(action["amount"]), authority="growth_mandate", basis="allocation", basis_digest=alloc.allocation_digest, status=status, mandate_receipt_digest=None if not digest else str(digest), subject=next((line.channel for line in alloc.lines if action["description"].startswith(f"Set the {line.channel} monthly budget")), None))
    elif alloc.verdict == "no_eligible_channel" and alloc.deployable_monthly > 0:
        decide("hold", f"{alloc.deployable_monthly} a month is deployable but no channel has paid back and cleared the LTV/CAC floor; hold paid spend and run the cheapest channel test", amount=alloc.deployable_monthly, authority="none", basis="allocation", basis_digest=alloc.allocation_digest, subject="allocation")
    if not decisions:
        decide("hold", "pipeline covers the period, the plan delivers the objective, and the allocation stands; no change this week", amount=None, authority="none", basis="review", basis_digest=model.model_digest)
    previous_ref = previous_digest = None
    cleared: list[str] = []
    if previous is not None:
        prior = verify_growth_review(previous)
        _require(prior.company_ref == company and prior.currency == currency, "REVIEW_SCOPE_MISMATCH", "the previous review names another company or currency")
        _require(parsed(prior.as_of) < parsed(at), "PREVIOUS_NOT_EARLIER", "the previous review must predate this one")
        previous_ref, previous_digest = prior.review_ref, prior.review_digest
        open_before = {(item.kind, item.subject): item for item in prior.decisions if item.kind != "hold" and item.status != "authorized"}
        for decision in decisions:
            match = open_before.pop((decision["kind"], decision["subject"]), None)
            if match is not None:
                decision["carried_from"] = match.carried_from or prior.review_ref
        cleared = [f"{item.kind}:{item.subject}" if item.subject else item.kind for item in open_before.values()]
    if any(item["kind"] == "protect_runway" for item in decisions):
        verdict = "protect_runway"
    elif all(item["kind"] == "hold" for item in decisions):
        verdict = "on_plan"
    else:
        verdict = "act"
    next_month = model.months[0].total if model.months else Decimal("0")
    payload = {
        "review_ref": review_ref, "company_ref": company, "currency": currency, "as_of": at,
        "documents": {"revenue_model": model.model_digest, "cohorts": table.report_digest, "coverage": cover.coverage_digest, "reconciliation": recon.reconciliation_digest, "allocation": alloc.allocation_digest},
        "mrr_now": str(model.mrr_now), "expected_next_month": str(_money(next_month)), "expected_over_horizon": str(model.total_expected),
        "coverage_verdict": cover.verdict, "coverage_period_ref": cover.period_ref, "pipeline_gap": str(cover.pipeline_gap),
        "reconciliation_verdict": recon.verdict, "revenue_shortfall_ahead": str(recon.total_revenue_shortfall_ahead),
        "allocation_verdict": alloc.verdict, "deployable_monthly": str(alloc.deployable_monthly), "allocated_monthly": str(alloc.allocated_monthly),
        "top_channel": table.channel_ranking[0] if table.channel_ranking else None, "decisions": decisions, "verdict": verdict,
        "previous_review_ref": previous_ref, "previous_review_digest": previous_digest, "carried": sum(1 for item in decisions if item["carried_from"] is not None), "cleared": cleared[:40],
    }
    return seal(GrowthReview, payload, "review_digest")


def verify_growth_review(value: Any) -> GrowthReview:
    return value if isinstance(value, GrowthReview) else GrowthReview.model_validate(dict(detached(value)))


GROWTH_REVIEW_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_operating_review",
    "golden_loop": "growth.attributed_revenue_to_next_tranche@0.1.0",
    "stages": ["verify_documents", "check_coherence", "order_decisions", "seal_review"],
    "decision_kinds": list(DECISION_KINDS),
    "verdicts": list(REVIEW_VERDICTS),
    "required_connectors": [],
    "hard_rules": [
        "five sealed documents in, one sealed review out; every document digest is carried",
        "documents that disagree about the company, the currency, or each other's digests are refused, as are stale ones",
        "decisions are ordered runway, plan, pipeline, channels; each names the authority it needs",
        "a mandate receipt is matched to its action by the allocation digest; the review never authorizes anything itself",
        "a decision still open from the previous review is carried with the review it was first raised in; one no longer raised is listed as cleared",
    ],
}

__all__ = ["DECISION_KINDS", "GROWTH_REVIEW_MANIFEST", "GROWTH_REVIEW_SCHEMA", "REVIEW_VERDICTS", "GrowthReview", "GrowthReviewError", "ReviewDecision", "build_growth_review", "verify_growth_review"]
