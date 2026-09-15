"""Intelligence review: every product and labour document read together, bound by digest, checked for freshness, and its actions ranked by the money at stake.

The margin report, the portfolio, the price probes, the contribution
bridge, the customer table, the supplier scorecard, the job costing, the open-to-buy list, the working capital, the break-even, the probe outcomes, the skills match, the sourcing plan, the
skills inventory, the services margin, the rate card, the capacity plan,
and the job quotes each say one thing well.  A week's decision needs them
read together.  ``build_intelligence_review`` takes whichever of them the
operator has, verifies each seal, refuses one that names another company
or currency, marks one older than the plan's horizon as stale, and lifts
every recommendation into one list where each action carries:

* its source document and digest, so the number can be traced;
* the money at stake, taken from the document's own figures (a drain
  customer's negative contribution, a price probe's uplift at held
  volume, a gap's sourcing cost, the bench's cost, a rate card gap times
  the hours, a quote's shortfall to its target, an engagement's value at
  risk);
* a severity (high for something losing money or blocking delivery now,
  medium for money left on the table, low for housekeeping).

Actions are ordered by severity, then money.  The documents the review
did not get are listed as blind spots.  Nothing here decides for the
operator, reads a provider, or persists anything.
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

INTELLIGENCE_REVIEW_SCHEMA = "lightbulb.intelligence_review.v1"
DOCUMENT_KINDS: tuple[str, ...] = ("product_margin", "product_portfolio", "price_probes", "contribution_bridge", "customer_profitability", "supplier_scorecard", "job_costing", "open_to_buy", "stockouts", "returns_ledger", "working_capital", "break_even", "probe_outcomes", "customer_cohorts", "skills_match", "labour_sourcing", "skills_inventory", "services_margin", "rate_card", "workforce_capacity", "job_quotes", "skills_development", "quote_outcomes")
SEVERITIES: tuple[str, ...] = ("high", "medium", "low")
Severity = Literal["high", "medium", "low"]
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_HUNDRED = Decimal("100")


class IntelligenceReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise IntelligenceReviewError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class DocumentBinding(StrictModel):
    kind: ShortText
    digest: Sha256Digest
    as_of: str
    age_days: int
    fresh: bool
    actions: int = Field(ge=0)


class ReviewAction(StrictModel):
    rank: int = Field(ge=1)
    source: ShortText
    source_digest: Sha256Digest
    kind: ShortText
    subject: ShortText
    severity: Severity
    money_at_stake: Decimal
    detail: ShortText
    carried_from: OpaqueRef | None = None
    decision: ShortText | None = None
    decision_owner_ref: OpaqueRef | None = None
    decision_due_at: str | None = None

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money_at_stake")


class IntelligenceReview(StrictModel):
    schema_id: str = Field(default=INTELLIGENCE_REVIEW_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    review_ref: OpaqueRef
    as_of: str
    max_age_days: int = Field(ge=1)
    documents: tuple[DocumentBinding, ...] = Field(default_factory=tuple, max_length=64)
    blind_spots: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=32)
    stale: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=32)
    actions: tuple[ReviewAction, ...] = Field(default_factory=tuple, max_length=200)
    money_at_stake: Decimal
    by_severity: dict[str, int] = Field(default_factory=dict)
    previous_review_ref: OpaqueRef | None = None
    previous_review_digest: Sha256Digest | None = None
    carried: int = Field(default=0, ge=0)
    cleared: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    headline: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=64)
    review_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("documents", "blind_spots", "stale", "actions", "cleared", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money_at_stake")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "IntelligenceReview":
        if sum(self.by_severity.values()) != len(self.actions):
            raise ValueError("every action is counted once by severity")
        if self.carried != sum(1 for action in self.actions if action.carried_from is not None):
            raise ValueError("carried must count the actions carried from the previous review")
        if not skip_digests(info) and self.review_digest != sealed_digest(IntelligenceReview, self, "review_digest"):
            raise ValueError("review_digest must commit the exact review")
        return self

    def render(self) -> str:
        lines = [f"**Intelligence review {self.review_ref}** ({self.company_ref}, as of {self.as_of[:10]}): {self.headline}"]
        for action in self.actions[:20]:
            lines.append(f"{action.rank}. [{action.severity}] {action.subject} ({action.source}): {action.detail}" + (f" [{action.money_at_stake} {self.currency}]" if action.money_at_stake > 0 else ""))
        if self.blind_spots:
            lines.append("- blind spots: " + ", ".join(self.blind_spots))
        if self.stale:
            lines.append("- stale: " + ", ".join(self.stale))
        if self.cleared:
            lines.append(f"- cleared since {self.previous_review_ref}: " + ", ".join(self.cleared))
        return "\n".join(lines)


def _verify(kind: str, value: Any) -> tuple[Any, str, str]:
    """The verified document, its digest, and its as_of for one kind."""

    if kind == "product_margin":
        from lightbulb.product_margin import verify_product_margin

        doc = verify_product_margin(value)
        return doc, doc.report_digest, doc.as_of
    if kind == "product_portfolio":
        from lightbulb.product_portfolio import verify_product_portfolio

        doc = verify_product_portfolio(value)
        return doc, doc.portfolio_digest, doc.as_of
    if kind == "price_probes":
        from lightbulb.price_probes import verify_price_probes

        doc = verify_price_probes(value)
        return doc, doc.probes_digest, doc.as_of
    if kind == "contribution_bridge":
        from lightbulb.contribution_bridge import verify_contribution_bridge

        doc = verify_contribution_bridge(value)
        return doc, doc.bridge_digest, doc.current_window_end
    if kind == "customer_profitability":
        from lightbulb.customer_profitability import verify_customer_profitability

        doc = verify_customer_profitability(value)
        return doc, doc.profitability_digest, doc.as_of
    if kind == "supplier_scorecard":
        from lightbulb.supplier_scorecard import verify_supplier_scorecard

        doc = verify_supplier_scorecard(value)
        return doc, doc.scorecard_digest, doc.as_of
    if kind == "job_costing":
        from lightbulb.job_costing import verify_job_costing

        doc = verify_job_costing(value)
        return doc, doc.costing_digest, doc.as_of
    if kind == "open_to_buy":
        from lightbulb.open_to_buy import verify_open_to_buy

        doc = verify_open_to_buy(value)
        return doc, doc.buy_digest, doc.as_of
    if kind == "working_capital":
        from lightbulb.working_capital import verify_working_capital

        doc = verify_working_capital(value)
        return doc, doc.capital_digest, doc.as_of
    if kind == "break_even":
        from lightbulb.break_even import verify_break_even

        doc = verify_break_even(value)
        return doc, doc.break_even_digest, doc.as_of
    if kind == "probe_outcomes":
        from lightbulb.probe_outcomes import verify_probe_outcomes

        doc = verify_probe_outcomes(value)
        return doc, doc.outcomes_digest, doc.as_of
    if kind == "skills_development":
        from lightbulb.skills_development import verify_skills_development

        doc = verify_skills_development(value)
        return doc, doc.development_digest, doc.as_of
    if kind == "customer_cohorts":
        from lightbulb.customer_cohorts import verify_customer_cohorts

        doc = verify_customer_cohorts(value)
        return doc, doc.cohorts_digest, doc.as_of
    if kind == "quote_outcomes":
        from lightbulb.quote_outcomes import verify_quote_outcomes

        doc = verify_quote_outcomes(value)
        return doc, doc.outcomes_digest, doc.as_of
    if kind == "stockouts":
        from lightbulb.stockouts import verify_stockouts

        doc = verify_stockouts(value)
        return doc, doc.stockouts_digest, doc.as_of
    if kind == "returns_ledger":
        from lightbulb.returns_ledger import verify_returns_ledger

        doc = verify_returns_ledger(value)
        return doc, doc.returns_digest, doc.as_of
    if kind == "skills_match":
        from lightbulb.skills_matching import verify_skills_match_report

        doc = verify_skills_match_report(value)
        return doc, doc.report_digest, doc.as_of
    if kind == "labour_sourcing":
        from lightbulb.labour_sourcing import verify_labour_sourcing

        doc = verify_labour_sourcing(value)
        return doc, doc.sourcing_digest, doc.as_of
    if kind == "skills_inventory":
        from lightbulb.skills_inventory import verify_skills_inventory

        doc = verify_skills_inventory(value)
        return doc, doc.inventory_digest, doc.as_of
    if kind == "services_margin":
        from lightbulb.services_margin import verify_services_margin

        doc = verify_services_margin(value)
        return doc, doc.margin_digest, doc.as_of
    if kind == "rate_card":
        from lightbulb.rate_card import verify_rate_card

        doc = verify_rate_card(value)
        return doc, doc.card_digest, doc.as_of
    if kind == "workforce_capacity":
        from lightbulb.workforce_capacity import verify_workforce_capacity

        doc = verify_workforce_capacity(value)
        return doc, doc.capacity_digest, doc.as_of
    if kind == "job_quotes":
        from lightbulb.job_quote import verify_job_quote

        doc = verify_job_quote(value)
        return doc, doc.quote_digest, doc.as_of
    raise IntelligenceReviewError("DOCUMENT_KIND_UNKNOWN", f"{kind} is not a document the review reads")


def _actions(kind: str, doc: Any, digest: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(action_kind: str, subject: str, severity: str, money: Any, detail: str) -> None:
        out.append({"source": kind, "source_digest": digest, "kind": action_kind, "subject": subject[:300], "severity": severity, "money_at_stake": str(abs(_money(money))), "detail": detail[:300]})

    if kind == "product_margin":
        for sku in doc.uncosted_skus:
            add("cost_the_sku", sku, "low", 0, "no landed cost; the margin cannot be judged")
        for sku in doc.unpriced_skus:
            add("price_the_sku", sku, "medium", 0, "no published price; revenue stays unallocated")
        for row in doc.rows:
            if row.priced and row.costed and Decimal(str(row.contribution)) < 0:
                add("losing_sku", row.sku_ref, "high", row.contribution, f"contribution {row.contribution} on {row.units_sold} unit(s)")
    elif kind == "product_portfolio":
        for row in doc.rows:
            if row.action == "hold":
                continue
            money = row.stock_value if row.action in ("run_down", "reorder", "discontinue") and row.stock_value is not None else (row.contribution if row.action == "fix_returns" else 0)
            severity = "high" if row.action in ("discontinue", "fix_returns") else "medium" if row.action in ("reorder", "run_down", "price_probe") else "low"
            add(row.action, row.sku_ref, severity, money or 0, row.rationale)
    elif kind == "price_probes":
        for row in doc.skus:
            if row.action == "probe" and row.recommended_move_percent is not None:
                move = next((item for item in row.moves if item.move_percent == row.recommended_move_percent), None)
                uplift = (Decimal(str(move.unit_contribution)) - Decimal(str(row.unit_contribution))) * Decimal(str(row.units_sold)) if move else Decimal("0")
                add("price_probe", row.sku_ref, "medium", uplift, row.rationale)
            elif row.action == "reprice_to_floor":
                add("reprice_to_floor", row.sku_ref, "high", (Decimal(str(row.floor_price)) - Decimal(str(row.realised_price))) * Decimal(str(row.units_sold)), row.rationale)
    elif kind == "contribution_bridge":
        worst = min(doc.effects.items(), key=lambda item: (item[1], item[0]))
        if worst[1] < 0:
            add("explain_contribution_drop", worst[0], "medium", worst[1], doc.explanation[0])
    elif kind == "customer_profitability":
        for row in doc.rows:
            if row.customer_class == "drain":
                add("fix_drain_customer", row.customer_ref, "high", row.contribution if Decimal(str(row.contribution)) < 0 else Decimal(str(row.returns_value)) + Decimal(str(row.return_handling)), row.rationale)
            elif row.customer_class == "promising":
                add("grow_customer", row.customer_ref, "low", row.contribution, row.rationale)
    elif kind == "supplier_scorecard":
        for row in doc.suppliers:
            if row.grade in ("replace", "watch"):
                add(f"supplier_{row.grade}", row.supplier_ref, "high" if row.grade == "replace" else "medium", row.landed_premium, row.rationale)
            elif "single-source" in row.rationale:
                add("single_source_supplier", row.supplier_ref, "low", 0, row.rationale)
    elif kind == "job_costing":
        for row in doc.kinds:
            if not row.verdict.startswith("estimates within"):
                add("rebase_estimates", row.kind, "medium", Decimal(str(row.actual_cost)) - Decimal(str(row.estimated_cost)), row.verdict)
        for row in doc.assets:
            if row.review:
                add("review_asset", row.asset_ref, "medium", row.actual_cost, row.note)
        for row in doc.contractors:
            if "query" in row.verdict:
                add("query_contractor_bills", row.contractor_ref, "high", Decimal(str(row.invoiced)) - Decimal(str(row.work_value)), row.verdict)
    elif kind == "open_to_buy":
        for row in doc.lines:
            if row.decision == "fund" and Decimal(str(row.funded_cost)) > 0:
                add("buy_stock", row.sku_ref, "medium", row.funded_cost, row.rationale)
            elif row.decision == "defer":
                add("buy_deferred", row.sku_ref, "low", row.order_cost, row.rationale)
    elif kind == "working_capital":
        over = doc.cash_conversion_days is not None and doc.cash_conversion_days > doc.target_cycle_days
        for row in doc.levers:
            if row.cash_to_free is not None and Decimal(str(row.cash_to_free)) > 0:
                add("free_working_capital", row.lever, "high" if over else "medium", row.cash_to_free, row.note)
    elif kind == "break_even":
        if not doc.fixed_cost_known:
            add("open_cost_register", "company", "low", 0, doc.verdict)
        elif doc.operating_result is not None and Decimal(str(doc.operating_result)) < 0:
            add("close_break_even_gap", "company", "high", -Decimal(str(doc.operating_result)), doc.verdict)
        elif doc.recommendations and doc.recommendations[0].startswith("margin of safety"):
            add("thin_margin_of_safety", "company", "medium", 0, doc.recommendations[0])
    elif kind == "probe_outcomes":
        for row in doc.outcomes:
            if row.verdict == "backfired":
                add("revert_price", row.sku_ref, "high", abs(Decimal(str(row.contribution_change))), row.rationale)
            elif row.verdict == "not_applied":
                add("apply_price_probe", row.sku_ref, "medium", max(Decimal(str(row.expected_change)), Decimal("0")), row.rationale)
    elif kind == "skills_development":
        for row in doc.actions:
            severity = "high" if row.need in ("shortfall", "licence") or row.chosen == "escalate" else "medium"
            add(f"develop_{row.chosen}", row.skill_ref + (f" / {row.subject_ref}" if row.subject_ref else ""), severity, row.cost, row.rationale)
    elif kind == "customer_cohorts":
        for row in doc.recommendations:
            cohort = row.split(":", 1)[0]
            if cohort not in {item.cohort for item in doc.cohorts}:
                continue
            spend = next((item.acquisition_spend for item in doc.cohorts if item.cohort == cohort), None) or 0
            if "never pays back" in row or "past the" in row:
                add("acquisition_payback", cohort, "high", spend, row)
            elif "repeat rate" in row:
                add("win_second_order", cohort, "medium", spend, row)
    elif kind == "quote_outcomes":
        for row in doc.outcomes:
            if row.verdict == "overran":
                add("quote_overran", row.job_ref, "high", max(Decimal(str(row.cost_variance or 0)), Decimal("0")), row.rationale)
            elif row.verdict == "underquoted" and row.price is not None:
                add("quote_underquoted", row.job_ref, "high", max(Decimal(str(row.price)) * Decimal("0.2") - Decimal(str(row.realised_margin or 0)), Decimal("0")), row.rationale)
        if doc.contingency_percent_needed is not None and Decimal(str(doc.contingency_percent_needed)) > Decimal(str(doc.contingency_percent_now)):
            add("raise_contingency", "stretch quotes", "medium", 0, doc.recommendations[-1])
    elif kind == "stockouts":
        for row in doc.rows:
            if not row.spells:
                continue
            money = row.lost_contribution if row.lost_contribution is not None else 0
            if row.reorder_point_needed is not None and Decimal(str(row.reorder_point_needed)) > Decimal(str(row.reorder_point)):
                add("raise_reorder_point", row.position_ref, "high" if Decimal(str(money)) > 0 else "medium", money, row.verdict)
            else:
                add("chase_late_order", row.position_ref, "medium", money, row.verdict)
    elif kind == "returns_ledger":
        for row in doc.recommendations:
            sku = row.split(":", 1)[0]
            item = doc.sku(sku)
            if item is None:
                continue
            if "not yet restocked" in row:
                add("restock_returns", sku, "medium", item.refund_value, row)
            elif "resaleable against" in row:
                add("fix_return_quality", sku, "high", item.net_cost, row)
            elif "threshold" in row:
                add("cut_returns", sku, "high", item.net_cost, row)
    elif kind == "skills_match":
        for job in doc.jobs:
            if not job.staffed:
                add("unstaffed_job", job.job_ref, "high", job.team_cost, job.recommendation)
    elif kind == "labour_sourcing":
        for action in doc.actions:
            add(f"source_{action.chosen}", f"{action.job_ref} / {action.skill_ref}", "high" if action.chosen == "escalate" else "medium", action.cost or 0, action.rationale)
        for item in doc.requisitions:
            add("open_requisition", item.role_ref, "medium", 0, item.rationale)
    elif kind == "skills_inventory":
        for row in doc.skills:
            if row.status in ("absent", "single_point_of_failure") and row.demanded:
                add("key_person_risk" if row.status == "single_point_of_failure" else "missing_skill", row.skill_ref, "high", 0, row.note)
            for alert in row.licence_alerts:
                add("licence_lapsing", f"{row.skill_ref} / {alert.worker_ref}", "high" if alert.lapsed else "medium", 0, f"licence {'lapsed' if alert.lapsed else 'lapses'} {alert.expires_at[:10]} ({alert.days_left} day(s))")
    elif kind == "services_margin":
        for row in doc.engagements:
            if row.verdict in ("over_contract", "underwater", "at_risk"):
                add(f"engagement_{row.verdict}", row.engagement_ref, "high", row.value_at_risk if row.verdict == "over_contract" else row.margin, row.rationale)
            elif row.verdict == "thin":
                add("engagement_thin", row.engagement_ref, "medium", 0, row.rationale)
        for row in doc.workers:
            if row.verdict in ("under_utilised", "idle", "over_loaded"):
                add(f"worker_{row.verdict}", row.worker_ref, "medium" if row.verdict != "over_loaded" else "high", 0, row.rationale)
    elif kind == "rate_card":
        for row in doc.rows:
            if row.action != "hold":
                add(f"rate_{row.action}", row.role_ref, "medium", (Decimal(str(row.required_bill_rate)) - Decimal(str(row.bill_rate))) * Decimal(str(row.hours)), row.rationale)
    elif kind == "workforce_capacity":
        for row in doc.skills:
            if Decimal(str(row.shortfall_hours)) > 0:
                add("capacity_shortfall", row.skill_ref, "high" if row.longest_run_short >= 4 else "medium", 0, row.recommendation)
            elif Decimal(str(row.bench_cost)) > 0 and Decimal(str(row.demand_hours)) <= 0:
                add("sell_the_bench", row.skill_ref, "medium", row.bench_cost, row.recommendation)
    elif kind == "job_quotes":
        if doc.verdict in ("no_bid", "negotiate"):
            add(f"quote_{doc.verdict}", doc.job_ref, "medium", Decimal(str(doc.target_price)) - Decimal(str(doc.offered_price or 0)), doc.rationale)
        elif doc.verdict == "cannot_staff":
            add("quote_cannot_staff", doc.job_ref, "high", 0, doc.rationale)
    return out


def build_intelligence_review(*, review_ref: str, company_ref: str, currency: str, as_of: str, max_age_days: int = 7, documents: Mapping[str, Any] | None = None, previous: Mapping[str, Any] | Any | None = None, decisions: Mapping[str, Any] | Any | None = None) -> IntelligenceReview:
    """The sealed weekly review over whichever sealed product and labour documents are supplied, keyed by kind (``job_quotes`` takes a list)."""

    _require(max_age_days >= 1, "HORIZON_INVALID", "max_age_days is at least 1")
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    supplied = dict(documents or {})
    unknown = sorted(set(supplied) - set(DOCUMENT_KINDS))
    _require(not unknown, "DOCUMENT_KIND_UNKNOWN", f"{', '.join(unknown)} are not documents the review reads")
    bindings: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    stale: list[str] = []
    digests: list[str] = []
    for kind in DOCUMENT_KINDS:
        if kind not in supplied or supplied[kind] is None:
            continue
        items = list(supplied[kind]) if kind == "job_quotes" else [supplied[kind]]
        for item in items:
            doc, digest, doc_as_of = _verify(kind, item)
            _require(getattr(doc, "company_ref", company_ref) == company_ref, "REVIEW_SCOPE_MISMATCH", f"the {kind} document names {getattr(doc, 'company_ref', None)}, not {company_ref}")
            doc_currency = getattr(doc, "currency", None)
            _require(doc_currency in (None, currency), "REVIEW_SCOPE_MISMATCH", f"the {kind} document is in {doc_currency}, not {currency}")
            age = (now - parsed(doc_as_of)).days
            _require(age >= 0, "DOCUMENT_FROM_FUTURE", f"the {kind} document is dated {doc_as_of}, after the review")
            fresh = age <= max_age_days
            found = _actions(kind, doc, digest) if fresh else []
            label = f"{kind}:{getattr(doc, 'job_ref', '')}" if kind == "job_quotes" else kind
            bindings.append({"kind": label[:300], "digest": digest, "as_of": doc_as_of, "age_days": age, "fresh": fresh, "actions": len(found)})
            digests.append(digest)
            if not fresh:
                stale.append(f"{label} ({age} day(s) old)")
            actions.extend(found)
    _require(bool(bindings), "DOCUMENTS_MISSING", "supply at least one sealed document")
    prior = None if previous is None else verify_intelligence_review(previous)
    cleared: list[str] = []
    ledger = None
    if decisions is not None:
        from lightbulb.review_decisions import verify_review_decisions

        ledger = verify_review_decisions(decisions)
        _require(prior is not None and ledger.review_digest == prior.review_digest, "DECISIONS_NOT_BOUND", "the decisions answer another review than the previous one")
    if prior is not None:
        _require(prior.company_ref == company_ref and prior.currency == currency, "REVIEW_SCOPE_MISMATCH", "the previous review names another company or currency")
        _require(parsed(prior.as_of) <= now, "DOCUMENT_FROM_FUTURE", "the previous review is dated after this one")
        keys = {f"{row['source']}:{row['kind']}:{row['subject']}" for row in actions}
        for action in prior.actions:
            key = f"{action.source}:{action.kind}:{action.subject}"
            if key in keys:
                decided = None if ledger is None else ledger.action(key)
                for row in actions:
                    if f"{row['source']}:{row['kind']}:{row['subject']}" == key:
                        row["carried_from"] = action.carried_from or prior.review_ref
                        if decided is not None and decided.decision is not None:
                            row["decision"], row["decision_owner_ref"], row["decision_due_at"] = decided.decision, decided.owner_ref, decided.due_at
            else:
                cleared.append(f"{action.kind} {action.subject}"[:300])
    actions.sort(key=lambda row: (_SEVERITY_RANK[row["severity"]], -Decimal(row["money_at_stake"]), row["source"], row["subject"]))
    for index, row in enumerate(actions[:200], start=1):
        row["rank"] = index
    actions = actions[:200]
    counts = {severity: sum(1 for row in actions if row["severity"] == severity) for severity in SEVERITIES if any(row["severity"] == severity for row in actions)}
    total = _money(sum((Decimal(row["money_at_stake"]) for row in actions), Decimal("0")))
    blind = [kind for kind in DOCUMENT_KINDS if kind not in supplied or supplied[kind] is None]
    if actions:
        top = actions[0]
        headline = f"{len(actions)} action(s) across {len(bindings)} document(s), {total} {currency} at stake; first: {top['subject']} ({top['source']}, {top['severity']})"
    else:
        headline = f"{len(bindings)} document(s) read and nothing needs acting on" + (f"; {len(stale)} stale" if stale else "")
    carried = sum(1 for row in actions if row.get("carried_from"))
    if carried and actions:
        headline = headline[:260] + f"; {carried} carried"
    payload = {"company_ref": company_ref, "currency": str(currency).upper(), "review_ref": review_ref, "as_of": at, "max_age_days": max_age_days, "documents": bindings, "blind_spots": blind, "stale": stale[:32], "actions": actions, "money_at_stake": str(total), "by_severity": counts, "previous_review_ref": None if prior is None else prior.review_ref, "previous_review_digest": None if prior is None else prior.review_digest, "carried": carried, "cleared": cleared[:40], "headline": headline[:300], "source_digests": digests}
    return seal(IntelligenceReview, payload, "review_digest")


def verify_intelligence_review(value: Any) -> IntelligenceReview:
    return value if isinstance(value, IntelligenceReview) else IntelligenceReview.model_validate(dict(detached(value)))


INTELLIGENCE_REVIEW_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "intelligence_review",
    "golden_loop": "company.operating_review@0.1.0",
    "stages": ["verify_each_seal", "bind_scope_and_freshness", "lift_actions_with_money", "carry_from_previous", "rank_by_severity_then_money", "name_blind_spots", "seal_review"],
    "documents": list(DOCUMENT_KINDS),
    "severities": list(SEVERITIES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every document is verified by its own seal and refused when it names another company or currency",
        "a document older than the horizon is bound but contributes no actions and is listed as stale",
        "money at stake is the document's own figure, never estimated here; severity is a fixed rule per action kind",
        "an action present last week is carried from the review that first raised it; one gone this week is listed as cleared",
        "nothing here decides, reads a provider, or persists anything",
    ],
}

__all__ = ["DOCUMENT_KINDS", "INTELLIGENCE_REVIEW_MANIFEST", "INTELLIGENCE_REVIEW_SCHEMA", "SEVERITIES", "DocumentBinding", "IntelligenceReview", "IntelligenceReviewError", "ReviewAction", "build_intelligence_review", "verify_intelligence_review"]
