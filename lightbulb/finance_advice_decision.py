"""A proposed replacement disposition bound to the existing holding and comparison.

This evidence can stop an unsupported replacement. It cannot approve advice,
waive an unresolved comparison, or complete the client's case.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import DecimalException
from typing import Any, Literal

from pydantic import Field, ValidationInfo, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, detached, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.finance_advice_catalog import Product
from lightbulb.finance_advice_engine import AdvicePlan, ClientState, Shortlist
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_switching import CurrentHolding, SwitchAnalysis, switching_analysis

ADVICE_DECISION_SCHEMA = "lightbulb.finance_advice_decision.v1"
AdviceDecisionOutcome = Literal["retain_current", "review_required", "replacement_supported"]


def _outcome(holdings: Sequence[CurrentHolding], comparisons: Sequence[SwitchAnalysis], missing: Sequence[str]) -> AdviceDecisionOutcome:
    if missing or len(holdings) != 1 or len(comparisons) != 1 or comparisons[0].verdict == "undecided":
        return "review_required"
    return "retain_current" if comparisons[0].verdict == "stay" else "replacement_supported"


class AdviceDecision(StrictModel):
    """The platform's proposed disposition; the licensed human retains authority."""

    schema_id: Literal["lightbulb.finance_advice_decision.v1"] = Field(default=ADVICE_DECISION_SCHEMA, alias="schema")
    case_ref: OpaqueRef
    plan_digest: Sha256Digest
    state_digest: Sha256Digest
    shortlist_digest: Sha256Digest
    candidate_product_ref: OpaqueRef
    holdings_digest: Sha256Digest
    holdings: tuple[CurrentHolding, ...] = Field(default_factory=tuple)
    comparisons: tuple[SwitchAnalysis, ...] = Field(default_factory=tuple)
    outcome: AdviceDecisionOutcome
    reason_codes: tuple[str, ...]
    reasons: tuple[str, ...]
    missing: tuple[str, ...] = Field(default_factory=tuple)
    human_review_required: Literal[True] = True
    prepared_at: str
    decision_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> AdviceDecision:
        refs = {holding.holding_ref for holding in self.holdings}
        if any(item.candidate_product_ref != self.candidate_product_ref or item.holding_ref not in refs for item in self.comparisons):
            raise ValueError("decision comparisons must identify the candidate and retained holdings")
        if self.outcome != _outcome(self.holdings, self.comparisons, self.missing):
            raise ValueError("the disposition must follow the bound comparison evidence")
        if not skip_digests(info) and self.decision_digest != sealed_digest(AdviceDecision, self, "decision_digest"):
            raise ValueError("decision_digest must commit the exact disposition evidence")
        return self


def replacement_decision(*, case_ref: str, plan: AdvicePlan | Mapping[str, Any], state: ClientState | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any], candidate: Product | Mapping[str, Any], holdings: Sequence[CurrentHolding | Mapping[str, Any]] = (), family: str, horizon_years: int, prepared_at: str) -> AdviceDecision | None:
    """Compare actual holdings before proposing one replacement; no holding means no comparison.

Multiple facilities, invalid facts, unknown break costs, and unlike balances
need a person's assessment. No incomplete arithmetic is promoted to permission
to replace a product, even when its supported published price ranks first.
"""

    p = AdvicePlan.model_validate(detached(plan))
    s = ClientState.model_validate(detached(state))
    ranked = Shortlist.model_validate(detached(shortlist))
    product = Product.model_validate(detached(candidate))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    if ranked.plan_digest != p.plan_digest or ranked.state_digest != s.state_digest or ranked.vertical_id != s.vertical_id:
        raise ValueError("DECISION_BASIS_MISMATCH: the shortlist must belong to this plan and state")
    if not any(entry.product_ref == product.product_ref and entry.rankable for entry in ranked.entries):
        raise ValueError("DECISION_CANDIDATE_MISMATCH: the candidate must rank in this shortlist")

    raw_state = s.facts.get("holdings")
    state_has_holdings = raw_state is not None and (not isinstance(raw_state, (list, tuple)) or bool(raw_state))
    if not state_has_holdings and not holdings:
        return None
    problems: list[str] = []
    codes: list[str] = []

    def gap(code: str, message: str) -> None:
        codes.append(code)
        problems.append(message)

    raw: list[Any] = []
    if raw_state is not None:
        if not isinstance(raw_state, (list, tuple)):
            gap("HOLDINGS_UNREADABLE", "the state's existing holdings must be supplied as a list of product facts")
        else:
            for index, item in enumerate(raw_state):
                if isinstance(item, Mapping):
                    item = {"holding_ref": f"holding:{s.client_ref}:{index + 1}", "vertical_id": s.vertical_id, **item}
                raw.append(item)
    raw.extend(holdings)
    parsed: list[CurrentHolding] = []
    comparisons: list[SwitchAnalysis] = []
    for index, item in enumerate(raw):
        try:
            holding = CurrentHolding.model_validate(detached(item))
        except (TypeError, ValueError, DecimalException, OverflowError):
            gap("HOLDING_UNREADABLE", f"existing holding {index + 1} needs valid product facts before comparison")
            continue
        if any(previous.holding_ref == holding.holding_ref for previous in parsed):
            previous = next(previous for previous in parsed if previous.holding_ref == holding.holding_ref)
            if detached(previous) != detached(holding):
                gap("HOLDING_CONFLICT", "the same existing holding has conflicting product facts")
            continue
        parsed.append(holding)
        if holding.vertical_id != s.vertical_id:
            gap("HOLDING_SCOPE_UNRESOLVED", "identify the existing product in this advice vertical before treating it as a replacement")
            continue
        if family == "credit":
            if holding.balance != s.amount:
                gap("COMPARISON_AMOUNT_MISMATCH", "the existing balance and proposed borrowing differ; the simple cost comparison cannot establish the replacement decision")
            if holding.remaining_term_years is None:
                gap("EXISTING_TERM_MISSING", "confirm the existing remaining loan term before relying on the comparison")
            if s.lvr_percent is not None and s.lvr_percent > 80:
                gap("REPLACEMENT_INSURANCE_COST_UNRESOLVED", "confirm any mortgage insurance cost for the proposed replacement before relying on the comparison")
        if holding.fixed_until and holding.fixed_until > stamp[:10] and not any("break" in key.lower() for key in holding.exit_costs):
            gap("BREAK_COST_MISSING", "obtain the existing provider's break cost for the active fixed period")
        try:
            comparison = switching_analysis(holding, product, s, family=family, horizon_years=horizon_years, prepared_at=stamp)
        except (ValueError, DecimalException, OverflowError):
            gap("COMPARISON_UNAVAILABLE", f"existing holding {index + 1} could not be compared from the supplied facts")
            continue
        comparisons.append(comparison)
        for missing in comparison.missing:
            gap("COMPARISON_INCOMPLETE", missing)
        if comparison.verdict == "undecided":
            gap("COMPARISON_REQUIRES_JUDGEMENT", "; ".join(comparison.reasons))
    if len(parsed) > 1:
        gap("REPLACEMENT_SCOPE_UNRESOLVED", "identify which existing facility the candidate replaces; separate comparisons do not establish a combined replacement strategy")
    outcome = _outcome(parsed, comparisons, problems)
    reasons = [reason for comparison in comparisons for reason in comparison.reasons]
    if outcome == "retain_current":
        codes.append("EXISTING_PRODUCT_PREFERRED")
        reasons.append("propose retaining the existing product on this comparison; the licensed adviser must review the disposition")
    elif outcome == "replacement_supported":
        codes.append("REPLACEMENT_COMPARISON_SUPPORTED")
        reasons.append("the comparison supports preparing a replacement proposal; the licensed adviser's approval is still required")
    else:
        reasons.extend(problems)
        reasons.append("replacement is unresolved; the licensed adviser must review the named gaps before a replacement proposal is prepared")
    return seal(AdviceDecision, {
        "case_ref": case_ref, "plan_digest": p.plan_digest, "state_digest": s.state_digest,
        "shortlist_digest": ranked.shortlist_digest, "candidate_product_ref": product.product_ref,
        "holdings_digest": stable_digest({"state_holdings": detached(raw_state), "supplied_holdings": detached(holdings)}),
        "holdings": [item.to_dict() for item in parsed], "comparisons": [item.to_dict() for item in comparisons],
        "outcome": outcome, "reason_codes": list(dict.fromkeys(codes)), "reasons": list(dict.fromkeys(reasons)),
        "missing": list(dict.fromkeys(problems)), "prepared_at": stamp,
    }, "decision_digest")


__all__ = ["ADVICE_DECISION_SCHEMA", "AdviceDecision", "AdviceDecisionOutcome", "replacement_decision"]
