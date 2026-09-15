"""The customer onboarding chain: one replay-fenced implementation per won account, from kick-off to a live customer handed to retention.

Activation was observed per account by the SaaS operating engine and
renewals were proven by the retention chain, but the stretch between a won
deal and a live customer had no lifecycle: which milestones the
implementation promised, which were done and when, whether the account
actually activated inside the promise, and when it was safe to treat the
customer as live.  ``ONBOARDING_LIFECYCLE`` does:

    kicked_off -> in_progress -> activated -> live -> handed_over      (terminal)
    kicked_off | in_progress -> at_risk -> in_progress
    any non-terminal -> abandoned                                       (terminal, with a reason)

* ``kickoff_receipt`` opens the onboarding from the replayed revenue case
  of the won deal (agreement executed or further along).
* ``milestone_receipt`` completes one milestone of the plan's template
  with an evidence digest and an owner.
* ``activation_receipt`` consumes the account's own usage row (the
  ``AccountUsage`` fact the SaaS engine observes) sealed by its read
  provenance; activation is the row's ``activated_at``, never asserted.
* ``go_live`` needs every required milestone and, when the plan demands
  it, activation; ``hand_over`` closes the implementation.

``onboarding_at_risk_signal`` names the first overdue required milestone.
Nothing here provisions anything, messages anyone, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
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
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

ONBOARDING_KIND = "customer_onboarding_chain"
ONBOARDING_GOLDEN_LOOP = "customer.won_deal_to_live_account@0.1.0"
ONBOARDING_PLAN_SCHEMA = "lightbulb.customer_onboarding_plan.v1"
MAX_ONBOARDING_TRANSITIONS = 60
WON_REVENUE_STATUSES: frozenset[str] = frozenset({"agreement_executed", "invoice_issued", "payment_applied", "cash_settled", "receivable_cleared"})
_HUNDRED = Decimal("100")

ONBOARDING_STATUSES: tuple[str, ...] = ("kicked_off", "in_progress", "at_risk", "activated", "live", "handed_over", "abandoned")
TERMINAL_ONBOARDING_STATUSES: frozenset[str] = frozenset({"handed_over", "abandoned"})
ONBOARDING_EVENTS: tuple[str, ...] = ("kick_off", "complete_milestone", "flag_at_risk", "resolve_risk", "activate", "go_live", "hand_over", "abandon")
_ONBOARDING_TABLE: dict[tuple[str, str], str] = {
    ("new", "kick_off"): "kicked_off",
    ("kicked_off", "complete_milestone"): "in_progress",
    ("in_progress", "complete_milestone"): "in_progress",
    ("at_risk", "complete_milestone"): "in_progress",
    ("activated", "complete_milestone"): "activated",
    ("kicked_off", "flag_at_risk"): "at_risk",
    ("in_progress", "flag_at_risk"): "at_risk",
    ("at_risk", "resolve_risk"): "in_progress",
    ("kicked_off", "activate"): "activated",
    ("in_progress", "activate"): "activated",
    ("at_risk", "activate"): "activated",
    ("in_progress", "go_live"): "live",
    ("activated", "go_live"): "live",
    ("live", "hand_over"): "handed_over",
    **{(status, "abandon"): "abandoned" for status in ("kicked_off", "in_progress", "at_risk", "activated", "live")},
}

ONBOARDING_PROFILES: dict[str, list[dict[str, Any]]] = {
    "saas_self_serve": [
        {"milestone_ref": "welcome", "title": "Welcome sequence delivered", "due_days": 1, "required": False},
        {"milestone_ref": "data_connected", "title": "First data source connected", "due_days": 7, "required": True},
        {"milestone_ref": "first_value", "title": "First value moment reached", "due_days": 14, "required": True},
    ],
    "sales_assisted": [
        {"milestone_ref": "kickoff_call", "title": "Kick-off call held", "due_days": 5, "required": True},
        {"milestone_ref": "integration", "title": "Integration configured", "due_days": 21, "required": True},
        {"milestone_ref": "training", "title": "Admin training delivered", "due_days": 28, "required": True},
        {"milestone_ref": "first_value", "title": "First value moment reached", "due_days": 45, "required": True},
    ],
    "services_engagement": [
        {"milestone_ref": "kickoff", "title": "Kick-off held", "due_days": 7, "required": True},
        {"milestone_ref": "discovery", "title": "Discovery complete", "due_days": 21, "required": True},
        {"milestone_ref": "delivery_plan_accepted", "title": "Delivery plan accepted by the customer", "due_days": 35, "required": True},
    ],
}


class OnboardingChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OnboardingChainError(code, message)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class MilestoneTemplate(StrictModel):
    milestone_ref: OpaqueRef
    title: ShortText
    due_days: int = Field(ge=0, le=365)
    required: bool = True


class OnboardingPlan(StrictModel):
    """What the chain enforces: the milestone template, the activation window, and whether going live needs activation."""

    schema_id: str = Field(default=ONBOARDING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    profile: ShortText
    milestones: tuple[MilestoneTemplate, ...] = Field(min_length=1, max_length=40)
    activation_within_days: int = Field(default=30, ge=1, le=365)
    require_activation_for_live: bool = True
    saas_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("milestones", mode="before")
    @classmethod
    def _milestones(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OnboardingPlan":
        unique([item.milestone_ref for item in self.milestones], label="milestones")
        if not skip_digests(info) and self.plan_digest != sealed_digest(OnboardingPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def milestone(self, ref: str) -> MilestoneTemplate | None:
        return next((item for item in self.milestones if item.milestone_ref == ref), None)


def compile_onboarding_chain(company_ref: str, *, currency: str, profile: str = "sales_assisted", milestones: Sequence[Mapping[str, Any]] | None = None, saas_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> OnboardingPlan:
    """The template comes from a profile or the caller; the activation window and the SaaS plan digest come from the sealed SaaS plan when given."""

    _require(milestones is not None or profile in ONBOARDING_PROFILES, "PROFILE_UNKNOWN", f"{profile} is not an onboarding profile; known: {sorted(ONBOARDING_PROFILES)}")
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "profile": profile, "milestones": [dict(detached(item)) for item in (milestones if milestones is not None else ONBOARDING_PROFILES[profile])]}
    if saas_plan is not None:
        parsed_plan = dict(detached(saas_plan))
        activation = dict(dict(parsed_plan.get("blueprint") or {}).get("activation") or {})
        if activation.get("within_days") is not None:
            raw["activation_within_days"] = int(activation["within_days"])
        raw["saas_plan_digest"] = parsed_plan.get("plan_digest")
    raw.update(dict(overrides or {}))
    return seal(OnboardingPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class MilestoneRecord(StrictModel):
    milestone_ref: OpaqueRef
    completed_at: str
    due_at: str
    late: bool = False
    owner_ref: OpaqueRef
    evidence_sha256: Sha256Digest


class OnboardingReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    account_ref: OpaqueRef | None = None
    revenue_source: dict[str, Any] | None = None
    revenue_plan: dict[str, Any] | None = None
    milestone_ref: OpaqueRef | None = None
    completed_at: str | None = None
    owner_ref: OpaqueRef | None = None
    evidence_sha256: Sha256Digest | None = None
    usage_row: dict[str, Any] | None = None
    usage_provenance: dict[str, Any] | None = None
    usage_digest: Sha256Digest | None = None
    activated_at: str | None = None
    handover_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("completed_at", "activated_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class OnboardingLedger(StrictModel):
    account_ref: str | None = None
    prospect_ref: str | None = None
    deal_ref: str | None = None
    deal_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    revenue_digest: str | None = None
    kicked_off_at: str | None = None
    milestones: tuple[MilestoneRecord, ...] = Field(default_factory=tuple, max_length=40)
    risks: tuple[str, ...] = Field(default_factory=tuple, max_length=40)
    at_risk_since: str | None = None
    activated_at: str | None = None
    days_to_activate: int | None = None
    activated_inside_window: bool | None = None
    usage_digest: str | None = None
    live_at: str | None = None
    days_to_live: int | None = None
    handed_over_at: str | None = None
    handover_ref: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "handed_over", "abandoned"] = "open"

    @field_validator("milestones", "risks", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("deal_value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="deal_value")

    @property
    def completed_refs(self) -> tuple[str, ...]:
        return tuple(item.milestone_ref for item in self.milestones)


class OnboardingEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    account_provisioned: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_onboarding(plan: OnboardingPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "kick_off":
        require(r.account_ref is not None and r.revenue_source is not None and r.revenue_plan is not None, "KICKOFF_NOT_PROVEN", "an onboarding opens from the account and the replayed revenue case of the won deal")
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE

        try:
            revenue_plan, case = REVENUE_CHAIN_LIFECYCLE.bind(r.revenue_plan, r.revenue_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "KICKOFF_NOT_PROVEN", f"the revenue case must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(revenue_plan.company_ref == plan.company_ref and case.scope.currency == plan.currency, "REVENUE_SCOPE_MISMATCH", "the revenue case belongs to another company or currency")
        require(case.status in WON_REVENUE_STATUSES, "DEAL_NOT_WON", f"the revenue case is {case.status}; onboarding starts once the agreement is executed")
        require(parsed(case.transition_history[-1].command.occurred_at) <= parsed(at), "REVENUE_FROM_FUTURE", "the revenue case cannot come from the future")
        data.update({"account_ref": r.account_ref, "prospect_ref": case.ledger.prospect_ref, "deal_ref": case.ledger.deal_ref, "deal_value": str(case.ledger.deal_value), "revenue_digest": case.state_digest, "kicked_off_at": at})
    elif event == "complete_milestone":
        require(r.milestone_ref is not None and r.completed_at is not None and r.owner_ref is not None and r.evidence_sha256 is not None, "MILESTONE_MISSING", "a milestone completion names the milestone, the time, the owner, and the evidence digest")
        template = plan.milestone(str(r.milestone_ref))
        require(template is not None, "MILESTONE_UNKNOWN", f"{r.milestone_ref} is not a milestone of the {plan.profile} template")
        assert template is not None
        done = [dict(item) for item in data.get("milestones", ())]
        require(all(item["milestone_ref"] != r.milestone_ref for item in done), "MILESTONE_ALREADY_COMPLETE", f"{r.milestone_ref} was already completed")
        require(parsed(str(data["kicked_off_at"])) <= parsed(str(r.completed_at)) <= parsed(at), "MILESTONE_TIME_INVALID", "a milestone completes after kick-off and before its recording")
        due_at = add_days(str(data["kicked_off_at"]), template.due_days)
        record = MilestoneRecord(milestone_ref=str(r.milestone_ref), completed_at=str(r.completed_at), due_at=due_at, late=parsed(str(r.completed_at)) > parsed(due_at), owner_ref=str(r.owner_ref), evidence_sha256=str(r.evidence_sha256)).to_dict()
        data.update({"milestones": [*done, record]})
        if status == "activated":
            return "activated", data
    elif event == "flag_at_risk":
        require(r.milestone_ref is not None, "RISK_MISSING", "a risk names the milestone it threatens")
        require(plan.milestone(str(r.milestone_ref)) is not None, "MILESTONE_UNKNOWN", f"{r.milestone_ref} is not a milestone of this template")
        data.update({"risks": [*data.get("risks", ()), str(r.milestone_ref)], "at_risk_since": at})
    elif event == "resolve_risk":
        require(r.evidence_sha256 is not None, "RESOLUTION_MISSING", "a risk resolves with the digest of what changed")
        data.update({"at_risk_since": None})
    elif event == "activate":
        require(r.usage_row is not None and r.usage_provenance is not None and r.usage_digest is not None and r.activated_at is not None, "ACTIVATION_NOT_PROVEN", "activation is the account's own usage row sealed by its read, never asserted")
        require(str(dict(r.usage_provenance or {}).get("output_digest")) == r.usage_digest == stable_digest(dict(r.usage_row or {})), "USAGE_NOT_BOUND", "the provenance does not seal this usage row")
        from lightbulb.saas_operating_loop import AccountUsage

        try:
            row = AccountUsage.model_validate(dict(r.usage_row or {}))
        except ValueError as exc:
            require(False, "USAGE_ROW_INVALID", f"the usage row is not an account usage fact: {exc}"[:300])
            raise AssertionError from exc
        require(str(row.account_ref) == str(data["account_ref"]), "ACCOUNT_MISMATCH", f"the usage row is for {row.account_ref}, not {data['account_ref']}")
        require(row.activated_at is not None and row.activated_at == r.activated_at, "ACCOUNT_NOT_ACTIVATED", f"the usage row does not show {data['account_ref']} activated at {r.activated_at}")
        require(parsed(str(r.activated_at)) <= parsed(at), "ACTIVATION_FROM_FUTURE", "activation cannot be recorded before it happened")
        days = (parsed(str(r.activated_at)) - parsed(str(data["kicked_off_at"]))).days
        data.update({"activated_at": r.activated_at, "days_to_activate": max(days, 0), "activated_inside_window": days <= plan.activation_within_days, "usage_digest": r.usage_digest, "at_risk_since": None})
    elif event == "go_live":
        done = {str(dict(item)["milestone_ref"]) for item in data.get("milestones", ())}
        missing = [item.milestone_ref for item in plan.milestones if item.required and item.milestone_ref not in done]
        require(not missing, "MILESTONES_OUTSTANDING", f"required milestones not completed: {missing}")
        require(not plan.require_activation_for_live or data.get("activated_at") is not None, "NOT_ACTIVATED", "this plan goes live only after the account activated")
        data.update({"live_at": at, "days_to_live": (parsed(at) - parsed(str(data["kicked_off_at"]))).days})
    elif event == "hand_over":
        require(r.handover_ref is not None, "HANDOVER_MISSING", "a handover names the retention or account-management reference that takes the customer")
        data.update({"handed_over_at": at, "handover_ref": r.handover_ref, "outcome": "handed_over"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


ONBOARDING_LIFECYCLE = LifecycleSpec(entity="customer_onboarding", schema_prefix=ONBOARDING_KIND, statuses=ONBOARDING_STATUSES, terminal=TERMINAL_ONBOARDING_STATUSES, events=ONBOARDING_EVENTS, table=_ONBOARDING_TABLE, opening_event="kick_off", reason_events=("abandon",), apply=_apply_onboarding, ledger_model=OnboardingLedger, receipt_model=OnboardingReceipt, effect_boundary_model=OnboardingEffectBoundary, plan_model=OnboardingPlan, max_transitions=MAX_ONBOARDING_TRANSITIONS)
CustomerOnboardingState = ONBOARDING_LIFECYCLE.State


def open_customer_onboarding(plan: OnboardingPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return ONBOARDING_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_customer_onboarding(plan: OnboardingPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return ONBOARDING_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def kickoff_receipt(revenue_state: Any, *, source_plan: Any, account_ref: str) -> dict[str, Any]:
    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE

    try:
        plan, state = REVENUE_CHAIN_LIFECYCLE.bind(source_plan, revenue_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise OnboardingChainError("KICKOFF_NOT_PROVEN", "retain the original revenue case and its sealed plan") from exc
    _require(state.status in WON_REVENUE_STATUSES, "DEAL_NOT_WON", f"the revenue case is {state.status}")
    return {"account_ref": account_ref, "revenue_source": state.to_dict(), "revenue_plan": plan.to_dict(), "evidence_refs": [f"revenue_case:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def milestone_receipt(*, milestone_ref: str, completed_at: str, owner_ref: str, evidence_sha256: str) -> dict[str, Any]:
    return {"milestone_ref": milestone_ref, "completed_at": timestamp(completed_at, field_name="completed_at"), "owner_ref": owner_ref, "evidence_sha256": evidence_sha256, "evidence_refs": [f"milestone:{milestone_ref}:{evidence_sha256[:16]}"]}


USAGE_TOOLS: frozenset[str] = frozenset({"posthog.query_events", "host.posthog_usage", "host.product_usage"})


def activation_receipt(provenance: Mapping[str, Any] | Any, usage_row: Mapping[str, Any] | Any, *, account_ref: str) -> dict[str, Any]:
    """From the account's usage row (an ``AccountUsage`` fact) and the read that produced it: the row's own ``activated_at``."""

    from lightbulb.saas_operating_loop import AccountUsage

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in USAGE_TOOLS, "USAGE_NOT_BOUND", f"expected a read from {sorted(USAGE_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "USAGE_NOT_BOUND", f"the provenance lacks {key}")
    raw = dict(detached(usage_row))
    _require(str(prov["output_digest"]) == stable_digest(raw), "USAGE_NOT_BOUND", "the provenance does not seal this exact usage row")
    row = AccountUsage.model_validate(raw)
    _require(str(row.account_ref) == account_ref, "ACCOUNT_MISMATCH", f"the usage row is for {row.account_ref}, not {account_ref}")
    _require(row.activated_at is not None, "ACCOUNT_NOT_ACTIVATED", f"the usage row shows {account_ref} not yet activated")
    return {"usage_row": raw, "usage_provenance": prov, "usage_digest": str(prov["output_digest"]), "activated_at": str(row.activated_at), "evidence_refs": [f"usage:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def overdue_milestones(state: Any, *, source_plan: Any, now: str) -> list[dict[str, Any]]:
    """Required milestones past due and not completed, oldest first."""

    plan, bound = ONBOARDING_LIFECYCLE.bind(source_plan, state)
    stamp = timestamp(now, field_name="now")
    if bound.status in TERMINAL_ONBOARDING_STATUSES or bound.status == "live":
        return []
    done = set(bound.ledger.completed_refs)
    out = []
    for template in plan.milestones:
        if not template.required or template.milestone_ref in done:
            continue
        due_at = add_days(str(bound.ledger.kicked_off_at), template.due_days)
        overdue = (parsed(stamp) - parsed(due_at)).days
        if overdue > 0:
            out.append({"milestone_ref": template.milestone_ref, "due_at": due_at, "days_overdue": overdue})
    return sorted(out, key=lambda item: item["due_at"])


def onboarding_at_risk_signal(state: Any, *, source_plan: Any, now: str) -> dict[str, Any] | None:
    """A ``signals.onboarding_at_risk`` payload for the oldest overdue required milestone; ``None`` when nothing is overdue."""

    overdue = overdue_milestones(state, source_plan=source_plan, now=now)
    if not overdue:
        return None
    _, bound = ONBOARDING_LIFECYCLE.bind(source_plan, state)
    first = overdue[0]
    return {"name": "signals.onboarding_at_risk", "producer": ONBOARDING_KIND, "emitted_at": timestamp(now, field_name="now"), "payload": {"account_ref": str(bound.ledger.account_ref), "milestone_ref": first["milestone_ref"], "days_overdue": first["days_overdue"], "source_digest": bound.state_digest}}


def onboarding_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in ONBOARDING_STATUSES}
    activated = [state for state in states if state.ledger.activated_at is not None]
    live = [state for state in states if state.ledger.live_at is not None]
    inside = sum(1 for state in activated if state.ledger.activated_inside_window)
    return {"onboardings": len(states), "by_status": counts, "activated": len(activated), "activated_inside_window_percent": None if not activated else str((Decimal(inside) / Decimal(len(activated)) * _HUNDRED).quantize(Decimal("0.01"))), "average_days_to_activate": None if not activated else str((Decimal(sum(state.ledger.days_to_activate or 0 for state in activated)) / Decimal(len(activated))).quantize(Decimal("0.1"))), "average_days_to_live": None if not live else str((Decimal(sum(state.ledger.days_to_live or 0 for state in live)) / Decimal(len(live))).quantize(Decimal("0.1"))), "late_milestones": sum(1 for state in states for item in state.ledger.milestones if item.late), "deal_value_onboarding": str(sum((state.ledger.deal_value for state in states if state.status not in TERMINAL_ONBOARDING_STATUSES), Decimal("0")).quantize(Decimal("0.01")))}


ONBOARDING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": ONBOARDING_KIND,
    "golden_loop": ONBOARDING_GOLDEN_LOOP,
    "stages": ["kick_off", "complete_milestone", "activate", "go_live", "hand_over"],
    "statuses": list(ONBOARDING_STATUSES),
    "events": list(ONBOARDING_EVENTS),
    "hops": {"kick_off": "the replayed revenue case of the won deal, agreement executed or later", "complete_milestone": "a template milestone with owner and evidence digest; late is computed against the due day", "activate": "the account's own usage row, sealed by its read, showing activated_at", "go_live": "every required milestone done and, when the plan demands it, activation", "hand_over": "the retention or account-management reference that takes the customer"},
    "required_connectors": ["posthog", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "onboarding opens only from a won revenue case; the deal value is the case's",
        "milestones come from the sealed template and lateness is computed, never asserted",
        "activation is the account's usage fact sealed by its read, never a claim",
        "an overdue required milestone is a signal to the operating system, not a silent slip",
    ],
}

__all__ = ["USAGE_TOOLS", "ONBOARDING_EVENTS", "ONBOARDING_GOLDEN_LOOP", "ONBOARDING_KIND", "ONBOARDING_LIFECYCLE", "ONBOARDING_MANIFEST", "ONBOARDING_PROFILES", "ONBOARDING_STATUSES", "TERMINAL_ONBOARDING_STATUSES", "WON_REVENUE_STATUSES", "CustomerOnboardingState", "MilestoneRecord", "MilestoneTemplate", "OnboardingChainError", "OnboardingLedger", "OnboardingPlan", "OnboardingReceipt", "activation_receipt", "advance_customer_onboarding", "compile_onboarding_chain", "kickoff_receipt", "milestone_receipt", "onboarding_at_risk_signal", "onboarding_summary", "open_customer_onboarding", "overdue_milestones"]
