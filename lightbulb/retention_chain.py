"""The retention chain: one replay-fenced lifecycle per account renewal, from due to renewed, expanded, or churned.

Renewals are the second revenue source and had no lifecycle: the SaaS
operating engine observed usage and churn risk, the billing observation
knew who had paid, and nothing tied a renewal to the cash it produced.
``RETENTION_LIFECYCLE`` does:

    renewal_due -> at_risk -> outreach_sent -> renewed | expanded | churned   (terminal)
    renewal_due -> outreach_sent -> ...
    renewal_due | at_risk | outreach_sent -> renewed | expanded | churned
    any non-terminal -> lapsed                                               (terminal)

* ``renewal_receipt`` opens the case from the account's billing row (the
  ``live_signal_observations`` billing observation) and the plan tier it is
  on: the renewal amount is the tier's price for the term, never a typed
  figure.
* ``risk_receipt`` consumes a ``ChurnRisk`` row from the usage snapshot.
* ``outreach_receipt`` consumes a bound execution receipt from a platform
  message write the operator approved (same shape as pipeline touches).
* ``renewal_evidence`` consumes the next billing observation: paid inside
  the renewal window at the same tier is ``renew``; paid at a higher tier is
  ``expand``; past due beyond the plan's grace, or cancelled, is ``churn``.

``hand_off_receipt`` turns a renewed or expanded case into the revenue
chain's opening receipt, so renewal cash is proven by the same chain as new
cash.  Nothing here writes to a provider.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
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
)
from lightbulb.saas_operating_loop import SaasOperatingLoopPlan

RETENTION_KIND = "retention_chain"
RETENTION_GOLDEN_LOOP = "saas.launched_product_to_compounding_revenue@0.1.0"
RETENTION_PLAN_SCHEMA = "lightbulb.retention_chain_plan.v1"
MAX_RETENTION_TRANSITIONS = 12
_HUNDRED = Decimal("100")

RETENTION_STATUSES: tuple[str, ...] = ("renewal_due", "at_risk", "outreach_sent", "renewed", "expanded", "churned", "lapsed")
TERMINAL_RETENTION_STATUSES: frozenset[str] = frozenset({"renewed", "expanded", "churned", "lapsed"})
RETENTION_EVENTS: tuple[str, ...] = ("flag_renewal", "mark_at_risk", "send_outreach", "renew", "expand", "churn", "lapse")
_RETENTION_TABLE: dict[tuple[str, str], str] = {
    ("new", "flag_renewal"): "renewal_due",
    ("renewal_due", "mark_at_risk"): "at_risk",
    ("renewal_due", "send_outreach"): "outreach_sent",
    ("at_risk", "send_outreach"): "outreach_sent",
    **{(status, "renew"): "renewed" for status in ("renewal_due", "at_risk", "outreach_sent")},
    **{(status, "expand"): "expanded" for status in ("renewal_due", "at_risk", "outreach_sent")},
    **{(status, "churn"): "churned" for status in ("renewal_due", "at_risk", "outreach_sent")},
    **{(status, "lapse"): "lapsed" for status in ("renewal_due", "at_risk", "outreach_sent")},
}


class RetentionChainPlan(StrictModel):
    """What the chain enforces: the tiers, the term, how early a renewal is flagged, and how long past due still counts as a renewal."""

    schema_id: str = Field(default=RETENTION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: ShortText
    term_months: int = Field(default=12, ge=1, le=36)
    flag_days_before_due: int = Field(default=45, ge=1, le=180)
    grace_days_past_due: int = Field(default=21, ge=0, le=120)
    min_outreach_lead_days: int = Field(default=7, ge=0, le=90)
    tiers: dict[str, Decimal] = Field(default_factory=dict)
    saas_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("tiers", mode="before")
    @classmethod
    def _tiers(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=f"tiers.{key}") for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RetentionChainPlan:
        if not self.tiers:
            raise ValueError("the plan names at least one tier and its monthly price")
        if not skip_digests(info) and self.plan_digest != sealed_digest(RetentionChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def term_amount(self, plan_ref: str) -> Decimal:
        return (self.tiers[plan_ref] * self.term_months).quantize(MONEY_QUANTUM)


def compile_retention_chain(company_ref: str, *, saas_plan: SaasOperatingLoopPlan | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> RetentionChainPlan:
    """Tiers and currency come from the sealed SaaS operating plan; the caller may override the term and windows only."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(saas_plan))
    tiers = {str(tier.plan_ref): str(tier.monthly_price) for tier in parsed_plan.blueprint.plans}
    raw = {"company_ref": company_ref, "currency": str(parsed_plan.blueprint.currency).upper(), "tiers": tiers, "saas_plan_digest": parsed_plan.plan_digest, **dict(overrides or {})}
    raw["tiers"] = tiers
    return seal(RetentionChainPlan, raw, "plan_digest")


class RetentionReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    account_ref: OpaqueRef | None = None
    plan_ref: ShortText | None = None
    renews_at: str | None = None
    renewal_amount: Decimal | None = None
    billing_digest: Sha256Digest | None = None
    inactive_days: int | None = Field(default=None, ge=0, le=3650)
    mrr_at_risk: Decimal | None = None
    snapshot_digest: Sha256Digest | None = None
    touch_ref: OpaqueRef | None = None
    channel: ShortText | None = None
    sent_at: str | None = None
    approval_ref: OpaqueRef | None = None
    execution_digest: Sha256Digest | None = None
    paid_amount: Decimal | None = None
    paid_at: str | None = None
    new_plan_ref: ShortText | None = None
    days_past_due: int | None = Field(default=None, ge=0, le=3650)
    cancelled: bool | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("renewal_amount", "mrr_at_risk", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("renews_at", "sent_at", "paid_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class RetentionLedger(StrictModel):
    account_ref: str | None = None
    plan_ref: str | None = None
    renews_at: str | None = None
    renewal_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    flagged_at: str | None = None
    at_risk_at: str | None = None
    inactive_days: int | None = None
    mrr_at_risk: Decimal = Field(default=Decimal("0"), validate_default=True)
    outreach_count: int = Field(default=0, ge=0)
    last_outreach_at: str | None = None
    outcome_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    outcome_plan_ref: str | None = None
    decided_at: str | None = None
    expansion_delta: Decimal = Field(default=Decimal("0"), validate_default=True)
    churn_reason: str | None = None
    lapse_reason: str | None = None
    outcome: Literal["open", "renewed", "expanded", "churned", "lapsed"] = "open"

    @field_validator("renewal_amount", "mrr_at_risk", "outcome_amount", "expansion_delta", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class RetentionEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    plan_changed: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_retention(plan: RetentionChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "flag_renewal":
        require(r.account_ref is not None and r.plan_ref is not None and r.renews_at is not None and r.billing_digest is not None, "RENEWAL_MISSING", "a renewal names the account, its tier, the renewal date, and the billing observation digest")
        require(r.plan_ref in plan.tiers, "TIER_UNKNOWN", f"{r.plan_ref} is not a tier of this plan")
        require((parsed(r.renews_at) - parsed(at)).days <= plan.flag_days_before_due, "FLAGGED_TOO_EARLY", f"the renewal is more than {plan.flag_days_before_due} days away")
        data.update({"account_ref": r.account_ref, "plan_ref": r.plan_ref, "renews_at": r.renews_at, "renewal_amount": str(plan.term_amount(r.plan_ref)), "flagged_at": at})
    elif event == "mark_at_risk":
        require(r.inactive_days is not None and r.mrr_at_risk is not None and r.snapshot_digest is not None, "RISK_MISSING", "a churn risk names the inactive days, the MRR at risk, and the snapshot digest")
        data.update({"at_risk_at": at, "inactive_days": r.inactive_days, "mrr_at_risk": str(r.mrr_at_risk)})
    elif event == "send_outreach":
        require(r.touch_ref is not None and r.channel is not None and r.sent_at is not None and r.approval_ref is not None and r.execution_digest is not None, "OUTREACH_MISSING", "an outreach carries the touch, the channel, the time, the approval, and the execution digest")
        require((parsed(str(data["renews_at"])) - parsed(r.sent_at)).days >= plan.min_outreach_lead_days, "OUTREACH_TOO_LATE", f"outreach must be sent at least {plan.min_outreach_lead_days} days before the renewal", "manual_reconciliation")
        data.update({"outreach_count": int(data.get("outreach_count", 0)) + 1, "last_outreach_at": r.sent_at})
    elif event in ("renew", "expand"):
        require(r.paid_amount is not None and r.paid_at is not None and r.billing_digest is not None, "RENEWAL_EVIDENCE_MISSING", "a renewal outcome carries the paid amount, the time, and the billing observation digest")
        past_due = (parsed(r.paid_at) - parsed(str(data["renews_at"]))).days
        require(past_due <= plan.grace_days_past_due, "RENEWAL_PAID_TOO_LATE", f"paid {past_due} days after renewal; the plan's grace is {plan.grace_days_past_due}", "manual_reconciliation")
        new_plan = r.new_plan_ref or str(data["plan_ref"])
        require(new_plan in plan.tiers, "TIER_UNKNOWN", f"{new_plan} is not a tier of this plan")
        expected = plan.term_amount(new_plan)
        require(r.paid_amount >= expected, "RENEWAL_UNDERPAID", f"paid {r.paid_amount}; the {new_plan} term is {expected}", "manual_reconciliation")
        delta = (expected - Decimal(str(data["renewal_amount"]))).quantize(MONEY_QUANTUM)
        if event == "expand":
            require(delta > 0, "EXPANSION_NOT_HIGHER", f"{new_plan} does not exceed the current tier")
        else:
            require(delta <= 0, "RENEWAL_IS_EXPANSION", f"{new_plan} exceeds the current tier; record an expansion")
        data.update({"outcome_amount": str(expected), "outcome_plan_ref": new_plan, "decided_at": r.paid_at, "expansion_delta": str(delta), "outcome": "expanded" if event == "expand" else "renewed"})
    elif event == "churn":
        require(r.billing_digest is not None and (r.cancelled or (r.days_past_due is not None and r.days_past_due > plan.grace_days_past_due)), "CHURN_UNPROVEN", f"churn needs a cancellation or more than {plan.grace_days_past_due} days past due in the billing observation")
        data.update({"decided_at": at, "churn_reason": str(command.reason)[:300], "outcome": "churned"})
    elif event == "lapse":
        data.update({"decided_at": at, "lapse_reason": str(command.reason)[:300], "outcome": "lapsed"})
    return next_status, data


RETENTION_LIFECYCLE = LifecycleSpec(entity="renewal_case", schema_prefix=RETENTION_KIND, statuses=RETENTION_STATUSES, terminal=TERMINAL_RETENTION_STATUSES, events=RETENTION_EVENTS, table=_RETENTION_TABLE, opening_event="flag_renewal", reason_events=("churn", "lapse"), apply=_apply_retention, ledger_model=RetentionLedger, receipt_model=RetentionReceipt, effect_boundary_model=RetentionEffectBoundary, plan_model=RetentionChainPlan, max_transitions=MAX_RETENTION_TRANSITIONS)
RenewalCaseState = RETENTION_LIFECYCLE.State


def open_renewal_case(plan: RetentionChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return RETENTION_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_renewal_case(plan: RetentionChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return RETENTION_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


class RetentionChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RetentionChainError(code, message)


def _account_row(billing: Mapping[str, Any] | Any, account_ref: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = dict(detached(billing))
    rows = [dict(detached(item)) for item in raw.get("accounts") or []]
    row = next((item for item in rows if str(item.get("account_ref")) == account_ref), None)
    _require(row is not None, "ACCOUNT_NOT_BILLED", f"{account_ref} is not in the billing observation")
    return raw, row  # type: ignore[return-value]


def renewals_due(plan: RetentionChainPlan | Mapping[str, Any], billing: Mapping[str, Any] | Any, *, now: str) -> list[dict[str, Any]]:
    """Opening receipts for every billed account whose term renews inside the flag window; the renewal date is the last payment plus the term."""

    parsed_plan = RetentionChainPlan.model_validate(detached(plan))
    raw = dict(detached(billing))
    stamp = timestamp(now, field_name="now")
    out: list[dict[str, Any]] = []
    for item in raw.get("accounts") or []:
        row = dict(detached(item))
        plan_ref = str(row.get("plan_ref") or "")
        if plan_ref not in parsed_plan.tiers or not row.get("last_paid_at") or parsed_plan.term_amount(plan_ref) <= 0:
            continue
        renews_at = add_days(str(row["last_paid_at"]), parsed_plan.term_months * 30)
        days = (parsed(renews_at) - parsed(stamp)).days
        if 0 <= days <= parsed_plan.flag_days_before_due:
            out.append(renewal_receipt(parsed_plan, billing, account_ref=str(row["account_ref"]), renews_at=renews_at))
    return out


def renewal_receipt(plan: RetentionChainPlan | Mapping[str, Any], billing: Mapping[str, Any] | Any, *, account_ref: str, renews_at: str) -> dict[str, Any]:
    """The opening receipt from the account's billing row; the tier must be one the plan prices."""

    parsed_plan = RetentionChainPlan.model_validate(detached(plan))
    raw, row = _account_row(billing, account_ref)
    plan_ref = str(row.get("plan_ref") or "")
    _require(plan_ref in parsed_plan.tiers, "TIER_UNKNOWN", f"{plan_ref} is not a tier of this plan")
    _require(parsed_plan.term_amount(plan_ref) > 0, "TIER_NOT_BILLABLE", f"{plan_ref} is a free tier; there is no renewal cash to prove")
    _require(str(raw.get("currency", "")).upper() == parsed_plan.currency, "BILLING_CURRENCY_MISMATCH", f"billing is in {raw.get('currency')}; the chain runs in {parsed_plan.currency}")
    return {"account_ref": account_ref, "plan_ref": plan_ref, "renews_at": timestamp(renews_at, field_name="renews_at"), "renewal_amount": str(parsed_plan.term_amount(plan_ref)), "billing_digest": str(raw.get("provenance_digest") or stable_digest(raw)), "evidence_refs": [f"billing:{str(raw.get('provenance_digest') or stable_digest(raw))[:16]}"]}


def risk_receipt(snapshot: Mapping[str, Any] | Any, *, account_ref: str) -> dict[str, Any]:
    """From the usage snapshot's churn-risk row for the account."""

    raw = dict(detached(snapshot))
    risk = next((dict(detached(item)) for item in raw.get("churn_risks") or [] if str(dict(detached(item)).get("account_ref")) == account_ref), None)
    _require(risk is not None, "ACCOUNT_NOT_AT_RISK", f"{account_ref} is not a churn risk in the snapshot")
    return {"inactive_days": int(risk["inactive_days"]), "mrr_at_risk": str(risk["mrr_at_risk"]), "snapshot_digest": str(raw.get("snapshot_digest") or stable_digest(raw)), "evidence_refs": [f"snapshot:{str(raw.get('snapshot_digest') or stable_digest(raw))[:16]}"]}  # type: ignore[index]


def outreach_receipt(execution: Mapping[str, Any] | Any, *, touch_ref: str, channel: str, approval_ref: str) -> dict[str, Any]:
    """From a bound platform execution receipt (the same shape pipeline touches bind); failed or unapproved sends are refused."""

    raw = dict(detached(execution))
    status = str(raw.get("status") or raw.get("outcome") or "").lower()
    _require(status in ("success", "succeeded", "applied", "bound"), "OUTREACH_NOT_SENT", f"the execution is {status or 'missing'}")
    digest = raw.get("receipt_digest") or raw.get("execution_digest") or raw.get("journal_receipt_sha256")
    _require(bool(digest), "EXECUTION_DIGEST_MISSING", "the execution receipt carries no digest")
    sent_at = raw.get("completed_at") or raw.get("sent_at")
    _require(bool(sent_at), "OUTREACH_TIME_MISSING", "the execution receipt carries no completion time")
    return {"touch_ref": touch_ref, "channel": channel, "sent_at": str(sent_at), "approval_ref": approval_ref, "execution_digest": str(digest), "evidence_refs": [f"execution:{str(digest)[:16]}"]}


def renewal_evidence(plan: RetentionChainPlan | Mapping[str, Any], billing: Mapping[str, Any] | Any, *, account_ref: str, renews_at: str, new_plan_ref: str | None = None, current_plan_ref: str | None = None) -> tuple[str, dict[str, Any]]:
    """Classify the next billing observation for the account: ``renew``, ``expand``, or ``churn`` with the receipt that proves it.

    ``current_plan_ref`` is the tier the case was flagged on; a paid tier above it is an expansion.
    """

    parsed_plan = RetentionChainPlan.model_validate(detached(plan))
    raw, row = _account_row(billing, account_ref)
    digest = str(raw.get("provenance_digest") or stable_digest(raw))
    evidence = [f"billing:{digest[:16]}"]
    paid = decimal_value(row.get("paid_in_window", "0"), field_name="paid_in_window")
    past_due_days = int(row.get("days_past_due") or 0)
    cancelled = bool(row.get("cancelled")) or str(row.get("status", "")).lower() in ("cancelled", "canceled")
    if cancelled or (paid <= 0 and past_due_days > parsed_plan.grace_days_past_due):
        return "churn", {"billing_digest": digest, "days_past_due": past_due_days, "cancelled": cancelled, "evidence_refs": evidence}
    _require(paid > 0 and bool(row.get("last_paid_at")), "RENEWAL_NOT_PAID", f"{account_ref} has not paid in the window")
    tier = new_plan_ref or str(row.get("plan_ref") or "")
    _require(tier in parsed_plan.tiers, "TIER_UNKNOWN", f"{tier} is not a tier of this plan")
    receipt = {"paid_amount": str(paid.quantize(MONEY_QUANTUM)), "paid_at": str(row["last_paid_at"]), "billing_digest": digest, "new_plan_ref": tier, "evidence_refs": evidence}
    timestamp(renews_at, field_name="renews_at")
    baseline = current_plan_ref or str(row.get("plan_ref") or "")
    event = "expand" if baseline in parsed_plan.tiers and parsed_plan.term_amount(tier) > parsed_plan.term_amount(baseline) else "renew"
    return event, receipt


def hand_off_receipt(case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """Replay a won renewal and retain its original plan and state.

    This proves the priced renewal hand-off. The revenue chain still requires
    its independent agreement, invoice, payment, and settlement evidence.
    """

    try:
        plan, source = RETENTION_LIFECYCLE.bind(source_plan, case_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise RetentionChainError("RETENTION_SOURCE_INVALID", "retain the original renewal state and its sealed plan") from exc
    _require(plan.schema_id == RETENTION_PLAN_SCHEMA, "RETENTION_SOURCE_INVALID", "the source must use the retention plan schema")
    _require(source.scope.company_ref in {plan.company_ref, "selected"} and source.scope.currency == plan.currency,
             "RETENTION_SCOPE_MISMATCH", "the renewal scope must match its logical company and currency")
    _require(source.status in ("renewed", "expanded"), "RENEWAL_NOT_WON", f"the case is {source.status}")
    ledger = source.ledger
    _require(ledger.outcome_amount > 0 and ledger.outcome_plan_ref in plan.tiers
             and ledger.outcome_amount == plan.term_amount(ledger.outcome_plan_ref),
             "RETENTION_SOURCE_INVALID", "the hand-off must equal the observed outcome tier's term price")
    _require(parsed(ledger.decided_at) <= parsed(source.transition_history[-1].command.occurred_at),
             "HAND_OFF_FROM_FUTURE", "the renewal outcome must already exist when it is recorded")
    return {"prospect_ref": f"renewal:{ledger.account_ref}", "deal_ref": f"renewal:{source.scope.entity_ref}",
            "deal_value": str(ledger.outcome_amount), "prospect_state_digest": source.state_digest,
            "retention_source": {"state": source.to_dict(), "source_plan": plan.to_dict()},
            "evidence_refs": [f"renewal_case:{source.scope.entity_ref}:{source.state_digest[:16]}"]}


def retention_summary(cases: Sequence[Any]) -> dict[str, Any]:
    """Net revenue retention across a set of cases: renewed and expanded amounts over the amounts that were due."""

    due = sum((Decimal(str(case.ledger.renewal_amount)) for case in cases), Decimal("0"))
    kept = sum((Decimal(str(case.ledger.outcome_amount)) for case in cases if case.status in ("renewed", "expanded")), Decimal("0"))
    counts = {status: sum(1 for case in cases if case.status == status) for status in RETENTION_STATUSES}
    nrr = None if due <= 0 else (kept / due * _HUNDRED).quantize(Decimal("0.01"))
    return {"cases": len(cases), "amount_due": str(due.quantize(MONEY_QUANTUM)), "amount_kept": str(kept.quantize(MONEY_QUANTUM)), "net_revenue_retention_percent": None if nrr is None else str(nrr), "by_status": counts}


RETENTION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": RETENTION_KIND,
    "golden_loop": RETENTION_GOLDEN_LOOP,
    "stages": ["flag_renewal", "mark_at_risk", "send_outreach", "renew_or_expand_or_churn"],
    "statuses": list(RETENTION_STATUSES),
    "events": list(RETENTION_EVENTS),
    "hops": {"flag_renewal": "billing observation row + the SaaS plan's tier price", "mark_at_risk": "usage snapshot churn risk row", "send_outreach": "bound platform execution receipt of an approved message", "renew|expand|churn": "the next billing observation row"},
    "required_connectors": ["stripe", "posthog", "gmail", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the renewal amount is the tier's term price from the sealed SaaS plan, never a typed figure",
        "an outcome is classified from the next billing observation; the caller cannot assert a renewal",
        "expansion requires a higher tier paid in full; churn requires a cancellation or the grace exceeded",
        "renewal cash enters the revenue chain through hand_off_receipt and is proven there like new cash",
    ],
}

__all__ = ["RETENTION_EVENTS", "RETENTION_GOLDEN_LOOP", "RETENTION_KIND", "RETENTION_LIFECYCLE", "RETENTION_MANIFEST", "RETENTION_STATUSES", "RenewalCaseState", "RetentionChainError", "RetentionChainPlan", "advance_renewal_case", "compile_retention_chain", "hand_off_receipt", "open_renewal_case", "outreach_receipt", "renewal_evidence", "renewal_receipt", "renewals_due", "retention_summary", "risk_receipt"]
