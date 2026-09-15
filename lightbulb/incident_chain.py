"""The incident chain: one replay-fenced lifecycle per production incident, from detection to the customer credited.

The SaaS operating engine carried SLA tables and a rollback window and a
release ledger that could only ever say ``incident_opened: False``.  Nothing
held an incident: how long the product was down, who was affected, whether
the SLA was breached, what the postmortem found, and what the credit
liability was.  ``INCIDENT_LIFECYCLE`` does:

    detected -> declared -> mitigated -> resolved -> reviewed -> credited -> closed   (terminal)
                declared ------------> resolved
                                              reviewed -> closed                        (no credits due)
    detected | declared -> invalidated                                                  (terminal, with a reason)

Every hop consumes a sealed artifact and the caller asserts nothing:

* ``detection_receipt`` opens the incident from a monitor, status page, or
  support-triage read with provenance.
* ``declaration_receipt`` names the severity (one of the SaaS plan's SLA
  rows), the commander, the start, and the affected accounts as opaque
  commitments on their plan tier.
* ``mitigation_receipt`` and ``resolution_receipt`` carry the times and the
  recovered-monitor read; the duration, the SLA verdict, and the credits due
  per affected account are computed from the sealed policy and the tier's
  monthly price, never typed.
* ``postmortem_receipt`` is accepted by a reviewer who is not the commander,
  inside the policy's window, with action items when the severity demands.
* ``credit_receipt`` consumes a billing credit-note read; every credit due
  must be settled for its exact amount before the incident closes.

``roadmap_candidates`` hands the postmortem's action items to
``saas_ops.rank_roadmap``; ``sla_breached_signal`` gives the operating
system its signal; ``credit_liability`` is what the treasury carries.
Nothing here pages anyone, issues a credit, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
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
from lightbulb.saas_operating_loop import SaasOperatingLoopPlan

INCIDENT_KIND = "incident_chain"
INCIDENT_GOLDEN_LOOP = "reliability.detected_incident_to_credited_customer@0.1.0"
INCIDENT_PLAN_SCHEMA = "lightbulb.incident_chain_plan.v1"
POSTMORTEM_SCHEMA = "lightbulb.incident_postmortem.v1"
MAX_INCIDENT_TRANSITIONS = 24
MONITOR_TOOLS: frozenset[str] = frozenset({"posthog.query_events", "github.get_workflow_run", "host.status_page", "host.monitor_alert", "host.support_triage", "host.uptime_check"})
CREDIT_TOOLS: frozenset[str] = frozenset({"stripe.list_credit_notes", "host.stripe_credit_notes", "stripe.list_invoices"})
Severity = Literal["sev1", "sev2", "sev3", "sev4"]
_HUNDRED = Decimal("100")
_MINUTE = 60

INCIDENT_STATUSES: tuple[str, ...] = ("detected", "declared", "mitigated", "resolved", "reviewed", "credited", "closed", "invalidated")
TERMINAL_INCIDENT_STATUSES: frozenset[str] = frozenset({"closed", "invalidated"})
INCIDENT_EVENTS: tuple[str, ...] = ("detect", "declare", "mitigate", "resolve", "accept_postmortem", "settle_credits", "close", "invalidate")
_INCIDENT_TABLE: dict[tuple[str, str], str] = {
    ("new", "detect"): "detected",
    ("detected", "declare"): "declared",
    ("declared", "mitigate"): "mitigated",
    ("declared", "resolve"): "resolved",
    ("mitigated", "resolve"): "resolved",
    ("resolved", "accept_postmortem"): "reviewed",
    ("reviewed", "settle_credits"): "credited",
    ("reviewed", "close"): "closed",
    ("credited", "close"): "closed",
    ("detected", "invalidate"): "invalidated",
    ("declared", "invalidate"): "invalidated",
}


class IncidentChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise IncidentChainError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class SlaRow(StrictModel):
    severity: Severity
    first_response_hours: int = Field(ge=1, le=720)
    resolution_hours: int = Field(ge=1, le=2000)
    escalate_to: ShortText


class CreditRule(StrictModel):
    severity: Severity
    credit_percent_of_monthly_fee: Decimal

    @field_validator("credit_percent_of_monthly_fee", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="credit_percent_of_monthly_fee")
        if result > _HUNDRED:
            raise ValueError("a credit never exceeds the monthly fee")
        return result


DEFAULT_CREDIT_RULES: tuple[dict[str, Any], ...] = ({"severity": "sev1", "credit_percent_of_monthly_fee": "25"}, {"severity": "sev2", "credit_percent_of_monthly_fee": "10"}, {"severity": "sev3", "credit_percent_of_monthly_fee": "0"}, {"severity": "sev4", "credit_percent_of_monthly_fee": "0"})


class IncidentChainPlan(StrictModel):
    """What the chain enforces: the SLA rows and tier prices from the sealed SaaS plan, the credit rules, and the postmortem window."""

    schema_id: str = Field(default=INCIDENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    slas: tuple[SlaRow, ...] = Field(min_length=1, max_length=4)
    tiers: dict[str, Decimal] = Field(default_factory=dict)
    credit_rules: tuple[CreditRule, ...] = Field(min_length=1, max_length=4)
    postmortem_due_days: int = Field(default=5, ge=1, le=60)
    postmortem_required_for: tuple[Severity, ...] = Field(default=("sev1", "sev2"), max_length=4)
    saas_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("slas", "credit_rules", "postmortem_required_for", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("tiers", mode="before")
    @classmethod
    def _tiers(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=f"tiers.{key}") for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "IncidentChainPlan":
        unique([row.severity for row in self.slas], label="SLA severities")
        unique([rule.severity for rule in self.credit_rules], label="credit rule severities")
        if not self.tiers:
            raise ValueError("the plan names at least one tier and its monthly price")
        if not skip_digests(info) and self.plan_digest != sealed_digest(IncidentChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def sla(self, severity: str) -> SlaRow | None:
        return next((row for row in self.slas if row.severity == severity), None)

    def credit_percent(self, severity: str) -> Decimal:
        return next((rule.credit_percent_of_monthly_fee for rule in self.credit_rules if rule.severity == severity), Decimal("0"))


def compile_incident_chain(company_ref: str, *, saas_plan: SaasOperatingLoopPlan | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> IncidentChainPlan:
    """SLAs, tiers, and currency come from the sealed SaaS operating plan; the caller may override the credit rules and windows only."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(saas_plan))
    bp = parsed_plan.blueprint
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(bp.currency).upper(), "slas": [item.to_dict() for item in bp.support_slas], "tiers": {str(tier.plan_ref): str(tier.monthly_price) for tier in bp.plans}, "credit_rules": [dict(item) for item in DEFAULT_CREDIT_RULES], "saas_plan_digest": parsed_plan.plan_digest, **dict(overrides or {})}
    raw["slas"], raw["tiers"] = [item.to_dict() for item in bp.support_slas], {str(tier.plan_ref): str(tier.monthly_price) for tier in bp.plans}
    return seal(IncidentChainPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class AffectedAccount(StrictModel):
    account_ref: OpaqueRef
    plan_ref: ShortText


class ActionItem(StrictModel):
    item_ref: OpaqueRef
    title: ShortText
    owner_ref: OpaqueRef
    due_at: str

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return timestamp(value, field_name="due_at")


class CreditRow(StrictModel):
    account_ref: OpaqueRef
    amount: Decimal
    credit_ref: OpaqueRef | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class IncidentReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    detection_ref: OpaqueRef | None = None
    detected_at: str | None = None
    monitor_provenance: dict[str, Any] | None = None
    monitor_digest: Sha256Digest | None = None
    severity: Severity | None = None
    commander_ref: OpaqueRef | None = None
    started_at: str | None = None
    affected: tuple[AffectedAccount, ...] = Field(default_factory=tuple, max_length=2000)
    mitigated_at: str | None = None
    action: ShortText | None = None
    release_ref: OpaqueRef | None = None
    evidence_sha256: Sha256Digest | None = None
    resolved_at: str | None = None
    recovery_provenance: dict[str, Any] | None = None
    recovery_digest: Sha256Digest | None = None
    postmortem_sha256: Sha256Digest | None = None
    reviewer_ref: OpaqueRef | None = None
    root_cause_category: ShortText | None = None
    action_items: tuple[ActionItem, ...] = Field(default_factory=tuple, max_length=50)
    credit_provenance: dict[str, Any] | None = None
    credit_digest: Sha256Digest | None = None
    credits: tuple[CreditRow, ...] = Field(default_factory=tuple, max_length=2000)
    credited_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "affected", "action_items", "credits", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("detected_at", "started_at", "mitigated_at", "resolved_at", "credited_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class IncidentLedger(StrictModel):
    detection_ref: str | None = None
    detected_at: str | None = None
    monitor_digest: str | None = None
    severity: str | None = None
    commander_ref: str | None = None
    started_at: str | None = None
    declared_at: str | None = None
    affected: tuple[AffectedAccount, ...] = Field(default_factory=tuple, max_length=2000)
    mitigated_at: str | None = None
    mitigation_action: str | None = None
    release_ref: str | None = None
    resolved_at: str | None = None
    duration_minutes: int = Field(default=0, ge=0)
    sla_resolution_hours: int | None = None
    sla_breached: bool = False
    credits_due: dict[str, Decimal] = Field(default_factory=dict)
    credits_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    postmortem_sha256: str | None = None
    reviewer_ref: str | None = None
    root_cause_category: str | None = None
    action_items: tuple[ActionItem, ...] = Field(default_factory=tuple, max_length=50)
    postmortem_accepted_at: str | None = None
    credits_settled_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    credited_at: str | None = None
    credit_digest: str | None = None
    closed_at: str | None = None
    invalid_reason: str | None = None
    outcome: Literal["open", "closed", "invalidated"] = "open"

    @field_validator("affected", "action_items", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("credits_due", mode="before")
    @classmethod
    def _credits(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="credits_due") for key, item in dict(value or {}).items()}

    @field_validator("credits_total", "credits_settled_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class IncidentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    page_sent: Literal[False] = False
    credit_issued: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_incident(plan: IncidentChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "detect":
        require(r.detection_ref is not None and r.detected_at is not None and r.monitor_provenance is not None and r.monitor_digest is not None, "DETECTION_MISSING", "a detection names the signal, the time, the monitor read provenance, and its digest")
        require(str(dict(r.monitor_provenance or {}).get("output_digest")) == r.monitor_digest, "DETECTION_NOT_BOUND", "the provenance does not seal this detection")
        require(parsed(str(r.detected_at)) <= parsed(at), "DETECTION_FROM_FUTURE", "a detection cannot post-date its recording")
        data.update({"detection_ref": r.detection_ref, "detected_at": r.detected_at, "monitor_digest": r.monitor_digest})
    elif event == "declare":
        require(r.severity is not None and r.commander_ref is not None and r.started_at is not None, "DECLARATION_MISSING", "a declaration names the severity, the commander, and when the impact started")
        require(plan.sla(str(r.severity)) is not None, "SEVERITY_UNKNOWN", f"{r.severity} has no SLA in this plan")
        require(parsed(str(r.started_at)) <= parsed(at), "IMPACT_FROM_FUTURE", "the impact started before the declaration")
        refs = [item.account_ref for item in r.affected]
        require(len(refs) == len(set(refs)), "AFFECTED_DUPLICATE", "each affected account appears once")
        for item in r.affected:
            require(item.plan_ref in plan.tiers, "TIER_UNKNOWN", f"{item.plan_ref} is not a tier of this plan")
        data.update({"severity": r.severity, "commander_ref": r.commander_ref, "started_at": r.started_at, "declared_at": at, "affected": [item.to_dict() for item in r.affected]})
    elif event == "mitigate":
        require(r.mitigated_at is not None and r.action is not None, "MITIGATION_MISSING", "a mitigation names the time and the action taken")
        require(parsed(str(data["started_at"])) <= parsed(str(r.mitigated_at)) <= parsed(at), "MITIGATION_TIME_INVALID", "mitigation follows the impact start and precedes its recording")
        data.update({"mitigated_at": r.mitigated_at, "mitigation_action": r.action, "release_ref": r.release_ref})
    elif event == "resolve":
        require(r.resolved_at is not None and r.recovery_provenance is not None and r.recovery_digest is not None, "RESOLUTION_MISSING", "a resolution names the time and the recovered-monitor read that proves it")
        require(str(dict(r.recovery_provenance or {}).get("output_digest")) == r.recovery_digest, "RESOLUTION_NOT_BOUND", "the provenance does not seal this recovery")
        floor = data.get("mitigated_at") or data["started_at"]
        require(parsed(str(floor)) <= parsed(str(r.resolved_at)) <= parsed(at), "RESOLUTION_TIME_INVALID", "resolution follows mitigation (or the impact start) and precedes its recording")
        minutes = int((parsed(str(r.resolved_at)) - parsed(str(data["started_at"]))).total_seconds() // _MINUTE)
        sla = plan.sla(str(data["severity"]))
        assert sla is not None
        breached = minutes > sla.resolution_hours * _MINUTE
        percent = plan.credit_percent(str(data["severity"])) if breached else Decimal("0")
        credits = {}
        for item in data.get("affected", ()):
            row = dict(item)
            price = plan.tiers.get(str(row["plan_ref"]), Decimal("0"))
            amount = _money(price * percent / _HUNDRED)
            if amount > 0:
                credits[str(row["account_ref"])] = str(amount)
        total = _money(sum((Decimal(value) for value in credits.values()), Decimal("0")))
        data.update({"resolved_at": r.resolved_at, "duration_minutes": minutes, "sla_resolution_hours": sla.resolution_hours, "sla_breached": breached, "credits_due": credits, "credits_total": str(total)})
    elif event == "accept_postmortem":
        require(r.postmortem_sha256 is not None and r.reviewer_ref is not None and r.root_cause_category is not None, "POSTMORTEM_MISSING", "a postmortem carries its digest, the reviewer, and the root cause category")
        require(r.reviewer_ref != data.get("commander_ref"), "SEGREGATION_VIOLATED", "the incident commander cannot accept their own postmortem")
        due_days = (parsed(at) - parsed(str(data["resolved_at"]))).days
        require(due_days <= plan.postmortem_due_days, "POSTMORTEM_LATE", f"the postmortem arrived {due_days} days after resolution; the window is {plan.postmortem_due_days} days", "manual_reconciliation")
        if str(data["severity"]) in plan.postmortem_required_for:
            require(bool(r.action_items), "ACTION_ITEMS_MISSING", f"a {data['severity']} postmortem names at least one action item with an owner and a due date")
        unique([item.item_ref for item in r.action_items], label="action items")
        for item in r.action_items:
            require(parsed(item.due_at) >= parsed(at), "ACTION_ITEM_OVERDUE", f"action item {item.item_ref} is due before the postmortem was accepted")
        data.update({"postmortem_sha256": r.postmortem_sha256, "reviewer_ref": r.reviewer_ref, "root_cause_category": r.root_cause_category, "action_items": [item.to_dict() for item in r.action_items], "postmortem_accepted_at": at})
    elif event == "settle_credits":
        due = {key: Decimal(str(value)) for key, value in dict(data.get("credits_due", {})).items()}
        require(bool(due), "NO_CREDITS_DUE", "no credit is due on this incident; close it")
        require(r.credit_provenance is not None and r.credit_digest is not None and bool(r.credits) and r.credited_at is not None, "CREDIT_EVIDENCE_MISSING", "settlement carries the billing credit read provenance, its digest, the credit rows, and the time")
        require(str(dict(r.credit_provenance or {}).get("output_digest")) == r.credit_digest, "CREDIT_NOT_BOUND", "the provenance does not seal these credits")
        require(parsed(str(r.credited_at)) <= parsed(at), "CREDIT_FROM_FUTURE", "credits cannot be settled in the future")
        settled = {row.account_ref: _money(row.amount) for row in r.credits}
        require(len(settled) == len(r.credits), "CREDIT_DUPLICATE", "one credit row per account")
        missing = sorted(set(due) - set(settled))
        require(not missing, "CREDIT_INCOMPLETE", f"no credit was observed for {missing[:5]}")
        extra = sorted(set(settled) - set(due))
        require(not extra, "CREDIT_UNEXPECTED", f"credits were observed for accounts with nothing due: {extra[:5]}")
        for account, amount in due.items():
            require(settled[account] == amount, "CREDIT_AMOUNT_MISMATCH", f"{account} is due {amount}; the credit read shows {settled[account]}")
        data.update({"credits_settled_total": str(_money(sum(settled.values(), Decimal("0")))), "credited_at": r.credited_at, "credit_digest": r.credit_digest})
    elif event == "close":
        if status == "reviewed":
            require(Decimal(str(data.get("credits_total", "0"))) == 0, "CREDITS_OUTSTANDING", f"{data.get('credits_total')} {plan.currency} of credits are due; settle them before closing")
        data.update({"closed_at": at, "outcome": "closed"})
    elif event == "invalidate":
        data.update({"invalid_reason": str(command.reason)[:300], "outcome": "invalidated"})
    return next_status, data


INCIDENT_LIFECYCLE = LifecycleSpec(entity="incident", schema_prefix=INCIDENT_KIND, statuses=INCIDENT_STATUSES, terminal=TERMINAL_INCIDENT_STATUSES, events=INCIDENT_EVENTS, table=_INCIDENT_TABLE, opening_event="detect", reason_events=("invalidate",), apply=_apply_incident, ledger_model=IncidentLedger, receipt_model=IncidentReceipt, effect_boundary_model=IncidentEffectBoundary, plan_model=IncidentChainPlan, max_transitions=MAX_INCIDENT_TRANSITIONS)
IncidentState = INCIDENT_LIFECYCLE.State


def open_incident(plan: IncidentChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return INCIDENT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_incident(plan: IncidentChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return INCIDENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in ("host_read", "governed_read"), code, f"a {raw.get('source_tool')} read arrives on a read lane, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def detection_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, detection_ref: str, detected_at: str | None = None) -> dict[str, Any]:
    """The opening receipt from a monitor, status page, or support-triage read."""

    prov = _provenance(provenance, tools=MONITOR_TOOLS, code="DETECTION_NOT_BOUND")
    _require(str(prov["output_digest"]) == stable_digest(detached(payload)), "DETECTION_NOT_BOUND", "the provenance does not seal this exact read")
    return {"detection_ref": detection_ref, "detected_at": timestamp(detected_at or str(prov["completed_at"]), field_name="detected_at"), "monitor_provenance": prov, "monitor_digest": str(prov["output_digest"]), "evidence_refs": [f"monitor:{prov['observation_ref']}"]}


def declaration_receipt(*, severity: str, commander_ref: str, started_at: str, affected: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    rows = [AffectedAccount.model_validate(dict(detached(item))).to_dict() for item in affected]
    return {"severity": severity, "commander_ref": commander_ref, "started_at": timestamp(started_at, field_name="started_at"), "affected": rows, "evidence_refs": [f"commander:{commander_ref}"]}


def mitigation_receipt(*, mitigated_at: str, action: str, release_ref: str | None = None, evidence_sha256: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"mitigated_at": timestamp(mitigated_at, field_name="mitigated_at"), "action": action, "evidence_refs": []}
    if release_ref is not None:
        receipt["release_ref"] = release_ref
        receipt["evidence_refs"].append(f"release:{release_ref}")
    if evidence_sha256 is not None:
        receipt["evidence_sha256"] = evidence_sha256
        receipt["evidence_refs"].append(f"mitigation:{evidence_sha256[:16]}")
    return receipt


def resolution_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, resolved_at: str | None = None) -> dict[str, Any]:
    """From the recovered-monitor read that proves service was restored."""

    prov = _provenance(provenance, tools=MONITOR_TOOLS, code="RESOLUTION_NOT_BOUND")
    _require(str(prov["output_digest"]) == stable_digest(detached(payload)), "RESOLUTION_NOT_BOUND", "the provenance does not seal this exact read")
    return {"resolved_at": timestamp(resolved_at or str(prov["completed_at"]), field_name="resolved_at"), "recovery_provenance": prov, "recovery_digest": str(prov["output_digest"]), "evidence_refs": [f"monitor:{prov['observation_ref']}"]}


def postmortem_receipt(document: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a self-naming postmortem record: digest, reviewer, root cause, action items."""

    raw = dict(detached(document))
    _require(str(raw.get("schema")) == POSTMORTEM_SCHEMA, "POSTMORTEM_SCHEMA_MISMATCH", f"a postmortem names itself {POSTMORTEM_SCHEMA}")
    for key in ("postmortem_sha256", "reviewer_ref", "root_cause_category"):
        _require(raw.get(key) is not None, "POSTMORTEM_INCOMPLETE", f"the postmortem lacks {key}")
    items = [ActionItem.model_validate(dict(item)).to_dict() for item in raw.get("action_items") or []]
    return {"postmortem_sha256": str(raw["postmortem_sha256"]), "reviewer_ref": str(raw["reviewer_ref"]), "root_cause_category": str(raw["root_cause_category"]), "action_items": items, "evidence_refs": [f"postmortem:{str(raw['postmortem_sha256'])[:16]}"]}


def credit_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, currency: str) -> dict[str, Any]:
    """From a billing credit-note read: one row per account credited, in the plan's currency."""

    prov = _provenance(provenance, tools=CREDIT_TOOLS, code="CREDIT_NOT_BOUND")
    raw = detached(payload)
    _require(str(prov["output_digest"]) == stable_digest(raw), "CREDIT_NOT_BOUND", "the provenance does not seal this exact read")
    rows = list(raw.get("credit_notes") or raw.get("data") or []) if isinstance(raw, Mapping) else list(raw)
    credits = []
    credited_at = None
    for item in rows:
        row = dict(item)
        _require(str(row.get("currency", currency)).upper() == str(currency).upper(), "CREDIT_CURRENCY_MISMATCH", f"a credit note is in {row.get('currency')}; the chain runs in {currency}")
        account = row.get("account_ref") or row.get("customer_ref") or row.get("customer")
        amount = row.get("amount") if row.get("amount") is not None else (Decimal(str(row.get("amount_minor", 0))) / 100)
        _require(account is not None and amount is not None, "CREDIT_ROW_INCOMPLETE", "a credit row names the account and the amount")
        credits.append(CreditRow(account_ref=str(account), amount=amount, credit_ref=(str(row["id"]) if row.get("id") is not None else None)).to_dict())
        stamp = row.get("credited_at") or row.get("created_at")
        if stamp is not None and (credited_at is None or parsed(str(stamp)) > parsed(str(credited_at))):
            credited_at = str(stamp)
    return {"credit_provenance": prov, "credit_digest": str(prov["output_digest"]), "credits": credits, "credited_at": timestamp(credited_at or str(prov["completed_at"]), field_name="credited_at"), "evidence_refs": [f"credits:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #

_IMPACT = {"sev1": 5, "sev2": 4, "sev3": 2, "sev4": 1}


def roadmap_candidates(state: Any, *, source_plan: Any) -> list[dict[str, Any]]:
    """The postmortem's action items as ``RoadmapCandidate`` rows for ``saas_ops.rank_roadmap``; reach is the accounts affected."""

    _, bound = INCIDENT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.postmortem_accepted_at is not None, "POSTMORTEM_NOT_ACCEPTED", "action items come from an accepted postmortem")
    return [{"candidate_ref": item.item_ref, "title": item.title, "reach_accounts": len(ledger.affected), "impact": _IMPACT.get(str(ledger.severity), 1), "confidence_percent": 80, "effort_weeks": "1", "evidence_refs": [f"incident:{bound.scope.entity_ref}:{bound.state_digest[:16]}", f"postmortem:{str(ledger.postmortem_sha256)[:16]}"]} for item in ledger.action_items]


def sla_breached_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    """A ``signals.sla_breached`` payload for a resolved incident that breached its SLA; ``None`` otherwise."""

    _, bound = INCIDENT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    if not ledger.sla_breached or ledger.resolved_at is None:
        return None
    return {"name": "signals.sla_breached", "producer": INCIDENT_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"incident_ref": bound.scope.entity_ref, "severity": str(ledger.severity), "duration_minutes": ledger.duration_minutes, "credits_due": str(ledger.credits_total), "source_digest": bound.state_digest}}


def credit_liability(states: Sequence[Any]) -> dict[str, Any]:
    """Credits due and not yet settled across incidents: the liability treasury carries."""

    due = sum((state.ledger.credits_total for state in states if state.status in ("resolved", "reviewed")), Decimal("0"))
    settled = sum((state.ledger.credits_settled_total for state in states), Decimal("0"))
    return {"credits_outstanding": str(_money(due)), "credits_settled": str(_money(settled)), "incidents_with_credits_outstanding": [state.scope.entity_ref for state in states if state.status in ("resolved", "reviewed") and state.ledger.credits_total > 0]}


def incident_summary(states: Sequence[Any]) -> dict[str, Any]:
    """Counts by status and severity, mean time to resolve, the SLA breach rate, and the credit position."""

    resolved = [state for state in states if state.ledger.resolved_at is not None]
    counts = {status: sum(1 for state in states if state.status == status) for status in INCIDENT_STATUSES}
    by_severity = {severity: sum(1 for state in states if state.ledger.severity == severity) for severity in ("sev1", "sev2", "sev3", "sev4")}
    mttr = None if not resolved else str((Decimal(sum(state.ledger.duration_minutes for state in resolved)) / Decimal(len(resolved))).quantize(Decimal("0.1")))
    breaches = sum(1 for state in resolved if state.ledger.sla_breached)
    rate = None if not resolved else str((Decimal(breaches) / Decimal(len(resolved)) * _HUNDRED).quantize(Decimal("0.01")))
    return {"incidents": len(states), "by_status": counts, "by_severity": by_severity, "mean_time_to_resolve_minutes": mttr, "sla_breaches": breaches, "sla_breach_rate_percent": rate, **credit_liability(states)}


INCIDENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": INCIDENT_KIND,
    "golden_loop": INCIDENT_GOLDEN_LOOP,
    "stages": ["detect", "declare", "mitigate", "resolve", "accept_postmortem", "settle_credits", "close"],
    "statuses": list(INCIDENT_STATUSES),
    "events": list(INCIDENT_EVENTS),
    "hops": {"detect": "monitor, status page, or support-triage read with provenance", "declare": "severity from the SaaS plan's SLA rows, the commander, the start, affected accounts on their tiers", "mitigate": "time and action, optionally the release rolled back", "resolve": "recovered-monitor read; duration, SLA verdict, and credits computed", "accept_postmortem": "postmortem digest accepted by a reviewer who is not the commander, inside the window, with action items", "settle_credits": "billing credit-note read matching every credit due exactly", "close": "no credits outstanding"},
    "required_connectors": ["posthog", "stripe", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "severity is one of the sealed SaaS plan's SLA rows and the breach verdict is computed from the resolution time",
        "credits are computed from the policy and the affected tier's monthly price; the caller cannot type a credit",
        "the commander never accepts their own postmortem, and sev1/sev2 postmortems carry action items",
        "an incident with credits due closes only after a billing read shows every credit settled for its exact amount",
        "action items reach the roadmap through roadmap_candidates, never as free text",
    ],
}

__all__ = ["CREDIT_TOOLS", "DEFAULT_CREDIT_RULES", "INCIDENT_EVENTS", "INCIDENT_GOLDEN_LOOP", "INCIDENT_KIND", "INCIDENT_LIFECYCLE", "INCIDENT_MANIFEST", "INCIDENT_STATUSES", "MONITOR_TOOLS", "POSTMORTEM_SCHEMA", "TERMINAL_INCIDENT_STATUSES", "ActionItem", "AffectedAccount", "CreditRow", "CreditRule", "IncidentChainError", "IncidentChainPlan", "IncidentLedger", "IncidentReceipt", "IncidentState", "SlaRow", "advance_incident", "compile_incident_chain", "credit_liability", "credit_receipt", "declaration_receipt", "detection_receipt", "incident_summary", "mitigation_receipt", "open_incident", "postmortem_receipt", "resolution_receipt", "roadmap_candidates", "sla_breached_signal"]
