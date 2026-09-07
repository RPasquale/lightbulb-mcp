"""Staff signed service scope and measure observed effort against adopted rates.

Priced scope establishes a baseline. Independent paper proves that work may
start. Effort records cost, never delivery acceptance or revenue. A changed
baseline consumes an accepted deal revision and an exact authority decision.
"""
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal
from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, EngineScope, LifecycleSpec, OpaqueRef, Rejected, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, require, seal, sealed_digest, skip_digests, stable_digest
from lightbulb.company_operating_system import CompanyOperatingPlan
from lightbulb.deal_desk_engine import ReadEvidence, verify_engagement_budget
from lightbulb.obligation_paper import verify_agreement_in_force

ENGAGEMENT_KIND = "engagement_engine"
ENGAGEMENT_GOLDEN_LOOP = "service.marketing_to_cash_engagement@0.1.0"
ENGAGEMENT_PROFILES = {name: {"profile": name} for name in ("professional_services", "services_delivery")}
ENGAGEMENT_STATUSES = ("opened", "staffed", "delivering", "at_risk", "completed", "cancelled")
ENGAGEMENT_EVENTS = ("open", "staff", "log_effort", "flag_risk", "revise_budget", "complete", "cancel")


class EngagementError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition, code, message):
    if not condition:
        raise EngagementError(code, message)


class EngagementPlan(StrictModel):
    schema_id: Literal["lightbulb.engagement_engine_plan.v1"] = Field(default="lightbulb.engagement_engine_plan.v1", alias="schema")
    company_ref: OpaqueRef
    operating_plan: CompanyOperatingPlan
    currency: CurrencyCode
    profile: Literal["professional_services", "services_delivery"] = "professional_services"
    risk_burn_percent: Decimal = Decimal("80.00")
    max_budget_revisions: int = Field(default=8, ge=1, le=20)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("risk_burn_percent", mode="before")
    @classmethod
    def _money(cls, value):
        result = decimal_value(value, field_name="risk_burn_percent")
        if not 0 < result <= 100:
            raise ValueError("risk threshold is a positive percentage")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo):
        if self.currency != self.operating_plan.blueprint.currency:
            raise ValueError("ENGAGEMENT_SCOPE_MISMATCH: operating and engagement currencies differ")
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self), self, "plan_digest"):
            raise ValueError("plan_digest must commit the engagement policy")
        return self


def compile_engagement_engine(company_ref, *, operating_plan, profile="professional_services", overrides=None):
    op = CompanyOperatingPlan.model_validate(detached(operating_plan))
    _require(profile in ENGAGEMENT_PROFILES, "UNKNOWN_ENGINE_PROFILE", profile)
    changes = dict(overrides or {})
    _require(not set(changes) & {"schema", "plan_digest", "company_ref", "operating_plan", "currency", "profile"}, "PLAN_OVERRIDE_INVALID", "plan identity cannot be overridden")
    return seal(EngagementPlan, {**ENGAGEMENT_PROFILES[profile], **changes, "company_ref": company_ref, "operating_plan": op, "currency": op.blueprint.currency}, "plan_digest")


class EngagementReceipt(StrictModel):
    scope_binding: dict[str, Any] | None = None
    budget: dict[str, Any] | None = None
    agreement_state: dict[str, Any] | None = None
    agreement_plan: dict[str, Any] | None = None
    staffing_read: ReadEvidence | None = None
    effort_read: ReadEvidence | None = None
    authorization_proof: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = ()


class EngagementLedger(StrictModel):
    scope: dict[str, Any] = {}
    company_ref: OpaqueRef | None = None
    customer_ref: OpaqueRef | None = None
    agreement_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    agreement_state: dict[str, Any] | None = None
    agreement_plan: dict[str, Any] | None = None
    baseline_budget_digest: Sha256Digest | None = None
    current_budget_digest: Sha256Digest | None = None
    baseline_value: Decimal = Decimal("0.00")
    baseline_cost: Decimal = Decimal("0.00")
    contract_value: Decimal = Decimal("0.00")
    cost_budget: Decimal = Decimal("0.00")
    configuration_ref: OpaqueRef | None = None
    configuration_revision: int = 0
    budget_revisions: int = 0
    rates: dict[str, dict[str, str]] = {}
    workers: dict[str, str] = {}
    entry_refs: tuple[OpaqueRef, ...] = ()
    hours: Decimal = Decimal("0.00")
    actual_cost: Decimal = Decimal("0.00")
    effort_value: Decimal = Decimal("0.00")
    burn_percent: Decimal = Decimal("0.00")
    risk_reason: ShortText | None = None
    outcome: str = "open"

    @field_validator("baseline_value", "baseline_cost", "contract_value", "cost_budget", "hours", "actual_cost", "effort_value", "burn_percent", mode="before")
    @classmethod
    def _money(cls, value, info: ValidationInfo):
        return decimal_value(value, field_name=str(info.field_name))


class EngagementEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    staffing_changed: Literal[False] = False
    revenue_recognized: Literal[False] = False
    invoice_created: Literal[False] = False


def budget_receipt(budget, agreement_state, *, agreement_plan):
    verified = verify_engagement_budget(budget)
    return {"budget": verified.to_dict(), "agreement_state": detached(agreement_state), "agreement_plan": detached(agreement_plan), "evidence_refs": [f"budget:{verified.budget_digest[:24]}"]}


def _observed(provenance, payload, tool, code):
    try:
        source = ReadEvidence.model_validate({"provenance": detached(provenance), "payload": detached(payload)})
    except ValueError as exc:
        raise EngagementError(code, "retain the exact source observation") from exc
    _require(source.provenance.lane == "host_read" and source.provenance.source_tool == tool, code, "use the named host read")
    return source


def staffing_receipt(provenance, payload):
    source = _observed(provenance, payload, "host.engagement_staffing", "STAFFING_UNEVIDENCED")
    rows = source.payload.get("workers", [])
    _require(bool(rows) and len({r["worker_ref"] for r in rows}) == len(rows) and all(set(r) == {"worker_ref", "role_ref", "available_hours"} and decimal_value(r["available_hours"], field_name="available hours") > 0 for r in rows), "STAFFING_UNEVIDENCED", "staffing requires unique worker assignments and observed capacity")
    return {"staffing_read": source.to_dict()}


def effort_receipt(provenance, payload):
    source = _observed(provenance, payload, "host.approved_engagement_timesheets", "EFFORT_UNEVIDENCED")
    rows = source.payload.get("entries", [])
    _require(bool(rows) and len({r["entry_ref"] for r in rows}) == len(rows) and all(set(r) == {"entry_ref", "worker_ref", "role_ref", "hours", "approved_by_ref", "performed_at"} and decimal_value(r["hours"], field_name="hours") > 0 and r["approved_by_ref"] != r["worker_ref"] and parsed(r["performed_at"]) <= parsed(source.provenance.completed_at) for r in rows), "EFFORT_UNEVIDENCED", "each time entry requires positive hours and independent approval")
    return {"effort_read": source.to_dict()}


def _paper(plan, data, at):
    return verify_agreement_in_force(data["agreement_state"], source_plan=data["agreement_plan"], company_ref=plan.company_ref, currency=plan.currency, at=at, agreement_ref=data["agreement_ref"], expected_scope=data["scope"])


def _rates(budget):
    rates = {}
    for line in budget.lines:
        rate = {"bill_rate": line["configured_unit_price"], "cost_rate": line["cost_rate"]}
        _require(line["cost_rate"] is not None and (line["product_ref"] not in rates or rates[line["product_ref"]] == rate), "BUDGET_UNPRICED", "each role must have one observed cost and billing rate")
        rates[line["product_ref"]] = rate
    return rates


def _apply(plan, next_status, status, data, cmd):
    r, event, at = cmd.receipt, cmd.event, cmd.occurred_at
    try:
        if event == "open":
            require(r.scope_binding is not None and r.budget is not None and r.agreement_state is not None and r.agreement_plan is not None, "BUDGET_UNPRICED", "open from a replayable budget and signed paper")
            scope = r.scope_binding
            require(scope["company_ref"] in {plan.company_ref, "selected"} and scope["currency"] == plan.currency, "ENGAGEMENT_SCOPE_MISMATCH", "scope must match the plan")
            budget = verify_engagement_budget(r.budget, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope)
            require(parsed(budget.source_state["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "BUDGET_FROM_FUTURE", "the priced baseline must exist before work opens")
            paper = verify_agreement_in_force(r.agreement_state, source_plan=r.agreement_plan, company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=scope)
            require(paper.ledger.counterparty_ref == budget.customer_ref and paper.ledger.amount == budget.contract_value and (budget.contract_ref is None or budget.contract_ref == paper.ledger.contract_ref), "AGREEMENT_BUDGET_MISMATCH", "signed customer and total must match the original priced baseline")
            source = budget.source_state["ledger"]
            data.update(scope=scope, company_ref=plan.company_ref, customer_ref=budget.customer_ref, agreement_ref=paper.ledger.agreement_ref, contract_ref=paper.ledger.contract_ref, agreement_state=r.agreement_state, agreement_plan=r.agreement_plan, baseline_budget_digest=budget.budget_digest, current_budget_digest=budget.budget_digest, baseline_value=str(budget.contract_value), baseline_cost=str(budget.cost_budget), contract_value=str(budget.contract_value), cost_budget=str(budget.cost_budget), configuration_ref=source["configuration_ref"], configuration_revision=source["configuration_revision"], rates=_rates(budget))
        elif event == "staff":
            require(r.staffing_read is not None, "STAFFING_UNEVIDENCED", "retain an observed staffing allocation")
            source = r.staffing_read
            staffing_receipt(source.provenance, source.payload)
            require(source.payload.get("scope") == data["scope"] and parsed(source.provenance.completed_at) <= parsed(at), "ENGAGEMENT_SCOPE_MISMATCH", "staffing must belong to this engagement and time")
            require({row["role_ref"] for row in source.payload["workers"]} == set(data["rates"]), "STAFFING_UNEVIDENCED", "staff every role in the adopted scope")
            _paper(plan, data, at)
            data["workers"] = {row["worker_ref"]: row["role_ref"] for row in source.payload["workers"]}
        elif event == "log_effort":
            require(r.effort_read is not None, "EFFORT_UNEVIDENCED", "retain independently approved source time entries")
            source = r.effort_read
            effort_receipt(source.provenance, source.payload)
            require(source.payload.get("scope") == data["scope"] and parsed(source.provenance.completed_at) <= parsed(at), "ENGAGEMENT_SCOPE_MISMATCH", "time belongs to this exact engagement and date")
            _paper(plan, data, at)
            for row in source.payload["entries"]:
                require(row["entry_ref"] not in data["entry_refs"], "EFFORT_ALREADY_RECORDED", "source entries are consumed once")
                require(data["workers"].get(row["worker_ref"]) == row["role_ref"], "WORKER_NOT_STAFFED", "work must come from the staffed worker and role")
                hours = decimal_value(row["hours"], field_name="hours")
                rates = data["rates"][row["role_ref"]]
                data["hours"] = str(Decimal(data["hours"]) + hours)
                data["actual_cost"] = str(Decimal(data["actual_cost"]) + decimal_value(hours * Decimal(rates["cost_rate"]), field_name="effort cost"))
                data["effort_value"] = str(Decimal(data["effort_value"]) + decimal_value(hours * Decimal(rates["bill_rate"]), field_name="effort value"))
                data["entry_refs"].append(row["entry_ref"])
            cost_budget = Decimal(data["cost_budget"])
            data["burn_percent"] = str(decimal_value(Decimal(data["actual_cost"]) / cost_budget * 100, field_name="burn percent")) if cost_budget else "0.00"
        elif event == "flag_risk":
            require(Decimal(data["burn_percent"]) >= plan.risk_burn_percent, "RISK_NOT_OBSERVED", "risk must follow observed budget burn")
            data["risk_reason"] = cmd.reason
        elif event == "revise_budget":
            require(r.budget is not None, "CHANGE_ORDER_UNAPPROVED", "supply an accepted revised deal budget")
            budget = verify_engagement_budget(r.budget, company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["scope"])
            require(parsed(budget.source_state["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "BUDGET_FROM_FUTURE", "the accepted change order must exist before the budget changes")
            source = budget.source_state["ledger"]
            require(budget.source_status in {"accepted", "deposit_held", "executed"} and budget.accepted_amount == budget.contract_value and budget.customer_ref == data["customer_ref"] and source["configuration_ref"] == data["configuration_ref"] and source["configuration_revision"] > data["configuration_revision"], "CHANGE_ORDER_UNAPPROVED", "change order must be the accepted revision of the original customer scope")
            require(data["budget_revisions"] < plan.max_budget_revisions and budget.cost_budget >= Decimal(data["actual_cost"]), "BUDGET_BELOW_ACTUAL", "a revision cannot erase spent cost or exceed the revision bound")
            require(r.authorization_proof is not None, "CHANGE_ORDER_UNAPPROVED", "an authorized owner must approve the exact revised scope", "await_approval")
            from lightbulb.authority_matrix import verify_authorization
            verify_authorization(r.authorization_proof, category="commitment", amount=budget.contract_value, currency=plan.currency, command=cmd, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["scope"]["entity_ref"])
            data.update(current_budget_digest=budget.budget_digest, contract_value=str(budget.contract_value), cost_budget=str(budget.cost_budget), rates=_rates(budget), configuration_revision=source["configuration_revision"], budget_revisions=data["budget_revisions"] + 1, risk_reason=None)
            data["burn_percent"] = str(decimal_value(Decimal(data["actual_cost"]) / budget.cost_budget * 100, field_name="burn percent")) if budget.cost_budget else "0.00"
        elif event in {"complete", "cancel"}:
            data["outcome"] = next_status
    except Rejected:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise Rejected(getattr(exc, "code", "ENGAGEMENT_SOURCE_INVALID"), str(exc), "correct_input") from exc
    return next_status, data


_TABLE = {("new", "open"): "opened", **{(s, "staff"): "at_risk" if s == "at_risk" else "staffed" for s in ("opened", "staffed", "delivering", "at_risk")}, **{(s, "log_effort"): "at_risk" if s == "at_risk" else "delivering" for s in ("staffed", "delivering", "at_risk")}, **{(s, "flag_risk"): "at_risk" for s in ("staffed", "delivering")}, **{(s, "revise_budget"): "delivering" for s in ("staffed", "delivering", "at_risk")}, **{(s, "complete"): "completed" for s in ("delivering", "at_risk")}, **{(s, "cancel"): "cancelled" for s in ("opened", "staffed", "delivering", "at_risk")}}
ENGAGEMENT_LIFECYCLE = LifecycleSpec(entity="engagement", schema_prefix="engagement_engine", statuses=ENGAGEMENT_STATUSES, terminal=("completed", "cancelled"), events=ENGAGEMENT_EVENTS, table=_TABLE, opening_event="open", reason_events=("flag_risk", "cancel"), apply=_apply, ledger_model=EngagementLedger, receipt_model=EngagementReceipt, effect_boundary_model=EngagementEffectBoundary, plan_model=EngagementPlan, max_transitions=100)
EngagementState, EngagementCommand, EngagementTransitionResult = ENGAGEMENT_LIFECYCLE.State, ENGAGEMENT_LIFECYCLE.Command, ENGAGEMENT_LIFECYCLE.TransitionResult


def open_engagement(plan, scope, *, receipt, opened_at, actor_ref):
    bound = EngineScope.model_validate(detached(scope))
    return ENGAGEMENT_LIFECYCLE.open(plan, bound, receipt={**detached(receipt), "scope_binding": bound.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_engagement(plan, state, command):
    return ENGAGEMENT_LIFECYCLE.advance(plan, state, command)


def verify_engagement(state, *, source_plan, company_ref=None, currency=None, expected_scope=None):
    try:
        plan, source = ENGAGEMENT_LIFECYCLE.bind(source_plan, state)
    except ValueError as exc:
        raise EngagementError("ENGAGEMENT_SOURCE_INVALID", "replay the original engagement state with its plan") from exc
    _require(source.ledger.scope == source.scope.to_dict() and (company_ref is None or plan.company_ref == company_ref) and (currency is None or plan.currency == currency), "ENGAGEMENT_SCOPE_MISMATCH", "source plan and engagement scope differ")
    if expected_scope is not None:
        scope = detached(expected_scope)
        _require(all(scope.get(key) == getattr(source.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "ENGAGEMENT_SCOPE_MISMATCH", "engagement belongs to another tenant or project")
    return source


def engagements(state, *, source_plan):
    source = verify_engagement(state, source_plan=source_plan)
    return {"status": source.status, "source_digest": source.state_digest, **source.ledger.to_dict()}


ENGAGEMENT_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": ENGAGEMENT_KIND, "golden_loop": ENGAGEMENT_GOLDEN_LOOP, "statuses": list(ENGAGEMENT_STATUSES), "events": list(ENGAGEMENT_EVENTS), "missing_reads": ["host.engagement_staffing", "host.approved_engagement_timesheets"], "hard_rules": ["signed scope and read-derived rates precede delivery", "observed effort records cost, never customer acceptance or revenue", "an accepted authorized revision preserves all actual burn"]}
__all__ = ["ENGAGEMENT_KIND", "ENGAGEMENT_GOLDEN_LOOP", "ENGAGEMENT_PROFILES", "ENGAGEMENT_MANIFEST", "ENGAGEMENT_STATUSES", "ENGAGEMENT_EVENTS", "ENGAGEMENT_LIFECYCLE", "EngagementError", "EngagementPlan", "EngagementReceipt", "EngagementLedger", "EngagementState", "EngagementCommand", "EngagementTransitionResult", "compile_engagement_engine", "budget_receipt", "staffing_receipt", "effort_receipt", "open_engagement", "advance_engagement", "verify_engagement", "engagements"]
