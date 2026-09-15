"""Services margin: what each engagement, role, and worker earned against what they cost, from the effort the engagement engine recorded.

A services business earns the gap between the rate it bills and the rate
it pays, times the hours it can keep people billable.  This module seals
that gap from the replayed engagements alone:

* per **engagement**: contract value, cost budget, hours, cost at the
  adopted cost rates, value at the adopted bill rates, the value the
  contract actually pays for (capped), margin to date and its percent,
  burn, work beyond the contract (value at risk), and a verdict;
* per **role** (the priced scope line): hours, value, cost, margin, the
  blended bill and cost rates, and the bill rate the target margin needs;
* per **worker**: billable hours in the window from the approved time
  entries, internal hours from the work order chain's timesheets,
  available hours from the profile, utilisation, billable share, and the
  margin their hours produced.

Every number is arithmetic on replayed states; nothing here predicts
utilisation, estimates a rate, reads a provider, or persists anything.
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

SERVICES_MARGIN_PLAN_SCHEMA = "lightbulb.services_margin_plan.v1"
SERVICES_MARGIN_SCHEMA = "lightbulb.services_margin.v1"
ENGAGEMENT_VERDICTS: tuple[str, ...] = ("healthy", "thin", "underwater", "over_contract", "at_risk", "no_effort")
WORKER_VERDICTS: tuple[str, ...] = ("billable", "under_utilised", "over_loaded", "idle", "unprofiled")
EngagementVerdict = Literal["healthy", "thin", "underwater", "over_contract", "at_risk", "no_effort"]
WorkerVerdict = Literal["billable", "under_utilised", "over_loaded", "idle", "unprofiled"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class ServicesMarginError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ServicesMarginError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ServicesMarginPlan(StrictModel):
    schema_id: str = Field(default=SERVICES_MARGIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    target_margin_percent: Decimal = Field(default=Decimal("35"), validate_default=True)
    utilisation_target_percent: Decimal = Field(default=Decimal("75"), validate_default=True)
    over_load_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_margin_percent", "utilisation_target_percent", "over_load_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result >= Decimal("100") and info.field_name == "target_margin_percent":
            raise ValueError("target_margin_percent is below 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ServicesMarginPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ServicesMarginPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_services_margin_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ServicesMarginPlan:
    return seal(ServicesMarginPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class EngagementMargin(StrictModel):
    engagement_ref: OpaqueRef
    customer_ref: OpaqueRef | None = None
    status: ShortText
    contract_value: Decimal
    cost_budget: Decimal
    hours: Decimal
    window_hours: Decimal
    actual_cost: Decimal
    effort_value: Decimal
    recognisable_value: Decimal
    margin: Decimal
    margin_percent: Decimal | None = None
    burn_percent: Decimal
    value_at_risk: Decimal
    verdict: EngagementVerdict
    rationale: ShortText

    @field_validator("contract_value", "cost_budget", "hours", "window_hours", "actual_cost", "effort_value", "recognisable_value", "margin", "margin_percent", "burn_percent", "value_at_risk", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class RoleMargin(StrictModel):
    role_ref: OpaqueRef
    engagements: int = Field(ge=1)
    hours: Decimal
    value: Decimal
    cost: Decimal
    margin: Decimal
    margin_percent: Decimal | None = None
    bill_rate: Decimal
    cost_rate: Decimal
    required_bill_rate: Decimal
    below_target: bool

    @field_validator("hours", "value", "cost", "margin", "margin_percent", "bill_rate", "cost_rate", "required_bill_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class WorkerMargin(StrictModel):
    worker_ref: OpaqueRef
    role_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    billable_hours: Decimal
    internal_hours: Decimal
    available_hours: Decimal | None = None
    utilisation_percent: Decimal | None = None
    billable_percent: Decimal | None = None
    value: Decimal
    cost: Decimal
    margin: Decimal
    verdict: WorkerVerdict
    rationale: ShortText

    @field_validator("role_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("billable_hours", "internal_hours", "available_hours", "utilisation_percent", "billable_percent", "value", "cost", "margin", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ServicesMargin(StrictModel):
    schema_id: str = Field(default=SERVICES_MARGIN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    engagements: tuple[EngagementMargin, ...] = Field(default_factory=tuple, max_length=2000)
    roles: tuple[RoleMargin, ...] = Field(default_factory=tuple, max_length=500)
    workers: tuple[WorkerMargin, ...] = Field(default_factory=tuple, max_length=5000)
    hours: Decimal
    effort_value: Decimal
    recognisable_value: Decimal
    actual_cost: Decimal
    margin: Decimal
    margin_percent: Decimal | None = None
    value_at_risk: Decimal
    by_verdict: dict[str, int] = Field(default_factory=dict)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    margin_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("engagements", "roles", "workers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours", "effort_value", "recognisable_value", "actual_cost", "margin", "margin_percent", "value_at_risk", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ServicesMargin":
        if sum(self.by_verdict.values()) != len(self.engagements):
            raise ValueError("every engagement is counted once by verdict")
        if not skip_digests(info) and self.margin_digest != sealed_digest(ServicesMargin, self, "margin_digest"):
            raise ValueError("margin_digest must commit the exact document")
        return self

    def engagement(self, engagement_ref: str) -> EngagementMargin | None:
        return next((row for row in self.engagements if row.engagement_ref == engagement_ref), None)

    def role(self, role_ref: str) -> RoleMargin | None:
        return next((row for row in self.roles if row.role_ref == role_ref), None)

    def worker(self, worker_ref: str) -> WorkerMargin | None:
        return next((row for row in self.workers if row.worker_ref == worker_ref), None)

    def render(self) -> str:
        margin = "n/a" if self.margin_percent is None else f"{self.margin_percent}%"
        lines = [f"**Services margin {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {len(self.engagements)} engagement(s), {self.hours}h, value {self.recognisable_value} {self.currency} against cost {self.actual_cost}, margin {self.margin} ({margin}); value at risk {self.value_at_risk}."]
        for row in self.engagements:
            lines.append(f"- {row.engagement_ref} [{row.verdict}]: {row.rationale}")
        for row in self.roles:
            lines.append(f"- role {row.role_ref}: {row.hours}h at {row.bill_rate} billed / {row.cost_rate} cost, margin {row.margin_percent if row.margin_percent is not None else 'n/a'}%" + (f"; needs {row.required_bill_rate}/h for the target" if row.below_target else ""))
        for row in self.workers:
            lines.append(f"- {row.worker_ref} [{row.verdict}]: {row.rationale}")
        return "\n".join(lines)


def _effort_entries(state: Any) -> list[dict[str, Any]]:
    """Every approved time entry the engagement consumed, from the log_effort receipts in its replayed history."""

    rows: list[dict[str, Any]] = []
    for item in state.transition_history:
        command = detached(item.command) if not isinstance(item, Mapping) else dict(item["command"])
        if str(command.get("event")) != "log_effort":
            continue
        read = dict(command.get("receipt") or {}).get("effort_read") or {}
        for entry in dict(read).get("payload", {}).get("entries", []):
            rows.append(dict(entry))
    return rows


def build_services_margin(plan: ServicesMarginPlan | Mapping[str, Any], *, engagement_states: Sequence[tuple[Any, Any]], work_order_states: Sequence[tuple[Any, Any]] = (), profiles: Sequence[Mapping[str, Any] | Any] = (), window_start: str, window_end: str, as_of: str) -> ServicesMargin:
    """The sealed services margin over a window from the replayed engagements, with the work order chain's timesheets as internal hours and worker profiles as available hours."""

    from lightbulb.engagement_engine import ENGAGEMENT_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ServicesMarginPlan) else ServicesMarginPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    engagements: list[dict[str, Any]] = []
    roles: dict[str, dict[str, Any]] = {}
    workers: dict[str, dict[str, Any]] = {}
    verdicts: dict[str, int] = {}
    for plan_doc, state_doc in engagement_states:
        eplan, state = ENGAGEMENT_LIFECYCLE.bind(plan_doc, state_doc)
        _require(eplan.company_ref == parsed_plan.company_ref and eplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"engagement {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        rates = {role: {"bill_rate": Decimal(str(rate["bill_rate"])), "cost_rate": Decimal(str(rate["cost_rate"]))} for role, rate in ledger.rates.items()}
        window_hours = Decimal("0")
        for entry in _effort_entries(state):
            performed = parsed(str(entry["performed_at"]))
            if not (parsed(start) <= performed < parsed(end)):
                continue
            hours = Decimal(str(entry["hours"]))
            role_ref = str(entry["role_ref"])
            rate = rates.get(role_ref)
            if rate is None:
                continue
            value, cost = _money(hours * rate["bill_rate"]), _money(hours * rate["cost_rate"])
            window_hours += hours
            role = roles.setdefault(role_ref, {"engagements": set(), "hours": Decimal("0"), "value": Decimal("0"), "cost": Decimal("0")})
            role["engagements"].add(state.scope.entity_ref)
            role["hours"] += hours
            role["value"] += value
            role["cost"] += cost
            worker = workers.setdefault(str(entry["worker_ref"]), {"roles": set(), "billable": Decimal("0"), "internal": Decimal("0"), "value": Decimal("0"), "cost": Decimal("0")})
            worker["roles"].add(role_ref)
            worker["billable"] += hours
            worker["value"] += value
            worker["cost"] += cost
        contract, cost_budget = Decimal(str(ledger.contract_value)), Decimal(str(ledger.cost_budget))
        effort_value, actual_cost = Decimal(str(ledger.effort_value)), Decimal(str(ledger.actual_cost))
        recognisable = min(effort_value, contract)
        margin = _money(recognisable - actual_cost)
        at_risk = _money(max(effort_value - contract, Decimal("0")))
        margin_percent = _pct(margin, recognisable)
        if Decimal(str(ledger.hours)) <= 0:
            verdict, rationale = "no_effort", f"no approved time yet against a {contract} contract"
        elif state.status == "at_risk":
            verdict, rationale = "at_risk", f"flagged at risk: {ledger.risk_reason or 'burn'}; burn {ledger.burn_percent}% of the {cost_budget} cost budget"
        elif at_risk > 0:
            verdict, rationale = "over_contract", f"{effort_value} of work against a {contract} contract: {at_risk} is unpaid unless a change order lands"
        elif margin < 0:
            verdict, rationale = "underwater", f"cost {actual_cost} exceeds the {recognisable} the contract pays for"
        elif margin_percent is not None and margin_percent < parsed_plan.target_margin_percent:
            verdict, rationale = "thin", f"margin {margin_percent}% against the {parsed_plan.target_margin_percent}% target on {recognisable} recognisable"
        else:
            verdict, rationale = "healthy", f"margin {margin_percent}% on {recognisable} recognisable; burn {ledger.burn_percent}%"
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        engagements.append({"engagement_ref": state.scope.entity_ref, "customer_ref": ledger.customer_ref, "status": state.status, "contract_value": str(_money(contract)), "cost_budget": str(_money(cost_budget)), "hours": str(ledger.hours), "window_hours": str(window_hours), "actual_cost": str(_money(actual_cost)), "effort_value": str(_money(effort_value)), "recognisable_value": str(_money(recognisable)), "margin": str(margin), "margin_percent": None if margin_percent is None else str(margin_percent), "burn_percent": str(ledger.burn_percent), "value_at_risk": str(at_risk), "verdict": verdict, "rationale": rationale[:300]})
    if work_order_states:
        from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

        for plan_doc, state_doc in work_order_states:
            wplan, state = WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)
            _require(wplan.company_ref == parsed_plan.company_ref and wplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"work order {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            stamp = state.ledger.completed_at or state.ledger.started_at or state.ledger.raised_at
            if stamp is None or not (parsed(start) <= parsed(stamp) < parsed(end)):
                continue
            for record in state.ledger.labour:
                worker = workers.setdefault(str(record.worker_ref), {"roles": set(), "billable": Decimal("0"), "internal": Decimal("0"), "value": Decimal("0"), "cost": Decimal("0")})
                worker["internal"] += Decimal(str(record.hours))
                worker["cost"] += Decimal(str(record.cost))
    weeks = Decimal((parsed(end) - parsed(start)).total_seconds()) / Decimal(7 * 86400)
    available: dict[str, Decimal] = {}
    for item in profiles:
        raw = dict(detached(item))
        available[str(raw["worker_ref"])] = (Decimal(str(raw.get("hours_per_week", "38"))) * weeks).quantize(_PCT, rounding=ROUND_HALF_UP)
        workers.setdefault(str(raw["worker_ref"]), {"roles": set(), "billable": Decimal("0"), "internal": Decimal("0"), "value": Decimal("0"), "cost": Decimal("0")})
    role_rows: list[dict[str, Any]] = []
    for role_ref, role in sorted(roles.items()):
        bill = (role["value"] / role["hours"]).quantize(_PCT, rounding=ROUND_HALF_UP) if role["hours"] > 0 else Decimal("0")
        cost = (role["cost"] / role["hours"]).quantize(_PCT, rounding=ROUND_HALF_UP) if role["hours"] > 0 else Decimal("0")
        margin = _money(role["value"] - role["cost"])
        percent = _pct(margin, role["value"])
        required = (cost / (Decimal("1") - parsed_plan.target_margin_percent / _HUNDRED)).quantize(_PCT, rounding=ROUND_HALF_UP)
        role_rows.append({"role_ref": role_ref, "engagements": len(role["engagements"]), "hours": str(role["hours"]), "value": str(_money(role["value"])), "cost": str(_money(role["cost"])), "margin": str(margin), "margin_percent": None if percent is None else str(percent), "bill_rate": str(bill), "cost_rate": str(cost), "required_bill_rate": str(required), "below_target": percent is not None and percent < parsed_plan.target_margin_percent})
    worker_rows: list[dict[str, Any]] = []
    for worker_ref, worker in sorted(workers.items()):
        total = (worker["billable"] + worker["internal"]).quantize(_PCT)
        billable_hours, internal_hours = worker["billable"].quantize(_PCT), worker["internal"].quantize(_PCT)
        free = available.get(worker_ref)
        utilisation = None if free is None else _pct(total, free)
        billable_share = _pct(worker["billable"], total)
        margin = _money(worker["value"] - worker["cost"])
        if free is None:
            verdict, rationale = "unprofiled", f"{billable_hours}h billable and {internal_hours}h internal; no profile to size availability"
        elif total <= 0:
            verdict, rationale = "idle", f"no hours recorded against {free}h available"
        elif utilisation is not None and utilisation > parsed_plan.over_load_percent:
            verdict, rationale = "over_loaded", f"{total}h against {free}h available ({utilisation}%)"
        elif utilisation is not None and utilisation < parsed_plan.utilisation_target_percent:
            verdict, rationale = "under_utilised", f"{total}h against {free}h available ({utilisation}%), below the {parsed_plan.utilisation_target_percent}% target; {billable_hours}h billable"
        else:
            verdict, rationale = "billable", f"{billable_hours}h billable of {total}h ({utilisation}% of {free}h), margin {margin}"
        worker_rows.append({"worker_ref": worker_ref, "role_refs": sorted(worker["roles"]), "billable_hours": str(billable_hours), "internal_hours": str(internal_hours), "available_hours": None if free is None else str(free), "utilisation_percent": None if utilisation is None else str(utilisation), "billable_percent": None if billable_share is None else str(billable_share), "value": str(_money(worker["value"])), "cost": str(_money(worker["cost"])), "margin": str(margin), "verdict": verdict, "rationale": rationale[:300]})
    engagements.sort(key=lambda row: (Decimal(row["margin"]), row["engagement_ref"]))
    total_value = _money(sum((Decimal(row["recognisable_value"]) for row in engagements), Decimal("0")))
    total_cost = _money(sum((Decimal(row["actual_cost"]) for row in engagements), Decimal("0")))
    total_margin = _money(total_value - total_cost)
    recommendations = [f"{row['engagement_ref']}: {row['rationale']}" for row in engagements if row["verdict"] in ("over_contract", "underwater", "at_risk", "thin")]
    recommendations += [f"role {row['role_ref']}: bill rate {row['bill_rate']}/h earns {row['margin_percent']}%; the {parsed_plan.target_margin_percent}% target needs {row['required_bill_rate']}/h" for row in role_rows if row["below_target"]]
    recommendations += [f"{row['worker_ref']}: {row['rationale']}" for row in worker_rows if row["verdict"] in ("under_utilised", "over_loaded", "idle")]
    if not recommendations:
        recommendations.append("every engagement, role, and worker is inside the plan's targets")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest,
        "engagements": engagements, "roles": role_rows, "workers": worker_rows, "hours": str(sum((Decimal(row["hours"]) for row in engagements), Decimal("0"))), "effort_value": str(_money(sum((Decimal(row["effort_value"]) for row in engagements), Decimal("0")))),
        "recognisable_value": str(total_value), "actual_cost": str(total_cost), "margin": str(total_margin), "margin_percent": None if _pct(total_margin, total_value) is None else str(_pct(total_margin, total_value)), "value_at_risk": str(_money(sum((Decimal(row["value_at_risk"]) for row in engagements), Decimal("0")))),
        "by_verdict": verdicts, "recommendations": [item[:300] for item in recommendations[:24]], "source_digests": digests,
    }
    return seal(ServicesMargin, payload, "margin_digest")


def verify_services_margin(value: Any) -> ServicesMargin:
    return value if isinstance(value, ServicesMargin) else ServicesMargin.model_validate(dict(detached(value)))


SERVICES_MARGIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "services_margin",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["replay_engagements", "read_approved_effort", "price_at_adopted_rates", "cap_at_contract", "ledger_roles_and_workers", "seal_document"],
    "engagement_verdicts": list(ENGAGEMENT_VERDICTS),
    "worker_verdicts": list(WORKER_VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "value is hours at the bill rate the engagement adopted and cost is hours at its cost rate; the rates come from the priced scope, never typed here",
        "revenue is capped at the contract value; work beyond it is value at risk until a change order lands",
        "internal hours are the work order chain's recorded timesheets and available hours are the worker profile's; utilisation is never estimated",
        "the bill rate a role needs for the target margin is cost rate over one minus the target",
    ],
}

__all__ = ["ENGAGEMENT_VERDICTS", "SERVICES_MARGIN_MANIFEST", "SERVICES_MARGIN_PLAN_SCHEMA", "SERVICES_MARGIN_SCHEMA", "WORKER_VERDICTS", "EngagementMargin", "RoleMargin", "ServicesMargin", "ServicesMarginError", "ServicesMarginPlan", "WorkerMargin", "build_services_margin", "compile_services_margin_plan", "verify_services_margin"]
