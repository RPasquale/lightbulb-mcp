"""Skills development: for every skill the company is short of or exposed on, whether to train a named worker, hire, or contract, with the cost, the lead time, and the payback.

The inventory names the thin and single-point skills and the workers
nearest each one; the capacity plan names the weeks each skill runs
short; the sourcing plan prices the market.  ``build_skills_development``
seals the decision per skill:

* the need: a capacity shortfall (hours short over weeks), a depth risk
  (absent, single point of failure, thin), or a licence lapsing;
* the options: train a named worker (levels short from the inventory,
  hours and weeks per level from the sourcing plan, at the worker's cost
  rate), hire into a role that carries the skill (recruiting cost plus
  the pay over the payback horizon, at the hiring lead), or contract at
  the market rate for the hours short (at the contractor lead);
* the choice: the cheapest option over the payback horizon that is ready
  before the peak week, else the soonest; a depth risk without a
  shortfall trains when a worker is within reach and otherwise hires;
* the schedule: who trains in what, for how many hours, ready by when;
  and the payback in weeks where a training spend avoids contracting.

Nothing here enrols anyone or opens a requisition; the actions are
shaped for the hiring chain and the work order chain.  Nothing reads a
provider or persists anything.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import timedelta
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

SKILLS_DEVELOPMENT_PLAN_SCHEMA = "lightbulb.skills_development_plan.v1"
SKILLS_DEVELOPMENT_SCHEMA = "lightbulb.skills_development.v1"
NEEDS: tuple[str, ...] = ("shortfall", "depth", "licence")
CHOICES: tuple[str, ...] = ("train", "hire", "contract", "renew_licence", "escalate")
Need = Literal["shortfall", "depth", "licence"]
Choice = Literal["train", "hire", "contract", "renew_licence", "escalate"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class SkillsDevelopmentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SkillsDevelopmentError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _iso(value: Any) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class SkillsDevelopmentPlan(StrictModel):
    schema_id: str = Field(default=SKILLS_DEVELOPMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    payback_horizon_weeks: int = Field(default=52, ge=1, le=260)
    max_levels_per_worker: int = Field(default=2, ge=1, le=4)
    assessment_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    licence_renewal_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    train_contractors: bool = False
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessment_cost", "licence_renewal_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsDevelopmentPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(SkillsDevelopmentPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_skills_development_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> SkillsDevelopmentPlan:
    return seal(SkillsDevelopmentPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class DevelopmentOption(StrictModel):
    kind: Choice
    feasible: bool
    subject_ref: OpaqueRef | None = None
    levels: int = Field(default=0, ge=0, le=5)
    hours: Decimal | None = None
    weeks: int | None = None
    ready_at: str | None = None
    cost: Decimal | None = None
    rationale: ShortText

    @field_validator("hours", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class DevelopmentAction(StrictModel):
    skill_ref: OpaqueRef
    family: ShortText
    need: Need
    depth_status: ShortText
    required_level: int = Field(ge=1, le=5)
    qualified: int = Field(ge=0)
    shortfall_hours: Decimal
    weeks_short: int = Field(ge=0)
    peak_week: str | None = None
    chosen: Choice
    subject_ref: OpaqueRef | None = None
    levels: int = Field(default=0, ge=0, le=5)
    hours: Decimal | None = None
    weeks: int | None = None
    ready_at: str | None = None
    cost: Decimal
    avoided_cost: Decimal
    payback_weeks: Decimal | None = None
    options: tuple[DevelopmentOption, ...] = Field(min_length=1, max_length=8)
    rationale: ShortText
    request: dict[str, Any] = Field(default_factory=dict)

    @field_validator("options", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("shortfall_hours", "hours", "cost", "avoided_cost", "payback_weeks", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class TrainingSlot(StrictModel):
    worker_ref: OpaqueRef
    skill_ref: OpaqueRef
    from_level: Decimal
    to_level: int = Field(ge=1, le=5)
    hours: Decimal
    starts_at: str
    ready_at: str
    cost: Decimal

    @field_validator("from_level", "hours", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class SkillsDevelopment(StrictModel):
    schema_id: str = Field(default=SKILLS_DEVELOPMENT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    inventory_digest: Sha256Digest
    capacity_digest: Sha256Digest | None = None
    sourcing_plan_digest: Sha256Digest
    payback_horizon_weeks: int = Field(ge=1)
    actions: tuple[DevelopmentAction, ...] = Field(default_factory=tuple, max_length=2000)
    schedule: tuple[TrainingSlot, ...] = Field(default_factory=tuple, max_length=2000)
    by_need: dict[str, int] = Field(default_factory=dict)
    by_choice: dict[str, int] = Field(default_factory=dict)
    training_cost: Decimal
    hiring_cost: Decimal
    contracting_cost: Decimal
    licence_cost: Decimal
    avoided_cost: Decimal
    workers_in_training: int = Field(ge=0)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    development_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("actions", "schedule", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("training_cost", "hiring_cost", "contracting_cost", "licence_cost", "avoided_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsDevelopment":
        if sum(self.by_choice.values()) != len(self.actions) or sum(self.by_need.values()) != len(self.actions):
            raise ValueError("by_choice and by_need count every action")
        if not skip_digests(info) and self.development_digest != sealed_digest(SkillsDevelopment, self, "development_digest"):
            raise ValueError("development_digest must commit the exact document")
        return self

    def action(self, skill_ref: str) -> DevelopmentAction | None:
        return next((row for row in self.actions if row.skill_ref == skill_ref), None)

    def render(self) -> str:
        lines = [f"**Skills development {self.company_ref}** as of {self.as_of[:10]}: {len(self.actions)} skill(s) to develop; train {self.training_cost} {self.currency}, hire {self.hiring_cost}, contract {self.contracting_cost}; {self.workers_in_training} worker(s) in training."]
        lines.extend(f"- {row.skill_ref}: {row.chosen}" + (f" {row.subject_ref}" if row.subject_ref else "") + f"; {row.rationale}" for row in self.actions)
        return "\n".join(lines)


def _hourly(rate: Decimal, uom: str | None, annual_hours: Decimal) -> Decimal:
    return rate / annual_hours if uom == "year" else rate


def build_skills_development(plan: SkillsDevelopmentPlan | Mapping[str, Any], *, inventory: Mapping[str, Any] | Any, sourcing_plan: Mapping[str, Any] | Any, profiles: Sequence[Mapping[str, Any] | Any], capacity: Mapping[str, Any] | Any | None = None, as_of: str) -> SkillsDevelopment:
    """The sealed development plan: per skill short or exposed, train a named worker, hire, or contract, with the cost, lead, and payback."""

    from lightbulb.labour_sourcing import LabourSourcingPlan
    from lightbulb.skills_inventory import verify_skills_inventory
    from lightbulb.skills_matching import WorkerProfile

    parsed_plan = plan if isinstance(plan, SkillsDevelopmentPlan) else SkillsDevelopmentPlan.model_validate(detached(plan))
    depth = verify_skills_inventory(inventory)
    _require(depth.company_ref == parsed_plan.company_ref, "SOURCE_SCOPE_MISMATCH", "the skills inventory names another company")
    market = sourcing_plan if isinstance(sourcing_plan, LabourSourcingPlan) else LabourSourcingPlan.model_validate(detached(sourcing_plan))
    _require(market.company_ref == parsed_plan.company_ref and market.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the labour sourcing plan names another company or currency")
    workers = [profile if isinstance(profile, WorkerProfile) else WorkerProfile.model_validate(detached(profile)) for profile in profiles]
    for worker in workers:
        _require(worker.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"profile {worker.worker_ref} is priced in another currency")
    by_worker = {worker.worker_ref: worker for worker in workers}
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    digests: list[str] = [depth.inventory_digest]
    per_skill_capacity: dict[str, Any] = {}
    capacity_digest = None
    if capacity is not None:
        from lightbulb.workforce_capacity import verify_workforce_capacity

        load = verify_workforce_capacity(capacity)
        _require(load.company_ref == parsed_plan.company_ref and load.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the workforce capacity names another company or currency")
        _require(load.taxonomy_digest == depth.taxonomy_digest, "TAXONOMY_MISMATCH", "the capacity and the inventory were built on different taxonomies")
        per_skill_capacity = {row.skill_ref: row for row in load.skills}
        capacity_digest = load.capacity_digest
        digests.append(capacity_digest)
    horizon = parsed_plan.payback_horizon_weeks
    hours_per_level = Decimal(str(market.upskill_hours_per_level))
    rows: list[dict[str, Any]] = []
    schedule: list[dict[str, Any]] = []
    totals = {"train": Decimal("0"), "hire": Decimal("0"), "contract": Decimal("0"), "renew_licence": Decimal("0"), "escalate": Decimal("0")}
    avoided_total = Decimal("0")
    trainees: set[str] = set()
    busy: dict[str, Any] = {}

    for skill in depth.skills:
        cap = per_skill_capacity.get(skill.skill_ref)
        shortfall = Decimal("0") if cap is None else Decimal(str(cap.shortfall_hours))
        weeks_short = 0 if cap is None else int(cap.weeks_short)
        peak = None if cap is None else cap.peak_shortfall_week
        lapsed = [alert for alert in skill.licence_alerts if alert.lapsed]
        expiring = [alert for alert in skill.licence_alerts if not alert.lapsed]
        if shortfall > 0:
            need = "shortfall"
        elif skill.status in ("absent", "single_point_of_failure", "thin") and skill.demanded:
            need = "depth"
        elif skill.licence and (lapsed or expiring):
            need = "licence"
        else:
            continue
        # the hours the need represents: the measured shortfall, else the demand the capacity plan saw for the skill
        need_hours = _money(shortfall) if shortfall > 0 else (_money(cap.demand_hours) if cap is not None else Decimal("0"))
        market_rate = market.market_rates.get(skill.skill_ref)
        options: list[dict[str, Any]] = []
        # train: the nearest workers the inventory names, at their own cost rate for the hours the sourcing plan says a level takes
        for candidate in skill.upskill_candidates:
            worker = by_worker.get(candidate.worker_ref)
            levels = max(1, math.ceil(Decimal(str(candidate.levels_short))))
            if worker is None:
                options.append({"kind": "train", "feasible": False, "subject_ref": candidate.worker_ref, "levels": levels, "rationale": f"{candidate.worker_ref} has no priced profile"})
                continue
            if worker.kind != "employee" and not parsed_plan.train_contractors:
                options.append({"kind": "train", "feasible": False, "subject_ref": worker.worker_ref, "levels": levels, "rationale": f"{worker.worker_ref} is a {worker.kind}; the plan trains employees only"})
                continue
            if levels > parsed_plan.max_levels_per_worker:
                options.append({"kind": "train", "feasible": False, "subject_ref": worker.worker_ref, "levels": levels, "rationale": f"{worker.worker_ref} is {candidate.levels_short} level(s) short, past the {parsed_plan.max_levels_per_worker}-level limit"})
                continue
            hours = _money(hours_per_level * levels)
            weeks = int(market.upskill_weeks_per_level) * levels
            start = busy.get(worker.worker_ref, now)
            ready = start + timedelta(weeks=weeks)
            cost = _money(hours * Decimal(str(worker.cost_rate)) + parsed_plan.assessment_cost)
            options.append({"kind": "train", "feasible": True, "subject_ref": worker.worker_ref, "levels": levels, "hours": str(hours), "weeks": weeks, "ready_at": _iso(ready), "cost": str(cost), "rationale": f"{worker.worker_ref} from {candidate.effective_level} to level {skill.required_level}: {hours}h over {weeks} week(s) at {worker.cost_rate}/h, ready {ready.date().isoformat()}"})
        # hire: a role the sourcing plan defines that carries the skill at the required level
        for role in market.roles:
            level = int(role.skills.get(skill.skill_ref, 0))
            if level < skill.required_level:
                continue
            if role.pay_rate is None:
                options.append({"kind": "hire", "feasible": False, "subject_ref": role.role_ref, "rationale": f"{role.role_ref} carries {skill.skill_ref} at level {level} but has no pay rate"})
                continue
            hourly = _hourly(Decimal(str(role.pay_rate)), role.pay_rate_uom, Decimal(str(market.annual_hours)))
            pay_hours = _money(Decimal(str(role.hours_per_week)) * Decimal(horizon))
            cost = _money(Decimal(str(market.recruiting_cost)) + hourly * pay_hours)
            ready = now + timedelta(weeks=int(market.hiring_lead_weeks))
            options.append({"kind": "hire", "feasible": True, "subject_ref": role.role_ref, "weeks": int(market.hiring_lead_weeks), "ready_at": _iso(ready), "cost": str(cost), "rationale": f"hire {role.role_ref} at {_money(hourly)}/h: {pay_hours}h of pay over the {horizon}-week horizon plus {_money(market.recruiting_cost)} recruiting, ready {ready.date().isoformat()}"})
            break
        # contract: the market rate for the hours short, at the contractor lead
        if market_rate is None:
            options.append({"kind": "contract", "feasible": False, "rationale": f"no market rate for {skill.skill_ref} in the sourcing plan"})
        elif need_hours <= 0:
            options.append({"kind": "contract", "feasible": False, "rationale": "no hours short to contract"})
        else:
            cost = _money(Decimal(str(market_rate)) * need_hours)
            ready = now + timedelta(weeks=int(market.contractor_lead_weeks))
            options.append({"kind": "contract", "feasible": True, "weeks": int(market.contractor_lead_weeks), "ready_at": _iso(ready), "cost": str(cost), "rationale": f"contract {need_hours}h at {_money(market_rate)}/h, ready {ready.date().isoformat()}"})
        if need == "licence":
            for alert in [*lapsed, *expiring]:
                options.append({"kind": "renew_licence", "feasible": True, "subject_ref": alert.worker_ref, "weeks": 0, "ready_at": at, "cost": str(_money(parsed_plan.licence_renewal_cost)), "rationale": f"{alert.worker_ref}'s licence " + ("lapsed" if alert.lapsed else f"expires in {alert.days_left} day(s)") + f" ({alert.expires_at[:10]})"})
        feasible = [option for option in options if option["feasible"]]
        contract_cost = next((Decimal(option["cost"]) for option in feasible if option["kind"] == "contract"), None)
        if need == "licence":
            chosen = next(option for option in feasible if option["kind"] == "renew_licence")
            rationale = f"licence risk: {chosen['rationale']}"
        elif not feasible:
            chosen = {"kind": "escalate", "feasible": True, "cost": "0.00", "rationale": "no feasible route"}
            reasons = "; ".join(option["rationale"] for option in options) or "no worker within reach, no role carries the skill, and no market rate is known"
            options.append(chosen)
            rationale = f"{need}: no feasible route; {reasons}"
        elif need == "shortfall":
            deadline = None if peak is None else parsed(peak)
            in_time = [option for option in feasible if option["kind"] != "renew_licence" and (deadline is None or option.get("ready_at") is None or parsed(option["ready_at"]) <= deadline)]
            pool = in_time or [option for option in feasible if option["kind"] != "renew_licence"]
            chosen = min(pool, key=lambda option: (Decimal(option["cost"]), option.get("weeks") or 0))
            rationale = f"short {shortfall}h over {weeks_short} week(s)" + (f" (peak week {peak[:10]})" if peak else "") + f": {chosen['kind']} is the cheapest route " + ("ready in time" if in_time else "though none is ready before the peak") + f" at {chosen['cost']}"
        else:
            builders = [option for option in feasible if option["kind"] in ("train", "hire")]
            if builders:
                chosen = min(builders, key=lambda option: (Decimal(option["cost"]), 0 if option["kind"] == "train" else 1))
                rationale = f"{skill.status.replace('_', ' ')}: {skill.qualified} qualified at level {skill.required_level}; {chosen['kind']} builds depth for {chosen['cost']}"
            else:
                chosen = {"kind": "escalate", "feasible": True, "cost": "0.00", "rationale": "no worker within reach and no role carries the skill"}
                options.append(chosen)
                rationale = f"{skill.status.replace('_', ' ')}: {skill.qualified} qualified at level {skill.required_level}; no worker within reach and no role carries the skill" + (f"; contracting covers the {need_hours}h of demand for {contract_cost} but builds no depth" if contract_cost is not None else "")
        cost = Decimal(chosen.get("cost") or "0")
        avoided = Decimal("0") if chosen["kind"] != "train" or contract_cost is None else _money(max(contract_cost - cost, Decimal("0")))
        payback = None
        if chosen["kind"] == "train" and need == "shortfall" and market_rate is not None and shortfall > 0:
            weekly = Decimal(str(market_rate)) * shortfall / Decimal(max(weeks_short, 1))
            payback = _pct(cost / weekly) if weekly > 0 else None
        if chosen["kind"] == "train":
            worker = by_worker[chosen["subject_ref"]]
            start = busy.get(worker.worker_ref, now)
            schedule.append({"worker_ref": worker.worker_ref, "skill_ref": skill.skill_ref, "from_level": str(next(Decimal(str(candidate.effective_level)) for candidate in skill.upskill_candidates if candidate.worker_ref == worker.worker_ref)), "to_level": skill.required_level, "hours": chosen["hours"], "starts_at": _iso(start), "ready_at": chosen["ready_at"], "cost": chosen["cost"]})
            busy[worker.worker_ref] = parsed(chosen["ready_at"])
            trainees.add(worker.worker_ref)
        totals[chosen["kind"]] += cost
        avoided_total += avoided
        request: dict[str, Any] = {}
        if chosen["kind"] == "hire":
            request = {"chain": "hiring_chain", "role_ref": chosen["subject_ref"], "skill_ref": skill.skill_ref, "minimum_level": skill.required_level}
        elif chosen["kind"] == "train":
            request = {"chain": "work_order_chain", "kind": "training", "worker_ref": chosen["subject_ref"], "skill_ref": skill.skill_ref, "to_level": skill.required_level, "hours": chosen["hours"]}
        elif chosen["kind"] == "contract":
            request = {"chain": "contractor_chain", "skill_ref": skill.skill_ref, "hours": str(need_hours), "minimum_level": skill.required_level}
        rows.append({"skill_ref": skill.skill_ref, "family": skill.family, "need": need, "depth_status": skill.status, "required_level": skill.required_level, "qualified": skill.qualified, "shortfall_hours": str(_money(shortfall)), "weeks_short": weeks_short, "peak_week": peak, "chosen": chosen["kind"], "subject_ref": chosen.get("subject_ref"), "levels": int(chosen.get("levels") or 0), "hours": chosen.get("hours"), "weeks": chosen.get("weeks"), "ready_at": chosen.get("ready_at"), "cost": str(_money(cost)), "avoided_cost": str(avoided), "payback_weeks": None if payback is None else str(payback), "options": options, "rationale": rationale[:300], "request": request})
    order = {"shortfall": 0, "licence": 1, "depth": 2}
    rows.sort(key=lambda row: (order[row["need"]], -Decimal(row["shortfall_hours"]), row["skill_ref"]))
    by_need = {need: sum(1 for row in rows if row["need"] == need) for need in NEEDS if any(row["need"] == need for row in rows)}
    by_choice = {kind: sum(1 for row in rows if row["chosen"] == kind) for kind in CHOICES if any(row["chosen"] == kind for row in rows)}
    recommendations = [f"{row['skill_ref']}: {row['chosen']}" + (f" {row['subject_ref']}" if row["subject_ref"] else "") + f" for {row['cost']}" + (f", avoiding {row['avoided_cost']} of contracting (payback {row['payback_weeks']} week(s))" if Decimal(row["avoided_cost"]) > 0 else "") + f"; {row['rationale']}" for row in rows][:24]
    if not recommendations:
        recommendations.append("no skill is short, thin, or lapsing; nothing to develop")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "inventory_digest": depth.inventory_digest, "capacity_digest": capacity_digest, "sourcing_plan_digest": market.plan_digest, "payback_horizon_weeks": horizon, "actions": rows, "schedule": schedule, "by_need": by_need, "by_choice": by_choice, "training_cost": str(_money(totals["train"])), "hiring_cost": str(_money(totals["hire"])), "contracting_cost": str(_money(totals["contract"])), "licence_cost": str(_money(totals["renew_licence"])), "avoided_cost": str(_money(avoided_total)), "workers_in_training": len(trainees), "recommendations": [row[:300] for row in recommendations], "source_digests": digests}
    return seal(SkillsDevelopment, payload, "development_digest")


def verify_skills_development(value: Any) -> SkillsDevelopment:
    return value if isinstance(value, SkillsDevelopment) else SkillsDevelopment.model_validate(dict(detached(value)))


SKILLS_DEVELOPMENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "skills_development",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["verify_inventory_and_capacity", "name_the_need_per_skill", "price_train_hire_contract", "choose_in_time_then_cheapest", "schedule_training", "seal_document"],
    "needs": list(NEEDS),
    "choices": list(CHOICES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "training is priced at the named worker's own cost rate for the hours the sourcing plan says a level takes; nobody is trained past the plan's level limit",
        "a shortfall takes the cheapest option ready before the peak week; a depth risk trains when a worker is within reach and otherwise hires",
        "nothing here enrols anyone, opens a requisition, reads a provider, or persists anything",
    ],
}

__all__ = ["CHOICES", "NEEDS", "SKILLS_DEVELOPMENT_MANIFEST", "SKILLS_DEVELOPMENT_PLAN_SCHEMA", "SKILLS_DEVELOPMENT_SCHEMA", "DevelopmentAction", "DevelopmentOption", "SkillsDevelopment", "SkillsDevelopmentError", "SkillsDevelopmentPlan", "TrainingSlot", "build_skills_development", "compile_skills_development_plan", "verify_skills_development"]
