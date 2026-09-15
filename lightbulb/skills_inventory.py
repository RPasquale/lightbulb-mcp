"""Skills inventory: how deep the company is in every skill, where one person is the only one, which licences lapse next, and who could be trained up.

The match report answers "who for this job".  The inventory answers the
standing question a services business has to keep answering: can we
keep delivering if someone leaves, gets sick, or lets a licence lapse?
From the sealed taxonomy, the worker profiles (with the work order
chain's recorded hours credited as evidence), and optionally the jobs on
the books, ``build_skills_inventory`` seals per skill:

* who holds it and at what effective level, how many are qualified at
  the level the jobs demand (or practitioner when nothing demands it),
  how many are verified by evidence, and the best worker;
* a depth status: absent, single point of failure, thin, or deep against
  the plan's minimum depth;
* every licence that lapses inside the horizon (and any already lapsed),
  with the days left;
* the upskilling candidates closest to the level, with how far short.

Everything is arithmetic on the same standing the match report uses;
nothing here predicts attrition, reads a provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
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
from lightbulb.skills_matching import JobRequirements, SkillsMatchingPlan, SkillsTaxonomy, WorkerProfile, effective_levels, evidence_from_work_orders, with_evidence

SKILLS_INVENTORY_SCHEMA = "lightbulb.skills_inventory.v1"
DEPTH_STATUSES: tuple[str, ...] = ("absent", "single_point_of_failure", "thin", "deep")
DepthStatus = Literal["absent", "single_point_of_failure", "thin", "deep"]
_LEVEL = Decimal("0.01")


class SkillsInventoryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SkillsInventoryError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class LicenceAlert(StrictModel):
    worker_ref: OpaqueRef
    expires_at: str
    days_left: int
    lapsed: bool


class UpskillCandidate(StrictModel):
    worker_ref: OpaqueRef
    kind: ShortText
    effective_level: Decimal
    levels_short: Decimal
    transferred_from: OpaqueRef | None = None

    @field_validator("effective_level", "levels_short", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SkillDepth(StrictModel):
    skill_ref: OpaqueRef
    family: ShortText
    licence: bool
    demanded: bool
    required_level: int = Field(ge=1, le=5)
    holders: int = Field(ge=0)
    qualified: int = Field(ge=0)
    verified: int = Field(ge=0)
    experts: int = Field(ge=0)
    best_worker_ref: OpaqueRef | None = None
    best_level: Decimal
    status: DepthStatus
    licence_alerts: tuple[LicenceAlert, ...] = Field(default_factory=tuple, max_length=200)
    upskill_candidates: tuple[UpskillCandidate, ...] = Field(default_factory=tuple, max_length=5)
    note: ShortText

    @field_validator("licence_alerts", "upskill_candidates", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("best_level", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="best_level")


class SkillsInventory(StrictModel):
    schema_id: str = Field(default=SKILLS_INVENTORY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    plan_digest: Sha256Digest
    taxonomy_digest: Sha256Digest
    minimum_depth: int = Field(ge=1)
    licence_horizon_days: int = Field(ge=0)
    skills: tuple[SkillDepth, ...] = Field(min_length=1, max_length=2000)
    workers: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    licence_alerts: int = Field(ge=0)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    inventory_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("skills", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsInventory":
        if sum(self.by_status.values()) != len(self.skills) or self.licence_alerts != sum(len(skill.licence_alerts) for skill in self.skills):
            raise ValueError("statuses and licence alerts must tie to the skills")
        if not skip_digests(info) and self.inventory_digest != sealed_digest(SkillsInventory, self, "inventory_digest"):
            raise ValueError("inventory_digest must commit the exact inventory")
        return self

    def skill(self, skill_ref: str) -> SkillDepth | None:
        return next((row for row in self.skills if row.skill_ref == skill_ref), None)

    def render(self) -> str:
        lines = [f"**Skills inventory {self.company_ref}** as of {self.as_of[:10]}: {len(self.skills)} skill(s) across {self.workers} worker(s); " + ", ".join(f"{count} {status.replace('_', ' ')}" for status, count in self.by_status.items() if count) + f"; {self.licence_alerts} licence alert(s)."]
        for row in self.skills:
            lines.append(f"- {row.skill_ref} [{row.status}]: {row.note}")
        return "\n".join(lines)


def build_skills_inventory(plan: SkillsMatchingPlan | Mapping[str, Any], *, taxonomy: SkillsTaxonomy | Mapping[str, Any], profiles: Sequence[WorkerProfile | Mapping[str, Any]], jobs: Sequence[JobRequirements | Mapping[str, Any]] = (), work_order_states: Sequence[tuple[Any, Any]] = (), as_of: str, minimum_depth: int = 2, licence_horizon_days: int = 90) -> SkillsInventory:
    """The sealed inventory: depth, single points of failure, licence alerts, and upskilling candidates per skill."""

    parsed_plan = plan if isinstance(plan, SkillsMatchingPlan) else SkillsMatchingPlan.model_validate(detached(plan))
    parsed_taxonomy = taxonomy if isinstance(taxonomy, SkillsTaxonomy) else SkillsTaxonomy.model_validate(detached(taxonomy))
    _require(parsed_taxonomy.company_ref == parsed_plan.company_ref, "SCOPE_MISMATCH", "the taxonomy names another company")
    _require(minimum_depth >= 1 and licence_horizon_days >= 0, "THRESHOLD_INVALID", "minimum_depth is at least 1 and licence_horizon_days at least 0")
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    _require(len({worker.worker_ref for worker in workers}) == len(workers), "WORKER_DUPLICATE", "worker refs must be unique")
    parsed_jobs = [item if isinstance(item, JobRequirements) else JobRequirements.model_validate(detached(item)) for item in jobs]
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    digests: list[str] = []
    if work_order_states:
        from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

        extra = evidence_from_work_orders(work_order_states, parsed_jobs, taxonomy=parsed_taxonomy)
        workers = [with_evidence(worker, extra[worker.worker_ref]) if worker.worker_ref in extra else worker for worker in workers]
        digests.extend(WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)[1].state_digest for plan_doc, state_doc in work_order_states)
    standings = {worker.worker_ref: effective_levels(parsed_taxonomy, parsed_plan, worker, as_of=at) for worker in workers}
    demanded: dict[str, int] = {}
    for job in parsed_jobs:
        for requirement in job.requirements:
            demanded[requirement.skill_ref] = max(demanded.get(requirement.skill_ref, 0), requirement.minimum_level)
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for skill in parsed_taxonomy.skills:
        required = demanded.get(skill.skill_ref, 3)
        holders = [(worker, standings[worker.worker_ref][skill.skill_ref]) for worker in workers if standings[worker.worker_ref][skill.skill_ref].effective_level > 0]
        qualified = [(worker, standing) for worker, standing in holders if standing.effective_level >= Decimal(required)]
        verified = sum(1 for _worker, standing in qualified if standing.verified)
        experts = sum(1 for _worker, standing in holders if standing.effective_level >= Decimal(4))
        best = max(holders, key=lambda item: (item[1].effective_level, -item[0].cost_rate, item[0].worker_ref), default=None)
        if not holders:
            status = "absent"
        elif not qualified:
            status = "thin"
        elif len(qualified) == 1:
            status = "single_point_of_failure"
        elif len(qualified) < minimum_depth:
            status = "thin"
        else:
            status = "deep"
        alerts: list[dict[str, Any]] = []
        if skill.licence:
            for worker in workers:
                claim = worker.claim(skill.skill_ref)
                if claim is None or claim.expires_at is None:
                    continue
                days_left = (parsed(claim.expires_at) - now).days
                if days_left <= licence_horizon_days:
                    alerts.append({"worker_ref": worker.worker_ref, "expires_at": claim.expires_at, "days_left": days_left, "lapsed": days_left <= 0})
            alerts.sort(key=lambda item: (item["days_left"], item["worker_ref"]))
        candidates: list[dict[str, Any]] = []
        if not skill.licence:
            for worker, standing in holders:
                if standing.effective_level < Decimal(required):
                    candidates.append({"worker_ref": worker.worker_ref, "kind": worker.kind, "effective_level": str(standing.effective_level), "levels_short": str((Decimal(required) - standing.effective_level).quantize(_LEVEL, rounding=ROUND_HALF_UP)), "transferred_from": standing.transferred_from})
            candidates.sort(key=lambda item: (Decimal(item["levels_short"]), item["worker_ref"]))
        if status == "absent":
            note = f"nobody holds {skill.skill_ref}" + (f"; jobs demand level {required}" if skill.skill_ref in demanded else "")
        elif status == "single_point_of_failure":
            note = f"only {qualified[0][0].worker_ref} is qualified at level {required} ({qualified[0][1].effective_level})" + (f"; {len(candidates)} candidate(s) to train, nearest {candidates[0]['worker_ref']} short {candidates[0]['levels_short']}" if candidates else "; nobody else holds it at all" if len(holders) == 1 else f"; {len(holders) - 1} other(s) hold it below the level")
        elif status == "thin":
            note = f"{len(qualified)} qualified at level {required} against a minimum depth of {minimum_depth}" + (f"; nearest to train {candidates[0]['worker_ref']} short {candidates[0]['levels_short']}" if candidates else "")
        else:
            note = f"{len(qualified)} qualified at level {required} ({verified} verified, {experts} expert or above); best {best[0].worker_ref} at {best[1].effective_level}"
        if alerts:
            lapsed = [item for item in alerts if item["lapsed"]]
            note += f"; {len(alerts)} licence alert(s)" + (f", {len(lapsed)} lapsed" if lapsed else "")
        rows.append({"skill_ref": skill.skill_ref, "family": skill.family, "licence": skill.licence, "demanded": skill.skill_ref in demanded, "required_level": required, "holders": len(holders), "qualified": len(qualified), "verified": verified, "experts": experts, "best_worker_ref": None if best is None else best[0].worker_ref, "best_level": "0" if best is None else str(best[1].effective_level), "status": status, "licence_alerts": alerts, "upskill_candidates": candidates[:5], "note": note[:300]})
    order = {"absent": 0, "single_point_of_failure": 1, "thin": 2, "deep": 3}
    rows.sort(key=lambda row: (order[row["status"]], not row["demanded"], row["skill_ref"]))
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in DEPTH_STATUSES if any(row["status"] == status for row in rows)}
    recommendations = [f"{row['skill_ref']}: {row['note']}" for row in rows if row["status"] != "deep" or row["licence_alerts"]][:24]
    if not recommendations:
        recommendations.append("every skill is held at depth and no licence lapses inside the horizon")
    payload = {
        "company_ref": parsed_plan.company_ref, "as_of": at, "plan_digest": parsed_plan.plan_digest, "taxonomy_digest": parsed_taxonomy.taxonomy_digest, "minimum_depth": minimum_depth, "licence_horizon_days": licence_horizon_days,
        "skills": rows, "workers": len(workers), "by_status": counts, "licence_alerts": sum(len(row["licence_alerts"]) for row in rows), "recommendations": [item[:300] for item in recommendations],
        "source_digests": [parsed_taxonomy.taxonomy_digest, *[worker.profile_digest for worker in workers], *[job.requirements_digest for job in parsed_jobs], *digests],
    }
    return seal(SkillsInventory, payload, "inventory_digest")


def verify_skills_inventory(value: Any) -> SkillsInventory:
    return value if isinstance(value, SkillsInventory) else SkillsInventory.model_validate(dict(detached(value)))


SKILLS_INVENTORY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "skills_inventory",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["credit_chain_evidence", "compute_standing", "count_depth", "alert_licences", "name_upskill_candidates", "seal_inventory"],
    "statuses": list(DEPTH_STATUSES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "standing is the match report's: claims corroborated or discounted by the work order chain's decayed hours, transfers from adjacent skills, licences that expire",
        "the level a skill is judged at is the highest a job on the books demands, else practitioner",
        "a single point of failure is exactly one qualified worker; a licence alert is a claim that lapses inside the horizon or has lapsed",
        "nothing here predicts attrition, reads a provider, or persists anything",
    ],
}

__all__ = ["DEPTH_STATUSES", "SKILLS_INVENTORY_MANIFEST", "SKILLS_INVENTORY_SCHEMA", "LicenceAlert", "SkillDepth", "SkillsInventory", "SkillsInventoryError", "UpskillCandidate", "build_skills_inventory", "verify_skills_inventory"]
