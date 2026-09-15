"""Skills matching: which worker fits which job, proven from the work the chains recorded.

A services company earns by putting the right skill on the right task.
This module makes that decision deterministic and explainable:

* a sealed **taxonomy** names each skill, its family, the five proficiency
  levels it is judged on (aware, working, practitioner, expert, master),
  which skills transfer to it and how much, whether it is a licence that
  expires, and how many hours of evidence corroborate each level;
* a sealed **worker profile** carries what a worker claims (and who said
  so), the evidence behind it, the hours they can give a week, when they
  are free, and what an hour of them costs;
* a sealed **job requirement** names the skills a job needs at what level,
  which are mandatory, the hours, the window, the headcount, and the
  budget;
* **evidence** comes from the work order chain: every timesheet hour and
  contractor unit booked to a job credits the skills that job required,
  decayed by a half-life so old work counts less.

``match_job`` scores every worker against a job on four components with
sealed weights: proficiency (effective level against the minimum, where a
claim the evidence does not corroborate is discounted and an adjacent
skill transfers at the taxonomy's weight), evidence (how much of the
requirement the recorded hours prove), availability (hours free in the
window against the hours needed), and cost (against the budget).  A
mandatory skill more than the plan's stretch below the minimum, an expired
licence, too little availability, or a cost too far over budget
disqualifies, with the reason.  The report ranks the candidates, assembles
a team for the headcount, names every gap no one covers, and each verdict
carries the numbers behind it.  Nothing here learns, predicts, reads a
provider, or persists anything.
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

SKILLS_TAXONOMY_SCHEMA = "lightbulb.skills_taxonomy.v1"
WORKER_PROFILE_SCHEMA = "lightbulb.worker_profile.v1"
JOB_REQUIREMENTS_SCHEMA = "lightbulb.job_requirements.v1"
SKILLS_MATCHING_PLAN_SCHEMA = "lightbulb.skills_matching_plan.v1"
SKILLS_MATCH_REPORT_SCHEMA = "lightbulb.skills_match_report.v1"
PROFICIENCY_LEVELS: dict[int, str] = {1: "aware", 2: "working", 3: "practitioner", 4: "expert", 5: "master"}
WORKER_KINDS: tuple[str, ...] = ("employee", "contractor", "candidate", "agency")
EVIDENCE_KINDS: tuple[str, ...] = ("timesheet", "contractor_work", "assessment", "licence")
CLAIM_SOURCES: tuple[str, ...] = ("self", "manager", "assessment", "licence")
REQUIREMENT_STATUSES: tuple[str, ...] = ("met", "stretch", "short", "missing", "licence_expired")
VERDICTS: tuple[str, ...] = ("fit", "stretch", "unavailable", "over_budget", "disqualified")
JOB_KINDS: tuple[str, ...] = ("work_order", "engagement", "task", "role")
WorkerKind = Literal["employee", "contractor", "candidate", "agency"]
EvidenceKind = Literal["timesheet", "contractor_work", "assessment", "licence"]
ClaimSource = Literal["self", "manager", "assessment", "licence"]
RequirementStatus = Literal["met", "stretch", "short", "missing", "licence_expired"]
Verdict = Literal["fit", "stretch", "unavailable", "over_budget", "disqualified"]
JobKind = Literal["work_order", "engagement", "task", "role"]
_LEVEL = Decimal("0.01")
_HOURS = Decimal("0.01")
_SCORE = Decimal("0.01")
_HUNDRED = Decimal("100")
_DAY_HOURS = Decimal("24")


class SkillsMatchingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SkillsMatchingError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _level(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_LEVEL, rounding=ROUND_HALF_UP)


def _score(value: Any) -> Decimal:
    return max(Decimal("0"), min(Decimal("1"), Decimal(str(value)))).quantize(_SCORE, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


# --------------------------------------------------------------------------- #
# Taxonomy
# --------------------------------------------------------------------------- #


class SkillDefinition(StrictModel):
    skill_ref: OpaqueRef
    name: ShortText
    family: ShortText
    transfers_from: dict[str, Decimal] = Field(default_factory=dict)
    licence: bool = False
    decay_half_life_days: int = Field(default=540, ge=30, le=3650)
    evidence_hours_per_level: tuple[Decimal, Decimal, Decimal, Decimal, Decimal] = Field(default=(Decimal("1"), Decimal("40"), Decimal("200"), Decimal("800"), Decimal("2000")), validate_default=True)

    @field_validator("evidence_hours_per_level", mode="before")
    @classmethod
    def _thresholds(cls, value: object) -> object:
        items = tuple(decimal_value(item, field_name="evidence_hours_per_level") for item in value) if isinstance(value, (list, tuple)) else value
        if isinstance(items, tuple) and any(items[index] > items[index + 1] for index in range(len(items) - 1)):
            raise ValueError("evidence_hours_per_level must not decrease from level to level")
        return items

    @field_validator("transfers_from", mode="before")
    @classmethod
    def _weights(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        out: dict[str, Decimal] = {}
        for key, weight in value.items():
            rate = decimal_value(weight, field_name=f"transfers_from[{key}]")
            if not Decimal("0") < rate < Decimal("1"):
                raise ValueError("a transfer weight is strictly between 0 and 1")
            out[str(key)] = rate
        return out


class SkillsTaxonomy(StrictModel):
    schema_id: str = Field(default=SKILLS_TAXONOMY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    skills: tuple[SkillDefinition, ...] = Field(min_length=1, max_length=2000)
    taxonomy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("skills", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsTaxonomy":
        refs = [skill.skill_ref for skill in self.skills]
        if len(set(refs)) != len(refs):
            raise ValueError("skill refs must be unique")
        known = set(refs)
        for skill in self.skills:
            for source in skill.transfers_from:
                if source not in known or source == skill.skill_ref:
                    raise ValueError(f"{skill.skill_ref} transfers from an unknown skill or itself")
        if not skip_digests(info) and self.taxonomy_digest != sealed_digest(SkillsTaxonomy, self, "taxonomy_digest"):
            raise ValueError("taxonomy_digest must commit the exact taxonomy")
        return self

    def skill(self, skill_ref: str) -> SkillDefinition | None:
        return next((skill for skill in self.skills if skill.skill_ref == skill_ref), None)


def compile_skills_taxonomy(company_ref: str, *, skills: Sequence[Mapping[str, Any]]) -> SkillsTaxonomy:
    return seal(SkillsTaxonomy, {"company_ref": company_ref, "skills": [dict(detached(skill)) for skill in skills]}, "taxonomy_digest")


# --------------------------------------------------------------------------- #
# Workers and jobs
# --------------------------------------------------------------------------- #


class SkillClaim(StrictModel):
    skill_ref: OpaqueRef
    level: int = Field(ge=1, le=5)
    declared_by: ClaimSource = "self"
    declared_at: str
    expires_at: str | None = None

    @field_validator("declared_at", "expires_at", mode="before")
    @classmethod
    def _times(cls, value: Any, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(str(value), field_name=str(info.field_name))


class SkillEvidence(StrictModel):
    skill_ref: OpaqueRef
    kind: EvidenceKind
    hours: Decimal
    at: str
    source_ref: ShortText
    source_digest: Sha256Digest

    @field_validator("hours", mode="before")
    @classmethod
    def _hours(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="hours")
        if result <= 0:
            raise ValueError("evidence hours are positive")
        return result

    @field_validator("at", mode="before")
    @classmethod
    def _time(cls, value: Any) -> str:
        return timestamp(str(value), field_name="at")


class WorkerProfile(StrictModel):
    schema_id: str = Field(default=WORKER_PROFILE_SCHEMA, alias="schema")
    worker_ref: OpaqueRef
    kind: WorkerKind
    role_ref: OpaqueRef | None = None
    claims: tuple[SkillClaim, ...] = Field(default_factory=tuple, max_length=200)
    evidence: tuple[SkillEvidence, ...] = Field(default_factory=tuple, max_length=5000)
    hours_per_week: Decimal = Field(default=Decimal("38"), validate_default=True)
    available_from: str | None = None
    available_until: str | None = None
    cost_rate: Decimal
    currency: CurrencyCode
    location_ref: OpaqueRef | None = None
    profile_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("claims", "evidence", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_per_week", "cost_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("available_from", "available_until", mode="before")
    @classmethod
    def _times(cls, value: Any, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(str(value), field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkerProfile":
        refs = [claim.skill_ref for claim in self.claims]
        if len(set(refs)) != len(refs):
            raise ValueError("one claim per skill")
        if self.hours_per_week > Decimal("84"):
            raise ValueError("hours_per_week is at most 84")
        if self.available_from and self.available_until and parsed(self.available_until) <= parsed(self.available_from):
            raise ValueError("available_until must follow available_from")
        if not skip_digests(info) and self.profile_digest != sealed_digest(WorkerProfile, self, "profile_digest"):
            raise ValueError("profile_digest must commit the exact profile")
        return self

    def claim(self, skill_ref: str) -> SkillClaim | None:
        return next((claim for claim in self.claims if claim.skill_ref == skill_ref), None)


def compile_worker_profile(worker_ref: str, *, kind: str, cost_rate: Any, currency: str, claims: Sequence[Mapping[str, Any]] = (), evidence: Sequence[Mapping[str, Any]] = (), **fields: Any) -> WorkerProfile:
    raw: dict[str, Any] = {"worker_ref": worker_ref, "kind": kind, "cost_rate": str(decimal_value(cost_rate, field_name="cost_rate")), "currency": str(currency).upper(), "claims": [dict(detached(item)) for item in claims], "evidence": [dict(detached(item)) for item in evidence], **fields}
    return seal(WorkerProfile, raw, "profile_digest")


def with_evidence(profile: WorkerProfile | Mapping[str, Any], evidence: Sequence[Mapping[str, Any] | SkillEvidence]) -> WorkerProfile:
    """The same profile re-sealed with more evidence appended; an entry already present (same source digest and skill) is not duplicated."""

    current = profile if isinstance(profile, WorkerProfile) else WorkerProfile.model_validate(detached(profile))
    rows = [item.to_dict() for item in current.evidence]
    seen = {(row["source_digest"], row["skill_ref"]) for row in rows}
    for item in evidence:
        row = dict(detached(item))
        key = (str(row.get("source_digest")), str(row.get("skill_ref")))
        if key not in seen:
            rows.append(row)
            seen.add(key)
    raw = {key: value for key, value in current.to_dict().items() if key not in {"profile_digest", "evidence"}}
    return seal(WorkerProfile, {**raw, "evidence": rows}, "profile_digest")


class SkillRequirement(StrictModel):
    skill_ref: OpaqueRef
    minimum_level: int = Field(ge=1, le=5)
    weight: Decimal = Field(default=Decimal("1"), validate_default=True)
    mandatory: bool = True

    @field_validator("weight", mode="before")
    @classmethod
    def _weight(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="weight")
        if result <= 0:
            raise ValueError("a requirement weight is positive")
        return result


class JobRequirements(StrictModel):
    schema_id: str = Field(default=JOB_REQUIREMENTS_SCHEMA, alias="schema")
    job_ref: OpaqueRef
    title: ShortText
    kind: JobKind = "task"
    source_ref: OpaqueRef | None = None
    requirements: tuple[SkillRequirement, ...] = Field(min_length=1, max_length=50)
    hours_required: Decimal
    headcount: int = Field(default=1, ge=1, le=500)
    starts_at: str
    due_at: str
    budget: Decimal | None = None
    currency: CurrencyCode
    location_ref: OpaqueRef | None = None
    requirements_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("requirements", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_required", "budget", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("starts_at", "due_at", mode="before")
    @classmethod
    def _times(cls, value: Any, info: ValidationInfo) -> str:
        return timestamp(str(value), field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobRequirements":
        refs = [item.skill_ref for item in self.requirements]
        if len(set(refs)) != len(refs):
            raise ValueError("one requirement per skill")
        if self.hours_required <= 0:
            raise ValueError("hours_required is positive")
        if parsed(self.due_at) <= parsed(self.starts_at):
            raise ValueError("due_at must follow starts_at")
        if not skip_digests(info) and self.requirements_digest != sealed_digest(JobRequirements, self, "requirements_digest"):
            raise ValueError("requirements_digest must commit the exact requirements")
        return self

    @property
    def hours_per_head(self) -> Decimal:
        return (self.hours_required / Decimal(self.headcount)).quantize(_HOURS, rounding=ROUND_HALF_UP)


def compile_job_requirements(job_ref: str, *, title: str, requirements: Sequence[Mapping[str, Any]], hours_required: Any, starts_at: str, due_at: str, currency: str, **fields: Any) -> JobRequirements:
    raw: dict[str, Any] = {"job_ref": job_ref, "title": title, "requirements": [dict(detached(item)) for item in requirements], "hours_required": str(decimal_value(hours_required, field_name="hours_required")), "starts_at": starts_at, "due_at": due_at, "currency": str(currency).upper(), **fields}
    return seal(JobRequirements, raw, "requirements_digest")


# --------------------------------------------------------------------------- #
# The plan: the weights and fences every match is judged by
# --------------------------------------------------------------------------- #


class SkillsMatchingPlan(StrictModel):
    schema_id: str = Field(default=SKILLS_MATCHING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    proficiency_weight: Decimal = Field(default=Decimal("0.45"), validate_default=True)
    evidence_weight: Decimal = Field(default=Decimal("0.20"), validate_default=True)
    availability_weight: Decimal = Field(default=Decimal("0.20"), validate_default=True)
    cost_weight: Decimal = Field(default=Decimal("0.15"), validate_default=True)
    unverified_claim_discount: Decimal = Field(default=Decimal("0.75"), validate_default=True)
    stretch_levels: Decimal = Field(default=Decimal("0.5"), validate_default=True)
    fit_threshold: Decimal = Field(default=Decimal("0.6"), validate_default=True)
    minimum_availability_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    budget_tolerance_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    max_candidates: int = Field(default=10, ge=1, le=100)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("proficiency_weight", "evidence_weight", "availability_weight", "cost_weight", "unverified_claim_discount", "stretch_levels", "fit_threshold", "minimum_availability_percent", "budget_tolerance_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsMatchingPlan":
        if self.proficiency_weight + self.evidence_weight + self.availability_weight + self.cost_weight != Decimal("1"):
            raise ValueError("the four component weights sum to 1")
        if not Decimal("0") < self.unverified_claim_discount <= Decimal("1") or self.stretch_levels > Decimal("2") or not Decimal("0") < self.fit_threshold <= Decimal("1"):
            raise ValueError("unverified_claim_discount is in (0, 1], stretch_levels at most 2, fit_threshold in (0, 1]")
        if not skip_digests(info) and self.plan_digest != sealed_digest(SkillsMatchingPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_skills_matching_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> SkillsMatchingPlan:
    return seal(SkillsMatchingPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


# --------------------------------------------------------------------------- #
# Evidence from the chains
# --------------------------------------------------------------------------- #


def evidence_from_work_orders(work_order_states: Sequence[tuple[Any, Any]], jobs: Sequence[JobRequirements | Mapping[str, Any]], *, taxonomy: SkillsTaxonomy) -> dict[str, list[dict[str, Any]]]:
    """Every timesheet hour and contractor unit a replayed work order recorded, credited to the skills the matching job required, keyed by worker."""

    from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

    by_source: dict[str, JobRequirements] = {}
    for item in jobs:
        job = item if isinstance(item, JobRequirements) else JobRequirements.model_validate(detached(item))
        by_source[job.source_ref or job.job_ref] = job
    out: dict[str, list[dict[str, Any]]] = {}
    for plan_doc, state_doc in work_order_states:
        _plan, state = WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)
        job = by_source.get(str(state.scope.entity_ref))
        if job is None:
            continue
        ledger = state.ledger
        at = ledger.completed_at or ledger.started_at or ledger.approved_at or ledger.raised_at
        if at is None:
            continue
        skills = [item.skill_ref for item in job.requirements if taxonomy.skill(item.skill_ref) is not None]
        for record in ledger.labour:
            for skill_ref in skills:
                out.setdefault(str(record.worker_ref), []).append({"skill_ref": skill_ref, "kind": "timesheet", "hours": str(record.hours), "at": at, "source_ref": f"{state.scope.entity_ref}:{record.period_ref}", "source_digest": record.timesheet_digest})
        for record in ledger.contractor_labour:
            for skill_ref in skills:
                out.setdefault(str(record.contractor_ref), []).append({"skill_ref": skill_ref, "kind": "contractor_work", "hours": str(record.units), "at": at, "source_ref": f"{state.scope.entity_ref}:{record.work_ref}", "source_digest": record.contractor_digest})
    return out


# --------------------------------------------------------------------------- #
# Standing: what a worker effectively holds in each skill
# --------------------------------------------------------------------------- #


class SkillStanding(StrictModel):
    skill_ref: OpaqueRef
    claimed_level: int = Field(default=0, ge=0, le=5)
    declared_by: ClaimSource | None = None
    evidence_hours: Decimal
    corroborated_level: int = Field(ge=0, le=5)
    effective_level: Decimal
    verified: bool
    licence_expired: bool = False
    transferred_from: OpaqueRef | None = None

    @field_validator("evidence_hours", "effective_level", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


def _decayed_hours(evidence: Sequence[SkillEvidence], skill: SkillDefinition, at: Any) -> Decimal:
    total = Decimal("0")
    for item in evidence:
        if item.skill_ref != skill.skill_ref:
            continue
        age_days = Decimal((at - parsed(item.at)).total_seconds()) / Decimal(86400)
        if age_days < 0:
            continue
        total += item.hours * (Decimal(2) ** (-(age_days / Decimal(skill.decay_half_life_days))))
    return total.quantize(_HOURS, rounding=ROUND_HALF_UP)


def _corroborated(hours: Decimal, skill: SkillDefinition) -> int:
    level = 0
    for index, need in enumerate(skill.evidence_hours_per_level, start=1):
        if hours > 0 and hours >= need:
            level = index
    return level


def _direct_standing(taxonomy: SkillsTaxonomy, plan: SkillsMatchingPlan, profile: WorkerProfile, skill: SkillDefinition, at: Any) -> SkillStanding:
    claim = profile.claim(skill.skill_ref)
    hours = _decayed_hours(profile.evidence, skill, at)
    corroborated = _corroborated(hours, skill)
    claimed = claim.level if claim else 0
    expired = bool(skill.licence and claim is not None and claim.expires_at is not None and parsed(claim.expires_at) <= at)
    if expired:
        effective = Decimal("0")
    elif claimed <= corroborated:
        effective = Decimal(max(claimed, corroborated))
    else:
        effective = Decimal(corroborated) + (Decimal(claimed) - Decimal(corroborated)) * plan.unverified_claim_discount
    if skill.licence and claim is None:
        effective = Decimal("0")
    return SkillStanding(skill_ref=skill.skill_ref, claimed_level=claimed, declared_by=claim.declared_by if claim else None, evidence_hours=hours, corroborated_level=corroborated, effective_level=_level(effective), verified=claimed > 0 and corroborated >= claimed and not expired, licence_expired=expired)


def effective_levels(taxonomy: SkillsTaxonomy, plan: SkillsMatchingPlan, profile: WorkerProfile, *, as_of: str) -> dict[str, SkillStanding]:
    """Each skill the worker effectively holds: claims corroborated or discounted by decayed evidence, plus transfers from adjacent skills; licences never transfer."""

    at = parsed(timestamp(as_of, field_name="as_of"))
    direct = {skill.skill_ref: _direct_standing(taxonomy, plan, profile, skill, at) for skill in taxonomy.skills}
    out: dict[str, SkillStanding] = {}
    for skill in taxonomy.skills:
        standing = direct[skill.skill_ref]
        if standing.effective_level > 0 or skill.licence:
            out[skill.skill_ref] = standing
            continue
        best: tuple[Decimal, str] | None = None
        for source_ref, weight in sorted(skill.transfers_from.items()):
            transferred = _level(direct[source_ref].effective_level * weight)
            if transferred > 0 and (best is None or transferred > best[0]):
                best = (transferred, source_ref)
        if best is not None:
            out[skill.skill_ref] = SkillStanding(skill_ref=skill.skill_ref, evidence_hours=standing.evidence_hours, corroborated_level=0, effective_level=best[0], verified=False, transferred_from=best[1])
        else:
            out[skill.skill_ref] = standing
    return out


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


class RequirementFit(StrictModel):
    skill_ref: OpaqueRef
    minimum_level: int = Field(ge=1, le=5)
    mandatory: bool
    weight: Decimal
    claimed_level: int = Field(ge=0, le=5)
    corroborated_level: int = Field(ge=0, le=5)
    effective_level: Decimal
    evidence_hours: Decimal
    fit: Decimal
    status: RequirementStatus
    note: ShortText

    @field_validator("weight", "effective_level", "evidence_hours", "fit", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class WorkerMatch(StrictModel):
    worker_ref: OpaqueRef
    kind: WorkerKind
    role_ref: OpaqueRef | None = None
    rank: int = Field(ge=1)
    verdict: Verdict
    score: Decimal
    proficiency_score: Decimal
    evidence_score: Decimal
    availability_score: Decimal
    cost_score: Decimal
    available_hours: Decimal
    hours_needed: Decimal
    cost_rate: Decimal
    cost: Decimal
    fits: tuple[RequirementFit, ...] = Field(min_length=1, max_length=50)
    reasons: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)

    @field_validator("fits", "reasons", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("score", "proficiency_score", "evidence_score", "availability_score", "cost_score", "available_hours", "hours_needed", "cost_rate", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SkillGap(StrictModel):
    job_ref: OpaqueRef
    skill_ref: OpaqueRef
    minimum_level: int = Field(ge=1, le=5)
    mandatory: bool
    hours: Decimal
    best_worker_ref: OpaqueRef | None = None
    best_effective_level: Decimal
    levels_short: Decimal
    note: ShortText

    @field_validator("hours", "best_effective_level", "levels_short", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class JobMatch(StrictModel):
    job_ref: OpaqueRef
    title: ShortText
    kind: JobKind
    requirements_digest: Sha256Digest
    hours_required: Decimal
    headcount: int = Field(ge=1)
    starts_at: str
    due_at: str
    budget: Decimal | None = None
    candidates: tuple[WorkerMatch, ...] = Field(default_factory=tuple, max_length=100)
    workers_considered: int = Field(ge=0)
    team: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    team_cost: Decimal
    team_hours: Decimal
    coverage_percent: Decimal
    staffed: bool
    gaps: tuple[SkillGap, ...] = Field(default_factory=tuple, max_length=50)
    recommendation: ShortText

    @field_validator("candidates", "team", "gaps", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_required", "budget", "team_cost", "team_hours", "coverage_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


def _available_hours(profile: WorkerProfile, job: JobRequirements, at: Any) -> Decimal:
    start = max(parsed(job.starts_at), at, *( [parsed(profile.available_from)] if profile.available_from else []))
    end = parsed(job.due_at) if not profile.available_until else min(parsed(job.due_at), parsed(profile.available_until))
    if end <= start:
        return Decimal("0")
    weeks = Decimal((end - start).total_seconds()) / Decimal(7 * 86400)
    return (profile.hours_per_week * weeks).quantize(_HOURS, rounding=ROUND_HALF_UP)


def _fit_requirement(requirement: SkillRequirement, standing: SkillStanding, plan: SkillsMatchingPlan) -> tuple[RequirementFit, bool]:
    minimum = Decimal(requirement.minimum_level)
    effective = standing.effective_level
    disqualify = False
    if standing.licence_expired:
        status, fit = "licence_expired", Decimal("0")
        note = f"the licence expired; the claim no longer counts"
        disqualify = requirement.mandatory
    elif effective <= 0:
        status, fit = "missing", Decimal("0")
        note = "no claim, evidence, or transferable skill"
        disqualify = requirement.mandatory
    elif effective >= minimum:
        status, fit = "met", Decimal("1")
        note = f"effective {effective} against minimum {requirement.minimum_level}" + (f" (verified by {standing.evidence_hours}h)" if standing.verified else f" (claim by {standing.declared_by}, {standing.evidence_hours}h corroborate level {standing.corroborated_level})" if standing.claimed_level else "")
        if standing.transferred_from:
            note = f"effective {effective} transferred from {standing.transferred_from}"
    elif minimum - effective <= plan.stretch_levels:
        status, fit = "stretch", _score(effective / minimum)
        note = f"effective {effective} is {_level(minimum - effective)} below minimum {requirement.minimum_level}, within the {plan.stretch_levels} stretch"
    else:
        status, fit = "short", _score(effective / minimum)
        note = f"effective {effective} is {_level(minimum - effective)} below minimum {requirement.minimum_level}"
        disqualify = requirement.mandatory
    return RequirementFit(skill_ref=requirement.skill_ref, minimum_level=requirement.minimum_level, mandatory=requirement.mandatory, weight=requirement.weight, claimed_level=standing.claimed_level, corroborated_level=standing.corroborated_level, effective_level=effective, evidence_hours=standing.evidence_hours, fit=fit, status=status, note=note[:300]), disqualify


def _match_worker(plan: SkillsMatchingPlan, job: JobRequirements, profile: WorkerProfile, standings: Mapping[str, SkillStanding], at: Any) -> dict[str, Any]:
    fits: list[RequirementFit] = []
    reasons: list[str] = []
    disqualified: list[str] = []
    total_weight = sum((item.weight for item in job.requirements), Decimal("0"))
    proficiency = evidence = Decimal("0")
    for requirement in job.requirements:
        standing = standings.get(requirement.skill_ref) or SkillStanding(skill_ref=requirement.skill_ref, evidence_hours="0", corroborated_level=0, effective_level="0", verified=False)
        fit, disqualify = _fit_requirement(requirement, standing, plan)
        fits.append(fit)
        proficiency += requirement.weight * fit.fit
        evidence += requirement.weight * _score(Decimal(standing.corroborated_level) / Decimal(requirement.minimum_level))
        if disqualify:
            disqualified.append(f"{requirement.skill_ref}: {fit.note}")
        elif fit.status == "stretch":
            reasons.append(f"stretch on {requirement.skill_ref}: {fit.note}")
    proficiency_score = _score(proficiency / total_weight)
    evidence_score = _score(evidence / total_weight)
    hours_needed = job.hours_per_head
    available = _available_hours(profile, job, at)
    availability_score = _score(available / hours_needed)
    cost = _money(profile.cost_rate * hours_needed)
    cost_score = Decimal("1.00")
    verdict = "fit"
    if job.budget is not None:
        share = _money(job.budget / Decimal(job.headcount))
        if cost > share:
            over = (cost - share) / share * _HUNDRED
            cost_score = _score(Decimal("1") - (cost - share) / share)
            if over > plan.budget_tolerance_percent:
                verdict = "over_budget"
                reasons.append(f"cost {cost} exceeds the {share} budget share by {over.quantize(_LEVEL)}%")
            else:
                reasons.append(f"cost {cost} is {over.quantize(_LEVEL)}% over the {share} budget share, inside the {plan.budget_tolerance_percent}% tolerance")
    if availability_score * _HUNDRED < plan.minimum_availability_percent:
        verdict = "unavailable"
        reasons.append(f"{available}h free in the window against {hours_needed}h needed")
    if disqualified:
        verdict = "disqualified"
        reasons = disqualified[:6] + reasons
    score = _score(plan.proficiency_weight * proficiency_score + plan.evidence_weight * evidence_score + plan.availability_weight * availability_score + plan.cost_weight * cost_score)
    if verdict == "fit":
        if any(fit.status == "stretch" for fit in fits):
            verdict = "stretch"
        elif score < plan.fit_threshold:
            verdict = "stretch"
            reasons.append(f"score {score} is below the {plan.fit_threshold} fit threshold")
        else:
            reasons.insert(0, f"score {score}: proficiency {proficiency_score}, evidence {evidence_score}, availability {availability_score}, cost {cost_score}")
    return {"worker_ref": profile.worker_ref, "kind": profile.kind, "role_ref": profile.role_ref, "verdict": verdict, "score": str(score), "proficiency_score": str(proficiency_score), "evidence_score": str(evidence_score), "availability_score": str(availability_score), "cost_score": str(cost_score), "available_hours": str(available), "hours_needed": str(hours_needed), "cost_rate": str(profile.cost_rate), "cost": str(cost), "fits": [fit.to_dict() for fit in fits], "reasons": [item[:300] for item in reasons[:12]]}


_VERDICT_ORDER = {"fit": 0, "stretch": 1, "over_budget": 2, "unavailable": 3, "disqualified": 4}


def match_job(taxonomy: SkillsTaxonomy, plan: SkillsMatchingPlan, job: JobRequirements | Mapping[str, Any], profiles: Sequence[WorkerProfile | Mapping[str, Any]], *, as_of: str, standings: Mapping[str, Mapping[str, SkillStanding]] | None = None) -> JobMatch:
    """Every worker scored against one job, ranked, a team assembled for the headcount, and the gaps nobody covers."""

    parsed_job = job if isinstance(job, JobRequirements) else JobRequirements.model_validate(detached(job))
    _require(parsed_job.currency == plan.currency, "SCOPE_MISMATCH", f"job {parsed_job.job_ref} is priced in {parsed_job.currency}, the plan in {plan.currency}")
    for requirement in parsed_job.requirements:
        _require(taxonomy.skill(requirement.skill_ref) is not None, "SKILL_UNKNOWN", f"job {parsed_job.job_ref} requires {requirement.skill_ref}, which the taxonomy does not define")
    at = parsed(timestamp(as_of, field_name="as_of"))
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    rows: list[dict[str, Any]] = []
    for profile in workers:
        _require(profile.currency == plan.currency, "SCOPE_MISMATCH", f"worker {profile.worker_ref} costs in {profile.currency}, the plan in {plan.currency}")
        standing = (standings or {}).get(profile.worker_ref) or effective_levels(taxonomy, plan, profile, as_of=as_of)
        rows.append(_match_worker(plan, parsed_job, profile, standing, at))
    rows.sort(key=lambda row: (_VERDICT_ORDER[row["verdict"]], -Decimal(row["score"]), Decimal(row["cost"]), row["worker_ref"]))
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
    usable = [row for row in rows if row["verdict"] in ("fit", "stretch")]
    team = usable[: parsed_job.headcount]
    team_refs = [row["worker_ref"] for row in team]
    covered: dict[str, Decimal] = {}
    best_seen: dict[str, tuple[Decimal, str | None]] = {}
    for requirement in parsed_job.requirements:
        for row in team:
            fit = next(item for item in row["fits"] if item["skill_ref"] == requirement.skill_ref)
            covered[requirement.skill_ref] = max(covered.get(requirement.skill_ref, Decimal("0")), Decimal(fit["fit"]))
        for row in rows:
            fit = next(item for item in row["fits"] if item["skill_ref"] == requirement.skill_ref)
            level = Decimal(fit["effective_level"])
            if requirement.skill_ref not in best_seen or level > best_seen[requirement.skill_ref][0]:
                best_seen[requirement.skill_ref] = (level, row["worker_ref"])
    total_weight = sum((item.weight for item in parsed_job.requirements), Decimal("0"))
    coverage = (sum((item.weight * covered.get(item.skill_ref, Decimal("0")) for item in parsed_job.requirements), Decimal("0")) / total_weight * _HUNDRED).quantize(_LEVEL, rounding=ROUND_HALF_UP)
    gaps: list[dict[str, Any]] = []
    for requirement in parsed_job.requirements:
        if covered.get(requirement.skill_ref, Decimal("0")) >= 1:
            continue
        best_level, best_ref = best_seen.get(requirement.skill_ref, (Decimal("0"), None))
        share = (parsed_job.hours_required * requirement.weight / total_weight).quantize(_HOURS, rounding=ROUND_HALF_UP)
        short = _level(Decimal(requirement.minimum_level) - best_level)
        note = f"no team member meets level {requirement.minimum_level}; best seen is {best_ref} at {best_level}" if best_ref and best_level > 0 else f"no worker holds {requirement.skill_ref} at all"
        gaps.append({"job_ref": parsed_job.job_ref, "skill_ref": requirement.skill_ref, "minimum_level": requirement.minimum_level, "mandatory": requirement.mandatory, "hours": str(share), "best_worker_ref": best_ref if best_level > 0 else None, "best_effective_level": str(best_level), "levels_short": str(max(short, Decimal("0"))), "note": note[:300]})
    staffed = len(team) == parsed_job.headcount and not any(gap["mandatory"] for gap in gaps)
    team_cost = _money(sum((Decimal(row["cost"]) for row in team), Decimal("0")))
    team_hours = sum((min(Decimal(row["available_hours"]), parsed_job.hours_per_head) for row in team), Decimal("0")).quantize(_HOURS)
    if staffed and not gaps:
        recommendation = f"staff with {', '.join(team_refs)} at {team_cost} {parsed_job.currency}; every requirement is met"
    elif staffed:
        recommendation = f"staff with {', '.join(team_refs)} at {team_cost}; optional skills short: {', '.join(gap['skill_ref'] for gap in gaps)}"
    elif len(team) < parsed_job.headcount:
        recommendation = f"{len(team)} of {parsed_job.headcount} heads found; source {parsed_job.headcount - len(team)} more" + (f" (gaps: {', '.join(gap['skill_ref'] for gap in gaps if gap['mandatory'])})" if gaps else "")
    else:
        recommendation = f"team {', '.join(team_refs)} leaves mandatory gaps: " + "; ".join(f"{gap['skill_ref']} short {gap['levels_short']} level(s)" for gap in gaps if gap["mandatory"])
    payload = {
        "job_ref": parsed_job.job_ref, "title": parsed_job.title, "kind": parsed_job.kind, "requirements_digest": parsed_job.requirements_digest, "hours_required": str(parsed_job.hours_required), "headcount": parsed_job.headcount, "starts_at": parsed_job.starts_at, "due_at": parsed_job.due_at, "budget": None if parsed_job.budget is None else str(parsed_job.budget),
        "candidates": rows[: plan.max_candidates], "workers_considered": len(rows), "team": team_refs, "team_cost": str(team_cost), "team_hours": str(team_hours), "coverage_percent": str(coverage), "staffed": staffed, "gaps": gaps, "recommendation": recommendation[:300],
    }
    return JobMatch.model_validate(payload)


class SkillsMatchReport(StrictModel):
    schema_id: str = Field(default=SKILLS_MATCH_REPORT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    taxonomy_digest: Sha256Digest
    jobs: tuple[JobMatch, ...] = Field(min_length=1, max_length=500)
    workers: int = Field(ge=0)
    staffed_jobs: int = Field(ge=0)
    open_gaps: int = Field(ge=0)
    total_cost: Decimal
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("jobs", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("total_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="total_cost")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SkillsMatchReport":
        if self.staffed_jobs != sum(1 for job in self.jobs if job.staffed) or self.open_gaps != sum(len(job.gaps) for job in self.jobs):
            raise ValueError("staffed_jobs and open_gaps must tie to the jobs")
        if not skip_digests(info) and self.report_digest != sealed_digest(SkillsMatchReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def job(self, job_ref: str) -> JobMatch | None:
        return next((job for job in self.jobs if job.job_ref == job_ref), None)

    def render(self) -> str:
        lines = [f"**Skills match {self.company_ref}** as of {self.as_of[:10]}: {self.staffed_jobs} of {len(self.jobs)} job(s) staffed from {self.workers} worker(s), {self.open_gaps} gap(s), {self.total_cost} {self.currency}."]
        for job in self.jobs:
            lines.append(f"- {job.job_ref} ({job.title}): {job.recommendation}; coverage {job.coverage_percent}%")
            for row in job.candidates[:3]:
                lines.append(f"  - #{row.rank} {row.worker_ref} [{row.verdict}] {row.score}: {row.reasons[0] if row.reasons else ''}")
        return "\n".join(lines)


def build_skills_match_report(plan: SkillsMatchingPlan | Mapping[str, Any], *, taxonomy: SkillsTaxonomy | Mapping[str, Any], jobs: Sequence[JobRequirements | Mapping[str, Any]], profiles: Sequence[WorkerProfile | Mapping[str, Any]], work_order_states: Sequence[tuple[Any, Any]] = (), as_of: str) -> SkillsMatchReport:
    """Every job matched against every worker, with the work order chain's recorded hours added to each worker's evidence first."""

    parsed_plan = plan if isinstance(plan, SkillsMatchingPlan) else SkillsMatchingPlan.model_validate(detached(plan))
    parsed_taxonomy = taxonomy if isinstance(taxonomy, SkillsTaxonomy) else SkillsTaxonomy.model_validate(detached(taxonomy))
    _require(parsed_taxonomy.company_ref == parsed_plan.company_ref, "SCOPE_MISMATCH", "the taxonomy names another company")
    _require(bool(jobs), "JOBS_MISSING", "match at least one job")
    parsed_jobs = [item if isinstance(item, JobRequirements) else JobRequirements.model_validate(detached(item)) for item in jobs]
    _require(len({job.job_ref for job in parsed_jobs}) == len(parsed_jobs), "JOB_DUPLICATE", "job refs must be unique")
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    _require(len({worker.worker_ref for worker in workers}) == len(workers), "WORKER_DUPLICATE", "worker refs must be unique")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    if work_order_states:
        extra = evidence_from_work_orders(work_order_states, parsed_jobs, taxonomy=parsed_taxonomy)
        workers = [with_evidence(worker, extra[worker.worker_ref]) if worker.worker_ref in extra else worker for worker in workers]
        from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

        digests.extend(WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)[1].state_digest for plan_doc, state_doc in work_order_states)
    standings = {worker.worker_ref: effective_levels(parsed_taxonomy, parsed_plan, worker, as_of=at) for worker in workers}
    matches = [match_job(parsed_taxonomy, parsed_plan, job, workers, as_of=at, standings=standings) for job in parsed_jobs]
    recommendations = [f"{job.job_ref}: {job.recommendation}" for job in matches if not job.staffed or job.gaps][:24]
    if not recommendations:
        recommendations.append("every job is staffed with every requirement met")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "taxonomy_digest": parsed_taxonomy.taxonomy_digest, "jobs": [job.to_dict() for job in matches], "workers": len(workers),
        "staffed_jobs": sum(1 for job in matches if job.staffed), "open_gaps": sum(len(job.gaps) for job in matches), "total_cost": str(_money(sum((job.team_cost for job in matches), Decimal("0")))), "recommendations": [item[:300] for item in recommendations],
        "source_digests": [parsed_taxonomy.taxonomy_digest, *[job.requirements_digest for job in parsed_jobs], *[worker.profile_digest for worker in workers], *digests],
    }
    return seal(SkillsMatchReport, payload, "report_digest")


def verify_skills_match_report(value: Any) -> SkillsMatchReport:
    return value if isinstance(value, SkillsMatchReport) else SkillsMatchReport.model_validate(dict(detached(value)))


SKILLS_MATCHING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "skills_matching",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["seal_taxonomy", "profile_workers", "credit_chain_evidence", "compute_standing", "score_requirements", "assemble_team", "name_gaps", "seal_report"],
    "proficiency_levels": PROFICIENCY_LEVELS,
    "components": ["proficiency", "evidence", "availability", "cost"],
    "verdicts": list(VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "evidence is the work order chain's recorded hours, decayed by the skill's half-life; nothing is inferred from text",
        "a claim the evidence does not corroborate is discounted by the plan's rate, never taken at face value",
        "a licence never transfers from an adjacent skill and an expired licence counts for nothing",
        "a mandatory skill more than the stretch below its minimum disqualifies, with the reason",
        "every score names its four components and every gap names the best worker seen and how far short",
    ],
}

__all__ = [
    "CLAIM_SOURCES", "EVIDENCE_KINDS", "JOB_KINDS", "JOB_REQUIREMENTS_SCHEMA", "PROFICIENCY_LEVELS", "REQUIREMENT_STATUSES", "SKILLS_MATCHING_MANIFEST", "SKILLS_MATCHING_PLAN_SCHEMA", "SKILLS_MATCH_REPORT_SCHEMA", "SKILLS_TAXONOMY_SCHEMA", "VERDICTS", "WORKER_KINDS", "WORKER_PROFILE_SCHEMA",
    "JobMatch", "JobRequirements", "RequirementFit", "SkillClaim", "SkillDefinition", "SkillEvidence", "SkillGap", "SkillRequirement", "SkillStanding", "SkillsMatchReport", "SkillsMatchingError", "SkillsMatchingPlan", "SkillsTaxonomy", "WorkerMatch", "WorkerProfile",
    "build_skills_match_report", "compile_job_requirements", "compile_skills_matching_plan", "compile_skills_taxonomy", "compile_worker_profile", "effective_levels", "evidence_from_work_orders", "match_job", "verify_skills_match_report", "with_evidence",
]
