"""A workforce that improves: grade workers on outcomes, revise the roster, and apply the revision behind the same fences.

Workers had budgets and outcome counters but nobody graded them.
``grade_workers`` scores every persisted worker against its role from the
sealed ledger: success rate, cost per success against the role's cap, cost
overruns, and unreconciled dispatches, weighted into a grade with the
reasons listed.  When an operating memory is supplied, the archetype's
learned success rate and cost per success for the same engine become the
bar the worker is measured against, so a "poor" grade means poor compared
with what this kind of work has actually achieved.

``revise_roster`` turns the grades into a sealed ``RosterRevision``: which
workers to release (with the reason), which to keep, which roles to hire
again with the better-performing action first, and the resulting roster.
``apply_roster_revision`` compiles the revised workforce plan, migrates every
retained worker's state to it through the plan-migration fence, and
releases the workers the revision names through their own lifecycle; hiring
replacements is left to bring-up so nothing is dispatched from here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_operating_system import CompanyOperatingPlan
from lightbulb.company_plan_migration import migrate_state
from lightbulb.company_workforce import WORKER_LIFECYCLE, WorkforcePlan, advance_worker, compile_workforce

GRADES_SCHEMA = "lightbulb.company_worker_grades.v1"
REVISION_SCHEMA = "lightbulb.company_roster_revision.v1"
Grade = Literal["strong", "adequate", "weak", "release"]
_HUNDRED = Decimal("100")


class WorkerGrade(StrictModel):
    worker_ref: OpaqueRef
    engine: ShortText
    status: ShortText
    outcomes: int = Field(ge=0)
    success_rate_percent: Decimal | None = None
    cost_per_success: Decimal | None = None
    cost_cap: Decimal
    benchmark_success_rate_percent: Decimal | None = None
    benchmark_cost_per_success: Decimal | None = None
    score: int = Field(ge=0, le=100)
    grade: Grade
    reasons: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=8)
    state_digest: Sha256Digest

    @field_validator("success_rate_percent", "cost_per_success", "cost_cap", "benchmark_success_rate_percent", "benchmark_cost_per_success", mode="before")
    @classmethod
    def _dec(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class WorkerGrades(StrictModel):
    schema_id: str = Field(default=GRADES_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    graded_at: str
    workers: tuple[WorkerGrade, ...] = Field(default_factory=tuple, max_length=60)
    memory_state_digest: Sha256Digest | None = None
    grades_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> WorkerGrades:
        if not skip_digests(info) and self.grades_digest != sealed_digest(WorkerGrades, self, "grades_digest"):
            raise ValueError("grades_digest must commit the exact grades")
        return self


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator * _HUNDRED).quantize(MONEY_QUANTUM)


def grade_workers(plan: WorkforcePlan | Mapping[str, Any], states: Sequence[Mapping[str, Any] | Any], *, graded_at: str, memory_state: Any = None, min_outcomes: int = 3) -> WorkerGrades:
    """Grade every persisted worker from its sealed ledger; fewer than ``min_outcomes`` outcomes is 'adequate' with a note, never a release."""

    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    stamp = timestamp(graded_at, field_name="graded_at")
    benchmarks: dict[str, dict[str, Decimal]] = {}
    memory_digest = None
    if memory_state is not None:
        from lightbulb.company_operating_memory import priors_for

        memory_digest = memory_state.state_digest
        for prior in priors_for(memory_state, metric="worker_success_rate"):
            benchmarks.setdefault(prior.engine, {})["success"] = prior.mean
        for prior in priors_for(memory_state, metric="worker_cost_per_success"):
            benchmarks.setdefault(prior.engine, {})["cost"] = prior.mean
    rows: list[dict[str, Any]] = []
    for record in states:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        state = WORKER_LIFECYCLE.State.model_validate(document, context={WORKER_LIFECYCLE.plan_context_key: parsed_plan})
        ledger = state.ledger
        role = parsed_plan.roster.worker(str(ledger.worker_ref))
        if role is None:
            continue
        outcomes = ledger.succeeded + ledger.failed + ledger.needs_input + ledger.pending_approval
        success = _pct(Decimal(ledger.succeeded), Decimal(outcomes))
        cost_per_success = (Decimal(str(ledger.total_cost)) / Decimal(ledger.succeeded)).quantize(MONEY_QUANTUM) if ledger.succeeded > 0 else None
        cap = Decimal(str(role.max_cost_per_dispatch))
        bench = benchmarks.get(str(role.engine), {})
        bench_success = bench.get("success")
        bench_cost = bench.get("cost")
        reasons: list[str] = []
        score = 50
        if state.status == "released":
            rows.append({"worker_ref": str(ledger.worker_ref), "engine": str(role.engine), "status": state.status, "outcomes": outcomes, "success_rate_percent": success, "cost_per_success": cost_per_success, "cost_cap": str(cap), "benchmark_success_rate_percent": bench_success, "benchmark_cost_per_success": bench_cost, "score": 0, "grade": "release", "reasons": [f"already released: {ledger.released_reason or 'unstated'}"], "state_digest": state.state_digest})
            continue
        if outcomes < min_outcomes:
            reasons.append(f"only {outcomes} outcome(s); needs {min_outcomes} before grading")
            rows.append({"worker_ref": str(ledger.worker_ref), "engine": str(role.engine), "status": state.status, "outcomes": outcomes, "success_rate_percent": success, "cost_per_success": cost_per_success, "cost_cap": str(cap), "benchmark_success_rate_percent": bench_success, "benchmark_cost_per_success": bench_cost, "score": 50, "grade": "adequate", "reasons": reasons, "state_digest": state.state_digest})
            continue
        assert success is not None
        target_success = bench_success if bench_success is not None else Decimal("70")
        if success >= target_success:
            score += 25
            reasons.append(f"success {success}% at or above the {'learned' if bench_success is not None else 'default'} bar {target_success}%")
        elif success >= target_success * Decimal("0.7"):
            reasons.append(f"success {success}% below the bar {target_success}%")
            score -= 10
        else:
            reasons.append(f"success {success}% far below the bar {target_success}%")
            score -= 35
        if cost_per_success is None:
            score -= 15
            reasons.append("no successful dispatch to cost")
        else:
            ceiling = min(cap, bench_cost) if bench_cost is not None else cap
            if cost_per_success <= ceiling:
                score += 20
                reasons.append(f"cost per success {cost_per_success} inside {ceiling}")
            else:
                score -= 20
                reasons.append(f"cost per success {cost_per_success} above {ceiling}")
        if ledger.open_dispatch_ref is not None:
            score -= 10
            reasons.append(f"dispatch {ledger.open_dispatch_ref} still unreconciled")
        if ledger.failed > ledger.succeeded:
            score -= 10
            reasons.append(f"{ledger.failed} failed versus {ledger.succeeded} succeeded")
        score = max(0, min(100, score))
        grade: Grade = "strong" if score >= 80 else "adequate" if score >= 50 else "weak" if score >= 30 else "release"
        rows.append({"worker_ref": str(ledger.worker_ref), "engine": str(role.engine), "status": state.status, "outcomes": outcomes, "success_rate_percent": success, "cost_per_success": cost_per_success, "cost_cap": str(cap), "benchmark_success_rate_percent": bench_success, "benchmark_cost_per_success": bench_cost, "score": score, "grade": grade, "reasons": reasons[:8], "state_digest": state.state_digest})
    return seal(WorkerGrades, {"plan_digest": parsed_plan.plan_digest, "graded_at": stamp, "workers": sorted(rows, key=lambda row: row["worker_ref"]), "memory_state_digest": memory_digest}, "grades_digest")


class RosterChange(StrictModel):
    worker_ref: OpaqueRef
    action: Literal["keep", "release", "rehire_with_action", "raise_cap", "lower_cap"]
    reason: BoundedText
    new_first_action: ShortText | None = None
    new_max_cost_per_dispatch: Decimal | None = None

    @field_validator("new_max_cost_per_dispatch", mode="before")
    @classmethod
    def _dec(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="new_max_cost_per_dispatch")


class RosterRevision(StrictModel):
    schema_id: str = Field(default=REVISION_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    grades_digest: Sha256Digest
    revised_at: str
    changes: tuple[RosterChange, ...] = Field(default_factory=tuple, max_length=60)
    roster: dict[str, Any]
    revised_plan_digest: Sha256Digest
    revision_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RosterRevision:
        if not skip_digests(info) and self.revision_digest != sealed_digest(RosterRevision, self, "revision_digest"):
            raise ValueError("revision_digest must commit the exact revision")
        return self

    @property
    def releases(self) -> tuple[str, ...]:
        return tuple(change.worker_ref for change in self.changes if change.action == "release")


def revise_roster(operating_plan: CompanyOperatingPlan | Mapping[str, Any], plan: WorkforcePlan | Mapping[str, Any], grades: WorkerGrades | Mapping[str, Any], *, revised_at: str, better_actions: Mapping[str, str] | None = None) -> RosterRevision:
    """Release 'release' grades, put the better-performing action first for 'weak' ones, tighten or loosen caps from cost evidence; compile the resulting plan."""

    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    parsed_grades = grades if isinstance(grades, WorkerGrades) else WorkerGrades.model_validate(dict(detached(grades)))
    if parsed_grades.plan_digest != parsed_plan.plan_digest:
        raise ValueError("the grades were computed for a different workforce plan")
    stamp = timestamp(revised_at, field_name="revised_at")
    by_ref = {grade.worker_ref: grade for grade in parsed_grades.workers}
    roster = parsed_plan.roster.to_dict()
    workers: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    for role in roster["workers"]:
        grade = by_ref.get(role["worker_ref"])
        if grade is None:
            workers.append(role)
            continue
        if grade.grade == "release" and grade.status != "released":
            changes.append({"worker_ref": role["worker_ref"], "action": "release", "reason": "; ".join(grade.reasons)[:900]})
            continue
        if grade.status == "released":
            changes.append({"worker_ref": role["worker_ref"], "action": "release", "reason": "already released; dropped from the roster"})
            continue
        revised = dict(role)
        if grade.grade == "weak":
            preferred = (better_actions or {}).get(role["worker_ref"])
            if preferred and preferred in role["actions"] and role["actions"][0] != preferred:
                revised["actions"] = [preferred, *[item for item in role["actions"] if item != preferred]]
                changes.append({"worker_ref": role["worker_ref"], "action": "rehire_with_action", "reason": f"weak grade; {preferred} performed better elsewhere", "new_first_action": preferred})
            else:
                changes.append({"worker_ref": role["worker_ref"], "action": "keep", "reason": "weak grade; no better action known, watch next period"})
        elif grade.grade == "strong" and grade.cost_per_success is not None and grade.cost_per_success < Decimal(str(role["max_cost_per_dispatch"])) * Decimal("0.5"):
            new_cap = max(grade.cost_per_success * Decimal("1.5"), Decimal("0.01")).quantize(MONEY_QUANTUM)
            revised["max_cost_per_dispatch"] = str(new_cap)
            changes.append({"worker_ref": role["worker_ref"], "action": "lower_cap", "reason": f"strong grade at {grade.cost_per_success} per success; cap lowered to {new_cap}", "new_max_cost_per_dispatch": str(new_cap)})
        else:
            changes.append({"worker_ref": role["worker_ref"], "action": "keep", "reason": f"{grade.grade} grade"})
        workers.append(revised)
    if not workers:
        raise ValueError("a revision cannot release every worker; keep at least one")
    revised_roster = {**roster, "workers": workers}
    revised_plan = compile_workforce(operating_plan, revised_roster)
    return seal(RosterRevision, {"plan_digest": parsed_plan.plan_digest, "grades_digest": parsed_grades.grades_digest, "revised_at": stamp, "changes": changes, "roster": revised_roster, "revised_plan_digest": revised_plan.plan_digest}, "revision_digest")


@dataclass(frozen=True)
class RevisionOutcome:
    revised_plan: WorkforcePlan
    migrated: tuple[str, ...]
    released: tuple[str, ...]
    refused: tuple[tuple[str, str], ...]


def apply_roster_revision(operating_plan: CompanyOperatingPlan | Mapping[str, Any], plan: WorkforcePlan | Mapping[str, Any], revision: RosterRevision | Mapping[str, Any], store: EngineStateStore, *, applied_at: str, actor_ref: str) -> RevisionOutcome:
    """Release the named workers through their lifecycle and migrate the retained ones to the revised plan behind the migration fence."""

    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    parsed_revision = revision if isinstance(revision, RosterRevision) else RosterRevision.model_validate(dict(detached(revision)))
    if parsed_revision.plan_digest != parsed_plan.plan_digest:
        raise ValueError("the revision was computed for a different workforce plan")
    revised_plan = compile_workforce(operating_plan, parsed_revision.roster)
    if revised_plan.plan_digest != parsed_revision.revised_plan_digest:
        raise ValueError("the revised roster no longer compiles to the revision's plan digest")
    stamp = timestamp(applied_at, field_name="applied_at")
    runtime = EngineRuntime(spec=WORKER_LIFECYCLE, engine="company_workforce", plan=parsed_plan, store=store, advance=advance_worker)
    released: list[str] = []
    refused: list[tuple[str, str]] = []
    for worker_ref in parsed_revision.releases:
        record = store.get("company_workforce", worker_ref)
        if record is None or record["status"] == "released":
            continue
        state = runtime.load(worker_ref)
        command = runtime.command(state, event="release", transition_ref=f"release:{worker_ref}:{stamp}", idempotency_key=f"release:{worker_ref}:{stamp}", occurred_at=stamp, actor_ref=actor_ref, reason="roster revision: " + next((change.reason for change in parsed_revision.changes if change.worker_ref == worker_ref), "graded for release")[:200])
        outcome = runtime.advance_and_persist(worker_ref, command)
        if outcome.persisted:
            released.append(worker_ref)
        else:
            refused.append((worker_ref, str(outcome.result.receipt.rejection_code)))
    migrated: list[str] = []
    for role in revised_plan.roster.workers:
        record = store.get("company_workforce", role.worker_ref)
        if record is None or record["plan_digest"] == revised_plan.plan_digest:
            continue
        try:
            result = migrate_state(WORKER_LIFECYCLE, state=dict(record["state"]), from_plan=parsed_plan, to_plan=revised_plan, migrated_at=stamp, actor_ref=actor_ref, reason="roster revision")
            store.migrate("company_workforce", role.worker_ref, detached(result.state), migration=result.migration.to_dict())
            migrated.append(role.worker_ref)
        except ValueError as exc:
            refused.append((role.worker_ref, str(exc)[:200]))
    return RevisionOutcome(revised_plan=revised_plan, migrated=tuple(migrated), released=tuple(released), refused=tuple(refused))


WORKFORCE_LEARNING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_workforce_learning",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["grade_from_ledgers", "benchmark_against_memory", "revise_roster", "release_and_migrate"],
    "grades": ["strong", "adequate", "weak", "release"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "grades come from sealed worker ledgers; fewer outcomes than the minimum never releases anyone",
        "the bar is the archetype's learned success rate and cost per success when memory has them, else the role's own cap",
        "a revision releases through the worker lifecycle and migrates retained workers behind the plan-migration fence; it hires nothing",
    ],
}

__all__ = ["GRADES_SCHEMA", "REVISION_SCHEMA", "WORKFORCE_LEARNING_MANIFEST", "RevisionOutcome", "RosterChange", "RosterRevision", "WorkerGrade", "WorkerGrades", "apply_roster_revision", "grade_workers", "revise_roster"]
