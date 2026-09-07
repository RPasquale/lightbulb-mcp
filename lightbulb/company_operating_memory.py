"""Operating memory: what closed periods, closes, prospects, and workers taught, as calibrated priors.

Health assessments produce learnings that went nowhere.  This module keeps
them: ``OperatingMemory`` is a replay-fenced lifecycle (``learn`` events)
whose ledger holds evidence-weighted priors keyed by archetype, engine, and
metric (realised return on spend, budget utilisation, days to close, reply
and meeting rates, worker success rates, cost overruns).  Each prior carries
its sample count, mean, and a p10/p90 band, plus the digests of the states it
learned from, so a prior can never come from a state twice and can always be
traced.

``learn_from_periods``, ``learn_from_closes``, ``learn_from_prospects``, and
``learn_from_workers`` derive the ``learn`` receipt from persisted states;
``priors_to_assumptions`` turns the priors into simulator assumptions
(p10..p90 as the return band) so forecasts use what actually happened;
``replan_hints`` and ``roster_hints`` expose the priors the replanner and the
workforce learning use.  Values are computed from sealed states, never
supplied by a model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
)
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan
from lightbulb.inference_cost_register import InferenceCostRegister, cost_overrun_rates

_COST_ENGINES: tuple[str, ...] = ("growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery")
from lightbulb.company_workforce import WORKER_LIFECYCLE, WorkforcePlan
from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, FinanceCloseLoopPlan
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan

MEMORY_KIND = "company_operating_memory"
MEMORY_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
MAX_MEMORY_TRANSITIONS = 4096
MetricKind = Literal["return_on_spend", "utilisation_percent", "days_to_close", "close_on_time_rate", "reply_rate_percent", "meeting_rate_percent", "worker_success_rate", "worker_cost_per_success", "cost_overrun_rate", "recommendation_abs_error_percent", "deal_win_rate_percent"]
_HUNDRED = Decimal("100")
_Q4 = Decimal("0.0001")


def _fine(value: Any, name: str) -> Decimal:
    """Four-decimal quantity (returns, rates, days); negatives allowed, non-numbers refused."""

    try:
        parsed_value = Decimal(str(value))
    except (ArithmeticError, ValueError, TypeError) as exc:
        raise ValueError(f"{name} must be a decimal") from exc
    if not parsed_value.is_finite():
        raise ValueError(f"{name} must be finite")
    return parsed_value.quantize(_Q4)


class Prior(StrictModel):
    key: ShortText
    archetype: ShortText
    engine: ShortText
    metric: MetricKind
    samples: int = Field(ge=1, le=1_000_000)
    mean: Decimal
    p10: Decimal
    p90: Decimal
    minimum: Decimal
    maximum: Decimal
    last_learned_at: str

    @field_validator("mean", "p10", "p90", "minimum", "maximum", mode="before")
    @classmethod
    def _dec(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _fine(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> Prior:
        if not (self.minimum <= self.p10 <= self.p90 <= self.maximum):
            raise ValueError("prior band must be ordered: minimum <= p10 <= p90 <= maximum")
        return self


class Sample(StrictModel):
    key: ShortText
    archetype: ShortText
    engine: ShortText
    metric: MetricKind
    value: Decimal
    source_engine: ShortText
    source_ref: OpaqueRef
    source_state_digest: Sha256Digest
    observed_at: str

    @field_validator("value", mode="before")
    @classmethod
    def _value(cls, value: Any) -> Decimal:
        return _fine(value, "value")


class MemoryReceipt(StrictModel):
    samples: tuple[Sample, ...] = Field(default_factory=tuple, max_length=2000)
    lesson: ShortText | None = None

    @field_validator("samples", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class MemoryLedger(StrictModel):
    archetype: str | None = None
    priors: dict[str, Prior] = Field(default_factory=dict)
    learned_state_digests: tuple[str, ...] = Field(default_factory=tuple)
    samples_total: int = Field(default=0, ge=0)
    lessons: tuple[str, ...] = Field(default_factory=tuple)
    outcome: Literal["learning"] = "learning"

    @field_validator("learned_state_digests", "lessons", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class MemoryEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    agent_dispatched: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


class MemoryPlan(StrictModel):
    """The plan a memory runs under: the archetype it learns for, sealed."""

    schema_id: str = Field(default="lightbulb.company_operating_memory_plan.v1", alias="schema")
    archetype: ShortText
    company_ref: OpaqueRef
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MemoryPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(MemoryPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact memory plan")
        return self


def memory_plan(archetype: str, company_ref: str) -> MemoryPlan:
    return seal(MemoryPlan, {"archetype": archetype, "company_ref": company_ref}, "plan_digest")


def _percentile(values: Sequence[Decimal], fraction: Decimal) -> Decimal:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (Decimal(len(ordered) - 1) * fraction)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - Decimal(lower)
    return (ordered[lower] * (1 - weight) + ordered[upper] * weight).quantize(_Q4)


def _fold(existing: Prior | None, samples: Sequence[Sample], *, now: str) -> Prior:
    values = [sample.value for sample in samples]
    if existing is not None:
        # Evidence-weighted: the existing band contributes its mean weighted by its sample count.
        count = existing.samples + len(values)
        mean = ((existing.mean * existing.samples + sum(values)) / count).quantize(_Q4)
        minimum = min(existing.minimum, *values)
        maximum = max(existing.maximum, *values)
        weight_old = Decimal(existing.samples) / Decimal(count)
        p10 = (existing.p10 * weight_old + _percentile(values, Decimal("0.1")) * (1 - weight_old)).quantize(_Q4)
        p90 = (existing.p90 * weight_old + _percentile(values, Decimal("0.9")) * (1 - weight_old)).quantize(_Q4)
        p10, p90 = max(minimum, min(p10, p90)), min(maximum, max(p10, p90))
    else:
        count = len(values)
        mean = (sum(values) / count).quantize(_Q4)
        minimum, maximum = min(values), max(values)
        p10, p90 = _percentile(values, Decimal("0.1")), _percentile(values, Decimal("0.9"))
    first = samples[0]
    return Prior(key=first.key, archetype=first.archetype, engine=first.engine, metric=first.metric, samples=count, mean=mean, p10=p10, p90=p90, minimum=minimum, maximum=maximum, last_learned_at=now)


def _apply_memory(plan: MemoryPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event = command.receipt, command.event
    if event == "open":
        data.update({"archetype": plan.archetype})
    elif event == "learn":
        require(len(r.samples) >= 1, "SAMPLES_MISSING", "a learn event carries at least one sample")
        require(all(sample.archetype == plan.archetype for sample in r.samples), "ARCHETYPE_MISMATCH", f"memory learns for {plan.archetype} only")
        learned = set(data.get("learned_state_digests", ()))
        digests = {sample.source_state_digest for sample in r.samples}
        repeated = sorted(digests & learned)
        require(not repeated, "STATE_ALREADY_LEARNED", f"these states were already learned: {repeated[:3]}", "do_not_replay")
        priors = {key: Prior.model_validate(value) if not isinstance(value, Prior) else value for key, value in (data.get("priors") or {}).items()}
        by_key: dict[str, list[Sample]] = {}
        for sample in r.samples:
            by_key.setdefault(sample.key, []).append(sample)
        for key, samples in by_key.items():
            priors[key] = _fold(priors.get(key), samples, now=command.occurred_at)
        data.update({"priors": {key: prior.to_dict() for key, prior in sorted(priors.items())}, "learned_state_digests": (*data.get("learned_state_digests", ()), *sorted(digests)), "samples_total": int(data.get("samples_total", 0)) + len(r.samples), "lessons": (*data.get("lessons", ()), *([r.lesson] if r.lesson else []))[-24:]})
    return next_status, data


MEMORY_STATUSES: tuple[str, ...] = ("learning",)
MEMORY_LIFECYCLE = LifecycleSpec(entity="operating_memory", schema_prefix=MEMORY_KIND, statuses=MEMORY_STATUSES, terminal=frozenset(), events=("open", "learn"), table={("new", "open"): "learning", ("learning", "learn"): "learning"}, opening_event="open", reason_events=(), apply=_apply_memory, ledger_model=MemoryLedger, receipt_model=MemoryReceipt, effect_boundary_model=MemoryEffectBoundary, plan_model=MemoryPlan, max_transitions=MAX_MEMORY_TRANSITIONS)
MemoryState = MEMORY_LIFECYCLE.State


def memory_ref(plan: MemoryPlan) -> str:
    return f"{plan.company_ref}:memory"


def open_memory(plan: MemoryPlan, scope: Mapping[str, Any], *, opened_at: str) -> Any:
    return MEMORY_LIFECYCLE.open(plan, {**scope, "entity_ref": memory_ref(plan)}, opened_at=opened_at, actor_ref="actor-operating-memory")


def advance_memory(plan: MemoryPlan, state: Any, command: Any) -> Any:
    return MEMORY_LIFECYCLE.advance(plan, state, command)


def learn_command(plan: MemoryPlan, state: Any, samples: Sequence[Sample | Mapping[str, Any]], *, learned_at: str, lesson: str | None = None) -> dict[str, Any]:
    rows = [item if isinstance(item, Sample) else Sample.model_validate(dict(detached(item))) for item in samples]
    digest = stable_digest({"samples": [row.to_dict() for row in rows], "learned_at": learned_at})[:24]
    return MEMORY_LIFECYCLE.seal_command({"event": "learn", "transition_ref": f"learn:{digest}", "idempotency_key": f"learn:{digest}", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": learned_at, "actor_ref": "actor-operating-memory", "receipt": {"samples": [row.to_dict() for row in rows], "lesson": lesson}})


# --------------------------------------------------------------------------- #
# Deriving samples from persisted states
# --------------------------------------------------------------------------- #


def _key(archetype: str, engine: str, metric: str) -> str:
    return f"{archetype}:{engine}:{metric}"


def _sample(archetype: str, engine: str, metric: str, value: Any, *, source_engine: str, source_ref: str, digest: str, at: str) -> dict[str, Any]:
    return {"key": _key(archetype, engine, metric), "archetype": archetype, "engine": engine, "metric": metric, "value": str(value), "source_engine": source_engine, "source_ref": source_ref, "source_state_digest": digest, "observed_at": at}


def learn_from_periods(plan: CompanyOperatingPlan | Mapping[str, Any], periods: Sequence[Mapping[str, Any] | Any], *, prior_plans: Sequence[Mapping[str, Any] | Any] = ()) -> list[dict[str, Any]]:
    """Return-on-spend and utilisation per engine from closed periods; open or halted periods teach nothing yet."""

    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    lineage = {parsed_plan.plan_digest: parsed_plan, **{CompanyOperatingPlan.model_validate(detached(item)).plan_digest: CompanyOperatingPlan.model_validate(detached(item)) for item in prior_plans}}
    archetype = parsed_plan.blueprint.archetype
    samples: list[dict[str, Any]] = []
    for record in periods:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        owner = lineage.get(str(document.get("plan_digest")))
        if owner is None:
            raise ValueError("a period belongs to a plan outside the supplied lineage")
        state = PERIOD_LIFECYCLE.State.model_validate(document, context={PERIOD_LIFECYCLE.plan_context_key: owner})
        if state.status != "closed":
            continue
        ledger = state.ledger
        at = state.transition_history[-1].command.occurred_at
        for engine, spend in ledger.spend_by_engine.items():
            budget = next((envelope.budget for envelope in owner.envelopes if envelope.engine == engine), None)
            revenue = ledger.revenue_by_engine.get(engine, Decimal("0"))
            if spend > 0:
                samples.append(_sample(archetype, engine, "return_on_spend", (Decimal(str(revenue)) / Decimal(str(spend))).quantize(_Q4), source_engine="company_operating_system", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
            if budget and Decimal(str(budget)) > 0:
                samples.append(_sample(archetype, engine, "utilisation_percent", (Decimal(str(spend)) / Decimal(str(budget)) * _HUNDRED).quantize(MONEY_QUANTUM), source_engine="company_operating_system", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
    return samples


def learn_from_closes(plan: FinanceCloseLoopPlan | Mapping[str, Any], closes: Sequence[Mapping[str, Any] | Any], *, archetype: str) -> list[dict[str, Any]]:
    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    samples: list[dict[str, Any]] = []
    for record in closes:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        state = CLOSE_LIFECYCLE.State.model_validate(document, context={CLOSE_LIFECYCLE.plan_context_key: parsed_plan})
        if state.status != "closed":
            continue
        at = state.transition_history[-1].command.occurred_at
        days = getattr(state.ledger, "days_to_close", None)
        if days is not None:
            samples.append(_sample(archetype, "finance_close", "days_to_close", days, source_engine="finance_close", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
        on_time = getattr(state.ledger, "on_time", None)
        if on_time is not None:
            samples.append(_sample(archetype, "finance_close", "close_on_time_rate", "100" if on_time else "0", source_engine="finance_close", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
    return samples


def learn_from_prospects(plan: PipelineEngineLoopPlan | Mapping[str, Any], prospects: Sequence[Mapping[str, Any] | Any], *, archetype: str) -> list[dict[str, Any]]:
    """Reply and meeting rates per prospect that reached an outcome (handed off, lost, disqualified, suppressed)."""

    parsed_plan = PipelineEngineLoopPlan.model_validate(detached(plan))
    samples: list[dict[str, Any]] = []
    for record in prospects:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        state = PROSPECT_LIFECYCLE.State.model_validate(document, context={PROSPECT_LIFECYCLE.plan_context_key: parsed_plan})
        ledger = state.ledger
        if ledger.outcome is None or ledger.touches == 0:
            continue
        at = state.transition_history[-1].command.occurred_at
        samples.append(_sample(archetype, "pipeline_engine", "reply_rate_percent", "100" if ledger.replies > 0 else "0", source_engine="pipeline_engine", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
        samples.append(_sample(archetype, "pipeline_engine", "meeting_rate_percent", "100" if ledger.meeting_ref else "0", source_engine="pipeline_engine", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
    return samples


def learn_from_workers(plan: WorkforcePlan | Mapping[str, Any], workers: Sequence[Mapping[str, Any] | Any], *, archetype: str) -> list[dict[str, Any]]:
    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    samples: list[dict[str, Any]] = []
    for record in workers:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        state = WORKER_LIFECYCLE.State.model_validate(document, context={WORKER_LIFECYCLE.plan_context_key: parsed_plan})
        ledger = state.ledger
        outcomes = ledger.succeeded + ledger.failed + ledger.needs_input + ledger.pending_approval
        if outcomes == 0:
            continue
        at = state.transition_history[-1].command.occurred_at
        engine = str(ledger.engine or "company_workforce")
        samples.append(_sample(archetype, engine, "worker_success_rate", (Decimal(ledger.succeeded) / Decimal(outcomes) * _HUNDRED).quantize(MONEY_QUANTUM), source_engine="company_workforce", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
        if ledger.succeeded > 0:
            samples.append(_sample(archetype, engine, "worker_cost_per_success", (Decimal(str(ledger.total_cost)) / Decimal(ledger.succeeded)).quantize(MONEY_QUANTUM), source_engine="company_workforce", source_ref=str(state.scope.entity_ref), digest=state.state_digest, at=at))
    return samples


def learn_from_cost_register(registers: Sequence[Mapping[str, Any] | Any], *, archetype: str) -> list[dict[str, Any]]:
    """cost_overrun_rate (metered / allocated) per engine-named cost centre from reconciled inference cost registers."""

    samples: list[dict[str, Any]] = []
    for record in registers:
        register = record if isinstance(record, InferenceCostRegister) else InferenceCostRegister.model_validate(dict(detached(record)))
        for centre, rate in cost_overrun_rates(register).items():
            if centre not in _COST_ENGINES:
                continue
            samples.append(_sample(archetype, centre, "cost_overrun_rate", rate, source_engine="inference_cost_register", source_ref=f"register:{register.provider}:{register.period_start[:10]}", digest=register.register_digest, at=register.period_end))
    return samples


# --------------------------------------------------------------------------- #
# Using the priors
# --------------------------------------------------------------------------- #


def priors_for(state: Any, *, engine: str | None = None, metric: str | None = None) -> list[Prior]:
    priors = [Prior.model_validate(value) if not isinstance(value, Prior) else value for value in state.ledger.priors.values()]
    return [prior for prior in priors if (engine is None or prior.engine == engine) and (metric is None or prior.metric == metric)]


def priors_to_assumptions(state: Any, *, engines: Sequence[str], min_samples: int = 2) -> list[dict[str, Any]]:
    """Simulator ``EngineAssumptions`` from the priors: the p10..p90 return band and utilisation band, only where enough was learned."""

    out: list[dict[str, Any]] = []
    for engine in engines:
        returns = priors_for(state, engine=engine, metric="return_on_spend")
        utilisation = priors_for(state, engine=engine, metric="utilisation_percent")
        assumption: dict[str, Any] = {"engine": engine}
        if returns and returns[0].samples >= min_samples:
            assumption["return_on_spend_min"] = str(max(Decimal("0"), returns[0].p10))
            assumption["return_on_spend_max"] = str(max(Decimal("0"), returns[0].p90))
        if utilisation and utilisation[0].samples >= min_samples:
            assumption["utilisation_min_percent"] = str(max(Decimal("0"), min(Decimal("100"), utilisation[0].p10)))
            assumption["utilisation_max_percent"] = str(max(Decimal("0"), min(Decimal("100"), utilisation[0].p90)))
        if len(assumption) > 1:
            out.append(assumption)
    return out


def replan_hints(state: Any) -> dict[str, dict[str, str]]:
    """Per engine: the learned return band the replanner can weigh against a single period's return."""

    hints: dict[str, dict[str, str]] = {}
    for prior in priors_for(state, metric="return_on_spend"):
        hints[prior.engine] = {"mean": str(prior.mean), "p10": str(prior.p10), "p90": str(prior.p90), "samples": str(prior.samples)}
    return hints


def roster_hints(state: Any) -> dict[str, dict[str, str]]:
    hints: dict[str, dict[str, str]] = {}
    for prior in priors_for(state, metric="worker_success_rate"):
        hints[prior.engine] = {"success_rate_mean": str(prior.mean), "samples": str(prior.samples)}
    for prior in priors_for(state, metric="worker_cost_per_success"):
        hints.setdefault(prior.engine, {})["cost_per_success_mean"] = str(prior.mean)
    return hints


def memory_summary(state: Any) -> dict[str, Any]:
    ledger = state.ledger
    return {"archetype": ledger.archetype, "priors": len(ledger.priors), "samples_total": ledger.samples_total, "states_learned": len(ledger.learned_state_digests), "lessons": list(ledger.lessons), "version": state.version, "state_digest": state.state_digest}


MEMORY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": MEMORY_KIND,
    "golden_loop": MEMORY_GOLDEN_LOOP,
    "stages": ["open", "learn_from_states", "fold_priors", "feed_simulator_and_replanner"],
    "metrics": ["return_on_spend", "utilisation_percent", "days_to_close", "close_on_time_rate", "reply_rate_percent", "meeting_rate_percent", "worker_success_rate", "worker_cost_per_success", "cost_overrun_rate", "recommendation_abs_error_percent"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a prior is folded only from sealed states; a state is learned once and its digest is retained",
        "priors carry sample counts and p10/p90 bands; a single period never becomes a certainty",
        "the simulator and replanner consume priors as bands, never as targets",
        "nothing here is model-minted",
    ],
}

__all__ = ["MEMORY_GOLDEN_LOOP", "MEMORY_KIND", "MEMORY_LIFECYCLE", "MEMORY_MANIFEST", "MemoryPlan", "MemoryState", "Prior", "Sample", "advance_memory", "learn_command", "learn_from_closes", "learn_from_cost_register", "learn_from_periods", "learn_from_prospects", "learn_from_workers", "memory_plan", "memory_ref", "memory_summary", "open_memory", "priors_for", "priors_to_assumptions", "replan_hints", "roster_hints"]
