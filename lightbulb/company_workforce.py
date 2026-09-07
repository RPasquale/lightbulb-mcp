"""Workforce binding: Lightbulb agents as the workers of a company's engines.

A company hires Lightbulb agents (domain agents such as ``crm``, ``finance``,
``content``) the way it hires staff: a :class:`WorkerRole` binds one agent to
one engine stage with a budget per operating period, a dispatch cap, and a
ceiling per dispatch.  :func:`compile_workforce` fits a roster inside the
operating plan's envelopes (a stage's workers never out-spend the engine
that pays them), and the replay-fenced worker lifecycle
(``hired → active → paused → released``) fences every dispatch against the
worker's budget, cap, and allowed actions, then records the outcome Spring
returned.

:func:`plan_dispatch` produces the exact payload for
``LightbulbClient.dispatch`` together with the sealed lifecycle command that
will record it, so a harness never types a dispatch by hand; nothing here
dispatches an agent, spends money, or reads a provider.
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
    EngineScope,
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
from lightbulb.company_operating_system import ENGINE_KINDS, CompanyOperatingPlan

WORKFORCE_GOLDEN_LOOP = "workforce.roster_to_governed_dispatch@0.1.0"
WORKFORCE_KIND = "company_workforce"
ROSTER_SCHEMA = "lightbulb.workforce_roster.v1"
PLAN_SCHEMA = "lightbulb.workforce_plan.v1"
DISPATCH_REQUEST_SCHEMA = "lightbulb.workforce_dispatch_request.v1"
ASSESSMENT_SCHEMA = "lightbulb.workforce_assessment.v1"
MAX_WORKER_TRANSITIONS = 120

KNOWN_DOMAINS: tuple[str, ...] = ("finance", "intuit", "crm", "legal", "engineering", "content", "it_ops", "commerce", "product", "hr", "coding", "document_intelligence", "solver", "customer_success", "procurement", "gtm", "grc", "smarthome")
Domain = Literal["finance", "intuit", "crm", "legal", "engineering", "content", "it_ops", "commerce", "product", "hr", "coding", "document_intelligence", "solver", "customer_success", "procurement", "gtm", "grc", "smarthome"]
EngineKind = Literal["growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery", "company_operating_system", "people_engine", "marketplace_supply_engine", "engagement_engine"]
EffectClass = Literal["read_only", "draft", "write_with_approval"]
DispatchOutcome = Literal["succeeded", "failed", "needs_input", "pending_approval"]

WorkerStatus = Literal["hired", "active", "paused", "released"]
WORKER_STATUSES: tuple[str, ...] = ("hired", "active", "paused", "released")
TERMINAL_WORKER_STATUSES: frozenset[str] = frozenset({"released"})
WorkerEvent = Literal["hire", "activate", "dispatch", "record_outcome", "pause", "resume", "release"]
WORKER_EVENTS: tuple[str, ...] = ("hire", "activate", "dispatch", "record_outcome", "pause", "resume", "release")
_WORKER_TABLE: dict[tuple[str, str], str] = {
    ("new", "hire"): "hired",
    ("hired", "activate"): "active",
    ("hired", "release"): "released",
    ("active", "dispatch"): "active",
    ("active", "record_outcome"): "active",
    ("active", "pause"): "paused",
    ("active", "release"): "released",
    ("paused", "record_outcome"): "paused",
    ("paused", "resume"): "active",
    ("paused", "release"): "released",
}
_COST_OVERRUN_TOLERANCE = Decimal("1.25")


def _money(value: Any, name: str, *, minimum: Decimal = Decimal("0")) -> Decimal:
    result = decimal_value(value, field_name=name)
    if result < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return result


# --------------------------------------------------------------------------- #
# Roster and plan
# --------------------------------------------------------------------------- #


class WorkerRole(StrictModel):
    worker_ref: OpaqueRef
    title: ShortText
    domain: Domain
    actions: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    engine: EngineKind
    stage: ShortText
    budget_per_period: Decimal
    max_dispatches_per_period: int = Field(ge=1, le=500)
    max_cost_per_dispatch: Decimal
    effect_class: EffectClass = "draft"
    required_paper_kinds: tuple[OpaqueRef, ...] = ()

    @field_validator("budget_per_period", "max_cost_per_dispatch", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name), minimum=Decimal("0.01"))

    @model_validator(mode="after")
    def _guard(self) -> WorkerRole:
        unique(list(self.actions), label="worker actions")
        if self.max_cost_per_dispatch > self.budget_per_period:
            raise ValueError("a single dispatch cannot cost more than the period budget")
        return self


class WorkforceRoster(StrictModel):
    schema_id: str = Field(default=ROSTER_SCHEMA, alias="schema")
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    workers: tuple[WorkerRole, ...] = Field(min_length=1, max_length=60)

    @model_validator(mode="after")
    def _guard(self) -> WorkforceRoster:
        unique([item.worker_ref for item in self.workers], label="worker refs")
        return self

    def worker(self, ref: str) -> WorkerRole | None:
        return next((item for item in self.workers if item.worker_ref == ref), None)


class EngineAllocation(StrictModel):
    engine: EngineKind
    envelope_budget: Decimal
    workforce_budget: Decimal
    headcount: int = Field(ge=0, le=60)
    worker_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)

    @field_validator("envelope_budget", "workforce_budget", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> EngineAllocation:
        if self.workforce_budget > self.envelope_budget:
            raise ValueError(f"{self.engine} workforce budget exceeds its envelope")
        if self.headcount != len(self.worker_refs):
            raise ValueError("headcount must equal the worker refs")
        return self


class WorkforcePlan(StrictModel):
    schema_id: str = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["workforce.roster_to_governed_dispatch@0.1.0"] = WORKFORCE_GOLDEN_LOOP
    operating_plan_digest: Sha256Digest
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    period_days: int = Field(ge=1, le=92)
    roster: WorkforceRoster
    allocations: tuple[EngineAllocation, ...] = Field(min_length=1, max_length=9)
    total_workforce_budget: Decimal
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total_workforce_budget", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, "total_workforce_budget")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> WorkforcePlan:
        if self.roster.currency != self.currency:
            raise ValueError("roster currency must match the plan currency")
        if sum((item.workforce_budget for item in self.allocations), Decimal("0")) != self.total_workforce_budget:
            raise ValueError("total_workforce_budget must equal the allocations")
        if not skip_digests(info) and self.plan_digest != sealed_digest(WorkforcePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact workforce plan")
        return self

    @property
    def blueprint(self) -> WorkforcePlan:
        return self

    def worker(self, ref: str) -> WorkerRole | None:
        return self.roster.worker(ref)

    def allocation(self, engine: str) -> EngineAllocation | None:
        return next((item for item in self.allocations if item.engine == engine), None)


def compile_workforce(operating_plan: CompanyOperatingPlan | Mapping[str, Any], roster: WorkforceRoster | Mapping[str, Any]) -> WorkforcePlan:
    """Fit a roster inside the operating plan's envelopes; every engine's workers stay under its budget."""

    plan = CompanyOperatingPlan.model_validate(detached(operating_plan))
    parsed_roster = WorkforceRoster.model_validate(detached(roster))
    if parsed_roster.currency != plan.blueprint.currency:
        raise ValueError(f"ROSTER_CURRENCY_MISMATCH: roster pays in {parsed_roster.currency}, the company operates in {plan.blueprint.currency}")
    bound_engines = set(plan.blueprint.engine_kinds) | {"company_operating_system"}
    allocations: list[EngineAllocation] = []
    for engine in (*plan.blueprint.engine_kinds, "company_operating_system"):
        workers = [item for item in parsed_roster.workers if item.engine == engine]
        envelope = plan.envelope(engine)
        envelope_budget = envelope.budget if envelope is not None else plan.blueprint.operating_budget_per_period
        workforce_budget = sum((item.budget_per_period for item in workers), Decimal("0")).quantize(MONEY_QUANTUM)
        if workforce_budget > envelope_budget:
            raise ValueError(f"ENVELOPE_EXCEEDED: {engine} workers cost {workforce_budget} per period against an envelope of {envelope_budget}")
        if not workers and engine == "company_operating_system":
            continue
        allocations.append(EngineAllocation(engine=engine, envelope_budget=envelope_budget, workforce_budget=workforce_budget, headcount=len(workers), worker_refs=tuple(item.worker_ref for item in workers)))
    for item in parsed_roster.workers:
        if item.engine not in bound_engines:
            raise ValueError(f"ENGINE_NOT_BOUND: {item.worker_ref} works {item.engine}, which this company does not run")
    total = sum((item.workforce_budget for item in allocations), Decimal("0")).quantize(MONEY_QUANTUM)
    return seal(WorkforcePlan, {"operating_plan_digest": plan.plan_digest, "currency": plan.blueprint.currency, "period_days": plan.blueprint.period_days, "roster": parsed_roster, "allocations": tuple(allocations), "total_workforce_budget": total}, "plan_digest")


# --------------------------------------------------------------------------- #
# Worker lifecycle
# --------------------------------------------------------------------------- #


class WorkerReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    entity_ref: OpaqueRef | None = None
    worker_ref: OpaqueRef | None = None
    period_ref: OpaqueRef | None = None
    dispatch_ref: OpaqueRef | None = None
    action: ShortText | None = None
    estimated_cost: Decimal | None = None
    actual_cost: Decimal | None = None
    outcome: DispatchOutcome | None = None
    approval_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    dispatch_intent_digest: Sha256Digest | None = None
    dispatch_observation: dict[str, Any] | None = None
    evidence_ref: OpaqueRef | None = None

    @field_validator("estimated_cost", "actual_cost", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name))


class WorkerLedger(StrictModel):
    entity_scope: EngineScope | None = None
    entity_ref: OpaqueRef | None = None
    authorization_proof_digest: Sha256Digest | None = None
    worker_ref: str | None = None
    domain: str | None = None
    engine: str | None = None
    period_ref: str | None = None
    dispatches_this_period: int = Field(default=0, ge=0)
    cost_this_period: Decimal = Decimal("0.00")
    total_dispatches: int = Field(default=0, ge=0)
    total_cost: Decimal = Decimal("0.00")
    open_dispatch_ref: str | None = None
    open_dispatch_estimate: Decimal = Decimal("0.00")
    succeeded: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    needs_input: int = Field(default=0, ge=0)
    pending_approval: int = Field(default=0, ge=0)
    released_reason: str | None = None
    outcome: Literal["working", "released"] = "working"

    @field_validator("cost_this_period", "total_cost", "open_dispatch_estimate", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))


class WorkerEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    agent_dispatched: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_worker(plan: WorkforcePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event = command.receipt, command.event
    if event == "hire":
        if r.entity_scope is not None:
            require(command.expected_state_digest == WORKER_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the retained worker scope must match the opening command")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.worker_ref is not None, "WORKER_MISSING", "hiring names the worker_ref from the roster")
        role = plan.worker(str(r.worker_ref))
        require(role is not None, "WORKER_NOT_ON_ROSTER", f"{r.worker_ref} is not on the workforce roster")
        assert role is not None
        data.update({"entity_ref": r.entity_ref, "worker_ref": role.worker_ref, "domain": role.domain, "engine": role.engine})
    elif event == "dispatch":
        role = plan.worker(str(data["worker_ref"]))
        assert role is not None
        dispatch_ref = r.dispatch_ref
        if r.dispatch_observation is not None:
            from lightbulb.company_execution_bridge import ObservationProvenance
            source = r.dispatch_observation
            observed_request = DispatchRequest.model_validate(source["request"])
            provenance = ObservationProvenance.model_validate(source["provenance"])
            output = source["output"]
            require(data.get("entity_scope") is not None and all(source["scope"].get(key) == data["entity_scope"].get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "DISPATCH_NOT_EVIDENCED", "the host dispatch must belong to this worker's authenticated company and project")
            require(provenance.lane == "host_read" and provenance.source_tool == "host.workforce_dispatch" and provenance.output_digest == stable_digest(output), "DISPATCH_NOT_EVIDENCED", "the dispatch output must be committed by its host journal observation")
            require(output.get("dispatch_request_digest") == observed_request.request_digest and output.get("project_id") == source["scope"]["project_id"] and parsed(provenance.observed_through) <= parsed(command.occurred_at), "DISPATCH_NOT_EVIDENCED", "the host output must bind this exact request, project and completed time")
            intent = {"worker_ref": observed_request.worker_ref, "action": observed_request.action, "message": observed_request.message, "inputs": observed_request.inputs, "period_ref": observed_request.period_ref, "estimated_cost": str(observed_request.estimated_cost), "currency": observed_request.currency}
            require(r.dispatch_intent_digest == stable_digest(intent) and observed_request.worker_ref == role.worker_ref and observed_request.action == r.action and observed_request.period_ref == r.period_ref and observed_request.estimated_cost == r.estimated_cost and observed_request.currency == plan.currency, "DISPATCH_NOT_EVIDENCED", "the observed dispatch must match the approved business intent and roster")
            require(observed_request.authorization_proof == r.authorization_proof, "DISPATCH_NOT_EVIDENCED", "the observed request must retain the consumed authority proof")
            trace = output.get("trace_ref")
            require(isinstance(trace, str) and bool(trace), "DISPATCH_UNTRACED", "the host observation names its execution trace")
            dispatch_ref = trace
        require(data.get("open_dispatch_ref") is None, "DISPATCH_OUTSTANDING", f"record the outcome of {data.get('open_dispatch_ref')} before dispatching again")
        require(dispatch_ref is not None and r.action is not None and r.period_ref is not None and r.estimated_cost is not None, "DISPATCH_MISSING", "a dispatch names its dispatch_ref, action, period_ref, and estimated_cost")
        require(str(r.action) in role.actions, "ACTION_NOT_ALLOWED", f"{role.worker_ref} may run {list(role.actions)}, not {r.action}")
        assert r.estimated_cost is not None
        require(r.estimated_cost <= role.max_cost_per_dispatch, "DISPATCH_TOO_EXPENSIVE", f"estimated {r.estimated_cost} exceeds the {role.max_cost_per_dispatch} ceiling per dispatch")
        if data.get("period_ref") != r.period_ref:
            data.update({"period_ref": r.period_ref, "dispatches_this_period": 0, "cost_this_period": "0.00"})
        require(int(data.get("dispatches_this_period", 0)) < role.max_dispatches_per_period, "WORKER_DISPATCH_CAP", f"{role.worker_ref} reached {role.max_dispatches_per_period} dispatch(es) this period")
        committed = Decimal(str(data.get("cost_this_period", "0"))) + r.estimated_cost
        require(committed <= role.budget_per_period, "WORKER_BUDGET_EXCEEDED", f"{role.worker_ref} would commit {committed} against a period budget of {role.budget_per_period}", "await_approval")
        if role.effect_class == "write_with_approval":
            from lightbulb.authority_matrix import require_authorization_proof

            proof = require_authorization_proof(r.authorization_proof, category="dispatch", amount=r.estimated_cost, currency=plan.currency, command=command, plan_digest=plan.plan_digest, entity_ref=data.get("entity_ref"))
            data["authorization_proof_digest"] = proof.proof_digest
        data.update({"dispatches_this_period": int(data.get("dispatches_this_period", 0)) + 1, "total_dispatches": int(data.get("total_dispatches", 0)) + 1, "open_dispatch_ref": dispatch_ref, "open_dispatch_estimate": str(r.estimated_cost)})
    elif event == "record_outcome":
        require(data.get("open_dispatch_ref") is not None, "NO_OPEN_DISPATCH", "no dispatch awaits an outcome")
        require(r.dispatch_ref == data.get("open_dispatch_ref"), "OUTCOME_UNMATCHED", f"the outcome must name the open dispatch {data.get('open_dispatch_ref')}")
        require(r.outcome is not None and r.actual_cost is not None, "OUTCOME_MISSING", "an outcome names its disposition and actual cost")
        assert r.actual_cost is not None
        estimate = Decimal(str(data.get("open_dispatch_estimate", "0")))
        require(r.actual_cost <= estimate * _COST_OVERRUN_TOLERANCE, "COST_OVERRUN", f"actual cost {r.actual_cost} exceeds the estimate {estimate} by more than 25%; reconcile the agent bill", "manual_reconciliation")
        data.update({"cost_this_period": str((Decimal(str(data.get("cost_this_period", "0"))) + r.actual_cost).quantize(MONEY_QUANTUM)), "total_cost": str((Decimal(str(data.get("total_cost", "0"))) + r.actual_cost).quantize(MONEY_QUANTUM)), "open_dispatch_ref": None, "open_dispatch_estimate": "0.00", str(r.outcome): int(data.get(str(r.outcome), 0)) + 1})
    elif event == "release":
        data.update({"released_reason": command.reason, "outcome": "released"})
    return next_status, data


WORKER_LIFECYCLE = LifecycleSpec(entity="worker", schema_prefix="workforce_worker", statuses=WORKER_STATUSES, terminal=TERMINAL_WORKER_STATUSES, events=WORKER_EVENTS, table=_WORKER_TABLE, opening_event="hire", reason_events=("release", "pause"), apply=_apply_worker, ledger_model=WorkerLedger, receipt_model=WorkerReceipt, effect_boundary_model=WorkerEffectBoundary, plan_model=WorkforcePlan, max_transitions=MAX_WORKER_TRANSITIONS)
WorkerCommand = WORKER_LIFECYCLE.Command
WorkerState = WORKER_LIFECYCLE.State
WorkerTransitionResult = WORKER_LIFECYCLE.TransitionResult
seal_worker_command = WORKER_LIFECYCLE.seal_command
worker_command_digest = WORKER_LIFECYCLE.command_digest


def hire_worker(plan: WorkforcePlan | Mapping[str, Any], scope: Mapping[str, Any] | Any, *, worker_ref: str, hired_at: str, actor_ref: str) -> Any:
    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    return WORKER_LIFECYCLE.open(parsed_plan, scope, opened_at=hired_at, actor_ref=actor_ref, receipt={"worker_ref": worker_ref, "entity_ref": dict(detached(scope))["entity_ref"], "entity_scope": detached(scope)})


def advance_worker(plan: WorkforcePlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return WORKER_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Dispatch planning
# --------------------------------------------------------------------------- #


class DispatchRequest(StrictModel):
    """The exact ``LightbulbClient.dispatch`` call and the lifecycle command that records it."""

    schema_id: str = Field(default=DISPATCH_REQUEST_SCHEMA, alias="schema")
    worker_ref: OpaqueRef
    engine: EngineKind
    domain: Domain
    action: ShortText
    message: BoundedText
    inputs: dict[str, Any] = Field(default_factory=dict)
    period_ref: OpaqueRef
    estimated_cost: Decimal
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    effect_class: EffectClass
    approval_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    client_method: Literal["LightbulbClient.dispatch"] = "LightbulbClient.dispatch"
    executes_nothing: Literal[True] = True
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("estimated_cost", mode="before")
    @classmethod
    def _cost(cls, value: Any) -> Decimal:
        return _money(value, "estimated_cost", minimum=Decimal("0.01"))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> DispatchRequest:
        if len(self.inputs) > 40:
            raise ValueError("dispatch inputs carry at most 40 keys")
        if not skip_digests(info) and self.request_digest != sealed_digest(DispatchRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact dispatch request")
        return self

    def to_client_call(self) -> dict[str, Any]:
        return {"domain": self.domain, "action": self.action, "message": self.message, "inputs": {**self.inputs, "worker_ref": self.worker_ref, "engine": self.engine, "period_ref": self.period_ref, "estimated_cost": str(self.estimated_cost), "currency": self.currency, "dispatch_request_digest": self.request_digest}}


def plan_dispatch(plan: WorkforcePlan | Mapping[str, Any], state: Any, *, action: str, message: str, period_ref: str, estimated_cost: Any, inputs: Mapping[str, Any] | None = None, approval_ref: str | None = None, authorization_proof: Mapping[str, Any] | Any | None = None, paper_sources: Sequence[Mapping[str, Any]] = (), now: str | None = None, company_ref: str | None = None) -> DispatchRequest:
    """Check the dispatch against the worker's role and budget before any call is made; returns the call payload."""

    parsed_plan, parsed_state = WORKER_LIFECYCLE.bind(plan, state)
    role = parsed_plan.worker(str(parsed_state.ledger.worker_ref))
    if role is None:
        raise ValueError("WORKER_NOT_ON_ROSTER: the worker is not on this plan's roster")
    if parsed_state.status != "active":
        raise ValueError(f"WORKER_NOT_ACTIVE: {role.worker_ref} is {parsed_state.status}")
    if action not in role.actions:
        raise ValueError(f"ACTION_NOT_ALLOWED: {role.worker_ref} may run {list(role.actions)}, not {action}")
    if role.required_paper_kinds:
        from lightbulb.obligation_paper import verify_paper_current
        if now is None or company_ref is None:
            raise ValueError("LICENCE_NOT_CURRENT: dispatch requires the company and current paper verification clock")
        for kind in role.required_paper_kinds:
            valid = []
            for source in paper_sources:
                try:
                    valid.append(verify_paper_current(source.get("state"), source_plan=source.get("plan"), company_ref=company_ref, currency=parsed_plan.currency, at=now, kind=kind, holder_ref=role.worker_ref, expected_scope=parsed_state.scope))
                except ValueError:
                    continue
            if not valid:
                raise ValueError(f"LICENCE_NOT_CURRENT: {role.worker_ref} requires current {kind} paper")
    cost = _money(estimated_cost, "estimated_cost", minimum=Decimal("0.01"))
    if cost > role.max_cost_per_dispatch:
        raise ValueError(f"DISPATCH_TOO_EXPENSIVE: {cost} exceeds the {role.max_cost_per_dispatch} ceiling")
    ledger = parsed_state.ledger
    committed = (ledger.cost_this_period if ledger.period_ref == period_ref else Decimal("0")) + cost
    if committed > role.budget_per_period:
        raise ValueError(f"WORKER_BUDGET_EXCEEDED: {committed} against a period budget of {role.budget_per_period}")
    if ledger.open_dispatch_ref is not None:
        raise ValueError(f"DISPATCH_OUTSTANDING: record the outcome of {ledger.open_dispatch_ref} first")
    proof = None
    if role.effect_class == "write_with_approval":
        from lightbulb.authority_matrix import AuthorizationProof, verify_authorization

        if authorization_proof is None:
            raise ValueError("APPROVAL_NOT_BOUND: a write dispatch requires a bound authority proof")
        source = AuthorizationProof.model_validate(detached(authorization_proof))
        approved = source.approved_command
        receipt = approved["receipt"]
        intent = {"worker_ref": role.worker_ref, "action": action, "message": message, "inputs": dict(detached(inputs or {})), "period_ref": period_ref, "estimated_cost": str(cost), "currency": parsed_plan.currency}
        if receipt.get("dispatch_intent_digest") != stable_digest(intent):
            raise ValueError("APPROVAL_TRANSITION_MISMATCH: the approval must commit the exact dispatch message, inputs and cost")
        if approved["expected_state_digest"] != parsed_state.state_digest or approved["expected_version"] != parsed_state.version or receipt.get("action") != action or receipt.get("period_ref") != period_ref:
            raise ValueError("APPROVAL_TRANSITION_MISMATCH: the proof must bind this worker state, action and period")
        proof = verify_authorization(source, category="dispatch", amount=cost, currency=parsed_plan.currency, command=approved, plan_digest=parsed_plan.plan_digest, entity_ref=parsed_state.scope.entity_ref)
    payload = {"worker_ref": role.worker_ref, "engine": role.engine, "domain": role.domain, "action": action, "message": message, "inputs": dict(detached(inputs or {})), "period_ref": period_ref, "estimated_cost": cost, "currency": parsed_plan.currency, "effect_class": role.effect_class, "approval_ref": proof.approval_task_id if proof else None, "authorization_proof": proof.to_dict() if proof else None}
    return seal(DispatchRequest, payload, "request_digest")


def dispatch_receipt_from_result(request: DispatchRequest | Mapping[str, Any], result: Mapping[str, Any] | Any, *, provenance: Any = None, scope: Any = None) -> dict[str, Any]:
    """The ``dispatch`` receipt for the worker lifecycle from the platform's dispatch result (its trace id is the dispatch_ref)."""

    parsed_request = request if isinstance(request, DispatchRequest) else DispatchRequest.model_validate(dict(detached(request)))
    raw = dict(detached(result)) if isinstance(result, Mapping) else {"trace_id": getattr(result, "trace_id", None), "conversation_id": getattr(result, "conversation_id", None)}
    trace = raw.get("trace_id") or raw.get("traceId")
    if not trace:
        raise ValueError("DISPATCH_UNTRACED: the platform result carries no trace id; nothing was dispatched")
    if parsed_request.authorization_proof is not None:
        from lightbulb.company_execution_bridge import ObservationProvenance
        if provenance is None or scope is None:
            raise ValueError("DISPATCH_NOT_EVIDENCED: an authorized write needs the host dispatch journal observation binding its request digest")
        observation = ObservationProvenance.model_validate(detached(provenance))
        output = {"trace_ref": f"trace:{trace}", "dispatch_request_digest": parsed_request.request_digest, "project_id": dict(detached(scope))["project_id"]}
        if observation.output_digest != stable_digest(output) or observation.source_tool != "host.workforce_dispatch":
            raise ValueError("DISPATCH_NOT_EVIDENCED: the host observation differs from this request and result")
        return {**parsed_request.authorization_proof["approved_command"]["receipt"], "authorization_proof": parsed_request.authorization_proof, "dispatch_observation": {"request": parsed_request.to_dict(), "provenance": observation.to_dict(), "output": output, "scope": detached(scope)}}
    return {"worker_ref": parsed_request.worker_ref, "period_ref": parsed_request.period_ref, "dispatch_ref": f"trace:{trace}", "action": parsed_request.action, "estimated_cost": str(parsed_request.estimated_cost), "approval_ref": parsed_request.approval_ref, "authorization_proof": parsed_request.authorization_proof, "evidence_ref": f"dispatch:{parsed_request.request_digest[:24]}"}


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


class WorkerHealth(StrictModel):
    worker_ref: OpaqueRef
    engine: EngineKind
    status: str
    dispatches: int = Field(ge=0)
    cost: Decimal
    budget_per_period: Decimal
    success_rate_percent: Decimal | None = None
    cost_per_success: Decimal | None = None

    @field_validator("cost", "budget_per_period", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("success_rate_percent", "cost_per_success", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name))


class WorkforceAssessment(StrictModel):
    schema_id: str = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    assessed_at: str
    workers: tuple[WorkerHealth, ...] = Field(default_factory=tuple, max_length=60)
    active: int = Field(ge=0)
    released: int = Field(ge=0)
    total_dispatches: int = Field(ge=0)
    total_cost: Decimal
    workforce_budget: Decimal
    cost_by_engine: dict[str, Decimal] = Field(default_factory=dict)
    learnings: tuple[BoundedText, ...] = Field(min_length=1, max_length=12)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @field_validator("total_cost", "workforce_budget", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("cost_by_engine", mode="before")
    @classmethod
    def _map(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): _money(item, "cost_by_engine") for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> WorkforceAssessment:
        if not skip_digests(info) and self.assessment_digest != sealed_digest(WorkforceAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_workforce(plan: WorkforcePlan | Mapping[str, Any], states: Sequence[Any], *, assessed_at: str) -> WorkforceAssessment:
    parsed_plan = WorkforcePlan.model_validate(detached(plan))
    bound = [WORKER_LIFECYCLE.bind(parsed_plan, item)[1] for item in states]
    unique([str(item.ledger.worker_ref) for item in bound], label="assessed workers")
    rows: list[WorkerHealth] = []
    cost_by_engine: dict[str, Decimal] = {}
    learnings: list[str] = []
    for state in bound:
        role = parsed_plan.worker(str(state.ledger.worker_ref))
        assert role is not None
        ledger = state.ledger
        outcomes = ledger.succeeded + ledger.failed + ledger.needs_input + ledger.pending_approval
        rate = (Decimal(ledger.succeeded) / Decimal(outcomes) * Decimal("100")).quantize(Decimal("0.01")) if outcomes else None
        per_success = (ledger.total_cost / Decimal(ledger.succeeded)).quantize(MONEY_QUANTUM) if ledger.succeeded else None
        rows.append(WorkerHealth(worker_ref=role.worker_ref, engine=role.engine, status=state.status, dispatches=ledger.total_dispatches, cost=ledger.total_cost, budget_per_period=role.budget_per_period, success_rate_percent=rate, cost_per_success=per_success))
        cost_by_engine[role.engine] = (cost_by_engine.get(role.engine, Decimal("0")) + ledger.total_cost).quantize(MONEY_QUANTUM)
        if rate is not None and rate < Decimal("50"):
            learnings.append(f"{role.worker_ref} succeeds on {rate}% of dispatches; review its actions or release it")
        if ledger.total_dispatches >= 3 and ledger.succeeded == 0:
            learnings.append(f"{role.worker_ref} has no successful dispatch after {ledger.total_dispatches}")
        if ledger.open_dispatch_ref is not None:
            learnings.append(f"{role.worker_ref} has an unreconciled dispatch {ledger.open_dispatch_ref}")
    total_cost = sum((item.cost for item in rows), Decimal("0")).quantize(MONEY_QUANTUM)
    if not rows:
        learnings.append("no workers hired yet; hire against the roster before dispatching")
    if not learnings:
        learnings.append("workforce is operating inside its budgets and caps")
    return seal(WorkforceAssessment, {"plan_digest": parsed_plan.plan_digest, "assessed_at": assessed_at, "workers": tuple(rows), "active": sum(1 for item in bound if item.status == "active"), "released": sum(1 for item in bound if item.status == "released"), "total_dispatches": sum(item.dispatches for item in rows), "total_cost": total_cost, "workforce_budget": parsed_plan.total_workforce_budget, "cost_by_engine": cost_by_engine, "learnings": tuple(learnings[:12])}, "assessment_digest")


STANDARD_ROSTERS: Mapping[str, dict[str, Any]] = {
    "b2b_saas": {"currency": "CAD", "workers": [
        {"worker_ref": "w-growth-content", "title": "Growth content producer", "domain": "content", "actions": ["generate_plan", "generate_content", "generate_variants"], "engine": "growth_engine", "stage": "compose_candidates", "budget_per_period": "600", "max_dispatches_per_period": 30, "max_cost_per_dispatch": "40", "effect_class": "draft"},
        {"worker_ref": "w-crm-sdr", "title": "Outbound SDR", "domain": "crm", "actions": ["lead_qualification", "outbound_messaging", "classify_reply", "plan_sequence"], "engine": "pipeline_engine", "stage": "compose_touches", "budget_per_period": "900", "max_dispatches_per_period": 60, "max_cost_per_dispatch": "30", "effect_class": "write_with_approval"},
        {"worker_ref": "w-product-triage", "title": "Support and roadmap analyst", "domain": "product", "actions": ["feedback_synthesis", "roadmap_prioritize", "feature_adoption"], "engine": "saas_operating_engine", "stage": "rank_roadmap", "budget_per_period": "500", "max_dispatches_per_period": 20, "max_cost_per_dispatch": "50", "effect_class": "read_only"},
        {"worker_ref": "w-finance-close", "title": "Close accountant", "domain": "finance", "actions": ["xero_close_books", "xero_bank_reconciliation", "finance_anomaly_investigation"], "engine": "finance_close", "stage": "reconcile", "budget_per_period": "400", "max_dispatches_per_period": 10, "max_cost_per_dispatch": "80", "effect_class": "draft"},
    ]},
    "dtc_commerce": {"currency": "AUD", "workers": [
        {"worker_ref": "w-commerce-merch", "title": "Merchandiser", "domain": "commerce", "actions": ["product_analysis", "pricing_intelligence", "campaign_brief"], "engine": "growth_engine", "stage": "plan_portfolio", "budget_per_period": "700", "max_dispatches_per_period": 40, "max_cost_per_dispatch": "35", "effect_class": "draft"},
        {"worker_ref": "w-cs-agent", "title": "Customer service agent", "domain": "customer_success", "actions": ["churn_risk_scan", "nps_action_loop"], "engine": "service_delivery", "stage": "resolve", "budget_per_period": "300", "max_dispatches_per_period": 50, "max_cost_per_dispatch": "10", "effect_class": "draft"},
        {"worker_ref": "w-finance-close", "title": "Close accountant", "domain": "finance", "actions": ["xero_close_books", "xero_bank_reconciliation"], "engine": "finance_close", "stage": "reconcile", "budget_per_period": "400", "max_dispatches_per_period": 10, "max_cost_per_dispatch": "80", "effect_class": "draft"},
    ]},
}


_PEOPLE_WORKER = {"worker_ref": "w-people-ops", "title": "People operations analyst", "domain": "hr",
                  "actions": ["payroll_context"], "engine": "people_engine", "stage": "assess_capacity",
                  "budget_per_period": "150", "max_dispatches_per_period": 10,
                  "max_cost_per_dispatch": "25", "effect_class": "read_only"}
for _archetype in ("b2b_saas", "dtc_commerce"):
    STANDARD_ROSTERS[_archetype] = {**STANDARD_ROSTERS[_archetype],
                                  "workers": [*STANDARD_ROSTERS[_archetype]["workers"], dict(_PEOPLE_WORKER)]}

_ROLE_TEMPLATES = {role["engine"]: role for role in STANDARD_ROSTERS["b2b_saas"]["workers"]}
_ROLE_TEMPLATES["service_delivery"] = STANDARD_ROSTERS["dtc_commerce"]["workers"][1]
_ROLE_TEMPLATES["marketplace_supply_engine"] = {
    **STANDARD_ROSTERS["dtc_commerce"]["workers"][0], "worker_ref": "w-marketplace-supply",
    "title": "Marketplace supply analyst", "engine": "marketplace_supply_engine", "stage": "assess_supply",
    "actions": ["product_analysis"], "effect_class": "read_only",
}
from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES as _COMPANY_ARCHETYPES

for _archetype in ("services_firm", "marketplace", "founder_led_saas", "local_services", "two_sided_marketplace"):
    _blueprint = _COMPANY_ARCHETYPES[_archetype]
    STANDARD_ROSTERS[_archetype] = {"currency": _blueprint["currency"],
                                  "workers": [dict(_ROLE_TEMPLATES[item["engine"]]) for item in _blueprint["engines"]]}


def standard_roster(archetype: str) -> WorkforceRoster:
    if archetype not in STANDARD_ROSTERS:
        raise ValueError(f"unknown standard roster {archetype!r}; known: {sorted(STANDARD_ROSTERS)}")
    return WorkforceRoster.model_validate(STANDARD_ROSTERS[archetype])


WORKFORCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": WORKFORCE_KIND,
    "golden_loop": WORKFORCE_GOLDEN_LOOP,
    "stages": ["roster", "fit_to_envelopes", "hire", "dispatch", "record_outcome", "assess"],
    "domains": list(KNOWN_DOMAINS),
    "engines": list(ENGINE_KINDS) + ["company_operating_system"],
    "worker_statuses": list(WORKER_STATUSES),
    "worker_events": list(WORKER_EVENTS),
    "required_connectors": ["lightbulb.domain_agents"],
    "hard_rules": ["a stage's workers never out-spend the engine envelope that pays them", "every dispatch is fenced by the worker's actions, budget, cap, and ceiling", "writes need an approval reference before dispatch", "outcomes reconcile against the open dispatch and its estimate"],
}

__all__ = [
    "KNOWN_DOMAINS",
    "STANDARD_ROSTERS",
    "TERMINAL_WORKER_STATUSES",
    "WORKER_EVENTS",
    "WORKER_LIFECYCLE",
    "WORKER_STATUSES",
    "WORKFORCE_GOLDEN_LOOP",
    "WORKFORCE_KIND",
    "WORKFORCE_MANIFEST",
    "DispatchRequest",
    "EngineAllocation",
    "WorkerCommand",
    "WorkerEffectBoundary",
    "WorkerHealth",
    "WorkerLedger",
    "WorkerReceipt",
    "WorkerRole",
    "WorkerState",
    "WorkerTransitionResult",
    "WorkforceAssessment",
    "WorkforcePlan",
    "WorkforceRoster",
    "advance_worker",
    "assess_workforce",
    "compile_workforce",
    "dispatch_receipt_from_result",
    "hire_worker",
    "plan_dispatch",
    "seal_worker_command",
    "standard_roster",
    "worker_command_digest",
]
