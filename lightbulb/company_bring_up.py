"""Company bring-up: from a formed company to a running, scheduled cadence, behind readiness gates.

``create_company`` forms a company; the operating engines assume a compiled
bundle, hired workers, an open period, a started cadence, and a scheduler
checkpoint.  Nothing joined those steps, so a new operator had to know the
order and the fences.  Bring-up is that order as a replay-fenced lifecycle:

    formed -> connectors_verified -> workforce_hired -> period_opened
           -> cadence_started -> scheduled -> live        (abandoned is terminal)

Each transition consumes a receipt that names a fact the platform produced
(the sealed connection readiness, the persisted worker states, the period
state digest, the cadence state digest, the checkpoint revision); the
lifecycle refuses to advance on a claim.  ``assess_readiness`` is the gate
that matters most: it compares the connectors the bundle's engines need
against the OAuth connections the account actually holds and says exactly
which engine is blocked by which missing provider, so an operator either
connects the provider or compiles a bundle without that engine.

``BringUpOrchestrator`` composes the existing runtimes (workforce, cadence,
hosted scheduler) to walk the lifecycle against a client and a store.  It
executes nothing itself: hiring persists engine states, opening a period is
the cadence runner's own automatic action, and scheduling writes a
checkpoint; every effect goes through the same fences as before.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_cadence_runner import CadenceBundle, CadenceWorker, CompanyCadenceRunner, build_bundle
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_hosted_scheduler import CheckpointGateway, HostedCadenceScheduler
from lightbulb.company_workforce import WORKER_LIFECYCLE, advance_worker, hire_worker

BRING_UP_KIND = "company_bring_up"
BRING_UP_GOLDEN_LOOP = "company.formed_to_running_cadence@0.1.0"
READINESS_SCHEMA = "lightbulb.company_connector_readiness.v1"
MAX_BRING_UP_TRANSITIONS = 64

BRING_UP_STATUSES: tuple[str, ...] = ("formed", "connectors_verified", "workforce_hired", "period_opened", "cadence_started", "scheduled", "live", "abandoned")
TERMINAL_BRING_UP_STATUSES: frozenset[str] = frozenset({"live", "abandoned"})
BRING_UP_EVENTS: tuple[str, ...] = ("form", "verify_connectors", "verify_paper", "hire_workforce", "open_period", "start_cadence", "schedule", "go_live", "abandon")
_BRING_UP_TABLE: dict[tuple[str, str], str] = {
    ("new", "form"): "formed",
    ("formed", "verify_connectors"): "connectors_verified",
    ("connectors_verified", "verify_connectors"): "connectors_verified",
    ("connectors_verified", "verify_paper"): "connectors_verified",
    ("connectors_verified", "hire_workforce"): "workforce_hired",
    ("workforce_hired", "open_period"): "period_opened",
    ("period_opened", "start_cadence"): "cadence_started",
    ("cadence_started", "schedule"): "scheduled",
    ("scheduled", "go_live"): "live",
    **{(status, "abandon"): "abandoned" for status in ("formed", "connectors_verified", "workforce_hired", "period_opened", "cadence_started", "scheduled")},
}

# Which connected providers satisfy each engine. Each inner tuple is a group of
# alternatives; an engine is ready when every group has at least one connected
# provider. Providers are the platform's normalized OAuth provider names.
ENGINE_CONNECTOR_GROUPS: Mapping[str, tuple[tuple[str, ...], ...]] = {
    "company_operating_system": (("stripe", "xero", "quickbooks"),),
    "growth_engine": (("shopify", "google_analytics", "meta_ads", "google_ads"),),
    "pipeline_engine": (("gmail", "microsoft"), ("hubspot", "salesforce")),
    "saas_operating_engine": (("stripe",), ("posthog", "mixpanel"), ("github",)),
    "finance_close": (("xero", "quickbooks"),),
    "service_delivery": (("gmail", "zendesk", "intercom", "freshservice", "microsoft"),),
    "company_workforce": (),
}
_PROVIDER_ALIASES: Mapping[str, str] = {"google-analytics": "google_analytics", "ga4": "google_analytics", "microsoft365": "microsoft", "microsoft_365": "microsoft", "m365": "microsoft", "google_workspace": "gmail", "google": "gmail", "intuit": "quickbooks", "meta": "meta_ads", "facebook_ads": "meta_ads"}


def normalize_provider(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")
    return _PROVIDER_ALIASES.get(text, text)


class ConnectedProvider(StrictModel):
    provider: ShortText
    connection_scope: ShortText
    expires_at: str | None = None
    connection_digest: Sha256Digest


class EngineReadiness(StrictModel):
    engine: ShortText
    required_groups: tuple[tuple[ShortText, ...], ...] = Field(default_factory=tuple, max_length=8)
    satisfied_by: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=16)
    missing_groups: tuple[tuple[ShortText, ...], ...] = Field(default_factory=tuple, max_length=8)
    ready: bool

    @field_validator("required_groups", "missing_groups", "satisfied_by", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        if isinstance(value, (list, tuple)):
            return tuple(tuple(item) if isinstance(item, (list, tuple)) else item for item in value)
        return value


class ConnectorReadiness(StrictModel):
    """Sealed comparison of the bundle's connector needs against the account's active connections."""

    schema_id: str = Field(default=READINESS_SCHEMA, alias="schema")
    bundle_digest: Sha256Digest
    assessed_at: str
    connected: tuple[ConnectedProvider, ...] = Field(default_factory=tuple, max_length=120)
    engines: tuple[EngineReadiness, ...] = Field(min_length=1, max_length=8)
    ready: bool
    blocked_engines: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    ignored_connections: int = Field(default=0, ge=0)
    readiness_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ConnectorReadiness:
        if self.ready != all(item.ready for item in self.engines):
            raise ValueError("ready must equal every engine being ready")
        if tuple(item.engine for item in self.engines if not item.ready) != self.blocked_engines:
            raise ValueError("blocked_engines must list exactly the engines that are not ready")
        if not skip_digests(info) and self.readiness_digest != sealed_digest(ConnectorReadiness, self, "readiness_digest"):
            raise ValueError("readiness_digest must commit the exact readiness")
        return self

    def missing_providers(self) -> dict[str, list[str]]:
        return {item.engine: [" or ".join(group) for group in item.missing_groups] for item in self.engines if not item.ready}


def _active(row: Mapping[str, Any], *, now: str, company_id: str | None) -> bool:
    if str(row.get("status", "")).lower() != "active":
        return False
    expires = row.get("expiresAt") or row.get("expires_at")
    if expires:
        try:
            if parsed(str(expires).replace(" ", "T") if "T" in str(expires) else str(expires)) <= parsed(now):
                return False
        except ValueError:
            return False
    scope = str(row.get("connectionScope") or row.get("connection_scope") or "").lower()
    row_company = row.get("companyId") or row.get("company_id")
    if company_id is not None and row_company not in (None, "") and str(row_company) != str(company_id) and scope == "company":
        return False
    return True


def assess_readiness(bundle: CadenceBundle | Mapping[str, Any], connections: Sequence[Mapping[str, Any]], *, now: str, company_id: str | None = None) -> ConnectorReadiness:
    """Compare the bundle's engines against active OAuth connections; pure, deterministic, sealed."""

    parsed_bundle = build_bundle(bundle)
    stamp = timestamp(now, field_name="now")
    connected: dict[str, dict[str, Any]] = {}
    ignored = 0
    for row in connections:
        raw = dict(detached(row))
        if not _active(raw, now=stamp, company_id=company_id):
            ignored += 1
            continue
        provider = normalize_provider(raw.get("provider"))
        if not provider:
            ignored += 1
            continue
        scope = str(raw.get("connectionScope") or raw.get("connection_scope") or "unknown").lower()
        expires = raw.get("expiresAt") or raw.get("expires_at")
        entry = {"provider": provider, "connection_scope": scope, "expires_at": None if not expires else timestamp(str(expires), field_name="expires_at") if str(expires).endswith("Z") else None, "connection_digest": stable_digest({"provider": provider, "scope": scope, "id": str(raw.get("id", ""))})}
        connected.setdefault(provider, entry)
    providers = set(connected)
    engines = ["company_operating_system", *parsed_bundle.operating_plan.blueprint.engine_kinds]
    if parsed_bundle.workforce_plan is not None:
        engines.append("company_workforce")
    rows: list[dict[str, Any]] = []
    for engine in engines:
        groups = ENGINE_CONNECTOR_GROUPS.get(engine, ())
        satisfied = sorted({provider for group in groups for provider in group if provider in providers})
        missing = [group for group in groups if not any(provider in providers for provider in group)]
        rows.append({"engine": engine, "required_groups": [list(group) for group in groups], "satisfied_by": satisfied, "missing_groups": [list(group) for group in missing], "ready": not missing})
    return seal(
        ConnectorReadiness,
        {"bundle_digest": parsed_bundle.plan_digest, "assessed_at": stamp, "connected": sorted(connected.values(), key=lambda item: item["provider"]), "engines": rows, "ready": all(row["ready"] for row in rows), "blocked_engines": [row["engine"] for row in rows if not row["ready"]], "ignored_connections": ignored},
        "readiness_digest",
    )


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


class BringUpReceipt(StrictModel):
    paper_sources: tuple[dict[str, Any], ...] = ()
    worker_sources: tuple[dict[str, Any], ...] = ()
    bundle_digest: Sha256Digest | None = None
    formed_company_ref: OpaqueRef | None = None
    readiness_digest: Sha256Digest | None = None
    ready: bool | None = None
    blocked_engines: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    worker_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)
    worker_state_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=60)
    period_ref: OpaqueRef | None = None
    period_state_digest: Sha256Digest | None = None
    cadence_ref: OpaqueRef | None = None
    cadence_state_digest: Sha256Digest | None = None
    checkpoint_run_ref: OpaqueRef | None = None
    checkpoint_revision: int | None = Field(default=None, ge=1)
    resume_at: str | None = None
    launch_gate_digest: Sha256Digest | None = None
    instruments_ready: bool | None = None
    blocked_instruments: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)

    @field_validator("worker_refs", "worker_state_digests", "blocked_engines", "blocked_instruments", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class BringUpLedger(StrictModel):
    paper_sources: tuple[dict[str, Any], ...] = ()
    paper_source_digests: tuple[Sha256Digest, ...] = ()
    paper_verified_at: str | None = None
    bundle_digest: str | None = None
    formed_company_ref: str | None = None
    readiness_digest: str | None = None
    launch_gate_digest: str | None = None
    readiness_checks: int = Field(default=0, ge=0)
    blocked_engines: tuple[str, ...] = Field(default_factory=tuple)
    workers_hired: int = Field(default=0, ge=0)
    worker_refs: tuple[str, ...] = Field(default_factory=tuple)
    period_ref: str | None = None
    cadence_ref: str | None = None
    checkpoint_run_ref: str | None = None
    checkpoint_revision: int | None = None
    first_tick_at: str | None = None
    live_at: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["in_progress", "live", "abandoned"] = "in_progress"

    @field_validator("blocked_engines", "worker_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class BringUpEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    agent_dispatched: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _verify_required_paper(plan: CadenceBundle, sources: Any, *, at: str) -> tuple[str, ...]:
    from lightbulb.obligation_paper import verify_paper_current
    digests = []
    for kind in plan.required_paper_kinds:
        valid = []
        for source in sources:
            try:
                valid.append(verify_paper_current(source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.operating_plan.blueprint.currency, at=at, kind=kind, expected_scope=plan.engine_scope("bring-up-paper")))
            except ValueError:
                continue
        require(bool(valid), "LICENCE_NOT_CURRENT", f"bring-up requires current {kind} paper in the company's execution scope")
        digests.extend(item.state_digest for item in valid)
    return tuple(sorted(set(digests)))


def _apply_bring_up(plan: CadenceBundle, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event = command.receipt, command.event
    if event == "form":
        require(r.bundle_digest == plan.bundle_digest, "BUNDLE_MISMATCH", "bring-up starts against this exact bundle")
        require(r.formed_company_ref is not None, "COMPANY_REF_MISSING", "bring-up names the formed company by an opaque ref")
        data.update({"bundle_digest": r.bundle_digest, "formed_company_ref": r.formed_company_ref})
    elif event == "verify_connectors":
        require(r.readiness_digest is not None and r.ready is not None, "READINESS_MISSING", "connector verification carries the sealed readiness digest and verdict")
        require(bool(r.ready), "CONNECTORS_NOT_READY", f"engines blocked by missing connectors: {', '.join(r.blocked_engines) or 'unknown'}; connect a provider or compile a bundle without them", "correct_input")
        data.update({"readiness_digest": r.readiness_digest, "readiness_checks": int(data.get("readiness_checks", 0)) + 1, "blocked_engines": ()})
        if r.launch_gate_digest is not None:
            require(bool(r.instruments_ready), "INSTRUMENTS_NOT_READY", f"instruments not active: {', '.join(r.blocked_instruments) or 'unknown'}; complete the named human steps or withdraw the instrument", "correct_input")
            data["launch_gate_digest"] = r.launch_gate_digest
    elif event == "verify_paper":
        digests = _verify_required_paper(plan, r.paper_sources, at=command.occurred_at)
        data.update(paper_sources=list(r.paper_sources), paper_source_digests=list(digests), paper_verified_at=command.occurred_at)
    elif event == "hire_workforce":
        require(plan.workforce_plan is not None and bool(plan.workforce_plan.roster.workers), "ROSTER_MISSING", "bring-up requires a staffed workforce plan")
        _verify_required_paper(plan, data.get("paper_sources", ()), at=command.occurred_at)
        expected = tuple(role.worker_ref for role in plan.workforce_plan.roster.workers) if plan.workforce_plan is not None else ()
        require(tuple(r.worker_refs) == expected, "ROSTER_MISMATCH", f"the hired workers must be exactly the roster: {list(expected)}")
        require(len(r.worker_state_digests) == len(r.worker_refs) and all(item != GENESIS_DIGEST for item in r.worker_state_digests), "WORKER_STATES_MISSING", "every hired worker names its persisted state digest")
        if r.worker_sources or plan.required_paper_kinds:
            require(len(r.worker_sources) == len(expected), "WORKER_STATES_MISSING", "retain every hired worker's replayable state")
            workers = []
            for source in r.worker_sources:
                try:
                    _, worker = WORKER_LIFECYCLE.bind(plan.workforce_plan, source)
                except ValueError:
                    require(False, "WORKER_STATES_MISSING", "worker state does not replay under this workforce plan")
                require(worker.status == "active" and all(getattr(worker.scope, key) == plan.engine_scope(worker.scope.entity_ref)[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "WORKER_STATES_MISSING", "each worker must be active in the company's execution scope")
                workers.append(worker)
            require(tuple(worker.ledger.worker_ref for worker in workers) == expected and tuple(worker.state_digest for worker in workers) == r.worker_state_digests, "ROSTER_MISMATCH", "the worker sources must exactly match the roster and supplied digests")
        data.update({"workers_hired": len(r.worker_refs), "worker_refs": tuple(r.worker_refs)})
    elif event == "open_period":
        require(r.period_ref is not None and r.period_state_digest not in (None, GENESIS_DIGEST), "PERIOD_MISSING", "opening names the persisted period and its state digest")
        data.update({"period_ref": r.period_ref})
    elif event == "start_cadence":
        require(r.cadence_ref is not None and r.cadence_state_digest not in (None, GENESIS_DIGEST), "CADENCE_MISSING", "starting names the persisted cadence state")
        data.update({"cadence_ref": r.cadence_ref})
    elif event == "schedule":
        require(r.checkpoint_run_ref is not None and r.checkpoint_revision is not None and r.resume_at is not None, "CHECKPOINT_MISSING", "scheduling names the checkpoint, its revision, and the first tick")
        require(parsed(timestamp(r.resume_at, field_name="resume_at")) >= parsed(command.occurred_at), "FIRST_TICK_IN_PAST", "the first tick is scheduled at or after now")
        data.update({"checkpoint_run_ref": r.checkpoint_run_ref, "checkpoint_revision": r.checkpoint_revision, "first_tick_at": r.resume_at})
    elif event == "go_live":
        _verify_required_paper(plan, data.get("paper_sources", ()), at=command.occurred_at)
        require(all(data.get(key) for key in ("readiness_digest", "period_ref", "cadence_ref", "checkpoint_run_ref")), "GATES_INCOMPLETE", "every gate must have passed before the company is live")
        data.update({"live_at": command.occurred_at, "outcome": "live"})
    elif event == "abandon":
        data.update({"abandon_reason": command.reason, "outcome": "abandoned"})
    return next_status, data


BRING_UP_LIFECYCLE = LifecycleSpec(entity="bring_up", schema_prefix=BRING_UP_KIND, statuses=BRING_UP_STATUSES, terminal=TERMINAL_BRING_UP_STATUSES, events=BRING_UP_EVENTS, table=_BRING_UP_TABLE, opening_event="form", reason_events=("abandon",), apply=_apply_bring_up, ledger_model=BringUpLedger, receipt_model=BringUpReceipt, effect_boundary_model=BringUpEffectBoundary, plan_model=CadenceBundle, max_transitions=MAX_BRING_UP_TRANSITIONS)
BringUpState = BRING_UP_LIFECYCLE.State


def bring_up_ref(bundle: CadenceBundle) -> str:
    return f"{bundle.company_ref}:bring-up"


def start_bring_up(bundle: CadenceBundle | Mapping[str, Any], *, formed_company_ref: str, formed_at: str) -> Any:
    parsed_bundle = build_bundle(bundle)
    return BRING_UP_LIFECYCLE.open(parsed_bundle, parsed_bundle.engine_scope(bring_up_ref(parsed_bundle)), opened_at=formed_at, actor_ref=parsed_bundle.actor_ref, receipt={"bundle_digest": parsed_bundle.bundle_digest, "formed_company_ref": formed_company_ref})


def advance_bring_up(bundle: CadenceBundle | Mapping[str, Any], state: Any, command: Any) -> Any:
    return BRING_UP_LIFECYCLE.advance(bundle, state, command)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


class BringUpStep(StrictModel):
    event: ShortText
    outcome: Literal["applied", "rejected", "skipped"]
    to_status: ShortText | None = None
    rejection_code: ShortText | None = None
    detail: BoundedText | None = None


class BringUpReport(StrictModel):
    schema_id: str = Field(default="lightbulb.company_bring_up_report.v1", alias="schema")
    company_ref: OpaqueRef
    bundle_digest: Sha256Digest
    status: ShortText
    steps: tuple[BringUpStep, ...] = Field(default_factory=tuple, max_length=16)
    readiness: ConnectorReadiness | None = None
    live: bool
    report_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BringUpReport:
        if self.live != (self.status == "live"):
            raise ValueError("live must reflect the status")
        if not skip_digests(info) and self.report_digest != sealed_digest(BringUpReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self


@dataclass
class BringUpOrchestrator:
    """Walk a company through bring-up against a client, a store, and a checkpoint gateway; every step is a fenced transition."""

    bundle: CadenceBundle
    store: EngineStateStore
    connections: Callable[[], Sequence[Mapping[str, Any]]]
    clock: Callable[[], str]
    formed_company_ref: str
    gateway: CheckpointGateway | None = None
    worker_ref: str = "bring-up-worker"
    interval_seconds: int = 3600
    company_id: str | None = None
    approval_requester: Callable[[Any], Mapping[str, Any]] | None = None
    launch_gate: Callable[[], Any] | None = None
    _counter: int = 0
    _readiness: ConnectorReadiness | None = field(default=None, init=False)

    def _runtime(self) -> EngineRuntime:
        return EngineRuntime(spec=BRING_UP_LIFECYCLE, engine=BRING_UP_KIND, plan=self.bundle, store=self.store, advance=advance_bring_up)

    def _ref(self) -> str:
        return bring_up_ref(self.bundle)

    def _advance(self, event: str, receipt: Mapping[str, Any] | None = None, *, reason: str | None = None) -> BringUpStep:
        runtime = self._runtime()
        state = runtime.load(self._ref())
        now = self.clock()
        self._counter += 1
        command = runtime.command(state, event=event, transition_ref=f"{event}:{now}:{self._counter}", idempotency_key=f"{event}:{self._counter}:{now}", occurred_at=now, actor_ref=self.bundle.actor_ref, receipt=receipt, reason=reason)
        outcome = runtime.advance_and_persist(self._ref(), command)
        if outcome.persisted:
            return BringUpStep(event=event, outcome="applied", to_status=outcome.result.state.status)
        receipt_model = outcome.result.receipt
        return BringUpStep(event=event, outcome="rejected", rejection_code=receipt_model.rejection_code, detail=str(receipt_model.recovery.instructions)[:900])

    def form(self) -> Any:
        state = start_bring_up(self.bundle, formed_company_ref=self.formed_company_ref, formed_at=self.clock())
        self._runtime().open(self._ref(), state)
        return state

    def verify_connectors(self) -> BringUpStep:
        readiness = assess_readiness(self.bundle, self.connections(), now=self.clock(), company_id=self.company_id)
        self._readiness = readiness
        receipt: dict[str, Any] = {"readiness_digest": readiness.readiness_digest, "ready": readiness.ready, "blocked_engines": list(readiness.blocked_engines)}
        if self.launch_gate is not None:
            gate = self.launch_gate()
            receipt.update({"launch_gate_digest": gate.gate_digest, "instruments_ready": gate.ready, "blocked_instruments": list(gate.blocked_instruments())})
        return self._advance("verify_connectors", receipt)

    def verify_paper(self, sources: Sequence[Mapping[str, Any]]) -> BringUpStep:
        return self._advance("verify_paper", {"paper_sources": [detached(source) for source in sources]})

    def hire_workforce(self) -> BringUpStep:
        plan = self.bundle.workforce_plan
        if plan is None:
            return self._advance("hire_workforce", {"worker_refs": [], "worker_state_digests": []})
        runtime = EngineRuntime(spec=WORKER_LIFECYCLE, engine="company_workforce", plan=plan, store=self.store, advance=advance_worker)
        refs: list[str] = []
        digests: list[str] = []
        sources: list[dict[str, Any]] = []
        for role in plan.roster.workers:
            existing = self.store.get("company_workforce", role.worker_ref)
            if existing is None:
                hired = hire_worker(plan, self.bundle.engine_scope(role.worker_ref), worker_ref=role.worker_ref, hired_at=self.clock(), actor_ref=self.bundle.actor_ref)
                runtime.open(role.worker_ref, hired)
            state = runtime.load(role.worker_ref)
            if state.status == "hired":
                self._counter += 1
                now = self.clock()
                command = runtime.command(state, event="activate", transition_ref=f"activate:{role.worker_ref}:{self._counter}", idempotency_key=f"activate:{role.worker_ref}:{self._counter}", occurred_at=now, actor_ref=self.bundle.actor_ref)
                outcome = runtime.advance_and_persist(role.worker_ref, command)
                if not outcome.persisted:
                    return BringUpStep(event="hire_workforce", outcome="rejected", rejection_code=outcome.result.receipt.rejection_code, detail=f"{role.worker_ref} could not be activated")
                state = outcome.result.state
            refs.append(role.worker_ref)
            digests.append(state.state_digest)
            sources.append(state.to_dict())
        return self._advance("hire_workforce", {"worker_refs": refs, "worker_state_digests": digests, "worker_sources": sources})

    def _runner(self) -> CompanyCadenceRunner:
        return CompanyCadenceRunner(bundle=self.bundle, store=self.store, approval_requester=self.approval_requester or (lambda request: {"id": "unrequested"}))

    def open_period(self) -> BringUpStep:
        runner = self._runner()
        now = self.clock()
        result = runner.tick(now=now)
        opened = next((item for item in result.applied if item.event == "open" and item.outcome == "applied"), None)
        if opened is None:
            periods = self.store.list(engine="company_operating_system")
            if not periods:
                return BringUpStep(event="open_period", outcome="rejected", rejection_code="PERIOD_NOT_OPENED", detail="the cadence runner did not open a period; check the bundle start_at against now")
            record = periods[0]
            return self._advance("open_period", {"period_ref": record["entity_ref"], "period_state_digest": record["state_digest"]})
        record = self.store.get("company_operating_system", opened.entity_ref)
        assert record is not None
        return self._advance("open_period", {"period_ref": opened.entity_ref, "period_state_digest": record["state_digest"]})

    def start_cadence(self) -> BringUpStep:
        worker = CadenceWorker(runner=self._runner(), clock=self.clock)
        if self.store.get("company_cadence", worker.cadence_ref) is None:
            worker.start()
        record = self.store.get("company_cadence", worker.cadence_ref)
        assert record is not None
        return self._advance("start_cadence", {"cadence_ref": worker.cadence_ref, "cadence_state_digest": record["state_digest"]})

    def schedule(self, *, first_tick_at: str) -> BringUpStep:
        if self.gateway is None:
            return BringUpStep(event="schedule", outcome="skipped", detail="no checkpoint gateway supplied; schedule later with HostedCadenceScheduler.register")
        scheduler = HostedCadenceScheduler(worker=CadenceWorker(runner=self._runner(), clock=self.clock), gateway=self.gateway, worker_ref=self.worker_ref, interval_seconds=self.interval_seconds)
        existing = self.gateway.get(scheduler.run_ref)
        record = existing if existing is not None else scheduler.register(first_tick_at=first_tick_at)
        return self._advance("schedule", {"checkpoint_run_ref": scheduler.run_ref, "checkpoint_revision": int(record["revision"]), "resume_at": timestamp(first_tick_at, field_name="first_tick_at")})

    def go_live(self) -> BringUpStep:
        return self._advance("go_live")

    def abandon(self, reason: str) -> BringUpStep:
        return self._advance("abandon", reason=reason)

    def run(self, *, first_tick_at: str, paper_sources: Sequence[Mapping[str, Any]] = ()) -> BringUpReport:
        """Form if needed, then advance every gate in order; stop at the first refusal and report."""

        if self.store.get(BRING_UP_KIND, self._ref()) is None:
            self.form()
        steps: list[BringUpStep] = []
        stage = self._runtime().load(self._ref()).status
        order: list[tuple[str, Callable[[], BringUpStep]]] = [
            ("formed", self.verify_connectors),
            ("connectors_verified", self.hire_workforce),
            ("workforce_hired", self.open_period),
            ("period_opened", self.start_cadence),
            ("cadence_started", lambda: self.schedule(first_tick_at=first_tick_at)),
            ("scheduled", self.go_live),
        ]
        started = False
        for from_status, action in order:
            if not started and stage != from_status:
                continue
            started = True
            if from_status == "connectors_verified" and paper_sources:
                paper_step = self.verify_paper(paper_sources)
                steps.append(paper_step)
                if paper_step.outcome != "applied":
                    break
            step = action()
            steps.append(step)
            if step.outcome != "applied":
                break
        status = self._runtime().load(self._ref()).status
        return seal(BringUpReport, {"company_ref": self.bundle.company_ref, "bundle_digest": self.bundle.plan_digest, "status": status, "steps": [item.to_dict() for item in steps], "readiness": self._readiness.to_dict() if self._readiness is not None else None, "live": status == "live"}, "report_digest")


BRING_UP_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": BRING_UP_KIND,
    "golden_loop": BRING_UP_GOLDEN_LOOP,
    "stages": ["form", "verify_connectors", "verify_paper", "hire_workforce", "open_period", "start_cadence", "schedule", "go_live"],
    "statuses": list(BRING_UP_STATUSES),
    "events": list(BRING_UP_EVENTS),
    "connector_groups": {engine: [list(group) for group in groups] for engine, groups in ENGINE_CONNECTOR_GROUPS.items()},
    "required_connectors": ["lightbulb.account", "lightbulb.oauth_connections", "lightbulb.sdk_engine_state", "lightbulb.sdk_project_runtime_checkpoints"],
    "hard_rules": [
        "connector readiness is computed from the account's active OAuth connections, never assumed",
        "a blocked engine blocks bring-up; the operator connects the provider or compiles a bundle without the engine",
        "every gate consumes a receipt naming a persisted fact: worker state digests, the period digest, the cadence digest, the checkpoint revision",
        "when a launch gate is supplied, every required instrument must be active before connectors are verified",
        "the orchestrator composes the existing runtimes and executes no effect of its own",
    ],
}

__all__ = [
    "BRING_UP_EVENTS",
    "BRING_UP_GOLDEN_LOOP",
    "BRING_UP_KIND",
    "BRING_UP_LIFECYCLE",
    "BRING_UP_MANIFEST",
    "BRING_UP_STATUSES",
    "ENGINE_CONNECTOR_GROUPS",
    "BringUpOrchestrator",
    "BringUpReport",
    "BringUpState",
    "BringUpStep",
    "ConnectorReadiness",
    "EngineReadiness",
    "advance_bring_up",
    "assess_readiness",
    "bring_up_ref",
    "normalize_provider",
    "start_bring_up",
]
