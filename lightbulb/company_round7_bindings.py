"""Round-seven bindings: the four new lifecycles as parts of a company, not four modules beside one.

``employment_chain``, ``job_chain``, ``wind_down_chain`` and ``ai_operator``
each prove one thing on their own.  None of them is yet *part* of a company:
the cadence bundle does not carry their plans, a tick raises none of their
work items, readiness does not know which connectors they need, and no
registry the reference generator reads names them.  This module is that
binding, and only that binding.

What it proves, from which artifacts:

* :class:`Round7Supplement` seals the three supporting plans one services
  company runs on -- an :class:`~lightbulb.employment_chain.EmploymentPlan`,
  a :class:`~lightbulb.job_chain.JobChainPlan` and (when the shutdown is
  compiled) a :class:`~lightbulb.wind_down_chain.WindDownPlan` -- against the
  sealed :class:`~lightbulb.company_cadence_runner.CadenceBundle` they belong
  to.  The job plan must name *this* employment plan's digest
  (``JOB_EMPLOYMENT_PLAN_MISMATCH``) and the wind-down plan must name *this*
  bundle (``WIND_DOWN_BUNDLE_MISMATCH``), so a supplement assembled out of
  two companies' plans cannot be sealed.
* :func:`plan_round7_actions` is a pure planner over the *persisted* states
  of those three engines plus the open period: the next legal move for every
  employee, job and wind-down, the receipt fields that move needs, and the
  sealed artifact that would satisfy it.  It never invents an input.  The
  only actions it marks ``automatic`` are the ones whose receipt it could
  build from state already in hand *and the hop's own guard would accept* -- a
  job assigned to a worker the roster covers and who is not on leave
  (``job_chain.assign_receipt``, on the ``local_services`` profile only: a
  consulting assignment stands on a staffed engagement no planner holds) and
  the period evidence of jobs whose cash landed
  (``job_chain.period_evidence_receipt``).  Every other item names the status
  it was raised for and an event ``_JOB_TABLE`` / ``_EMPLOYMENT_TABLE`` /
  ``_WIND_DOWN_TABLE`` actually allows from it.
* :func:`assess_round7_readiness` compares the supplement's engines against
  the connected providers, and refuses a go-live whose employment plan has no
  rostered worker (``PEOPLE_NOT_ROSTERED``).
* :func:`round7_observation_requests` names, for each observation a work item
  asks for, the governed tool, its *closed* input key set, and which of those
  keys the platform fills from its own correlation.  The SDK never mints a
  provider identifier, so an id-bearing key is named, never valued.

What it hands to the rest of the runtime: :func:`round7_runtimes` (the
``EngineRuntime`` per round-7 engine, sharing the cadence runner's approval
requester and the operator's request decorator), :data:`ROUND7_CONSOLE_VERBS`
and :data:`ROUND7_MCP_TOOLS` (the operator surface), :data:`ROUND7_LIFECYCLE_TARGETS`
(the plan-migration registry), :data:`ROUND7_CHAIN_VERBS` /
:data:`ROUND7_CHAIN_ACTION_KINDS` (the chain catalog),
:data:`ROUND7_CONNECTOR_GROUPS` (bring-up readiness),
:data:`ROUND7_COMPANY_MODULES` (the reference generator) and
:func:`round7_summary` (the console and the daily brief).

Nothing here reads a provider, writes to one, dispatches anything, or
persists anything of its own: it binds what the four chains already proved.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.ai_operator import DEFAULT_BINDINGS
from lightbulb.company_bring_up import normalize_provider
from lightbulb.company_cadence_runner import CadenceAction, CadenceBundle, build_bundle
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
    stable_digest,
    timestamp,
)
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_execution_bridge import HUMAN_ONLY_CATEGORIES
from lightbulb.employment_chain import (
    EMPLOYMENT_LIFECYCLE,
    EmploymentPlan,
    advance_employee,
    capacity_expectation,
    compile_employment_chain,
    employee_summary,
    headcount_receipt,
    narrate_employee,
    timesheet_expectation,
)
from lightbulb.job_chain import (
    JOB_LIFECYCLE,
    ROSTERED_STATUSES as JOB_ROSTERED_STATUSES,
    JobChainPlan,
    advance_job,
    assign_receipt,
    compile_job_chain,
    jobs_summary,
    narrate_job,
    period_evidence_receipt,
)
from lightbulb.wind_down_chain import (
    WIND_DOWN_LIFECYCLE,
    TERMINAL_WIND_DOWN_STATUSES,
    WindDownPlan,
    advance_wind_down,
    compile_wind_down,
    narrate_wind_down,
    wind_down_summary,
)

BINDINGS_GOLDEN_LOOP = "company.round7_bindings@0.1.0"
BINDINGS_KIND = "company_round7_bindings"
SUPPLEMENT_SCHEMA = "lightbulb.company_round7_supplement.v1"
READINESS_SCHEMA = "lightbulb.company_round7_readiness.v1"
SUMMARY_SCHEMA = "lightbulb.company_round7_summary.v1"
OBSERVATION_REQUEST_SCHEMA = "lightbulb.company_round7_observation_request.v1"
PERIOD_SCHEMA = "lightbulb.company_round7_period.v1"

Round7Archetype = Literal["local_services", "consulting_firm"]
#: The archetypes that carry the round-7 supporting plans.  ``local_services``
#: is round five's; ``consulting_firm`` is this round's, and its dict lives in
#: the ROUND5_SHIM below until ``company_operating_system`` can hold it.
ROUND7_ARCHETYPES: tuple[str, ...] = ("local_services", "consulting_firm")
#: The rail each archetype's jobs settle on, and the job-chain profile it runs.
ARCHETYPE_RAILS: Mapping[str, tuple[str, str]] = {"local_services": ("square", "local_services"), "consulting_firm": ("xero", "consulting")}
ROUND7_ENGINES: tuple[str, ...] = ("employment_chain", "job_chain", "wind_down_chain", "ai_operator")
#: The three that are replay-fenced lifecycles.  ``ai_operator`` is a loop over
#: the others, not a lifecycle of its own (see "Wiring needed").
ROUND7_CHAIN_ENGINES: tuple[str, ...] = ("employment_chain", "job_chain", "wind_down_chain")


class Round7BindingsError(ValueError):
    """A supplement, a registry merge, or a work-item plan that does not line up; carries the code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise Round7BindingsError(code, message)


# --------------------------------------------------------------------------- #
# ROUND5_SHIM
#
# Round 5 lands ``company_operating_system``'s ``local_services`` archetype and
# the ``people_engine`` / ``engagement_engine`` engine kinds,
# ``lightbulb/company_chain_catalog.py`` (CHAIN_MODULES, OPERATOR_CHAIN_MODULES,
# CHAIN_VERBS, CHAIN_ACTION_KINDS), ``company_workforce._ROLE_TEMPLATES`` and
# its derived ``STANDARD_ROSTERS`` loop, ``company_cost_centres``
# (REVENUE_STATE_SCHEMAS, SETTLED_REVENUE_STATUSES) and
# ``company_cadence_runner.compile_company_bundle`` with its
# ``CadenceBundle.supporting_plans`` slot.  None of them is in this tree.
#
# Everything round seven *adds* to those registries lives here, with round
# five's key names and value shapes, so the merge is mechanical and checkable
# (:func:`merge_registry` refuses to replace an entry that already exists).
# When round 5 lands, fold these tables into the registries they name and
# delete this block; nothing below it changes.
# --------------------------------------------------------------------------- #

_COMMON_SIGNALS: tuple[str, ...] = ("signals.company_formed", "signals.attributed_revenue", "signals.envelope_exhausted", "signals.books_verified")

#: ``company_operating_system.COMPANY_OS_ARCHETYPES['consulting_firm']``.  AUD
#: keeps ``fortnightly_close``'s currency rule; the four shares sum to 100.
CONSULTING_FIRM_ARCHETYPE: dict[str, Any] = {
    "archetype": "consulting_firm",
    "name": "Consulting firm",
    "country": "AU",
    "currency": "AUD",
    "operating_budget_per_period": "12000",
    "period_days": 14,
    "engines": [
        {"engine": "pipeline_engine", "profile": "agency_outbound", "budget_share_percent": "30", "cadence_days": 2},
        {"engine": "engagement_engine", "profile": "professional_services", "budget_share_percent": "30", "cadence_days": 1},
        {"engine": "people_engine", "profile": "small_team", "budget_share_percent": "20", "cadence_days": 14},
        {"engine": "finance_close", "profile": "fortnightly_close", "budget_share_percent": "20", "cadence_days": 14},
    ],
    "signals": [*_COMMON_SIGNALS, "signals.qualified_pipeline", "signals.capacity_shortfall", "signals.case_resolved"],
    "formation": {"industry": "Management consulting", "purpose": "Win engagements, staff them with proven people, bill accepted work and collect it.", "contact_email_required": True},
    "targets": {"revenue_per_period": "45000", "gross_margin_percent": "50", "min_cash_runway_months": 4},
}

#: ``company_workforce._ROLE_TEMPLATES`` entries for the two new engines.
ROUND7_ROLE_TEMPLATES: Mapping[str, dict[str, Any]] = {
    "job_chain": {"worker_ref": "w-quote-drafter", "title": "Quote drafter", "domain": "commerce", "actions": ["service_catalog", "pricing_intelligence"], "engine": "job_chain", "stage": "quote", "budget_per_period": "400", "max_dispatches_per_period": 40, "max_cost_per_dispatch": "10", "effect_class": "draft"},
    "employment_chain": {"worker_ref": "w-dispatcher", "title": "Roster and dispatch planner", "domain": "solver", "actions": ["schedule_optimization", "assign_resources"], "engine": "employment_chain", "stage": "roster", "budget_per_period": "300", "max_dispatches_per_period": 30, "max_cost_per_dispatch": "10", "effect_class": "read_only"},
}

#: ``company_workforce.STANDARD_ROSTERS['consulting_firm']``: the round-5 loop's
#: roles for this archetype's engines, plus the two round-7 additions.
CONSULTING_FIRM_ROSTER: dict[str, Any] = {
    "currency": "AUD",
    "workers": [
        {"worker_ref": "w-crm-sdr", "title": "Outbound SDR", "domain": "crm", "actions": ["lead_qualification", "outbound_messaging", "classify_reply"], "engine": "pipeline_engine", "stage": "compose_touches", "budget_per_period": "900", "max_dispatches_per_period": 60, "max_cost_per_dispatch": "30", "effect_class": "write_with_approval"},
        {"worker_ref": "w-proposal", "title": "Proposal writer", "domain": "document_intelligence", "actions": ["create_sales_collateral", "write_document"], "engine": "job_chain", "stage": "quote", "budget_per_period": "500", "max_dispatches_per_period": 20, "max_cost_per_dispatch": "50", "effect_class": "draft"},
        {"worker_ref": "w-dispatcher", "title": "Roster and dispatch planner", "domain": "solver", "actions": ["schedule_optimization", "assign_resources"], "engine": "employment_chain", "stage": "roster", "budget_per_period": "300", "max_dispatches_per_period": 30, "max_cost_per_dispatch": "10", "effect_class": "read_only"},
        {"worker_ref": "w-bookkeeper", "title": "Close accountant", "domain": "finance", "actions": ["xero_close_books", "xero_bank_reconciliation"], "engine": "finance_close", "stage": "reconcile", "budget_per_period": "400", "max_dispatches_per_period": 10, "max_cost_per_dispatch": "80", "effect_class": "draft"},
    ],
}

#: ``company_chain_catalog`` additions.
ROUND7_CHAIN_MODULES: tuple[str, ...] = ("employment_chain", "job_chain", "wind_down_chain", "ai_operator")
ROUND7_OPERATOR_CHAIN_MODULES: tuple[str, ...] = ("employment_chain", "job_chain", "wind_down_chain")
ROUND7_CHAIN_VERBS: Mapping[str, tuple[str, ...]] = {
    "employees": ("employment_chain",),
    "people_ops": ("employment_chain",),
    "jobs": ("job_chain",),
    "wind_down": ("wind_down_chain",),
    "closure": ("wind_down_chain",),
    "operator": ("ai_operator",),
    "escalations": ("ai_operator",),
}
ROUND7_CHAIN_ACTION_KINDS: Mapping[str, str] = {
    "employment_chain": "advance_employee",
    "job_chain": "advance_job",
    "wind_down_chain": "advance_wind_down",
    "ai_operator": "record_operator_decision",
}

#: ``company_cost_centres`` additions: a job state is a revenue state, and a
#: paid job is settled revenue.
ROUND7_REVENUE_STATE_SCHEMAS: tuple[str, ...] = ("lightbulb.job_chain_state.v1",)
ROUND7_SETTLED_REVENUE_STATUSES: tuple[str, ...] = ("paid",)
#: ``collections_chain.open_receivable_receipt`` also accepts an invoiced job.
ROUND7_RECEIVABLE_STATE_SCHEMAS: Mapping[str, tuple[str, ...]] = {"lightbulb.job_chain_state.v1": ("invoiced",)}

# --------------------------------------------------------------------------- #
# end ROUND5_SHIM
# --------------------------------------------------------------------------- #


#: ``company_plan_migration._register_late_lifecycles``: engine key -> (module,
#: lifecycle, advance function).  Iterated after ``ROUND5_LIFECYCLE_TARGETS``.
ROUND7_LIFECYCLE_TARGETS: Mapping[str, tuple[str, str, str]] = {
    "employment_chain": ("employment_chain", "EMPLOYMENT_LIFECYCLE", "advance_employee"),
    "job_chain": ("job_chain", "JOB_LIFECYCLE", "advance_job"),
    "wind_down_chain": ("wind_down_chain", "WIND_DOWN_LIFECYCLE", "advance_wind_down"),
}

#: ``company_reference.COMPANY_MODULES`` additions.
ROUND7_COMPANY_MODULES: tuple[str, ...] = ("lightbulb.employment_chain", "lightbulb.job_chain", "lightbulb.wind_down_chain", "lightbulb.ai_operator")

#: ``company_bring_up.ENGINE_CONNECTOR_GROUPS`` additions.  Each inner tuple is
#: a group of alternatives; the engine is ready when every group is satisfied.
ROUND7_CONNECTOR_GROUPS: Mapping[str, tuple[tuple[str, ...], ...]] = {
    "engagement_engine": (("xero", "quickbooks"),),
    "people_engine": (("xero",),),
    "job_chain": (("square", "xero"),),
    "employment_chain": (("xero",), ("greenhouse", "bamboohr")),
}

#: The authority categories round seven adds, and the hops each may cover.
#: Both already live in ``ai_operator``'s round-5 shim; these are the copies the
#: real ``authority_matrix`` merges.
ROUND7_AUTHORITY_CATEGORIES: tuple[str, ...] = ("job_quote", "job_invoice", "people_change", "wind_down")
ROUND7_ADDITIONAL_HOPS: Mapping[str, tuple[tuple[str, str], ...]] = {category: DEFAULT_BINDINGS[category] for category in ROUND7_AUTHORITY_CATEGORIES}

#: ``company_signal_consumers``: signal -> the round-7 work item that answers it.
#: A capacity shortfall is answered by rostering somebody.  ``signals.capability_lapsed``
#: is deliberately absent: a lapsed licence or police check is an
#: ``obligation_paper`` standing item a human re-verifies, and round seven raises
#: no work item for it -- naming ``advance_employee`` here would put a chain
#: action kind in a registry of cadence action kinds and route the signal at a
#: consumer that cannot act on it.
ROUND7_SIGNAL_INTENTS: Mapping[str, str] = {"signals.capacity_shortfall": "roster_people"}
#: ``company_chaos.FAULT_KINDS``: a typed approval string on a quote must be
#: refused ``APPROVAL_NOT_BOUND``, never accepted as authority.
ROUND7_FAULT_KINDS: tuple[str, ...] = ("typed_approval_on_quote",)

#: ``company_cadence_runner.ActionKind`` additions.
ROUND7_ACTION_KINDS: tuple[str, ...] = ("roster_people", "approve_timesheets", "run_pay", "book_jobs", "assign_jobs", "advance_job", "wind_down_step")

ROUND7_CONSOLE_VERBS: Mapping[str, dict[str, Any]] = {
    "employees": {"chains": ("employment_chain",), "signature": "employees(*, now=None)", "returns": "headcount, the period capacity expectation, and one narration line per employee"},
    "people_ops": {"chains": ("employment_chain",), "signature": "people_ops(operation='list', *, entity_ref='', payload=None, now=None)", "returns": "the employment chain's work items and one advance_employee transition"},
    "jobs": {"chains": ("job_chain",), "signature": "jobs(*, now=None)", "returns": "jobs_summary plus one narrate_job line per job"},
    "wind_down": {"chains": ("wind_down_chain",), "signature": "wind_down(operation='list', *, entity_ref='', payload=None, now=None)", "returns": "the wind-down summary; refuses to open one without a decision proof"},
    "closure": {"chains": ("wind_down_chain",), "signature": "closure(*, now=None)", "returns": "the wind-down's remaining steps and the cadence stop reason once it is earned"},
    "operator": {"chains": ("ai_operator",), "signature": "operator(policy, *, now=None, minutes=1)", "returns": "the OperatorLog narration, the proofs minted, and the unattended spend"},
    "escalations": {"chains": ("ai_operator",), "signature": "escalations(*, now=None)", "returns": "the sealed EscalationRegister: what is waiting in a human's inbox and why"},
}

#: ``read_only`` becomes the tool's ``readOnlyHint``, and ``mcp_server`` routes a
#: read-hinted capability through ``lightbulb_use_read_capability``.  The four
#: chain tools carry an ``operation`` and a ``payload_json`` and reach
#: ``CompanyOperatorSurface.operate_chain``, which *advances* a lifecycle, so
#: none of them is a read however often it is called with ``operation='list'``.
_CHAIN_TOOL_SIGNATURE = "(project_id, bundle_json, operation='list', engine='', entity_ref='', payload_json='{}', now='')"
ROUND7_MCP_TOOLS: Mapping[str, dict[str, Any]] = {
    "company_employees": {"verb": "employees", "signature": _CHAIN_TOOL_SIGNATURE, "read_only": False},
    "company_jobs": {"verb": "jobs", "signature": _CHAIN_TOOL_SIGNATURE, "read_only": False},
    "company_wind_down": {"verb": "wind_down", "signature": _CHAIN_TOOL_SIGNATURE, "read_only": False},
    "company_operator": {"verb": "operator", "signature": _CHAIN_TOOL_SIGNATURE, "read_only": False},
    "create_operator_policy": {"client_method": "create_operator_policy", "read_only": False},
    "activate_operator_policy": {"client_method": "activate_operator_policy", "read_only": False},
    "get_operator_policy": {"client_method": "get_operator_policy", "read_only": True},
    "provision_ai_operator": {"client_method": "provision_ai_operator", "read_only": False},
}


def merge_registry(base: Mapping[str, Any], additions: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    """Fold round seven's additions into a round-five registry without ever replacing an entry."""

    merged = dict(base)
    for key, value in additions.items():
        _require(key not in merged or merged[key] == value, "REGISTRY_KEY_CONFLICT", f"{label} already binds {key!r} to something else; round seven only adds")
        merged[key] = value
    return merged


def merge_kinds(base: Sequence[str], additions: Sequence[str], *, label: str) -> tuple[str, ...]:
    """Append round seven's kinds to a round-five tuple, keeping order and refusing duplicates inside the additions."""

    distinct = len(set(additions)) == len(tuple(additions))
    _require(distinct, "REGISTRY_KEY_CONFLICT", f"{label} additions repeat a kind")
    merged = list(base)
    for kind in additions:
        if kind not in merged:
            merged.append(kind)
    return tuple(merged)


# --------------------------------------------------------------------------- #
# The supplement: the three supporting plans, sealed against the bundle
# --------------------------------------------------------------------------- #


_LIFECYCLES: Mapping[str, Any] = {"employment_chain": EMPLOYMENT_LIFECYCLE, "job_chain": JOB_LIFECYCLE, "wind_down_chain": WIND_DOWN_LIFECYCLE}
_ADVANCERS: Mapping[str, Callable[..., Any]] = {"employment_chain": advance_employee, "job_chain": advance_job, "wind_down_chain": advance_wind_down}
_PLAN_MODELS: Mapping[str, type[StrictModel]] = {"employment_chain": EmploymentPlan, "job_chain": JobChainPlan, "wind_down_chain": WindDownPlan}


def lifecycle_for(engine: str) -> Any:
    """The ``LifecycleSpec`` one round-7 engine key runs on."""

    _require(engine in _LIFECYCLES, "ENGINE_NOT_ROUND7", f"{engine!r} is not a round-7 lifecycle; known: {sorted(_LIFECYCLES)}")
    return _LIFECYCLES[engine]


def advance_for(engine: str) -> Callable[..., Any]:
    _require(engine in _ADVANCERS, "ENGINE_NOT_ROUND7", f"{engine!r} is not a round-7 lifecycle; known: {sorted(_ADVANCERS)}")
    return _ADVANCERS[engine]


def plan_model_for(engine: str) -> type[StrictModel]:
    _require(engine in _PLAN_MODELS, "ENGINE_NOT_ROUND7", f"{engine!r} is not a round-7 lifecycle; known: {sorted(_PLAN_MODELS)}")
    return _PLAN_MODELS[engine]


class Round7Supplement(StrictModel):
    """The round-7 plans one company runs on, sealed against the cadence bundle they belong to."""

    schema_id: str = Field(default=SUPPLEMENT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    archetype: Round7Archetype
    currency: CurrencyCode
    bundle_digest: Sha256Digest
    employment_plan: EmploymentPlan
    job_plan: JobChainPlan
    wind_down_plan: WindDownPlan | None = None
    supplement_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Round7Supplement:
        rail, profile = ARCHETYPE_RAILS[self.archetype]
        for name, plan in (("employment", self.employment_plan), ("job", self.job_plan)):
            if plan.company_ref != self.company_ref:
                raise ValueError(f"SUPPLEMENT_COMPANY_MISMATCH: the {name} plan belongs to {plan.company_ref}, not {self.company_ref}")
            if plan.currency != self.currency:
                raise ValueError(f"SUPPLEMENT_CURRENCY_MISMATCH: the {name} plan is {plan.currency}; this company operates in {self.currency}")
        if self.job_plan.employment_plan_digest != self.employment_plan.plan_digest:
            raise ValueError("JOB_EMPLOYMENT_PLAN_MISMATCH: the job chain must name this company's employment plan, or an assignment proves nothing about who was rostered")
        if (self.job_plan.rail, self.job_plan.profile) != (rail, profile):
            raise ValueError(f"SUPPLEMENT_RAIL_MISMATCH: a {self.archetype} settles jobs on {rail}/{profile}, not {self.job_plan.rail}/{self.job_plan.profile}")
        if self.wind_down_plan is not None:
            if self.wind_down_plan.company_ref != self.company_ref:
                raise ValueError(f"SUPPLEMENT_COMPANY_MISMATCH: the wind-down plan belongs to {self.wind_down_plan.company_ref}, not {self.company_ref}")
            if self.wind_down_plan.currency != self.currency:
                raise ValueError(f"SUPPLEMENT_CURRENCY_MISMATCH: the wind-down plan is {self.wind_down_plan.currency}; this company operates in {self.currency}")
            if self.wind_down_plan.bundle_digest != self.bundle_digest:
                raise ValueError("WIND_DOWN_BUNDLE_MISMATCH: the wind-down must name the exact cadence bundle it shuts down")
        if not skip_digests(info) and self.supplement_digest != sealed_digest(Round7Supplement, self, "supplement_digest"):
            raise ValueError("supplement_digest must commit the exact supplement")
        return self

    @property
    def plan_digest(self) -> str:
        return self.supplement_digest

    def plan_for(self, engine: str) -> Any:
        return {"employment_chain": self.employment_plan, "job_chain": self.job_plan, "wind_down_chain": self.wind_down_plan}[engine]

    def supporting_plans(self) -> dict[str, dict[str, Any]]:
        """The ``CadenceBundle.supporting_plans`` slot round five will hold these in."""

        plans = {"employment_chain": self.employment_plan.to_dict(), "job_chain": self.job_plan.to_dict()}
        if self.wind_down_plan is not None:
            plans["wind_down_chain"] = self.wind_down_plan.to_dict()
        return plans


def build_round7_supplement(supplement: Round7Supplement | Mapping[str, Any]) -> Round7Supplement:
    if isinstance(supplement, Round7Supplement):
        return supplement
    return Round7Supplement.model_validate(dict(detached(supplement)))


def compile_round7_supplement(
    bundle: CadenceBundle | Mapping[str, Any],
    *,
    archetype: str,
    jurisdiction: str | None = None,
    payroll_plan: Any = None,
    obligation_paper_plan: Any = None,
    engagement_plan: Any = None,
    wip_plan: Any = None,
    settlement_reserve: Any = None,
    compile_wind_down_plan: bool = True,
    tenant_id: str | None = None,
    company_id: str | None = None,
    employment_overrides: Mapping[str, Any] | None = None,
    job_overrides: Mapping[str, Any] | None = None,
    wind_down_overrides: Mapping[str, Any] | None = None,
) -> Round7Supplement:
    """Compile the three supporting plans for one sealed cadence bundle; every default comes off the bundle's blueprint."""

    _require(archetype in ARCHETYPE_RAILS, "SUPPLEMENT_ARCHETYPE_UNKNOWN", f"{archetype!r} carries no round-7 supporting plans; known: {sorted(ARCHETYPE_RAILS)}")
    parsed_bundle = build_bundle(bundle)
    blueprint = parsed_bundle.operating_plan.blueprint
    company_ref, currency = str(parsed_bundle.company_ref), str(blueprint.currency)
    country = str(jurisdiction or blueprint.country).upper()
    rail, profile = ARCHETYPE_RAILS[archetype]
    employment = compile_employment_chain(company_ref, currency=currency, jurisdiction=country, payroll_plan=payroll_plan, obligation_paper_plan=obligation_paper_plan, overrides=employment_overrides)
    job = compile_job_chain(company_ref, currency=currency, rail=rail, profile=profile, employment_plan=employment, engagement_plan=engagement_plan, wip_plan=wip_plan, overrides=job_overrides)
    wind_down = None
    if compile_wind_down_plan:
        reserve = settlement_reserve if settlement_reserve is not None else str((blueprint.operating_budget_per_period * Decimal("3")).quantize(MONEY_QUANTUM))
        wind_down = compile_wind_down(company_ref, currency=currency, jurisdiction=country, bundle=parsed_bundle, settlement_reserve=reserve, overrides=wind_down_overrides, tenant_id=tenant_id, company_id=company_id)
    payload: dict[str, Any] = {"company_ref": company_ref, "archetype": archetype, "currency": currency, "bundle_digest": parsed_bundle.plan_digest, "employment_plan": employment, "job_plan": job}
    if wind_down is not None:
        payload["wind_down_plan"] = wind_down
    return seal(Round7Supplement, payload, "supplement_digest")


# --------------------------------------------------------------------------- #
# Runtimes
# --------------------------------------------------------------------------- #


def round7_runtimes(
    supplement: Round7Supplement | Mapping[str, Any],
    store: EngineStateStore,
    *,
    approval_requester: Callable[..., Mapping[str, Any]] | None = None,
    request_decorator: Callable[..., Any] | None = None,
) -> dict[str, EngineRuntime]:
    """One ``EngineRuntime`` per round-7 lifecycle the supplement carries, sharing the runner's approval lane."""

    parsed_supplement = build_round7_supplement(supplement)
    runtimes: dict[str, EngineRuntime] = {}
    for engine in ROUND7_CHAIN_ENGINES:
        plan = parsed_supplement.plan_for(engine)
        if plan is None:
            continue
        runtimes[engine] = EngineRuntime(spec=lifecycle_for(engine), engine=engine, plan=plan, store=store, advance=advance_for(engine), approval_requester=approval_requester, request_decorator=request_decorator)
    return runtimes


def install_round7_runtimes(
    runner: Any,
    supplement: Round7Supplement | Mapping[str, Any],
    *,
    request_decorator: Callable[..., Any] | None = None,
) -> dict[str, EngineRuntime]:
    """Register the round-7 runtimes on a ``CompanyCadenceRunner``, reusing its approval requester.

    ``request_decorator`` is the operator's own
    (:meth:`ai_operator.OperatorLoop.decorate`): the runner holds no decorator
    of its own, so an unattended company passes it here or its round-7 requests
    reach the platform undecorated and are escalated for want of a category.
    """

    runtimes = round7_runtimes(supplement, runner.store, approval_requester=getattr(runner, "approval_requester", None), request_decorator=request_decorator)
    for engine, runtime in runtimes.items():
        _require(engine not in runner.runtimes, "REGISTRY_KEY_CONFLICT", f"the runner already holds a {engine} runtime")
        runner.runtimes[engine] = runtime
    return runtimes


# --------------------------------------------------------------------------- #
# The work items one tick raises for the round-7 engines
# --------------------------------------------------------------------------- #


class Round7Period(StrictModel):
    """The open operating period the people work items are raised against."""

    schema_id: str = Field(default=PERIOD_SCHEMA, alias="schema")
    period_ref: OpaqueRef
    period_start: str
    period_end: str
    pay_date: str | None = None

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @field_validator("pay_date")
    @classmethod
    def _pay(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="pay_date")

    @model_validator(mode="after")
    def _guard(self) -> Round7Period:
        if parsed(self.period_end) <= parsed(self.period_start):
            raise ValueError("period_end must follow period_start")
        if self.pay_date is not None and parsed(self.pay_date) < parsed(self.period_end):
            raise ValueError("a pay date falls on or after the period it pays for")
        return self


#: ``status -> (event, required receipt fields, satisfied_by)`` for the people
#: chain.  Every field name is one the hop's own guard reads off the receipt, so
#: a work item never asks for less than the transition needs.
_EMPLOYMENT_REQUIREMENTS: Mapping[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "roster": ("roster", ("roster_source", "period_start", "period_end", "rostered_hours"), ("host.roster", "operator:roster_sheet")),
    # TIMESHEET_OUTSIDE_PERIOD re-checks the declared window against the rostered
    # one, so the window is part of what the item asks for.
    "record_time": ("record_time", ("timesheet_source", "timesheet_hours", "approver_ref", "period_start", "period_end"), ("observation:xero.observe_timesheets",)),
    "record_pay": ("record_pay", ("pay_run_source", "payrun_observation", "pay_run_ref", "gross", "net", "paid_at"), ("payroll_run_chain.state", "observation:xero.observe_payrun")),
}
#: The statuses ``employment_chain`` itself calls rostered, and ``job_chain``
#: re-checks in its ``assign`` guard (``ASSIGNEE_NOT_ROSTERED``).  Imported from
#: the chain rather than restated: an employee on leave is *not* one of them, and
#: a planner that disagreed would hand out assignments the chain refuses.
_ROSTERED_STATUSES: frozenset[str] = JOB_ROSTERED_STATUSES
#: The statuses ``_EMPLOYMENT_TABLE`` accepts a ``roster`` from.  ``time_recorded``
#: is deliberately absent: that employee's next legal move is ``record_pay``.
_ROSTERABLE_STATUSES: frozenset[str] = frozenset({"onboarded", "rostered", "paid"})
#: The only status a ``record_time`` work item is raised for.  The table also
#: allows the event from ``time_recorded`` and ``paid``, but a period's time is
#: recorded once; ``on_leave`` cannot record time at all.
_TIMESHEET_STATUSES: frozenset[str] = frozenset({"rostered"})

#: ``job status -> (event, required receipt fields)``.  ``satisfied_by`` depends
#: on the plan's rail and is resolved by :func:`_job_satisfied_by`.
_JOB_REQUIREMENTS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "lead_received": ("quote", ("quote_ref", "quote_correlation", "quote_total", "list_total", "quote_expiry", "authorization_proof")),
    "quoted": ("accept", ("acceptance_digest", "quote_ref", "accepted_at")),
    "accepted": ("book", ("booking_ref", "booking_row", "start_at", "duration_minutes")),
    "booked": ("assign", ("assignee_ref", "assignment_kind", "employment_sources")),
    "assigned": ("complete", ("completion_row", "completion_signoff", "completed_at", "completion_evidence_refs")),
    "done": ("invoice", ("invoice_ref", "invoice_correlation", "invoice_total", "issued_at", "authorization_proof")),
    # PAYMENT_CORRELATION_MISMATCH re-checks the invoice correlation, so the item
    # asks for it rather than letting the payment name any invoice.
    "invoiced": ("apply_payment", ("payment_observation", "paid_amount", "paid_at", "invoice_correlation")),
    "paid": ("reconcile", ("close_ref", "close_state_digest", "reconciliation_ref", "period_end")),
}
#: Fields one rail adds to a hop.  A Square invoice is only owed once it is
#: published (``INVOICE_NOT_PUBLISHED``), so the publish execution is part of
#: what that work item asks for.
_JOB_RAIL_FIELDS: Mapping[tuple[str, str], tuple[str, ...]] = {("invoice", "square"): ("publish_execution_digest",)}
_JOB_SATISFIED_BY: Mapping[tuple[str, str], tuple[str, ...]] = {
    ("quote", "xero"): ("execution_receipt:xero.create_quote", "observation:xero.observe_quote"),
    ("quote", "square"): ("operator:quote_input",),
    ("accept", "xero"): ("observation:xero.observe_quote", "observation:gmail.classify_reply", "operator:signed_quote"),
    ("accept", "square"): ("observation:gmail.classify_reply", "operator:signed_quote"),
    ("book", "xero"): ("observation:square.observe_bookings",),
    ("book", "square"): ("observation:square.observe_bookings",),
    ("assign", "xero"): ("employment_chain.state", "engagement_engine.state", "workforce.dispatch_receipt"),
    ("assign", "square"): ("employment_chain.state", "workforce.dispatch_receipt"),
    ("complete", "xero"): ("observation:square.observe_bookings", "operator:completion_signoff"),
    ("complete", "square"): ("observation:square.observe_bookings", "operator:completion_signoff"),
    ("invoice", "xero"): ("execution_receipt:xero.create_invoice",),
    ("invoice", "square"): ("execution_receipt:square.create_invoice", "execution_receipt:square.publish_invoice"),
    ("apply_payment", "xero"): ("observation:xero.list_payments",),
    ("apply_payment", "square"): ("observation:square.observe_invoice_payment",),
    ("reconcile", "xero"): ("finance_close.state",),
    ("reconcile", "square"): ("finance_close.state",),
}

#: ``wind-down status -> (event, required receipt fields, satisfied_by)``.
_WIND_DOWN_REQUIREMENTS: Mapping[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "decided": ("notify", ("notices", "eligibility"), ("execution_receipt:communication.send", "permission_register.state")),
    "customers_notified": ("settle_refunds", ("inventory_reads", "refund_sources", "refund_total"), ("refund_and_dispute_chain.state",)),
    "refunds_settled": ("cancel_subscriptions", ("inventory_reads", "commitment_sources", "customer_subscription_sources", "subscription_cancel_executions"), ("subscription_chain.state", "spend_control_chain.state")),
    "subscriptions_cancelled": ("close_receivables", ("inventory_reads", "collections_sources", "write_off_proofs"), ("collections_chain.state",)),
    "receivables_closed": ("settle_payables", ("inventory_reads", "payable_sources", "disbursement_sources"), ("payables_chain.state", "disbursement_run.state")),
    "payables_settled": ("run_final_pay", ("inventory_reads", "headcount", "employment_sources", "payroll_sources"), ("employment_chain.state", "payroll_run_chain.state")),
    "final_pay_run_done": ("deregister", ("inventory_reads", "standing_sources", "lodgements", "compliance_sources"), ("obligation_paper.state", "operator:filing_receipt")),
    "deregistered": ("close_accounts", ("inventory_reads", "bank_source", "close_source", "register_source", "connections", "closing_balance"), ("bank_reconciliation.state", "host.connections")),
    "accounts_closed": ("close", ("inventory_reads",), ("lightbulb.get_engine_inventory",)),
}

#: The hops that carry money or a person, and therefore reach a human (or the
#: approver's standing ceiling) before they apply.
_NEEDS_APPROVAL: frozenset[tuple[str, str]] = frozenset({("job_chain", "quote"), ("job_chain", "invoice"), ("employment_chain", "hire"), ("employment_chain", "initiate_offboarding"), ("wind_down_chain", "decide")})


def _job_satisfied_by(event: str, rail: str) -> tuple[str, ...]:
    return _JOB_SATISFIED_BY.get((event, rail), ())


def _job_fields(event: str, rail: str, base: Sequence[str]) -> tuple[str, ...]:
    return (*base, *_JOB_RAIL_FIELDS.get((event, rail), ()))


def _authority_hint(engine: str, event: str) -> dict[str, Any] | None:
    """The authority category and whether a human must decide, both off closed tables.

    ``transition_authority`` is deliberately *not* called here: it needs the
    hop's money, and a pure planner holding no receipt would have to invent it.
    The category comes from ``ai_operator.DEFAULT_BINDINGS`` and ``human_only``
    from ``HUMAN_ONLY_CATEGORIES`` -- the same source
    :func:`ai_operator.compile_operator_policy` derives a ceiling's own
    ``human_only`` from -- so the hint cannot drift from the ceiling the
    platform will match against.
    """

    category = next((name for name, hops in DEFAULT_BINDINGS.items() if (engine, event) in hops), None)
    if category is None:
        return None
    return {"category": category, "human_only": category in HUMAN_ONLY_CATEGORIES}


def _bind(engine: str, records: Sequence[Mapping[str, Any]], plan: Any) -> list[Any]:
    if plan is None:
        # a persisted state with no plan to bind it to is never silently dropped
        _require(not records, "PLAN_MISSING_FOR_STATE", f"{len(records)} {engine} state(s) are persisted but this supplement carries no {engine} plan to bind them to")
        return []
    spec = lifecycle_for(engine)
    states: list[Any] = []
    for record in records:
        raw = dict(detached(record))
        _require("state" in raw, "STATE_RECORD_INVALID", f"a {engine} store record carries no 'state'; this planner reads persisted records, never bare ledgers")
        _require(str(raw.get("engine", engine)) == engine, "STATE_RECORD_INVALID", f"a record filed under {engine} says it belongs to {raw.get('engine')!r}")
        states.append(spec.State.model_validate(dict(raw["state"]), context={spec.plan_context_key: plan}))
    return states


def _action(
    actions: list[CadenceAction],
    kind: str,
    mode: str,
    engine: str,
    entity_ref: str,
    summary: str,
    *,
    event: str | None = None,
    fields: Sequence[str] = (),
    satisfied_by: Sequence[str] = (),
    prepared: Mapping[str, Any] | None = None,
    due_at: str | None = None,
    key: str | None = None,
) -> None:
    action_id = f"{kind}:{engine}:{entity_ref}" + (f":{event}" if event else "") + (f":{key}" if key else "")
    actions.append(CadenceAction(action_id=action_id, kind=kind, mode=mode, engine=engine, entity_ref=entity_ref, event=event, summary=summary[:900], required_receipt_fields=tuple(fields)[:12], satisfied_by=tuple(satisfied_by)[:8], prepared=dict(prepared or {}), due_at=due_at))


def _covers(employee: Any, start_at: str | None) -> bool:
    """Is this worker rostered across the moment the job starts, and not on leave?

    Every clause here is one ``job_chain``'s own ``assign`` guard re-checks
    (``ASSIGNEE_NOT_ROSTERED``, ``ASSIGNEE_ON_LEAVE``): an employee this returns
    ``True`` for is one whose ``assign_receipt`` the chain will accept, which is
    the whole licence for calling the resulting work item ``automatic``.
    """

    ledger = employee.ledger
    if employee.status not in _ROSTERED_STATUSES or not start_at:
        return False
    if bool(ledger.leave_open):
        return False
    if not ledger.current_period_start or not ledger.current_period_end:
        return False
    return parsed(str(ledger.current_period_start)) <= parsed(str(start_at)) <= parsed(str(ledger.current_period_end))


def plan_round7_actions(
    supplement: Round7Supplement | Mapping[str, Any],
    states: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    now: str,
    period: Round7Period | Mapping[str, Any] | None = None,
) -> tuple[CadenceAction, ...]:
    """Pure planner: from the persisted round-7 states and a clock, the next legal moves and the missing inputs.

    Only two modes are ever ``automatic``, and both are receipts this module
    builds from state already persisted *and the hop's guard would accept*:
    assigning a ``local_services`` job to a worker the roster covers and who is
    not on leave, and recording the period evidence of jobs whose cash landed.
    Everything else names the sealed artifact that would satisfy it, under an
    event the lifecycle table allows from the status it was raised for.
    """

    parsed_supplement = build_round7_supplement(supplement)
    stamp = timestamp(now, field_name="now")
    window = None if period is None else (period if isinstance(period, Round7Period) else Round7Period.model_validate(dict(detached(period))))
    rail = parsed_supplement.job_plan.rail
    employees = _bind("employment_chain", states.get("employment_chain", ()), parsed_supplement.employment_plan)
    jobs = _bind("job_chain", states.get("job_chain", ()), parsed_supplement.job_plan)
    wind_downs = _bind("wind_down_chain", states.get("wind_down_chain", ()), parsed_supplement.wind_down_plan)
    actions: list[CadenceAction] = []

    # -- people -------------------------------------------------------------- #
    if window is not None:
        for employee in employees:
            entity = str(employee.scope.entity_ref)
            ledger = employee.ledger
            # the same instant, however each side spelled it: a roster window and
            # an operating period are stamped by different artifacts.
            rostered_here = bool(ledger.current_period_start) and parsed(str(ledger.current_period_start)) == parsed(window.period_start)
            if employee.status in _ROSTERABLE_STATUSES and not rostered_here:
                event, fields, satisfied = _EMPLOYMENT_REQUIREMENTS["roster"]
                _action(actions, "roster_people", "needs_input", "employment_chain", entity, f"Roster {entity} for {window.period_ref}; a published roster is the only evidence", event=event, fields=fields, satisfied_by=satisfied, due_at=window.period_start, prepared={"period_start": window.period_start, "period_end": window.period_end})
            if rostered_here and parsed(stamp) >= parsed(window.period_end) and employee.status in _TIMESHEET_STATUSES:
                event, fields, satisfied = _EMPLOYMENT_REQUIREMENTS["record_time"]
                _action(actions, "approve_timesheets", "needs_input", "employment_chain", entity, f"The period closed {window.period_end}; {entity} needs an approved timesheet read, approved by somebody other than the worker", event=event, fields=fields, satisfied_by=satisfied, due_at=window.period_end)
            # ``record_pay`` is the only legal move out of ``time_recorded``: an
            # employee waiting on pay is never asked to be rostered again first.
            if employee.status == "time_recorded" and window.pay_date is not None and parsed(stamp) >= parsed(window.pay_date):
                event, fields, satisfied = _EMPLOYMENT_REQUIREMENTS["record_pay"]
                _action(actions, "run_pay", "needs_input", "employment_chain", entity, f"Pay day {window.pay_date}: {entity}'s share of a posted pay run", event=event, fields=fields, satisfied_by=satisfied, due_at=window.pay_date)

    # -- jobs ---------------------------------------------------------------- #
    if rail == "square":
        _action(actions, "book_jobs", "needs_input", "job_chain", f"{parsed_supplement.company_ref}:jobs", "Read the Square booking page for this window; a booking the provider never showed cannot open or advance a job", satisfied_by=("observation:square.observe_bookings",), due_at=None if window is None else window.period_end)
    for job in jobs:
        if job.status in JOB_LIFECYCLE.terminal:
            continue
        entity = str(job.scope.entity_ref)
        requirement = _JOB_REQUIREMENTS.get(job.status)
        if requirement is None:
            continue
        event, base_fields = requirement
        fields = _job_fields(event, rail, base_fields)
        satisfied = _job_satisfied_by(event, rail)
        if event == "assign":
            # a consulting job is assigned *under a staffed engagement*
            # (ENGAGEMENT_MISSING), and no engagement state is in this planner's
            # hand, so that profile's assignment is a question, never automatic.
            consulting = parsed_supplement.job_plan.profile == "consulting"
            covering = None if consulting else next((item for item in employees if _covers(item, job.ledger.start_at)), None)
            if covering is not None:
                receipt = assign_receipt(covering, employment_plan=parsed_supplement.employment_plan)
                _action(actions, "assign_jobs", "automatic", "job_chain", entity, f"Assign {entity} to {covering.scope.entity_ref}, who is rostered across {job.ledger.start_at}", event=event, fields=fields, satisfied_by=satisfied, prepared=receipt)
            elif consulting:
                _action(actions, "assign_jobs", "needs_input", "job_chain", entity, f"engagement_required: a consulting job is assigned under a staffed engagement; name the engagement_engine state covering {job.ledger.start_at}", event=event, fields=(*fields, "engagement_source"), satisfied_by=satisfied, prepared={"reason": "engagement_required", "start_at": job.ledger.start_at}, due_at=job.ledger.start_at)
            else:
                _action(actions, "assign_jobs", "needs_input", "job_chain", entity, f"roster_gap: nobody is rostered across {job.ledger.start_at}; roster somebody or move the booking", event=event, fields=fields, satisfied_by=satisfied, prepared={"reason": "roster_gap", "start_at": job.ledger.start_at}, due_at=job.ledger.start_at)
            continue
        hint = _authority_hint("job_chain", event)
        mode = "needs_approval" if ("job_chain", event) in _NEEDS_APPROVAL else "needs_input"
        prepared: dict[str, Any] = {"rail": rail}
        if hint is not None:
            prepared["authority"] = hint
        _action(actions, "advance_job", mode, "job_chain", entity, f"{entity} is {job.status}; next is {event}", event=event, fields=fields, satisfied_by=satisfied, prepared=prepared)

    # -- period evidence: the paid job's cash, not its quoted value ----------- #
    if window is not None:
        # half-open on the instants, not on the strings: two stamps of the same
        # moment need not be spelled the same way.
        opened, closes = parsed(window.period_start), parsed(window.period_end)
        paid = [job for job in jobs if job.ledger.paid_at and opened <= parsed(str(job.ledger.paid_at)) < closes]
        if paid:
            receipts = [period_evidence_receipt(job, plan=parsed_supplement.job_plan) for job in paid]
            engine = str(receipts[0]["engine"])
            revenue = sum((decimal_value(item["revenue"], field_name="revenue") for item in receipts), Decimal("0")).quantize(MONEY_QUANTUM)
            evidence_ref = f"jobs:{window.period_ref}:{stable_digest({'jobs': sorted(str(job.scope.entity_ref) for job in paid)})[:16]}"
            _action(
                actions,
                "collect_evidence",
                "automatic",
                "company_operating_system",
                window.period_ref,
                f"{len(paid)} job(s) settled {revenue} {parsed_supplement.currency} of {engine} revenue in {window.period_ref}",
                event="record_evidence",
                fields=("engine", "evidence_ref", "spend", "revenue", "signals"),
                satisfied_by=("job_chain.state",),
                prepared={"engine": engine, "evidence_ref": evidence_ref, "spend": "0", "revenue": str(revenue), "signals": [], "sources": receipts},
                due_at=window.period_end,
                key=engine,
            )

    # -- wind-down ----------------------------------------------------------- #
    for wind_down in wind_downs:
        if wind_down.status in TERMINAL_WIND_DOWN_STATUSES:
            continue
        requirement = _WIND_DOWN_REQUIREMENTS.get(wind_down.status)
        if requirement is None:
            continue
        event, fields, satisfied = requirement
        _action(actions, "wind_down_step", "needs_input", "wind_down_chain", str(wind_down.scope.entity_ref), f"Wind-down is {wind_down.status}; next is {event}", event=event, fields=fields, satisfied_by=satisfied)
    return tuple(actions)


# --------------------------------------------------------------------------- #
# The reads those work items ask for
# --------------------------------------------------------------------------- #


#: ``satisfied_by token -> (tool, closed input keys, keys the platform fills)``.
#: The key sets are the adapters' own reviewed sets; an id-bearing key is named
#: here and valued by the platform from its correlation, never by the SDK.
ROUND7_OBSERVATION_TOOLS: Mapping[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "observation:xero.observe_timesheets": ("xero.observe_timesheets", ("period_start", "period_end", "page"), ()),
    "observation:xero.observe_leave": ("xero.observe_leave", ("period_start", "period_end", "page"), ()),
    "observation:xero.observe_payrun": ("xero.observe_payrun", ("pay_run_id",), ("pay_run_id",)),
    "observation:xero.observe_headcount": ("xero.observe_headcount", ("status", "page"), ()),
    "observation:xero.observe_quote": ("xero.observe_quote", ("quote_id", "correlation_ref"), ("quote_id", "correlation_ref")),
    "observation:square.observe_bookings": ("square.observe_bookings", ("location_id", "start_at_min", "start_at_max", "limit"), ("location_id",)),
    "observation:square.observe_invoice_payment": ("square.observe_invoice_payment", ("invoice_id", "correlation_ref"), ("invoice_id", "correlation_ref")),
    "observation:xero.list_payments": ("xero.list_payments", ("where", "page"), ("where",)),
}

#: The page size ``SquareJobObservationEvidence.BOOKING_PAGE_SIZE`` fixes.  The
#: adapter refuses any other value ("limit must be exactly 25"), so a request
#: that named a different one would be sealed here and rejected there.
SQUARE_BOOKING_PAGE_SIZE = 25
#: ``tool -> the widest window its adapter parses``.  ``requireBookingWindow``
#: caps a Square booking read at 31 days and ``WindowQuery`` caps a Xero payroll
#: window at 62; a period longer than that is split by the caller, never asked
#: for in one read.
_OBSERVATION_WINDOW_DAYS: Mapping[str, int] = {
    "square.observe_bookings": 31,
    "xero.observe_timesheets": 62,
    "xero.observe_leave": 62,
}


class Round7ObservationRequest(StrictModel):
    """One governed read a work item needs: the tool, its closed inputs, and what the platform must fill."""

    schema_id: str = Field(default=OBSERVATION_REQUEST_SCHEMA, alias="schema")
    action_id: OpaqueRef
    tool: ShortText
    input_keys: tuple[ShortText, ...] = Field(min_length=1, max_length=8)
    arguments: dict[str, Any] = Field(default_factory=dict)
    supplied_by_platform: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    window_start: str
    window_end: str
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end")
    @classmethod
    def _window(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Round7ObservationRequest:
        for key in self.arguments:
            if key not in self.input_keys:
                raise ValueError(f"{self.tool} does not review the input {key!r}")
            # naming an identifier key is the whole point; valuing one is the
            # boundary this module exists to hold.  The platform fills these
            # from its own correlation and the SDK never mints a provider id.
            if key in self.supplied_by_platform:
                raise ValueError(f"{self.tool} input {key!r} is filled by the platform's own correlation; the SDK names it and never values it")
        if not skip_digests(info) and self.request_digest != sealed_digest(Round7ObservationRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self


def round7_observation_requests(actions: Sequence[CadenceAction | Mapping[str, Any]], *, window_start: str, window_end: str) -> tuple[Round7ObservationRequest, ...]:
    """The governed reads this tick's work items ask for, with the window filled and every identifier left to the platform."""

    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    ordered = parsed(end) > parsed(start)
    _require(ordered, "OBSERVATION_WINDOW_INVALID", "window_end must follow window_start")
    span = (parsed(end) - parsed(start)).days
    requests: dict[str, Round7ObservationRequest] = {}
    for raw in actions:
        action = raw if isinstance(raw, CadenceAction) else CadenceAction.model_validate(dict(detached(raw)))
        for token in action.satisfied_by:
            entry = ROUND7_OBSERVATION_TOOLS.get(str(token))
            if entry is None:
                continue
            tool, keys, supplied = entry
            cap = _OBSERVATION_WINDOW_DAYS.get(tool)
            _require(cap is None or span <= cap, "OBSERVATION_WINDOW_TOO_WIDE", f"{tool} reads at most {cap} days at a time; this window is {span}. Split it rather than sealing a read the adapter refuses")
            arguments: dict[str, Any] = {}
            if "period_start" in keys:
                arguments.update({"period_start": start[:10], "period_end": end[:10], "page": 1})
            if "start_at_min" in keys:
                arguments.update({"start_at_min": start, "start_at_max": end, "limit": SQUARE_BOOKING_PAGE_SIZE})
            if "status" in keys and tool.endswith("observe_headcount"):
                arguments.update({"status": "ACTIVE", "page": 1})
            if "page" in keys and tool.endswith("list_payments"):
                arguments.update({"page": 1})
            request = seal(Round7ObservationRequest, {"action_id": action.action_id, "tool": tool, "input_keys": keys, "arguments": arguments, "supplied_by_platform": supplied, "window_start": start, "window_end": end}, "request_digest")
            requests[f"{action.action_id}:{tool}"] = request
    return tuple(requests[key] for key in sorted(requests))


# --------------------------------------------------------------------------- #
# Readiness
# --------------------------------------------------------------------------- #


class Round7EngineReadiness(StrictModel):
    engine: ShortText
    required_groups: tuple[tuple[ShortText, ...], ...] = Field(default_factory=tuple, max_length=6)
    satisfied_by: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    missing_groups: tuple[tuple[ShortText, ...], ...] = Field(default_factory=tuple, max_length=6)
    ready: bool

    @field_validator("required_groups", "missing_groups", mode="before")
    @classmethod
    def _groups(cls, value: object) -> object:
        if isinstance(value, (list, tuple)):
            return tuple(tuple(group) if isinstance(group, (list, tuple)) else group for group in value)
        return value


class Round7Readiness(StrictModel):
    """Whether the round-7 engines of one supplement can go live, and what is missing."""

    schema_id: str = Field(default=READINESS_SCHEMA, alias="schema")
    supplement_digest: Sha256Digest
    assessed_at: str
    connected: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    engines: tuple[Round7EngineReadiness, ...] = Field(default_factory=tuple, max_length=8)
    blocked_engines: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    people_rostered: int = Field(default=0, ge=0)
    gates: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    ready: bool = False
    readiness_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Round7Readiness:
        if not skip_digests(info) and self.readiness_digest != sealed_digest(Round7Readiness, self, "readiness_digest"):
            raise ValueError("readiness_digest must commit the exact readiness")
        return self


def rostered_people(supplement: Round7Supplement | Mapping[str, Any], states: Mapping[str, Sequence[Mapping[str, Any]]]) -> int:
    """How many employees this company has actually put on a roster."""

    parsed_supplement = build_round7_supplement(supplement)
    return sum(1 for state in _bind("employment_chain", states.get("employment_chain", ()), parsed_supplement.employment_plan) if state.status in _ROSTERED_STATUSES)


def require_people_rostered(supplement: Round7Supplement | Mapping[str, Any], states: Mapping[str, Sequence[Mapping[str, Any]]]) -> int:
    """A company that employs people does not go live before one of them is on a roster."""

    count = rostered_people(supplement, states)
    _require(count > 0, "PEOPLE_NOT_ROSTERED", "this company carries an employment plan; at least one employee must be rostered before go-live, or the first job has nobody to assign")
    return count


def assess_round7_readiness(
    supplement: Round7Supplement | Mapping[str, Any],
    connections: Sequence[Mapping[str, Any]],
    *,
    now: str,
    states: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> Round7Readiness:
    """Compare the supplement's engines against the connected providers; pure, deterministic, sealed."""

    parsed_supplement = build_round7_supplement(supplement)
    stamp = timestamp(now, field_name="now")
    providers = {normalize_provider(dict(detached(row)).get("provider")) for row in connections}
    providers.discard("")
    # the plans this supplement actually carries, in the order it carries them,
    # narrowed to the ones any connector group names -- never a hardcoded pair.
    engines = [engine for engine in parsed_supplement.supporting_plans() if engine in ROUND7_CONNECTOR_GROUPS]
    rows: list[Round7EngineReadiness] = []
    for engine in engines:
        groups = ROUND7_CONNECTOR_GROUPS.get(engine, ())
        satisfied = sorted({provider for group in groups for provider in group if provider in providers})
        missing = tuple(group for group in groups if not any(provider in providers for provider in group))
        rows.append(Round7EngineReadiness(engine=engine, required_groups=groups, satisfied_by=tuple(satisfied), missing_groups=missing, ready=not missing))
    count = 0 if states is None else rostered_people(parsed_supplement, states)
    gates = [] if (states is None or count > 0) else ["PEOPLE_NOT_ROSTERED"]
    blocked = [row.engine for row in rows if not row.ready]
    return seal(
        Round7Readiness,
        {"supplement_digest": parsed_supplement.supplement_digest, "assessed_at": stamp, "connected": tuple(sorted(providers)), "engines": tuple(row.to_dict() for row in rows), "blocked_engines": tuple(blocked), "people_rostered": count, "gates": tuple(gates), "ready": not blocked and not gates},
        "readiness_digest",
    )


# --------------------------------------------------------------------------- #
# The console's rows
# --------------------------------------------------------------------------- #


def round7_summary(
    supplement: Round7Supplement | Mapping[str, Any],
    states: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    now: str,
    period: Round7Period | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """What the ``employees`` / ``jobs`` / ``wind_down`` console verbs render, from the persisted states alone."""

    parsed_supplement = build_round7_supplement(supplement)
    stamp = timestamp(now, field_name="now")
    window = None if period is None else (period if isinstance(period, Round7Period) else Round7Period.model_validate(dict(detached(period))))
    employees = _bind("employment_chain", states.get("employment_chain", ()), parsed_supplement.employment_plan)
    jobs = _bind("job_chain", states.get("job_chain", ()), parsed_supplement.job_plan)
    wind_downs = _bind("wind_down_chain", states.get("wind_down_chain", ()), parsed_supplement.wind_down_plan)
    summary: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "company_ref": str(parsed_supplement.company_ref),
        "archetype": parsed_supplement.archetype,
        "currency": parsed_supplement.currency,
        "supplement_digest": parsed_supplement.supplement_digest,
        "at": stamp,
        "employees": {
            "count": len(employees),
            "rostered": sum(1 for item in employees if item.status in _ROSTERED_STATUSES),
            "rows": [employee_summary(item) for item in employees],
            "headcount": headcount_receipt(employees, plan=parsed_supplement.employment_plan) if employees else None,
            "narration": [narrate_employee(item, currency=parsed_supplement.currency) for item in employees],
        },
        "jobs": {**jobs_summary(jobs), "narration": [narrate_job(item, currency=parsed_supplement.currency, plan=parsed_supplement.job_plan) for item in jobs]},
        "wind_down": [{**wind_down_summary(item, plan=parsed_supplement.wind_down_plan), "narration": narrate_wind_down(item, currency=parsed_supplement.currency)} for item in wind_downs],
    }
    if window is not None and employees:
        summary["capacity_expectation"] = capacity_expectation(employees, plan=parsed_supplement.employment_plan, period_start=window.period_start, period_end=window.period_end)
        summary["timesheet_expectation"] = timesheet_expectation(employees, plan=parsed_supplement.employment_plan, period_start=window.period_start, period_end=window.period_end)
    return summary


ROUND7_BINDINGS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": BINDINGS_KIND,
    "golden_loop": BINDINGS_GOLDEN_LOOP,
    "stages": ["compile_supplement", "register_runtimes", "plan_work_items", "plan_reads", "assess_readiness", "summarize"],
    "statuses": [],
    "events": [],
    "hops": list(ROUND7_ACTION_KINDS),
    "engines": list(ROUND7_ENGINES),
    "archetypes": list(ROUND7_ARCHETYPES),
    "console_verbs": sorted(ROUND7_CONSOLE_VERBS),
    "action_kinds": dict(ROUND7_CHAIN_ACTION_KINDS),
    "authority_categories": list(ROUND7_AUTHORITY_CATEGORIES),
    "required_connectors": sorted({provider for groups in ROUND7_CONNECTOR_GROUPS.values() for group in groups for provider in group}),
    "hard_rules": [
        "the job chain must name this company's employment plan, or an assignment proves nothing about who was rostered",
        "a wind-down plan names the exact cadence bundle it shuts down",
        "only two work items are ever automatic, and both are receipts built from persisted state: assigning a job the roster covers, and the period evidence of jobs whose cash landed",
        "the period's service revenue is the job's paid cash, never its quoted value",
        "a company that employs people does not go live before one of them is rostered",
        "the SDK names an observation's identifier keys and never values them; the platform fills them from its own correlation",
        "a work item names an event the lifecycle table allows from the status it was raised for, and every receipt field that hop's guard reads",
        "a read is sealed only in a shape its adapter parses: the reviewed key set, the fixed page size, the window cap",
    ],
}

__all__ = [
    "ARCHETYPE_RAILS",
    "BINDINGS_GOLDEN_LOOP",
    "BINDINGS_KIND",
    "CONSULTING_FIRM_ARCHETYPE",
    "CONSULTING_FIRM_ROSTER",
    "OBSERVATION_REQUEST_SCHEMA",
    "READINESS_SCHEMA",
    "ROUND7_ACTION_KINDS",
    "ROUND7_ADDITIONAL_HOPS",
    "ROUND7_ARCHETYPES",
    "ROUND7_AUTHORITY_CATEGORIES",
    "ROUND7_BINDINGS_MANIFEST",
    "ROUND7_CHAIN_ACTION_KINDS",
    "ROUND7_CHAIN_ENGINES",
    "ROUND7_CHAIN_MODULES",
    "ROUND7_CHAIN_VERBS",
    "ROUND7_COMPANY_MODULES",
    "ROUND7_CONNECTOR_GROUPS",
    "ROUND7_CONSOLE_VERBS",
    "ROUND7_ENGINES",
    "ROUND7_FAULT_KINDS",
    "ROUND7_LIFECYCLE_TARGETS",
    "ROUND7_MCP_TOOLS",
    "ROUND7_OBSERVATION_TOOLS",
    "ROUND7_OPERATOR_CHAIN_MODULES",
    "ROUND7_RECEIVABLE_STATE_SCHEMAS",
    "ROUND7_REVENUE_STATE_SCHEMAS",
    "ROUND7_ROLE_TEMPLATES",
    "ROUND7_SETTLED_REVENUE_STATUSES",
    "ROUND7_SIGNAL_INTENTS",
    "SQUARE_BOOKING_PAGE_SIZE",
    "SUMMARY_SCHEMA",
    "SUPPLEMENT_SCHEMA",
    "Round7BindingsError",
    "Round7EngineReadiness",
    "Round7ObservationRequest",
    "Round7Period",
    "Round7Readiness",
    "Round7Supplement",
    "advance_for",
    "assess_round7_readiness",
    "build_round7_supplement",
    "compile_round7_supplement",
    "install_round7_runtimes",
    "lifecycle_for",
    "merge_kinds",
    "merge_registry",
    "plan_model_for",
    "plan_round7_actions",
    "require_people_rostered",
    "rostered_people",
    "round7_observation_requests",
    "round7_runtimes",
    "round7_summary",
]
