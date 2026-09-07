"""The front door's critical path: a simulated blueprint run as a replay-fenced lifecycle to the first settled dollar.

``launch_blueprint`` compiles what a person declared and what the platform's
planning runs produced into a :class:`~lightbulb.launch_blueprint.LaunchBlueprint`
where every field names its source.  A blueprint is still only a document.  This
module turns one into a plan the platform can actually be held to, and then runs
it:

* :func:`compile_launch_plan` refuses to plan before it has simulated.  It
  compiles the blueprint's operating blueprint into a
  :class:`~lightbulb.company_operating_system.CompanyOperatingPlan`, runs
  ``company_simulator`` over the kill-or-scale window, and seals the outcome as
  a :class:`LaunchSimulation` pinned into the plan.  A run that halts before it
  earns, never earns at all, dips under the cash floor, forecasts the first
  dollar past the target, or spends past the cap is refused - before a dollar
  moves.
* ``LAUNCH_LIFECYCLE`` walks ``planned -> formed -> registered -> banked ->
  paper_signed -> insured -> licensed -> payments_ready -> provisioned ->
  connectors_verified -> live -> first_dollar -> scaled | killed``.  The
  automated hops consume real platform outputs - the guided formation response,
  a page-builder deploy, a phone purchase, a connector readiness assessment, a
  bring-up report, a SETTLED Stripe settlement or a settled revenue case.  The
  legally human hops (registrar filing, the bank account and its KYC, wet
  signatures, insurance, licences, Stripe hosted onboarding, the kill-or-scale
  decision) are refused with ``*_APPROVAL_REQUIRED`` until a ``sdk_launch_gate``
  task **decided by a person other than the requester** is bound to that exact
  sealed command.
* :class:`LaunchGateLane` is that approval lane.  ``bind_approval`` refuses any
  task whose ``approvalType`` is not ``sdk_engine_transition``, so the launch
  gate carries its own request, bind, and re-issue path and plugs into
  ``EngineRuntime`` through ``approval_lane``.

What it hands on: a sealed :class:`LaunchPlan` (with its pinned simulation),
persisted ``company_launch`` states, and ``LaunchGateApprovalRequest`` bodies for
``POST /api/workflows/approvals/launch-gates``.  Nothing here forms a company,
files anything, provisions anything, or moves money; every number in the ledger
came off a receipt built from a sealed artifact or an attestation that names
itself as operator-supplied.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic import ValidationError as _PydanticValidationError

from lightbulb.company_bring_up import BringUpReport, ConnectorReadiness
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
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
from lightbulb.company_engine_store import EngineRuntime
from lightbulb.company_execution_bridge import ApprovalBinding, ObservationProvenance, command_with_approval
from lightbulb.company_formation import NEXT_STEP_OPEN_WORKSPACE, normalize_formation_country
from lightbulb.company_operating_system import CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_simulator import MAX_PERIODS, build_scenario, simulate_company, standard_scenario
from lightbulb.company_treasury import BALANCE_TOOLS, CashPosition
from lightbulb.launch_blueprint import LaunchBlueprint, OperatorIntent
from lightbulb.revenue_chain import settlement_receipt

LAUNCH_KIND = "company_launch"
LAUNCH_GOLDEN_LOOP = "company.idea_to_first_dollar@0.1.0"
LAUNCH_PLAN_SCHEMA = "lightbulb.company_launch_plan.v1"
LAUNCH_SIMULATION_SCHEMA = "lightbulb.company_launch_simulation.v1"
LAUNCH_GATE_REQUEST_SCHEMA = "lightbulb.launch_gate_request.v1"
LAUNCH_GATE_BINDING_SCHEMA = "lightbulb.launch_gate_binding.v1"
LAUNCH_GATE_APPROVAL_TYPE = "sdk_launch_gate"
LAUNCH_GATES_PATH = "/api/workflows/approvals/launch-gates"
MAX_LAUNCH_TRANSITIONS = 64
MIN_LAUNCH_STEPS, MAX_LAUNCH_STEPS = 10, 16
SETTLEMENT_OBSERVATION_SCHEMA = "lightbulb.stripe_cash_settlement_observation.v1"
SIGNING_TOOL = "signing.get_envelope"

# ``reject_secret_like_payload`` does not treat a UUID as identity-like, so the module refuses one
# itself: a launch names its company by slug, never by the id Spring minted.
_COMPANY_REF = re.compile(r"^company:[a-z0-9][a-z0-9-]{0,79}$")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

REGISTRARS_BY_COUNTRY: Mapping[str, tuple[str, ...]] = {
    "AU": ("ASIC", "Australian Securities & Investments Commission (ASIC)"),
    "CA": ("Corporations Canada", "Corporations Canada / provincial registrar", "provincial_registrar"),
}
REGISTRATION_NUMBER_BY_COUNTRY: Mapping[str, str] = {"AU": "ABN", "CA": "CRA BN"}
ARCHETYPE_FIRST_DOLLAR_DAYS: Mapping[str, int] = {"services_firm": 30, "dtc_commerce": 45, "marketplace": 60, "b2b_saas": 90}
STOREFRONT_REQUIRED: Mapping[str, tuple[str, ...]] = {"services_firm": ("website", "phone_number")}
_DEFAULT_STOREFRONT: tuple[str, ...] = ("website",)

ProvisioningKind = Literal["website", "phone_number"]
GateKind = Literal[
    "entity_registered",
    "bank_account_opened",
    "signature_executed",
    "insurance_bound",
    "licence_granted",
    "payments_onboarding_completed",
    "kill_or_scale_decided",
]
HumanRole = Literal["director", "signatory", "account_holder", "broker", "licensing_authority", "operator"]
StepKind = Literal["automated", "platform_read", "platform_write", "human_gate"]

GATE_FOR_EVENT: Mapping[str, str] = {
    "register": "entity_registered",
    "open_bank": "bank_account_opened",
    "sign_paper": "signature_executed",
    "bind_insurance": "insurance_bound",
    "grant_licence": "licence_granted",
    "verify_payments": "payments_onboarding_completed",
    "scale": "kill_or_scale_decided",
    "kill": "kill_or_scale_decided",
}
GATE_ATTESTATION: Mapping[str, str] = {
    "entity_registered": "the director or registered agent files with the registrar outside Lightbulb",
    "bank_account_opened": "the account holder opens the account and passes the bank's KYC outside Lightbulb",
    "signature_executed": "the signatories sign outside Lightbulb",
    "insurance_bound": "a broker binds the cover outside Lightbulb",
    "licence_granted": "the licensing authority grants the licence outside Lightbulb",
    "payments_onboarding_completed": "the account holder completes Stripe hosted onboarding on Stripe's own page",
    "kill_or_scale_decided": "the director decides scale or kill at the fixed date",
}

LAUNCH_STATUSES: tuple[str, ...] = (
    "planned", "formed", "registered", "banked", "paper_signed", "insured", "licensed", "payments_ready",
    "provisioned", "connectors_verified", "live", "first_dollar", "scaled", "killed", "abandoned",
)
TERMINAL_LAUNCH_STATUSES: frozenset[str] = frozenset({"scaled", "killed", "abandoned"})
LAUNCH_EVENTS: tuple[str, ...] = (
    "plan", "form", "register", "open_bank", "sign_paper", "bind_insurance", "grant_licence", "verify_payments",
    "provision", "verify_connectors", "go_live", "record_first_dollar", "scale", "kill", "abandon",
)
_LAUNCH_TABLE: dict[tuple[str, str], str] = {
    ("new", "plan"): "planned",
    ("planned", "form"): "formed",
    ("formed", "register"): "registered",
    ("registered", "open_bank"): "banked",
    ("banked", "sign_paper"): "paper_signed",
    ("paper_signed", "sign_paper"): "paper_signed",
    ("paper_signed", "bind_insurance"): "insured",
    # A blueprint may legitimately require no paper at all (nothing to sign, nothing to block on);
    # without this edge such a plan compiles and then dies at ``banked`` with ILLEGAL_TRANSITION.
    ("banked", "bind_insurance"): "insured",
    ("insured", "grant_licence"): "licensed",
    ("licensed", "grant_licence"): "licensed",
    ("insured", "verify_payments"): "payments_ready",
    ("licensed", "verify_payments"): "payments_ready",
    # Cover is no more universal than paper: a blueprint may require none at all, and
    # ``insurance_attestation`` refuses every kind such a blueprint did not ask for, so without these
    # edges a plan that legitimately needs no cover compiles and then dies at ``paper_signed`` (or at
    # ``banked``) with ILLEGAL_TRANSITION.  ``_paper_and_cover`` keeps the skip honest: a plan that
    # DOES require cover still owes it - and its paper - on whichever edge reaches these hops.
    ("banked", "grant_licence"): "licensed",
    ("paper_signed", "grant_licence"): "licensed",
    ("banked", "verify_payments"): "payments_ready",
    ("paper_signed", "verify_payments"): "payments_ready",
    ("payments_ready", "provision"): "provisioned",
    ("provisioned", "provision"): "provisioned",
    ("provisioned", "verify_connectors"): "connectors_verified",
    ("connectors_verified", "verify_connectors"): "connectors_verified",
    ("connectors_verified", "go_live"): "live",
    ("live", "record_first_dollar"): "first_dollar",
    ("live", "kill"): "killed",
    ("first_dollar", "kill"): "killed",
    ("first_dollar", "scale"): "scaled",
    **{(status, "abandon"): "abandoned" for status in LAUNCH_STATUSES if status not in TERMINAL_LAUNCH_STATUSES},
}


class LaunchPlanError(ValueError):
    """A blueprint, artifact, or approval task does not prove what the caller claims; carries a code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LaunchPlanError(code, message)


def _sha(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _document(value: Any) -> dict[str, Any]:
    """A plain mapping from a model, a dataclass carrying ``to_dict``, or a mapping."""

    if not isinstance(value, Mapping):
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return dict(detached(to_dict()))
    return dict(detached(value))


def _stamp(value: Any, *, field_name: str) -> str:
    """Normalise a provider timestamp; DocuSign returns seven fractional digits."""

    text = str(value)
    try:
        return timestamp(text, field_name=field_name)
    except ValueError:
        if "T" in text and "." in text:
            return timestamp(text.split(".")[0] + "Z", field_name=field_name)
        raise


def _money(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    return decimal_value(value, field_name=field_name, allow_negative=allow_negative)


# --------------------------------------------------------------------------- #
# The plan: targets, steps, and the simulation that had to pass first
# --------------------------------------------------------------------------- #


class LaunchTargets(StrictModel):
    """The dates and the money the launch is held to; the archetype's defaults until an operator overrides them."""

    time_to_first_dollar_days: int = Field(ge=1, le=365)
    kill_or_scale_days: int = Field(ge=1, le=730)
    cash_floor: Decimal
    max_spend_before_first_dollar: Decimal
    targets_source: Literal["archetype_default", "operator"] = "archetype_default"

    @field_validator("cash_floor", "max_spend_before_first_dollar", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> LaunchTargets:
        if self.kill_or_scale_days < self.time_to_first_dollar_days:
            raise ValueError(f"KILL_BEFORE_TARGET: the kill-or-scale date ({self.kill_or_scale_days}d) cannot precede the first-dollar target ({self.time_to_first_dollar_days}d)")
        return self


class LaunchStep(StrictModel):
    """One step of the critical path: who does it, what proves it, and by which day."""

    step_ref: OpaqueRef
    event: ShortText
    title: ShortText
    kind: StepKind
    gate_kind: GateKind | None = None
    human_role: HumanRole | None = None
    verb: ShortText
    produces: ShortText
    target_day: int = Field(ge=0, le=365)
    blocking_requirements: tuple[OpaqueRef, ...] = Field(default=(), max_length=20)

    @field_validator("blocking_requirements", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _gate_shape(self) -> LaunchStep:
        expected = GATE_FOR_EVENT.get(self.event)
        if (self.kind == "human_gate") != (self.gate_kind is not None):
            raise ValueError("a human gate names its gate_kind and nothing else does")
        if self.gate_kind is not None and self.gate_kind != expected:
            raise ValueError(f"{self.event} is the {expected} gate, not {self.gate_kind}")
        if (self.kind == "human_gate") != (self.human_role is not None):
            raise ValueError("a human gate names the role that performs it")
        return self


class LaunchSimulation(StrictModel):
    """The forecast the plan is pinned to: synthetic, executed nothing, and sealed with its scenario and result."""

    schema_id: str = Field(default=LAUNCH_SIMULATION_SCHEMA, alias="schema")
    operating_plan_digest: Sha256Digest
    scenario_digest: Sha256Digest
    result_digest: Sha256Digest
    periods_run: int = Field(ge=1, le=MAX_PERIODS)
    first_revenue_period: int | None = Field(default=None, ge=1, le=MAX_PERIODS)
    spend_before_first_revenue: Decimal
    total_spend: Decimal
    total_revenue: Decimal
    min_cash: Decimal
    final_cash: Decimal
    halted_at_period: int | None = Field(default=None, ge=1, le=MAX_PERIODS)
    halt_reason: ShortText | None = None
    synthetic: Literal[True] = True
    simulation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("spend_before_first_revenue", "total_spend", "total_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name))

    @field_validator("min_cash", "final_cash", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchSimulation:
        if not skip_digests(info) and self.simulation_digest != sealed_digest(LaunchSimulation, self, "simulation_digest"):
            raise ValueError("simulation_digest must commit the exact simulation")
        return self


class _PlanCurrency:
    """What ``LifecycleSpec.open`` reads off ``plan.blueprint`` to fence the scope currency."""

    __slots__ = ("currency",)

    def __init__(self, currency: str) -> None:
        self.currency = currency


class LaunchPlan(StrictModel):
    """The critical path from a simulated blueprint to the first settled dollar, sealed."""

    schema_id: str = Field(default=LAUNCH_PLAN_SCHEMA, alias="schema")
    company_name: ShortText
    archetype: ShortText
    country: str = Field(min_length=2, max_length=2)
    region_code: ShortText
    currency: CurrencyCode
    period_days: int = Field(ge=1, le=92)
    blueprint_digest: Sha256Digest
    operating_plan_digest: Sha256Digest
    simulation: LaunchSimulation
    first_dollar_day_forecast: int | None = Field(default=None, ge=0, le=730)
    targets: LaunchTargets
    steps: tuple[LaunchStep, ...] = Field(min_length=MIN_LAUNCH_STEPS, max_length=MAX_LAUNCH_STEPS)
    required_paper_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=12)
    paper_content_digests: dict[str, str] = Field(default_factory=dict)
    required_licence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=20)
    required_insurance_kinds: tuple[ShortText, ...] = Field(default=(), max_length=12)
    registrars: tuple[ShortText, ...] = Field(min_length=1, max_length=4)
    storefront_required: tuple[ShortText, ...] = Field(default=(), max_length=4)
    planned_at: str
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("planned_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="planned_at")

    @field_validator("steps", "required_paper_refs", "required_licence_refs", "required_insurance_kinds", "registrars", "storefront_required", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchPlan:
        unique([step.step_ref for step in self.steps], label="step refs")
        order = {event: index for index, event in enumerate(LAUNCH_EVENTS)}
        events = [step.event for step in self.steps]
        for event in events:
            if event not in order:
                raise ValueError(f"{event} is not a launch event")
        collapsed = [event for index, event in enumerate(events) if index == 0 or event != events[index - 1]]
        unique(collapsed, label="launch step events (only provision, sign_paper and grant_licence repeat)")
        if [order[event] for event in collapsed] != sorted(order[event] for event in collapsed):
            raise ValueError("launch steps must follow the lifecycle event order")
        for step in self.steps:
            if step.event == "sign_paper" and not set(step.blocking_requirements) <= set(self.required_paper_refs):
                raise ValueError("a sign_paper step blocks only on the plan's required paper")
        for ref in self.required_paper_refs:
            if ref not in self.paper_content_digests:
                raise ValueError(f"required paper {ref} has no content digest to sign against")
        if not skip_digests(info) and self.plan_digest != sealed_digest(LaunchPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    @property
    def blueprint(self) -> _PlanCurrency:
        """The currency fence ``LifecycleSpec.open`` checks the scope against."""

        return _PlanCurrency(self.currency)

    def step(self, event: str) -> LaunchStep | None:
        return next((item for item in self.steps if item.event == event), None)

    def steps_for(self, event: str) -> tuple[LaunchStep, ...]:
        return tuple(item for item in self.steps if item.event == event)

    @property
    def human_gates(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(step.gate_kind) for step in self.steps if step.gate_kind is not None))


# --------------------------------------------------------------------------- #
# Simulate before spend
# --------------------------------------------------------------------------- #


def simulate_launch(
    operating_plan: CompanyOperatingPlan | Mapping[str, Any],
    *,
    planned_at: str,
    opening_cash: Any,
    fixed_costs_per_period: Any,
    kill_window_days: int,
    assumptions: Sequence[Mapping[str, Any]] = (),
) -> LaunchSimulation:
    """Run the operating plan over the kill-or-scale window and seal the forecast; nothing here executes."""

    plan = operating_plan if isinstance(operating_plan, CompanyOperatingPlan) else CompanyOperatingPlan.model_validate(detached(operating_plan))
    period_days = plan.blueprint.period_days
    periods = max(1, min(MAX_PERIODS, math.ceil(kill_window_days / period_days)))
    base = standard_scenario("steady_state").to_dict()
    base.pop("scenario_digest", None)
    base.update({
        "name": "launch_forecast",
        "periods": periods,
        "start_at": timestamp(planned_at, field_name="planned_at"),
        "starting_cash": str(_money(opening_cash, field_name="opening_cash")),
        "fixed_costs_per_period": str(_money(fixed_costs_per_period, field_name="fixed_costs_per_period")),
        "assumptions": [dict(detached(item)) for item in assumptions],
        "replan_each_period": False,
    })
    scenario = build_scenario(base)
    result = simulate_company(plan, scenario)
    first = next((period.period for period in result.periods if period.revenue > 0), None)
    spend = sum((period.spend for period in result.periods if first is None or period.period <= first), Decimal("0"))
    return seal(LaunchSimulation, {
        "operating_plan_digest": plan.plan_digest,
        "scenario_digest": scenario.scenario_digest,
        "result_digest": result.result_digest,
        "periods_run": result.periods_run,
        "first_revenue_period": first,
        "spend_before_first_revenue": str(spend),
        "total_spend": str(result.total_spend),
        "total_revenue": str(result.total_revenue),
        "min_cash": str(result.min_cash),
        "final_cash": str(result.final_cash),
        "halted_at_period": result.halted_at_period,
        "halt_reason": result.halt_reason,
    }, "simulation_digest")


def _launch_cash(blueprint: LaunchBlueprint, intent: Any) -> tuple[Decimal, Decimal]:
    """Opening cash and fixed costs: off the blueprint when it carries them, otherwise off the sealed intent it compiled from."""

    cash, fixed = getattr(blueprint, "starting_cash", None), getattr(blueprint, "fixed_costs_per_period", None)
    if cash is not None and fixed is not None:
        return _money(cash, field_name="starting_cash"), _money(fixed, field_name="fixed_costs_per_period")
    _require(intent is not None, "INTENT_MISSING", "the blueprint carries no starting cash; supply the sealed operator intent it compiled from")
    # The intent is parsed through its own model, so ``intent_digest`` is a seal the payload has to
    # earn - a hand-written mapping that merely copies the digest and lies about the cash is refused.
    try:
        sealed = intent if isinstance(intent, OperatorIntent) else OperatorIntent.model_validate(_document(intent))
    except _PydanticValidationError as exc:
        raise LaunchPlanError("INTENT_MISMATCH", f"the supplied intent is not a sealed operator intent: {exc.errors()[0]['msg'] if exc.errors() else exc}") from exc
    _require(sealed.intent_digest == blueprint.intent_digest, "INTENT_MISMATCH", "the supplied intent is not the one this blueprint compiled from")
    return _money(sealed.starting_cash, field_name="starting_cash"), _money(sealed.fixed_costs_per_period, field_name="fixed_costs_per_period")


def _launch_steps(
    blueprint: LaunchBlueprint,
    *,
    targets: LaunchTargets,
    paper_refs: Sequence[str],
    licence_refs: Sequence[str],
    register_blockers: Sequence[str],
    storefront: Sequence[str],
) -> list[dict[str, Any]]:
    country = blueprint.country
    registrar = REGISTRARS_BY_COUNTRY[country][0]
    number = REGISTRATION_NUMBER_BY_COUNTRY[country]
    rows: list[dict[str, Any]] = [
        {"event": "plan", "title": "Seal the launch plan", "kind": "automated", "verb": "compile_launch_plan over a passing simulation", "produces": "start_launch", "target_day": 0},
        {"event": "form", "title": "Form the company", "kind": "platform_write", "verb": "create_company", "produces": "formation_receipt", "target_day": 1},
        {"event": "register", "title": f"File with {registrar}", "kind": "human_gate", "gate_kind": "entity_registered", "human_role": "director", "verb": f"file with {registrar} + register {number} (director)", "produces": "registration_attestation", "target_day": 3, "blocking_requirements": list(register_blockers)},
        {"event": "open_bank", "title": "Open the business bank account", "kind": "human_gate", "gate_kind": "bank_account_opened", "human_role": "account_holder", "verb": "open the business bank account; then a governed balance read", "produces": "bank_receipt", "target_day": 7},
    ]
    rows.extend({
        "event": "sign_paper",
        "title": f"Execute {ref.split(':', 1)[-1].replace('_', ' ')}",
        "kind": "human_gate",
        "gate_kind": "signature_executed",
        "human_role": "signatory",
        "verb": "signing.get_envelope read or signature attestation",
        "produces": "signature_receipt",
        "target_day": 9,
        "blocking_requirements": [ref],
    } for ref in paper_refs)
    # Omitted, like grant_licence, when the blueprint asks for none: a step list that tells an operator
    # to bind cover their own blueprint does not require is a gate nobody can honestly attest to.
    if blueprint.insurance:
        rows.append({"event": "bind_insurance", "title": "Bind the cover", "kind": "human_gate", "gate_kind": "insurance_bound", "human_role": "broker", "verb": "bind cover (broker)", "produces": "insurance_attestation", "target_day": 10, "blocking_requirements": list(paper_refs)})
    rows.extend({
        "event": "grant_licence",
        "title": f"Hold {ref}",
        "kind": "human_gate",
        "gate_kind": "licence_granted",
        "human_role": "licensing_authority",
        "verb": "apply and hold the licence (licensing authority)",
        "produces": "licence_attestation",
        "target_day": 10,
        "blocking_requirements": [ref],
    } for ref in licence_refs)
    rows.append({"event": "verify_payments", "title": "Complete payments onboarding", "kind": "human_gate", "gate_kind": "payments_onboarding_completed", "human_role": "account_holder", "verb": "complete Stripe hosted onboarding (account holder); attest", "produces": "payments_attestation", "target_day": 12})
    rows.extend({
        "event": "provision",
        "title": "Provision the website" if kind == "website" else "Provision the phone number",
        "kind": "platform_write",
        "verb": "page_builder_deploy" if kind == "website" else "POST /api/phone-provisioning/purchase",
        "produces": "provisioning_receipt",
        "target_day": 14,
    } for kind in storefront)
    rows.extend([
        {"event": "verify_connectors", "title": "Verify the connectors", "kind": "automated", "verb": "company_readiness", "produces": "readiness_receipt", "target_day": 15},
        {"event": "go_live", "title": "Go live", "kind": "automated", "verb": "lightbulb company bring-up", "produces": "bring_up_receipt", "target_day": 16},
        {"event": "record_first_dollar", "title": "Record the first settled dollar", "kind": "platform_read", "verb": "stripe.observe_cash_settlement or a revenue case at cash_settled", "produces": "first_dollar_receipt", "target_day": targets.time_to_first_dollar_days},
        {"event": "scale", "title": "Decide scale or kill", "kind": "human_gate", "gate_kind": "kill_or_scale_decided", "human_role": "director", "verb": "decide scale or kill at the date (director)", "produces": "decision_attestation", "target_day": min(365, targets.kill_or_scale_days)},
    ])
    for index, row in enumerate(rows, start=1):
        row["step_ref"] = f"s{index:02d}:{row['event']}"
    return rows


def compile_launch_plan(
    blueprint: LaunchBlueprint | Mapping[str, Any],
    intent: Any = None,
    *,
    planned_at: str,
    targets: Mapping[str, Any] | None = None,
    assumptions: Sequence[Mapping[str, Any]] = (),
) -> LaunchPlan:
    """Compile a blueprint with no blockers into a launch plan, refusing to plan what the simulation will not carry."""

    parsed_blueprint = blueprint if isinstance(blueprint, LaunchBlueprint) else LaunchBlueprint.model_validate(_document(blueprint))
    _require(not parsed_blueprint.blockers, "BLUEPRINT_NOT_READY", f"the blueprint carries {len(parsed_blueprint.blockers)} blockers ({', '.join(sorted(set(parsed_blueprint.blocker_codes)))}); resolve them before planning")
    at = timestamp(planned_at, field_name="planned_at")
    operating = compile_company_operating_blueprint(parsed_blueprint.operating_blueprint)
    opening_cash, fixed_costs = _launch_cash(parsed_blueprint, intent)
    budget = parsed_blueprint.operating_blueprint.operating_budget_per_period
    period_days = parsed_blueprint.operating_blueprint.period_days
    archetype = parsed_blueprint.archetype
    default_days = ARCHETYPE_FIRST_DOLLAR_DAYS[archetype]
    floor = (budget * 2).quantize(budget)
    overrides = {key: value for key, value in dict(targets or {}).items() if key != "targets_source"}
    resolved: dict[str, Any] = {
        "time_to_first_dollar_days": default_days,
        "kill_or_scale_days": default_days * 2,
        "cash_floor": str(floor),
        "max_spend_before_first_dollar": str(max(Decimal("0"), opening_cash - floor)),
        "targets_source": "operator" if overrides else "archetype_default",
    }
    resolved.update(overrides)
    _require(int(resolved["kill_or_scale_days"]) >= int(resolved["time_to_first_dollar_days"]), "KILL_BEFORE_TARGET", f"the kill-or-scale date ({resolved['kill_or_scale_days']}d) cannot precede the first-dollar target ({resolved['time_to_first_dollar_days']}d)")
    launch_targets = LaunchTargets.model_validate(resolved)

    simulation = simulate_launch(operating, planned_at=at, opening_cash=opening_cash, fixed_costs_per_period=fixed_costs, kill_window_days=launch_targets.kill_or_scale_days, assumptions=assumptions)
    _require(
        simulation.halted_at_period is None or (simulation.first_revenue_period is not None and simulation.halted_at_period > simulation.first_revenue_period),
        "SIMULATION_HALTS_BEFORE_FIRST_DOLLAR",
        f"the forecast halts at period {simulation.halted_at_period} ({simulation.halt_reason}) before it earns; a launch is not planned against a run that stops first",
    )
    _require(simulation.first_revenue_period is not None, "SIMULATION_NO_REVENUE", f"the forecast earns nothing across {simulation.periods_run} periods; there is no first dollar to plan for")
    _require(simulation.min_cash >= launch_targets.cash_floor, "CASH_FLOOR_BREACHED", f"the forecast dips to {simulation.min_cash}, under the cash floor {launch_targets.cash_floor}")

    paper_refs = tuple(f"paper:{item.kind}" for item in parsed_blueprint.required_paper)
    digests = {f"paper:{item.kind}": str(item.content_sha256) for item in parsed_blueprint.required_paper if item.content_sha256}
    formation_licences = tuple(str(item.evidence_ref) for item in parsed_blueprint.licences if item.required_before == "formation" and item.evidence_ref)
    licence_refs = tuple(str(item.evidence_ref) for item in parsed_blueprint.licences if item.required_before != "formation" and item.evidence_ref)
    register_blockers = (*formation_licences, *(("paper:incorporation",) if "paper:incorporation" in paper_refs else ()))
    storefront = STOREFRONT_REQUIRED.get(archetype, _DEFAULT_STOREFRONT)
    steps = _launch_steps(parsed_blueprint, targets=launch_targets, paper_refs=paper_refs, licence_refs=licence_refs, register_blockers=register_blockers, storefront=storefront)
    # ``LaunchPlan.steps`` is bounded; without this the compiler dies inside pydantic on a blueprint
    # carrying enough paper and licences to overrun the critical path, naming no code the caller can act on.
    _require(
        MIN_LAUNCH_STEPS <= len(steps) <= MAX_LAUNCH_STEPS,
        "PLAN_STEPS_EXCEEDED",
        f"the critical path needs {len(steps)} steps ({len(paper_refs)} paper, {len(licence_refs)} licences, {len(storefront)} storefront); a launch plan carries {MIN_LAUNCH_STEPS}..{MAX_LAUNCH_STEPS}",
    )
    go_live_day = next(row["target_day"] for row in steps if row["event"] == "go_live")
    forecast = int(go_live_day + (simulation.first_revenue_period - 1) * period_days + math.ceil(period_days / 2))
    _require(forecast <= launch_targets.time_to_first_dollar_days, "TARGET_UNREACHABLE", f"the forecast reaches the first dollar on day {forecast}, past the target of {launch_targets.time_to_first_dollar_days} days")
    _require(simulation.spend_before_first_revenue <= launch_targets.max_spend_before_first_dollar, "SPEND_CAP_EXCEEDED", f"the forecast spends {simulation.spend_before_first_revenue} before it earns, past the cap {launch_targets.max_spend_before_first_dollar}")

    return seal(LaunchPlan, {
        "company_name": parsed_blueprint.operating_blueprint.name,
        "archetype": archetype,
        "country": parsed_blueprint.country,
        "region_code": parsed_blueprint.region_code,
        "currency": parsed_blueprint.currency,
        "period_days": period_days,
        "blueprint_digest": parsed_blueprint.blueprint_digest,
        "operating_plan_digest": operating.plan_digest,
        "simulation": simulation.to_dict(),
        "first_dollar_day_forecast": forecast,
        "targets": launch_targets.to_dict(),
        "steps": steps,
        "required_paper_refs": list(paper_refs),
        "paper_content_digests": digests,
        "required_licence_refs": list(licence_refs),
        "required_insurance_kinds": [item.kind for item in parsed_blueprint.insurance],
        "registrars": list(REGISTRARS_BY_COUNTRY[parsed_blueprint.country]),
        "storefront_required": list(storefront),
        "planned_at": at,
    }, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, effect boundary
# --------------------------------------------------------------------------- #


class LaunchReceipt(StrictModel):
    """Everything one launch hop may prove; every field arrives from a receipt builder, never typed loose."""

    entity_scope: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=50)
    blueprint_digest: Sha256Digest | None = None
    simulation_digest: Sha256Digest | None = None
    formed_company_ref: OpaqueRef | None = None
    formation_country: ShortText | None = None
    region_matches_country: bool | None = None
    provisioning: ShortText | None = None
    next_step: ShortText | None = None
    registrar: ShortText | None = None
    registration_ref: OpaqueRef | None = None
    registered_at: str | None = None
    filed_by_ref: OpaqueRef | None = None
    licence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=20)
    position_digest: Sha256Digest | None = None
    bank_available: Decimal | None = None
    bank_currency: ShortText | None = None
    account_holder_ref: OpaqueRef | None = None
    paper_ref: OpaqueRef | None = None
    envelope_ref: OpaqueRef | None = None
    envelope_status: ShortText | None = None
    document_digest: Sha256Digest | None = None
    signed_at: str | None = None
    signer_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=20)
    insurance_kinds: tuple[ShortText, ...] = Field(default=(), max_length=12)
    policy_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=12)
    bound_at: str | None = None
    licence_ref: OpaqueRef | None = None
    licence_expires_at: str | None = None
    issued_by_ref: OpaqueRef | None = None
    payments_account_sha256: Sha256Digest | None = None
    charges_enabled: bool | None = None
    provisioned_kind: ProvisioningKind | None = None
    provisioned_ref_sha256: Sha256Digest | None = None
    site_project_ref: OpaqueRef | None = None
    readiness_digest: Sha256Digest | None = None
    ready: bool | None = None
    blocked_engines: tuple[ShortText, ...] = Field(default=(), max_length=8)
    bring_up_report_digest: Sha256Digest | None = None
    bring_up_status: ShortText | None = None
    storefront_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=8)
    case_ref: OpaqueRef | None = None
    settled_amount: Decimal | None = None
    settlement_currency: ShortText | None = None
    settlement_evidence_sha256: Sha256Digest | None = None
    first_dollar_source: dict[str, Any] | None = None
    settled_at: str | None = None
    decision: Literal["scale", "kill"] | None = None
    brief_digest: Sha256Digest | None = None
    spend_to_date: Decimal | None = None
    approval_ref: OpaqueRef | None = None
    gate_task_ref: OpaqueRef | None = None
    gate_kind: GateKind | None = None
    decided_by_ref: OpaqueRef | None = None
    decided_at: str | None = None
    evidence_sha256: tuple[Sha256Digest, ...] = Field(default=(), max_length=8)
    attestation_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "licence_refs", "signer_refs", "insurance_kinds", "policy_refs", "blocked_engines", "storefront_refs", "evidence_sha256", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("bank_available", "settled_amount", "spend_to_date", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, field_name=str(info.field_name))

    @field_validator("registered_at", "signed_at", "bound_at", "licence_expires_at", "settled_at", "decided_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @field_validator("formed_company_ref")
    @classmethod
    def _slug_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _UUID.search(value) or not _COMPANY_REF.match(value):
            raise ValueError(f"FORMED_REF_IS_IDENTIFIER: a launch names its company by slug ('company:<slug>'), never by the id Spring minted; got {value!r}")
        return value


class LaunchLedger(StrictModel):
    """Derived state only: every value came off a receipt the guards accepted."""

    entity_scope: dict[str, Any] | None = None
    blueprint_digest: str | None = None
    simulation_digest: str | None = None
    planned_at: str | None = None
    formed_company_ref: str | None = None
    formed_at: str | None = None
    registrar: str | None = None
    registration_ref: str | None = None
    registered_at: str | None = None
    bank_available: Decimal = Field(default=Decimal("0"), validate_default=True)
    banked_at: str | None = None
    paper_done: tuple[str, ...] = ()
    paper_signed_at: str | None = None
    insurance_kinds: tuple[str, ...] = ()
    insured_at: str | None = None
    licences_granted: tuple[str, ...] = ()
    payments_ready_at: str | None = None
    provisioned_kinds: tuple[str, ...] = ()
    provisioning_ref_digests: tuple[str, ...] = ()
    readiness_digest: str | None = None
    readiness_checks: int = 0
    bring_up_state_digest: str | None = None
    live_at: str | None = None
    first_dollar_at: str | None = None
    first_dollar_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    days_to_first_dollar: int | None = None
    spend_before_first_dollar: Decimal = Field(default=Decimal("0"), validate_default=True)
    spend_ceiling_breached: bool = False
    kill_or_scale_at: str | None = None
    gates_passed: tuple[str, ...] = ()
    decision: str | None = None
    decided_at: str | None = None
    kill_reason: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["in_progress", "first_dollar", "scaled", "killed", "abandoned"] = "in_progress"

    @field_validator("paper_done", "insurance_kinds", "licences_granted", "provisioned_kinds", "provisioning_ref_digests", "gates_passed", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("bank_available", "first_dollar_amount", "spend_before_first_dollar", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, field_name=str(info.field_name))


class LaunchEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    company_formed: Literal[False] = False
    registrar_filed: Literal[False] = False
    kyc_submitted: Literal[False] = False
    document_signed: Literal[False] = False
    bank_account_opened: Literal[False] = False
    insurance_bound: Literal[False] = False
    provisioning_executed: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


# --------------------------------------------------------------------------- #
# The lifecycle
# --------------------------------------------------------------------------- #


def _gate(data: dict[str, Any], command: Any, event: str) -> None:
    """Every legally human hop parks here until a person other than the requester decided it in Spring."""

    receipt, kind = command.receipt, GATE_FOR_EVENT[event]
    require(
        # ``approval_ref`` is written by ``command_with_approval`` and ``gate_task_ref`` by the lane's
        # re-issue; they name the same decided task, so a receipt pointing at two is not a proven gate.
        receipt.approval_ref is not None and receipt.approval_ref == receipt.gate_task_ref and receipt.gate_kind == kind and receipt.decided_by_ref is not None,
        f"{kind.upper()}_APPROVAL_REQUIRED",
        f"{GATE_ATTESTATION[kind]}; a person other than the requester approves the sdk_launch_gate task before this hop applies",
        "await_approval",
    )
    # Dual control, checked against the command itself: ``LaunchGateBinding`` refuses a decider who is
    # the acting actor, and a receipt assembled by hand does not get to skip that.
    require(receipt.decided_by_ref != command.actor_ref, "GATE_SELF_DECIDED", f"{command.actor_ref} both requested and decided this {kind} gate; a person other than the requester approves it", "do_not_replay")
    data["gates_passed"] = [*(data.get("gates_passed") or ()), f"{kind}:{receipt.gate_task_ref}"]


def _missing(required: Sequence[str], held: Sequence[str]) -> list[str]:
    return [item for item in required if item not in set(held)]


def _paper_and_cover(plan: LaunchPlan, data: dict[str, Any]) -> None:
    """What ``bind_insurance`` used to be the only gatekeeper of, checked on every edge that can skip it.

    A launch needing no cover reaches ``grant_licence``/``verify_payments`` straight from ``banked`` or
    ``paper_signed``; one that does need cover (or still owes paper) must not slip through the same door.
    """

    absent = _missing(list(plan.required_paper_refs), list(data.get("paper_done") or ()))
    require(not absent, "PAPER_INCOMPLETE", f"the launch still owes {', '.join(absent)}; the paper lands before cover, licences and payments")
    short = _missing(list(plan.required_insurance_kinds), list(data.get("insurance_kinds") or ()))
    require(not short, "INSURANCE_INCOMPLETE", f"the launch still owes cover for {', '.join(short)}; bind it before the licences and the payments hop")


def _apply_launch(plan: LaunchPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "plan":
        require(r.entity_scope is not None, "LAUNCH_SCOPE_REQUIRED", "opening the launch must retain its engine scope")
        data["entity_scope"] = r.entity_scope
        require(r.blueprint_digest == plan.blueprint_digest, "BLUEPRINT_MISMATCH", "the opening receipt must name this plan's blueprint")
        require(r.simulation_digest == plan.simulation.simulation_digest, "SIMULATION_MISMATCH", "the opening receipt must name the simulation pinned into this plan")
        data.update({"blueprint_digest": r.blueprint_digest, "simulation_digest": r.simulation_digest, "planned_at": at, "kill_or_scale_at": add_days(at, plan.targets.kill_or_scale_days)})
    elif event == "form":
        require(r.formed_company_ref is not None and r.formation_country is not None and r.provisioning is not None and r.next_step is not None, "FORMATION_MISSING", "a formation names the formed company, its country, its provisioning state, and the next step")
        require(r.formation_country == plan.country, "FORMATION_COUNTRY_MISMATCH", f"the company formed in {r.formation_country}; the plan targets {plan.country}")
        require(r.region_matches_country is not False, "FORMATION_REGION_MISMATCH", "the company was provisioned outside its country's residency region", "manual_reconciliation")
        require(r.provisioning == "provisioned" and r.next_step == NEXT_STEP_OPEN_WORKSPACE, "FORMATION_NOT_PROVISIONED", f"formation is {r.provisioning} at {r.next_step}; the workspace is not open yet")
        data.update({"formed_company_ref": r.formed_company_ref, "formed_at": at})
    elif event == "register":
        _gate(data, command, event)
        require(r.registrar is not None and r.registration_ref is not None and r.registered_at is not None and r.filed_by_ref is not None, "REGISTRATION_MISSING", "a registration names the registrar, the registration reference, when it was registered, and who filed it")
        require(r.registrar in plan.registrars, "REGISTRAR_NOT_FOR_COUNTRY", f"{r.registrar} does not register companies in {plan.country}; expected one of {list(plan.registrars)}")
        require(parsed(r.registered_at) <= parsed(at), "REGISTRATION_IN_FUTURE", "a registration cannot be dated after the transition that records it")
        needed = [ref for step in plan.steps_for("register") for ref in step.blocking_requirements]
        absent = _missing(needed, [*r.evidence_refs, *r.licence_refs])
        require(not absent, "LICENCE_PREREQUISITE_MISSING", f"the registration does not evidence {', '.join(absent)}, which must be held before the entity is registered")
        data.update({"registrar": r.registrar, "registration_ref": r.registration_ref, "registered_at": r.registered_at})
    elif event == "open_bank":
        _gate(data, command, event)
        require(r.position_digest is not None and r.bank_available is not None and r.bank_currency is not None and r.account_holder_ref is not None, "BANK_MISSING", "a bank account is proven by a balance read with provenance, its currency, and the account holder")
        require(r.bank_currency == plan.currency, "BANK_CURRENCY_MISMATCH", f"the account holds {r.bank_currency}; the company operates in {plan.currency}")
        require(r.bank_available >= plan.targets.cash_floor, "BANK_UNDERFUNDED", f"the account holds {r.bank_available}, under the cash floor {plan.targets.cash_floor}")
        data.update({"bank_available": str(r.bank_available), "banked_at": at})
    elif event == "sign_paper":
        require(r.paper_ref is not None and r.paper_ref in plan.required_paper_refs, "PAPER_UNKNOWN", f"{r.paper_ref} is not required paper for this launch; the plan requires {list(plan.required_paper_refs)}")
        done = list(data.get("paper_done") or ())
        require(r.paper_ref not in done, "PAPER_ALREADY_DONE", f"{r.paper_ref} is already signed")
        # The plan pins a content digest for every required paper so the launch records WHICH document
        # was signed.  An attestation is the cheapest path to a signature, so it is held to the same
        # pin as the platform read; otherwise attesting is a way to sign a different document.
        require(r.document_digest == plan.paper_content_digests.get(str(r.paper_ref)), "DOCUMENT_DIGEST_MISMATCH", f"the signed document does not carry the content digest the plan pinned for {r.paper_ref}", "manual_reconciliation")
        if r.envelope_ref is not None:
            require(r.envelope_status == "completed", "ENVELOPE_NOT_COMPLETED", f"the signing envelope is {r.envelope_status}, not completed")
        else:
            _gate(data, command, event)
        data.update({"paper_done": [*done, r.paper_ref], "paper_signed_at": at})
    elif event == "bind_insurance":
        absent = _missing(list(plan.required_paper_refs), list(data.get("paper_done") or ()))
        require(not absent, "PAPER_INCOMPLETE", f"the launch still owes {', '.join(absent)}; the paper lands before cover is bound")
        _gate(data, command, event)
        require(bool(r.insurance_kinds) and bool(r.policy_refs) and r.bound_at is not None, "INSURANCE_MISSING", "bound cover names its kinds, its policies, and when it was bound")
        short = _missing(list(plan.required_insurance_kinds), list(r.insurance_kinds))
        require(not short, "INSURANCE_INCOMPLETE", f"the cover does not include {', '.join(short)}")
        data.update({"insurance_kinds": list(r.insurance_kinds), "insured_at": at})
    elif event == "grant_licence":
        _paper_and_cover(plan, data)
        _gate(data, command, event)
        require(r.licence_ref is not None and r.licence_ref in plan.required_licence_refs, "LICENCE_UNKNOWN", f"{r.licence_ref} is not a licence this launch requires; the plan requires {list(plan.required_licence_refs)}")
        require(r.licence_expires_at is None or parsed(r.licence_expires_at) > parsed(at), "LICENCE_EXPIRED", f"licence {r.licence_ref} expired at {r.licence_expires_at}")
        granted = list(data.get("licences_granted") or ())
        require(r.licence_ref not in granted, "LICENCE_ALREADY_GRANTED", f"{r.licence_ref} is already held by this launch")
        data.update({"licences_granted": [*granted, r.licence_ref]})
    elif event == "verify_payments":
        _paper_and_cover(plan, data)
        # Checked from ``licensed`` too: ``grant_licence`` loops on itself, so a launch that needs two
        # licences can reach ``licensed`` holding one and would otherwise walk straight past the second.
        if plan.required_licence_refs:
            absent = _missing(list(plan.required_licence_refs), list(data.get("licences_granted") or ()))
            require(not absent, "LICENCES_INCOMPLETE", f"the launch still owes {', '.join(absent)}; every required licence is granted before payments are verified", "correct_input")
        _gate(data, command, event)
        require(r.payments_account_sha256 is not None and r.charges_enabled is True, "PAYMENTS_MISSING", "payments readiness names the hashed account and proves charges are enabled")
        data.update({"payments_ready_at": at})
    elif event == "provision":
        require(r.provisioned_kind is not None and r.provisioned_ref_sha256 is not None, "PROVISIONING_MISSING", "a provisioning receipt names what was provisioned and the digest of the reference the platform returned")
        kinds = list(data.get("provisioned_kinds") or ())
        require(r.provisioned_kind not in kinds, "PROVISIONING_DUPLICATE", f"{r.provisioned_kind} is already provisioned for this launch")
        data.update({"provisioned_kinds": [*kinds, r.provisioned_kind], "provisioning_ref_digests": [*(data.get("provisioning_ref_digests") or ()), r.provisioned_ref_sha256]})
    elif event == "verify_connectors":
        absent = _missing(list(plan.storefront_required), list(data.get("provisioned_kinds") or ()))
        require(not absent, "STOREFRONT_INCOMPLETE", f"the storefront still owes {', '.join(absent)} before the connectors are verified")
        require(r.readiness_digest is not None and r.ready is not None, "READINESS_MISSING", "a connector check names its readiness digest and whether the account is ready")
        require(r.ready is True, "CONNECTORS_NOT_READY", f"connectors are not ready for {', '.join(r.blocked_engines) or 'one or more engines'}")
        data.update({"readiness_digest": r.readiness_digest, "readiness_checks": int(data.get("readiness_checks") or 0) + 1})
    elif event == "go_live":
        require(r.bring_up_report_digest is not None and r.bring_up_status is not None, "BRING_UP_MISSING", "going live is proven by a bring-up report")
        require(r.bring_up_status == "live", "BRING_UP_NOT_LIVE", f"the bring-up report is {r.bring_up_status}, not live")
        data.update({"bring_up_state_digest": r.bring_up_report_digest, "live_at": at})
    elif event == "record_first_dollar":
        require(r.case_ref is not None and r.settled_amount is not None and r.settlement_currency is not None and r.settlement_evidence_sha256 is not None and r.settled_at is not None, "FIRST_DOLLAR_MISSING", "a first dollar names the case, the settled amount and currency, the settlement evidence, and when it settled")
        require(r.settled_amount > 0, "FIRST_DOLLAR_ZERO", "a first dollar is a positive settled amount")
        require(r.settlement_currency == plan.currency, "FIRST_DOLLAR_CURRENCY_MISMATCH", f"the cash settled in {r.settlement_currency}; the company operates in {plan.currency}")
        require(parsed(r.settled_at) >= parsed(str(data.get("live_at"))), "FIRST_DOLLAR_BEFORE_LIVE", "cash cannot have settled before the company went live", "manual_reconciliation")
        require(parsed(r.settled_at) <= parsed(str(data.get("kill_or_scale_at"))), "FIRST_DOLLAR_AFTER_KILL_DATE", f"the cash settled at {r.settled_at}, after the fixed kill-or-scale date {data.get('kill_or_scale_at')}", "manual_reconciliation")
        require(r.first_dollar_source is not None, "FIRST_DOLLAR_SOURCE_REQUIRED", "settled cash must retain its complete replayable source")
        source = r.first_dollar_source
        if "observation" in source:
            source_value = source["observation"]
            require(parsed(source_value["observed_at"]) <= parsed(at), "FIRST_DOLLAR_FROM_FUTURE", "the settlement observation must exist before recording it")
            derived = first_dollar_receipt(source_value, currency=plan.currency, case_ref=r.case_ref, spend_to_date=r.spend_to_date or "0")
        else:
            from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
            from lightbulb.company_engine_core import same_scope
            source_plan, case = REVENUE_CHAIN_LIFECYCLE.bind(source["plan"], source["state"])
            from lightbulb.company_engine_core import EngineScope
            require(source_plan.company_ref == data.get("formed_company_ref")
                    and same_scope(case.scope, EngineScope.model_validate(data["entity_scope"])),
                    "FIRST_DOLLAR_SCOPE_MISMATCH", "revenue must belong to the launched company and engine scope")
            require(parsed(case.transition_history[-1].command.occurred_at) <= parsed(at), "FIRST_DOLLAR_FROM_FUTURE", "the settled case must exist before recording it")
            derived = first_dollar_receipt(case, source_plan=source_plan, currency=plan.currency, case_ref=r.case_ref, spend_to_date=r.spend_to_date or "0")
        require(all(str(getattr(r, key)) == str(derived[key]) for key in ("settled_amount", "settlement_currency", "settlement_evidence_sha256", "settled_at")),
                "FIRST_DOLLAR_SOURCE_MISMATCH", "first-dollar facts must reproduce the retained source")
        spend = r.spend_to_date if r.spend_to_date is not None else Decimal("0")
        data.update({
            "first_dollar_at": r.settled_at,
            "first_dollar_amount": str(r.settled_amount),
            "days_to_first_dollar": (parsed(r.settled_at) - parsed(str(data.get("formed_at")))).days,
            "spend_before_first_dollar": str(spend),
            "spend_ceiling_breached": spend > plan.targets.max_spend_before_first_dollar,
            "outcome": "first_dollar",
        })
    elif event == "scale":
        _gate(data, command, event)
        require(parsed(at) >= parsed(str(data.get("kill_or_scale_at"))), "SCALE_TOO_EARLY", f"the kill-or-scale date is {data.get('kill_or_scale_at')}; scaling before it is not the decision this plan fixed", "do_not_replay")
        require(r.brief_digest is not None, "BRIEF_MISSING", "a scale decision names the decision brief it was taken against")
        data.update({"decision": "scale", "decided_at": at, "outcome": "scaled"})
    elif event == "kill":
        _gate(data, command, event)
        require(r.brief_digest is not None, "BRIEF_MISSING", "a kill decision names the decision brief it was taken against")
        data.update({"decision": "kill", "decided_at": at, "kill_reason": str(command.reason)[:300], "outcome": "killed"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


LAUNCH_LIFECYCLE = LifecycleSpec(
    entity="launch",
    schema_prefix=LAUNCH_KIND,
    statuses=LAUNCH_STATUSES,
    terminal=TERMINAL_LAUNCH_STATUSES,
    events=LAUNCH_EVENTS,
    table=_LAUNCH_TABLE,
    opening_event="plan",
    reason_events=("kill", "abandon"),
    apply=_apply_launch,
    ledger_model=LaunchLedger,
    receipt_model=LaunchReceipt,
    effect_boundary_model=LaunchEffectBoundary,
    plan_model=LaunchPlan,
    max_transitions=MAX_LAUNCH_TRANSITIONS,
)
LaunchState = LAUNCH_LIFECYCLE.State


def launch_ref(company_ref: str) -> str:
    return f"{company_ref}:launch"


def start_launch(plan: LaunchPlan | Mapping[str, Any], scope: Mapping[str, Any], *, planned_at: str, actor_ref: str) -> Any:
    parsed_plan = plan if isinstance(plan, LaunchPlan) else LaunchPlan.model_validate(_document(plan))
    receipt = {"entity_scope": _document(scope), "blueprint_digest": parsed_plan.blueprint_digest, "simulation_digest": parsed_plan.simulation.simulation_digest}
    return LAUNCH_LIFECYCLE.open(parsed_plan, scope, opened_at=planned_at, actor_ref=actor_ref, receipt=receipt)


def advance_launch(plan: LaunchPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return LAUNCH_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# The launch gate lane: human-only approvals of type sdk_launch_gate
# --------------------------------------------------------------------------- #

_ENGINE_BINDING_FIELDS: tuple[str, ...] = ("engine", "entity_ref", "event", "transition_ref", "idempotency_key", "request_digest", "expected_version", "expected_state_digest", "plan_digest", "actor_ref", "approval_request_digest")
_GATE_BINDING_FIELDS: tuple[str, ...] = ("gate_kind", "evidence_sha256", "evidence_refs", "attestation_sha256")
_LIST_BINDING_FIELDS: frozenset[str] = frozenset({"evidence_sha256", "evidence_refs"})


class LaunchGateApprovalRequest(StrictModel):
    """A human-only attestation request bound to one exact sealed ``company_launch`` command."""

    schema_id: str = Field(default=LAUNCH_GATE_REQUEST_SCHEMA, alias="schema")
    engine: Literal["company_launch"] = LAUNCH_KIND
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    expected_version: int = Field(ge=0)
    expected_state_digest: Sha256Digest
    plan_digest: Sha256Digest
    actor_ref: OpaqueRef
    rejection_code: ShortText
    summary: ShortText
    description: BoundedText
    risk_level: int = Field(default=8, ge=1, le=10)
    expires_in_hours: int = Field(default=168, ge=1, le=720)
    gate_kind: GateKind
    evidence_sha256: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=8)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=8)
    attestation_sha256: Sha256Digest
    approval_request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("evidence_sha256", "evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchGateApprovalRequest:
        if self.gate_kind != GATE_FOR_EVENT.get(self.event):
            raise ValueError(f"{self.event} is not the {self.gate_kind} gate")
        if not skip_digests(info) and self.approval_request_digest != sealed_digest(LaunchGateApprovalRequest, self, "approval_request_digest"):
            raise ValueError("approval_request_digest must commit the exact request")
        return self

    def binding(self) -> dict[str, Any]:
        """The 15-field launch gate binding Spring validates and stores on both proposedAction and contextData."""

        out: dict[str, Any] = {}
        for field_name in (*_ENGINE_BINDING_FIELDS, *_GATE_BINDING_FIELDS):
            value = getattr(self, field_name)
            out[field_name] = list(value) if field_name in _LIST_BINDING_FIELDS else value
        return out

    def to_platform_body(self) -> dict[str, Any]:
        """The body for ``POST /api/workflows/approvals/launch-gates``; scope comes from the session, never the body."""

        binding = self.binding()
        return {"approvalType": LAUNCH_GATE_APPROVAL_TYPE, "summary": self.summary, "description": self.description, "riskLevel": self.risk_level, "expiresInHours": self.expires_in_hours, "proposedAction": binding, "contextData": {**binding, "rejection_code": self.rejection_code}}


def launch_gate_request(
    result: Mapping[str, Any] | Any,
    command: Mapping[str, Any] | Any,
    *,
    entity_ref: str,
    plan_digest: str,
    summary: str,
    description: str,
    risk_level: int = 8,
    engine: str = LAUNCH_KIND,
    expires_in_hours: int = 168,
) -> LaunchGateApprovalRequest:
    """Build the human-only attestation request for a hop the launch engine parked on its gate."""

    _require(str(engine) == LAUNCH_KIND, "GATE_EVENT_UNKNOWN", f"the launch gate lane serves {LAUNCH_KIND}, not {engine}")
    raw_result = dict(detached(result))
    receipt = dict(raw_result.get("receipt") or {})
    _require(raw_result.get("candidate_validated") is False and receipt.get("status") == "rejected", "APPROVAL_NOT_NEEDED", "only a rejected transition asks for approval")
    _require(str(receipt.get("rejection_code", "")).endswith("APPROVAL_REQUIRED"), "APPROVAL_NOT_NEEDED", f"rejection {receipt.get('rejection_code')} is not an approval gate")
    _require(dict(receipt.get("recovery") or {}).get("disposition") == "await_approval", "APPROVAL_NOT_NEEDED", "the rejection does not await approval")
    raw_command = dict(detached(command))
    for key in ("transition_ref", "idempotency_key", "request_digest", "expected_state_digest", "actor_ref", "event"):
        _require(bool(raw_command.get(key)), "COMMAND_INCOMPLETE", f"the sealed command lacks {key}")
    _require(raw_command["request_digest"] == receipt.get("request_digest") and raw_command["transition_ref"] == receipt.get("transition_ref"), "COMMAND_RECEIPT_MISMATCH", "the command is not the one the receipt rejected")
    event = str(raw_command["event"])
    gate_kind = GATE_FOR_EVENT.get(event)
    _require(gate_kind is not None, "GATE_EVENT_UNKNOWN", f"{event} is not a human gate of the launch lifecycle")
    command_receipt = dict(raw_command.get("receipt") or {})
    evidence = list(command_receipt.get("evidence_sha256") or ())
    attestation = command_receipt.get("attestation_sha256")
    _require(bool(evidence) and bool(attestation), "GATE_EVIDENCE_MISSING", f"the {gate_kind} attestation carries no evidence digests; a person attests to something specific")
    payload = {
        "engine": LAUNCH_KIND,
        "entity_ref": entity_ref,
        "event": event,
        "transition_ref": str(raw_command["transition_ref"]),
        "idempotency_key": str(raw_command["idempotency_key"]),
        "request_digest": str(raw_command["request_digest"]),
        "expected_version": int(raw_command.get("expected_version", 0)),
        "expected_state_digest": str(raw_command["expected_state_digest"]),
        "plan_digest": plan_digest,
        "actor_ref": str(raw_command["actor_ref"]),
        "rejection_code": str(receipt["rejection_code"]),
        "summary": summary,
        "description": description,
        "risk_level": risk_level,
        "expires_in_hours": expires_in_hours,
        "gate_kind": gate_kind,
        "evidence_sha256": evidence[:8],
        "evidence_refs": list(command_receipt.get("evidence_refs") or ())[:8],
        "attestation_sha256": str(attestation),
    }
    return seal(LaunchGateApprovalRequest, payload, "approval_request_digest")


class LaunchGateBinding(StrictModel):
    """A human decision proven to bind one exact launch command, by someone other than its requester."""

    schema_id: str = Field(default=LAUNCH_GATE_BINDING_SCHEMA, alias="schema")
    approval_ref: OpaqueRef
    engine: Literal["company_launch"] = LAUNCH_KIND
    entity_ref: OpaqueRef
    event: ShortText
    transition_ref: OpaqueRef
    request_digest: Sha256Digest
    plan_digest: Sha256Digest
    actor_ref: OpaqueRef
    gate_kind: GateKind
    evidence_sha256: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=8)
    decided_by_ref: OpaqueRef
    decided_at: str
    task_status: Literal["APPROVED"] = "APPROVED"
    binding_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("evidence_sha256", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("decided_at")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="decided_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchGateBinding:
        if self.decided_by_ref == self.actor_ref:
            raise ValueError("GATE_SELF_DECIDED: the decider cannot be the acting actor")
        if not skip_digests(info) and self.binding_digest != sealed_digest(LaunchGateBinding, self, "binding_digest"):
            raise ValueError("binding_digest must commit the exact binding")
        return self

    def engine_binding(self) -> ApprovalBinding:
        """The same decision in the shape ``command_with_approval`` re-issues a command from."""

        return seal(ApprovalBinding, {
            "approval_ref": self.approval_ref,
            "engine": self.engine,
            "entity_ref": self.entity_ref,
            "event": self.event,
            "transition_ref": self.transition_ref,
            "request_digest": self.request_digest,
            "plan_digest": self.plan_digest,
            "actor_ref": self.actor_ref,
            "decided_by_ref": self.decided_by_ref,
            "decided_at": self.decided_at,
            "task_status": "APPROVED",
        }, "approval_receipt_digest")


def bind_launch_gate(task: Mapping[str, Any], request: LaunchGateApprovalRequest | Mapping[str, Any]) -> LaunchGateBinding:
    """Accept a platform task only when a person other than the requester approved this exact attestation."""

    parsed_request = request if isinstance(request, LaunchGateApprovalRequest) else LaunchGateApprovalRequest.model_validate(dict(detached(request)))
    raw = dict(detached(task))
    status = str(raw.get("status", "")).upper()
    _require(status == "APPROVED", "GATE_NOT_APPROVED", f"the launch gate task is {status or 'unknown'}, not APPROVED")
    # No default: a task that does not say it is a launch gate is not one.  ``bind_approval`` may
    # assume its own type when the field is absent; a human-only gate never assumes it was human.
    _require(str(raw.get("approvalType") or "") == LAUNCH_GATE_APPROVAL_TYPE, "GATE_TYPE_MISMATCH", f"the task is a {raw.get('approvalType')} approval; a launch gate is {LAUNCH_GATE_APPROVAL_TYPE} and human-only")
    task_id = str(raw.get("id") or raw.get("approvalRef") or raw.get("approval_ref") or "")
    _require(bool(task_id), "GATE_BINDING_MISMATCH", "the task carries no id to bind the decision to")
    context = dict(raw.get("contextData") or raw.get("context") or {})
    for key in (*_ENGINE_BINDING_FIELDS, *_GATE_BINDING_FIELDS):
        expected = getattr(parsed_request, key)
        actual = context.get(key)
        agrees = list(actual or ()) == list(expected) if key in _LIST_BINDING_FIELDS else str(actual) == str(expected)
        _require(agrees, "GATE_BINDING_MISMATCH", f"task context {key} does not commit the requested attestation")
    decided_by = str(raw.get("decidedBy") or raw.get("decided_by") or "")
    decided_at = str(raw.get("decidedAt") or raw.get("decided_at") or "")
    _require(bool(decided_by) and bool(decided_at), "GATE_DECIDER_MISSING", "a launch gate names who decided and when")
    requested_by = str(context.get("requested_by_user_id") or "")
    _require(bool(requested_by), "GATE_DECIDER_MISSING", "the task does not name who requested it; dual control cannot be proven")
    _require(requested_by != decided_by, "GATE_SELF_DECIDED", "the requester decided their own launch gate; Spring refuses this and so does the SDK")
    if not decided_at.endswith("Z") and "T" in decided_at:
        decided_at = decided_at.split(".")[0] + "Z"
    try:
        decided_at = timestamp(decided_at, field_name="decided_at")
    except ValueError as exc:
        raise LaunchPlanError("GATE_DECIDER_MISSING", f"the decision time {raw.get('decidedAt') or raw.get('decided_at')!r} is not an ISO-8601 UTC timestamp; a gate records when a person decided") from exc
    return seal(LaunchGateBinding, {
        "approval_ref": task_id,
        "engine": parsed_request.engine,
        "entity_ref": parsed_request.entity_ref,
        "event": parsed_request.event,
        "transition_ref": parsed_request.transition_ref,
        "request_digest": parsed_request.request_digest,
        "plan_digest": parsed_request.plan_digest,
        "actor_ref": parsed_request.actor_ref,
        "gate_kind": parsed_request.gate_kind,
        "evidence_sha256": list(parsed_request.evidence_sha256),
        "decided_by_ref": decided_by,
        "decided_at": decided_at,
        "task_status": "APPROVED",
    }, "binding_digest")


class LaunchGateLane:
    """``EngineRuntime``'s approval lane for ``company_launch``: request, bind, and re-issue through ``sdk_launch_gate``."""

    def request(self, result: Any, command: Mapping[str, Any], *, engine: str, entity_ref: str, plan_digest: str, summary: str, description: str, risk_level: int) -> LaunchGateApprovalRequest:
        return launch_gate_request(result, command, engine=engine, entity_ref=entity_ref, plan_digest=plan_digest, summary=summary, description=description, risk_level=risk_level)

    def bind(self, task: Mapping[str, Any], request: Any) -> LaunchGateBinding:
        return bind_launch_gate(task, request)

    def reissue(self, binding: Any, command: Mapping[str, Any], *, state: Any, occurred_at: str) -> dict[str, Any]:
        reissued = command_with_approval(binding.engine_binding(), command, state=state, occurred_at=occurred_at)
        receipt = dict(reissued.get("receipt") or {})
        receipt.update({"gate_task_ref": binding.approval_ref, "gate_kind": binding.gate_kind, "decided_by_ref": binding.decided_by_ref, "decided_at": binding.decided_at})
        reissued["receipt"] = receipt
        return reissued


def launch_runtime(plan: LaunchPlan, store: Any, *, approval_requester: Any = None) -> EngineRuntime:
    """The durable loop for one launch: engine states behind Spring's fences, human hops through the launch gate lane."""

    return EngineRuntime(spec=LAUNCH_LIFECYCLE, engine=LAUNCH_KIND, plan=plan, store=store, advance=advance_launch, approval_requester=approval_requester, approval_lane=LaunchGateLane(), risk_level=8)


# --------------------------------------------------------------------------- #
# Receipts from the platform's own outputs and from operator attestations
# --------------------------------------------------------------------------- #


def formation_receipt(result: Any) -> dict[str, Any]:
    """From ``client.create_company`` / ``company_formation.parse_guided_response``; the company is named by slug, never by id."""

    raw = _document(result)
    _require(str(raw.get("provisioning")) == "provisioned" and str(raw.get("next_step")) == NEXT_STEP_OPEN_WORKSPACE, "FORMATION_INCOMPLETE", f"formation is {raw.get('provisioning')} at {raw.get('next_step')}; wait for a provisioned company whose next step opens the workspace")
    company = dict(raw.get("company") or {})
    slug = str(company.get("slug") or "").strip()
    _require(bool(slug), "FORMATION_SLUG_MISSING", "the guided company response carries no slug; the SDK will not name a company by its id")
    ref = f"company:{slug}"
    return {"formed_company_ref": ref, "formation_country": normalize_formation_country(raw.get("country")), "region_matches_country": bool(raw.get("region_matches_country")), "provisioning": "provisioned", "next_step": NEXT_STEP_OPEN_WORKSPACE, "evidence_refs": [ref]}


def registration_attestation(
    *,
    country: str,
    registrar: str,
    registration_ref: str,
    registered_at: str,
    filed_by_ref: str,
    licence_refs: Sequence[str] = (),
    evidence_sha256: Sequence[str],
    attestation_text: str,
    evidence_refs: Sequence[str] = (),
) -> dict[str, Any]:
    """Operator evidence that names itself: the platform performs no registrar write anywhere."""

    code = normalize_formation_country(country)
    allowed = REGISTRARS_BY_COUNTRY.get(code, ())
    _require(registrar in allowed, "REGISTRAR_NOT_FOR_COUNTRY", f"{registrar} does not register companies in {code}; expected one of {list(allowed)}")
    return {
        "registrar": registrar,
        "registration_ref": registration_ref,
        "registered_at": timestamp(registered_at, field_name="registered_at"),
        "filed_by_ref": filed_by_ref,
        "licence_refs": list(licence_refs),
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [*evidence_refs, f"registration:{registration_ref}"],
        "detail": "operator-supplied attestation; the platform holds no registrar write",
    }


def bank_receipt(position: CashPosition | Mapping[str, Any], *, account_holder_ref: str, evidence_sha256: Sequence[str], attestation_text: str) -> dict[str, Any]:
    """The account is proven by a governed balance read (``company_treasury.cash_position``); the KYC itself is attested."""

    try:
        parsed_position = position if isinstance(position, CashPosition) else CashPosition.model_validate(_document(position))
    except _PydanticValidationError as exc:
        raise LaunchPlanError("BANK_POSITION_INVALID", f"the cash position does not describe an account: {exc.errors()[0]['msg'] if exc.errors() else exc}") from exc
    _require(parsed_position.accounts >= 1, "BANK_POSITION_INVALID", "the balance read matched no account in this currency")
    # ``CashPosition`` carries no seal of its own, so the receipt checks what produced it the way
    # ``signature_receipt`` checks its provenance: a position that did not come from a governed
    # balance read proves no bank account.
    _require(parsed_position.source_tool in BALANCE_TOOLS, "BANK_POSITION_INVALID", f"a bank account is proven by a governed balance read ({', '.join(BALANCE_TOOLS)}); this position names {parsed_position.source_tool}")
    return {
        "position_digest": parsed_position.provenance_digest,
        "bank_available": str(parsed_position.available),
        "bank_currency": parsed_position.currency,
        "account_holder_ref": account_holder_ref,
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [f"position:{parsed_position.provenance_digest[:24]}"],
        "detail": "operator-supplied attestation over a governed balance read; the bank's KYC happens outside Lightbulb",
    }


def signature_receipt(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any], *, paper_ref: str, document_digest: str) -> dict[str, Any]:
    """From a ``signing.get_envelope`` read: a completed envelope proves the act without an approval."""

    parsed_provenance = provenance if isinstance(provenance, ObservationProvenance) else ObservationProvenance.model_validate(_document(provenance))
    _require(parsed_provenance.source_tool == SIGNING_TOOL, "OBSERVATION_TOOL_MISMATCH", f"expected a {SIGNING_TOOL} read; got {parsed_provenance.source_tool}")
    envelope = dict(dict(detached(payload)).get("envelope") or {})
    _require(bool(envelope.get("id")) and bool(envelope.get("status")), "ENVELOPE_INCOMPLETE", "the canonical envelope carries no id or status")
    recipients = [dict(item) for item in (envelope.get("recipients") or []) if isinstance(item, Mapping)]
    completed = envelope.get("completed_date") or envelope.get("completedDateTime")
    # An envelope that is not completed carries no completion date; the receipt still builds so the
    # ``sign_paper`` guard can refuse it with ENVELOPE_NOT_COMPLETED instead of a bare ValueError here.
    _require(bool(completed) or str(envelope["status"]) != "completed", "ENVELOPE_INCOMPLETE", "the envelope claims completion but carries no completion date")
    return {
        "paper_ref": paper_ref,
        "envelope_ref": f"envelope:{stable_digest({'id': envelope['id']})[:24]}",
        "envelope_status": str(envelope["status"]),
        "document_digest": document_digest,
        "signed_at": None if not completed else _stamp(completed, field_name="signed_at"),
        "signer_refs": [f"signer:{_sha(item['email'])[:16]}" for item in recipients if item.get("email")],
        "evidence_refs": [parsed_provenance.observation_ref],
    }


def signature_attestation(*, paper_ref: str, document_digest: str, signer_refs: Sequence[str], signed_at: str, evidence_sha256: Sequence[str], attestation_text: str) -> dict[str, Any]:
    """A wet signature nothing read: attested, and therefore gated."""

    return {
        "paper_ref": paper_ref,
        "document_digest": document_digest,
        "signer_refs": list(signer_refs),
        "signed_at": timestamp(signed_at, field_name="signed_at"),
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [paper_ref],
        "detail": "operator-supplied attestation; no signing read proves this document",
    }


def insurance_attestation(blueprint: LaunchBlueprint | Mapping[str, Any], policies: Sequence[Mapping[str, Any]], *, evidence_sha256: Sequence[str], attestation_text: str) -> dict[str, Any]:
    """Bound cover the broker confirmed; every policy must be one the blueprint asked for, at or above its minimum."""

    parsed_blueprint = blueprint if isinstance(blueprint, LaunchBlueprint) else LaunchBlueprint.model_validate(_document(blueprint))
    minimums = {item.kind: item.minimum_cover for item in parsed_blueprint.insurance}
    kinds: list[str] = []
    refs: list[str] = []
    bound: list[str] = []
    for row in policies:
        item = dict(detached(row))
        kind = str(item.get("kind"))
        _require(kind in minimums, "INSURANCE_KIND_UNKNOWN", f"{kind} is not cover this blueprint requires; it requires {sorted(minimums)}")
        cover = _money(item.get("cover"), field_name="cover")
        _require(cover >= minimums[kind], "INSURANCE_COVER_BELOW_MINIMUM", f"{kind} is bound at {cover}, under the declared minimum {minimums[kind]}")
        _require(bool(item.get("policy_ref")) and bool(item.get("bound_at")), "INSURANCE_MISSING", f"the {kind} policy names no policy reference or bind date")
        kinds.append(kind)
        refs.append(str(item["policy_ref"]))
        bound.append(timestamp(str(item["bound_at"]), field_name="bound_at"))
    return {
        "insurance_kinds": kinds,
        "policy_refs": refs,
        "bound_at": max(bound) if bound else None,
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": refs,
        "detail": "operator-supplied attestation; a broker binds cover outside Lightbulb",
    }


def licence_attestation(*, licence_ref: str, issued_by_ref: str, expires_at: str | None = None, evidence_sha256: Sequence[str], attestation_text: str) -> dict[str, Any]:
    return {
        "licence_ref": licence_ref,
        "issued_by_ref": issued_by_ref,
        "licence_expires_at": None if expires_at is None else timestamp(expires_at, field_name="licence_expires_at"),
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [licence_ref],
        "detail": "operator-supplied attestation; the licensing authority grants outside Lightbulb",
    }


def payments_attestation(*, account_id: str, charges_enabled: bool, evidence_sha256: Sequence[str], attestation_text: str) -> dict[str, Any]:
    """Stripe hosted onboarding, attested until a governed onboarding observer exists; the ``acct_`` id never travels raw."""

    _require(bool(charges_enabled), "PAYMENTS_NOT_ENABLED", "the connected account cannot take charges yet; finish Stripe's hosted onboarding first")
    return {
        "payments_account_sha256": _sha(account_id),
        "charges_enabled": True,
        "evidence_sha256": list(evidence_sha256),
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [f"payments:{_sha(account_id)[:24]}"],
        "detail": "operator-supplied attestation; the account id travels only as a digest",
    }


def provisioning_receipt(kind: str, document: Mapping[str, Any]) -> dict[str, Any]:
    """From the platform's own deploy or purchase response; the SDK provisions nothing and keeps no raw address or number."""

    raw = dict(detached(document))
    if kind == "website":
        _require(str(raw.get("status")) == "deployed" and bool(raw.get("subdomain")), "SITE_NOT_DEPLOYED", f"the page-builder response is {raw.get('status')} with subdomain {raw.get('subdomain')!r}")
        digest = _sha(raw["subdomain"])
        site = raw.get("siteProjectId")
        return {"provisioned_kind": "website", "provisioned_ref_sha256": digest, "site_project_ref": None if site is None else f"site:{_sha(site)[:24]}", "evidence_refs": [f"site:{digest[:24]}"]}
    if kind == "phone_number":
        _require(bool(raw.get("success")) and bool(raw.get("phoneNumber")), "PHONE_NOT_PURCHASED", f"the phone provisioning response is {raw.get('error') or raw.get('success')!r}")
        digest = _sha(raw["phoneNumber"])
        return {"provisioned_kind": "phone_number", "provisioned_ref_sha256": digest, "evidence_refs": [f"phone:{digest[:24]}"]}
    raise LaunchPlanError("PROVISIONING_MISSING", f"{kind!r} is not a provisioning kind this launch knows; expected website or phone_number")


def readiness_receipt(readiness: ConnectorReadiness | Mapping[str, Any]) -> dict[str, Any]:
    parsed_readiness = readiness if isinstance(readiness, ConnectorReadiness) else ConnectorReadiness.model_validate(_document(readiness))
    return {"readiness_digest": parsed_readiness.readiness_digest, "ready": parsed_readiness.ready, "blocked_engines": list(parsed_readiness.blocked_engines), "evidence_refs": [f"readiness:{parsed_readiness.readiness_digest[:24]}"]}


def bring_up_receipt(report: BringUpReport | Mapping[str, Any], *, storefront_refs: Sequence[str] = ()) -> dict[str, Any]:
    parsed_report = report if isinstance(report, BringUpReport) else BringUpReport.model_validate(_document(report))
    _require(parsed_report.live, "BRING_UP_NOT_LIVE", f"the bring-up report is {parsed_report.status}; the company is not live")
    return {"bring_up_report_digest": parsed_report.report_digest, "bring_up_status": parsed_report.status, "storefront_refs": list(storefront_refs), "evidence_refs": [f"bring_up:{parsed_report.report_digest[:24]}"]}


def first_dollar_receipt(source: Any, *, currency: str, case_ref: str | None = None, spend_to_date: Any = "0", source_plan: Any = None) -> dict[str, Any]:
    """The first dollar is settled cash: a SETTLED Stripe settlement observation, or a revenue case that reached it."""

    spend = str(_money(spend_to_date, field_name="spend_to_date"))
    if isinstance(source, Mapping) and str(dict(source).get("schema")) == SETTLEMENT_OBSERVATION_SCHEMA:
        settled = settlement_receipt(source, currency=currency)
        return {
            "first_dollar_source": {"observation": dict(source)},
            "case_ref": case_ref or f"settlement:{settled['settlement_evidence_sha256'][:24]}",
            "settled_amount": settled["settled_amount"],
            "settlement_currency": currency.upper(),
            "settlement_evidence_sha256": settled["settlement_evidence_sha256"],
            "settled_at": settled["payout_arrival_at"],
            "spend_to_date": spend,
            "evidence_refs": list(settled["evidence_refs"]),
        }
    ledger = getattr(source, "ledger", None)
    status = getattr(source, "status", None)
    if ledger is not None and status in ("cash_settled", "receivable_cleared"):
        # The case names its own currency in its sealed scope; the caller's ``currency`` is checked
        # against it rather than stamped onto the receipt, so a CAD case cannot be reported as AUD.
        _require(getattr(source, "entity", None) == "revenue_case", "FIRST_DOLLAR_SOURCE_UNKNOWN", f"a settled {getattr(source, 'entity', None)} state is not a revenue case")
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
        _require(source_plan is not None, "FIRST_DOLLAR_SOURCE_PLAN_REQUIRED", "a settled case requires its full source plan for replay")
        _, source = REVENUE_CHAIN_LIFECYCLE.bind(source_plan, source)
        ledger = source.ledger
        _require(str(source.scope.currency).upper() == currency.upper(), "SETTLEMENT_CURRENCY_MISMATCH", f"the revenue case settled in {source.scope.currency}, not {currency.upper()}")
        return {
            "first_dollar_source": {"state": source.to_dict(), "plan": _document(source_plan)},
            "case_ref": case_ref or str(source.scope.entity_ref),
            "settled_amount": str(ledger.settled_amount),
            "settlement_currency": currency.upper(),
            "settlement_evidence_sha256": source.state_digest,
            "settled_at": str(ledger.settled_at),
            "spend_to_date": spend,
            "evidence_refs": [f"revenue_case:{source.scope.entity_ref}", f"state:{source.state_digest[:24]}"],
        }
    raise LaunchPlanError("FIRST_DOLLAR_SOURCE_UNKNOWN", "a first dollar comes from a SETTLED cash settlement observation or a revenue case at cash_settled / receivable_cleared")


def decision_attestation(brief: Any, *, decision: Literal["scale", "kill"], spend_to_date: Any, evidence_sha256: Sequence[str] = (), attestation_text: str) -> dict[str, Any]:
    """The kill-or-scale decision, taken by a director against a sealed brief."""

    raw = _document(brief)
    digest = str(raw.get("brief_digest") or raw.get("board_pack_digest") or raw.get("decision_digest") or "")
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)), "BRIEF_MISSING", "the decision brief carries no sealed digest to decide against")
    return {
        "decision": decision,
        "brief_digest": digest,
        "spend_to_date": str(_money(spend_to_date, field_name="spend_to_date")),
        "evidence_sha256": [digest, *evidence_sha256][:8],
        "attestation_sha256": _sha(attestation_text),
        "evidence_refs": [f"brief:{digest[:24]}"],
        "detail": "operator-supplied attestation; the director decides scale or kill at the fixed date",
    }


def launch_summary(state: Any) -> dict[str, Any]:
    ledger = state.ledger
    return {
        "launch_ref": str(state.scope.entity_ref),
        "status": state.status,
        "formed_company_ref": ledger.formed_company_ref,
        "gates_passed": list(ledger.gates_passed),
        "live_at": ledger.live_at,
        "first_dollar_at": ledger.first_dollar_at,
        "first_dollar_amount": str(ledger.first_dollar_amount),
        "days_to_first_dollar": ledger.days_to_first_dollar,
        "spend_before_first_dollar": str(ledger.spend_before_first_dollar),
        "spend_ceiling_breached": ledger.spend_ceiling_breached,
        "kill_or_scale_at": ledger.kill_or_scale_at,
        "outcome": ledger.outcome,
        "state_digest": state.state_digest,
    }


# ``saas_product_loop`` already exports a ``LaunchPlan``; the root package takes this one under its
# unambiguous name, so the alias lives here rather than being minted by the wiring.
CompanyLaunchPlan = LaunchPlan

LAUNCH_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": LAUNCH_KIND,
    "golden_loop": LAUNCH_GOLDEN_LOOP,
    "stages": ["plan", "form", "register", "open_bank", "sign_paper", "bind_insurance", "grant_licence", "verify_payments", "provision", "verify_connectors", "go_live", "record_first_dollar", "decide"],
    "statuses": list(LAUNCH_STATUSES),
    "events": list(LAUNCH_EVENTS),
    "hops": {
        "plan": "compile_launch_plan over a LaunchBlueprint with no blockers and a passing LaunchSimulation",
        "form": "the guided formation response (company slug, provisioned, open_company_workspace)",
        "register": "operator registration attestation behind a sdk_launch_gate decision",
        "open_bank": "company_treasury.cash_position over a governed balance read, behind a sdk_launch_gate decision",
        "sign_paper": "a signing.get_envelope read with a matching document digest, otherwise an attestation behind a gate",
        "bind_insurance": "operator policy attestation behind a sdk_launch_gate decision",
        "grant_licence": "operator licence attestation behind a sdk_launch_gate decision",
        "verify_payments": "operator Stripe onboarding attestation behind a sdk_launch_gate decision",
        "provision": "the platform's page-builder deploy response and phone purchase response",
        "verify_connectors": "company_bring_up.assess_readiness",
        "go_live": "a live BringUpReport",
        "record_first_dollar": "a SETTLED stripe cash settlement observation or a settled revenue_chain case",
        "decide": "operator scale-or-kill attestation behind a sdk_launch_gate decision, at the fixed date",
    },
    "human_gates": {
        "register": "director files with ASIC / Corporations Canada; attested",
        "open_bank": "account holder opens the account and completes bank KYC; proven by a balance read, attested",
        "sign_paper": "signatories sign; a signing.get_envelope read proves it, otherwise attested",
        "bind_insurance": "broker binds cover; attested",
        "grant_licence": "licensing authority grants; attested",
        "verify_payments": "account holder completes Stripe hosted onboarding; attested until the governed onboarding observer lands",
        "decide": "director decides scale or kill at the date; attested",
    },
    "platform_steps": {"form": "POST /api/companies/guided", "provision": ["page_builder_deploy", "POST /api/phone-provisioning/purchase"]},
    "required_connectors": ["lightbulb.account", "lightbulb.launch_gate_approvals", "lightbulb.sdk_engine_state", "page_builder", "stripe (settlement observation)", "airwallex or xero or quickbooks (balance read)", "docusign (optional)"],
    "hard_rules": [
        "the plan opens only against a simulation of this exact operating plan that reaches revenue without halting and stays above the cash floor",
        "every human step is refused with *_APPROVAL_REQUIRED until a sdk_launch_gate task decided by a person other than the requester is bound to that exact command",
        "provisioning consumes the platform's own deploy and purchase responses; the SDK never provisions",
        "the company is named by slug, never id; account ids, subdomains and phone numbers travel only as digests",
        "first dollar is settled cash, never a booking or an invoice",
        "the kill-or-scale date is fixed at planning; a first dollar after it needs manual reconciliation",
    ],
}

__all__ = [
    "ARCHETYPE_FIRST_DOLLAR_DAYS",
    "GATE_FOR_EVENT",
    "LAUNCH_EVENTS",
    "LAUNCH_GATES_PATH",
    "LAUNCH_GATE_APPROVAL_TYPE",
    "LAUNCH_GATE_BINDING_SCHEMA",
    "LAUNCH_GATE_REQUEST_SCHEMA",
    "LAUNCH_GOLDEN_LOOP",
    "LAUNCH_KIND",
    "LAUNCH_LIFECYCLE",
    "LAUNCH_MANIFEST",
    "LAUNCH_PLAN_SCHEMA",
    "LAUNCH_SIMULATION_SCHEMA",
    "LAUNCH_STATUSES",
    "MAX_LAUNCH_STEPS",
    "MAX_LAUNCH_TRANSITIONS",
    "MIN_LAUNCH_STEPS",
    "REGISTRARS_BY_COUNTRY",
    "STOREFRONT_REQUIRED",
    "TERMINAL_LAUNCH_STATUSES",
    "CompanyLaunchPlan",
    "GateKind",
    "HumanRole",
    "ProvisioningKind",
    "StepKind",
    "LaunchEffectBoundary",
    "LaunchGateApprovalRequest",
    "LaunchGateBinding",
    "LaunchGateLane",
    "LaunchLedger",
    "LaunchPlan",
    "LaunchPlanError",
    "LaunchReceipt",
    "LaunchSimulation",
    "LaunchState",
    "LaunchStep",
    "LaunchTargets",
    "advance_launch",
    "bank_receipt",
    "bind_launch_gate",
    "bring_up_receipt",
    "compile_launch_plan",
    "decision_attestation",
    "first_dollar_receipt",
    "formation_receipt",
    "insurance_attestation",
    "launch_gate_request",
    "launch_ref",
    "launch_runtime",
    "launch_summary",
    "licence_attestation",
    "payments_attestation",
    "provisioning_receipt",
    "readiness_receipt",
    "registration_attestation",
    "signature_attestation",
    "signature_receipt",
    "simulate_launch",
    "start_launch",
]
