"""Company provisioning: one replay-fenced case per instrument, from planned to active, with every human step named.

A formed company owns nothing an engine can reach.  Payments, a site, a phone
number, an e-signature envelope, a treasury account, a payee and a tax
registration are *instruments*, and an instrument that does not exist yet
cannot be reached through the governed connector rail at all.  Round 6 gives
the platform one Company Provisioning Authority that mints the first three
behind an approval task and a journal, leaves the rest to approval-required
governed writes with closed contracts, and observes every one of them through
a digest-only governed read.  This module is the ledger of that work::

    planned -> approval_requested -> provisioned -> awaiting_human -> active
            -> inactive -> active ...            (refused | withdrawn terminal)

Each transition consumes a sealed
``lightbulb.company_provisioning_receipt.v1`` built by
``lightbulb.company_provisioning_receipts`` from the platform artifact that
produced it -- a durable provisioning receipt, a SUCCESS governed execution
receipt, a HITL_REQUIRED proposal, a recomputed observation, or a self-naming
operator attestation.  Nothing here mints, writes, reads, signs, files, or
approves; the guards only refuse the receipts that do not line up: a proposal
that does not name its instrument's write tool, a write that does not carry
the approval the case is waiting on, an observation from the wrong observer,
an observation of a different instrument, an observation dated in the future,
or an onboarding link whose expiry has passed.

``assess_launch_gate`` seals a ``lightbulb.company_launch_gate.v1`` that says
exactly which instrument is blocked by which named human step, and
``bring_up_receipt`` turns that gate into the three fields
``company_bring_up.verify_connectors`` consumes, so a company cannot be
brought up on connectors alone while its payments account is still waiting on
its owner's own act.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

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
    timestamp,
    unique,
)
from lightbulb.company_engine_store import EngineRuntime, EngineStateStore
from lightbulb.company_formation import normalize_formation_country
from lightbulb.company_operating_system import CompanyOperatingPlan
from lightbulb.company_provisioning_receipts import (
    HUMAN_STEP_TEXT,
    PLATFORM_SOURCE_TOOL,
    RECEIPT_SCHEMA,
    Disposition,
    HumanActor,
    HumanGateKind,
    HumanStep,
    InstrumentKind,
    Lane,
    ProvisioningReceipt,
)

PROVISIONING_KIND = "company_provisioning"
PROVISIONING_GOLDEN_LOOP = "company.formed_to_instrumented@0.1.0"
PROVISIONING_PLAN_SCHEMA = "lightbulb.company_provisioning_plan.v1"
LAUNCH_GATE_SCHEMA = "lightbulb.company_launch_gate.v1"
MAX_INSTRUMENT_TRANSITIONS = 24
MAX_INSTRUMENTS = 8

INSTRUMENT_STATUSES: tuple[str, ...] = ("planned", "approval_requested", "provisioned", "awaiting_human", "active", "inactive", "refused", "withdrawn")
TERMINAL_INSTRUMENT_STATUSES: frozenset[str] = frozenset({"refused", "withdrawn"})
INSTRUMENT_EVENTS: tuple[str, ...] = ("plan", "request_approval", "record_write", "hand_to_human", "observe", "refuse", "withdraw")
_INSTRUMENT_TABLE: dict[tuple[str, str], str] = {
    ("new", "plan"): "planned",
    ("planned", "request_approval"): "approval_requested",
    ("planned", "record_write"): "provisioned",
    ("approval_requested", "record_write"): "provisioned",
    ("provisioned", "hand_to_human"): "awaiting_human",
    # A write whose receipt already names a pending step lands in awaiting_human; the
    # runner still journals the hand-off as its own transition, so it must be legal there.
    ("awaiting_human", "hand_to_human"): "awaiting_human",
    ("planned", "observe"): "active",
    ("provisioned", "observe"): "active",
    ("awaiting_human", "observe"): "active",
    ("active", "observe"): "active",
    ("inactive", "observe"): "active",
    **{(status, "refuse"): "refused" for status in ("planned", "approval_requested", "provisioned", "awaiting_human", "active", "inactive")},
    **{(status, "withdraw"): "withdrawn" for status in ("planned", "approval_requested", "awaiting_human")},
}


class CompanyProvisioningError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CompanyProvisioningError(code, message)


# --------------------------------------------------------------------------- #
# What each instrument is, who mints it, and who observes it
# --------------------------------------------------------------------------- #


class InstrumentSpec(StrictModel):
    """The fixed shape of one instrument: its provider, its lane, and the exact tools that may move it."""

    provider: ShortText
    lane: Lane
    write_tool: ShortText | None = None
    observe_tool: ShortText | None = None
    completes_by_human: bool = False
    optional_by_default: bool = False


INSTRUMENT_CATALOG: Mapping[str, InstrumentSpec] = {
    "payments": InstrumentSpec(provider="stripe", lane="platform_approval", write_tool=PLATFORM_SOURCE_TOOL, observe_tool="stripe.observe_account_readiness", completes_by_human=True, optional_by_default=False),
    "web_presence": InstrumentSpec(provider="lightbulb_pages", lane="platform_approval", write_tool=PLATFORM_SOURCE_TOOL, observe_tool="square.observe_locations", completes_by_human=False, optional_by_default=False),
    "phone": InstrumentSpec(provider="twilio_platform", lane="platform_approval", write_tool=PLATFORM_SOURCE_TOOL, observe_tool=None, completes_by_human=False, optional_by_default=True),
    "esign": InstrumentSpec(provider="docusign", lane="governed_write", write_tool="docusign.create_envelope", observe_tool="docusign.observe_envelope_status", completes_by_human=True, optional_by_default=True),
    "treasury_account": InstrumentSpec(provider="airwallex", lane="governed_write", write_tool="airwallex.create_global_account", observe_tool="airwallex.get_global_account", completes_by_human=False, optional_by_default=True),
    "payee": InstrumentSpec(provider="airwallex", lane="governed_write", write_tool="airwallex.create_beneficiary", observe_tool=None, completes_by_human=False, optional_by_default=True),
    "registration": InstrumentSpec(provider="ato|cra", lane="operator_attestation", write_tool=None, observe_tool=None, completes_by_human=True, optional_by_default=False),
}

# The human gate each human-completed instrument opens, for the plan preview.
INSTRUMENT_HUMAN_GATE: Mapping[str, str] = {"payments": "stripe_hosted_onboarding", "esign": "counterparty_signature", "registration": "tax_registration"}

# Which instruments an archetype provisions.  ``None`` means always required; a string
# names the operator override that decides whether that instrument is required.
INSTRUMENTS_BY_ARCHETYPE: Mapping[str, tuple[tuple[str, str | None], ...]] = {
    "services_firm": (("payments", None), ("web_presence", None), ("phone", "receptionist"), ("esign", "esign"), ("registration", None)),
    "b2b_saas": (("payments", None), ("web_presence", None), ("esign", None), ("registration", None)),
    "dtc_commerce": (("payments", None), ("web_presence", None), ("registration", None)),
    "marketplace": (("payments", None), ("web_presence", None), ("esign", None), ("registration", None)),
    "custom": (("payments", None), ("registration", None)),
}
TREASURY_INSTRUMENTS: tuple[str, ...] = ("treasury_account", "payee")
REGISTRATION_AUTHORITY: Mapping[str, str] = {"AU": "ato", "CA": "cra"}


# The only company reference a caller may supply: the derived ref formation mints.  A
# tenant, company or user id from the platform is never one, and is never accepted here.
_DERIVED_COMPANY_REF = re.compile(r"^company:[0-9a-f]{24}$")


def _slug(value: str) -> str:
    text = "".join(character if character.isalnum() else "-" for character in str(value).lower())
    return "-".join(part for part in text.split("-") if part) or "company"


class InstrumentRequirement(StrictModel):
    instrument: InstrumentKind
    provider: ShortText
    required: bool


class ProvisioningPlan(StrictModel):
    """Which instruments this company needs, who provides each, and which of them gate launch."""

    schema_id: str = Field(default=PROVISIONING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    archetype: ShortText
    country: Literal["AU", "CA"]
    instruments: tuple[InstrumentRequirement, ...] = Field(min_length=1, max_length=MAX_INSTRUMENTS)
    operating_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("country", mode="before")
    @classmethod
    def _country(cls, value: Any) -> str:
        return normalize_formation_country(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProvisioningPlan:
        unique([item.instrument for item in self.instruments], label="provisioned instruments")
        for item in self.instruments:
            if item.instrument not in INSTRUMENT_CATALOG:
                raise ValueError(f"{item.instrument} is not a known instrument")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ProvisioningPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def requirement(self, instrument: str | None) -> InstrumentRequirement | None:
        return next((item for item in self.instruments if item.instrument == instrument), None)

    @property
    def instrument_kinds(self) -> tuple[str, ...]:
        return tuple(item.instrument for item in self.instruments)

    @property
    def required_kinds(self) -> tuple[str, ...]:
        return tuple(item.instrument for item in self.instruments if item.required)


def compile_provisioning_plan(operating_plan: CompanyOperatingPlan | Mapping[str, Any], *, overrides: Mapping[str, bool] | None = None, company_ref: str | None = None) -> ProvisioningPlan:
    """Compile the instruments an archetype needs from its sealed operating plan; nothing is provisioned here."""

    plan = CompanyOperatingPlan.model_validate(detached(operating_plan))
    if company_ref is not None:
        derived = _DERIVED_COMPANY_REF.match(str(company_ref)) is not None
        _require(derived, "COMPANY_REF_NOT_DERIVED", "company_ref is the derived company:<digest> reference formation mints; a platform company id is never accepted")
    blueprint = plan.blueprint
    flags = {str(key): bool(value) for key, value in dict(overrides or {}).items()}
    country = normalize_formation_country(blueprint.country)
    rows: list[dict[str, Any]] = []
    for kind, override_key in INSTRUMENTS_BY_ARCHETYPE.get(blueprint.archetype, INSTRUMENTS_BY_ARCHETYPE["custom"]):
        provider = REGISTRATION_AUTHORITY[country] if kind == "registration" else INSTRUMENT_CATALOG[kind].provider
        rows.append({"instrument": kind, "provider": provider, "required": True if override_key is None else flags.get(override_key, False)})
    if flags.get("treasury"):
        rows.extend({"instrument": kind, "provider": INSTRUMENT_CATALOG[kind].provider, "required": not INSTRUMENT_CATALOG[kind].optional_by_default} for kind in TREASURY_INSTRUMENTS)
    return seal(ProvisioningPlan, {"company_ref": company_ref or _slug(blueprint.name), "archetype": blueprint.archetype, "country": country, "instruments": rows, "operating_plan_digest": plan.plan_digest}, "plan_digest")


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


class InstrumentReceipt(StrictModel):
    """The projection of one sealed provisioning receipt; every field comes from that document."""

    provisioning_receipt_digest: Sha256Digest | None = None
    instrument: InstrumentKind | None = None
    disposition: Disposition | None = None
    lane: Lane | None = None
    source_tool: ShortText | None = None
    instrument_sha256: Sha256Digest | None = None
    journal_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    correlation_sha256: Sha256Digest | None = None
    evidence_sha256: Sha256Digest | None = None
    human_steps: tuple[HumanStep, ...] = Field(default_factory=tuple, max_length=4)
    observed_at: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("human_steps", "evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="observed_at")


class InstrumentLedger(StrictModel):
    """Derived state only: what the receipts proved about this instrument."""

    instrument: str | None = None
    provider: str | None = None
    instrument_sha256: str | None = None
    observed_instrument_sha256: str | None = None
    journal_ref: str | None = None
    approval_ref: str | None = None
    correlation_sha256: str | None = None
    evidence_sha256: str | None = None
    pending_step: HumanGateKind | None = None
    pending_step_actor: HumanActor | None = None
    pending_step_expires_at: str | None = None
    requested_at: str | None = None
    provisioned_at: str | None = None
    handed_to_human_at: str | None = None
    activated_at: str | None = None
    last_observed_at: str | None = None
    observation_count: int = Field(default=0, ge=0)
    refuse_reason: str | None = None
    withdraw_reason: str | None = None
    outcome: Literal["open", "active", "inactive", "refused", "withdrawn"] = "open"


class InstrumentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_written: Literal[False] = False
    approval_decided: Literal[False] = False
    custody_held_by_sdk: Literal[False] = False
    url_handled: Literal[False] = False
    money_spent: Literal[False] = False
    message_sent: Literal[False] = False


def _pending(receipt: Any) -> HumanStep | None:
    return next((step for step in receipt.human_steps if step.status == "pending"), None)


def _observe_lane(spec: InstrumentSpec) -> str:
    """A registration is proved by the operator's own attestation; everything else by a governed read."""

    return "operator_attestation" if spec.lane == "operator_attestation" else "governed_read"


def _apply_instrument(plan: ProvisioningPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "plan":
        requirement = plan.requirement(r.instrument)
        require(requirement is not None, "INSTRUMENT_NOT_PLANNED", f"{r.instrument!r} is not one of the instruments this plan provisions: {list(plan.instrument_kinds)}")
        assert requirement is not None
        data.update({"instrument": requirement.instrument, "provider": requirement.provider})
        return next_status, data
    spec = INSTRUMENT_CATALOG[str(data.get("instrument"))]
    kind = str(data.get("instrument"))
    if event in ("request_approval", "record_write", "hand_to_human", "observe"):
        # ``payments``, ``web_presence`` and ``phone`` are all minted by the one platform
        # tool, so the tool guards below cannot tell them apart; the receipt must name the
        # instrument whose case it is moving or a site mint would land in the payments ledger.
        same_instrument = r.instrument == kind
        require(same_instrument, "INSTRUMENT_MISMATCH", f"this case provisions {kind}; the receipt names {r.instrument!r}")
    if event == "request_approval":
        require(r.disposition == "awaiting_approval" and r.approval_ref is not None, "APPROVAL_RECEIPT_MISSING", "an approval request names the pending approval task a human must decide, and nothing dispatched")
        require(r.source_tool == spec.write_tool, "APPROVAL_TOOL_MISMATCH", f"a {kind} proposal runs {spec.write_tool!r}, not {r.source_tool!r}")
        data.update({"approval_ref": r.approval_ref, "requested_at": at, "evidence_sha256": r.evidence_sha256})
    elif event == "record_write":
        written = r.disposition in ("provisioned", "partial", "awaiting_human") and r.instrument_sha256 is not None and r.journal_ref is not None
        require(written, "WRITE_RECEIPT_MISSING", "a recorded write names the instrument it minted and the journal that recorded it")
        own_tool = r.lane in ("governed_write", "platform_approval") and r.source_tool == spec.write_tool
        require(own_tool, "WRITE_TOOL_MISMATCH", f"a {kind} write runs {spec.write_tool!r} on the {spec.lane!r} lane, not {r.source_tool!r} on {r.lane!r}")
        if status == "approval_requested":
            awaited = data.get("approval_ref")
            same_approval = r.approval_ref == awaited
            require(same_approval, "APPROVAL_REF_MISMATCH", f"the write names approval {r.approval_ref!r}; this case is waiting on {awaited!r}", "refresh_state")
        step = _pending(r)
        data.update({"instrument_sha256": r.instrument_sha256, "journal_ref": r.journal_ref, "approval_ref": r.approval_ref or data.get("approval_ref"), "correlation_sha256": r.correlation_sha256 or data.get("correlation_sha256"), "evidence_sha256": r.evidence_sha256, "provisioned_at": at})
        if step is not None:
            data.update({"pending_step": step.kind, "pending_step_actor": step.actor, "pending_step_expires_at": step.expires_at})
            next_status = "awaiting_human"
    elif event == "hand_to_human":
        step = _pending(r)
        named = step is not None or data.get("pending_step") is not None
        require(named, "HUMAN_STEP_MISSING", "a hand-off names the pending human step the platform opened; nothing here performs it")
        if step is not None:
            data.update({"pending_step": step.kind, "pending_step_actor": step.actor, "pending_step_expires_at": step.expires_at})
        data.update({"handed_to_human_at": at})
    elif event == "observe":
        lane = _observe_lane(spec)
        observation = r.lane == lane and r.disposition in ("observed_active", "observed_inactive", "awaiting_human") and r.observed_at is not None
        require(observation, "OBSERVATION_MISSING", f"an observation is a {lane} carrying a disposition and the moment it was taken")
        require(r.source_tool == spec.observe_tool, "OBSERVE_TOOL_MISMATCH", f"a {kind} observation comes from {spec.observe_tool!r}, not {r.source_tool!r}")
        observed = data.get("observed_instrument_sha256")
        # A governed write and its observer digest the same object (an envelope id, a global
        # account id), so the minted digest fences the very first observation.  A platform mint
        # seals a digest of its own request instead, so there only observations fence each other.
        minted = data.get("instrument_sha256") if spec.lane == "governed_write" else None
        expected = observed if observed is not None else minted
        same_ref = expected is None or r.instrument_sha256 == expected
        require(same_ref, "INSTRUMENT_REF_MISMATCH", f"this case names instrument {str(expected)[:24]}...; the observation carries a different one", "manual_reconciliation")
        correlation = data.get("correlation_sha256")
        require(correlation is None or r.correlation_sha256 is None or r.correlation_sha256 == correlation, "CORRELATION_MISMATCH", "the observation does not carry the correlation the write recorded", "manual_reconciliation")
        in_the_past = parsed(str(r.observed_at)) <= parsed(at)
        require(in_the_past, "OBSERVATION_IN_FUTURE", "an observation cannot be dated after the transition that consumes it")
        expires = data.get("pending_step_expires_at")
        still_open = expires is None or r.disposition != "awaiting_human" or parsed(str(expires)) >= parsed(at)
        require(still_open, "HUMAN_STEP_EXPIRED", f"the {data.get('pending_step')} link expired at {expires}; request a new onboarding link before observing again", "correct_input")
        data.update({"observation_count": int(data.get("observation_count", 0)) + 1, "last_observed_at": r.observed_at, "evidence_sha256": r.evidence_sha256, "observed_instrument_sha256": r.instrument_sha256 or observed, "correlation_sha256": r.correlation_sha256 or correlation})
        if r.disposition == "observed_active":
            data.update({"activated_at": at, "outcome": "active", "pending_step": None, "pending_step_actor": None, "pending_step_expires_at": None})
        elif r.disposition == "observed_inactive":
            next_status = "inactive"
            data.update({"outcome": "inactive"})
        else:
            next_status = "awaiting_human"
            step = _pending(r)
            if step is not None:
                data.update({"pending_step": step.kind, "pending_step_actor": step.actor, "pending_step_expires_at": step.expires_at or data.get("pending_step_expires_at")})
    elif event == "refuse":
        data.update({"refuse_reason": str(command.reason)[:300], "outcome": "refused"})
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    return next_status, data


INSTRUMENT_LIFECYCLE = LifecycleSpec(entity="instrument", schema_prefix=PROVISIONING_KIND, statuses=INSTRUMENT_STATUSES, terminal=TERMINAL_INSTRUMENT_STATUSES, events=INSTRUMENT_EVENTS, table=_INSTRUMENT_TABLE, opening_event="plan", reason_events=("refuse", "withdraw"), apply=_apply_instrument, ledger_model=InstrumentLedger, receipt_model=InstrumentReceipt, effect_boundary_model=InstrumentEffectBoundary, plan_model=ProvisioningPlan, max_transitions=MAX_INSTRUMENT_TRANSITIONS)
InstrumentState = INSTRUMENT_LIFECYCLE.State


def instrument_ref(plan: ProvisioningPlan, instrument: str) -> str:
    return f"{plan.company_ref}:instrument:{instrument}"


def open_instrument(plan: ProvisioningPlan | Mapping[str, Any], scope: Mapping[str, Any], *, instrument: str, opened_at: str, actor_ref: str) -> Any:
    parsed_plan = ProvisioningPlan.model_validate(detached(plan))
    entity_scope = {**dict(detached(scope)), "entity_ref": instrument_ref(parsed_plan, instrument)}
    return INSTRUMENT_LIFECYCLE.open(parsed_plan, entity_scope, opened_at=opened_at, actor_ref=actor_ref, receipt={"instrument": instrument})


def advance_instrument(plan: ProvisioningPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return INSTRUMENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# The receipt the lifecycle consumes
# --------------------------------------------------------------------------- #


def instrument_receipt(receipt: ProvisioningReceipt | Mapping[str, Any]) -> dict[str, Any]:
    """Project a sealed ``lightbulb.company_provisioning_receipt.v1`` into a lifecycle receipt.

    The receipt is re-validated here, so a tampered digest, disposition or human
    step is refused before it can move a case.
    """

    raw = dict(detached(receipt))
    schema_id = raw.get("schema")
    own_schema = schema_id == RECEIPT_SCHEMA
    _require(own_schema, "PROVISIONING_RECEIPT_SCHEMA_MISMATCH", f"expected a {RECEIPT_SCHEMA} document, not {schema_id!r}")
    try:
        sealed = ProvisioningReceipt.model_validate(raw)
    except ValueError as exc:
        raise CompanyProvisioningError("PROVISIONING_RECEIPT_INVALID", f"the provisioning receipt does not re-validate: {exc}") from exc
    return {
        "provisioning_receipt_digest": sealed.receipt_digest,
        "instrument": sealed.instrument,
        "disposition": sealed.disposition,
        "lane": sealed.lane,
        "source_tool": sealed.source_tool,
        "instrument_sha256": sealed.instrument_sha256,
        "journal_ref": sealed.journal_ref,
        "approval_ref": sealed.approval_ref,
        "correlation_sha256": sealed.correlation_sha256,
        "evidence_sha256": sealed.evidence_sha256,
        "human_steps": [step.to_dict() for step in sealed.human_steps],
        "observed_at": sealed.observed_at,
        "evidence_refs": list(sealed.evidence_refs),
    }


# --------------------------------------------------------------------------- #
# The launch gate
# --------------------------------------------------------------------------- #


class PendingHumanStep(StrictModel):
    instrument: InstrumentKind
    kind: HumanGateKind
    actor: HumanActor
    action: BoundedText
    expires_at: str | None = None

    @field_validator("expires_at")
    @classmethod
    def _expiry(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="expires_at")


class LaunchGate(StrictModel):
    """Which instruments are live, which wait on a person, and which required one is still missing."""

    schema_id: str = Field(default=LAUNCH_GATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    assessed_at: str
    required: tuple[InstrumentKind, ...] = Field(default_factory=tuple, max_length=MAX_INSTRUMENTS)
    active: tuple[InstrumentKind, ...] = Field(default_factory=tuple, max_length=MAX_INSTRUMENTS)
    awaiting_human: tuple[PendingHumanStep, ...] = Field(default_factory=tuple, max_length=MAX_INSTRUMENTS)
    awaiting_approval: tuple[InstrumentKind, ...] = Field(default_factory=tuple, max_length=MAX_INSTRUMENTS)
    missing: tuple[InstrumentKind, ...] = Field(default_factory=tuple, max_length=MAX_INSTRUMENTS)
    ready: bool
    gate_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("required", "active", "awaiting_human", "awaiting_approval", "missing", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchGate:
        if self.ready != (self.missing == () and all(item in self.active for item in self.required)):
            raise ValueError("ready must equal every required instrument being active with nothing missing")
        if not skip_digests(info) and self.gate_digest != sealed_digest(LaunchGate, self, "gate_digest"):
            raise ValueError("gate_digest must commit the exact gate")
        return self

    def blocked_instruments(self) -> list[str]:
        ordered = [*self.missing, *(item.instrument for item in self.awaiting_human), *self.awaiting_approval]
        return [item for index, item in enumerate(ordered) if item not in ordered[:index]]


def _counts_active(status: str, spec: InstrumentSpec) -> bool:
    """An instrument with no observer is proved by its mint; everything else by an observation."""

    return status == "active" or (status == "provisioned" and spec.observe_tool is None)


def assess_launch_gate(plan: ProvisioningPlan | Mapping[str, Any], states: Sequence[Mapping[str, Any] | Any], *, now: str) -> LaunchGate:
    """Seal the gate from the persisted instrument cases; a state from another plan is refused."""

    parsed_plan = ProvisioningPlan.model_validate(detached(plan))
    stamp = timestamp(now, field_name="now")
    bound: dict[str, Any] = {}
    for state in states:
        _, case = INSTRUMENT_LIFECYCLE.bind(parsed_plan, state)
        kind = str(case.ledger.instrument)
        # Two cases for one instrument would make the verdict depend on the order they arrived in.
        fresh = kind not in bound
        _require(fresh, "DUPLICATE_INSTRUMENT_STATE", f"two cases were handed in for {kind}; a gate is assessed over one case per instrument")
        bound[kind] = case
    active: list[str] = []
    waiting: list[dict[str, Any]] = []
    approving: list[str] = []
    missing: list[str] = []
    for requirement in parsed_plan.instruments:
        kind = requirement.instrument
        spec = INSTRUMENT_CATALOG[kind]
        case = bound.get(kind)
        if case is not None and _counts_active(case.status, spec):
            active.append(kind)
        elif case is not None and case.status == "awaiting_human" and case.ledger.pending_step is not None:
            gate = str(case.ledger.pending_step)
            waiting.append({"instrument": kind, "kind": gate, "actor": case.ledger.pending_step_actor or HUMAN_STEP_TEXT[gate][0], "action": HUMAN_STEP_TEXT[gate][1], "expires_at": case.ledger.pending_step_expires_at})
        elif case is not None and case.status == "approval_requested":
            approving.append(kind)
        if requirement.required and kind not in active:
            missing.append(kind)
    return seal(LaunchGate, {"plan_digest": parsed_plan.plan_digest, "assessed_at": stamp, "required": list(parsed_plan.required_kinds), "active": active, "awaiting_human": waiting, "awaiting_approval": approving, "missing": missing, "ready": not missing}, "gate_digest")


def bring_up_receipt(gate: LaunchGate | Mapping[str, Any]) -> dict[str, Any]:
    """The three fields ``company_bring_up.verify_connectors`` consumes from a sealed gate."""

    sealed = LaunchGate.model_validate(detached(gate))
    return {"launch_gate_digest": sealed.gate_digest, "instruments_ready": sealed.ready, "blocked_instruments": sealed.blocked_instruments()}


def launch_gate_summary(gate: LaunchGate) -> str:
    if gate.ready:
        return "ready"
    parts = [f"{item.instrument} blocked by {item.kind} ({item.actor})" for item in gate.awaiting_human]
    parts.extend(f"{kind} blocked by a pending approval" for kind in gate.awaiting_approval)
    named = {item.instrument for item in gate.awaiting_human} | set(gate.awaiting_approval)
    parts.extend(f"{kind} not provisioned" for kind in gate.missing if kind not in named)
    return "; ".join(parts) or "not ready"


def instrument_summary(case_state: Any) -> dict[str, Any]:
    ledger = case_state.ledger
    return {"instrument_ref": str(case_state.scope.entity_ref), "instrument": ledger.instrument, "provider": ledger.provider, "status": case_state.status, "pending_step": ledger.pending_step, "pending_step_actor": ledger.pending_step_actor, "observations": ledger.observation_count, "activated_at": ledger.activated_at, "outcome": ledger.outcome, "state_digest": case_state.state_digest}


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


class InstrumentStep(StrictModel):
    instrument: ShortText
    event: ShortText
    outcome: Literal["applied", "rejected", "skipped"]
    to_status: ShortText | None = None
    rejection_code: ShortText | None = None
    detail: BoundedText | None = None


@dataclass
class ProvisioningRunner:
    """Open one case per planned instrument and advance each on the receipts the platform sealed."""

    plan: ProvisioningPlan
    store: EngineStateStore
    clock: Callable[[], str]
    actor_ref: str
    scope: Mapping[str, Any]
    _counter: int = field(default=0, init=False)

    def _runtime(self) -> EngineRuntime:
        return EngineRuntime(spec=INSTRUMENT_LIFECYCLE, engine=PROVISIONING_KIND, plan=self.plan, store=self.store, advance=advance_instrument)

    def ensure_cases(self) -> list[str]:
        """Open a planned case for every instrument the plan names that has none yet."""

        runtime = self._runtime()
        opened: list[str] = []
        for requirement in self.plan.instruments:
            ref = instrument_ref(self.plan, requirement.instrument)
            if self.store.get(PROVISIONING_KIND, ref) is None:
                runtime.open(ref, open_instrument(self.plan, self.scope, instrument=requirement.instrument, opened_at=self.clock(), actor_ref=self.actor_ref))
                opened.append(ref)
        return opened

    def _events(self, projected: Mapping[str, Any]) -> tuple[str, ...]:
        disposition, lane = projected.get("disposition"), projected.get("lane")
        if disposition == "prepared_only":
            return ()
        if disposition == "awaiting_approval":
            return ("request_approval",)
        if lane in ("governed_write", "platform_approval") and disposition in ("provisioned", "partial", "awaiting_human"):
            pending = any(str(step.get("status")) == "pending" for step in projected.get("human_steps", ()))
            return ("record_write", "hand_to_human") if pending else ("record_write",)
        if lane in ("governed_read", "operator_attestation") and disposition in ("observed_active", "observed_inactive", "awaiting_human"):
            return ("observe",)
        return ()

    def _advance(self, ref: str, instrument: str, event: str, receipt: Mapping[str, Any]) -> InstrumentStep:
        runtime = self._runtime()
        state = runtime.load(ref)
        now = self.clock()
        self._counter += 1
        command = runtime.command(state, event=event, transition_ref=f"{event}:{instrument}:{self._counter}", idempotency_key=f"{instrument}:{event}:{self._counter}", occurred_at=now, actor_ref=self.actor_ref, receipt=receipt)
        outcome = runtime.advance_and_persist(ref, command)
        if outcome.persisted:
            return InstrumentStep(instrument=instrument, event=event, outcome="applied", to_status=outcome.result.state.status)
        rejected = outcome.result.receipt
        return InstrumentStep(instrument=instrument, event=event, outcome="rejected", rejection_code=rejected.rejection_code, detail=str(rejected.recovery.instructions)[:900])

    def apply(self, receipt: ProvisioningReceipt | Mapping[str, Any]) -> list[InstrumentStep]:
        """Choose the events one sealed receipt authorizes and advance the case through each."""

        projected = instrument_receipt(receipt)
        instrument = str(projected["instrument"])
        if self.plan.requirement(projected.get("instrument")) is None:
            return [InstrumentStep(instrument=instrument, event="none", outcome="rejected", rejection_code="INSTRUMENT_NOT_PLANNED", detail=f"this plan provisions {list(self.plan.instrument_kinds)}; no case exists for {instrument}")]
        events = self._events(projected)
        if not events:
            return [InstrumentStep(instrument=instrument, event="none", outcome="skipped", detail=f"a {projected.get('disposition')} receipt on the {projected.get('lane')} lane advances no case")]
        ref = instrument_ref(self.plan, instrument)
        self.ensure_cases()
        steps: list[InstrumentStep] = []
        for event in events:
            step = self._advance(ref, instrument, event, projected)
            steps.append(step)
            if step.outcome != "applied":
                break
        return steps

    def gate(self, now: str | None = None) -> LaunchGate:
        states = [record["state"] for record in (self.store.get(PROVISIONING_KIND, instrument_ref(self.plan, kind)) for kind in self.plan.instrument_kinds) if record is not None]
        return assess_launch_gate(self.plan, states, now=now or self.clock())

    # -- console verbs ------------------------------------------------------- #

    def provision(self, receipts: Sequence[ProvisioningReceipt | Mapping[str, Any]], *, now: str | None = None) -> dict[str, Any]:
        self.ensure_cases()
        steps: list[InstrumentStep] = []
        for receipt in receipts:
            steps.extend(self.apply(receipt))
        gate = self.gate(now)
        return {**gate.to_dict(), "steps": [step.to_dict() for step in steps], "summary": launch_gate_summary(gate)}

    def instruments(self, *, now: str | None = None) -> dict[str, Any]:
        gate = self.gate(now)
        return {**gate.to_dict(), "summary": launch_gate_summary(gate)}


PROVISIONING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PROVISIONING_KIND,
    "golden_loop": PROVISIONING_GOLDEN_LOOP,
    "stages": ["plan", "request_approval", "record_write", "hand_to_human", "observe"],
    "statuses": list(INSTRUMENT_STATUSES),
    "events": list(INSTRUMENT_EVENTS),
    "hops": {
        "payments": "POST /api/companies/{companyId}/provisioning (approved mint) -> stripe.observe_account_readiness",
        "web_presence": "POST /api/companies/{companyId}/provisioning (approved mint) -> square.observe_locations",
        "phone": "POST /api/companies/{companyId}/provisioning (approved mint); no governed observer exists yet",
        "esign": "docusign.create_envelope (HITL_REQUIRED proposal, then approved write) -> docusign.observe_envelope_status",
        "treasury_account": "airwallex.create_global_account (approved write) -> airwallex.get_global_account",
        "payee": "airwallex.create_beneficiary (approved write, verified out of band); no governed observer exists yet",
        "registration": "no tool: a director or registered agent lodges the registration and the operator attests to it",
    },
    "required_connectors": ["lightbulb.company_provisioning", "stripe", "square", "docusign", "airwallex", "lightbulb.page_builder", "lightbulb.phone_provisioning", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a case advances only on a sealed provisioning receipt",
        "write receipts prove approval",
        "onboarding links are never stored",
        "registrations are human",
    ],
}

__all__ = [
    "INSTRUMENTS_BY_ARCHETYPE",
    "INSTRUMENT_CATALOG",
    "INSTRUMENT_EVENTS",
    "INSTRUMENT_HUMAN_GATE",
    "INSTRUMENT_LIFECYCLE",
    "INSTRUMENT_STATUSES",
    "LAUNCH_GATE_SCHEMA",
    "MAX_INSTRUMENTS",
    "MAX_INSTRUMENT_TRANSITIONS",
    "PROVISIONING_GOLDEN_LOOP",
    "PROVISIONING_KIND",
    "PROVISIONING_MANIFEST",
    "PROVISIONING_PLAN_SCHEMA",
    "REGISTRATION_AUTHORITY",
    "TERMINAL_INSTRUMENT_STATUSES",
    "CompanyProvisioningError",
    "InstrumentLedger",
    "InstrumentReceipt",
    "InstrumentRequirement",
    "InstrumentSpec",
    "InstrumentState",
    "InstrumentStep",
    "LaunchGate",
    "PendingHumanStep",
    "ProvisioningPlan",
    "ProvisioningRunner",
    "advance_instrument",
    "assess_launch_gate",
    "bring_up_receipt",
    "compile_provisioning_plan",
    "instrument_receipt",
    "instrument_ref",
    "instrument_summary",
    "launch_gate_summary",
    "open_instrument",
]
