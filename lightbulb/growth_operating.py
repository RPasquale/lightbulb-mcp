"""Growth operating loop: the conductor that makes the instruments fire.

The Growth Engine's modules are honest instruments — funnel, experiments,
learnings, planners, profit, rail bridge, workspace — but the choreography
between them has lived in the agent's session memory: the weakest substrate
in the system, across exactly the multi-week horizons the engine was built
for. A missed fixed-horizon readout is a fully-paid experiment earning zero
learnings; a duplicate experiment burns a test cycle; evidence minted before
``measure_after`` poisons a causal readout; decisions on a stale snapshot
plan against dead data. This module converts workspace state into the exact
ordered agenda that prevents all four, and answers the operator's weekly
question no other function answers: did last week's work move anything?

Two artifacts, both **re-derivable digest-pinned advice** (the custody class
of :class:`~lightbulb.growth_cockpit.GrowthDiagnosis` — advice carries a
content digest, never a seal):

- :func:`compile_growth_agenda` joins caller-supplied Growth artifacts into a
  :class:`GrowthAgenda`: ranked :class:`AgendaItem` rows under a fixed,
  documented precedence (due readouts, then unrecorded learnings, then
  receipt reconciliation, then post-action measurement, then evidence gaps,
  then opportunities — dollar-ranked before funnel-only — then undispatched
  plans, then expiring learnings). It **cites** the stored diagnosis and
  profit review verbatim — it never re-ranks or re-derives them — and adds
  only workspace-derived state: due, blocked, stale, pending. Opportunities
  that would duplicate an in-flight experiment are emitted *blocked*, naming
  the design they collide with. ``idle`` and ``wake_at`` tell a scheduler
  exactly when the loop next needs the agent.
- :func:`compare_funnel_snapshots` produces a :class:`FunnelDelta`: honest
  week-over-week movement between two funnel snapshots. Every delta is
  structurally labeled ``observational_movement_not_attribution`` — causal
  claims remain the experiment engine's monopoly. Unknown stays unknown,
  cross-basis rates stay flagged, and cross-scope comparison is refused.

Cadence thresholds live in :class:`GrowthCadencePolicy`, a plain frozen
model of **caller-supplied heuristics** — deliberately unsealed: a policy
nothing enforces must not wear a seal that manufactures the appearance of
governance. No wall clock is read anywhere; ``as_of`` is caller-supplied.

Naming note: ``lightbulb/growth_primitives.py`` predates the Growth Engine
and holds unrelated catalog primitives; the Growth Engine lives in the
``growth_funnel`` / ``growth_experiments`` / ``growth_learnings`` /
``growth_profit`` / ``growth_operating`` module family.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .demand_gen_primitives import AudienceGrowthPlan, ContentCalendarPlan
from .growth_cockpit import GrowthDiagnosis
from .growth_customers import CustomerValueReview, CustomerValueSnapshot
from .growth_experiments import GrowthExperimentDesign, GrowthExperimentReadout
from .growth_funnel import (
    CurrencyCode,
    GrowthFunnelSnapshot,
    build_growth_funnel_snapshot,
)
from .growth_learnings import GrowthLearningEntry
from .growth_mandate import ActionAuthorization, GrowthMandate
from .growth_objectives import GrowthObjective, ObjectiveAssessment
from .growth_profit import ProfitReview, UnitEconomicsSnapshot
from .growth_rail_bridge import DispatchReconciliation, RailDispatchPackage
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_AGENDA_SCHEMA = "lightbulb.growth_agenda.v1"
GROWTH_FUNNEL_DELTA_SCHEMA = "lightbulb.growth_funnel_delta.v2"

_RATE_QUANTUM = Decimal("0.000001")
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MAX_AGENDA_ITEMS = 50
_MAX_AGENDA_DESIGNS = 50
_MAX_AGENDA_READOUTS = 50
_MAX_AGENDA_LEARNINGS = 100
_MAX_AGENDA_PLANS = 10
_MAX_AGENDA_DISPATCHES = 20
_MAX_AGENDA_AUTHORIZATIONS = 200
_MAX_SOURCE_DIGESTS = 8

AgendaItemKind = Literal[
    "readout_due",
    "learning_unrecorded",
    "dispatch_unreconciled",
    "measurement_window_open",
    "snapshot_stale",
    "economics_stale",
    "customer_value_stale",
    "objective_attention",
    "mandate_attention",
    "opportunity",
    "opportunity_blocked",
    "plan_undispatched",
    "learning_expiring",
]

AgendaUrgency = Literal["overdue", "due_now", "upcoming", "informational"]

EvidenceScopeStatus = Literal[
    "caller_supplied_unverified",
    "host_hmac_verified",
]

MovementLabel = Literal["observational_movement_not_attribution"]
Movement = Literal["moved_up", "moved_down", "unchanged", "unknown"]

# The fixed agenda precedence. Documented here and enforced by construction:
# duties that rot (readouts, learnings, receipts, measurement) outrank
# hygiene (staleness), which outranks new work (opportunities), which
# outranks supporting work (dispatch compilation) and information.
AGENDA_PRECEDENCE: tuple[AgendaItemKind, ...] = (
    "readout_due",
    "learning_unrecorded",
    "dispatch_unreconciled",
    "measurement_window_open",
    "snapshot_stale",
    "economics_stale",
    "customer_value_stale",
    "objective_attention",
    "mandate_attention",
    "opportunity",
    "opportunity_blocked",
    "plan_undispatched",
    "learning_expiring",
)

# Workspace-kind coverage contract, asserted by the test suite: every
# workspace artifact kind is either consumed by the agenda or explicitly
# declared exempt with a reason. A new kind that is neither breaks CI
# instead of being silently ignored.
AGENDA_CONSUMED_WORKSPACE_KINDS: frozenset[str] = frozenset(
    {
        "funnel_snapshot",
        "experiment_design",
        "experiment_readout",
        "unit_economics",
        "growth_diagnosis",
        "profit_review",
        "customer_value",
        "customer_value_review",
        "growth_objective",
        "objective_assessment",
        "growth_mandate",
        "action_authorization",
        "content_calendar_plan",
        "audience_growth_plan",
        "rail_dispatch",
        "rail_receipt",
    }
)
AGENDA_EXEMPT_WORKSPACE_KINDS: dict[str, str] = {
    "arm_evidence": "inputs to readouts; surfaced through readout_due items",
    "price_plan": (
        "surfaced through its embedded experiment design and the profit review"
    ),
    "portfolio_rollup": "fleet layer; a portfolio agenda is future work",
    "portfolio_diagnosis": "fleet layer; a portfolio agenda is future work",
    "price_elasticity": "operating input to plans, not an open loop by itself",
    "growth_agenda": "this module's own output",
    "funnel_delta": "this module's own output",
}


class GrowthOperatingValidationError(ValueError):
    """Operating-loop inputs cannot produce an honest agenda or delta."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _render_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


# ---------------------------------------------------------------------------
# Cadence policy (caller-supplied heuristics; deliberately unsealed)
# ---------------------------------------------------------------------------


class GrowthCadencePolicy(_StrictModel):
    """Operating-cadence thresholds. Heuristics, not truths.

    These are the caller's preferences about how fresh evidence should be
    and how many experiments may run at once. They are deliberately NOT
    sealed: no other module enforces them, and a seal on an unenforced
    policy would manufacture the appearance of governance. Every agenda
    item they produce is labeled as heuristic-driven.
    """

    max_snapshot_age_hours: int = Field(default=168, ge=1, le=8_760)
    max_economics_age_hours: int = Field(default=720, ge=1, le=8_760)
    max_customer_value_age_hours: int = Field(default=720, ge=1, le=8_760)
    max_concurrent_experiments: int = Field(default=3, ge=1, le=50)
    learning_expiry_window_hours: int = Field(default=168, ge=1, le=8_760)
    mandate_expiry_warning_hours: int = Field(default=168, ge=1, le=8_760)
    escalation_attention_window_hours: int = Field(default=336, ge=1, le=8_760)


# ---------------------------------------------------------------------------
# Agenda artifacts
# ---------------------------------------------------------------------------


class AgendaItem(_StrictModel):
    """One duty or option, with everything needed to act on it."""

    rank: int = Field(ge=1, le=_MAX_AGENDA_ITEMS)
    kind: AgendaItemKind
    urgency: AgendaUrgency
    title: ShortText
    mechanism: ShortText
    next_primitive_ref: ShortText | None = None
    argument_hints: dict[str, str] = Field(default_factory=dict)
    blocked_by: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=3)
    source_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=_MAX_SOURCE_DIGESTS
    )

    @field_validator("argument_hints", mode="before")
    @classmethod
    def _string_hints(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
        return value

    @field_validator("blocked_by", "source_digests", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _blocked_shape(self) -> "AgendaItem":
        if (self.kind == "opportunity_blocked") != bool(self.blocked_by):
            raise ValueError(
                "blocked_by is required exactly for opportunity_blocked items"
            )
        return self


class GrowthAgenda(_StrictModel):
    """One deterministic answer to "what does this scope need from me now"."""

    schema_id: Literal["lightbulb.growth_agenda.v1"] = Field(
        default=GROWTH_AGENDA_SCHEMA,
        alias="schema",
    )
    as_of: str
    policy: GrowthCadencePolicy
    evidence_scope_status: EvidenceScopeStatus
    items: tuple[AgendaItem, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_ITEMS
    )
    idle: bool
    wake_at: str | None = None
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=20
    )
    agenda_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("wake_at")
    @classmethod
    def _valid_wake_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("items", "data_quality_notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "GrowthAgenda":
        ranks = [item.rank for item in self.items]
        if ranks != sorted(ranks) or len(ranks) != len(set(ranks)):
            raise ValueError("agenda items must carry unique ascending ranks")
        kind_order = [AGENDA_PRECEDENCE.index(item.kind) for item in self.items]
        if kind_order != sorted(kind_order):
            raise ValueError("agenda items must follow the documented precedence")
        if self.idle and any(
            item.urgency in {"overdue", "due_now"} for item in self.items
        ):
            raise ValueError("an idle agenda cannot carry overdue or due items")
        if self.wake_at is not None and (
            _parse_timestamp(self.wake_at) <= _parse_timestamp(self.as_of)
        ):
            raise ValueError("wake_at must lie strictly after as_of")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"agenda_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.agenda_digest != "0" * 64 and self.agenda_digest != expected:
            raise ValueError("agenda_digest does not match the canonical payload")
        object.__setattr__(self, "agenda_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class GrowthAgendaInput(_StrictModel):
    """Everything the agenda may consult, supplied explicitly by the caller.

    The pure function takes artifacts, not a workspace, so the primitive
    projection stays bounded; ``GrowthWorkspace.compile_agenda`` is the
    host-side convenience that gathers verified artifacts and calls this.
    Verification is the caller's job — the agenda echoes the lowest trust
    label found among its inputs and never upgrades it.
    """

    as_of: str
    policy: GrowthCadencePolicy = Field(default_factory=GrowthCadencePolicy)
    designs: tuple[GrowthExperimentDesign, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_DESIGNS
    )
    readouts: tuple[GrowthExperimentReadout, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_READOUTS
    )
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_LEARNINGS
    )
    funnel_snapshot: GrowthFunnelSnapshot | None = None
    unit_economics: UnitEconomicsSnapshot | None = None
    customer_value: CustomerValueSnapshot | None = None
    diagnosis: GrowthDiagnosis | None = None
    profit_review: ProfitReview | None = None
    customer_value_review: CustomerValueReview | None = None
    objective: GrowthObjective | None = None
    objective_assessment: ObjectiveAssessment | None = None
    mandate: GrowthMandate | None = None
    authorizations: tuple[ActionAuthorization, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_AUTHORIZATIONS
    )
    calendar_plans: tuple[ContentCalendarPlan, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_PLANS
    )
    audience_plans: tuple[AudienceGrowthPlan, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_PLANS
    )
    dispatches: tuple[RailDispatchPackage, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_DISPATCHES
    )
    reconciliations: tuple[DispatchReconciliation, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_DISPATCHES
    )
    # Readout digests already banked in the ledger, INCLUDING superseded and
    # expired entries: the recorded-learning duty asks "was it ever banked",
    # so a validity-filtered ledger view must not resurrect it.
    recorded_readout_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=500
    )
    # Reconciliation failures the gatherer hit (defective receipts). Echoed
    # into data_quality_notes so a bad receipt degrades to a visible note and
    # a standing dispatch_unreconciled duty instead of an unrecoverable error.
    reconciliation_errors: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=_MAX_AGENDA_DISPATCHES
    )

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "designs",
        "readouts",
        "learnings",
        "authorizations",
        "calendar_plans",
        "audience_plans",
        "dispatches",
        "reconciliations",
        "recorded_readout_digests",
        "reconciliation_errors",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _coherent_members(self) -> "GrowthAgendaInput":
        design_digests = [design.design_digest for design in self.designs]
        if len(design_digests) != len(set(design_digests)):
            raise ValueError("designs must be unique per design digest")
        readout_designs = [readout.design_digest for readout in self.readouts]
        if len(readout_designs) != len(set(readout_designs)):
            raise ValueError(
                "at most one readout per design; fixed-horizon designs have "
                "exactly one truth"
            )
        known_designs = set(design_digests)
        for readout in self.readouts:
            if readout.design_digest not in known_designs:
                raise ValueError("every readout must accompany its design in the input")
        package_digests = [item.package_digest for item in self.dispatches]
        if len(package_digests) != len(set(package_digests)):
            raise ValueError("dispatch packages must be unique per package digest")
        known_packages = set(package_digests)
        reconciled = [item.package_digest for item in self.reconciliations]
        if len(reconciled) != len(set(reconciled)):
            raise ValueError("at most one reconciliation per dispatch package")
        for digest in reconciled:
            if digest not in known_packages:
                raise ValueError(
                    "every reconciliation must accompany its dispatch package"
                )
        if (
            self.objective_assessment is not None
            and self.objective is not None
            and self.objective_assessment.objective_digest
            != self.objective.objective_digest
        ):
            raise ValueError("the assessment must accompany the objective it assessed")
        if self.mandate is None and self.authorizations:
            raise ValueError(
                "authorizations without their mandate cannot ground an agenda"
            )
        authorization_refs = [
            receipt.authorization_ref for receipt in self.authorizations
        ]
        if len(authorization_refs) != len(set(authorization_refs)):
            raise ValueError(
                "authorizations must be unique per authorization_ref; a "
                "duplicated receipt double-counts window spend"
            )
        if self.mandate is not None:
            for receipt in self.authorizations:
                if receipt.mandate_digest != self.mandate.mandate_digest:
                    raise ValueError(
                        "every authorization must cite the supplied mandate; "
                        "receipts from other mandates belong to their own "
                        "audit trail"
                    )
        scope_digests = {
            artifact.exact_scope_digest
            for artifact in (
                self.funnel_snapshot,
                self.unit_economics,
                self.customer_value,
                self.objective,
                self.mandate,
                *self.authorizations,
                *self.designs,
                *self.readouts,
                *self.learnings,
                *self.calendar_plans,
                *self.audience_plans,
                *self.dispatches,
            )
            if artifact is not None and artifact.exact_scope_digest is not None
        }
        if len(scope_digests) > 1:
            raise ValueError(
                "the supplied artifacts are sealed to different scopes; a "
                "cross-scope agenda is not a thing that can honestly exist"
            )
        return self


# ---------------------------------------------------------------------------
# Agenda compilation
# ---------------------------------------------------------------------------


def _input_trust(
    parsed: GrowthAgendaInput,
    *,
    inputs_verified_by_host: bool,
) -> EvidenceScopeStatus:
    """The lowest trust label the agenda can honestly claim; never upgraded.

    Two hard rules. First, advisory artifacts (diagnosis, profit review)
    carry self-asserted labels with no seal behind them — they can DOWNGRADE
    the join but can never establish "verified"; a forged advisory claiming
    ``host_hmac_verified`` buys nothing. Second, sealed artifacts supplied
    to the pure function may never have been verified at all, so "verified"
    additionally requires ``inputs_verified_by_host`` — the explicit
    assertion the workspace host path makes after HMAC-verifying every
    sealed input. The primitive/MCP path cannot make that assertion, so it
    is always labeled ``caller_supplied_unverified``.
    """

    statuses: list[str] = []
    for artifact in (
        parsed.funnel_snapshot,
        parsed.unit_economics,
        parsed.customer_value,
        parsed.diagnosis,
        parsed.profit_review,
        parsed.customer_value_review,
        parsed.objective_assessment,
        *parsed.calendar_plans,
        *parsed.audience_plans,
        *parsed.dispatches,
    ):
        if artifact is not None:
            statuses.append(artifact.evidence_scope_status)
    if not inputs_verified_by_host:
        return "caller_supplied_unverified"
    if statuses and all(status == "host_hmac_verified" for status in statuses):
        return "host_hmac_verified"
    return "caller_supplied_unverified"


def _in_flight_designs(
    parsed: GrowthAgendaInput,
) -> tuple[GrowthExperimentDesign, ...]:
    read_out = {readout.design_digest for readout in parsed.readouts}
    return tuple(
        design for design in parsed.designs if design.design_digest not in read_out
    )


def _experiment_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for design in sorted(
        _in_flight_designs(parsed), key=lambda item: item.design_digest
    ):
        horizon = _parse_timestamp(design.readout_horizon)
        if as_of_at < horizon:
            continue
        items.append(
            {
                "kind": "readout_due",
                "urgency": "overdue",
                "title": f"Read out experiment {design.design_ref}",
                "mechanism": (
                    f"the preregistered horizon {design.readout_horizon} has "
                    "passed; an unread fixed-horizon experiment is paid-for "
                    "traffic earning zero learnings"
                ),
                "next_primitive_ref": "read_out_growth_experiment",
                "argument_hints": {
                    "design_ref": design.design_ref,
                    "design_digest": design.design_digest,
                    "arm_evidence_window_start": design.exposure_start,
                    "arm_evidence_window_end": design.readout_horizon,
                    "metric_name": design.hypothesis.metric_name,
                },
                "blocked_by": (),
                "source_digests": (design.design_digest,),
                "_order": (design.readout_horizon, design.design_digest),
            }
        )
    return items


def _learning_items(parsed: GrowthAgendaInput) -> list[dict[str, Any]]:
    recorded = {
        entry.readout_digest
        for entry in parsed.learnings
        if entry.readout_digest is not None
    } | set(parsed.recorded_readout_digests)
    designs_by_digest = {design.design_digest: design for design in parsed.designs}
    items: list[dict[str, Any]] = []
    for readout in sorted(parsed.readouts, key=lambda item: item.readout_digest):
        if not readout.causal or readout.readout_digest in recorded:
            continue
        design = designs_by_digest[readout.design_digest]
        items.append(
            {
                "kind": "learning_unrecorded",
                "urgency": "due_now",
                "title": f"Record the learning from {readout.readout_ref}",
                "mechanism": (
                    f"a causal {readout.verdict} readout exists but no "
                    "experimental ledger entry cites it; knowledge bought "
                    "and not banked compounds for no one"
                ),
                "next_primitive_ref": "GrowthLearningsLedger.record_experiment_learning",
                "argument_hints": {
                    "design_digest": design.design_digest,
                    "readout_digest": readout.readout_digest,
                    "metric_name": readout.metric_name,
                },
                "blocked_by": (),
                "source_digests": (design.design_digest, readout.readout_digest),
                "_order": (readout.readout_digest,),
            }
        )
    return items


def _dispatch_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reconciliations = {item.package_digest: item for item in parsed.reconciliations}
    unreconciled: list[dict[str, Any]] = []
    measurement: list[dict[str, Any]] = []
    snapshot = parsed.funnel_snapshot
    for package in sorted(parsed.dispatches, key=lambda item: item.package_digest):
        reconciliation = reconciliations.get(package.package_digest)
        if reconciliation is None or reconciliation.pending_operation_ids:
            pending = (
                reconciliation.pending_operation_ids
                if reconciliation is not None
                else tuple(operation.operation_id for operation in package.operations)
            )
            unreconciled.append(
                {
                    "kind": "dispatch_unreconciled",
                    "urgency": "due_now",
                    "title": f"Reconcile dispatch {package.dispatch_ref}",
                    "mechanism": (
                        f"{len(pending)} of {len(package.operations)} "
                        "dispatched operations have no verified receipt; "
                        "until receipts come home the plan's execution state "
                        "is unknown"
                    ),
                    "next_primitive_ref": "reconcile_dispatch_receipts",
                    "argument_hints": {
                        "dispatch_ref": package.dispatch_ref,
                        "package_digest": package.package_digest,
                        "pending_operation_ids": ", ".join(pending),
                    },
                    "blocked_by": (),
                    "source_digests": (package.package_digest,),
                    "_order": (package.package_digest,),
                }
            )
            continue
        measure_after = reconciliation.measure_after
        assert measure_after is not None  # all_completed structural pairing
        measure_after_at = _parse_timestamp(measure_after)
        if as_of_at <= measure_after_at:
            continue
        # Coverage means the snapshot MEASURED a post-action window, not
        # merely that it was assembled after the action: a routine snapshot
        # built late from an entirely pre-action window proves nothing.
        snapshot_covers = snapshot is not None and any(
            _parse_timestamp(evidence.window_start) > measure_after_at
            for evidence in snapshot.admitted_evidence
        )
        if snapshot_covers:
            continue
        measurement.append(
            {
                "kind": "measurement_window_open",
                "urgency": "due_now",
                "title": f"Measure after dispatch {package.dispatch_ref}",
                "mechanism": (
                    "every dispatched operation completed and no funnel "
                    "snapshot admits evidence from a window opening after "
                    f"{measure_after}; the rail time law requires the "
                    "post-action window to open STRICTLY after that instant"
                ),
                "next_primitive_ref": "growth.build_funnel_snapshot",
                "argument_hints": {
                    "window_start_strictly_after": measure_after,
                    "package_digest": package.package_digest,
                },
                "blocked_by": (),
                "source_digests": (
                    package.package_digest,
                    reconciliation.reconciliation_digest,
                ),
                "_order": (measure_after, package.package_digest),
            }
        )
    return unreconciled, measurement


def _staleness_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> tuple[list[dict[str, Any]], list[str]]:
    items: list[dict[str, Any]] = []
    notes: list[str] = []
    policy = parsed.policy

    snapshot = parsed.funnel_snapshot
    if snapshot is None:
        items.append(
            {
                "kind": "snapshot_stale",
                "urgency": "due_now",
                "title": "Build the first funnel snapshot",
                "mechanism": (
                    "no funnel snapshot was supplied; every growth decision "
                    "for this scope is blind until demand is measured"
                ),
                "next_primitive_ref": "growth.build_funnel_snapshot",
                "argument_hints": {},
                "blocked_by": (),
                "source_digests": (),
                "_order": ("0",),
            }
        )
    else:
        age_hours = (
            as_of_at - _parse_timestamp(snapshot.analysis_as_of)
        ).total_seconds() / 3_600
        # Inclusive at the boundary so an agent waking exactly at wake_at
        # finds the duty due instead of an idle agenda with no next wake.
        if age_hours >= policy.max_snapshot_age_hours:
            items.append(
                {
                    "kind": "snapshot_stale",
                    "urgency": "due_now",
                    "title": "Refresh the funnel snapshot",
                    "mechanism": (
                        f"the latest snapshot is {age_hours:.0f}h old against "
                        f"the {policy.max_snapshot_age_hours}h cadence "
                        "threshold; decisions made on it plan against dead "
                        "data"
                    ),
                    "next_primitive_ref": "growth.build_funnel_snapshot",
                    "argument_hints": {
                        "previous_snapshot_digest": snapshot.funnel_digest,
                    },
                    "blocked_by": (),
                    "source_digests": (snapshot.funnel_digest,),
                    "_order": ("1",),
                }
            )

    economics = parsed.unit_economics
    if economics is not None:
        age_hours = (
            as_of_at - _parse_timestamp(economics.analysis_as_of)
        ).total_seconds() / 3_600
        if age_hours >= policy.max_economics_age_hours:
            items.append(
                {
                    "kind": "economics_stale",
                    "urgency": "due_now",
                    "title": "Refresh unit economics",
                    "mechanism": (
                        f"the unit economics are {age_hours:.0f}h old against "
                        f"the {policy.max_economics_age_hours}h cadence "
                        "threshold; margin-guarded planning needs a current "
                        "ledger"
                    ),
                    "next_primitive_ref": "growth.build_unit_economics",
                    "argument_hints": {
                        "previous_economics_digest": economics.economics_digest,
                    },
                    "blocked_by": (),
                    "source_digests": (economics.economics_digest,),
                    "_order": ("0",),
                }
            )
    customer_value = parsed.customer_value
    if customer_value is None:
        # A never-measured customer base is an opportunity, not an overdue
        # duty: the loop runs without LTV, it just prices acquisition on
        # first-order math and should know it is doing so.
        items.append(
            {
                "kind": "customer_value_stale",
                "urgency": "upcoming",
                "title": "Measure customer value",
                "mechanism": (
                    "no customer value snapshot was supplied; acquisition is "
                    "being priced on first-order math, which is wrong by the "
                    "repeat multiple for any repeat-purchase business"
                ),
                "next_primitive_ref": "growth.build_customer_value",
                "argument_hints": {},
                "blocked_by": (),
                "source_digests": (),
                "_order": ("0",),
            }
        )
    else:
        age_hours = (
            as_of_at - _parse_timestamp(customer_value.analysis_as_of)
        ).total_seconds() / 3_600
        if age_hours >= policy.max_customer_value_age_hours:
            items.append(
                {
                    "kind": "customer_value_stale",
                    "urgency": "due_now",
                    "title": "Refresh customer value",
                    "mechanism": (
                        f"the customer value snapshot is {age_hours:.0f}h old "
                        f"against the {policy.max_customer_value_age_hours}h "
                        "cadence threshold; new cohorts have aged past "
                        "horizons since it was measured"
                    ),
                    "next_primitive_ref": "growth.build_customer_value",
                    "argument_hints": {
                        "previous_value_digest": customer_value.value_digest,
                    },
                    "blocked_by": (),
                    "source_digests": (customer_value.value_digest,),
                    "_order": ("1",),
                }
            )
    if any(
        item["kind"] in {"snapshot_stale", "economics_stale", "customer_value_stale"}
        for item in items
    ):
        notes.append(
            "staleness thresholds come from the caller's cadence policy; "
            "they are operating heuristics, not truths"
        )
    return items, notes


def _objective_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> list[dict[str, Any]]:
    """The governing commitment's demands on this session, if one exists."""

    objective = parsed.objective
    if objective is None:
        return []
    assessment = parsed.objective_assessment
    economics = parsed.unit_economics
    items: list[dict[str, Any]] = []
    target_at = _parse_timestamp(objective.target_by)
    # The deadline itself demands a fresh judgement: an assessment made
    # before target_by cannot speak for the closed window, whatever its
    # verdict was — without this the wake at the deadline finds silence.
    deadline_stale = (
        assessment is not None
        and as_of_at >= target_at
        and _parse_timestamp(assessment.as_of) < target_at
        and assessment.verdict not in {"expired_missed", "achieved"}
    )
    if (
        assessment is None
        or deadline_stale
        or (
            economics is not None
            and assessment.economics_digest != economics.economics_digest
        )
    ):
        if assessment is None:
            mechanism = "a sealed growth objective exists but has no assessment"
        elif deadline_stale:
            mechanism = (
                "the commitment window has closed but the latest assessment "
                "predates the deadline"
            )
        else:
            mechanism = (
                "the objective's latest assessment predates the current unit economics"
            )
        items.append(
            {
                "kind": "objective_attention",
                "urgency": "due_now",
                "title": f"Assess objective {objective.objective_ref}",
                "mechanism": (
                    mechanism + "; the loop cannot steer toward a target it has not "
                    "measured against"
                )[:300].rstrip(),
                "next_primitive_ref": "growth.assess_objective",
                "argument_hints": {
                    "objective_digest": objective.objective_digest,
                },
                "blocked_by": (),
                "source_digests": (objective.objective_digest,),
                "_order": ("0",),
            }
        )
        return items
    if assessment.verdict in {"off_track", "at_risk"}:
        funding = assessment.gap_funding
        if funding is not None:
            funding_note = (
                f"the reviews could fund {funding.funded_expected} of it "
                f"(scenario {funding.funded_low}..{funding.funded_high}); "
                f"unfunded: {funding.shortfall_after_expected}"
            )
        else:
            funding_note = (
                "no reviews were supplied to the assessment; price the gap "
                "with growth.review_profit and growth.review_customer_value"
            )
        items.append(
            {
                "kind": "objective_attention",
                "urgency": "due_now",
                "title": f"Objective {objective.objective_ref} is {assessment.verdict}",
                "mechanism": (
                    f"observed {assessment.observed_per_period} vs glide "
                    f"{assessment.glide_expected_per_period} "
                    f"{assessment.currency}/period; gap "
                    f"{assessment.remaining_gap_per_period}; " + funding_note
                )[:300].rstrip(),
                "next_primitive_ref": None,
                "argument_hints": {
                    "remaining_gap_per_period": str(
                        assessment.remaining_gap_per_period
                    ),
                    "verdict": assessment.verdict,
                },
                "blocked_by": (),
                "source_digests": (
                    objective.objective_digest,
                    assessment.assessment_digest,
                ),
                "_order": ("1",),
            }
        )
    elif assessment.verdict == "expired_missed":
        items.append(
            {
                "kind": "objective_attention",
                "urgency": "due_now",
                "title": f"Objective {objective.objective_ref} expired missed",
                "mechanism": (
                    "the committed window closed short of target; the honest "
                    "next move is a superseding objective naming this one, "
                    "not a quiet re-baseline"
                ),
                "next_primitive_ref": "commit_growth_objective",
                "argument_hints": {
                    "supersedes": objective.objective_digest,
                },
                "blocked_by": (),
                "source_digests": (
                    objective.objective_digest,
                    assessment.assessment_digest,
                ),
                "_order": ("2",),
            }
        )
    elif assessment.verdict == "achieved":
        items.append(
            {
                "kind": "objective_attention",
                "urgency": "informational",
                "title": f"Objective {objective.objective_ref} achieved",
                "mechanism": (
                    "the observed run-rate meets the committed target; "
                    "commit the next objective to keep the loop pointed at "
                    "something"
                ),
                "next_primitive_ref": "commit_growth_objective",
                "argument_hints": {
                    "supersedes": objective.objective_digest,
                },
                "blocked_by": (),
                "source_digests": (
                    objective.objective_digest,
                    assessment.assessment_digest,
                ),
                "_order": ("3",),
            }
        )
    return items


def _mandate_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
    notes: list[str],
) -> list[dict[str, Any]]:
    """What the delegation contract needs: renewal, and answers to escalations."""

    mandate = parsed.mandate
    if mandate is None:
        return []
    items: list[dict[str, Any]] = []
    expires_at = _parse_timestamp(mandate.expires_at)
    warning_at = expires_at - timedelta(
        hours=parsed.policy.mandate_expiry_warning_hours
    )
    if as_of_at >= expires_at:
        items.append(
            {
                "kind": "mandate_attention",
                "urgency": "due_now",
                "title": f"Mandate {mandate.mandate_ref} expired",
                "mechanism": (
                    f"the delegation lapsed at {mandate.expires_at}; nothing "
                    "further can be authorized under it — renewal is the "
                    "human's call (grant_growth_mandate, naming supersedes)"
                )[:300].rstrip(),
                "next_primitive_ref": None,
                "argument_hints": {"supersedes": mandate.mandate_digest},
                "blocked_by": (),
                "source_digests": (mandate.mandate_digest,),
                "_order": ("0",),
            }
        )
    elif as_of_at >= warning_at:
        items.append(
            {
                "kind": "mandate_attention",
                "urgency": "upcoming",
                "title": f"Mandate {mandate.mandate_ref} expires soon",
                "mechanism": (
                    f"the delegation expires at {mandate.expires_at}; "
                    "renewal needs the human before autonomy lapses (the "
                    "warning window is the caller's cadence heuristic)"
                )[:300].rstrip(),
                "next_primitive_ref": None,
                "argument_hints": {"expires_at": mandate.expires_at},
                "blocked_by": (),
                "source_digests": (mandate.mandate_digest,),
                "_order": ("1",),
            }
        )
    # An escalate receipt is a message TO the human; it stays on the agenda
    # until a STRICTLY LATER receipt re-decides the same action or the
    # attention window (a cadence heuristic) lets it age out — visibly, via
    # a note. On a decided_at tie the escalation stays visible: input or
    # storage order must never be able to hide an unanswered ask.
    window_start = as_of_at - timedelta(
        hours=parsed.policy.escalation_attention_window_hours
    )
    by_action: dict[str, list[ActionAuthorization]] = {}
    for receipt in parsed.authorizations:
        if _parse_timestamp(receipt.decided_at) <= as_of_at:
            by_action.setdefault(receipt.action_ref, []).append(receipt)
    pending: list[ActionAuthorization] = []
    aged_out = 0
    for receipts in by_action.values():
        latest_at = max(_parse_timestamp(receipt.decided_at) for receipt in receipts)
        escalates_at_latest = sorted(
            (
                receipt
                for receipt in receipts
                if receipt.verdict == "escalate"
                and _parse_timestamp(receipt.decided_at) == latest_at
            ),
            key=lambda receipt: receipt.authorization_digest,
        )
        if not escalates_at_latest:
            continue
        if latest_at > window_start:
            pending.append(escalates_at_latest[0])
        else:
            aged_out += 1
    if aged_out:
        notes.append(
            f"{aged_out} escalated authorization(s) older than the "
            f"{parsed.policy.escalation_attention_window_hours}h attention "
            "window remain unanswered; they aged off the agenda, not out of "
            "the audit trail"
        )
    if pending:
        pending.sort(
            key=lambda item: (
                _parse_timestamp(item.decided_at),
                item.authorization_digest,
            )
        )
        named = ", ".join(receipt.action_ref for receipt in pending[:3])
        if len(pending) > 3:
            named += f", … ({len(pending) - 3} more)"
        items.append(
            {
                "kind": "mandate_attention",
                "urgency": "due_now",
                "title": f"{len(pending)} escalated action(s) await the human",
                "mechanism": (
                    f"the gate escalated: {named}; each receipt carries its "
                    "reasons — the human approves personally, amends the "
                    "mandate, or declines"
                )[:300].rstrip(),
                "next_primitive_ref": None,
                "argument_hints": {
                    "action_refs": ", ".join(
                        receipt.action_ref for receipt in pending[:8]
                    ),
                },
                "blocked_by": (),
                "source_digests": tuple(
                    receipt.authorization_digest
                    for receipt in pending[:_MAX_SOURCE_DIGESTS]
                ),
                "_order": ("2",),
            }
        )
    return items


def _opportunity_conflict(
    metric_name: str | None,
    in_flight: tuple[GrowthExperimentDesign, ...],
) -> str | None:
    if metric_name is None:
        return None
    for design in in_flight:
        if design.hypothesis.metric_name == metric_name:
            return f"design {design.design_ref} is already in flight on {metric_name}"
    return None


def _newest_readout_after(
    parsed: GrowthAgendaInput,
    metric_name: str | None,
    advice_as_of: datetime,
) -> GrowthExperimentReadout | None:
    if metric_name is None:
        return None
    newest: GrowthExperimentReadout | None = None
    for readout in parsed.readouts:
        if readout.metric_name != metric_name:
            continue
        if _parse_timestamp(readout.analysis_as_of) <= advice_as_of:
            continue
        if newest is None or (
            _parse_timestamp(readout.analysis_as_of)
            > _parse_timestamp(newest.analysis_as_of)
        ):
            newest = readout
    return newest


def _opportunity_items(
    parsed: GrowthAgendaInput,
    notes: list[str],
) -> list[dict[str, Any]]:
    in_flight = _in_flight_designs(parsed)
    concurrency_reached = len(in_flight) >= parsed.policy.max_concurrent_experiments
    items: list[dict[str, Any]] = []
    seen_experiment_metrics: set[str] = set()

    def _echo(
        *,
        title: str,
        mechanism: str,
        next_primitive_ref: str | None,
        hints: Mapping[str, str],
        source_digest: str,
        source_rank: int,
        source_order: str,
        is_experiment: bool,
        metric_name: str | None,
        advice_as_of: datetime,
    ) -> None:
        blocked: list[str] = []
        if is_experiment:
            conflict = _opportunity_conflict(metric_name, in_flight)
            newer = _newest_readout_after(parsed, metric_name, advice_as_of)
            if conflict is not None:
                blocked.append(conflict)
            elif newer is not None:
                blocked.append(
                    f"readout {newer.readout_ref} on {metric_name} postdates "
                    "this advice; re-diagnose with its learning before "
                    "re-proposing"
                )
            elif concurrency_reached:
                blocked.append(
                    "experiment concurrency cap reached "
                    f"({parsed.policy.max_concurrent_experiments} in flight)"
                )
        items.append(
            {
                "kind": "opportunity_blocked" if blocked else "opportunity",
                "urgency": "upcoming",
                "title": title[:300],
                "mechanism": mechanism[:300],
                "next_primitive_ref": next_primitive_ref,
                "argument_hints": dict(hints),
                "blocked_by": tuple(blocked),
                "source_digests": (source_digest,),
                "_order": (source_order, f"{source_rank:04d}"),
            }
        )

    review = parsed.profit_review
    if review is not None:
        review_as_of = _parse_timestamp(review.as_of)
        for opportunity in review.opportunities:
            metric = opportunity.argument_hints.get("metric_name")
            # Every price move ships as a preregistered revenue_per_session
            # experiment, whatever its objective — protect_margin included —
            # so all of them contend for the experiment slots.
            is_experiment = opportunity.kind in {
                "run_experiment",
                "plan_price_move",
            }
            if opportunity.kind == "plan_price_move" and metric is None:
                metric = "revenue_per_session"
            if is_experiment and metric is not None:
                seen_experiment_metrics.add(metric)
            _echo(
                title=opportunity.title,
                mechanism=opportunity.mechanism,
                next_primitive_ref=opportunity.next_primitive_ref,
                hints=opportunity.argument_hints,
                source_digest=review.review_digest,
                source_rank=opportunity.rank,
                source_order="0-profit-review",
                is_experiment=is_experiment,
                metric_name=metric,
                advice_as_of=review_as_of,
            )

    value_review = parsed.customer_value_review
    if value_review is not None:
        review_as_of = _parse_timestamp(value_review.as_of)
        for opportunity in value_review.opportunities:
            metric = opportunity.argument_hints.get("metric_name")
            is_experiment = opportunity.kind == "run_experiment"
            if is_experiment and metric is not None:
                seen_experiment_metrics.add(metric)
            _echo(
                title=opportunity.title,
                mechanism=opportunity.mechanism,
                next_primitive_ref=opportunity.next_primitive_ref,
                hints=opportunity.argument_hints,
                source_digest=value_review.review_digest,
                source_rank=opportunity.rank,
                source_order="1-customer-value-review",
                is_experiment=is_experiment,
                metric_name=metric,
                advice_as_of=review_as_of,
            )

    diagnosis = parsed.diagnosis
    if diagnosis is not None:
        diagnosis_as_of = _parse_timestamp(diagnosis.as_of)
        deduplicated = 0
        for opportunity in diagnosis.opportunities:
            metric = opportunity.argument_hints.get("metric_name")
            is_experiment = opportunity.kind == "run_experiment"
            if (
                is_experiment
                and metric is not None
                and (metric in seen_experiment_metrics)
            ):
                deduplicated += 1
                continue
            _echo(
                title=opportunity.title,
                mechanism=opportunity.mechanism,
                next_primitive_ref=opportunity.next_primitive_ref,
                hints=opportunity.argument_hints,
                source_digest=diagnosis.diagnosis_digest,
                source_rank=opportunity.rank,
                source_order="2-diagnosis",
                is_experiment=is_experiment,
                metric_name=metric,
                advice_as_of=diagnosis_as_of,
            )
        if deduplicated:
            notes.append(
                f"{deduplicated} diagnosis opportunity(ies) duplicated a "
                "money-ranked profit-review opportunity on the same metric "
                "and were cited once, from the review"
            )
    return items


def _lineage_notes(parsed: GrowthAgendaInput, notes: list[str]) -> None:
    """Call out advice that derives from evidence other than the supplied one."""

    if (
        parsed.diagnosis is not None
        and parsed.funnel_snapshot is not None
        and parsed.diagnosis.funnel_digest != parsed.funnel_snapshot.funnel_digest
    ):
        notes.append(
            "the stored diagnosis derives from a different funnel snapshot "
            "than the one supplied; re-diagnose before acting on its "
            "opportunities"
        )
    if (
        parsed.profit_review is not None
        and parsed.unit_economics is not None
        and parsed.profit_review.economics_digest
        != parsed.unit_economics.economics_digest
    ):
        notes.append(
            "the stored profit review derives from different unit economics "
            "than the ones supplied; re-review before acting on its "
            "opportunities"
        )
    if (
        parsed.customer_value_review is not None
        and parsed.customer_value is not None
        and parsed.customer_value_review.value_digest
        != parsed.customer_value.value_digest
    ):
        notes.append(
            "the stored customer value review derives from a different "
            "customer value snapshot than the one supplied; re-review "
            "before acting on its opportunities"
        )


def _plan_items(parsed: GrowthAgendaInput) -> list[dict[str, Any]]:
    dispatched_plan_digests = {
        package.calendar_plan_digest for package in parsed.dispatches
    }
    items: list[dict[str, Any]] = []
    plans: list[tuple[str, str, str]] = [
        ("content calendar", plan.calendar_ref, plan.plan_digest)
        for plan in parsed.calendar_plans
    ] + [
        ("audience growth", plan.plan_ref, plan.plan_digest)
        for plan in parsed.audience_plans
    ]
    for family, ref, digest in sorted(plans, key=lambda entry: entry[2]):
        if digest in dispatched_plan_digests:
            continue
        items.append(
            {
                "kind": "plan_undispatched",
                "urgency": "upcoming",
                "title": f"Author and compile the {family} plan {ref}",
                "mechanism": (
                    "an approved-shape plan exists but no dispatch package "
                    "binds it; nothing ships until items are authored and "
                    "compiled for the rail"
                ),
                "next_primitive_ref": "compile_content_calendar_dispatch"
                if family == "content calendar"
                else "compile_audience_growth_dispatch",
                "argument_hints": {"plan_ref": ref, "plan_digest": digest},
                "blocked_by": (),
                "source_digests": (digest,),
                "_order": (digest,),
            }
        )
    return items


def _expiring_items(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> list[dict[str, Any]]:
    window_end = as_of_at + timedelta(hours=parsed.policy.learning_expiry_window_hours)
    items: list[dict[str, Any]] = []
    for entry in sorted(parsed.learnings, key=lambda item: item.entry_digest):
        if entry.valid_until is None:
            continue
        valid_until_at = _parse_timestamp(entry.valid_until)
        if not as_of_at < valid_until_at <= window_end:
            continue
        items.append(
            {
                "kind": "learning_expiring",
                "urgency": "informational",
                "title": f"Learning {entry.entry_ref} expires {entry.valid_until}",
                "mechanism": (
                    f"the {entry.grade} learning on lever {entry.lever} "
                    "leaves its validity window soon; re-verify it or let "
                    "plans stop citing it"
                ),
                "next_primitive_ref": None,
                "argument_hints": {"entry_digest": entry.entry_digest},
                "blocked_by": (),
                "source_digests": (entry.entry_digest,),
                "_order": (entry.valid_until, entry.entry_digest),
            }
        )
    return items


def _wake_at(
    parsed: GrowthAgendaInput,
    as_of_at: datetime,
) -> str | None:
    candidates: list[datetime] = []
    for design in _in_flight_designs(parsed):
        exposure = _parse_timestamp(design.exposure_start)
        horizon = _parse_timestamp(design.readout_horizon)
        if as_of_at < exposure:
            candidates.append(exposure)
        if as_of_at < horizon:
            candidates.append(horizon)
    if parsed.funnel_snapshot is not None:
        candidates.append(
            _parse_timestamp(parsed.funnel_snapshot.analysis_as_of)
            + timedelta(hours=parsed.policy.max_snapshot_age_hours)
        )
    if parsed.unit_economics is not None:
        candidates.append(
            _parse_timestamp(parsed.unit_economics.analysis_as_of)
            + timedelta(hours=parsed.policy.max_economics_age_hours)
        )
    if parsed.customer_value is not None:
        candidates.append(
            _parse_timestamp(parsed.customer_value.analysis_as_of)
            + timedelta(hours=parsed.policy.max_customer_value_age_hours)
        )
    if parsed.objective is not None:
        candidates.append(_parse_timestamp(parsed.objective.target_by))
    if parsed.mandate is not None:
        expires_at = _parse_timestamp(parsed.mandate.expires_at)
        candidates.append(expires_at)
        candidates.append(
            expires_at - timedelta(hours=parsed.policy.mandate_expiry_warning_hours)
        )
    for entry in parsed.learnings:
        if entry.valid_until is not None:
            candidates.append(_parse_timestamp(entry.valid_until))
    for reconciliation in parsed.reconciliations:
        if reconciliation.measure_after is not None:
            # The post-action window opens STRICTLY after measure_after, so
            # wake one second past it — waking exactly at the instant would
            # find the measurement duty not yet due.
            candidates.append(
                _parse_timestamp(reconciliation.measure_after) + timedelta(seconds=1)
            )
    future = [candidate for candidate in candidates if candidate > as_of_at]
    if not future:
        return None
    return _render_timestamp(min(future))


def compile_growth_agenda(
    inputs: GrowthAgendaInput | Mapping[str, Any],
    *,
    inputs_verified_by_host: bool = False,
) -> GrowthAgenda:
    """Deterministically compile the scope's open loops into one agenda.

    The agenda is a join layer: it cites the stored diagnosis and profit
    review verbatim (their digests travel in ``source_digests``) and adds
    only lifecycle state — due, blocked, pending, stale. It never re-ranks
    an instrument's own output, never invents work, and labels every
    cadence judgement as the caller's heuristic. ``idle=True`` plus
    ``wake_at`` means exactly: nothing needs the agent before that instant.

    ``inputs_verified_by_host`` is the trust assertion: pass ``True`` only
    when every sealed input was HMAC-verified against the scope keyring
    (the :meth:`~lightbulb.growth_workspace.GrowthWorkspace.compile_agenda`
    path does). Without it the agenda is honestly labeled
    ``caller_supplied_unverified``, whatever the inputs claim.
    """

    parsed = (
        inputs
        if isinstance(inputs, GrowthAgendaInput)
        else GrowthAgendaInput.model_validate(inputs)
    )
    as_of_at = _parse_timestamp(parsed.as_of)

    notes: list[str] = list(parsed.reconciliation_errors)
    _lineage_notes(parsed, notes)
    staleness, staleness_notes = _staleness_items(parsed, as_of_at)
    notes.extend(staleness_notes)
    unreconciled, measurement = _dispatch_items(parsed, as_of_at)
    opportunity_items = _opportunity_items(parsed, notes)

    by_kind: dict[str, list[dict[str, Any]]] = {
        "readout_due": _experiment_items(parsed, as_of_at),
        "learning_unrecorded": _learning_items(parsed),
        "dispatch_unreconciled": unreconciled,
        "measurement_window_open": measurement,
        "snapshot_stale": [
            item for item in staleness if item["kind"] == "snapshot_stale"
        ],
        "economics_stale": [
            item for item in staleness if item["kind"] == "economics_stale"
        ],
        "customer_value_stale": [
            item for item in staleness if item["kind"] == "customer_value_stale"
        ],
        "objective_attention": _objective_items(parsed, as_of_at),
        "mandate_attention": _mandate_items(parsed, as_of_at, notes),
        "opportunity": [
            item for item in opportunity_items if item["kind"] == "opportunity"
        ],
        "opportunity_blocked": [
            item for item in opportunity_items if item["kind"] == "opportunity_blocked"
        ],
        "plan_undispatched": _plan_items(parsed),
        "learning_expiring": _expiring_items(parsed, as_of_at),
    }

    ordered: list[dict[str, Any]] = []
    for kind in AGENDA_PRECEDENCE:
        ordered.extend(sorted(by_kind[kind], key=lambda item: item["_order"]))
    if len(ordered) > _MAX_AGENDA_ITEMS:
        notes.append(
            f"agenda truncated to the first {_MAX_AGENDA_ITEMS} items of "
            f"{len(ordered)}; resolve duties to surface the rest"
        )
        ordered = ordered[:_MAX_AGENDA_ITEMS]

    items = tuple(
        AgendaItem(
            rank=rank,
            **{key: value for key, value in body.items() if key != "_order"},
        )
        for rank, body in enumerate(ordered, start=1)
    )
    idle = not any(item.urgency in {"overdue", "due_now"} for item in items)
    return GrowthAgenda(
        as_of=parsed.as_of,
        policy=parsed.policy,
        evidence_scope_status=_input_trust(
            parsed, inputs_verified_by_host=inputs_verified_by_host
        ),
        items=items,
        idle=idle,
        wake_at=_wake_at(parsed, as_of_at),
        data_quality_notes=tuple(notes[:20]),
    )


# ---------------------------------------------------------------------------
# Funnel delta
# ---------------------------------------------------------------------------


class RateDelta(_StrictModel):
    rate_name: ShortText
    previous: Decimal | None = Field(default=None, ge=0, multiple_of=_RATE_QUANTUM)
    current: Decimal | None = Field(default=None, ge=0, multiple_of=_RATE_QUANTUM)
    change: Decimal | None = Field(default=None, multiple_of=_RATE_QUANTUM)
    movement: Movement
    cross_basis: bool
    label: MovementLabel = "observational_movement_not_attribution"

    @field_validator("previous", "current", "change", mode="before")
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return value
        return Decimal(str(value))

    @model_validator(mode="after")
    def _movement_shape(self) -> "RateDelta":
        if (self.previous is None or self.current is None) != (
            self.movement == "unknown"
        ):
            raise ValueError("movement is unknown exactly when a side is missing")
        if self.movement == "unknown":
            if self.change is not None:
                raise ValueError("unknown movement cannot carry a change")
            return self
        expected = self.current - self.previous
        if self.change != expected:
            raise ValueError("change must equal current minus previous")
        expected_movement: Movement = (
            "moved_up"
            if expected > 0
            else "moved_down"
            if expected < 0
            else "unchanged"
        )
        if self.movement != expected_movement:
            raise ValueError("movement does not match the change sign")
        return self


class MetricTotalDelta(_StrictModel):
    metric: ShortText
    basis: ShortText
    previous: Decimal | None = Field(default=None, ge=0)
    current: Decimal | None = Field(default=None, ge=0)
    change: Decimal | None = None
    movement: Movement
    label: MovementLabel = "observational_movement_not_attribution"

    @field_validator("previous", "current", "change", mode="before")
    @classmethod
    def _value_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return value
        return Decimal(str(value))

    @model_validator(mode="after")
    def _movement_shape(self) -> "MetricTotalDelta":
        if (self.previous is None or self.current is None) != (
            self.movement == "unknown"
        ):
            raise ValueError("movement is unknown exactly when a side is missing")
        if self.movement == "unknown":
            if self.change is not None:
                raise ValueError("unknown movement cannot carry a change")
            return self
        expected = self.current - self.previous
        if self.change != expected:
            raise ValueError("change must equal current minus previous")
        expected_movement: Movement = (
            "moved_up"
            if expected > 0
            else "moved_down"
            if expected < 0
            else "unchanged"
        )
        if self.movement != expected_movement:
            raise ValueError("movement does not match the change sign")
        return self


class FunnelDelta(_StrictModel):
    """Observational movement between two funnel snapshots of one scope.

    Structurally incapable of a causal claim: every row carries the
    ``observational_movement_not_attribution`` label, and attribution stays
    the experiment engine's monopoly. Unknown stays unknown.
    """

    schema_id: Literal["lightbulb.growth_funnel_delta.v2"] = Field(
        default=GROWTH_FUNNEL_DELTA_SCHEMA,
        alias="schema",
    )
    previous_digest: Sha256Digest
    current_digest: Sha256Digest
    previous_as_of: str
    current_as_of: str
    currency: CurrencyCode | None = None
    evidence_scope_status: EvidenceScopeStatus
    rate_deltas: tuple[RateDelta, ...] = Field(default_factory=tuple, max_length=10)
    # 17 canonical metrics x 4 bases = 68 possible (metric, basis) rows; the
    # bound holds them all, so truncation is a defensive path that must
    # always leave a data-quality note.
    total_deltas: tuple[MetricTotalDelta, ...] = Field(
        default_factory=tuple, max_length=80
    )
    derived_deltas: tuple[MetricTotalDelta, ...] = Field(
        default_factory=tuple, max_length=4
    )
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=10
    )
    delta_digest: Sha256Digest = "0" * 64

    @field_validator("previous_as_of", "current_as_of")
    @classmethod
    def _valid_timestamps(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "rate_deltas",
        "total_deltas",
        "derived_deltas",
        "data_quality_notes",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "FunnelDelta":
        if _parse_timestamp(self.previous_as_of) >= _parse_timestamp(
            self.current_as_of
        ):
            raise ValueError("the previous snapshot must predate the current one")
        carries_money = any(
            row.metric == "revenue"
            and (row.previous is not None or row.current is not None)
            for row in self.total_deltas
        ) or any(
            row.previous is not None or row.current is not None
            for row in self.derived_deltas
        )
        if carries_money and self.currency is None:
            raise ValueError("monetary funnel deltas require currency")
        if not carries_money and self.currency is not None:
            raise ValueError("count-only funnel deltas must not carry currency")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"delta_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.delta_digest != "0" * 64 and self.delta_digest != expected:
            raise ValueError("delta_digest does not match the canonical payload")
        object.__setattr__(self, "delta_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CompareFunnelSnapshotsInput(_StrictModel):
    previous: GrowthFunnelSnapshot
    current: GrowthFunnelSnapshot


def _snapshot_span(
    snapshot: GrowthFunnelSnapshot,
) -> tuple[datetime, datetime] | None:
    windows = [
        (
            _parse_timestamp(evidence.window_start),
            _parse_timestamp(evidence.window_end),
        )
        for evidence in snapshot.admitted_evidence
    ]
    if not windows:
        return None
    return min(start for start, _ in windows), max(end for _, end in windows)


def compare_funnel_snapshots(
    inputs: CompareFunnelSnapshotsInput | Mapping[str, Any],
) -> FunnelDelta:
    """Honest movement between two snapshots of the same scope.

    Refusals are structural: identical snapshots, a previous snapshot that
    does not predate the current one, or two sealed snapshots bound to
    different scopes. When either snapshot is unsealed the delta cannot
    prove same-scope and says so. Movement is never attribution.
    """

    parsed = (
        inputs
        if isinstance(inputs, CompareFunnelSnapshotsInput)
        else CompareFunnelSnapshotsInput.model_validate(inputs)
    )
    previous = parsed.previous
    current = parsed.current
    if previous.funnel_digest == current.funnel_digest:
        raise GrowthOperatingValidationError(
            "the two snapshots are identical; there is no movement to report"
        )
    if _parse_timestamp(previous.analysis_as_of) >= _parse_timestamp(
        current.analysis_as_of
    ):
        raise GrowthOperatingValidationError(
            "the previous snapshot must predate the current one"
        )
    if (
        previous.currency is not None
        and current.currency is not None
        and previous.currency != current.currency
    ):
        raise GrowthOperatingValidationError(
            "the snapshots carry different revenue currencies; movement cannot "
            "be compared without governed FX evidence"
        )
    delta_currency = current.currency or previous.currency
    notes: list[str] = []
    if (
        previous.exact_scope_digest is not None
        and current.exact_scope_digest is not None
    ):
        if previous.exact_scope_digest != current.exact_scope_digest:
            raise GrowthOperatingValidationError(
                "the snapshots are sealed to different scopes; cross-scope "
                "deltas are not a thing that can honestly exist"
            )
    else:
        notes.append(
            "at least one snapshot is unsealed; same-scope cannot be proven, "
            "only asserted by the caller"
        )
    both_verified = (
        previous.evidence_scope_status == "host_hmac_verified"
        and current.evidence_scope_status == "host_hmac_verified"
    )

    previous_span = _snapshot_span(previous)
    current_span = _snapshot_span(current)
    if previous_span is not None and current_span is not None:
        if current_span[0] < previous_span[1]:
            notes.append(
                "the measurement spans overlap; movement double-counts the "
                "shared window"
            )
        previous_length = (previous_span[1] - previous_span[0]).total_seconds()
        current_length = (current_span[1] - current_span[0]).total_seconds()
        if previous_length <= 0 or current_length <= 0:
            notes.append(
                "a snapshot's measurement span is zero-width; span "
                "comparability cannot be assessed and totals are not "
                "directly comparable"
            )
        else:
            ratio = current_length / previous_length
            if ratio > 1.5 or ratio < (1 / 1.5):
                notes.append(
                    "the measurement spans differ materially in length; "
                    "totals are not directly comparable"
                )

    previous_rates = {rate.rate_name: rate for rate in previous.rates}
    current_rates = {rate.rate_name: rate for rate in current.rates}
    rate_deltas: list[RateDelta] = []
    for rate_name in sorted(set(previous_rates) | set(current_rates)):
        before = previous_rates.get(rate_name)
        after = current_rates.get(rate_name)
        if before is None or after is None:
            rate_deltas.append(
                RateDelta(
                    rate_name=rate_name,
                    previous=before.value if before is not None else None,
                    current=after.value if after is not None else None,
                    movement="unknown",
                    cross_basis=any(
                        rate is not None and rate.cross_basis
                        for rate in (before, after)
                    ),
                )
            )
            continue
        change = after.value - before.value
        rate_deltas.append(
            RateDelta(
                rate_name=rate_name,
                previous=before.value,
                current=after.value,
                change=change,
                movement=(
                    "moved_up"
                    if change > 0
                    else "moved_down"
                    if change < 0
                    else "unchanged"
                ),
                cross_basis=before.cross_basis or after.cross_basis,
            )
        )

    def _totals(snapshot: GrowthFunnelSnapshot) -> dict[tuple[str, str], Decimal]:
        return {
            (total.metric, total.basis): total.value
            for aggregate in snapshot.stages
            for total in aggregate.totals
        }

    previous_totals = _totals(previous)
    current_totals = _totals(current)
    total_deltas: list[MetricTotalDelta] = []
    for key in sorted(set(previous_totals) | set(current_totals)):
        before_value = previous_totals.get(key)
        after_value = current_totals.get(key)
        if before_value is None or after_value is None:
            total_deltas.append(
                MetricTotalDelta(
                    metric=key[0],
                    basis=key[1],
                    previous=before_value,
                    current=after_value,
                    movement="unknown",
                )
            )
            continue
        change = after_value - before_value
        total_deltas.append(
            MetricTotalDelta(
                metric=key[0],
                basis=key[1],
                previous=before_value,
                current=after_value,
                change=change,
                movement=(
                    "moved_up"
                    if change > 0
                    else "moved_down"
                    if change < 0
                    else "unchanged"
                ),
            )
        )

    previous_derived = {item.name: item.value for item in previous.derived_values}
    current_derived = {item.name: item.value for item in current.derived_values}
    derived_deltas: list[MetricTotalDelta] = []
    for name in sorted(set(previous_derived) | set(current_derived)):
        before_value = previous_derived.get(name)
        after_value = current_derived.get(name)
        if before_value is None or after_value is None:
            derived_deltas.append(
                MetricTotalDelta(
                    metric=name,
                    basis="derived",
                    previous=before_value,
                    current=after_value,
                    movement="unknown",
                )
            )
            continue
        change = after_value - before_value
        derived_deltas.append(
            MetricTotalDelta(
                metric=name,
                basis="derived",
                previous=before_value,
                current=after_value,
                change=change,
                movement=(
                    "moved_up"
                    if change > 0
                    else "moved_down"
                    if change < 0
                    else "unchanged"
                ),
            )
        )

    if len(total_deltas) > 80:
        notes.append(
            f"total deltas truncated to the first 80 of {len(total_deltas)} "
            "(metric, basis) rows"
        )
    return FunnelDelta(
        previous_digest=previous.funnel_digest,
        current_digest=current.funnel_digest,
        previous_as_of=previous.analysis_as_of,
        current_as_of=current.analysis_as_of,
        currency=delta_currency,
        evidence_scope_status=(
            "host_hmac_verified" if both_verified else "caller_supplied_unverified"
        ),
        rate_deltas=tuple(rate_deltas),
        total_deltas=tuple(total_deltas[:80]),
        derived_deltas=tuple(derived_deltas),
        data_quality_notes=tuple(notes[:10]),
    )


# ---------------------------------------------------------------------------
# Executable primitives (read-only; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_FUNNEL_EVIDENCE: dict[str, Any] = {
    "observation_ref": "ga-week-a",
    "connector_account_ref": "acct.ga.example",
    "provider": "google_analytics",
    "source_capability": "google_analytics.fetch_metrics",
    "observed_at": "2026-08-11T00:00:00Z",
    "window_start": "2026-08-03T00:00:00Z",
    "window_end": "2026-08-10T00:00:00Z",
    "sample_size": 1000,
    "metrics": {"sessions": 1400, "engagements": 400},
    "evidence_digest": "4" * 64,
}
_EXAMPLE_PREVIOUS_SNAPSHOT: dict[str, Any] = build_growth_funnel_snapshot(
    {
        "analysis_as_of": "2026-08-11T00:00:00Z",
        "snapshot_ref": "snap-week-a",
        "evidence": (_EXAMPLE_FUNNEL_EVIDENCE,),
    }
).to_dict()
_EXAMPLE_CURRENT_SNAPSHOT: dict[str, Any] = build_growth_funnel_snapshot(
    {
        "analysis_as_of": "2026-08-18T00:00:00Z",
        "snapshot_ref": "snap-week-b",
        "evidence": (
            {
                **_EXAMPLE_FUNNEL_EVIDENCE,
                "observation_ref": "ga-week-b",
                "observed_at": "2026-08-18T00:00:00Z",
                "window_start": "2026-08-10T00:00:00Z",
                "window_end": "2026-08-17T00:00:00Z",
                "metrics": {"sessions": 1650, "engagements": 505},
                "evidence_digest": "5" * 64,
            },
        ),
    }
).to_dict()


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The operating loop rejected the inputs.",
        blockers=[
            PrimitiveBlocker(
                code="growth_operating_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class CompileGrowthAgendaPrimitive(
    BusinessProcessPrimitive[GrowthAgendaInput, GrowthAgenda]
):
    """Compile the scope's open loops into one ranked, argument-hinted agenda."""

    primitive_ref = "growth.compile_agenda"
    version = "2.0.0"
    title = "Compile growth agenda"
    description = (
        "Join supplied Growth Engine artifacts (designs, readouts, learnings, "
        "snapshots, economics, diagnosis, profit review, plans, dispatches, "
        "reconciliations) into one deterministic agenda: due readouts, "
        "unrecorded learnings, receipts to reconcile, open measurement "
        "windows, stale evidence, and cited opportunities — with duplicate "
        "experiments blocked, source digests on every item, and idle/wake_at "
        "for schedulers. Advice only; it never re-ranks the instruments it "
        "cites and never dispatches."
    )
    input_model = GrowthAgendaInput
    output_model = GrowthAgenda
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-08-19T00:00:00Z",
        "funnel_snapshot": _EXAMPLE_CURRENT_SNAPSHOT,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: GrowthAgendaInput,
    ) -> PrimitiveExecutionResult[GrowthAgenda]:
        try:
            agenda = compile_growth_agenda(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[GrowthAgenda](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Agenda ready: {len(agenda.items)} items; "
                + ("idle" if agenda.idle else "action needed")
                + (f", wake at {agenda.wake_at}" if agenda.wake_at else "")
                + "."
            ),
            output=agenda,
            events=[
                PrimitiveEvent(
                    type="growth.agenda_compiled",
                    payload={
                        "items": len(agenda.items),
                        "idle": agenda.idle,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Agenda digest "
                    + agenda.agenda_digest[:16]
                    + "… derived from the supplied artifacts only.",
                )
            ],
        )


class CompareFunnelSnapshotsPrimitive(
    BusinessProcessPrimitive[CompareFunnelSnapshotsInput, FunnelDelta]
):
    """Report honest week-over-week movement between two funnel snapshots."""

    primitive_ref = "growth.compare_funnel_snapshots"
    version = "2.0.0"
    title = "Compare funnel snapshots"
    description = (
        "Compute per-rate, per-total, and per-derived-value movement between "
        "two funnel snapshots of one scope. Every delta is labeled "
        "observational movement, never attribution; unknown stays unknown; "
        "cross-scope comparison is refused; overlapping or mismatched "
        "measurement spans are called out."
    )
    input_model = CompareFunnelSnapshotsInput
    output_model = FunnelDelta
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "previous": _EXAMPLE_PREVIOUS_SNAPSHOT,
        "current": _EXAMPLE_CURRENT_SNAPSHOT,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CompareFunnelSnapshotsInput,
    ) -> PrimitiveExecutionResult[FunnelDelta]:
        try:
            delta = compare_funnel_snapshots(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        moved = sum(1 for row in delta.rate_deltas if row.movement != "unchanged")
        return PrimitiveExecutionResult[FunnelDelta](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Delta ready: {moved} of {len(delta.rate_deltas)} rates "
                "moved or lack a side; movement is observational, not "
                "attribution."
            ),
            output=delta,
            events=[
                PrimitiveEvent(
                    type="growth.funnel_delta_computed",
                    payload={
                        "rates": len(delta.rate_deltas),
                        "totals": len(delta.total_deltas),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Delta digest "
                    + delta.delta_digest[:16]
                    + "… binds both snapshot digests.",
                )
            ],
        )


__all__ = [
    "AGENDA_CONSUMED_WORKSPACE_KINDS",
    "AGENDA_EXEMPT_WORKSPACE_KINDS",
    "AGENDA_PRECEDENCE",
    "GROWTH_AGENDA_SCHEMA",
    "GROWTH_FUNNEL_DELTA_SCHEMA",
    "AgendaItem",
    "CompareFunnelSnapshotsInput",
    "CompareFunnelSnapshotsPrimitive",
    "CompileGrowthAgendaPrimitive",
    "FunnelDelta",
    "GrowthAgenda",
    "GrowthAgendaInput",
    "GrowthCadencePolicy",
    "GrowthOperatingValidationError",
    "MetricTotalDelta",
    "RateDelta",
    "compare_funnel_snapshots",
    "compile_growth_agenda",
]
