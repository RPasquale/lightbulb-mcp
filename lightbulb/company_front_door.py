"""The front door: one operator sentence, the planning runs the platform already made, and a launch a person can argue with.

An operator says "start a plumbing company in Brisbane".  Four modules already
know how to answer that; this one is the composition, and the composition is the
product:

* :func:`planning_dispatch_plan` is the half that happens **on the platform**.
  It turns a sealed :class:`~lightbulb.launch_blueprint.OperatorIntent` into the
  exact ordered list of domain-agent dispatches a wrapper (the MCP tool
  ``company_start``, the CLI ``company start --dispatch``) must execute, so the
  harness surface, the console and the CLI cannot drift from each other.  Every
  ``(domain, action)`` pair is a real registry action, every input is derived
  from something the operator declared, and the incorporation dispatch carries
  only the country, the sub-jurisdiction and the proposed name: **directors,
  share structure and the registered office are the director's own facts and are
  never minted**, so that run is expected to answer ``needs_input`` and the
  report lists the slots it asked for.
* :func:`start_company_plan` is the half that happens **in the SDK**.  It seals
  each returned run through :func:`~lightbulb.planning_intake.planning_run_receipt`
  (collecting a :class:`RefusedRun` row, with its code and its missing slots, for
  every run that will not seal - never silently dropping one), compiles the
  admitted receipts and the intent into a
  :class:`~lightbulb.launch_blueprint.LaunchBlueprint` where every field names
  its run or its declarer, and - only when that blueprint carries no blockers -
  compiles and **simulates** a :class:`~lightbulb.launch_plan.LaunchPlan` before
  a dollar moves and renders the :class:`~lightbulb.launch_board.LaunchBoard` of
  a launch that has not started.  The result is a sealed
  :class:`FrontDoorReport` whose ``next_actions`` say who moves next: the
  operator, another platform run, a person acting in the world, or - exactly
  once, and only when there is a plan - the single platform write that comes
  after the report, ``create_company`` under the signed-in tenant admin.

What it hands on: ``FrontDoorReport`` (``lightbulb.company_front_door_report.v1``)
with ``report_digest``, :func:`render_report` markdown, and the
``PlanningDispatch`` rows the wrapper executes verbatim.  It forms nothing,
files nothing, spends nothing and reads no provider: ``executes_nothing`` is a
constant ``True`` on the report, and the first write of any kind is named as an
action for a person, never taken.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.launch_blueprint import (
    LaunchBlueprint,
    OperatorIntent,
    build_intent,
    compile_launch_blueprint,
    render_blueprint,
)
from lightbulb.launch_board import SUPPLY_VERB, LaunchBoard, launch_board, render_board
from lightbulb.launch_plan import LaunchPlan, LaunchPlanError, compile_launch_plan
from lightbulb.planning_intake import (
    PlanningIntake,
    PlanningIntakeError,
    PlanningSource,
    build_intake,
    planning_run_receipt,
)

FRONT_DOOR_SCHEMA = "lightbulb.company_front_door_report.v1"
FRONT_DOOR_GOLDEN_LOOP = "company.idea_to_first_dollar@0.1.0"

MAX_PLANNING_RUNS = 12
MAX_DISPATCH_INPUTS = 16
MAX_ASSUMPTIONS = 5
MAX_MISSING_SLOTS = 12
MAX_NEXT_ACTIONS = 40

# The platform action the operator (not the SDK) takes once the report reads well.
FORMATION_WRITE = "create_company"
# Archetypes whose offers are priced against a market the platform can actually observe.
PRICED_ARCHETYPES: frozenset[str] = frozenset({"dtc_commerce", "marketplace"})
# The paper kinds ``planning_intake`` can seal a packet for; the rest have a platform action
# (``launch_blueprint.PACKET_ACTIONS``) but no receipt, so the front door does not pretend to plan them.
PACKET_SOURCES: Mapping[str, str] = {
    "service_agreement": "legal.service_agreement_packet",
    "employment_agreement": "legal.employment_agreement_packet",
}
# Channels that make an organic content plan worth dispatching, and what it would post to.
SOCIAL_PLATFORMS: tuple[str, ...] = ("instagram", "facebook")

NextActionKind = Literal["operator_input", "platform_run", "human_action", "platform_write"]
# A refusal names the planning source it belongs to, or the compile step that produced it.
RefusalSource = PlanningSource | Literal["launch_plan"]
# Who moves first, and who moves last: the one platform write is always the tail of the list.
_ACTION_ORDER: tuple[str, ...] = ("operator_input", "platform_run", "human_action", "platform_write")
_BLOCKER_RESOLVERS: tuple[str, ...] = tuple(kind for kind in _ACTION_ORDER if kind != "platform_write")

# A run whose facts will not seal is refused under its own code when ``planning_intake`` raised one,
# and under this code when the receipt model refused the shape of what came back.
RUN_NOT_SEALED = "PLANNING_RUN_NOT_SEALED"
# The plan refuses under its own ``LaunchPlanError`` code; this one carries everything else the
# compiler would not take (an operator target or assumption the plan models refuse).
PLAN_NOT_COMPILED = "LAUNCH_PLAN_NOT_COMPILED"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class FrontDoorError(ValueError):
    """The front door was handed something that is not what it says it is; carries a code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise FrontDoorError(code, message)


# --------------------------------------------------------------------------- #
# What the wrapper dispatches on the platform
# --------------------------------------------------------------------------- #


class PlanningDispatch(StrictModel):
    """One domain-agent run the MCP tool or the CLI executes on the platform, derived from the intent."""

    source: PlanningSource
    domain: ShortText
    action: ShortText
    message: BoundedText
    inputs: dict[str, str | bool | int | list | dict] = Field(default_factory=dict)
    optional: bool = False

    @model_validator(mode="after")
    def _guard(self) -> PlanningDispatch:
        if f"{self.domain}.{self.action}" != self.source:
            raise ValueError(f"DISPATCH_SOURCE_MISMATCH: {self.domain}.{self.action} is not {self.source}")
        if len(self.inputs) > MAX_DISPATCH_INPUTS:
            raise ValueError(f"DISPATCH_INPUTS_EXCEEDED: {len(self.inputs)} inputs; a dispatch carries at most {MAX_DISPATCH_INPUTS}")
        return self


def _dispatch(source: str, *, message: str, inputs: Mapping[str, Any] | None = None, optional: bool = False) -> PlanningDispatch:
    domain, action = str(source).split(".", 1)
    return PlanningDispatch.model_validate({
        "source": source,
        "domain": domain,
        "action": action,
        "message": message,
        "inputs": dict(inputs or {}),
        "optional": optional,
    })


def _sealed_intent(value: OperatorIntent | Mapping[str, Any]) -> OperatorIntent:
    """The operator's declaration, sealed; an unsealed mapping is sealed here rather than trusted."""

    if isinstance(value, OperatorIntent):
        return value
    try:
        raw = dict(detached(value))
    except (TypeError, ValueError) as exc:  # pragma: no cover - detached only fails on exotic inputs
        raise FrontDoorError("INTENT_INVALID", f"the supplied intent is not a document: {exc}") from exc
    try:
        if raw.get("intent_digest") in (None, GENESIS_DIGEST):
            return build_intent(raw)
        return OperatorIntent.model_validate(raw)
    except (ValueError, TypeError) as exc:
        raise FrontDoorError("INTENT_INVALID", f"the supplied document is not an operator launch intent: {exc}") from exc


def planning_dispatch_plan(intent: OperatorIntent | Mapping[str, Any]) -> tuple[PlanningDispatch, ...]:
    """The exact planning runs to dispatch for this intent, in order; the wrapper executes them verbatim."""

    declared = _sealed_intent(intent)
    offers = ", ".join(offer.name for offer in declared.offers)
    # Only the go-to-market pair composes a longer brief, because that planner reads the market off
    # the message itself.  Everywhere else the message stays the operator's own sentence.
    brief = f"{declared.idea}. Market: {declared.region}. Archetype {declared.archetype}. Offers: {offers}"
    market = {"target_market": declared.region, "industry": declared.industry}
    rows: list[PlanningDispatch] = [
        _dispatch("gtm.go_to_market_plan", message=brief, inputs=market),
        _dispatch("gtm.market_entry_analysis", message=brief, inputs=market, optional=True),
        _dispatch(
            "crm.icp_intelligence",
            message=declared.idea,
            inputs={"notes": declared.idea, "industry": declared.industry, "region": declared.region_code[:2]},
        ),
    ]

    forecast: dict[str, Any] = {"forecast_type": "revenue", "periods": 12}
    if declared.revenue_per_period_target is not None:
        forecast["revenue_per_period_target"] = str(declared.revenue_per_period_target)
    # A declared target already answers the blueprint's revenue question, so the run is worth making
    # and not worth blocking on; with nothing declared the forecast is the only evidence there is.
    rows.append(_dispatch(
        "finance.finance_forecasting",
        message=declared.idea,
        inputs=forecast,
        optional=declared.revenue_per_period_target is not None,
    ))

    intake: dict[str, Any] = {"country": declared.country, "proposed_names": [declared.name]}
    region_part = declared.region_code.split("-")[-1]
    if region_part != declared.region_code:
        intake["sub_jurisdiction"] = region_part
    # directors, share_structure and registered_office are the director's own facts.  The SDK does not
    # have them and will not invent them, so this run is expected to answer needs_input and the report
    # lists the slots it asked for as an operator_input next action.
    rows.append(_dispatch("legal.incorporation_document_package", message=declared.idea, inputs={"intake": intake}))

    for paper in declared.required_paper:
        source = PACKET_SOURCES.get(paper.kind)
        if source is None:
            continue
        rows.append(_dispatch(
            source,
            message=declared.idea,
            inputs={"document_packet_type": paper.kind, "counterparty_role": paper.counterparty_role},
        ))

    if declared.archetype in PRICED_ARCHETYPES:
        rows.append(_dispatch("product.pricing_intelligence", message=declared.idea, inputs={"industry": declared.industry}, optional=True))

    platforms = list(SOCIAL_PLATFORMS) if "organic_social" in declared.channels else []
    rows.append(_dispatch(
        "content.generate_plan",
        message=declared.idea,
        inputs={"platforms": platforms, "business_description": declared.idea},
        optional=True,
    ))
    return tuple(rows)


# --------------------------------------------------------------------------- #
# What the wrapper hands back
# --------------------------------------------------------------------------- #


class _PlatformDocument(BaseModel):
    """The platform's own JSON, in transit.

    Deliberately **not** a ``StrictModel``: a workflow instance carries the tenant,
    company and user ids the platform filed the run under, and the strict guard
    would refuse every real run.  Nothing on this model is ever sealed.  The only
    path from here into the report runs through ``planning_run_receipt``, whose
    per-source whitelist copies no identifier, no payload and no document body.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class PlanningRunDocument(_PlatformDocument):
    """One dispatched planning run as the wrapper fetched it: ``DispatchResult.raw`` and its instance."""

    source: PlanningSource
    dispatch: dict
    instance: dict | None = None


class RefusedRun(StrictModel):
    """A run that would not seal, with the code that refused it and the slots it asked for."""

    source: RefusalSource
    code: ShortText
    detail: BoundedText
    missing_slots: tuple[ShortText, ...] = Field(default=(), max_length=MAX_MISSING_SLOTS)

    @field_validator("missing_slots", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class FrontDoorRequest(_PlatformDocument):
    """What the wrapper hands the SDK: the sealed intent, the runs it made, and the operator's targets."""

    intent: OperatorIntent
    planning_runs: tuple[PlanningRunDocument, ...] = Field(default=(), max_length=MAX_PLANNING_RUNS)
    targets: dict | None = None
    assumptions: tuple[dict, ...] = Field(default=(), max_length=MAX_ASSUMPTIONS)
    now: str

    @field_validator("intent", mode="before")
    @classmethod
    def _seal(cls, value: Any) -> Any:
        return _sealed_intent(value) if not isinstance(value, OperatorIntent) else value

    @field_validator("now")
    @classmethod
    def _when(cls, value: str) -> str:
        return timestamp(value, field_name="now")

    @model_validator(mode="after")
    def _guard(self) -> FrontDoorRequest:
        sources = [row.source for row in self.planning_runs]
        if len(set(sources)) != len(sources):
            raise ValueError(f"PLANNING_RUN_DUPLICATE: one run per planning source; got {sorted(sources)}")
        return self


class NextAction(StrictModel):
    """One thing that has to happen next, and who does it."""

    kind: NextActionKind
    detail: BoundedText
    platform_action: ShortText | None = None


class FrontDoorReport(StrictModel):
    """The whole front door, sealed: what was admitted, what was refused, the blueprint, the plan, the board, the next moves."""

    schema_id: Literal["lightbulb.company_front_door_report.v1"] = Field(default=FRONT_DOOR_SCHEMA, alias="schema")
    intent_digest: Sha256Digest
    intake_digest: Sha256Digest | None = None
    admitted_sources: tuple[PlanningSource, ...] = Field(default=(), max_length=MAX_PLANNING_RUNS)
    refused_runs: tuple[RefusedRun, ...] = Field(default=(), max_length=MAX_PLANNING_RUNS)
    blueprint: LaunchBlueprint
    launch_plan: LaunchPlan | None = None
    launch_plan_refusal: RefusedRun | None = None
    board: LaunchBoard | None = None
    next_actions: tuple[NextAction, ...] = Field(default=(), max_length=MAX_NEXT_ACTIONS)
    executes_nothing: Literal[True] = True
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("admitted_sources", "refused_runs", "next_actions", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FrontDoorReport:
        if self.launch_plan is not None and self.launch_plan_refusal is not None:
            raise ValueError("a report carries either a launch plan or the refusal that stopped it, never both")
        if self.launch_plan is not None and self.launch_plan.blueprint_digest != self.blueprint.blueprint_digest:
            raise ValueError("the launch plan must be the one this blueprint compiled")
        if self.board is not None and self.launch_plan is None:
            raise ValueError("a board reads a launch plan; there is none")
        # The board names the plan it read in ``source_digests``; a board rendered from any other
        # plan is a different company's critical path and never rides in this report.
        if self.board is not None and self.board.source_digests.get("plan") != self.launch_plan.plan_digest:
            raise ValueError("the board must be the one this launch plan rendered")
        # The blueprint already commits the declaration and the intake it compiled from; the report
        # may only repeat them, never name a different operator declaration or a different intake.
        if self.intent_digest != self.blueprint.intent_digest:
            raise ValueError("intent_digest must be the declaration this blueprint compiled from")
        if self.intake_digest != self.blueprint.intake_digest:
            raise ValueError("intake_digest must be the intake this blueprint compiled from")
        both = set(self.admitted_sources) & {row.source for row in self.refused_runs}
        if both:
            raise ValueError(f"a planning run is admitted or refused, never both; got {sorted(both)}")
        if not self.blueprint.ready_to_plan and (self.launch_plan is not None or self.launch_plan_refusal is not None):
            raise ValueError("a blueprint that carries blockers never reached the simulation, so nothing planned or refused it")
        writes = [row for row in self.next_actions if row.kind == "platform_write"]
        if len(writes) > 1:
            raise ValueError("the front door names exactly one platform write, or none")
        if writes and self.launch_plan is None:
            raise ValueError("the platform write is only named once there is a plan behind it")
        if self.launch_plan is not None and not writes:
            raise ValueError("a sealed plan owes the operator the one write that follows it")
        if writes and writes[0].platform_action != FORMATION_WRITE:
            raise ValueError(f"the one write the front door names is {FORMATION_WRITE}, not {writes[0].platform_action!r}")
        if not skip_digests(info) and self.report_digest != sealed_digest(FrontDoorReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def refusal(self, source: str) -> RefusedRun | None:
        return next((item for item in self.refused_runs if item.source == source), None)

    def actions_of(self, kind: str) -> tuple[NextAction, ...]:
        return tuple(item for item in self.next_actions if item.kind == kind)

    @property
    def refused_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.refused_runs)

    @property
    def ready_to_plan(self) -> bool:
        return self.launch_plan is not None


# --------------------------------------------------------------------------- #
# Sealing the runs
# --------------------------------------------------------------------------- #


def _outputs(run: PlanningRunDocument) -> Mapping[str, Any]:
    """The outputs ``planning_intake`` reads, on the same instance-then-dispatch precedence."""

    instance = run.instance if isinstance(run.instance, Mapping) else {}
    outputs = instance.get("outputs")
    if not isinstance(outputs, Mapping) or not outputs:
        outputs = run.dispatch.get("outputs") if isinstance(run.dispatch, Mapping) else None
    return outputs if isinstance(outputs, Mapping) else {}


def _missing_slots(run: PlanningRunDocument) -> tuple[str, ...]:
    """The slots the run said it needs, verbatim; the SDK never fills one in."""

    raw = _outputs(run).get("missing_slots")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return ()
    slots: list[str] = []
    for item in raw:
        text = str(item).strip()[:300]
        if text and text not in slots:
            slots.append(text)
        if len(slots) >= MAX_MISSING_SLOTS:
            break
    return tuple(slots)


def _uncoded_detail(error: ValueError) -> str:
    """What an uncoded refusal may say: which field was refused and why, never the value supplied.

    ``str()`` on a pydantic error echoes ``input_value=`` - the operator's own targets, or the
    platform's own outputs - straight back out, and that string would then be sealed into the
    report.  The field paths and the messages say the same thing and carry nothing of the payload.
    """

    errors = getattr(error, "errors", None)
    if not callable(errors):
        return str(error)
    try:
        rows = list(errors())
    except TypeError:  # pragma: no cover - only a non-pydantic object exposing errors()
        return str(error)
    named = [f"{'.'.join(str(part) for part in row.get('loc', ())) or 'input'}: {row.get('msg', '')}" for row in rows[:6]]
    more = f" (+{len(rows) - 6} more)" if len(rows) > 6 else ""
    return f"{len(rows)} field(s) refused - {'; '.join(named)}{more}"


def _refusal(source: str, code: str, detail: str, slots: Sequence[str] = ()) -> RefusedRun:
    """A refusal row, or - if the message itself will not pass the boundary guard - the code alone.

    ``RefusedRun`` is a ``StrictModel``, so a compiler message that quotes a card-like or
    secret-like value out of the platform's own JSON is refused rather than sealed.  A refusal that
    cannot carry its message still has to be listed, so the row is kept and the message is not.
    """

    payload = {"source": source, "code": code, "detail": detail[:4000] or code, "missing_slots": tuple(slots)}
    unsayable = f"{code}: the refusal message could not be carried across the boundary"
    # A row is owed for every run that would not seal, so each fallback drops one more thing the
    # boundary guard would refuse rather than letting the refusal itself take the report down.
    for attempt in (payload, {**payload, "detail": unsayable}):
        try:
            return RefusedRun.model_validate(attempt)
        except ValueError:
            continue
    # The slots are the platform's own words; if one of them is what the guard refuses, the row
    # survives without them - the code still says the run asked for something it did not get.
    return RefusedRun.model_validate({"source": source, "code": code, "detail": unsayable})


def planning_run_refusal(run: PlanningRunDocument, error: ValueError) -> RefusedRun:
    """Why one run did not seal, as a row the report carries instead of dropping it."""

    code = getattr(error, "code", None)
    detail = str(error) if code is not None else _uncoded_detail(error)
    slots = _missing_slots(run) if code == "PLANNING_RUN_NEEDS_INPUT" else ()
    return _refusal(run.source, code or RUN_NOT_SEALED, detail, slots)


def _request(value: FrontDoorRequest | Mapping[str, Any]) -> FrontDoorRequest:
    if isinstance(value, FrontDoorRequest):
        return value
    _require(isinstance(value, Mapping), "FRONT_DOOR_REQUEST_INVALID", f"a front door request is a mapping; got {type(value).__name__}")
    try:
        # Sealed here as well as in the field validator, so an operator who mistyped the declaration
        # is told INTENT_INVALID rather than being handed the whole request's validation error.
        # A request with no intent at all is the request's own problem, not the intent's.
        if "intent" in value:
            _sealed_intent(value["intent"])
        return FrontDoorRequest.model_validate(dict(value))
    except FrontDoorError:
        raise
    except (ValueError, TypeError) as exc:
        raise FrontDoorError("FRONT_DOOR_REQUEST_INVALID", f"the supplied document is not a front door request: {exc}") from exc


def _next_actions(
    blueprint: LaunchBlueprint,
    refused: Sequence[RefusedRun],
    *,
    intent: OperatorIntent,
    planned: bool,
    plan_refusal: RefusedRun | None,
) -> list[dict[str, Any]]:
    """Every move that is still owed, grouped by who owns it; the one write comes last."""

    rows: list[dict[str, Any]] = []
    for resolver in _BLOCKER_RESOLVERS:
        for blocker in blueprint.blockers:
            if blocker.resolves_by != resolver:
                continue
            rows.append({"kind": resolver, "detail": f"{blocker.code}: {blocker.detail}"[:4000], "platform_action": blocker.platform_action})
        if resolver != "platform_run":
            continue
        for row in refused:
            slots = f"; it asked for {', '.join(row.missing_slots)}" if row.missing_slots else ""
            rows.append({
                "kind": "platform_run",
                "detail": f"re-dispatch {row.source}: {row.code}{slots}"[:4000],
                "platform_action": row.source,
            })
    if plan_refusal is not None:
        rows.append({
            "kind": "operator_input",
            "detail": f"the simulation refused the plan ({plan_refusal.code}): {plan_refusal.detail}"[:4000],
            "platform_action": None,
        })
    # The one write is held out of the truncation below and appended last, so a long list of
    # blockers can never be what makes the report forget the operator's own next move.
    write = [{
        "kind": "platform_write",
        "detail": (
            f"{FORMATION_WRITE}(name={intent.name}, country={intent.country}) through the signed-in tenant admin; "
            f"then {SUPPLY_VERB} form with the formation receipt"
        )[:4000],
        "platform_action": FORMATION_WRITE,
    }] if planned else []

    room = MAX_NEXT_ACTIONS - len(write)
    if len(rows) <= room:
        return rows + write
    # Nothing owed is dropped in silence: the last slot before the write says how many rows did
    # not fit, and the blueprint render carries them all.
    dropped = len(rows) - (room - 1)
    overflow = {
        "kind": "operator_input",
        "detail": f"{dropped} further action(s) are owed and did not fit this list; read the blueprint's own blockers and the refused runs",
        "platform_action": None,
    }
    return rows[: room - 1] + [overflow] + write


def start_company_plan(request: FrontDoorRequest | Mapping[str, Any]) -> FrontDoorReport:
    """Seal the planning runs, compile the blueprint, simulate the plan, render the board; execute nothing."""

    parsed = _request(request)
    intent, now = parsed.intent, parsed.now

    receipts = []
    refused: list[RefusedRun] = []
    for run in parsed.planning_runs:
        try:
            receipts.append(planning_run_receipt(run.source, run.dispatch, run.instance, now=now))
        except PlanningIntakeError as exc:
            refused.append(planning_run_refusal(run, exc))
        except ValueError as exc:
            # ``planning_intake`` raises its coded error for the gates it checks itself, but the
            # receipt model refuses shapes it cannot describe (a fact too long, a ref that is not
            # opaque) with a plain validation error.  That run is still a run that would not seal,
            # so it is listed under RUN_NOT_SEALED rather than taking the whole report down.
            refused.append(planning_run_refusal(run, exc))

    intake: PlanningIntake | None = build_intake(receipts, sealed_at=now) if receipts else None
    blueprint = compile_launch_blueprint(intent, intake, compiled_at=now)

    plan: LaunchPlan | None = None
    plan_refusal: RefusedRun | None = None
    if blueprint.ready_to_plan:
        try:
            # The intent is passed because the blueprint holds no cash: ``_launch_cash`` reads the
            # opening cash and the fixed costs off the sealed intent the blueprint compiled from.
            plan = compile_launch_plan(
                blueprint,
                intent,
                planned_at=now,
                targets=parsed.targets,
                assumptions=parsed.assumptions,
            )
        except LaunchPlanError as exc:
            plan_refusal = _refusal("launch_plan", exc.code, str(exc))
        except ValueError as exc:
            # Operator targets and assumptions are the two things on the request the operator types
            # rather than derives, so the models behind them refuse with a plain validation error.
            # That is still the simulation declining to plan, and it reads as one.
            plan_refusal = _refusal("launch_plan", PLAN_NOT_COMPILED, _uncoded_detail(exc))

    board = launch_board(plan, None, now=now, blueprint_blockers=[item.code for item in blueprint.blockers]) if plan is not None else None
    actions = _next_actions(blueprint, refused, intent=intent, planned=plan is not None, plan_refusal=plan_refusal)

    payload: dict[str, Any] = {
        "intent_digest": intent.intent_digest,
        "intake_digest": intake.intake_digest if intake is not None else None,
        "admitted_sources": [receipt.source for receipt in receipts],
        "refused_runs": [row.to_dict() for row in refused],
        "blueprint": blueprint.to_dict(),
        "launch_plan": plan.to_dict() if plan is not None else None,
        "launch_plan_refusal": plan_refusal.to_dict() if plan_refusal is not None else None,
        "board": board.to_dict() if board is not None else None,
        "next_actions": actions,
    }
    return seal(FrontDoorReport, {key: value for key, value in payload.items() if value is not None}, "report_digest")


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _report(value: FrontDoorReport | Mapping[str, Any]) -> FrontDoorReport:
    if isinstance(value, FrontDoorReport):
        return value
    try:
        return FrontDoorReport.model_validate(dict(detached(value)))
    except (ValueError, TypeError) as exc:
        raise FrontDoorError("FRONT_DOOR_REPORT_INVALID", f"the supplied document is not a sealed front door report: {exc}") from exc


def _simulation_lines(report: FrontDoorReport) -> list[str]:
    lines = ["## Simulation"]
    if report.launch_plan is not None:
        sim = report.launch_plan.simulation
        first = sim.first_revenue_period if sim.first_revenue_period is not None else "never"
        lines.append(
            f"- {sim.periods_run} period(s) simulated; min cash {sim.min_cash} {report.launch_plan.currency} "
            f"against a floor of {report.launch_plan.targets.cash_floor}; first revenue in period {first}; "
            f"synthetic={sim.synthetic}"
        )
    elif report.launch_plan_refusal is not None:
        lines.append(f"- refused before any spend: {report.launch_plan_refusal.code}: {report.launch_plan_refusal.detail}")
    else:
        lines.append("- not simulated: the blueprint is not ready to plan")
    return lines


def render_report(report: FrontDoorReport | Mapping[str, Any]) -> str:
    """Markdown a person can argue with: the blueprint, the simulation, the board, and what happens next."""

    parsed = _report(report)
    lines = [render_blueprint(parsed.blueprint), ""]
    if parsed.refused_runs:
        lines.append("## Refused planning runs")
        for row in parsed.refused_runs:
            slots = f" (missing: {', '.join(row.missing_slots)})" if row.missing_slots else ""
            lines.append(f"- {row.source}: {row.code}{slots}")
        lines.append("")
    lines.extend(_simulation_lines(parsed))
    lines.append("")
    if parsed.board is not None:
        lines.extend([render_board(parsed.board).rstrip(), ""])
    lines.append("## Next actions")
    if parsed.next_actions:
        for action in parsed.next_actions:
            named = f" [{action.platform_action}]" if action.platform_action else ""
            lines.append(f"- ({action.kind}){named} {action.detail}")
    else:
        lines.append("- nothing is owed; the blueprint is ready and the plan is sealed")
    lines.extend(["", f"executes nothing; report {parsed.report_digest[:16]}"])
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# The manifest
# --------------------------------------------------------------------------- #

# A documentation example only: it is not an operator declaration and nothing compiles from it.
# It exists so the manifest can say which planning runs a typical services-firm intent dispatches.
MANIFEST_EXAMPLE_INTENT: dict[str, Any] = {
    "declared_by_ref": "actor-operator",
    "declared_at": "2026-10-01T00:00:00Z",
    "idea": "start a plumbing company in Brisbane",
    "name": "Example Plumbing",
    "archetype": "services_firm",
    "country": "AU",
    "region": "Brisbane, QLD",
    "region_code": "AU-QLD",
    "currency": "AUD",
    "trade": "plumbing",
    "industry": "Plumbing services",
    "purpose": "Residential plumbing with governed booking and invoicing.",
    "offers": [{"name": "call-out", "unit": "hour", "price": "140", "cost_of_delivery": "55", "currency": "AUD"}],
    "channels": ["paid_search_google", "organic_social"],
    "operating_budget_per_period": "4000",
    "period_days": 14,
    "starting_cash": "60000",
    "fixed_costs_per_period": "1200",
    "required_paper": [
        {"kind": "incorporation", "counterparty_role": "registrar", "required_before": "formation"},
        {"kind": "service_agreement", "counterparty_role": "customer", "required_before": "first_job"},
        {"kind": "employment_agreement", "counterparty_role": "apprentice", "required_before": "first_hire"},
    ],
}


FRONT_DOOR_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_front_door",
    "golden_loop": FRONT_DOOR_GOLDEN_LOOP,
    "stages": [
        "declare_intent",
        "dispatch_planning_on_platform",
        "seal_intake",
        "compile_blueprint",
        "simulate_before_spend",
        "compile_launch_plan",
        "render_board",
        "hand_to_operator",
    ],
    "dispatches": [row.source for row in planning_dispatch_plan(MANIFEST_EXAMPLE_INTENT)],
    "required_connectors": ["lightbulb.domain_agents", "lightbulb.workflow_instances", "lightbulb.account"],
    "hard_rules": [
        "the front door returns a blueprint, a simulation and a board; it forms nothing and spends nothing",
        "planning runs are dispatched by the MCP or CLI wrapper on the platform and fetched by trace; the SDK seals what came back",
        "refused runs are listed with their codes and missing slots, never silently dropped",
        "the first platform write after the report is create_company under the signed-in tenant admin, named as the next action",
    ],
}


__all__ = [
    "FORMATION_WRITE",
    "FRONT_DOOR_GOLDEN_LOOP",
    "FRONT_DOOR_MANIFEST",
    "FRONT_DOOR_SCHEMA",
    "MANIFEST_EXAMPLE_INTENT",
    "MAX_ASSUMPTIONS",
    "MAX_DISPATCH_INPUTS",
    "MAX_MISSING_SLOTS",
    "MAX_NEXT_ACTIONS",
    "MAX_PLANNING_RUNS",
    "PACKET_SOURCES",
    "PLAN_NOT_COMPILED",
    "PRICED_ARCHETYPES",
    "RUN_NOT_SEALED",
    "SOCIAL_PLATFORMS",
    "FrontDoorError",
    "FrontDoorReport",
    "FrontDoorRequest",
    "NextAction",
    "NextActionKind",
    "PlanningDispatch",
    "PlanningRunDocument",
    "RefusalSource",
    "RefusedRun",
    "planning_dispatch_plan",
    "planning_run_refusal",
    "render_report",
    "start_company_plan",
]
