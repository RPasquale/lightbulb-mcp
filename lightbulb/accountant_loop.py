"""The AI accountant's operating loop: one routine over the whole layer.

The cash, ingestion, allocation, and grant modules are the accountant's tools;
this is the accountant *doing the job*. Given the period's cash evidence (and,
optionally, the growth objective and a company profile) it runs one cycle —
measure runway, size the budget, judge health, gate growth spend, and surface
non-dilutive capital — and emits a single prioritized agenda.

The ordering is the whole point, and it is not negotiable: **survival outranks
growth.** An unknown runway means "measure first"; a runway below its floor
means "cut burn and raise capital" before anything discretionary; only once the
floor is safe does growth spend get a hearing. Non-dilutive grants are surfaced
exactly when they matter most — when runway is tight — because they extend
runway without giving away equity.

This module composes the other modules and adds no new trust: it runs the
honest-but-unverified path (the host seals the underlying snapshot if it wants a
verified one), invents no numbers, and every action it emits traces to a digest
of the artifact that justified it. Advisory, deliberately unsealed — a seal on
an unenforced agenda would manufacture the appearance of governance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

from .business_allocation import ObjectiveFundingGate, gate_objective_funding
from .cash_forecast import (
    CashFlowForecast,
    ScheduledCashEvent,
    build_cash_flow_forecast,
)
from .cash_payables import PayablesAssessment
from .cash_receivables import ReceivablesAssessment
from .cash_runway import (
    CashLedgerEvidence,
    CashStalenessPolicy,
    assess_runway,
    build_runway_snapshot,
    derive_budget_envelope,
)
from .fundraise_readiness import DefaultAliveAssessment
from .grant_discovery import CompanyGrantProfile, match_grant_programs
from .growth_objectives import ObjectiveAssessment
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)
from .tax_provision import TaxProvision

ACCOUNTANT_AGENDA_SCHEMA = "lightbulb.accountant_agenda.v2"

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

AccountantActionKind = Literal[
    "collect_evidence",
    "reduce_burn",
    "raise_capital",
    "collect_receivables",
    "settle_payables",
    "pursue_grants",
    "reserve_tax",
    "defer_growth_spend",
    "deploy_growth",
    "review_grants",
    "hold",
]

AccountantSeverity = Literal["healthy", "caution", "danger", "unknown"]


class AccountantLoopValidationError(ValueError):
    """The cycle inputs cannot produce an honest agenda."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
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
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _normalized_timestamp(value: str) -> str:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _decimal(value: Any) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    return parsed


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class AccountantAction(_StrictModel):
    """One ranked next action, traceable to the artifact that justified it."""

    rank: int = Field(ge=1, le=50)
    kind: AccountantActionKind
    title: ShortText
    rationale: ShortText
    source_digest: Sha256Digest


class AccountantAgenda(_StrictModel):
    """One accountant cycle: the financial state and the ranked next actions."""

    schema_id: Literal["lightbulb.accountant_agenda.v2"] = Field(
        default=ACCOUNTANT_AGENDA_SCHEMA,
        alias="schema",
    )
    cycle_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    runway_status: Literal["burning", "not_burning", "unknown"]
    runway_months: Decimal | None = None
    budget_status: Literal[
        "healthy_surplus", "at_floor", "below_floor", "not_burning", "unknown"
    ]
    severity: AccountantSeverity
    runway_digest: Sha256Digest
    assessment_digest: Sha256Digest
    funding_gate_verdict: (
        Literal["deploy_permitted", "hold_at_floor", "defer_protect_runway", "unknown"]
        | None
    ) = None
    funding_gate_digest: Sha256Digest | None = None
    grant_matches: int | None = None
    grant_match_digest: Sha256Digest | None = None
    default_alive_verdict: (
        Literal["already_profitable", "default_alive", "default_dead"] | None
    ) = None
    default_alive_digest: Sha256Digest | None = None
    tax_set_aside: Decimal | None = None
    spendable_cash_net_of_tax: Decimal | None = None
    tax_provision_digest: Sha256Digest | None = None
    receivables_outstanding: Decimal | None = None
    receivables_overdue: Decimal | None = None
    receivables_dso_days: Decimal | None = None
    collections_within_horizon: Decimal | None = None
    receivables_digest: Sha256Digest | None = None
    payables_outstanding: Decimal | None = None
    payables_overdue: Decimal | None = None
    payables_dpo_days: Decimal | None = None
    payables_are_floor: bool | None = None
    payments_within_horizon: Decimal | None = None
    payables_digest: Sha256Digest | None = None
    forecast_horizon_weeks: int | None = None
    forecast_closing_cash: Decimal | None = None
    forecast_lowest_cash: Decimal | None = None
    forecast_first_negative_week: int | None = None
    forecast_reliability: (
        Literal["projection", "optimistic_ceiling"] | None
    ) = None
    forecast_digest: Sha256Digest | None = None
    actions: tuple[AccountantAction, ...] = Field(default_factory=tuple)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    agenda_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("actions", "notes", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class AccountantCycleInput(_StrictModel):
    cycle_ref: PortableRef
    as_of: str
    currency: CurrencyCode
    cash_evidence: tuple[CashLedgerEvidence, ...] = Field(min_length=1, max_length=200)
    runway_floor_months: Decimal = Field(default=Decimal("12"), gt=0, le=Decimal("120"))
    caution_threshold_months: Decimal = Field(
        default=Decimal("18"), gt=0, le=Decimal("120")
    )
    cash_on_hand_override: Decimal | None = None
    staleness_policy: CashStalenessPolicy = Field(default_factory=CashStalenessPolicy)
    grant_profile: CompanyGrantProfile | None = None
    objective_assessment: ObjectiveAssessment | None = None
    tax_provision: TaxProvision | None = None
    default_alive: DefaultAliveAssessment | None = None
    receivables: ReceivablesAssessment | None = None
    payables: PayablesAssessment | None = None
    # When forecast_weeks is set, the cycle also builds a 13-week-style cash-flow
    # forecast: opening cash from the runway snapshot, plus these scheduled
    # events, plus an optional operating run-rate, plus AR's expected collections
    # (auto-fed as inflows). Left unset, no forecast is built.
    forecast_weeks: int | None = Field(default=None, ge=1, le=52)
    scheduled_cash_events: tuple[ScheduledCashEvent, ...] = Field(
        default_factory=tuple, max_length=500
    )
    assumed_weekly_operating_outflow: Decimal | None = None
    scheduled_events_complete: bool = False

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("runway_floor_months", "caution_threshold_months", mode="before")
    @classmethod
    def _floor_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator(
        "cash_on_hand_override", "assumed_weekly_operating_outflow", mode="before"
    )
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value)

    @field_validator("cash_evidence", "scheduled_cash_events", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)


def run_accountant_cycle(
    inputs: AccountantCycleInput | Mapping[str, Any],
) -> AccountantAgenda:
    """Run one accountant cycle and emit its prioritized agenda.

    Composes runway → budget → assessment (always), the funding gate (when a
    growth objective is supplied), and grant matching (when a company profile is
    supplied). Actions are ranked survival-first; each traces to a digest.
    """

    parsed = (
        inputs
        if isinstance(inputs, AccountantCycleInput)
        else AccountantCycleInput.model_validate(inputs)
    )

    build_payload: dict[str, Any] = {
        "analysis_as_of": parsed.as_of,
        "runway_ref": parsed.cycle_ref,
        "currency": parsed.currency,
        "evidence": parsed.cash_evidence,
        "staleness_policy": parsed.staleness_policy,
    }
    if parsed.cash_on_hand_override is not None:
        build_payload["cash_on_hand_override"] = parsed.cash_on_hand_override
    snapshot = build_runway_snapshot(build_payload)

    envelope = derive_budget_envelope(
        {
            "envelope_ref": parsed.cycle_ref,
            "analysis_as_of": parsed.as_of,
            "runway_snapshot": snapshot,
            "runway_floor_months": parsed.runway_floor_months,
        }
    )
    assessment = assess_runway(
        {
            "assessment_ref": parsed.cycle_ref,
            "analysis_as_of": parsed.as_of,
            "runway_snapshot": snapshot,
            "runway_floor_months": parsed.runway_floor_months,
            "caution_threshold_months": parsed.caution_threshold_months,
        }
    )

    gate: ObjectiveFundingGate | None = None
    if parsed.objective_assessment is not None:
        gate = gate_objective_funding(
            {
                "gate_ref": parsed.cycle_ref,
                "as_of": parsed.as_of,
                "objective_assessment": parsed.objective_assessment,
                "budget_envelope": envelope,
            }
        )

    grant_result = None
    if parsed.grant_profile is not None:
        grant_result = match_grant_programs(parsed.grant_profile)

    default_alive = parsed.default_alive
    tax = parsed.tax_provision
    receivables = parsed.receivables
    payables = parsed.payables

    # Money in two currencies is never summed or co-reported. Any supplied book
    # denominated differently from the cycle would print its amounts under the
    # cycle's currency label — a fabrication — and the tax set-aside is worse: it
    # is subtracted from cash on hand. Every currency-bearing input is refused
    # outright on a mismatch.
    for _label, _book in (
        ("receivables", receivables),
        ("payables", payables),
        ("tax provision", tax),
        ("default-alive", default_alive),
    ):
        if _book is not None and _book.currency != parsed.currency:
            raise AccountantLoopValidationError(
                f"{_label} assessment is denominated in {_book.currency} but the "
                f"cycle is {parsed.currency}; amounts in different currencies are "
                "never summed or co-reported"
            )

    severity: AccountantSeverity = assessment.severity
    runway_component = snapshot.component("runway_months")
    runway_months = runway_component.value if runway_component is not None else None

    # Cash owed in tax is committed, not spendable. Net it out so the CFO
    # briefing reasons about the cash actually available to deploy.
    cash_component = snapshot.component("cash_on_hand")
    cash_on_hand = cash_component.value if cash_component is not None else None
    tax_set_aside = tax.total_set_aside if tax is not None else None
    spendable_cash_net_of_tax: Decimal | None = None
    if cash_on_hand is not None and tax_set_aside is not None:
        spendable_cash_net_of_tax = cash_on_hand - tax_set_aside

    # --- Assemble the survival-first agenda -------------------------------
    actions: list[dict[str, Any]] = []
    notes: list[str] = []

    def add(kind: str, title: str, rationale: str, digest: str) -> None:
        actions.append(
            {"kind": kind, "title": title, "rationale": rationale, "source_digest": digest}
        )

    # Overdue AR is the most certain non-dilutive cash there is — it is already
    # owed. It is NEVER folded into runway or the budget (uncollected cash is not
    # cash on hand — that is the optimism trap this layer exists to avoid); it is
    # surfaced only as its own collection lever.
    has_overdue_ar = receivables is not None and receivables.overdue_total > 0

    def add_collect_receivables() -> None:
        assert receivables is not None  # guarded by has_overdue_ar at every call site
        add(
            "collect_receivables",
            "Chase overdue receivables to bring in owed cash",
            f"{receivables.overdue_total} {parsed.currency} is already owed and "
            "overdue — the most certain non-dilutive cash to extend runway",
            receivables.assessment_digest,
        )

    # Overdue AP is the mirror of overdue AR and it inverts the logic: AR
    # overdue is cash not yet received, AP overdue is an obligation already —
    # broken. Like AR it is NEVER netted against runway or the budget: the bills,
    # when paid, ARE the burn the runway snapshot already measured, so
    # subtracting them again would double-count.
    settleable_overdue_ap = (
        payables.overdue_total - payables.on_hold_overdue_total
        if payables is not None
        else Decimal("0")
    )
    has_overdue_ap = settleable_overdue_ap > 0
    critical_overdue = (
        payables.critical_vendors_overdue if payables is not None else ()
    )
    critical_overdue_count = (
        payables.critical_vendors_overdue_count if payables is not None else 0
    )

    def add_settle_payables(*, critical: bool = False) -> None:
        assert payables is not None  # guarded by has_overdue_ap at every call site
        if critical:
            named = ", ".join(name[:40] for name in critical_overdue[:3])
            more = (
                f" +{critical_overdue_count - 3} more"
                if critical_overdue_count > 3
                else ""
            )
            add(
                "settle_payables",
                "Settle overdue bills with critical vendors before supply stops",
                f"{payables.critical_vendor_overdue_total} {parsed.currency} is overdue "
                "with critical vendors; the wider settleable overdue book is "
                f"{settleable_overdue_ap} {parsed.currency}. It "
                f"includes critical vendor(s) ({named}{more}) — interruption "
                "halts operations",
                payables.assessment_digest,
            )
            return
        add(
            "settle_payables",
            "Settle overdue supplier bills before terms are withdrawn",
            f"{settleable_overdue_ap} {parsed.currency} is already past due "
            "— an obligation you were late paying, which risks vendor terms "
            "and supply",
            payables.assessment_digest,
        )

    # Stopped supply stops the business, so this leads the agenda whenever it is
    # present — ahead of even the default-dead trajectory call below.
    if has_overdue_ap and critical_overdue:
        add_settle_payables(critical=True)

    # Default-dead is the gravest strategic fact when present: at the stated
    # growth the company runs out of cash before it reaches profitability. It is
    # independent of the runway-floor severity (you can clear the floor today and
    # still be default-dead), so it leads the agenda whenever it is supplied.
    if default_alive is not None and default_alive.verdict == "default_dead":
        add(
            "raise_capital",
            "Change trajectory: default-dead under current assumptions",
            "projected to run out of cash before reaching profitability at the "
            "stated growth rates — cut burn, accelerate revenue, or raise now",
            default_alive.assessment_digest,
        )

    if severity == "unknown":
        add(
            "collect_evidence",
            "Measure cash before deciding anything",
            "runway is unknown; connect a cash source or import a bank statement",
            assessment.assessment_digest,
        )
    elif severity == "danger":
        add(
            "reduce_burn",
            "Cut net burn to restore the runway floor",
            "runway is below its floor; survival comes before growth",
            assessment.assessment_digest,
        )
        if has_overdue_ar:
            add_collect_receivables()
        if has_overdue_ap and not critical_overdue:
            add_settle_payables()
        if grant_result is not None and grant_result.matched:
            add(
                "pursue_grants",
                f"Pursue {len(grant_result.matched)} non-dilutive program(s) to extend runway",
                "grants extend runway without giving up equity — verify each at source",
                grant_result.result_digest,
            )
        else:
            add(
                "raise_capital",
                "Raise capital to extend runway past the floor",
                "new cash directly lifts runway at the current burn",
                assessment.assessment_digest,
            )
    elif severity == "caution":
        add(
            "raise_capital",
            "Extend runway toward the caution threshold",
            "runway clears the floor but is under the caution line",
            assessment.assessment_digest,
        )
        if has_overdue_ar:
            add_collect_receivables()
        if has_overdue_ap and not critical_overdue:
            add_settle_payables()
        if grant_result is not None and grant_result.matched:
            add(
                "pursue_grants",
                f"Line up {len(grant_result.matched)} non-dilutive program(s) early",
                "grant rounds are slow; start before runway tightens further",
                grant_result.result_digest,
            )

    # Tax owed is committed cash, not spendable. Reserve it before any growth
    # deployment is even weighed — spending it is borrowing from the tax office.
    if tax is not None and tax.total_set_aside > 0:
        rationale = (
            f"{tax.total_set_aside} {parsed.currency} is provisioned for tax and "
            "is not discretionary cash"
        )
        if not tax.complete:
            rationale += "; provision is partial — some bases were skipped, not guessed"
        add(
            "reserve_tax",
            "Reserve the tax set-aside before committing discretionary cash",
            rationale,
            tax.provision_digest,
        )

    # Growth spend is only ever discussed after survival is handled.
    if gate is not None:
        if gate.verdict == "deploy_permitted":
            add(
                "deploy_growth",
                "Deploy discretionary capacity toward the objective",
                "runway clears the floor; paid growth is affordable within capacity",
                gate.gate_digest,
            )
        elif gate.verdict in ("defer_protect_runway", "hold_at_floor"):
            add(
                "defer_growth_spend",
                "Defer paid growth; protect runway first",
                "the runway floor overrides the growth objective",
                gate.gate_digest,
            )

    # Overdue AR is worth chasing even when the runway is fine — it is owed cash
    # aging on the balance sheet. (In danger/caution it was already surfaced
    # inside those branches, ranked above prospective grants.)
    if has_overdue_ar and severity not in ("danger", "caution"):
        add_collect_receivables()

    # A late bill is worth clearing even when runway is fine: the cost is vendor
    # terms and supply, not solvency. (danger/caution surfaced it above.)
    if has_overdue_ap and not critical_overdue and severity not in (
        "danger",
        "caution",
    ):
        add_settle_payables()

    # Grants worth reviewing even when healthy (non-dilutive is always cheap).
    if (
        grant_result is not None
        and grant_result.matched
        and severity not in ("danger", "caution")
    ):
        add(
            "review_grants",
            f"Review {len(grant_result.matched)} eligible non-dilutive program(s)",
            "free capital worth claiming — verify current terms at each source",
            grant_result.result_digest,
        )

    if not actions:
        add(
            "hold",
            "Hold; the books are healthy and no action is due",
            "runway clears the caution line and no growth objective is pending",
            assessment.assessment_digest,
        )

    ranked = tuple(
        AccountantAction(
            rank=index + 1,
            kind=item["kind"],
            title=item["title"][:300],
            rationale=item["rationale"][:300],
            source_digest=item["source_digest"],
        )
        for index, item in enumerate(actions)
    )

    if envelope.status == "unknown":
        notes.append("budget is unknown; no discretionary capacity can be sized")
    if grant_result is not None and not grant_result.matched:
        notes.append("no flagship grant programs matched; run a live grant search")
    if default_alive is not None:
        notes.append(
            f"default-alive verdict: {default_alive.verdict} "
            "(conditional on the stated growth assumptions)"
        )
    if tax is not None and not tax.complete:
        notes.append("tax provision is partial; unsupported bases were skipped, not guessed")
    if spendable_cash_net_of_tax is not None and tax_set_aside:
        notes.append(
            f"spendable cash net of tax set-aside is {spendable_cash_net_of_tax} "
            f"{parsed.currency}"
        )
        if spendable_cash_net_of_tax < 0:
            notes.append("tax owed exceeds cash on hand; the set-aside is not fully funded")
    if receivables is not None:
        notes.append(
            f"AR: {receivables.total_outstanding} {parsed.currency} outstanding, "
            f"{receivables.overdue_total} overdue — owed cash, not counted in runway"
        )
        if receivables.collections_within_horizon > 0:
            notes.append(
                f"{receivables.collections_within_horizon} {parsed.currency} of AR is "
                "expected within the forecast horizon; feed it to the cash-flow forecast"
            )
        if receivables.concentration_flag and receivables.largest_customer is not None:
            notes.append(
                f"AR collection risk is concentrated in '{receivables.largest_customer[:80]}'"
            )
    if payables is not None:
        floor_phrase = (
            " (a floor — un-invoiced commitments are absent)"
            if payables.obligations_are_floor
            else ""
        )
        notes.append(
            f"AP: {payables.total_outstanding} {parsed.currency} owed{floor_phrase}, "
            f"{payables.overdue_total} overdue — money committed, not netted against runway"
        )
        if payables.on_hold_total > 0:
            notes.append(
                f"{payables.on_hold_total} {parsed.currency} of AP is on hold but "
                "still counted and still scheduled; a dispute lost is payable"
            )
        if payables.critical_vendors_on_hold:
            named = ", ".join(
                name[:40] for name in payables.critical_vendors_on_hold[:3]
            )
            more = (
                f" +{payables.critical_vendors_on_hold_count - 3} more"
                if payables.critical_vendors_on_hold_count > 3
                else ""
            )
            notes.append(
                f"Held overdue AP involves critical vendor(s) ({named}{more}); resolve "
                "the dispute or reserve for it — do not treat a hold as permission to pay"
            )
        if payables.concentration_flag and payables.largest_vendor is not None:
            notes.append(
                f"AP is concentrated in '{payables.largest_vendor[:80]}' — that vendor "
                "holds the supply leverage"
            )
    # Which way working capital runs can only be said with both books in hand.
    if (
        receivables is not None
        and payables is not None
        and receivables.dso_days is not None
        and payables.dpo_days is not None
    ):
        gap = receivables.dso_days - payables.dpo_days
        if gap > 0:
            notes.append(
                f"working capital runs against you: DSO {receivables.dso_days}d "
                f"exceeds DPO {payables.dpo_days}d by {gap}d — you finance customers "
                "for that gap"
            )
        else:
            notes.append(
                f"working capital runs for you: DPO {payables.dpo_days}d meets or "
                f"exceeds DSO {receivables.dso_days}d"
            )

    # --- Forward weekly cash-flow forecast (optional) --------------------
    # When forecast_weeks is set, project cash forward from the runway snapshot's
    # opening balance across the caller's scheduled events, AR's expected
    # collections (auto-fed as inflows) and AP's expected payments (auto-fed as
    # outflows). Feeding only one side would flatter cash in the dangerous
    # direction, so both books go in or the forecast is not honest. It is a
    # scenario, and
    # like AR it is NEVER folded back into runway — the forecast trough can reveal
    # a near-term liquidity gap the monthly runway average hides.
    forecast: CashFlowForecast | None = None
    if parsed.forecast_weeks is not None:
        if cash_on_hand is None:
            notes.append(
                "cash-flow forecast skipped: opening cash is unknown (measure cash first)"
            )
        else:
            events: list[Any] = [
                event
                for event in parsed.scheduled_cash_events
                if event.week_index <= parsed.forecast_weeks
            ]
            dropped = len(parsed.scheduled_cash_events) - len(events)
            if receivables is not None:
                for collection in receivables.expected_collections:
                    if collection.expected_week <= parsed.forecast_weeks:
                        events.append(
                            {
                                "event_ref": collection.invoice_ref,
                                "week_index": collection.expected_week,
                                "direction": "inflow",
                                "amount": str(collection.amount),
                                "category": "ar_collection",
                            }
                        )
            if payables is not None:
                for payment in payables.expected_payments:
                    if payment.expected_week <= parsed.forecast_weeks:
                        events.append(
                            {
                                "event_ref": payment.bill_ref,
                                "week_index": payment.expected_week,
                                "direction": "outflow",
                                "amount": str(payment.amount),
                                "category": "ap_payment",
                            }
                        )
            request: dict[str, Any] = {
                "forecast_ref": parsed.cycle_ref,
                "as_of": parsed.as_of,
                "currency": parsed.currency,
                "opening_cash": str(cash_on_hand),
                "horizon_weeks": parsed.forecast_weeks,
                "scheduled_events": tuple(events),
                "events_are_complete": parsed.scheduled_events_complete,
            }
            if parsed.assumed_weekly_operating_outflow is not None:
                request["assumed_weekly_operating_outflow"] = str(
                    parsed.assumed_weekly_operating_outflow
                )
            try:
                forecast = build_cash_flow_forecast(request)
            except ValueError as exc:
                notes.append(f"cash-flow forecast skipped: {exc}")
            else:
                if dropped:
                    notes.append(
                        f"{dropped} scheduled event(s) beyond week "
                        f"{parsed.forecast_weeks} were excluded from the forecast"
                    )
                if forecast.first_negative_week is not None:
                    notes.append(
                        f"cash-flow forecast: balance goes negative in week "
                        f"{forecast.first_negative_week} — a near-term liquidity gap "
                        "the monthly runway average can hide"
                    )
                if forecast.reliability == "optimistic_ceiling":
                    notes.append(
                        "cash-flow forecast is an optimistic ceiling; ongoing opex is "
                        "not fully modeled (supply a run-rate or mark events complete)"
                    )

    agenda = AccountantAgenda(
        cycle_ref=parsed.cycle_ref,
        as_of=parsed.as_of,
        currency=parsed.currency,
        runway_status=snapshot.status,
        runway_months=runway_months,
        budget_status=envelope.status,
        severity=severity,
        runway_digest=snapshot.runway_digest,
        assessment_digest=assessment.assessment_digest,
        funding_gate_verdict=gate.verdict if gate is not None else None,
        funding_gate_digest=gate.gate_digest if gate is not None else None,
        grant_matches=len(grant_result.matched) if grant_result is not None else None,
        grant_match_digest=grant_result.result_digest if grant_result is not None else None,
        default_alive_verdict=(
            default_alive.verdict if default_alive is not None else None
        ),
        default_alive_digest=(
            default_alive.assessment_digest if default_alive is not None else None
        ),
        tax_set_aside=tax_set_aside,
        spendable_cash_net_of_tax=spendable_cash_net_of_tax,
        tax_provision_digest=tax.provision_digest if tax is not None else None,
        receivables_outstanding=(
            receivables.total_outstanding if receivables is not None else None
        ),
        receivables_overdue=(
            receivables.overdue_total if receivables is not None else None
        ),
        receivables_dso_days=(
            receivables.dso_days if receivables is not None else None
        ),
        collections_within_horizon=(
            receivables.collections_within_horizon if receivables is not None else None
        ),
        receivables_digest=(
            receivables.assessment_digest if receivables is not None else None
        ),
        payables_outstanding=(
            payables.total_outstanding if payables is not None else None
        ),
        payables_overdue=(payables.overdue_total if payables is not None else None),
        payables_dpo_days=(payables.dpo_days if payables is not None else None),
        payables_are_floor=(
            payables.obligations_are_floor if payables is not None else None
        ),
        payments_within_horizon=(
            payables.payments_within_horizon if payables is not None else None
        ),
        payables_digest=(
            payables.assessment_digest if payables is not None else None
        ),
        forecast_horizon_weeks=(
            forecast.horizon_weeks if forecast is not None else None
        ),
        forecast_closing_cash=(
            forecast.closing_cash if forecast is not None else None
        ),
        forecast_lowest_cash=(
            forecast.lowest_cash if forecast is not None else None
        ),
        forecast_first_negative_week=(
            forecast.first_negative_week if forecast is not None else None
        ),
        forecast_reliability=(
            forecast.reliability if forecast is not None else None
        ),
        forecast_digest=(
            forecast.forecast_digest if forecast is not None else None
        ),
        actions=ranked,
        notes=tuple(dict.fromkeys(notes))[:20],
    )
    digest = _stable_digest(agenda.model_dump(mode="json", exclude={"agenda_digest"}))
    return agenda.model_copy(update={"agenda_digest": digest})


# ---------------------------------------------------------------------------
# Executable primitive
# ---------------------------------------------------------------------------


def _build_example() -> dict[str, Any]:
    from .cash_payables import build_payables_assessment
    from .cash_receivables import build_receivables_assessment
    from .cash_runway import mint_cash_ledger_evidence  # noqa: F401 (doc reference)
    from .fundraise_readiness import assess_default_alive
    from .tax_provision import estimate_tax_set_aside

    # Unsealed bank-statement evidence (the primitive runs the unverified path).
    evidence = (
        {
            "observation_ref": "bank-example",
            "connector_account_ref": "acct.bank.operating",
            "provider": "bank",
            "source_capability": "bank.statement_import",
            "currency": "USD",
            "observed_at": "2026-08-01T00:00:00Z",
            "window_start": "2026-07-01T00:00:00Z",
            "window_end": "2026-08-01T00:00:00Z",
            "metrics": {
                "cash_inflows": "30000.00",
                "cash_outflows": "60000.00",
                "ending_cash_balance": "120000.00",
            },
            "evidence_digest": "e" * 64,
        },
    )
    # Tax owed (committed cash) and a forward default-alive read, built with the
    # real estimators so the example round-trips exactly what the loop consumes.
    tax_provision = estimate_tax_set_aside(
        {
            "provision_ref": "august-tax-example",
            "as_of": "2026-08-02T00:00:00Z",
            "currency": "USD",
            "jurisdiction": "CA",
            "period_label": "2026-Q3",
            "bases": (
                {
                    "tax_type": "corporate_income",
                    "basis_amount": "40000.00",
                    "rate_override": "0.15",
                },
            ),
        }
    ).to_dict()
    default_alive = assess_default_alive(
        {
            "assessment_ref": "august-default-alive-example",
            "as_of": "2026-08-02T00:00:00Z",
            "currency": "USD",
            "cash_on_hand": "120000.00",
            "monthly_revenue": "30000.00",
            "monthly_costs": "60000.00",
            "monthly_revenue_growth_rate": "0.15",
            "monthly_cost_growth_rate": "0.05",
            "horizon_months": 36,
        }
    ).to_dict()
    receivables = build_receivables_assessment(
        {
            "assessment_ref": "august-ar-example",
            "as_of": "2026-08-02T00:00:00Z",
            "currency": "USD",
            "credit_sales_in_period": "180000.00",
            "period_days": 90,
            "invoices": (
                {
                    "invoice_ref": "INV-2001",
                    "customer": "Enterprise Buyer",
                    "amount": "40000.00",
                    "due_at": "2026-07-10T00:00:00Z",
                },
                {
                    "invoice_ref": "INV-2010",
                    "customer": "SMB Customer",
                    "amount": "12000.00",
                    "due_at": "2026-08-20T00:00:00Z",
                },
            ),
        }
    ).to_dict()
    payables = build_payables_assessment(
        {
            "assessment_ref": "august-ap-example",
            "as_of": "2026-08-02T00:00:00Z",
            "currency": "USD",
            "credit_purchases_in_period": "120000.00",
            "period_days": 90,
            "bills": (
                {
                    "bill_ref": "BILL-3301",
                    "vendor": "Contract Manufacturer",
                    "amount": "31000.00",
                    "due_at": "2026-07-12T00:00:00Z",
                    "trade_credit": True,
                    "critical_vendor": True,
                },
                {
                    "bill_ref": "BILL-3318",
                    "vendor": "Cloud Hosting",
                    "amount": "6200.00",
                    "due_at": "2026-08-18T00:00:00Z",
                    "trade_credit": True,
                },
            ),
        }
    ).to_dict()
    return {
        "cycle_ref": "august-cycle-example",
        "as_of": "2026-08-02T00:00:00Z",
        "currency": "USD",
        "cash_evidence": evidence,
        "runway_floor_months": "12",
        "caution_threshold_months": "18",
        "grant_profile": {
            "profile_ref": "example-startup",
            "country": "CA",
            "region": "Ontario",
            "is_incorporated": True,
            "conducts_rnd": True,
            "export_intent": True,
            "is_sme": True,
            "sectors": ["software"],
        },
        "tax_provision": tax_provision,
        "default_alive": default_alive,
        "receivables": receivables,
        "payables": payables,
        "forecast_weeks": 13,
        "assumed_weekly_operating_outflow": "8000.00",
        "scheduled_cash_events": (
            {
                "event_ref": "payroll-w4",
                "week_index": 4,
                "direction": "outflow",
                "amount": "30000.00",
                "category": "payroll",
            },
        ),
    }


_EXAMPLE_CYCLE: dict[str, Any] = _build_example()


class RunAccountantCyclePrimitive(
    BusinessProcessPrimitive[AccountantCycleInput, AccountantAgenda]
):
    """Run the accountant's routine and emit a survival-first agenda."""

    primitive_ref = "accounting.run_cycle"
    version = "2.0.0"
    title = "Run the accountant cycle"
    description = (
        "One pass of the AI accountant: measure runway from the period's cash "
        "evidence, size the budget envelope, judge severity, gate growth spend "
        "against the runway floor when a growth objective is supplied, surface "
        "matched non-dilutive grants, reserve tax, read default-alive/dead, "
        "fold in both sides of working capital — chasing overdue "
        "receivables (the cheapest cash there is) and settling overdue payables "
        "(an obligation already late), neither ever netted against runway — and, "
        "when a horizon is given, project cash forward week by week fed by BOTH "
        "books, so the forecast cannot flatter cash by counting the collections "
        "without the bills, surfacing a near-term liquidity gap the monthly "
        "runway average hides. "
        "Emits one prioritized agenda, survival-first — unknown runway means "
        "measure, below-floor means cut burn and collect what is owed before "
        "raising or spending on growth. Every action traces to the digest that "
        "justified it; nothing is invented."
    )
    input_model = AccountantCycleInput
    output_model = AccountantAgenda
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _EXAMPLE_CYCLE

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: AccountantCycleInput,
    ) -> PrimitiveExecutionResult[AccountantAgenda]:
        try:
            agenda = run_accountant_cycle(inputs)
        except ValueError as exc:
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.FAILED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=f"accountant cycle rejected: {exc}",
                output=None,
            )
        return PrimitiveExecutionResult[AccountantAgenda](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Accountant cycle {agenda.cycle_ref}: {agenda.severity}; "
                f"{len(agenda.actions)} action(s), top = {agenda.actions[0].kind}."
            ),
            output=agenda,
            events=[
                PrimitiveEvent(
                    type="accounting.cycle_run",
                    payload={"cycle_ref": agenda.cycle_ref, "severity": agenda.severity},
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Agenda bound to runway "
                    + agenda.runway_digest[:16]
                    + "…",
                )
            ],
        )


__all__ = [
    "ACCOUNTANT_AGENDA_SCHEMA",
    "AccountantAction",
    "AccountantActionKind",
    "AccountantAgenda",
    "AccountantCycleInput",
    "AccountantLoopValidationError",
    "AccountantSeverity",
    "RunAccountantCyclePrimitive",
    "run_accountant_cycle",
]
