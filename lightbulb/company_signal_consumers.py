"""Signal consumers: the engines act on each other's typed signals.

The company operating system routes ``signals.*`` to the engines that should
hear them and attaches an advisory.  Consumers make the advisory concrete.
Given a routed signal and the persisted states of the consumer engines, a
consumer returns two things, both sealed:

* **commands** — exact engine transitions that follow from the signal and
  whose inputs the signal already carries: a churn-risk account suppresses
  the prospects on that account; a rolled-back release pauses the live
  campaigns that promote its affected claims.  They are applied through the
  engines' own replay fences.
* **intents** — typed work that needs a plan or a primitive rather than a
  transition: exclude look-alikes of the churn-risk account from the next
  portfolio, open a retention or onboarding case, hold launches on an
  exhausted envelope until replan, reserve onboarding capacity for a booked
  meeting, source an expansion prospect only once consent is on record.

Consumers never over-act: without the payload that names what a signal
affects, they raise a review intent instead of touching every campaign or
prospect, and nothing here sends, pauses on a provider, or spends.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, add_days, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_operating_system import CompanyOperatingPlan, CompanySignal, EngineKind, SignalRouting, route_signal
from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, TERMINAL_PROSPECT_STATUSES

CONSUMPTION_SCHEMA = "lightbulb.company_signal_consumption.v1"
ConsumerEngine = EngineKind | Literal["company_operating_system"]
IntentKind = Literal["add_to_suppression_list", "exclude_audience_lookalike", "open_retention_case", "hold_launch", "review_campaigns_for_release", "halt_new_launches_until_verified", "replan_period", "reserve_onboarding_capacity", "open_onboarding_case", "forecast_update", "source_expansion_prospect", "reconcile_period", "customer_verification_followup", "bind_engine", "book_attributed_revenue", "adopt_reforecast", "pause_campaigns_for_sku", "expedite_replenishment", "open_incident_case", "hold_release_until_postmortem", "carry_sla_credit_liability", "review_fulfilment_backlog", "open_late_order_cases", "hold_expansion_outreach", "review_onboarding", "order_fx_conversion", "carry_fx_position", "pause_discretionary_spend", "bring_forward_collections", "review_cash_floor_breach", "notify_insurer", "carry_claim_receivable", "chase_board_actions", "open_asset_cases", "reschedule_work_orders", "notify_option_holders", "prepare_share_issue", "carry_deposit_liability", "resolve_unapplied_deposit"]
_MONEY = Decimal("0.01")


class _PaymentOverduePayload(StrictModel):
    invoice_ref: OpaqueRef
    account_ref: OpaqueRef
    amount_remaining: Decimal
    currency: CurrencyCode
    days_overdue: int = Field(ge=0)
    due_at: str
    source_digest: Sha256Digest

    @field_validator("amount_remaining", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        amount = decimal_value(value, field_name="amount_remaining")
        if amount <= 0:
            raise ValueError("amount_remaining must be positive")
        return amount

    @field_validator("invoice_ref", "account_ref")
    @classmethod
    def _reference(cls, value: str) -> str:
        if ":/" in value or "@" in value or value.lower().startswith(("http:", "https:", "file:", "mailto:", "javascript:", "data:")):
            raise ValueError("invoice and account references must be opaque, not URLs or email addresses")
        return value

    @field_validator("due_at")
    @classmethod
    def _due(cls, value: str) -> str:
        return timestamp(value, field_name="due_at")


class ConsumerCommand(StrictModel):
    engine: ConsumerEngine
    entity_ref: OpaqueRef
    event: ShortText
    receipt: dict[str, Any] = Field(default_factory=dict)
    reason: BoundedText | None = None
    rationale: BoundedText


class ConsumerIntent(StrictModel):
    engine: ConsumerEngine
    kind: IntentKind
    summary: BoundedText
    payload: dict[str, Any] = Field(default_factory=dict)
    satisfied_by: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)
    requires_consent: bool = False
    requires_approval: bool = False


class SignalConsumption(StrictModel):
    schema_id: str = Field(default=CONSUMPTION_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    routing_digest: Sha256Digest
    signal: CompanySignal
    consumers: tuple[ShortText, ...] = Field(min_length=1, max_length=6)
    commands: tuple[ConsumerCommand, ...] = Field(default_factory=tuple, max_length=200)
    intents: tuple[ConsumerIntent, ...] = Field(default_factory=tuple, max_length=40)
    executes_nothing: Literal[True] = True
    consumption_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SignalConsumption:
        for command in self.commands:
            if command.engine not in self.consumers:
                raise ValueError(f"{command.engine} is not a consumer of {self.signal.name}")
        for intent in self.intents:
            if intent.engine not in self.consumers:
                raise ValueError(f"{intent.engine} is not a consumer of {self.signal.name}")
        if not skip_digests(info) and self.consumption_digest != sealed_digest(SignalConsumption, self, "consumption_digest"):
            raise ValueError("consumption_digest must commit the exact consumption")
        return self


def _states(records: Sequence[Any] | None, spec: Any) -> list[Any]:
    parsed: list[Any] = []
    for record in records or ():
        raw = detached(record)
        document = raw.get("state", raw) if isinstance(raw, Mapping) else raw
        parsed.append(spec.State.model_validate(dict(document)))
    return parsed


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if value is None or str(value).strip() == "":
        raise ValueError(f"SIGNAL_PAYLOAD_INCOMPLETE: {key} is required")
    return str(value)


def _money(payload: Mapping[str, Any], key: str) -> Decimal:
    try:
        return Decimal(str(payload[key])).quantize(_MONEY)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"SIGNAL_PAYLOAD_INVALID: {key} must be a decimal") from exc


def _split(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if value is None:
        return ()
    return tuple(item.strip() for item in str(value).split(",") if item.strip())


def consume_signal(plan: CompanyOperatingPlan | Mapping[str, Any], signal: CompanySignal | Mapping[str, Any], *, states: Mapping[str, Sequence[Any]] | None = None, now: str) -> SignalConsumption:
    """Route the signal through the operating plan and turn the advisory into commands and intents."""

    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    routing: SignalRouting = route_signal(parsed_plan, signal)
    now = timestamp(now, field_name="now")
    payload = dict(routing.signal.payload)
    consumers = set(routing.consumers)
    commands: list[ConsumerCommand] = []
    intents: list[ConsumerIntent] = []
    name = routing.signal.name
    all_states = states or {}

    def intent(engine: str, kind: str, summary: str, *, payload_: Mapping[str, Any] | None = None, satisfied_by: Sequence[str] = (), requires_consent: bool = False, requires_approval: bool = False) -> None:
        if engine in consumers:
            intents.append(ConsumerIntent(engine=engine, kind=kind, summary=summary, payload=dict(payload_ or {}), satisfied_by=tuple(satisfied_by), requires_consent=requires_consent, requires_approval=requires_approval))

    if name == "signals.churn_risk":
        account = _text(payload, "account_ref")
        mrr = _money(payload, "mrr_at_risk")
        inactive = int(payload.get("inactive_days", 0))
        reason = f"churn risk on {account}: {mrr} MRR at risk after {inactive} inactive day(s)"
        if "pipeline_engine" in consumers:
            for prospect in _states(all_states.get("pipeline_engine"), PROSPECT_LIFECYCLE):
                if str(prospect.ledger.account_ref) == account and prospect.status not in TERMINAL_PROSPECT_STATUSES:
                    commands.append(ConsumerCommand(engine="pipeline_engine", entity_ref=prospect.scope.entity_ref, event="suppress", reason=reason, rationale="no outreach to an account the product is already losing"))
            intent("pipeline_engine", "add_to_suppression_list", f"Add {account} to the outreach suppression list until the retention play resolves", payload_={"account_ref": account, "until": add_days(now, 30)}, satisfied_by=("pipeline.plan_sequence",))
        intent("growth_engine", "exclude_audience_lookalike", f"Exclude look-alikes of {account} from the next acquisition portfolio", payload_={"account_ref": account, "until": add_days(now, 30)}, satisfied_by=("growth_engine.plan_campaign_portfolio",))
        severity = "sev2" if mrr >= Decimal("500") else "sev3"
        intent("service_delivery", "open_retention_case", f"Open a retention case for {account} ({severity})", payload_={"case_ref": f"retention:{account}", "customer_ref": account, "channel": "email", "subject": f"Retention: {account} inactive {inactive} day(s)", "severity": severity}, satisfied_by=("service_delivery.advance_case", "customer_success.prevent_returns_and_expand_ltv"))
    elif name == "signals.payment_overdue":
        try:
            overdue = _PaymentOverduePayload.model_validate(payload)
        except ValueError:
            raise ValueError("SIGNAL_PAYLOAD_INVALID: payment_overdue requires exact overdue invoice facts") from None
        if overdue.currency != parsed_plan.blueprint.currency:
            raise ValueError("SIGNAL_CURRENCY_MISMATCH: invoice balance must use the company's accounting currency")
        observed = parsed(routing.signal.emitted_at)
        due = parsed(overdue.due_at)
        if not due < observed <= parsed(now):
            raise ValueError("SIGNAL_OVERDUE_TIME_INVALID: invoice must be overdue at emission, and emission cannot be in the future")
        if overdue.days_overdue != (observed - due).days:
            raise ValueError("SIGNAL_OVERDUE_DAYS_MISMATCH: days_overdue must describe the original emission time")
        severity = "sev2" if overdue.amount_remaining >= Decimal("500") else "sev3"
        intent("service_delivery", "open_retention_case",
               f"Review overdue invoice {overdue.invoice_ref}: {overdue.amount_remaining} {overdue.currency} remains unpaid",
               payload_={**overdue.to_dict(), "case_ref": f"retention:{overdue.account_ref}",
                         "customer_ref": overdue.account_ref, "channel": "email",
                         "subject": f"Invoice {overdue.invoice_ref[:120]} overdue by {overdue.days_overdue} day(s)",
                         "severity": severity}, satisfied_by=("service_delivery.advance_case",))
    elif name == "signals.release_rolled_back":
        release = _text(payload, "release_ref")
        affected = _split(payload, "affected_claim_refs")
        campaigns = _states(all_states.get("growth_engine"), CAMPAIGN_LIFECYCLE)
        if affected:
            for campaign in campaigns:
                if not set(campaign.ledger.claim_refs) & set(affected):
                    continue
                if campaign.status == "live":
                    commands.append(ConsumerCommand(engine="growth_engine", entity_ref=campaign.scope.entity_ref, event="pause", reason=f"release {release} rolled back: {payload.get('reason', 'regression')}", rationale="a live campaign must not promote a capability that was rolled back"))
                elif campaign.status in ("composed", "pending_approval", "approved"):
                    intent("growth_engine", "hold_launch", f"Hold the launch of {campaign.scope.entity_ref} until {release} is verified again", payload_={"campaign_ref": campaign.scope.entity_ref, "release_ref": release}, satisfied_by=("growth_engine.advance_campaign",))
        else:
            live = [campaign.scope.entity_ref for campaign in campaigns if campaign.status == "live"]
            intent("growth_engine", "review_campaigns_for_release", f"Release {release} rolled back without affected claims named; review {len(live)} live campaign(s) for claims it promoted", payload_={"release_ref": release, "live_campaign_refs": live[:50]}, satisfied_by=("growth_engine.advance_campaign",))
        intent("company_operating_system", "halt_new_launches_until_verified", f"No new launches promoting {release} until the release is verified", payload_={"release_ref": release}, satisfied_by=("company.advance_period",))
    elif name == "signals.envelope_exhausted":
        envelope = _text(payload, "envelope_ref")
        spend, budget = _money(payload, "spend"), _money(payload, "budget")
        for campaign in _states(all_states.get("growth_engine"), CAMPAIGN_LIFECYCLE):
            if str(campaign.ledger.envelope_ref) == envelope and campaign.status in ("drafted", "composed", "pending_approval", "approved"):
                intent("company_operating_system", "hold_launch", f"Hold {campaign.scope.entity_ref}: envelope {envelope} spent {spend} of {budget}", payload_={"campaign_ref": campaign.scope.entity_ref, "envelope_ref": envelope}, satisfied_by=("growth_engine.advance_campaign", "company.advance_period"))
        intent("company_operating_system", "replan_period", f"Envelope {envelope} is exhausted ({spend} of {budget}); replan before further launches", payload_={"envelope_ref": envelope}, satisfied_by=("company.advance_period", "growth_engine.propose_reallocation"), requires_approval=True)
    elif name == "signals.qualified_pipeline":
        prospect = _text(payload, "prospect_ref")
        value, meeting_at = _money(payload, "deal_value"), _text(payload, "meeting_at")
        intent("saas_operating_engine", "reserve_onboarding_capacity", f"Reserve onboarding capacity for {prospect} ({value}) meeting at {meeting_at}", payload_={"prospect_ref": prospect, "deal_value": str(value), "meeting_at": meeting_at}, satisfied_by=("saas_ops.observe_usage",))
        intent("service_delivery", "open_onboarding_case", f"Open an onboarding case for {prospect} after the meeting", payload_={"case_ref": f"onboarding:{prospect}", "customer_ref": prospect, "channel": "email", "subject": f"Onboard {prospect}", "severity": "sev3"}, satisfied_by=("service_delivery.advance_case",))
        intent("company_operating_system", "forecast_update", f"Carry {prospect} at stage weight in the pipeline forecast", payload_={"prospect_ref": prospect, "deal_value": str(value)}, satisfied_by=("pipeline.forecast_pipeline",))
    elif name == "signals.expansion_candidate":
        account = _text(payload, "account_ref")
        plan_ref = _text(payload, "suggested_plan_ref")
        consent = payload.get("consent_ref")
        intent("pipeline_engine", "source_expansion_prospect", f"Source {account} as an expansion prospect for {plan_ref}" + ("" if consent else " once consent is on record"), payload_={"account_ref": account, "suggested_plan_ref": plan_ref, "consent_ref": consent}, satisfied_by=("pipeline.evaluate_icp_fit", "pipeline.advance_prospect"), requires_consent=consent is None)
    elif name == "signals.books_verified":
        intent("company_operating_system", "reconcile_period", f"Reconcile the operating period ending {_text(payload, 'period_end')} against the verified books", payload_={"period_end": _text(payload, "period_end"), "gross_margin_percent": str(payload.get("gross_margin_percent"))}, satisfied_by=("company.advance_period", "finance_close.verify_books"))
    elif name == "signals.case_resolved":
        case = _text(payload, "case_ref")
        if not bool(payload.get("resolution_verified")):
            intent("saas_operating_engine", "customer_verification_followup", f"Case {case} closed without customer verification; follow up before counting it as resolved", payload_={"case_ref": case}, satisfied_by=("service_delivery.advance_case",))
    elif name == "signals.company_formed":
        for engine in parsed_plan.blueprint.engine_kinds:
            intent(engine, "bind_engine", f"Bind {engine} to the formed company {_text(payload, 'company_ref')} in {_text(payload, 'region')}", payload_={"company_ref": _text(payload, "company_ref"), "country": _text(payload, "country")}, satisfied_by=("blueprint.compile_company_operating_system",))
    elif name == "signals.budget_variance":
        period, kind, ref = _text(payload, "period_ref"), _text(payload, "kind"), _text(payload, "ref")
        planned, actual = _money(payload, "planned"), _money(payload, "actual")
        movement = "overran" if kind == "spend" else "fell short of"
        intent("company_operating_system", "replan_period", f"{ref} {movement} plan in {period}: {actual} against {planned}; replan before further discretionary spend", payload_={"period_ref": period, "kind": kind, "ref": ref, "planned": str(planned), "actual": str(actual)}, satisfied_by=("company.advance_period",), requires_approval=True)
        if kind == "spend" and ref == "growth_engine":
            intent("growth_engine", "hold_launch", f"Hold new campaign launches: growth spend overran plan in {period}", payload_={"period_ref": period, "planned": str(planned), "actual": str(actual)}, satisfied_by=("growth_engine.advance_campaign",))
    elif name == "signals.reforecast_adopted":
        intent("company_operating_system", "adopt_reforecast", f"Carry reforecast version {payload.get('forecast_version')} into the next period's budget ({_text(payload, 'period_refs')})", payload_={"forecast_version": str(payload.get("forecast_version")), "period_refs": _text(payload, "period_refs"), "delta_spend": _text(payload, "delta_spend"), "delta_revenue": _text(payload, "delta_revenue")}, satisfied_by=("company.advance_period",))
    elif name == "signals.stockout_risk":
        sku, location = _text(payload, "sku_ref"), _text(payload, "location_ref")
        intent("growth_engine", "pause_campaigns_for_sku", f"Pause campaigns promoting {sku}: {_text(payload, 'on_hand')} on hand at {location} against a reorder point of {_text(payload, 'reorder_point')}", payload_={"sku_ref": sku, "location_ref": location, "until": add_days(now, 14)}, satisfied_by=("growth_engine.advance_campaign",))
        intent("company_operating_system", "expedite_replenishment", f"Expedite replenishment of {sku} at {location}", payload_={"sku_ref": sku, "location_ref": location}, satisfied_by=("company.advance_period",))
    elif name == "signals.sla_breached":
        incident, severity = _text(payload, "incident_ref"), _text(payload, "severity")
        intent("service_delivery", "open_incident_case", f"Open customer cases for the accounts affected by {incident} ({severity}, {payload.get('duration_minutes')} minutes)", payload_={"case_ref": f"incident:{incident}", "incident_ref": incident, "severity": severity, "channel": "email", "subject": f"Service incident {incident[:80]}"}, satisfied_by=("service_delivery.advance_case",))
        intent("saas_operating_engine", "hold_release_until_postmortem", f"Hold releases until the postmortem for {incident} is accepted", payload_={"incident_ref": incident}, satisfied_by=("saas_ops.advance_release",))
        intent("company_operating_system", "carry_sla_credit_liability", f"Carry {_text(payload, 'credits_due')} of SLA credits for {incident} as a liability against the period", payload_={"incident_ref": incident, "credits_due": _text(payload, "credits_due")}, satisfied_by=("company.advance_period",))
    elif name == "signals.late_shipments":
        store, count = _text(payload, "store_ref"), int(payload.get("late_count", 0))
        intent("service_delivery", "open_late_order_cases", f"Open customer cases for {count} late order(s) from {store}", payload_={"store_ref": store, "order_refs": _text(payload, "order_refs"), "channel": "email"}, satisfied_by=("service_delivery.advance_case",))
        intent("growth_engine", "hold_launch", f"Hold launches that add orders to {store} while {count} order(s) are late", payload_={"store_ref": store, "until": add_days(now, 7)}, satisfied_by=("growth_engine.advance_campaign",))
        intent("company_operating_system", "review_fulfilment_backlog", f"Review the fulfilment backlog at {store}: {count} order(s) past the {payload.get('promised_ship_days')}-day promise", payload_={"store_ref": store, "late_count": str(count)}, satisfied_by=("company.advance_period",))
    elif name == "signals.onboarding_at_risk":
        account, milestone = _text(payload, "account_ref"), _text(payload, "milestone_ref")
        intent("service_delivery", "open_onboarding_case", f"Open an onboarding case for {account}: {milestone} is {payload.get('days_overdue')} day(s) overdue", payload_={"case_ref": f"onboarding:{account}", "customer_ref": account, "channel": "email", "subject": f"Onboarding milestone {milestone[:80]} overdue"}, satisfied_by=("service_delivery.advance_case",))
        intent("saas_operating_engine", "hold_expansion_outreach", f"Hold expansion outreach to {account} until onboarding is live", payload_={"account_ref": account}, satisfied_by=("saas_ops.observe_usage",))
        intent("company_operating_system", "review_onboarding", f"Review onboarding for {account}", payload_={"account_ref": account, "milestone_ref": milestone}, satisfied_by=("company.advance_period",))
    elif name == "signals.fx_exposure_high":
        code, value = _text(payload, "exposure_currency"), _text(payload, "exposure_value")
        intent("finance_close", "order_fx_conversion", f"Order conversions to bring the {code} exposure of {value} under the limit {_text(payload, 'exposure_limit')}", payload_={"exposure_currency": code, "exposure_refs": _text(payload, "exposure_refs")}, satisfied_by=("fx_exposure_chain.advance",))
        intent("company_operating_system", "carry_fx_position", f"Carry the unrealised {code} position of {value} into the period close", payload_={"exposure_currency": code, "exposure_value": value}, satisfied_by=("company.advance_period",))
    elif name == "signals.cash_floor_breach":
        period, week = _text(payload, "period_ref"), int(payload.get("first_breach_week", 0))
        intent("growth_engine", "pause_discretionary_spend", f"Pause discretionary spend: the cash forecast for {period} breaches the floor in week {week}", payload_={"period_ref": period, "until": add_days(now, 7 * max(week, 1))}, satisfied_by=("growth_engine.advance_campaign",))
        intent("finance_close", "bring_forward_collections", f"Bring forward collections ahead of the week {week} breach in {period}", payload_={"period_ref": period, "minimum_balance": _text(payload, "minimum_balance")}, satisfied_by=("collections_chain.advance",))
        intent("company_operating_system", "review_cash_floor_breach", f"Replan {period}: minimum balance {_text(payload, 'minimum_balance')} against floor {_text(payload, 'floor')}", payload_={"period_ref": period, "first_breach_week": str(week), "runway_weeks": _text(payload, "runway_weeks")}, satisfied_by=("company.advance_period",))
    elif name == "signals.claim_notification_due":
        refs, by = _text(payload, "claim_refs"), _text(payload, "earliest_notify_by")
        intent("company_operating_system", "notify_insurer", f"Notify the insurer for {refs} by {by}", payload_={"claim_refs": refs, "earliest_notify_by": by, "late_count": _text(payload, "late_count")}, satisfied_by=("insurance_claim_chain.advance",))
        intent("finance_close", "carry_claim_receivable", f"Carry {_text(payload, 'claimable_total')} of claimable losses into the close", payload_={"claim_refs": refs, "claimable_total": _text(payload, "claimable_total")}, satisfied_by=("company.advance_period",))
    elif name == "signals.board_action_overdue":
        meeting, count = _text(payload, "meeting_ref"), int(payload.get("overdue_count", 0))
        intent("company_operating_system", "chase_board_actions", f"Chase {count} overdue board action(s) from {meeting}: owners {_text(payload, 'owner_refs')}", payload_={"meeting_ref": meeting, "action_refs": _text(payload, "action_refs"), "owner_refs": _text(payload, "owner_refs")}, satisfied_by=("board_cadence_chain.advance",))
    elif name == "signals.work_order_overdue":
        count, assets = int(payload.get("overdue_count", 0)), _text(payload, "asset_refs")
        intent("service_delivery", "open_asset_cases", f"Open cases for {assets}: {count} work order(s) past target", payload_={"asset_refs": assets, "work_order_refs": _text(payload, "work_order_refs"), "channel": "email"}, satisfied_by=("service_delivery.advance_case",))
        intent("company_operating_system", "reschedule_work_orders", f"Reschedule {count} overdue work order(s); oldest target {_text(payload, 'oldest_target_at')}", payload_={"work_order_refs": _text(payload, "work_order_refs"), "overdue_count": str(count)}, satisfied_by=("work_order_chain.advance",))
    elif name == "signals.option_window_closing":
        holders, deadline = _text(payload, "holder_refs"), _text(payload, "earliest_deadline")
        intent("people_engine", "notify_option_holders", f"Tell {holders} their exercise window closes {deadline}", payload_={"holder_refs": holders, "grant_refs": _text(payload, "grant_refs"), "earliest_deadline": deadline}, satisfied_by=("equity_grant_chain.advance",))
        intent("company_operating_system", "prepare_share_issue", f"Prepare the share issue for up to {_text(payload, 'exercisable_units')} exercisable option(s)", payload_={"grant_refs": _text(payload, "grant_refs"), "exercisable_units": _text(payload, "exercisable_units")}, satisfied_by=("company.advance_period",))
    elif name == "signals.deposit_unapplied":
        customers, total = _text(payload, "customer_refs"), _text(payload, "unapplied_total")
        intent("finance_close", "carry_deposit_liability", f"Carry {total} of unapplied customer deposits as unearned revenue in the close", payload_={"deposit_refs": _text(payload, "deposit_refs"), "unapplied_total": total}, satisfied_by=("company.advance_period",))
        intent("service_delivery", "resolve_unapplied_deposit", f"Invoice the work or refund the balance for {customers}: deposits held past {_text(payload, 'oldest_hold_until')}", payload_={"customer_refs": customers, "deposit_refs": _text(payload, "deposit_refs"), "channel": "email"}, satisfied_by=("prepayment_chain.advance",))
    elif name == "signals.attributed_revenue":
        intent("finance_close", "book_attributed_revenue", f"Book {_money(payload, 'attributed_revenue')} attributed to {_text(payload, 'channel')} against spend {_money(payload, 'spend')}", payload_={"channel": _text(payload, "channel"), "attributed_revenue": str(_money(payload, "attributed_revenue")), "spend": str(_money(payload, "spend")), "window_end": _text(payload, "window_end")}, satisfied_by=("finance.evaluate_period_reconciliation",))
    return seal(SignalConsumption, {"plan_digest": parsed_plan.plan_digest, "routing_digest": routing.routing_digest, "signal": routing.signal, "consumers": routing.consumers, "commands": tuple(commands), "intents": tuple(intents)}, "consumption_digest")


class ConsumerApplied(StrictModel):
    engine: ConsumerEngine
    entity_ref: OpaqueRef
    event: ShortText
    outcome: Literal["applied", "rejected", "no_runtime"]
    to_status: str | None = None
    rejection_code: str | None = None


def apply_consumption(consumption: SignalConsumption | Mapping[str, Any], runtimes: Mapping[str, Any], *, now: str, actor_ref: str) -> tuple[ConsumerApplied, ...]:
    """Apply the consumption's commands through the engines' runtimes (each behind its own fences)."""

    parsed = consumption if isinstance(consumption, SignalConsumption) else SignalConsumption.model_validate(dict(detached(consumption)))
    now = timestamp(now, field_name="now")
    applied: list[ConsumerApplied] = []
    for index, command in enumerate(parsed.commands, start=1):
        runtime = runtimes.get(command.engine)
        if runtime is None:
            applied.append(ConsumerApplied(engine=command.engine, entity_ref=command.entity_ref, event=command.event, outcome="no_runtime"))
            continue
        state = runtime.load(command.entity_ref)
        sealed = runtime.command(state, event=command.event, transition_ref=f"signal:{parsed.consumption_digest[:24]}:{index}", idempotency_key=f"signal:{parsed.consumption_digest[:24]}:{command.entity_ref}:{command.event}", occurred_at=now, actor_ref=actor_ref, receipt=command.receipt, reason=command.reason)
        outcome = runtime.advance_and_persist(command.entity_ref, sealed)
        if outcome.persisted:
            applied.append(ConsumerApplied(engine=command.engine, entity_ref=command.entity_ref, event=command.event, outcome="applied", to_status=str(outcome.record["status"])))
        else:
            applied.append(ConsumerApplied(engine=command.engine, entity_ref=command.entity_ref, event=command.event, outcome="rejected", rejection_code=outcome.result.receipt.rejection_code))
    return tuple(applied)


__all__ = ["CONSUMPTION_SCHEMA", "ConsumerApplied", "ConsumerCommand", "ConsumerIntent", "SignalConsumption", "apply_consumption", "consume_signal"]
