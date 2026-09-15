"""Channel cohorts: CAC, payback, and lifetime value per acquisition channel per cohort, outbound and referrals included.

Unit economics gives one CAC and one payback per period.  A cheap channel
with bad retention and an expensive channel with great retention look the
same in that average, and outbound sales is not a channel at all in the
growth engine, so its cost never enters CAC.  ``build_channel_cohorts``
fixes both, from replayed states only:

* a customer's cohort is the month their first revenue settled; their
  channel is the attribution ledger's credited touch when one exists, else
  the way the case was won (``outbound`` for a pipeline prospect,
  ``partner`` for a commission-attributed case, ``unattributed`` otherwise);
* a channel's cost in a cohort month is the sum of the replayed cost
  register's sources in the centres the plan assigns to that channel, so
  SDR payroll and contractor hours cost outbound the way media bills cost
  paid social;
* revenue to date comes from settled revenue-chain cash and subscription
  cash; contribution applies the plan's sealed margin; payback is the months
  of contribution it takes to return the cost; lifetime value projects
  subscription MRR over the plan's horizon at the cohort's observed churn.

Nothing here reads a provider or persists anything; the report retains the
digest of every state it read.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, ROUND_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

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
    unique,
)

CHANNEL_COHORT_PLAN_SCHEMA = "lightbulb.channel_cohort_plan.v1"
CHANNEL_COHORT_REPORT_SCHEMA = "lightbulb.channel_cohort_report.v1"
ACQUISITION_CHANNELS: tuple[str, ...] = ("paid_social_meta", "paid_search_google", "paid_social_tiktok", "organic_social", "email_lifecycle", "sms_lifecycle", "seo_content", "affiliate", "local_presence", "outbound", "referral", "partner", "unattributed")
COST_SOURCE_KINDS: frozenset[str] = frozenset({"channel_spend", "media_invoice", "payable", "spend_case", "payroll", "worker", "metered_dispatch", "inference_cost"})
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class ChannelCohortError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ChannelCohortError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _month(stamp: str) -> str:
    return str(stamp)[:7]


def _months_between(start: str, end: str) -> int:
    a, b = parsed(start), parsed(end)
    return max(0, (b.year - a.year) * 12 + (b.month - a.month))


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ChannelCentres(StrictModel):
    channel: ShortText
    centre_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("centre_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self) -> "ChannelCentres":
        if self.channel not in ACQUISITION_CHANNELS:
            raise ValueError(f"{self.channel} is not an acquisition channel; one of {ACQUISITION_CHANNELS}")
        return self


class ChannelCohortPlan(StrictModel):
    """What the report enforces: which cost centres fund which channel, the margin contribution is judged at, and the payback and lifetime horizons."""

    schema_id: str = Field(default=CHANNEL_COHORT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    channel_centres: tuple[ChannelCentres, ...] = Field(default_factory=tuple, max_length=13)
    contribution_margin_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    payback_target_months: int = Field(default=12, ge=1, le=60)
    lifetime_horizon_months: int = Field(default=24, ge=1, le=120)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("channel_centres", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("contribution_margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="contribution_margin_percent")
        if result <= 0 or result > _HUNDRED:
            raise ValueError("contribution margin is a percentage in (0, 100]")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChannelCohortPlan":
        unique([item.channel for item in self.channel_centres], label="channel centres")
        unique([ref for item in self.channel_centres for ref in item.centre_refs], label="centre assignments")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ChannelCohortPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def channel_for_centre(self, centre_ref: str) -> str | None:
        return next((item.channel for item in self.channel_centres if centre_ref in item.centre_refs), None)


def compile_channel_cohort_plan(company_ref: str, *, currency: str, channel_centres: Sequence[Mapping[str, Any]] = (), overrides: Mapping[str, Any] | None = None) -> ChannelCohortPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "channel_centres": [dict(detached(item)) for item in channel_centres], **dict(overrides or {})}
    return seal(ChannelCohortPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


class CohortCustomer(StrictModel):
    customer_ref: OpaqueRef
    channel: ShortText
    channel_basis: Literal["attributed_touch", "pipeline_prospect", "partner_commission", "unattributed"]
    cohort: ShortText
    first_revenue_at: str
    revenue_to_date: Decimal
    mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    churned: bool = False
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=40)

    @field_validator("source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("revenue_to_date", "mrr", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ChannelCohort(StrictModel):
    cohort: ShortText
    channel: ShortText
    customers: int = Field(ge=0)
    churned: int = Field(ge=0)
    months_observed: int = Field(ge=0)
    acquisition_cost: Decimal
    revenue_to_date: Decimal
    contribution_to_date: Decimal
    mrr: Decimal
    cac: Decimal | None = None
    payback_months: int | None = None
    payback_met: bool | None = None
    monthly_churn_percent: Decimal | None = None
    lifetime_value: Decimal | None = None
    ltv_cac: Decimal | None = None
    cost_source_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)

    @field_validator("cost_source_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("acquisition_cost", "revenue_to_date", "contribution_to_date", "mrr", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("cac", "lifetime_value", "ltv_cac", "monthly_churn_percent", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


class ChannelCohortReport(StrictModel):
    schema_id: str = Field(default=CHANNEL_COHORT_REPORT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    customers: tuple[CohortCustomer, ...] = Field(default_factory=tuple, max_length=5000)
    cohorts: tuple[ChannelCohort, ...] = Field(default_factory=tuple, max_length=2000)
    channel_ranking: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=13)
    unassigned_cost: Decimal
    unassigned_cost_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("customers", "cohorts", "channel_ranking", "unassigned_cost_refs", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("unassigned_cost", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="unassigned_cost")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChannelCohortReport":
        if not skip_digests(info) and self.report_digest != sealed_digest(ChannelCohortReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def by_channel(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for row in self.cohorts:
            item = out.setdefault(row.channel, {"customers": 0, "acquisition_cost": Decimal("0"), "revenue_to_date": Decimal("0"), "contribution_to_date": Decimal("0"), "mrr": Decimal("0")})
            item["customers"] += row.customers
            for key in ("acquisition_cost", "revenue_to_date", "contribution_to_date", "mrr"):
                item[key] += getattr(row, key)
        for item in out.values():
            item["cac"] = _money(item["acquisition_cost"] / item["customers"]) if item["customers"] else None
        return out

    def render(self) -> str:
        lines = [f"**Channel cohorts {self.company_ref}** as of {self.as_of[:10]}: {len(self.customers)} customer(s), {len(self.cohorts)} cohort row(s), ranking {', '.join(self.channel_ranking) or 'n/a'}, unassigned cost {self.unassigned_cost} {self.currency}"]
        for row in self.cohorts:
            lines.append(f"- {row.cohort} {row.channel}: {row.customers} customer(s), cost {row.acquisition_cost}, revenue {row.revenue_to_date}, CAC {row.cac if row.cac is not None else 'n/a'}, payback {row.payback_months if row.payback_months is not None else 'n/a'} mo, LTV/CAC {row.ltv_cac if row.ltv_cac is not None else 'n/a'}")
        return "\n".join(lines)


def _customer_of(ledger: Mapping[str, Any]) -> str | None:
    for key in ("customer_ref", "account_ref", "prospect_ref"):
        value = ledger.get(key)
        if value:
            return str(value)
    return None


def _unit_commitment(customer_ref: str) -> str:
    import re

    return customer_ref if re.fullmatch(r"[0-9a-f]{64}", customer_ref) else stable_digest({"customer_ref": customer_ref})


def build_channel_cohorts(plan: ChannelCohortPlan | Mapping[str, Any], *, revenue_states: Sequence[tuple[Any, Any]] = (), subscription_states: Sequence[tuple[Any, Any]] = (), register_states: Sequence[tuple[Any, Any]] = (), commission_states: Sequence[tuple[Any, Any]] = (), attribution: Any = None, as_of: str) -> ChannelCohortReport:
    """The sealed cohort table from replayed revenue and subscription cases, the replayed cost registers, the replayed partner commissions, and the attribution ledger."""

    from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE
    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
    from lightbulb.subscription_chain import SUBSCRIPTION_CHAIN_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ChannelCohortPlan) else ChannelCohortPlan.model_validate(detached(plan))
    stamp = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    customers: dict[str, dict[str, Any]] = {}

    def seen(customer: str, at: str, amount: Decimal, digest: str, *, mrr: Decimal = Decimal("0"), churned: bool = False, pipeline: bool = False) -> None:
        row = customers.setdefault(customer, {"customer_ref": customer, "first_revenue_at": at, "revenue_to_date": Decimal("0"), "mrr": Decimal("0"), "churned": False, "pipeline": False, "partner": False, "source_digests": []})
        row["first_revenue_at"] = min(str(row["first_revenue_at"]), at)
        row["revenue_to_date"] += amount
        row["mrr"] += mrr
        row["churned"] = row["churned"] or churned
        row["pipeline"] = row["pipeline"] or pipeline
        row["source_digests"].append(digest)

    for plan_doc, state_doc in revenue_states:
        source_plan, state = REVENUE_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        _require(source_plan.company_ref == parsed_plan.company_ref and state.scope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"revenue case {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if ledger.settled_amount <= 0 or ledger.settled_at is None or parsed(str(ledger.settled_at)) > parsed(stamp):
            continue
        customer = _customer_of(ledger.to_dict())
        if customer is None:
            continue
        seen(customer, str(ledger.settled_at), Decimal(str(ledger.settled_amount)), state.state_digest, pipeline=ledger.prospect_ref is not None)
    for plan_doc, state_doc in subscription_states:
        source_plan, state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        _require(getattr(source_plan, "company_ref", parsed_plan.company_ref) == parsed_plan.company_ref and state.scope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"subscription {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        cash = Decimal(str(ledger.cash_settled_to_date))
        started = ledger.activated_at or ledger.settled_at or ledger.issued_at
        if cash <= 0 or started is None or parsed(str(started)) > parsed(stamp):
            continue
        customer = _customer_of(ledger.to_dict())
        if customer is None:
            continue
        live = state.status not in ("cancelled", "written_off", "trial_lapsed")
        seen(customer, str(started), cash, state.state_digest, mrr=Decimal(str(ledger.mrr)) if live else Decimal("0"), churned=not live)
    partner_customers: set[str] = set()
    for plan_doc, state_doc in commission_states:
        from lightbulb.partner_commission_chain import PARTNER_COMMISSION_LIFECYCLE

        _source_plan, state = PARTNER_COMMISSION_LIFECYCLE.bind(plan_doc, state_doc)
        digests.append(state.state_digest)
        for key in ("attributed_case_refs", "case_refs", "attributed_customers"):
            for ref in tuple(getattr(state.ledger, key, ()) or ()):
                partner_customers.add(str(ref))
    attributed: dict[str, str] = {}
    if attribution is not None:
        from lightbulb.conversion_attribution import verify_attribution

        ledger = verify_attribution(attribution)
        _require(ledger.company_ref == parsed_plan.company_ref, "ATTRIBUTION_SCOPE_MISMATCH", "the attribution ledger belongs to another company")
        digests.append(stable_digest(ledger.to_dict()))
        touches = {touch.touch_digest: touch for touch in ledger.touches}
        conversions = {item.conversion_digest: item for item in ledger.conversions}
        for credit in ledger.credits:
            conversion = conversions.get(credit.conversion_digest)
            touch = touches.get(credit.touch_digest)
            if conversion is None or touch is None:
                continue
            attributed.setdefault(conversion.unit_commitment, str(touch.channel))
        # an attributed conversion is a customer with settled revenue in its own right (a replayed economic source)
        for conversion in ledger.conversions:
            if parsed(conversion.occurred_at) > parsed(stamp):
                continue
            customer = _customer_of(dict(dict(conversion.source_state).get("ledger") or {})) or conversion.unit_commitment
            if _unit_commitment(customer) != conversion.unit_commitment:
                customer = conversion.unit_commitment
            seen(customer, conversion.occurred_at, Decimal(str(conversion.value)), conversion.conversion_digest)
    for row in customers.values():
        unit = _unit_commitment(str(row["customer_ref"]))
        if unit in attributed:
            row["channel"], row["channel_basis"] = attributed[unit], "attributed_touch"
        elif str(row["customer_ref"]) in partner_customers or any(digest in partner_customers for digest in row["source_digests"]):
            row["channel"], row["channel_basis"] = "partner", "partner_commission"
        elif row["pipeline"]:
            row["channel"], row["channel_basis"] = "outbound", "pipeline_prospect"
        else:
            row["channel"], row["channel_basis"] = "unattributed", "unattributed"
        row["cohort"] = _month(str(row["first_revenue_at"]))
    # channel cost per cohort month from the replayed registers
    cost: dict[tuple[str, str], Decimal] = {}
    cost_refs: dict[tuple[str, str], list[str]] = {}
    unassigned = Decimal("0")
    unassigned_refs: list[str] = []
    for plan_doc, state_doc in register_states:
        register_map, register = COST_REGISTER_LIFECYCLE.bind(plan_doc, state_doc)
        _require(register_map.company_ref == parsed_plan.company_ref and register_map.currency == parsed_plan.currency, "REGISTER_SCOPE_MISMATCH", f"register {register.scope.entity_ref} belongs to another company or currency")
        digests.append(register.state_digest)
        for source in register.ledger.sources:
            if source.source_kind not in COST_SOURCE_KINDS:
                continue
            amount = Decimal(str(source.spend_amount)) if Decimal(str(source.spend_amount)) > 0 else Decimal(str(source.amount))
            if amount <= 0:
                continue
            channel = parsed_plan.channel_for_centre(str(source.centre_ref))
            month = _month(str(source.recorded_at))
            if channel is None:
                unassigned += amount
                unassigned_refs.append(str(source.source_ref))
                continue
            cost[(month, channel)] = cost.get((month, channel), Decimal("0")) + amount
            cost_refs.setdefault((month, channel), []).append(str(source.source_ref))
    # cohort rows: every (cohort, channel) that has customers or cost
    keys = sorted({(str(row["cohort"]), str(row["channel"])) for row in customers.values()} | set(cost))
    margin = parsed_plan.contribution_margin_percent / _HUNDRED
    rows: list[dict[str, Any]] = []
    for cohort, channel in keys:
        members = [row for row in customers.values() if row["cohort"] == cohort and row["channel"] == channel]
        count = len(members)
        churned = sum(1 for row in members if row["churned"])
        months = _months_between(f"{cohort}-01T00:00:00Z", stamp)
        acquisition = _money(cost.get((cohort, channel), Decimal("0")))
        revenue = _money(sum((row["revenue_to_date"] for row in members), Decimal("0")))
        contribution = _money(revenue * margin)
        mrr = _money(sum((row["mrr"] for row in members), Decimal("0")))
        cac = _money(acquisition / count) if count and acquisition > 0 else None
        payback = None
        if count and acquisition > 0:
            monthly = contribution / Decimal(max(months, 1))
            payback = int((acquisition / monthly).to_integral_value(rounding=ROUND_UP)) if monthly > 0 else None
        churn = None
        if count and months > 0:
            churn = (Decimal(churned) / Decimal(count) / Decimal(months) * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)
        ltv = None
        if count:
            if mrr > 0:
                expected_months = Decimal(parsed_plan.lifetime_horizon_months) if not churn or churn <= 0 else min(Decimal(parsed_plan.lifetime_horizon_months), _HUNDRED / churn)
                ltv = _money((contribution + mrr * margin * expected_months) / count)
            else:
                ltv = _money(contribution / count)
        rows.append({"cohort": cohort, "channel": channel, "customers": count, "churned": churned, "months_observed": months, "acquisition_cost": str(acquisition), "revenue_to_date": str(revenue), "contribution_to_date": str(contribution), "mrr": str(mrr), "cac": None if cac is None else str(cac), "payback_months": payback, "payback_met": None if payback is None else payback <= parsed_plan.payback_target_months, "monthly_churn_percent": None if churn is None else str(churn), "lifetime_value": None if ltv is None else str(ltv), "ltv_cac": None if ltv is None or not cac else str(_money(ltv / cac)), "cost_source_refs": sorted(cost_refs.get((cohort, channel), []))})
    ranking_scores: dict[str, tuple[Decimal, Decimal]] = {}
    for row in rows:
        if row["ltv_cac"] is not None:
            score = ranking_scores.setdefault(str(row["channel"]), (Decimal("0"), Decimal("0")))
            ranking_scores[str(row["channel"])] = (score[0] + Decimal(str(row["ltv_cac"])) * Decimal(int(row["customers"])), score[1] + Decimal(int(row["customers"])))
    ranking = sorted(ranking_scores, key=lambda channel: (-(ranking_scores[channel][0] / ranking_scores[channel][1]), channel))
    people = sorted(({"customer_ref": row["customer_ref"], "channel": row["channel"], "channel_basis": row["channel_basis"], "cohort": row["cohort"], "first_revenue_at": row["first_revenue_at"], "revenue_to_date": str(_money(row["revenue_to_date"])), "mrr": str(_money(row["mrr"])), "churned": bool(row["churned"]), "source_digests": sorted(set(row["source_digests"]))} for row in customers.values()), key=lambda row: (str(row["cohort"]), str(row["channel"]), str(row["customer_ref"])))
    return seal(ChannelCohortReport, {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": stamp, "plan_digest": parsed_plan.plan_digest, "customers": people, "cohorts": rows, "channel_ranking": ranking, "unassigned_cost": str(_money(unassigned)), "unassigned_cost_refs": sorted(set(unassigned_refs)), "source_digests": sorted(set(digests))}, "report_digest")


CHANNEL_COHORT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_channel_cohorts",
    "golden_loop": "growth.store_truth_to_attributed_revenue@0.1.0",
    "stages": ["replay_customers", "assign_channels", "cost_channels_from_registers", "seal_cohorts"],
    "channels": list(ACQUISITION_CHANNELS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a customer's channel is the attribution ledger's credited touch, else how the case was won; a name typed by an operator never assigns a channel",
        "a channel's cost is the replayed register's sources in the centres the plan assigns to it; outbound costs what its people cost",
        "payback and lifetime value are computed from settled cash, the plan's sealed margin, and observed churn; nothing is projected beyond the plan's horizon",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["ACQUISITION_CHANNELS", "CHANNEL_COHORT_MANIFEST", "CHANNEL_COHORT_PLAN_SCHEMA", "CHANNEL_COHORT_REPORT_SCHEMA", "COST_SOURCE_KINDS", "ChannelCentres", "ChannelCohort", "ChannelCohortError", "ChannelCohortPlan", "ChannelCohortReport", "CohortCustomer", "build_channel_cohorts", "compile_channel_cohort_plan"]
