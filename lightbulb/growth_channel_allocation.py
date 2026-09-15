"""Allocate by payback: turn the deployable growth spend into a monthly budget per acquisition channel from the sealed cohort table.

The funding gate says how much incremental monthly burn the runway affords
and the cohort table says what each channel earns back; nothing joined
them.  ``build_channel_allocation`` does, from sealed documents only:

* the deployable amount is the funding gate's ``deployable_monthly`` when
  the gate permits deployment, else the budget envelope's affordable
  incremental monthly burn; the allocation names which and refuses to
  spend when neither affords anything;
* a channel is eligible when some cohort has met the plan's payback target,
  its CAC is known, and its LTV/CAC clears the plan's floor; every excluded
  channel carries its reason;
* eligible channels share the deployable amount in proportion to LTV/CAC,
  capped at the plan's maximum share, and what the caps leave stays
  unallocated rather than forced into a weaker channel.

``allocation_actions`` turns each line into a proposed
``adjust_channel_budget`` action bound to the sealed allocation, and
``authorize_allocation`` puts every action through the growth mandate so
the per-action and window limits still hold.  Nothing here reads a
provider, persists anything, or moves a budget: the allocation is the
proposal, the mandate is the authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
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
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

CHANNEL_ALLOCATION_PLAN_SCHEMA = "lightbulb.channel_allocation_plan.v1"
CHANNEL_ALLOCATION_SCHEMA = "lightbulb.channel_allocation.v1"
ALLOCATION_VERDICTS: tuple[str, ...] = ("allocated", "nothing_deployable", "no_eligible_channel")
DEPLOYABLE_BASES: tuple[str, ...] = ("funding_gate", "budget_envelope")
AllocationVerdict = Literal["allocated", "nothing_deployable", "no_eligible_channel"]
DeployableBasis = Literal["funding_gate", "budget_envelope"]
_HUNDRED = Decimal("100")
_RATE_QUANTUM = Decimal("0.01")


class ChannelAllocationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ChannelAllocationError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ChannelAllocationPlan(StrictModel):
    """The eligibility floors and the share cap, sealed so every reader allocates the same way."""

    schema_id: str = Field(default=CHANNEL_ALLOCATION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    min_ltv_cac: Decimal = Field(default=Decimal("3"), validate_default=True)
    max_share_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    min_monthly_budget: Decimal = Field(default=Decimal("0"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("min_ltv_cac", "max_share_percent", "min_monthly_budget", mode="before")
    @classmethod
    def _bounds(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if info.field_name == "max_share_percent" and (result <= 0 or result > _HUNDRED):
            raise ValueError("the maximum share is a percentage above 0 and up to 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChannelAllocationPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ChannelAllocationPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_channel_allocation_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ChannelAllocationPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(ChannelAllocationPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Allocation
# --------------------------------------------------------------------------- #


class ChannelBudgetLine(StrictModel):
    channel: ShortText
    monthly_budget: Decimal
    share_percent: Decimal
    capped: bool
    cac: Decimal
    ltv_cac: Decimal
    payback_months: int = Field(ge=0)
    cohorts_met_payback: int = Field(ge=1)
    customers: int = Field(ge=0)

    @field_validator("monthly_budget", "share_percent", "cac", "ltv_cac", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ExcludedChannel(StrictModel):
    channel: ShortText
    reason: ShortText


class ChannelAllocation(StrictModel):
    schema_id: str = Field(default=CHANNEL_ALLOCATION_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    allocation_ref: OpaqueRef
    cohort_report_digest: Sha256Digest
    deployable_basis: DeployableBasis
    deployable_source_digest: Sha256Digest | None = None
    deployable_monthly: Decimal
    lines: tuple[ChannelBudgetLine, ...] = Field(default_factory=tuple, max_length=13)
    excluded: tuple[ExcludedChannel, ...] = Field(default_factory=tuple, max_length=13)
    allocated_monthly: Decimal
    unallocated_monthly: Decimal
    verdict: AllocationVerdict
    assumptions: dict[str, str] = Field(default_factory=dict)
    allocation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "excluded", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("deployable_monthly", "allocated_monthly", "unallocated_monthly", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ChannelAllocation":
        if sum((item.monthly_budget for item in self.lines), Decimal("0")).quantize(MONEY_QUANTUM) != self.allocated_monthly:
            raise ValueError("allocated_monthly must equal the lines")
        if (self.allocated_monthly + self.unallocated_monthly).quantize(MONEY_QUANTUM) != self.deployable_monthly:
            raise ValueError("allocated and unallocated must sum to the deployable amount")
        if not skip_digests(info) and self.allocation_digest != sealed_digest(ChannelAllocation, self, "allocation_digest"):
            raise ValueError("allocation_digest must commit the exact allocation")
        return self

    def line(self, channel: str) -> ChannelBudgetLine | None:
        return next((item for item in self.lines if item.channel == channel), None)

    def render(self) -> str:
        lines = [f"**Channel allocation {self.company_ref}** as of {self.as_of[:10]}: {self.verdict}; {self.deployable_monthly} {self.currency} a month deployable ({self.deployable_basis}), {self.allocated_monthly} allocated, {self.unallocated_monthly} left."]
        for item in self.lines:
            lines.append(f"- {item.channel}: {item.monthly_budget} ({item.share_percent}%{', capped' if item.capped else ''}); CAC {item.cac}, LTV/CAC {item.ltv_cac}, payback {item.payback_months} month(s)")
        for item in self.excluded:
            lines.append(f"- {item.channel}: excluded, {item.reason}")
        return "\n".join(lines)


def _deployable(plan: ChannelAllocationPlan, funding_gate: Any, budget_envelope: Any) -> tuple[Decimal, str, str | None]:
    _require((funding_gate is None) != (budget_envelope is None), "DEPLOYABLE_AMBIGUOUS" if funding_gate is not None and budget_envelope is not None else "DEPLOYABLE_MISSING", "exactly one of funding_gate or budget_envelope says what is deployable")
    if funding_gate is not None:
        from lightbulb.business_allocation import ObjectiveFundingGate

        gate = funding_gate if isinstance(funding_gate, ObjectiveFundingGate) else ObjectiveFundingGate.model_validate(dict(detached(funding_gate)))
        _require(gate.currency == plan.currency, "SOURCE_SCOPE_MISMATCH", f"the funding gate is in {gate.currency}, not {plan.currency}")
        amount = gate.deployable_monthly if gate.verdict == "deploy_permitted" and gate.deployable_monthly is not None else Decimal("0")
        return _money(amount), "funding_gate", gate.gate_digest
    from lightbulb.cash_runway import CashBudgetEnvelope

    envelope = budget_envelope if isinstance(budget_envelope, CashBudgetEnvelope) else CashBudgetEnvelope.model_validate(dict(detached(budget_envelope)))
    _require(envelope.currency == plan.currency, "SOURCE_SCOPE_MISMATCH", f"the budget envelope is in {envelope.currency}, not {plan.currency}")
    amount = envelope.affordable_incremental_monthly_burn if envelope.status in {"healthy_surplus", "not_burning"} and envelope.affordable_incremental_monthly_burn is not None else Decimal("0")
    return _money(max(Decimal("0"), amount)), "budget_envelope", envelope.runway_digest


def build_channel_allocation(plan: ChannelAllocationPlan | Mapping[str, Any], *, cohorts: Mapping[str, Any] | Any, as_of: str, allocation_ref: str, funding_gate: Mapping[str, Any] | Any | None = None, budget_envelope: Mapping[str, Any] | Any | None = None) -> ChannelAllocation:
    """The sealed monthly budget per channel from the sealed cohort table and one deployable amount."""

    from lightbulb.growth_channel_cohorts import ChannelCohortReport

    parsed_plan = plan if isinstance(plan, ChannelAllocationPlan) else ChannelAllocationPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    report = cohorts if isinstance(cohorts, ChannelCohortReport) else ChannelCohortReport.model_validate(dict(detached(cohorts)))
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the cohort report names another company or currency")
    deployable, basis, source_digest = _deployable(parsed_plan, funding_gate, budget_envelope)
    channels: dict[str, list[Any]] = {}
    for row in report.cohorts:
        channels.setdefault(row.channel, []).append(row)
    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for channel in sorted(channels):
        rows = channels[channel]
        cost = sum((row.acquisition_cost for row in rows), Decimal("0"))
        customers = sum(row.customers for row in rows)
        met = [row for row in rows if row.payback_met]
        ltv_rows = [row for row in rows if row.lifetime_value is not None]
        if not cost or not customers:
            excluded.append({"channel": channel, "reason": "no known acquisition cost or no customers, so no CAC"})
            continue
        if not met:
            excluded.append({"channel": channel, "reason": "no cohort has met the payback target"})
            continue
        ltv = sum((row.lifetime_value for row in ltv_rows), Decimal("0"))
        ltv_cac = _rate(ltv / cost)
        if ltv_cac < parsed_plan.min_ltv_cac:
            excluded.append({"channel": channel, "reason": f"LTV/CAC {ltv_cac} is below the {parsed_plan.min_ltv_cac} floor"})
            continue
        eligible.append({"channel": channel, "cac": _money(cost / customers), "ltv_cac": ltv_cac, "payback_months": max(int(row.payback_months or 0) for row in met), "cohorts_met_payback": len(met), "customers": customers})
    lines: list[dict[str, Any]] = []
    if deployable <= 0:
        verdict = "nothing_deployable"
    elif not eligible:
        verdict = "no_eligible_channel"
    else:
        verdict = "allocated"
        cap = _money(deployable * parsed_plan.max_share_percent / _HUNDRED)
        budgets = {item["channel"]: Decimal("0") for item in eligible}
        capped: set[str] = set()
        remaining = deployable
        for _ in range(len(eligible)):
            open_items = [item for item in eligible if item["channel"] not in capped]
            weight = sum((item["ltv_cac"] for item in open_items), Decimal("0"))
            if remaining <= 0 or not open_items or weight <= 0:
                break
            newly = False
            for item in open_items:
                proposed = budgets[item["channel"]] + remaining * item["ltv_cac"] / weight
                if proposed > cap:
                    budgets[item["channel"]] = cap
                    capped.add(item["channel"])
                    newly = True
            if not newly:
                for item in open_items:
                    budgets[item["channel"]] = _money(budgets[item["channel"]] + remaining * item["ltv_cac"] / weight)
                break
            remaining = deployable - sum((budgets[name] for name in capped), Decimal("0"))
            for item in open_items:
                if item["channel"] not in capped:
                    budgets[item["channel"]] = Decimal("0")
        for item in eligible:
            budget = _money(budgets[item["channel"]])
            if budget < parsed_plan.min_monthly_budget:
                excluded.append({"channel": item["channel"], "reason": f"allocated {budget} is below the {parsed_plan.min_monthly_budget} minimum"})
                continue
            lines.append({**item, "cac": str(item["cac"]), "ltv_cac": str(item["ltv_cac"]), "monthly_budget": str(budget), "share_percent": str(_rate(budget / deployable * _HUNDRED)), "capped": item["channel"] in capped})
        if not lines:
            verdict = "no_eligible_channel"
    allocated = _money(sum((Decimal(item["monthly_budget"]) for item in lines), Decimal("0")))
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "allocation_ref": allocation_ref,
        "cohort_report_digest": report.report_digest, "deployable_basis": basis, "deployable_source_digest": source_digest, "deployable_monthly": str(deployable),
        "lines": lines, "excluded": excluded, "allocated_monthly": str(allocated), "unallocated_monthly": str(_money(deployable - allocated)), "verdict": verdict,
        "assumptions": {"min_ltv_cac": str(parsed_plan.min_ltv_cac), "max_share_percent": str(parsed_plan.max_share_percent), "min_monthly_budget": str(parsed_plan.min_monthly_budget)},
    }
    return seal(ChannelAllocation, payload, "allocation_digest")


def verify_channel_allocation(value: Any) -> ChannelAllocation:
    return value if isinstance(value, ChannelAllocation) else ChannelAllocation.model_validate(dict(detached(value)))


def _portable(value: str) -> str:
    """A mandate-side ref: lower-case, letters, digits, underscore, and hyphen only, starting with a letter."""

    cleaned = re.sub(r"[^a-z0-9_-]+", "-", value.lower()).strip("-")
    return (cleaned if cleaned[:1].isalpha() else f"a-{cleaned}")[:64].rstrip("-")


def allocation_actions(allocation: ChannelAllocation | Mapping[str, Any]) -> list[dict[str, Any]]:
    """One proposed ``adjust_channel_budget`` action per line, bound to the sealed allocation, for the growth mandate to decide."""

    verified = verify_channel_allocation(allocation)
    return [
        {"action_ref": _portable(f"{verified.allocation_ref}-{item.channel}"), "action_kind": "adjust_channel_budget", "amount": str(item.monthly_budget), "currency": verified.currency, "description": f"Set the {item.channel} monthly budget to {item.monthly_budget} {verified.currency} from allocation {verified.allocation_ref} (LTV/CAC {item.ltv_cac}, payback {item.payback_months} month(s)).", "plan_digest": verified.allocation_digest}
        for item in verified.lines
    ]


def authorize_allocation(allocation: ChannelAllocation | Mapping[str, Any], *, mandate: Mapping[str, Any] | Any, scope: Any, scope_keyring: Any, as_of: str, prior_authorizations: Sequence[Any] = (), current_economics: Any = None, objective: Any = None) -> list[Any]:
    """Every action through the growth mandate in line order; each receipt counts toward the next one's window."""

    from lightbulb.growth_mandate import ActionAuthorization, authorize_growth_action

    verified = verify_channel_allocation(allocation)
    priors = [item.to_dict() if isinstance(item, ActionAuthorization) else dict(detached(item)) for item in prior_authorizations]
    receipts: list[Any] = []
    for action in allocation_actions(verified):
        inputs: dict[str, Any] = {"as_of": as_of, "authorization_ref": _portable(f"{action['action_ref']}-{str(as_of)[:10]}"), "mandate": detached(mandate), "action": action, "prior_authorizations": tuple(priors)}
        if current_economics is not None:
            inputs["current_economics"] = detached(current_economics)
        if objective is not None:
            inputs["objective"] = detached(objective)
        receipt = authorize_growth_action(inputs, scope=scope, scope_keyring=scope_keyring)
        receipts.append(receipt)
        priors.append(receipt.to_dict())
    return receipts


CHANNEL_ALLOCATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_channel_allocation",
    "golden_loop": "growth.attributed_revenue_to_next_tranche@0.1.0",
    "stages": ["verify_cohorts", "resolve_deployable", "screen_channels", "share_by_ltv_cac", "seal_allocation"],
    "verdicts": list(ALLOCATION_VERDICTS),
    "deployable_bases": list(DEPLOYABLE_BASES),
    "required_connectors": [],
    "hard_rules": [
        "the deployable amount is the funding gate's or the budget envelope's; the allocation never invents capacity",
        "a channel earns budget only after a cohort has paid back and its LTV/CAC clears the floor; every exclusion carries its reason",
        "shares are capped and the remainder stays unallocated rather than forced into a weaker channel",
        "every line is a proposed action for the growth mandate; nothing here moves a budget",
    ],
}

__all__ = ["ALLOCATION_VERDICTS", "CHANNEL_ALLOCATION_MANIFEST", "CHANNEL_ALLOCATION_PLAN_SCHEMA", "CHANNEL_ALLOCATION_SCHEMA", "DEPLOYABLE_BASES", "ChannelAllocation", "ChannelAllocationError", "ChannelAllocationPlan", "ChannelBudgetLine", "ExcludedChannel", "allocation_actions", "authorize_allocation", "build_channel_allocation", "compile_channel_allocation_plan", "verify_channel_allocation"]
