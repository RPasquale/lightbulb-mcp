"""The cost register: one place where every dollar a company spent is attributed exactly once.

Total spend was the softest number in the runtime.  ``record_evidence``
defaulted spend to zero and no builder produced it; a worker's
``cost_this_period`` never left the worker ledger; the payables chain bound
bills to a five-tuple of engines, so rent, software, insurance and
professional fees never reached a period at all; the revenue chain booked
every settled case against ``pipeline_engine``; the operating period kept no
evidence references, so one case could fund a period twice; and a campaign
was opened with the whole envelope budget with no sibling check.

``COST_REGISTER_LIFECYCLE`` is one register per company per operating period:

    open -> attributing -> coverage_asserted -> closed     (terminal)
    open | attributing | coverage_asserted -> abandoned     (terminal)

Every ``record_source`` consumes the sealed artifact of the hop that proved
the money left - a paid or cleared ``PayableCaseState``, a cleared spend
control case, a ``WorkerState`` carrying the period's agent cost, a sealed
``MeteredDispatch``, a media invoice paid to an ad platform, or a settled
revenue chain case for the revenue side - and the register keeps the state
digest *and* the stable source reference of each, so the same dollar can
never arrive twice, at a later version or under a second centre.

What it hands to other engines: ``period_evidence_receipt`` gives the
company operating system a ``record_evidence`` receipt with a real spend
figure and the engine taken from the sealed :class:`CostCentreMap` (not a
hardcoded one); ``attributed_revenue_signal`` and
``envelope_exhausted_signal`` are the two signals ``SIGNAL_SPECS`` declares
``growth_engine`` produces and nothing built; ``overhead_rollup`` gives
treasury derived ``ScheduledFlow(kind='fixed_cost')`` rows instead of a
typed fixed-cost schedule; ``spend_coverage`` proves how much of the bank's
reconciled cash out the register actually attributed; ``portfolio_capacity``
is the sibling check a campaign envelope never had.

Nothing here reads a provider, writes anything, or estimates a cost: a
merchant with no centre is refused rather than dropped; platform reported
media spend is a claim until an invoice-proven payable backs it; a media
source that names an envelope must carry that envelope's sealed sibling
verdict, so the approval gate is not a keyword a caller can omit; and agent
labour arrives through one lane per register, because a worker rollup
aggregates the same dispatches a metering trace names one at a time and no
sealed artifact proves the two are disjoint.
"""

from __future__ import annotations

import re
import importlib
import json
from copy import deepcopy
from functools import lru_cache
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_dispatch_metering import MeteredDispatch, MeteringError, outcome_receipt
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    EngineScope,
    LifecycleSpec,
    Rejected,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    percent_value,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_operating_system import ENGINE_KINDS, CompanySignal, EngineKind
from lightbulb.company_treasury import ScheduledFlow

COST_REGISTER_KIND = "company_cost_centres"
COST_REGISTER_GOLDEN_LOOP = "company.blueprint_to_governed_operating_cadence@0.1.0"
COST_CENTRE_MAP_SCHEMA = "lightbulb.company_cost_centre_map.v1"
OVERHEAD_ROLLUP_SCHEMA = "lightbulb.company_overhead_rollup.v1"
SPEND_COVERAGE_SCHEMA = "lightbulb.company_spend_coverage.v1"
PORTFOLIO_CAPACITY_SCHEMA = "lightbulb.company_portfolio_capacity.v1"
PAYABLE_STATE_SCHEMA = "lightbulb.payables_chain_state.v1"
WORKER_STATE_SCHEMA = "lightbulb.workforce_worker_state.v1"
CAMPAIGN_STATE_SCHEMA = "lightbulb.growth_campaign_state.v1"
REGISTER_STATE_SCHEMA = "lightbulb.company_cost_register_state.v1"
MAX_REGISTER_TRANSITIONS = 512
_HUNDRED = Decimal("100")
_REF_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")

DEFAULT_OVERHEAD_CATEGORIES: tuple[str, ...] = ("rent", "software", "professional_fees", "insurance", "bank_charges", "freight", "other")
CentreKind = Literal["engine", "overhead", "labour"]
SourceKind = Literal["channel_spend", "job_case", "inference_cost", "payable", "spend_case", "worker", "metered_dispatch", "media_invoice", "revenue_case", "payroll", "subscription_case", "storefront_batch", "marketplace_transaction", "refund_case"]
SOURCE_KINDS: tuple[str, ...] = ("channel_spend", "job_case", "inference_cost", "payable", "spend_case", "worker", "metered_dispatch", "media_invoice", "revenue_case", "payroll", "subscription_case", "storefront_batch", "marketplace_transaction", "refund_case")
CASH_SOURCE_KINDS: frozenset[str] = frozenset({"payable", "spend_case", "media_invoice", "payroll"})
REVENUE_STATE_SCHEMAS: tuple[str, ...] = ("lightbulb.job_chain_state.v1", "lightbulb.revenue_chain_state.v1", "lightbulb.subscription_chain_state.v1", "lightbulb.storefront_settlement_state.v1", "lightbulb.marketplace_supply_transaction_state.v1")
SETTLED_REVENUE_STATUSES: frozenset[str] = frozenset({"cash_settled", "receivable_cleared", "revenue_recognized", "payout_settled", "net_revenue_recorded", "reconciled", "settled", "cleared"})

REGISTER_STATUSES: tuple[str, ...] = ("open", "attributing", "coverage_asserted", "closed", "abandoned")
TERMINAL_REGISTER_STATUSES: frozenset[str] = frozenset({"closed", "abandoned"})
REGISTER_EVENTS: tuple[str, ...] = ("open_register", "record_source", "record_return", "assert_coverage", "close_register", "abandon")
_REGISTER_TABLE: dict[tuple[str, str], str] = {
    ("new", "open_register"): "open",
    ("open", "record_source"): "attributing",
    ("attributing", "record_source"): "attributing",
    ("attributing", "record_return"): "attributing",
    ("open", "assert_coverage"): "coverage_asserted",
    ("attributing", "assert_coverage"): "coverage_asserted",
    ("coverage_asserted", "record_source"): "attributing",
    ("coverage_asserted", "record_return"): "attributing",
    ("coverage_asserted", "close_register"): "closed",
    **{(status, "abandon"): "abandoned" for status in ("open", "attributing", "coverage_asserted")},
}


# --------------------------------------------------------------------------- #
# The map: which centre owns which cost (an explicit operator input, sealed)
# --------------------------------------------------------------------------- #


class CostCentre(StrictModel):
    centre_ref: OpaqueRef
    kind: CentreKind
    engine: EngineKind | None = None
    label: ShortText

    @model_validator(mode="after")
    def _guard(self) -> CostCentre:
        if self.kind == "engine" and self.engine is None:
            raise ValueError("an engine cost centre names the engine it belongs to")
        if self.kind == "overhead" and self.engine is not None:
            raise ValueError("an overhead centre is company-wide; it never names an engine")
        return self


class MerchantAttribution(StrictModel):
    """One merchant bound to one centre; the operator states this, nothing infers it."""

    merchant_ref: OpaqueRef
    centre_ref: OpaqueRef


class CostCentreMap(StrictModel):
    """The register's plan: the centres, the overhead categories, and the operator-supplied merchant attribution."""

    schema_id: str = Field(default=COST_CENTRE_MAP_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    period_ref: OpaqueRef
    centres: tuple[CostCentre, ...] = Field(min_length=1, max_length=24)
    overhead_categories: tuple[ShortText, ...] = Field(default=DEFAULT_OVERHEAD_CATEGORIES, min_length=1, max_length=24)
    merchant_map: tuple[MerchantAttribution, ...] = Field(default_factory=tuple, max_length=400)
    merchant_map_source: Literal["operator_supplied"] = "operator_supplied"
    spend_coverage_floor_percent: Decimal = Field(default=Decimal("80.00"), validate_default=True)
    media_variance_tolerance_percent: Decimal = Field(default=Decimal("10.00"), validate_default=True)
    require_invoice_backed_media: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("centres", "overhead_categories", "merchant_map", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("spend_coverage_floor_percent", "media_variance_tolerance_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CostCentreMap:
        unique([item.centre_ref for item in self.centres], label="cost centre refs")
        unique([item.merchant_ref for item in self.merchant_map], label="merchant refs")
        unique(list(self.overhead_categories), label="overhead categories")
        known = {item.centre_ref for item in self.centres}
        for item in self.merchant_map:
            if item.centre_ref not in known:
                raise ValueError(f"merchant {item.merchant_ref} is attributed to unknown centre {item.centre_ref}")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CostCentreMap, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact cost centre map")
        return self

    def centre(self, ref: str) -> CostCentre | None:
        return next((item for item in self.centres if item.centre_ref == ref), None)

    def merchant_centre(self, merchant_ref: str) -> str | None:
        return next((item.centre_ref for item in self.merchant_map if item.merchant_ref == merchant_ref), None)

    def engine_centre(self, engine: str) -> CostCentre | None:
        return next((item for item in self.centres if item.engine == engine), None)


def compile_cost_centres(company_ref: str, *, currency: str, period_ref: str, centres: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> CostCentreMap:
    return seal(CostCentreMap, {"company_ref": company_ref, "currency": currency.upper(), "period_ref": period_ref, "centres": [dict(detached(item)) for item in centres], **dict(overrides or {})}, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipt, ledger, effect boundary
# --------------------------------------------------------------------------- #


class CostSourceReceipt(StrictModel):
    """Retained source plans replay every derived scalar before attribution."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    period_ref: OpaqueRef | None = None
    entity_scope: EngineScope | None = None
    period_start: str | None = None
    period_end: str | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    inference_source: dict[str, Any] | None = None
    media_statement: dict[str, Any] | None = None
    metered_artifact: dict[str, Any] | None = None
    usd_rate: Decimal | None = None
    campaign_state: dict[str, Any] | None = None
    campaign_plan: dict[str, Any] | None = None
    capacity: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None
    refund_source: dict[str, Any] | None = None
    source_kind: SourceKind | None = None
    source_ref: OpaqueRef | None = None
    source_digest: Sha256Digest | None = None
    centre_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    currency: ShortText | None = None
    occurred_at: str | None = None
    engine: ShortText | None = None
    category: ShortText | None = None
    merchant_ref: OpaqueRef | None = None
    supplier_ref: OpaqueRef | None = None
    operator_supplied: bool | None = None
    dispatch_count: int | None = Field(default=None, ge=0, le=100000)
    campaign_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    envelope_ref: OpaqueRef | None = None
    reported_spend: Decimal | None = None
    invoice_backed: bool | None = None
    capacity_digest: Sha256Digest | None = None
    envelope_oversubscribed: bool | None = None
    against_source_digest: Sha256Digest | None = None
    coverage_digest: Sha256Digest | None = None
    source_state_digest: Sha256Digest | None = None
    attributed_cash_out: Decimal | None = None
    reconciled_cash_out: Decimal | None = None
    coverage_percent: Decimal | None = None
    unattributed_merchants: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    reconciliation_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "campaign_refs", "unattributed_merchants", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", "usd_rate", "reported_spend", "attributed_cash_out", "reconciled_cash_out", "coverage_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("occurred_at", "period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class RecordedSource(StrictModel):
    """One dollar-carrying artifact this register already consumed; the fence against double counting."""

    source_kind: SourceKind
    source_ref: OpaqueRef
    source_digest: Sha256Digest
    primary_source_ref: OpaqueRef
    media_account_ref: OpaqueRef | None = None
    media_window_start: str | None = None
    media_window_end: str | None = None
    media_document_digest: Sha256Digest | None = None
    inference_bill_ref: OpaqueRef | None = None
    inference_register_digest: Sha256Digest | None = None
    centre_ref: OpaqueRef
    centre_kind: CentreKind
    engine: str | None = None
    category: str | None = None
    campaign_ref: str | None = None
    cash: bool = False
    amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    spend_amount: Decimal = Decimal("0.00")
    revenue_amount: Decimal = Decimal("0.00")
    cash_amount: Decimal = Decimal("0.00")
    cash_source_digests: tuple[Sha256Digest, ...] = ()
    returned: Decimal = Field(default=Decimal("0"), validate_default=True)
    returned_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    recorded_at: str | None = None

    @field_validator("returned_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", "spend_amount", "revenue_amount", "cash_amount", "returned", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class CostRegisterLedger(StrictModel):
    entity_scope: EngineScope | None = None
    company_ref: OpaqueRef | None = None
    bound_engines: tuple[EngineKind, ...] = ()
    period_ref: str | None = None
    currency: str | None = None
    opened_at: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    sources: tuple[RecordedSource, ...] = Field(default_factory=tuple, max_length=MAX_REGISTER_TRANSITIONS)
    sources_recorded: int = Field(default=0, ge=0)
    engine_spend: dict[str, Decimal] = Field(default_factory=dict)
    engine_revenue: dict[str, Decimal] = Field(default_factory=dict)
    overhead_spend: dict[str, Decimal] = Field(default_factory=dict)
    campaign_media_spend: dict[str, Decimal] = Field(default_factory=dict)
    campaigns_with_shared_media: tuple[str, ...] = Field(default_factory=tuple)
    labour_spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    media_spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    media_reported_spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    returns_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    attributed_cash_out: Decimal = Field(default=Decimal("0"), validate_default=True)
    reconciled_cash_out: Decimal = Field(default=Decimal("0"), validate_default=True)
    coverage_percent: Decimal | None = None
    coverage_digest: str | None = None
    reconciliation_ref: str | None = None
    unattributed_merchants: tuple[str, ...] = Field(default_factory=tuple)
    coverage_asserted_at: str | None = None
    closed_at: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "closed", "abandoned"] = "open"

    @field_validator("labour_spend", "media_spend", "media_reported_spend", "returns_value", "attributed_cash_out", "reconciled_cash_out", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("coverage_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="coverage_percent")

    @field_validator("engine_spend", "engine_revenue", "overhead_spend", "campaign_media_spend", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=str(info.field_name)) for key, item in dict(value or {}).items()}

    @property
    def source_digests(self) -> tuple[str, ...]:
        """The uniqueness fence: every state digest this register has already consumed."""

        return tuple(item.source_digest for item in self.sources)

    @property
    def source_refs(self) -> tuple[str, ...]:
        return tuple(item.source_ref for item in self.sources)

    @property
    def total_spend(self) -> Decimal:
        return sum((item.spend_amount for item in self.sources), Decimal("0")).quantize(MONEY_QUANTUM)

    @property
    def total_revenue(self) -> Decimal:
        return sum((value for value in self.engine_revenue.values()), Decimal("0")).quantize(MONEY_QUANTUM)


class CostRegisterEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_spent: Literal[False] = False
    journal_posted: Literal[False] = False
    budget_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _add(current: Any, amount: Decimal) -> Decimal:
    return (Decimal(str(current or "0")) + amount).quantize(MONEY_QUANTUM)


#: A coverage assertion describes one exact register state.  The moment another
#: dollar lands (or comes back), the asserted percentage no longer describes the
#: register, so the register drops it rather than leaving a stale number for the
#: ``coverage`` verb to read.  ``step`` filters None keys, so these reset to their
#: ledger defaults.
_COVERAGE_CLEARED: dict[str, Any] = {"coverage_percent": None, "coverage_digest": None, "coverage_asserted_at": None, "reconciled_cash_out": None, "reconciliation_ref": None, "unattributed_merchants": None}


def _bump(bucket: dict[str, Any], key: str, amount: Decimal) -> None:
    total = _add(bucket.get(key), amount)
    bucket[key] = str(total)


def _apply_register(plan: CostCentreMap, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "open_register":
        require(r.period_ref is not None and r.period_ref == plan.period_ref, "PERIOD_MISMATCH", f"a register opens on the map's operating period {plan.period_ref}")
        require(r.entity_scope is not None and command.expected_state_digest == COST_REGISTER_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SOURCE_SCOPE_MISMATCH", "register opening must retain the actual authenticated scope")
        require(r.period_start is not None and r.period_end is not None and parsed(r.period_start) < parsed(r.period_end), "PERIOD_MISMATCH", "register opening names the actual accounting window")
        data.update({"entity_scope": r.entity_scope.to_dict(), "company_ref": plan.company_ref, "bound_engines": list(dict.fromkeys(item.engine for item in plan.centres if item.engine)), "period_ref": plan.period_ref, "period_start": r.period_start, "period_end": r.period_end, "currency": plan.currency, "opened_at": at})
    elif event == "record_source":
        rows = [dict(detached(item)) for item in data.get("sources", [])]
        require(r.source_kind is not None and r.source_ref is not None and r.source_digest is not None and r.amount is not None, "SOURCE_NOT_PROVEN", "a source names its kind, its reference, the sealed state digest that proved the money moved, and the amount")
        r, derived = _proven_source(plan, data, r, at)
        require(all(row["source_digest"] != r.source_digest for row in rows), "SOURCE_ALREADY_RECORDED", f"the state digest {str(r.source_digest)[:16]} already funded this register", "do_not_replay")
        require(all(row["source_ref"] != r.source_ref for row in rows), "SOURCE_ALREADY_RECORDED", f"{r.source_ref} already funded this register at another version", "do_not_replay")
        require(all(row["primary_source_ref"] != derived["primary_source_ref"] for row in rows), "SOURCE_ALREADY_RECORDED", "the same primary cash source cannot be renamed as another source kind or later status", "do_not_replay")
        require(r.currency is None or str(r.currency).upper() == plan.currency, "CURRENCY_MISMATCH", f"the source is in {r.currency}; the register runs in {plan.currency}")
        require(r.period_ref is None or r.period_ref == plan.period_ref, "PERIOD_MISMATCH", f"the source belongs to period {r.period_ref}, not {plan.period_ref}")
        centre = plan.centre(str(r.centre_ref)) if r.centre_ref is not None else None
        require(centre is not None, "CENTRE_UNKNOWN", f"{r.centre_ref} is not a centre in this cost centre map")
        assert centre is not None
        if r.source_kind == "spend_case":
            require(r.merchant_ref is not None, "MERCHANT_UNATTRIBUTED", "a card charge names the merchant it paid")
            mapped = plan.merchant_centre(str(r.merchant_ref))
            require(mapped is not None, "MERCHANT_UNATTRIBUTED", f"{r.merchant_ref} has no cost centre in the sealed map; extend the map rather than dropping the charge")
            require(mapped == centre.centre_ref, "MERCHANT_UNATTRIBUTED", f"the map attributes {r.merchant_ref} to {mapped}, not {centre.centre_ref}")
        if r.engine is not None:
            require(str(r.engine) in ENGINE_KINDS, "ENGINE_NOT_BOUND", f"{r.engine} is not an operating engine")
            require(centre.engine == r.engine, "ENGINE_NOT_BOUND", f"the source names {r.engine}; centre {centre.centre_ref} carries {centre.engine or 'no engine'}")
        if derived["revenue_amount"] > 0:
            require(centre.engine is not None, "ENGINE_NOT_BOUND", "revenue is attributed to a centre that names the engine that earned it")
        if centre.kind == "overhead":
            require(r.category is not None and str(r.category) in plan.overhead_categories, "CENTRE_UNKNOWN", f"{r.category} is not an overhead category of this map")
        if r.source_kind in ("channel_spend", "media_invoice"):
            other = "media_invoice" if r.source_kind == "channel_spend" else "channel_spend"
            require(not any(row["source_kind"] == other and row["centre_ref"] == r.centre_ref for row in rows),
                    "MEDIA_SOURCE_OVERLAP", "accrued channel statements and paid media invoices in the same centre cannot be proven disjoint")
        if r.source_kind == "channel_spend":
            for row in rows:
                if row.get("media_account_ref") == derived["media_account_ref"]:
                    require(not (parsed(row["media_window_start"]) < parsed(derived["media_window_end"])
                                 and parsed(derived["media_window_start"]) < parsed(row["media_window_end"])),
                            "SOURCE_ALREADY_RECORDED", "overlapping channel-account spend cannot fund multiple centres")
                require(not derived["media_document_digest"] or row.get("media_document_digest") != derived["media_document_digest"],
                        "SOURCE_ALREADY_RECORDED", "an invoice document cannot be renamed into another spend source")
        if r.source_kind in ("inference_cost", "worker", "metered_dispatch"):
            require(not any((r.source_kind == "inference_cost" and row["source_kind"] in ("worker", "metered_dispatch")) or (r.source_kind in ("worker", "metered_dispatch") and row["source_kind"] == "inference_cost") for row in rows), "LABOUR_SOURCE_OVERLAP", "provider billing and dispatch labour aggregates cannot be proven disjoint", "manual_reconciliation")
        if r.source_kind == "inference_cost":
            require(all(row.get("inference_bill_ref") != derived["inference_bill_ref"] or row.get("inference_register_digest") == derived["inference_register_digest"] for row in rows), "SOURCE_ALREADY_RECORDED", "all allocations of a provider bill must retain the same reconciled register", "do_not_replay")
        if r.source_kind in ("worker", "metered_dispatch"):
            # A worker rollup is an aggregate over that worker's dispatches for the period; a metered
            # dispatch is one of the same population of traces.  Neither artifact carries the dispatch
            # references that would prove the two are disjoint, so one register attributes agent labour
            # through one lane.  The SDK attributes cost, it never estimates the overlap away.
            other = "metered_dispatch" if r.source_kind == "worker" else "worker"
            require(all(row["source_kind"] != other for row in rows), "LABOUR_SOURCE_OVERLAP", f"this register already attributes agent labour from {other} sources; a {r.source_kind} source cannot be proven disjoint from them", "manual_reconciliation")
        if r.source_kind == "media_invoice":
            require(centre.kind == "engine", "CENTRE_UNKNOWN", f"a media invoice is attributed to the engine centre that ran the campaign; {centre.centre_ref} is a {centre.kind} centre")
            require(not plan.require_invoice_backed_media or bool(r.invoice_backed), "MEDIA_SPEND_NOT_INVOICE_BACKED", "platform-reported media spend is a claim; record the paid invoice that proved the cash left", "manual_reconciliation")
            # the sibling check is not a keyword the caller may omit: a source that names an envelope
            # states the sealed PortfolioCapacity verdict for it, or it is refused.
            require(r.envelope_ref is None or r.envelope_oversubscribed is not None, "PORTFOLIO_ENVELOPE_OVERSUBSCRIBED", f"envelope {r.envelope_ref} was never judged against its sibling campaigns; reconcile through a sealed portfolio capacity", "await_approval")
            require(not bool(r.envelope_oversubscribed), "PORTFOLIO_ENVELOPE_OVERSUBSCRIBED", f"envelope {r.envelope_ref} carries sibling campaign budgets beyond the envelope; reallocate under approval first", "await_approval")
            if r.reported_spend is not None and r.amount > 0:
                variance = ((r.reported_spend - r.amount).copy_abs() * _HUNDRED / r.amount).quantize(MONEY_QUANTUM)
                require(variance <= plan.media_variance_tolerance_percent, "SPEND_VARIANCE_EXCEEDED", f"platform-reported {r.reported_spend} differs from invoice-proven {r.amount} by {variance}%, beyond the {plan.media_variance_tolerance_percent}% tolerance; the campaign's evidence is platform-reported only", "manual_reconciliation")
        engine_spend, engine_revenue = dict(data.get("engine_spend", {})), dict(data.get("engine_revenue", {}))
        overhead, campaign_media = dict(data.get("overhead_spend", {})), dict(data.get("campaign_media_spend", {}))
        amount, campaign_ref = r.amount, r.campaign_refs[0] if len(r.campaign_refs) == 1 else None
        assert amount is not None
        # only an invoice-proven media payable is cash the bank saw leave; a platform claim never
        # moves ``attributed_cash_out`` even when the map does not require invoice backing.
        cash = derived["cash_amount"] > 0
        if derived["revenue_amount"] > 0:
            _bump(engine_revenue, str(centre.engine), derived["revenue_amount"])
        if derived["spend_amount"] > 0:
            spend = derived["spend_amount"]
            if centre.engine is not None:
                _bump(engine_spend, centre.engine, spend)
            if centre.kind == "overhead":
                _bump(overhead, str(r.category), spend)
            elif centre.kind == "labour":
                data["labour_spend"] = str(_add(data.get("labour_spend"), spend))
            if r.source_kind in ("media_invoice", "channel_spend"):
                data["media_spend"] = str(_add(data.get("media_spend"), spend))
                data["media_reported_spend"] = str(_add(data.get("media_reported_spend"), r.reported_spend or Decimal("0")))
                if campaign_ref is not None:
                    _bump(campaign_media, campaign_ref, spend)
                elif r.campaign_refs:
                    data["campaigns_with_shared_media"] = list(dict.fromkeys([*data.get("campaigns_with_shared_media", ()), *r.campaign_refs]))
        if cash:
            data["attributed_cash_out"] = str(_add(data.get("attributed_cash_out"), derived["cash_amount"]))
        rows.append({"source_kind": r.source_kind, "source_ref": r.source_ref, "source_digest": r.source_digest, "centre_ref": centre.centre_ref, "centre_kind": centre.kind, "engine": centre.engine, "category": r.category, "campaign_ref": campaign_ref, "cash": cash, "amount": str(amount), "returned": "0.00", "recorded_at": r.occurred_at or at, **{key: str(value) if isinstance(value, Decimal) else value for key, value in derived.items()}})
        data.update({"sources": rows, "sources_recorded": len(rows), "engine_spend": engine_spend, "engine_revenue": engine_revenue, "overhead_spend": overhead, "campaign_media_spend": campaign_media, **_COVERAGE_CLEARED})
    elif event == "record_return":
        from lightbulb.refund_and_dispute_chain import verify_cleared_refund
        require(r.refund_source is not None, "SOURCE_NOT_PROVEN", "a return retains a cleared refund state and its source plan")
        source = r.refund_source
        refund = verify_cleared_refund(source["state"], source_plan=source.get("source_plan", source.get("plan")), company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"], at=at)
        expected = refund_cost_receipt(refund, source_plan=source.get("source_plan", source.get("plan")))
        require(all(r.to_dict().get(k) == expected[k] for k in ("source_kind", "source_ref", "source_digest", "against_source_digest", "amount", "currency", "occurred_at")), "SOURCE_NOT_PROVEN", "the return amount and original cash source must equal the replayed refund")
        require(parsed(data["period_start"]) <= parsed(refund.ledger.cleared_at) < parsed(data["period_end"]), "PERIOD_MISMATCH", "the cleared revenue correction belongs to this accounting window")
        rows = [dict(detached(item)) for item in data.get("sources", [])]
        require(r.against_source_digest is not None and r.amount is not None and r.source_ref is not None, "SOURCE_NOT_PROVEN", "a return names the refund or credit note that produced it, the source digest it reverses, and the amount that came back")
        require(all(r.source_ref not in tuple(row.get("returned_refs") or ()) for row in rows), "SOURCE_ALREADY_RECORDED", f"{r.source_ref} already came back out of this register", "do_not_replay")
        require(r.currency is None or str(r.currency).upper() == plan.currency, "CURRENCY_MISMATCH", f"the return is in {r.currency}; the register runs in {plan.currency}")
        index = next((position for position, row in enumerate(rows) if r.against_source_digest in (row["source_digest"], *row.get("cash_source_digests", ()))), None)
        require(index is not None, "SOURCE_NOT_PROVEN", f"no source with digest {str(r.against_source_digest)[:16]} was ever recorded here")
        assert index is not None
        row = rows[index]
        amount = r.amount
        assert amount is not None
        require(Decimal(row["revenue_amount"]) > 0, "SOURCE_NOT_PROVEN", "a customer refund reverses company revenue, never a cost or seller liability")
        outstanding = (Decimal(str(row["revenue_amount"])) - Decimal(str(row["returned"]))).quantize(MONEY_QUANTUM)
        require(amount <= outstanding, "RETURN_EXCEEDS_RECORDED", f"a return of {amount} exceeds the {outstanding} still recorded against {row['source_ref']}")
        engine_spend, engine_revenue = dict(data.get("engine_spend", {})), dict(data.get("engine_revenue", {}))
        overhead, campaign_media = dict(data.get("overhead_spend", {})), dict(data.get("campaign_media_spend", {}))
        _bump(engine_revenue, str(row["engine"]), -amount)
        rows[index] = {**row, "returned": str(_add(row["returned"], amount)), "returned_refs": [*(row.get("returned_refs") or ()), r.source_ref]}
        data.update({"sources": rows, "returns_value": str(_add(data.get("returns_value"), amount)), "engine_spend": engine_spend, "engine_revenue": engine_revenue, "overhead_spend": overhead, "campaign_media_spend": campaign_media, **_COVERAGE_CLEARED})
    elif event == "assert_coverage":
        require(r.coverage is not None, "COVERAGE_EVIDENCE_MISSING", "coverage retains both replayed source states and plans")
        proof = SpendCoverage.model_validate(r.coverage)
        expected = coverage_receipt(proof)
        require(all(r.to_dict().get(k) == expected[k] for k in ("coverage_digest", "source_state_digest", "attributed_cash_out", "reconciled_cash_out", "coverage_percent", "unattributed_merchants", "reconciliation_ref")), "COVERAGE_EVIDENCE_MISSING", "coverage claims must equal their replayed bank proof")
        require(proof.register_plan == plan.to_dict(), "COVERAGE_EVIDENCE_MISSING", "coverage must retain this register's exact plan")
        require(_same_scope(proof.register_state["scope"], data["entity_scope"]) and parsed(proof.bank_state["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "COVERAGE_EVIDENCE_MISSING", "coverage must exist in this scope before it is asserted")
        require(r.coverage_digest is not None and r.reconciled_cash_out is not None, "COVERAGE_EVIDENCE_MISSING", "coverage is asserted from a sealed SpendCoverage carrying the reconciled cash out and the coverage percent")
        require(r.source_state_digest == command.expected_state_digest, "COVERAGE_STALE", "the coverage was computed from a different register state; recompute it against the current one", "refresh_state")
        # the floor is only a fence if the numbers behind it are the register's own:
        # re-derive the percentage rather than believing the one the receipt states.
        attributed = Decimal(str(data.get("attributed_cash_out") or "0"))
        require(r.attributed_cash_out == attributed, "COVERAGE_EVIDENCE_MISSING", f"the coverage attributes {r.attributed_cash_out}; this register attributed {attributed}")
        if r.reconciled_cash_out == 0:
            require(attributed == 0 and r.coverage_percent is None, "COVERAGE_EVIDENCE_MISSING", "a proven zero-outflow period has no percentage denominator")
        else:
            require(r.coverage_percent == (attributed * _HUNDRED / r.reconciled_cash_out).quantize(MONEY_QUANTUM), "COVERAGE_EVIDENCE_MISSING", "coverage must equal the attributed proportion of bank cash")
            require(r.coverage_percent >= plan.spend_coverage_floor_percent, "COVERAGE_BELOW_FLOOR", f"coverage {r.coverage_percent}% is below the {plan.spend_coverage_floor_percent}% floor; attribute the missing charges or approve the gap", "await_approval")
        data.update({"reconciled_cash_out": str(r.reconciled_cash_out), "coverage_percent": None if r.coverage_percent is None else str(r.coverage_percent), "coverage_digest": r.coverage_digest, "reconciliation_ref": r.reconciliation_ref, "unattributed_merchants": list(r.unattributed_merchants), "coverage_asserted_at": at})
    elif event == "close_register":
        data.update({"closed_at": at, "outcome": "closed"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


def _guarded_register(*args: Any) -> Any:
    try:
        return _apply_register(*args)
    except Rejected:
        raise
    except CostCentreError as exc:
        disposition = "do_not_replay" if exc.code == "SOURCE_ALREADY_RECORDED" else "await_approval" if exc.code == "PORTFOLIO_ENVELOPE_OVERSUBSCRIBED" else "manual_reconciliation" if exc.code in ("MEDIA_SPEND_NOT_INVOICE_BACKED", "SPEND_VARIANCE_EXCEEDED") else "correct_input"
        require(False, exc.code, str(exc), disposition)
    except (ValueError, KeyError, TypeError) as exc:
        require(False, "SOURCE_NOT_PROVEN", f"retained source proof must validate: {exc}", "correct_input")


COST_REGISTER_LIFECYCLE = LifecycleSpec(entity="cost_register", schema_prefix="company_cost_register", statuses=REGISTER_STATUSES, terminal=TERMINAL_REGISTER_STATUSES, events=REGISTER_EVENTS, table=_REGISTER_TABLE, opening_event="open_register", reason_events=("abandon",), apply=_guarded_register, ledger_model=CostRegisterLedger, receipt_model=CostSourceReceipt, effect_boundary_model=CostRegisterEffectBoundary, plan_model=CostCentreMap, max_transitions=MAX_REGISTER_TRANSITIONS)
CostRegisterState = COST_REGISTER_LIFECYCLE.State
CostRegisterCommand = COST_REGISTER_LIFECYCLE.Command
seal_register_command = COST_REGISTER_LIFECYCLE.seal_command


def open_cost_register(plan: CostCentreMap | Mapping[str, Any], scope: Mapping[str, Any], *, opened_at: str, actor_ref: str, receipt: Mapping[str, Any] | None = None, period_start: str | None = None, period_end: str | None = None) -> Any:
    parsed_plan = CostCentreMap.model_validate(detached(plan))
    values = {"period_ref": parsed_plan.period_ref, **dict(receipt or {}), "entity_scope": detached(scope)}
    if period_start is not None:
        values["period_start"] = period_start
    if period_end is not None:
        values["period_end"] = period_end
    return COST_REGISTER_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=values)


def advance_cost_register(plan: CostCentreMap | Mapping[str, Any], state: Any, command: Any) -> Any:
    return COST_REGISTER_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the sealed artifacts that proved the money moved
# --------------------------------------------------------------------------- #


class CostCentreError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CostCentreError(code, message)


_STATE_LIFECYCLES = {"lightbulb.job_chain_state.v1": ("job_chain", "JOB_LIFECYCLE"),
    PAYABLE_STATE_SCHEMA: ("payables_chain", "PAYABLES_CHAIN_LIFECYCLE"),
    "lightbulb.spend_item_state.v1": ("spend_control_chain", "SPEND_LIFECYCLE"),
    WORKER_STATE_SCHEMA: ("company_workforce", "WORKER_LIFECYCLE"),
    CAMPAIGN_STATE_SCHEMA: ("growth_engine_loop", "CAMPAIGN_LIFECYCLE"),
    REGISTER_STATE_SCHEMA: ("company_cost_centres", "COST_REGISTER_LIFECYCLE"),
    "lightbulb.revenue_chain_state.v1": ("revenue_chain", "REVENUE_CHAIN_LIFECYCLE"),
    "lightbulb.subscription_chain_state.v1": ("subscription_chain", "SUBSCRIPTION_CHAIN_LIFECYCLE"),
    "lightbulb.storefront_settlement_state.v1": ("storefront_settlement_chain", "STOREFRONT_SETTLEMENT_LIFECYCLE"),
    "lightbulb.marketplace_supply_transaction_state.v1": ("marketplace_supply_engine", "TRANSACTION_LIFECYCLE"),
    "lightbulb.payroll_run_state.v1": ("payroll_run_chain", "PAYROLL_LIFECYCLE"),
    "lightbulb.bank_reconciliation_state.v1": ("bank_reconciliation", "BANK_REC_LIFECYCLE"),
    "lightbulb.disbursement_run_state.v1": ("disbursement_run", "DISBURSEMENT_LIFECYCLE"),
}


def _spec(schema: str) -> Any:
    _require(schema in _STATE_LIFECYCLES, "ARTIFACT_NOT_A_STATE", "only exact registered lifecycle schemas can prove money")
    module, name = _STATE_LIFECYCLES[schema]
    return getattr(importlib.import_module("lightbulb." + module), name)


@lru_cache(maxsize=64)
def _replayed_state(canonical: str) -> tuple[Any, Any]:
    source = json.loads(canonical)
    return _spec(source["state"]["schema"]).bind(source["plan"], source["state"])


def _bound(artifact: Any, source_plan: Any) -> tuple[Any, Any]:
    _require(source_plan is not None, "SOURCE_NOT_PROVEN", "a source state must retain its plan for actual lifecycle replay")
    try:
        # Include the complete ledger, history and plan in the cache key. A
        # state digest alone excludes the ledger and is not a proof key.
        value = json.dumps({"state": detached(artifact), "plan": detached(source_plan)}, sort_keys=True, separators=(",", ":"))
        return deepcopy(_replayed_state(value))
    except CostCentreError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise CostCentreError("SOURCE_NOT_PROVEN", f"the source must replay against its exact retained plan: {exc}") from exc


def _state(artifact: Any, *, source_plan: Any = None) -> dict[str, Any]:
    return _bound(artifact, source_plan)[1].to_dict()


def _retained(raw: Any, source_plan: Any) -> dict[str, Any]:
    return {"source_state": detached(raw), "source_plan": detached(source_plan)}


def _same_scope(left: Any, right: Any) -> bool:
    left, right = detached(left), detached(right)
    return all(left.get(k) == right.get(k) for k in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _history_digests(raw: Mapping[str, Any]) -> list[str]:
    spec = _spec(str(raw["schema"]))
    state = spec.State.model_validate(raw)
    return [spec.state_digest(state.plan_digest, state.scope, state.transition_history[:i]) for i in range(1, state.version + 1)]


def _cash_digests(raw: Mapping[str, Any]) -> list[str]:
    values = _history_digests(raw)
    # A payable paid through a run inherits that run's bank proof, which may
    # aggregate other invoices. Coverage still allocates only this bill's cash.
    for transition in raw["transition_history"]:
        source = transition["command"]["receipt"].get("disbursement_source")
        if source is not None:
            run = _state(source["state"], source_plan=source["plan"])
            values.extend(_history_digests(run))
    return sorted(set(values))


def _primary_source(raw: Mapping[str, Any], kind: str, *, period_ref: str | None = None, dispatch_ref: str | None = None) -> str:
    ledger = raw["ledger"]
    scope = {k: raw["scope"][k] for k in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")}
    if kind in ("payable", "media_invoice"):
        identity = ("supplier_payment", ledger.get("correlation_sha256") or (ledger.get("supplier_ref"), ledger.get("invoice_number")))
    elif kind == "spend_case":
        identity = ("card_charge", ledger.get("transaction_ref"))
    elif kind == "payroll":
        identity = ("payroll", ledger.get("run_ref"), ledger.get("period_start"), ledger.get("period_end"))
    elif kind == "metered_dispatch":
        identity = ("agent_dispatch", dispatch_ref)
    elif kind == "worker":
        identity = ("worker_period", _entity_ref(raw), period_ref)
    else:
        identity = ("customer_cash", ledger.get("payment_ref") or ledger.get("payout_ref") or ledger.get("invoice_ref") or ledger.get("correlation") or ledger.get("correlation_ref") or _entity_ref(raw))
    return "cash-source:" + stable_digest({"scope": scope, "identity": identity})


def _entity_ref(raw: Mapping[str, Any]) -> str:
    return str((raw.get("scope") or {}).get("entity_ref") or "")


def _scope_currency(raw: Mapping[str, Any]) -> str | None:
    """The currency the source engine ran in; the register refuses another, it never converts."""

    value = (raw.get("scope") or {}).get("currency")
    return None if value is None else str(value).upper()


def _expect_schema(raw: Mapping[str, Any], schema: str, code: str, label: str) -> None:
    _require(str(raw.get("schema")) == schema, code, f"expected {label}, not {raw.get('schema')}")


def payable_cost_receipt(payable_case_state: Any, *, source_plan: Any, centre_ref: str, category: str | None = None) -> dict[str, Any]:
    """From a paid or cleared ``PayableCaseState``: the cash that left, keyed by the case, not the bill.

    ``category`` is the one explicit operator input on this hop - rent,
    software, insurance and professional fees arrive as ordinary supplier
    bills and the payable itself never says which overhead they are - so the
    receipt names itself operator-supplied when it carries one.
    """

    raw = _state(payable_case_state, source_plan=source_plan)
    _expect_schema(raw, PAYABLE_STATE_SCHEMA, "PAYABLE_SCHEMA_MISMATCH", "a payables chain state")
    _require(str(raw.get("status")) in ("paid", "cleared"), "PAYABLE_NOT_PAID", f"the payable case is {raw.get('status')}; only paid cash is cost")
    ledger = dict(raw["ledger"])
    _require(ledger.get("paid_at") is not None, "PAYABLE_NOT_PAID", "the payable case carries no payment time")
    amount = ledger.get("applied_amount") or ledger.get("amount")
    _require(amount is not None, "PAYABLE_AMOUNT_MISSING", "the payable case carries no applied amount")
    ref = _entity_ref(raw)
    return {"source_kind": "payable", "source_ref": f"payable:{ref}", "source_digest": str(raw["state_digest"]), "centre_ref": centre_ref, "category": category, "operator_supplied": category is not None, "amount": str(decimal_value(amount, field_name="applied_amount")), "currency": _scope_currency(raw), "occurred_at": str(ledger["paid_at"]), "supplier_ref": ledger.get("supplier_ref"), "engine": ledger.get("engine"), "evidence_refs": [f"payable_case:{ref}", f"state:{str(raw['state_digest'])[:24]}"], **_retained(raw, source_plan)}


def spend_case_receipt(spend_case_state: Any, *, source_plan: Any, centre_ref: str) -> dict[str, Any]:
    """From a cleared spend control case (a card charge that settled); the centre comes from the operator's merchant map."""

    raw = _state(spend_case_state, source_plan=source_plan)
    schema = str(raw.get("schema") or "")
    _require(schema == "lightbulb.spend_item_state.v1", "SPEND_CASE_SCHEMA_MISMATCH", "card cost requires the exact spend item lifecycle schema")
    _require(str(raw.get("status")) == "cleared", "SPEND_CASE_NOT_CLEARED", f"the spend case is {raw.get('status')}; only a cleared charge is cost")
    ledger = dict(raw["ledger"])
    for key in ("amount", "merchant_ref", "cleared_at"):
        _require(ledger.get(key) is not None, "SPEND_CASE_INCOMPLETE", f"the spend case ledger lacks {key}")
    ref = _entity_ref(raw)
    return {"source_kind": "spend_case", "source_ref": f"spend_case:{ref}", "source_digest": str(raw["state_digest"]), "centre_ref": centre_ref, "operator_supplied": True, "amount": str(decimal_value(ledger["amount"], field_name="amount")), "occurred_at": str(ledger["cleared_at"]), "merchant_ref": str(ledger["merchant_ref"]), "category": ledger.get("category"), "currency": str(ledger["currency"]).upper() if ledger.get("currency") else _scope_currency(raw), "evidence_refs": [f"spend_case:{ref}", f"state:{str(raw['state_digest'])[:24]}"], **_retained(raw, source_plan)}


def worker_cost_receipt(worker_state: Any, *, source_plan: Any, period_ref: str, centre_ref: str) -> dict[str, Any]:
    """From a ``WorkerState``: the hop that finally carries agent-dispatch spend out of the worker ledger."""

    raw = _state(worker_state, source_plan=source_plan)
    _expect_schema(raw, WORKER_STATE_SCHEMA, "WORKER_SCHEMA_MISMATCH", "a workforce worker state")
    ledger = dict(raw["ledger"])
    _require(str(ledger.get("period_ref") or "") == period_ref, "WORKER_PERIOD_MISMATCH", f"the worker's cost belongs to period {ledger.get('period_ref')}, not {period_ref}")
    cost = decimal_value(ledger.get("cost_this_period") or "0", field_name="cost_this_period")
    _require(cost > 0, "WORKER_COST_ZERO", "the worker recorded no cost this period; there is nothing to attribute")
    _require(ledger.get("open_dispatch_ref") is None, "WORKER_DISPATCH_OPEN", f"dispatch {ledger.get('open_dispatch_ref')} has no outcome yet; settle it before attributing the period")
    ref = _entity_ref(raw)
    moments = [t["command"]["occurred_at"] for t in raw["transition_history"] if t["command"]["event"] == "record_outcome"]
    _require(bool(moments), "WORKER_COST_ZERO", "worker cost requires a retained outcome time")
    return {"source_kind": "worker", "source_ref": f"worker:{ref}:{period_ref}", "source_digest": str(raw["state_digest"]), "centre_ref": centre_ref, "amount": str(cost), "currency": _scope_currency(raw), "period_ref": period_ref, "engine": ledger.get("engine"), "occurred_at": max(moments, key=parsed), "dispatch_count": int(ledger.get("total_dispatches") or 0), "evidence_refs": [f"worker:{ref}", f"state:{str(raw['state_digest'])[:24]}"], **_retained(raw, source_plan)}


def metered_dispatch_receipt(metered_dispatch: MeteredDispatch | Mapping[str, Any], *, worker_state: Any, source_plan: Any, centre_ref: str, currency: str, usd_rate: Any = None, period_ref: str | None = None) -> dict[str, Any]:
    """From a sealed ``MeteredDispatch``: the platform's own metered cost, converted at an explicit rate."""

    parsed_dispatch = MeteredDispatch.model_validate(detached(metered_dispatch))
    _require(parsed_dispatch.schema_id == "lightbulb.company_metered_dispatch.v1", "DISPATCH_NOT_SETTLED", "the dispatch must use the exact metering schema")
    worker = _state(worker_state, source_plan=source_plan)
    _expect_schema(worker, WORKER_STATE_SCHEMA, "WORKER_SCHEMA_MISMATCH", "a scoped worker dispatch owner")
    dispatches = [t["command"] for t in worker["transition_history"] if t["command"]["event"] == "dispatch" and t["command"]["receipt"].get("dispatch_ref") == parsed_dispatch.dispatch_ref]
    _require(len(dispatches) == 1 and dispatches[0]["receipt"].get("period_ref") == period_ref and worker["scope"]["currency"] == currency.upper(), "PERIOD_MISMATCH", "the metered dispatch must bind its scoped worker's actual period dispatch")
    _require(parsed_dispatch.settled, "DISPATCH_NOT_SETTLED", f"{parsed_dispatch.trace_id} is {parsed_dispatch.workflow_status}; a running dispatch has no cost")
    _require(parsed(parsed_dispatch.completed_at) >= parsed(dispatches[0]["occurred_at"]), "DISPATCH_NOT_SETTLED", "metered completion cannot precede the scoped dispatch")
    try:
        converted = outcome_receipt(parsed_dispatch, currency=currency, usd_rate=usd_rate)
    except MeteringError as exc:  # the metering module's own rate guards, restated in this module's error
        raise CostCentreError(exc.code, str(exc)) from exc
    return {"source_kind": "metered_dispatch", "source_ref": f"dispatch:{parsed_dispatch.dispatch_ref}", "source_digest": parsed_dispatch.metered_digest, "centre_ref": centre_ref, "amount": converted["actual_cost"], "currency": currency.upper(), "period_ref": period_ref, "occurred_at": parsed_dispatch.completed_at, "dispatch_count": 1, "metered_artifact": parsed_dispatch.to_dict(), "usd_rate": None if usd_rate is None else str(usd_rate), "engine": worker["ledger"].get("engine"), "evidence_refs": [f"dispatch:{parsed_dispatch.dispatch_ref}", f"metered:{parsed_dispatch.metered_digest[:24]}"], **_retained(worker, source_plan)}


def media_invoice_receipt(payable_case_state: Any, *, source_plan: Any, campaign_refs: Sequence[str], centre_ref: str) -> dict[str, Any]:
    """From a paid ``PayableCaseState`` attributed to a growth centre: the only media spend that is cost."""

    receipt = payable_cost_receipt(payable_case_state, source_plan=source_plan, centre_ref=centre_ref)
    refs = [str(item) for item in campaign_refs]
    _require(bool(refs), "MEDIA_INVOICE_UNATTRIBUTED", "a media invoice names the campaign(s) it paid for")
    return {**receipt, "source_kind": "media_invoice", "source_ref": receipt["source_ref"].replace("payable:", "media_invoice:", 1), "campaign_refs": refs, "invoice_backed": True, "evidence_refs": [*receipt["evidence_refs"], *[f"campaign:{ref}" for ref in refs[:10]]]}


def spend_reconciliation(campaign_state: Any, media_receipt: Mapping[str, Any] | None = None, *, source_plan: Any, capacity: Mapping[str, Any] | Any, centre_ref: str | None = None) -> dict[str, Any]:
    """Compare a campaign's platform-reported spend against the invoice-proven cash that paid for it.

    Without a media invoice receipt the result is a claim, and the register
    refuses it with ``MEDIA_SPEND_NOT_INVOICE_BACKED``.  With one, the
    reported figure rides along so the register can judge the variance.

    ``capacity`` is required rather than optional: a campaign's media spend
    cannot be judged against an envelope without the sealed
    :class:`PortfolioCapacity` that counted its siblings, and an
    approval-gated fence a caller can disarm by omitting a keyword is not a
    fence.  The capacity must be the campaign's own portfolio and must have
    counted this campaign, so an empty or unrelated one cannot stand in.
    """

    raw = _state(campaign_state, source_plan=source_plan)
    _expect_schema(raw, CAMPAIGN_STATE_SCHEMA, "CAMPAIGN_SCHEMA_MISMATCH", "a growth campaign state")
    ledger = dict(raw["ledger"])
    ref, envelope = _entity_ref(raw), str(ledger.get("envelope_ref") or "")
    _require(bool(envelope), "CAMPAIGN_ENVELOPE_MISSING", "the campaign carries no portfolio envelope")
    reported = decimal_value(ledger.get("spend") or "0", field_name="spend")
    rows = PortfolioCapacity.model_validate(detached(capacity)).to_dict()
    _expect_schema(rows, PORTFOLIO_CAPACITY_SCHEMA, "CAPACITY_SCHEMA_MISMATCH", "a sealed portfolio capacity")
    _require(str(rows.get("portfolio_digest") or "") == str(ledger.get("portfolio_digest") or ""), "CAPACITY_PORTFOLIO_MISMATCH", f"the capacity judges another portfolio than the one campaign {ref} was opened on")
    row = next((item for item in rows.get("envelopes", []) if str(item.get("envelope_ref")) == envelope), None)
    _require(row is not None, "CAPACITY_ENVELOPE_UNKNOWN", f"the capacity does not cover envelope {envelope}")
    assert row is not None
    _require(ref in [str(item) for item in (row.get("campaign_refs") or ())], "CAPACITY_CAMPAIGN_MISSING", f"the capacity never counted campaign {ref}; a sibling check that omits the campaign it judges proves nothing")
    _require(any(item["state"]["state_digest"] == raw["state_digest"] and item["state"]["scope"] == raw["scope"] for item in rows["campaign_sources"]), "CAPACITY_CAMPAIGN_MISSING", "capacity must retain this exact campaign version")
    common = {"envelope_ref": envelope, "reported_spend": str(reported), "capacity_digest": str(rows["capacity_digest"]), "envelope_oversubscribed": bool(row.get("oversubscribed")), "campaign_state": raw, "campaign_plan": detached(source_plan), "capacity": rows}
    if media_receipt is None:
        return {"source_kind": "media_invoice", "source_ref": f"campaign_reported:{ref}", "source_digest": str(raw["state_digest"]), "centre_ref": centre_ref, "amount": str(reported), "campaign_refs": [ref], "invoice_backed": False, "occurred_at": ledger.get("observed_through"), "evidence_refs": [f"campaign:{ref}"], **_retained(raw, source_plan), **common}
    invoice = dict(media_receipt)
    _require(ref in [str(item) for item in invoice.get("campaign_refs", [])], "CAMPAIGN_NOT_ON_INVOICE", f"the media invoice does not name campaign {ref}")
    return {**invoice, **common, "evidence_refs": [*invoice.get("evidence_refs", []), f"campaign_state:{str(raw['state_digest'])[:24]}"]}


def chain_revenue_receipt(case_state: Any, *, source_plan: Any, centre_ref: str) -> dict[str, Any]:
    """From a settled chain case (revenue chain, subscription, storefront batch): cash in, attributed to the engine that earned it."""

    raw = _state(case_state, source_plan=source_plan)
    schema = str(raw.get("schema") or "")
    _require(schema in REVENUE_STATE_SCHEMAS, "REVENUE_SCHEMA_MISMATCH", f"expected one of {', '.join(REVENUE_STATE_SCHEMAS)}, not {schema or 'an unschemad document'}")
    _require(str(raw.get("status")) in (SETTLED_REVENUE_STATUSES | {"paid"} if schema == "lightbulb.job_chain_state.v1" else SETTLED_REVENUE_STATUSES), "REVENUE_NOT_SETTLED", f"the case is {raw.get('status')}; only settled cash is revenue")
    ledger = dict(raw["ledger"])
    kind = {"lightbulb.job_chain_state.v1": "job_case", "lightbulb.subscription_chain_state.v1": "subscription_case", "lightbulb.storefront_settlement_state.v1": "storefront_batch", "lightbulb.marketplace_supply_transaction_state.v1": "marketplace_transaction"}.get(schema, "revenue_case")
    if kind == "job_case":
        settled = ledger.get("paid_amount")
    elif kind == "marketplace_transaction":
        from lightbulb.marketplace_supply_engine import verify_settled_transaction
        verify_settled_transaction(raw, source_plan=source_plan)
        settled = ledger.get("company_take_revenue")
    else:
        settled = next((ledger[key] for key in ("settled_amount", "net_settled", "recognised_revenue") if ledger.get(key) is not None), None)
    _require(settled is not None, "REVENUE_NOT_SETTLED", "the case carries no settled amount")
    ref = _entity_ref(raw)
    occurred_at = ledger.get("paid_at") if kind == "job_case" else ledger.get("settled_at") or ledger.get("payout_arrival_at")
    _require(occurred_at is not None, "REVENUE_NOT_SETTLED", "settled revenue must carry its cash settlement time")
    attribution = {"engine": "service_delivery" if detached(source_plan)["profile"] == "local_services" else "engagement_engine"} if kind == "job_case" else {}
    return {**attribution, "source_kind": kind, "source_ref": f"{kind}:{ref}", "source_digest": str(raw["state_digest"]), "centre_ref": centre_ref, "amount": str(decimal_value(settled, field_name="settled_amount")), "currency": _scope_currency(raw), "occurred_at": occurred_at, "evidence_refs": [f"revenue_case:{ref}", f"state:{str(raw['state_digest'])[:24]}"], **_retained(raw, source_plan)}


def payroll_cost_receipt(run_state: Any, *, source_plan: Any, centre_ref: str, period_ref: str | None = None) -> dict[str, Any]:
    raw = _state(run_state, source_plan=source_plan)
    _expect_schema(raw, "lightbulb.payroll_run_state.v1", "SOURCE_NOT_PROVEN", "a payroll run")
    _require(raw["status"] in ("paid", "liabilities_reserved", "reconciled"), "SOURCE_NOT_PROVEN", "payroll cost requires the actually paid run")
    ledger = raw["ledger"]
    amount = sum((Decimal(str(ledger.get(k) or "0")) for k in ("gross", "employer_super", "employer_tax")), Decimal("0.00"))
    return {"source_kind": "payroll", "source_ref": "payroll:" + _entity_ref(raw), "source_digest": raw["state_digest"], "centre_ref": centre_ref, "amount": str(amount), "currency": raw["scope"]["currency"], "occurred_at": ledger["period_end"], "period_ref": period_ref, "engine": "people_engine", "evidence_refs": [f"payroll:{raw['state_digest']}"], **_retained(raw, source_plan)}


def refund_cost_receipt(refund_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.refund_and_dispute_chain import verify_cleared_refund
    refund = verify_cleared_refund(refund_state, source_plan=source_plan)
    _require(refund.ledger.company_revenue_reversal > 0, "SOURCE_NOT_PROVEN", "a seller-only adjustment does not reverse company revenue")
    return {"source_kind": "refund_case", "source_ref": "refund:" + refund.ledger.refund_ref,
            "source_digest": refund.state_digest, "against_source_digest": refund.ledger.source_transaction_digest,
            "amount": str(refund.ledger.company_revenue_reversal), "currency": refund.scope.currency,
            "occurred_at": refund.ledger.cleared_at, "refund_source": {"state": refund.to_dict(), "source_plan": detached(source_plan)},
            "evidence_refs": [f"refund:{refund.ledger.refund_ref}"]}


def inference_cost_receipt(register: Any, *, source_plan: Any, centre_ref: str) -> dict[str, Any]:
    """Accrue a scoped provider bill allocation; this receipt never claims bank cash.

    Retain the complete reconciliation. Metering scope must originate at the
    authenticated host boundary, just as lifecycle source scope does.
    Cent rounding is allocated across the complete bill, never independently.
    """
    from lightbulb.inference_cost_register import verify_register, allocate
    bill = verify_register(register)
    plan = CostCentreMap.model_validate(detached(source_plan))
    metered = bill.source_metered
    _require(metered.scope is not None and metered.company_ref == plan.company_ref, "SOURCE_SCOPE_MISMATCH", "inference metering must retain the company's authenticated scope")
    _require(bill.currency == plan.currency == metered.scope.currency, "CURRENCY_MISMATCH", "inference billing must use the register currency; an unproven FX rate cannot translate it")
    centre = plan.centre(centre_ref)
    _require(centre is not None, "CENTRE_UNKNOWN", "inference allocation must name a mapped centre")
    grouped: dict[str, int] = {}
    for line in bill.lines:
        _require(plan.centre(line.cost_centre_ref) is not None, "CENTRE_UNKNOWN", "every provider bill allocation must name a mapped centre")
        grouped[line.cost_centre_ref] = grouped.get(line.cost_centre_ref, 0) + line.cost_micros
    _require(centre_ref in grouped, "SOURCE_NOT_PROVEN", "this bill has no allocation for the requested centre")
    cents = int((bill.total * 100).quantize(Decimal("1")))
    shares = allocate(cents, [(key, key, value) for key, value in sorted(grouped.items())])
    amount = next(Decimal(share) / 100 for _, key, _, share in shares if key == centre_ref)
    identity = stable_digest({"provider": bill.provider, "start": bill.period_start, "end": bill.period_end, "company_ref": plan.company_ref, "scope": {key: getattr(metered.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")}})
    return {"source_kind": "inference_cost", "source_ref": "inference:" + stable_digest({"bill": identity, "centre": centre_ref}), "source_digest": stable_digest({"register": bill.register_digest, "centre": centre_ref}), "centre_ref": centre_ref, "amount": str(amount), "currency": bill.currency, "occurred_at": bill.period_end, "period_ref": plan.period_ref, "engine": centre.engine, "category": "software" if centre.kind == "overhead" else None, "inference_source": bill.to_dict(), "evidence_refs": [bill.source_statement.evidence_ref]}


def _proven_inference_source(plan: CostCentreMap, data: Mapping[str, Any], receipt: CostSourceReceipt, at: str) -> tuple[CostSourceReceipt, dict[str, Any]]:
    from lightbulb.inference_cost_register import verify_register
    _require(receipt.inference_source is not None, "SOURCE_NOT_PROVEN", "retain the complete reconciled inference register")
    bill = verify_register(receipt.inference_source)
    expected = CostSourceReceipt.model_validate(inference_cost_receipt(bill, source_plan=plan, centre_ref=str(receipt.centre_ref)))
    _require(receipt.to_dict() == expected.to_dict(), "SOURCE_NOT_PROVEN", "inference receipt must equal the allocation reproduced from its sources")
    _require(_same_scope(bill.source_metered.scope, data["entity_scope"]), "SOURCE_SCOPE_MISMATCH", "inference metering and company register must share exact scope")
    _require(parsed(str(data["period_start"])) <= parsed(bill.period_start) < parsed(bill.period_end) <= parsed(str(data["period_end"])), "PERIOD_MISMATCH", "the entire provider billing period must belong to this accounting register")
    statement = bill.source_statement
    observed = statement.operator_receipt.attested_at if statement.operator_receipt is not None else statement.observation_provenance.completed_at
    _require(parsed(bill.period_end) <= parsed(at) and parsed(observed) <= parsed(at), "SOURCE_NOT_PROVEN", "recording must follow the billing window and its evidence")
    identity = stable_digest({"provider": bill.provider, "start": bill.period_start, "end": bill.period_end})
    return expected, {"spend_amount": expected.amount, "revenue_amount": Decimal("0.00"), "cash_amount": Decimal("0.00"), "primary_source_ref": expected.source_ref, "cash_source_digests": [], "inference_bill_ref": identity, "inference_register_digest": bill.register_digest}


def channel_spend_cost_receipt(statement: Any, *, source_plan: Any, centre_ref: str) -> dict[str, Any]:
    from lightbulb.channel_spend_statements import verify_statement
    plan = CostCentreMap.model_validate(detached(source_plan))
    source = verify_statement(statement)
    centre = plan.centre(centre_ref)
    _require(centre is not None and centre.kind == "engine", "CENTRE_UNKNOWN", "channel spend belongs to an engine centre")
    _require(source.company_ref == plan.company_ref and source.currency == plan.currency, "SOURCE_SCOPE_MISMATCH", "channel statement belongs to another company or currency")
    identity = stable_digest({"company": source.company_ref, "scope": source.scope.to_dict(), "channel": source.channel,
                              "account": source.account_commitment, "start": source.window_start, "end": source.window_end})
    return {"source_kind": "channel_spend", "source_ref": "channel-spend:" + identity,
            "source_digest": source.statement_digest, "centre_ref": centre_ref, "engine": centre.engine,
            "amount": str(source.amount.quantize(MONEY_QUANTUM)), "currency": source.currency,
            "occurred_at": source.window_end, "period_ref": plan.period_ref,
            "media_statement": source.to_dict(), "evidence_refs": ["media:" + source.statement_digest]}


def _proven_channel_spend(plan: CostCentreMap, data: Mapping[str, Any], receipt: CostSourceReceipt, at: str) -> tuple[CostSourceReceipt, dict[str, Any]]:
    from lightbulb.channel_spend_statements import verify_statement
    _require(receipt.media_statement is not None, "SOURCE_NOT_PROVEN", "retain the complete channel statement")
    source = verify_statement(receipt.media_statement)
    expected = CostSourceReceipt.model_validate(channel_spend_cost_receipt(source, source_plan=plan, centre_ref=str(receipt.centre_ref)))
    _require(expected == receipt, "SOURCE_NOT_PROVEN", "channel costs must reproduce the retained source")
    _require(_same_scope(source.scope, data["entity_scope"]), "SOURCE_SCOPE_MISMATCH", "channel costs must use this register scope")
    _require(parsed(data["period_start"]) <= parsed(source.window_start) < parsed(source.window_end) <= parsed(data["period_end"]),
             "PERIOD_MISMATCH", "the complete spend window must belong to this accounting period")
    observed = source.operator_receipt.attested_at if source.operator_receipt else source.provenance.completed_at
    _require(parsed(observed) <= parsed(at), "SOURCE_NOT_PROVEN", "future spend observations cannot enter the register")
    return expected, {"spend_amount": expected.amount, "revenue_amount": Decimal("0.00"), "cash_amount": Decimal("0.00"),
        "primary_source_ref": expected.source_ref, "cash_source_digests": [],
        "media_account_ref": "media-account:" + stable_digest({"channel": source.channel, "account": source.account_commitment}),
        "media_window_start": source.window_start, "media_window_end": source.window_end,
        "media_document_digest": source.operator_receipt.document_sha256 if source.operator_receipt else None}


def _proven_source(plan: CostCentreMap, data: Mapping[str, Any], receipt: CostSourceReceipt, at: str) -> tuple[CostSourceReceipt, dict[str, Any]]:
    r = receipt
    if r.source_kind == "channel_spend":
        return _proven_channel_spend(plan, data, r, at)
    if r.source_kind == "inference_cost":
        return _proven_inference_source(plan, data, r, at)
    _require(r.source_state is not None and r.source_plan is not None, "SOURCE_NOT_PROVEN", "money attribution requires the actual source state and plan, not typed totals")
    source_plan, state = _bound(r.source_state, r.source_plan)
    raw, kind = state.to_dict(), str(r.source_kind)
    _require(state.scope.currency == plan.currency and (r.currency is None or r.currency == plan.currency), "CURRENCY_MISMATCH", "source money must use the register currency")
    _require(_same_scope(state.scope, data["entity_scope"]) and getattr(source_plan, "company_ref", plan.company_ref) == plan.company_ref, "SOURCE_SCOPE_MISMATCH", "source money must belong to this logical company and authenticated scope")
    _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_NOT_PROVEN", "source state cannot come from the future")
    args = {"source_plan": r.source_plan, "centre_ref": r.centre_ref}
    if kind == "payable":
        expected = payable_cost_receipt(state, category=r.category, **args)
    elif kind == "spend_case":
        expected = spend_case_receipt(state, **args)
    elif kind == "worker":
        expected = worker_cost_receipt(state, period_ref=r.period_ref, **args)
    elif kind == "metered_dispatch":
        _require(r.metered_artifact is not None, "SOURCE_NOT_PROVEN", "metered cost retains the actual sealed dispatch")
        expected = metered_dispatch_receipt(r.metered_artifact, worker_state=state, currency=plan.currency, usd_rate=r.usd_rate, period_ref=r.period_ref, **args)
    elif kind == "media_invoice":
        _require(r.invoice_backed is True, "MEDIA_SPEND_NOT_INVOICE_BACKED", "platform-reported media is never a cash-backed cost source")
        expected = media_invoice_receipt(state, campaign_refs=r.campaign_refs, **args)
        if r.campaign_state is not None or r.envelope_ref is not None:
            _require(r.campaign_state is not None and r.campaign_plan is not None and r.capacity is not None, "PORTFOLIO_ENVELOPE_OVERSUBSCRIBED", "media comparison requires a replayed campaign and sibling capacity")
            campaign = _state(r.campaign_state, source_plan=r.campaign_plan)
            for sibling in (r.capacity or {}).get("campaign_sources", ()):
                _require(_same_scope(sibling["state"]["scope"], data["entity_scope"]) and parsed(sibling["state"]["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "SOURCE_SCOPE_MISMATCH", "sibling capacity must exist in this scope before attribution")
            _require(_same_scope(campaign["scope"], data["entity_scope"]), "SOURCE_SCOPE_MISMATCH", "campaign and invoice must belong to this register scope")
            _require(parsed(campaign["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "SOURCE_NOT_PROVEN", "a campaign comparison cannot use a future source")
            expected = spend_reconciliation(campaign, expected, source_plan=r.campaign_plan, capacity=r.capacity)
    elif kind in ("job_case", "revenue_case", "subscription_case", "storefront_batch", "marketplace_transaction"):
        expected = chain_revenue_receipt(state, **args)
    elif kind == "payroll":
        expected = payroll_cost_receipt(state, period_ref=r.period_ref, **args)
    else:
        raise CostCentreError("SOURCE_NOT_PROVEN", "this source kind cannot introduce money into the register")
    expected_model = CostSourceReceipt.model_validate(expected)
    claimed = r.to_dict()
    actual = expected_model.to_dict()
    # The caller chooses a centre/category; every provider-derived claim must
    # match the source builder again at the consuming transition.
    for key in ("source_kind", "source_ref", "source_digest", "amount", "currency", "occurred_at", "engine", "merchant_ref", "supplier_ref", "dispatch_count", "invoice_backed", "reported_spend", "envelope_ref", "capacity_digest", "envelope_oversubscribed"):
        _require(claimed.get(key) == actual.get(key), "SOURCE_NOT_PROVEN", f"{key} must equal the value derived from the replayed source")
    moment = expected_model.occurred_at
    _require(moment is not None and parsed(moment) <= parsed(at), "SOURCE_NOT_PROVEN", "recording cannot precede the proven money event")
    start, end = parsed(str(data["period_start"])), parsed(str(data["period_end"]))
    if kind == "payroll":
        _require(start <= parsed(raw["ledger"]["period_start"]) < parsed(raw["ledger"]["period_end"]) <= end, "PERIOD_MISMATCH", "the complete payroll earning period must belong to the register")
    else:
        _require(start <= parsed(moment) < end, "PERIOD_MISMATCH", "the proven source event must fall inside the accounting period")
    amount = expected_model.amount
    assert amount is not None
    revenue_kinds = {"job_case", "revenue_case", "subscription_case", "storefront_batch", "marketplace_transaction"}
    spend = Decimal("0.00") if kind in revenue_kinds else amount
    revenue = amount if kind in revenue_kinds else Decimal("0.00")
    cash = amount if kind in ("payable", "spend_case", "media_invoice") else Decimal("0.00")
    if kind == "storefront_batch":
        spend = Decimal(str(raw["ledger"]["fees"])) + Decimal(str(raw["ledger"]["refunds"]))
    if kind == "payroll" and start <= parsed(raw["ledger"]["paid_at"]) < end:
        cash = Decimal(str(raw["ledger"]["net"]))
    derived = {"spend_amount": spend, "revenue_amount": revenue, "cash_amount": cash,
               "primary_source_ref": _primary_source(raw, kind, period_ref=r.period_ref, dispatch_ref=(r.metered_artifact or {}).get("dispatch_ref")),
               "cash_source_digests": _cash_digests(raw)}
    return expected_model, derived


# --------------------------------------------------------------------------- #
# What the register hands to the other engines
# --------------------------------------------------------------------------- #


def period_evidence_receipt(register_state: Any, *, source_plan: Any, engine: str, period_ref: str, signals: Sequence[str] = (), evidence_ref: str | None = None) -> dict[str, Any]:
    """The company operating system's ``record_evidence`` receipt with a real spend figure and the engine from the map.

    The receipt carries the digests of the artifacts that proved this
    engine's money moved, so the period's own ``EVIDENCE_ALREADY_RECORDED``
    fence refuses a second evidence row that would fund the period with the
    same sources again.  ``source_digest`` keys the register state *and* the
    engine, because one register legitimately reports one row per engine.
    """

    raw = _state(register_state, source_plan=source_plan)
    _expect_schema(raw, REGISTER_STATE_SCHEMA, "REGISTER_SCHEMA_MISMATCH", "a cost register state")
    _require(engine in ENGINE_KINDS, "ENGINE_NOT_BOUND", f"{engine} is not an operating engine")
    ledger = dict(raw["ledger"])
    _require(str(ledger.get("period_ref") or "") == period_ref, "PERIOD_MISMATCH", f"this register attributes period {ledger.get('period_ref')}, not {period_ref}")
    _require(int(ledger.get("sources_recorded") or 0) > 0, "REGISTER_NOT_ATTRIBUTED", "the register has recorded no source; there is no proven spend to report")
    ref = _entity_ref(raw)
    spend = decimal_value(dict(ledger.get("engine_spend") or {}).get(engine, "0"), field_name="spend")
    revenue = decimal_value(dict(ledger.get("engine_revenue") or {}).get(engine, "0"), field_name="revenue")
    selected = [dict(detached(row)) for row in (ledger.get("sources") or ()) if str(dict(detached(row)).get("engine") or "") == engine]
    sources = [stable_digest({"primary_source_ref": row["primary_source_ref"]}) for row in selected]
    _require(bool(sources), "REGISTER_NOT_ATTRIBUTED", f"no source in this register is attributed to {engine}; there is nothing to report for it")
    out = {"engine": engine, "evidence_ref": evidence_ref or f"cost_register:{ref}:{engine}:{str(raw['state_digest'])[:16]}", "spend": str(spend), "revenue": str(revenue), "signals": list(signals), "source_kind": COST_REGISTER_KIND, "source_digest": stable_digest({"register_state": str(raw["state_digest"]), "engine": engine}), "source_digests": sources, **_retained(raw, source_plan)}
    # zero-spend revenue names itself rather than looking like a missing spend figure
    return {**out, "revenue_only": True} if spend == 0 and revenue > 0 else out


def attributed_revenue_signal(campaign_state: Any, register_state: Any, *, campaign_plan: Any, source_plan: Any, emitted_at: str | None = None) -> CompanySignal:
    """``signals.attributed_revenue`` with the spend the register proved, not the spend the platform reported."""

    campaign, register = _state(campaign_state, source_plan=campaign_plan), _state(register_state, source_plan=source_plan)
    _require(_same_scope(campaign["scope"], register["scope"]), "SOURCE_SCOPE_MISMATCH", "campaign and register must share exact authenticated scope")
    _expect_schema(campaign, CAMPAIGN_STATE_SCHEMA, "CAMPAIGN_SCHEMA_MISMATCH", "a growth campaign state")
    _expect_schema(register, REGISTER_STATE_SCHEMA, "REGISTER_SCHEMA_MISMATCH", "a cost register state")
    ledger, register_ledger = dict(campaign["ledger"]), dict(register["ledger"])
    ref = _entity_ref(campaign)
    _require(ledger.get("attribution_model") is not None, "CAMPAIGN_NOT_ATTRIBUTED", f"campaign {ref} has not attributed revenue yet")
    _require(ref not in list(register_ledger.get("campaigns_with_shared_media") or ()), "MEDIA_SPEND_NOT_SOLELY_ATTRIBUTED", f"an invoice covering {ref} also paid sibling campaigns; the SDK attributes cost, it never splits it")
    spend = dict(register_ledger.get("campaign_media_spend") or {}).get(ref)
    _require(spend is not None, "MEDIA_SPEND_NOT_RECORDED", f"no invoice-proven media spend is recorded for {ref}")
    window_end = str(ledger.get("observed_through") or "")
    _require(bool(window_end), "CAMPAIGN_WINDOW_MISSING", "the campaign carries no observed-through time")
    latest = max(parsed(item["transition_history"][-1]["command"]["occurred_at"]) for item in (campaign, register))
    stamp = timestamp(emitted_at or latest.isoformat().replace("+00:00", "Z"), field_name="emitted_at")
    _require(parsed(stamp) >= latest, "SOURCE_NOT_PROVEN", "signal cannot precede its retained evidence")
    payload = {"channel": str(ledger["channel"]), "attributed_revenue": str(decimal_value(ledger.get("attributed_revenue") or "0", field_name="attributed_revenue")), "spend": str(decimal_value(spend, field_name="spend")), "window_end": window_end}
    return CompanySignal(name="signals.attributed_revenue", producer="growth_engine", emitted_at=stamp, payload=payload)


def envelope_exhausted_signal(campaign_state: Any, *, source_plan: Any, emitted_at: str | None = None) -> CompanySignal:
    """``signals.envelope_exhausted``: raised only once the campaign's observed spend has reached its envelope budget."""

    raw = _state(campaign_state, source_plan=source_plan)
    _expect_schema(raw, CAMPAIGN_STATE_SCHEMA, "CAMPAIGN_SCHEMA_MISMATCH", "a growth campaign state")
    ledger = dict(raw["ledger"])
    spend = decimal_value(ledger.get("spend") or "0", field_name="spend")
    budget = decimal_value(ledger.get("budget") or "0", field_name="budget")
    _require(budget > 0, "ENVELOPE_BUDGET_MISSING", "the campaign carries no envelope budget")
    _require(spend >= budget, "ENVELOPE_NOT_EXHAUSTED", f"spend {spend} has not reached the envelope budget {budget}")
    window_end = str(ledger.get("observed_through") or "")
    latest = raw["transition_history"][-1]["command"]["occurred_at"]
    stamp = timestamp(emitted_at or latest, field_name="emitted_at")
    _require(parsed(stamp) >= parsed(latest), "SOURCE_NOT_PROVEN", "signal cannot precede its campaign evidence")
    return CompanySignal(name="signals.envelope_exhausted", producer="growth_engine", emitted_at=stamp, payload={"envelope_ref": str(ledger["envelope_ref"]), "spend": str(spend), "budget": str(budget)})


class OverheadRow(StrictModel):
    category: ShortText
    amount: Decimal
    sources: int = Field(ge=0)

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class OverheadRollup(StrictModel):
    """The company's own cost base for treasury and unit economics, in two views that must never be added together.

    *By nature* — ``overhead_total``, ``labour_spend``, ``media_spend`` and
    ``direct_spend`` — partitions the register's spend: every recorded source
    falls in exactly one of the four, and the four sum to ``total_spend``.
    *By engine* — ``engine_spend`` — is the orthogonal view: a labour centre
    that names an engine appears in ``labour_spend`` and again under its
    engine, on purpose.  ``total_spend`` is the only safe total.
    """

    schema_id: str = Field(default=OVERHEAD_ROLLUP_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    currency: CurrencyCode
    categories: tuple[OverheadRow, ...] = Field(default_factory=tuple, max_length=24)
    overhead_total: Decimal
    labour_spend: Decimal
    media_spend: Decimal
    #: Spend on engine centres that is neither media nor labour; the fourth part of the by-nature view.
    direct_spend: Decimal
    engine_spend: dict[str, Decimal] = Field(default_factory=dict)
    total_spend: Decimal
    flows: tuple[ScheduledFlow, ...] = Field(default_factory=tuple, max_length=24)
    register_state_digest: Sha256Digest
    register_state: dict[str, Any]
    register_plan: dict[str, Any]
    due_at: str | None = None
    rollup_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("overhead_total", "labour_spend", "media_spend", "direct_spend", "total_spend", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _partition(self) -> OverheadRollup:
        parts = (self.overhead_total + self.labour_spend + self.media_spend + self.direct_spend).quantize(MONEY_QUANTUM)
        if parts != self.total_spend:
            raise ValueError(f"the by-nature view must partition total spend: {parts} != {self.total_spend}")
        return self

    @field_validator("engine_spend", mode="before")
    @classmethod
    def _maps(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="engine_spend") for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> OverheadRollup:
        if not skip_digests(info):
            if self.rollup_digest != sealed_digest(OverheadRollup, self, "rollup_digest"):
                raise ValueError("rollup_digest must commit the exact rollup")
            expected = _overhead_payload(self.register_state, self.register_plan, self.due_at)
            _require(self.rollup_digest == sealed_digest(OverheadRollup, expected, "rollup_digest"), "SOURCE_NOT_PROVEN", "overhead must equal the replayed register")
        return self


def _overhead_payload(register_state: Any, source_plan: Any, due_at: str | None) -> dict[str, Any]:
    raw = _state(register_state, source_plan=source_plan)
    _expect_schema(raw, REGISTER_STATE_SCHEMA, "REGISTER_SCHEMA_MISMATCH", "a cost register state")
    ledger = CostRegisterLedger.model_validate(dict(raw["ledger"]))
    company_ref = str(CostCentreMap.model_validate(detached(source_plan)).company_ref)
    counts: dict[str, int] = {}
    direct = Decimal("0")
    for item in ledger.sources:
        if item.centre_kind == "overhead" and item.category:
            counts[item.category] = counts.get(item.category, 0) + 1
        # the fourth part of the by-nature view: an engine centre's own non-media, non-labour cost
        if item.source_kind != "media_invoice" and item.centre_kind == "engine":
            direct = _add(direct, item.spend_amount)
    rows = [{"category": category, "amount": str(amount), "sources": counts.get(category, 0)} for category, amount in sorted(ledger.overhead_spend.items()) if amount != 0]
    stamp = None if due_at is None else timestamp(due_at, field_name="due_at")
    flows = [] if stamp is None else [{"kind": "fixed_cost", "ref": f"overhead:{ledger.period_ref}:{row['category']}", "due_at": stamp, "amount": row["amount"], "source": f"cost_register:{_entity_ref(raw)}"} for row in rows]
    payload = {
        "company_ref": company_ref,
        "period_ref": str(ledger.period_ref),
        "currency": str(ledger.currency),
        "categories": rows,
        "overhead_total": str(sum(ledger.overhead_spend.values(), Decimal("0")).quantize(MONEY_QUANTUM)),
        "labour_spend": str(ledger.labour_spend),
        "media_spend": str(ledger.media_spend),
        "direct_spend": str(direct),
        "engine_spend": {key: str(value) for key, value in sorted(ledger.engine_spend.items())},
        "total_spend": str(ledger.total_spend),
        "flows": flows,
        "register_state_digest": str(raw["state_digest"]),
        "register_state": raw,
        "register_plan": detached(source_plan),
        "due_at": stamp,
    }
    return payload


def overhead_rollup(register_state: Any, *, source_plan: Any = None, plan: CostCentreMap | Mapping[str, Any] | None = None, due_at: str | None = None) -> OverheadRollup:
    """Replay the register's own cost base and retain it for consumers."""
    retained_plan = source_plan if source_plan is not None else plan
    _require(retained_plan is not None, "SOURCE_NOT_PROVEN", "a rollup must retain the register plan")
    return seal(OverheadRollup, _overhead_payload(register_state, retained_plan, due_at), "rollup_digest")


class SpendCoverage(StrictModel):
    """How much of the bank's reconciled cash out this register actually attributed."""

    schema_id: str = Field(default=SPEND_COVERAGE_SCHEMA, alias="schema")
    period_ref: OpaqueRef
    currency: CurrencyCode
    attributed_cash_out: Decimal
    reconciled_cash_out: Decimal
    coverage_percent: Decimal | None = None
    unattributed_merchants: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    sources_recorded: int = Field(ge=0)
    reconciliation_ref: OpaqueRef
    reconciliation_state_digest: Sha256Digest
    register_state_digest: Sha256Digest
    register_state: dict[str, Any]
    register_plan: dict[str, Any]
    bank_state: dict[str, Any]
    bank_plan: dict[str, Any]
    coverage_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("attributed_cash_out", "reconciled_cash_out", "coverage_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return None if value is None and info.field_name == "coverage_percent" else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> SpendCoverage:
        if not skip_digests(info):
            if self.coverage_digest != sealed_digest(SpendCoverage, self, "coverage_digest"):
                raise ValueError("coverage_digest must commit the exact coverage")
            expected = _coverage_payload(self.register_state, self.bank_state, self.register_plan, self.bank_plan)
            _require(self.coverage_digest == sealed_digest(SpendCoverage, expected, "coverage_digest"), "COVERAGE_EVIDENCE_MISSING", "coverage must equal the replayed bank and register")
        return self


def _unmatched_debits(bank: Mapping[str, Any]) -> list[str]:
    """The money-out lines the reconciliation never matched: what the register has not attributed yet."""

    matched = {str(item) for item in (bank.get("matched_line_refs") or ())}
    out: list[str] = []
    for line in bank.get("lines") or ():
        row = dict(detached(line))
        if str(row.get("direction")) != "debit" or str(row.get("line_ref")) in matched:
            continue
        reference = str(row.get("reference") or "")
        out.append(reference if _REF_SHAPE.fullmatch(reference) else str(row.get("line_ref")))
    return out[:100]


def _coverage_payload(register_state: Any, bank_reconciliation_state: Any, source_plan: Any, bank_plan: Any) -> dict[str, Any]:
    raw = _state(register_state, source_plan=source_plan)
    _expect_schema(raw, REGISTER_STATE_SCHEMA, "REGISTER_SCHEMA_MISMATCH", "a cost register state")
    reconciliation = _state(bank_reconciliation_state, source_plan=bank_plan)
    schema = str(reconciliation.get("schema") or "")
    _require(schema == "lightbulb.bank_reconciliation_state.v1", "RECONCILIATION_SCHEMA_MISMATCH", "coverage requires the actual bank reconciliation lifecycle")
    _require(str(reconciliation.get("status")) == "reconciled", "RECONCILIATION_NOT_RECONCILED", f"the bank reconciliation is {reconciliation.get('status')}")
    ledger, bank = CostRegisterLedger.model_validate(dict(raw["ledger"])), dict(reconciliation["ledger"])
    _require(_same_scope(raw["scope"], reconciliation["scope"]), "SOURCE_SCOPE_MISMATCH", "register and bank must share exact authenticated scope")
    _require(detached(bank_plan)["company_ref"] == detached(source_plan)["company_ref"], "SOURCE_SCOPE_MISMATCH", "register and bank must share the logical company")
    _require(parsed(bank["period_start"]) == parsed(ledger.period_start) and parsed(bank["period_end"]) == parsed(ledger.period_end), "PERIOD_MISMATCH", "bank and register must cover the exact same accounting window")
    _require(bank.get("currency") is None or str(bank["currency"]).upper() == str(ledger.currency), "CURRENCY_MISMATCH", f"the reconciliation is in {bank.get('currency')}; the register runs in {ledger.currency}; balances are never converted")
    # ``statement_debits`` is the reconciliation's own cash-out field; the register reads that one
    # rather than a friendlier name no BankReconciliationLedger carries.
    _require(bank.get("statement_debits") is not None, "RECONCILIATION_CASH_OUT_MISSING", "the bank reconciliation carries no statement debits; there is no cash out to judge coverage against")
    reconciled = decimal_value(bank["statement_debits"], field_name="statement_debits")
    _require(reconciled > 0 or ledger.attributed_cash_out == 0, "RECONCILIATION_CASH_OUT_MISSING", "a zero-outflow bank period cannot cover recorded cash expenses")
    matches = [dict(item) for item in bank.get("matches", ()) if Decimal(str(item["amount"])) < 0]
    allocations = [Decimal("0.00") for _ in matches]
    for source in ledger.sources:
        if source.cash_amount == 0:
            continue
        candidates = [i for i, match in enumerate(matches) if match["counterpart_state_digest"] in source.cash_source_digests]
        _require(len(candidates) == 1, "COVERAGE_SOURCE_UNMATCHED", "every cash cost must identify exactly one actual bank match for its retained source")
        i = candidates[0]
        allocations[i] += source.cash_amount
        _require(allocations[i] <= abs(Decimal(str(matches[i]["amount"]))), "COVERAGE_SOURCE_OVERALLOCATED", "registered cash cannot exceed its proven bank payment")
    covered_lines = {str(ref) for i, match in enumerate(matches) if allocations[i] == abs(Decimal(str(match["amount"]))) for ref in match["line_refs"]}
    unattributed = []
    for line in bank["lines"]:
        if Decimal(str(line["amount"])) < 0 and line["line_ref"] not in covered_lines:
            value = str(line.get("reference") or "")
            unattributed.append(value if _REF_SHAPE.fullmatch(value) else str(line["line_ref"]))
    payload = {
        "period_ref": str(ledger.period_ref),
        "currency": str(ledger.currency),
        "attributed_cash_out": str(ledger.attributed_cash_out),
        "reconciled_cash_out": str(reconciled),
        "coverage_percent": None if reconciled == 0 else str((ledger.attributed_cash_out * _HUNDRED / reconciled).quantize(MONEY_QUANTUM)),
        "unattributed_merchants": unattributed[:100],
        "sources_recorded": int(ledger.sources_recorded),
        "reconciliation_ref": str(bank.get("reconciliation_ref") or f"bank_reconciliation:{_entity_ref(reconciliation)}"),
        "reconciliation_state_digest": str(reconciliation["state_digest"]),
        "register_state_digest": str(raw["state_digest"]),
        "register_state": raw, "register_plan": detached(source_plan),
        "bank_state": reconciliation, "bank_plan": detached(bank_plan),
    }
    return payload


def spend_coverage(register_state: Any, bank_reconciliation_state: Any, *, source_plan: Any, bank_plan: Any) -> SpendCoverage:
    """Attribute only costs linked to the period's real reconciled bank matches."""
    return seal(SpendCoverage, _coverage_payload(register_state, bank_reconciliation_state, source_plan, bank_plan), "coverage_digest")


def coverage_receipt(coverage: SpendCoverage | Mapping[str, Any]) -> dict[str, Any]:
    """The ``assert_coverage`` receipt from a sealed :class:`SpendCoverage`."""

    raw = SpendCoverage.model_validate(detached(coverage)).to_dict()
    _expect_schema(raw, SPEND_COVERAGE_SCHEMA, "COVERAGE_SCHEMA_MISMATCH", "a sealed spend coverage")
    return {"coverage": raw, "coverage_digest": str(raw["coverage_digest"]), "source_state_digest": str(raw["register_state_digest"]), "attributed_cash_out": str(raw["attributed_cash_out"]), "reconciled_cash_out": str(raw["reconciled_cash_out"]), "coverage_percent": None if raw.get("coverage_percent") is None else str(raw["coverage_percent"]), "unattributed_merchants": list(raw.get("unattributed_merchants") or []), "reconciliation_ref": str(raw["reconciliation_ref"]), "evidence_refs": [f"coverage:{str(raw['coverage_digest'])[:24]}", f"reconciliation:{str(raw['reconciliation_state_digest'])[:24]}"]}


class EnvelopeCapacity(StrictModel):
    envelope_ref: OpaqueRef
    budget: Decimal
    committed: Decimal
    remaining: Decimal
    campaigns: int = Field(ge=0)
    #: The campaigns actually counted on this envelope, so a capacity cannot claim to
    #: judge a campaign it never saw.
    campaign_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=64)
    oversubscribed: bool

    @field_validator("campaign_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("budget", "committed", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("remaining", mode="before")
    @classmethod
    def _remaining(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="remaining", allow_negative=True)


class PortfolioCapacity(StrictModel):
    """What is left on every envelope once its live sibling campaigns are counted."""

    schema_id: str = Field(default=PORTFOLIO_CAPACITY_SCHEMA, alias="schema")
    portfolio_digest: Sha256Digest
    period_start: str
    period_end: str
    currency: CurrencyCode
    source_portfolio: dict[str, Any]
    source_plan: dict[str, Any]
    campaign_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=64)
    envelopes: tuple[EnvelopeCapacity, ...] = Field(min_length=1, max_length=64)
    oversubscribed_envelopes: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=64)
    capacity_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> PortfolioCapacity:
        if not skip_digests(info):
            if self.capacity_digest != sealed_digest(PortfolioCapacity, self, "capacity_digest"):
                raise ValueError("capacity_digest must commit the exact capacity")
            expected = _capacity_payload(self.source_portfolio, self.source_plan, self.campaign_sources)
            _require(self.capacity_digest == sealed_digest(PortfolioCapacity, expected, "capacity_digest"), "SOURCE_NOT_PROVEN", "capacity must equal replayed sibling commitments")
        return self

    def envelope(self, ref: str) -> EnvelopeCapacity | None:
        return next((item for item in self.envelopes if item.envelope_ref == ref), None)


def _capacity_payload(portfolio: Any, source_plan: Any, campaign_sources: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    from lightbulb.growth_engine_loop import CampaignPortfolio, GrowthEngineLoopPlan
    plan = GrowthEngineLoopPlan.model_validate(detached(source_plan))
    raw = CampaignPortfolio.model_validate(detached(portfolio)).to_dict()
    _require(raw["plan_digest"] == plan.plan_digest and raw["currency"] == plan.blueprint.currency, "CAPACITY_PORTFOLIO_MISMATCH", "portfolio must match its actual growth plan")
    _expect_schema(raw, "lightbulb.campaign_portfolio.v1", "PORTFOLIO_SCHEMA_MISMATCH", "a sealed campaign portfolio")
    committed: dict[str, Decimal] = {}
    counted: dict[str, list[str]] = {}
    seen_entities: set[str] = set()
    scope = None
    for item in campaign_sources:
        _require(detached(item["source_plan"]) == plan.to_dict(), "CAPACITY_PORTFOLIO_MISMATCH", "all siblings must use the portfolio plan")
        state = _state(item["state"], source_plan=item["source_plan"])
        entity_key = stable_digest(state["scope"])
        _require(entity_key not in seen_entities, "SOURCE_ALREADY_RECORDED", "one sibling is counted once even when supplied at different versions")
        seen_entities.add(entity_key)
        _require(scope is None or _same_scope(scope, state["scope"]), "SOURCE_SCOPE_MISMATCH", "sibling campaigns share exact authenticated scope")
        scope = state["scope"]
        _require(scope["currency"] == raw["currency"], "CURRENCY_MISMATCH", "campaign currency matches the portfolio")
        _expect_schema(state, CAMPAIGN_STATE_SCHEMA, "CAMPAIGN_SCHEMA_MISMATCH", "a growth campaign state")
        ledger = dict(state["ledger"])
        _require(str(ledger.get("portfolio_digest") or "") == str(raw["portfolio_digest"]), "CAMPAIGN_NOT_IN_PORTFOLIO", f"campaign {_entity_ref(state)} belongs to another portfolio")
        ref = str(ledger.get("envelope_ref") or "")
        _require(any(ref == envelope["envelope_ref"] for envelope in raw["envelopes"]), "CAPACITY_ENVELOPE_UNKNOWN", "every sibling names a portfolio envelope")
        # a halted campaign releases the budget it never used, but the cash it already
        # spent is gone: commitment is what it spent, never zero.
        halted = str(state.get("status")) == "halted"
        held = decimal_value(ledger.get("spend" if halted else "budget") or "0", field_name="spend" if halted else "budget")
        committed[ref] = _add(committed.get(ref), held)
        counted.setdefault(ref, []).append(_entity_ref(state))
    rows = []
    for envelope in raw["envelopes"]:
        ref = str(envelope["envelope_ref"])
        budget = decimal_value(envelope["budget"], field_name="budget")
        used = committed.get(ref, Decimal("0"))
        seen = counted.get(ref, [])
        rows.append({"envelope_ref": ref, "budget": str(budget), "committed": str(used), "remaining": str((budget - used).quantize(MONEY_QUANTUM)), "campaigns": len(seen), "campaign_refs": seen, "oversubscribed": used > budget})
    return {"portfolio_digest": str(raw["portfolio_digest"]), "period_start": str(raw["period_start"]), "period_end": str(raw["period_end"]), "currency": str(raw["currency"]), "envelopes": rows, "oversubscribed_envelopes": [row["envelope_ref"] for row in rows if row["oversubscribed"]], "source_portfolio": raw, "source_plan": plan.to_dict(), "campaign_sources": detached(campaign_sources)}


def portfolio_capacity(portfolio: Mapping[str, Any] | Any, campaign_states: Sequence[Any] = (), *, source_plan: Any) -> PortfolioCapacity:
    """Replay and retain each distinct scoped sibling before counting commitments."""
    sources = [{"state": detached(state), "source_plan": detached(source_plan)} for state in campaign_states]
    return seal(PortfolioCapacity, _capacity_payload(portfolio, source_plan, sources), "capacity_digest")


# --------------------------------------------------------------------------- #
# What the operator sees
# --------------------------------------------------------------------------- #


def register_summary(register_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The ``costs`` verb: what this period cost, by engine, overhead category, labour, and media."""

    raw = _state(register_state, source_plan=source_plan)
    ledger = CostRegisterLedger.model_validate(dict(raw["ledger"]))
    grade = "invoice_proven" if ledger.media_spend >= ledger.media_reported_spend else "platform_reported_gap"
    return {
        "register_ref": _entity_ref(raw),
        "status": str(raw["status"]),
        "period_ref": ledger.period_ref,
        "currency": ledger.currency,
        "sources_recorded": ledger.sources_recorded,
        "engine_spend": {key: str(value) for key, value in sorted(ledger.engine_spend.items())},
        "engine_revenue": {key: str(value) for key, value in sorted(ledger.engine_revenue.items())},
        "overhead_spend": {key: str(value) for key, value in sorted(ledger.overhead_spend.items())},
        "labour_spend": str(ledger.labour_spend),
        "media_spend": str(ledger.media_spend),
        "media_reported_spend": str(ledger.media_reported_spend),
        "media_evidence_grade": grade,
        "returns_value": str(ledger.returns_value),
        "total_spend": str(ledger.total_spend),
        "attributed_cash_out": str(ledger.attributed_cash_out),
        "state_digest": str(raw["state_digest"]),
    }


def coverage_summary(register_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The ``coverage`` verb: how much of the bank's cash out this register has proven."""

    raw = _state(register_state, source_plan=source_plan)
    ledger = CostRegisterLedger.model_validate(dict(raw["ledger"]))
    return {"register_ref": _entity_ref(raw), "status": str(raw["status"]), "period_ref": ledger.period_ref, "attributed_cash_out": str(ledger.attributed_cash_out), "reconciled_cash_out": str(ledger.reconciled_cash_out), "coverage_percent": None if ledger.coverage_percent is None else str(ledger.coverage_percent), "unattributed_merchants": list(ledger.unattributed_merchants), "coverage_digest": ledger.coverage_digest, "reconciliation_ref": ledger.reconciliation_ref, "asserted_at": ledger.coverage_asserted_at, "summary_digest": stable_digest({"register": _entity_ref(raw), "state": str(raw["state_digest"])})}


COST_CENTRES_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": COST_REGISTER_KIND,
    "golden_loop": COST_REGISTER_GOLDEN_LOOP,
    "stages": ["open_register", "record_source", "record_return", "assert_coverage", "close_register"],
    "statuses": list(REGISTER_STATUSES),
    "events": list(REGISTER_EVENTS),
    "hops": {
        "payable": "payables_chain case in paid or cleared (payable_cost_receipt)",
        "spend_case": "spend control chain case in cleared, attributed through the operator's merchant map (spend_case_receipt)",
        "worker": "company_workforce WorkerState carrying cost_this_period for the period (worker_cost_receipt)",
        "metered_dispatch": "company_dispatch_metering MeteredDispatch, converted at an explicit rate (metered_dispatch_receipt)",
        "media_invoice": "a paid payable attributed to a growth centre, reconciled against the campaign's reported spend (media_invoice_receipt + spend_reconciliation)",
        "revenue_case": "a settled chain case (chain_revenue_receipt)",
        "assert_coverage": "a sealed SpendCoverage over the period's bank reconciliation (spend_coverage + coverage_receipt)",
    },
    "produces": ["company_operating_system.record_evidence receipts", "signals.attributed_revenue", "signals.envelope_exhausted", "OverheadRollup", "SpendCoverage", "PortfolioCapacity", "ScheduledFlow(kind=fixed_cost)"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a dollar of cost reaches the period exactly once, keyed by the sealed state digest that proved it left",
        "platform-reported media spend is a claim; only an invoice-proven payable is cost",
        "a merchant with no cost centre is refused, never dropped",
        "agent labour arrives through one lane per register: a worker rollup and a metered dispatch cannot be proven disjoint",
        "a media source that names an envelope carries that envelope's sealed sibling verdict; the approval gate is not optional",
        "the SDK attributes cost, it never estimates it",
    ],
}

__all__ = [
    "CASH_SOURCE_KINDS",
    "COST_CENTRES_MANIFEST",
    "COST_CENTRE_MAP_SCHEMA",
    "COST_REGISTER_GOLDEN_LOOP",
    "COST_REGISTER_KIND",
    "COST_REGISTER_LIFECYCLE",
    "DEFAULT_OVERHEAD_CATEGORIES",
    "OVERHEAD_ROLLUP_SCHEMA",
    "PORTFOLIO_CAPACITY_SCHEMA",
    "REGISTER_EVENTS",
    "REGISTER_STATE_SCHEMA",
    "REGISTER_STATUSES",
    "REVENUE_STATE_SCHEMAS",
    "SETTLED_REVENUE_STATUSES",
    "SOURCE_KINDS",
    "inference_cost_receipt",
    "channel_spend_cost_receipt",
    "SPEND_COVERAGE_SCHEMA",
    "TERMINAL_REGISTER_STATUSES",
    "CostCentre",
    "CostCentreError",
    "CostCentreMap",
    "CostRegisterEffectBoundary",
    "CostRegisterLedger",
    "CostRegisterState",
    "CostSourceReceipt",
    "EnvelopeCapacity",
    "MerchantAttribution",
    "OverheadRollup",
    "OverheadRow",
    "PortfolioCapacity",
    "RecordedSource",
    "SpendCoverage",
    "advance_cost_register",
    "attributed_revenue_signal",
    "chain_revenue_receipt",
    "compile_cost_centres",
    "coverage_receipt",
    "coverage_summary",
    "envelope_exhausted_signal",
    "media_invoice_receipt",
    "metered_dispatch_receipt",
    "open_cost_register",
    "overhead_rollup",
    "payable_cost_receipt",
    "payroll_cost_receipt",
    "refund_cost_receipt",
    "period_evidence_receipt",
    "portfolio_capacity",
    "register_summary",
    "seal_register_command",
    "spend_case_receipt",
    "spend_coverage",
    "spend_reconciliation",
    "worker_cost_receipt",
]
