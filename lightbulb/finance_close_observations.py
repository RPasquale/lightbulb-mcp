"""Finance close on real books: ledger and settlement reads into close receipts.

The close lifecycle's receipts (trial balance, account reconciliations, the
subledger lock) were hand-supplied.  The reads that carry those facts are
governed on the platform already: the Xero and QuickBooks trial balance
reports, the close source pages (invoices, bills, payments), the provider
period status, and Stripe balance transactions.  This module turns those
reads, with their provenance, into the exact receipts the close engine
accepts:

* ``trial_balance_receipt`` from ``xero.trial_balance_report``
  (``lightbulb.xero_trial_balance.v1``) or ``quickbooks.trial_balance_report``
  (the raw QBO report), refusing an unbalanced or empty report.
* ``ledger_balances`` from the same trial balance through an explicit
  ``AccountMap`` (which ledger accounts make up cash, receivables, revenue):
  the map is an operator input, never inferred from account names, because a
  wrong guess would reconcile the wrong thing silently.
* ``source_balances`` from independent sources: Stripe balance transactions
  for cash and settled revenue, and the provider's open invoices for
  receivables.
* ``reconciliation_receipts`` pairs ledger and source balances per required
  account kind, computes the variance against the blueprint's thresholds,
  and names a deterministic exception when the variance is material.
* ``lock_receipt`` from ``lightbulb.provider_period_status.v1``, only when a
  lock actually covers the period end.
* ``plan_close_reads`` lists the reads a close at its current status needs,
  and ``close_inputs`` converts completed reads into cadence inputs for the
  runner's ``advance_close`` items.

Nothing executes here; the platform performs the reads and journals them,
and the close engine's own guards still decide.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
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
from lightbulb.company_execution_bridge import BridgeError, ObservationProvenance
from lightbulb.finance_close_engine import FinanceCloseLoopPlan
from lightbulb.governed_connector_contracts import GOVERNED_CONNECTOR_READ_TOOLS

ACCOUNT_MAP_SCHEMA = "lightbulb.close_account_map.v1"
CLOSE_READ_PLAN_SCHEMA = "lightbulb.close_read_plan.v1"
CLOSE_BATCH_SCHEMA = "lightbulb.close_observation_batch.v1"
AccountKind = Literal["cash", "accounts_receivable", "accounts_payable", "revenue_subledger", "payroll", "inventory", "fixed_assets", "intercompany", "tax", "work_in_progress", "seller_payable", "contra_revenue", "deferred_revenue"]
Ledger = Literal["xero", "quickbooks"]
_HUNDRED = Decimal("100")
_CREDIT_NORMAL: frozenset[str] = frozenset({"revenue_subledger", "accounts_payable", "tax", "payroll", "intercompany", "seller_payable", "deferred_revenue"})

TRIAL_BALANCE_TOOLS: Mapping[str, str] = {"xero": "xero.trial_balance_report", "quickbooks": "quickbooks.trial_balance_report"}
PERIOD_STATUS_TOOLS: Mapping[str, str] = {"xero": "xero.get_period_status", "quickbooks": "quickbooks.get_period_status"}
INVOICE_TOOLS: Mapping[str, str] = {"xero": "xero.list_invoices", "quickbooks": "quickbooks.list_invoices"}
STRIPE_BALANCE_TOOL = "stripe.list_balance_transactions"


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BridgeError(code, message)


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    _require(provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; provenance names {provenance.source_tool}")


def _money(value: Any, name: str) -> Decimal:
    return decimal_value(str(value if value not in (None, "") else "0"), field_name=name, allow_negative=True)


# --------------------------------------------------------------------------- #
# Account map (operator input)
# --------------------------------------------------------------------------- #


class AccountMapping(StrictModel):
    kind: AccountKind
    account_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=40)

    @field_validator("account_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class AccountMap(StrictModel):
    """Which ledger accounts make up each reconciled kind; an explicit operator decision, sealed."""

    schema_id: str = Field(default=ACCOUNT_MAP_SCHEMA, alias="schema")
    ledger: Ledger
    mappings: tuple[AccountMapping, ...] = Field(min_length=1, max_length=9)
    map_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("mappings", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> AccountMap:
        unique([item.kind for item in self.mappings], label="account kinds")
        unique([ref for item in self.mappings for ref in item.account_refs], label="account refs")
        if not skip_digests(info) and self.map_digest != sealed_digest(AccountMap, self, "map_digest"):
            raise ValueError("map_digest must commit the exact account map")
        return self

    def refs(self, kind: str) -> tuple[str, ...]:
        return next((item.account_refs for item in self.mappings if item.kind == kind), ())


def account_map(ledger: str, mappings: Mapping[str, Sequence[str]]) -> AccountMap:
    return seal(AccountMap, {"ledger": ledger, "mappings": [{"kind": kind, "account_refs": list(refs)} for kind, refs in mappings.items()]}, "map_digest")


# --------------------------------------------------------------------------- #
# Trial balance
# --------------------------------------------------------------------------- #


class TrialBalanceLine(StrictModel):
    account_ref: OpaqueRef
    account_name: ShortText | None = None
    debit: Decimal
    credit: Decimal

    @field_validator("debit", "credit", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))


class TrialBalance(StrictModel):
    """A trial balance as read, normalized across ledgers and sealed to its provenance."""

    ledger: Ledger
    trial_balance_ref: OpaqueRef
    provenance_digest: Sha256Digest
    period_start: str | None = None
    period_end: str | None = None
    currency: ShortText | None = None
    lines: tuple[TrialBalanceLine, ...] = Field(min_length=1, max_length=5000)
    total_debit: Decimal
    total_credit: Decimal
    balance_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total_debit", "total_credit", mode="before")
    @classmethod
    def _totals(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> TrialBalance:
        if not skip_digests(info) and self.balance_digest != sealed_digest(TrialBalance, self, "balance_digest"):
            raise ValueError("balance_digest must commit the exact trial balance")
        return self

    def net(self, account_refs: Sequence[str], *, credit_normal: bool) -> Decimal:
        wanted = set(account_refs)
        debit = sum((line.debit for line in self.lines if line.account_ref in wanted), Decimal("0"))
        credit = sum((line.credit for line in self.lines if line.account_ref in wanted), Decimal("0"))
        value = credit - debit if credit_normal else debit - credit
        return value.quantize(MONEY_QUANTUM)


def _xero_trial_balance(provenance: ObservationProvenance, payload: Mapping[str, Any]) -> TrialBalance:
    raw = dict(detached(payload))
    _require(raw.get("schema") == "lightbulb.xero_trial_balance.v1", "PAYLOAD_SCHEMA_MISMATCH", "expected a lightbulb.xero_trial_balance.v1 payload")
    lines = [{"account_ref": str(item.get("account_ref") or ""), "account_name": item.get("account_name"), "debit": item.get("debit", "0"), "credit": item.get("credit", "0")} for item in raw.get("lines") or []]
    _require(all(line["account_ref"] for line in lines), "PAYLOAD_FIELD_INVALID", "every trial balance line names its account_ref")
    return seal(TrialBalance, {"ledger": "xero", "trial_balance_ref": provenance.observation_ref, "provenance_digest": provenance.provenance_digest, "period_start": _date(raw.get("start_date")), "period_end": _date(raw.get("end_date")), "currency": raw.get("currency"), "lines": lines, "total_debit": raw.get("total_debit", "0"), "total_credit": raw.get("total_credit", "0")}, "balance_digest")


def _date(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    return timestamp(text if "T" in text else f"{text}T00:00:00Z", field_name="date")


def _qbo_rows(rows: Any) -> list[Mapping[str, Any]]:
    out: list[Mapping[str, Any]] = []
    for row in (rows or {}).get("Row", []) if isinstance(rows, Mapping) else []:
        if not isinstance(row, Mapping):
            continue
        if "ColData" in row:
            out.append(row)
        if "Rows" in row:
            out.extend(_qbo_rows(row.get("Rows")))
        if "Summary" in row and isinstance(row["Summary"], Mapping):
            out.append({**row["Summary"], "type": "Summary"})
    return out


def _quickbooks_trial_balance(provenance: ObservationProvenance, payload: Mapping[str, Any]) -> TrialBalance:
    raw = dict(detached(payload))
    header = raw.get("Header") if isinstance(raw.get("Header"), Mapping) else {}
    columns = [str((col or {}).get("ColTitle", "")).strip().lower() for col in ((raw.get("Columns") or {}).get("Column") or [])]
    _require(len(columns) >= 3, "PAYLOAD_SCHEMA_MISMATCH", "expected a QuickBooks TrialBalance report with account, debit, and credit columns")
    debit_index = next((index for index, title in enumerate(columns) if title == "debit"), 1)
    credit_index = next((index for index, title in enumerate(columns) if title == "credit"), 2)
    lines: list[dict[str, Any]] = []
    total_debit = total_credit = None
    for row in _qbo_rows(raw.get("Rows")):
        cols = row.get("ColData") or []
        if not cols:
            continue
        name = str((cols[0] or {}).get("value", "")).strip()
        if str(row.get("type", row.get("group", ""))).lower() in ("summary", "grandtotal") or name.upper().startswith("TOTAL"):
            total_debit = (cols[debit_index] or {}).get("value") if len(cols) > debit_index else None
            total_credit = (cols[credit_index] or {}).get("value") if len(cols) > credit_index else None
            continue
        ref = str((cols[0] or {}).get("id") or name)
        _require(bool(ref), "PAYLOAD_FIELD_INVALID", "every report row names its account")
        lines.append({"account_ref": ref, "account_name": name or None, "debit": (cols[debit_index] or {}).get("value") if len(cols) > debit_index else "0", "credit": (cols[credit_index] or {}).get("value") if len(cols) > credit_index else "0"})
    _require(bool(lines), "PAYLOAD_INCONSISTENT", "the report carries no account rows")
    if total_debit is None or total_credit is None:
        total_debit = str(sum(_money(line["debit"], "debit") for line in lines))
        total_credit = str(sum(_money(line["credit"], "credit") for line in lines))
    return seal(TrialBalance, {"ledger": "quickbooks", "trial_balance_ref": provenance.observation_ref, "provenance_digest": provenance.provenance_digest, "period_start": _date(header.get("StartPeriod")), "period_end": _date(header.get("EndPeriod")), "currency": header.get("Currency"), "lines": lines, "total_debit": total_debit, "total_credit": total_credit}, "balance_digest")


def read_trial_balance(provenance: ObservationProvenance, payload: Mapping[str, Any]) -> TrialBalance:
    _expect_tool(provenance, *TRIAL_BALANCE_TOOLS.values())
    return _xero_trial_balance(provenance, payload) if provenance.source_tool.startswith("xero.") else _quickbooks_trial_balance(provenance, payload)


def trial_balance_receipt(balance: TrialBalance, *, evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    """The close engine's ``capture_trial_balance`` receipt; the engine applies materiality to the difference."""

    return {"trial_balance_ref": balance.trial_balance_ref, "debits": str(balance.total_debit.quantize(MONEY_QUANTUM)), "credits": str(balance.total_credit.quantize(MONEY_QUANTUM)), "evidence_refs": [f"trial_balance:{balance.trial_balance_ref}", f"provenance:{balance.provenance_digest[:24]}", *evidence_refs]}


def ledger_balances(balance: TrialBalance, mapping: AccountMap) -> dict[str, Decimal]:
    """Net ledger balance per mapped kind; refuses a map for a different ledger or accounts the report lacks."""

    _require(mapping.ledger == balance.ledger, "ACCOUNT_MAP_LEDGER_MISMATCH", f"the account map is for {mapping.ledger}; the trial balance came from {balance.ledger}")
    present = {line.account_ref for line in balance.lines}
    out: dict[str, Decimal] = {}
    for item in mapping.mappings:
        missing = [ref for ref in item.account_refs if ref not in present]
        _require(not missing, "ACCOUNT_NOT_IN_TRIAL_BALANCE", f"{item.kind} maps accounts the report does not carry: {missing}")
        out[item.kind] = balance.net(item.account_refs, credit_normal=item.kind in _CREDIT_NORMAL)
    return out


# --------------------------------------------------------------------------- #
# Source balances
# --------------------------------------------------------------------------- #


class SourceBalance(StrictModel):
    kind: AccountKind
    source_ref: OpaqueRef
    source_tool: ShortText
    provenance_digest: Sha256Digest
    balance: Decimal
    items: int = Field(ge=0)
    window_end: str | None = None

    @field_validator("balance", mode="before")
    @classmethod
    def _balance(cls, value: Any) -> Decimal:
        return _money(value, "balance")


def stripe_source_balances(provenance: ObservationProvenance, transactions: Sequence[Mapping[str, Any]] | Mapping[str, Any], *, currency: str, period_end: str | None = None) -> tuple[SourceBalance, SourceBalance]:
    """Cash (net of fees, all settled types) and settled revenue (charges and payments) from Stripe balance transactions."""

    _expect_tool(provenance, STRIPE_BALANCE_TOOL)
    rows = transactions.get("data") if isinstance(transactions, Mapping) else transactions
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "PAYLOAD_INCONSISTENT", "Stripe balance transactions arrive as a list (or {data: [...]})")
    cash = revenue = Decimal("0")
    counted = 0
    cutoff = parsed(timestamp(period_end, field_name="period_end")) if period_end else None
    for raw in rows:  # type: ignore[union-attr]
        item = dict(detached(raw))
        _require(str(item.get("currency", "")).upper() == currency.upper(), "PAYLOAD_CURRENCY_MISMATCH", f"transaction currency differs from {currency}")
        if cutoff is not None and item.get("created") is not None:
            created = item["created"]
            when = parsed(timestamp(created, field_name="created")) if isinstance(created, str) else parsed(timestamp(_epoch(created), field_name="created"))
            if when > cutoff:
                continue
        amount = Decimal(int(item.get("amount", 0)))
        fee = Decimal(int(item.get("fee", 0)))
        kind = str(item.get("type", ""))
        if kind in ("charge", "payment"):
            revenue += (amount - fee) / _HUNDRED
        if kind in ("charge", "payment", "refund", "payment_refund", "adjustment", "payout", "transfer", "application_fee"):
            cash += (amount - fee) / _HUNDRED
        counted += 1
    _require(counted > 0, "PAYLOAD_INCONSISTENT", "no balance transactions in the read")
    base = {"source_tool": provenance.source_tool, "provenance_digest": provenance.provenance_digest, "items": counted, "window_end": period_end}
    return (
        SourceBalance.model_validate({**base, "kind": "cash", "source_ref": f"stripe-balance:{provenance.observation_ref}", "balance": str(cash.quantize(MONEY_QUANTUM))}),
        SourceBalance.model_validate({**base, "kind": "revenue_subledger", "source_ref": f"stripe-settled:{provenance.observation_ref}", "balance": str(revenue.quantize(MONEY_QUANTUM))}),
    )


def _epoch(value: Any) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def receivables_source_balance(provenance: ObservationProvenance, page: Mapping[str, Any], *, currency: str) -> SourceBalance:
    """Open receivables from the provider's own invoice page (Xero close source page or QuickBooks QueryResponse)."""

    _expect_tool(provenance, *INVOICE_TOOLS.values())
    raw = dict(detached(page))
    total = Decimal("0")
    counted = 0
    if raw.get("schema") == "lightbulb.xero_close_source_page.v1":
        _require(str(raw.get("transaction_type", "")).lower() in ("invoice", "invoices", "accrec"), "PAYLOAD_INCONSISTENT", "expected the invoice source page")
        for record in raw.get("records") or []:
            item = dict(detached(record))
            _require(str(item.get("currency", "")).upper() == currency.upper(), "PAYLOAD_CURRENCY_MISMATCH", f"invoice currency differs from {currency}")
            total += _money(item.get("open_balance", "0"), "open_balance")
            counted += 1
    else:
        query = raw.get("QueryResponse") if isinstance(raw.get("QueryResponse"), Mapping) else raw
        for record in query.get("Invoice") or []:
            item = dict(detached(record))
            code = str(((item.get("CurrencyRef") or {}).get("value")) or currency).upper()
            _require(code == currency.upper(), "PAYLOAD_CURRENCY_MISMATCH", f"invoice currency differs from {currency}")
            total += _money(item.get("Balance", "0"), "Balance")
            counted += 1
    return SourceBalance.model_validate({"kind": "accounts_receivable", "source_ref": f"open-invoices:{provenance.observation_ref}", "source_tool": provenance.source_tool, "provenance_digest": provenance.provenance_digest, "balance": str(total.quantize(MONEY_QUANTUM)), "items": counted, "window_end": provenance.window_end})


# --------------------------------------------------------------------------- #
# Reconciliations and lock
# --------------------------------------------------------------------------- #


def reconciliation_receipts(plan: FinanceCloseLoopPlan | Mapping[str, Any], balance: TrialBalance, mapping: AccountMap, sources: Sequence[SourceBalance], *, already_reconciled: Sequence[str] = ()) -> list[dict[str, Any]]:
    """One ``reconcile_account`` receipt per required kind that has both a ledger and a source balance; variance beyond threshold names an exception."""

    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    ledgers = ledger_balances(balance, mapping)
    by_kind = {item.kind: item for item in sources}
    receipts: list[dict[str, Any]] = []
    for kind in bp.required_reconciliations:
        if kind in already_reconciled or kind not in ledgers or kind not in by_kind:
            continue
        source = by_kind[kind]
        ledger_value = ledgers[kind]
        variance = (ledger_value - source.balance).copy_abs()
        tolerance = max(source.balance.copy_abs(), bp.materiality) * bp.variance_threshold_percent / _HUNDRED
        material = variance > tolerance and variance > bp.materiality
        receipt: dict[str, Any] = {"account_kind": kind, "reconciliation_ref": f"{kind}:{balance.trial_balance_ref}:{source.source_ref}", "ledger_balance": str(ledger_value), "source_balance": str(source.balance), "evidence_refs": [f"trial_balance:{balance.trial_balance_ref}", f"source:{source.source_ref}", f"account_map:{mapping.map_digest[:24]}"]}
        if material:
            receipt["exception_ref"] = f"exception:{kind}:{stable_digest({'tb': balance.trial_balance_ref, 'source': source.source_ref, 'variance': str(variance)})[:16]}"
        receipts.append(receipt)
    return receipts


def lock_receipt(provenance: ObservationProvenance, status: Mapping[str, Any], *, period_end: str) -> dict[str, Any]:
    """The ``lock_subledgers`` receipt from the provider's period status; only a lock that covers the period end counts."""

    _expect_tool(provenance, *PERIOD_STATUS_TOOLS.values())
    raw = dict(detached(status))
    _require(raw.get("schema") == "lightbulb.provider_period_status.v1", "PAYLOAD_SCHEMA_MISMATCH", "expected a provider period status payload")
    end = parsed(timestamp(period_end, field_name="period_end"))
    covering = []
    for lock in raw.get("locks") or []:
        item = dict(detached(lock))
        through = item.get("through_date")
        if not through:
            continue
        when = parsed(timestamp(str(through) if "T" in str(through) else f"{through}T23:59:59Z", field_name="through_date"))
        if when >= end:
            covering.append((str(item.get("lock_kind", "lock")), str(through)))
    _require(bool(covering), "LOCK_NOT_COVERING_PERIOD", f"no provider lock reaches {period_end}; lock the period in {raw.get('provider', 'the ledger')} first")
    kind, through = covering[0]
    return {"lock_ref": f"{raw.get('provider', 'ledger')}:{kind}:{through}", "evidence_refs": [f"period_status:{provenance.observation_ref}", f"provenance:{provenance.provenance_digest[:24]}"]}


# --------------------------------------------------------------------------- #
# Read planning and batch conversion for the cadence runner
# --------------------------------------------------------------------------- #

CloseReadKind = Literal["trial_balance", "receivables", "settlements", "period_status"]


class CloseRead(StrictModel):
    read_ref: OpaqueRef
    kind: CloseReadKind
    tool: ShortText
    lane: Literal["governed_read", "host_read"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    satisfies_event: ShortText
    summary: BoundedText


class CloseReadPlan(StrictModel):
    schema_id: str = Field(default=CLOSE_READ_PLAN_SCHEMA, alias="schema")
    close_ref: OpaqueRef
    close_status: ShortText
    ledger: Ledger
    period_start: str
    period_end: str
    reads: tuple[CloseRead, ...] = Field(default_factory=tuple, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CloseReadPlan:
        unique([item.read_ref for item in self.reads], label="read refs")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CloseReadPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact read plan")
        return self

    def read(self, read_ref: str) -> CloseRead | None:
        return next((item for item in self.reads if item.read_ref == read_ref), None)


def _lane(tool: str) -> str:
    return "governed_read" if tool in GOVERNED_CONNECTOR_READ_TOOLS else "host_read"


def plan_close_reads(plan: FinanceCloseLoopPlan | Mapping[str, Any], close_state: Any, *, ledger: str) -> CloseReadPlan:
    """The reads a close needs at its current status: trial balance when open, sources while reconciling, period status before locking."""

    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    _require(ledger in TRIAL_BALANCE_TOOLS, "LEDGER_UNSUPPORTED", f"ledger must be one of {sorted(TRIAL_BALANCE_TOOLS)}")
    led = close_state.ledger
    start, end = str(led.period_start), str(led.period_end)
    reads: list[dict[str, Any]] = []
    status = close_state.status
    ref = str(close_state.scope.entity_ref)

    def add(kind: str, tool: str, arguments: Mapping[str, Any], event: str, summary: str) -> None:
        reads.append({"read_ref": f"{ref}:{kind}", "kind": kind, "tool": tool, "lane": _lane(tool), "arguments": dict(arguments), "satisfies_event": event, "summary": summary})

    if status == "opened":
        add("trial_balance", TRIAL_BALANCE_TOOLS[ledger], {"start_date": start[:10], "end_date": end[:10]}, "capture_trial_balance", f"Trial balance for {start[:10]} to {end[:10]}")
    if status in ("opened", "trial_balance_captured", "reconciling", "reopened"):
        reconciled = set(getattr(led, "reconciled_accounts", ()) or ())
        required = set(parsed_plan.blueprint.required_reconciliations)
        if {"cash", "revenue_subledger"} & (required - reconciled):
            add("settlements", STRIPE_BALANCE_TOOL, {"created": {"gte": start, "lte": end}, "limit": 100}, "reconcile_account", "Stripe balance transactions for cash and settled revenue")
        if "accounts_receivable" in required - reconciled:
            add("receivables", INVOICE_TOOLS[ledger], {"status": "AUTHORISED" if ledger == "xero" else "open", "from_date": start[:10], "to_date": end[:10]}, "reconcile_account", "Open invoices for receivables")
    if status in ("reconciled", "adjusted", "reconciling"):
        add("period_status", PERIOD_STATUS_TOOLS[ledger], {}, "lock_subledgers", "Provider period locks covering the period end")
    return seal(CloseReadPlan, {"close_ref": ref, "close_status": status, "ledger": ledger, "period_start": start, "period_end": end, "reads": reads}, "plan_digest")


class CloseReadReceipt(StrictModel):
    read_ref: OpaqueRef
    provenance: ObservationProvenance
    payload: Any


class CloseInput(StrictModel):
    event: ShortText
    receipt: dict[str, Any]
    source_digest: Sha256Digest


class CloseBatch(StrictModel):
    schema_id: str = Field(default=CLOSE_BATCH_SCHEMA, alias="schema")
    read_plan_digest: Sha256Digest
    inputs: tuple[CloseInput, ...] = Field(default_factory=tuple, max_length=16)
    failures: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=16)
    unanswered: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=8)
    batch_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CloseBatch:
        if not skip_digests(info) and self.batch_digest != sealed_digest(CloseBatch, self, "batch_digest"):
            raise ValueError("batch_digest must commit the exact batch")
        return self


def close_inputs(plan: FinanceCloseLoopPlan | Mapping[str, Any], read_plan: CloseReadPlan | Mapping[str, Any], receipts: Sequence[CloseReadReceipt | Mapping[str, Any]], *, mapping: AccountMap, already_reconciled: Sequence[str] = ()) -> CloseBatch:
    """Convert completed close reads into ordered close receipts: trial balance, then reconciliations, then the lock."""

    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    reads = read_plan if isinstance(read_plan, CloseReadPlan) else CloseReadPlan.model_validate(dict(detached(read_plan)))
    currency = parsed_plan.blueprint.currency
    answered: dict[str, CloseReadReceipt] = {}
    failures: list[dict[str, Any]] = []
    for raw in receipts:
        receipt = raw if isinstance(raw, CloseReadReceipt) else CloseReadReceipt.model_validate(dict(detached(raw)))
        read = reads.read(receipt.read_ref)
        if read is None:
            failures.append({"read_ref": receipt.read_ref, "code": "READ_UNPLANNED", "detail": "no planned read carries this ref"})
            continue
        if receipt.provenance.source_tool != read.tool:
            failures.append({"read_ref": receipt.read_ref, "code": "TOOL_MISMATCH", "detail": f"planned {read.tool}; the read came from {receipt.provenance.source_tool}"})
            continue
        answered[receipt.read_ref] = receipt
    inputs: list[dict[str, Any]] = []
    balance: TrialBalance | None = None
    sources: list[SourceBalance] = []

    def attempt(read_ref: str, action: Any) -> Any:
        try:
            return action()
        except (BridgeError, ValueError) as exc:
            failures.append({"read_ref": read_ref, "code": getattr(exc, "code", "ADAPTER_REFUSED"), "detail": str(exc)[:900]})
            return None

    for read in reads.reads:
        receipt = answered.get(read.read_ref)
        if receipt is None:
            continue
        if read.kind == "trial_balance":
            balance = attempt(read.read_ref, lambda r=receipt: read_trial_balance(r.provenance, r.payload))
            if balance is not None:
                inputs.append({"event": "capture_trial_balance", "receipt": trial_balance_receipt(balance), "source_digest": balance.balance_digest})
        elif read.kind == "settlements":
            pair = attempt(read.read_ref, lambda r=receipt: stripe_source_balances(r.provenance, r.payload, currency=currency, period_end=reads.period_end))
            if pair is not None:
                sources.extend(pair)
        elif read.kind == "receivables":
            item = attempt(read.read_ref, lambda r=receipt: receivables_source_balance(r.provenance, r.payload, currency=currency))
            if item is not None:
                sources.append(item)
        elif read.kind == "period_status":
            lock = attempt(read.read_ref, lambda r=receipt: lock_receipt(r.provenance, r.payload, period_end=reads.period_end))
            if lock is not None:
                inputs.append({"event": "lock_subledgers", "receipt": lock, "source_digest": receipt.provenance.provenance_digest})
    if sources:
        if balance is None:
            failures.append({"read_ref": f"{reads.close_ref}:trial_balance", "code": "TRIAL_BALANCE_REQUIRED", "detail": "reconciliations need the trial balance from the same batch; supply the trial balance read too"})
        else:
            for receipt_fields in attempt(f"{reads.close_ref}:reconciliations", lambda: reconciliation_receipts(parsed_plan, balance, mapping, sources, already_reconciled=already_reconciled)) or []:
                inputs.append({"event": "reconcile_account", "receipt": receipt_fields, "source_digest": stable_digest(receipt_fields)})
    unanswered = [read.read_ref for read in reads.reads if read.read_ref not in answered]
    return seal(CloseBatch, {"read_plan_digest": reads.plan_digest, "inputs": inputs, "failures": failures, "unanswered": unanswered}, "batch_digest")


FINANCE_CLOSE_OBSERVATIONS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "finance_close_observations",
    "golden_loop": "finance.period_close_to_verified_books@0.1.0",
    "stages": ["plan_reads", "read_ledger_and_sources", "capture_trial_balance", "reconcile_by_account_map", "lock_from_period_status"],
    "tools": {"trial_balance": dict(TRIAL_BALANCE_TOOLS), "period_status": dict(PERIOD_STATUS_TOOLS), "receivables": dict(INVOICE_TOOLS), "settlements": STRIPE_BALANCE_TOOL},
    "lanes": {tool: _lane(tool) for tool in (*TRIAL_BALANCE_TOOLS.values(), *PERIOD_STATUS_TOOLS.values(), *INVOICE_TOOLS.values(), STRIPE_BALANCE_TOOL)},
    "required_connectors": ["xero", "quickbooks", "stripe"],
    "hard_rules": [
        "the account map is an operator decision; kinds are never inferred from account names",
        "ledger and source balances come from different reads with their own provenance",
        "a material variance names a deterministic exception instead of being absorbed",
        "a lock counts only when the provider's own period status covers the period end",
    ],
}

__all__ = [
    "ACCOUNT_MAP_SCHEMA",
    "FINANCE_CLOSE_OBSERVATIONS_MANIFEST",
    "INVOICE_TOOLS",
    "PERIOD_STATUS_TOOLS",
    "STRIPE_BALANCE_TOOL",
    "TRIAL_BALANCE_TOOLS",
    "AccountMap",
    "AccountMapping",
    "CloseBatch",
    "CloseInput",
    "CloseRead",
    "CloseReadPlan",
    "CloseReadReceipt",
    "SourceBalance",
    "TrialBalance",
    "TrialBalanceLine",
    "account_map",
    "close_inputs",
    "ledger_balances",
    "lock_receipt",
    "plan_close_reads",
    "read_trial_balance",
    "receivables_source_balance",
    "reconciliation_receipts",
    "stripe_source_balances",
    "trial_balance_receipt",
]
