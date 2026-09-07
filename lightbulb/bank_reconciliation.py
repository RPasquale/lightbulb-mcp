"""Bank reconciliation: the case that makes the cash line true, one account per period.

Every other cash claim in the runtime hangs off a page nobody reconciled.
``company_treasury.cash_position`` sums a balance read and calls it available
cash; ``finance_close`` expects a ``SourceBalance(kind='cash')`` that
``finance_close_observations`` only ever derived from Stripe and receivables;
``revenue_chain.settle_cash`` and ``payables_chain.apply_payment`` each trust
one provider observation with no proof the money reached the bank.  This
engine is the spine those claims should hang from::

    opened -> lines_loaded -> matched -> reconciled              (terminal)
    lines_loaded | matched -> exception_raised -> matched
    matched | exception_raised -> variance_resolved -> reconciled
    any non-terminal -> abandoned                                (terminal)

What it proves, and from which sealed artifacts:

* ``open_receipt`` takes the **prior reconciled case's** sealed
  ``statement_closing`` as this period's opening balance, so the opening is a
  continuation and never a number somebody typed (an operator opening is
  allowed only for a declared first period, and names itself as operator
  input).
* ``lines_receipt`` normalizes a bank/payout line page (Xero bank
  transactions, Airwallex transactions, QuickBooks deposits, Square payouts,
  PayPal transactions) with its ``ObservationProvenance`` into line_count,
  credits, debits and coverage, and takes the closing balance from an
  independent balance read (a treasury ``CashPosition``).  ``opening +
  credits - debits`` must equal that closing or the statement is refused.
* ``match_receipt`` settles bank lines against **another engine's sealed
  state digest** — a revenue chain settlement, a payables chain payment, a
  payroll run, a card settlement, a disbursement run, a payout run — never a
  caller's assertion, and one bank line settles one thing.
* ``financing_receipt`` classifies a large unexplained inflow as financing
  against a named instrument and an approval reference; a financing inflow
  offered as period revenue evidence is refused, so a raise never inflates
  the return-on-spend priors.
* ``ledger_receipt`` reuses ``finance_close_observations.read_trial_balance``
  and ``ledger_balances(map, 'cash')`` over the governed trial balance, so
  the ledger side of the difference is the books, not a guess.

What it hands on: ``cash_source_balance`` is the ``SourceBalance(kind='cash')``
that ``reconciliation_receipts`` already expected and nothing produced;
``reconciled_position`` is a ``company_treasury.CashPosition`` built on a
reconciled balance rather than an unreconciled page;
``books_reconciliation_receipt`` turns a sealed ``BooksVerification`` into the
company operating system's ``reconcile`` receipt and refuses a bare boolean;
``unmatched_line_exception`` opens an exceptions-desk case for a line nothing
settles.  Nothing here reads a provider, writes a ledger, or moves money.
"""

from __future__ import annotations

import re
import hashlib
import importlib
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import BridgeError, ObservationProvenance
from lightbulb.company_treasury import CashPosition
from lightbulb.finance_close_engine import BooksVerification
from lightbulb.finance_close_observations import AccountMap, SourceBalance, TrialBalance, ledger_balances
from lightbulb.governed_connector_contracts import GOVERNED_CONNECTOR_READ_TOOLS

BANK_REC_KIND = "bank_reconciliation"
BANK_REC_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
BANK_REC_PLAN_SCHEMA = "lightbulb.bank_reconciliation_plan.v1"
BOOKS_VERIFICATION_SCHEMA = "lightbulb.books_verification.v1"
#: The settlement-evidence document ``payroll_run_chain.payment_receipt`` (and
#: the disbursement and payout hops behind it) reads back from a reconciled line.
BANK_MATCH_SCHEMA = "lightbulb.bank_reconciliation_match.v1"
MAX_BANK_REC_TRANSITIONS = 24

#: Bank/payout line pages this engine can normalize.  Only ``stripe`` is
#: governed on the bank side today; the rest run in the host lane until one
#: governed bank-line contract exists (see ``MISSING_GOVERNED_READS``).
BANK_LINE_TOOLS: tuple[str, ...] = ("xero.list_bank_transactions", "airwallex.list_transactions", "quickbooks.list_deposits", "square.list_payouts", "paypal.list_transactions")
#: The governed reads that carry ledger entry detail behind the trial balance.
ENTRY_DETAIL_TOOLS: tuple[str, ...] = ("quickbooks.general_ledger_report", "xero.list_journals")
MISSING_GOVERNED_READS: tuple[str, ...] = tuple(tool for tool in BANK_LINE_TOOLS if tool not in GOVERNED_CONNECTOR_READ_TOOLS)
#: Exceptions-desk kind for a bank line nothing settles.  ``unmatched_bank_line``
#: is not registered in ``exceptions_desk.RESOLUTION_PATHS`` yet; until it is,
#: an unmatched line opens as a chain reconciliation.
UNMATCHED_LINE_EXCEPTION_KIND = "chain_reconciliation"

BANK_REC_STATUSES: tuple[str, ...] = ("opened", "lines_loaded", "matched", "variance_resolved", "reconciled", "exception_raised", "abandoned")
TERMINAL_BANK_REC_STATUSES: frozenset[str] = frozenset({"reconciled", "abandoned"})
BANK_REC_EVENTS: tuple[str, ...] = ("open", "load_lines", "match", "classify_financing", "raise_exception", "resolve_variance", "reconcile", "abandon")
_BANK_REC_TABLE: dict[tuple[str, str], str] = {
    ("new", "open"): "opened",
    ("opened", "load_lines"): "lines_loaded",
    ("lines_loaded", "match"): "matched",
    ("lines_loaded", "classify_financing"): "matched",
    ("lines_loaded", "reconcile"): "reconciled",
    ("matched", "match"): "matched",
    ("matched", "classify_financing"): "matched",
    ("lines_loaded", "raise_exception"): "exception_raised",
    ("matched", "raise_exception"): "exception_raised",
    ("exception_raised", "match"): "matched",
    ("exception_raised", "resolve_variance"): "variance_resolved",
    ("matched", "resolve_variance"): "variance_resolved",
    ("matched", "reconcile"): "reconciled",
    ("variance_resolved", "reconcile"): "reconciled",
    **{(status, "abandon"): "abandoned" for status in ("opened", "lines_loaded", "matched", "variance_resolved", "exception_raised")},
}

#: What a bank line may be settled against: the sealed state of another engine,
#: the state schema that engine's lifecycle stamps, which statuses of it count
#: as settled, and where its amount lives.  ``SHIPPED_COUNTERPARTS`` names the
#: entries checked against a lifecycle that exists in this package today; the
#: rest are forward declarations for engines that have not shipped, and their
#: statuses and amount fields are unproven until they do.
COUNTERPART_KINDS: dict[str, dict[str, Any]] = {
    "revenue_chain": {"state_schema": "lightbulb.revenue_chain_state.v1", "statuses": ("cash_settled", "receivable_cleared"), "amount_fields": ("settled_amount",), "reference_prefix": "LB-AR-"},
    "payables_chain": {"state_schema": "lightbulb.payables_chain_state.v1", "statuses": ("paid", "cleared"), "amount_fields": ("applied_amount",), "reference_prefix": "LB-AP-"},
    "payroll_run_chain": {"state_schema": "lightbulb.payroll_run_state.v1", "statuses": ("funded", "paid", "liabilities_reserved", "reconciled"), "amount_fields": ("net",), "reference_prefix": "LB-PAY-"},
    "spend_control_chain": {"state_schema": "lightbulb.spend_item_state.v1", "statuses": ("posted", "cleared"), "amount_fields": ("amount",), "reference_prefix": "LB-CARD-"},
    "disbursement_run": {"state_schema": "lightbulb.disbursement_run_state.v1", "statuses": ("released", "settled", "reconciled"), "amount_fields": ("released_total",), "reference_prefix": "LB-DR-"},
    "payout_chain": {"state_schema": "lightbulb.payout_chain_state.v1", "statuses": ("released", "settled", "cleared"), "amount_fields": ("released_amount", "settled_amount", "amount"), "reference_prefix": "LB-PO-"},
}
#: Counterpart kinds whose engine ships in this package; the rest are declared
#: ahead of the engines that will produce them.
SHIPPED_COUNTERPARTS: tuple[str, ...] = ("revenue_chain", "payables_chain", "payroll_run_chain")
#: Counterparts whose money is period revenue; a financing inflow may never settle one.
REVENUE_COUNTERPARTS: frozenset[str] = frozenset({"revenue_chain"})
FINANCING_INSTRUMENTS: tuple[str, ...] = ("term_loan", "credit_line_draw", "convertible_note", "equity_raise", "shareholder_loan", "grant", "government_rebate")

_REF_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
_EPOCH = re.compile(r"^(-?\d+)")


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class BankReconciliationPlan(StrictModel):
    """What this account's reconciliation enforces: the ledger it ties to, the tolerances, and how fresh the balance must be."""

    schema_id: Literal["lightbulb.bank_reconciliation_plan.v1"] = Field(default=BANK_REC_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    account_ref: OpaqueRef
    currency: ShortText
    ledger: Literal["xero", "quickbooks"] = "xero"
    materiality: Decimal = Field(default=Decimal("50.00"), validate_default=True)
    max_unmatched_value: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    require_opening_continuity: bool = True
    stale_balance_hours: int = Field(default=72, ge=1, le=8760)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("materiality", "max_unmatched_value", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BankReconciliationPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(BankReconciliationPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_bank_reconciliation(company_ref: str, *, account_ref: str, currency: str, overrides: Mapping[str, Any] | None = None) -> BankReconciliationPlan:
    return seal(BankReconciliationPlan, {"company_ref": company_ref, "account_ref": account_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class BankBalanceObservation(StrictModel):
    """One account balance in a platform-normalized, digest-bound host read.

    The platform supplies ``lightbulb.bank_balance.v1`` with account_ref,
    currency, balance and observed_at. A portfolio CashPosition cannot establish
    this account's opening or closing balance.
    """

    schema_id: Literal["lightbulb.bank_balance_observation.v1"] = Field(default="lightbulb.bank_balance_observation.v1", alias="schema")
    provenance: ObservationProvenance
    payload: dict[str, Any]
    account_ref: OpaqueRef
    currency: ShortText
    balance: Decimal
    observed_at: str
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("balance", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="balance", allow_negative=True)

    @field_validator("observed_at")
    @classmethod
    def _at(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BankBalanceObservation:
        raw = self.payload
        if raw.get("schema") != "lightbulb.bank_balance.v1" or self.provenance.source_tool != "host.bank_balance" or self.provenance.lane != "host_read":
            raise ValueError("BALANCE_NOT_SEALED: expected the normalized host.bank_balance observation")
        if stable_digest(raw) != self.provenance.output_digest:
            raise ValueError("OBSERVATION_DIGEST_MISMATCH: the balance does not match its read")
        if (raw.get("account_ref"), raw.get("currency"), _money(raw.get("balance"), "balance"), raw.get("observed_at")) != (self.account_ref, self.currency, self.balance, self.observed_at):
            raise ValueError("BALANCE_NOT_SEALED: derived balance fields differ from the observation")
        if parsed(self.observed_at) > parsed(self.provenance.completed_at):
            raise ValueError("BALANCE_NOT_SEALED: observation is newer than the completed read")
        if not skip_digests(info) and self.observation_digest != sealed_digest(BankBalanceObservation, self, "observation_digest"):
            raise ValueError("BALANCE_NOT_SEALED: observation_digest must commit the balance")
        return self


def bank_balance_observation(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any]) -> BankBalanceObservation:
    """Normalize a trusted host bank balance read; no SDK read is performed."""
    raw = dict(detached(payload))
    try:
        return seal(BankBalanceObservation, {"provenance": detached(provenance), "payload": raw, "account_ref": raw.get("account_ref"), "currency": raw.get("currency"), "balance": raw.get("balance"), "observed_at": raw.get("observed_at")}, "observation_digest")
    except ValueError as exc:
        raise BankReconciliationError("BALANCE_NOT_SEALED", str(exc)) from exc


# --------------------------------------------------------------------------- #
# Receipt, ledger, effect boundary
# --------------------------------------------------------------------------- #


class BankLineRow(StrictModel):
    """One normalized bank line: signed in the account's own direction, never converted."""

    line_ref: OpaqueRef
    occurred_at: str
    amount: Decimal
    direction: Literal["credit", "debit"]
    reference: ShortText | None = None
    provider_reconciled: bool = False

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(str(value), field_name="amount", allow_negative=True)

    @field_validator("occurred_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")


class BankMatch(StrictModel):
    counterpart_kind: ShortText
    counterpart_ref: OpaqueRef
    counterpart_state_digest: Sha256Digest
    correlation_sha256: Sha256Digest | None = None
    amount: Decimal
    line_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("line_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(str(value), field_name="amount", allow_negative=True)


class BankException(StrictModel):
    exception_ref: OpaqueRef
    code: ShortText
    detail: BoundedText | None = None
    line_ref: OpaqueRef | None = None
    resolved: bool = False
    resolution_ref: OpaqueRef | None = None


class BankReconciliationReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    # open
    account_ref: OpaqueRef | None = None
    currency: ShortText | None = None
    period_start: str | None = None
    period_end: str | None = None
    opening_balance: Decimal | None = None
    opening_source: Literal["prior_case", "balance_observation"] | None = None
    opening_observation: BankBalanceObservation | None = None
    prior_state: dict[str, Any] | None = None
    prior_plan: dict[str, Any] | None = None
    prior_state_digest: Sha256Digest | None = None
    prior_coverage_end: str | None = None
    first_period: bool | None = None
    # load_lines
    line_count: int | None = Field(default=None, ge=0, le=5000)
    statement_credits: Decimal | None = None
    statement_debits: Decimal | None = None
    statement_closing: Decimal | None = None
    coverage_start: str | None = None
    coverage_end: str | None = None
    balance_observed_at: str | None = None
    balance_source_tool: ShortText | None = None
    balance_provenance_digest: Sha256Digest | None = None
    source_tool: ShortText | None = None
    provenance_digest: Sha256Digest | None = None
    lines: tuple[BankLineRow, ...] = Field(default_factory=tuple, max_length=5000)
    lines_provenance: ObservationProvenance | None = None
    lines_payload: dict[str, Any] | None = None
    closing_observation: BankBalanceObservation | None = None
    # match
    line_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    counterpart_kind: ShortText | None = None
    counterpart_ref: OpaqueRef | None = None
    counterpart_state_digest: Sha256Digest | None = None
    counterpart_status: ShortText | None = None
    counterpart_amount: Decimal | None = None
    correlation_sha256: Sha256Digest | None = None
    counterpart_state: dict[str, Any] | None = None
    counterpart_plan: dict[str, Any] | None = None
    counterpart_currency: ShortText | None = None
    payment_correlation: OpaqueRef | None = None
    # classify_financing
    financing_line_ref: OpaqueRef | None = None
    instrument: ShortText | None = None
    approval_ref: OpaqueRef | None = None
    operator_supplied: bool | None = None
    # exceptions and variance
    exception_ref: OpaqueRef | None = None
    code: ShortText | None = None
    detail: BoundedText | None = None
    resolution_ref: OpaqueRef | None = None
    explanation: BoundedText | None = None
    # ledger side
    ledger_balance: Decimal | None = None
    trial_balance_ref: OpaqueRef | None = None
    account_map_digest: Sha256Digest | None = None
    ledger_source_digest: Sha256Digest | None = None
    trial_balance: TrialBalance | None = None
    account_map: AccountMap | None = None
    entry_count: int | None = Field(default=None, ge=0, le=100000)

    @field_validator("evidence_refs", "line_refs", "lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("opening_balance", "statement_credits", "statement_debits", "statement_closing", "counterpart_amount", "ledger_balance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(str(value), field_name=str(info.field_name), allow_negative=True)

    @field_validator("period_start", "period_end", "prior_coverage_end", "coverage_start", "coverage_end", "balance_observed_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class BankReconciliationLedger(StrictModel):
    entity_scope: EngineScope | None = None
    account_ref: str | None = None
    currency: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    opening_balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    opening_source: str | None = None
    prior_state_digest: str | None = None
    prior_coverage_end: str | None = None
    statement_credits: Decimal = Field(default=Decimal("0"), validate_default=True)
    statement_debits: Decimal = Field(default=Decimal("0"), validate_default=True)
    statement_closing: Decimal = Field(default=Decimal("0"), validate_default=True)
    line_count: int = Field(default=0, ge=0)
    lines: tuple[BankLineRow, ...] = Field(default_factory=tuple, max_length=5000)
    matched_lines: int = Field(default=0, ge=0)
    matched_line_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=5000)
    matches: tuple[BankMatch, ...] = Field(default_factory=tuple, max_length=5000)
    unmatched_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    financing_line_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=500)
    financing_inflows: Decimal = Field(default=Decimal("0"), validate_default=True)
    coverage_start: str | None = None
    coverage_end: str | None = None
    balance_observed_at: str | None = None
    exceptions: tuple[BankException, ...] = Field(default_factory=tuple, max_length=500)
    variance_explanation: str | None = None
    ledger_balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    difference: Decimal = Field(default=Decimal("0"), validate_default=True)
    trial_balance_ref: str | None = None
    account_map_digest: str | None = None
    reconciled_at: str | None = None
    days_to_reconcile: int | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "reconciled", "abandoned"] = "open"

    @field_validator("opening_balance", "statement_credits", "statement_debits", "statement_closing", "unmatched_value", "financing_inflows", "ledger_balance", "difference", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(str(value), field_name=str(info.field_name), allow_negative=True)

    @field_validator("lines", "matches", "exceptions", "matched_line_refs", "financing_line_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @property
    def open_exceptions(self) -> tuple[BankException, ...]:
        return tuple(item for item in self.exceptions if not item.resolved)


class BankReconciliationEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    bank_line_marked_reconciled: Literal[False] = False
    journal_posted: Literal[False] = False
    money_moved: Literal[False] = False


# --------------------------------------------------------------------------- #
# The lifecycle
# --------------------------------------------------------------------------- #


def _dec(value: Any) -> Decimal:
    return decimal_value(str(value if value not in (None, "") else "0"), field_name="amount", allow_negative=True)


def _unmatched(lines: Sequence[Mapping[str, Any]], settled: Sequence[str]) -> Decimal:
    done = set(settled)
    return sum((_dec(line["amount"]).copy_abs() for line in lines if str(line["line_ref"]) not in done), Decimal("0")).quantize(MONEY_QUANTUM)


def _derived_receipt(builder: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return builder(*args, **kwargs)
    except BankReconciliationError as exc:
        require(False, exc.code, str(exc))
    raise AssertionError("unreachable")


def _same_derived(receipt: Any, expected: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    actual = receipt.to_dict()
    normalized = BankReconciliationReceipt.model_validate(expected).to_dict()
    require(all(actual.get(key) == normalized.get(key) for key in fields), code, "receipt values must be derived from the retained sealed artifacts")


def _apply_bank_reconciliation(plan: BankReconciliationPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    lines: list[dict[str, Any]] = [dict(item) for item in data.get("lines", ())]
    matched: list[str] = list(data.get("matched_line_refs", ()))
    financing: list[str] = list(data.get("financing_line_refs", ()))

    if event == "open":
        if r.entity_scope is not None:
            require(command.expected_state_digest == BANK_REC_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "COUNTERPART_SCOPE_MISMATCH", "the retained reconciliation scope belongs to this bank case")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.account_ref is not None and r.currency is not None and r.period_start is not None and r.period_end is not None and r.opening_balance is not None and r.opening_source is not None, "OPENING_MISSING", "a case opens with the account, currency, period bounds, and an opening balance that names where it came from")
        require(r.account_ref == plan.account_ref, "ACCOUNT_MISMATCH", f"this plan reconciles {plan.account_ref}, not {r.account_ref}")
        require(str(r.currency).upper() == plan.currency, "CURRENCY_MISMATCH", f"the case is in {r.currency}; the plan runs in {plan.currency}; balances are never converted")
        require(parsed(str(r.period_end)) > parsed(str(r.period_start)), "PERIOD_INVERTED", "period_end is after period_start")
        if plan.require_opening_continuity:
            require(r.prior_state_digest is not None or r.first_period is True, "COVERAGE_GAP", "the opening balance does not continue a prior reconciled case; open from the prior case's sealed statement_closing or declare the first period")
        expected = _derived_receipt(open_receipt, r.prior_state, prior_plan=r.prior_plan, account_ref=r.account_ref, currency=r.currency, period_start=r.period_start, period_end=r.period_end, opening_balance=r.opening_observation, first_period=r.first_period is True)
        _same_derived(r, expected, ("opening_balance", "opening_source", "prior_state_digest", "prior_coverage_end"), "OPENING_NOT_SEALED")
        if r.prior_state is not None:
            require(r.prior_plan is not None and r.prior_plan.get("company_ref") == plan.company_ref, "ACCOUNT_MISMATCH", "the prior plan belongs to this company")
            require(data.get("entity_scope") is not None and _scope_matches(data["entity_scope"], r.prior_state.get("scope", {})), "COUNTERPART_SCOPE_MISMATCH", "the prior statement must share the authenticated company and project")
        data.update({"account_ref": r.account_ref, "currency": str(r.currency).upper(), "period_start": r.period_start, "period_end": r.period_end, "opening_balance": str(r.opening_balance), "opening_source": r.opening_source, "prior_state_digest": r.prior_state_digest, "prior_coverage_end": r.prior_coverage_end})
    elif event == "load_lines":
        require(r.currency is not None and r.line_count is not None and r.statement_credits is not None and r.statement_debits is not None and r.statement_closing is not None and r.coverage_start is not None and r.coverage_end is not None and r.balance_observed_at is not None, "LINES_MISSING", "a line load names the currency, the line count, credits, debits, the closing balance from an independent balance read, the coverage window, and when the balance was observed")
        require(str(r.currency).upper() == str(data.get("currency")), "CURRENCY_MISMATCH", f"the page is in {r.currency}; the case is in {data.get('currency')}; cross-currency balances are refused, never converted")
        require(len(r.lines) == r.line_count, "LINE_COUNT_INVALID", "the receipt carries exactly the lines the complete statement returned")
        counted_credits = sum((row.amount for row in r.lines if row.amount > 0), Decimal("0")).quantize(MONEY_QUANTUM)
        counted_debits = sum((-row.amount for row in r.lines if row.amount < 0), Decimal("0")).quantize(MONEY_QUANTUM)
        signed = all((row.amount > 0) == (row.direction == "credit") for row in r.lines)
        require(counted_credits == r.statement_credits and counted_debits == r.statement_debits and signed, "STATEMENT_TOTALS_INCONSISTENT", f"the rows carry credits {counted_credits} and debits {counted_debits} in the direction they name; the receipt claims {r.statement_credits} and {r.statement_debits}")
        require(r.lines_provenance is not None and r.lines_payload is not None, "OBSERVATION_NOT_SEALED", "bank lines retain the payload and provenance of the exact read")
        expected = _derived_receipt(lines_receipt, r.lines_provenance, r.lines_payload, currency=r.currency, position=r.closing_observation)
        _same_derived(r, expected, ("account_ref", "lines", "line_count", "statement_credits", "statement_debits", "statement_closing", "coverage_start", "coverage_end", "balance_observed_at", "source_tool", "provenance_digest", "balance_source_tool", "balance_provenance_digest"), "OBSERVATION_NOT_SEALED")
        require(r.account_ref == plan.account_ref, "ACCOUNT_MISMATCH", "bank lines and closing balance must name this account")
        hours = (parsed(at) - parsed(str(r.balance_observed_at))).total_seconds() / 3600
        require(0 <= hours <= plan.stale_balance_hours, "STALE_BALANCE", f"the balance was observed {int(hours)}h ago; this plan reconciles on a balance no older than {plan.stale_balance_hours}h", "refresh_state")
        prior_end = data.get("prior_coverage_end")
        if prior_end:
            require(parsed(str(r.coverage_start)) >= parsed(str(prior_end)), "COVERAGE_OVERLAP", f"coverage starts {r.coverage_start}, inside the prior case which covered through {prior_end}", "do_not_replay")
            require(parsed(str(r.coverage_start)) <= parsed(str(prior_end)), "COVERAGE_GAP", f"coverage starts {r.coverage_start} but the prior case covered only through {prior_end}; the days between are unreconciled")
        require(r.coverage_start == data.get("period_start") and r.coverage_end == data.get("period_end"), "COVERAGE_GAP", "the statement must cover the exact case period")
        opening = _dec(data.get("opening_balance"))
        derived = (opening + r.statement_credits - r.statement_debits).quantize(MONEY_QUANTUM)
        require(derived == r.statement_closing, "STATEMENT_UNBALANCED", f"opening {opening} + credits {r.statement_credits} - debits {r.statement_debits} is {derived}, not the observed closing {r.statement_closing}")
        rows = [item.to_dict() for item in r.lines]
        data.update({"line_count": r.line_count, "statement_credits": str(r.statement_credits), "statement_debits": str(r.statement_debits), "statement_closing": str(r.statement_closing), "coverage_start": r.coverage_start, "coverage_end": r.coverage_end, "balance_observed_at": r.balance_observed_at, "lines": rows, "matched_lines": 0, "unmatched_value": str(_unmatched(rows, ()))})
    elif event == "match":
        require(len(r.line_refs) > 0 and r.counterpart_kind is not None and r.counterpart_ref is not None and r.counterpart_amount is not None, "MATCH_MISSING", "a match names the bank lines, the counterpart, and the amount the counterpart settled")
        require(r.counterpart_state_digest is not None, "COUNTERPART_NOT_SEALED", "a match names another engine's sealed state digest, never a caller assertion")
        require(str(r.counterpart_kind) in COUNTERPART_KINDS, "COUNTERPART_KIND_UNKNOWN", f"{r.counterpart_kind} is not a settleable counterpart; expected one of {sorted(COUNTERPART_KINDS)}")
        require(r.counterpart_state is not None and r.counterpart_plan is not None, "COUNTERPART_NOT_SEALED", "a match retains the sealed counterpart state and its replay plan")
        require(data.get("entity_scope") is not None and _scope_matches(data["entity_scope"], r.counterpart_state.get("scope", {})), "COUNTERPART_SCOPE_MISMATCH", "the counterpart must share the authenticated company and project during replay")
        expected = _derived_receipt(match_receipt, r.line_refs, r.counterpart_state, kind=r.counterpart_kind, counterpart_plan=r.counterpart_plan)
        _same_derived(r, expected, ("counterpart_state_digest", "counterpart_status", "counterpart_ref", "counterpart_amount", "counterpart_currency", "correlation_sha256", "payment_correlation"), "COUNTERPART_NOT_SEALED")
        require(parsed(r.counterpart_state["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "COUNTERPART_FROM_FUTURE", "the settled counterpart must already be observed before a bank match")
        require(r.counterpart_currency == plan.currency, "CURRENCY_MISMATCH", "counterpart and bank statement must share the same currency")
        require(r.counterpart_plan.get("company_ref") == plan.company_ref, "COUNTERPART_SCOPE_MISMATCH", "counterpart plan belongs to this company")
        require(len(set(r.line_refs)) == len(r.line_refs), "LINE_ALREADY_MATCHED", "a line may occur only once in one match", "do_not_replay")
        known = {str(line["line_ref"]) for line in lines}
        unknown = [ref for ref in r.line_refs if ref not in known]
        require(not unknown, "LINE_UNKNOWN", f"the statement carries no line {unknown}")
        if str(r.counterpart_kind) in REVENUE_COUNTERPARTS:
            offered = [ref for ref in r.line_refs if ref in financing]
            require(not offered, "FINANCING_AS_REVENUE", f"{offered} was classified as financing; a financing inflow is never period revenue evidence")
        replayed = [ref for ref in r.line_refs if ref in matched or ref in financing]
        require(not replayed, "LINE_ALREADY_MATCHED", f"{replayed} already settles something; one bank line settles one thing", "do_not_replay")
        require(all(str(item.get("counterpart_state_digest")) != str(r.counterpart_state_digest) for item in data.get("matches", ())), "COUNTERPART_ALREADY_MATCHED", f"{r.counterpart_ref} already settled a bank line on this case; one sealed counterpart settles one thing", "do_not_replay")
        named = [line for line in lines if str(line["line_ref"]) in set(r.line_refs)]
        require(len({str(line.get("direction")) for line in named}) == 1, "MATCH_DIRECTION_MIXED", "a match settles money moving one way; credits and debits are never netted into one settlement")
        total = sum((_dec(line["amount"]) for line in named), Decimal("0")).quantize(MONEY_QUANTUM)
        require(total.copy_abs() == r.counterpart_amount.copy_abs(), "MATCH_AMOUNT_MISMATCH", f"the named bank lines move {total.copy_abs()}; {r.counterpart_ref} settled {r.counterpart_amount}")
        require((total > 0) == (str(r.counterpart_kind) in REVENUE_COUNTERPARTS), "MATCH_DIRECTION_MISMATCH", "the direction of the bank movement must agree with its counterpart")
        prefix = str(COUNTERPART_KINDS[str(r.counterpart_kind)]["reference_prefix"])
        stray = [str(line["line_ref"]) for line in named if str(line.get("reference") or "").upper().startswith("LB-") and not str(line["reference"]).upper().startswith(prefix)]
        require(not stray, "MATCH_REFERENCE_MISMATCH", f"{stray} carry a runtime reference that is not a {r.counterpart_kind} reference ({prefix})")
        require(all((str(line.get("reference") or "") == r.payment_correlation if r.payment_correlation else hashlib.sha256(str(line.get("reference") or "").encode()).hexdigest() == r.correlation_sha256) for line in named), "MATCH_REFERENCE_MISMATCH", "each bank line must carry the exact sealed counterpart correlation")
        matched.extend(str(ref) for ref in r.line_refs)
        record = {"counterpart_kind": str(r.counterpart_kind), "counterpart_ref": str(r.counterpart_ref), "counterpart_state_digest": str(r.counterpart_state_digest), "amount": str(total), "line_refs": [str(ref) for ref in r.line_refs]}
        if r.correlation_sha256 is not None:
            record["correlation_sha256"] = str(r.correlation_sha256)
        data.update({"matches": [*data.get("matches", ()), record], "matched_line_refs": matched, "matched_lines": len(matched), "unmatched_value": str(_unmatched(lines, [*matched, *financing]))})
    elif event == "classify_financing":
        require(r.financing_line_ref is not None and r.instrument is not None and r.approval_ref is not None and r.operator_supplied is True, "FINANCING_MISSING", "financing is an operator classification: it names the line, the instrument, the approval reference, and that it was operator-supplied")
        require(r.instrument in FINANCING_INSTRUMENTS, "FINANCING_INSTRUMENT_UNKNOWN", "the classification must name a recognized financing instrument")
        row = next((line for line in lines if str(line["line_ref"]) == str(r.financing_line_ref)), None)
        require(row is not None, "LINE_UNKNOWN", f"the statement carries no line {r.financing_line_ref}")
        assert row is not None
        require(str(r.financing_line_ref) not in matched and str(r.financing_line_ref) not in financing, "LINE_ALREADY_MATCHED", f"{r.financing_line_ref} already settles something; one bank line settles one thing", "do_not_replay")
        amount = _dec(row["amount"])
        require(amount > 0, "FINANCING_NOT_INFLOW", f"{r.financing_line_ref} moves {amount}; only an inflow is financing")
        financing.append(str(r.financing_line_ref))
        data.update({"financing_line_refs": financing, "financing_inflows": str((_dec(data.get("financing_inflows")) + amount).quantize(MONEY_QUANTUM)), "unmatched_value": str(_unmatched(lines, [*matched, *financing]))})
    elif event == "raise_exception":
        require(r.exception_ref is not None and r.code is not None, "EXCEPTION_MISSING", "an exception names its reference and the code that raised it")
        existing = [dict(item) for item in data.get("exceptions", ())]
        require(all(str(item["exception_ref"]) != str(r.exception_ref) for item in existing), "EXCEPTION_DUPLICATE", f"{r.exception_ref} is already raised on this case", "do_not_replay")
        existing.append({"exception_ref": str(r.exception_ref), "code": str(r.code), "detail": r.detail, "line_ref": r.line_refs[0] if r.line_refs else None, "resolved": False, "resolution_ref": None})
        data.update({"exceptions": [{key: value for key, value in item.items() if value is not None} for item in existing]})
    elif event == "resolve_variance":
        require(r.explanation is not None and r.resolution_ref is not None, "RESOLUTION_MISSING", "resolving a variance names the evidence reference and explains what the difference is")
        existing = [dict(item) for item in data.get("exceptions", ())]
        if r.exception_ref is not None:
            match = next((item for item in existing if str(item["exception_ref"]) == str(r.exception_ref)), None)
            require(match is not None, "EXCEPTION_UNKNOWN", f"{r.exception_ref} is not an exception on this case")
            assert match is not None
            require(not match.get("resolved"), "EXCEPTION_ALREADY_RESOLVED", f"{r.exception_ref} is already resolved", "do_not_replay")
            match.update({"resolved": True, "resolution_ref": str(r.resolution_ref)})
        else:
            for item in existing:
                if not item.get("resolved"):
                    item.update({"resolved": True, "resolution_ref": str(r.resolution_ref)})
        data.update({"exceptions": [{key: value for key, value in item.items() if value is not None} for item in existing], "variance_explanation": str(r.explanation)[:900]})
        if r.ledger_balance is not None:
            expected = _derived_receipt(ledger_receipt, r.trial_balance, r.account_map)
            _same_derived(r, expected, ("ledger_balance", "trial_balance_ref", "account_map_digest", "ledger_source_digest"), "LEDGER_NOT_SEALED")
            data.update({"ledger_balance": str(r.ledger_balance), "difference": str((r.ledger_balance - _dec(data.get("statement_closing"))).quantize(MONEY_QUANTUM)), "trial_balance_ref": r.trial_balance_ref, "account_map_digest": r.account_map_digest})
    elif event == "reconcile":
        require(r.ledger_balance is not None and r.trial_balance_ref is not None, "LEDGER_BALANCE_MISSING", "reconciling names the ledger cash balance and the trial balance it came from")
        expected = _derived_receipt(ledger_receipt, r.trial_balance, r.account_map)
        _same_derived(r, expected, ("ledger_balance", "trial_balance_ref", "account_map_digest", "ledger_source_digest"), "LEDGER_NOT_SEALED")
        require(r.trial_balance.currency == plan.currency, "CURRENCY_MISMATCH", "trial balance must be in the account currency")
        require(r.trial_balance.ledger == plan.ledger, "ACCOUNT_MAP_LEDGER_MISMATCH", "trial balance must come from the plan's ledger")
        require(r.trial_balance.period_end == data.get("period_end"), "COVERAGE_GAP", "trial balance must close at the statement's period end")
        require(r.account_map.refs("cash") == (plan.account_ref,), "ACCOUNT_MISMATCH", "one-account reconciliation requires exactly that cash account in the account map")
        open_items = [item for item in data.get("exceptions", ()) if not item.get("resolved")]
        require(not open_items, "EXCEPTION_UNRESOLVED", f"{len(open_items)} exception(s) remain open on this account; resolve the variance before reconciling", "manual_reconciliation")
        unmatched = _dec(data.get("unmatched_value"))
        require(unmatched <= plan.max_unmatched_value, "UNMATCHED_ABOVE_TOLERANCE", f"{unmatched} of bank movement settles nothing; this plan allows {plan.max_unmatched_value}", "manual_reconciliation")
        difference = (r.ledger_balance - _dec(data.get("statement_closing"))).quantize(MONEY_QUANTUM)
        require(difference.copy_abs() <= plan.materiality, "LEDGER_DIFFERENCE_ABOVE_MATERIALITY", f"the ledger says {r.ledger_balance} and the bank says {data.get('statement_closing')}; {difference} is beyond {plan.materiality} materiality; explanatory text cannot change a proven balance", "manual_reconciliation")
        data.update({"ledger_balance": str(r.ledger_balance), "difference": str(difference), "trial_balance_ref": r.trial_balance_ref, "account_map_digest": r.account_map_digest, "reconciled_at": at, "days_to_reconcile": max((parsed(at) - parsed(str(data.get("period_end")))).days, 0), "outcome": "reconciled"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


BANK_REC_LIFECYCLE = LifecycleSpec(entity="bank_reconciliation", schema_prefix=BANK_REC_KIND, statuses=BANK_REC_STATUSES, terminal=TERMINAL_BANK_REC_STATUSES, events=BANK_REC_EVENTS, table=_BANK_REC_TABLE, opening_event="open", reason_events=("abandon",), apply=_apply_bank_reconciliation, ledger_model=BankReconciliationLedger, receipt_model=BankReconciliationReceipt, effect_boundary_model=BankReconciliationEffectBoundary, plan_model=BankReconciliationPlan, max_transitions=MAX_BANK_REC_TRANSITIONS)
BankReconciliationState = BANK_REC_LIFECYCLE.State


def open_bank_reconciliation(plan: BankReconciliationPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    prior = receipt.get("prior_state")
    if prior is not None:
        _require(_scope_matches(scope, dict(detached(prior)).get("scope", {})), "COUNTERPART_SCOPE_MISMATCH", "the prior bank case must belong to the same tenant, company and project")
    return BANK_REC_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_scope": detached(scope)})


def advance_bank_reconciliation(plan: BankReconciliationPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    raw = detached(command)
    counterpart = (raw.get("receipt") or {}).get("counterpart_state")
    if raw.get("event") == "match" and counterpart is not None:
        _require(_scope_matches(dict(detached(state)).get("scope", {}), counterpart.get("scope", {})), "COUNTERPART_SCOPE_MISMATCH", "bank match must remain within its tenant, company and project")
    return BANK_REC_LIFECYCLE.advance(plan, state, command)


def _scope_matches(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left.get(key) == right.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id"))


# --------------------------------------------------------------------------- #
# Receipts from the sealed artifacts each hop actually has
# --------------------------------------------------------------------------- #


class BankReconciliationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BankReconciliationError(code, message)


def _money(value: Any, name: str) -> Decimal:
    _require(value not in (None, ""), "LINE_FIELD_MISSING", f"the observed amount {name} is required")
    return decimal_value(str(value), field_name=name, allow_negative=True)


def _stamp(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip()
    _require(bool(text), "LINE_FIELD_MISSING", f"a bank line names its {field_name}")
    if text.startswith("/Date(") and text.endswith(")/"):
        match = _EPOCH.match(text[6:-2])
        _require(match is not None, "LINE_FIELD_INVALID", f"{field_name} {value!r} is not a provider timestamp")
        assert match is not None
        text = datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if text.endswith("+0000"):
        text = text[:-5]
    elif text.endswith("+00:00"):
        text = text[:-6]
    if "T" not in text:
        text = f"{text}T00:00:00Z"
    if not text.endswith("Z"):
        text = f"{text}Z"
    try:
        return timestamp(text, field_name=field_name)
    except ValueError as exc:
        raise BankReconciliationError("LINE_FIELD_INVALID", f"{field_name} {value!r} is not an ISO-8601 timestamp") from exc


def _ref(value: Any, *, prefix: str) -> str:
    _require(value not in (None, ""), "LINE_FIELD_MISSING", "each bank line must name its provider reference")
    text = f"{prefix}{str(value or '').strip()}"
    _require(_REF_OK.match(text) is not None, "LINE_FIELD_INVALID", f"{text!r} is not an opaque reference; bank line identifiers carry no spaces")
    return text


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    _require(provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; the provenance names {provenance.source_tool}")


# -- opening ---------------------------------------------------------------- #


def open_receipt(prior_state: Any | None = None, *, prior_plan: Any | None = None, account_ref: str, currency: str, period_start: str, period_end: str, opening_balance: Any | None = None, first_period: bool = False) -> dict[str, Any]:
    """Open from a replayed prior case or a sealed first-period bank balance observation."""

    base = {"account_ref": account_ref, "currency": currency.upper(), "period_start": _stamp(period_start, field_name="period_start"), "period_end": _stamp(period_end, field_name="period_end")}
    if prior_state is not None:
        raw = dict(detached(prior_state))
        _require(str(raw.get("entity")) == BANK_REC_KIND, "PRIOR_CASE_SCHEMA_MISMATCH", f"expected a {BANK_REC_KIND} state; got entity {raw.get('entity')!r}")
        _require(str(raw.get("status")) == "reconciled", "PRIOR_CASE_NOT_RECONCILED", f"the prior case is {raw.get('status')}; only a reconciled case carries a continuing balance")
        ledger = dict(raw.get("ledger") or {})
        _require(str(ledger.get("account_ref")) == account_ref, "PRIOR_ACCOUNT_MISMATCH", f"the prior case reconciled {ledger.get('account_ref')}, not {account_ref}")
        _require(str(ledger.get("currency")) == currency.upper(), "PRIOR_CURRENCY_MISMATCH", f"the prior case is in {ledger.get('currency')}; balances are never converted")
        _require(prior_plan is not None, "PRIOR_CASE_NOT_SEALED", "the prior case must retain its replay plan")
        try:
            bound_plan, bound = BANK_REC_LIFECYCLE.bind(prior_plan, raw)
        except ValueError as exc:
            raise BankReconciliationError("PRIOR_CASE_NOT_SEALED", str(exc)) from exc
        _require(bound_plan.account_ref == account_ref, "PRIOR_ACCOUNT_MISMATCH", "the prior plan must reconcile the same account")
        digest = str(raw.get("state_digest"))
        return {**base, "opening_balance": str(bound.ledger.statement_closing), "opening_source": "prior_case", "prior_state": bound.to_dict(), "prior_plan": bound_plan.to_dict(), "prior_state_digest": digest, "prior_coverage_end": ledger.get("coverage_end"), "evidence_refs": [f"bank_reconciliation:{raw.get('scope', {}).get('entity_ref')}", f"state:{digest[:24]}"]}
    _require(opening_balance is not None, "OPENING_BALANCE_MISSING", "supply the prior reconciled case or a sealed bank balance observation")
    try:
        observation = BankBalanceObservation.model_validate(detached(opening_balance))
    except ValueError as exc:
        raise BankReconciliationError("OPENING_NOT_SEALED", str(exc)) from exc
    _require(observation.account_ref == account_ref, "ACCOUNT_MISMATCH", "opening observation names this account")
    _require(observation.currency == currency.upper(), "CURRENCY_MISMATCH", "opening observation names this currency")
    _require(observation.observed_at == base["period_start"], "COVERAGE_GAP", "opening observation must be as of period_start")
    return {**base, "opening_balance": str(observation.balance), "opening_source": "balance_observation", "opening_observation": observation.to_dict(), "first_period": bool(first_period), "evidence_refs": [f"balance:{observation.observation_digest[:24]}"]}


# -- bank lines -------------------------------------------------------------- #


def _page_rows(tool: str, raw: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if tool.startswith("xero."):
        rows = raw.get("BankTransactions", raw.get("bank_transactions"))
    elif tool.startswith("airwallex."):
        rows = raw.get("items", raw.get("data"))
    elif tool.startswith("quickbooks."):
        query = raw.get("QueryResponse") if isinstance(raw.get("QueryResponse"), Mapping) else raw
        rows = query.get("Deposit")
    elif tool.startswith("square."):
        rows = raw.get("payouts", raw.get("items"))
    else:
        rows = [dict(detached(item)).get("transaction_info", item) for item in (raw.get("transaction_details") or [])]
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "PAYLOAD_INCONSISTENT", f"a {tool} page carries its lines as a list")
    return [dict(detached(item)) for item in rows]  # type: ignore[union-attr]


def _normalize(tool: str, item: Mapping[str, Any]) -> dict[str, Any]:
    if tool.startswith("xero."):
        kind = str(item.get("Type") or item.get("type") or "").upper()
        _require(kind.startswith("RECEIVE") or kind.startswith("SPEND"), "LINE_FIELD_INVALID", f"a Xero bank transaction is SPEND or RECEIVE; got {kind or 'nothing'}")
        amount = _money(item.get("Total", item.get("TotalAmount")), "Total").copy_abs() * (1 if kind.startswith("RECEIVE") else -1)
        return {"line_ref": _ref(item.get("BankTransactionID") or item.get("ID") or item.get("id"), prefix="xero:banktxn:"), "occurred_at": _stamp(item.get("Date") or item.get("DateString"), field_name="Date"), "amount": str(amount.quantize(MONEY_QUANTUM)), "currency": str(item.get("CurrencyCode") or "").upper(), "reference": item.get("Reference"), "provider_reconciled": bool(item.get("IsReconciled", False))}
    if tool.startswith("airwallex."):
        return {"line_ref": _ref(item.get("id"), prefix="airwallex:txn:"), "occurred_at": _stamp(item.get("created_at") or item.get("created"), field_name="created_at"), "amount": str(_money(item.get("amount"), "amount").quantize(MONEY_QUANTUM)), "currency": str(item.get("currency") or "").upper(), "reference": item.get("source_id") or item.get("description"), "provider_reconciled": False}
    if tool.startswith("quickbooks."):
        currency = str(((item.get("CurrencyRef") or {}) if isinstance(item.get("CurrencyRef"), Mapping) else {}).get("value") or "").upper()
        return {"line_ref": _ref(item.get("Id"), prefix="quickbooks:deposit:"), "occurred_at": _stamp(item.get("TxnDate"), field_name="TxnDate"), "amount": str(_money(item.get("TotalAmt"), "TotalAmt").quantize(MONEY_QUANTUM)), "currency": currency, "reference": item.get("PrivateNote") or item.get("DocNumber"), "provider_reconciled": False}
    if tool.startswith("square."):
        money = item.get("amount_money") if isinstance(item.get("amount_money"), Mapping) else {}
        return {"line_ref": _ref(item.get("id"), prefix="square:payout:"), "occurred_at": _stamp(item.get("created_at"), field_name="created_at"), "amount": str((_money(money.get("amount"), "amount_money.amount") / Decimal("100")).quantize(MONEY_QUANTUM)), "currency": str(money.get("currency") or "").upper(), "reference": item.get("destination_id") or item.get("id"), "provider_reconciled": False}
    money = item.get("transaction_amount") if isinstance(item.get("transaction_amount"), Mapping) else {}
    return {"line_ref": _ref(item.get("transaction_id"), prefix="paypal:txn:"), "occurred_at": _stamp(item.get("transaction_initiation_date") or item.get("transaction_updated_date"), field_name="transaction_initiation_date"), "amount": str(_money(money.get("value"), "transaction_amount.value").quantize(MONEY_QUANTUM)), "currency": str(money.get("currency_code") or "").upper(), "reference": item.get("invoice_id") or item.get("paypal_reference_id"), "provider_reconciled": False}


def lines_receipt(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any], *, currency: str, position: BankBalanceObservation | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Normalized bank lines from a line page, with the closing balance taken from an independent balance read.

    Every row belongs to this account and currency; no row is silently dropped.
    """

    prov = provenance if isinstance(provenance, ObservationProvenance) else ObservationProvenance.model_validate(dict(detached(provenance)))
    _expect_tool(prov, *BANK_LINE_TOOLS)
    raw = dict(detached(payload))
    wanted = currency.upper()
    rows = [_normalize(prov.source_tool, item) for item in _page_rows(prov.source_tool, raw)]
    _require(all(row["currency"] == wanted for row in rows), "CURRENCY_MISMATCH", "every line must explicitly carry the account currency; mixed pages are refused")
    kept = rows
    _require(len({row["line_ref"] for row in rows}) == len(rows), "LINE_ALREADY_MATCHED", "a statement may not repeat a bank line")
    _require(stable_digest(raw) == prov.output_digest, "OBSERVATION_DIGEST_MISMATCH", "the bank page does not match the output digest of its read")
    _require(prov.lane != "governed_read" or prov.source_tool in GOVERNED_CONNECTOR_READ_TOOLS, "OBSERVATION_TOOL_MISMATCH", "an ungoverned bank tool must use the host lane")
    credits = sum((_money(row["amount"], "amount") for row in kept if _money(row["amount"], "amount") > 0), Decimal("0")).quantize(MONEY_QUANTUM)
    debits = sum((-_money(row["amount"], "amount") for row in kept if _money(row["amount"], "amount") < 0), Decimal("0")).quantize(MONEY_QUANTUM)
    if position is not None:
        try:
            pos = BankBalanceObservation.model_validate(detached(position))
        except ValueError as exc:
            raise BankReconciliationError("BALANCE_NOT_SEALED", str(exc)) from exc
        _require(pos.currency.upper() == wanted, "POSITION_CURRENCY_MISMATCH", f"the balance read is in {pos.currency}; the lines are in {wanted}")
        _require(raw.get("account_ref") == pos.account_ref, "ACCOUNT_MISMATCH", "the host bank page must retain the opaque account_ref bound by its read")
        closing, observed_at, balance_tool, balance_digest = pos.balance, pos.observed_at, pos.provenance.source_tool, pos.provenance.provenance_digest
    else:
        raise BankReconciliationError("STATEMENT_CLOSING_MISSING", "supply the sealed account-specific bank balance observation")
    starts = sorted(row["occurred_at"] for row in kept)
    _require(prov.window_start is not None and prov.window_end is not None, "COVERAGE_GAP", "bank lines require a complete read window")
    if prov.window_start is not None and prov.window_end is not None:
        outside = [row["line_ref"] for row in kept if not (parsed(prov.window_start) <= parsed(row["occurred_at"]) < parsed(prov.window_end))]
        _require(not outside, "LINE_OUTSIDE_WINDOW", f"{outside[:5]} fall outside the window the read declares ({prov.window_start} to {prov.window_end}); coverage is what the rows cover, never what the page claims")
    return {
        "account_ref": pos.account_ref,
        "lines_provenance": prov.to_dict(),
        "lines_payload": raw,
        "closing_observation": pos.to_dict(),
        "currency": wanted,
        "line_count": len(kept),
        "statement_credits": str(credits),
        "statement_debits": str(debits),
        "statement_closing": str(closing),
        "coverage_start": prov.window_start or starts[0],
        "coverage_end": prov.window_end or starts[-1],
        "balance_observed_at": observed_at,
        "balance_source_tool": balance_tool,
        "balance_provenance_digest": balance_digest,
        "source_tool": prov.source_tool,
        "provenance_digest": prov.provenance_digest,
        "lines": [{key: value for key, value in row.items() if key != "currency" and value not in (None, "")} | {"direction": "credit" if _money(row["amount"], "amount") > 0 else "debit"} for row in kept],
        "evidence_refs": [f"bank_lines:{prov.observation_ref}", f"provenance:{prov.provenance_digest[:24]}", f"balance:{balance_digest[:24]}"],
    }


# -- the ledger side --------------------------------------------------------- #


def ledger_receipt(trial_balance: TrialBalance | Mapping[str, Any], account_map: AccountMap | Mapping[str, Any], *, entries_provenance: ObservationProvenance | Mapping[str, Any] | None = None, entries: Mapping[str, Any] | Sequence[Any] | None = None) -> dict[str, Any]:
    """The ledger cash balance from the governed trial balance through a sealed account map, with optional entry detail."""

    try:
        balance = TrialBalance.model_validate(detached(trial_balance))
        mapping = AccountMap.model_validate(detached(account_map))
    except ValueError as exc:
        raise BankReconciliationError("LEDGER_NOT_SEALED", str(exc)) from exc
    try:
        balances = ledger_balances(balance, mapping)
    except BridgeError as exc:
        raise BankReconciliationError(exc.code, str(exc)) from exc
    _require("cash" in balances, "CASH_NOT_MAPPED", "the account map names no cash accounts; the cash line cannot be tied to the books")
    out: dict[str, Any] = {"trial_balance": balance.to_dict(), "account_map": mapping.to_dict(), "ledger_balance": str(balances["cash"]), "trial_balance_ref": balance.trial_balance_ref, "account_map_digest": mapping.map_digest, "ledger_source_digest": balance.balance_digest, "evidence_refs": [f"trial_balance:{balance.trial_balance_ref}", f"account_map:{mapping.map_digest[:24]}"]}
    if entries is not None:
        _require(entries_provenance is not None, "ENTRY_PROVENANCE_MISSING", "entry detail arrives with the provenance of the read that produced it")
        prov = entries_provenance if isinstance(entries_provenance, ObservationProvenance) else ObservationProvenance.model_validate(dict(detached(entries_provenance)))
        _expect_tool(prov, *ENTRY_DETAIL_TOOLS)
        raw = dict(detached(entries)) if isinstance(entries, Mapping) else {"rows": list(detached(entries))}
        _require(stable_digest(raw) == prov.output_digest, "OBSERVATION_DIGEST_MISMATCH", "ledger entries must match their observation digest")
        rows = raw.get("Journals") or raw.get("journals") or raw.get("rows") or (raw.get("Rows") or {}).get("Row") or []
        out.update({"entry_count": len(list(rows))})
        out["evidence_refs"].append(f"entries:{prov.observation_ref}")
    return out


# -- matches ----------------------------------------------------------------- #


def _verify_counterpart_seal(raw: Mapping[str, Any], *, kind: str, digest: str, status: str) -> None:
    """The counterpart must be a whole engine state whose digest commits its own scope and transition chain."""

    history = raw.get("transition_history")
    _require(isinstance(history, Sequence) and not isinstance(history, str) and len(history) > 0, "COUNTERPART_NOT_SEALED", f"a {kind} match names a whole sealed engine state; this payload carries no transition history")
    rows = [dict(item) for item in history]  # type: ignore[union-attr]
    _require(raw.get("version") == len(rows), "COUNTERPART_NOT_SEALED", f"the {kind} state names version {raw.get('version')} over {len(rows)} retained transitions")
    _require(str(rows[-1].get("to_status")) == status, "COUNTERPART_NOT_SEALED", f"the {kind} state claims {status} but its last retained transition landed on {rows[-1].get('to_status')}")
    derived = stable_digest({"plan_digest": raw.get("plan_digest"), "entity": raw.get("entity"), "scope": raw.get("scope"), "transitions": [item.get("transition_digest") for item in rows]})
    _require(derived == digest, "COUNTERPART_NOT_SEALED", f"the {kind} state_digest does not commit this scope and transition history; a match names another engine's sealed state, never an edited copy of one")


def match_receipt(line_refs: Sequence[str], counterpart: Any, *, kind: str, counterpart_plan: Any | None = None) -> dict[str, Any]:
    """A settlement of bank lines against another engine's sealed state; a claim without a state digest is refused."""

    _require(kind in COUNTERPART_KINDS, "COUNTERPART_KIND_UNKNOWN", f"{kind} is not a settleable counterpart; expected one of {sorted(COUNTERPART_KINDS)}")
    _require(bool(line_refs), "MATCH_LINES_MISSING", "a match names at least one bank line")
    spec = COUNTERPART_KINDS[kind]
    raw = dict(detached(counterpart))
    _require(raw.get("schema") == spec["state_schema"], "COUNTERPART_SCHEMA_MISMATCH", f"a {kind} match names a {spec['state_schema']} state; this payload is {raw.get('schema')!r}")
    digest = str(raw.get("state_digest") or "")
    _require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "COUNTERPART_NOT_SEALED", f"{kind} carries no sealed state digest; a match names another engine's sealed state, never a claim")
    status = str(raw.get("status") or "")
    _require(status in spec["statuses"], "COUNTERPART_NOT_SETTLED", f"the {kind} is {status or 'missing'}; only {list(spec['statuses'])} moved money")
    ledger = dict(raw.get("ledger") or {})
    amount = next((ledger[field] for field in spec["amount_fields"] if ledger.get(field) is not None), None)
    _require(amount is not None, "COUNTERPART_AMOUNT_MISSING", f"the {kind} ledger carries none of {list(spec['amount_fields'])}")
    entity_ref = str((raw.get("scope") or {}).get("entity_ref") or raw.get("entity_ref") or "")
    _require(bool(entity_ref), "COUNTERPART_REF_MISSING", f"the {kind} state names no entity_ref")
    _verify_counterpart_seal(raw, kind=kind, digest=digest, status=status)
    _require(counterpart_plan is not None, "COUNTERPART_NOT_SEALED", "the counterpart plan is required to replay its sealed state and derive the ledger")
    lifecycle_names = {"revenue_chain": "REVENUE_CHAIN_LIFECYCLE", "payables_chain": "PAYABLES_CHAIN_LIFECYCLE", "payroll_run_chain": "PAYROLL_LIFECYCLE", "spend_control_chain": "SPEND_CHAIN_LIFECYCLE", "disbursement_run": "DISBURSEMENT_LIFECYCLE", "payout_chain": "PAYOUT_LIFECYCLE"}
    try:
        lifecycle = getattr(importlib.import_module(f"lightbulb.{kind}"), lifecycle_names[kind])
        parsed_plan, state = lifecycle.bind(counterpart_plan, raw)
    except (ValueError, ImportError, AttributeError) as exc:
        raise BankReconciliationError("COUNTERPART_NOT_SEALED", f"the counterpart must replay through its actual lifecycle: {exc}") from exc
    correlation = ledger.get("correlation_sha256")
    payment_correlation = ledger.get("payment_correlation") or ledger.get("correlation")
    _require(bool(correlation or payment_correlation), "MATCH_REFERENCE_MISMATCH", "the settled counterpart must retain its exact payment correlation")
    return {
        "counterpart_state": state.to_dict(),
        "counterpart_plan": parsed_plan.to_dict(),
        "counterpart_currency": state.scope.currency,
        "line_refs": [str(ref) for ref in line_refs],
        "counterpart_kind": kind,
        "counterpart_ref": f"{kind}:{entity_ref}",
        "counterpart_state_digest": digest,
        "counterpart_status": status,
        "counterpart_amount": str(_money(amount, "counterpart_amount")),
        "correlation_sha256": str(correlation) if correlation else None,
        "payment_correlation": str(payment_correlation) if payment_correlation else None,
        "evidence_refs": [f"{kind}:{entity_ref}", f"state:{digest[:24]}"],
    }


def financing_receipt(line_ref: str, *, instrument: str, approval_ref: str) -> dict[str, Any]:
    """An operator classification of an inflow as financing, against a named instrument and an approval."""

    _require(instrument in FINANCING_INSTRUMENTS, "FINANCING_INSTRUMENT_UNKNOWN", f"{instrument} is not a financing instrument; expected one of {list(FINANCING_INSTRUMENTS)}")
    _require(bool(approval_ref), "FINANCING_APPROVAL_MISSING", "classifying an inflow as financing carries the approval reference that authorized the classification")
    return {"financing_line_ref": str(line_ref), "instrument": instrument, "approval_ref": str(approval_ref), "operator_supplied": True, "evidence_refs": [f"approval:{approval_ref}", f"line:{line_ref}"[:200]]}


def exception_receipt(line_ref: str, *, code: str, detail: str) -> dict[str, Any]:
    """The ``raise_exception`` receipt for a bank line the case cannot settle."""

    return {"exception_ref": f"bankrec:{code.lower()}:{stable_digest({'line_ref': line_ref, 'code': code})[:16]}", "code": code, "detail": detail[:900], "line_refs": [str(line_ref)], "evidence_refs": [f"line:{line_ref}"[:200]]}


# --------------------------------------------------------------------------- #
# What the reconciled case hands to the rest of the runtime
# --------------------------------------------------------------------------- #


def _bank_state(state: Any, plan: Any | None) -> Any:
    _require(plan is not None, "CASE_NOT_SEALED", "the bank case requires its replay plan")
    try:
        return BANK_REC_LIFECYCLE.bind(plan, state)[1]
    except ValueError as exc:
        raise BankReconciliationError("CASE_NOT_SEALED", str(exc)) from exc


def _reconciled(state: Any, plan: Any | None) -> Any:
    raw = detached(state)
    _require(isinstance(raw, Mapping) and raw.get("status") == "reconciled", "CASE_NOT_RECONCILED", "only a reconciled case proves a cash balance")
    return _bank_state(state, plan)


def cash_source_balance(state: Any, *, plan: Any | None = None) -> SourceBalance:
    """The ``SourceBalance(kind='cash')`` ``finance_close_observations.reconciliation_receipts`` already expected."""

    state = _reconciled(state, plan)
    ledger = state.ledger
    return SourceBalance.model_validate({"kind": "cash", "source_ref": f"bank-rec:{state.scope.entity_ref}", "source_tool": BANK_REC_KIND, "provenance_digest": state.state_digest, "balance": str(ledger.statement_closing), "items": ledger.line_count, "window_end": ledger.coverage_end})


def reconciled_position(state: Any, *, plan: Any | None = None) -> CashPosition:
    """A treasury ``CashPosition`` built on a reconciled balance rather than an unreconciled balance page."""

    state = _reconciled(state, plan)
    ledger = state.ledger
    return CashPosition(source_tool=f"{BANK_REC_KIND}:{state.scope.entity_ref}", provenance_digest=state.state_digest, observed_at=str(ledger.coverage_end or ledger.reconciled_at), currency=str(ledger.currency), available=str(ledger.statement_closing), pending="0", accounts=1)


def books_reconciliation_receipt(verification: Any, *, reconciliation_ref: str | None = None) -> dict[str, Any]:
    """The company operating system's ``reconcile`` receipt from a **sealed** ``BooksVerification``; a bare boolean is refused."""

    _require(not isinstance(verification, bool), "BOOKS_PROOF_NOT_SEALED", "reconciliation carries the sealed BooksVerification from finance_close.verify_books, not a boolean")
    raw = dict(detached(verification)) if not isinstance(verification, (str, int, float)) else {}
    _require(raw.get("schema") == BOOKS_VERIFICATION_SCHEMA, "BOOKS_PROOF_NOT_SEALED", f"expected a {BOOKS_VERIFICATION_SCHEMA} payload; got {raw.get('schema')!r}")
    digest = str(raw.get("verification_digest") or "")
    _require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None and digest != GENESIS_DIGEST, "BOOKS_PROOF_NOT_SEALED", "the books verification is not sealed")
    try:
        proof = BooksVerification.model_validate(raw)
    except ValueError as exc:
        raise BankReconciliationError("BOOKS_PROOF_NOT_SEALED", f"the verification digest does not commit this payload: {exc}") from exc
    _require(proof.verified, "BOOKS_NOT_VERIFIED", f"the books are not verified: {list(proof.reasons)[:3]}")
    return {"reconciliation_ref": reconciliation_ref or f"books:{proof.verification_digest[:24]}", "books_verified": True, "close_state_digest": proof.close_state_digest}


def unmatched_line_exception(state: Any, *, line_ref: str, plan: Any | None = None, kind: str = UNMATCHED_LINE_EXCEPTION_KIND) -> dict[str, Any] | None:
    """An exceptions-desk opening receipt for a bank line nothing settles; ``None`` when the line is settled."""

    state = _bank_state(state, plan)
    ledger = state.ledger
    if line_ref in ledger.matched_line_refs or line_ref in ledger.financing_line_refs:
        return None
    row = next((item for item in ledger.lines if item.line_ref == line_ref), None)
    _require(row is not None, "LINE_UNKNOWN", f"the case carries no line {line_ref}")
    assert row is not None
    return {"kind": kind, "source_engine": BANK_REC_KIND, "source_ref": f"{BANK_REC_KIND}:{state.scope.entity_ref}:{line_ref}"[:200], "source_digest": state.state_digest, "code": "UNMATCHED_BANK_LINE", "detail": f"bank line {line_ref} of {row.amount} on {row.occurred_at} settles nothing in any engine's sealed state", "evidence_refs": [f"bank_reconciliation:{state.scope.entity_ref}", f"state:{state.state_digest[:24]}"]}


def bank_match_evidence(state: Any, *, line_ref: str, source_plan: Any) -> dict[str, Any]:
    """The settlement evidence a settled bank line hands back to the engine that moved the money.

    ``payroll_run_chain.payment_receipt`` (and the disbursement and payout hops
    behind it) reads a ``lightbulb.bank_reconciliation_match.v1`` document:
    the reconciled line's correlation reference, the amount that moved, when it
    moved, and a digest of the match that proves it.  Nothing here is a claim —
    every field is read off this case's sealed ledger.
    """

    state = _bank_state(state, source_plan)
    ledger = state.ledger
    row = next((item for item in ledger.lines if item.line_ref == line_ref), None)
    _require(row is not None, "LINE_UNKNOWN", f"the case carries no line {line_ref}")
    assert row is not None
    match = next((item for item in ledger.matches if line_ref in item.line_refs), None)
    _require(match is not None, "LINE_NOT_MATCHED", f"{line_ref} settles nothing on this case; only a matched line is settlement evidence")
    assert match is not None
    payload = {
        "schema": BANK_MATCH_SCHEMA,
        "reconciliation_ref": f"{BANK_REC_KIND}:{state.scope.entity_ref}"[:200],
        "reconciliation_state_digest": state.state_digest,
        "line_ref": line_ref,
        "correlation": row.reference,
        "amount": str(row.amount),
        "occurred_at": row.occurred_at,
        "counterpart_kind": match.counterpart_kind,
        "counterpart_ref": match.counterpart_ref,
        "counterpart_state_digest": match.counterpart_state_digest,
        "currency": state.scope.currency,
        "source_state": state.to_dict(),
        "source_plan": detached(source_plan),
        "evidence_refs": [f"{BANK_REC_KIND}:{state.scope.entity_ref}", f"line:{line_ref}"[:200]],
    }
    payload = {key: value for key, value in payload.items() if value is not None}
    payload["match_digest"] = stable_digest(payload)
    return payload


def verify_bank_match_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(detached(evidence))
    _require(raw.get("schema") == BANK_MATCH_SCHEMA, "CASE_NOT_SEALED", "settlement requires the bank match schema")
    rebuilt = bank_match_evidence(raw.get("source_state"), source_plan=raw.get("source_plan"), line_ref=str(raw.get("line_ref")))
    _require(raw == rebuilt, "CASE_NOT_SEALED", "bank match fields must derive from its replayed source state")
    return rebuilt


def bank_reconciliation_summary(state: Any) -> dict[str, Any]:
    ledger = state.ledger
    return {"case_ref": str(state.scope.entity_ref), "account_ref": ledger.account_ref, "status": state.status, "currency": ledger.currency, "opening_balance": str(ledger.opening_balance), "statement_closing": str(ledger.statement_closing), "ledger_balance": str(ledger.ledger_balance), "difference": str(ledger.difference), "line_count": ledger.line_count, "matched_lines": ledger.matched_lines, "unmatched_value": str(ledger.unmatched_value), "financing_inflows": str(ledger.financing_inflows), "open_exceptions": len(ledger.open_exceptions), "days_to_reconcile": ledger.days_to_reconcile, "outcome": ledger.outcome, "state_digest": state.state_digest}


BANK_RECONCILIATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": BANK_REC_KIND,
    "golden_loop": BANK_REC_GOLDEN_LOOP,
    "stages": ["open", "load_lines", "match", "classify_financing", "resolve_variance", "reconcile"],
    "statuses": list(BANK_REC_STATUSES),
    "events": list(BANK_REC_EVENTS),
    "hops": {
        "open": "the prior reconciled case's sealed statement_closing (or a declared first-period operator opening)",
        "load_lines": f"a bank/payout line page from {list(BANK_LINE_TOOLS)} with provenance, closed by an independent balance read (treasury CashPosition)",
        "match": "another engine's sealed state digest: revenue_chain settlement, payables_chain payment, payroll run, card settlement, disbursement run, payout run",
        "classify_financing": "an operator classification naming the instrument and the approval that authorized it",
        "resolve_variance": "the evidence that explains the ledger-to-bank difference",
        "reconcile": "the governed trial balance through a sealed account map (finance_close_observations.ledger_balances)",
    },
    "produces": {"finance_close": "SourceBalance(kind='cash')", "company_treasury": "a reconciled CashPosition", "company_operating_system": "the sealed books reconciliation receipt", "payroll_run_chain": f"{BANK_MATCH_SCHEMA} settlement evidence for a reconciled line", "exceptions_desk": f"unmatched bank lines (as {UNMATCHED_LINE_EXCEPTION_KIND} until unmatched_bank_line is registered)"},
    "counterparts": {kind: dict(spec) for kind, spec in COUNTERPART_KINDS.items()},
    "required_connectors": ["xero", "quickbooks", "airwallex", "square", "paypal", "lightbulb.sdk_engine_state"],
    "missing_governed_reads": list(MISSING_GOVERNED_READS),
    "hard_rules": [
        "cash is reconciled, never summed",
        "a match names another engine's sealed state, never a caller assertion",
        "one bank line settles one thing",
        "cross-currency balances are refused, not converted",
        "a financing inflow is never period revenue",
    ],
}

__all__ = [
    "BankBalanceObservation",
    "BankReconciliationEffectBoundary",
    "bank_balance_observation",
    "BANK_LINE_TOOLS",
    "BANK_MATCH_SCHEMA",
    "BANK_RECONCILIATION_MANIFEST",
    "BANK_REC_EVENTS",
    "BANK_REC_GOLDEN_LOOP",
    "BANK_REC_KIND",
    "BANK_REC_LIFECYCLE",
    "BANK_REC_STATUSES",
    "COUNTERPART_KINDS",
    "ENTRY_DETAIL_TOOLS",
    "FINANCING_INSTRUMENTS",
    "MISSING_GOVERNED_READS",
    "REVENUE_COUNTERPARTS",
    "SHIPPED_COUNTERPARTS",
    "TERMINAL_BANK_REC_STATUSES",
    "UNMATCHED_LINE_EXCEPTION_KIND",
    "BankException",
    "BankLineRow",
    "BankMatch",
    "BankReconciliationError",
    "BankReconciliationLedger",
    "BankReconciliationPlan",
    "BankReconciliationReceipt",
    "BankReconciliationState",
    "advance_bank_reconciliation",
    "bank_match_evidence",
    "verify_bank_match_evidence",
    "bank_reconciliation_summary",
    "books_reconciliation_receipt",
    "cash_source_balance",
    "compile_bank_reconciliation",
    "exception_receipt",
    "financing_receipt",
    "ledger_receipt",
    "lines_receipt",
    "match_receipt",
    "open_bank_reconciliation",
    "open_receipt",
    "reconciled_position",
    "unmatched_line_exception",
]
