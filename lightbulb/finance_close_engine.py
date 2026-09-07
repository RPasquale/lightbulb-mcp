"""Finance Close Engine Golden Operating Loop: period close to verified books.

The finance engine the company operating system gates on.  A close
blueprint fixes the ledger system, materiality, variance threshold, the
reconciliations every period needs, whether approval must be independent of
the preparer, and the close deadline.  Each period close is a replay-fenced
lifecycle::

    opened -> trial_balance_captured -> reconciling -> reconciled
      -> adjusted -> locked -> approved -> closed  (| reopened | abandoned)

Guards: the trial balance must balance inside materiality; every required
account reconciles inside the variance threshold or opens an exception that
must be resolved before reconciliation completes; adjustments stop at lock;
approval must come from someone other than the preparer when the blueprint
requires independence; the close must land inside the deadline; a closed
period may be reopened only inside the reopen window.

:func:`verify_books` turns a closed state into a sealed
:class:`BooksVerification`: the proof (``close_state_digest``) the company
operating system requires before it reconciles an operating period.

Nothing here posts a journal, locks a ledger, or reads a provider; the
existing ``finance.*`` primitives discover and prepare, Spring authorizes,
and connectors execute.
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
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    percent_value,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)

FINANCE_CLOSE_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
FINANCE_CLOSE_KIND = "finance_close"
BLUEPRINT_SCHEMA = "lightbulb.finance_close_blueprint.v1"
PLAN_SCHEMA = "lightbulb.finance_close_loop_plan.v1"
VERIFICATION_SCHEMA = "lightbulb.books_verification.v1"
ASSESSMENT_SCHEMA = "lightbulb.finance_close_assessment.v1"
MAX_CLOSE_TRANSITIONS = 120

Profile = Literal["weekly_close", "fortnightly_close", "monthly_close", "monthly_close_cad", "dtc_weekly_close", "custom"]
LedgerSystem = Literal["xero", "quickbooks", "netsuite", "myob", "manual"]
AccountKind = Literal["cash", "accounts_receivable", "accounts_payable", "revenue_subledger", "payroll", "inventory", "fixed_assets", "intercompany", "tax", "work_in_progress", "seller_payable", "contra_revenue", "deferred_revenue"]
ACCOUNT_KINDS: tuple[str, ...] = ("cash", "accounts_receivable", "accounts_payable", "revenue_subledger", "payroll", "inventory", "fixed_assets", "intercompany", "tax", "work_in_progress", "seller_payable", "contra_revenue", "deferred_revenue")
LoopStage = Literal["capture_trial_balance", "reconcile_accounts", "resolve_exceptions", "adjust", "lock_subledgers", "approve", "close", "verify"]
STAGE_ORDER: tuple[str, ...] = ("capture_trial_balance", "reconcile_accounts", "resolve_exceptions", "adjust", "lock_subledgers", "approve", "close", "verify")

CloseStatus = Literal["opened", "trial_balance_captured", "reconciling", "reconciled", "adjusted", "locked", "approved", "closed", "reopened", "abandoned"]
CLOSE_STATUSES: tuple[str, ...] = ("opened", "trial_balance_captured", "reconciling", "reconciled", "adjusted", "locked", "approved", "closed", "reopened", "abandoned")
TERMINAL_CLOSE_STATUSES: frozenset[str] = frozenset({"abandoned"})
CloseEvent = Literal["open", "capture_trial_balance", "reconcile_account", "resolve_exception", "complete_reconciliation", "record_adjustment", "lock_subledgers", "approve", "close", "reopen", "abandon"]
CLOSE_EVENTS: tuple[str, ...] = ("open", "capture_trial_balance", "reconcile_account", "resolve_exception", "complete_reconciliation", "record_adjustment", "lock_subledgers", "approve", "close", "reopen", "abandon")
_CLOSE_TABLE: dict[tuple[str, str], str] = {
    ("new", "open"): "opened",
    ("opened", "capture_trial_balance"): "trial_balance_captured",
    ("opened", "abandon"): "abandoned",
    ("trial_balance_captured", "reconcile_account"): "reconciling",
    ("trial_balance_captured", "abandon"): "abandoned",
    ("reconciling", "reconcile_account"): "reconciling",
    ("reconciling", "resolve_exception"): "reconciling",
    ("reconciling", "complete_reconciliation"): "reconciled",
    ("reconciling", "abandon"): "abandoned",
    ("reconciled", "record_adjustment"): "adjusted",
    ("reconciled", "lock_subledgers"): "locked",
    ("reconciled", "abandon"): "abandoned",
    ("adjusted", "record_adjustment"): "adjusted",
    ("adjusted", "lock_subledgers"): "locked",
    ("adjusted", "abandon"): "abandoned",
    ("locked", "approve"): "approved",
    ("locked", "abandon"): "abandoned",
    ("approved", "close"): "closed",
    ("approved", "abandon"): "abandoned",
    ("closed", "reopen"): "reopened",
    ("reopened", "reconcile_account"): "reconciling",
    ("reopened", "abandon"): "abandoned",
}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_finance_close", "finance_close.advance_close", "finance_close.verify_books", "finance_close.assess_close",
        "finance.discover_trial_balance", "finance.discover_ledger_accounts", "finance.discover_general_ledger_activity", "finance.evaluate_period_reconciliation", "finance.evaluate_close_reconciliation_readiness",
        "finance.prepare_adjusting_entries_package", "finance.prepare_journal_entry", "finance.evaluate_journal_entry_controls", "finance.prepare_subledger_lock_package", "finance.prepare_close_approval_package",
        "finance.propose_period_close_transition", "finance.prepare_close_evidence_bundle", "finance.build_close_audit_packet", "finance.evaluate_period_close_readiness", "compliance.evaluate_regulated_controls", "approval.request_decision",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset({"xero.trial_balance_report", "xero.list_journals", "xero.list_bank_transactions", "xero.list_invoices", "xero.list_bills", "xero.list_payments", "quickbooks.trial_balance_report", "quickbooks.list_accounts", "quickbooks.list_invoices", "quickbooks.list_bills", "quickbooks.list_payments", "stripe.list_balance_transactions", "stripe.list_payouts"})
_LEDGER_TOOLS: Mapping[str, tuple[str, ...]] = {
    "xero": ("xero.trial_balance_report", "xero.list_journals", "xero.list_bank_transactions", "xero.list_invoices", "xero.list_bills", "xero.list_payments"),
    "quickbooks": ("quickbooks.trial_balance_report", "quickbooks.list_accounts", "quickbooks.list_invoices", "quickbooks.list_bills", "quickbooks.list_payments"),
    "netsuite": (),
    "myob": (),
    "manual": (),
}


def _money(value: Any, name: str, *, allow_negative: bool = False) -> Decimal:
    return decimal_value(value, field_name=name, allow_negative=allow_negative)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class CloseTargets(StrictModel):
    max_days_to_close: int = Field(ge=1, le=60)
    max_open_exceptions: int = Field(default=0, ge=0, le=50)
    min_on_time_percent: Decimal = Field(default=Decimal("90"), validate_default=True)

    @field_validator("min_on_time_percent", mode="before")
    @classmethod
    def _pct(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="min_on_time_percent")


class FinanceCloseBlueprint(StrictModel):
    schema_id: str = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: Profile
    name: ShortText
    currency: CurrencyCode
    ledger_system: LedgerSystem
    period_days: int = Field(ge=1, le=92)
    materiality: Decimal
    variance_threshold_percent: Decimal
    required_reconciliations: tuple[AccountKind, ...] = Field(min_length=1, max_length=len(ACCOUNT_KINDS))
    independent_approver_required: bool = True
    close_deadline_days: int = Field(ge=1, le=45)
    reopen_window_days: int = Field(default=30, ge=1, le=365)
    max_adjustment_multiple_of_materiality: int = Field(default=20, ge=1, le=1000)
    targets: CloseTargets
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("materiality", mode="before")
    @classmethod
    def _materiality(cls, value: Any) -> Decimal:
        result = _money(value, "materiality")
        if result <= 0:
            raise ValueError("materiality must be positive")
        return result

    @field_validator("variance_threshold_percent", mode="before")
    @classmethod
    def _variance(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="variance_threshold_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FinanceCloseBlueprint:
        unique(list(self.required_reconciliations), label="required reconciliations")
        if self.targets.max_days_to_close > self.close_deadline_days:
            raise ValueError("the close target cannot be later than the close deadline")
        if not skip_digests(info) and self.blueprint_digest != sealed_digest(FinanceCloseBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self


FINANCE_CLOSE_PROFILES: dict[str, dict[str, Any]] = {
    "weekly_close": {"profile": "weekly_close", "name": "Weekly operating close", "currency": "CAD", "ledger_system": "xero", "period_days": 7, "materiality": "250", "variance_threshold_percent": "1", "required_reconciliations": ["cash", "accounts_receivable", "revenue_subledger"], "independent_approver_required": True, "close_deadline_days": 3, "reopen_window_days": 14, "targets": {"max_days_to_close": 2, "max_open_exceptions": 0, "min_on_time_percent": "90"}},
    "fortnightly_close": {"profile": "fortnightly_close", "name": "Fortnightly services close", "currency": "AUD", "ledger_system": "xero", "period_days": 14, "materiality": "500", "variance_threshold_percent": "1", "required_reconciliations": ["cash", "accounts_receivable", "accounts_payable", "payroll"], "independent_approver_required": True, "close_deadline_days": 5, "reopen_window_days": 30, "targets": {"max_days_to_close": 4, "max_open_exceptions": 1, "min_on_time_percent": "85"}},
    "monthly_close": {"profile": "monthly_close", "name": "Monthly statutory close", "currency": "USD", "ledger_system": "quickbooks", "period_days": 31, "materiality": "1000", "variance_threshold_percent": "0.5", "required_reconciliations": ["cash", "accounts_receivable", "accounts_payable", "revenue_subledger", "payroll", "inventory", "tax"], "independent_approver_required": True, "close_deadline_days": 10, "reopen_window_days": 60, "targets": {"max_days_to_close": 7, "max_open_exceptions": 0, "min_on_time_percent": "95"}},
}


FINANCE_CLOSE_PROFILES["dtc_weekly_close"] = {
    **FINANCE_CLOSE_PROFILES["weekly_close"], "profile": "dtc_weekly_close",
    "name": "DTC weekly operating close", "currency": "AUD",
    "required_reconciliations": ["cash", "revenue_subledger", "accounts_payable"],
}
FINANCE_CLOSE_PROFILES["monthly_close_cad"] = {
    **FINANCE_CLOSE_PROFILES["monthly_close"], "profile": "monthly_close_cad",
    "name": "Canadian monthly operating close", "currency": "CAD", "period_days": 30,
    "ledger_system": "xero",
    "required_reconciliations": ["cash", "accounts_receivable", "accounts_payable", "revenue_subledger", "payroll", "tax"],
}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[str, ...] = Field(min_length=1, max_length=8)
    connector_tools: tuple[str, ...] = Field(default_factory=tuple, max_length=8)
    gate: ShortText | None = None

    @field_validator("primitive_refs")
    @classmethod
    def _refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for ref in value:
            if ref not in _KNOWN_PRIMITIVE_REFS:
                raise ValueError(f"unknown primitive ref {ref}")
        return value

    @field_validator("connector_tools")
    @classmethod
    def _tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for tool in value:
            if tool not in _KNOWN_CONNECTOR_TOOLS:
                raise ValueError(f"unknown connector tool {tool}")
        return value


class FinanceCloseLoopPlan(StrictModel):
    schema_id: str = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["finance.period_close_to_verified_books@0.1.0"] = FINANCE_CLOSE_GOLDEN_LOOP
    blueprint: FinanceCloseBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=len(STAGE_ORDER), max_length=len(STAGE_ORDER))
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FinanceCloseLoopPlan:
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("stages must follow the loop order")
        if not skip_digests(info) and self.plan_digest != sealed_digest(FinanceCloseLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stages(bp: FinanceCloseBlueprint) -> tuple[StageBinding, ...]:
    tools = _LEDGER_TOOLS[bp.ledger_system]
    return (
        StageBinding(stage="capture_trial_balance", title=f"Capture the {bp.ledger_system} trial balance inside {bp.currency} {bp.materiality} materiality", primitive_refs=("finance.discover_trial_balance", "finance_close.advance_close"), connector_tools=tools[:1]),
        StageBinding(stage="reconcile_accounts", title=f"Reconcile {len(bp.required_reconciliations)} account(s) inside {bp.variance_threshold_percent}%", primitive_refs=("finance.evaluate_period_reconciliation", "finance.evaluate_close_reconciliation_readiness", "finance_close.advance_close"), connector_tools=tools[1:6]),
        StageBinding(stage="resolve_exceptions", title="Resolve every reconciliation exception with evidence", primitive_refs=("finance.discover_general_ledger_activity", "finance_close.advance_close")),
        StageBinding(stage="adjust", title="Prepare adjusting entries under journal controls", primitive_refs=("finance.prepare_adjusting_entries_package", "finance.evaluate_journal_entry_controls", "finance_close.advance_close"), gate="spring_authorized_post"),
        StageBinding(stage="lock_subledgers", title="Lock subledgers", primitive_refs=("finance.prepare_subledger_lock_package", "finance_close.advance_close"), gate="spring_authorized_lock"),
        StageBinding(stage="approve", title="Independent approval of the close package" if bp.independent_approver_required else "Approve the close package", primitive_refs=("finance.prepare_close_approval_package", "approval.request_decision", "finance_close.advance_close"), gate="independent_human_approval" if bp.independent_approver_required else "human_approval"),
        StageBinding(stage="close", title=f"Close inside {bp.close_deadline_days} day(s) of period end", primitive_refs=("finance.propose_period_close_transition", "finance_close.advance_close"), gate="spring_authorized_close"),
        StageBinding(stage="verify", title="Seal the books verification and audit packet", primitive_refs=("finance_close.verify_books", "finance.prepare_close_evidence_bundle", "finance.build_close_audit_packet", "finance_close.assess_close")),
    )


def compile_finance_close_blueprint(blueprint: str | FinanceCloseBlueprint | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> FinanceCloseLoopPlan:
    if isinstance(blueprint, str):
        if blueprint not in FINANCE_CLOSE_PROFILES:
            raise ValueError(f"unknown finance close profile {blueprint!r}; known: {sorted(FINANCE_CLOSE_PROFILES)}")
        raw: dict[str, Any] = dict(FINANCE_CLOSE_PROFILES[blueprint])
    elif isinstance(blueprint, FinanceCloseBlueprint):
        raw = blueprint.to_dict()
        raw.pop("blueprint_digest", None)
    else:
        raw = dict(detached(blueprint))
    if overrides:
        if any(key in ("schema", "blueprint_digest") for key in overrides):
            raise ValueError("overrides cannot set schema or digest fields")
        raw.update(detached(overrides))
    raw["blueprint_digest"] = sealed_digest(FinanceCloseBlueprint, raw, "blueprint_digest")
    bp = FinanceCloseBlueprint.model_validate(raw)
    return seal(FinanceCloseLoopPlan, {"blueprint": bp, "stages": _stages(bp)}, "plan_digest")


# --------------------------------------------------------------------------- #
# Close lifecycle
# --------------------------------------------------------------------------- #


class CloseException(StrictModel):
    exception_ref: OpaqueRef
    account_kind: AccountKind
    variance: Decimal
    resolved: bool = False
    resolution_ref: OpaqueRef | None = None

    @field_validator("variance", mode="before")
    @classmethod
    def _variance(cls, value: Any) -> Decimal:
        return _money(value, "variance", allow_negative=True)


class CloseReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    period_start: str | None = None
    period_end: str | None = None
    ledger_ref: OpaqueRef | None = None
    preparer_ref: OpaqueRef | None = None
    trial_balance_ref: OpaqueRef | None = None
    debits: Decimal | None = None
    credits: Decimal | None = None
    account_kind: AccountKind | None = None
    reconciliation_ref: OpaqueRef | None = None
    ledger_balance: Decimal | None = None
    source_balance: Decimal | None = None
    exception_ref: OpaqueRef | None = None
    resolution_ref: OpaqueRef | None = None
    explanation: BoundedText | None = None
    journal_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    lock_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    close_ref: OpaqueRef | None = None

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @field_validator("debits", "credits", "amount", mode="before")
    @classmethod
    def _positive(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name))

    @field_validator("ledger_balance", "source_balance", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name), allow_negative=True)


class CloseLedger(StrictModel):
    period_start: str | None = None
    period_end: str | None = None
    ledger_ref: str | None = None
    preparer_ref: str | None = None
    trial_balance_ref: str | None = None
    trial_balance_difference: Decimal = Decimal("0.00")
    reconciled_accounts: tuple[AccountKind, ...] = Field(default_factory=tuple)
    exceptions: tuple[CloseException, ...] = Field(default_factory=tuple)
    adjustments: int = Field(default=0, ge=0)
    adjustment_total: Decimal = Decimal("0.00")
    lock_ref: str | None = None
    approver_ref: str | None = None
    approval_ref: str | None = None
    close_ref: str | None = None
    closed_at: str | None = None
    days_to_close: int | None = Field(default=None, ge=0)
    on_time: bool | None = None
    reopen_count: int = Field(default=0, ge=0)
    outcome: Literal["open", "closed", "reopened", "abandoned"] = "open"

    @field_validator("trial_balance_difference", "adjustment_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name), allow_negative=True)

    @property
    def open_exceptions(self) -> tuple[CloseException, ...]:
        return tuple(item for item in self.exceptions if not item.resolved)


class CloseEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    journal_posted: Literal[False] = False
    ledger_locked: Literal[False] = False
    period_closed: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_close(plan: FinanceCloseLoopPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    bp, r, event = plan.blueprint, command.receipt, command.event
    if event == "open":
        require(r.period_start is not None and r.period_end is not None and r.ledger_ref is not None and r.preparer_ref is not None, "PERIOD_MISSING", "a close opens with period_start, period_end, ledger_ref, and preparer_ref")
        assert r.period_start is not None and r.period_end is not None
        require(parsed(r.period_end) > parsed(r.period_start), "PERIOD_INVERTED", "period_end is after period_start")
        require(parsed(r.period_end) <= parsed(add_days(r.period_start, bp.period_days)), "PERIOD_TOO_LONG", f"a close period is at most {bp.period_days} day(s)")
        data.update({"period_start": r.period_start, "period_end": r.period_end, "ledger_ref": r.ledger_ref, "preparer_ref": r.preparer_ref})
    elif event == "capture_trial_balance":
        require(r.trial_balance_ref is not None and r.debits is not None and r.credits is not None, "TRIAL_BALANCE_MISSING", "capture links the trial balance and its debit and credit totals")
        require(parsed(command.occurred_at) >= parsed(str(data["period_end"])), "PERIOD_NOT_ENDED", "the trial balance is captured after the period ends")
        assert r.debits is not None and r.credits is not None
        difference = (r.debits - r.credits).quantize(MONEY_QUANTUM)
        require(abs(difference) <= bp.materiality, "TRIAL_BALANCE_OUT_OF_BALANCE", f"debits and credits differ by {difference}, beyond {bp.materiality} materiality; do not proceed", "manual_reconciliation")
        data.update({"trial_balance_ref": r.trial_balance_ref, "trial_balance_difference": str(difference)})
    elif event == "reconcile_account":
        require(r.account_kind is not None and r.reconciliation_ref is not None and r.ledger_balance is not None and r.source_balance is not None, "RECONCILIATION_MISSING", "a reconciliation names the account kind, reconciliation_ref, ledger and source balances")
        require(r.account_kind in bp.required_reconciliations, "ACCOUNT_NOT_REQUIRED", f"{r.account_kind} is not one of {list(bp.required_reconciliations)}")
        require(r.account_kind not in data.get("reconciled_accounts", ()), "ACCOUNT_ALREADY_RECONCILED", f"{r.account_kind} is already reconciled this period")
        assert r.ledger_balance is not None and r.source_balance is not None
        variance = (r.ledger_balance - r.source_balance).quantize(MONEY_QUANTUM)
        base = max(abs(r.source_balance), bp.materiality)
        inside = abs(variance) <= bp.materiality or (abs(variance) / base * Decimal("100")) <= bp.variance_threshold_percent
        exceptions = list(data.get("exceptions", ()))
        if not inside:
            require(r.exception_ref is not None, "EXCEPTION_REF_MISSING", f"{r.account_kind} variance {variance} exceeds the threshold; open an exception with exception_ref")
            require(all(str(item.get("exception_ref") if isinstance(item, Mapping) else item.exception_ref) != r.exception_ref for item in exceptions), "EXCEPTION_DUPLICATE", f"{r.exception_ref} already exists")
            exceptions.append({"exception_ref": r.exception_ref, "account_kind": r.account_kind, "variance": str(variance), "resolved": False, "resolution_ref": None})
        data.update({"reconciled_accounts": (*data.get("reconciled_accounts", ()), r.account_kind), "exceptions": tuple(exceptions)})
    elif event == "resolve_exception":
        require(r.exception_ref is not None and r.resolution_ref is not None and r.explanation is not None, "RESOLUTION_MISSING", "resolving names the exception, the resolution evidence, and an explanation")
        exceptions = [dict(item) if isinstance(item, Mapping) else item.to_dict() for item in data.get("exceptions", ())]
        match = next((item for item in exceptions if item["exception_ref"] == r.exception_ref), None)
        require(match is not None, "EXCEPTION_UNKNOWN", f"{r.exception_ref} is not an open exception")
        assert match is not None
        require(not match["resolved"], "EXCEPTION_ALREADY_RESOLVED", f"{r.exception_ref} is already resolved")
        match.update({"resolved": True, "resolution_ref": r.resolution_ref})
        data.update({"exceptions": tuple(exceptions)})
    elif event == "complete_reconciliation":
        missing = [kind for kind in bp.required_reconciliations if kind not in data.get("reconciled_accounts", ())]
        require(not missing, "RECONCILIATIONS_INCOMPLETE", f"reconcile {missing} before completing")
        open_items = [item for item in data.get("exceptions", ()) if not (item.get("resolved") if isinstance(item, Mapping) else item.resolved)]
        require(len(open_items) <= bp.targets.max_open_exceptions, "EXCEPTIONS_OPEN", f"{len(open_items)} exception(s) remain open; the blueprint allows {bp.targets.max_open_exceptions}", "manual_reconciliation")
    elif event == "record_adjustment":
        require(r.journal_ref is not None and r.amount is not None and r.explanation is not None, "ADJUSTMENT_MISSING", "an adjustment names the journal reference, amount, and explanation")
        assert r.amount is not None
        require(r.amount <= bp.materiality * bp.max_adjustment_multiple_of_materiality, "ADJUSTMENT_TOO_LARGE", f"adjustment {r.amount} exceeds {bp.max_adjustment_multiple_of_materiality}x materiality; escalate", "manual_reconciliation")
        data.update({"adjustments": int(data.get("adjustments", 0)) + 1, "adjustment_total": str((Decimal(str(data.get("adjustment_total", "0"))) + r.amount).quantize(MONEY_QUANTUM))})
    elif event == "lock_subledgers":
        require(r.lock_ref is not None, "LOCK_MISSING", "locking links the subledger lock reference")
        data.update({"lock_ref": r.lock_ref})
    elif event == "approve":
        require(r.approver_ref is not None and r.approval_ref is not None, "APPROVAL_MISSING", "approval names the approver and the server-issued approval reference")
        if bp.independent_approver_required:
            require(r.approver_ref != data.get("preparer_ref") and r.approver_ref != command.actor_ref, "SELF_APPROVAL", "the approver must be independent of the preparer and the acting actor", "await_approval")
        data.update({"approver_ref": r.approver_ref, "approval_ref": r.approval_ref})
    elif event == "close":
        require(r.close_ref is not None, "CLOSE_MISSING", "closing links the Spring close reference")
        deadline = parsed(add_days(str(data["period_end"]), bp.close_deadline_days))
        at = parsed(command.occurred_at)
        require(at <= deadline, "CLOSE_DEADLINE_MISSED", f"the close deadline was {deadline.isoformat()}; the period closes late only through manual reconciliation", "manual_reconciliation")
        days = (at - parsed(str(data["period_end"]))).days
        data.update({"close_ref": r.close_ref, "closed_at": command.occurred_at, "days_to_close": max(days, 0), "on_time": days <= bp.targets.max_days_to_close, "outcome": "closed"})
    elif event == "reopen":
        closed_at = data.get("closed_at")
        require(closed_at is not None and parsed(command.occurred_at) <= parsed(add_days(str(closed_at), bp.reopen_window_days)), "REOPEN_WINDOW_CLOSED", f"a period reopens only within {bp.reopen_window_days} day(s) of closing", "manual_reconciliation")
        data.update({"reopen_count": int(data.get("reopen_count", 0)) + 1, "outcome": "reopened", "close_ref": None, "closed_at": None, "days_to_close": None, "on_time": None, "approver_ref": None, "approval_ref": None, "lock_ref": None, "reconciled_accounts": (), "exceptions": ()})
    elif event == "abandon":
        data.update({"outcome": "abandoned"})
    return next_status, data


CLOSE_LIFECYCLE = LifecycleSpec(entity="period_close", schema_prefix="finance_period_close", statuses=CLOSE_STATUSES, terminal=TERMINAL_CLOSE_STATUSES, events=CLOSE_EVENTS, table=_CLOSE_TABLE, opening_event="open", reason_events=("reopen", "abandon"), apply=_apply_close, ledger_model=CloseLedger, receipt_model=CloseReceipt, effect_boundary_model=CloseEffectBoundary, plan_model=FinanceCloseLoopPlan, max_transitions=MAX_CLOSE_TRANSITIONS)
CloseCommand = CLOSE_LIFECYCLE.Command
CloseState = CLOSE_LIFECYCLE.State
CloseTransitionResult = CLOSE_LIFECYCLE.TransitionResult
seal_close_command = CLOSE_LIFECYCLE.seal_command
close_command_digest = CLOSE_LIFECYCLE.command_digest


def open_period_close(plan: FinanceCloseLoopPlan | Mapping[str, Any], scope: Mapping[str, Any] | Any, *, period_start: str, period_end: str | None, ledger_ref: str, preparer_ref: str, opened_at: str, actor_ref: str) -> Any:
    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    end = period_end or add_days(period_start, parsed_plan.blueprint.period_days)
    return CLOSE_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={"period_start": period_start, "period_end": end, "ledger_ref": ledger_ref, "preparer_ref": preparer_ref})


def advance_period_close(plan: FinanceCloseLoopPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CLOSE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Books verification (the proof the company operating system consumes)
# --------------------------------------------------------------------------- #


class BooksVerification(StrictModel):
    schema_id: str = Field(default=VERIFICATION_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    close_state_digest: Sha256Digest
    period_start: str
    period_end: str
    ledger_ref: OpaqueRef
    verified: bool
    reasons: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=8)
    closed_at: str | None = None
    approver_ref: OpaqueRef | None = None
    days_to_close: int | None = Field(default=None, ge=0)
    open_exceptions: int = Field(ge=0)
    adjustment_total: Decimal
    verification_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("adjustment_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, "adjustment_total", allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BooksVerification:
        if self.verified and (self.closed_at is None or self.approver_ref is None or self.reasons):
            raise ValueError("verified books carry the close and approver and no reasons")
        if not self.verified and not self.reasons:
            raise ValueError("unverified books carry at least one reason")
        if not skip_digests(info) and self.verification_digest != sealed_digest(BooksVerification, self, "verification_digest"):
            raise ValueError("verification_digest must commit the exact verification")
        return self


def verify_books(plan: FinanceCloseLoopPlan | Mapping[str, Any], state: Any) -> BooksVerification:
    """Seal whether a close state proves verified books; the digest is the proof the company OS reconciles on."""

    parsed_plan, bound = CLOSE_LIFECYCLE.bind(plan, state)
    ledger = bound.ledger
    reasons: list[str] = []
    if bound.status != "closed":
        reasons.append(f"the period is {bound.status}, not closed")
    if ledger.open_exceptions:
        reasons.append(f"{len(ledger.open_exceptions)} reconciliation exception(s) remain open")
    if abs(ledger.trial_balance_difference) > parsed_plan.blueprint.materiality:
        reasons.append("the trial balance is out of balance beyond materiality")
    if parsed_plan.blueprint.independent_approver_required and ledger.approver_ref is not None and ledger.approver_ref == ledger.preparer_ref:
        reasons.append("the approver is the preparer")
    verified = not reasons
    payload = {"plan_digest": parsed_plan.plan_digest, "close_state_digest": bound.state_digest, "period_start": ledger.period_start, "period_end": ledger.period_end, "ledger_ref": ledger.ledger_ref, "verified": verified, "reasons": tuple(reasons), "closed_at": ledger.closed_at if verified else None, "approver_ref": ledger.approver_ref if verified else None, "days_to_close": ledger.days_to_close, "open_exceptions": len(ledger.open_exceptions), "adjustment_total": ledger.adjustment_total}
    return seal(BooksVerification, payload, "verification_digest")


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


class FinanceCloseAssessment(StrictModel):
    schema_id: str = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    assessed_at: str
    periods: int = Field(ge=0)
    closed: int = Field(ge=0)
    reopened: int = Field(ge=0)
    abandoned: int = Field(ge=0)
    on_time_percent: Decimal | None = None
    average_days_to_close: Decimal | None = None
    exceptions_raised: int = Field(ge=0)
    exceptions_open: int = Field(ge=0)
    adjustment_total: Decimal
    learnings: tuple[BoundedText, ...] = Field(min_length=1, max_length=12)
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @field_validator("adjustment_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, "adjustment_total", allow_negative=True)

    @field_validator("on_time_percent", "average_days_to_close", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> FinanceCloseAssessment:
        if not skip_digests(info) and self.assessment_digest != sealed_digest(FinanceCloseAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_finance_close(plan: FinanceCloseLoopPlan | Mapping[str, Any], states: Sequence[Any], *, assessed_at: str) -> FinanceCloseAssessment:
    parsed_plan = FinanceCloseLoopPlan.model_validate(detached(plan))
    bound = [CLOSE_LIFECYCLE.bind(parsed_plan, item)[1] for item in states]
    closed = [item for item in bound if item.status == "closed"]
    on_time = sum(1 for item in closed if item.ledger.on_time)
    days = [item.ledger.days_to_close for item in closed if item.ledger.days_to_close is not None]
    raised = sum(len(item.ledger.exceptions) for item in bound)
    open_count = sum(len(item.ledger.open_exceptions) for item in bound)
    adjustment_total = sum((item.ledger.adjustment_total for item in bound), Decimal("0")).quantize(MONEY_QUANTUM)
    on_time_percent = (Decimal(on_time) / Decimal(len(closed)) * Decimal("100")).quantize(Decimal("0.01")) if closed else None
    average_days = (Decimal(sum(days)) / Decimal(len(days))).quantize(Decimal("0.01")) if days else None
    learnings: list[str] = []
    bp = parsed_plan.blueprint
    if not bound:
        learnings.append("no period closes yet; open the first close after the period ends")
    if on_time_percent is not None and on_time_percent < bp.targets.min_on_time_percent:
        learnings.append(f"on-time closes {on_time_percent}% are below the {bp.targets.min_on_time_percent}% target")
    if average_days is not None and average_days > bp.targets.max_days_to_close:
        learnings.append(f"average {average_days} day(s) to close exceeds the {bp.targets.max_days_to_close}-day target")
    if open_count:
        learnings.append(f"{open_count} reconciliation exception(s) remain open across periods")
    reopened = sum(1 for item in bound if item.ledger.reopen_count > 0)
    if reopened:
        learnings.append(f"{reopened} period(s) were reopened; review the close checklist")
    if not learnings:
        learnings.append("closes land on time with clean reconciliations")
    return seal(FinanceCloseAssessment, {"plan_digest": parsed_plan.plan_digest, "assessed_at": assessed_at, "periods": len(bound), "closed": len(closed), "reopened": reopened, "abandoned": sum(1 for item in bound if item.status == "abandoned"), "on_time_percent": on_time_percent, "average_days_to_close": average_days, "exceptions_raised": raised, "exceptions_open": open_count, "adjustment_total": adjustment_total, "learnings": tuple(learnings[:12])}, "assessment_digest")


FINANCE_CLOSE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": FINANCE_CLOSE_KIND,
    "golden_loop": FINANCE_CLOSE_GOLDEN_LOOP,
    "stages": list(STAGE_ORDER),
    "profiles": sorted(FINANCE_CLOSE_PROFILES),
    "close_statuses": list(CLOSE_STATUSES),
    "close_events": list(CLOSE_EVENTS),
    "account_kinds": list(ACCOUNT_KINDS),
    "required_connectors": ["xero", "quickbooks", "stripe"],
    "hard_rules": ["the trial balance balances inside materiality before reconciliation", "every required account reconciles inside the variance threshold or opens an exception", "exceptions resolve before reconciliation completes", "adjustments stop at subledger lock and stay inside the materiality multiple", "approval is independent of the preparer when the blueprint requires it", "the close lands inside the deadline; reopening stays inside the window", "verified books are a sealed proof, never a flag"],
}

__all__ = [
    "ACCOUNT_KINDS",
    "CLOSE_EVENTS",
    "CLOSE_LIFECYCLE",
    "CLOSE_STATUSES",
    "FINANCE_CLOSE_GOLDEN_LOOP",
    "FINANCE_CLOSE_KIND",
    "FINANCE_CLOSE_MANIFEST",
    "FINANCE_CLOSE_PROFILES",
    "STAGE_ORDER",
    "TERMINAL_CLOSE_STATUSES",
    "BooksVerification",
    "CloseCommand",
    "CloseEffectBoundary",
    "CloseException",
    "CloseLedger",
    "CloseReceipt",
    "CloseState",
    "CloseTargets",
    "CloseTransitionResult",
    "FinanceCloseAssessment",
    "FinanceCloseBlueprint",
    "FinanceCloseLoopPlan",
    "StageBinding",
    "advance_period_close",
    "assess_finance_close",
    "close_command_digest",
    "compile_finance_close_blueprint",
    "open_period_close",
    "seal_close_command",
    "verify_books",
]
