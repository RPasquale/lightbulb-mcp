"""Deterministic Stripe settlement-to-ledger reconciliation candidates.

This module consumes two complete, evidence-bound source observations and one
structurally sealed close workspace. It performs no connector operation,
persistence, exception disposition, journal posting, certification, or period
transition. Exact matches and exception candidates are deterministic; Spring
and an independent reviewer remain authoritative for retained reconciliation
evidence and close advancement.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.finance_close_workspace import (
    FinanceCloseWorkspace,
    FinanceCloseWorkspaceInput,
    PrepareCloseWorkspacePrimitive,
    prepare_close_workspace,
)
from lightbulb.finance_general_ledger import (
    GeneralLedgerActivityLine,
    GeneralLedgerActivityObservation,
)
from lightbulb.finance_stripe_settlements import (
    StripeSettlementMovement,
    StripeSettlementObservationResult,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

STRIPE_LEDGER_RECONCILIATION_INPUT_SCHEMA = (
    "lightbulb.finance_stripe_ledger_reconciliation_input.v1"
)
STRIPE_LEDGER_RECONCILIATION_MATCH_SCHEMA = (
    "lightbulb.finance_stripe_ledger_reconciliation_match.v1"
)
STRIPE_LEDGER_RECONCILIATION_EXCEPTION_SCHEMA = (
    "lightbulb.finance_stripe_ledger_reconciliation_exception.v1"
)
STRIPE_LEDGER_RECONCILIATION_RESULT_SCHEMA = (
    "lightbulb.finance_stripe_ledger_reconciliation_result.v1"
)

_MAX_PAYOUTS = 10_000
_MAX_LEDGER_LINES = 10_000
_COVERAGE_QUANTUM = Decimal("0.00000001")
_MAX_DATE_TOLERANCE_DAYS = 31
_MAX_MINOR_UNIT_EXPONENT = 4
_MAX_MONEY = Decimal("1000000000000000000")
_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_PAYOUT_REF_PATTERN = re.compile(r"^po_[A-Za-z0-9]{8,64}$")
_PAYOUT_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(po_[A-Za-z0-9]{8,64})(?![A-Za-z0-9_])"
)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _money(value: Any, *, non_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, (int, float)):
        raise ValueError("money must use an exact Decimal or decimal string")
    if not isinstance(value, (Decimal, str)):
        raise ValueError("money must use an exact Decimal or decimal string")
    if isinstance(value, str) and (not value or value != value.strip()):
        raise ValueError("money must use canonical visible decimal text")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("money must be a finite decimal") from exc
    if not parsed.is_finite() or abs(parsed) > _MAX_MONEY:
        raise ValueError("money must be finite and within the supported bound")
    if parsed.as_tuple().exponent < -4:
        raise ValueError("money supports at most four decimal places")
    if non_negative and parsed < 0:
        raise ValueError("money must be non-negative")
    return Decimal(0) if parsed == 0 else parsed


def _minor_units(value: int, exponent: int) -> Decimal:
    return Decimal(value).scaleb(-exponent)


def _coverage_ratio(matched_count: int, payout_count: int) -> Decimal:
    if payout_count == 0:
        return Decimal(1)
    with localcontext() as context:
        context.prec = 50
        context.rounding = ROUND_HALF_EVEN
        return (Decimal(matched_count) / Decimal(payout_count)).quantize(
            _COVERAGE_QUANTUM
        )


def _date_from_timestamp(value: str) -> date:
    return _as_datetime(value).date()


def _line_payout_refs(line: GeneralLedgerActivityLine) -> tuple[str, ...]:
    refs: set[str] = set()
    for value in (line.document_number, line.memo):
        if value is not None:
            refs.update(_PAYOUT_TOKEN_PATTERN.findall(value))
    return tuple(sorted(refs))


class StripeLedgerReconciliationInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_stripe_ledger_reconciliation_input.v1"] = (
        Field(default=STRIPE_LEDGER_RECONCILIATION_INPUT_SCHEMA, alias="schema")
    )
    workspace: FinanceCloseWorkspace
    stripe_observation: StripeSettlementObservationResult
    ledger_observation: GeneralLedgerActivityObservation
    reconciled_at: str
    minor_unit_exponent: int = Field(default=2, ge=0, le=_MAX_MINOR_UNIT_EXPONENT)
    settlement_date_tolerance_days: int = Field(
        default=7,
        ge=0,
        le=_MAX_DATE_TOLERANCE_DAYS,
    )

    @field_validator(
        "workspace",
        "stripe_observation",
        "ledger_observation",
        mode="before",
    )
    @classmethod
    def _detached_source_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "stripe_observation": StripeSettlementObservationResult,
            "ledger_observation": GeneralLedgerActivityObservation,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("reconciled_at")
    @classmethod
    def _reconciled_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="reconciled_at")

    @model_validator(mode="after")
    def _exact_source_scope(self) -> "StripeLedgerReconciliationInput":
        workspace = self.workspace
        scope = workspace.close_scope
        stripe = self.stripe_observation
        ledger = self.ledger_observation
        period_start = _as_datetime(scope.period_started_at).date().isoformat()
        period_end = _as_datetime(scope.period_ended_at).date().isoformat()
        if (
            stripe.project_id != scope.project_id
            or ledger.project_id != scope.project_id
        ):
            raise ValueError("source observations must match the close project UUID")
        if (
            stripe.start_date != period_start
            or ledger.start_date != period_start
            or stripe.end_date != period_end
            or ledger.end_date != period_end
        ):
            raise ValueError("source observations must match the exact close period")
        if stripe.currency != scope.functional_currency:
            raise ValueError("Stripe currency must match the close functional currency")
        if ledger.currency != scope.functional_currency:
            raise ValueError("ledger currency must match the close functional currency")
        if _as_datetime(stripe.observed_at).date() <= date.fromisoformat(
            stripe.end_date
        ) or _as_datetime(ledger.observed_at).date() <= date.fromisoformat(
            ledger.end_date
        ):
            raise ValueError("source observations must occur after the complete month")
        if _as_datetime(self.reconciled_at) < max(
            _as_datetime(stripe.observed_at),
            _as_datetime(ledger.observed_at),
            _as_datetime(workspace.prepared_at),
        ):
            raise ValueError(
                "reconciliation cannot precede its workspace or source observations"
            )
        if workspace.close_authorized or workspace.persistence_authorized:
            raise ValueError("SDK reconciliation requires a structural workspace only")
        payout_amounts = tuple(
            abs(_minor_units(item.net_minor, self.minor_unit_exponent))
            for item in stripe.movements
            if item.movement_type == "payout" or item.reporting_category == "payout"
        )
        control_amounts = tuple(
            item.amount
            for item in ledger.lines
            if item.account_ref == workspace.stripe_control_account_ref
        )
        for amount in (*payout_amounts, *control_amounts):
            _money(amount)
        _money(sum(payout_amounts, Decimal(0)), non_negative=True)
        _money(sum((abs(item) for item in control_amounts), Decimal(0)))
        return self


class StripeLedgerReconciliationMatch(_StrictModel):
    schema_id: Literal["lightbulb.finance_stripe_ledger_reconciliation_match.v1"] = (
        Field(default=STRIPE_LEDGER_RECONCILIATION_MATCH_SCHEMA, alias="schema")
    )
    match_ref: Sha256Digest
    payout_ref: OpaqueRef
    stripe_transaction_ref: OpaqueRef
    ledger_line_ref: Sha256Digest
    match_basis: Literal["payout_reference_amount_and_date"] = (
        "payout_reference_amount_and_date"
    )
    expected_amount: Decimal = Field(ge=0)
    ledger_amount: Decimal = Field(ge=0)
    amount_delta: Decimal
    settlement_date: str
    ledger_date: str
    date_delta_days: int = Field(ge=0, le=_MAX_DATE_TOLERANCE_DAYS)

    @field_validator("expected_amount", "ledger_amount", "amount_delta", mode="before")
    @classmethod
    def _exact_money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, non_negative=info.field_name != "amount_delta")

    @field_validator("settlement_date", "ledger_date")
    @classmethod
    def _dates(cls, value: str) -> str:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError("match dates must use YYYY-MM-DD")
        return value

    @model_validator(mode="after")
    def _exact_match(self) -> "StripeLedgerReconciliationMatch":
        if self.amount_delta != self.ledger_amount - self.expected_amount:
            raise ValueError("match amount_delta must be exact")
        if self.amount_delta != 0:
            raise ValueError("automatic settlement matches require exact amounts")
        expected_ref = _stable_digest(
            {
                "schema": self.schema_id,
                "payout_ref": self.payout_ref,
                "stripe_transaction_ref": self.stripe_transaction_ref,
                "ledger_line_ref": self.ledger_line_ref,
                "expected_amount": str(self.expected_amount),
                "ledger_amount": str(self.ledger_amount),
                "settlement_date": self.settlement_date,
                "ledger_date": self.ledger_date,
            }
        )
        if self.match_ref != expected_ref:
            raise ValueError("match_ref must commit to the exact source identities")
        return self


ReconciliationExceptionKind = Literal[
    "ambiguous_ledger_reference",
    "amount_mismatch",
    "date_out_of_tolerance",
    "duplicate_stripe_payout_reference",
    "invalid_payout_direction",
    "ledger_without_stripe_payout",
    "missing_in_ledger",
    "missing_stripe_payout_reference",
    "pending_settlement",
]


class StripeLedgerReconciliationException(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_stripe_ledger_reconciliation_exception.v1"
    ] = Field(default=STRIPE_LEDGER_RECONCILIATION_EXCEPTION_SCHEMA, alias="schema")
    exception_ref: Sha256Digest
    kind: ReconciliationExceptionKind
    payout_ref: OpaqueRef | None = None
    stripe_transaction_refs: tuple[OpaqueRef, ...] = Field(max_length=_MAX_PAYOUTS)
    ledger_line_refs: tuple[Sha256Digest, ...] = Field(max_length=_MAX_LEDGER_LINES)
    expected_amount: Decimal | None = None
    ledger_amount: Decimal | None = None
    amount_delta: Decimal | None = None
    settlement_date: str | None = None
    ledger_date: str | None = None
    age_days: int = Field(ge=0, le=36_600)
    material: bool

    @field_validator("stripe_transaction_refs", "ledger_line_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("expected_amount", "ledger_amount", "amount_delta", mode="before")
    @classmethod
    def _optional_money(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)

    @model_validator(mode="after")
    def _sealed_exception(self) -> "StripeLedgerReconciliationException":
        if tuple(sorted(self.stripe_transaction_refs)) != self.stripe_transaction_refs:
            raise ValueError("stripe transaction references must use canonical order")
        if tuple(sorted(self.ledger_line_refs)) != self.ledger_line_refs:
            raise ValueError("ledger line references must use canonical order")
        if len(set(self.stripe_transaction_refs)) != len(self.stripe_transaction_refs):
            raise ValueError("stripe transaction references must be unique")
        if len(set(self.ledger_line_refs)) != len(self.ledger_line_refs):
            raise ValueError("ledger line references must be unique")
        if self.amount_delta is not None and (
            self.expected_amount is None or self.ledger_amount is None
        ):
            raise ValueError("amount_delta requires both source amounts")
        if self.amount_delta is not None and self.amount_delta != (
            self.ledger_amount - self.expected_amount
        ):
            raise ValueError("exception amount_delta must be exact")
        expected_ref = _stable_digest(
            {
                "schema": self.schema_id,
                "kind": self.kind,
                "payout_ref": self.payout_ref,
                "stripe_transaction_refs": self.stripe_transaction_refs,
                "ledger_line_refs": self.ledger_line_refs,
                "expected_amount": (
                    str(self.expected_amount)
                    if self.expected_amount is not None
                    else None
                ),
                "ledger_amount": (
                    str(self.ledger_amount) if self.ledger_amount is not None else None
                ),
                "settlement_date": self.settlement_date,
                "ledger_date": self.ledger_date,
                "age_days": self.age_days,
                "material": self.material,
            }
        )
        if self.exception_ref != expected_ref:
            raise ValueError("exception_ref must commit to the exact exception sources")
        return self


class StripeLedgerMatchProposal(_StrictModel):
    proposal_ref: Sha256Digest
    payout_ref: OpaqueRef
    stripe_transaction_ref: OpaqueRef
    ledger_line_ref: Sha256Digest
    proposal_basis: Literal["unique_exact_amount_within_date_window"] = (
        "unique_exact_amount_within_date_window"
    )
    expected_amount: Decimal = Field(ge=0)
    ledger_amount: Decimal = Field(ge=0)
    settlement_date: str
    ledger_date: str
    date_delta_days: int = Field(ge=0, le=_MAX_DATE_TOLERANCE_DAYS)
    automatic_match_authorized: Literal[False] = False
    human_review_required: Literal[True] = True

    @field_validator("expected_amount", "ledger_amount", mode="before")
    @classmethod
    def _exact_money(cls, value: Any) -> Decimal:
        return _money(value, non_negative=True)

    @model_validator(mode="after")
    def _sealed_proposal(self) -> "StripeLedgerMatchProposal":
        if self.expected_amount != self.ledger_amount:
            raise ValueError("amount/date proposals require exact amounts")
        expected_ref = _stable_digest(
            {
                "payout_ref": self.payout_ref,
                "stripe_transaction_ref": self.stripe_transaction_ref,
                "ledger_line_ref": self.ledger_line_ref,
                "expected_amount": str(self.expected_amount),
                "settlement_date": self.settlement_date,
                "ledger_date": self.ledger_date,
            }
        )
        if self.proposal_ref != expected_ref:
            raise ValueError("proposal_ref must commit to the exact candidate sources")
        return self


class StripeLedgerReconciliationSummary(_StrictModel):
    payout_count: int = Field(ge=0, le=_MAX_PAYOUTS)
    referenced_ledger_line_count: int = Field(ge=0, le=_MAX_LEDGER_LINES)
    matched_count: int = Field(ge=0, le=_MAX_PAYOUTS)
    proposed_match_count: int = Field(ge=0, le=_MAX_PAYOUTS)
    unresolved_exception_count: int = Field(ge=0, le=_MAX_PAYOUTS + _MAX_LEDGER_LINES)
    material_exception_count: int = Field(ge=0, le=_MAX_PAYOUTS + _MAX_LEDGER_LINES)
    unreferenced_control_account_line_count: int = Field(
        ge=0,
        le=_MAX_LEDGER_LINES,
    )
    stripe_payout_total: Decimal = Field(ge=0)
    referenced_ledger_total: Decimal
    matched_total: Decimal = Field(ge=0)
    unexplained_variance: Decimal
    match_coverage: Decimal = Field(ge=0, le=1)
    oldest_unresolved_exception_age_days: int = Field(ge=0, le=36_600)
    close_reconciliation_ready: bool

    @field_validator(
        "stripe_payout_total",
        "referenced_ledger_total",
        "matched_total",
        "unexplained_variance",
        mode="before",
    )
    @classmethod
    def _exact_money(cls, value: Any, info: Any) -> Decimal:
        return _money(
            value,
            non_negative=info.field_name in {"stripe_payout_total", "matched_total"},
        )

    @field_validator("match_coverage", mode="before")
    @classmethod
    def _bounded_coverage(cls, value: Any) -> Decimal:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("match_coverage must be an exact decimal") from exc
        if not parsed.is_finite() or parsed < 0 or parsed > 1:
            raise ValueError("match_coverage must be between zero and one")
        if parsed.as_tuple().exponent < -8:
            raise ValueError("match_coverage supports at most eight decimal places")
        return parsed

    @model_validator(mode="after")
    def _arithmetic_and_readiness(self) -> "StripeLedgerReconciliationSummary":
        expected_coverage = _coverage_ratio(self.matched_count, self.payout_count)
        if self.match_coverage != expected_coverage:
            raise ValueError("match_coverage must match exact payout coverage")
        if self.unexplained_variance != (
            self.referenced_ledger_total - self.stripe_payout_total
        ):
            raise ValueError("unexplained_variance must match source totals")
        expected_ready = (
            self.matched_count == self.payout_count
            and self.proposed_match_count == 0
            and self.unresolved_exception_count == 0
            and self.unexplained_variance == 0
        )
        if self.close_reconciliation_ready != expected_ready:
            raise ValueError("close readiness must match deterministic reconciliation")
        return self


class StripeLedgerReconciliationResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_stripe_ledger_reconciliation_result.v1"] = (
        Field(default=STRIPE_LEDGER_RECONCILIATION_RESULT_SCHEMA, alias="schema")
    )
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    stripe_subledger_ref: OpaqueRef
    control_account_ref: OpaqueRef
    ledger_provider: Literal["quickbooks", "xero"]
    start_date: str
    end_date: str
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    reconciled_at: str
    stripe_source_digest: Sha256Digest
    ledger_source_digest: Sha256Digest
    matches: tuple[StripeLedgerReconciliationMatch, ...] = Field(
        max_length=_MAX_PAYOUTS
    )
    proposed_matches: tuple[StripeLedgerMatchProposal, ...] = Field(
        max_length=_MAX_PAYOUTS
    )
    exceptions: tuple[StripeLedgerReconciliationException, ...] = Field(
        max_length=_MAX_PAYOUTS + _MAX_LEDGER_LINES
    )
    summary: StripeLedgerReconciliationSummary
    connector_operation_performed: Literal[False] = False
    authority_state: Literal["structural_candidate_only"] = "structural_candidate_only"
    reconciliation_authority: Literal[False] = False
    exception_disposition_authority: Literal[False] = False
    close_transition_authority: Literal[False] = False
    result_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("matches", "proposed_matches", "exceptions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("reconciled_at")
    @classmethod
    def _reconciled_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="reconciled_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_result(self) -> "StripeLedgerReconciliationResult":
        if len(self.matches) != self.summary.matched_count:
            raise ValueError("summary matched_count must match exact matches")
        if len(self.proposed_matches) != self.summary.proposed_match_count:
            raise ValueError("summary proposed_match_count must match proposals")
        if len(self.exceptions) != self.summary.unresolved_exception_count:
            raise ValueError("summary unresolved count must match exceptions")
        if sum(item.material for item in self.exceptions) != (
            self.summary.material_exception_count
        ):
            raise ValueError("summary material count must match exceptions")
        match_refs = [item.match_ref for item in self.matches]
        proposal_refs = [item.proposal_ref for item in self.proposed_matches]
        exception_refs = [item.exception_ref for item in self.exceptions]
        if len(match_refs) != len(set(match_refs)):
            raise ValueError("match references must be unique")
        if len(proposal_refs) != len(set(proposal_refs)):
            raise ValueError("proposal references must be unique")
        if len(exception_refs) != len(set(exception_refs)):
            raise ValueError("exception references must be unique")
        expected = _stable_digest(self.digest_payload())
        if self.result_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("result_digest does not match reconciliation evidence")
        object.__setattr__(self, "result_digest", expected)
        return self


def _exception(
    *,
    kind: ReconciliationExceptionKind,
    payout_ref: str | None = None,
    stripe_transaction_refs: tuple[str, ...] = (),
    ledger_line_refs: tuple[str, ...] = (),
    expected_amount: Decimal | None = None,
    ledger_amount: Decimal | None = None,
    settlement_date: str | None = None,
    ledger_date: str | None = None,
    age_days: int,
    materiality_threshold: Decimal,
) -> StripeLedgerReconciliationException:
    stripe_refs = tuple(sorted(stripe_transaction_refs))
    ledger_refs = tuple(sorted(ledger_line_refs))
    delta = (
        ledger_amount - expected_amount
        if ledger_amount is not None and expected_amount is not None
        else None
    )
    magnitude = (
        abs(delta)
        if delta is not None
        else abs(expected_amount or ledger_amount or Decimal(0))
    )
    material = magnitude > materiality_threshold
    payload = {
        "schema": STRIPE_LEDGER_RECONCILIATION_EXCEPTION_SCHEMA,
        "kind": kind,
        "payout_ref": payout_ref,
        "stripe_transaction_refs": stripe_refs,
        "ledger_line_refs": ledger_refs,
        "expected_amount": (
            str(expected_amount) if expected_amount is not None else None
        ),
        "ledger_amount": str(ledger_amount) if ledger_amount is not None else None,
        "settlement_date": settlement_date,
        "ledger_date": ledger_date,
        "age_days": age_days,
        "material": material,
    }
    return StripeLedgerReconciliationException(
        exception_ref=_stable_digest(payload),
        kind=kind,
        payout_ref=payout_ref,
        stripe_transaction_refs=stripe_refs,
        ledger_line_refs=ledger_refs,
        expected_amount=expected_amount,
        ledger_amount=ledger_amount,
        amount_delta=delta,
        settlement_date=settlement_date,
        ledger_date=ledger_date,
        age_days=age_days,
        material=material,
    )


def _match(
    *,
    payout_ref: str,
    movement: StripeSettlementMovement,
    line: GeneralLedgerActivityLine,
    expected_amount: Decimal,
    settlement_date: str,
    date_delta_days: int,
) -> StripeLedgerReconciliationMatch:
    payload = {
        "schema": STRIPE_LEDGER_RECONCILIATION_MATCH_SCHEMA,
        "payout_ref": payout_ref,
        "stripe_transaction_ref": movement.transaction_ref,
        "ledger_line_ref": line.line_ref,
        "expected_amount": str(expected_amount),
        "ledger_amount": str(line.amount),
        "settlement_date": settlement_date,
        "ledger_date": line.transaction_date,
    }
    return StripeLedgerReconciliationMatch(
        match_ref=_stable_digest(payload),
        payout_ref=payout_ref,
        stripe_transaction_ref=movement.transaction_ref,
        ledger_line_ref=line.line_ref,
        expected_amount=expected_amount,
        ledger_amount=line.amount,
        amount_delta=line.amount - expected_amount,
        settlement_date=settlement_date,
        ledger_date=line.transaction_date,
        date_delta_days=date_delta_days,
    )


def _proposal(
    *,
    payout_ref: str,
    movement: StripeSettlementMovement,
    line: GeneralLedgerActivityLine,
    expected_amount: Decimal,
    settlement_date: str,
    date_delta_days: int,
) -> StripeLedgerMatchProposal:
    payload = {
        "payout_ref": payout_ref,
        "stripe_transaction_ref": movement.transaction_ref,
        "ledger_line_ref": line.line_ref,
        "expected_amount": str(expected_amount),
        "settlement_date": settlement_date,
        "ledger_date": line.transaction_date,
    }
    return StripeLedgerMatchProposal(
        proposal_ref=_stable_digest(payload),
        payout_ref=payout_ref,
        stripe_transaction_ref=movement.transaction_ref,
        ledger_line_ref=line.line_ref,
        expected_amount=expected_amount,
        ledger_amount=line.amount,
        settlement_date=settlement_date,
        ledger_date=line.transaction_date,
        date_delta_days=date_delta_days,
    )


def reconcile_stripe_settlements(
    inputs: StripeLedgerReconciliationInput,
) -> StripeLedgerReconciliationResult:
    workspace = inputs.workspace
    stripe = inputs.stripe_observation
    ledger = inputs.ledger_observation
    control_lines = tuple(
        line
        for line in ledger.lines
        if line.account_ref == workspace.stripe_control_account_ref
    )
    referenced_lines: dict[str, list[GeneralLedgerActivityLine]] = {}
    unreferenced_lines: list[GeneralLedgerActivityLine] = []
    ambiguous_reference_lines: list[
        tuple[GeneralLedgerActivityLine, tuple[str, ...]]
    ] = []
    for line in control_lines:
        refs = _line_payout_refs(line)
        if not refs:
            unreferenced_lines.append(line)
        elif len(refs) > 1:
            ambiguous_reference_lines.append((line, refs))
        else:
            referenced_lines.setdefault(refs[0], []).append(line)

    payouts = tuple(
        movement
        for movement in stripe.movements
        if movement.movement_type == "payout" or movement.reporting_category == "payout"
    )
    payouts_by_ref: dict[str, list[StripeSettlementMovement]] = {}
    missing_ref_payouts: list[StripeSettlementMovement] = []
    for movement in payouts:
        if (
            movement.source_ref is None
            or _PAYOUT_REF_PATTERN.fullmatch(movement.source_ref) is None
        ):
            missing_ref_payouts.append(movement)
        else:
            payouts_by_ref.setdefault(movement.source_ref, []).append(movement)

    matches: list[StripeLedgerReconciliationMatch] = []
    proposals: list[StripeLedgerMatchProposal] = []
    exceptions: list[StripeLedgerReconciliationException] = []
    used_ledger_lines: set[str] = set()
    reconciled_date = _as_datetime(inputs.reconciled_at).date()
    materiality = workspace.close_scope.materiality_threshold

    for line, _refs in ambiguous_reference_lines:
        exceptions.append(
            _exception(
                kind="ambiguous_ledger_reference",
                payout_ref=None,
                ledger_line_refs=(line.line_ref,),
                ledger_amount=line.amount,
                ledger_date=line.transaction_date,
                age_days=max(
                    0,
                    (reconciled_date - date.fromisoformat(line.transaction_date)).days,
                ),
                materiality_threshold=materiality,
            )
        )
        used_ledger_lines.add(line.line_ref)

    for movement in missing_ref_payouts:
        expected_amount = abs(
            _minor_units(movement.net_minor, inputs.minor_unit_exponent)
        )
        settlement_date = _date_from_timestamp(movement.available_on).isoformat()
        exceptions.append(
            _exception(
                kind="missing_stripe_payout_reference",
                stripe_transaction_refs=(movement.transaction_ref,),
                expected_amount=expected_amount,
                settlement_date=settlement_date,
                age_days=max(
                    0,
                    (reconciled_date - date.fromisoformat(settlement_date)).days,
                ),
                materiality_threshold=materiality,
            )
        )

    for payout_ref in sorted(payouts_by_ref):
        movements = tuple(
            sorted(
                payouts_by_ref[payout_ref],
                key=lambda item: item.transaction_ref,
            )
        )
        if len(movements) != 1:
            expected = sum(
                (
                    abs(_minor_units(item.net_minor, inputs.minor_unit_exponent))
                    for item in movements
                ),
                Decimal(0),
            )
            exceptions.append(
                _exception(
                    kind="duplicate_stripe_payout_reference",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=tuple(
                        item.transaction_ref for item in movements
                    ),
                    ledger_line_refs=tuple(
                        item.line_ref for item in referenced_lines.get(payout_ref, ())
                    ),
                    expected_amount=expected,
                    ledger_amount=sum(
                        (item.amount for item in referenced_lines.get(payout_ref, ())),
                        Decimal(0),
                    ),
                    age_days=max(
                        max(
                            0,
                            (
                                reconciled_date
                                - _date_from_timestamp(item.available_on)
                            ).days,
                        )
                        for item in movements
                    ),
                    materiality_threshold=materiality,
                )
            )
            used_ledger_lines.update(
                item.line_ref for item in referenced_lines.get(payout_ref, ())
            )
            continue

        movement = movements[0]
        expected_amount = abs(
            _minor_units(movement.net_minor, inputs.minor_unit_exponent)
        )
        settlement_date = _date_from_timestamp(movement.available_on).isoformat()
        age_days = max(
            0,
            (reconciled_date - date.fromisoformat(settlement_date)).days,
        )
        candidates = tuple(
            sorted(
                referenced_lines.get(payout_ref, ()),
                key=lambda line: line.line_ref,
            )
        )
        if movement.net_minor >= 0:
            exceptions.append(
                _exception(
                    kind="invalid_payout_direction",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    ledger_line_refs=tuple(line.line_ref for line in candidates),
                    expected_amount=expected_amount,
                    ledger_amount=sum(
                        (line.amount for line in candidates),
                        Decimal(0),
                    ),
                    settlement_date=settlement_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
            used_ledger_lines.update(line.line_ref for line in candidates)
            continue
        if movement.status != "available":
            exceptions.append(
                _exception(
                    kind="pending_settlement",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    ledger_line_refs=tuple(line.line_ref for line in candidates),
                    expected_amount=expected_amount,
                    ledger_amount=sum(
                        (line.amount for line in candidates),
                        Decimal(0),
                    ),
                    settlement_date=settlement_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
            used_ledger_lines.update(line.line_ref for line in candidates)
            continue
        if not candidates:
            proposal_candidates = [
                line
                for line in unreferenced_lines
                if line.line_ref not in used_ledger_lines
                and line.amount == expected_amount
                and abs(
                    (
                        date.fromisoformat(line.transaction_date)
                        - date.fromisoformat(settlement_date)
                    ).days
                )
                <= inputs.settlement_date_tolerance_days
            ]
            if len(proposal_candidates) == 1:
                candidate = proposal_candidates[0]
                proposals.append(
                    _proposal(
                        payout_ref=payout_ref,
                        movement=movement,
                        line=candidate,
                        expected_amount=expected_amount,
                        settlement_date=settlement_date,
                        date_delta_days=abs(
                            (
                                date.fromisoformat(candidate.transaction_date)
                                - date.fromisoformat(settlement_date)
                            ).days
                        ),
                    )
                )
                used_ledger_lines.add(candidate.line_ref)
            exceptions.append(
                _exception(
                    kind="missing_in_ledger",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    expected_amount=expected_amount,
                    settlement_date=settlement_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
            continue
        if len(candidates) > 1:
            ledger_total = sum((line.amount for line in candidates), Decimal(0))
            exceptions.append(
                _exception(
                    kind="ambiguous_ledger_reference",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    ledger_line_refs=tuple(line.line_ref for line in candidates),
                    expected_amount=expected_amount,
                    ledger_amount=ledger_total,
                    settlement_date=settlement_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
            used_ledger_lines.update(line.line_ref for line in candidates)
            continue

        candidate = candidates[0]
        used_ledger_lines.add(candidate.line_ref)
        date_delta = abs(
            (
                date.fromisoformat(candidate.transaction_date)
                - date.fromisoformat(settlement_date)
            ).days
        )
        if candidate.amount != expected_amount:
            exceptions.append(
                _exception(
                    kind="amount_mismatch",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    ledger_line_refs=(candidate.line_ref,),
                    expected_amount=expected_amount,
                    ledger_amount=candidate.amount,
                    settlement_date=settlement_date,
                    ledger_date=candidate.transaction_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
        elif date_delta > inputs.settlement_date_tolerance_days:
            exceptions.append(
                _exception(
                    kind="date_out_of_tolerance",
                    payout_ref=payout_ref,
                    stripe_transaction_refs=(movement.transaction_ref,),
                    ledger_line_refs=(candidate.line_ref,),
                    expected_amount=expected_amount,
                    ledger_amount=candidate.amount,
                    settlement_date=settlement_date,
                    ledger_date=candidate.transaction_date,
                    age_days=age_days,
                    materiality_threshold=materiality,
                )
            )
        else:
            matches.append(
                _match(
                    payout_ref=payout_ref,
                    movement=movement,
                    line=candidate,
                    expected_amount=expected_amount,
                    settlement_date=settlement_date,
                    date_delta_days=date_delta,
                )
            )

    known_payout_refs = set(payouts_by_ref)
    for payout_ref, lines in sorted(referenced_lines.items()):
        if payout_ref in known_payout_refs:
            continue
        for line in sorted(lines, key=lambda item: item.line_ref):
            if line.line_ref in used_ledger_lines:
                continue
            exceptions.append(
                _exception(
                    kind="ledger_without_stripe_payout",
                    payout_ref=payout_ref,
                    ledger_line_refs=(line.line_ref,),
                    ledger_amount=line.amount,
                    ledger_date=line.transaction_date,
                    age_days=max(
                        0,
                        (
                            reconciled_date - date.fromisoformat(line.transaction_date)
                        ).days,
                    ),
                    materiality_threshold=materiality,
                )
            )
            used_ledger_lines.add(line.line_ref)

    matches_tuple = tuple(sorted(matches, key=lambda item: item.match_ref))
    proposals_tuple = tuple(sorted(proposals, key=lambda item: item.proposal_ref))
    exceptions_tuple = tuple(sorted(exceptions, key=lambda item: item.exception_ref))
    payout_total = sum(
        (
            abs(_minor_units(item.net_minor, inputs.minor_unit_exponent))
            for item in payouts
        ),
        Decimal(0),
    )
    referenced_total = sum(
        (line.amount for lines in referenced_lines.values() for line in lines),
        Decimal(0),
    ) + sum((line.amount for line, _refs in ambiguous_reference_lines), Decimal(0))
    matched_total = sum((item.expected_amount for item in matches_tuple), Decimal(0))
    coverage = _coverage_ratio(len(matches_tuple), len(payouts))
    summary = StripeLedgerReconciliationSummary(
        payout_count=len(payouts),
        referenced_ledger_line_count=(
            sum(len(lines) for lines in referenced_lines.values())
            + len(ambiguous_reference_lines)
        ),
        matched_count=len(matches_tuple),
        proposed_match_count=len(proposals_tuple),
        unresolved_exception_count=len(exceptions_tuple),
        material_exception_count=sum(item.material for item in exceptions_tuple),
        unreferenced_control_account_line_count=len(unreferenced_lines),
        stripe_payout_total=payout_total,
        referenced_ledger_total=referenced_total,
        matched_total=matched_total,
        unexplained_variance=referenced_total - payout_total,
        match_coverage=coverage,
        oldest_unresolved_exception_age_days=max(
            (item.age_days for item in exceptions_tuple),
            default=0,
        ),
        close_reconciliation_ready=(
            len(matches_tuple) == len(payouts)
            and not proposals_tuple
            and not exceptions_tuple
            and referenced_total == payout_total
        ),
    )
    return StripeLedgerReconciliationResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        stripe_subledger_ref=workspace.stripe_subledger_ref,
        control_account_ref=workspace.stripe_control_account_ref,
        ledger_provider=ledger.provider,
        start_date=stripe.start_date,
        end_date=stripe.end_date,
        currency=stripe.currency,
        reconciled_at=inputs.reconciled_at,
        stripe_source_digest=stripe.source_digest,
        ledger_source_digest=ledger.source_digest,
        matches=matches_tuple,
        proposed_matches=proposals_tuple,
        exceptions=exceptions_tuple,
        summary=summary,
    )


def _example_inputs() -> dict[str, Any]:
    workspace_input = FinanceCloseWorkspaceInput.model_validate(
        deepcopy(PrepareCloseWorkspacePrimitive.example_inputs)
    )
    workspace = prepare_close_workspace(workspace_input).workspace
    project_id = workspace.close_scope.project_id
    page_digest = _stable_digest("stripe-empty-page")
    stripe = StripeSettlementObservationResult(
        project_id=project_id,
        tenant_connector_id=UUID("00000000-0000-0000-0000-000000000711"),
        connector_account_ref="stripe-account-example",
        route_digest=_stable_digest("stripe-route-example"),
        start_date="2026-08-01",
        end_date="2026-08-31",
        currency="USD",
        movements=(),
        movement_count=0,
        page_count=1,
        page_digests=(page_digest,),
        provenance_receipt_digests=(_stable_digest("stripe-receipt-example"),),
        observation_completed_ats=("2026-09-01T12:00:00Z",),
        observed_at="2026-09-01T12:00:00Z",
    )
    ledger = GeneralLedgerActivityObservation(
        provider="quickbooks",
        tool="quickbooks.general_ledger_report",
        tool_version=2,
        project_id=project_id,
        tenant_connector_id=UUID("00000000-0000-0000-0000-000000000712"),
        connector_account_ref="quickbooks-account-example",
        route_digest=_stable_digest("ledger-route-example"),
        start_date="2026-08-01",
        end_date="2026-08-31",
        currency="USD",
        lines=(),
        line_count=0,
        provider_report_digest=_stable_digest("empty-general-ledger"),
        provenance_receipt_digest=_stable_digest("ledger-receipt-example"),
        observed_at="2026-09-01T12:01:00Z",
    )
    return {
        "workspace": workspace.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "stripe_observation": stripe.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "ledger_observation": ledger.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "reconciled_at": "2026-09-01T12:35:00Z",
        "minor_unit_exponent": 2,
        "settlement_date_tolerance_days": 7,
    }


class ReconcileStripeSettlementsPrimitive(
    BusinessProcessPrimitive[
        StripeLedgerReconciliationInput,
        StripeLedgerReconciliationResult,
    ]
):
    primitive_ref = "finance.reconcile_stripe_settlements"
    version = "1.0.0"
    title = "Reconcile Stripe settlements to ledger activity"
    description = (
        "Deterministically match Stripe payout balance transactions to canonical "
        "General Ledger activity under one sealed monthly close workspace, while "
        "emitting bounded exception and human-review candidates without authority."
    )
    input_model = StripeLedgerReconciliationInput
    output_model = StripeLedgerReconciliationResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "workspace_writes": 0,
            "ledger_writes": 0,
            "exception_dispositions": 0,
            "period_transitions": 0,
        }
        contract["automatic_match_policy"] = (
            "unique_payout_reference_exact_amount_within_date_tolerance"
        )
        contract["provider_support"] = {
            "stripe": "governed_settlement_observation_implemented_dark",
            "quickbooks": "governed_general_ledger_observation_implemented_dark",
            "xero": "governed_general_ledger_observation_implemented_dark",
        }
        contract["system_of_record_authority"] = "spring_host_required"
        contract["reconciliation_authority"] = "structural_candidate_only"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: StripeLedgerReconciliationInput,
    ) -> PrimitiveExecutionResult[StripeLedgerReconciliationResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="stripe_ledger_reconciliation_scope_mismatch",
                message=(
                    "The reconciliation workspace tenant, company, project, and "
                    "project UUID must exactly match the active runtime scope."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = reconcile_stripe_settlements(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Evaluated {output.summary.payout_count} Stripe payouts: "
                f"{output.summary.matched_count} exact matches and "
                f"{output.summary.unresolved_exception_count} unresolved exceptions."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.stripe_ledger_reconciliation_evaluated",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "workspace_revision": output.workspace_revision,
                        "matched_count": output.summary.matched_count,
                        "proposed_match_count": output.summary.proposed_match_count,
                        "unresolved_exception_count": (
                            output.summary.unresolved_exception_count
                        ),
                        "material_exception_count": (
                            output.summary.material_exception_count
                        ),
                        "close_reconciliation_ready": (
                            output.summary.close_reconciliation_ready
                        ),
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="stripe_ledger_reconciliation_candidate",
                    summary=(
                        "Deterministic settlement matches and exception candidates "
                        "were derived from two complete source observations."
                    ),
                    labels=[
                        "stripe",
                        output.ledger_provider,
                        "monthly_close",
                        "structural_candidate_only",
                        "independent_review_required",
                    ],
                    refs={"result_digest": output.result_digest},
                )
            ],
        )


FINANCE_SETTLEMENT_RECONCILIATION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ReconcileStripeSettlementsPrimitive(),)


__all__ = [
    "FINANCE_SETTLEMENT_RECONCILIATION_EXECUTABLE_PRIMITIVES",
    "ReconcileStripeSettlementsPrimitive",
    "ReconciliationExceptionKind",
    "STRIPE_LEDGER_RECONCILIATION_EXCEPTION_SCHEMA",
    "STRIPE_LEDGER_RECONCILIATION_INPUT_SCHEMA",
    "STRIPE_LEDGER_RECONCILIATION_MATCH_SCHEMA",
    "STRIPE_LEDGER_RECONCILIATION_RESULT_SCHEMA",
    "StripeLedgerMatchProposal",
    "StripeLedgerReconciliationException",
    "StripeLedgerReconciliationInput",
    "StripeLedgerReconciliationMatch",
    "StripeLedgerReconciliationResult",
    "StripeLedgerReconciliationSummary",
    "reconcile_stripe_settlements",
]
