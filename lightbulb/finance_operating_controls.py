"""Evidence-bound controls for finance operating subledgers.

The evaluator covers planning, treasury, expenses, payroll, tax, revenue
recognition, fixed assets, and financial-control evidence.  It is deliberately
read-only: a trusted host supplies normalized snapshots and Spring remains the
authority for scope, approval, persistence, filings, postings, payments, and
other consequential effects.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
    revalidate_model_boundary,
)


FINANCE_OPERATING_CONTROLS_INPUT_SCHEMA = (
    "lightbulb.finance_operating_controls_input.v1"
)
FINANCE_OPERATING_CONTROLS_RESULT_SCHEMA = (
    "lightbulb.finance_operating_controls_result.v1"
)

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
FindingCode = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,119}$"),
]

FinanceOperatingDomain = Literal[
    "planning",
    "treasury",
    "expense",
    "payroll",
    "tax",
    "revenue_recognition",
    "fixed_assets",
    "financial_controls",
]
FinanceOperatingStatus = Literal["pass", "fail", "indeterminate"]
FinanceOperatingDisposition = Literal["ready", "blocked", "indeterminate"]

_MONEY_QUANTUM = Decimal("0.0001")
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_REQUIRED_EVIDENCE_KINDS = (
    "financial_plan",
    "treasury_position",
    "expense_register",
    "payroll_register",
    "tax_compliance",
    "revenue_schedule",
    "fixed_asset_register",
    "financial_control_test",
)
_ZERO_DIGEST = "0" * 64


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


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _money(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("money values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError("money values must use bounded notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(_MONEY_QUANTUM)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("money values must be finite and within precision") from exc
    if not parsed.is_finite() or parsed != normalized or abs(parsed) > Decimal("1e24"):
        raise ValueError("money values must be finite and support four decimal places")
    return normalized


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PlanningControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    budget_ref: OpaqueRef
    budget_status: Literal["draft", "pending_approval", "approved", "superseded"]
    forecast_ref: OpaqueRef
    forecast_as_of: str
    actuals_as_of: str
    required_cost_center_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=5_000
    )
    budgeted_cost_center_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=5_000
    )
    unexplained_material_variance_count: int = Field(ge=0, le=1_000_000)

    @field_validator("forecast_as_of", "actuals_as_of")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "required_cost_center_refs", "budgeted_cost_center_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_cost_centers(self) -> "PlanningControlSnapshot":
        for name, values in (
            ("required", self.required_cost_center_refs),
            ("budgeted", self.budgeted_cost_center_refs),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{name} cost center references must be unique")
        return self


class TreasuryControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    position_as_of: str
    cash_position_complete: bool
    bank_account_count: int = Field(ge=1, le=100_000)
    reconciled_bank_account_count: int = Field(ge=0, le=100_000)
    cash_forecast_horizon_days: int = Field(ge=0, le=3_650)
    available_liquidity_days: int = Field(ge=0, le=3_650)
    signatory_conflict_count: int = Field(ge=0, le=100_000)

    @field_validator("position_as_of")
    @classmethod
    def _position_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="position_as_of")

    @model_validator(mode="after")
    def _reconciled_count_is_bounded(self) -> "TreasuryControlSnapshot":
        if self.reconciled_bank_account_count > self.bank_account_count:
            raise ValueError("reconciled bank accounts cannot exceed bank accounts")
        return self


class ExpenseControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    submitted_report_count: int = Field(ge=0, le=10_000_000)
    approved_report_count: int = Field(ge=0, le=10_000_000)
    reimbursed_report_count: int = Field(ge=0, le=10_000_000)
    missing_receipt_count: int = Field(ge=0, le=10_000_000)
    duplicate_suspect_count: int = Field(ge=0, le=10_000_000)
    unreviewed_policy_exception_count: int = Field(ge=0, le=10_000_000)
    corporate_cards_reconciled: bool

    @model_validator(mode="after")
    def _report_counts_are_ordered(self) -> "ExpenseControlSnapshot":
        if self.approved_report_count > self.submitted_report_count:
            raise ValueError("approved reports cannot exceed submitted reports")
        if self.reimbursed_report_count > self.approved_report_count:
            raise ValueError("reimbursed reports cannot exceed approved reports")
        return self


class PayrollControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    pay_run_ref: OpaqueRef
    currency: CurrencyCode
    status: Literal["calculated", "approved", "funded", "posted", "cancelled"]
    employee_count: int = Field(ge=1, le=10_000_000)
    gross_pay: Decimal
    net_pay: Decimal
    employee_tax: Decimal
    employee_deductions: Decimal
    funding_confirmed: bool
    payroll_register_reconciled: bool
    tax_liability_reconciled: bool

    @field_validator(
        "gross_pay", "net_pay", "employee_tax", "employee_deductions", mode="before"
    )
    @classmethod
    def _money_fields(cls, value: Any) -> Decimal:
        parsed = _money(value)
        if parsed < 0:
            raise ValueError("payroll amounts must be non-negative")
        return parsed


class TaxControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    tax_period_ref: OpaqueRef
    jurisdiction_count: int = Field(ge=1, le=100_000)
    assessed_jurisdiction_count: int = Field(ge=0, le=100_000)
    filings_due_count: int = Field(ge=0, le=1_000_000)
    filings_ready_count: int = Field(ge=0, le=1_000_000)
    past_due_filing_count: int = Field(ge=0, le=1_000_000)
    nexus_assessment_current: bool
    remittance_funding_confirmed: bool

    @model_validator(mode="after")
    def _tax_counts_are_bounded(self) -> "TaxControlSnapshot":
        if self.assessed_jurisdiction_count > self.jurisdiction_count:
            raise ValueError("assessed jurisdictions cannot exceed jurisdictions")
        if self.filings_ready_count > self.filings_due_count:
            raise ValueError("ready filings cannot exceed due filings")
        return self


class RevenueRecognitionControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    currency: CurrencyCode
    contract_count: int = Field(ge=0, le=10_000_000)
    allocated_contract_count: int = Field(ge=0, le=10_000_000)
    performance_obligation_count: int = Field(ge=0, le=100_000_000)
    scheduled_obligation_count: int = Field(ge=0, le=100_000_000)
    unresolved_contract_exception_count: int = Field(ge=0, le=10_000_000)
    contract_consideration: Decimal
    recognized_revenue: Decimal
    deferred_revenue: Decimal

    @field_validator(
        "contract_consideration",
        "recognized_revenue",
        "deferred_revenue",
        mode="before",
    )
    @classmethod
    def _money_fields(cls, value: Any) -> Decimal:
        parsed = _money(value)
        if parsed < 0:
            raise ValueError("revenue amounts must be non-negative")
        return parsed

    @model_validator(mode="after")
    def _revenue_counts_are_bounded(self) -> "RevenueRecognitionControlSnapshot":
        if self.allocated_contract_count > self.contract_count:
            raise ValueError("allocated contracts cannot exceed contracts")
        if self.scheduled_obligation_count > self.performance_obligation_count:
            raise ValueError("scheduled obligations cannot exceed obligations")
        return self


class FixedAssetControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    currency: CurrencyCode
    asset_register_count: int = Field(ge=0, le=100_000_000)
    tagged_asset_count: int = Field(ge=0, le=100_000_000)
    depreciation_due_count: int = Field(ge=0, le=100_000_000)
    depreciation_completed_count: int = Field(ge=0, le=100_000_000)
    subledger_gl_difference: Decimal
    overdue_impairment_review_count: int = Field(ge=0, le=100_000_000)
    disposal_pending_approval_count: int = Field(ge=0, le=100_000_000)

    @field_validator("subledger_gl_difference", mode="before")
    @classmethod
    def _difference(cls, value: Any) -> Decimal:
        return _money(value)

    @model_validator(mode="after")
    def _asset_counts_are_bounded(self) -> "FixedAssetControlSnapshot":
        if self.tagged_asset_count > self.asset_register_count:
            raise ValueError("tagged assets cannot exceed registered assets")
        if self.depreciation_completed_count > self.depreciation_due_count:
            raise ValueError("completed depreciation cannot exceed due depreciation")
        return self


class FinancialControlSnapshot(_StrictModel):
    company_ref: OpaqueRef
    control_period_ref: OpaqueRef
    key_control_count: int = Field(ge=1, le=1_000_000)
    tested_control_count: int = Field(ge=0, le=1_000_000)
    failed_control_count: int = Field(ge=0, le=1_000_000)
    overdue_remediation_count: int = Field(ge=0, le=1_000_000)
    segregation_conflict_count: int = Field(ge=0, le=1_000_000)
    audit_request_count: int = Field(ge=0, le=1_000_000)
    fulfilled_audit_request_count: int = Field(ge=0, le=1_000_000)
    evidence_trace_complete: bool

    @model_validator(mode="after")
    def _control_counts_are_bounded(self) -> "FinancialControlSnapshot":
        if self.tested_control_count > self.key_control_count:
            raise ValueError("tested controls cannot exceed key controls")
        if self.failed_control_count > self.tested_control_count:
            raise ValueError("failed controls cannot exceed tested controls")
        if self.fulfilled_audit_request_count > self.audit_request_count:
            raise ValueError("fulfilled audit requests cannot exceed requests")
        return self


class FinanceOperatingPolicy(_StrictModel):
    maximum_snapshot_age_hours: int = Field(default=168, ge=1, le=8_760)
    minimum_cash_forecast_horizon_days: int = Field(default=13, ge=1, le=3_650)
    minimum_liquidity_days: int = Field(default=30, ge=0, le=3_650)
    maximum_subledger_gl_difference: Decimal = Field(default=Decimal("0"), ge=0)
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    required_evidence_kinds: tuple[str, ...] = Field(
        default=_REQUIRED_EVIDENCE_KINDS,
        min_length=1,
        max_length=30,
    )

    @field_validator("maximum_subledger_gl_difference", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        parsed = _money(value)
        if parsed < 0:
            raise ValueError("difference tolerance must be non-negative")
        return parsed

    @field_validator("required_evidence_kinds", mode="before")
    @classmethod
    def _required_kinds_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _required_kinds_are_unique(self) -> "FinanceOperatingPolicy":
        if len(self.required_evidence_kinds) != len(set(self.required_evidence_kinds)):
            raise ValueError("required evidence kinds must be unique")
        return self


class FinanceOperatingControlsInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_operating_controls_input.v1"] = Field(
        default=FINANCE_OPERATING_CONTROLS_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    currency: CurrencyCode
    evaluated_at: str
    planning: PlanningControlSnapshot
    treasury: TreasuryControlSnapshot
    expense: ExpenseControlSnapshot
    payroll: PayrollControlSnapshot
    tax: TaxControlSnapshot
    revenue_recognition: RevenueRecognitionControlSnapshot
    fixed_assets: FixedAssetControlSnapshot
    financial_controls: FinancialControlSnapshot
    policy: FinanceOperatingPolicy = Field(default_factory=FinanceOperatingPolicy)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=200
    )

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _scope_and_evidence_are_exact(self) -> "FinanceOperatingControlsInput":
        snapshots = (
            self.planning,
            self.treasury,
            self.expense,
            self.payroll,
            self.tax,
            self.revenue_recognition,
            self.fixed_assets,
            self.financial_controls,
        )
        if any(snapshot.company_ref != self.company_ref for snapshot in snapshots):
            raise ValueError("all finance snapshots must match company_ref")
        if any(
            snapshot.currency != self.currency
            for snapshot in (
                self.payroll,
                self.revenue_recognition,
                self.fixed_assets,
            )
        ):
            raise ValueError("all monetary snapshots must match currency")
        snapshot_period_refs = (
            self.expense.period_ref,
            self.tax.tax_period_ref,
            self.revenue_recognition.period_ref,
            self.fixed_assets.period_ref,
            self.financial_controls.control_period_ref,
        )
        if any(period_ref != self.period_ref for period_ref in snapshot_period_refs):
            raise ValueError("all finance snapshot periods must match period_ref")
        refs = [evidence.evidence_ref for evidence in self.evidence_refs]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence references must be unique")
        return self


class FinanceOperatingFinding(_StrictModel):
    code: FindingCode
    domain: FinanceOperatingDomain
    status: FinanceOperatingStatus
    message: str = Field(min_length=1, max_length=500)
    affected_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("affected_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class FinanceOperatingControlsResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_operating_controls_result.v1"] = Field(
        default=FINANCE_OPERATING_CONTROLS_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    company_ref: OpaqueRef
    period_ref: OpaqueRef
    evaluated_at: str
    disposition: FinanceOperatingDisposition
    findings: tuple[FinanceOperatingFinding, ...]
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    indeterminate_count: int = Field(ge=0)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )
    operation_spec: PrimitiveOperationSpec
    budget_approved: Literal[False] = False
    cash_movement_authorized: Literal[False] = False
    expense_reimbursement_authorized: Literal[False] = False
    payroll_release_authorized: Literal[False] = False
    tax_filing_authorized: Literal[False] = False
    revenue_posting_authorized: Literal[False] = False
    asset_disposition_authorized: Literal[False] = False
    control_remediation_closed: Literal[False] = False

    @field_validator("findings", "evidence_refs", mode="before")
    @classmethod
    def _result_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _counts_and_operation_are_exact(self) -> "FinanceOperatingControlsResult":
        for evidence in self.evidence_refs:
            PrimitiveEvidenceRef.model_validate(
                evidence.model_dump(mode="python", by_alias=True)
            )
        PrimitiveOperationSpec.model_validate(
            self.operation_spec.model_dump(mode="python", by_alias=True)
        )
        counts = {
            "pass": self.passed_count,
            "fail": self.failed_count,
            "indeterminate": self.indeterminate_count,
        }
        actual = {status: 0 for status in counts}
        for finding in self.findings:
            actual[finding.status] += 1
        if actual != counts:
            raise ValueError("finding counts must match findings")
        expected_disposition: FinanceOperatingDisposition = (
            "blocked"
            if self.failed_count
            else "indeterminate"
            if self.indeterminate_count
            else "ready"
        )
        if self.disposition != expected_disposition:
            raise ValueError("disposition must match finding counts")
        evidence_refs = tuple(item.evidence_ref for item in self.evidence_refs)
        if evidence_refs != tuple(sorted(set(evidence_refs))):
            raise ValueError("evidence_refs must be unique and in canonical order")
        expected_evidence_digest = _stable_digest(
            [item.to_dict() for item in self.evidence_refs]
        )
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match evidence_refs")
        if self.operation_spec != FINANCE_OPERATING_CONTROLS_OPERATION:
            raise ValueError("operation_spec must identify this evaluator")
        expected_evaluation_digest = _stable_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"evaluation_digest"},
                exclude_none=True,
            )
        )
        if self.evaluation_digest not in {
            _ZERO_DIGEST,
            expected_evaluation_digest,
        }:
            raise ValueError("evaluation_digest does not match the evaluation")
        object.__setattr__(
            self,
            "evaluation_digest",
            expected_evaluation_digest,
        )
        return self


FINANCE_OPERATING_CONTROLS_OPERATION = PrimitiveOperationSpec(
    operation_ref="finance-operating-controls.evaluate",
    tool="finance.evaluate_operating_subledger_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _finding(
    findings: list[FinanceOperatingFinding],
    *,
    code: str,
    domain: FinanceOperatingDomain,
    status: FinanceOperatingStatus,
    message: str,
    refs: tuple[str, ...] = (),
) -> None:
    findings.append(
        FinanceOperatingFinding(
            code=code,
            domain=domain,
            status=status,
            message=message,
            affected_refs=refs,
        )
    )


def _boolean_gate(
    findings: list[FinanceOperatingFinding],
    *,
    code: str,
    domain: FinanceOperatingDomain,
    passed: bool,
    pass_message: str,
    fail_message: str,
) -> None:
    _finding(
        findings,
        code=code,
        domain=domain,
        status="pass" if passed else "fail",
        message=pass_message if passed else fail_message,
    )


def _evidence_findings(
    inputs: FinanceOperatingControlsInput,
    findings: list[FinanceOperatingFinding],
) -> None:
    evaluated_at = _parsed_timestamp(inputs.evaluated_at)
    by_kind: dict[str, list[PrimitiveEvidenceRef]] = {}
    for evidence in inputs.evidence_refs:
        by_kind.setdefault(evidence.kind, []).append(evidence)
    kind_domains: dict[str, FinanceOperatingDomain] = dict(
        zip(_REQUIRED_EVIDENCE_KINDS, FinanceOperatingDomain.__args__, strict=True)
    )
    for kind in inputs.policy.required_evidence_kinds:
        domain = kind_domains.get(kind, "financial_controls")
        candidates = by_kind.get(kind, [])
        if not candidates:
            _finding(
                findings,
                code=f"evidence.{kind}.missing",
                domain=domain,
                status="indeterminate",
                message=f"Required {kind.replace('_', ' ')} evidence is missing.",
            )
            continue
        usable = False
        invalid_future = False
        for evidence in candidates:
            observed_at = _parsed_timestamp(evidence.observed_at)
            if observed_at > evaluated_at:
                invalid_future = True
                continue
            age_hours = (evaluated_at - observed_at).total_seconds() / 3_600
            if (
                age_hours <= inputs.policy.maximum_snapshot_age_hours
                and _GRADE_RANK[evidence.verification_grade]
                >= _GRADE_RANK[inputs.policy.minimum_evidence_grade]
            ):
                usable = True
                break
        _finding(
            findings,
            code=f"evidence.{kind}",
            domain=domain,
            status="pass" if usable else "fail" if invalid_future else "indeterminate",
            message=(
                f"Required {kind.replace('_', ' ')} evidence is usable."
                if usable
                else f"Required {kind.replace('_', ' ')} evidence is future-dated."
                if invalid_future
                else f"Required {kind.replace('_', ' ')} evidence is stale or below grade."
            ),
        )


def evaluate_finance_operating_controls(
    inputs: FinanceOperatingControlsInput | dict[str, Any],
) -> FinanceOperatingControlsResult:
    """Evaluate a complete normalized finance operating-control packet."""

    parsed = revalidate_model_boundary(FinanceOperatingControlsInput, inputs)
    findings: list[FinanceOperatingFinding] = []
    _evidence_findings(parsed, findings)

    planning = parsed.planning
    _boolean_gate(
        findings,
        code="planning.budget_approved",
        domain="planning",
        passed=planning.budget_status == "approved",
        pass_message="The operating budget is approved in the supplied snapshot.",
        fail_message="The operating budget is not approved.",
    )
    missing_cost_centers = tuple(
        sorted(
            set(planning.required_cost_center_refs)
            - set(planning.budgeted_cost_center_refs)
        )
    )
    _finding(
        findings,
        code="planning.cost_center_coverage",
        domain="planning",
        status="pass" if not missing_cost_centers else "fail",
        message=(
            "All required cost centers are represented in the budget."
            if not missing_cost_centers
            else "One or more required cost centers are absent from the budget."
        ),
        refs=missing_cost_centers,
    )
    evaluated_at = _parsed_timestamp(parsed.evaluated_at)
    planning_timestamps = (
        _parsed_timestamp(planning.forecast_as_of),
        _parsed_timestamp(planning.actuals_as_of),
    )
    future_planning = any(value > evaluated_at for value in planning_timestamps)
    stale_planning = any(
        (evaluated_at - value).total_seconds() / 3_600
        > parsed.policy.maximum_snapshot_age_hours
        for value in planning_timestamps
        if value <= evaluated_at
    )
    _finding(
        findings,
        code="planning.forecast_freshness",
        domain="planning",
        status="fail"
        if future_planning
        else "indeterminate"
        if stale_planning
        else "pass",
        message=(
            "Planning timestamps occur after the evaluation time."
            if future_planning
            else "Planning snapshots are stale."
            if stale_planning
            else "Forecast and actuals snapshots are current."
        ),
    )
    _boolean_gate(
        findings,
        code="planning.variance_explanations",
        domain="planning",
        passed=planning.unexplained_material_variance_count == 0,
        pass_message="All material planning variances are explained.",
        fail_message="Material planning variances remain unexplained.",
    )

    treasury = parsed.treasury
    position_at = _parsed_timestamp(treasury.position_as_of)
    position_future = position_at > evaluated_at
    position_stale = (
        not position_future
        and (evaluated_at - position_at).total_seconds() / 3_600
        > parsed.policy.maximum_snapshot_age_hours
    )
    _finding(
        findings,
        code="treasury.position_freshness",
        domain="treasury",
        status="fail"
        if position_future
        else "indeterminate"
        if position_stale
        else "pass",
        message=(
            "Treasury position occurs after the evaluation time."
            if position_future
            else "Treasury position is stale."
            if position_stale
            else "Treasury position is current."
        ),
    )
    _boolean_gate(
        findings,
        code="treasury.cash_and_bank_reconciliation",
        domain="treasury",
        passed=treasury.cash_position_complete
        and treasury.reconciled_bank_account_count == treasury.bank_account_count,
        pass_message="Cash position is complete and all bank accounts are reconciled.",
        fail_message="Cash position or bank-account reconciliation is incomplete.",
    )
    _boolean_gate(
        findings,
        code="treasury.liquidity_and_forecast",
        domain="treasury",
        passed=treasury.cash_forecast_horizon_days
        >= parsed.policy.minimum_cash_forecast_horizon_days
        and treasury.available_liquidity_days >= parsed.policy.minimum_liquidity_days,
        pass_message="Cash forecast and liquidity meet policy thresholds.",
        fail_message="Cash forecast horizon or liquidity is below policy threshold.",
    )
    _boolean_gate(
        findings,
        code="treasury.signatory_segregation",
        domain="treasury",
        passed=treasury.signatory_conflict_count == 0,
        pass_message="No treasury signatory conflicts are reported.",
        fail_message="Treasury signatory conflicts require remediation.",
    )

    expense = parsed.expense
    _boolean_gate(
        findings,
        code="expense.support_and_duplicates",
        domain="expense",
        passed=expense.missing_receipt_count == 0
        and expense.duplicate_suspect_count == 0,
        pass_message="Expenses have required support and no duplicate suspects.",
        fail_message="Expense support is missing or duplicate suspects remain.",
    )
    _boolean_gate(
        findings,
        code="expense.policy_exception_review",
        domain="expense",
        passed=expense.unreviewed_policy_exception_count == 0,
        pass_message="All expense policy exceptions are reviewed.",
        fail_message="Expense policy exceptions remain unreviewed.",
    )
    _boolean_gate(
        findings,
        code="expense.card_reconciliation",
        domain="expense",
        passed=expense.corporate_cards_reconciled,
        pass_message="Corporate-card activity is reconciled.",
        fail_message="Corporate-card activity is not fully reconciled.",
    )

    payroll = parsed.payroll
    _boolean_gate(
        findings,
        code="payroll.status_and_funding",
        domain="payroll",
        passed=payroll.status in {"approved", "funded", "posted"}
        and payroll.funding_confirmed,
        pass_message="Payroll is approved and funding is confirmed.",
        fail_message="Payroll approval or funding is incomplete.",
    )
    _boolean_gate(
        findings,
        code="payroll.register_balance",
        domain="payroll",
        passed=payroll.gross_pay
        == payroll.net_pay + payroll.employee_tax + payroll.employee_deductions,
        pass_message="Payroll gross pay reconciles to net pay, tax, and deductions.",
        fail_message="Payroll register does not mathematically reconcile.",
    )
    _boolean_gate(
        findings,
        code="payroll.liability_reconciliation",
        domain="payroll",
        passed=payroll.payroll_register_reconciled and payroll.tax_liability_reconciled,
        pass_message="Payroll register and tax liabilities are reconciled.",
        fail_message="Payroll register or tax liabilities are not reconciled.",
    )

    tax = parsed.tax
    _boolean_gate(
        findings,
        code="tax.jurisdiction_and_nexus",
        domain="tax",
        passed=tax.assessed_jurisdiction_count == tax.jurisdiction_count
        and tax.nexus_assessment_current,
        pass_message="All jurisdictions are assessed and nexus analysis is current.",
        fail_message="Jurisdiction coverage or nexus analysis is incomplete.",
    )
    _boolean_gate(
        findings,
        code="tax.filing_readiness",
        domain="tax",
        passed=tax.filings_ready_count == tax.filings_due_count
        and tax.past_due_filing_count == 0
        and tax.remittance_funding_confirmed,
        pass_message="Tax filings are ready, current, and funded.",
        fail_message="Tax filings are incomplete, past due, or unfunded.",
    )

    revenue = parsed.revenue_recognition
    _boolean_gate(
        findings,
        code="revenue.contract_allocation",
        domain="revenue_recognition",
        passed=revenue.allocated_contract_count == revenue.contract_count
        and revenue.scheduled_obligation_count == revenue.performance_obligation_count,
        pass_message="Contracts and performance obligations are allocated and scheduled.",
        fail_message="Contract allocation or performance-obligation scheduling is incomplete.",
    )
    _boolean_gate(
        findings,
        code="revenue.schedule_balance",
        domain="revenue_recognition",
        passed=revenue.contract_consideration
        == revenue.recognized_revenue + revenue.deferred_revenue,
        pass_message="Recognized and deferred revenue reconcile to consideration.",
        fail_message="Revenue schedules do not reconcile to contract consideration.",
    )
    _boolean_gate(
        findings,
        code="revenue.contract_exceptions",
        domain="revenue_recognition",
        passed=revenue.unresolved_contract_exception_count == 0,
        pass_message="No unresolved revenue-contract exceptions remain.",
        fail_message="Revenue-contract exceptions remain unresolved.",
    )

    assets = parsed.fixed_assets
    _boolean_gate(
        findings,
        code="fixed_assets.register_and_depreciation",
        domain="fixed_assets",
        passed=assets.tagged_asset_count == assets.asset_register_count
        and assets.depreciation_completed_count == assets.depreciation_due_count,
        pass_message="Asset register coverage and depreciation are complete.",
        fail_message="Asset tagging or depreciation is incomplete.",
    )
    _boolean_gate(
        findings,
        code="fixed_assets.subledger_reconciliation",
        domain="fixed_assets",
        passed=abs(assets.subledger_gl_difference)
        <= parsed.policy.maximum_subledger_gl_difference,
        pass_message="Fixed-asset subledger reconciles within policy tolerance.",
        fail_message="Fixed-asset subledger difference exceeds policy tolerance.",
    )
    _boolean_gate(
        findings,
        code="fixed_assets.review_and_disposal",
        domain="fixed_assets",
        passed=assets.overdue_impairment_review_count == 0
        and assets.disposal_pending_approval_count == 0,
        pass_message="Impairment reviews and disposal approvals are current.",
        fail_message="Asset impairment reviews or disposal approvals remain open.",
    )

    controls = parsed.financial_controls
    _boolean_gate(
        findings,
        code="financial_controls.test_coverage",
        domain="financial_controls",
        passed=controls.tested_control_count == controls.key_control_count,
        pass_message="All key financial controls were tested.",
        fail_message="Key financial-control testing is incomplete.",
    )
    _boolean_gate(
        findings,
        code="financial_controls.deficiencies_and_sod",
        domain="financial_controls",
        passed=controls.failed_control_count == 0
        and controls.overdue_remediation_count == 0
        and controls.segregation_conflict_count == 0,
        pass_message="No failed controls, overdue remediation, or segregation conflicts remain.",
        fail_message="Financial-control deficiencies or segregation conflicts remain.",
    )
    _boolean_gate(
        findings,
        code="financial_controls.audit_evidence",
        domain="financial_controls",
        passed=controls.fulfilled_audit_request_count == controls.audit_request_count
        and controls.evidence_trace_complete,
        pass_message="Audit requests and evidence trace are complete.",
        fail_message="Audit requests or evidence trace are incomplete.",
    )

    passed_count = sum(finding.status == "pass" for finding in findings)
    failed_count = sum(finding.status == "fail" for finding in findings)
    indeterminate_count = sum(finding.status == "indeterminate" for finding in findings)
    disposition: FinanceOperatingDisposition = (
        "blocked"
        if failed_count
        else "indeterminate"
        if indeterminate_count
        else "ready"
    )
    input_digest = _stable_digest(parsed.to_dict())
    evidence_digest = _stable_digest(
        [
            evidence.to_dict()
            for evidence in sorted(
                parsed.evidence_refs, key=lambda item: item.evidence_ref
            )
        ]
    )
    return FinanceOperatingControlsResult(
        evaluation_ref=parsed.evaluation_ref,
        company_ref=parsed.company_ref,
        period_ref=parsed.period_ref,
        evaluated_at=parsed.evaluated_at,
        disposition=disposition,
        findings=tuple(findings),
        passed_count=passed_count,
        failed_count=failed_count,
        indeterminate_count=indeterminate_count,
        evidence_refs=tuple(
            sorted(parsed.evidence_refs, key=lambda item: item.evidence_ref)
        ),
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        operation_spec=FINANCE_OPERATING_CONTROLS_OPERATION,
    )


def _example_inputs() -> dict[str, Any]:
    evidence = []
    for index, kind in enumerate(_REQUIRED_EVIDENCE_KINDS, start=1):
        evidence.append(
            {
                "schema": "lightbulb.primitive_evidence_ref.v1",
                "evidence_ref": f"evidence-{kind}",
                "kind": kind,
                "issuer_ref": "spring-finance-authority",
                "sha256": f"{index:x}" * 64,
                "observed_at": "2026-08-24T12:00:00Z",
                "verification_grade": "attested",
                "classification": "confidential",
                "retention_policy": "finance-seven-years",
            }
        )
    return {
        "schema": FINANCE_OPERATING_CONTROLS_INPUT_SCHEMA,
        "evaluation_ref": "finance-controls-2026-08",
        "company_ref": "company-401",
        "period_ref": "period-2026-08",
        "currency": "USD",
        "evaluated_at": "2026-08-24T13:00:00Z",
        "planning": {
            "company_ref": "company-401",
            "budget_ref": "budget-2026",
            "budget_status": "approved",
            "forecast_ref": "forecast-2026-08",
            "forecast_as_of": "2026-08-24T12:00:00Z",
            "actuals_as_of": "2026-08-24T12:00:00Z",
            "required_cost_center_refs": ["cc-sales", "cc-operations"],
            "budgeted_cost_center_refs": ["cc-sales", "cc-operations"],
            "unexplained_material_variance_count": 0,
        },
        "treasury": {
            "company_ref": "company-401",
            "position_as_of": "2026-08-24T12:00:00Z",
            "cash_position_complete": True,
            "bank_account_count": 3,
            "reconciled_bank_account_count": 3,
            "cash_forecast_horizon_days": 90,
            "available_liquidity_days": 60,
            "signatory_conflict_count": 0,
        },
        "expense": {
            "company_ref": "company-401",
            "period_ref": "period-2026-08",
            "submitted_report_count": 20,
            "approved_report_count": 18,
            "reimbursed_report_count": 15,
            "missing_receipt_count": 0,
            "duplicate_suspect_count": 0,
            "unreviewed_policy_exception_count": 0,
            "corporate_cards_reconciled": True,
        },
        "payroll": {
            "company_ref": "company-401",
            "pay_run_ref": "payroll-2026-08-2",
            "currency": "USD",
            "status": "approved",
            "employee_count": 100,
            "gross_pay": "100000.0000",
            "net_pay": "70000.0000",
            "employee_tax": "20000.0000",
            "employee_deductions": "10000.0000",
            "funding_confirmed": True,
            "payroll_register_reconciled": True,
            "tax_liability_reconciled": True,
        },
        "tax": {
            "company_ref": "company-401",
            "tax_period_ref": "period-2026-08",
            "jurisdiction_count": 4,
            "assessed_jurisdiction_count": 4,
            "filings_due_count": 3,
            "filings_ready_count": 3,
            "past_due_filing_count": 0,
            "nexus_assessment_current": True,
            "remittance_funding_confirmed": True,
        },
        "revenue_recognition": {
            "company_ref": "company-401",
            "period_ref": "period-2026-08",
            "currency": "USD",
            "contract_count": 10,
            "allocated_contract_count": 10,
            "performance_obligation_count": 14,
            "scheduled_obligation_count": 14,
            "unresolved_contract_exception_count": 0,
            "contract_consideration": "250000.0000",
            "recognized_revenue": "100000.0000",
            "deferred_revenue": "150000.0000",
        },
        "fixed_assets": {
            "company_ref": "company-401",
            "period_ref": "period-2026-08",
            "currency": "USD",
            "asset_register_count": 120,
            "tagged_asset_count": 120,
            "depreciation_due_count": 120,
            "depreciation_completed_count": 120,
            "subledger_gl_difference": "0.0000",
            "overdue_impairment_review_count": 0,
            "disposal_pending_approval_count": 0,
        },
        "financial_controls": {
            "company_ref": "company-401",
            "control_period_ref": "period-2026-08",
            "key_control_count": 25,
            "tested_control_count": 25,
            "failed_control_count": 0,
            "overdue_remediation_count": 0,
            "segregation_conflict_count": 0,
            "audit_request_count": 5,
            "fulfilled_audit_request_count": 5,
            "evidence_trace_complete": True,
        },
        "evidence_refs": evidence,
    }


class EvaluateFinanceOperatingControlsPrimitive(
    BusinessProcessPrimitive[
        FinanceOperatingControlsInput,
        FinanceOperatingControlsResult,
    ]
):
    primitive_ref = "finance.evaluate_operating_subledger_controls"
    version = "1.0.0"
    title = "Evaluate finance operating subledger controls"
    description = (
        "Evaluate budgeting, forecast, treasury, expense, payroll, tax, revenue "
        "recognition, fixed-asset, and audit controls without authorizing effects."
    )
    input_model = FinanceOperatingControlsInput
    output_model = FinanceOperatingControlsResult
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
        contract["operation_contract"] = FINANCE_OPERATING_CONTROLS_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "ledger_writes": 0,
            "payments_or_cash_movements": 0,
            "payroll_releases": 0,
            "tax_filings": 0,
            "asset_dispositions": 0,
            "authorization_granted": False,
        }
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: FinanceOperatingControlsInput,
    ) -> PrimitiveExecutionResult[FinanceOperatingControlsResult]:
        del context
        output = evaluate_finance_operating_controls(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=FINANCE_OPERATING_CONTROLS_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.input_digest,
            external_refs={"evaluation_digest": output.evaluation_digest},
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"Finance operating controls evaluated: {output.disposition}.",
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.operating_controls_evaluated",
                    payload={
                        "disposition": output.disposition,
                        "evaluation_digest": output.evaluation_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_operating_control_evaluation",
                    summary="Finance operating controls evaluated without a system-of-record mutation.",
                    labels=[
                        output.disposition,
                        "read_only",
                        "spring_authority_required",
                    ],
                    refs={
                        "input_digest": output.input_digest,
                        "evidence_digest": output.evidence_digest,
                        "evaluation_digest": output.evaluation_digest,
                    },
                )
            ],
            evidence_refs=list(output.evidence_refs),
            operation_receipts=[receipt],
        )


FINANCE_OPERATING_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluateFinanceOperatingControlsPrimitive(),)


__all__ = [
    "EvaluateFinanceOperatingControlsPrimitive",
    "ExpenseControlSnapshot",
    "FINANCE_OPERATING_CONTROLS_INPUT_SCHEMA",
    "FINANCE_OPERATING_CONTROLS_OPERATION",
    "FINANCE_OPERATING_CONTROLS_RESULT_SCHEMA",
    "FINANCE_OPERATING_EXECUTABLE_PRIMITIVES",
    "FinanceOperatingControlsInput",
    "FinanceOperatingControlsResult",
    "FinanceOperatingDisposition",
    "FinanceOperatingDomain",
    "FinanceOperatingFinding",
    "FinanceOperatingPolicy",
    "FinanceOperatingStatus",
    "FinancialControlSnapshot",
    "FixedAssetControlSnapshot",
    "PayrollControlSnapshot",
    "PlanningControlSnapshot",
    "RevenueRecognitionControlSnapshot",
    "TaxControlSnapshot",
    "TreasuryControlSnapshot",
    "evaluate_finance_operating_controls",
]
