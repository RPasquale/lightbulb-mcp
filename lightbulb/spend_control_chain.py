"""Observed card costs and recurring vendor commitments, with replayable controls.

Charge, receipt, policy and bill facts retain their provenance-bound provider
pages. Coding retains sealed account and cost-centre maps. Money decisions
consume exact authority proofs; posting consumes a bound write and readback;
clearing consumes replayed bank and finance-close states. Agreement clocks are
replayed through obligation_paper. The SDK never reads providers or sends money.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec,
    OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached,
    parsed, require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance

SPEND_CONTROL_KIND = "spend_control_chain"
SPEND_CONTROL_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
SPEND_STATUSES = ("captured", "receipted", "coded", "approved", "posted", "cleared", "policy_exception", "rejected", "reconciliation_required")
SPEND_EVENTS = ("capture", "attach_receipt", "code", "approve", "post", "clear", "flag_policy_exception", "resolve_exception", "reject", "require_reconciliation")
COMMITMENT_STATUSES = ("observed", "attributed", "active", "assurance_due", "renewal_due", "decision_pending", "renewed", "renegotiated", "terminated", "suspended", "reconciliation_required")
COMMITMENT_EVENTS = ("observe_charge", "attribute_centre", "confirm_recurring", "flag_assurance", "refresh_assurance", "suspend", "flag_renewal", "decide", "renew", "renegotiate", "terminate", "require_reconciliation")
_SPEND_TABLE = {("new", "capture"): "captured", ("captured", "attach_receipt"): "receipted", ("coded", "approve"): "approved", ("approved", "post"): "posted", ("posted", "clear"): "cleared", ("policy_exception", "resolve_exception"): "coded",
    **{(s, "code"): "coded" for s in ("captured", "receipted")},
    **{(s, "flag_policy_exception"): "policy_exception" for s in ("captured", "receipted", "coded")},
    **{(s, "reject"): "rejected" for s in ("captured", "receipted", "coded", "policy_exception")},
    **{(s, "require_reconciliation"): "reconciliation_required" for s in ("approved", "posted")}}
_COMMITMENT_TABLE = {("new", "observe_charge"): "observed", ("observed", "attribute_centre"): "attributed", ("attributed", "confirm_recurring"): "active", ("active", "flag_assurance"): "assurance_due", ("assurance_due", "refresh_assurance"): "active", ("assurance_due", "suspend"): "suspended", ("suspended", "refresh_assurance"): "active", ("active", "flag_renewal"): "renewal_due", ("renewal_due", "decide"): "decision_pending", ("decision_pending", "renew"): "active", ("decision_pending", "renegotiate"): "active",
    **{(s, "terminate"): "terminated" for s in ("decision_pending", "renewal_due", "active")},
    **{(s, "require_reconciliation"): "reconciliation_required" for s in ("active", "renewal_due", "decision_pending")}}
_CHARGE_TOOLS = ("ramp.list_transactions", "expensify.list_expenses", "ramp.list_reimbursements", "xero.list_expense_claims")
_BILL_TOOLS = ("xero.list_bills", "quickbooks.list_bills", "billcom.list_bills", "xero.list_repeating_invoices", "stripe.list_charges")
_POST_TOOLS = ("xero.create_expense_claim", "xero.create_receipt", "quickbooks.create_journal_entry")
_BODY_KEYS = {"body", "image", "image_body", "image_data", "base64", "document_body", "content", "file_content"}


class SpendControlError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SpendControlError(code, message)


def _safe(value: Any) -> None:
    if isinstance(value, Mapping):
        _require(not (_BODY_KEYS & {str(k).lower() for k in value}), "OBSERVATION_INVALID", "only document metadata and digests are accepted")
        for item in value.values():
            _safe(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _safe(item)


class SpendControlPlan(StrictModel):
    schema_id: Literal["lightbulb.spend_control_plan.v1"] = Field(default="lightbulb.spend_control_plan.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    receipt_threshold: Decimal = Field(default=Decimal("75.00"), validate_default=True)
    receipt_grace_hours: int = Field(default=72, ge=0, le=720)
    category_limits: dict[str, Decimal] = Field(default_factory=dict)
    per_cardholder_limit: Decimal = Field(default=Decimal("500.00"), validate_default=True)
    tax_claimable_categories: tuple[ShortText, ...] = ("software", "professional_fees", "freight", "other")
    prohibited_merchants: tuple[OpaqueRef, ...] = ()
    recurrence_min_charges: int = Field(default=2, ge=2, le=100)
    flag_days_before_renewal: int = Field(default=45, ge=0, le=365)
    notice_days: int = Field(default=30, ge=0, le=365)
    price_increase_tolerance_percent: Decimal = Field(default=Decimal("10.00"), validate_default=True)
    renewal_approval_threshold: Decimal = Field(default=Decimal("1000.00"), validate_default=True)
    require_owner: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("receipt_threshold", "per_cardholder_limit", "price_increase_tolerance_percent", "renewal_approval_threshold", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("category_limits", mode="before")
    @classmethod
    def _limits(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="category_limit") for key, item in dict(value).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        if not skip_digests(info) and self.plan_digest != sealed_digest(SpendControlPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact spend policy")
        return self


def compile_spend_control(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> SpendControlPlan:
    return seal(SpendControlPlan, {"company_ref": company_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class ReadEvidence(StrictModel):
    provenance: ObservationProvenance
    payload: dict[str, Any]

    @model_validator(mode="after")
    def _guard(self) -> Any:
        _safe(self.payload)
        if self.provenance.schema_id != "lightbulb.engine_observation_provenance.v1" or stable_digest(self.payload) != self.provenance.output_digest:
            raise ValueError("provider payload must equal its observation output_digest")
        return self


class AssuranceEvidence(StrictModel):
    source: Literal["operator_supplied_vendor_artifact"] = "operator_supplied_vendor_artifact"
    artifact_ref: OpaqueRef
    sha256: Sha256Digest
    valid_until: str
    standing_source: dict[str, Any] | None = None

    @field_validator("valid_until")
    @classmethod
    def _time(cls, value: str) -> str:
        return timestamp(value, field_name="valid_until")


class SpendReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    entity_scope: dict[str, Any] | None = None
    charge_read: ReadEvidence | None = None
    receipt_read: ReadEvidence | None = None
    policy_read: ReadEvidence | None = None
    bill_reads: tuple[ReadEvidence, ...] = Field(default_factory=tuple, max_length=100)
    account_map: dict[str, Any] | None = None
    cost_centre_map: dict[str, Any] | None = None
    account_ref: OpaqueRef | None = None
    tax_code: OpaqueRef | None = None
    centre_ref: OpaqueRef | None = None
    prior_states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    authorization_proof: dict[str, Any] | None = None
    post_execution: dict[str, Any] | None = None
    post_request: dict[str, Any] | None = None
    post_read: ReadEvidence | None = None
    bank_source: dict[str, Any] | None = None
    close_source: dict[str, Any] | None = None
    agreement_source: dict[str, Any] | None = None
    assurance: AssuranceEvidence | None = None
    owner_ref: OpaqueRef | None = None
    exit_read: ReadEvidence | None = None
    access_execution: dict[str, Any] | None = None
    access_request: dict[str, Any] | None = None


class SpendLedger(StrictModel):
    entity_scope: dict[str, Any] = Field(default_factory=dict)
    transaction_ref: OpaqueRef | None = None
    merchant_ref: OpaqueRef | None = None
    cardholder_ref: OpaqueRef | None = None
    reimbursement: bool = False
    amount: Decimal = Decimal("0.00")
    tax_amount: Decimal = Decimal("0.00")
    currency: CurrencyCode | None = None
    category: ShortText | None = None
    transacted_at: str | None = None
    captured_at: str | None = None
    charge_digest: Sha256Digest | None = None
    receipt_digest: Sha256Digest | None = None
    receipt_total: Decimal | None = None
    centre_ref: OpaqueRef | None = None
    account_ref: OpaqueRef | None = None
    tax_code: OpaqueRef | None = None
    tax_claimable: bool = False
    policy_read: dict[str, Any] | None = None
    account_map: dict[str, Any] | None = None
    cost_centre_map: dict[str, Any] | None = None
    approval_ref: OpaqueRef | None = None
    authorization_proof_digest: Sha256Digest | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    posted_at: str | None = None
    posting_journal_ref: OpaqueRef | None = None
    correlation: OpaqueRef | None = None
    correlation_sha256: Sha256Digest | None = None
    cleared_at: str | None = None
    close_ref: OpaqueRef | None = None
    bank_state_digest: Sha256Digest | None = None
    exception_reason: ShortText | None = None
    outcome: str = "open"

    @field_validator("amount", "tax_amount", "receipt_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("transacted_at", "captured_at", "approved_at", "posted_at", "cleared_at")
    @classmethod
    def _time(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class CommitmentLedger(StrictModel):
    entity_scope: dict[str, Any] = Field(default_factory=dict)
    merchant_ref: OpaqueRef | None = None
    counterparty_ref: OpaqueRef | None = None
    currency: CurrencyCode | None = None
    category: ShortText | None = None
    amount: Decimal = Decimal("0.00")
    centre_ref: OpaqueRef | None = None
    owner_ref: OpaqueRef | None = None
    bill_reads: tuple[dict[str, Any], ...] = ()
    charge_count: int = Field(default=0, ge=0)
    cadence_days: int | None = None
    last_bill: dict[str, Any] | None = None
    next_charge_at: str | None = None
    renews_at: str | None = None
    notice_days: int | None = None
    term_months: int | None = None
    auto_renew: bool = False
    commitment_limit: Decimal = Decimal("0.00")
    uplift_cap_percent: Decimal = Decimal("0.00")
    assurance_minimum: Decimal = Decimal("0.00")
    assurance: dict[str, Any] | None = None
    agreement_source: dict[str, Any] | None = None
    cost_centre_map: dict[str, Any] | None = None
    pending_reads: tuple[dict[str, Any], ...] = ()
    pending_amount: Decimal | None = None
    pending_digest: Sha256Digest | None = None
    authorization_proof_digest: Sha256Digest | None = None
    decision_at: str | None = None
    renewals: int = Field(default=0, ge=0)
    outcome: str = "open"

    @field_validator("amount", "commitment_limit", "uplift_cap_percent", "assurance_minimum", "pending_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("next_charge_at", "renews_at", "decision_at")
    @classmethod
    def _time(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class SpendEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    payment_sent: Literal[False] = False
    journal_posted: Literal[False] = False
    contract_renewed: Literal[False] = False


def _read(provenance: Any, payload: Any, tools: Sequence[str], *, host_only: bool = False) -> ReadEvidence:
    try:
        source = ReadEvidence(provenance=ObservationProvenance.model_validate(detached(provenance)), payload=detached(payload))
        _require(source.provenance.source_tool in tools and (not host_only or source.provenance.lane == "host_read"), "OBSERVATION_INVALID", "observation uses the named tool and admitted read lane")
        if source.provenance.source_tool in ("xero.list_bills", "quickbooks.list_bills"):
            _require(source.provenance.lane in ("governed_read", "observation_read_receipt"), "OBSERVATION_INVALID", "accounting bill pages use their governed read lane")
        return source
    except (ValueError, TypeError) as exc:
        raise SpendControlError("OBSERVATION_INVALID", "expected provenance-bound metadata from the named read") from exc


def _validate_read(source: Any, tools: Sequence[str], *, host_only: bool = False) -> ReadEvidence:
    _require(source is not None, "OBSERVATION_INVALID", "this hop needs its source observation")
    raw = detached(source)
    return _read(raw.get("provenance"), raw.get("payload"), tools, host_only=host_only)


def _rows(source: ReadEvidence) -> list[dict[str, Any]]:
    p = source.payload
    rows = next((p[key] for key in ("transactions", "expenses", "receipts", "policies", "bills", "Bills", "Invoices", "data", "rows", "claims", "entries") if key in p), None)
    if rows is None and "QueryResponse" in p:
        rows = p["QueryResponse"].get("Bill", [])
    _require(isinstance(rows, (list, tuple)) and bool(rows) and all(isinstance(row, Mapping) for row in rows), "OBSERVATION_INVALID", "read page must carry nonempty structured rows")
    return [dict(row) for row in rows]


def _date(value: Any) -> str:
    text = str(value or "")
    return timestamp(text if "T" in text else text + "T00:00:00Z", field_name="observed_date")


def _observed_money(value: Any, *, field_name: str) -> Decimal:
    _require(not isinstance(value, bool) and value is not None, "OBSERVATION_INVALID", "observed money must be a numeric field")
    return decimal_value(str(value), field_name=field_name)


def _alias(kind: str, value: Any) -> str:
    _require(value is not None and str(value) != "", "OBSERVATION_INVALID", f"observed {kind} is required")
    return f"{kind}:{stable_digest(str(value))[:32]}"


def _charge(source: Any) -> dict[str, Any]:
    read = _validate_read(source, _CHARGE_TOOLS, host_only=True)
    rows = _rows(read)
    _require(len(rows) == 1, "OBSERVATION_INVALID", "one spend item binds exactly one observed charge")
    row = rows[0]
    amount = _observed_money(row.get("amount", row.get("total")), field_name="amount")
    tax = _observed_money(row.get("tax_amount", "0"), field_name="tax_amount")
    _require(amount > 0, "OBSERVATION_INVALID", "captured cash out must be positive")
    _require(tax <= amount, "OBSERVATION_INVALID", "reported input tax cannot exceed the charge")
    return {"transaction_ref": _alias("transaction", row.get("id", row.get("transaction_id"))), "merchant_ref": _alias("merchant", row.get("merchant", row.get("merchant_name"))),
            "cardholder_ref": _alias("cardholder", row.get("cardholder", row.get("card"))),
            "amount": str(amount), "tax_amount": str(tax), "currency": str(row.get("currency", "")).upper(), "category": row.get("category", "other"),
            "transacted_at": _date(row.get("transacted_at", row.get("date"))), "charge_digest": read.provenance.output_digest,
            "reimbursement": read.provenance.source_tool in ("ramp.list_reimbursements", "xero.list_expense_claims") or row.get("reimbursement") is True}


def capture_receipt(provenance: Any, payload: Any, *, prior_states: Sequence[Any] = (), source_plans: Mapping[str, Any] | None = None) -> dict[str, Any]:
    source = _read(provenance, payload, _CHARGE_TOOLS, host_only=True)
    _charge(source)
    prior = [{"state": detached(s), "plan": detached((source_plans or {}).get(detached(s).get("plan_digest")))} for s in prior_states]
    return {"charge_read": source.to_dict(), "prior_states": prior, "evidence_refs": [f"charge:{source.provenance.output_digest}"]}


def receipt_match(provenance: Any, payload: Any) -> dict[str, Any]:
    source = _read(provenance, payload, ("ramp.list_receipts",), host_only=True)
    _require(len(_rows(source)) == 1, "RECEIPT_AMOUNT_MISMATCH", "one receipt must match one charge")
    return {"receipt_read": source.to_dict(), "evidence_refs": [f"receipt:{source.provenance.output_digest}"]}


def policy_receipt(provenance: Any, payload: Any) -> dict[str, Any]:
    source = _read(provenance, payload, ("expensify.list_policies",), host_only=True)
    _rows(source)
    return {"policy_read": source.to_dict(), "evidence_refs": [f"policy:{source.provenance.output_digest}"]}


def code_receipt(account_map: Any, cost_centre_map: Any, *, account_ref: str, tax_code: str, centre_ref: str) -> dict[str, Any]:
    from lightbulb.finance_close_observations import AccountMap
    from lightbulb.company_cost_centres import CostCentreMap
    try:
        accounts, centres = AccountMap.model_validate(detached(account_map)), CostCentreMap.model_validate(detached(cost_centre_map))
    except (ValueError, TypeError) as exc:
        raise SpendControlError("ACCOUNT_NOT_IN_MAP", "coding requires sealed account and cost-centre maps") from exc
    _require(accounts.schema_id == "lightbulb.close_account_map.v1" and centres.schema_id == "lightbulb.company_cost_centre_map.v1", "ACCOUNT_NOT_IN_MAP", "coding maps must use their exact artifact schemas")
    _require(account_ref in {ref for item in accounts.mappings for ref in item.account_refs}, "ACCOUNT_NOT_IN_MAP", "account must exist in the sealed map")
    _require(centres.centre(centre_ref) is not None, "CENTRE_UNKNOWN", "centre must exist in the sealed map")
    return {"account_map": accounts.to_dict(), "cost_centre_map": centres.to_dict(), "account_ref": account_ref, "tax_code": tax_code, "centre_ref": centre_ref,
            "evidence_refs": [f"account-map:{accounts.map_digest}", f"cost-map:{centres.plan_digest}"]}


def _binding(source: Mapping[str, Any], spec: Any, code: str) -> tuple[Any, Any]:
    try:
        return spec.bind(source["plan"], source["state"])
    except (ValueError, TypeError, KeyError) as exc:
        raise SpendControlError(code, "source state must replay through its exact retained plan") from exc


def _receipt_required(plan: SpendControlPlan, data: Mapping[str, Any], at: str, *, approve: bool = False) -> None:
    overdue = (parsed(at)-parsed(data["transacted_at"])).total_seconds() > plan.receipt_grace_hours * 3600
    require(Decimal(data["amount"]) < plan.receipt_threshold or bool(data.get("receipt_digest")) or not (overdue or approve), "RECEIPT_MISSING_ABOVE_THRESHOLD", "an above-threshold charge must have its receipt before approval or after the grace period")


def _code(plan: SpendControlPlan, data: dict[str, Any], r: SpendReceipt, *, commitment: bool = False) -> None:
    from lightbulb.company_cost_centres import CostCentreMap
    require(r.cost_centre_map is not None and r.centre_ref is not None, "CENTRE_UNKNOWN" if commitment else "MERCHANT_UNATTRIBUTED", "attribution requires the sealed cost-centre map")
    centres = CostCentreMap.model_validate(r.cost_centre_map)
    require(centres.company_ref == plan.company_ref and centres.currency == plan.currency and centres.centre(r.centre_ref) is not None, "CENTRE_UNKNOWN", "cost centre belongs to the company and currency")
    require(centres.merchant_centre(data["merchant_ref"]) == r.centre_ref, "MERCHANT_UNATTRIBUTED", "the merchant must be explicitly attributed to this centre")
    data.update(centre_ref=r.centre_ref, cost_centre_map=centres.to_dict())
    if not commitment:
        require(r.account_map is not None and r.account_ref is not None and r.tax_code is not None, "ACCOUNT_NOT_IN_MAP", "coding requires an account and tax-code selection")
        code_receipt(r.account_map, centres, account_ref=r.account_ref, tax_code=r.tax_code, centre_ref=r.centre_ref)
        data.update(account_ref=r.account_ref, account_map=r.account_map, tax_code=r.tax_code, tax_claimable=data["category"] in plan.tax_claimable_categories)


def _policy(plan: SpendControlPlan, data: Mapping[str, Any], source: Any, at: str) -> dict[str, Any]:
    read = _validate_read(source, ("expensify.list_policies",), host_only=True)
    require(parsed(read.provenance.completed_at) <= parsed(at), "POLICY_VIOLATION", "spend policy must have been observed before use", "await_approval")
    matches = [row for row in _rows(read) if row.get("category") in (data["category"], "*")]
    require(len(matches) == 1, "POLICY_VIOLATION", "one observed policy must govern this expense category", "await_approval")
    row = matches[0]
    limit = decimal_value(row.get("limit"), field_name="observed_limit")
    require(row.get("currency") == plan.currency and parsed(_date(row.get("valid_until"))) > parsed(at) and row.get("allowed", True) is True and Decimal(data["amount"]) <= min(limit, plan.category_limits.get(data["category"], limit)), "POLICY_VIOLATION", "charge exceeds its current read policy or stricter plan ceiling", "await_approval")
    require(Decimal(data["amount"]) <= min(decimal_value(row.get("cardholder_limit", plan.per_cardholder_limit), field_name="cardholder_limit"), plan.per_cardholder_limit), "AMOUNT_ABOVE_CARDHOLDER_LIMIT", "charge exceeds the cardholder ceiling", "await_approval")
    return read.to_dict()


def _post_request(plan: Any, data: Mapping[str, Any], state_digest: str) -> Any:
    from lightbulb.connector_execution import ConnectorExecutionRequest
    scope = data["entity_scope"]
    tool = "quickbooks.create_journal_entry" if (data.get("account_map") or {}).get("ledger") == "quickbooks" else "xero.create_expense_claim"
    return ConnectorExecutionRequest(tool=tool, effect="write", approval_required=True, approval_ref=data.get("approval_ref"), preview_only=not bool(data.get("approval_ref")), idempotency_key=f"spend:{data['transaction_ref']}",
        scope={k: scope[k] for k in ("tenant_ref", "company_ref", "project_ref", "project_id")},
        arguments={"spend_ref": scope["entity_ref"], "transaction_ref": data["transaction_ref"], "plan_digest": plan.plan_digest, "state_digest": state_digest,
            "amount": str(data["amount"]), "tax_amount": str(data["tax_amount"]), "currency": plan.currency, "account_ref": data.get("account_ref"), "tax_code": data.get("tax_code"), "correlation": data["correlation"]})


def post_request(state: Any, *, source_plan: Any) -> Any:
    plan, item = _binding({"state": state, "plan": source_plan}, SPEND_LIFECYCLE, "POST_NOT_PROVEN")
    _require(item.status in ("coded", "approved"), "POST_NOT_PROVEN", "only coded or approved expenses produce posting requests")
    return _post_request(plan, item.ledger.to_dict(), item.state_digest)


def post_receipt(execution_receipt: Any, *, request: Any, provenance: Any, payload: Any) -> dict[str, Any]:
    from lightbulb.connector_execution import ConnectorExecutionRequest
    try:
        execution = ExecutionReceipt.model_validate(detached(execution_receipt))
        call = ConnectorExecutionRequest.model_validate(detached(request))
        _require(execution.schema_id == "lightbulb.engine_execution_receipt.v1" and execution.effect == "write" and execution.tool in _POST_TOOLS and execution.tool == call.tool and execution.request_digest == call.custody_fingerprint() and call.approval_required and not call.preview_only and call.approval_ref == execution.approval_ref, "POST_NOT_PROVEN", "posting requires an approved write bound to the exact request")
        read = _read(provenance, payload, ("xero.list_expense_claims", "quickbooks.get_journal_entry"))
        _require(read.provenance.lane in ("governed_read", "observation_read_receipt") and parsed(read.provenance.completed_at) >= parsed(execution.completed_at), "POST_NOT_PROVEN", "readback must be a governed read after the write")
        rows = _rows(read)
        _require(len(rows) == 1 and rows[0].get("correlation") == call.arguments.get("correlation") and decimal_value(rows[0].get("amount"), field_name="readback_amount") == decimal_value(call.arguments.get("amount"), field_name="posted_amount") and rows[0].get("currency") == call.arguments.get("currency") and rows[0].get("account_ref") == call.arguments.get("account_ref") and rows[0].get("status") in ("posted", "approved", "paid"), "POST_NOT_PROVEN", "readback must prove the exact expense amount, currency, account and correlation")
        _require(_observed_money(rows[0].get("tax_amount", "0"), field_name="readback_tax") == decimal_value(call.arguments.get("tax_amount", "0"), field_name="posted_tax"), "POST_NOT_PROVEN", "readback must retain the observed input tax")
    except (ValueError, TypeError) as exc:
        raise SpendControlError("POST_NOT_PROVEN", "posting needs exact execution and readback evidence") from exc
    return {"post_execution": execution.to_dict(), "post_request": detached(call), "post_read": read.to_dict(), "evidence_refs": [f"post:{execution.execution_digest}"]}


def clear_receipt(bank_match: Any, close_state: Any, *, bank_plan: Any, close_plan: Any) -> dict[str, Any]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
    _, bank = _binding({"state": bank_match, "plan": bank_plan}, BANK_REC_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
    _, close = _binding({"state": close_state, "plan": close_plan}, CLOSE_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
    return {"bank_source": {"state": bank.to_dict(), "plan": detached(bank_plan)}, "close_source": {"state": close.to_dict(), "plan": detached(close_plan)}, "evidence_refs": [f"bank:{bank.state_digest}", f"close:{close.state_digest}"]}


def _apply_spend(plan: SpendControlPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    from lightbulb.authority_matrix import require_authorization_proof
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "capture":
        require(r.entity_scope is not None, "OBSERVATION_INVALID", "capture through the scoped lifecycle wrapper")
        scope = EngineScope.model_validate(r.entity_scope)
        require(command.expected_state_digest == SPEND_LIFECYCLE.state_digest(plan.plan_digest, scope, ()), "OBSERVATION_INVALID", "captured scope must equal lifecycle scope")
        charge = _charge(r.charge_read)
        require(charge["currency"] == plan.currency == scope.currency and parsed(charge["transacted_at"]) <= parsed(at) and parsed(r.charge_read.provenance.completed_at) <= parsed(at), "OBSERVATION_INVALID", "charge currency and evidence time must match this capture")
        require(charge["merchant_ref"] not in plan.prohibited_merchants, "MERCHANT_PROHIBITED", "merchant is prohibited by the spend plan", "manual_reconciliation")
        for prior in r.prior_states:
            _, item = _binding(prior, SPEND_LIFECYCLE, "DUPLICATE_TRANSACTION")
            require(item.scope.tenant_ref == scope.tenant_ref and item.scope.company_ref == scope.company_ref, "OBSERVATION_INVALID", "duplicate history must belong to this company")
            require(item.ledger.transaction_ref != charge["transaction_ref"], "DUPLICATE_TRANSACTION", "this observed transaction has already been captured", "do_not_replay")
        correlation = f"LB-CARD-{charge['transaction_ref'].split(':')[1]}"
        data.update(charge, entity_scope=scope.to_dict(), captured_at=at, correlation=correlation, correlation_sha256=hashlib.sha256(correlation.encode()).hexdigest())
    elif event == "attach_receipt":
        source = _validate_read(r.receipt_read, ("ramp.list_receipts",), host_only=True)
        rows = _rows(source)
        require(len(rows) == 1, "RECEIPT_AMOUNT_MISMATCH", "receipt must uniquely match this transaction")
        row = rows[0]
        require(_alias("transaction", row.get("transaction_id")) == data["transaction_ref"] and decimal_value(row.get("total"), field_name="receipt_total") == Decimal(data["amount"]), "RECEIPT_AMOUNT_MISMATCH", "receipt must match exact charge reference and total")
        digest = row.get("sha256", row.get("digest"))
        require(isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest) and parsed(source.provenance.completed_at) <= parsed(at), "RECEIPT_AMOUNT_MISMATCH", "receipt requires document digest and observed metadata")
        data.update(receipt_digest=digest, receipt_total=data["amount"])
    elif event in ("code", "resolve_exception"):
        _receipt_required(plan, data, at)
        _code(plan, data, r)
        data["policy_read"] = _policy(plan, data, r.policy_read, at)
        data["outcome"] = "open"
    elif event == "approve":
        _receipt_required(plan, data, at, approve=True)
        _policy(plan, data, data.get("policy_read"), at)
        proof = require_authorization_proof(r.authorization_proof, category="payable", amount=data["amount"], currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_scope"]["entity_ref"])
        require(proof.approver_ref != data["cardholder_ref"], "REIMBURSEMENT_TO_APPROVER", "a cardholder cannot approve their charge or reimbursement", "manual_reconciliation")
        data.update(approval_ref=proof.approval_task_id, authorization_proof_digest=proof.proof_digest, approver_ref=proof.approver_ref, approved_at=proof.decided_at)
    elif event == "post":
        require(r.post_execution is not None and r.post_request is not None and r.post_read is not None, "POST_NOT_PROVEN", "posting requires its bound execution and governed readback")
        post_receipt(r.post_execution, request=r.post_request, provenance=r.post_read.provenance, payload=r.post_read.payload)
        execution = ExecutionReceipt.model_validate(r.post_execution)
        expected = _post_request(plan, data, command.expected_state_digest)
        require(all(str(r.post_request["scope"].get(key)) == str(data["entity_scope"][key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "POST_NOT_PROVEN", "posting request must use this spend item's exact scope")
        require(execution.request_digest == expected.custody_fingerprint() and execution.approval_ref == data["approval_ref"] and execution.project_id == data["entity_scope"]["project_id"] and parsed(data["approved_at"]) <= parsed(execution.completed_at) <= parsed(r.post_read.provenance.completed_at) <= parsed(at), "POST_NOT_PROVEN", "posting must bind this approved state, project and observed readback time")
        data.update(posted_at=execution.completed_at, posting_journal_ref=execution.journal_ref)
    elif event == "clear":
        from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
        from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
        require(r.bank_source is not None and r.close_source is not None, "CLEARED_WITHOUT_STATEMENT_MATCH", "clearing requires the statement match and covering close", "manual_reconciliation")
        bp, bank = _binding(r.bank_source, BANK_REC_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
        _, close = _binding(r.close_source, CLOSE_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
        scope = data["entity_scope"]
        matches = [m for m in bank.ledger.matches if m.counterpart_kind == SPEND_CONTROL_KIND and m.counterpart_state_digest == command.expected_state_digest and m.amount == -Decimal(data["amount"])]
        require(len(matches) == 1 and bp.company_ref == plan.company_ref and all(s.scope.company_ref == scope["company_ref"] and s.scope.tenant_ref == scope["tenant_ref"] and s.scope.currency == plan.currency for s in (bank, close)), "CLEARED_WITHOUT_STATEMENT_MATCH", "statement must settle this exact expense under the same tenant, company and currency", "manual_reconciliation")
        lines = [line for line in bank.ledger.lines if line.line_ref in matches[0].line_refs]
        cleared_at = max((line.occurred_at for line in lines), default="")
        require(bool(cleared_at) and all(line.reference == data["correlation"] for line in lines) and parsed(data["transacted_at"]) <= parsed(cleared_at) <= parsed(at), "CLEARED_WITHOUT_STATEMENT_MATCH", "bank lines must carry the exact card correlation and valid settlement time", "manual_reconciliation")
        from lightbulb.finance_close_observations import AccountMap
        require(close.status == "closed" and "accounts_payable" in close.ledger.reconciled_accounts and data["account_ref"] in AccountMap.model_validate(data["account_map"]).refs("accounts_payable") and parsed(close.ledger.period_start) <= parsed(cleared_at) <= parsed(close.ledger.period_end) and parsed(close.transition_history[-1].command.occurred_at) <= parsed(at), "CLEARED_WITHOUT_STATEMENT_MATCH", "close must cover the mapped card-clearing liability within accounts payable", "manual_reconciliation")
        data.update(cleared_at=cleared_at, close_ref=close.scope.entity_ref, bank_state_digest=bank.state_digest, outcome="cleared")
    elif event == "flag_policy_exception":
        data.update(exception_reason=command.reason, outcome="exception")
    elif event in ("reject", "require_reconciliation"):
        data["outcome"] = next_status
    return next_status, data


def recurrence_receipt(bill_pages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Each page carries ``provenance`` and the original provider ``payload``."""
    reads = [_read(page["provenance"], page["payload"], _BILL_TOOLS) for page in bill_pages]
    for read in reads:
        _rows(read)
    return {"bill_reads": [read.to_dict() for read in reads], "evidence_refs": [f"bills:{read.provenance.output_digest}" for read in reads]}


def _bills(reads: Sequence[Any]) -> list[dict[str, Any]]:
    out = []
    for source in reads:
        read = _validate_read(source, _BILL_TOOLS)
        for row in _rows(read):
            contact = row.get("Contact", row.get("VendorRef", {})) or {}
            vendor = row.get("merchant", row.get("vendor", contact.get("Name", contact.get("name"))))
            amount = _observed_money(row.get("amount", row.get("Total", row.get("TotalAmt"))), field_name="bill_amount")
            _require(amount > 0, "CHARGE_NOT_RECURRING", "recurring bills must carry positive observed charges")
            ref = row.get("id", row.get("InvoiceID", row.get("Id")))
            out.append({"bill_ref": _alias("bill", ref), "merchant_ref": _alias("merchant", vendor), "counterparty_ref": row.get("counterparty_ref"),
                "invoice_number": str(row.get("invoice_number", row.get("InvoiceNumber", row.get("DocNumber", _alias("invoice", ref))))),
                "amount": str(amount), "currency": row.get("currency", row.get("CurrencyCode", (row.get("CurrencyRef") or {}).get("value"))),
                "at": _date(row.get("date", row.get("Date", row.get("TxnDate")))), "due_at": _date(row.get("due_at", row.get("DueDate", row.get("date")))),
                "next_charge_at": _date(row["next_charge_at"]) if row.get("next_charge_at") else None,
                "category": row.get("category", "software"), "observed_at": read.provenance.completed_at})
    _require(bool(out), "CHARGE_NOT_RECURRING", "recurrence requires observed bills")
    _require(len({row["bill_ref"] for row in out}) == len(out), "DUPLICATE_TRANSACTION", "bill pages cannot repeat a charge")
    return sorted(out, key=lambda row: (row["at"], row["bill_ref"]))


def agreement_terms_receipt(executed_agreement_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.obligation_paper import AGREEMENT_LIFECYCLE
    _, state = _binding({"state": executed_agreement_state, "plan": source_plan}, AGREEMENT_LIFECYCLE, "CHARGE_NOT_RECURRING")
    _require(state.status in ("in_force", "notice_window", "notice_given"), "CHARGE_NOT_RECURRING", "recurrence terms require an in-force agreement")
    return {"agreement_source": {"state": state.to_dict(), "plan": detached(source_plan)}, "evidence_refs": [f"agreement:{state.state_digest}"]}


def assurance_receipt(artifact_ref: str, sha256: str, valid_until: str, *, standing_state: Any = None, source_plan: Any = None) -> dict[str, Any]:
    evidence = AssuranceEvidence(artifact_ref=artifact_ref, sha256=sha256, valid_until=valid_until, standing_source={"state": detached(standing_state), "plan": detached(source_plan)} if standing_state is not None else None)
    return {"assurance": evidence.to_dict(), "evidence_refs": [f"assurance:{sha256}"]}


def _assurance(plan: SpendControlPlan, data: Mapping[str, Any], source: Any, at: str) -> dict[str, Any]:
    require(source is not None, "ASSURANCE_EXPIRED", "vendor assurance is required", "manual_reconciliation")
    evidence = AssuranceEvidence.model_validate(detached(source))
    require(parsed(evidence.valid_until) > parsed(at), "ASSURANCE_EXPIRED", "vendor assurance has expired", "manual_reconciliation")
    minimum = Decimal(data.get("assurance_minimum", "0"))
    if minimum > 0:
        require(evidence.standing_source is not None, "ASSURANCE_BELOW_CONTRACTED_MINIMUM", "contracted insurance needs its replayed paid-cover state", "await_approval")
        from lightbulb.obligation_paper import verify_cover_current
        try:
            standing = evidence.standing_source
            cover = verify_cover_current(standing["state"], source_plan=standing["plan"], company_ref=plan.company_ref, currency=plan.currency, at=at, required_limit=minimum, expected_scope=data["entity_scope"])
            require(evidence.sha256 == cover.ledger.document_sha256 and parsed(evidence.valid_until) <= parsed(cover.ledger.period_end), "ASSURANCE_BELOW_CONTRACTED_MINIMUM", "assurance document and expiry must agree with the retained paid cover", "await_approval")
        except ValueError as exc:
            require(False, "ASSURANCE_BELOW_CONTRACTED_MINIMUM", f"contracted vendor assurance is unproven: {exc}"[:300], "await_approval")
    return evidence.to_dict()


def _recurrence(plan: SpendControlPlan, rows: Sequence[Mapping[str, Any]], data: Mapping[str, Any], at: str) -> None:
    require(len(rows) >= plan.recurrence_min_charges, "CHARGE_NOT_RECURRING", "a one-off charge cannot establish a recurring commitment")
    require(all(row["merchant_ref"] == data["merchant_ref"] and row.get("counterparty_ref") == data.get("counterparty_ref") and row["currency"] == plan.currency and parsed(row["at"]) <= parsed(row["observed_at"]) <= parsed(at) for row in rows), "CHARGE_NOT_RECURRING", "all recurring charges must belong to the same vendor, currency and observation window")
    intervals = [(parsed(b["at"])-parsed(a["at"])).days for a, b in zip(rows, rows[1:])]
    require(all(0 < days <= 366 for days in intervals) and max(intervals)-min(intervals) <= 3, "CHARGE_NOT_RECURRING", "observed charges must follow a consistent cadence")


def _terms(plan: SpendControlPlan, data: dict[str, Any], source: Any, at: str) -> None:
    require(source is not None, "CHARGE_NOT_RECURRING", "recurring commitments require in-force contractual terms")
    from lightbulb.obligation_paper import verify_agreement_in_force
    try:
        agreement = verify_agreement_in_force(source["state"], source_plan=source["plan"], company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data["entity_scope"])
    except (ValueError, KeyError, TypeError) as exc:
        raise SpendControlError("CHARGE_NOT_RECURRING", "agreement terms must replay as in force for this exact company and project") from exc
    terms = agreement.ledger
    require(terms.counterparty_ref == (data.get("counterparty_ref") or data["merchant_ref"]), "CHARGE_NOT_RECURRING", "agreement must bind the vendor alias carried by the observed bill")
    data.update(agreement_source=detached(source), term_months=terms.term_months, auto_renew=terms.auto_renew,
        notice_days=max(terms.notice_days or 0, plan.notice_days), commitment_limit=str(terms.amount),
        uplift_cap_percent=str(min(plan.price_increase_tolerance_percent if terms.uplift_cap_percent is None else terms.uplift_cap_percent, plan.price_increase_tolerance_percent)),
        assurance_minimum=str(max(terms.insurance_minima.values(), default=Decimal(0))), renews_at=terms.expires_at)


def _authority(plan: SpendControlPlan, data: Mapping[str, Any], command: Any, amount: Any) -> Any:
    from lightbulb.authority_matrix import require_authorization_proof
    require(command.receipt.authorization_proof is not None, "RENEWAL_NOT_AUTHORIZED", "commitment decisions require a bound authority proof", "await_approval")
    return require_authorization_proof(command.receipt.authorization_proof, category="commitment", amount=amount, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_scope"]["entity_ref"])


def exit_receipt(provenance: Any, payload: Any, *, access_execution: Any, access_request: Any) -> dict[str, Any]:
    read = _read(provenance, payload, ("host.vendor_exit_evidence",), host_only=True)
    execution = ExecutionReceipt.model_validate(detached(access_execution))
    return {"exit_read": read.to_dict(), "access_execution": execution.to_dict(), "access_request": detached(access_request), "evidence_refs": [f"exit:{read.provenance.output_digest}"]}


def _apply_commitment(plan: SpendControlPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "observe_charge":
        require(r.entity_scope is not None, "OBSERVATION_INVALID", "open through the scoped commitment wrapper")
        scope = EngineScope.model_validate(r.entity_scope)
        require(command.expected_state_digest == COMMITMENT_LIFECYCLE.state_digest(plan.plan_digest, scope, ()), "OBSERVATION_INVALID", "commitment scope must equal lifecycle scope")
        rows = _bills(r.bill_reads)
        require(all(row["currency"] == plan.currency == scope.currency and row["merchant_ref"] == rows[0]["merchant_ref"] and parsed(row["observed_at"]) <= parsed(at) for row in rows), "CHARGE_NOT_RECURRING", "observed bills must identify one vendor in this currency")
        data.update(entity_scope=scope.to_dict(), merchant_ref=rows[-1]["merchant_ref"], counterparty_ref=rows[-1]["counterparty_ref"], currency=plan.currency, category=rows[-1]["category"], amount=rows[-1]["amount"], last_bill=rows[-1], bill_reads=list(detached(r.bill_reads)), charge_count=len(rows), next_charge_at=rows[-1]["next_charge_at"])
    elif event == "attribute_centre":
        _code(plan, data, r, commitment=True)
        require(not plan.require_owner or r.owner_ref is not None, "OWNER_MISSING", "recurring vendor spend needs an accountable owner")
        data["owner_ref"] = r.owner_ref
    elif event == "confirm_recurring":
        rows = _bills(data["bill_reads"])
        _recurrence(plan, rows, data, at)
        _terms(plan, data, r.agreement_source, at)
        require(Decimal(data["amount"]) <= Decimal(data["commitment_limit"]), "SPEND_ABOVE_COMMITMENT", "observed charge exceeds the agreed commitment", "await_approval")
        data["assurance"] = _assurance(plan, data, r.assurance, at)
        proof = _authority(plan, data, command, data["amount"])
        data.update(authorization_proof_digest=proof.proof_digest, cadence_days=(parsed(rows[-1]["at"])-parsed(rows[-2]["at"])).days)
    elif event == "flag_assurance":
        require(data.get("assurance") is None or parsed(data["assurance"]["valid_until"]) <= parsed(at), "ASSURANCE_EXPIRED", "assurance flag requires expired vendor evidence", "manual_reconciliation")
    elif event == "refresh_assurance":
        data["assurance"] = _assurance(plan, data, r.assurance, at)
        data["outcome"] = "open"
    elif event == "suspend":
        data["outcome"] = "suspended"
    elif event == "flag_renewal":
        require(parsed(at) >= parsed(data["renews_at"])-timedelta(days=max(plan.flag_days_before_renewal, data["notice_days"])), "NOTICE_WINDOW_MISSED", "the commitment has not entered its configured or contractual renewal window", "manual_reconciliation")
    elif event == "decide":
        require(parsed(at) <= parsed(data["renews_at"])-timedelta(days=data["notice_days"]), "NOTICE_WINDOW_MISSED", "the contractual notice deadline has already passed", "manual_reconciliation")
        _terms(plan, data, r.agreement_source or data.get("agreement_source"), at)
        _assurance(plan, data, data.get("assurance"), at)
        reads = list(detached(r.bill_reads)) or data["bill_reads"]
        rows = _bills(reads)
        _recurrence(plan, rows, data, at)
        amount = Decimal(rows[-1]["amount"])
        uplift = (amount-Decimal(data["amount"]))*100/Decimal(data["amount"])
        require(uplift <= Decimal(data["uplift_cap_percent"]), "PRICE_UPLIFT_ABOVE_CAP", "renewal price exceeds the contracted or plan uplift cap", "await_approval")
        require(amount <= Decimal(data["commitment_limit"]), "SPEND_ABOVE_COMMITMENT", "renewal charge exceeds the agreed commitment", "await_approval")
        proof = _authority(plan, data, command, amount)
        data.update(pending_reads=reads, pending_digest=stable_digest(reads), pending_amount=str(amount), authorization_proof_digest=proof.proof_digest, decision_at=at)
    elif event in ("renew", "renegotiate"):
        _terms(plan, data, r.agreement_source or data.get("agreement_source"), at)
        _assurance(plan, data, data.get("assurance"), at)
        reads = list(detached(r.bill_reads)) or data.get("pending_reads", [])
        require(stable_digest(reads) == data.get("pending_digest"), "RENEWAL_NOT_AUTHORIZED", "renewal must use the exact observed bills authorized by the decision", "await_approval")
        rows = _bills(reads)
        if Decimal(data["pending_amount"]) >= plan.renewal_approval_threshold or r.authorization_proof is not None:
            _authority(plan, data, command, data["pending_amount"])
        require(rows[-1]["next_charge_at"] is not None and parsed(rows[-1]["next_charge_at"]) > parsed(data["renews_at"]), "CHARGE_NOT_RECURRING", "renewal needs the provider's explicit next charge date; the SDK cannot invent one")
        data.update(amount=data["pending_amount"], bill_reads=reads, last_bill=rows[-1], next_charge_at=rows[-1]["next_charge_at"], renews_at=rows[-1]["next_charge_at"], renewals=data.get("renewals", 0)+1, outcome="renewed" if event == "renew" else "renegotiated")
    elif event == "terminate":
        require(r.exit_read is not None and r.access_execution is not None and r.access_request is not None, "TERMINATION_WITHOUT_EXIT_EVIDENCE", "exit requires deletion evidence, final invoice and executed access revocation")
        read = _validate_read(r.exit_read, ("host.vendor_exit_evidence",), host_only=True)
        payload = read.payload
        execution = ExecutionReceipt.model_validate(r.access_execution)
        from lightbulb.connector_execution import ConnectorExecutionRequest
        call = ConnectorExecutionRequest.model_validate(r.access_request)
        digest = payload.get("deletion_certificate_digest")
        output = payload.get("access_output") or {}
        require(payload.get("schema") == "lightbulb.vendor_exit_evidence.v1" and payload.get("merchant_ref") == data["merchant_ref"] and isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest) and bool(payload.get("final_invoice_ref")) and execution.effect == "write" and execution.request_digest == call.custody_fingerprint() and call.arguments.get("merchant_ref") == data["merchant_ref"] and call.arguments.get("access_revoked") is True and execution.tool == call.tool and call.approval_required and not call.preview_only and call.approval_ref == execution.approval_ref and output.get("merchant_ref") == data["merchant_ref"] and output.get("access_revoked") is True and stable_digest(output) == execution.output_digest and parsed(execution.completed_at) <= parsed(read.provenance.completed_at) <= parsed(at), "TERMINATION_WITHOUT_EXIT_EVIDENCE", "offboarding evidence must bind this vendor, deleted data, final invoice and the executed access-revocation result")
        require(execution.project_id == data["entity_scope"]["project_id"] and all(str(getattr(call.scope,key)) == str(data["entity_scope"][key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "TERMINATION_WITHOUT_EXIT_EVIDENCE", "vendor exit belongs to this tenant, company and project")
        data["outcome"] = "terminated"
    elif event == "require_reconciliation":
        data["outcome"] = "reconciliation_required"
    return next_status, data


def _guarded(apply: Any) -> Any:
    def run(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
        try:
            return apply(plan, next_status, status, data, command)
        except SpendControlError as exc:
            recovery = "do_not_replay" if exc.code == "DUPLICATE_TRANSACTION" else "manual_reconciliation" if exc.code in ("CLEARED_WITHOUT_STATEMENT_MATCH", "ASSURANCE_EXPIRED") else "correct_input"
            require(False, exc.code, exc.message, recovery)
            raise AssertionError("unreachable")
    return run


SPEND_LIFECYCLE = LifecycleSpec(entity="spend_item", schema_prefix="spend_item", statuses=SPEND_STATUSES, terminal=("cleared", "rejected", "reconciliation_required"), events=SPEND_EVENTS, table=_SPEND_TABLE, opening_event="capture", reason_events=("flag_policy_exception", "reject", "require_reconciliation"), apply=_guarded(_apply_spend), ledger_model=SpendLedger, receipt_model=SpendReceipt, effect_boundary_model=SpendEffectBoundary, plan_model=SpendControlPlan, max_transitions=12)
SPEND_CHAIN_LIFECYCLE = SPEND_LIFECYCLE
COMMITMENT_LIFECYCLE = LifecycleSpec(entity="vendor_commitment", schema_prefix="vendor_commitment", statuses=COMMITMENT_STATUSES, terminal=("terminated", "reconciliation_required"), events=COMMITMENT_EVENTS, table=_COMMITMENT_TABLE, opening_event="observe_charge", reason_events=("suspend", "terminate", "require_reconciliation"), apply=_guarded(_apply_commitment), ledger_model=CommitmentLedger, receipt_model=SpendReceipt, effect_boundary_model=SpendEffectBoundary, plan_model=SpendControlPlan, max_transitions=24)
SpendItemState = SPEND_LIFECYCLE.State
VendorCommitmentState = COMMITMENT_LIFECYCLE.State


def open_spend_item(plan: Any, scope: Any, *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return SPEND_LIFECYCLE.open(plan, scope, receipt={**receipt, "entity_scope": detached(scope)}, opened_at=opened_at, actor_ref=actor_ref)


def advance_spend_item(plan: Any, state: Any, command: Any) -> Any:
    return SPEND_LIFECYCLE.advance(plan, state, command)


def open_vendor_commitment(plan: Any, scope: Any, *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return COMMITMENT_LIFECYCLE.open(plan, scope, receipt={**receipt, "entity_scope": detached(scope)}, opened_at=opened_at, actor_ref=actor_ref)


def advance_vendor_commitment(plan: Any, state: Any, command: Any) -> Any:
    return COMMITMENT_LIFECYCLE.advance(plan, state, command)


def renewal_bill_receipt(commitment_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """Project the actual observed renewal bill, retaining its commitment and read."""
    plan, state = _binding({"state": commitment_state, "plan": source_plan}, COMMITMENT_LIFECYCLE, "RENEWAL_NOT_AUTHORIZED")
    _require(state.status == "active" and state.ledger.renewals > 0, "RENEWAL_NOT_AUTHORIZED", "only a completed renewal can create its observed bill case")
    row = _bills(state.ledger.bill_reads)[-1]
    _require(row == state.ledger.last_bill and Decimal(row["amount"]) == state.ledger.amount, "RENEWAL_NOT_AUTHORIZED", "the payable must equal the exact observed bill approved by the renewal")
    sources = [read for read in state.ledger.bill_reads if any(item["bill_ref"] == row["bill_ref"] for item in _bills([read]))]
    _require(len(sources) == 1, "RENEWAL_NOT_AUTHORIZED", "retain the unique original provider page containing this renewal bill")
    read = _validate_read(sources[0], ("xero.list_bills", "quickbooks.list_bills", "billcom.list_bills"))
    _require(parsed(row["at"]) <= parsed(row["due_at"]), "RENEWAL_NOT_AUTHORIZED", "the observed bill cannot fall due before its issue date")
    centre = next(item for item in state.ledger.cost_centre_map["centres"] if item["centre_ref"] == state.ledger.centre_ref)
    return {"commitment_source": {"state": state.to_dict(), "source_plan": plan.to_dict()},
            "intake_source": detached(read.payload), "source_provenance": read.provenance.to_dict(),
            "supplier_ref": row.get("counterparty_ref") or state.ledger.merchant_ref, "bill_ref": row["bill_ref"], "invoice_number": row["invoice_number"],
            "amount": row["amount"], "currency": row["currency"], "due_at": row["due_at"], "engine": centre.get("engine"),
            "intake_digest": read.provenance.output_digest,
            "correlation_sha256": stable_digest({"scope": state.scope.to_dict(), "bill": row["bill_ref"]}),
            "evidence_refs": [f"commitment:{state.state_digest}", f"bills:{read.provenance.output_digest}"]}


def fixed_cost_flows(commitment_states: Sequence[Any], *, source_plans: Mapping[str, Any]) -> tuple[Any, ...]:
    from lightbulb.company_treasury import ScheduledFlow
    out, seen, expected_scope = [], set(), None
    for source in commitment_states:
        raw = detached(source)
        plan, state = _binding({"state": source, "plan": source_plans.get(raw.get("plan_digest"))}, COMMITMENT_LIFECYCLE, "CHARGE_NOT_RECURRING")
        scope = (state.scope.tenant_ref, state.scope.company_ref, plan.company_ref, plan.currency)
        _require(expected_scope is None or expected_scope == scope, "CHARGE_NOT_RECURRING", "one fixed-cost forecast cannot mix tenant, company or currency")
        expected_scope = scope
        key = (state.scope.tenant_ref, state.scope.company_ref, state.scope.entity_ref)
        _require(key not in seen, "DUPLICATE_TRANSACTION", "one commitment cannot reserve its next charge twice, including older state versions")
        seen.add(key)
        if state.status in ("active", "renewal_due", "decision_pending", "assurance_due"):
            _require(state.ledger.next_charge_at is not None, "CHARGE_NOT_RECURRING", "forecast needs the provider's observed next charge date")
            out.append(ScheduledFlow(kind="fixed_cost", ref=f"commitment:{state.scope.entity_ref}", due_at=state.ledger.next_charge_at, amount=-state.ledger.amount, source=f"commitment:{state.state_digest}"))
    return tuple(out)


def period_spend_receipts(states: Sequence[Any], *, source_plans: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    from lightbulb.company_cost_centres import spend_case_receipt
    out, seen = [], set()
    for source in states:
        raw = detached(source)
        _, item = _binding({"state": source, "plan": source_plans.get(raw.get("plan_digest"))}, SPEND_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
        _require(item.status == "cleared", "CLEARED_WITHOUT_STATEMENT_MATCH", "only statement-cleared expenses enter period cost")
        _require(item.ledger.transaction_ref not in seen, "DUPLICATE_TRANSACTION", "one transaction cannot enter period cost twice")
        seen.add(item.ledger.transaction_ref)
        out.append(spend_case_receipt(item, source_plan=source_plans[item.plan_digest], centre_ref=item.ledger.centre_ref))
    return tuple(out)


def spend_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, item = _binding({"state": state, "plan": source_plan}, SPEND_LIFECYCLE, "OBSERVATION_INVALID")
    return {"spend_ref": item.scope.entity_ref, "status": item.status, "amount": str(item.ledger.amount), "merchant_ref": item.ledger.merchant_ref, "centre_ref": item.ledger.centre_ref, "outcome": item.ledger.outcome}


def commitment_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, item = _binding({"state": state, "plan": source_plan}, COMMITMENT_LIFECYCLE, "CHARGE_NOT_RECURRING")
    return {"commitment_ref": item.scope.entity_ref, "status": item.status, "amount": str(item.ledger.amount), "owner_ref": item.ledger.owner_ref, "renews_at": item.ledger.renews_at, "outcome": item.ledger.outcome}


class SpendInputTax(StrictModel):
    """Observed tax on cleared, coded charges; this does not calculate tax rates."""
    schema_id: Literal["lightbulb.spend_input_tax.v1"] = Field(default="lightbulb.spend_input_tax.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    sources: tuple[dict[str, Any], ...] = Field(min_length=1, max_length=200)
    input_tax: Decimal
    evidence_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("input_tax", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="input_tax")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        total, seen, scope = Decimal(0), set(), None
        for source in self.sources:
            plan, item = _binding(source, SPEND_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH")
            current = (item.scope.tenant_ref, item.scope.company_ref)
            if item.status != "cleared" or plan.company_ref != self.company_ref or plan.currency != self.currency or (scope is not None and current != scope) or item.ledger.transaction_ref in seen:
                raise ValueError("input tax requires unique cleared charges in one company and currency")
            scope = current
            seen.add(item.ledger.transaction_ref)
            if item.ledger.tax_claimable:
                total += item.ledger.tax_amount
        if total.quantize(MONEY_QUANTUM) != self.input_tax:
            raise ValueError("input tax must equal the observed tax on cleared eligible categories")
        if not skip_digests(info) and self.evidence_digest != sealed_digest(SpendInputTax, self, "evidence_digest"):
            raise ValueError("evidence_digest must commit the exact tax sources")
        return self


def claimable_input_tax(states: Sequence[Any], *, source_plans: Mapping[str, Any]) -> SpendInputTax:
    sources = [{"state": detached(s), "plan": detached(source_plans.get(detached(s).get("plan_digest")))} for s in states]
    _require(bool(sources), "CLEARED_WITHOUT_STATEMENT_MATCH", "input tax needs cleared expense evidence")
    bound = [_binding(source, SPEND_LIFECYCLE, "CLEARED_WITHOUT_STATEMENT_MATCH") for source in sources]
    return seal(SpendInputTax, {"company_ref": bound[0][0].company_ref, "currency": bound[0][0].currency, "sources": sources,
        "input_tax": str(sum((item.ledger.tax_amount for _, item in bound if item.ledger.tax_claimable), Decimal(0)))}, "evidence_digest")


def spend_exceptions(states: Sequence[Any], *, source_plans: Mapping[str, Any], now: str) -> tuple[dict[str, Any], ...]:
    """Real exceptions-desk opening receipts, preserving the specific source code."""
    at = timestamp(now, field_name="now")
    out = []
    for source in states:
        raw = detached(source)
        spec = SPEND_LIFECYCLE if raw.get("schema") == "lightbulb.spend_item_state.v1" else COMMITMENT_LIFECYCLE
        plan, state = _binding({"state": source, "plan": source_plans.get(raw.get("plan_digest"))}, spec, "OBSERVATION_INVALID")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "OBSERVATION_INVALID", "exception assessment cannot predate its source")
        code = None
        if spec is SPEND_LIFECYCLE and state.status not in ("cleared", "rejected"):
            if state.ledger.amount >= plan.receipt_threshold and state.ledger.receipt_digest is None and (parsed(at)-parsed(state.ledger.transacted_at)).total_seconds() > plan.receipt_grace_hours*3600:
                code = "RECEIPT_MISSING_ABOVE_THRESHOLD"
            elif state.status == "policy_exception":
                code = "POLICY_VIOLATION"
        elif spec is COMMITMENT_LIFECYCLE and state.status in ("active", "assurance_due", "suspended", "renewal_due", "decision_pending") and state.ledger.assurance is not None and parsed(state.ledger.assurance["valid_until"]) <= parsed(at):
            code = "ASSURANCE_EXPIRED"
        if code:
            out.append({"kind": "chain_reconciliation", "source_engine": SPEND_CONTROL_KIND, "source_ref": state.scope.entity_ref, "source_digest": state.state_digest, "code": code, "detail": "Resolve the observed spend or vendor-control exception before further approval.", "evidence_refs": [f"spend:{state.state_digest}"]})
    return tuple(out)


def commitment_expiring_signal(state: Any, *, source_plan: Any, emitted_at: str) -> Any:
    from lightbulb.company_operating_system import CompanySignal
    plan, item = _binding({"state": state, "plan": source_plan}, COMMITMENT_LIFECYCLE, "CHARGE_NOT_RECURRING")
    at = timestamp(emitted_at, field_name="emitted_at")
    _require(item.status in ("active", "renewal_due", "decision_pending") and item.ledger.renews_at is not None and parsed(at) >= parsed(item.transition_history[-1].command.occurred_at) and parsed(at) >= parsed(item.ledger.renews_at)-timedelta(days=max(plan.flag_days_before_renewal,item.ledger.notice_days)), "NOTICE_WINDOW_MISSED", "renewal signal requires an observed commitment inside its review window")
    due = (parsed(item.ledger.renews_at)-timedelta(days=item.ledger.notice_days)).isoformat().replace("+00:00", "Z")
    return CompanySignal(name="signals.commitment_expiring", producer=SPEND_CONTROL_KIND, emitted_at=at,
        payload={"commitment_ref": item.scope.entity_ref, "merchant_ref": item.ledger.merchant_ref, "renews_at": item.ledger.renews_at, "notice_due_at": due, "amount": str(item.ledger.amount), "currency": plan.currency, "state_digest": item.state_digest})


SPEND_CONTROL_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": SPEND_CONTROL_KIND, "golden_loop": SPEND_CONTROL_GOLDEN_LOOP, "stages": ["capture", "code", "approve", "post", "clear", "confirm_recurring", "decide", "renew"], "statuses": list(SPEND_STATUSES+COMMITMENT_STATUSES), "events": list(SPEND_EVENTS+COMMITMENT_EVENTS), "hops": {"capture": "provenance-bound card charge", "code": "sealed account and cost-centre maps and observed policy", "post": "approved write plus governed readback", "clear": "statement match plus close", "confirm_recurring": "observed bills and replayed agreement terms", "renew": "authority-bound observed renewal bill"}, "required_connectors": ["ramp", "expensify", "xero", "quickbooks", "billcom", "stripe", "lightbulb.sdk_engine_state"], "missing_reads": ["ramp and expensify: host-read fixtures", "billcom.list_bills and xero.list_repeating_invoices: host-read fixtures", "host.vendor_exit_evidence: retained supplier exit evidence"], "hard_rules": ["a charge with no receipt above the threshold becomes an exception, never a silent cost", "the spend policy is a read with provenance, not a rule typed into the plan", "a recurring commitment is confirmed by observed charges, never declared", "a missed notice window is recorded as a missed decision, never papered over"]}

__all__ = ["SPEND_CONTROL_KIND", "SPEND_CONTROL_GOLDEN_LOOP", "SPEND_CONTROL_MANIFEST", "SPEND_STATUSES", "SPEND_EVENTS", "COMMITMENT_STATUSES", "COMMITMENT_EVENTS", "SPEND_LIFECYCLE", "SPEND_CHAIN_LIFECYCLE", "COMMITMENT_LIFECYCLE", "SpendControlError", "SpendControlPlan", "ReadEvidence", "AssuranceEvidence", "SpendReceipt", "SpendLedger", "CommitmentLedger", "SpendEffectBoundary", "SpendItemState", "VendorCommitmentState", "SpendInputTax", "compile_spend_control", "open_spend_item", "advance_spend_item", "open_vendor_commitment", "advance_vendor_commitment", "capture_receipt", "receipt_match", "policy_receipt", "code_receipt", "post_request", "post_receipt", "clear_receipt", "recurrence_receipt", "agreement_terms_receipt", "assurance_receipt", "exit_receipt", "renewal_bill_receipt", "fixed_cost_flows", "period_spend_receipts", "claimable_input_tax", "spend_exceptions", "commitment_expiring_signal", "spend_summary", "commitment_summary"]
