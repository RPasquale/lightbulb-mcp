"""Prove priced scope, governed quotes and explicit acceptance before execution.

Books come from retained provider reads, configurations from the existing
commercial snapshot, and service rates from explicitly named operator inputs.
Pricing decisions bind exact authority proofs. Provider quote writes are read
back; reply classification retains both the governed thread and its bound host
classification. Executed deals project verified value and engagement budgets.
These are local candidates: Spring owns custody, scope, approvals and effects.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, LifecycleSpec, OpaqueRef,
    Rejected, Sha256Digest, ShortText, StrictModel, decimal_value, detached,
    iso, parsed, require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)
from lightbulb.company_execution_bridge import OBSERVATION_PROVENANCE_SCHEMA, ObservationProvenance

DEAL_DESK_KIND = "deal_desk_engine"
DEAL_DESK_GOLDEN_LOOP = "commercial.approved_quote_to_executed_agreement_custody@0.1.0"
DEAL_DESK_PLAN_SCHEMA = "lightbulb.deal_desk_plan.v1"
DEAL_STATUSES = ("configured", "priced", "discount_review", "approved", "quoted", "accepted", "deposit_held", "executed", "expired", "withdrawn", "reconciliation_required")
DEAL_EVENTS = ("configure", "price", "request_discount_approval", "approve_discount", "issue_quote", "accept", "take_deposit", "execute", "revise", "expire", "withdraw", "require_reconciliation")
TERMINAL_DEAL_STATUSES = frozenset({"executed", "expired", "withdrawn", "reconciliation_required"})
MAX_REVISIONS = 5
CUSTODY_CANDIDATE_SCHEMA = "lightbulb.commercial_legal_handoff_custody_candidate.v1"
MISSING_GOVERNED_READS = ("xero.list_items", "quickbooks.list_items", "xero.list_tax_rates", "quickbooks.list_tax_rates", "quickbooks.list_terms", "host.commercial_configuration_snapshot", "host.classify_quote_acceptance", "host.partner_deal_registration")


class DealDeskError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DealDeskError(code, message)


def _read(model: Any, value: Any, code: str = "DEAL_SOURCE_INVALID") -> Any:
    try:
        return model.model_validate(detached(value))
    except (ValueError, TypeError) as exc:
        raise DealDeskError(code, f"the retained {model.__name__} is invalid") from exc


def _ratio(value: Any) -> Decimal:
    result = Decimal(str(value))
    if not result.is_finite() or result < 0 or result > 1:
        raise ValueError("discount ratio must be finite and within zero and one")
    return result.quantize(Decimal("0.000001"))


class DealDeskPlan(StrictModel):
    schema_id: Literal["lightbulb.deal_desk_plan.v1"] = Field(default=DEAL_DESK_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    profile: Literal["b2b_enterprise", "services_scope", "wholesale", "local_trades"] = "b2b_enterprise"
    price_book_digest: Sha256Digest
    discount_threshold: Decimal = Field(default=Decimal("0.250000"), validate_default=True)
    max_discount_percent: Decimal = Field(default=Decimal("40.00"), ge=0, le=100, validate_default=True)
    floor_margin_percent: Decimal = Field(default=Decimal("35.00"), ge=0, le=100, validate_default=True)
    max_quote_validity_days: int = Field(default=30, ge=1, le=365)
    variation_tolerance_percent: Decimal = Field(default=Decimal("15.00"), ge=0, le=100, validate_default=True)
    deposit_percent: Decimal = Field(default=Decimal("0.00"), ge=0, le=100, validate_default=True)
    allowed_terms: tuple[OpaqueRef, ...] = ("net_7", "net_14", "net_30")
    requires_partner_registration: bool = False
    requires_allocation: bool = False
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("discount_threshold", mode="before")
    @classmethod
    def _discount(cls, value: Any) -> Decimal:
        return _ratio(value)

    @field_validator("max_discount_percent", "floor_margin_percent", "variation_tolerance_percent", "deposit_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        if not self.allowed_terms or len(set(self.allowed_terms)) != len(self.allowed_terms):
            raise ValueError("allowed terms must be nonempty and unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self), self, "plan_digest"):
            raise ValueError("plan_digest must commit exact deal policy")
        return self


class ReadEvidence(StrictModel):
    provenance: ObservationProvenance
    payload: dict[str, Any]

    @model_validator(mode="after")
    def _guard(self) -> Any:
        if self.provenance.schema_id != OBSERVATION_PROVENANCE_SCHEMA or self.provenance.output_digest != stable_digest(self.payload) or self.provenance.provenance_digest == GENESIS_DIGEST:
            raise ValueError("read output must match the retained provenance output digest")
        return self


class BookLine(StrictModel):
    product_ref: OpaqueRef
    unit_price: Decimal
    cost_rate: Decimal | None = None
    tax_code: OpaqueRef
    tax_percent: Decimal

    @field_validator("unit_price", "cost_rate", "tax_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class OperatorRateCard(StrictModel):
    schema_id: Literal["lightbulb.operator_rate_card.v1"] = Field(default="lightbulb.operator_rate_card.v1", alias="schema")
    operator_supplied: Literal[True] = True
    price_book_ref: OpaqueRef
    currency: CurrencyCode
    effective_from: str
    rates: tuple[dict[str, Any], ...] = Field(min_length=1, max_length=200)

    @field_validator("effective_from")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="effective_from")

    @model_validator(mode="after")
    def _rates(self) -> Any:
        refs = []
        for row in self.rates:
            if set(row) != {"role_ref", "bill_rate", "cost_rate"}:
                raise ValueError("operator rates carry only opaque role_ref, bill_rate and cost_rate")
            _RateLine.model_validate(row)
            refs.append(row["role_ref"])
        if len(set(refs)) != len(refs):
            raise ValueError("rate-card roles must be unique")
        return self


class _RateLine(StrictModel):
    role_ref: OpaqueRef
    bill_rate: Decimal
    cost_rate: Decimal

    @field_validator("bill_rate", "cost_rate", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class PriceBook(StrictModel):
    schema_id: Literal["lightbulb.deal_price_book.v1"] = Field(default="lightbulb.deal_price_book.v1", alias="schema")
    price_book_ref: OpaqueRef
    currency: CurrencyCode
    effective_from: str
    lines: tuple[BookLine, ...] = Field(min_length=1, max_length=2000)
    terms: tuple[OpaqueRef, ...] = ()
    source_reads: tuple[ReadEvidence, ...] = Field(default_factory=tuple, max_length=8)
    operator_rate_card: OperatorRateCard | None = None
    price_book_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("effective_from")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="effective_from")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        if bool(self.source_reads) == (self.operator_rate_card is not None):
            raise ValueError("a book retains exactly provider reads or an explicit operator rate card")
        if len({line.product_ref for line in self.lines}) != len(self.lines):
            raise ValueError("book product references must be unique")
        if not skip_digests(info) and self.price_book_digest != sealed_digest(type(self), self, "price_book_digest"):
            raise ValueError("price_book_digest must commit the exact read-derived book")
        return self


def _native_rows(payload: Mapping[str, Any], plural: str, singular: str) -> list[dict[str, Any]]:
    data = payload.get("data", payload)
    if isinstance(data, list):
        return list(data)
    rows = data.get(plural, data.get("QueryResponse", {}).get(singular, []))
    return [dict(row) for row in rows]


def _provider_date(value: str) -> str:
    return timestamp(value + "T00:00:00Z" if len(value) == 10 else value, field_name="provider date")


def price_book_receipt(provenance: Any, payload: Any, *, price_book_ref: str | None = None, currency: str | None = None, supporting_reads: Sequence[Any] = ()) -> PriceBook:
    """Read native Xero Items or QuickBooks Item rows; retain tax/terms reads.

    Currency and book aliases are operator routing metadata when the provider's
    item response omits them. No price, cost or tax number is operator-supplied.
    """
    primary = _read(ReadEvidence, {"provenance": detached(provenance), "payload": detached(payload)}, "PRICE_NOT_IN_BOOK")
    reads = (primary, *(_read(ReadEvidence, source, "PRICE_NOT_IN_BOOK") for source in supporting_reads))
    _require(primary.provenance.source_tool in {"xero.list_items", "quickbooks.list_items"} and primary.provenance.lane == "host_read", "PRICE_NOT_IN_BOOK", "item books require their named host-lane provider read")
    taxes: dict[str, Decimal] = {}
    terms = []
    for source in reads[1:]:
        tool = source.provenance.source_tool
        _require(source.provenance.lane == "host_read" and tool in {"xero.list_tax_rates", "quickbooks.list_tax_rates", "quickbooks.list_terms"}, "PRICE_NOT_IN_BOOK", "supporting book evidence must be a named host tax or terms read")
        if tool.endswith("list_tax_rates"):
            for row in _native_rows(source.payload, "TaxRates", "TaxRate"):
                code = row.get("TaxType", row.get("Id"))
                value = row.get("EffectiveRate", row.get("RateValue"))
                _require(code is not None and value is not None, "PRICE_NOT_IN_BOOK", "tax rows carry exact code and rate")
                taxes[str(code)] = decimal_value(value, field_name="tax rate")
        else:
            for row in _native_rows(source.payload, "Terms", "Term"):
                if row.get("Active", True) and row.get("DueDays") is not None:
                    terms.append(f"net_{int(row['DueDays'])}")
    lines = []
    for row in _native_rows(primary.payload, "Items", "Item"):
        xero = primary.provenance.source_tool == "xero.list_items"
        sales, purchase = row.get("SalesDetails", {}), row.get("PurchaseDetails", {})
        product = row.get("Code") if xero else row.get("Sku", row.get("Name"))
        price = sales.get("UnitPrice") if xero else row.get("UnitPrice")
        cost = purchase.get("UnitPrice") if xero else row.get("PurchaseCost")
        tax_code = sales.get("TaxType") if xero else (row.get("SalesTaxCodeRef") or {}).get("value")
        _require(product is not None and price is not None and tax_code in taxes, "PRICE_NOT_IN_BOOK", "every book line requires read-proven SKU, list price and tax code")
        lines.append({"product_ref": product, "unit_price": price, "cost_rate": cost, "tax_code": tax_code, "tax_percent": str(taxes[tax_code])})
    _require(bool(lines), "PRICE_NOT_IN_BOOK", "the item read must retain priced lines")
    return seal(PriceBook, {"price_book_ref": price_book_ref or primary.payload.get("price_book_ref"), "currency": currency or primary.payload.get("currency"), "effective_from": max(source.provenance.completed_at for source in reads), "lines": lines, "terms": sorted(set(terms)), "source_reads": [source.to_dict() for source in reads]}, "price_book_digest")


def rate_card_receipt(rate_card: Any) -> PriceBook:
    source = _read(OperatorRateCard, rate_card, "SCOPE_UNPRICED")
    lines = [{"product_ref": row["role_ref"], "unit_price": row["bill_rate"], "cost_rate": row["cost_rate"], "tax_code": "operator-tax-exclusive", "tax_percent": "0"} for row in source.rates]
    return seal(PriceBook, {"price_book_ref": source.price_book_ref, "currency": source.currency, "effective_from": source.effective_from, "lines": lines, "operator_rate_card": source.to_dict()}, "price_book_digest")


def _book(value: Any) -> PriceBook:
    source = _read(PriceBook, value, "PRICE_NOT_IN_BOOK")
    if source.operator_rate_card is not None:
        derived = rate_card_receipt(source.operator_rate_card)
    else:
        primary = source.source_reads[0]
        derived = price_book_receipt(primary.provenance, primary.payload, price_book_ref=source.price_book_ref, currency=source.currency, supporting_reads=source.source_reads[1:])
    _require(derived.price_book_digest == source.price_book_digest, "PRICE_NOT_IN_BOOK", "book prices must reproduce their retained provider reads or operator rate card")
    return source


def compile_deal_desk(company_ref: str, *, currency: str, price_book: Any, profile: str = "b2b_enterprise", overrides: Mapping[str, Any] | None = None) -> DealDeskPlan:
    book = _book(price_book)
    _require(book.currency == currency.upper(), "DEAL_SCOPE_MISMATCH", "the adopted book must use the deal currency")
    _require(book.operator_rate_card is None or profile in {"services_scope", "local_trades"}, "PRICE_NOT_IN_BOOK", "operator rates are restricted to services and trades profiles")
    return seal(DealDeskPlan, {"company_ref": company_ref, "currency": currency.upper(), "profile": profile, "price_book_digest": book.price_book_digest, **dict(overrides or {})}, "plan_digest")


class DealReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)
    scope_binding: dict[str, Any] | None = None
    price_book: dict[str, Any] | None = None
    configuration: dict[str, Any] | None = None
    configuration_snapshot: dict[str, Any] | None = None
    configuration_read: dict[str, Any] | None = None
    prospect_state: dict[str, Any] | None = None
    prospect_plan: dict[str, Any] | None = None
    terms: OpaqueRef | None = None
    pricing_digest: Sha256Digest | None = None
    approved_discount_ratio: Decimal | None = None
    authorization_proof: dict[str, Any] | None = None
    quote_execution: dict[str, Any] | None = None
    quote_request: dict[str, Any] | None = None
    quote_read: dict[str, Any] | None = None
    acceptance_read: dict[str, Any] | None = None
    classification_read: dict[str, Any] | None = None
    signature_execution: dict[str, Any] | None = None
    signature_payload: dict[str, Any] | None = None
    deposit_read: dict[str, Any] | None = None
    deposit_quote_ref: OpaqueRef | None = None
    custody_candidate: dict[str, Any] | None = None
    partner_read: dict[str, Any] | None = None
    inventory_read: dict[str, Any] | None = None
    allocated_units: dict[str, Decimal] | None = None

    @field_validator("approved_discount_ratio", mode="before")
    @classmethod
    def _ratio(cls, value: Any) -> Decimal | None:
        return None if value is None else _ratio(value)

    @field_validator("allocated_units", mode="before")
    @classmethod
    def _units(cls, value: Any) -> dict[str, Decimal] | None:
        return None if value is None else {key: decimal_value(item, field_name="allocated units") for key, item in value.items()}


class DealLedger(StrictModel):
    company_ref: OpaqueRef | None = None
    tenant_ref: OpaqueRef | None = None
    project_ref: OpaqueRef | None = None
    project_id: str | None = None
    entity_ref: OpaqueRef | None = None
    customer_ref: OpaqueRef | None = None
    configuration_ref: OpaqueRef | None = None
    configuration_revision: int = 0
    configuration_digest: Sha256Digest | None = None
    lines: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    subtotal: Decimal = Decimal("0.00")
    discount_total: Decimal = Decimal("0.00")
    tax_total: Decimal = Decimal("0.00")
    contract_value: Decimal = Decimal("0.00")
    cost_budget: Decimal = Decimal("0.00")
    margin_percent: Decimal = Decimal("0.00")
    discount_ratio: Decimal = Decimal("0.000000")
    terms: OpaqueRef | None = None
    pricing_digest: Sha256Digest | None = None
    authorized_pricing_digest: Sha256Digest | None = None
    authorization_proof_digest: Sha256Digest | None = None
    quote_ref: OpaqueRef | None = None
    quote_number: OpaqueRef | None = None
    quote_source_digest: Sha256Digest | None = None
    valid_until: str | None = None
    issued_at: str | None = None
    accepted_at: str | None = None
    accepted_amount: Decimal = Decimal("0.00")
    deposit_amount: Decimal = Decimal("0.00")
    deposit_ref: OpaqueRef | None = None
    deposit_source_digest: Sha256Digest | None = None
    acceptance_ref: OpaqueRef | None = None
    acceptance_source_digest: Sha256Digest | None = None
    agreement_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    custody_candidate_digest: Sha256Digest | None = None
    variations_require_approval: bool = False
    revisions: int = 0
    outcome: str = "open"

    @field_validator("subtotal", "discount_total", "tax_total", "contract_value", "cost_budget", "accepted_amount", "deposit_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="margin_percent", allow_negative=True)

    @field_validator("discount_ratio", mode="before")
    @classmethod
    def _discount(cls, value: Any) -> Decimal:
        return _ratio(value)

    @field_validator("valid_until", "issued_at", "accepted_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class DealEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    quote_created: Literal[False] = False
    payment_collected: Literal[False] = False
    agreement_executed: Literal[False] = False


def configuration_receipt(commercial_configuration_snapshot: Any, *, source_snapshot: Any = None, provenance: Any = None) -> dict[str, Any]:
    from lightbulb.commercial_controls import CommercialConfigurationSnapshot
    raw = dict(detached(commercial_configuration_snapshot))
    _require(bool(raw.get("lines")) and all(Decimal(str(row.get("quantity", "0"))) > 0 for row in raw.get("lines", ())), "SCOPE_UNPRICED", "every deliverable requires positive estimated units or hours")
    config = _read(CommercialConfigurationSnapshot, raw, "SCOPE_UNPRICED")
    _require(config.status == "validated", "SCOPE_UNPRICED", "configuration must have validated scope")
    result = {"configuration": config.to_dict()}
    if source_snapshot is not None:
        from lightbulb.commercial_operations_lifecycle import CommercialOperationsLifecycleSnapshot
        source = _read(CommercialOperationsLifecycleSnapshot, source_snapshot, "SCOPE_UNPRICED")
        _require(source.configuration == config, "SCOPE_UNPRICED", "configuration must be the verbatim artifact retained in the commercial lifecycle")
        result["configuration_snapshot"] = source.to_dict()
        digest = source.state_digest
    else:
        read = _read(ReadEvidence, {"provenance": detached(provenance), "payload": raw}, "SCOPE_UNPRICED")
        _require(read.provenance.lane == "host_read" and read.provenance.source_tool == "host.commercial_configuration_snapshot", "SCOPE_UNPRICED", "an unsealed configuration needs its exact host artifact observation")
        result["configuration_read"] = read.to_dict()
        digest = read.provenance.output_digest
    return {**result, "evidence_refs": [f"configuration:{digest[:16]}"]}


def prospect_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE
    try:
        plan, source = PROSPECT_LIFECYCLE.bind(source_plan, state)
    except (ValueError, TypeError) as exc:
        raise DealDeskError("DEAL_SOURCE_INVALID", "prospect evidence requires the real source state and plan") from exc
    _require(source.status == "handed_off" and source.ledger.deal_ref is not None, "DEAL_SOURCE_INVALID", "only a handed-off prospect is a deal source")
    return {"prospect_state": source.to_dict(), "prospect_plan": plan.to_dict(), "evidence_refs": [f"prospect:{source.state_digest[:16]}"]}


def _quote_facts(execution: Any, request: Any, confirming_read: Any) -> dict[str, Any]:
    from lightbulb.company_execution_bridge import ExecutionReceipt
    from lightbulb.connector_execution import ConnectorExecutionRequest
    write = _read(ExecutionReceipt, execution, "QUOTE_NOT_ISSUED")
    call = _read(ConnectorExecutionRequest, request, "QUOTE_NOT_ISSUED")
    read = _read(ReadEvidence, confirming_read, "QUOTE_NOT_ISSUED")
    _require(write.schema_id == "lightbulb.engine_execution_receipt.v1" and write.tool == call.tool == "xero.create_quote" and write.effect == "write" and call.approval_required and write.request_digest == call.custody_fingerprint() and write.project_id == str(call.scope.project_id), "QUOTE_NOT_ISSUED", "quote needs the exact approved completed Xero write")
    _require(read.provenance.source_tool == "xero.list_quotes" and read.provenance.lane in {"host_read", "governed_read"} and parsed(read.provenance.completed_at) >= parsed(write.completed_at), "QUOTE_NOT_ISSUED", "confirm the quote through its named read after issuance")
    targets = call.arguments.get("Quotes", [])
    _require(len(targets) == 1, "QUOTE_NOT_ISSUED", "each quote execution writes exactly one quoted scope")
    target = targets[0]
    rows = [row for row in _native_rows(read.payload, "Quotes", "Quote") if row.get("QuoteNumber") == target.get("QuoteNumber")]
    _require(len(rows) == 1, "QUOTE_NOT_ISSUED", "the confirming read must uniquely match the quote number")
    row = rows[0]
    _require(row.get("Status") in {"SENT", "ACCEPTED"} and row.get("Reference") == target.get("Reference") and row.get("CurrencyCode") == target.get("CurrencyCode") and row.get("Contact", {}).get("ContactID") == target.get("Contact", {}).get("ContactID") and decimal_value(row.get("Total"), field_name="quote total") == decimal_value(target.get("Total"), field_name="requested quote total"), "QUOTE_NOT_ISSUED", "the provider quote must match the exact request's customer, reference, currency and total")
    _require(bool(row.get("LineItems")) and row["LineItems"] == target.get("LineItems"), "QUOTE_NOT_ISSUED", "quote read must retain the exact requested product quantities and rates")
    return {"quote_ref": row["Reference"], "quote_number": row["QuoteNumber"], "customer_ref": row["Contact"]["ContactID"], "currency": row["CurrencyCode"], "contract_value": str(decimal_value(row["Total"], field_name="quote total")), "tax_total": str(decimal_value(row["TotalTax"], field_name="quote tax")), "subtotal": str(decimal_value(row["SubTotal"], field_name="quote subtotal")), "valid_until": _provider_date(row["ExpiryDate"]), "issued_at": write.completed_at, "quote_source_digest": read.provenance.output_digest}


def quote_receipt(execution_receipt: Any, confirming_read: Any, *, request: Any) -> dict[str, Any]:
    _quote_facts(execution_receipt, request, confirming_read)
    return {"quote_execution": detached(execution_receipt), "quote_request": detached(request), "quote_read": detached(confirming_read), "evidence_refs": [f"quote:{dict(detached(execution_receipt))['journal_ref']}"]}


def _acceptance_facts(r: Any) -> dict[str, Any]:
    if r.signature_execution is not None:
        from lightbulb.company_execution_bridge import ExecutionReceipt
        execution = _read(ExecutionReceipt, r.signature_execution, "ACCEPTANCE_UNEVIDENCED")
        payload = r.signature_payload or {}
        _require(execution.schema_id == "lightbulb.engine_execution_receipt.v1" and execution.effect == "read" and execution.tool == "docusign.get_envelope" and execution.output_digest == stable_digest(payload) and payload.get("status") == "completed" and payload.get("counterparty_signed") is True, "ACCEPTANCE_UNEVIDENCED", "signature acceptance requires exact completed envelope evidence")
        return {"quote_ref": payload.get("quote_ref"), "customer_ref": payload.get("customer_ref"), "currency": payload.get("currency"), "accepted_amount": str(decimal_value(payload.get("accepted_amount"), field_name="accepted amount")), "accepted_at": execution.completed_at, "acceptance_ref": execution.journal_ref, "acceptance_source_digest": execution.execution_digest}
    from lightbulb.pipeline_execution import reply_receipt
    thread = _read(ReadEvidence, r.acceptance_read, "ACCEPTANCE_UNEVIDENCED")
    classification = _read(ReadEvidence, r.classification_read, "ACCEPTANCE_UNEVIDENCED")
    _require(thread.provenance.lane == "governed_read" and thread.provenance.source_tool in {"gmail.get_thread", "microsoft.get_conversation"}, "ACCEPTANCE_UNEVIDENCED", "acceptance must retain its governed communication read")
    result = classification.payload
    _require(classification.provenance.source_tool == "host.classify_quote_acceptance" and classification.provenance.lane == "host_read" and result.get("source_output_digest") == thread.provenance.output_digest and parsed(classification.provenance.completed_at) >= parsed(thread.provenance.completed_at) and result.get("explicit_acceptance") is True and result.get("confidence") is not None and result.get("needs_human_review") is False, "ACCEPTANCE_UNEVIDENCED", "the host classification must bind exact read content and explicit counterparty acceptance")
    try:
        classified = reply_receipt(result, reply_ref=thread.provenance.observation_ref)
    except ValueError as exc:
        raise DealDeskError("ACCEPTANCE_UNEVIDENCED", "unconfident or review-required replies cannot prove acceptance") from exc
    _require(classified["disposition"] == "positive", "ACCEPTANCE_UNEVIDENCED", "a negative or conditional reply is not acceptance")
    return {"quote_ref": result.get("quote_ref"), "customer_ref": result.get("customer_ref"), "currency": result.get("currency"), "accepted_amount": str(decimal_value(result.get("accepted_amount"), field_name="accepted amount")), "accepted_at": thread.provenance.completed_at, "acceptance_ref": thread.provenance.observation_ref, "acceptance_source_digest": classification.provenance.output_digest}


def acceptance_receipt(thread_observation: Any = None, *, classification: Any = None, signature_receipt: Any = None, signature_payload: Any = None) -> dict[str, Any]:
    result = {"signature_execution": detached(signature_receipt), "signature_payload": detached(signature_payload)} if signature_receipt is not None else {"acceptance_read": detached(thread_observation), "classification_read": detached(classification)}
    facts = _acceptance_facts(_read(DealReceipt, result, "ACCEPTANCE_UNEVIDENCED"))
    return {**result, "evidence_refs": [f"acceptance:{facts['acceptance_ref']}"]}


def _deposit_facts(observation: Any, quote_ref: str | None = None) -> dict[str, Any]:
    read = _read(ReadEvidence, observation, "DEPOSIT_NOT_OBSERVED")
    tool, payload = read.provenance.source_tool, read.payload
    if tool == "square.list_payments" and read.provenance.lane == "host_read":
        rows = payload.get("payments", [])
        _require(len(rows) == 1 and rows[0].get("status") == "COMPLETED" and int((rows[0].get("refunded_money") or {}).get("amount", 0)) == 0, "DEPOSIT_NOT_OBSERVED", "deposit read must uniquely retain an unreversed completed payment")
        row = rows[0]
        amount, currency, ref, quote = row["amount_money"]["amount"], row["amount_money"]["currency"], row["id"], row.get("reference_id")
    elif tool == "stripe.list_charges" and read.provenance.lane == "host_read":
        rows = payload.get("data", [])
        _require(len(rows) == 1 and rows[0].get("paid") is True and rows[0].get("captured") is True and int(rows[0].get("amount_refunded", 0)) == 0 and rows[0].get("disputed", False) is False, "DEPOSIT_NOT_OBSERVED", "deposit must be one captured unreversed charge")
        row = rows[0]
        amount, currency, ref, quote = row["amount"], row["currency"], row["id"], row.get("metadata", {}).get("quote_ref")
    else:
        from hashlib import sha256
        from lightbulb.cash_collection import StripeCashSettlementObservation
        _require(tool == "stripe.observe_cash_settlement" and read.provenance.lane == "governed_read", "DEPOSIT_NOT_OBSERVED", "deposit needs its named payment or settlement read")
        settled = _read(StripeCashSettlementObservation, payload, "DEPOSIT_NOT_OBSERVED")
        _require(settled.disposition == "SETTLED" and quote_ref is not None and settled.invoice_correlation_sha256 == sha256(quote_ref.encode()).hexdigest(), "DEPOSIT_NOT_OBSERVED", "the canonical settlement must carry this quote's exact correlation")
        if settled.query_sha256 is None:
            _require(parsed(settled.charge_created_at) <= parsed(settled.payout_arrival_at), "DEPOSIT_NOT_OBSERVED", "the SDK settlement variant must observe charge creation before payout")
        _require((parsed(settled.observed_at) - parsed(settled.payout_arrival_at)).days >= settled.reversal_window_days and parsed(settled.observed_at) <= parsed(read.provenance.completed_at), "DEPOSIT_NOT_OBSERVED", "settlement must observe the complete reversal window before its read")
        amount, currency, ref, quote = settled.amount_minor, settled.currency, settled.charge_id_sha256, quote_ref
    _require(bool(quote) and isinstance(amount, int) and not isinstance(amount, bool) and amount > 0, "DEPOSIT_NOT_OBSERVED", "deposit must carry positive minor units and an explicit quote correlation")
    return {"quote_ref": quote, "currency": currency.upper(), "deposit_amount": str((Decimal(amount) / 100).quantize(MONEY_QUANTUM)), "deposit_ref": f"deposit:{stable_digest(ref)[:32]}", "deposit_source_digest": read.provenance.output_digest, "observed_at": read.provenance.completed_at}


def deposit_receipt(payment_observation: Any, *, provenance: Any = None, quote_ref: str | None = None) -> dict[str, Any]:
    source = {"provenance": detached(provenance), "payload": detached(payment_observation)} if provenance is not None else detached(payment_observation)
    facts = _deposit_facts(source, quote_ref)
    return {"deposit_read": source, "deposit_quote_ref": quote_ref, "evidence_refs": [facts["deposit_ref"]]}


def execute_receipt(custody_candidate: Any) -> dict[str, Any]:
    from lightbulb.commercial_legal_handoff import ExecutedCommercialAgreementCustodyCandidate
    raw = dict(detached(custody_candidate))
    _require(bool(raw.get("signatures")), "EXECUTION_UNSIGNED", "execution requires retained counterparty signatures")
    source = _read(ExecutedCommercialAgreementCustodyCandidate, raw, "EXECUTION_UNSIGNED")
    return {"custody_candidate": source.to_dict(), "evidence_refs": [f"custody:{source.custody_candidate_digest[:24]}"]}


def allocation_receipt(inventory_observation: Any, *, units: Mapping[str, Any]) -> dict[str, Any]:
    source = _read(ReadEvidence, inventory_observation, "ALLOCATION_EXCEEDS_AVAILABLE")
    _require(source.provenance.source_tool == "ecommerce.get_inventory" and source.provenance.lane in {"host_read", "governed_read"}, "ALLOCATION_EXCEEDS_AVAILABLE", "allocation must retain the named inventory observation")
    rows = source.payload.get("inventory", source.payload.get("items", ()))
    indexed = {row["sku"]: row for row in rows}
    _require(len(indexed) == len(rows), "ALLOCATION_EXCEEDS_AVAILABLE", "inventory SKUs must be unique")
    quantities = {key: decimal_value(value, field_name="allocated units") for key, value in units.items()}
    _require(bool(quantities) and all(key in indexed and value > 0 and value <= decimal_value(indexed[key]["available"], field_name="available") - decimal_value(indexed[key].get("committed", 0), field_name="committed") for key, value in quantities.items()), "ALLOCATION_EXCEEDS_AVAILABLE", "allocation cannot exceed observed available-minus-committed inventory")
    return {"inventory_read": source.to_dict(), "allocated_units": {key: str(value) for key, value in quantities.items()}, "evidence_refs": [f"allocation:{source.provenance.output_digest[:16]}"]}


def partner_registration_receipt(provenance: Any, payload: Any) -> dict[str, Any]:
    from lightbulb.commercial_controls import CommercialChannelAuthorizationSnapshot
    source = _read(ReadEvidence, {"provenance": detached(provenance), "payload": detached(payload)}, "PARTNER_NOT_REGISTERED")
    partner = _read(CommercialChannelAuthorizationSnapshot, payload, "PARTNER_NOT_REGISTERED")
    _require(source.provenance.source_tool == "host.partner_deal_registration" and source.provenance.lane == "host_read" and partner.route == "partner" and partner.authorization_status == "authorized" and partner.deal_registration_ref is not None, "PARTNER_NOT_REGISTERED", "the host must retain current partner registration evidence")
    return {"partner_read": source.to_dict(), "evidence_refs": [partner.deal_registration_ref]}


def _configure(plan: Any, r: Any, data: dict[str, Any], at: str) -> None:
    from lightbulb.commercial_controls import CommercialConfigurationSnapshot
    require(r.configuration is not None and r.price_book is not None, "SCOPE_UNPRICED", "configure from a retained commercial snapshot and adopted book")
    configuration_receipt((r.configuration_read or {}).get("payload", r.configuration), source_snapshot=r.configuration_snapshot, provenance=(r.configuration_read or {}).get("provenance"))
    if r.configuration_read is not None:
        require(_read(CommercialConfigurationSnapshot, r.configuration_read["payload"]) == _read(CommercialConfigurationSnapshot, r.configuration), "SCOPE_UNPRICED", "configuration must equal the validated exact read output")
    config, book = _read(CommercialConfigurationSnapshot, r.configuration), _book(r.price_book)
    require(book.price_book_digest == plan.price_book_digest and config.price_book_ref == book.price_book_ref, "PRICE_NOT_IN_BOOK", "configuration must use the exact adopted read-derived book")
    require(config.currency == book.currency == plan.currency, "DEAL_SCOPE_MISMATCH", "configuration and book must share the plan currency")
    require(parsed(config.effective_at) <= parsed(at) and parsed(book.effective_from) <= parsed(at) and (config.expires_at is None or parsed(at) < parsed(config.expires_at)), "QUOTE_EXPIRED", "configuration and book must be effective at configuration time")
    if r.configuration_snapshot is not None:
        scope = r.configuration_snapshot["scope"]
        require(all(str(scope[key]) == str(data[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "DEAL_SCOPE_MISMATCH", "commercial snapshot belongs to another tenant/company/project")
    require(data.get("customer_ref") in {None, config.account_ref}, "DEAL_SCOPE_MISMATCH", "revisions cannot substitute the customer")
    index = {row.product_ref: row for row in book.lines}
    lines = []
    for line in config.lines:
        require(line.product_ref in index, "PRICE_NOT_IN_BOOK", "every configured product must exist in the adopted book")
        source = index[line.product_ref]
        lines.append({**line.to_dict(), "book_unit_price": str(source.unit_price), "cost_rate": None if source.cost_rate is None else str(source.cost_rate), "tax_percent": str(source.tax_percent)})
    if r.prospect_state is not None:
        prospect_receipt(r.prospect_state, source_plan=r.prospect_plan)
        source = r.prospect_state
        require(all(str(source["scope"][key]) == str(data[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "DEAL_SCOPE_MISMATCH", "prospect must share the deal scope")
        require(source["ledger"].get("account_ref") == config.account_ref and source["scope"].get("currency") == plan.currency, "DEAL_SCOPE_MISMATCH", "the priced customer and currency must match the handed-off prospect")
    data.update({"customer_ref": config.account_ref, "configuration_ref": config.configuration_ref, "configuration_revision": config.revision, "configuration_digest": stable_digest(config.to_dict()), "lines": lines})


def _price(plan: Any, data: dict[str, Any], terms: str | None) -> None:
    require(terms in plan.allowed_terms, "TERMS_NOT_ALLOWED", "select a permitted payment term")
    subtotal = discount = tax = costs = Decimal("0")
    ratios = []
    for line in data["lines"]:
        quantity = Decimal(line["quantity"])
        listed, configured = decimal_value(line["list_unit_price"], field_name="list price"), decimal_value(line["configured_unit_price"], field_name="configured price")
        ratio = _ratio(line["discount_ratio"])
        require(listed == Decimal(line["book_unit_price"]), "PRICE_NOT_IN_BOOK", "configured list price must equal the sealed book price")
        # The commercial_controls CPQ invariant, with cent-quantized money.
        require(configured == (listed * (1 - ratio)).quantize(MONEY_QUANTUM), "PRICE_NOT_RECONCILED", "configured price must equal list price times one-minus-discount")
        require(quantity > 0 and line.get("cost_rate") is not None, "SCOPE_UNPRICED", "every unit needs an observed landed cost or an operator service cost rate")
        amount = (quantity * configured).quantize(MONEY_QUANTUM)
        subtotal += amount
        discount += (quantity * (listed - configured)).quantize(MONEY_QUANTUM)
        tax += (amount * Decimal(line["tax_percent"]) / 100).quantize(MONEY_QUANTUM)
        costs += (quantity * Decimal(line["cost_rate"])).quantize(MONEY_QUANTUM)
        ratios.append(ratio)
    require(subtotal > 0, "SCOPE_UNPRICED", "scope must carry positive priced value")
    data.update({"subtotal": str(subtotal), "discount_total": str(discount), "tax_total": str(tax), "contract_value": str(subtotal + tax), "cost_budget": str(costs), "margin_percent": str(((subtotal - costs) / subtotal * 100).quantize(MONEY_QUANTUM)), "discount_ratio": str(max(ratios)), "terms": terms})
    data["pricing_digest"] = stable_digest({key: data[key] for key in ("configuration_digest", "customer_ref", "lines", "subtotal", "tax_total", "contract_value", "cost_budget", "terms", "revisions")})
    data["authorized_pricing_digest"] = None
    data["authorization_proof_digest"] = None


def _check_pricing(plan: Any, data: dict[str, Any]) -> None:
    approved = data.get("authorized_pricing_digest") == data["pricing_digest"]
    require(approved or Decimal(data["discount_ratio"]) * 100 <= plan.max_discount_percent, "DISCOUNT_ABOVE_MAX", "discount above the maximum requires exact pricing authority", "await_approval")
    require(approved or Decimal(data["discount_ratio"]) <= plan.discount_threshold and not data["variations_require_approval"], "DISCOUNT_APPROVAL_REQUIRED", "discount or scope variation needs an approved pricing decision", "await_approval")
    require(approved or Decimal(data["margin_percent"]) >= plan.floor_margin_percent, "MARGIN_BELOW_FLOOR", "thin-margin work requires exact pricing approval", "await_approval")


def _apply_deal(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event == "configure":
            require(r.scope_binding is not None and r.scope_binding["company_ref"] in {plan.company_ref, "selected"} and r.scope_binding["currency"] == plan.currency, "DEAL_SCOPE_MISMATCH", "open the deal with its exact scoped wrapper")
            data.update({key: r.scope_binding[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "entity_ref")})
            _configure(plan, r, data, at)
        elif event in {"price", "revise"}:
            old_value = Decimal(data["contract_value"])
            if event == "revise":
                require(data["revisions"] < MAX_REVISIONS, "REVISION_LIMIT", "the quote reached its bounded revision limit")
                previous_revision = data["configuration_revision"]
                _configure(plan, r, data, at)
                require(data["configuration_revision"] > previous_revision, "REVISION_LIMIT", "a revised configuration must advance its original revision")
                data["revisions"] += 1
                data.update({"quote_ref": None, "quote_number": None, "quote_source_digest": None, "valid_until": None, "issued_at": None})
            _price(plan, data, r.terms)
            if event == "revise" and plan.profile == "local_trades":
                data["variations_require_approval"] = abs(Decimal(data["contract_value"]) - old_value) > old_value * plan.variation_tolerance_percent / 100
        elif event == "request_discount_approval":
            require(r.pricing_digest in {None, data["pricing_digest"]}, "DISCOUNT_APPROVAL_MISMATCH", "the review must refer to current pricing", "manual_reconciliation")
        elif event == "approve_discount":
            from lightbulb.authority_matrix import verify_authorization
            require(r.pricing_digest == data["pricing_digest"] and r.approved_discount_ratio == Decimal(data["discount_ratio"]), "DISCOUNT_APPROVAL_MISMATCH", "approved ratio and pricing digest must equal this quote", "manual_reconciliation")
            require(r.authorization_proof is not None, "DISCOUNT_APPROVAL_REQUIRED", "fetch exact pricing authorization", "await_approval")
            try:
                proof = verify_authorization(r.authorization_proof, category="pricing", amount=data["contract_value"], currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_ref"])
            except (ValueError, TypeError) as exc:
                raise Rejected("DISCOUNT_APPROVAL_MISMATCH", "pricing proof must bind this exact ratio, amount, scope and command", "manual_reconciliation") from exc
            data.update({"authorized_pricing_digest": data["pricing_digest"], "authorization_proof_digest": proof.proof_digest})
        elif event == "issue_quote":
            _check_pricing(plan, data)
            facts = _quote_facts(r.quote_execution, r.quote_request, r.quote_read)
            require(facts["customer_ref"] == data["customer_ref"] and facts["currency"] == plan.currency and all(Decimal(facts[key]) == Decimal(data[key]) for key in ("contract_value", "subtotal", "tax_total")), "QUOTE_NOT_ISSUED", "provider quote values must equal the exact priced scope")
            require(all(str(r.quote_request["scope"][key]) == str(data[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "QUOTE_NOT_ISSUED", "provider request scope must equal the deal scope")
            quoted_lines = r.quote_request["arguments"]["Quotes"][0]["LineItems"]
            require(len(quoted_lines) == len(data["lines"]) and all(row.get("ItemCode") == line["product_ref"] and Decimal(str(row.get("Quantity", 0))) == Decimal(line["quantity"]) and Decimal(str(row.get("UnitAmount", 0))) == Decimal(line["configured_unit_price"]) for row, line in zip(quoted_lines, data["lines"])), "QUOTE_NOT_ISSUED", "provider quote must describe the exact configured deliverables")
            require(parsed(facts["issued_at"]) <= parsed(r.quote_read["provenance"]["completed_at"]) <= parsed(at) < parsed(facts["valid_until"]) <= parsed(facts["issued_at"]) + timedelta(days=plan.max_quote_validity_days), "QUOTE_EXPIRED", "quote validity and observation time must fit the bounded offer window")
            if plan.requires_partner_registration:
                require(r.partner_read is not None, "PARTNER_NOT_REGISTERED", "partner deals require retained registration")
                partner_registration_receipt(r.partner_read["provenance"], r.partner_read["payload"])
                partner = r.partner_read["payload"]
                require(partner["account_ref"] == data["customer_ref"] and parsed(partner["valid_from"]) <= parsed(at) < parsed(partner["valid_until"]) and {line["product_ref"] for line in data["lines"]} <= set(partner["authorized_product_refs"]), "PARTNER_NOT_REGISTERED", "partner registration must cover this customer, products and time")
            if plan.requires_allocation:
                require(r.inventory_read is not None and r.allocated_units is not None, "ALLOCATION_EXCEEDS_AVAILABLE", "wholesale issuance requires an inventory allocation")
                allocation_receipt(r.inventory_read, units=r.allocated_units)
                required_units: dict[str, Decimal] = {}
                for line in data["lines"]:
                    required_units[line["product_ref"]] = required_units.get(line["product_ref"], Decimal("0")) + Decimal(line["quantity"])
                require(r.allocated_units == required_units and parsed(r.inventory_read["provenance"]["completed_at"]) <= parsed(at), "ALLOCATION_EXCEEDS_AVAILABLE", "inventory allocation must cover exactly every quoted unit")
            data.update({key: value for key, value in facts.items() if key not in {"customer_ref", "currency", "contract_value", "tax_total", "subtotal"}})
        elif event == "accept":
            require(parsed(at) <= parsed(data["valid_until"]), "QUOTE_EXPIRED", "expired quotes cannot be accepted")
            facts = _acceptance_facts(r)
            require(r.signature_execution is None or r.signature_execution["project_id"] == data["project_id"], "ACCEPTANCE_UNEVIDENCED", "signature custody belongs to this project")
            require(facts["quote_ref"] == data["quote_ref"] and facts["customer_ref"] == data["customer_ref"] and facts["currency"] == plan.currency and parsed(data["issued_at"]) <= parsed(facts["accepted_at"]) <= parsed(at), "ACCEPTANCE_UNEVIDENCED", "acceptance must bind the exact issued quote, customer, currency and time")
            require(0 < Decimal(facts["accepted_amount"]) <= Decimal(data["contract_value"]), "ACCEPTANCE_EXCEEDS_QUOTE", "accepted value must be positive and no greater than the issued quote", "manual_reconciliation")
            data.update({key: value for key, value in facts.items() if key not in {"quote_ref", "customer_ref", "currency"}})
        elif event == "take_deposit":
            facts = _deposit_facts(r.deposit_read, r.deposit_quote_ref)
            require(facts["quote_ref"] == data["quote_ref"] and facts["currency"] == plan.currency and parsed(data["accepted_at"]) <= parsed(facts["observed_at"]) <= parsed(at), "DEPOSIT_NOT_OBSERVED", "deposit must bind the accepted quote, currency and payment window")
            require(Decimal(facts["deposit_amount"]) <= Decimal(data["accepted_amount"]), "DEPOSIT_EXCEEDS_QUOTE", "deposit cannot exceed accepted quote value")
            data.update({key: value for key, value in facts.items() if key not in {"quote_ref", "currency", "observed_at"}})
        elif event == "execute":
            require(r.custody_candidate is not None, "EXECUTION_UNSIGNED", "retain the signed custody candidate")
            execute_receipt(r.custody_candidate)
            source = r.custody_candidate
            require(source["scope"]["commercial"]["currency"] == plan.currency, "EXECUTION_UNSIGNED", "signed custody currency must equal the accepted quote")
            require(source["customer_ref"] == data["customer_ref"] and source["quote_ref"] == data["quote_ref"] and all(str(source["scope"]["commercial"][key]) == str(data[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")) and parsed(data["accepted_at"]) <= parsed(source["executed_at"]) <= parsed(at), "EXECUTION_UNSIGNED", "custody must bind the exact accepted quote and company scope")
            require(Decimal(data["deposit_amount"]) >= (Decimal(data["accepted_amount"]) * plan.deposit_percent / 100).quantize(MONEY_QUANTUM), "DEPOSIT_NOT_OBSERVED", "execution requires the policy's observed deposit")
            data.update({"contract_ref": source["contract_ref"], "agreement_ref": f"agreement:{source['contract_ref']}:{source['agreement_version']}", "custody_candidate_digest": source["custody_candidate_digest"], "outcome": "executed"})
        elif event == "expire":
            require(parsed(at) > parsed(data["valid_until"]), "QUOTE_EXPIRED", "quote has not reached its expiry")
            data["outcome"] = "expired"
        elif event in {"withdraw", "require_reconciliation"}:
            data["outcome"] = next_status
    except DealDeskError as exc:
        raise Rejected(exc.code, exc.message, "manual_reconciliation" if exc.code == "DISCOUNT_APPROVAL_MISMATCH" else "correct_input") from exc
    return next_status, data


_TABLE = {("new", "configure"): "configured", ("configured", "price"): "priced", ("priced", "request_discount_approval"): "discount_review", ("discount_review", "approve_discount"): "approved", ("priced", "issue_quote"): "quoted", ("approved", "issue_quote"): "quoted", ("quoted", "revise"): "priced", ("quoted", "accept"): "accepted", ("accepted", "take_deposit"): "deposit_held", ("accepted", "execute"): "executed", ("deposit_held", "execute"): "executed", ("quoted", "expire"): "expired", **{(s, "withdraw"): "withdrawn" for s in ("configured", "priced", "discount_review", "quoted", "accepted")}, **{(s, "require_reconciliation"): "reconciliation_required" for s in ("accepted", "deposit_held")}}
DEAL_DESK_LIFECYCLE = LifecycleSpec(entity="deal", schema_prefix="deal_desk", statuses=DEAL_STATUSES, terminal=TERMINAL_DEAL_STATUSES, events=DEAL_EVENTS, table=_TABLE, opening_event="configure", reason_events=("withdraw", "require_reconciliation"), apply=_apply_deal, ledger_model=DealLedger, receipt_model=DealReceipt, effect_boundary_model=DealEffectBoundary, plan_model=DealDeskPlan, max_transitions=32)
DealState, DealCommand, DealTransitionResult = DEAL_DESK_LIFECYCLE.State, DEAL_DESK_LIFECYCLE.Command, DEAL_DESK_LIFECYCLE.TransitionResult


def open_deal(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    from lightbulb.company_engine_core import EngineScope
    policy, bound = _read(DealDeskPlan, plan), _read(EngineScope, scope)
    _require(bound.company_ref in {policy.company_ref, "selected"} and policy.currency == bound.currency, "DEAL_SCOPE_MISMATCH", "plan must match the scoped company or selected company alias and currency")
    return DEAL_DESK_LIFECYCLE.open(policy, bound, receipt={**dict(detached(receipt)), "scope_binding": bound.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_deal(plan: Any, state: Any, command: Any) -> Any:
    return DEAL_DESK_LIFECYCLE.advance(plan, state, command)


def _state(state: Any, source_plan: Any) -> tuple[Any, Any]:
    try:
        plan, source = DEAL_DESK_LIFECYCLE.bind(source_plan, state)
    except (ValueError, TypeError) as exc:
        raise DealDeskError("DEAL_SOURCE_INVALID", "deal evidence requires the replayable original state and plan") from exc
    _require(all(getattr(source.scope, key) == getattr(source.ledger, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "entity_ref")) and source.scope.company_ref in {plan.company_ref, "selected"} and source.scope.currency == plan.currency, "DEAL_SCOPE_MISMATCH", "source plan, ledger and state scope must agree")
    return plan, source


def discount_approval_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, source = _state(state, source_plan)
    _require(source.status == "discount_review", "DISCOUNT_APPROVAL_MISMATCH", "pricing must be awaiting its exact review")
    return {"pricing_digest": source.ledger.pricing_digest, "approved_discount_ratio": str(source.ledger.discount_ratio), "evidence_refs": [f"pricing:{source.ledger.pricing_digest[:16]}"]}


def accepted_value_binding(state: Any, *, source_plan: Any, delivery_binding: Any = None, delivery_provenance: Any = None, delivery_observation: Any = None) -> dict[str, Any]:
    """Project executed deal value; optional delivery acceptance remains its own artifact.

    Quote acceptance does not fabricate a contract-delivery AcceptedValueBinding.
    The retained delivery binding, when supplied, must agree with this contract.
    """
    plan, source = _state(state, source_plan)
    _require(source.status == "executed", "EXECUTION_UNSIGNED", "accepted value must be bound to the executed contract")
    out = {"contract_ref": source.ledger.contract_ref, "contract_value": str(source.ledger.contract_value), "accepted_amount": str(source.ledger.accepted_amount), "acceptance_ref": source.ledger.acceptance_ref, "agreement_ref": source.ledger.agreement_ref, "source_state": source.to_dict(), "source_plan": plan.to_dict(), "source_digest": source.state_digest}
    _require(delivery_binding is None or delivery_observation is None, "ACCEPTANCE_UNEVIDENCED", "supply exactly one delivery acceptance source")
    if delivery_binding is not None:
        from lightbulb.contract_delivery_acceptance import AcceptedValueBinding
        delivery = _read(AcceptedValueBinding, delivery_binding, "ACCEPTANCE_UNEVIDENCED")
        from lightbulb.wip_billing import delivery_acceptance_projection
        delivery_observation = {"provenance": detached(delivery_provenance), "payload": delivery_acceptance_projection(delivery)}
    if delivery_observation is not None:
        # The existing binding contains raw workflow identities. The host
        # attests its portable projection while preserving its original digest.
        from lightbulb.wip_billing import _acceptance
        observed = _acceptance(delivery_observation)
        delivery = observed.payload
        custody = source.transition_history[-1].command.receipt.custody_candidate
        _require(delivery["agreement_digest"] == custody["executed_agreement_digest"] and delivery["custody_candidate_digest"] == source.ledger.custody_candidate_digest and delivery["currency"] == plan.currency and Decimal(delivery["accepted_amount"]) <= source.ledger.accepted_amount, "ACCEPTANCE_EXCEEDS_QUOTE", "delivery acceptance must belong to this signed contract and remain within accepted quote value")
        _require(all(str(delivery["scope"][key]) == str(getattr(source.scope, key)) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "DEAL_SCOPE_MISMATCH", "delivery acceptance must share the deal's tenant and project")
        out["delivery_observation"] = observed.to_dict()
        out["agreement_ref"] = delivery["agreement_ref"]
        out["accepted_amount"] = str(decimal_value(delivery["accepted_amount"], field_name="delivered accepted amount"))
        out["acceptance_ref"] = delivery["acceptance_reference"]
    out["binding_digest"] = stable_digest(out)
    return out


def verify_accepted_value_binding(binding: Any, *, contract_ref: str | None = None, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None) -> dict[str, Any]:
    raw = dict(detached(binding))
    derived = accepted_value_binding(raw.get("source_state"), source_plan=raw.get("source_plan"), delivery_observation=raw.get("delivery_observation"))
    _require(raw == derived, "ACCEPTANCE_UNEVIDENCED", "accepted amounts must reproduce the retained source deal and optional delivery binding")
    plan, source = _state(derived["source_state"], derived["source_plan"])
    _require((contract_ref is None or contract_ref == source.ledger.contract_ref) and (company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency), "DEAL_SCOPE_MISMATCH", "accepted value belongs to another contract, company or currency")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(scope.get(key) == getattr(source.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "DEAL_SCOPE_MISMATCH", "accepted value belongs to another tenant/project scope")
    return derived


class EngagementBudget(StrictModel):
    schema_id: Literal["lightbulb.engagement_budget.v1"] = Field(default="lightbulb.engagement_budget.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    deal_ref: OpaqueRef
    customer_ref: OpaqueRef
    contract_ref: OpaqueRef | None = None
    source_status: ShortText
    subtotal: Decimal
    contract_value: Decimal
    accepted_amount: Decimal
    cost_budget: Decimal
    margin_percent: Decimal
    lines: tuple[dict[str, Any], ...]
    source_state: dict[str, Any]
    source_plan: dict[str, Any]
    source_digest: Sha256Digest
    budget_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("contract_value", "subtotal", "accepted_amount", "cost_budget", "margin_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=info.field_name == "margin_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> Any:
        if not skip_digests(info) and self.budget_digest != sealed_digest(type(self), self, "budget_digest"):
            raise ValueError("budget_digest must commit exact executed-deal economics")
        return self


def engagement_budget(state: Any, *, source_plan: Any) -> EngagementBudget:
    plan, source = _state(state, source_plan)
    _require(source.status in {"priced", "approved", "quoted", "accepted", "deposit_held", "executed"}, "SCOPE_UNPRICED", "engagement baseline requires actual priced scope; delivery independently verifies signed paper")
    values = {key: getattr(source.ledger, key) for key in ("customer_ref", "contract_ref", "subtotal", "contract_value", "accepted_amount", "cost_budget", "margin_percent", "lines")}
    return seal(EngagementBudget, {"company_ref": plan.company_ref, "currency": plan.currency, "deal_ref": source.scope.entity_ref, "source_status": source.status, **values, "source_state": source.to_dict(), "source_plan": plan.to_dict(), "source_digest": source.state_digest}, "budget_digest")


def verify_engagement_budget(value: Any, *, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None) -> EngagementBudget:
    budget = _read(EngagementBudget, value)
    derived = engagement_budget(budget.source_state, source_plan=budget.source_plan)
    _require(derived == budget, "DEAL_SOURCE_INVALID", "engagement budget numbers must reproduce the executed deal")
    plan, source = _state(budget.source_state, budget.source_plan)
    _require((company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency), "DEAL_SCOPE_MISMATCH", "budget belongs to another company or currency")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(scope.get(key) == getattr(source.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "DEAL_SCOPE_MISMATCH", "budget belongs to another tenant or project")
    return budget


def deposit_evidence(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """Retain the observed deposit for an invoice-correlation host handoff.

    A quote deposit alone does not assert that any invoice has been paid or
    that cash has settled in the bank; those remain revenue-chain observations.
    """
    plan, source = _state(state, source_plan)
    _require(source.ledger.deposit_amount > 0, "DEPOSIT_NOT_OBSERVED", "the deal has no observed deposit")
    original_receipt = next(step.command.receipt for step in source.transition_history if step.command.event == "take_deposit")
    original = original_receipt.deposit_read
    result = {**_deposit_facts(original, original_receipt.deposit_quote_ref), "source_state": source.to_dict(), "source_plan": plan.to_dict(), "source_digest": source.state_digest, "deposit_read": original}
    return {**result, "evidence_digest": stable_digest(result)}


def verify_deposit_evidence(value: Any, *, company_ref: str, currency: str, expected_scope: Any = None) -> dict[str, Any]:
    raw = dict(detached(value))
    derived = deposit_evidence(raw.get("source_state"), source_plan=raw.get("source_plan"))
    _require(raw == derived, "DEPOSIT_NOT_OBSERVED", "deposit evidence must reproduce the original source read and deal")
    plan, source = _state(raw["source_state"], raw["source_plan"])
    _require(plan.company_ref == company_ref and plan.currency == currency, "DEAL_SCOPE_MISMATCH", "deposit belongs to another company or currency")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(scope.get(key) == getattr(source.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "DEAL_SCOPE_MISMATCH", "deposit belongs to another tenant or project")
    return derived


def deals(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, source = _state(state, source_plan)
    return {"status": source.status, "state_digest": source.state_digest, **source.ledger.to_dict()}


def quotes(state: Any, *, source_plan: Any) -> dict[str, Any]:
    return deals(state, source_plan=source_plan)


def price_book(book: Any) -> dict[str, Any]:
    return _book(book).to_dict()


def deal_quoted_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    _, source = _state(state, source_plan)
    _require(source.status == "quoted", "QUOTE_NOT_ISSUED", "emit from the actual quoted transition")
    _require(parsed(emitted_at) >= parsed(source.ledger.issued_at), "QUOTE_NOT_ISSUED", "signal cannot precede issuance")
    return {"name": "signals.deal_quoted", "producer": DEAL_DESK_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"deal_ref": source.scope.entity_ref, "quote_ref": source.ledger.quote_ref, "contract_value": str(source.ledger.contract_value), "deal_state_digest": source.state_digest}}


def deal_executed_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    _, source = _state(state, source_plan)
    value = accepted_value_binding(source, source_plan=source_plan)
    _require(parsed(emitted_at) >= parsed(source.transition_history[-1].command.occurred_at), "EXECUTION_UNSIGNED", "signal cannot precede execution")
    return {"name": "signals.deal_executed", "producer": DEAL_DESK_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"deal_ref": source.scope.entity_ref, "contract_ref": value["contract_ref"], "accepted_amount": value["accepted_amount"], "deal_state_digest": source.state_digest}}


def discount_band_samples(states: Sequence[Any], *, source_plan: Any, archetype: str, observed_at: str) -> list[dict[str, Any]]:
    result = []
    for state in states:
        _, source = _state(state, source_plan)
        if source.status not in {"executed", "expired", "withdrawn"}:
            continue
        _require(parsed(observed_at) >= parsed(source.transition_history[-1].command.occurred_at), "DEAL_SOURCE_INVALID", "sample observation cannot precede the outcome")
        band = int(source.ledger.discount_ratio * 100 // 5) * 5
        result.append({"key": f"discount_band:{band}", "archetype": archetype, "engine": DEAL_DESK_KIND, "metric": "deal_win_rate_percent", "value": "100.000000" if source.status == "executed" else "0.000000", "source_engine": DEAL_DESK_KIND, "source_ref": source.scope.entity_ref, "source_state_digest": source.state_digest, "observed_at": timestamp(observed_at, field_name="observed_at")})
    return result


deal_summary = deals
price_book_summary = price_book



DEAL_DESK_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": DEAL_DESK_KIND, "golden_loop": DEAL_DESK_GOLDEN_LOOP, "stages": ["configure", "price", "approve", "quote", "accept", "execute"], "statuses": list(DEAL_STATUSES), "events": list(DEAL_EVENTS), "hops": ["provider book -> priced configuration", "pricing authority -> confirmed quote", "explicit acceptance + signatures -> bound contract value"], "required_connectors": ["xero", "quickbooks", "gmail", "microsoft", "docusign", "square", "stripe", "ecommerce"], "missing_reads": ["provider item, tax and terms reads remain host-lane observations", "host.commercial_configuration_snapshot is required when no sealed commercial lifecycle is supplied", "host.classify_quote_acceptance binds explicit acceptance interpretation to the governed thread", "host.partner_deal_registration retains external registration evidence"], "hard_rules": ["a price comes from a sealed book that was read, never typed", "a discount above the threshold is an authorized decision with a limit, not a note", "quoted means the provider holds a quote we can read back", "acceptance is the counterparty's own words or signature, classified with confidence, never inferred", "quote acceptance does not fabricate delivery acceptance", "engine ledgers are replayed using their retained source plans"]}

__all__ = ["DEAL_DESK_KIND", "DEAL_DESK_GOLDEN_LOOP", "DEAL_DESK_PLAN_SCHEMA", "DEAL_DESK_MANIFEST", "DEAL_STATUSES", "DEAL_EVENTS", "TERMINAL_DEAL_STATUSES", "DEAL_DESK_LIFECYCLE", "MAX_REVISIONS", "MISSING_GOVERNED_READS", "CUSTODY_CANDIDATE_SCHEMA", "DealDeskError", "DealDeskPlan", "ReadEvidence", "BookLine", "PriceBook", "OperatorRateCard", "DealReceipt", "DealLedger", "DealEffectBoundary", "DealState", "DealCommand", "DealTransitionResult", "EngagementBudget", "compile_deal_desk", "price_book_receipt", "rate_card_receipt", "configuration_receipt", "prospect_receipt", "discount_approval_receipt", "quote_receipt", "acceptance_receipt", "deposit_receipt", "execute_receipt", "allocation_receipt", "partner_registration_receipt", "open_deal", "advance_deal", "accepted_value_binding", "verify_accepted_value_binding", "engagement_budget", "verify_engagement_budget", "deposit_evidence", "verify_deposit_evidence", "deals", "quotes", "price_book", "deal_summary", "price_book_summary", "deal_quoted_signal", "deal_executed_signal", "discount_band_samples"]
