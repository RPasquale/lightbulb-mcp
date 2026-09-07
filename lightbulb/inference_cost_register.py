"""Inference cost register: the provider's own money as the second party to the platform's metering.

Every cost figure the platform holds is a price-catalog quote: tokens times a catalog rate,
snapshotted before the provider boundary. This module receives what the provider itself says,
either a governed cost read (``anthropic_admin.get_cost_report``, ``openai_admin.get_costs``,
``google_cloud_billing.query_ai_costs``) sealed as ``ObservationProvenance``, or an operator
invoice that names itself as one, reconciles it against metered cost with exactly the rejection
codes the platform uses, and lands the reconciled statement in the operating period the way a paid
supplier bill does.

Where a provider exposes no usable usage or cost API (xAI, and any OpenAI-compatible endpoint)
``PROVIDER_COST_SOURCES`` is an empty tuple. That is not a comment: a statement naming a source
tool outside its provider's tuple is ``LANE_SOURCE_MISMATCH``, so "do not invent an endpoint" is
structural. The SDK reads nothing and writes nothing; every figure here arrives sealed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    EngineScope,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    stable_digest,
)
from lightbulb.company_execution_bridge import ObservationProvenance

INFERENCE_COST_KIND = "lightbulb.inference_cost"
OBSERVATION_SCHEMA = "lightbulb.inference_cost_observation.v1"
STATEMENT_SCHEMA = "lightbulb.inference_cost_statement.v1"
OPERATOR_INVOICE_SCHEMA = "lightbulb.inference_cost_operator_invoice.v1"
METERED_SCHEMA = "lightbulb.inference_metered_cost.v1"
RECONCILIATION_SCHEMA = "lightbulb.inference_cost_reconciliation.v1"
REGISTER_SCHEMA = "lightbulb.inference_cost_register.v1"

InferenceProvider = Literal["anthropic", "openai", "gemini", "vertex_ai", "xai", "openai_compatible"]
InferenceCostSource = Literal["provider_usage_api", "provider_cost_api", "cloud_billing_export", "operator_statement"]
CostLane = Literal["governed_read", "billing_export", "operator_invoice"]
Basis = Literal["direct", "metered_proportional", "stated_share"]
Verdict = Literal["WITHIN_TOLERANCE", "VARIANCE_EXCEEDED", "METERING_INCOMPLETE", "SKU_UNMAPPED", "WINDOW_MISALIGNED", "CURRENCY_MISMATCH"]
Disposition = Literal["register", "manual_reconciliation", "await_metering", "reject"]

# Which lane each provider's money travels on. The lane is a property of the provider, not of the caller.
PROVIDER_COST_LANES: Mapping[str, CostLane] = {
    "anthropic": "governed_read",
    "openai": "governed_read",
    "gemini": "billing_export",
    "vertex_ai": "billing_export",
    "xai": "operator_invoice",
    "openai_compatible": "operator_invoice",
}
# The exact tools that may speak for a provider. An EMPTY tuple forces the operator lane.
PROVIDER_COST_SOURCES: Mapping[str, tuple[str, ...]] = {
    "anthropic": ("anthropic_admin.get_cost_report", "anthropic_admin.get_usage_report"),
    "openai": ("openai_admin.get_costs", "openai_admin.get_usage"),
    "gemini": ("google_cloud_billing.query_ai_costs",),
    "vertex_ai": ("google_cloud_billing.query_ai_costs",),
    "xai": (),
    "openai_compatible": (),
}
# Only a cost read or a billing export is a bill; a usage read is priced externally and never becomes a statement.
STATEMENT_TOOLS: Mapping[str, InferenceCostSource] = {
    "anthropic_admin.get_cost_report": "provider_cost_api",
    "openai_admin.get_costs": "provider_cost_api",
    "google_cloud_billing.query_ai_costs": "cloud_billing_export",
}
USAGE_TOOLS: tuple[str, ...] = ("anthropic_admin.get_usage_report", "openai_admin.get_usage")
# The platform's provider spellings (AiProvider) to this module's.
PROVIDER_CODES: Mapping[str, str] = {"ANTHROPIC": "anthropic", "OPENAI": "openai", "GEMINI": "gemini", "VERTEX_AI": "vertex_ai", "XAI": "xai"}
SOURCE_CODES: Mapping[str, InferenceCostSource] = {"PROVIDER_USAGE_API": "provider_usage_api", "PROVIDER_COST_API": "provider_cost_api", "CLOUD_BILLING_EXPORT": "cloud_billing_export"}

# Cross-boundary parity: the platform register emits exactly these codes for the same inputs.
REJECTION_CODES: tuple[str, ...] = (
    "AI_COST_VARIANCE_EXCEEDED",
    "AI_COST_METERING_INCOMPLETE",
    "AI_COST_STATEMENT_WINDOW_MISALIGNED",
    "AI_COST_CURRENCY_MISMATCH",
    "AI_COST_STATEMENT_DUPLICATE",
    "AI_COST_SKU_UNMAPPED",
    "AI_COST_PRICE_CATALOG_VERSION_MISSING",
)
DEFAULT_TOLERANCE_RATIO = Decimal("0.02")
GOOGLE_TOLERANCE_RATIO = Decimal("0.05")
DEFAULT_ABSOLUTE_FLOOR_MICROS = 5_000_000
UNATTRIBUTED = "unattributed"
METERING_CURRENCY = "USD"
MAX_REGISTER_LINES = 500
_ENGINES: tuple[str, ...] = ("growth_engine", "pipeline_engine", "saas_operating_engine", "finance_close", "service_delivery", "people_engine", "marketplace_supply_engine", "engagement_engine")
_MIDNIGHT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_MICRO = Decimal(1_000_000)
_RATIO_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.000001")


class InferenceCostError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise InferenceCostError(code, message)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _aligned(value: str) -> bool:
    return bool(_MIDNIGHT.match(value))


def _micros_to_money(micros: int) -> Decimal:
    return (Decimal(micros) / _MICRO).quantize(_MONEY_QUANTUM)


def tolerance_for(provider: str) -> Decimal:
    return GOOGLE_TOLERANCE_RATIO if provider in ("gemini", "vertex_ai") else DEFAULT_TOLERANCE_RATIO


# --------------------------------------------------------------------------- #
# Statements: a governed read, or an operator invoice that names itself
# --------------------------------------------------------------------------- #


class OperatorInvoiceReceipt(StrictModel):
    """The explicit operator input: it names itself, it names who attested it, and it can never carry a read's authority."""

    schema_id: str = Field(default=OPERATOR_INVOICE_SCHEMA, alias="schema")
    input_kind: Literal["operator_supplied_invoice"]
    provider: InferenceProvider
    window_start: str
    window_end: str
    currency: str
    invoice_total_micros: int = Field(ge=0)
    document_sha256: Sha256Digest
    attested_by_ref: OpaqueRef
    attested_at: str
    attestation: BoundedText
    receipt_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end", "attested_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        if not _CURRENCY.match(value):
            raise ValueError("currency must be an ISO 4217 code")
        return value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorInvoiceReceipt:
        if parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("OPERATOR_RECEIPT_WINDOW_INVALID: window_end must follow window_start")
        if not self.attestation.strip():
            raise ValueError("OPERATOR_RECEIPT_UNATTESTED: the operator attests the figure in their own words")
        if not skip_digests(info) and self.receipt_digest != sealed_digest(OperatorInvoiceReceipt, self, "receipt_digest"):
            raise ValueError("receipt_digest must commit the exact operator invoice")
        return self


def operator_invoice_receipt(payload: Mapping[str, Any] | Any) -> OperatorInvoiceReceipt:
    """Seal an operator invoice; a payload carrying any read provenance is refused before validation."""

    data = dict(detached(payload))
    for key in ("provenance_digest", "observation_ref", "source_tool", "output_digest", "evidence_sha256"):
        _require(key not in data, "OPERATOR_STATEMENT_CLAIMS_PROVENANCE", f"an operator invoice cannot carry {key}; an operator cannot borrow a read's authority")
    _require(data.get("input_kind") == "operator_supplied_invoice", "OPERATOR_INPUT_KIND_REQUIRED", "an operator invoice declares input_kind = operator_supplied_invoice")
    for key in ("attested_by_ref", "attested_at", "attestation"):
        _require(bool(str(data.get(key) or "").strip()), "OPERATOR_RECEIPT_UNATTESTED", f"an operator invoice names {key}")
    try:
        start, end = timestamp(str(data.get("window_start")), field_name="window_start"), timestamp(str(data.get("window_end")), field_name="window_end")
    except Exception as invalid:  # noqa: BLE001
        raise InferenceCostError("OPERATOR_RECEIPT_WINDOW_INVALID", str(invalid)) from invalid
    _require(parsed(end) > parsed(start) and _aligned(start) and _aligned(end), "OPERATOR_RECEIPT_WINDOW_INVALID", "the invoice window is whole UTC days with window_end after window_start")
    try:
        return seal(OperatorInvoiceReceipt, data, "receipt_digest")
    except InferenceCostError:
        raise
    except Exception as invalid:  # noqa: BLE001
        text = str(invalid)
        for code in ("OPERATOR_RECEIPT_WINDOW_INVALID", "OPERATOR_RECEIPT_UNATTESTED"):
            if code in text:
                raise InferenceCostError(code, text) from invalid
        raise InferenceCostError("OPERATOR_RECEIPT_INVALID", text) from invalid


class ProviderStatement(StrictModel):
    """One provider figure for one window, with exactly one provenance: a read's digest, or an operator receipt's digest."""

    schema_id: str = Field(default=STATEMENT_SCHEMA, alias="schema")
    provider: InferenceProvider
    source: InferenceCostSource
    lane: CostLane
    source_tool: ShortText | None = None
    window_start: str
    window_end: str
    currency: Literal["USD"] = "USD"
    statement_micros: int = Field(ge=0)
    original_currency: str
    original_micros: int = Field(ge=0)
    usd_rate: Decimal | None = None
    evidence_ref: OpaqueRef
    provenance_digest: Sha256Digest | None = None
    receipt_digest: Sha256Digest | None = None
    observation_output: dict[str, Any] | None = None
    observation_provenance: ObservationProvenance | None = None
    operator_receipt: OperatorInvoiceReceipt | None = None
    statement_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @field_validator("usd_rate", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProviderStatement:
        if self.source == "operator_statement":
            if self.provenance_digest is not None or self.receipt_digest is None or self.source_tool is not None:
                raise ValueError("an operator statement carries its receipt digest and never a read provenance")
            if self.lane != "operator_invoice":
                raise ValueError("an operator statement travels on the operator_invoice lane")
        else:
            if self.provenance_digest is None or self.receipt_digest is not None or self.source_tool is None:
                raise ValueError("a read statement carries its provenance digest and never an operator receipt")
            if self.source_tool not in PROVIDER_COST_SOURCES[self.provider]:
                raise ValueError(f"LANE_SOURCE_MISMATCH: {self.source_tool} does not speak for {self.provider}")
            if self.lane != PROVIDER_COST_LANES[self.provider]:
                raise ValueError(f"{self.provider} money travels on the {PROVIDER_COST_LANES[self.provider]} lane")
        if parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("window_end must follow window_start")
        if self.original_currency != "USD" and self.usd_rate is None:
            raise ValueError("RATE_REQUIRED: a non-USD statement carries the usd_rate it was converted at")
        if not skip_digests(info) and self.statement_digest != sealed_digest(ProviderStatement, self, "statement_digest"):
            raise ValueError("statement_digest must commit the exact statement")
        return self


def statement_from_observation(provenance: ObservationProvenance | Mapping[str, Any] | Any, output: Mapping[str, Any] | Any) -> ProviderStatement:
    """A sealed governed cost read becomes a statement; a usage read never does."""

    sealed = ObservationProvenance.model_validate(detached(provenance))
    payload = dict(detached(output))
    _require(payload.get("schema") == OBSERVATION_SCHEMA, "OBSERVATION_SCHEMA_MISMATCH", f"expected {OBSERVATION_SCHEMA}, got {payload.get('schema')}")
    provider = PROVIDER_CODES.get(str(payload.get("provider")))
    _require(provider is not None, "PROVIDER_UNKNOWN", f"{payload.get('provider')} is not a provider this register knows")
    assert provider is not None
    tool = str(sealed.source_tool)
    _require(tool in PROVIDER_COST_SOURCES[provider], "LANE_SOURCE_MISMATCH", f"{provider} costs never come from {tool}; its lane is {PROVIDER_COST_LANES[provider]}")
    _require(tool in STATEMENT_TOOLS and payload.get("priced_externally") is False, "USAGE_READ_IS_NOT_A_BILL", f"{tool} is priced externally; a usage read is not a statement")
    source = STATEMENT_TOOLS[tool]
    _require(SOURCE_CODES.get(str(payload.get("source"))) == source, "SOURCE_MISMATCH", f"the observation names source {payload.get('source')}, the tool implies {source}")
    _require(payload.get("exhaustive_read") is True and payload.get("truncated") is False, "OBSERVATION_NOT_EXHAUSTIVE", "a truncated cost read is not a statement; narrow the window")
    totals = payload.get("totals") if isinstance(payload.get("totals"), Mapping) else {}
    micros = int(totals.get("cost_micros", -1))
    _require(micros >= 0, "STATEMENT_AMOUNT_INVALID", "totals.cost_micros is a non-negative integer")
    currency = str(payload.get("currency") or "")
    _require(currency == METERING_CURRENCY, "RATE_REQUIRED", f"a {currency} read cannot be reconciled without a rate; record it as an operator statement with usd_rate")
    _require(sealed.lane == "governed_read", "LANE_SOURCE_MISMATCH", "provider statements require a governed cost read")
    _require(stable_digest(payload) == sealed.output_digest, "OBSERVATION_DIGEST_MISMATCH", "the statement must use the exact retained provider output")
    _require(parsed(sealed.completed_at) >= parsed(str(payload.get("window_end"))), "OBSERVATION_TOO_EARLY", "a completed cost window cannot follow the read")
    for key in ("window_start", "window_end"):
        bound = getattr(sealed, key)
        _require(bound is None or bound == payload.get(key), "OBSERVATION_WINDOW_MISMATCH", "the cost window must match its read provenance")
    return seal(ProviderStatement, {"observation_output": payload, "observation_provenance": sealed.to_dict(), "provider": provider, "source": source, "lane": PROVIDER_COST_LANES[provider], "source_tool": tool, "window_start": str(payload.get("window_start")), "window_end": str(payload.get("window_end")), "currency": "USD", "statement_micros": micros, "original_currency": currency, "original_micros": micros, "usd_rate": None, "evidence_ref": f"observation:{sealed.observation_ref}", "provenance_digest": sealed.provenance_digest, "receipt_digest": None}, "statement_digest")


def statement_from_operator_invoice(receipt: OperatorInvoiceReceipt | Mapping[str, Any] | Any, *, usd_rate: Any = None) -> ProviderStatement:
    """An operator invoice becomes a statement on the operator lane, converted to USD micros at the stated rate."""

    sealed = receipt if isinstance(receipt, OperatorInvoiceReceipt) else operator_invoice_receipt(receipt)
    rate = None if usd_rate is None else Decimal(str(usd_rate))
    if sealed.currency != METERING_CURRENCY:
        _require(rate is not None and rate > 0, "RATE_REQUIRED", f"a {sealed.currency} invoice needs the usd_rate it converts at")
        assert rate is not None
        micros = int((Decimal(sealed.invoice_total_micros) * rate).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    else:
        micros = sealed.invoice_total_micros
    return seal(ProviderStatement, {"operator_receipt": sealed.to_dict(), "provider": sealed.provider, "source": "operator_statement", "lane": "operator_invoice", "source_tool": None, "window_start": sealed.window_start, "window_end": sealed.window_end, "currency": "USD", "statement_micros": micros, "original_currency": sealed.currency, "original_micros": sealed.invoice_total_micros, "usd_rate": None if sealed.currency == METERING_CURRENCY else str(rate), "evidence_ref": f"invoice:{sealed.receipt_digest[:24]}", "provenance_digest": None, "receipt_digest": sealed.receipt_digest}, "statement_digest")


# --------------------------------------------------------------------------- #
# The metered side
# --------------------------------------------------------------------------- #


class MeteredLine(StrictModel):
    model_key: ShortText
    cost_centre_ref: ShortText = UNATTRIBUTED
    cost_micros: int = Field(ge=0)
    price_catalog_version: ShortText | None = None


class MeteredCost(StrictModel):
    """The platform's quote for the same window: per model and cost centre, with the completeness the metering itself reports."""

    schema_id: str = Field(default=METERED_SCHEMA, alias="schema")
    provider: InferenceProvider
    window_start: str
    window_end: str
    currency: Literal["USD"] = "USD"
    lines: tuple[MeteredLine, ...] = Field(default_factory=tuple, max_length=2000)
    complete: bool = True
    unbound_events: int = Field(default=0, ge=0)
    source_ref: OpaqueRef
    scope: EngineScope | None = None
    company_ref: OpaqueRef | None = None
    host_observation: dict[str, Any] | None = None
    host_provenance: dict[str, Any] | None = None
    metered_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> MeteredCost:
        if self.host_observation is not None or self.host_provenance is not None:
            facts = _host_metered_facts(self.host_provenance, self.host_observation)
            _require(all(self.to_dict().get(key) == value for key,value in facts.items()),
                "METERING_SOURCE_MISMATCH", "metered allocations must replay their complete host source")
        if parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("window_end must follow window_start")
        if not skip_digests(info) and self.metered_digest != sealed_digest(MeteredCost, self, "metered_digest"):
            raise ValueError("metered_digest must commit the exact metered cost")
        return self

    @property
    def total_micros(self) -> int:
        return sum(line.cost_micros for line in self.lines)


def metered_cost(provider: str, *, window_start: str, window_end: str, lines: Sequence[Mapping[str, Any]], source_ref: str, complete: bool = True, unbound_events: int = 0, scope: Mapping[str, str] | EngineScope | None = None, company_ref: str | None = None) -> MeteredCost:
    return seal(MeteredCost, {"provider": provider, "window_start": window_start, "window_end": window_end, "currency": "USD", "lines": [dict(line) for line in lines], "complete": complete, "unbound_events": unbound_events, "source_ref": source_ref, "scope": detached(scope) if scope is not None else None, "company_ref": company_ref}, "metered_digest")


def _host_metered_facts(provenance, output):
    proof = ObservationProvenance.model_validate(detached(provenance))
    raw = dict(detached(output))
    _require(proof.lane == "host_read" and proof.source_tool == "lightbulb.ai_costs.metered"
        and proof.output_digest == stable_digest(raw), "METERING_SOURCE_MISMATCH", "retain the authenticated host metering response")
    _require(raw.get("schema") == "lightbulb.ai_metered_cost_observation.v1" and raw.get("currency") == "USD",
        "METERING_SOURCE_MISMATCH", "native metering has an explicit USD observation schema")
    digest = stable_digest({key:value for key,value in raw.items() if key not in ("evidence_sha256","observed_at")})
    _require(raw.get("evidence_sha256") == digest, "METERING_SOURCE_MISMATCH", "recompute the full metering evidence commitment")
    _require(parsed(raw["window_start"]) < parsed(raw["window_end"]) <= parsed(raw["observed_at"]) <= parsed(proof.completed_at),
        "METERING_WINDOW_INVALID", "the host observes metering only after the complete window")
    provider = PROVIDER_CODES.get(raw.get("provider"))
    _require(provider is not None,"PROVIDER_UNKNOWN","host provider must have a known metering lane")
    lines = [MeteredLine.model_validate(line).to_dict() for line in raw["lines"]]
    _require(type(raw.get("total_cost_micros")) is int and sum(line["cost_micros"] for line in lines) == raw["total_cost_micros"],
        "METERING_SOURCE_MISMATCH", "metered lines must conserve the host total")
    _require(type(raw.get("complete")) is bool and type(raw.get("unbound_events")) is int and raw["unbound_events"] >= 0,
        "METERING_SOURCE_MISMATCH", "host completeness is an explicit boolean with an exact unbound count")
    _require(not raw["complete"] or raw["unbound_events"] == 0 and all(line.get("price_catalog_version") for line in lines),
        "METERING_SOURCE_MISMATCH", "unbound or unpriced metering cannot be complete")
    return {"provider":provider,"window_start":raw["window_start"],"window_end":raw["window_end"],"currency":"USD",
        "lines":lines,"complete":raw["complete"],"unbound_events":raw["unbound_events"],"source_ref":"metered:"+digest}


def metered_from_host(provenance, output, *, scope, company_ref, tenant_commitment, company_commitment):
    """Bind the native authenticated cost export to the host-selected portable scope.

    Expected commitments come from the authenticated host context, not from an
    agent choosing the response's company. Full source bytes remain replayable.
    """
    raw = dict(detached(output))
    _require(raw.get("tenant_commitment") == tenant_commitment and raw.get("company_commitment") == company_commitment
        and re.fullmatch(r"[0-9a-f]{64}", str(tenant_commitment)) and re.fullmatch(r"[0-9a-f]{64}", str(company_commitment)),
        "SOURCE_SCOPE_MISMATCH", "metering must belong to the host-selected tenant and company")
    bound = EngineScope.model_validate(detached(scope))
    _require(bound.currency == "USD", "SOURCE_SCOPE_MISMATCH", "native metering cannot infer foreign exchange")
    return seal(MeteredCost,{**_host_metered_facts(provenance,raw),"scope":bound.to_dict(),"company_ref":company_ref,
        "host_observation":raw,"host_provenance":detached(provenance)},"metered_digest")


# --------------------------------------------------------------------------- #
# Reconciliation
# --------------------------------------------------------------------------- #


class ReconciliationVerdict(StrictModel):
    schema_id: str = Field(default=RECONCILIATION_SCHEMA, alias="schema")
    provider: InferenceProvider
    window_start: str
    window_end: str
    statement_micros: int = Field(ge=0)
    metered_micros: int = Field(ge=0)
    variance_micros: int
    variance_ratio: Decimal | None = None
    tolerance_ratio: Decimal
    absolute_floor_micros: int = Field(ge=0)
    verdict: Verdict
    rejection_code: str | None = None
    disposition: Disposition
    statement_digest: Sha256Digest
    metered_digest: Sha256Digest
    verdict_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("variance_ratio", "tolerance_ratio", mode="before")
    @classmethod
    def _ratios(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ReconciliationVerdict:
        if (self.verdict == "WITHIN_TOLERANCE") != (self.rejection_code is None):
            raise ValueError("a verdict outside tolerance carries its rejection code, and only then")
        if self.rejection_code is not None and self.rejection_code not in REJECTION_CODES:
            raise ValueError(f"{self.rejection_code} is not a register rejection code")
        if not skip_digests(info) and self.verdict_digest != sealed_digest(ReconciliationVerdict, self, "verdict_digest"):
            raise ValueError("verdict_digest must commit the exact verdict")
        return self


def reconcile_inference_cost(metered: MeteredCost | Mapping[str, Any] | Any, statement: ProviderStatement | Mapping[str, Any] | Any, *, tolerance_ratio: Any = None, absolute_floor_micros: int = DEFAULT_ABSOLUTE_FLOOR_MICROS) -> ReconciliationVerdict:
    """Metered versus statement, in the platform's order: window, currency, completeness, catalog, variance."""

    m = metered if isinstance(metered, MeteredCost) else MeteredCost.model_validate(dict(detached(metered)))
    s = verify_statement(statement)
    _require(m.provider == s.provider, "PROVIDER_MISMATCH", f"metered {m.provider} cannot reconcile a {s.provider} statement")
    tolerance = Decimal(str(tolerance_ratio)) if tolerance_ratio is not None else tolerance_for(s.provider)
    _require(tolerance.is_finite() and 0 <= tolerance <= 1 and absolute_floor_micros >= 0, "TOLERANCE_INVALID", "cost tolerances must be finite and nonnegative")
    statement_micros = s.statement_micros
    metered_micros = m.total_micros

    def verdict(kind: Verdict, code: str | None, disposition: Disposition, ratio: Decimal | None = None) -> ReconciliationVerdict:
        return seal(ReconciliationVerdict, {"provider": s.provider, "window_start": s.window_start, "window_end": s.window_end, "statement_micros": statement_micros, "metered_micros": metered_micros if kind in ("WITHIN_TOLERANCE", "VARIANCE_EXCEEDED") else 0, "variance_micros": statement_micros - (metered_micros if kind in ("WITHIN_TOLERANCE", "VARIANCE_EXCEEDED") else 0), "variance_ratio": None if ratio is None else str(ratio), "tolerance_ratio": str(tolerance), "absolute_floor_micros": absolute_floor_micros, "verdict": kind, "rejection_code": code, "disposition": disposition, "statement_digest": s.statement_digest, "metered_digest": m.metered_digest}, "verdict_digest")

    if not (_aligned(s.window_start) and _aligned(s.window_end)):
        return verdict("WINDOW_MISALIGNED", "AI_COST_STATEMENT_WINDOW_MISALIGNED", "reject")
    if (m.window_start, m.window_end) != (s.window_start, s.window_end):
        # the metering window is aligned to the statement window, never the reverse
        return verdict("WINDOW_MISALIGNED", "AI_COST_STATEMENT_WINDOW_MISALIGNED", "await_metering")
    if m.currency != s.currency:
        return verdict("CURRENCY_MISMATCH", "AI_COST_CURRENCY_MISMATCH", "reject")
    if not m.complete or m.unbound_events > 0:
        return verdict("METERING_INCOMPLETE", "AI_COST_METERING_INCOMPLETE", "await_metering")
    if any(line.price_catalog_version is None for line in m.lines):
        return verdict("METERING_INCOMPLETE", "AI_COST_PRICE_CATALOG_VERSION_MISSING", "await_metering")
    variance = abs(statement_micros - metered_micros)
    ratio = Decimal("0") if statement_micros == 0 and metered_micros == 0 else (Decimal("1") if statement_micros == 0 else (Decimal(variance) / Decimal(statement_micros)).quantize(_RATIO_QUANTUM, rounding=ROUND_HALF_UP))
    if variance <= absolute_floor_micros or ratio <= tolerance:
        return verdict("WITHIN_TOLERANCE", None, "register", ratio)
    return verdict("VARIANCE_EXCEEDED", "AI_COST_VARIANCE_EXCEEDED", "manual_reconciliation", ratio)


# --------------------------------------------------------------------------- #
# The register
# --------------------------------------------------------------------------- #


class InferenceCostLine(StrictModel):
    provider: InferenceProvider
    model_key: ShortText
    model_key_sha256: Sha256Digest
    cost_centre_ref: ShortText
    period_start: str
    period_end: str
    metered_micros: int = Field(ge=0)
    cost_micros: int = Field(ge=0)
    cost: Decimal
    basis: Basis
    source: InferenceCostSource
    evidence_ref: OpaqueRef
    provenance_digest: Sha256Digest | None = None

    @field_validator("cost", mode="before")
    @classmethod
    def _cost(cls, value: Any) -> Decimal:
        return Decimal(str(value))

    @model_validator(mode="after")
    def _guard(self) -> InferenceCostLine:
        if self.cost != _micros_to_money(self.cost_micros):
            raise ValueError("cost is exactly cost_micros in money")
        if self.model_key_sha256 != _sha256(self.model_key):
            raise ValueError("model_key_sha256 commits the model key")
        return self


class InferenceCostRegister(StrictModel):
    schema_id: str = Field(default=REGISTER_SCHEMA, alias="schema")
    provider: InferenceProvider
    period_start: str
    period_end: str
    currency: Literal["USD"] = "USD"
    lines: tuple[InferenceCostLine, ...] = Field(default_factory=tuple, max_length=MAX_REGISTER_LINES)
    total: Decimal
    total_micros: int = Field(ge=0)
    unattributed: Decimal
    verdict_digest: Sha256Digest
    statement_digest: Sha256Digest
    source_statement: ProviderStatement
    source_metered: MeteredCost
    source_verdict: ReconciliationVerdict
    register_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total", "unattributed", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return Decimal(str(value))

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> InferenceCostRegister:
        summed = sum((line.cost_micros for line in self.lines), 0)
        if summed != self.total_micros or self.total != _micros_to_money(self.total_micros):
            raise ValueError(f"REGISTER_TOTAL_MISMATCH: lines sum to {summed} micros, the register claims {self.total_micros}")
        unattributed = sum((line.cost_micros for line in self.lines if line.cost_centre_ref == UNATTRIBUTED), 0)
        if self.unattributed != _micros_to_money(unattributed):
            raise ValueError("unattributed is exactly the unattributed lines")
        if not skip_digests(info) and self.register_digest != sealed_digest(InferenceCostRegister, self, "register_digest"):
            raise ValueError("register_digest must commit the exact register")
        return self

    def spend_for(self, cost_centre_ref: str) -> Decimal:
        return _micros_to_money(sum((line.cost_micros for line in self.lines if line.cost_centre_ref == cost_centre_ref), 0))


def allocate(statement_micros: int, metered: Sequence[tuple[str, str, int]]) -> list[tuple[str, str, int, int]]:
    """Largest-remainder apportionment of the statement across (model, centre) by metered share; the parts sum exactly."""

    total = sum(micros for _, _, micros in metered)
    if statement_micros == 0 and total == 0:
        return []
    if total == 0:
        return [(UNATTRIBUTED, UNATTRIBUTED, 0, statement_micros)]
    floors: list[tuple[str, str, int, int]] = []
    remainders: list[Decimal] = []
    allocated = 0
    for model_key, centre, micros in metered:
        exact = Decimal(statement_micros) * Decimal(micros) / Decimal(total)
        floor = int(exact.quantize(Decimal("1"), rounding=ROUND_FLOOR))
        floors.append((model_key, centre, micros, floor))
        remainders.append(exact - floor)
        allocated += floor
    leftover = statement_micros - allocated
    order = sorted(range(len(floors)), key=lambda index: (-remainders[index], index))
    result = list(floors)
    for index in order[:leftover]:
        model_key, centre, micros, share = result[index]
        result[index] = (model_key, centre, micros, share + 1)
    return result


def build_register(verdict: ReconciliationVerdict | Mapping[str, Any] | Any, metered: MeteredCost | Mapping[str, Any] | Any, statement: ProviderStatement | Mapping[str, Any] | Any) -> InferenceCostRegister:
    """Only a WITHIN_TOLERANCE verdict for exactly these two artifacts becomes register lines."""

    v = verdict if isinstance(verdict, ReconciliationVerdict) else ReconciliationVerdict.model_validate(dict(detached(verdict)))
    m = metered if isinstance(metered, MeteredCost) else MeteredCost.model_validate(dict(detached(metered)))
    s = verify_statement(statement)
    _require(v.verdict == "WITHIN_TOLERANCE", "EVIDENCE_FROM_UNRECONCILED_COST", f"the verdict is {v.verdict} ({v.rejection_code}); nothing enters the register until it is within tolerance")
    _require(v.statement_digest == s.statement_digest and v.metered_digest == m.metered_digest, "VERDICT_MISMATCH", "the verdict was reached for different artifacts")
    expected = reconcile_inference_cost(m, s, tolerance_ratio=v.tolerance_ratio, absolute_floor_micros=v.absolute_floor_micros)
    _require(expected.verdict_digest == v.verdict_digest, "VERDICT_MISMATCH", "replay must reproduce the actual reconciliation decision")
    grouped: dict[tuple[str, str], int] = {}
    for line in m.lines:
        grouped[(line.model_key, line.cost_centre_ref)] = grouped.get((line.model_key, line.cost_centre_ref), 0) + line.cost_micros
    allocations = allocate(s.statement_micros, [(model_key, centre, micros) for (model_key, centre), micros in grouped.items()])
    basis: Basis = "metered_proportional" if m.total_micros > 0 else "stated_share"
    lines = [{"provider": s.provider, "model_key": model_key, "model_key_sha256": _sha256(model_key), "cost_centre_ref": centre, "period_start": s.window_start, "period_end": s.window_end, "metered_micros": metered_micros, "cost_micros": share, "cost": str(_micros_to_money(share)), "basis": basis, "source": s.source, "evidence_ref": s.evidence_ref, "provenance_digest": s.provenance_digest} for model_key, centre, metered_micros, share in allocations]
    total = sum(share for _, _, _, share in allocations)
    unattributed = sum(share for _, centre, _, share in allocations if centre == UNATTRIBUTED)
    return seal(InferenceCostRegister, {"source_statement": s.to_dict(), "source_metered": m.to_dict(), "source_verdict": v.to_dict(), "provider": s.provider, "period_start": s.window_start, "period_end": s.window_end, "currency": "USD", "lines": lines, "total": str(_micros_to_money(total)), "total_micros": total, "unattributed": str(_micros_to_money(unattributed)), "verdict_digest": v.verdict_digest, "statement_digest": s.statement_digest}, "register_digest")


def verify_statement(statement: ProviderStatement | Mapping[str, Any]) -> ProviderStatement:
    """Reproduce the projection from the complete original read or operator receipt."""
    s = ProviderStatement.model_validate(detached(statement))
    if s.source == "operator_statement":
        _require(s.operator_receipt is not None and s.observation_output is None and s.observation_provenance is None, "STATEMENT_SOURCE_MISSING", "retain exactly the original operator receipt")
        expected = statement_from_operator_invoice(OperatorInvoiceReceipt.model_validate(detached(s.operator_receipt)), usd_rate=s.usd_rate)
    else:
        _require(s.observation_output is not None and s.observation_provenance is not None and s.operator_receipt is None, "STATEMENT_SOURCE_MISSING", "retain exactly the original cost read and provenance")
        expected = statement_from_observation(s.observation_provenance, s.observation_output)
    _require(expected.statement_digest == s.statement_digest, "STATEMENT_SOURCE_MISMATCH", "the statement projection must match its original source")
    return s


def verify_register(register: InferenceCostRegister | Mapping[str, Any]) -> InferenceCostRegister:
    """Recompute reconciliation and allocation before a consumer uses the money."""
    r = InferenceCostRegister.model_validate(detached(register))
    expected = build_register(r.source_verdict, r.source_metered, r.source_statement)
    _require(expected.register_digest == r.register_digest, "REGISTER_SOURCE_MISMATCH", "the register must match its retained reconciliation and sources")
    return r


def period_evidence_receipt(register: InferenceCostRegister | Mapping[str, Any] | Any, *, engine: str, cost_centre_ref: str | None = None, evidence_ref: str | None = None) -> dict[str, Any]:
    """Legacy period projection; protected cadence requires company-cost-centre source evidence."""

    r = verify_register(register)
    _require(engine in _ENGINES, "ENGINE_REQUIRED", "name the operating engine the inference cost belongs to")
    centre = cost_centre_ref or engine
    matched = [line for line in r.lines if line.cost_centre_ref == centre]
    _require(bool(matched), "COST_CENTRE_UNKNOWN", f"the register holds no lines for cost centre {centre}")
    return {"period_start": r.period_start, "period_end": r.period_end, "engine": engine, "evidence_ref": evidence_ref or f"inference_cost:{r.provider}:{r.register_digest[:16]}", "spend": str(r.spend_for(centre)), "revenue": "0", "signals": []}


def cost_overrun_rates(register: InferenceCostRegister | Mapping[str, Any] | Any) -> dict[str, Decimal]:
    """metered / allocated per cost centre: the priors the operating memory has a slot for and no producer."""

    r = verify_register(register)
    metered: dict[str, int] = {}
    allocated: dict[str, int] = {}
    for line in r.lines:
        metered[line.cost_centre_ref] = metered.get(line.cost_centre_ref, 0) + line.metered_micros
        allocated[line.cost_centre_ref] = allocated.get(line.cost_centre_ref, 0) + line.cost_micros
    return {centre: (Decimal(metered[centre]) / Decimal(allocated[centre])).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP) for centre in allocated if allocated[centre] > 0}


def inference_cost_summary(verdict: ReconciliationVerdict | Mapping[str, Any] | Any, register: InferenceCostRegister | Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    """Console view: billed vs metered, variance, verdict, and the line that explains it."""

    v = verdict if isinstance(verdict, ReconciliationVerdict) else ReconciliationVerdict.model_validate(dict(detached(verdict)))
    summary: dict[str, Any] = {"provider": v.provider, "window_start": v.window_start, "window_end": v.window_end, "billed": str(_micros_to_money(v.statement_micros)), "metered": str(_micros_to_money(v.metered_micros)), "variance": str(_micros_to_money(v.variance_micros)), "variance_ratio": None if v.variance_ratio is None else str(v.variance_ratio), "tolerance_ratio": str(v.tolerance_ratio), "verdict": v.verdict, "rejection_code": v.rejection_code, "disposition": v.disposition, "explaining_line": None}
    if register is not None:
        r = verify_register(register)
        if r.lines:
            worst = max(r.lines, key=lambda line: abs(line.metered_micros - line.cost_micros))
            summary["explaining_line"] = {"model_key": worst.model_key, "cost_centre_ref": worst.cost_centre_ref, "metered": str(_micros_to_money(worst.metered_micros)), "allocated": str(worst.cost), "basis": worst.basis}
        summary["register_total"] = str(r.total)
        summary["unattributed"] = str(r.unattributed)
    return summary


INFERENCE_COST_MANIFEST: dict[str, Any] = {
    "kind": INFERENCE_COST_KIND,
    "schemas": [OBSERVATION_SCHEMA, STATEMENT_SCHEMA, OPERATOR_INVOICE_SCHEMA, METERED_SCHEMA, RECONCILIATION_SCHEMA, REGISTER_SCHEMA],
    "provider_lanes": dict(PROVIDER_COST_LANES),
    "provider_sources": {provider: list(tools) for provider, tools in PROVIDER_COST_SOURCES.items()},
    "statement_tools": dict(STATEMENT_TOOLS),
    "usage_tools": list(USAGE_TOOLS),
    "rejection_codes": list(REJECTION_CODES),
    "tolerance": {"default_ratio": str(DEFAULT_TOLERANCE_RATIO), "google_ratio": str(GOOGLE_TOLERANCE_RATIO), "absolute_floor_micros": DEFAULT_ABSOLUTE_FLOOR_MICROS},
    "hard_rules": [
        "a quote is not a bill",
        "a provider with no confirmed usage API is on the operator-invoice lane and no endpoint is invented for it",
        "an operator invoice names itself as operator-declared and can never carry a read provenance",
        "a quote whose price catalog version is unstated is not reconcilable",
        "the metering window is aligned to the statement window, never the reverse",
        "a variance beyond tolerance is a manual reconciliation, never a silent adjustment",
        "a per-centre figure carries basis metered_proportional and is an allocation, not an observation",
        "allocated inference cost enters the period exactly as a paid supplier bill does",
    ],
}

__all__ = [
    "DEFAULT_ABSOLUTE_FLOOR_MICROS",
    "DEFAULT_TOLERANCE_RATIO",
    "GOOGLE_TOLERANCE_RATIO",
    "INFERENCE_COST_KIND",
    "INFERENCE_COST_MANIFEST",
    "METERED_SCHEMA",
    "OBSERVATION_SCHEMA",
    "OPERATOR_INVOICE_SCHEMA",
    "PROVIDER_CODES",
    "PROVIDER_COST_LANES",
    "PROVIDER_COST_SOURCES",
    "RECONCILIATION_SCHEMA",
    "REGISTER_SCHEMA",
    "REJECTION_CODES",
    "STATEMENT_SCHEMA",
    "STATEMENT_TOOLS",
    "UNATTRIBUTED",
    "USAGE_TOOLS",
    "InferenceCostError",
    "InferenceCostLine",
    "InferenceCostRegister",
    "MeteredCost",
    "MeteredLine",
    "OperatorInvoiceReceipt",
    "ProviderStatement",
    "ReconciliationVerdict",
    "allocate",
    "build_register",
    "cost_overrun_rates",
    "inference_cost_summary",
    "metered_cost",
    "metered_from_host",
    "operator_invoice_receipt",
    "period_evidence_receipt",
    "reconcile_inference_cost",
    "statement_from_observation",
    "statement_from_operator_invoice",
    "tolerance_for",
    "verify_statement",
    "verify_register",
]
