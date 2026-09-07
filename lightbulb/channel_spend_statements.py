"""Channel spend with explicit invoice custody and exact governed observation replay.

Only Google and Meta currently have governed reads. Other channels must carry an
operator's attestation and document commitment. Provider attribution metrics never
become revenue in this lane. Calendar dates are retained as provider dates.
"""
from __future__ import annotations
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Literal, Mapping, Sequence
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import (StrictModel, EngineScope, OpaqueRef, Sha256Digest,
    GENESIS_DIGEST, CurrencyCode, BoundedText, detached, parsed, timestamp, stable_digest,
    seal, sealed_digest, skip_digests, same_scope)
from lightbulb.company_execution_bridge import ObservationProvenance

CHANNEL_SPEND_LANES = {
    "paid_search_google": ("google_ads.get_metrics",), "paid_social_meta": ("meta_ads.get_insights",),
    "paid_social_linkedin": (), "paid_social_tiktok": (), "email_lifecycle": (), "sms_lifecycle": (),
    "affiliate": (), "agency": (), "offline": (), "organic_social": (), "seo_content": (),
}
SCHEMAS = {"google_ads.get_metrics":"lightbulb.google_ads_spend_observation.v1",
           "meta_ads.get_insights":"lightbulb.meta_ads_spend_observation.v1"}

class ChannelSpendError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ChannelSpendError(code, message)

class OperatorMediaSpendReceipt(StrictModel):
    schema_id: Literal["lightbulb.operator_media_spend_receipt.v1"] = Field(default="lightbulb.operator_media_spend_receipt.v1",alias="schema")
    input_kind: Literal["operator_supplied_media_invoice"]
    company_ref: OpaqueRef
    scope: EngineScope
    channel: OpaqueRef
    account_commitment: Sha256Digest
    invoice_ref: OpaqueRef
    document_sha256: Sha256Digest
    operator_ref: OpaqueRef
    attestation: BoundedText
    window_start: str
    window_end: str
    currency: CurrencyCode
    invoice_total_micros: int = Field(ge=0,le=9223372036854775807)
    attested_at: str
    receipt_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("window_start", "window_end", "attested_at")
    @classmethod
    def stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value,field_name=str(info.field_name))

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo):
        require(self.channel in CHANNEL_SPEND_LANES,"CHANNEL_UNKNOWN","channel must have a declared spend lane")
        require(parsed(self.window_start)<parsed(self.window_end)<=parsed(self.attested_at),"SPEND_WINDOW_INVALID","attested spend must cover a completed positive window")
        require(self.currency==self.scope.currency,"SOURCE_CURRENCY_MISMATCH","invoice currency must match execution scope; FX is not inferred")
        if not skip_digests(info) and self.receipt_digest != sealed_digest(type(self),self,"receipt_digest"):
            raise ValueError("receipt_digest must commit the complete invoice")
        return self

def operator_media_spend_receipt(payload: Mapping[str,Any]) -> OperatorMediaSpendReceipt:
    require(not any(key in payload for key in ("provenance_digest","evidence_sha256","tool_invocation_id")),
            "OPERATOR_STATEMENT_CLAIMS_PROVENANCE","an operator invoice cannot claim a governed read's provenance")
    return seal(OperatorMediaSpendReceipt,payload,"receipt_digest")

class ChannelSpendStatement(StrictModel):
    schema_id: Literal["lightbulb.channel_spend_statement.v1"] = Field(default="lightbulb.channel_spend_statement.v1",alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    channel: OpaqueRef
    account_commitment: Sha256Digest
    window_start: str
    window_end: str
    currency: CurrencyCode
    cost_micros: int = Field(ge=0,le=9223372036854775807)
    basis: Literal["operator_invoice","governed_read"]
    operator_receipt: OperatorMediaSpendReceipt | None = None
    observation: dict[str,Any] | None = None
    provenance: ObservationProvenance | None = None
    statement_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo):
        require(self.currency==self.scope.currency,"SOURCE_CURRENCY_MISMATCH","statement currency must match execution scope")
        require(parsed(self.window_start)<parsed(self.window_end),"SPEND_WINDOW_INVALID","spend needs a positive window")
        require((self.basis=="operator_invoice" and self.operator_receipt is not None and self.observation is None and self.provenance is None)
                or (self.basis=="governed_read" and self.operator_receipt is None and self.observation is not None and self.provenance is not None),
                "SPEND_SOURCE_MISSING","statement must retain exactly one kind of source")
        if not skip_digests(info) and self.statement_digest != sealed_digest(type(self),self,"statement_digest"):
            raise ValueError("statement_digest must commit retained source and projection")
        return self

    @property
    def amount(self) -> Decimal:
        return Decimal(self.cost_micros)/Decimal(1000000)


def statement_from_operator(receipt: Any) -> ChannelSpendStatement:
    invoice=OperatorMediaSpendReceipt.model_validate(detached(receipt))
    return seal(ChannelSpendStatement,{**{key:invoice.to_dict()[key] for key in
        ("company_ref","scope","channel","account_commitment","window_start","window_end","currency")},
        "basis":"operator_invoice","cost_micros":invoice.invoice_total_micros,"operator_receipt":invoice.to_dict()},"statement_digest")


def _integer(value: Any, field: str) -> int:
    require(type(value) is int and 0<=value<=9223372036854775807,"SPEND_AMOUNT_INVALID",f"{field} must be a non-negative integer")
    return value


def statement_from_observation(*,company_ref: str,scope: Any,channel: str,provenance: Any,output: Any) -> ChannelSpendStatement:
    prov=ObservationProvenance.model_validate(detached(provenance)); raw=dict(detached(output))
    require(prov.lane=="governed_read" and prov.source_tool in CHANNEL_SPEND_LANES.get(channel,()),"LANE_SOURCE_MISMATCH","channel has no matching governed spend read")
    require(raw.get("schema")==SCHEMAS[prov.source_tool],"SPEND_SCHEMA_MISMATCH","read must use the canonical provider spend schema")
    require(stable_digest(raw)==prov.output_digest,"OBSERVATION_DIGEST_MISMATCH","statement must use exact retained output")
    require(stable_digest({k:v for k,v in raw.items() if k not in ("evidence_sha256","observed_at")})==raw.get("evidence_sha256"),
            "SPEND_EVIDENCE_MISMATCH","provider evidence must commit all observed fields")
    require(raw.get("exhaustive_read") is True and raw.get("truncated") is False,"SPEND_READ_INCOMPLETE","truncated reads cannot supply complete spend")
    start=date.fromisoformat(raw["window_start"]); end=date.fromisoformat(raw["window_end"])+timedelta(days=1)
    require(0<(end-start).days<=92,"SPEND_WINDOW_INVALID","provider date window must be bounded")
    begin=start.isoformat()+"T00:00:00Z"; finish=end.isoformat()+"T00:00:00Z"
    require(parsed(prov.completed_at)>=parsed(finish) and parsed(raw["observed_at"])<=parsed(prov.completed_at),
            "SPEND_WINDOW_INCOMPLETE","a complete spend window must have ended before the read")
    require(prov.window_start in (None,begin) and prov.window_end in (None,finish),"SPEND_WINDOW_MISALIGNED","provider dates must match the governed read window")
    google=prov.source_tool=="google_ads.get_metrics"; key="cost_micros" if google else "spend_minor"
    rows=raw.get("rows");require(isinstance(rows,list) and len(rows)<=2000 and raw.get("row_count")==len(rows),"SPEND_READ_INCOMPLETE","all bounded provider rows must be retained")
    total=_integer(raw.get("totals",{}).get(key),key)
    require(total==sum(_integer(row.get(key),key) for row in rows),"SPEND_TOTAL_MISMATCH","spend totals must equal the retained rows")
    identities=[(row.get("campaign_id_sha256"),row.get("date") or row.get("date_start")) for row in rows]
    require(len(identities)==len(set(identities)),"SPEND_ROW_DUPLICATED","a campaign day may appear only once")
    for _,day in identities:
        require(isinstance(day,str) and start<=date.fromisoformat(day)<end,"SPEND_ROW_OUTSIDE_WINDOW","every campaign day must be in the observation window")
    exponent=6 if google else _integer(raw.get("currency_minor_exponent"),"currency_minor_exponent")
    require(exponent<=6,"CURRENCY_EXPONENT_UNSUPPORTED","currency precision exceeds micros")
    return seal(ChannelSpendStatement,{"company_ref":company_ref,"scope":detached(scope),"channel":channel,
        "account_commitment":raw.get("customer_id_sha256" if google else "ad_account_id_sha256"),
        "window_start":begin,"window_end":finish,"currency":raw.get("currency_code" if google else "currency"),
        "cost_micros":total*(10**(6-exponent)),"basis":"governed_read","observation":raw,"provenance":prov.to_dict()},"statement_digest")


def verify_statement(value: Any) -> ChannelSpendStatement:
    statement=ChannelSpendStatement.model_validate(detached(value))
    expected=statement_from_operator(statement.operator_receipt) if statement.basis=="operator_invoice" else statement_from_observation(
        company_ref=statement.company_ref,scope=statement.scope,channel=statement.channel,provenance=statement.provenance,output=statement.observation)
    require(expected.statement_digest==statement.statement_digest,"SPEND_SOURCE_MISMATCH","statement facts must reproduce their source")
    return statement


def total_channel_spend(statements: Sequence[Any], *, company_ref: str, scope: Any,
                        window_start: str,window_end: str) -> Decimal:
    """Non-overlapping proved statements only; reconciled replacements are selected before this fold."""
    scoped=EngineScope.model_validate(detached(scope)); verified=[verify_statement(value) for value in statements]
    require(len(verified)<=2000,"SPEND_INPUT_LIMIT","split large periods before folding")
    seen=[];documents=set()
    for item in verified:
        require(item.company_ref==company_ref and same_scope(item.scope,scoped),"SOURCE_SCOPE_MISMATCH","spend belongs to another execution scope")
        require(parsed(window_start)<=parsed(item.window_start)<parsed(item.window_end)<=parsed(window_end),"SPEND_WINDOW_MISALIGNED","statement must fall inside the requested period")
        for prior in seen:
            require(not(item.channel==prior.channel and item.account_commitment==prior.account_commitment
                    and parsed(item.window_start)<parsed(prior.window_end) and parsed(prior.window_start)<parsed(item.window_end)),
                    "SPEND_STATEMENT_DUPLICATE","overlapping statements for one channel account cannot be added")
        if item.operator_receipt is not None:
            doc=item.operator_receipt.document_sha256
            require(doc not in documents,"SPEND_STATEMENT_DUPLICATE","one invoice document cannot be relabelled into multiple costs")
            documents.add(doc)
        seen.append(item)
    return sum((item.amount for item in verified),Decimal(0))


def reconcile_channel_spend(invoice: Any, observation: Any, *, tolerance_ratio: Any="0.02") -> dict[str,Any]:
    stated=verify_statement(invoice); observed=verify_statement(observation); tolerance=Decimal(str(tolerance_ratio))
    require(tolerance.is_finite() and 0<=tolerance<=Decimal("0.1"),"SPEND_TOLERANCE_INVALID","tolerance must be bounded between zero and ten percent")
    require(stated.basis=="operator_invoice" and observed.basis=="governed_read","SPEND_LANE_MISMATCH","reconciliation compares an invoice to a provider read")
    require(all(getattr(stated,key)==getattr(observed,key) for key in ("company_ref","channel","account_commitment","window_start","window_end","currency"))
            and same_scope(stated.scope,observed.scope),"SPEND_WINDOW_MISALIGNED","invoice and read must cover the exact same company, account and window")
    variance=abs(stated.cost_micros-observed.cost_micros)
    require(Decimal(variance)<=Decimal(stated.cost_micros)*tolerance,"SPEND_VARIANCE_EXCEEDED","invoice and observed spend need manual reconciliation")
    return {"schema":"lightbulb.channel_spend_reconciliation.v1","invoice":stated.to_dict(),"observation":observed.to_dict(),
            "tolerance_ratio":str(tolerance),"variance_micros":variance,"selected_statement_digest":stated.statement_digest,"verdict":"within_tolerance"}

__all__=["CHANNEL_SPEND_LANES","ChannelSpendError","OperatorMediaSpendReceipt","ChannelSpendStatement",
         "operator_media_spend_receipt","statement_from_operator","statement_from_observation","verify_statement",
         "total_channel_spend","reconcile_channel_spend"]
