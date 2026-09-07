"""Shared demand budget claims, proved spend and period pacing.

The registry is persisted through the normal engine store compare-and-swap fence.
A detached candidate is not a reservation. The host must commit a claim before
opening its campaign. Observed overspend remains recorded and pauses new claims;
refusing to record a real provider expense would hide the incident.
"""
from __future__ import annotations
from decimal import Decimal
from typing import Any, Literal, Mapping
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import (StrictModel, EngineScope, OpaqueRef, Sha256Digest, CurrencyCode,
    LifecycleSpec, GENESIS_DIGEST, MONEY_QUANTUM, decimal_value, detached, parsed, require, seal,
    sealed_digest, skip_digests, same_scope)
from lightbulb.growth_engine_loop import GrowthEngineLoopPlan, CampaignPortfolio

def _spent_decimal(value: Any) -> Decimal:
    if isinstance(value, (bool, float)):
        raise ValueError("spend must retain exact decimal micros")
    amount=Decimal(str(value))
    if not amount.is_finite() or not 0<=amount<=Decimal("1000000000000") or amount != amount.quantize(Decimal("0.000001")):
        raise ValueError("spend must retain bounded non-negative decimal micros")
    return amount

class DemandEnvelopePlan(StrictModel):
    schema_id: Literal["lightbulb.demand_envelope_plan.v1"] = Field(default="lightbulb.demand_envelope_plan.v1",alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    growth_plan: GrowthEngineLoopPlan
    portfolio: CampaignPortfolio
    pace_slack_percent: int = Field(default=20,ge=0,le=100)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo):
        if self.portfolio.plan_digest != self.growth_plan.plan_digest or self.portfolio.currency != self.currency:
            raise ValueError("PORTFOLIO_NOT_BOUND: the budget must belong to the retained growth plan and currency")
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self),self,"plan_digest"):
            raise ValueError("plan_digest must commit the full budget and policy")
        return self


def compile_demand_envelope(company_ref: str, *, growth_plan: Any, portfolio: Any, pace_slack_percent: int=20) -> DemandEnvelopePlan:
    plan=GrowthEngineLoopPlan.model_validate(detached(growth_plan))
    return seal(DemandEnvelopePlan,{"company_ref":company_ref,"currency":plan.blueprint.currency,
        "growth_plan":plan.to_dict(),"portfolio":detached(portfolio),"pace_slack_percent":pace_slack_percent},"plan_digest")

class EnvelopeClaim(StrictModel):
    campaign_ref: OpaqueRef
    campaign_scope: EngineScope
    envelope_ref: OpaqueRef
    budget: Decimal
    spent: Decimal = Field(default=Decimal(0),validate_default=True)
    provider_campaign_commitment: Sha256Digest | None = None
    released: bool = False

    @field_validator("budget","spent",mode="before")
    @classmethod
    def money(cls,value: Any,info: ValidationInfo) -> Decimal:
        if info.field_name == "spent":
            return _spent_decimal(value)
        return decimal_value(value,field_name=str(info.field_name))

class DemandReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef,...] = ()
    registry_scope: EngineScope | None = None
    campaign_scope: EngineScope | None = None
    campaign_ref: OpaqueRef | None = None
    envelope_ref: OpaqueRef | None = None
    budget: Decimal | None = None
    provider_campaign_commitment: Sha256Digest | None = None
    statement: dict[str,Any] | None = None

    @field_validator("budget",mode="before")
    @classmethod
    def money(cls,value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value,field_name="budget")

class DemandLedger(StrictModel):
    registry_scope: EngineScope | None = None
    claims: tuple[EnvelopeClaim,...] = Field(default=(),max_length=2000)
    source_watermarks: dict[str,str] = Field(default_factory=dict)
    statement_digests: tuple[Sha256Digest,...] = Field(default=(),max_length=2000)
    document_digests: tuple[Sha256Digest,...] = Field(default=(),max_length=2000)
    spent: Decimal = Field(default=Decimal(0),validate_default=True)
    pacing_alerts: tuple[OpaqueRef,...] = ()

    @field_validator("spent",mode="before")
    @classmethod
    def money(cls,value: Any) -> Decimal:
        return _spent_decimal(value)

class DemandEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_write: Literal[False] = False
    money_spent: Literal[False] = False


def _apply(plan: DemandEnvelopePlan,next_status: str,status: str,data: dict[str,Any],command: Any):
    r=command.receipt; portfolio=plan.portfolio; now=parsed(command.occurred_at)
    claims=[EnvelopeClaim.model_validate(item) for item in data.get("claims",())]
    if command.event=="open_registry":
        require(r.registry_scope is not None and r.registry_scope.currency==plan.currency,"SOURCE_SCOPE_MISMATCH","registry must retain its actual scope")
        require(command.expected_state_digest==DEMAND_LIFECYCLE.state_digest(plan.plan_digest,r.registry_scope,()),"SOURCE_SCOPE_MISMATCH","registry scope must match its opening command")
        require(parsed(portfolio.period_start)<=now<parsed(portfolio.period_end),"PERIOD_ELAPSED","open the demand registry inside its budget period")
        data["registry_scope"]=r.registry_scope.to_dict()
    elif command.event=="claim":
        require(parsed(portfolio.period_start)<=now<parsed(portfolio.period_end),"PERIOD_ELAPSED","new budget claims must belong to the current period")
        require(r.campaign_scope is not None and same_scope(r.campaign_scope,EngineScope.model_validate(data["registry_scope"])),"SOURCE_SCOPE_MISMATCH","campaign and registry scopes must match")
        require(r.campaign_ref==r.campaign_scope.entity_ref,"CAMPAIGN_SCOPE_MISMATCH","claim must name the campaign's actual entity")
        require(not any(item.campaign_ref==r.campaign_ref for item in claims),"CAMPAIGN_ALREADY_CLAIMED","one campaign may reserve budget only once")
        envelope=portfolio.envelope(str(r.envelope_ref))
        require(envelope is not None,"ENVELOPE_UNKNOWN","claim must name a portfolio envelope")
        require(r.budget is not None and r.budget>0,"BUDGET_MISSING","a claim must reserve a positive budget")
        claimed=sum((item.budget for item in claims if item.envelope_ref==r.envelope_ref and not item.released),Decimal(0))
        require(claimed+r.budget<=envelope.budget,"ENVELOPE_OVERCLAIMED","sibling campaigns cannot reserve more than the shared envelope")
        claims.append(EnvelopeClaim(campaign_ref=r.campaign_ref,campaign_scope=r.campaign_scope,envelope_ref=r.envelope_ref,budget=r.budget))
    elif command.event in ("bind_campaign","release_claim"):
        matched=[item for item in claims if item.campaign_ref==r.campaign_ref and not item.released]
        require(len(matched)==1,"CAMPAIGN_NOT_CLAIMED","the campaign must have an active claim")
        claim=matched[0]
        if command.event=="bind_campaign":
            require(now<parsed(portfolio.period_end),"PERIOD_ELAPSED","provider campaigns cannot launch after the budget period")
            require(r.provider_campaign_commitment is not None and claim.provider_campaign_commitment is None,"CAMPAIGN_ALREADY_BOUND","a provider identity is immutable once bound")
            require(not any(item.provider_campaign_commitment==r.provider_campaign_commitment for item in claims),"CAMPAIGN_ALREADY_BOUND","one provider campaign cannot spend from multiple claims")
            claim=claim.model_copy(update={"provider_campaign_commitment":r.provider_campaign_commitment})
        else:
            require(claim.spent==0 and claim.provider_campaign_commitment is None,"CLAIM_ALREADY_USED","only an unused, unlaunched claim may be released")
            claim=claim.model_copy(update={"released":True})
        claims=[claim if item.campaign_ref==claim.campaign_ref else item for item in claims]
    elif command.event=="observe_spend":
        from lightbulb.channel_spend_statements import verify_statement
        require(r.statement is not None,"SPEND_SOURCE_REQUIRED","typed spend supplements cannot consume a budget")
        source=verify_statement(r.statement)
        require(source.company_ref==plan.company_ref and same_scope(source.scope,EngineScope.model_validate(data["registry_scope"])),"SOURCE_SCOPE_MISMATCH","spend belongs to another company or scope")
        require(parsed(portfolio.period_start)<=parsed(source.window_start)<parsed(source.window_end)<=parsed(portfolio.period_end),"PERIOD_ELAPSED","spend must belong to the portfolio period")
        observed_at=source.operator_receipt.attested_at if source.operator_receipt else source.provenance.completed_at
        require(parsed(observed_at)<=now,"SPEND_FROM_FUTURE","spend evidence must already exist")
        require(source.statement_digest not in data["statement_digests"],"SPEND_ALREADY_RECORDED","a statement may consume budget once")
        source_key=source.channel+":"+source.account_commitment
        last=data["source_watermarks"].get(source_key)
        require(last is None or parsed(source.window_start)>=parsed(last),"SPEND_WINDOW_OVERLAP","source windows may not overlap, including invoice/read duplicates")
        amounts={}
        if source.basis=="operator_invoice":
            require(source.operator_receipt.document_sha256 not in data["document_digests"],"SPEND_ALREADY_RECORDED","an invoice may not be renamed into another cost")
            require(r.campaign_ref is not None,"CAMPAIGN_NOT_CLAIMED","operator invoices must name the claim charged")
            amounts[r.campaign_ref]=source.amount
            data["document_digests"]=[*data["document_digests"],source.operator_receipt.document_sha256]
        else:
            google=source.provenance.source_tool=="google_ads.get_metrics"
            divisor=Decimal(1000000) if google else Decimal(10)**source.observation["currency_minor_exponent"]
            for row in source.observation["rows"]:
                matched=[item for item in claims if not item.released and item.provider_campaign_commitment==row["campaign_id_sha256"]]
                require(len(matched)==1,"SPEND_UNATTRIBUTED","every observed provider campaign must have one budget claim")
                ref=matched[0].campaign_ref
                amounts[ref]=amounts.get(ref,Decimal(0))+Decimal(row["cost_micros" if google else "spend_minor"])/divisor
        require(sum(amounts.values(),Decimal(0))==source.amount,"SPEND_TOTAL_MISMATCH","all observed spend must be assigned exactly once")
        require(all(any(item.campaign_ref==ref and not item.released for item in claims) for ref in amounts),"CAMPAIGN_NOT_CLAIMED","spend requires an active claim")
        updated=[];alerts=[]
        fraction=Decimal(str((parsed(source.window_end)-parsed(portfolio.period_start)).total_seconds()))/Decimal(str((parsed(portfolio.period_end)-parsed(portfolio.period_start)).total_seconds()))
        for claim in claims:
            amount=amounts.get(claim.campaign_ref,Decimal(0));envelope=portfolio.envelope(claim.envelope_ref)
            require(amount==0 or envelope.channel==source.channel,"SPEND_CHANNEL_MISMATCH","provider spend must match the claim's channel")
            spent=claim.spent+amount
            if spent>claim.budget:
                alerts.append("ENVELOPE_OVERSPEND")
            elif amount>0 and spent>claim.budget*fraction*(Decimal(100+plan.pace_slack_percent)/100):
                alerts.append("PACE_AHEAD_OF_PLAN")
            updated.append(claim.model_copy(update={"spent":spent}))
        claims=updated
        data["statement_digests"]=[*data["statement_digests"],source.statement_digest]
        data["source_watermarks"]={**data["source_watermarks"],source_key:source.window_end}
        data["spent"]=str(sum((item.spent for item in claims),Decimal(0)))
        data["pacing_alerts"]=list(dict.fromkeys([*data["pacing_alerts"],*alerts]))
        if data["pacing_alerts"]:
            next_status="paused"
    elif command.event=="close":
        require(now>=parsed(portfolio.period_end),"PERIOD_NOT_ENDED","a demand period closes after its window")
    data["claims"]=[item.to_dict() for item in claims]
    return next_status,data


DEMAND_LIFECYCLE=LifecycleSpec(entity="demand_envelope",schema_prefix="demand_envelope",statuses=("open","paused","closed"),terminal=frozenset({"closed"}),
    events=("open_registry","claim","bind_campaign","release_claim","observe_spend","close"),
    table={("new","open_registry"):"open",("open","claim"):"open",("open","bind_campaign"):"open",("open","release_claim"):"open",
           ("open","observe_spend"):"open",("paused","observe_spend"):"paused",("open","close"):"closed",("paused","close"):"closed"},
    opening_event="open_registry",reason_events=(),apply=_apply,ledger_model=DemandLedger,receipt_model=DemandReceipt,
    effect_boundary_model=DemandEffectBoundary,plan_model=DemandEnvelopePlan,max_transitions=4096)
DemandState=DEMAND_LIFECYCLE.State
seal_demand_command=DEMAND_LIFECYCLE.seal_command

def open_demand_registry(plan: Any,scope: Any,*,opened_at: str,actor_ref: str) -> Any:
    return DEMAND_LIFECYCLE.open(plan,scope,opened_at=opened_at,actor_ref=actor_ref,receipt={"registry_scope":detached(scope)})

def advance_demand_registry(plan: Any,state: Any,command: Any) -> Any:
    return DEMAND_LIFECYCLE.advance(plan,state,command)


def verify_campaign_claim(state: Any,*,source_plan: Any,campaign_scope: Any,envelope_ref: str,at: str) -> EnvelopeClaim:
    plan,registry=DEMAND_LIFECYCLE.bind(source_plan,state)
    scope=EngineScope.model_validate(detached(campaign_scope))
    require(same_scope(scope,registry.scope),"SOURCE_SCOPE_MISMATCH","campaign belongs to another registry scope")
    require(registry.status=="open" and parsed(plan.portfolio.period_start)<=parsed(at)<parsed(plan.portfolio.period_end),"PERIOD_ELAPSED","campaign launch requires a live paced envelope")
    require(parsed(registry.transition_history[-1].command.occurred_at)<=parsed(at),"CLAIM_FROM_FUTURE","claim must exist before launch")
    matched=[item for item in registry.ledger.claims if item.campaign_ref==scope.entity_ref and item.envelope_ref==envelope_ref and not item.released]
    require(len(matched)==1,"CAMPAIGN_NOT_CLAIMED","campaign has no committed envelope claim")
    return matched[0]

__all__=["DemandEnvelopePlan","EnvelopeClaim","DemandReceipt","DemandLedger","DemandState","DEMAND_LIFECYCLE",
         "compile_demand_envelope","open_demand_registry","advance_demand_registry","seal_demand_command","verify_campaign_claim"]
