"""Durable content identity, approved publication and measured organic life.

briefed -> drafted -> reviewed -> approved -> scheduled -> published -> observed
Observed parents may be repurposed and continue observing. Retirement requires
complete, non-overlapping quiet windows. Organic observations never create money.
All host reads, connector requests and executions are retained for replay.
"""
from __future__ import annotations
from decimal import Decimal
from typing import Any, Literal, Mapping
from pydantic import Field, ValidationInfo, model_validator, field_validator
from lightbulb.company_engine_core import (StrictModel, OpaqueRef, Sha256Digest, CurrencyCode,
    GENESIS_DIGEST, LifecycleSpec, seal, sealed_digest, skip_digests, detached,
    stable_digest, parsed, require, EngineScope, same_scope, decimal_value)
from lightbulb.company_execution_bridge import ObservationProvenance, ExecutionReceipt
from lightbulb.connector_execution import ConnectorExecutionRequest

CONTENT_ASSET_KIND = "content_asset_lifecycle"
CONTENT_ASSET_GOLDEN_LOOP = "growth.brief_to_compounding_asset@0.1.0"
ASSET_STATUSES = ("briefed","drafted","reviewed","approved","scheduled","published","observed","repurposed","retired")
ASSET_EVENTS = ("brief","draft","review","request_changes","approve","schedule","publish","observe","repurpose","retire")
TERMINAL_ASSET_STATUSES = frozenset({"retired"})
AssetKind = Literal["blog_post","social_post","landing_page","video","email","local_post","collateral"]
ContentChannel = Literal["seo_content","organic_social","local_presence","email_lifecycle","paid_social_meta","paid_search_google"]
_KIND_CHANNELS = {"blog_post":{"seo_content"}, "social_post":{"organic_social","paid_social_meta"},
    "landing_page":{"seo_content","paid_search_google","paid_social_meta"}, "video":{"organic_social","seo_content"},
    "email":{"email_lifecycle"}, "local_post":{"local_presence"}, "collateral":set(ContentChannel.__args__)}
_PUBLISH_TOOLS = frozenset({"facebook.publish_post","instagram.publish_post","linkedin.publish_post","x.publish_post","website.publish_post","gbp.create_local_post"})
_HOST_CHANNELS = {"web":"seo_content","website":"seo_content","blog":"seo_content","linkedin":"organic_social","facebook":"organic_social","instagram":"organic_social","x":"organic_social","twitter":"organic_social","gbp":"local_presence","google_business_profile":"local_presence","email":"email_lifecycle"}
_TABLE = {("new","brief"):"briefed", ("briefed","draft"):"drafted", ("drafted","draft"):"drafted",
    ("drafted","review"):"reviewed", ("reviewed","request_changes"):"drafted", ("reviewed","approve"):"approved",
    ("approved","schedule"):"scheduled", ("scheduled","publish"):"published", ("published","observe"):"observed",
    ("observed","observe"):"observed", ("repurposed","observe"):"observed", ("observed","repurpose"):"repurposed",
    ("repurposed","repurpose"):"repurposed", ("observed","retire"):"retired", ("repurposed","retire"):"retired"}

class ContentAssetPlan(StrictModel):
    schema_id: Literal["lightbulb.content_asset_lifecycle_plan.v1"] = Field(default="lightbulb.content_asset_lifecycle_plan.v1", alias="schema")
    company_ref: OpaqueRef
    company_commitment: Sha256Digest
    tenant_commitment: Sha256Digest
    currency: CurrencyCode = "USD"
    prohibited_terms: tuple[str, ...] = ()
    min_observation_window_days: int = Field(default=7, ge=1, le=92)
    retire_min_days_since_last_click: int = Field(default=90, ge=0, le=1095)
    max_derivatives_per_asset: int = Field(default=8, ge=1, le=20)
    claim_max_age_days: int = Field(default=365,ge=1,le=365)
    growth_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def validate_plan(self, info: ValidationInfo):
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self),self,"plan_digest"):
            raise ValueError("plan_digest must commit the exact content policy")
        return self

def compile_content_asset_plan(company_ref, *, company_id, tenant_id, growth_plan=None, overrides=None):
    from uuid import UUID
    from hashlib import sha256
    raw = {**(overrides or {}),"company_ref":company_ref,
        "company_commitment":sha256(str(UUID(company_id)).encode()).hexdigest(),
        "tenant_commitment":sha256(str(UUID(tenant_id)).encode()).hexdigest()}
    if growth_plan is not None:
        from lightbulb.growth_engine_loop import GrowthEngineLoopPlan
        growth = GrowthEngineLoopPlan.model_validate(detached(growth_plan))
        raw.update(currency=growth.blueprint.currency, prohibited_terms=growth.blueprint.prohibited_terms, growth_plan_digest=growth.plan_digest)
    return seal(ContentAssetPlan,raw,"plan_digest")

class ContentAssetReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef,...] = ()
    entity_scope: dict[str, Any] | None = None
    host_read: dict[str, Any] | None = None
    body: str | None = None
    request: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    observation: dict[str, Any] | None = None
    attribution: dict[str, Any] | None = None
    derivative: dict[str, Any] | None = None

class AssetLedger(StrictModel):
    asset_ref: str | None = None
    asset_kind: AssetKind | None = None
    channel: ContentChannel | None = None
    entity_scope: dict[str, Any] | None = None
    brief_digest: Sha256Digest | None = None
    body_digest: Sha256Digest | None = None
    published_at: str | None = None
    canonical_url_commitment: Sha256Digest | None = None
    provider_post_commitment: Sha256Digest | None = None
    scheduled_for_at: str | None = None
    approved_read: dict[str, Any] | None = None
    windows: tuple[dict[str, Any], ...] = Field(default=(),max_length=260)
    derivatives: tuple[str,...] = ()
    cumulative_clicks: int = 0
    cumulative_impressions: int = 0
    credited_revenue: Decimal = Decimal(0)
    credited_conversions: int = 0
    credited_identities: tuple[str,...] = ()
    last_window_end: str | None = None
    last_click_window_end: str | None = None
    retired_at: str | None = None

    @field_validator("credited_revenue",mode="before")
    @classmethod
    def money(cls,value):
        return decimal_value(value,field_name="credited_revenue")

class ContentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    publication_written: Literal[False] = False
    provider_read: Literal[False] = False
    money_posted: Literal[False] = False

def _host(read, plan, at, *, asset_ref=None):
    require(read is not None,"CONTENT_HOST_READ_REQUIRED","retain the host content registry read")
    provenance = ObservationProvenance.model_validate(read["provenance"])
    output = read["output"]
    require(provenance.lane == "host_read" and provenance.source_tool == "lightbulb.content_assets.get"
        and provenance.output_digest == stable_digest(output) and parsed(provenance.completed_at) <= parsed(at),
        "CONTENT_HOST_READ_MISMATCH","content facts must come from the retained host registry response")
    from hashlib import sha256
    require(output.get("schema") == "lightbulb.content_asset.v1" and sha256(str(output.get("companyId")).encode()).hexdigest() == plan.company_commitment
        and sha256(str(output.get("tenantId")).encode()).hexdigest() == plan.tenant_commitment,"SOURCE_SCOPE_MISMATCH","content registry evidence must name this tenant and company")
    require(asset_ref is None or output.get("assetRef") == asset_ref,"CONTENT_ASSET_MISMATCH","host read names another content asset")
    return output

def _claims(row,plan,at):
    require(isinstance(row.get("claims"),list),"CONTENT_CLAIMS_REQUIRED","retain the complete host claim register")
    from datetime import timedelta
    for claim in row["claims"]:
        require(claim.get("evidenceKind") not in (None,"none") and bool(claim.get("evidenceRef"))
            and bool(claim.get("verifiedByUserId")) and bool(claim.get("verifiedAt"))
            and parsed(claim["verifiedAt"]) <= parsed(at),"CONTENT_CLAIM_UNPROVEN","every claim needs attributed evidence")
        require(parsed(at)<parsed(claim["verifiedAt"])+timedelta(days=plan.claim_max_age_days)
            and (claim.get("expiresAt") is None or parsed(at)<parsed(claim["expiresAt"])),
            "CONTENT_CLAIM_EXPIRED","reverify expired claim evidence before approval or publication")
        require(claim.get("claimKind")!="testimonial" or bool(claim.get("consentRef")),
            "CONTENT_CONSENT_REQUIRED","testimonials require customer consent")


def _apply(plan,next_status,status,data,command):
    r, at, event = command.receipt, command.occurred_at, command.event
    if event == "brief":
        row = _host(r.host_read,plan,at)
        channel=_HOST_CHANNELS.get(row.get("channel"),row.get("channel"))
        require(row.get("status") == "BRIEFED" and row.get("assetKind") in _KIND_CHANNELS
            and channel in _KIND_CHANNELS[row["assetKind"]],"CONTENT_KIND_CHANNEL_MISMATCH","registered kind and channel must agree")
        require(r.entity_scope is not None and r.entity_scope.get("currency") == plan.currency,"SOURCE_SCOPE_MISMATCH","content opens in the plan currency")
        data.update(asset_ref=row["assetRef"],asset_kind=row["assetKind"],channel=channel,brief_digest=row["briefDigest"],entity_scope=r.entity_scope)
    elif event == "draft":
        import hashlib
        row = _host(r.host_read,plan,at,asset_ref=data["asset_ref"])
        require(bool(r.body) and not any(term.casefold() in r.body.casefold() for term in plan.prohibited_terms),
            "CONTENT_BRAND_SAFETY","draft must be nonempty and obey prohibited terms")
        body_digest = hashlib.sha256(r.body.encode()).hexdigest()
        require(row.get("status") == "DRAFTED" and row.get("bodyDigest") == body_digest,
            "CONTENT_BODY_MISMATCH","the retained draft must be the body committed by the host")
        data.update(body_digest=body_digest,approved_read=None)
    elif event in ("review","approve","schedule"):
        row = _host(r.host_read,plan,at,asset_ref=data["asset_ref"])
        expected = {"review":"REVIEWED","approve":"APPROVED","schedule":"SCHEDULED"}[event]
        require(row.get("status") == expected and row.get("bodyDigest") == data["body_digest"],
            "CONTENT_BODY_MISMATCH","review, approval and schedule retain this exact body")
        _claims(row,plan,at)
        if event in ("approve","schedule"):
            require(bool(row.get("decidedByUserId")) and bool(row.get("decidedAt")) and parsed(row["decidedAt"]) <= parsed(at),
                "CONTENT_APPROVAL_REQUIRED","retain the human approval for this body")
        if event == "approve": data["approved_read"] = r.host_read
        if event == "schedule":
            require(bool(row.get("scheduledForAt")) and bool(row.get("workflowTraceId")),"CONTENT_SCHEDULE_UNTRACED","schedule must retain its workflow trace")
            require(parsed(row["scheduledForAt"])>=parsed(at),"CONTENT_SCHEDULE_IN_PAST","schedule must not predate the recorded scheduling step")
            data["scheduled_for_at"]=row["scheduledForAt"]
    elif event == "request_changes":
        data["approved_read"] = None
    elif event == "publish":
        request = ConnectorExecutionRequest.model_validate(r.request)
        execution = ExecutionReceipt.model_validate(r.execution)
        require(execution.tool in _PUBLISH_TOOLS and execution.effect == "write" and execution.approval_ref is not None
            and execution.approval_ref == request.approval_ref and execution.request_digest == request.custody_fingerprint()
            and execution.output_digest == stable_digest(r.output) and execution.tool == request.tool,
            "CONTENT_PUBLICATION_UNPROVEN","publication needs the approved exact connector request and output")
        require(execution.project_id == data["entity_scope"]["project_id"] and same_scope(
            EngineScope.model_validate(data["entity_scope"]),EngineScope.model_validate({**detached(request.scope),
                "entity_ref":data["asset_ref"],"currency":plan.currency})),"SOURCE_SCOPE_MISMATCH","publication must execute in the asset scope")
        import hashlib
        body = request.arguments.get("content") or request.arguments.get("body") or request.arguments.get("text") or request.arguments.get("summary")
        require(isinstance(body,str) and hashlib.sha256(body.encode()).hexdigest() == data["body_digest"],
            "CONTENT_BODY_MISMATCH","the connector must publish the exact reviewed body")
        row = _host(r.host_read,plan,at,asset_ref=data["asset_ref"])
        require(row.get("status") == "PUBLISHED" and row.get("bodyDigest") == data["body_digest"]
            and (row.get("canonicalUrlSha256") or row.get("providerPostRefSha256")) and parsed(execution.completed_at) <= parsed(at),
            "CONTENT_PUBLICATION_UNPROVEN","host publication must retain this body and canonical URL")
        _claims(row,plan,execution.completed_at)
        require(data.get("scheduled_for_at") is None or parsed(execution.completed_at)>=parsed(data["scheduled_for_at"]),
            "CONTENT_PUBLICATION_BEFORE_SCHEDULE","execution must respect the approved schedule")
        published_url=r.output.get("url") or r.output.get("canonical_url") or r.output.get("permalink")
        published_ref=r.output.get("post_ref") or r.output.get("post_id") or r.output.get("id") or r.output.get("name")
        for value,commitment in ((published_url,row.get("canonicalUrlSha256")),(published_ref,row.get("providerPostRefSha256"))):
            if commitment is not None:
                require(isinstance(value,str) and hashlib.sha256(value.strip().encode()).hexdigest()==commitment,
                    "CONTENT_PUBLICATION_URL_MISMATCH","host publication commitments must match this exact provider output")
        data.update(published_at=execution.completed_at,canonical_url_commitment=row.get("canonicalUrlSha256"),
            provider_post_commitment=row.get("providerPostRefSha256"))
    elif event == "observe":
        require(len(data.get("windows",[])) < 260,"CONTENT_WINDOW_LIMIT","archive history before adding another window")
        if r.attribution is not None:
            from lightbulb.conversion_attribution import verify_attribution
            ledger = verify_attribution(r.attribution)
            require(ledger.company_ref == plan.company_ref and same_scope(ledger.scope,EngineScope.model_validate(data["entity_scope"]))
                and parsed(ledger.window_end) <= parsed(at),"SOURCE_SCOPE_MISMATCH","content credits must belong to this company and observation time")
            touches = {touch.touch_digest:touch for touch in ledger.touches}
            asset_commitment = stable_digest({"asset_ref":data["asset_ref"]})
            credits = [credit for credit in ledger.credits if touches[credit.touch_digest].asset_commitment == asset_commitment]
            seen = set(data.get("credited_identities",[]))
            require(not any(c.identity_commitment in seen for c in credits),"CONTENT_CREDIT_ALREADY_RECORDED","one economic conversion is credited only once")
            data.update(credited_identities=sorted(seen|{c.identity_commitment for c in credits}),
                credited_conversions=data.get("credited_conversions",0)+len({c.identity_commitment for c in credits}),
                credited_revenue=str(Decimal(str(data.get("credited_revenue",0)))+sum((c.value for c in credits),Decimal(0))))
        else:
            require(data.get("canonical_url_commitment") is not None,"CONTENT_PAGE_REQUIRED","Search Console measures a canonical page; a provider post reference is insufficient")
            read = r.observation
            require(read is not None,"CONTENT_OBSERVATION_REQUIRED","retain the complete organic read")
            provenance = ObservationProvenance.model_validate(read["provenance"]); output=read["output"]
            require(provenance.source_tool == "search_console.query_analytics" and provenance.output_digest == stable_digest(output)
                and parsed(provenance.completed_at) <= parsed(at),"CONTENT_OBSERVATION_MISMATCH","organic evidence must match its governed read")
            require(output.get("schema") == "lightbulb.search_console_organic_observation.v1", "CONTENT_OBSERVATION_SCHEMA", "use the canonical Search Console page observation")
            require(output.get("exhaustive_read") is True and output.get("truncated") is False,"CONTENT_OBSERVATION_TRUNCATED","absence in a partial read is not zero")
            from datetime import date, timedelta
            require(output.get("evidence_sha256") == stable_digest({k:v for k,v in output.items() if k not in ("evidence_sha256","observed_at")}),
                "CONTENT_OBSERVATION_MISMATCH","recompute the canonical organic evidence commitment")
            start=output["window_start"]+"T00:00:00Z"
            end=(date.fromisoformat(output["window_end"])+timedelta(days=1)).isoformat()+"T00:00:00Z"
            require(parsed(end) <= parsed(output["observed_at"]) <= parsed(provenance.completed_at),
                "CONTENT_WINDOW_INVALID","final data must be observed after the complete measurement window")
            require(output.get("row_count") == len(output["rows"]),"CONTENT_OBSERVATION_MISMATCH","the canonical row count must be exact")
            seen=set(); all_clicks=0; all_impressions=0
            for row in output["rows"]:
                key=(row["date"],row["page_url_sha256"])
                require(key not in seen and output["window_start"]<=row["date"]<=output["window_end"],
                    "CONTENT_PAGE_DUPLICATE","page/day keys must be unique and inside the measured window")
                seen.add(key)
                require(type(row["clicks"]) is int and type(row["impressions"]) is int and 0<=row["clicks"]<=row["impressions"],
                    "CONTENT_METRIC_INVALID","organic counts must be exact nonnegative integers")
                all_clicks+=row["clicks"]; all_impressions+=row["impressions"]
            require(output["totals"] == {"clicks":all_clicks,"impressions":all_impressions},
                "CONTENT_OBSERVATION_MISMATCH","organic totals must conserve all page/day rows")
            require(parsed(end)<=parsed(at) and parsed(start)>=parsed(data["published_at"])
                and (parsed(end)-parsed(start)).days>=plan.min_observation_window_days
                and (data.get("last_window_end") is None or parsed(start)>=parsed(data["last_window_end"])),
                "CONTENT_WINDOW_INVALID","organic windows must be complete, post-publication and non-overlapping")
            rows = [row for row in output["rows"] if row.get("page_url_sha256") == data["canonical_url_commitment"]]
            clicks=sum(row["clicks"] for row in rows); impressions=sum(row["impressions"] for row in rows)
            require(type(clicks) is int and type(impressions) is int and 0<=clicks<=impressions,"CONTENT_METRIC_INVALID","organic counts must be exact nonnegative integers")
            windows=list(data.get("windows",[])); windows.append({"window_start":start,"window_end":end,"clicks":clicks,"impressions":impressions,"read":read})
            data.update(windows=windows,last_window_end=end,cumulative_clicks=data.get("cumulative_clicks",0)+clicks,
                cumulative_impressions=data.get("cumulative_impressions",0)+impressions)
            if clicks: data["last_click_window_end"]=end
    elif event == "repurpose":
        child=_host(r.derivative,plan,at)
        require(bool(data.get("windows")) and child.get("derivedFromAssetRef")==data["asset_ref"]
            and child.get("assetRef") not in [data["asset_ref"],*data.get("derivatives",[])],
            "CONTENT_DERIVATIVE_UNPROVEN","a new registered derivative must name its observed parent")
        require(len(data.get("derivatives",[]))<plan.max_derivatives_per_asset,"CONTENT_DERIVATIVE_LIMIT","the plan caps derivatives")
        data["derivatives"]=[*data.get("derivatives",[]),child["assetRef"]]
    elif event == "retire":
        require(bool(data.get("windows")),"CONTENT_UNOBSERVED","an asset needs an exhaustive measurement before retirement")
        quiet_start=data["last_window_end"]
        for window in reversed(data["windows"]):
            if window["clicks"] or window["window_end"] != quiet_start: break
            quiet_start=window["window_start"]
        last=max(quiet_start,data.get("last_click_window_end") or data["published_at"])
        require(data["windows"][-1]["clicks"]==0 and (parsed(data["last_window_end"])-parsed(last)).days>=plan.retire_min_days_since_last_click,
            "CONTENT_STILL_EARNING","retirement requires measured inactivity through the quiet horizon")
        data["retired_at"]=at
    return next_status,data

class _ContentLifecycle(LifecycleSpec):
    def bind(self,plan,state):
        policy,bound=super().bind(plan,state)
        if not same_scope(bound.scope,EngineScope.model_validate(bound.ledger.entity_scope)) or bound.scope.entity_ref!=bound.ledger.entity_scope["entity_ref"]:
            raise ValueError("SOURCE_SCOPE_MISMATCH: retained content evidence must use the state scope")
        return policy,bound

    def open(self,plan,scope,**kwargs):
        state=super().open(plan,scope,**kwargs)
        return self.bind(plan,state)[1]


CONTENT_ASSET_LIFECYCLE=_ContentLifecycle(entity="content_asset",schema_prefix="content_asset_lifecycle",statuses=ASSET_STATUSES,
    terminal=TERMINAL_ASSET_STATUSES,events=ASSET_EVENTS,table=_TABLE,opening_event="brief",reason_events=("request_changes","retire"),
    apply=_apply,ledger_model=AssetLedger,receipt_model=ContentAssetReceipt,effect_boundary_model=ContentEffectBoundary,
    plan_model=ContentAssetPlan,max_transitions=400)
ContentAssetState=CONTENT_ASSET_LIFECYCLE.State

def open_content_asset(plan,scope,*,receipt,opened_at,actor_ref):
    return CONTENT_ASSET_LIFECYCLE.open(plan,scope,receipt={**detached(receipt),"entity_scope":detached(scope)},opened_at=opened_at,actor_ref=actor_ref)

def advance_content_asset(plan,state,command):
    return CONTENT_ASSET_LIFECYCLE.advance(plan,state,command)

class ContentLibrary(StrictModel):
    schema_id: Literal["lightbulb.content_library.v1"] = Field(default="lightbulb.content_library.v1",alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    observed_at: str
    assets: tuple[dict[str,Any],...]
    cost_register: dict[str,Any]
    cost_plan: dict[str,Any]
    allocations: tuple[dict[str,Any],...]
    rows: tuple[dict[str,Any],...]
    period_start: str
    period_end: str
    allocated_production_cost: Decimal
    unallocated_cost: Decimal
    allocation_basis: Literal["declared_source_allocation"] = "declared_source_allocation"
    posts_money: Literal[False] = False
    library_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("allocated_production_cost","unallocated_cost",mode="before")
    @classmethod
    def cost(cls,value,info):
        return decimal_value(value,field_name=info.field_name)

    @model_validator(mode="after")
    def exact(self,info):
        if not skip_digests(info) and self.library_digest!=sealed_digest(type(self),self,"library_digest"):
            raise ValueError("CONTENT_LIBRARY_DIGEST_MISMATCH")
        return self


def content_library(assets, cost_register, *, cost_plan, allocations, company_ref, scope, observed_at):
    """Replay selected assets and allocate already-recorded costs without reposting.

    Allocations are an explicit reporting policy over source refs, not new bills.
    The complete allocation vector conserves the protected register numerator.
    Lifetime performance stays separate from this register period's cost.
    """
    from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE
    cp,register=COST_REGISTER_LIFECYCLE.bind(cost_plan,cost_register)
    scoped=EngineScope.model_validate(detached(scope))
    if cp.company_ref!=company_ref or not same_scope(register.scope,scoped):
        raise ValueError("SOURCE_SCOPE_MISMATCH: protected costs belong to another company")
    if register.status=="abandoned" or parsed(register.transition_history[-1].command.occurred_at)>parsed(observed_at):
        raise ValueError("CONTENT_COST_SOURCE_INVALID")
    bound={};retained=[]
    for pair in assets:
        policy,state=CONTENT_ASSET_LIFECYCLE.bind(pair["plan"],pair["state"])
        if policy.company_ref!=company_ref or not same_scope(state.scope,scoped):
            raise ValueError("SOURCE_SCOPE_MISMATCH: content belongs to another company")
        if state.ledger.asset_ref in bound or parsed(state.transition_history[-1].command.occurred_at)>parsed(observed_at):
            raise ValueError("CONTENT_LIBRARY_ASSET_INVALID")
        bound[state.ledger.asset_ref]=state
        retained.append({"plan":policy.to_dict(),"state":state.to_dict()})
    sources={r.source_ref:r for r in register.ledger.sources if r.spend_amount>0}
    totals={};per_asset={};seen=set();allocation_rows=[]
    for item in allocations:
        if set(item)!={"asset_ref","source_ref","amount"}:
            raise ValueError("CONTENT_COST_ALLOCATION_INVALID")
        asset,source=item["asset_ref"],item["source_ref"]
        amount=decimal_value(item["amount"],field_name="amount")
        if asset not in bound or source not in sources or (asset,source) in seen or amount<=0:
            raise ValueError("CONTENT_COST_ALLOCATION_INVALID")
        row=sources[source]
        if row.source_kind not in {"inference_cost","payable","spend_case","worker","metered_dispatch","payroll"}:
            raise ValueError("CONTENT_PRODUCTION_SOURCE_REQUIRED")
        seen.add((asset,source));totals[source]=totals.get(source,Decimal(0))+amount
        if totals[source]>row.spend_amount:
            raise ValueError("CONTENT_COST_OVERALLOCATED")
        per_asset[asset]=per_asset.get(asset,Decimal(0))+amount
        allocation_rows.append({"asset_ref":asset,"source_ref":source,"amount":str(amount)})
    rows=[]
    for ref,state in sorted(bound.items()):
        ledger=state.ledger
        decline=None
        if len(ledger.windows)>=2:
            previous,current=ledger.windows[-2:]
            if previous["window_end"]==current["window_start"] and previous["clicks"]>0 and parsed(previous["window_end"])-parsed(previous["window_start"])==parsed(current["window_end"])-parsed(current["window_start"]):
                decline=max(Decimal(0),(Decimal(previous["clicks"])-Decimal(current["clicks"]))/Decimal(previous["clicks"]))
        rows.append({"asset_ref":ref,"status":state.status,"channel":ledger.channel,
            "production_cost_in_period":str(per_asset.get(ref,Decimal(0))),
            "lifetime_credited_revenue":str(ledger.credited_revenue),"lifetime_clicks":ledger.cumulative_clicks,
            "click_decline_ratio":None if decline is None else str(decline),
            "refresh_suggested":decline is not None and decline>=Decimal("0.30") and state.status!="retired",
            "state_digest":state.state_digest})
    total=sum((r.spend_amount for r in register.ledger.sources),Decimal(0))
    allocated=sum(per_asset.values(),Decimal(0))
    return seal(ContentLibrary,{"company_ref":company_ref,"scope":scoped.to_dict(),"observed_at":observed_at,
        "assets":retained,"cost_register":register.to_dict(),"cost_plan":cp.to_dict(),"allocations":allocation_rows,
        "rows":rows,"period_start":register.ledger.period_start,"period_end":register.ledger.period_end,
        "allocated_production_cost":allocated,"unallocated_cost":total-allocated},"library_digest")


def verify_content_library(value):
    library=ContentLibrary.model_validate(detached(value))
    expected=content_library(library.assets,library.cost_register,cost_plan=library.cost_plan,
        allocations=library.allocations,company_ref=library.company_ref,scope=library.scope,observed_at=library.observed_at)
    if expected.library_digest!=library.library_digest:
        raise ValueError("CONTENT_LIBRARY_SOURCE_MISMATCH")
    return library


CONTENT_ASSET_MANIFEST={"schema":"lightbulb.company_engine_manifest.v1","engine":CONTENT_ASSET_KIND,
    "golden_loop":CONTENT_ASSET_GOLDEN_LOOP,"stages":["brief","draft","review","approve","schedule","publish","observe","repurpose_or_retire"],
    "statuses":list(ASSET_STATUSES),"events":list(ASSET_EVENTS),"hard_rules":["publish the exact approved body", "organic observations never create revenue",
        "content costs enter the protected register once", "a derivative preserves its parent", "unobserved assets cannot be retired"]}
__all__=["CONTENT_ASSET_KIND","CONTENT_ASSET_GOLDEN_LOOP","CONTENT_ASSET_LIFECYCLE","CONTENT_ASSET_MANIFEST","ASSET_STATUSES","ASSET_EVENTS",
    "TERMINAL_ASSET_STATUSES","ContentAssetPlan","ContentAssetReceipt","ContentAssetState","AssetLedger","compile_content_asset_plan","open_content_asset","advance_content_asset","ContentLibrary","content_library","verify_content_library"]
