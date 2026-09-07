"""Trusted company host: observed periods, conservative decisions and approvals.

The host configuration names retained business engines, source coverage and
provider object mappings. It cannot make missing evidence complete. All reads,
decisions and write proofs use authenticated Spring checkpoint journals.
"""
from dataclasses import dataclass
from datetime import timedelta
from lightbulb.company_engine_core import detached, stable_digest, parsed, same_scope
from lightbulb.company_observation_host import _write, _require, ReallocationExecutionHost
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult, ExecutionScope
from lightbulb.company_execution_bridge import execution_receipt_from_connector, provenance_from_execution_receipt
from lightbulb.trusted_touch_sources import using_touch_verifier


def _days(start, end):
    cursor = parsed(start)
    stop = parsed(end)
    _require(cursor < stop and (stop-cursor).total_seconds() % 86400 == 0 and (stop-cursor).days <= 366, "GROWTH_PERIOD_DAYS_INVALID")
    while cursor < stop:
        following = cursor + timedelta(days=1)
        yield cursor.isoformat().replace("+00:00","Z"), following.isoformat().replace("+00:00","Z")
        cursor = following


@dataclass
class CompanyGrowthHost:
    intake: object
    configuration: dict

    def __post_init__(self):
        _require(set(self.configuration) <= {"periods","reallocations"}, "GROWTH_HOST_CONFIGURATION_INVALID")
        items = [*self.configuration.get("periods",()), *self.configuration.get("reallocations",())]
        _require(len(items)<=32 and len({x["ref"] for x in items})==len(items),"GROWTH_HOST_CONFIGURATION_INVALID")

    @property
    def console(self): return self.intake.console
    @property
    def gateway(self): return self.intake.gateway

    def step(self, *, now, fence):
        reports=[]
        with using_touch_verifier(self.intake.touch_verifier):
            work=[("period",spec,self.period) for spec in self.configuration.get("periods",()) if parsed(spec["portfolio"]["period_end"])<=parsed(now)]
            work += [("decision",spec,self.reallocate) for spec in self.configuration.get("reallocations",()) if parsed(spec["portfolio"]["period_start"])<=parsed(now)]
            for kind,spec,run in work:
                try:
                    reports.append(run(spec,now=now,fence=fence))
                except (ValueError,LookupError) as exc:
                    ref,old=self._existing(kind,spec)
                    # Preserve partial execution proof and report a terminal
                    # disposition without aborting unrelated company work.
                    terminal = any(code in str(exc) for code in ("REALLOCATION_PERIOD_EXPIRED","REALLOCATION_EVIDENCE_STALE","BUDGET_TARGET_READ_STALE"))
                    report={**(old or {}),"configuration_digest":stable_digest(spec),"status":"BLOCKED","complete":False,"terminal":terminal,
                        "error_code":getattr(exc,"code",str(exc).split(":",1)[0])[:160]}
                    fence();reports.append(_write(self.gateway,ref,report,old))
        return {"all_applied":all(r.get("complete",False) for r in reports),
                "ready_for_cadence":all(r.get("complete",False) or r.get("terminal",False) for r in reports),"reports":reports}

    def _existing(self, kind, spec):
        ref="company-growth-"+kind+"-"+spec["ref"]
        old=self.gateway.get(ref)
        if old is not None:
            _require(old.get("configuration_digest")==stable_digest(spec),"GROWTH_CONFIGURATION_CHANGED: use a new operation reference")
        return ref,old

    def period(self, spec, *, now, fence):
        from lightbulb.growth_engine_loop import CampaignPortfolio
        from lightbulb.conversion_attribution import conversion_from_revenue, attribute_conversions
        from lightbulb.company_cost_centres import REVENUE_STATE_SCHEMAS, SETTLED_REVENUE_STATUSES
        portfolio=CampaignPortfolio.model_validate(spec["portfolio"])
        ref,old=self._existing("period",spec)
        if old is not None and old.get("eligible_for_budget_decisions"):
            return old
        _require(portfolio.plan_digest==self.console.bundle.growth_plan.plan_digest,"GROWTH_PLAN_MISMATCH")
        required=set(spec.get("required_source_refs",()))
        sources={s.source_ref:s for s in self.intake.sources}
        _require(required and required<=set(sources),"SOURCE_CENSUS_REQUIRED: name every configured source required for this period")
        missing=[]; touches={}; cohorts=[]; coverage=[]
        for start,end in _days(portfolio.period_start,portfolio.period_end):
            for source_ref in sorted(required):
                source=sources[source_ref]
                observation=self.intake.retained(source,start=start,end=end)
                if observation is None:
                    missing.append({"source_ref":source_ref,"start":start,"end":end});continue
                artifact=observation["ingestion"]
                coverage.append({"source_ref":source_ref,"start":start,"end":end,"binding_digest":observation["binding_digest"]})
                for touch in self.intake.touches(artifact) if source.kind=="marketing_touches" else ():
                    prior=touches.get(touch["touch_ref"])
                    _require(prior is None or prior==touch,"TOUCH_SOURCE_CONFLICT")
                    touches[touch["touch_ref"]]=touch
                if source_ref==spec.get("cohort_source_ref"):
                    cohorts.extend(artifact.get("cohorts",()))
        # Include retained lookback without claiming missing historical intake
        # was observed. Revenue is still conserved as direct/unattributed.
        lookback_missing=[]
        lookback_start=(parsed(portfolio.period_start)-timedelta(days=self.console.bundle.growth_plan.blueprint.attribution_window_days)).isoformat().replace("+00:00","Z")
        for start,end in _days(lookback_start,portfolio.period_start):
            for source_ref in sorted(required):
                source=sources[source_ref]
                if source.kind!="marketing_touches":continue
                observation=self.intake.retained(source,start=start,end=end)
                if observation is None:
                    lookback_missing.append({"source_ref":source_ref,"start":start,"end":end});continue
                for touch in self.intake.touches(observation["ingestion"]):
                    prior=touches.get(touch["touch_ref"])
                    _require(prior is None or prior==touch,"TOUCH_SOURCE_CONFLICT")
                    touches[touch["touch_ref"]]=touch
        base={"schema":"lightbulb.company_growth_period_checkpoint.v1","configuration_digest":stable_digest(spec),
              "complete":False,"missing_sources":missing,"coverage":coverage,"missing_touch_lookback":lookback_missing,
              "coverage_basis":"declared_source_census","external_liabilities_proven_complete":False}
        if missing:
            fence();return _write(self.gateway,ref,{**base,"status":"NEEDS_INPUT"},old)
        conversions=[]; failures=[]
        _require(bool(spec.get("revenue_engines")),"REVENUE_SOURCE_CENSUS_REQUIRED")
        for engine in spec["revenue_engines"]:
            plan=self.console._plan_for(engine)
            fence()
            for record in self.console.store.list_all(engine=engine):
                state=record["state"]
                _require(state["schema"] in REVENUE_STATE_SCHEMAS,"REVENUE_SOURCE_ENGINE_UNSUPPORTED")
                if state["status"] not in SETTLED_REVENUE_STATUSES|({"paid"} if state["schema"]=="lightbulb.job_chain_state.v1" else set()):continue
                try:
                    conversion=conversion_from_revenue(state,source_plan=plan)
                    if parsed(portfolio.period_start)<=parsed(conversion.occurred_at)<parsed(portfolio.period_end):
                        conversions.append(conversion)
                except ValueError as exc:
                    failures.append({"engine":engine,"entity_ref":record["entity_ref"],"code":getattr(exc,"code",str(exc)[:160])})
        if failures:
            fence();return _write(self.gateway,ref,{**base,"status":"NEEDS_INPUT","revenue_failures":failures},old)
        scope={**self.console.bundle.scope,"entity_ref":spec["register_ref"],"currency":self.console.bundle.operating_plan.blueprint.currency}
        attribution=attribute_conversions(company_ref=self.console.bundle.company_ref,scope=scope,portfolio_digest=portfolio.portfolio_digest,
            window_start=portfolio.period_start,window_end=portfolio.period_end,attribution_window_days=self.console.bundle.growth_plan.blueprint.attribution_window_days,
            conversions=conversions,touches=list(touches.values()),holdout_units=spec.get("holdout_units",()),
            method={"last_touch":"last_eligible_touch","first_touch":"first_eligible_touch","linear":"linear_eligible_touches"}[self.console.bundle.growth_plan.blueprint.attribution_model])
        cohort=self._cohort(cohorts,portfolio,now) if spec.get("cohort_source_ref") else None
        report=self.console.growth_period(portfolio.to_dict(),attribution.to_dict(),register_ref=spec["register_ref"],
            acquisition_engines=spec.get("acquisition_engines",("growth_engine","pipeline_engine")),customer_cohort=cohort,now=now)
        content=None
        if spec.get("content_asset_refs"):
            _require("content_allocations" in spec,"CONTENT_ALLOCATION_REQUIRED")
            content=self.console.content_library(spec["content_asset_refs"],register_ref=spec["register_ref"],allocations=spec["content_allocations"],now=now)
        fold=report["fold"]
        criteria={"declared_sources_ingested":True,"trusted_touch_lookback_complete":not lookback_missing,
                  "first_purchase_history_verified":cohort is not None,"protected_cost_register_reconciled":fold["cost_register_status"]=="closed" and bool(fold["cost_register"]["ledger"].get("coverage_digest")) and (str(fold.get("cost_coverage_percent")) in {"100","100.00"} or fold.get("cost_coverage_percent") is None and str(fold["cost_register"]["ledger"]["reconciled_cash_out"]) in {"0","0.00"}),
                  "content_allocations_checked":content is not None or not spec.get("content_asset_refs")}
        fence();return _write(self.gateway,ref,{**base,"status":"COMPLETED","complete":True,"economics":report,"content":content,
            "acceptance":criteria,"eligible_for_budget_decisions":all(criteria.values())},old)

    def _cohort(self, cohorts, portfolio, now):
        from lightbulb.growth_customers import verify_customer_cohort_evidence,mint_customer_cohort_evidence,CustomerCohortEvidence
        _require(bool(cohorts),"COHORT_SOURCE_INCOMPLETE")
        checked=sorted([verify_customer_cohort_evidence(c,scope=self.console.cohort_scope,scope_keyring=self.console.cohort_keyring) for c in cohorts],key=lambda c:c.acquisition_window_start)
        cursor=portfolio.period_start;first=checked[0]
        for row in checked:
            _require(row.acquisition_window_start==cursor and row.connector_account_ref==first.connector_account_ref and row.provider==first.provider and row.currency==first.currency and parsed(row.observed_at)<=parsed(now),"COHORT_COVERAGE_INVALID")
            cursor=row.acquisition_window_end
        _require(cursor==portfolio.period_end,"COHORT_COVERAGE_INVALID")
        digest=stable_digest([row.model_dump(mode="json") for row in checked])
        joined=CustomerCohortEvidence(cohort_ref="period-"+digest[:32],connector_account_ref=first.connector_account_ref,provider=first.provider,
            source_capability=first.source_capability,currency=first.currency,acquisition_window_start=portfolio.period_start,acquisition_window_end=portfolio.period_end,
            observed_at=max(c.observed_at for c in checked),cohort_size=sum(c.cohort_size for c in checked),age_buckets=(),evidence_digest=digest)
        return mint_customer_cohort_evidence(joined,scope=self.console.cohort_scope,scope_keyring=self.console.cohort_keyring).model_dump(mode="json")

    def _read(self, spec, read_spec, *, now, fence):
        scope=ExecutionScope(**self.console.bundle.scope,actor_ref=self.console.bundle.actor_ref)
        request=ConnectorExecutionRequest(tool=read_spec["tool"],arguments=read_spec["arguments"],connector_account_ref=read_spec["connector_account_ref"],scope=scope,effect="read",
            idempotency_key="growth-read-"+stable_digest({"decision":spec["ref"],"read":read_spec}))
        ref=request.idempotency_key;old=self.gateway.get(ref)
        if old is None:
            fence();old=_write(self.gateway,ref,{"status":"RUNNING","request":request.model_dump(mode="json",by_alias=True)})
        _require(old["request"]==request.model_dump(mode="json",by_alias=True),"GROWTH_READ_BINDING_CHANGED")
        if old.get("result") is None:
            fence();result=ConnectorExecutionResult.model_validate(detached(self.intake.executor.execute(request)))
            execution_receipt_from_connector(result,request)
            old=_write(self.gateway,ref,{**old,"status":"COMPLETED","result":result.model_dump(mode="json",by_alias=True)},old)
        result=ConnectorExecutionResult.model_validate(old["result"])
        receipt=execution_receipt_from_connector(result,request)
        now=max((now,self.console.clock()),key=parsed)
        _require(parsed(receipt.completed_at)<=parsed(now)<=parsed(receipt.completed_at)+timedelta(hours=24),"BUDGET_TARGET_READ_STALE")
        return {"provenance":provenance_from_execution_receipt(receipt).to_dict(),"output":result.output}

    def reallocate(self, spec, *, now, fence):
        from lightbulb.growth_reallocation import propose_incremental_reallocation,compile_budget_write_plan,object_bindings,envelope_object_map
        ref,old=self._existing("decision",spec)
        if old is not None and (old.get("complete") or old.get("terminal")):return old
        _require(parsed(now)<parsed(spec["portfolio"]["period_end"]),"REALLOCATION_PERIOD_EXPIRED")
        if old is None or old.get("write_plan") is None:
            period=self.gateway.get("company-growth-period-"+spec["economic_period_ref"])
            if period is None or not period.get("eligible_for_budget_decisions"):
                fence();return _write(self.gateway,ref,{"status":"NEEDS_INPUT","configuration_digest":stable_digest(spec),"complete":False,"reason":"economic acceptance criteria are unmet"},old)
            campaigns=[]
            for entity in spec.get("campaign_refs",()):
                record=self.console.store.get("growth_engine",entity)
                _require(record is not None,"CAMPAIGN_STATE_REQUIRED");campaigns.append(record["state"])
            returns=[]
            for source_ref in spec.get("return_checkpoint_refs",()):
                retained=self.gateway.get(source_ref)
                _require(retained is not None,"MARGINAL_RETURN_REQUIRED");returns.append(retained["marginal_return"])
            proposal=propose_incremental_reallocation(self.console.bundle.growth_plan,spec["portfolio"],campaigns,returns=returns,
                scope=self.console.cohort_scope,scope_keyring=self.console.cohort_keyring,
                engine_scope=self.console.bundle.engine_scope("reallocation"),company_ref=self.console.bundle.company_ref,designs=spec.get("designs",()),proposed_at=now)
            base={"configuration_digest":stable_digest(spec),"proposal":proposal.to_dict(),"economic_period_ref":spec["economic_period_ref"]}
            if not proposal.shifts:
                fence();return _write(self.gateway,ref,{**base,"status":"COMPLETED","complete":True,"decision":"hold"},old)
            bindings=[];accounts={}
            for channel,reads in spec["provider_reads"].items():
                observed=self._read(spec,reads["objects"],now=now,fence=fence)
                bindings.extend(object_bindings(observed["provenance"],observed["output"],channel=channel))
                accounts[channel]=self._read(spec,reads["account"],now=now,fence=fence)
            now=max((now,self.console.clock()),key=parsed)
            mapping=envelope_object_map(spec["portfolio"],spec["object_entries"],declared_by_ref=self.console.bundle.actor_ref,declared_at=now,bindings=bindings)
            plan=compile_budget_write_plan(self.console.bundle.growth_plan,spec["portfolio"],proposal,mapping,compiled_at=now,account_observations=accounts,
                require_all_channels=True,scope=self.console.cohort_scope,scope_keyring=self.console.cohort_keyring)
            fence();old=_write(self.gateway,ref,{**base,"status":"PENDING_APPROVAL","complete":False,"write_plan":plan.to_dict(),
                "identifiers_by_unit":{u.unit_ref:spec["identifiers_by_envelope"][u.envelope_ref] for u in plan.units}},old)
        execution=ReallocationExecutionHost(self.gateway,self.intake.executor,self.console.clock)
        report=execution.step(old["write_plan"],scope=ExecutionScope(**self.console.bundle.scope,actor_ref=self.console.bundle.actor_ref),
            connector_account_refs=spec["connector_account_refs"],identifiers_by_unit=old["identifiers_by_unit"],now=now,fence=fence)
        fence();return _write(self.gateway,ref,{**old,"status":"COMPLETED" if report["all_applied"] else "PENDING_APPROVAL","complete":report["all_applied"],"execution":report},old)
