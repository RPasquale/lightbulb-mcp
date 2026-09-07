"""Durable host execution of company intake and approved budget changes.

Uses the existing Spring project-runtime checkpoints and Connector Runtime.
Every provider request and result is retained before ingestion; stable request
identity makes a lost response recover through the server's execution journal.
The host supplies authenticated configuration, not a model-facing write API.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Mapping
from lightbulb.company_engine_core import detached, stable_digest, parsed, EngineScope
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult, ExecutionScope
from lightbulb.company_execution_bridge import execution_receipt_from_connector, provenance_from_execution_receipt
from lightbulb.company_recurring_observations import RecurringObservationBinding
from lightbulb.trusted_touch_sources import using_touch_verifier, touches_from_posthog


def _require(value, code):
    if not value:
        raise ValueError(code)


def _write(gateway, ref, document, current=None):
    return dict(gateway.put(ref, {**document, "run_ref":ref, "resume_at":None},
                            expected_revision=0 if current is None else int(current["revision"])))


def _same_binding(record, digest):
    _require(record.get("binding_digest") == digest, "HOST_OPERATION_BINDING_CHANGED")


@dataclass
class CompanyObservationHost:
    console: Any
    gateway: Any
    executor: Any
    sources: tuple[RecurringObservationBinding, ...]
    touch_verifier: Any = field(default=None, repr=False)

    def __post_init__(self):
        self.sources = tuple(RecurringObservationBinding.model_validate(detached(x)) for x in self.sources)
        _require(len(self.sources) <= 100 and len({s.source_ref for s in self.sources}) == len(self.sources), "OBSERVATION_BINDINGS_INVALID")
        if self.console.bundle.growth_plan is not None and self.console.bundle.growth_plan.blueprint.require_demand_registry:
            _require(all(s.demand_registry_ref for s in self.sources if s.kind == "channel_spend"),"DEMAND_DESTINATION_REQUIRED")

    def retained(self, source, *, start, end):
        job = source.job(start=start,end=end)
        identity = stable_digest({"bundle":self.console.bundle.plan_digest,"job":job.job_digest})
        record = self.gateway.get("company-observation-"+identity)
        if record is None or record.get("phase") != "ingested":
            return None
        _same_binding(record,identity)
        request = ConnectorExecutionRequest.model_validate(record["request"])
        _require(request.arguments==job.arguments and request.tool==source.tool and request.connector_account_ref==source.connector_account_ref,
                 "HOST_OPERATION_REQUEST_CHANGED")
        execution_receipt_from_connector(record["result"],request)
        return record

    def cycle(self, *, start, end, now, fence: Callable[[], Any]):
        """Run each configured source once for an exact completed window.

        A failed cycle keeps its window. Successful jobs are reused, and engine
        ingestion has a separate stable transition identity for crash recovery.
        ``fence`` renews the parent Spring lease immediately before each effect.
        """
        _require(parsed(start) < parsed(end) <= parsed(now), "OBSERVATION_WINDOW_NOT_COMPLETE")
        results, failures = [], []
        # Read/ingest budget reductions and spend before downstream decisions.
        ordered = sorted(self.sources, key=lambda s: (s.kind != "channel_spend", s.kind != "local_performance", s.source_ref))
        with using_touch_verifier(self.touch_verifier):
            for source in ordered:
                job = source.job(start=start, end=end)
                identity = stable_digest({"bundle":self.console.bundle.plan_digest, "job":job.job_digest})
                ref = "company-observation-" + identity
                scope = ExecutionScope(**self.console.bundle.scope, actor_ref=self.console.bundle.actor_ref)
                request = ConnectorExecutionRequest(tool=source.tool, arguments=job.arguments,
                    scope=scope, connector_account_ref=source.connector_account_ref, effect="read",
                    idempotency_key="observation-"+identity)
                current = self.gateway.get(ref)
                if current is not None:
                    _same_binding(current, identity)
                    _require(current.get("request") == request.model_dump(mode="json",by_alias=True), "HOST_OPERATION_REQUEST_CHANGED")
                else:
                    fence()
                    current = _write(self.gateway,ref,{"schema":"lightbulb.company_observation_checkpoint.v1",
                        "status":"RUNNING", "binding_digest":identity, "job":job.to_dict(),
                        "request":request.model_dump(mode="json",by_alias=True), "phase":"read"})
                if current.get("phase") == "ingested":
                    results.append(current["ingestion"])
                    continue
                try:
                    if current.get("result") is None:
                        fence()
                        result = self.executor.execute(request)
                        result = ConnectorExecutionResult.model_validate(detached(result))
                        execution_receipt_from_connector(result,request)
                        current = _write(self.gateway,ref,{**current,"result":result.model_dump(mode="json",by_alias=True),"phase":"ingest"},current)
                    result = ConnectorExecutionResult.model_validate(current["result"])
                    fence()
                    ingestion = self._ingest(source, job, request, result, now=now, identity=identity, fence=fence)
                    current = _write(self.gateway,ref,{**current,"phase":"ingested","status":"COMPLETED","ingestion":ingestion},current)
                    results.append(ingestion)
                except (ValueError, LookupError) as exc:
                    failures.append({"source_ref":source.source_ref,"code":getattr(exc,"code",type(exc).__name__),"detail":str(exc)[:500]})
        return {"complete":not failures, "window_start":start,"window_end":end,"results":results,"failures":failures}

    def _apply(self, engine, entity, event, receipt, *, now, identity):
        from lightbulb.company_operator_surface import CompanyOperatorSurface, _scope
        runtime = CompanyOperatorSurface(self.console).runtime(engine)
        state = runtime.load(entity)
        _scope(self.console.bundle,state)
        key = "observation-"+identity
        prior = next((t.command for t in state.transition_history if t.command.idempotency_key == key),None)
        if prior is not None:
            _require(prior.event == event and detached(prior.receipt) == detached(runtime.spec.receipt_model.model_validate(receipt)), "OBSERVATION_INGESTION_CHANGED")
            return {"kind":engine,"entity_ref":entity,"state_digest":state.state_digest,"already_ingested":True}
        command = runtime.command(state,event=event,transition_ref=key,idempotency_key=key,
            occurred_at=now,actor_ref=self.console.bundle.actor_ref,receipt=receipt)
        outcome = runtime.advance_and_persist(entity,command)
        _require(outcome.persisted, "OBSERVATION_ENGINE_REFUSED:"+str(outcome.result.receipt.rejection_code))
        return {"kind":engine,"entity_ref":entity,"state_digest":outcome.result.state.state_digest,"already_ingested":False}

    def _ingest(self, source, job, request, result, *, now, identity, fence):
        now = max((now,self.console.clock()),key=parsed)
        receipt = execution_receipt_from_connector(result,request)
        _require(parsed(receipt.completed_at) <= parsed(now), "OBSERVATION_FROM_FUTURE")
        provenance = provenance_from_execution_receipt(receipt,window_start=job.window_start,window_end=job.window_end)
        output = dict(result.output)
        if source.kind == "channel_spend":
            from lightbulb.channel_spend_statements import statement_from_observation
            from lightbulb.company_cost_centres import channel_spend_cost_receipt
            from lightbulb.company_operator_surface import CompanyOperatorSurface
            runtime = CompanyOperatorSurface(self.console).runtime("company_cost_centres")
            state = runtime.load(source.target_entity_ref)
            statement = statement_from_observation(company_ref=self.console.bundle.company_ref,scope=state.scope,
                channel=source.channel,provenance=provenance,output=output)
            fields = channel_spend_cost_receipt(statement,source_plan=runtime.plan,centre_ref=source.centre_ref)
            existing = next((s for s in state.ledger.sources if s.source_ref == fields["source_ref"]),None)
            if existing is not None:
                _require(existing.source_digest == fields["source_digest"], "SPEND_SOURCE_VERSION_CHANGED")
                applied = {"already_ingested":True}
            else:
                applied = self._apply("company_cost_centres",source.target_entity_ref,"record_source",fields,now=now,identity=identity)
            pacing = None
            if source.demand_registry_ref:
                pacing = self._apply("demand_envelope",source.demand_registry_ref,"observe_spend",{"statement":statement.to_dict()},now=now,identity=identity+"-demand")
                demand = CompanyOperatorSurface(self.console).runtime("demand_envelope").load(source.demand_registry_ref)
                pacing = {**pacing,"status":demand.status,"alerts":list(demand.ledger.pacing_alerts)}
                if demand.status == "paused":
                    pacing["provider_controls"] = self._pacing_controls(source,statement,demand,now=now,identity=identity,fence=fence)
                    _require(pacing["provider_controls"]["complete"],"PACING_PAUSE_AWAITS_APPROVAL_OR_RECONCILIATION")
            return {**applied,"kind":"channel_spend","statement":statement.to_dict(),"pacing":pacing}
        if source.kind == "marketing_touches":
            _require(self.touch_verifier is not None,"TOUCH_VERIFIER_REQUIRED")
            return self._touch_pages(source,request,result,now=now,identity=identity,fence=fence)
        if source.kind in {"local_profile","local_verification","local_performance"}:
            from lightbulb.local_presence_engine import location_receipt,verification_receipt,performance_receipt
            from lightbulb.company_operator_surface import CompanyOperatorSurface
            runtime = CompanyOperatorSurface(self.console).runtime("local_presence_engine")
            if source.kind == "local_profile":
                fields = location_receipt(provenance,output,location_commitment=runtime.plan.location_commitment)
            elif source.kind == "local_verification":
                fields = verification_receipt(provenance,output)
            else:
                fields = performance_receipt(provenance,output)
            _require(fields["location_commitment"]==runtime.plan.location_commitment,"LOCAL_LOCATION_MISMATCH")
            state=runtime.load(source.target_entity_ref)
            if source.kind == "local_verification":
                if state.status == "verification_pending" and fields["verification_state"] == "PENDING":
                    return {"kind":source.kind,"entity_ref":source.target_entity_ref,"verification_state":"PENDING","action":"await_provider_verification"}
                if state.status in {"verified","published"}:
                    _require(fields["verification_state"]=="COMPLETED","LOCAL_VERIFICATION_DRIFT_RECONCILIATION_REQUIRED")
                    return {"kind":source.kind,"entity_ref":source.target_entity_ref,"verification_state":"COMPLETED","observation_ref":fields["observation_ref"]}
            if source.kind == "local_profile" and parsed(job.window_end) < parsed(now).replace(hour=0,minute=0,second=0,microsecond=0):
                # Profile reads describe now, even when catching up historical
                # performance. Keep that witnessed read without advancing the
                # shared lifecycle watermark past unprocessed history.
                _require(fields.get("profile_digest")==state.ledger.published_profile_digest,"PROFILE_DRIFT")
                return {"kind":source.kind,"entity_ref":source.target_entity_ref,"observation_ref":fields["observation_ref"],"current_profile_retained":True,"historical_performance_pending":True}
            if source.kind == "local_performance":
                _require(output.get("window_start")==job.arguments["window_start"] and output.get("window_end")==job.arguments["window_end"],"LOCAL_PERFORMANCE_WINDOW_MISMATCH")
            event = "observe_verification" if source.kind == "local_verification" else "observe_profile"
            return self._apply("local_presence_engine",source.target_entity_ref,event,fields,now=now,identity=identity)
        if source.kind == "content_observation":
            return self._apply("content_asset_lifecycle",source.target_entity_ref,"observe",
                {"observation":{"provenance":provenance.to_dict(),"output":output}},now=now,identity=identity)
        if source.kind == "customer_cohort":
            from lightbulb.growth_money_ingestion import normalize_customer_cohorts_response
            from lightbulb.growth_customers import mint_customer_cohort_evidence
            _require(self.console.cohort_scope is not None and self.console.cohort_keyring is not None,"COHORT_AUTHORITY_REQUIRED")
            converted = normalize_customer_cohorts_response(source_capability=source.tool,response=output,
                connector_account_ref=source.connector_account_ref,currency=self.console.bundle.operating_plan.blueprint.currency,observed_at=receipt.completed_at)
            cohorts = [mint_customer_cohort_evidence(x,scope=self.console.cohort_scope,scope_keyring=self.console.cohort_keyring) for x in converted.cohorts]
            _require(all(x.acquisition_window_start == job.window_start and x.acquisition_window_end == job.window_end for x in cohorts),"COHORT_WINDOW_MISMATCH")
            return {"kind":"customer_cohort","cohorts":[x.model_dump(mode="json",by_alias=True) for x in cohorts],"source_digest":receipt.output_digest}
        raise ValueError("OBSERVATION_SINK_UNSUPPORTED")


    def touches(self, ingestion):
        """Read authenticated leaves; never trust unsigned replacement pages."""
        from lightbulb.conversion_attribution import TouchClaim
        seen={}
        for ref in ingestion.get("touch_page_refs",()):
            page=self.gateway.get(ref)
            _require(page is not None and page.get("phase")=="ingested","TOUCH_PAGE_MISSING")
            for raw in page["ingestion"]["touches"]:
                claim=TouchClaim.model_validate(raw);self.touch_verifier.verify(claim)
                comparison={k:claim.to_dict().get(k) for k in ("touch_ref","company_ref","scope","unit_commitment","channel","asset_commitment","occurred_at","basis")}
                prior=seen.get(claim.touch_ref)
                _require(prior is None or prior[0]==comparison,"TOUCH_SOURCE_CONFLICT")
                if prior is None:seen[claim.touch_ref]=(comparison,claim.to_dict())
        _require(len(seen)==ingestion.get("touch_count"),"TOUCH_PAGE_COUNT_MISMATCH")
        return [row[1] for row in seen.values()]

    def _touch_pages(self, source, request, result, *, now, identity, fence):
        original=request;cursor=None;refs=[];seen={};unmatched=set();total=0;source_digests=[]
        for index in range(100):
            ref="company-touch-page-"+stable_digest({"observation":identity,"index":index,"cursor":cursor})
            page=self.gateway.get(ref)
            if index:
                request=original.model_copy(update={"arguments":{**original.arguments,"cursor":cursor},"idempotency_key":ref})
                if page is None:
                    fence();page=_write(self.gateway,ref,{"status":"RUNNING","request":request.model_dump(mode="json",by_alias=True)})
                _require(page["request"]==request.model_dump(mode="json",by_alias=True),"TOUCH_PAGE_REQUEST_MISMATCH")
                if page.get("result") is None:
                    fence();result=ConnectorExecutionResult.model_validate(detached(self.executor.execute(request)))
                    execution_receipt_from_connector(result,request)
                    page=_write(self.gateway,ref,{**page,"result":result.model_dump(mode="json",by_alias=True)},page)
                result=ConnectorExecutionResult.model_validate(page["result"])
            output=result.output
            legacy=index==0 and "pagination_mode" not in output and output.get("has_more") is False
            if not legacy:
                _require(output.get("pagination_mode")=="timestamp_overlap_ascending_v1" and output.get("page_index")==index
                    and output.get("cursor")==cursor and output.get("total_record_limit")==10000,"TOUCH_PAGE_CHAIN_INVALID")
                _require(type(output.get("has_more")) is bool and bool(output.get("next_cursor"))==output["has_more"],"TOUCH_PAGE_CHAIN_INVALID")
            now=max((now,self.console.clock()),key=parsed)
            execution=execution_receipt_from_connector(result,request)
            _require(parsed(execution.completed_at)<=parsed(now),"OBSERVATION_FROM_FUTURE")
            converted=touches_from_posthog(request,result,verifier=self.touch_verifier,event_bindings=source.event_bindings,identity_links=source.identity_links,require_complete=False)
            rows=output["events"];total+=len(rows)
            _require(total<=10000,"TOUCH_RECORD_LIMIT")
            for row in rows:
                event_id=row["uuid_sha256"];digest=stable_digest(row)
                _require(event_id not in seen or seen[event_id]==digest,"TOUCH_EVENT_CHANGED_ACROSS_PAGES")
                seen[event_id]=digest
            unmatched.update(converted["unmatched_event_refs"]);source_digests.append(converted["source_digest"])
            artifact={**converted,"touches":[t.to_dict() for t in converted["touches"]]}
            if page is None or page.get("phase")!="ingested":
                fence();_write(self.gateway,ref,{"status":"COMPLETED","phase":"ingested","request":request.model_dump(mode="json",by_alias=True),
                    "result":result.model_dump(mode="json",by_alias=True),"ingestion":artifact},page)
            refs.append(ref)
            if output["has_more"] is False:
                return {"kind":"marketing_touches","complete":True,"touch_page_refs":refs,"touch_count":len(seen)-len(unmatched),
                        "unmatched_event_count":len(unmatched),"source_digest":stable_digest(source_digests)}
            following=output.get("next_cursor")
            _require(isinstance(following,str) and following!=cursor,"TOUCH_CURSOR_NOT_PROGRESSING")
            cursor=following
        raise ValueError("TOUCH_PAGE_LIMIT")

    def _pacing_controls(self, source, statement, demand, *, now, identity, fence):
        from hashlib import sha256
        google = source.tool == "google_ads.get_metrics"
        tool = "google_ads.pause_campaign" if google else "meta_ads.pause_campaign"
        proofs=[];pending=[]
        for claim in demand.ledger.claims:
            if claim.released or claim.provider_campaign_commitment is None:
                continue
            envelope = self.console._plan_for("demand_envelope").portfolio.envelope(claim.envelope_ref)
            if envelope.channel != source.channel:
                continue
            args = source.pacing_controls.get(claim.provider_campaign_commitment)
            _require(args is not None,"PACING_CONTROL_REQUIRED: configure the exact provider target for each active budget claim")
            fields = {"customer_id","resource_name"} if google else {"ad_account_id","campaign_id"}
            _require(set(args)==fields,"PACING_TARGET_INVALID")
            account = str(args["customer_id" if google else "ad_account_id"])
            target = str(args["resource_name" if google else "campaign_id"])
            campaign = target.rsplit("/",1)[-1] if google else target
            _require(sha256(account.encode()).hexdigest()==statement.account_commitment and sha256(campaign.encode()).hexdigest()==claim.provider_campaign_commitment,
                     "PACING_TARGET_MISMATCH")
            if google:
                _require(target==f"customers/{account}/campaigns/{campaign}","PACING_TARGET_MISMATCH")
            key="pacing-pause-"+stable_digest({"source":identity,"campaign":claim.provider_campaign_commitment,"arguments":args})
            request=ConnectorExecutionRequest(tool=tool,arguments=args,scope=ExecutionScope(**self.console.bundle.scope,actor_ref=self.console.bundle.actor_ref),
                connector_account_ref=source.connector_account_ref,effect="write",idempotency_key=key)
            saved=self.gateway.get(key)
            if saved is None:
                fence();saved=_write(self.gateway,key,{"status":"RUNNING","request":request.model_dump(mode="json",by_alias=True)})
            if saved.get("proof"):
                proofs.append(saved["proof"]);continue
            if saved.get("approval_ref"):
                request=request.model_copy(update={"approval_ref":saved["approval_ref"]})
            fence();result=ConnectorExecutionResult.model_validate(detached(self.executor.execute(request)))
            row={**saved,"request":request.model_dump(mode="json",by_alias=True),"result":result.model_dump(mode="json",by_alias=True),
                 "approval_ref":request.approval_ref or result.approval_ref,"status":"PENDING_APPROVAL"}
            if result.status.value == "completed":
                receipt=execution_receipt_from_connector(result,request)
                now=max((now,self.console.clock()),key=parsed)
                output=result.output
                _require(receipt.approval_ref is not None and parsed(receipt.completed_at)<=parsed(now),"PACING_APPROVAL_REQUIRED")
                _require(output.get("status")=="paused" and output.get("resource_name_sha256" if google else "object_id_sha256")==sha256(target.encode()).hexdigest()
                    and (not google or output.get("mutated_count")==1),"PACING_EXECUTION_NOT_RECONCILED")
                row.update(status="COMPLETED",proof={"execution_digest":receipt.execution_digest,"approval_ref":receipt.approval_ref,"target_commitment":sha256(target.encode()).hexdigest()})
                proofs.append(row["proof"])
            else:
                pending.append({"campaign_ref":claim.campaign_ref,"status":result.status.value,"approval_ref":row["approval_ref"]})
            _write(self.gateway,key,row,saved)
        _require(bool(proofs or pending),"PACING_CONTROL_REQUIRED")
        return {"complete":not pending,"proofs":proofs,"pending":pending}


@dataclass
class ReallocationExecutionHost:
    gateway: Any
    executor: Any
    clock: Any = field(default=lambda:datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),repr=False)

    def step(self, write_plan, *, scope, connector_account_refs, identifiers_by_unit, now, fence):
        from lightbulb.growth_reallocation import BudgetWritePlan,resolve_write_plan_requests,write_plan_proof,applied_write_plan
        plan = BudgetWritePlan.model_validate(detached(write_plan))
        _require(not plan.unsupported_channels and not plan.unmapped_envelope_refs,"REALLOCATION_MAPPING_INCOMPLETE")
        _require(parsed(plan.compiled_at) <= parsed(now), "REALLOCATION_PLAN_FROM_FUTURE")
        scope = ExecutionScope.model_validate(detached(scope))
        original = resolve_write_plan_requests(plan,scope=scope,connector_account_refs=connector_account_refs,identifiers_by_unit=identifiers_by_unit)
        identity = stable_digest({"plan":plan.write_plan_digest,"requests":[r.custody_fingerprint() for r in original]})
        ref = "company-reallocation-"+plan.write_plan_digest
        current = self.gateway.get(ref)
        if current is None:
            fence()
            current = _write(self.gateway,ref,{"schema":"lightbulb.company_reallocation_checkpoint.v1","status":"RUNNING",
                "binding_digest":identity,"write_plan":plan.to_dict(),"units":{}})
        _same_binding(current,identity)
        units = dict(current["units"])
        by_ref = {unit.unit_ref:request for unit,request in zip(plan.units,original)}
        # Never increase a budget while a required decrease/pause is unresolved.
        ordered = sorted(plan.units,key=lambda x:(x.intent=="increase_budget",x.ordinal))
        for unit in ordered:
            now = max((now,self.clock()),key=parsed)
            saved = units.get(unit.unit_ref,{})
            if saved.get("proof") is not None:
                continue
            _require(parsed(now)<parsed(plan.period_end),"REALLOCATION_PERIOD_EXPIRED")
            _require(plan.evidence_expires_at is not None and parsed(now)<=parsed(plan.evidence_expires_at),"REALLOCATION_EVIDENCE_STALE: prepare a new reviewed decision before further provider writes")
            if saved.get("status") in {"blocked","failed"}:
                continue
            if unit.intent == "increase_budget" and any(u.intent != "increase_budget" and not units.get(u.unit_ref,{}).get("proof") for u in plan.units):
                break
            request = by_ref[unit.unit_ref]
            if saved.get("approval_ref"):
                request = request.model_copy(update={"approval_ref":saved["approval_ref"]})
            fence()
            try:
                result = ConnectorExecutionResult.model_validate(detached(self.executor.execute(request)))
            except Exception:
                # Retain the exact intent; retry must use the server journal's
                # idempotency key, never compile a new provider write.
                units[unit.unit_ref] = {**saved,"request":request.model_dump(mode="json",by_alias=True),"status":"waiting_for_recovery"}
                _write(self.gateway,ref,{**current,"status":"WAITING_FOR_RECOVERY","units":units},current)
                raise
            row = {"request":request.model_dump(mode="json",by_alias=True),"status":result.status.value,
                   "approval_ref":request.approval_ref or result.approval_ref,"result":result.model_dump(mode="json",by_alias=True)}
            if result.status.value == "completed":
                execution = execution_receipt_from_connector(result,request)
                now = max((now,self.clock()),key=parsed)
                _require(parsed(execution.completed_at)<=parsed(now),"WRITE_COMPLETION_FROM_FUTURE")
                # An immediately completed result must still provide the exact
                # Spring-issued per-unit approval before proof construction.
                if request.approval_ref is None:
                    request = request.model_copy(update={"approval_ref":execution.approval_ref})
                    row["request"] = request.model_dump(mode="json",by_alias=True)
                row["proof"] = write_plan_proof(plan,unit.unit_ref,execution,output=result.output,request=request).to_dict()
            units[unit.unit_ref] = row
            current = _write(self.gateway,ref,{**current,"units":units,"status":"PENDING_APPROVAL" if result.status.value=="pending_approval" else "RUNNING"},current)
        proofs = [row["proof"] for row in units.values() if row.get("proof")]
        requests = {key:row["request"] for key,row in units.items() if row.get("proof")}
        report = applied_write_plan(plan,proofs,requests_by_unit=requests)
        current = _write(self.gateway,ref,{**current,"units":units,"status":"COMPLETED" if report["all_applied"] else "PENDING_APPROVAL","report":report},current)
        return {**report,"checkpoint_ref":ref,"unit_states":{key:row["status"] for key,row in units.items()}}
