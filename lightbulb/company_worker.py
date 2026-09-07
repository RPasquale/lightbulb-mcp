"""Runnable company host on authenticated Spring stores and governed connectors.

This entry point is installed on a trusted host. It does not expose receipt
keys or configuration through MCP, and provider writes still request exact
Spring approvals. Run under the deployment's normal process supervisor.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import time
from uuid import UUID


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


class ScopedHostClient:
    """Refresh an expired session once without changing its authenticated owner."""
    def __init__(self, client, *, tenant_id, company_id, user_id, project_id):
        self.client=client
        self.identity=(tenant_id,company_id,user_id,project_id)

    def __getattr__(self, name):
        value=getattr(self.client,name)
        if not callable(value):return value
        def invoke(*args,**kwargs):
            from lightbulb.errors import AuthenticationError
            try:
                return value(*args,**kwargs)
            except AuthenticationError:
                if not self.client.refresh_auth():raise
                from lightbulb.dynamic_workflow_scope_resolution import _required_uuid_alias
                identity=self.client.whoami()
                tenant=_required_uuid_alias(identity,("tenantId","tenant_id"),field_name="authenticated tenant")
                user=_required_uuid_alias(identity,("id","userId","user_id"),field_name="authenticated user")
                if (tenant,user)!=(self.identity[0],self.identity[2]):
                    raise ValueError("HOST_AUTHENTICATED_OWNER_CHANGED")
                self.client.active_company_id=self.identity[1]
                self.client.list_engine_states(self.identity[3],company_id=self.identity[1],limit=1)
                return value(*args,**kwargs)
        return invoke


def build_worker(client, bundle, *, company_id, sources, worker_ref, keyring=None,
                 interval_seconds=86400, reallocation_ref=None, growth_config=None, clock=utc_now):
    from lightbulb.company_cadence_runner import build_bundle,CadenceWorker
    from lightbulb.company_console import CompanyConsole
    from lightbulb.company_engine_store import HostedEngineStateStore
    from lightbulb.company_hosted_scheduler import HostedCheckpointGateway,HostedCadenceScheduler
    from lightbulb.company_observation_host import CompanyObservationHost,ReallocationExecutionHost
    from lightbulb.connector_execution import HostedConnectorExecutor,ExecutionScope
    from lightbulb.dynamic_workflows import DynamicWorkflowScope
    from lightbulb.company_engine_core import EngineScope
    from lightbulb.trusted_touch_sources import TrustedTouchVerifier
    from lightbulb.launch_plan import LaunchGateApprovalRequest
    from lightbulb.dynamic_workflow_scope_resolution import _required_uuid_alias
    bundle=build_bundle(bundle)
    from lightbulb.company_engine_core import parsed
    start=parsed(bundle.start_at)
    if sources and (start.hour or start.minute or start.second or start.microsecond):
        raise ValueError("COMPANY_INTAKE_MIDNIGHT_REQUIRED: select an explicit whole UTC-day intake boundary in the bundle before registration")
    selected=str(UUID(company_id));project=str(UUID(bundle.scope["project_id"]))
    client.active_company_id=selected
    identity=client.whoami()
    tenant=_required_uuid_alias(identity,("tenantId","tenant_id"),field_name="authenticated tenant")
    user=_required_uuid_alias(identity,("id","userId","user_id"),field_name="authenticated user")
    # The scoped project route authorizes selection before any local signing,
    # registration or effect. A home-company identity alone is insufficient.
    client.list_engine_states(project,limit=1,company_id=selected)
    authority=DynamicWorkflowScope(tenant_id=tenant,company_id=selected,user_id=user,project_ref=bundle.scope["project_ref"])
    client=ScopedHostClient(client,tenant_id=tenant,company_id=selected,user_id=user,project_id=project)
    engine_scope=EngineScope(**bundle.engine_scope("observation-intake"))
    store=HostedEngineStateStore(client,project_id=project,company_id=selected)
    gateway=HostedCheckpointGateway(client,project,selected)
    def approve(request):
        return client.request_launch_gate_approval(request) if isinstance(request,LaunchGateApprovalRequest) else client.request_engine_transition_approval(request)
    console=CompanyConsole(bundle,store,clock,approval_requester=approve,cohort_scope=authority,cohort_keyring=keyring)
    verifier=TrustedTouchVerifier(authority,engine_scope,bundle.company_ref,keyring) if keyring is not None else None
    if any(s.get("kind") in {"marketing_touches","customer_cohort"} for s in sources) and verifier is None:
        raise ValueError("RECEIPT_KEYRING_REQUIRED: configure a trusted host receipt key file")
    if keyring is None:
        raise ValueError("RECEIPT_KEYRING_REQUIRED: durable host artifacts must be authenticated")
    from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
    journal=AuthenticatedCheckpointGateway(gateway,authority,keyring,bundle.plan_digest,claim_run_ref="cadence-"+bundle.company_ref)
    executor=HostedConnectorExecutor(client)
    intake=CompanyObservationHost(console,journal,executor,tuple(sources),verifier)
    worker=CadenceWorker(console._runner(),clock)
    step=None
    if reallocation_ref:
        execution=ReallocationExecutionHost(journal,executor,clock)
        def step(*,now,fence):
            source=journal.get(reallocation_ref)
            if source is None or not source.get("write_plan"):
                return None
            # Scope is always derived above; the queued document cannot replace it.
            return execution.step(source["write_plan"],scope=ExecutionScope(**bundle.scope,actor_ref=bundle.actor_ref),
                connector_account_refs=source["connector_account_refs"],identifiers_by_unit=source["identifiers_by_unit"],now=now,fence=fence)
    if growth_config is not None:
        if reallocation_ref:
            raise ValueError("choose growth-config or reallocation-ref, not both")
        from lightbulb.company_growth_host import CompanyGrowthHost
        growth=CompanyGrowthHost(intake,growth_config)
        step=growth.step
    return HostedCadenceScheduler(worker,journal,worker_ref,interval_seconds=interval_seconds,
                                  observation_host=intake,reallocation_step=step)


def main(argv=None):
    parser=argparse.ArgumentParser(description="Run a durable company observation and cadence worker")
    parser.add_argument("--bundle",required=True)
    parser.add_argument("--sources",required=True)
    parser.add_argument("--company-id",required=True)
    parser.add_argument("--worker-ref",required=True)
    parser.add_argument("--receipt-key-file",required=True)
    parser.add_argument("--receipt-key-id",default="company-receipts-v1")
    parser.add_argument("--interval-seconds",type=int,default=86400)
    parser.add_argument("--reallocation-ref")
    parser.add_argument("--growth-config")
    parser.add_argument("--register",action="store_true")
    parser.add_argument("--once",action="store_true")
    args=parser.parse_args(argv)
    if not 60<=args.interval_seconds<=604800:
        parser.error("interval-seconds must be between 60 and 604800")
    from lightbulb.cli import _client_from_env, _resolve_auth
    import os
    from lightbulb.dynamic_workflow_control import DynamicWorkflowReceiptKeyRing
    keyring=None
    if args.receipt_key_file:
        key=Path(args.receipt_key_file).read_bytes()
        if len(key)<32 or len(key)>4096:
            parser.error("receipt key file must contain 32 to 4096 bytes")
        keyring=DynamicWorkflowReceiptKeyRing({args.receipt_key_id:key},active_key_id=args.receipt_key_id)
    base_url=os.getenv("LIGHTBULB_URL","https://agents.lightbulbpartners.com").rstrip("/")
    scheduler=build_worker(_client_from_env(auth_refresh=lambda:_resolve_auth(base_url)),json.loads(Path(args.bundle).read_text()),
        company_id=args.company_id,sources=json.loads(Path(args.sources).read_text()),worker_ref=args.worker_ref,
        keyring=keyring,interval_seconds=args.interval_seconds,reallocation_ref=args.reallocation_ref,
        growth_config=json.loads(Path(args.growth_config).read_text()) if args.growth_config else None)
    if args.register:
        if scheduler.worker.runner.store.get("company_cadence",scheduler.worker.cadence_ref) is None:
            scheduler.worker.start()
        if scheduler.gateway.get(scheduler.run_ref) is None:
            scheduler.register(first_tick_at=utc_now())
    while True:
        try:
            result=scheduler.run_once(now=utc_now())
            print(json.dumps(result.to_dict()),flush=True)
            if args.once:
                return 0 if result.outcome in {"ticked","not_due"} else 2
        except Exception as exc:
            # Preserve the authoritative lease/journal for recovery. Do not
            # log transport bodies or credentials in a supervisor error line.
            print(json.dumps({"outcome":"worker_error","error_type":type(exc).__name__,"at":utc_now()}),flush=True)
            if args.once:
                return 2
        time.sleep(10)


if __name__=="__main__":
    raise SystemExit(main())
