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
                    from lightbulb.company_host_journal import HostAuthorityError
                    raise HostAuthorityError("HOST_AUTHENTICATED_OWNER_CHANGED")
                self.client.active_company_id=self.identity[1]
                self.client.list_engine_states(self.identity[3],company_id=self.identity[1],limit=1)
                return value(*args,**kwargs)
        return invoke


def build_worker(client, bundle, *, company_id, sources, worker_ref, keyring=None, signals=(),
                 interval_seconds=86400, reallocation_ref=None, growth_config=None, sales_config=None, capability_waits=(), native_connection_id=None, capability_development=None, customer_lifecycle=None, clock=utc_now):
    """Bind a trusted host; configured signals are operator inputs, not provider evidence."""
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
    from lightbulb.company_preflight import validate_worker_configuration, validate_worker_signals
    configured_signals=validate_worker_signals(signals)
    bundle, sources = validate_worker_configuration(bundle, sources, growth_config=growth_config, interval_seconds=interval_seconds, signals=configured_signals, sales_config=sales_config, capability_waits=capability_waits, native_connection_id=native_connection_id, capability_development=capability_development, customer_lifecycle=customer_lifecycle)
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
    if any(s.kind in {"marketing_touches","customer_cohort"} for s in sources) and verifier is None:
        raise ValueError("RECEIPT_KEYRING_REQUIRED: configure a trusted host receipt key file")
    if keyring is None:
        raise ValueError("RECEIPT_KEYRING_REQUIRED: durable host artifacts must be authenticated")
    from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
    journal=AuthenticatedCheckpointGateway(gateway,authority,keyring,bundle.plan_digest,claim_run_ref="cadence-"+bundle.company_ref)
    executor=HostedConnectorExecutor(client)
    intake=CompanyObservationHost(console,journal,executor,tuple(sources),verifier)
    worker=CadenceWorker(console._runner(),clock)
    from lightbulb.company_signal_execution import CompanySignalIntentExecutor,SignalIntentExecutionError
    signal_executor=CompanySignalIntentExecutor(worker.runner,journal)
    def signal_step(*,now,fence):
        admission_failures=[]
        for index,signal in enumerate(configured_signals):
            try:
                signal_executor.enqueue(signal,now=now,fence=fence)
            except SignalIntentExecutionError as exc:
                if exc.code not in {"SIGNAL_QUEUE_FULL", "SIGNAL_JOURNAL_TOO_LARGE"}:
                    raise
                admission_failures.append({"signal_index":index,"code":exc.code})
        result=signal_executor.drain(now=now,fence=fence)
        return {**result,"admission_failures":admission_failures} if admission_failures else result
    step=None
    if reallocation_ref:
        execution=ReallocationExecutionHost(journal,executor,clock)
        def step(*,now,fence):
            source=journal.get(reallocation_ref)
            if source is None or not source.get("write_plan"):
                return None
            from lightbulb.company_data_review import correction_hold
            if not source.get("economic_period_ref"):
                raise ValueError("REALLOCATION_ECONOMIC_SOURCE_REQUIRED")
            original_fence = fence
            def fence():
                original_fence()
                if correction_hold(journal, source["economic_period_ref"]) is not None:
                    raise ValueError("ECONOMIC_PERIOD_CORRECTED")
            # Scope is always derived above; the queued document cannot replace it.
            return execution.step(source["write_plan"],scope=ExecutionScope(**bundle.scope,actor_ref=bundle.actor_ref),
                connector_account_refs=source["connector_account_refs"],identifiers_by_unit=source["identifiers_by_unit"],now=now,fence=fence)
    growth = None
    if growth_config is not None:
        if reallocation_ref:
            raise ValueError("choose growth-config or reallocation-ref, not both")
        from lightbulb.company_growth_host import CompanyGrowthHost
        growth=CompanyGrowthHost(intake,growth_config)
        step=growth.step
    sales = None
    if sales_config is not None:
        from lightbulb.company_sales_host import CompanySalesHost
        from lightbulb.company_sales_communication import HostedSalesCommunication
        sales = CompanySalesHost(worker.runner, journal, executor,
            HostedSalesCommunication(client, selected, authority_scope=authority), sales_config, sources, clock=clock)
    if customer_lifecycle is not None:
        from lightbulb.company_customer_lifecycle import CompanyCustomerLifecycle
        sales.customer_lifecycle = CompanyCustomerLifecycle(sales, customer_lifecycle)
        if sales.customer_lifecycle.configuration.crm_sources:
            from lightbulb.company_customer_crm import CompanyCustomerCrmIntake
            intake.crm_intake = CompanyCustomerCrmIntake(worker.runner,journal,client,sales.customer_lifecycle.configuration.crm_sources)
    fast_intake = None
    if sales is not None and sales.customer_lifecycle.configuration.fast_intake is not None:
        from lightbulb.company_customer_fast_intake import CompanyCustomerFastIntake
        fast_intake = CompanyCustomerFastIntake(worker.runner, journal, client, intake, sales.customer_lifecycle.configuration.fast_intake)
    from lightbulb.company_capability_waits import CompanyCapabilityWaits
    waits = CompanyCapabilityWaits(worker.runner, journal, client, connection_id=native_connection_id, clock=clock,
        sales=sales, growth=growth, signals=signal_executor, configured=capability_waits, signal_sources=configured_signals, development_policy=capability_development)
    signal_executor.capability_waits = waits
    if growth is not None:
        growth.capability_waits = waits
    return HostedCadenceScheduler(worker,journal,worker_ref,interval_seconds=interval_seconds, capability_waits=waits,
                                  observation_host=intake,reallocation_step=step,signal_step=signal_step, sales_host=sales,customer_fast_intake=fast_intake)


def main(argv=None):
    parser=argparse.ArgumentParser(description="Run a durable company observation and cadence worker")
    parser.add_argument("--bundle")
    parser.add_argument("--sources")
    parser.add_argument("--company-id")
    parser.add_argument("--worker-ref")
    parser.add_argument("--receipt-key-file")
    parser.add_argument("--receipt-key-id",default="company-receipts-v1")
    parser.add_argument("--interval-seconds",type=int,default=86400)
    parser.add_argument("--reallocation-ref")
    parser.add_argument("--growth-config")
    parser.add_argument("--sales-config", help="JSON playbooks, existing-thread contacts, expansion/win-back intake and billing coordination")
    parser.add_argument("--customer-lifecycle", help="JSON reviewed customer enrollments with source coverage and bounded trials")
    parser.add_argument("--capability-development", help="JSON policy for automatic SDK gap proposals and human-approved handoffs")
    parser.add_argument("--capability-waits", help="JSON array of exact blocked work and capability dependencies")
    parser.add_argument("--native-connection-id", help="This worker runtime connection used for installation evidence")
    parser.add_argument("--signals",help="JSON array of trusted operator company signals; not provider outcome evidence")
    parser.add_argument("--register",action="store_true")
    parser.add_argument("--once",action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="Validate configuration offline; never authenticate or register")
    mode.add_argument("--source-template", action="store_true", help="Print a non-secret recurring-source example and exit")
    mode.add_argument("--status", action="store_true", help="Read authenticated operational status without claiming work")
    mode.add_argument("--record-census", help="Retain a reviewed source-census JSON file in the authenticated host journal")
    mode.add_argument("--record-correction", help="Hold an economic period using an exact historical-correction JSON file")
    parser.add_argument("--report-html", help="Write an escaped local report with --status or --preflight")
    args=parser.parse_args(argv)
    from lightbulb.company_preflight import source_template, worker_preflight
    if args.source_template:
        print(json.dumps(source_template(), indent=2))
        return 0
    if not args.bundle or not args.sources:
        parser.error("bundle and sources are required")
    if (args.preflight or args.status or args.record_census or args.record_correction) and (args.register or args.once):
        parser.error("preflight/status cannot register or run work")
    if args.report_html and not (args.preflight or args.status):
        parser.error("report-html requires preflight or status")
    bundle_document = json.loads(Path(args.bundle).read_text())
    source_documents = json.loads(Path(args.sources).read_text())
    growth_configuration = json.loads(Path(args.growth_config).read_text()) if args.growth_config else None
    sales_configuration = json.loads(Path(args.sales_config).read_text(encoding="utf-8")) if args.sales_config else None
    lifecycle_configuration = json.loads(Path(args.customer_lifecycle).read_text(encoding="utf-8")) if args.customer_lifecycle else None
    development_policy = json.loads(Path(args.capability_development).read_text(encoding="utf-8")) if args.capability_development else None
    wait_documents = json.loads(Path(args.capability_waits).read_text(encoding="utf-8")) if args.capability_waits else ()
    signal_documents = json.loads(Path(args.signals).read_text(encoding="utf-8")) if args.signals else ()
    report = worker_preflight(bundle_document, source_documents, company_id=args.company_id,
                              growth_config=growth_configuration, interval_seconds=args.interval_seconds, signals=signal_documents, sales_config=sales_configuration, capability_waits=wait_documents, native_connection_id=args.native_connection_id, capability_development=development_policy, customer_lifecycle=lifecycle_configuration)
    if args.preflight or not report["configuration_valid"]:
        print(json.dumps(report, indent=2))
        if args.report_html:
            from lightbulb.company_operations import render_operations_html
            Path(args.report_html).write_text(render_operations_html(report), encoding="utf-8")
        return 0 if report["configuration_valid"] else 2
    if not args.company_id or not args.worker_ref or not args.receipt_key_file:
        parser.error("connected operation requires company-id, worker-ref and receipt-key-file")
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
    scheduler=build_worker(_client_from_env(auth_refresh=lambda:_resolve_auth(base_url)),bundle_document,
        company_id=args.company_id,sources=source_documents,worker_ref=args.worker_ref,
        keyring=keyring,interval_seconds=args.interval_seconds,reallocation_ref=args.reallocation_ref,
        signals=signal_documents,
        growth_config=growth_configuration, sales_config=sales_configuration, capability_waits=wait_documents, native_connection_id=args.native_connection_id, capability_development=development_policy, customer_lifecycle=lifecycle_configuration)
    if args.status:
        from lightbulb.company_operations import operations_status, render_operations_html
        report = operations_status(scheduler, now=utc_now(), growth_config=growth_configuration)
        print(json.dumps(report, indent=2))
        if args.report_html:
            Path(args.report_html).write_text(render_operations_html(report), encoding="utf-8")
        return 0
    if args.record_census or args.record_correction:
        from lightbulb.company_data_review import record_source_census, record_correction
        if args.record_census:
            result = record_source_census(scheduler.gateway, json.loads(Path(args.record_census).read_text()),
                                          configured_source_refs=[s.source_ref for s in scheduler.observation_host.sources])
        else:
            result = record_correction(scheduler.gateway, json.loads(Path(args.record_correction).read_text()))
        print(json.dumps(result, indent=2))
        return 0
    if args.register:
        if scheduler.worker.runner.store.get("company_cadence",scheduler.worker.cadence_ref) is None:
            scheduler.worker.start()
        if scheduler.gateway.get(scheduler.run_ref) is None:
            scheduler.register(first_tick_at=utc_now())
    while True:
        try:
            result=scheduler.run_once(now=utc_now())
            print(json.dumps(result.to_dict()),flush=True)
            from lightbulb.company_operations import record_worker_health
            try:
                record_worker_health(scheduler, now=utc_now(), outcome=result.outcome)
            except Exception as health_error:
                print(json.dumps({"outcome": "health_record_failed", "error_type": type(health_error).__name__}), flush=True)
            if args.once:
                return 0 if result.outcome in {"ticked","not_due"} else 2
        except Exception as exc:
            # Preserve the authoritative lease/journal for recovery. Do not
            # log transport bodies or credentials in a supervisor error line.
            print(json.dumps({"outcome":"worker_error","error_type":type(exc).__name__,"at":utc_now()}),flush=True)
            from lightbulb.company_operations import record_worker_health
            try:
                record_worker_health(scheduler, now=utc_now(), outcome="worker_error", error_type=type(exc).__name__)
            except Exception:
                pass  # An unavailable journal must not mask the original failure.
            if args.once:
                return 2
        time.sleep(10)


if __name__=="__main__":
    raise SystemExit(main())
