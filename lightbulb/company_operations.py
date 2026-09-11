"""Read-only health projection from authenticated company-worker journals.

HTML is a static local report, never a hosted RBAC bypass or an approval UI.
No connector output, credential, customer mapping or journal payload is shown.
"""
from __future__ import annotations

from datetime import timedelta
from html import escape
import json

from lightbulb.company_engine_core import parsed, stable_digest
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
from lightbulb.company_data_review import correction_hold


def record_worker_health(scheduler, *, now, outcome, error_type=None):
    """Retain a bounded authenticated heartbeat; does not change scheduling."""
    if not isinstance(scheduler.gateway, AuthenticatedCheckpointGateway):
        raise ValueError("AUTHENTICATED_HOST_JOURNAL_REQUIRED")
    ref = "company-worker-health-" + scheduler.run_ref
    old = scheduler.gateway.get(ref)
    if old and old.get("outcome") == outcome and parsed(now) - parsed(old["observed_at"]) < timedelta(seconds=60):
        return old
    return scheduler.gateway.put(ref, {"schema": "lightbulb.company_worker_health.v1", "status": "completed", "resume_at": None,
                                      "observed_at": now, "worker_ref": scheduler.worker_ref, "outcome": outcome,
                                      "error_type": error_type}, expected_revision=old["revision"] if old else 0)


def operations_status(scheduler, *, now, growth_config=None):
    from lightbulb.sdk_capability_assessment import capability_runtime_report
    from lightbulb.company_capability_investments import rank_capability_investments
    gateway = scheduler.gateway
    if not isinstance(gateway, AuthenticatedCheckpointGateway):
        raise ValueError("AUTHENTICATED_HOST_JOURNAL_REQUIRED")
    clock = parsed(now)
    bundle = scheduler.worker.runner.bundle
    checkpoint = gateway.get(scheduler.run_ref)
    heartbeat = gateway.get("company-worker-health-" + scheduler.run_ref)
    heartbeat_status = "not_observed"
    if heartbeat:
        age = (clock - parsed(heartbeat["observed_at"])).total_seconds()
        heartbeat_status = "fresh" if 0 <= age <= 120 else "stale" if age > 120 else "clock_skew"
    alerts, sources, periods, decisions = [], [], [], []
    if heartbeat_status in {"stale", "clock_skew"}:
        alerts.append({"code": "WORKER_HEARTBEAT_" + heartbeat_status.upper(), "severity": "error", "action": "Check the supervisor, clock and host connectivity."})
    if heartbeat and heartbeat.get("error_type"):
        alerts.append({"code": "WORKER_ERROR", "severity": "error", "action": "Inspect scoped host logs; retain journals for retry."})
    if checkpoint is None:
        alerts.append({"code": "WORKER_NOT_REGISTERED", "severity": "error", "action": "Complete connected preflight before registration."})
    else:
        if checkpoint.get("bundle_digest") != bundle.plan_digest:
            raise ValueError("STATUS_BUNDLE_MISMATCH")
        due = checkpoint.get("resume_at")
        if due and parsed(due) + timedelta(seconds=scheduler.interval_seconds) < clock:
            alerts.append({"code": "CADENCE_OVERDUE", "severity": "error", "action": "Inspect the supervisor and renewable identity; resume the existing run."})
        if checkpoint.get("status") in {"blocked", "completed"}:
            alerts.append({"code": "CADENCE_PARKED", "severity": "warning", "action": "Inspect the cadence before an authorized resume."})
    closed = clock.replace(hour=0, minute=0, second=0, microsecond=0)
    watermark = (checkpoint or {}).get("last_observation_at") or bundle.start_at
    backlog = max(0, (closed - parsed(watermark)).days)
    if backlog and scheduler.observation_host and scheduler.observation_host.sources:
        alerts.append({"code": "INTAKE_BACKLOG", "severity": "warning", "action": "Drain frozen daily windows; do not edit watermarks."})
    intake = scheduler.observation_host
    billing = []
    if intake:
        for source in intake.sources:
            if source.kind == "invoice_health":
                from lightbulb.company_billing_recovery import CompanyBillingRecovery
                billing.append(CompanyBillingRecovery(scheduler.worker.runner, gateway, source).report())
    if intake and closed - timedelta(days=1) >= parsed(bundle.start_at):
        start = (closed - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        end = closed.isoformat().replace("+00:00", "Z")
        for source in intake.sources:
            record = intake.retained(source, start=start, end=end)
            job = source.job(start=start, end=end)
            identity = stable_digest({"bundle":bundle.plan_digest,"job":job.job_digest})
            pending = gateway.get("company-observation-" + identity) if record is None else record
            sources.append({"source_ref": source.source_ref, "kind": source.kind, "window_start": start, "window_end": end,
                            "status": "ingested" if record else "failed" if (pending or {}).get("last_error_type") else "missing",
                            "last_error_type": (pending or {}).get("last_error_type"), "last_failure_at": (pending or {}).get("last_failure_at")})
    for spec in (growth_config or {}).get("periods", []):
        record = gateway.get("company-growth-period-" + spec["ref"])
        hold = correction_hold(gateway, spec["ref"])
        periods.append({"ref": spec["ref"], "status": "correction_hold" if hold else (record or {}).get("status", "not_started"),
                        "eligible_for_budget_decisions": bool(record and record.get("eligible_for_budget_decisions") and not hold),
                        "missing_source_windows": len((record or {}).get("missing_sources", [])),
                        "account_census": "reviewed" if (record or {}).get("source_census", {}).get("declared_coverage_reviewed") else "unresolved" if (record or {}).get("source_census") else "not_recorded",
                        "external_liabilities_proven_complete": False})
    for spec in (growth_config or {}).get("reallocations", []):
        record = gateway.get("company-growth-decision-" + spec["ref"])
        child = None
        if record and record.get("write_plan", {}).get("write_plan_digest"):
            child = gateway.get("company-reallocation-" + record["write_plan"]["write_plan_digest"])
        units = list((child or {}).get("units", {}).values())
        pending_units = [u for u in units if u.get("status") == "pending_approval"]
        ages = [max(0, int((clock - parsed(u["pending_since"])).total_seconds())) for u in pending_units if u.get("pending_since")]
        decisions.append({"ref": spec["ref"], "status": (record or {}).get("status", "not_started"),
                          "complete": bool(record and record.get("complete")), "terminal": bool(record and record.get("terminal")),
                          "pending_approval_units": len(pending_units) if child is not None else None, "oldest_pending_seconds": max(ages) if ages else None,
                          "approval_age_complete": all(u.get("pending_since") for u in pending_units) if child is not None else None,
                          "evidence_expires_at": (record or {}).get("write_plan", {}).get("evidence_expires_at"),
                          "unreconciled_units": sum(u.get("status") in {"waiting_for_recovery", "failed", "blocked"} for u in units) if child is not None else None})
        if record and not record.get("complete"):
            alerts.append({"code": "DECISION_UNRESOLVED", "severity": "warning", "action": "Review exact approvals, expiry and retained execution proofs."})
    if any(s["status"] != "ingested" for s in sources):
        alerts.append({"code": "SOURCE_WINDOW_MISSING", "severity": "warning", "action": "Inspect source failures and retry through the existing journal."})
    if any(not p["eligible_for_budget_decisions"] for p in periods):
        alerts.append({"code": "ECONOMIC_ACCEPTANCE_PENDING", "severity": "warning", "action": "Resolve source coverage, corrections and cost reconciliation."})
    return {"schema": "lightbulb.company_operations_status.v1", "observed_at": now, "company_ref": bundle.company_ref,
            "bundle_digest": bundle.plan_digest, "basis": "authenticated_journal_snapshot", "live_provider_certified": False,
            "worker": {"run_ref": scheduler.run_ref, "status": (checkpoint or {}).get("status", "not_registered"),
                       "last_tick_at": (checkpoint or {}).get("last_tick_at"), "next_due_at": (checkpoint or {}).get("resume_at"),
                       "heartbeat_status": heartbeat_status, "heartbeat_at": (heartbeat or {}).get("observed_at"),
                       "backlog_days": backlog if intake and intake.sources else 0},
            "sources": sources, "billing": billing,
            "customer_actions": scheduler.sales_host.customer_actions.report() if getattr(scheduler, "sales_host", None) else {},
            "customer_experiments": scheduler.sales_host.customer_lifecycle.experiments.report() if getattr(scheduler, "sales_host", None) else [],
            "customer_fast_intake": scheduler.customer_fast_intake.report() if getattr(scheduler,"customer_fast_intake",None) else None,
            "customer_lifecycle": scheduler.sales_host.customer_lifecycle.report() if getattr(scheduler, "sales_host", None) else [],
            "sales": scheduler.sales_host.report() if getattr(scheduler, "sales_host", None) else [],
            "capability_waits": scheduler.capability_waits.report() if getattr(scheduler, "capability_waits", None) else [],
            "capability_development": scheduler.capability_waits.development.report() if getattr(scheduler, "capability_waits", None) else [],
            "capability_runtime": capability_runtime_report(scheduler.capability_waits) if getattr(scheduler, "capability_waits", None) else {},
            "capability_learning": scheduler.capability_waits.learning.report() if getattr(scheduler, "capability_waits", None) else {},
            "capability_outcomes": scheduler.capability_waits.outcomes.report() if getattr(scheduler, "capability_waits", None) else {},
            "capability_investments": rank_capability_investments([scheduler.capability_waits], now=now) if getattr(scheduler, "capability_waits", None) else {},
            "periods": periods, "decisions": decisions, "alerts": alerts,
            "unobserved": ["workspace_quarantine", "external_account_completeness"]}


def render_operations_html(report):
    """Render a portable escaped report with no scripts or remote dependencies."""
    title = "Company operations" if report.get("schema") == "lightbulb.company_operations_status.v1" else "Company readiness"
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
             '<title>' + title + '</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172b3a;background:#f8fafc}section{background:white;padding:20px;margin:16px 0;border:1px solid #dfe6ed;border-radius:12px;overflow:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #e7edf2;overflow-wrap:anywhere}th{color:#425b70}h2{font-size:20px;margin:0 0 15px}pre{white-space:pre-wrap;overflow-wrap:anywhere}dt{font-weight:600;margin-top:10px}dd{margin:4px 0 12px}</style>',
             '<h1>' + title + '</h1><p>Read-only snapshot. Refresh by running the status command again. This report grants no approvals.</p>']
    def cell(value):
        if value is None:
            return "Unknown"
        if type(value) is bool:
            return "Yes" if value else "No"
        return escape(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value))
    primary = [k for k in ("demonstration", "configuration_valid", "deployment_ready", "checks", "alerts", "worker", "sources", "billing", "sales", "customer_lifecycle", "customer_actions", "customer_experiments", "customer_fast_intake", "capability_waits", "capability_development", "capability_outcomes", "capability_investments", "capability_learning", "capability_runtime", "periods", "decisions", "unobserved") if k in report]
    ordered = primary + [k for k in report if k not in primary]
    for index, key in enumerate(ordered):
        value = report[key]
        if index == len(primary):
            parts.append('<details><summary>Evidence metadata</summary>')
        parts.append('<section><h2>' + escape(key.replace('_', ' ').capitalize()) + '</h2>')
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            columns = list(dict.fromkeys(k for row in value for k in row))
            parts.append('<table><thead><tr>' + ''.join('<th scope="col">' + escape(c.replace('_', ' ').capitalize()) + '</th>' for c in columns) + '</tr></thead><tbody>')
            for row in value:
                parts.append('<tr>' + ''.join('<td>' + cell(row.get(c)) + '</td>' for c in columns) + '</tr>')
            parts.append('</tbody></table>')
        elif isinstance(value, dict):
            parts.append('<dl>' + ''.join('<dt>' + escape(k.replace('_', ' ').capitalize()) + '</dt><dd>' + cell(v) + '</dd>' for k, v in value.items()) + '</dl>')
        else:
            parts.append('<p>' + ("None recorded" if value == [] else cell(value)) + '</p>')
        parts.append('</section>')
    if len(ordered) > len(primary):
        parts.append('</details>')
    return ''.join(parts) + '</html>'
