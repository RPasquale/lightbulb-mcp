"""Unattended software factory loop for a company's generated apps.

Run on a trusted host under the deployment's process supervisor.  Each step reads every
configured app's recent signals from the platform, rolls errors up by signature, and for each
signature past the threshold compiles a defect request whose acceptance criterion the host can
state without a person: the error stops, and a test reproduces it before the fix and passes after.
It asks the platform for a grant (the owner's mandate decides: act, ask or refuse), verifies the
grant against the request through the platform's authoritative lookup, and dispatches the run.
The platform completes finished runs itself, publishing a draft pull request only when the run's
tests passed, its changes stayed in scope and carry no secrets.

Raw feedback stays with the operating agent's ``next`` step. Structured, redacted support
briefs can enter this same verified grant path with fixed host acceptance criteria. Sensitive
classes and owner-alert events require manual review; alert intents are returned for the platform
to deliver. Nothing here merges or deploys.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

log = logging.getLogger(__name__)

HOST_SCHEMA = "lightbulb.software_factory_host_step.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FactoryApp:
    """One generated app the host watches, and where its fixes are built."""

    app_instance_id: str
    workspace_id: str
    repository_binding_ref: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FactoryApp":
        return cls(app_instance_id=str(value["app_instance_id"]), workspace_id=str(value["workspace_id"]), repository_binding_ref=str(value["repository_binding_ref"]))


@dataclass(frozen=True)
class FactoryHostConfig:
    """What the host may do for one company: the apps it watches, the budget per change, how much per step."""

    company_id: str
    company_ref: str
    project_id: str
    tenant_ref: str
    project_ref: str
    apps: tuple[FactoryApp, ...]
    coding_budget: str
    currency: str
    window_days: int = 7
    error_threshold: int | None = None
    max_changes_per_step: int = 3
    requesting_agent_ref: str = "agent:software_factory_host"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FactoryHostConfig":
        apps = tuple(FactoryApp.from_mapping(app) for app in value.get("apps") or ())
        if not apps:
            raise ValueError("FACTORY_APPS_REQUIRED: configure at least one app with its workspace and repository")
        max_changes = int(value.get("max_changes_per_step", 3))
        if not 1 <= max_changes <= 20:
            raise ValueError("max_changes_per_step is between 1 and 20")
        return cls(
            company_id=str(value["company_id"]),
            company_ref=str(value["company_ref"]),
            project_id=str(value["project_id"]),
            tenant_ref=str(value["tenant_ref"]),
            project_ref=str(value["project_ref"]),
            apps=apps,
            coding_budget=str(value["coding_budget"]),
            currency=str(value["currency"]).upper(),
            window_days=int(value.get("window_days", 7)),
            error_threshold=None if value.get("error_threshold") is None else int(value["error_threshold"]),
            max_changes_per_step=max_changes,
            requesting_agent_ref=str(value.get("requesting_agent_ref", "agent:software_factory_host")),
        )


def acceptance_for_error(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The criterion an error spike carries on its own: it stops, and a test proves it."""
    signature = str(row["error_signature"])[:200]
    pages = ", ".join(str(page) for page in (row.get("pages") or ())[:5])
    return [
        {
            "criterion_id": "error-stops",
            "description": f"The error '{signature}' no longer occurs" + (f" on {pages}" if pages else "") + ".",
            "required_evidence": ["test_report"],
        },
        {
            "criterion_id": "regression-test",
            "description": "A test reproduces the failure before the fix and passes after it.",
            "required_evidence": ["test_report"],
        },
    ]


@dataclass
class SoftwareFactoryHost:
    """One company's unattended error-to-draft-pull-request loop."""

    client: Any
    config: FactoryHostConfig
    clock: Callable[[], str] = utc_now
    attempted: set[str] = field(default_factory=set)
    support_cases: set[tuple[str, str]] = field(default_factory=set)
    support_reporter_attempts: dict[str, list[str]] = field(default_factory=dict)

    def step(self) -> dict[str, Any]:
        from lightbulb.app_signals import DEFAULT_ERROR_THRESHOLD, candidate_from_error_rollup, compile_app_signal_batch, rollup_errors
        from lightbulb.change_candidate import compile_production_request
        from lightbulb.execution_grant import GrantError, verify_execution_grant

        now = self.clock()
        since = (datetime.fromisoformat(now.replace("Z", "+00:00")) - timedelta(days=self.config.window_days)).isoformat().replace("+00:00", "Z")
        outcomes: list[dict[str, Any]] = []
        owner_alerts: dict[str, dict[str, Any]] = {}
        pending = []
        pending_cases = set()
        reporter_counts = {}
        started = 0
        for app in self.config.apps:
            try:
                read = self.client.factory_app_signals(app.app_instance_id, company_id=self.config.company_id, since=since)
                signals = list(read.get("signals") or ())
                if read.get("app_ref") and str(read["app_ref"]) != app.app_instance_id:
                    raise ValueError("APP_SCOPE_MISMATCH")
            except Exception:
                outcomes.append({"app": app.app_instance_id, "outcome": "signals_rejected", "reason": "APP_SIGNAL_READ_OR_SCOPE_FAILED"})
                continue
            valid = []
            if len(signals) >= 500 or read.get("has_more"):
                outcomes.append({"app": app.app_instance_id, "outcome": "signal_feed_incomplete", "reason": "SIGNAL_PAGE_LIMIT_REACHED", "platform_pagination_required": True})
            for index, raw in enumerate(signals[:500]):
                try:
                    one = compile_app_signal_batch(self.config.company_ref, app_ref=app.app_instance_id, signals=[raw], received_at=now).signals[0]
                except (ValueError, TypeError, KeyError):
                    outcomes.append({"app": app.app_instance_id, "signal_index": index, "outcome": "signals_rejected", "reason": "INVALID_SIGNAL_PAYLOAD"})
                    continue
                if not since <= one.occurred_at <= now:
                    outcomes.append({"app": app.app_instance_id, "signal_index": index, "outcome": "signal_out_of_window", "reason": "future" if one.occurred_at > now else "stale"})
                    continue
                valid.append(one.to_dict())
            if not valid:
                continue
            batch = compile_app_signal_batch(self.config.company_ref, app_ref=app.app_instance_id, signals=valid, received_at=now)
            for signal in sorted(batch.signals, key=lambda item: not bool((item.support_fix_brief or {}).get("owner_alert_events"))):
                if signal.support_fix_brief is None:
                    continue
                from lightbulb.support_reports import prepare_support_intake
                try:
                    intake = prepare_support_intake(signal.to_dict(), scope={"tenant_ref": self.config.tenant_ref, "company_ref": self.config.company_ref, "project_ref": self.config.project_ref, "project_id": self.config.project_id}, app_ref=app.app_instance_id, repository_binding_ref=app.repository_binding_ref, workspace_binding_ref=app.workspace_id, coding_budget=self.config.coding_budget, currency=self.config.currency, now=now, requesting_agent_ref=self.config.requesting_agent_ref)
                except (ValueError, TypeError):
                    outcomes.append({"app": app.app_instance_id, "outcome": "support_rejected", "reason": "SUPPORT_SCOPE_OR_CONTRACT_MISMATCH"})
                    continue
                for alert in intake["owner_alerts"]:
                    owner_alerts[alert["alert_ref"]] = alert
                evidence = {key: value for key, value in intake.items() if key not in {"request", "candidate_ref", "owner_alerts"}}
                if intake["outcome"] != "request_prepared":
                    outcomes.append({**evidence, "app": app.app_instance_id})
                    continue
                case = (app.app_instance_id, intake["report_ref"])
                reporter = signal.reporter_ref
                recent = [stamp for stamp in self.support_reporter_attempts.get(reporter, []) if stamp[:10] == now[:10]] if reporter else []
                count = reporter_counts.get(reporter, len(recent))
                if case in self.support_cases or case in pending_cases:
                    outcomes.append({**evidence, "app": app.app_instance_id, "outcome": "duplicate_case"})
                    continue
                if reporter and count >= 3:
                    outcomes.append({**evidence, "app": app.app_instance_id, "outcome": "reporter_rate_limited"})
                    continue
                pending_cases.add(case)
                if reporter:
                    reporter_counts[reporter] = count + 1
                pending.append((app, intake["candidate_ref"], intake["request"], {**evidence, "app": app.app_instance_id}, case, reporter))
            try:
                rollup = rollup_errors(self.config.company_ref, batches=[batch.to_dict()], as_of=now, window_days=self.config.window_days,
                                       threshold=self.config.error_threshold or DEFAULT_ERROR_THRESHOLD)
                for row in rollup.to_dict()["rows"]:
                    if not row.get("over_threshold"):
                        continue
                    candidate = candidate_from_error_rollup(self.config.company_ref, project_id=self.config.project_id, row=row)
                    request = compile_production_request(candidate, tenant_ref=self.config.tenant_ref, project_ref=self.config.project_ref, workspace_binding_ref=app.workspace_id, repository_binding_ref=app.repository_binding_ref, acceptance_criteria=acceptance_for_error(row), coding_budget=self.config.coding_budget, currency=self.config.currency, requested_at=now, requesting_agent_ref=self.config.requesting_agent_ref)
                    pending.append((app, candidate.candidate_ref, request, {"app": app.app_instance_id, "error_signature": row["error_signature"], "count": row["count"]}, None, None))
            except (ValueError, TypeError):
                outcomes.append({"app": app.app_instance_id, "outcome": "signals_rejected", "reason": "ERROR_ROLLUP_INVALID"})
        # Alerts are collected before effects and retained in every handled failure.
        # Only the alerting support case is held; unrelated apps continue working.
        try:
            lookup = self.client.factory_grant_lookup(company_id=self.config.company_id) if pending else None
        except Exception:
            lookup = None
        for app, ref, request, evidence, case, reporter in pending:
            if ref in self.attempted:
                continue
            if started >= self.config.max_changes_per_step:
                outcomes.append({"candidate_ref": ref, "app": app.app_instance_id, "outcome": "deferred", "reason": "max_changes_per_step reached"})
                continue
            if lookup is None:
                outcomes.append({**evidence, "outcome": "deferred", "reason": "GRANT_LOOKUP_UNAVAILABLE"})
                continue
            self.attempted.add(ref)
            if case:
                self.support_cases.add(case)
            if reporter:
                self.support_reporter_attempts[reporter] = [stamp for stamp in self.support_reporter_attempts.get(reporter, []) if stamp[:10] == now[:10]] + [now]
            outcome = {**evidence, "candidate_ref": ref}
            try:
                answer = self.client.factory_issue_grant(company_id=self.config.company_id, request=request, coding_budget=self.config.coding_budget,
                                                         workspace_id=app.workspace_id, currency=self.config.currency, app_ref=app.app_instance_id)
            except Exception:
                outcomes.append({**outcome, "outcome": "refused", "reason": "PLATFORM_GRANT_FAILED"})
                continue
            if not isinstance(answer, Mapping):
                outcomes.append({**outcome, "outcome": "refused", "reason": "PLATFORM_GRANT_INVALID"})
                continue
            if not answer.get("issued"):
                outcomes.append({**outcome, "outcome": "not_issued", "code": answer.get("code"), "reason": "Platform did not issue a grant."})
                continue
            grant = answer.get("grant")
            if not isinstance(grant, Mapping):
                outcomes.append({**outcome, "outcome": "grant_unverified", "code": "INVALID_GRANT"})
                continue
            try:
                verify_execution_grant(grant, request=request, now=now, lookup=lookup, effect="branch_create")
            except GrantError as exc:
                outcomes.append({**outcome, "outcome": "grant_unverified", "grant_ref": grant.get("grant_ref"), "code": exc.code})
                continue
            except Exception:
                outcomes.append({**outcome, "outcome": "grant_unverified", "code": "GRANT_VERIFICATION_FAILED"})
                continue
            try:
                dispatched = self.client.factory_dispatch(str(grant["grant_ref"]), company_id=self.config.company_id)
                if not isinstance(dispatched, Mapping):
                    raise ValueError("INVALID_DISPATCH_RESULT")
            except Exception:
                outcomes.append({**outcome, "outcome": "dispatch_failed", "reason": "PLATFORM_DISPATCH_FAILED"})
                continue
            started += 1
            outcomes.append({**outcome, "outcome": "dispatched", "grant_ref": grant["grant_ref"], "replayed": bool(answer.get("replayed")), "run_id": dispatched.get("run_id")})
        return {"schema": HOST_SCHEMA, "company_ref": self.config.company_ref, "as_of": now, "window_since": since, "dispatched": started, "outcomes": outcomes, "owner_alerts": list(owner_alerts.values())}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the unattended software factory loop for a company's generated apps")
    parser.add_argument("--config", required=True, help="JSON: company_id, company_ref, project_id, tenant_ref, project_ref, apps[], coding_budget, currency")
    parser.add_argument("--interval-seconds", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    config = FactoryHostConfig.from_mapping(json.loads(Path(args.config).read_text(encoding="utf-8")))
    import os

    from lightbulb.cli import _client_from_env, _resolve_auth

    base_url = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com").rstrip("/")
    client = _client_from_env(auth_refresh=lambda: _resolve_auth(base_url))
    host = SoftwareFactoryHost(client, config)
    while True:
        try:
            print(json.dumps(host.step(), sort_keys=True), flush=True)
        except Exception as exc:  # one failed step never stops the supervised loop
            log.warning("software factory step failed: %s", type(exc).__name__)
        if args.once:
            return 0
        time.sleep(max(60, args.interval_seconds))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
