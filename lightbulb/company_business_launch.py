"""Read-only launch discovery and exact reviewed worker configuration materialization."""

from typing import Any, Literal
from pydantic import Field
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    detached,
    stable_digest,
    parsed,
)
from lightbulb.company_customer_events import require
from lightbulb.company_preflight import worker_preflight


class LaunchIdentityCandidate(StrictModel):
    source_ref: OpaqueRef
    provider_identity_digest: Sha256Digest
    account_ref: OpaqueRef
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)


class BusinessLaunchRequest(StrictModel):
    request_ref: OpaqueRef
    bundle: dict[str, Any]
    sources: tuple[dict[str, Any], ...] = Field(max_length=100)
    sales_config: dict[str, Any] | None = None
    customer_lifecycle: dict[str, Any] | None = None
    identity_candidates: tuple[LaunchIdentityCandidate, ...] = Field(default=(), max_length=1000)
    interval_seconds: int = Field(default=86400, ge=60, le=604800, strict=True)
    probe_start: str | None = None
    probe_end: str | None = None


class BusinessLaunchProposal(StrictModel):
    schema_id: Literal["lightbulb.business_launch_proposal.v1"] = Field(
        default="lightbulb.business_launch_proposal.v1", alias="schema"
    )
    request: BusinessLaunchRequest
    connected_accounts: tuple[dict[str, str], ...]
    route_checks: tuple[dict[str, Any], ...]
    instrumentation_gaps: tuple[dict[str, Any], ...]
    dry_run: dict[str, Any]
    proposal_digest: Sha256Digest
    execution_authorized: Literal[False] = False


class CompanyBusinessLaunch:
    """Inspects scoped metadata only. A review never substitutes for hosted effect approval."""

    def __init__(self, client, *, company_id, executor=None):
        from uuid import UUID

        self.client, self.company_id = client, str(UUID(str(company_id)))
        self.executor = executor

    @property
    def packages(self):
        from lightbulb.company_launch_packages import CompanyBusinessLaunchPackages
        return CompanyBusinessLaunchPackages(self)

    def prepare(self, request, *, probe_sources=True):
        from lightbulb.company_cadence_runner import build_bundle

        request = BusinessLaunchRequest.model_validate(request)
        from lightbulb.observation_runtime import _assert_no_secret_keys

        _assert_no_secret_keys(request.to_dict())
        bundle = build_bundle(request.bundle)
        project = str(bundle.scope["project_id"])
        rows = self.client.list_project_connector_accounts(project, company_id=self.company_id)
        require(isinstance(rows, list) and len(rows) <= 100, "LAUNCH_ACCOUNT_INVENTORY_INVALID")
        accounts = []
        for row in rows:
            require(
                isinstance(row, dict)
                and isinstance(row.get("connectorAccountRef"), str)
                and isinstance(row.get("provider"), str),
                "LAUNCH_ACCOUNT_INVENTORY_INVALID",
            )
            accounts.append(
                {
                    key: str(row[key])
                    for key in ("connectorAccountRef", "provider", "status")
                    if key in row
                }
            )
        refs = [row["connectorAccountRef"] for row in accounts]
        require(len(refs) == len(set(refs)), "LAUNCH_ACCOUNT_INVENTORY_DUPLICATED")
        configured = detached(request.sources)
        by_source = {row["source_ref"]: row for row in configured}
        require(len(by_source) == len(configured), "LAUNCH_SOURCE_DUPLICATED")
        for candidate in request.identity_candidates:
            require(candidate.source_ref in by_source, "LAUNCH_IDENTITY_SOURCE_REQUIRED")
            links = by_source[candidate.source_ref].setdefault("identity_links", {})
            previous = links.get(candidate.provider_identity_digest)
            require(
                previous is None or previous == candidate.account_ref, "LAUNCH_IDENTITY_CONFLICT"
            )
            links[candidate.provider_identity_digest] = candidate.account_ref
        proposed = request.model_copy(update={"sources": tuple(configured)})
        checks, gaps = [], []
        required = {(row.get("connector_account_ref"), row.get("tool")) for row in configured}
        from lightbulb.company_sales_configuration import CompanySalesConfiguration

        sales = CompanySalesConfiguration.model_validate(request.sales_config or {})
        for binding in sales.all_bindings():
            required.add((binding.connector_account_ref, "gmail.get_thread"))
            required.add((binding.connector_account_ref, "gmail.send_email"))
        for account, tool in sorted(required, key=str):
            if account not in refs:
                checks.append({"account_ref": account, "tool": tool, "status": "binding_required"})
                continue
            try:
                descriptor = self.client.get_project_connector_route_descriptor(
                    project, account, tool, company_id=self.company_id
                )
                checks.append(
                    {
                        "account_ref": account,
                        "tool": tool,
                        "status": "resolved",
                        "descriptor_digest": stable_digest(descriptor),
                    }
                )
            except Exception as error:
                # No provider bodies, credentials or exception strings enter the proposal.
                checks.append(
                    {
                        "account_ref": account,
                        "tool": tool,
                        "status": "unresolved",
                        "error_type": type(error).__name__,
                    }
                )
        for row in configured:
            if row.get("kind") == "customer_events":
                gaps.append(
                    {
                        "source_ref": row["source_ref"],
                        "event": row.get("arguments", {}).get("event"),
                        "status": "instrumentation_not_observed",
                        "identity_mapping": (
                            "proposed"
                            if any(
                                c.source_ref == row["source_ref"]
                                for c in request.identity_candidates
                            )
                            else "configured"
                        ),
                    }
                )
        require(
            (request.probe_start is None) == (request.probe_end is None),
            "LAUNCH_PROBE_WINDOW_REQUIRED",
        )
        if request.probe_start is not None and probe_sources:
            from datetime import datetime, timezone

            require(
                parsed(request.probe_start)
                < parsed(request.probe_end)
                <= datetime.now(timezone.utc)
                and (parsed(request.probe_end) - parsed(request.probe_start)).total_seconds()
                <= 604800,
                "LAUNCH_PROBE_WINDOW_INVALID",
            )
            from lightbulb.connector_execution import HostedConnectorExecutor
            from lightbulb.connector_execution import ConnectorExecutionRequest, ExecutionScope
            from lightbulb.company_sales_progression import scoped_receipt
            from lightbulb.company_recurring_observations import RecurringObservationBinding

            executor = self.executor or HostedConnectorExecutor(self.client)
            for gap in gaps:
                source = RecurringObservationBinding.model_validate(by_source[gap["source_ref"]])
                if not any(
                    c["account_ref"] == source.connector_account_ref
                    and c["tool"] == source.tool
                    and c["status"] == "resolved"
                    for c in checks
                ):
                    continue
                job = source.job(start=request.probe_start, end=request.probe_end)
                read = ConnectorExecutionRequest(
                    tool=source.tool,
                    effect="read",
                    scope=ExecutionScope(**bundle.scope, actor_ref=bundle.actor_ref),
                    connector_account_ref=source.connector_account_ref,
                    arguments=job.arguments,
                )
                result = executor.execute(read)
                receipt = scoped_receipt(result, read)
                output = result.output
                from hashlib import sha256

                require(
                    output.get("schema") == "lightbulb.posthog_event_page.v1"
                    and output.get("event") == source.arguments["event"]
                    and output.get("project_id_sha256")
                    == sha256(str(source.arguments["project_id"]).encode()).hexdigest()
                    and parsed(output.get("after")) == parsed(request.probe_start)
                    and parsed(output.get("before")) == parsed(request.probe_end)
                    and isinstance(output.get("events"), list)
                    and len(output["events"]) <= 100,
                    "LAUNCH_PROBE_RESULT_INVALID",
                )
                import re

                require(
                    all(
                        isinstance(r, dict)
                        and re.fullmatch(r"[a-f0-9]{64}", str(r.get("distinct_id_sha256", "")))
                        and re.fullmatch(r"[a-f0-9]{64}", str(r.get("uuid_sha256", "")))
                        and parsed(request.probe_start)
                        <= parsed(r.get("timestamp"))
                        < parsed(request.probe_end)
                        for r in output["events"]
                    ),
                    "LAUNCH_PROBE_IDENTITY_INVALID",
                )
                valid = [r for r in output["events"] if r.get("event") == source.arguments["event"]]
                require(len(valid) == len(output["events"]), "LAUNCH_PROBE_EVENT_MISMATCH")
                gap.update(
                    status=(
                        "observed"
                        if valid
                        else (
                            "not_observed_in_window"
                            if output.get("has_more") is False
                            else "incomplete_probe"
                        )
                    ),
                    receipt_digest=receipt.receipt_digest,
                    window_start=request.probe_start,
                    window_end=request.probe_end,
                    unmatched_identity_digests=sorted(
                        {
                            r["distinct_id_sha256"]
                            for r in valid
                            if r["distinct_id_sha256"] not in source.identity_links
                        }
                    ),
                )
        report = worker_preflight(
            bundle.to_dict(),
            configured,
            company_id=self.company_id,
            sales_config=request.sales_config,
            customer_lifecycle=request.customer_lifecycle,
            interval_seconds=request.interval_seconds,
        )
        body = dict(
            request=proposed.to_dict(),
            connected_accounts=accounts,
            route_checks=checks,
            instrumentation_gaps=gaps,
            dry_run=report,
        )
        return BusinessLaunchProposal(**body, proposal_digest=stable_digest(body))

    def materialize_reviewed(self, proposal, *, expected_digest):
        proposal = BusinessLaunchProposal.model_validate(proposal)
        body = {
            key: detached(getattr(proposal, key))
            for key in (
                "request",
                "connected_accounts",
                "route_checks",
                "instrumentation_gaps",
                "dry_run",
            )
        }
        require(
            proposal.proposal_digest == expected_digest == stable_digest(body),
            "LAUNCH_REVIEW_CHANGED",
        )
        require(proposal.dry_run.get("configuration_valid") is True, "LAUNCH_CONFIGURATION_INVALID")
        require(
            all(row["status"] == "resolved" for row in proposal.route_checks),
            "LAUNCH_ROUTES_REQUIRED",
        )
        # Re-resolve after review; changes require a new preview and review.
        fresh = self.prepare(proposal.request, probe_sources=False)
        require(
            all(
                detached(getattr(fresh, key)) == detached(getattr(proposal, key))
                for key in ("request", "connected_accounts", "route_checks", "dry_run")
            ),
            "LAUNCH_DISCOVERY_CHANGED",
        )
        return {
            "bundle": proposal.request.bundle,
            "sources": list(proposal.request.sources),
            "sales_config": proposal.request.sales_config,
            "customer_lifecycle": proposal.request.customer_lifecycle,
            "interval_seconds": proposal.request.interval_seconds,
            "reviewed_proposal_digest": expected_digest,
            "deployment_ready": False,
            "execution_authorized": False,
        }


def main(argv=None):
    """Print a launch preview or materialize an exact reviewed proposal; never run it."""
    import argparse
    import json
    from pathlib import Path
    from lightbulb.cli import _client_from_env

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--company-id", required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--request", help="BusinessLaunchRequest JSON to inspect")
    choice.add_argument("--reviewed-proposal", help="Previously inspected proposal JSON")
    parser.add_argument("--expected-digest", help="Exact proposal digest reviewed by the user")
    args = parser.parse_args(argv)
    if bool(args.reviewed_proposal) != bool(args.expected_digest):
        parser.error("reviewed-proposal and expected-digest must be supplied together")
    assistant = CompanyBusinessLaunch(_client_from_env(), company_id=args.company_id)
    if args.request:
        result = assistant.prepare(
            json.loads(Path(args.request).read_text(encoding="utf-8"))
        ).to_dict()
    else:
        result = assistant.materialize_reviewed(
            json.loads(Path(args.reviewed_proposal).read_text(encoding="utf-8")),
            expected_digest=args.expected_digest,
        )
    print(json.dumps(result, indent=2))
    return 0
