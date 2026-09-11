"""Bounded PostHog continuation on the company observation host's existing journal."""

from lightbulb.company_engine_core import detached, stable_digest, parsed
from lightbulb.company_observation_host import _write
from lightbulb.company_customer_events import CompanyCustomerEvents, require
from lightbulb.connector_execution import ConnectorExecutionResult
from lightbulb.company_execution_bridge import execution_receipt_from_connector


def ingest_customer_event_pages(host, source, request, result, *, now, identity, fence):
    events = CompanyCustomerEvents(host.console._runner(), host.gateway)
    original, cursor, total = request, None, 0
    seen, unmatched, references = {}, set(), []
    for index in range(100):
        ref = "company-customer-event-page-" + stable_digest(
            {"observation": identity, "index": index, "cursor": cursor}
        )
        saved = host.gateway.get(ref)
        if index:
            request = original.model_copy(
                update={
                    "arguments": {**original.arguments, "cursor": cursor},
                    "idempotency_key": ref,
                }
            )
        if saved is None:
            fence()
            saved = _write(
                host.gateway,
                ref,
                {"status": "RUNNING", "request": request.model_dump(mode="json", by_alias=True)},
            )
        require(
            saved["request"] == request.model_dump(mode="json", by_alias=True),
            "CUSTOMER_EVENT_PAGE_REQUEST_CHANGED",
        )
        if saved.get("result") is None:
            if index:
                fence()
                result = ConnectorExecutionResult.model_validate(
                    detached(host.executor.execute(request))
                )
            execution_receipt_from_connector(result, request)
            fence()
            saved = _write(
                host.gateway,
                ref,
                {**saved, "result": result.model_dump(mode="json", by_alias=True)},
                saved,
            )
        result = ConnectorExecutionResult.model_validate(saved["result"])
        output = result.output
        require(
            output.get("pagination_mode") == "timestamp_overlap_ascending_v1"
            and output.get("page_index") == index
            and output.get("cursor") == cursor
            and output.get("total_record_limit") == 10000,
            "CUSTOMER_EVENT_PAGE_CHAIN_INVALID",
        )
        require(
            type(output.get("has_more")) is bool
            and bool(output.get("next_cursor")) == output["has_more"],
            "CUSTOMER_EVENT_PAGE_CHAIN_INVALID",
        )
        converted = events.ingest_posthog(
            source, request, result, now=max((now, host.console.clock()), key=parsed), fence=fence
        )
        total += len(output["events"])
        require(total <= 10000, "CUSTOMER_EVENT_READ_LIMIT")
        for row in output["events"]:
            event_id, digest = row["uuid_sha256"], stable_digest(row)
            require(
                event_id not in seen or seen[event_id] == digest,
                "CUSTOMER_EVENT_CHANGED_ACROSS_PAGES",
            )
            seen[event_id] = digest
        unmatched.update(converted["unmapped_identities"])
        references.append(ref)
        fence()
        _write(
            host.gateway,
            ref,
            {**saved, "phase": "ingested", "status": "COMPLETED", "ingestion": converted},
            saved,
        )
        if not output["has_more"]:
            events.complete_window(
                source,
                start=original.arguments["after"],
                end=original.arguments["before"],
                unmatched=unmatched,
                fence=fence,
            )
            return {
                "kind": "customer_events",
                "complete": True,
                "event_count": len(seen),
                "unmapped_count": len(unmatched),
                "page_refs": references,
            }
        following = output["next_cursor"]
        require(isinstance(following, str) and following != cursor, "CUSTOMER_EVENT_CURSOR_STALLED")
        cursor = following
    raise ValueError("CUSTOMER_EVENT_PAGE_LIMIT")
