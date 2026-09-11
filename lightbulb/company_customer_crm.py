"""Accepted CRM inquiries via the authenticated project API and existing host journal."""

from typing import Literal
from uuid import UUID
from pydantic import Field, field_validator
from lightbulb.company_engine_core import StrictModel, OpaqueRef, stable_digest, parsed, detached
from lightbulb.company_customer_events import CompanyCustomerEvents, CustomerEvent, require


class CustomerCrmSource(StrictModel):
    source_ref: OpaqueRef
    kind: Literal["crm_inbound"] = "crm_inbound"
    identity_links: dict[str, OpaqueRef] = Field(min_length=1, max_length=1000)
    event_bindings: dict = Field(
        default_factory=lambda: {"inquiry_received": {"kind": "inquiry_received"}}
    )

    @field_validator("identity_links")
    @classmethod
    def identities(cls, value):
        require(
            all(len(k) == 64 and set(k) <= set("0123456789abcdef") for k in value),
            "CUSTOMER_CRM_IDENTITY_INVALID",
        )
        return value

    @field_validator("event_bindings")
    @classmethod
    def event_kind(cls, value):
        require(
            value == {"inquiry_received": {"kind": "inquiry_received"}},
            "CUSTOMER_CRM_EVENT_INVALID",
        )
        return value


def customer_crm_identity(contact_id):
    return stable_digest(str(UUID(str(contact_id))))


class CompanyCustomerCrmIntake:
    def __init__(self, runner, gateway, client, sources):
        self.events = CompanyCustomerEvents(runner, gateway)
        self.client = client
        self.sources = tuple(CustomerCrmSource.model_validate(s) for s in sources)
        require(
            len(self.sources) <= 20
            and len({s.source_ref for s in self.sources}) == len(self.sources),
            "CUSTOMER_CRM_SOURCES_INVALID",
        )

    def cycle(self, *, start, end, now, fence):
        require(parsed(start) < parsed(end) <= parsed(now), "CUSTOMER_CRM_WINDOW_INVALID")
        reports = []
        for source in self.sources:
            reports.append(self._source(source, start=start, end=end, now=now, fence=fence))
        return reports

    def _source(self, source, *, start, end, now, fence):
        events = self.events
        authority = events.gateway.authority_scope.model_dump(mode="json")
        expected = {k: str(authority[k]) for k in ("tenant_id", "company_id", "user_id")}
        expected["project_id"] = str(events.runner.bundle.scope["project_id"])
        events.validate_source_revision(source)
        cursor = None
        unmatched = set()
        count = 0
        for index in range(100):
            ref = (
                events.prefix
                + "-crm-page-"
                + stable_digest(
                    {"source": source.to_dict(), "start": start, "end": end, "cursor": cursor}
                )
            )
            old = events.read(ref)
            if old is None:
                fence()
                response = self.client.list_customer_inbound_events(
                    expected["project_id"],
                    start=start,
                    end=end,
                    cursor=cursor,
                    company_id=expected["company_id"],
                )
                require(
                    isinstance(response, dict)
                    and response.get("schema") == "lightbulb.crm_customer_event_page.v1"
                    and all(response.get(k) == v for k, v in expected.items()),
                    "CUSTOMER_CRM_SCOPE_MISMATCH",
                )
                require(
                    set(response)
                    == {
                        "schema",
                        "tenant_id",
                        "company_id",
                        "user_id",
                        "project_id",
                        "start",
                        "end",
                        "events",
                        "has_more",
                        "next_cursor",
                    }
                    and isinstance(response["events"], list)
                    and len(response["events"]) <= 100
                    and all(
                        isinstance(row, dict)
                        and set(row) == {"event_ref", "occurred_at", "identity_digest", "kind"}
                        for row in response["events"]
                    ),
                    "CUSTOMER_CRM_PAGE_INVALID",
                )
                require(
                    parsed(response["start"]) == parsed(start)
                    and parsed(response["end"]) == parsed(end),
                    "CUSTOMER_CRM_WINDOW_MISMATCH",
                )

                def retain(doc):
                    require(
                        not doc.get("response") or doc["response"] == response,
                        "CUSTOMER_CRM_PAGE_CHANGED",
                    )
                    doc["response"] = detached(response)

                old = events.change(ref, retain, fence)
            response = old["response"]
            rows = response["events"]
            require(
                isinstance(rows, list)
                and len(rows) <= 100
                and type(response.get("has_more")) is bool
                and bool(response.get("next_cursor")) == response["has_more"],
                "CUSTOMER_CRM_PAGE_INVALID",
            )
            previous = (parsed(cursor["after_at"]), cursor["after_id"]) if cursor else None
            for row in rows:
                key = (parsed(row["occurred_at"]), str(UUID(row["event_ref"])))
                require(
                    parsed(start) <= key[0] < parsed(end)
                    and (previous is None or key > previous)
                    and row["kind"] == "inquiry_received",
                    "CUSTOMER_CRM_EVENT_MISMATCH",
                )
                previous = key
                identity = row["identity_digest"]
                require(
                    isinstance(identity, str)
                    and len(identity) == 64
                    and set(identity) <= set("0123456789abcdef"),
                    "CUSTOMER_CRM_IDENTITY_INVALID",
                )
                account = source.identity_links.get(identity)
                if account is None:
                    unmatched.add(identity)
                    continue
                provider = stable_digest(
                    {"proposal": row["event_ref"], "accepted_revision_at": row["occurred_at"]}
                )
                event = CustomerEvent(
                    event_ref=stable_digest({"crm": expected, "event": provider}),
                    account_ref=account,
                    kind="inquiry_received",
                    occurred_at=row["occurred_at"],
                    source_ref=source.source_ref,
                    provider_event_digest=provider,
                    identity_digest=identity,
                )
                events._retain(
                    event,
                    {
                        "source_kind": "authenticated_crm_accepted_proposal",
                        "page_ref": ref,
                        "response_digest": stable_digest(response),
                        "binding_digest": stable_digest(source.to_dict()),
                    },
                    fence,
                )
                count += 1
            if not response["has_more"]:
                events.complete_window(
                    source, start=start, end=end, unmatched=unmatched, fence=fence
                )
                return {
                    "kind": "crm_inbound",
                    "source_ref": source.source_ref,
                    "event_count": count,
                    "unmapped_count": len(unmatched),
                    "complete": True,
                }
            following = response["next_cursor"]
            require(
                rows
                and following
                == {"after_at": rows[-1]["occurred_at"], "after_id": rows[-1]["event_ref"]}
                and following != cursor,
                "CUSTOMER_CRM_CURSOR_INVALID",
            )
            cursor = following
        raise ValueError("CUSTOMER_CRM_PAGE_LIMIT")
