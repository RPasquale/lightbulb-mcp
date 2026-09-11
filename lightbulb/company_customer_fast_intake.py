"""Rapid scoped ingress hints and authoritative reconciliation under the cadence lease."""

from datetime import timedelta
from uuid import UUID
from httpx import TransportError
from lightbulb.errors import RateLimitedError, ServerError
from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest, detached
from lightbulb.company_customer_events import CompanyCustomerEvents, require


class CustomerFastIntakePolicy(StrictModel):
    poll_seconds: int = Field(default=60, ge=60, le=3600, strict=True)
    webhook_connector_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=20)


class CompanyCustomerFastIntake:
    def __init__(self, runner, gateway, client, observation_host, policy):
        self.events = CompanyCustomerEvents(runner, gateway)
        self.client, self.observation = client, observation_host
        self.policy = CustomerFastIntakePolicy.model_validate(policy)
        require(
            len(set(self.policy.webhook_connector_refs)) == len(self.policy.webhook_connector_refs),
            "CUSTOMER_WEBHOOK_BINDING_DUPLICATED",
        )
        available = {
            source.connector_account_ref
            for source in observation_host.sources
            if source.kind == "invoice_health"
        }
        require(
            set(self.policy.webhook_connector_refs) <= available,
            "CUSTOMER_WEBHOOK_INVOICE_SOURCE_REQUIRED",
        )
        self.ref = self.events.prefix + "-fast-intake"

    def hints(self, account, *, start, end, fence):
        scope = self.events.gateway.authority_scope.model_dump(mode="json")
        expected = {key: str(scope[key]) for key in ("tenant_id", "company_id", "user_id")}
        expected.update(
            project_id=str(self.events.runner.bundle.scope["project_id"]),
            connector_account_ref=account,
        )
        cursor, seen = None, set()
        for page in range(100):
            ref = (
                self.ref
                + "-page-"
                + stable_digest({"account": account, "start": start, "end": end, "cursor": cursor})
            )
            old = self.events.read(ref)
            if not old:
                fence()
                response = self.client.list_customer_webhook_hints(
                    expected["project_id"],
                    connector_account_ref=account,
                    start=start,
                    end=end,
                    cursor=cursor,
                    company_id=expected["company_id"],
                )
                require(
                    isinstance(response, dict)
                    and set(response)
                    == {"schema", *expected, "start", "end", "events", "has_more", "next_cursor"}
                    and response["schema"] == "lightbulb.customer_webhook_hints.v1"
                    and all(response[key] == value for key, value in expected.items()),
                    "CUSTOMER_WEBHOOK_SCOPE_MISMATCH",
                )
                require(
                    parsed(response["start"]) == parsed(start)
                    and parsed(response["end"]) == parsed(end),
                    "CUSTOMER_WEBHOOK_WINDOW_MISMATCH",
                )
                require(
                    isinstance(response["events"], list)
                    and len(response["events"]) <= 100
                    and type(response["has_more"]) is bool
                    and bool(response["next_cursor"]) == response["has_more"],
                    "CUSTOMER_WEBHOOK_PAGE_INVALID",
                )
                previous = (
                    (parsed(cursor["after_at"]), str(UUID(cursor["after_id"]))) if cursor else None
                )
                for row in response["events"]:
                    require(
                        isinstance(row, dict)
                        and set(row)
                        == {
                            "event_ref",
                            "provider_event_id",
                            "event_type",
                            "received_at",
                            "occurred_at",
                        },
                        "CUSTOMER_WEBHOOK_EVENT_INVALID",
                    )
                    key = (parsed(row["received_at"]), str(UUID(row["event_ref"])))
                    require(
                        parsed(start) <= key[0] < parsed(end)
                        and (previous is None or key > previous),
                        "CUSTOMER_WEBHOOK_CURSOR_INVALID",
                    )
                    require(
                        isinstance(row["provider_event_id"], str)
                        and row["provider_event_id"].startswith("evt_")
                        and len(row["provider_event_id"]) <= 255
                        and isinstance(row["event_type"], str)
                        and len(row["event_type"]) <= 255,
                        "CUSTOMER_WEBHOOK_EVENT_INVALID",
                    )
                    if row["occurred_at"] is not None:
                        require(
                            parsed(row["occurred_at"]) <= parsed(end),
                            "CUSTOMER_WEBHOOK_EVENT_FROM_FUTURE",
                        )
                    previous = key
                if response["has_more"]:
                    require(
                        bool(response["events"])
                        and response["next_cursor"]
                        == {
                            "after_at": response["events"][-1]["received_at"],
                            "after_id": response["events"][-1]["event_ref"],
                        },
                        "CUSTOMER_WEBHOOK_CURSOR_INVALID",
                    )

                def retain(doc):
                    require(
                        not doc.get("response") or doc["response"] == response,
                        "CUSTOMER_WEBHOOK_PAGE_CHANGED",
                    )
                    doc["response"] = detached(response)

                old = self.events.change(ref, retain, fence)
            response = old["response"]
            for row in response["events"]:
                event_key = stable_digest({"account": account, "event": row["provider_event_id"]})
                require(event_key not in seen, "CUSTOMER_WEBHOOK_DUPLICATED")
                seen.add(event_key)
                event_ref = self.ref + "-hint-" + event_key

                def retain_hint(doc):
                    require(
                        not doc.get("event") or doc["event"] == row,
                        "CUSTOMER_WEBHOOK_EVENT_CHANGED",
                    )
                    doc.update(
                        event=row,
                        account_ref=account,
                        payment_confirmed=False,
                        absence_coverage=False,
                    )

                self.events.change(event_ref, retain_hint, fence)
            if not response["has_more"]:
                return len(seen)
            cursor = response["next_cursor"]
        raise ValueError("CUSTOMER_WEBHOOK_PAGE_LIMIT")

    def cycle(self, *, now, fence):
        from lightbulb.company_observation_host import CompanyObservationHost

        old = self.events.read(self.ref) or {}
        digest = stable_digest(self.policy.to_dict())
        require(
            not old.get("policy_digest") or old["policy_digest"] == digest,
            "CUSTOMER_FAST_POLICY_CHANGED",
        )
        start = old.get("through") or self.events.runner.bundle.start_at
        end = old.get("pending_end") or min(
            parsed(now), parsed(start) + timedelta(days=1)
        ).isoformat().replace("+00:00", "Z")
        if parsed(end) <= parsed(start):
            return {"complete": True, "hints": 0}

        def freeze(doc):
            require(
                doc.get("through", self.events.runner.bundle.start_at) == start,
                "CUSTOMER_FAST_WINDOW_CHANGED",
            )
            require(
                not doc.get("pending_end") or doc["pending_end"] == end,
                "CUSTOMER_FAST_WINDOW_CHANGED",
            )
            doc.update(pending_end=end, policy_digest=digest)

        self.events.change(self.ref, freeze, fence)
        count, hint_failures = 0, []
        for account in self.policy.webhook_connector_refs:
            hint_ref = self.ref + "-cursor-" + stable_digest(account)
            prior = self.events.read(hint_ref) or {}
            hint_start = prior.get("through") or self.events.runner.bundle.start_at
            hint_end = prior.get("pending_end") or min(
                parsed(now), parsed(hint_start) + timedelta(days=1)
            ).isoformat().replace("+00:00", "Z")
            if parsed(hint_start) >= parsed(hint_end):
                continue

            def freeze_hint(doc):
                require(
                    doc.get("through", self.events.runner.bundle.start_at) == hint_start,
                    "CUSTOMER_WEBHOOK_WINDOW_CHANGED",
                )
                require(
                    not doc.get("pending_end") or doc["pending_end"] == hint_end,
                    "CUSTOMER_WEBHOOK_WINDOW_CHANGED",
                )
                doc["pending_end"] = hint_end

            self.events.change(hint_ref, freeze_hint, fence)
            try:
                count += self.hints(account, start=hint_start, end=hint_end, fence=fence)
            except (
                TimeoutError,
                ConnectionError,
                OSError,
                TransportError,
                RateLimitedError,
                ServerError,
            ) as error:
                hint_failures.append({"account_ref": account, "error_type": type(error).__name__})
                continue

            def finish_hint(doc):
                require(doc.get("pending_end") == hint_end, "CUSTOMER_WEBHOOK_WINDOW_CHANGED")
                doc.update(through=hint_end, pending_end=None)

            self.events.change(hint_ref, finish_hint, fence)
        # Provider reads, including periodic polling when there was no webhook, own facts.
        host = CompanyObservationHost(
            self.observation.console,
            self.observation.gateway,
            self.observation.executor,
            tuple(
                s
                for s in self.observation.sources
                if s.kind in {"customer_events", "invoice_health"}
            ),
            crm_intake=self.observation.crm_intake,
        )
        result = host.cycle(start=start, end=end, now=now, fence=fence)
        if result["complete"]:

            def finish(doc):
                require(doc.get("pending_end") == end, "CUSTOMER_FAST_WINDOW_CHANGED")
                doc.update(through=end, pending_end=None, last_hint_count=count)

            self.events.change(self.ref, finish, fence)
        return {**result, "hints": count, "hint_failures": hint_failures}

    def report(self):
        return self.events.read(self.ref)
