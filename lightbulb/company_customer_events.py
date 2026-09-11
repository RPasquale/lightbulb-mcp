"""Verified customer events on the existing authenticated company journal."""

from __future__ import annotations
from typing import Literal
from pydantic import Field, field_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    detached,
    stable_digest,
    parsed,
    timestamp,
)
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway, HostAuthorityError
from lightbulb.company_hosted_scheduler import CheckpointConflict
from lightbulb.company_execution_bridge import execution_receipt_from_connector
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult

CustomerEventKind = Literal[
    "signed_up",
    "activated",
    "product_used",
    "capacity_reached",
    "upgrade_requested",
    "expanded",
    "demo_requested",
    "inquiry_received",
    "referral_claimed",
    "renewal_due",
    "invoice_overdue",
    "invoice_paid",
]


class CustomerEventError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise CustomerEventError(code)


class CustomerEvent(StrictModel):
    event_ref: Sha256Digest
    account_ref: OpaqueRef
    kind: CustomerEventKind
    occurred_at: str
    source_ref: OpaqueRef
    provider_event_digest: Sha256Digest
    identity_digest: Sha256Digest
    amount_minor: int | None = Field(default=None, ge=0, le=9007199254740991, strict=True)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")

    @field_validator("occurred_at")
    @classmethod
    def at(cls, value):
        return timestamp(value, field_name="occurred_at")


class CustomerEventMapping(StrictModel):
    kind: CustomerEventKind

    @field_validator("kind")
    @classmethod
    def product_kind(cls, value):
        require(
            value not in {"invoice_paid", "invoice_overdue"},
            "CUSTOMER_EVENT_BILLING_SOURCE_REQUIRED",
        )
        return value


class CompanyCustomerEvents:
    """Receipt-backed intake; mappings are host configuration, never inferred identity."""

    def __init__(self, runner, gateway):
        if not isinstance(gateway, AuthenticatedCheckpointGateway):
            raise HostAuthorityError("AUTHENTICATED_HOST_JOURNAL_REQUIRED")
        require(
            gateway.bundle_digest == runner.bundle.plan_digest, "CUSTOMER_EVENT_BUNDLE_MISMATCH"
        )
        self.runner, self.gateway = runner, gateway
        self.prefix = "customer-events-" + stable_digest(
            {"scope": runner.bundle.scope, "bundle": runner.bundle.plan_digest}
        )

    def read(self, ref):
        row = self.gateway.get(ref)
        if row is not None:
            if (
                row.get("schema") != "lightbulb.customer_events.v1"
                or row.get("bundle_digest") != self.runner.bundle.plan_digest
                or row.get("scope") != self.runner.bundle.scope
            ):
                raise HostAuthorityError("CUSTOMER_EVENT_SCOPE_MISMATCH")
        return row

    def change(self, ref, mutate, fence):
        import json

        for _ in range(3):
            old = self.read(ref)
            doc = detached(old or {})
            doc.update(
                schema="lightbulb.customer_events.v1",
                bundle_digest=self.runner.bundle.plan_digest,
                scope=dict(self.runner.bundle.scope),
                status="COMPLETED",
                resume_at=None,
            )
            mutate(doc)
            require(len(json.dumps(doc).encode()) < 400000, "CUSTOMER_EVENT_CAPACITY")
            fence()
            try:
                return self.gateway.put(ref, doc, expected_revision=old["revision"] if old else 0)
            except CheckpointConflict:
                continue
        raise CheckpointConflict("Customer event journal changed; replay original source")

    def _retain(self, event, proof, fence):
        event = CustomerEvent.model_validate(event)
        ref = self.prefix + "-event-" + event.event_ref

        def retain(doc):
            require(
                not doc.get("event") or doc["event"] == event.to_dict(), "CUSTOMER_EVENT_CONFLICT"
            )
            # A repeat read may have a new receipt; retain the original exact source proof.
            if "event" not in doc:
                doc.update(event=event.to_dict(), proof=proof)

        self.change(ref, retain, fence)
        account_key = stable_digest(event.account_ref)

        def index(doc):
            accounts = dict(doc.get("accounts", {}))
            require(account_key in accounts or len(accounts) < 512, "CUSTOMER_ACCOUNT_CAPACITY")
            accounts[account_key] = event.account_ref
            doc["accounts"] = accounts

        self.change(self.prefix, index, fence)

        def fold(doc):
            kinds = dict(doc.get("kinds", {}))
            previous = kinds.get(event.kind)
            if not previous or (parsed(event.occurred_at), event.event_ref) > (
                parsed(previous["event"]["occurred_at"]),
                previous["event"]["event_ref"],
            ):
                kinds[event.kind] = {"event": event.to_dict(), "event_journal_ref": ref}
            doc.update(account_ref=event.account_ref, kinds=kinds)

        self.change(self.prefix + "-account-" + account_key, fold, fence)
        return event

    def _receipt(self, source, request, result, now):
        request = ConnectorExecutionRequest.model_validate(detached(request))
        result = ConnectorExecutionResult.model_validate(detached(result))
        receipt = execution_receipt_from_connector(result, request)
        require(
            request.tool == source.tool
            and request.connector_account_ref == source.connector_account_ref
            and request.scope.model_dump(mode="json")
            == {**self.runner.bundle.scope, "actor_ref": self.runner.bundle.actor_ref}
            and receipt.connector_account_ref == request.connector_account_ref
            and receipt.project_id == str(request.scope.project_id)
            and receipt.effect == "read"
            and not request.preview_only,
            "CUSTOMER_EVENT_SOURCE_MISMATCH",
        )
        require(
            receipt.receipt_digest != "0" * 64
            and receipt.route_digest != "0" * 64
            and parsed(receipt.completed_at) <= parsed(now),
            "CUSTOMER_EVENT_RECEIPT_INVALID",
        )
        return request, result, receipt

    def validate_source_revision(self, source):
        old = self.read(self.prefix + "-source-" + stable_digest(source.source_ref))
        if old is None:
            return None
        if old.get("source_definition") is None:
            require(
                old["binding_digest"] == stable_digest(source.to_dict()),
                "CUSTOMER_EVENT_MAPPING_CHANGED",
            )
            return old
        previous = old["source_definition"]
        current = source.to_dict()
        require(
            {k: v for k, v in previous.items() if k != "identity_links"}
            == {k: v for k, v in current.items() if k != "identity_links"},
            "CUSTOMER_EVENT_SOURCE_CHANGED",
        )
        require(
            all(
                current["identity_links"].get(k) == v for k, v in previous["identity_links"].items()
            ),
            "CUSTOMER_EVENT_IDENTITY_REASSIGNMENT",
        )
        return old

    def ingest_posthog(self, source, request, result, *, now, fence):
        from hashlib import sha256

        self.validate_source_revision(source)
        request, result, receipt = self._receipt(source, request, result, now)
        output = dict(result.output)
        require(
            source.tool == "posthog.query_events"
            and output.get("schema") == "lightbulb.posthog_event_page.v1",
            "CUSTOMER_EVENT_SOURCE_UNSUPPORTED",
        )
        require(
            output.get("project_id_sha256")
            == sha256(str(request.arguments["project_id"]).encode()).hexdigest()
            and output.get("event") == request.arguments["event"]
            and parsed(output["after"]) == parsed(request.arguments["after"])
            and parsed(output["before"]) == parsed(request.arguments["before"])
            and parsed(output["before"]) <= parsed(receipt.completed_at),
            "CUSTOMER_EVENT_WINDOW_MISMATCH",
        )
        rows = output.get("events")
        require(
            isinstance(rows, list)
            and len(rows) <= 100
            and type(output.get("record_count")) is int
            and output["record_count"] == len(rows)
            and type(output.get("has_more")) is bool,
            "CUSTOMER_EVENT_PAGE_INVALID",
        )
        mapping = CustomerEventMapping.model_validate(
            source.event_bindings[request.arguments["event"]]
        )
        ingested, unmapped = [], []
        for row in rows:
            require(
                row.get("event") == request.arguments["event"]
                and parsed(output["after"]) <= parsed(row["timestamp"]) < parsed(output["before"]),
                "CUSTOMER_EVENT_ROW_MISMATCH",
            )
            identity, provider = row.get("distinct_id_sha256"), row.get("uuid_sha256")
            require(
                all(
                    isinstance(v, str) and len(v) == 64 and set(v) <= set("0123456789abcdef")
                    for v in (identity, provider)
                ),
                "CUSTOMER_EVENT_STABLE_ID_REQUIRED",
            )
            account = source.identity_links.get(identity)
            if not account:
                unmapped.append(identity)
                continue
            event_ref = stable_digest(
                {
                    "tool": source.tool,
                    "connector": source.connector_account_ref,
                    "project": output["project_id_sha256"],
                    "event": provider,
                }
            )
            event = CustomerEvent(
                event_ref=event_ref,
                account_ref=account,
                kind=mapping.kind,
                occurred_at=row["timestamp"],
                source_ref=source.source_ref,
                provider_event_digest=provider,
                identity_digest=identity,
            )
            proof = {
                "receipt": receipt.to_dict(),
                "row_digest": stable_digest(row),
                "binding_digest": stable_digest(source.to_dict()),
            }
            self._retain(event, proof, fence)
            ingested.append(event.event_ref)
        return {
            "event_refs": sorted(set(ingested)),
            "unmapped_identities": sorted(set(unmapped)),
            "has_more": output["has_more"],
            "next_cursor": output.get("next_cursor"),
        }

    def complete_window(self, source, *, start, end, unmatched, fence):
        ref = self.prefix + "-source-" + stable_digest(source.source_ref)
        self.validate_source_revision(source)

        def complete(doc):
            binding = stable_digest(source.to_dict())
            previous = doc.get("source_definition")
            if previous:
                require(
                    {k: v for k, v in previous.items() if k != "identity_links"}
                    == {k: v for k, v in source.to_dict().items() if k != "identity_links"},
                    "CUSTOMER_EVENT_SOURCE_CHANGED",
                )
                require(
                    all(
                        source.identity_links.get(k) == v
                        for k, v in previous["identity_links"].items()
                    ),
                    "CUSTOMER_EVENT_IDENTITY_REASSIGNMENT",
                )
            mapping_changed = bool(doc.get("binding_digest") and doc["binding_digest"] != binding)
            covered_from, through = start, end
            if not mapping_changed and doc.get("through"):
                before = doc.get("covered_from", doc["window_start"])
                if parsed(end) < parsed(before):
                    return
                if parsed(start) <= parsed(doc["through"]):
                    covered_from = min((start, before), key=parsed)
                    through = max((end, doc["through"]), key=parsed)
            doc.update(
                source_definition=source.to_dict(),
                source_ref=source.source_ref,
                binding_digest=binding,
                through=through,
                window_start=start,
                covered_from=covered_from,
                unmapped_identities=sorted(set(unmatched)),
            )

        return self.change(ref, complete, fence)

    def account(self, account_ref):
        return self.read(self.prefix + "-account-" + stable_digest(account_ref))

    def report(self):
        index = self.read(self.prefix) or {}
        return {
            "accounts": [self.account(ref) for ref in index.get("accounts", {}).values()],
            "execution_authorized": False,
        }

    def ingest_invoices(self, source, request, result, *, now, fence):
        from lightbulb.billing_health import invoice_health_observation

        request, result, receipt = self._receipt(source, request, result, now)
        observation = invoice_health_observation(
            request, result, currency=self.runner.bundle.operating_plan.blueprint.currency, now=now
        )
        customer = request.arguments["customer_id"]
        account = source.identity_links[customer]
        retained = []
        for row in observation.rows:
            kind = (
                "invoice_paid"
                if row.status == "paid"
                else (
                    "invoice_overdue"
                    if row.days_overdue(observation.observed_at) is not None
                    else None
                )
            )
            if kind is None:
                continue
            occurred = row.paid_at if kind == "invoice_paid" else row.due_at
            provider = stable_digest(
                {
                    "invoice": row.invoice_ref,
                    "kind": kind,
                    "amount_paid": row.amount_paid_minor,
                    "remaining": row.amount_remaining_minor,
                    "occurred_at": occurred,
                }
            )
            event = CustomerEvent(
                event_ref=stable_digest(
                    {
                        "tool": source.tool,
                        "connector": source.connector_account_ref,
                        "event": provider,
                    }
                ),
                account_ref=account,
                kind=kind,
                occurred_at=occurred,
                source_ref=source.source_ref,
                provider_event_digest=provider,
                identity_digest=stable_digest(customer),
                amount_minor=(
                    row.amount_paid_minor if kind == "invoice_paid" else row.amount_remaining_minor
                ),
                currency=row.currency,
            )
            self._retain(
                event,
                {
                    "receipt": receipt.to_dict(),
                    "invoice_ref": row.invoice_ref,
                    "observation_digest": observation.observation_digest,
                    "binding_digest": stable_digest(source.to_dict()),
                },
                fence,
            )
            retained.append(event.event_ref)
        return retained
