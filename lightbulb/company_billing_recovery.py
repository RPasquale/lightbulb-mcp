"""Durable invoice observations, overdue work and subsequent payment reporting.

Spring owns journal custody and the connector read. This host composes the
existing signal executor; invoice payment observations do not prove settlement
or that retention work caused a payment.
"""
from __future__ import annotations

import json
from typing import Any

from lightbulb.billing_health import InvoiceHealthObservation, invoice_health_observation, invoice_payment_change, minor_units_to_amount
from lightbulb.company_engine_core import detached, parsed, stable_digest
from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
from lightbulb.company_hosted_scheduler import CheckpointConflict
from lightbulb.company_signal_execution import CompanySignalIntentExecutor, SignalIntentExecutionError


LEDGER_SCHEMA = "lightbulb.company_billing_recovery.v1"
POLL_SCHEMA = "lightbulb.company_billing_poll.v1"
MAX_TRACKED_INVOICES = 1000
MAX_DOCUMENT_BYTES = 512 * 1024


class BillingRecoveryError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise BillingRecoveryError(code)


class CompanyBillingRecovery:
    def __init__(self, runner, gateway, source):
        _require(isinstance(gateway, AuthenticatedCheckpointGateway), "BILLING_AUTHENTICATED_JOURNAL_REQUIRED")
        _require(gateway.bundle_digest == runner.bundle.plan_digest, "BILLING_BUNDLE_MISMATCH")
        _require(source.kind == "invoice_health", "BILLING_SOURCE_REQUIRED")
        self.runner, self.gateway, self.source = runner, gateway, source
        self.binding = {"scope": detached(runner.bundle.scope), "bundle_digest": runner.bundle.plan_digest,
                        "source": source.to_dict()}
        self.binding_digest = stable_digest(self.binding)
        self.ledger_ref = "billing-recovery-" + self.binding_digest
        self.signals = CompanySignalIntentExecutor(runner, gateway)

    def _read(self, ref, schema):
        record = self.gateway.get(ref)
        if record is not None:
            _require(record.get("schema") == schema and record.get("binding") == self.binding,
                     "BILLING_JOURNAL_BINDING_MISMATCH")
        return record

    def _write(self, ref, document, old, fence, *, reserve_bytes=0):
        _require(len(json.dumps(detached(document), ensure_ascii=True).encode("utf-8")) + reserve_bytes <= MAX_DOCUMENT_BYTES,
                 "BILLING_JOURNAL_TOO_LARGE")
        fence()
        return self.gateway.put(ref, document, expected_revision=old["revision"] if old else 0)

    def _observation(self, ref):
        record = self._read(ref, POLL_SCHEMA)
        _require(record is not None, "BILLING_OBSERVATION_MISSING")
        return InvoiceHealthObservation.model_validate(record["observation"])

    def _plan(self, observation, poll_ref, ledger):
        invoices = detached(ledger["invoices"]) if ledger else {}
        if ledger:
            _require(parsed(observation.observed_at) >= parsed(ledger["observed_at"]), "BILLING_OBSERVATION_REGRESSED")
        pending, changes = [], []
        cache: dict[str, Any] = {}
        account = self.source.identity_links[self.source.arguments["customer_id"]]
        for row in observation.rows:
            previous = invoices.get(row.invoice_ref)
            paid_delta = 0
            if previous:
                _require(row.amount_paid_minor >= previous["amount_paid_minor"], "BILLING_PAID_AMOUNT_REGRESSED")
                if previous.get("risk_observed_at"):
                    latest = previous["latest_observation_ref"]
                    if latest not in cache:
                        cache[latest] = self._observation(latest)
                    # The latest snapshot owns monotonicity and same-time
                    # conflict checks, even though payment accounting retains
                    # the older risk baseline below.
                    invoice_payment_change(cache[latest], observation, invoice_ref=row.invoice_ref,
                                           risk_observed_at=previous["risk_observed_at"])
                    ref = previous["risk_observation_ref"]
                    if ref not in cache:
                        cache[ref] = self._observation(ref)
                    change = invoice_payment_change(cache[ref], observation, invoice_ref=row.invoice_ref,
                                                    risk_observed_at=previous["risk_observed_at"])
                    # A partial payment while still open is not yet a paid
                    # invoice. Compare with the original risk baseline, then
                    # deduct the amount already reported by this ledger.
                    paid_delta = max(0, change.observed_payment_minor - previous["observed_payment_minor"])
                    if paid_delta:
                        changes.append({**change.to_dict(), "observed_payment_minor": paid_delta})
            entry = {**(previous or {}), "latest_observation_ref": poll_ref,
                     "status": row.status, "amount_remaining_minor": row.amount_remaining_minor,
                     "amount_paid_minor": row.amount_paid_minor,
                     "observed_payment_minor": (previous or {}).get("observed_payment_minor", 0) + paid_delta}
            overdue = row.days_overdue(observation.observed_at) is not None
            if overdue and not entry.get("risk_observed_at"):
                signal = {"name": "signals.payment_overdue", "producer": "finance_close",
                          "emitted_at": observation.observed_at,
                          "payload": {"invoice_ref": row.invoice_ref, "account_ref": account,
                                      "amount_remaining": str(minor_units_to_amount(row.amount_remaining_minor, observation.currency)),
                                      "currency": observation.currency, "due_at": row.due_at,
                                      "days_overdue": int((parsed(observation.observed_at) - parsed(row.due_at)).total_seconds() // 86400),
                                      "source_digest": observation.observation_digest}}
                entry.update(risk_observed_at=observation.observed_at, risk_observation_ref=poll_ref,
                             risk_signal=signal)
                pending.append({"invoice_ref": row.invoice_ref, "signal": signal})
            invoices[row.invoice_ref] = entry
        _require(len(invoices) <= MAX_TRACKED_INVOICES, "BILLING_INVOICE_CAPACITY")
        return {"schema": LEDGER_SCHEMA, "status": "RUNNING", "binding": self.binding,
                "observed_at": observation.observed_at, "last_poll_ref": poll_ref, "invoices": invoices}, pending, changes

    def ingest(self, request, result, *, identity, now, fence):
        observation = invoice_health_observation(request, result, currency=self.runner.bundle.operating_plan.blueprint.currency, now=now)
        _require(request.tool == self.source.tool and request.connector_account_ref == self.source.connector_account_ref
                 and request.arguments == {**self.source.arguments, "limit": 100}
                 and request.scope.model_dump(mode="json") == {**self.runner.bundle.scope, "actor_ref": self.runner.bundle.actor_ref},
                 "BILLING_REQUEST_BINDING_MISMATCH")
        poll_ref = "billing-poll-" + stable_digest({"binding": self.binding_digest, "identity": identity})
        poll = self._read(poll_ref, POLL_SCHEMA)
        if poll is None:
            ledger = self._read(self.ledger_ref, LEDGER_SCHEMA)
            proposed, pending, changes = self._plan(observation, poll_ref, ledger)
            poll = self._write(poll_ref, {"schema": POLL_SCHEMA, "status": "RUNNING", "binding": self.binding,
                "observation": observation.to_dict(), "phase": "planned", "proposed": proposed,
                "expected_ledger_revision": ledger["revision"] if ledger else 0,
                "pending_signals": pending, "payment_changes": changes}, None, fence, reserve_bytes=2048)
        _require(poll["observation"] == observation.to_dict(), "BILLING_POLL_OBSERVATION_CHANGED")
        if poll["phase"] == "completed":
            return detached(poll["summary"])
        ledger = self._read(self.ledger_ref, LEDGER_SCHEMA)
        if ledger is None or ledger.get("last_poll_ref") != poll_ref:
            _require((ledger["revision"] if ledger else 0) == poll["expected_ledger_revision"],
                     "BILLING_LEDGER_CHANGED")
            for pending in poll["pending_signals"]:
                try:
                    self.signals.enqueue(pending["signal"], now=now, fence=fence)
                except SignalIntentExecutionError as exc:
                    if exc.code != "SIGNAL_QUEUE_FULL":
                        raise
                    # A full queue must still drain accepted work while intake
                    # holds its window; never drop this original signal.
                    self.signals.drain(now=now, fence=fence)
                    self.signals.enqueue(pending["signal"], now=now, fence=fence)
            try:
                ledger = self._write(self.ledger_ref, poll["proposed"], ledger, fence)
            except CheckpointConflict:
                ledger = self._read(self.ledger_ref, LEDGER_SCHEMA)
                if ledger is None or ledger.get("last_poll_ref") != poll_ref:
                    raise
        _require(all(ledger.get(key) == value for key, value in poll["proposed"].items()),
                 "BILLING_LEDGER_CONTENT_MISMATCH")
        summary = {"kind": "invoice_health", "source_ref": self.source.source_ref,
                   "ledger_ref": self.ledger_ref, "poll_ref": poll_ref,
                   "observed_at": observation.observed_at, "invoice_count": len(observation.rows),
                   "signals_queued": len(poll["pending_signals"]),
                   "observed_payment_minor": sum(change["observed_payment_minor"] for change in poll["payment_changes"]),
                   "currency": observation.currency, "revenue_verified": False, "settlement_verified": False}
        self._write(poll_ref, {**poll, "phase": "completed", "status": "COMPLETED", "summary": summary}, poll, fence)
        return summary

    def invoice_snapshot(self, invoice_ref):
        """Return the authenticated latest page, including explicit invoice absence.

        The retained per-invoice ledger may outlive a page that omits it. A
        follow-up must inspect this current page, never infer unpaid status
        from that older ledger row. This accessor grants no send authority.
        """
        ledger = self._read(self.ledger_ref, LEDGER_SCHEMA)
        if ledger is None:
            return None
        observation = self._observation(ledger["last_poll_ref"])
        row = observation.row(invoice_ref)
        tracked = ledger["invoices"].get(invoice_ref)
        if row is not None:
            _require(tracked is not None and tracked["latest_observation_ref"] == ledger["last_poll_ref"]
                     and all(tracked[key] == getattr(row, key) for key in
                             ("status", "amount_paid_minor", "amount_remaining_minor")),
                     "BILLING_LEDGER_CONTENT_MISMATCH")
        configured = self.binding["source"]
        customer = configured["arguments"]["customer_id"]
        return {"binding_digest": self.binding_digest, "ledger_ref": self.ledger_ref,
                "ledger_revision": ledger["revision"], "source_ref": configured["source_ref"],
                "connector_account_ref": configured["connector_account_ref"],
                "customer_ref": customer, "account_ref": configured["identity_links"][customer],
                "invoice_ref": invoice_ref, "present": row is not None,
                "observation": observation.to_dict(), "invoice": None if row is None else row.to_dict(),
                "risk_observed_at": (tracked or {}).get("risk_observed_at")}

    def report(self):
        ledger = self._read(self.ledger_ref, LEDGER_SCHEMA)
        if ledger is None:
            return {"source_ref": self.source.source_ref, "status": "not_observed", "revenue_verified": False}
        invoices = ledger["invoices"]
        return {"source_ref": self.source.source_ref, "status": "observed", "ledger_ref": self.ledger_ref,
                "observed_at": ledger["observed_at"], "tracked_invoice_count": len(invoices),
                "previously_overdue_invoice_count": sum(bool(row.get("risk_observed_at")) for row in invoices.values()),
                "observed_payment_minor": sum(row["observed_payment_minor"] for row in invoices.values()),
                "currency": self.runner.bundle.operating_plan.blueprint.currency,
                "revenue_verified": False, "settlement_verified": False}


__all__ = ["BillingRecoveryError", "CompanyBillingRecovery"]
