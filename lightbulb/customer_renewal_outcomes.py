"""Retained subscription evidence joins the original renewal case to a paid invoice."""

from lightbulb.company_engine_core import parsed, stable_digest
from lightbulb.company_customer_events import require


def verified_renewal_outcome(lifecycle, row, first, *, now):
    from lightbulb.retention_chain import hand_off_receipt
    from lightbulb.company_billing_recovery import CompanyBillingRecovery
    from lightbulb.billing_health import minor_units_to_amount

    host = lifecycle.sales
    runtime = host.runner.runtimes.get("retention_chain")
    require(runtime is not None, "CUSTOMER_RETENTION_RUNTIME_REQUIRED")
    state = host.intake._scoped_state(runtime, row.retention_case_ref)
    binding = host.progression.binding(row.binding_ref)
    require(state.ledger.account_ref == binding.account_ref, "CUSTOMER_RENEWAL_ACCOUNT_MISMATCH")
    if state.status not in {"renewed", "expanded"}:
        return None
    hand_off_receipt(state, source_plan=runtime.plan)
    completed = first["effect"]["completed_at"]
    if not parsed(completed) <= parsed(state.ledger.decided_at) <= parsed(now):
        return None
    matches = []
    for source in host.sources:
        if (
            source.kind != "invoice_health"
            or binding.account_ref not in source.identity_links.values()
        ):
            continue
        snapshot = CompanyBillingRecovery(host.runner, host.gateway, source).invoice_snapshot(
            row.renewal_invoice_ref
        )
        if not snapshot or not snapshot["present"] or snapshot["invoice"]["status"] != "paid":
            continue
        invoice = snapshot["invoice"]
        if parsed(invoice["paid_at"]) != parsed(state.ledger.decided_at):
            continue
        if (
            invoice["currency"] != runtime.plan.currency
            or minor_units_to_amount(invoice["amount_paid_minor"], invoice["currency"])
            < state.ledger.outcome_amount
        ):
            continue
        provider = stable_digest(
            {
                "invoice": row.renewal_invoice_ref,
                "kind": "invoice_paid",
                "amount_paid": invoice["amount_paid_minor"],
                "remaining": invoice["amount_remaining_minor"],
                "occurred_at": invoice["paid_at"],
            }
        )
        event_ref = (
            lifecycle.events.prefix
            + "-event-"
            + stable_digest(
                {"tool": source.tool, "connector": source.connector_account_ref, "event": provider}
            )
        )
        event = lifecycle.events.read(event_ref)
        if event and event["proof"].get("invoice_ref") == row.renewal_invoice_ref:
            matches.append((event_ref, event))
    require(len(matches) <= 1, "CUSTOMER_RENEWAL_INVOICE_AMBIGUOUS")
    if not matches:
        return None
    event_ref, event = matches[0]
    return {
        "kind": "subscription_retained",
        "observed_at": state.ledger.decided_at,
        "event_ref": event_ref,
        "evidence_digest": stable_digest(
            {"retention_state_digest": state.state_digest, "invoice_event": event["event"]}
        ),
        "effect_digest": stable_digest(first["effect"]),
        "basis": "observed_after_intervention",
        "causal_uplift_verified": False,
    }


def record_renewal_risk(lifecycle, row, trigger, *, now, fence):
    """Persist a conservative inactivity assessment through the existing retention engine."""
    host = lifecycle.sales
    runtime = host.runner.runtimes["retention_chain"]
    state = host.intake._scoped_state(runtime, row.retention_case_ref)
    binding = host.progression.binding(row.binding_ref)
    require(state.ledger.account_ref == binding.account_ref, "CUSTOMER_RENEWAL_ACCOUNT_MISMATCH")
    if state.status != "renewal_due":
        return
    identity = "customer-risk-" + stable_digest(
        {"enrollment": row.enrollment_ref, "event": trigger["event_journal_ref"]}
    )
    evidence = {
        "trigger": trigger,
        "account": lifecycle.events.account(binding.account_ref),
        "source_coverage": [
            lifecycle.events.read(lifecycle.events.prefix + "-source-" + stable_digest(ref))
            for ref in row.required_source_refs
        ],
    }
    command = runtime.command(
        state,
        event="mark_at_risk",
        transition_ref=identity,
        idempotency_key=identity,
        occurred_at=now,
        actor_ref=host.runner.bundle.actor_ref,
        receipt={
            "inactive_days": row.renewal_inactivity_days,
            "mrr_at_risk": str(runtime.plan.tiers[state.ledger.plan_ref]),
            "snapshot_digest": stable_digest(evidence),
            "evidence_refs": [trigger["event_journal_ref"]],
        },
    )
    fence()
    outcome = runtime.advance_and_persist(row.retention_case_ref, command)
    require(outcome.persisted, "CUSTOMER_RENEWAL_RISK_REFUSED")
