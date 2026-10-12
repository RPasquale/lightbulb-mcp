"""Sync: fresh provider reads advance the persisted chains through their own receipts, week after week.

Adoption replays the current cycle once.  A subscription then needs its
next invoice issued, its payment applied, its cash settled, and its
revenue recognised; a bill paid at the provider needs someone to notice.
``plan_sync`` is pure: from fresh reads (a Stripe invoice page, a Stripe
charge page, cash settlement observations) and the persisted states it is
handed (subscription cases, payable cases, closed finance periods) it lists,
per entity, the exact next transitions the chain's own receipts admit:

* ``issue_invoice`` when the page carries a later billing cycle for a
  subscribed or recognised case;
* ``apply_payment`` when the case's current invoice now reads paid;
* ``fail_payment`` when it reads open and the charge page carries the
  failed charge that names the decline code;
* ``settle_cash`` when a settlement observation names the case's invoice
  (or the platform correlation its issuance recorded) and its reversal
  window has elapsed; or, for a case whose charges carry no platform
  correlation (an adopted one), when a fresh ``stripe.list_subscription_invoices``
  read shows the paying charge neither refunded nor disputed and a
  ``stripe.list_payouts`` read shows the paid automatic payout that swept
  it, a reversal window before that invoice read;
* ``recognize_revenue`` when a closed finance period that reconciled the
  revenue subledger covers the settlement.

Rows for accounts and bills the store does not hold become an adoption
plan; what the reads show that no chain transition can honestly absorb (a
bill paid at the provider while the case still awaits approval, an
invoice voided) is reported as a discrepancy for a human.  ``run_sync``
applies the plan through the console's runtimes, each step a real
persisted transition, then adopts the newcomers.  Nothing here invents a
fact, fabricates an approval, or touches a provider.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

SYNC_PLAN_SCHEMA = "lightbulb.company_sync_plan.v1"
SYNC_REPORT_SCHEMA = "lightbulb.company_sync_report.v1"
SYNC_SOURCE_KINDS: tuple[str, ...] = ("stripe_invoices", "stripe_charges", "stripe_settlements", "stripe_payouts", "ledger_bills")
SyncSourceKind = Literal["stripe_invoices", "stripe_charges", "stripe_settlements", "stripe_payouts", "ledger_bills"]
# A payout settlement that is only early: the next read settles it, so it is a note, not a discrepancy.
_PAYOUT_WAITING = frozenset({"FUNDS_PENDING", "PAYOUT_NOT_FOUND", "PAYOUT_PENDING", "REVERSAL_WINDOW_NOT_OBSERVED"})
SETTLEMENT_TOOL = "stripe.observe_cash_settlement"
_MAX_TEXT = 200


class SyncError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SyncError(code, message)


def _text(value: Any) -> str:
    return str(value)[:_MAX_TEXT]


class SyncStep(StrictModel):
    entity_ref: OpaqueRef
    engine: ShortText
    event: ShortText
    at: str
    source_ref: ShortText
    receipt: dict[str, Any]

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")


class SyncDiscrepancy(StrictModel):
    engine: ShortText
    entity_ref: OpaqueRef
    kind: ShortText
    detail: ShortText


class SyncPlan(StrictModel):
    schema_id: str = Field(default=SYNC_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    steps: tuple[SyncStep, ...] = Field(default_factory=tuple, max_length=4000)
    adoption: dict[str, Any] | None = None
    discrepancies: tuple[SyncDiscrepancy, ...] = Field(default_factory=tuple, max_length=2000)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=2000)
    entities: int = Field(ge=0)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=64)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("steps", "discrepancies", "notes", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SyncPlan":
        if self.entities != len({(item.engine, item.entity_ref) for item in self.steps}):
            raise ValueError("entities must count the distinct entities the steps advance")
        if not skip_digests(info) and self.plan_digest != sealed_digest(SyncPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def by_entity(self) -> dict[tuple[str, str], list[SyncStep]]:
        out: dict[tuple[str, str], list[SyncStep]] = {}
        for step in self.steps:
            out.setdefault((step.engine, step.entity_ref), []).append(step)
        return out

    def render(self) -> str:
        adopted = 0 if self.adoption is None else int(self.adoption.get("entities", 0))
        lines = [f"**Sync plan {self.company_ref}** as of {self.as_of[:10]}: {self.entities} entity(ies) advance over {len(self.steps)} step(s), {adopted} newcomer(s) adopt, {len(self.discrepancies)} discrepancy(ies)."]
        for (engine, entity_ref), steps in self.by_entity().items():
            lines.append(f"- {engine} {entity_ref}: {' -> '.join(step.event for step in steps)}")
        for item in self.discrepancies:
            lines.append(f"- discrepancy ({item.engine} {item.entity_ref}): {item.detail}")
        lines.extend(f"- {note}" for note in self.notes)
        return "\n".join(lines)


def _sources_by_kind(sources: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {kind: [] for kind in SYNC_SOURCE_KINDS}
    for source in sources:
        raw = dict(detached(source))
        kind = str(raw.get("kind", ""))
        _require(kind in SYNC_SOURCE_KINDS, "SOURCE_KIND_UNKNOWN", f"{kind or 'untyped'} is not one of {SYNC_SOURCE_KINDS}")
        _require(raw.get("provenance") is not None and raw.get("payload") is not None, "SOURCE_NOT_SEALED", f"a {kind} source carries its provenance and the exact payload")
        out[kind].append(raw)
    return out


def plan_sync(*, company_ref: str, currency: str, as_of: str, sources: Sequence[Mapping[str, Any]], subscription_states: Sequence[tuple[Any, Any]] = (), payable_states: Sequence[tuple[Any, Any]] = (), close_states: Sequence[tuple[Any, Any]] = (), saas_plan: Any = None, subscription_plan: Any = None, payables_plan: Any = None) -> SyncPlan:
    """The sealed sync plan: next transitions for persisted cases, an adoption plan for newcomers, and discrepancies for a human."""

    from lightbulb.company_adoption import plan_adoption
    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE, ledger_bill_rows
    from lightbulb.subscription_chain import (
        SUBSCRIPTION_INVOICE_TOOL,
        BillingRow,
        ChargeRow,
        SUBSCRIPTION_CHAIN_LIFECYCLE,
        billing_rows,
        charge_rows,
        failure_receipt,
        invoice_correlations,
        invoice_receipt,
        payment_receipt,
        payout_settlement_receipt,
        recognition_receipt,
        settlement_receipt,
    )

    at = timestamp(as_of, field_name="as_of")
    by_kind = _sources_by_kind(sources)
    _require(any(by_kind.values()), "SOURCES_MISSING", "sync needs at least one provider read")
    steps: list[dict[str, Any]] = []
    discrepancies: list[dict[str, Any]] = []
    notes: list[str] = []
    digests: list[str] = []
    for kind in SYNC_SOURCE_KINDS:
        for source in by_kind[kind]:
            digests.append(str(dict(detached(source["provenance"])).get("provenance_digest") or stable_digest(detached(source["provenance"]))))

    cases: dict[str, tuple[Any, Any]] = {}
    for plan_doc, state_doc in subscription_states:
        plan, state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        if state.ledger.account_ref:
            cases[str(state.ledger.account_ref)] = (plan, state)
    closes = []
    for plan_doc, state_doc in close_states:
        plan, state = CLOSE_LIFECYCLE.bind(plan_doc, state_doc)
        if state.status == "closed":
            closes.append((plan, state))
    charges: dict[str, list[ChargeRow]] = {}
    for source in by_kind["stripe_charges"]:
        for row in charge_rows(source["provenance"], source["payload"], currency=currency):
            charge = ChargeRow.model_validate(row)
            if charge.invoice_ref:
                charges.setdefault(str(charge.invoice_ref), []).append(charge)
    settlements: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for source in by_kind["stripe_settlements"]:
        payload = source["payload"]
        rows = payload if isinstance(payload, list) else [payload]
        for observation in rows:
            settlements.append((dict(detached(observation)), dict(detached(source["provenance"]))))
    payout_pages = [(dict(detached(source["provenance"])), source["payload"]) for source in by_kind["stripe_payouts"]]
    charged: dict[str, BillingRow] = {}  # invoice_ref -> the latest subscription-invoice row, which carries the paying charge
    projected: dict[str, str] = {}  # entity_ref -> status after the steps planned so far
    last_at: dict[str, str] = {}  # entity_ref -> when the last step planned for it happens

    settled_when: dict[str, str] = {}

    def advance(state: Any, event: str, receipt: Mapping[str, Any], source_ref: str, to_status: str, *, when: str | None = None) -> None:
        # a step never precedes one already planned for the same case (a payment applied by this sync, say)
        step_at = max(when or at, last_at.get(state.scope.entity_ref, when or at), key=parsed)
        steps.append({"entity_ref": state.scope.entity_ref, "engine": "subscription_chain", "event": event, "at": step_at, "source_ref": source_ref, "receipt": dict(receipt)})
        projected[state.scope.entity_ref] = to_status
        last_at[state.scope.entity_ref] = step_at
        if event == "settle_cash":
            settled_when[state.scope.entity_ref] = step_at

    def status_of(state: Any) -> str:
        return projected.get(state.scope.entity_ref, state.status)

    seen_accounts: set[str] = set()
    for source in by_kind["stripe_invoices"]:
        rows = [BillingRow.model_validate(row) for row in billing_rows(source["provenance"], source["payload"], currency=currency)]
        for row in rows:
            known = charged.get(row.invoice_ref)
            if row.source_tool == SUBSCRIPTION_INVOICE_TOOL and (known is None or parsed(row.source_provenance.completed_at) > parsed(known.source_provenance.completed_at)):
                charged[row.invoice_ref] = row
        for row in sorted(rows, key=lambda item: (parsed(item.period_start), item.invoice_ref)):
            seen_accounts.add(row.account_ref)
            found = cases.get(row.account_ref)
            if found is None:
                continue
            plan, state = found
            status = status_of(state)
            ledger = state.ledger
            billed = set(ledger.billed_invoice_refs or ())
            if row.invoice_ref == ledger.invoice_ref or row.invoice_ref in billed:
                if status == "invoiced" and row.status == "paid" and row.paid_at is not None and row.amount_paid > 0:
                    try:
                        advance(state, "apply_payment", payment_receipt(row), row.invoice_ref, "paid")
                    except ValueError as exc:
                        discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "payment_not_admissible", "detail": _text(exc)})
                elif status == "invoiced" and row.status == "open" and charges.get(row.invoice_ref):
                    failed = [charge for charge in charges[row.invoice_ref] if charge.status == "failed"]
                    if failed:
                        try:
                            advance(state, "fail_payment", failure_receipt(row, failed[-1]), failed[-1].charge_ref, "payment_failed")
                        except ValueError as exc:
                            discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "failure_not_admissible", "detail": _text(exc)})
                elif row.status in ("void", "uncollectible") and status in ("invoiced", "payment_failed", "retry_scheduled", "outreach_sent"):
                    discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "invoice_voided", "detail": _text(f"invoice {row.invoice_ref} reads {row.status} at the provider while the case is {status}; write it off or require reconciliation")})
                continue
            if status in ("subscribed", "revenue_recognized") and ledger.period_end is not None and parsed(row.period_start) >= parsed(str(ledger.period_end)) and row.status in ("open", "paid"):
                try:
                    advance(state, "issue_invoice", invoice_receipt(row), row.invoice_ref, "invoiced")
                except ValueError as exc:
                    discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "invoice_not_admissible", "detail": _text(exc)})
                    continue
                if row.status == "paid" and row.paid_at is not None and row.amount_paid > 0:
                    advance(state, "apply_payment", payment_receipt(row), row.invoice_ref, "paid")
            elif status == "subscribed" and ledger.period_end is None and row.status in ("open", "paid"):
                advance(state, "issue_invoice", invoice_receipt(row), row.invoice_ref, "invoiced")
                if row.status == "paid" and row.paid_at is not None and row.amount_paid > 0:
                    advance(state, "apply_payment", payment_receipt(row), row.invoice_ref, "paid")
            elif status in ("paid", "cash_settled", "payment_failed", "retry_scheduled", "outreach_sent", "recovered") and ledger.period_end is not None and parsed(row.period_start) >= parsed(str(ledger.period_end)):
                notes.append(_text(f"{state.scope.entity_ref}: invoice {row.invoice_ref} starts a new cycle but the case is {status}; the current cycle settles and recognises first"))
    for account_ref, (plan, state) in cases.items():
        if status_of(state) in ("paid", "recovered"):
            correlated = False
            for observation, provenance in settlements:
                if observation.get("invoice_correlation_sha256") not in invoice_correlations(state.ledger):
                    continue
                correlated = True
                settle_at = str(provenance.get("completed_at") or at)  # cash settles when the read that proves it completed, so a close that ends before now can still cover it
                if parsed(settle_at) > parsed(at):
                    discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "settlement_from_future", "detail": _text(f"the settlement read completed {settle_at}, after the sync")})
                    break
                try:
                    advance(state, "settle_cash", settlement_receipt(observation, currency=currency, provenance=provenance), str(observation.get("balance_transaction_ref") or observation.get("payout_ref") or "settlement"), "cash_settled", when=settle_at)
                except ValueError as exc:
                    discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "settlement_not_admissible", "detail": _text(exc)})
                break
            row = charged.get(str(state.ledger.invoice_ref))
            if not correlated and row is not None and payout_pages:
                refused: list[ValueError] = []
                for payout_provenance, payout_page in payout_pages:
                    try:
                        receipt = payout_settlement_receipt(row, payout_provenance, payout_page, reversal_window_days=plan.min_reversal_window_days)
                    except ValueError as exc:
                        refused.append(exc)
                        continue
                    settle_at = str(receipt["settlement_source"]["observed_at"])
                    if parsed(settle_at) > parsed(at):
                        discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "settlement_from_future", "detail": _text(f"the settlement reads completed {settle_at}, after the sync")})
                    else:
                        advance(state, "settle_cash", receipt, str(receipt["settlement_source"]["balance_transaction_ref"]), "cash_settled", when=settle_at)
                    break
                else:
                    blocking = [exc for exc in refused if getattr(exc, "code", "") not in _PAYOUT_WAITING]
                    waiting = [exc for exc in refused if getattr(exc, "code", "") != "PAYOUT_NOT_FOUND"] or refused
                    if blocking:
                        discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "settlement_not_admissible", "detail": _text(blocking[0])})
                    elif waiting:
                        notes.append(_text(f"{state.scope.entity_ref}: not settled yet: {waiting[0]}"))
        if status_of(state) == "cash_settled":
            settled_at = settled_when.get(state.scope.entity_ref) or str(state.ledger.settled_at or at)
            covering = [(close_plan, close) for close_plan, close in closes if parsed(str(close.ledger.period_end)) >= parsed(settled_at) and "revenue_subledger" in list(getattr(close.ledger, "reconciled_accounts", ()) or ())]
            if covering:
                close_plan, close = min(covering, key=lambda row: str(row[1].ledger.period_end))
                try:
                    advance(state, "recognize_revenue", recognition_receipt(close, source_plan=close_plan), str(close.scope.entity_ref), "revenue_recognized")
                except ValueError as exc:
                    discrepancies.append({"engine": "subscription_chain", "entity_ref": state.scope.entity_ref, "kind": "recognition_not_admissible", "detail": _text(exc)})
        if by_kind["stripe_invoices"] and account_ref not in seen_accounts:
            notes.append(_text(f"{state.scope.entity_ref}: no invoice for {account_ref} on the page(s) read"))

    bills: dict[str, tuple[Any, Any]] = {}
    for plan_doc, state_doc in payable_states:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
        if str(state.ledger.bill_ref or "").startswith("ledger:"):
            bills[str(state.ledger.bill_ref)[len("ledger:"):]] = (plan, state)
    for source in by_kind["ledger_bills"]:
        for row in ledger_bill_rows(source["payload"]):
            found = bills.get(row["bill_ref"])
            if found is None:
                continue
            plan, state = found
            outstanding = str(row.get("outstanding") or "")
            if state.status in ("bill_received", "approved", "scheduled") and outstanding and float(outstanding) <= 0:
                discrepancies.append({"engine": "payables_chain", "entity_ref": state.scope.entity_ref, "kind": "paid_at_provider", "detail": _text(f"bill {row['bill_ref']} reads paid at the provider while the case is {state.status}; a payment is applied only to a scheduled bill, so approve and schedule it or reconcile it")})

    adoption = None
    adoptable = [source for kind in ("stripe_invoices", "ledger_bills") for source in by_kind[kind]]
    if adoptable and (saas_plan is not None or payables_plan is not None):
        try:
            plan = plan_adoption(company_ref=company_ref, currency=currency, as_of=at, sources=adoptable, saas_plan=saas_plan, subscription_plan=subscription_plan, payables_plan=payables_plan)
        except ValueError as exc:
            notes.append(_text(f"newcomers not planned: {exc}"))
        else:
            kept = [step for step in plan.steps if not ((step.engine == "subscription_chain" and str(step.receipt.get("account_ref", "")) in cases) or (step.engine == "payables_chain" and step.entity_ref[len("bill:"):] in bills))]
            if kept:
                adoption = seal(type(plan), {**{key: value for key, value in plan.to_dict().items() if key not in {"plan_digest", "steps", "entities"}}, "steps": [step.to_dict() for step in kept], "entities": len({(step.engine, step.entity_ref) for step in kept})}, "plan_digest").to_dict()
            else:
                notes.append("every account and bill on the page(s) is already persisted; nothing to adopt")
    payload = {"company_ref": company_ref, "currency": str(currency).upper(), "as_of": at, "steps": steps, "adoption": adoption, "discrepancies": discrepancies[:2000], "notes": notes[:2000], "entities": len({(step["engine"], step["entity_ref"]) for step in steps}), "source_digests": digests}
    return seal(SyncPlan, payload, "plan_digest")


def verify_sync_plan(value: Any) -> SyncPlan:
    return value if isinstance(value, SyncPlan) else SyncPlan.model_validate(dict(detached(value)))


def run_sync(console: Any, plan: SyncPlan | Mapping[str, Any]) -> dict[str, Any]:
    """Apply a sealed sync plan through the console's runtimes: every step is a real persisted transition; a refused step stops that entity; newcomers are adopted afterwards."""

    from lightbulb.company_adoption import run_adoption
    from lightbulb.company_operator_surface import CompanyOperatorSurface

    verified = verify_sync_plan(plan)
    _require(verified.company_ref == console.bundle.company_ref and verified.currency == console.bundle.operating_plan.blueprint.currency, "SCOPE_MISMATCH", "the sync plan names another company or currency")
    surface = CompanyOperatorSurface(console)
    advanced: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    applied = 0
    for (engine, entity_ref), steps in verified.by_entity().items():
        try:
            runtime = surface.runtime(engine)
        except (LookupError, ValueError) as exc:
            runner = getattr(console, "runner", None) or (console._runner() if hasattr(console, "_runner") else None)
            runtime = runner.runtimes.get(engine) if runner is not None else None
            if runtime is None:
                refused.append({"engine": engine, "entity_ref": entity_ref, "event": steps[0].event, "code": "NO_RUNTIME", "detail": _text(exc)})
                continue
        if console.store.get(engine, entity_ref) is None:
            refused.append({"engine": engine, "entity_ref": entity_ref, "event": steps[0].event, "code": "NOT_PERSISTED", "detail": f"{entity_ref} is not persisted; adopt it first"})
            continue
        final_status = None
        for index, step in enumerate(steps, start=1):
            current = runtime.load(entity_ref)
            ref = f"sync:{entity_ref}:{step.event}:{index}:{verified.plan_digest[:8]}"
            command = runtime.command(current, event=step.event, transition_ref=ref, idempotency_key=ref, occurred_at=step.at, actor_ref=console.bundle.actor_ref, receipt=step.receipt)
            outcome = runtime.advance_and_persist(entity_ref, command)
            if not outcome.persisted:
                receipt = outcome.result.receipt
                refused.append({"engine": engine, "entity_ref": entity_ref, "event": step.event, "code": str(receipt.rejection_code or "NOT_PERSISTED"), "detail": _text(receipt.recovery.instructions or "")})
                break
            applied += 1
            final_status = outcome.result.state.status
        if final_status is not None:
            advanced.append({"engine": engine, "entity_ref": entity_ref, "status": final_status})
    adoption_report = None if verified.adoption is None else run_adoption(console, verified.adoption)
    return {"schema": SYNC_REPORT_SCHEMA, "plan_digest": verified.plan_digest, "company_ref": verified.company_ref, "as_of": verified.as_of, "advanced": advanced, "refused": refused, "steps_applied": applied, "adoption": adoption_report, "discrepancies": [item.to_dict() for item in verified.discrepancies], "notes": list(verified.notes), "provider_effect_executed": False}


SYNC_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_sync",
    "golden_loop": "subscription.trial_to_renewal_business@0.1.0",
    "stages": ["seal_reads", "match_cases", "plan_next_transitions", "plan_newcomers", "advance_and_adopt", "report"],
    "source_kinds": list(SYNC_SOURCE_KINDS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every step is the chain's own receipt on the provider's exact row; the chain's fences decide what is admissible",
        "cash settles only on a settlement observation past its reversal window that names the case's invoice; revenue recognises only on a closed finance period that reconciled the revenue subledger",
        "what no transition can honestly absorb is a discrepancy for a human, never a forced state",
        "accounts and bills the store does not hold are adopted after the persisted cases advance",
    ],
}

__all__ = ["SETTLEMENT_TOOL", "SYNC_MANIFEST", "SYNC_PLAN_SCHEMA", "SYNC_REPORT_SCHEMA", "SYNC_SOURCE_KINDS", "SyncDiscrepancy", "SyncError", "SyncPlan", "SyncStep", "plan_sync", "run_sync", "verify_sync_plan"]
