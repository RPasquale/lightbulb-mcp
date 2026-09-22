"""Adoption: a company's existing subscriptions, bills, and open deals become chain states from the provider reads that already exist.

Every chain opens from a provider row (a Stripe invoice opens and bills a
subscription, a ledger bill opens a payable) and advances on the rows that
follow, but nothing turned the reads a company already has into the states
the cadence, the treasury period, the revenue model, and the cohort table
expect.  ``plan_adoption`` does the pure part: from one governed read per
source it lists, per entity, the exact opening receipt and the transitions
that replay what the provider shows (the latest invoice of each Stripe
customer, every ledger bill with something outstanding, every open CRM deal
with the facts the ICP needs), every row it will
not adopt with the reason, and the history it deliberately leaves alone.
``run_adoption`` applies that plan through the console's own runtimes: each
step is a real transition with the historical timestamp, persisted through
the host store, idempotent (an entity already persisted is skipped), and a
refused step stops that entity and is reported.

Nothing here invents a fact the provider did not state, fabricates an
approval, or touches a provider: adoption replays what was read, and the
chains' own fences decide what is admissible.
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

ADOPTION_PLAN_SCHEMA = "lightbulb.company_adoption_plan.v1"
ADOPTION_REPORT_SCHEMA = "lightbulb.company_adoption_report.v1"
SOURCE_KINDS: tuple[str, ...] = ("stripe_invoices", "ledger_bills", "crm_prospects")
SourceKind = Literal["stripe_invoices", "ledger_bills", "crm_prospects"]
_MAX_TEXT = 200


class AdoptionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdoptionError(code, message)


def _text(value: Any) -> str:
    return str(value)[:_MAX_TEXT]


class AdoptionStep(StrictModel):
    entity_ref: OpaqueRef
    engine: ShortText
    event: ShortText
    at: str
    opening: bool = False
    source_ref: ShortText
    receipt: dict[str, Any]

    @field_validator("at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="at")


class AdoptionRejection(StrictModel):
    engine: ShortText
    source_ref: ShortText
    reason: ShortText


class AdoptionPlan(StrictModel):
    schema_id: str = Field(default=ADOPTION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    steps: tuple[AdoptionStep, ...] = Field(default_factory=tuple, max_length=4000)
    rejections: tuple[AdoptionRejection, ...] = Field(default_factory=tuple, max_length=2000)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=2000)
    entities: int = Field(ge=0)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=64)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("steps", "rejections", "notes", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "AdoptionPlan":
        if self.entities != len({(item.engine, item.entity_ref) for item in self.steps}):
            raise ValueError("entities must count the distinct entities the steps open or advance")
        if not skip_digests(info) and self.plan_digest != sealed_digest(AdoptionPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def by_entity(self) -> dict[tuple[str, str], list[AdoptionStep]]:
        out: dict[tuple[str, str], list[AdoptionStep]] = {}
        for step in self.steps:
            out.setdefault((step.engine, step.entity_ref), []).append(step)
        return out

    def render(self) -> str:
        lines = [f"**Adoption plan {self.company_ref}** as of {self.as_of[:10]}: {self.entities} entity(ies) over {len(self.steps)} step(s); {len(self.rejections)} row(s) not adopted."]
        for (engine, entity_ref), steps in self.by_entity().items():
            lines.append(f"- {engine} {entity_ref}: {' -> '.join(step.event for step in steps)}")
        for item in self.rejections:
            lines.append(f"- not adopted ({item.engine} {item.source_ref}): {item.reason}")
        lines.extend(f"- {note}" for note in self.notes)
        return "\n".join(lines)


def plan_subscription_adoption(*, saas_plan: Any, subscription_plan: Any, provenance: Mapping[str, Any] | Any, invoices: Mapping[str, Any] | Sequence[Mapping[str, Any]], currency: str, as_of: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Per Stripe customer on the page: open as an adopted subscription at the adoption time, subscribe on the latest invoice, issue it, and apply its payment if paid; the row carries the billing period."""

    from lightbulb.subscription_chain import BillingRow, adoption_receipt, billing_rows, invoice_receipt, payment_receipt, subscription_receipt

    at = timestamp(as_of, field_name="as_of")
    rows = [BillingRow.model_validate(row) for row in billing_rows(provenance, invoices, currency=currency)]
    by_account: dict[str, list[BillingRow]] = {}
    for row in rows:
        by_account.setdefault(row.account_ref, []).append(row)
    steps: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    notes: list[str] = []
    for account_ref in sorted(by_account):
        items = sorted(by_account[account_ref], key=lambda row: (parsed(row.period_start), row.invoice_ref))
        latest = items[-1]
        entity_ref = f"sub:{account_ref}"
        if len(items) > 1:
            notes.append(_text(f"{entity_ref}: {len(items) - 1} earlier invoice(s) not replayed; the chain adopts the current cycle and history stays with the provider"))
        if parsed(latest.period_start) > parsed(at):
            rejections.append({"engine": "subscription_chain", "source_ref": latest.invoice_ref, "reason": _text(f"the billing period starts {latest.period_start[:10]}, after the adoption date")})
            continue
        try:
            opening = adoption_receipt(saas_plan, latest, adopted_at=at)
            subscribe = subscription_receipt(saas_plan, latest)
        except ValueError as exc:
            rejections.append({"engine": "subscription_chain", "source_ref": latest.invoice_ref, "reason": _text(exc)})
            continue
        if subscribe.get("mrr") is None:
            rejections.append({"engine": "subscription_chain", "source_ref": latest.invoice_ref, "reason": _text(f"PLAN_REF_UNKNOWN: {latest.plan_ref} is not a priced tier on the SaaS plan")})
            continue
        steps.append({"entity_ref": entity_ref, "engine": "subscription_chain", "event": "start_trial", "at": at, "opening": True, "source_ref": latest.invoice_ref, "receipt": opening})
        steps.append({"entity_ref": entity_ref, "engine": "subscription_chain", "event": "subscribe", "at": at, "opening": False, "source_ref": latest.invoice_ref, "receipt": subscribe})
        if latest.status in ("open", "paid"):
            steps.append({"entity_ref": entity_ref, "engine": "subscription_chain", "event": "issue_invoice", "at": at, "opening": False, "source_ref": latest.invoice_ref, "receipt": invoice_receipt(latest)})
            if latest.status == "paid" and latest.paid_at is not None and latest.amount_paid > 0:
                steps.append({"entity_ref": entity_ref, "engine": "subscription_chain", "event": "apply_payment", "at": at, "opening": False, "source_ref": latest.invoice_ref, "receipt": payment_receipt(latest)})
        else:
            notes.append(_text(f"{entity_ref}: invoice {latest.invoice_ref} is {latest.status}; adopted as subscribed without an issued invoice"))
    return steps, rejections, notes


def plan_bill_adoption(*, payables_plan: Any, provenance: Mapping[str, Any] | Any, bills: Mapping[str, Any] | Sequence[Mapping[str, Any]], currency: str, as_of: str, engine: str | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Every ledger bill with something outstanding opens a payable case at bill_received at the adoption time; paid and void bills stay with the provider.

    A page that states no due date (the governed Xero month page) is adopted only under the plan's ``default_terms_days``.
    """

    from lightbulb.payables_chain import PayablesChainPlan, ledger_bill_receipt, ledger_bill_rows

    at = timestamp(as_of, field_name="as_of")
    terms = (payables_plan if isinstance(payables_plan, PayablesChainPlan) else PayablesChainPlan.model_validate(detached(payables_plan))).default_terms_days
    steps: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    notes: list[str] = []
    for row in ledger_bill_rows(bills):
        ref = str(row.get("bill_ref") or "")
        try:
            receipt = ledger_bill_receipt(bills, bill_ref=ref, provenance=provenance, currency=currency, engine=engine, default_terms_days=terms)
        except ValueError as exc:
            rejections.append({"engine": "payables_chain", "source_ref": ref or "unnamed", "reason": _text(exc)})
            continue
        steps.append({"entity_ref": f"bill:{ref}", "engine": "payables_chain", "event": "receive_bill", "at": at, "opening": True, "source_ref": ref, "receipt": receipt})
    if not steps and not rejections:
        notes.append("no ledger bills on the page")
    return steps, rejections, notes


# The platform's CRM reads are the provider-neutral ``crm.*`` tools (HubSpot sits behind them); the ``hubspot.*`` names are kept for hosts that read the provider directly.
CRM_PROSPECT_TOOLS: tuple[str, ...] = ("crm.search_deals", "crm.search_contacts", "crm.search_accounts", "hubspot.search_deals", "hubspot.search_contacts", "hubspot.search_companies", "crm.list_deals", "host.crm_prospects")
CLOSED_STAGES: frozenset[str] = frozenset({"closedwon", "closedlost", "closed_won", "closed_lost", "won", "lost"})


def _first(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def crm_prospect_rows(prospects: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """CRM rows (HubSpot search results with ``properties``, or plain rows) read into the facts a prospect needs; nothing is inferred and a missing fact stays missing."""

    raw = detached(prospects)
    rows = (raw.get("results") or raw.get("data") or raw.get("prospects") or raw.get("deals") or []) if isinstance(raw, Mapping) else list(raw)
    out: list[dict[str, Any]] = []
    for item in rows:
        row = dict(item)
        properties = dict(row.get("properties") or {})
        merged = {**row, **properties}
        signals = _first(merged, "signals", "hs_signals")
        flags = _first(merged, "flags")
        employees = _first(merged, "employees", "numberofemployees", "number_of_employees")
        out.append({
            "id": str(_first(merged, "id", "hs_object_id", "deal_id", "prospect_ref") or ""),
            "account_ref": str(_first(merged, "account_ref", "company_id", "associatedcompanyid", "company", "domain") or ""),
            "industry": str(_first(merged, "industry") or ""),
            "employees": int(str(employees)) if employees is not None and str(employees).strip().lstrip("-").isdigit() else None,
            "region": str(_first(merged, "region", "country", "hs_country", "state") or ""),
            "title": str(_first(merged, "title", "jobtitle", "buyer_title") or ""),
            "signals": [str(item).strip() for item in (signals.split(";") if isinstance(signals, str) else (signals or ())) if str(item).strip()],
            "flags": [str(item).strip() for item in (flags.split(";") if isinstance(flags, str) else (flags or ())) if str(item).strip()],
            "stage": str(_first(merged, "stage", "dealstage", "status") or "").lower(),
            "name": str(_first(merged, "dealname", "name") or ""),
        })
    return out


def plan_prospect_adoption(*, pipeline_plan: Any, provenance: Mapping[str, Any] | Any, prospects: Mapping[str, Any] | Sequence[Mapping[str, Any]], currency: str, as_of: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Every open CRM deal with the facts the ICP needs opens a sourced prospect on its sealed fit; closed deals are history, rows missing a fact or below the fit threshold are reported."""

    from lightbulb.company_execution_bridge import ObservationProvenance
    from lightbulb.pipeline_engine_loop import PipelineEngineLoopPlan, ProspectFacts, evaluate_icp_fit

    at = timestamp(as_of, field_name="as_of")
    plan = PipelineEngineLoopPlan.model_validate(detached(pipeline_plan))
    _require(plan.blueprint.currency == str(currency).upper(), "SOURCE_SCOPE_MISMATCH", f"the pipeline blueprint runs in {plan.blueprint.currency}, not {currency}")
    read = ObservationProvenance.model_validate(detached(provenance))
    _require(read.source_tool in CRM_PROSPECT_TOOLS, "SOURCE_TOOL_MISMATCH", f"prospects adopt from {list(CRM_PROSPECT_TOOLS)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(prospects)), "SOURCE_DIGEST_MISMATCH", "the CRM page must be the exact output the read returned")
    _require(parsed(read.completed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the CRM read must complete before the adoption")
    steps: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    notes: list[str] = []
    for row in crm_prospect_rows(prospects):
        ref = row["id"] or row["name"] or "unnamed"
        if not row["id"]:
            rejections.append({"engine": "pipeline_engine", "source_ref": ref, "reason": "the row carries no id"})
            continue
        if row["stage"] in CLOSED_STAGES:
            notes.append(_text(f"crm:{ref}: {row['stage']} is history; the revenue chain, not the pipeline, carries won deals"))
            continue
        missing = [name for name in ("account_ref", "industry", "employees", "region", "title") if not row.get(name)]
        if missing:
            rejections.append({"engine": "pipeline_engine", "source_ref": ref, "reason": _text(f"FACTS_MISSING: the CRM row does not state {', '.join(missing)}; the ICP cannot be evaluated without them")})
            continue
        prospect_ref = f"crm:{row['id']}"
        try:
            facts = ProspectFacts.model_validate({"prospect_ref": prospect_ref, "account_ref": row["account_ref"], "industry": row["industry"], "employees": row["employees"], "region": row["region"], "title": row["title"], "signals": row["signals"][:20], "flags": row["flags"][:20], "source_ref": f"{read.source_tool}:{read.observation_ref}"})
            fit = evaluate_icp_fit(plan, facts)
        except ValueError as exc:
            rejections.append({"engine": "pipeline_engine", "source_ref": ref, "reason": _text(exc)})
            continue
        if not fit.fits:
            rejections.append({"engine": "pipeline_engine", "source_ref": ref, "reason": _text(f"BELOW_FIT_THRESHOLD: {fit.reasons[0]}")})
            continue
        steps.append({"entity_ref": prospect_ref, "engine": "pipeline_engine", "event": "source", "at": at, "opening": True, "source_ref": ref, "receipt": {"facts": facts.to_dict(), "fit": fit.to_dict(), "stage": row["stage"], "read": read.to_dict()}})
    return steps, rejections, notes


def plan_adoption(*, company_ref: str, currency: str, as_of: str, sources: Sequence[Mapping[str, Any]], saas_plan: Any = None, subscription_plan: Any = None, payables_plan: Any = None, pipeline_plan: Any = None) -> AdoptionPlan:
    """The sealed plan from one or more provider reads; each source names its kind, its provenance, and the exact payload the read returned."""

    at = timestamp(as_of, field_name="as_of")
    _require(bool(sources), "SOURCES_MISSING", "adoption needs at least one provider read")
    steps: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    notes: list[str] = []
    digests: list[str] = []
    seen: set[tuple[str, str]] = set()
    for source in sources:
        raw = dict(detached(source))
        kind = str(raw.get("kind", ""))
        _require(kind in SOURCE_KINDS, "SOURCE_KIND_UNKNOWN", f"{kind or 'untyped'} is not one of {SOURCE_KINDS}")
        _require(raw.get("provenance") is not None and raw.get("payload") is not None, "SOURCE_NOT_SEALED", f"a {kind} source carries its provenance and the exact payload")
        provenance, payload = raw["provenance"], raw["payload"]
        digests.append(str(dict(detached(provenance)).get("provenance_digest") or stable_digest(detached(provenance))))
        if kind == "stripe_invoices":
            _require(saas_plan is not None and subscription_plan is not None, "PLAN_MISSING", "adopting subscriptions needs the sealed SaaS plan and the subscription chain plan")
            new_steps, new_rejections, new_notes = plan_subscription_adoption(saas_plan=saas_plan, subscription_plan=subscription_plan, provenance=provenance, invoices=payload, currency=currency, as_of=at)
        elif kind == "crm_prospects":
            _require(pipeline_plan is not None, "PLAN_MISSING", "adopting prospects needs the pipeline plan")
            new_steps, new_rejections, new_notes = plan_prospect_adoption(pipeline_plan=pipeline_plan, provenance=provenance, prospects=payload, currency=currency, as_of=at)
        else:
            _require(payables_plan is not None, "PLAN_MISSING", "adopting bills needs the payables chain plan")
            new_steps, new_rejections, new_notes = plan_bill_adoption(payables_plan=payables_plan, provenance=provenance, bills=payload, currency=currency, as_of=at, engine=raw.get("engine"))
        for step in new_steps:
            key = (step["engine"], step["entity_ref"])
            if step["opening"] and key in seen:
                rejections.append({"engine": step["engine"], "source_ref": step["source_ref"], "reason": _text(f"{step['entity_ref']} appears in more than one source; the first read wins")})
                seen.add(("skip", step["entity_ref"]))
                continue
            if ("skip", step["entity_ref"]) in seen:
                continue
            seen.add(key)
            steps.append(step)
        rejections.extend(new_rejections)
        notes.extend(new_notes)
    entities = len({(step["engine"], step["entity_ref"]) for step in steps})
    return seal(AdoptionPlan, {"company_ref": company_ref, "currency": str(currency).upper(), "as_of": at, "steps": steps, "rejections": rejections, "notes": notes, "entities": entities, "source_digests": digests}, "plan_digest")


def verify_adoption_plan(value: Any) -> AdoptionPlan:
    return value if isinstance(value, AdoptionPlan) else AdoptionPlan.model_validate(dict(detached(value)))


def run_adoption(console: Any, plan: AdoptionPlan | Mapping[str, Any]) -> dict[str, Any]:
    """Apply a sealed plan through the console's runtimes: open, then advance step by step with the historical timestamps; persisted entities are skipped, refused steps reported."""

    from lightbulb.company_operator_surface import CompanyOperatorSurface

    verified = verify_adoption_plan(plan)
    _require(verified.company_ref == console.bundle.company_ref and verified.currency == console.bundle.operating_plan.blueprint.currency, "SCOPE_MISMATCH", "the adoption plan names another company or currency")
    surface = CompanyOperatorSurface(console)
    adopted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
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
        if console.store.get(engine, entity_ref) is not None:
            skipped.append({"engine": engine, "entity_ref": entity_ref, "reason": "already persisted"})
            continue
        _require(steps[0].opening, "PLAN_INCOHERENT", f"{entity_ref} has no opening step")
        scope = console.bundle.engine_scope(entity_ref)
        try:
            if engine == "pipeline_engine":
                from lightbulb.pipeline_engine_loop import open_prospect

                state = open_prospect(runtime.plan, scope, facts=steps[0].receipt["facts"], fit=steps[0].receipt["fit"], opened_at=steps[0].at, actor_ref=console.bundle.actor_ref)
            else:
                state = runtime.spec.open(runtime.plan, scope, receipt=steps[0].receipt, opened_at=steps[0].at, actor_ref=console.bundle.actor_ref)
        except ValueError as exc:
            refused.append({"engine": engine, "entity_ref": entity_ref, "event": steps[0].event, "code": str(exc).split(":", 1)[0][:60], "detail": _text(exc)})
            continue
        runtime.open(entity_ref, state)
        applied += 1
        final_status = state.status
        for index, step in enumerate(steps[1:], start=2):
            current = runtime.load(entity_ref)
            ref = f"adopt:{entity_ref}:{step.event}:{index}"
            command = runtime.command(current, event=step.event, transition_ref=ref, idempotency_key=ref, occurred_at=step.at, actor_ref=console.bundle.actor_ref, receipt=step.receipt)
            outcome = runtime.advance_and_persist(entity_ref, command)
            if not outcome.persisted:
                receipt = outcome.result.receipt
                refused.append({"engine": engine, "entity_ref": entity_ref, "event": step.event, "code": str(receipt.rejection_code or "NOT_PERSISTED"), "detail": _text(receipt.recovery.instructions or "")})
                break
            applied += 1
            final_status = outcome.result.state.status
        adopted.append({"engine": engine, "entity_ref": entity_ref, "status": final_status, "steps": sum(1 for item in refused if item["entity_ref"] == entity_ref) and len(steps) - 1 or len(steps)})
    return {"schema": ADOPTION_REPORT_SCHEMA, "plan_digest": verified.plan_digest, "company_ref": verified.company_ref, "as_of": verified.as_of, "adopted": adopted, "skipped_existing": skipped, "refused": refused, "steps_applied": applied, "rejections": [item.to_dict() for item in verified.rejections], "notes": list(verified.notes), "provider_effect_executed": False}


ADOPTION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_adoption",
    "golden_loop": "company.formation_to_operating_cadence@0.1.0",
    "stages": ["seal_reads", "plan_entities", "open_and_replay", "report"],
    "source_kinds": list(SOURCE_KINDS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every adopted state is opened and advanced through the chain's own receipts on the provider's exact rows; nothing is typed",
        "the current billing cycle is adopted; earlier invoices are reported as history, never replayed without their evidence",
        "a paid bill is not adopted; only what is still outstanding becomes a payable",
        "an open CRM deal opens a sourced prospect only on its sealed ICP fit; a row missing a fact or below the threshold is reported, a closed deal is history",
        "an entity already persisted is skipped; a refused step stops that entity and is reported with the chain's own code",
    ],
}

__all__ = ["ADOPTION_MANIFEST", "ADOPTION_PLAN_SCHEMA", "ADOPTION_REPORT_SCHEMA", "CLOSED_STAGES", "CRM_PROSPECT_TOOLS", "SOURCE_KINDS", "AdoptionError", "AdoptionPlan", "AdoptionRejection", "AdoptionStep", "crm_prospect_rows", "plan_adoption", "plan_bill_adoption", "plan_prospect_adoption", "plan_subscription_adoption", "run_adoption", "verify_adoption_plan"]
