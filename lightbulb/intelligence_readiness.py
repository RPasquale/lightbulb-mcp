"""Intelligence readiness: for every document, whether it can be built now, on what evidence, and the one thing that would unlock it.

Twenty-odd documents each need a plan in the bundle and evidence to read.
An owner who asks for one and gets a ``LookupError`` learns nothing about
what to do next.  ``assess_intelligence_readiness`` answers for all of them
at once, from facts the console already holds: which plans the bundle
carries, how many states each chain holds, whether books are recorded and
whether they carry balances, and which connectors the project has bound.

Each document is ``ready`` (with its basis: the chains, or the books),
``ready_with_input`` (the plans are there and the caller supplies the jobs
or people it judges), ``needs_evidence`` (the plan is there and nothing
feeds it; the row names the chains it reads and the connectors that feed
them), or ``needs_plan``.  The rows are a fixed table, so the answer is the
same for the same facts and nothing is inferred.  Nothing here reads a
provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp

INTELLIGENCE_READINESS_SCHEMA = "lightbulb.intelligence_readiness.v1"
READINESS_STATUSES: tuple[str, ...] = ("ready", "ready_with_input", "needs_evidence", "needs_plan")
ReadinessStatus = Literal["ready", "ready_with_input", "needs_evidence", "needs_plan"]

# kind -> verb, the plans it needs, the chains it reads (any one with a state is evidence), whether recorded books will do,
# the connectors that feed those chains, and what the caller must supply when nothing persisted can.
DOCUMENT_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "books_snapshot": {"verb": "books", "plans": ("books_snapshot",), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": "the ledger's profit and loss and balance sheet reads"},
    "cash_calendar": {"verb": "cash_calendar", "plans": (), "chains": (), "books": "balances", "connectors": ("xero", "quickbooks"), "input": None},
    "break_even": {"verb": "break_even", "plans": ("break_even",), "chains": ("fulfilment_chain", "engagement_engine", "work_order_chain"), "books": "recorded", "connectors": ("xero", "quickbooks", "shopify"), "input": None},
    "working_capital": {"verb": "working_capital", "plans": ("working_capital",), "chains": ("collections_chain", "payables_chain", "inventory_chain"), "books": "balances", "connectors": ("xero", "quickbooks"), "input": None},
    "product_margin": {"verb": "product_margin", "plans": ("product_margin",), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "product_portfolio": {"verb": "product_portfolio", "plans": ("product_margin", "product_portfolio"), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "price_probes": {"verb": "price_probes", "plans": ("product_margin", "product_portfolio", "price_probes"), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "contribution_bridge": {"verb": "contribution_bridge", "plans": ("product_margin",), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "customer_profitability": {"verb": "customer_profitability", "plans": ("product_margin",), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "customer_cohorts": {"verb": "customer_cohorts", "plans": ("customer_cohorts",), "chains": ("fulfilment_chain", "subscription_chain"), "books": None, "connectors": ("shopify", "square", "stripe"), "input": None},
    "stockouts": {"verb": "stockouts", "plans": ("stockouts",), "chains": ("inventory_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "returns_ledger": {"verb": "returns_ledger", "plans": ("returns_ledger",), "chains": ("fulfilment_chain",), "books": None, "connectors": ("shopify",), "input": None},
    "open_to_buy": {"verb": "open_to_buy", "plans": ("product_margin", "product_portfolio", "open_to_buy"), "chains": ("inventory_chain",), "books": None, "connectors": ("shopify", "square"), "input": None},
    "supplier_scorecard": {"verb": "supplier_scorecard", "plans": ("supplier_scorecard",), "chains": ("inventory_chain",), "books": None, "connectors": ("shopify",), "input": None},
    "services_margin": {"verb": "services_margin", "plans": ("services_margin",), "chains": ("engagement_engine", "work_order_chain"), "books": None, "connectors": (), "input": None},
    "rate_card": {"verb": "rate_card", "plans": ("services_margin", "rate_card"), "chains": ("engagement_engine", "work_order_chain"), "books": None, "connectors": (), "input": None},
    "job_costing": {"verb": "job_costing", "plans": ("job_costing",), "chains": ("work_order_chain", "contractor_chain"), "books": None, "connectors": (), "input": None},
    "skills_match": {"verb": "skills", "plans": ("skills_taxonomy", "skills_matching"), "chains": (), "books": None, "connectors": (), "input": "the jobs to staff and the worker profiles"},
    "skills_inventory": {"verb": "skills_inventory", "plans": ("skills_taxonomy", "skills_matching"), "chains": (), "books": None, "connectors": (), "input": "the worker profiles"},
    "workforce_capacity": {"verb": "workforce_capacity", "plans": ("skills_taxonomy", "skills_matching"), "chains": (), "books": None, "connectors": (), "input": "the jobs and the worker profiles"},
    "labour_sourcing": {"verb": "sourcing", "plans": ("skills_taxonomy", "skills_matching", "labour_sourcing"), "chains": (), "books": None, "connectors": (), "input": "the jobs and the worker profiles"},
    "skills_development": {"verb": "skills_development", "plans": ("skills_taxonomy", "skills_matching", "labour_sourcing", "skills_development"), "chains": (), "books": None, "connectors": (), "input": "the jobs and the worker profiles"},
    "job_assignment": {"verb": "assignment", "plans": ("skills_taxonomy", "skills_matching", "job_assignment"), "chains": (), "books": None, "connectors": (), "input": "the jobs to staff and the worker profiles"},
    "job_quotes": {"verb": "job_quote", "plans": ("skills_taxonomy", "skills_matching", "job_quote"), "chains": (), "books": None, "connectors": (), "input": "the job to quote and the worker profiles"},
    "customer_ledger": {"verb": "customers", "plans": ("customer_ledger",), "chains": (), "books": None, "connectors": ("xero", "quickbooks"), "input": "the ledger's sales invoice read"},
    "company_scenario": {"verb": "what_if", "plans": (), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": "the levers to test"},
    "intelligence_history": {"verb": "history", "plans": (), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
    "threshold_calibration": {"verb": "calibrate", "plans": (), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
    "ledger_tie_out": {"verb": "tie_out", "plans": ("ledger_tie_out",), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
    "pipeline_coverage": {"verb": "pipeline_coverage", "plans": ("pipeline_coverage",), "chains": ("pipeline_engine",), "books": None, "connectors": ("hubspot", "salesforce"), "input": None},
}
# documents declared in lightbulb.document_registry bring their own requirement
from lightbulb.document_registry import readiness_requirements as _registered_requirements  # noqa: E402

DOCUMENT_REQUIREMENTS.update(_registered_requirements())


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ReadinessRow(StrictModel):
    kind: ShortText
    verb: ShortText
    status: ReadinessStatus
    basis: ShortText | None = None
    missing_plans: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    next_step: ShortText

    @field_validator("missing_plans", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class IntelligenceReadiness(StrictModel):
    schema_id: str = Field(default=INTELLIGENCE_READINESS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    rows: tuple[ReadinessRow, ...] = Field(max_length=60)
    ready: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
    next_steps: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    verdict: ShortText
    readiness_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "next_steps", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "IntelligenceReadiness":
        counts: dict[str, int] = {}
        for row in self.rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        if self.by_status != counts or self.ready != counts.get("ready", 0) + counts.get("ready_with_input", 0):
            raise ValueError("ready and by_status count the rows")
        if not skip_digests(info) and self.readiness_digest != sealed_digest(IntelligenceReadiness, self, "readiness_digest"):
            raise ValueError("readiness_digest must commit the exact document")
        return self

    def row(self, kind: str) -> ReadinessRow:
        found = next((item for item in self.rows if item.kind == kind), None)
        if found is None:
            raise LookupError(f"{kind} is not an intelligence document")
        return found

    def render(self) -> str:
        lines = [f"**Intelligence readiness** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- [{row.status}] {row.kind}: {row.next_step}" for row in self.rows)
        return "\n".join(lines)


def assess_intelligence_readiness(*, company_ref: str, as_of: str, plans: Sequence[str], chain_states: Mapping[str, int], books_recorded: bool, books_with_balances: bool, connectors_bound: Sequence[str] = ()) -> IntelligenceReadiness:
    """The sealed readiness of every document from the bundle's plans, the chains' state counts, the recorded books and the bound connectors."""

    at = timestamp(as_of, field_name="as_of")
    have, bound = set(plans), {str(item).lower() for item in connectors_bound}
    counts = {str(key): int(value) for key, value in dict(detached(chain_states)).items()}
    rows: list[dict[str, Any]] = []
    for kind, need in DOCUMENT_REQUIREMENTS.items():
        missing = [name for name in need["plans"] if name not in have]
        fed = [chain for chain in need["chains"] if counts.get(chain, 0) > 0]
        books_ok = (need["books"] == "recorded" and books_recorded) or (need["books"] == "balances" and books_with_balances)
        feeders = [name for name in need["connectors"] if name in bound]
        if missing:
            status, basis, step = "needs_plan", None, f"add {', '.join(missing)} to the bundle (propose the bundle again, or compile the plan)"
        elif kind == "books_snapshot":
            status, basis = ("ready", "books") if books_recorded else ("ready_with_input", None)
            step = "recorded; record again after the ledger changes" if books_recorded else f"supply {need['input']}" + ("" if feeders else "; bind the ledger connector to this project first")
        elif fed:
            status, basis, step = "ready", "chains", f"reads {', '.join(fed)}"
        elif books_ok:
            status, basis, step = "ready", "books", "reads the recorded books for its own window"
        elif need["input"] and not need["chains"] and need["books"] is None:
            status, basis, step = "ready_with_input", None, f"supply {need['input']}"
        else:
            status, basis = "needs_evidence", None
            wants = []
            if need["chains"]:
                wants.append(f"states in {' or '.join(need['chains'])}")
            if need["books"]:
                wants.append("recorded books with a balance sheet" if need["books"] == "balances" else "recorded books for the window")
            source = f"; {', '.join(need['connectors'])} feed it" + ("" if feeders else " and none is bound to this project") if need["connectors"] else ""
            step = f"needs {' or '.join(wants)}{source}"
        rows.append({"kind": kind, "verb": need["verb"], "status": status, "basis": basis, "missing_plans": missing, "next_step": step[:300]})
    order = {name: index for index, name in enumerate(READINESS_STATUSES)}
    rows.sort(key=lambda item: (order[item["status"]], list(DOCUMENT_REQUIREMENTS).index(item["kind"])))
    by_status: dict[str, int] = {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    ready = by_status.get("ready", 0) + by_status.get("ready_with_input", 0)
    steps: list[str] = []
    for row in rows:
        if row["status"] in ("needs_evidence", "needs_plan") and row["next_step"] not in steps:
            steps.append(row["next_step"])
    verdict = f"{ready} of {len(rows)} document(s) can be built now ({by_status.get('ready', 0)} from persisted evidence, {by_status.get('ready_with_input', 0)} once their input is supplied); {by_status.get('needs_evidence', 0)} need evidence and {by_status.get('needs_plan', 0)} need a plan"
    return seal(IntelligenceReadiness, {"company_ref": company_ref, "as_of": at, "rows": rows, "ready": ready, "by_status": by_status, "next_steps": steps[:8], "verdict": verdict[:300]}, "readiness_digest")


def verify_intelligence_readiness(value: Any) -> IntelligenceReadiness:
    return value if isinstance(value, IntelligenceReadiness) else IntelligenceReadiness.model_validate(dict(detached(value)))


__all__ = ["DOCUMENT_REQUIREMENTS", "INTELLIGENCE_READINESS_SCHEMA", "READINESS_STATUSES", "IntelligenceReadiness", "ReadinessRow", "assess_intelligence_readiness", "verify_intelligence_readiness"]
