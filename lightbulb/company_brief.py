"""The operator brief and the board pack: one sealed document per tick, one per month, every number with its evidence.

The console has verbs; a founder at 7am needs a page.  ``daily_brief``
assembles what the verbs already return into one ``OperatorBrief``: the
period and what is due, the work items and automatic actions, the approvals
waiting with their decision briefs, the cash position and the first breach
week, the exceptions past SLA, the compliance obligations due, and the
explanations behind the headline numbers.  ``board_pack`` is the monthly
roll-up over the persisted periods and closes: revenue and spend by engine,
books verified, revenue and payables chains cleared, retention, the runway,
the exceptions record, and the decisions taken with what the counterfactual
said.  Both render to markdown; both are sealed; neither computes a number
the engines did not already hold.  Synthetic figures are marked.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, stable_digest, timestamp

BRIEF_SCHEMA = "lightbulb.company_operator_brief.v1"
BOARD_PACK_SCHEMA = "lightbulb.company_board_pack.v1"


class BriefSection(StrictModel):
    title: ShortText
    lines: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=60)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=60)
    synthetic: bool = False

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class OperatorBrief(StrictModel):
    schema_id: str = Field(default=BRIEF_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    headline: BoundedText
    sections: tuple[BriefSection, ...] = Field(min_length=1, max_length=48)
    attention: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    source_digests: dict[str, str] = Field(default_factory=dict)
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("sections", "attention", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorBrief:
        if not skip_digests(info) and self.brief_digest != sealed_digest(OperatorBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self

    def render(self) -> str:
        lines = [f"# {self.company_ref} — operator brief for {self.as_of[:10]}", "", self.headline, ""]
        if self.attention:
            lines.append("## Needs you")
            lines.extend(f"- {item}" for item in self.attention)
            lines.append("")
        for section in self.sections:
            lines.append(f"## {section.title}" + (" (synthetic)" if section.synthetic else ""))
            lines.extend(f"- {line}" for line in section.lines)
            if section.evidence_refs:
                lines.append(f"  evidence: {', '.join(section.evidence_refs[:8])}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def _money(value: Any) -> str:
    try:
        return str(Decimal(str(value)).quantize(MONEY_QUANTUM))
    except Exception:  # noqa: BLE001
        return str(value)


def daily_brief(*, company_ref: str, now: str, work_items: Mapping[str, Any] | None = None, inbox: Sequence[Mapping[str, Any]] = (), decisions: Sequence[Mapping[str, Any]] = (), forecast: Mapping[str, Any] | None = None, exceptions: Mapping[str, Any] | None = None, compliance: Mapping[str, Any] | None = None, explanations: Sequence[Mapping[str, Any]] = (), period: Mapping[str, Any] | None = None, retention: Mapping[str, Any] | None = None, chain_sources: Sequence[Mapping[str, Any]] = ()) -> OperatorBrief:
    """One page from the console's own documents; every section names the digest of what it was rendered from."""

    stamp = timestamp(now, field_name="now")
    sections: list[dict[str, Any]] = []
    attention: list[str] = []
    digests: dict[str, str] = {}

    if period is not None:
        raw = dict(detached(period))
        ledger = dict(raw.get("ledger") or {})
        digests["period"] = str(raw.get("state_digest") or stable_digest(raw))
        lines = [f"period {raw.get('scope', {}).get('entity_ref', '?')} is {raw.get('status')} (version {raw.get('version')})", f"spend {_money(ledger.get('total_spend', '0'))} of budget {_money(ledger.get('budget_total', '0'))}; revenue {_money(ledger.get('total_revenue', '0'))}"]
        for engine, spend in dict(ledger.get("spend_by_engine") or {}).items():
            lines.append(f"{engine}: spend {_money(spend)}, revenue {_money(dict(ledger.get('revenue_by_engine') or {}).get(engine, '0'))}")
        if ledger.get("halt_reason"):
            attention.append(f"the period halted: {ledger['halt_reason']}")
        sections.append({"title": "The period", "lines": lines, "evidence_refs": [f"period:{digests['period'][:16]}"]})

    if work_items is not None:
        raw = dict(detached(work_items))
        digests["work_items"] = str(raw.get("plan_digest") or stable_digest(raw))
        items = [dict(detached(item)) for item in raw.get("work_items") or []]
        automatic = [dict(detached(item)) for item in raw.get("automatic") or []]
        lines = [f"{len(automatic)} automatic action(s) the runner applies; {len(items)} work item(s) need an input"]
        for item in items[:12]:
            lines.append(f"{item.get('engine')}.{item.get('event')} on {item.get('entity_ref')}: {item.get('needs') or item.get('kind') or item.get('detail') or 'a receipt'}")
        if items:
            attention.append(f"{len(items)} work item(s) are waiting on a read or a receipt")
        sections.append({"title": "Due now", "lines": lines, "evidence_refs": [f"tick_plan:{digests['work_items'][:16]}"]})

    if inbox:
        rows = [dict(detached(item)) for item in inbox]
        digests["inbox"] = stable_digest(rows)
        briefs = {str(dict(detached(brief)).get("task_id")): dict(detached(brief)) for brief in decisions}
        lines = []
        for item in rows[:12]:
            brief = briefs.get(str(item.get("task_id")))
            line = f"{item.get('approval_type')} `{item.get('task_id')}`: {item.get('summary')}"
            if brief is not None:
                line += f" — counterfactual recommends **{brief.get('recommendation')}**"
            if item.get("freshness") == "stale":
                line += " (stale: the state moved since it was raised)"
            lines.append(line)
        attention.append(f"{len(rows)} approval(s) are waiting for a person")
        sections.append({"title": "Approvals waiting", "lines": lines, "evidence_refs": [f"inbox:{digests['inbox'][:16]}"] + [f"brief:{str(brief.get('brief_digest', ''))[:16]}" for brief in briefs.values()][:8], "synthetic": bool(briefs)})

    if forecast is not None:
        raw = dict(detached(forecast))
        digests["forecast"] = str(raw.get("forecast_digest") or stable_digest(raw))
        breach = raw.get("first_breach_week")
        lines = [f"opening {_money(raw.get('opening_balance'))} {raw.get('currency')}; floor {_money(raw.get('floor'))}; minimum over {raw.get('horizon_weeks')} weeks {_money(raw.get('minimum_balance'))}"]
        lines.append(f"runway {raw.get('runway_weeks')} week(s); first breach in week {breach}" if breach else "no breach inside the horizon")
        tax = sum((Decimal(str(dict(detached(flow)).get("amount", "0"))) for flow in raw.get("flows") or [] if dict(detached(flow)).get("kind") == "tax_reservation"), Decimal("0"))
        if tax != 0:
            lines.append(f"tax reservations inside the horizon: {_money(tax.copy_abs())}")
        if breach:
            attention.append(f"cash breaches the floor in week {breach}")
        sections.append({"title": "Cash", "lines": lines, "evidence_refs": [f"forecast:{digests['forecast'][:16]}", f"position:{str(raw.get('position_digest', ''))[:16]}"]})

    if exceptions is not None:
        raw = dict(detached(exceptions))
        digests["exceptions"] = str(raw.get("summary_digest") or stable_digest(raw))
        lines = [f"{raw.get('open', 0)} open, {raw.get('past_sla', 0)} past SLA, {raw.get('resolved', 0)} resolved ({raw.get('resolved_within_sla', 0)} within SLA)"]
        for case in [dict(detached(item)) for item in raw.get("cases") or []][:10]:
            lines.append(f"{case.get('kind')} on {case.get('source_ref')} ({case.get('code')}): waiting on {case.get('waiting_on')}" + (" — PAST SLA" if case.get("past_sla") else ""))
        if int(raw.get("past_sla", 0) or 0) > 0:
            attention.append(f"{raw.get('past_sla')} exception(s) are past their SLA")
        sections.append({"title": "Exceptions", "lines": lines, "evidence_refs": [f"desk:{digests['exceptions'][:16]}"]})

    if compliance is not None:
        raw = dict(detached(compliance))
        digests["compliance"] = str(raw.get("summary_digest") or stable_digest(raw))
        rows = [dict(detached(item)) for item in raw.get("open") or []]
        lines = [f"{len(rows)} obligation(s) open; {_money(raw.get('reserved_from_reads', '0'))} reserved from reads, {_money(raw.get('still_estimated', '0'))} still estimated, {_money(raw.get('overdue', '0'))} overdue"]
        for row in rows[:8]:
            lines.append(f"{row.get('kind')} due {str(row.get('due_at', ''))[:10]}: {_money(row.get('amount'))} ({row.get('basis')}, {row.get('status')})" + (" — OVERDUE" if row.get("overdue") else ""))
        if Decimal(str(raw.get("overdue", "0") or "0")) > 0:
            attention.append("a statutory obligation is overdue")
        sections.append({"title": "Compliance", "lines": lines, "evidence_refs": [f"calendar:{digests['compliance'][:16]}"]})

    if retention is not None:
        raw = dict(detached(retention))
        digests["retention"] = stable_digest(raw)
        nrr = raw.get("net_revenue_retention_percent")
        sections.append({"title": "Retention", "lines": [f"{raw.get('cases', 0)} renewal case(s): {_money(raw.get('amount_kept', '0'))} kept of {_money(raw.get('amount_due', '0'))} due" + (f"; net revenue retention {nrr}%" if nrr is not None else ""), "by status: " + ", ".join(f"{key} {value}" for key, value in dict(raw.get("by_status") or {}).items() if value)], "evidence_refs": [f"retention:{digests['retention'][:16]}"]})

    if explanations:
        lines = []
        refs: list[str] = []
        synthetic = False
        for item in explanations[:6]:
            raw = dict(detached(item))
            lines.append(f"{raw.get('engine')}.{raw.get('field')} = {raw.get('value')}: {len(raw.get('contributions') or [])} transition(s); sources {', '.join(raw.get('source_kinds') or [])}")
            refs.append(f"explanation:{str(raw.get('explanation_digest', stable_digest(raw)))[:16]}")
            synthetic = synthetic or bool(raw.get("synthetic"))
        sections.append({"title": "Behind the numbers", "lines": lines, "evidence_refs": refs, "synthetic": synthetic})

    chain_sections, chain_digests = _chain_sections(chain_sources, company_ref=company_ref)
    sections.extend(chain_sections)
    digests.update(chain_digests)
    if not sections:
        sections.append({"title": "Nothing persisted yet", "lines": ["no period, forecast, inbox, or exceptions were supplied; run the cadence first"]})
    headline = f"{company_ref}: " + ("; ".join(attention[:3]) if attention else "nothing needs you; the runner has what it needs")
    return seal(OperatorBrief, {"company_ref": company_ref, "as_of": stamp, "headline": headline, "sections": sections, "attention": attention, "source_digests": digests}, "brief_digest")


# --------------------------------------------------------------------------- #
# The board pack
# --------------------------------------------------------------------------- #


class BoardPack(StrictModel):
    schema_id: str = Field(default=BOARD_PACK_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    month: ShortText
    prepared_at: str
    periods: int = Field(ge=0)
    revenue: Decimal
    spend: Decimal
    gross_margin_percent: Decimal | None = None
    revenue_by_engine: dict[str, Decimal] = Field(default_factory=dict)
    spend_by_engine: dict[str, Decimal] = Field(default_factory=dict)
    books_verified_periods: int = Field(ge=0)
    revenue_cases_cleared: int = Field(ge=0)
    revenue_cash_proven: Decimal
    payable_cases_cleared: int = Field(ge=0)
    payables_cash_proven: Decimal
    net_revenue_retention_percent: Decimal | None = None
    runway_weeks: int | None = None
    exceptions_opened: int = Field(ge=0)
    exceptions_resolved_within_sla: int = Field(ge=0)
    decisions: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    sections: tuple[BriefSection, ...] = Field(default_factory=tuple, max_length=48)
    source_digests: dict[str, str] = Field(default_factory=dict)
    pack_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("revenue", "spend", "revenue_cash_proven", "payables_cash_proven", mode="before")
    @classmethod
    def _amounts(cls, value: Any) -> Decimal:
        return Decimal(str(value)).quantize(MONEY_QUANTUM)

    @field_validator("gross_margin_percent", "net_revenue_retention_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal | None:
        return None if value is None else Decimal(str(value)).quantize(Decimal("0.01"))

    @field_validator("revenue_by_engine", "spend_by_engine", mode="before")
    @classmethod
    def _maps(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): Decimal(str(item)).quantize(MONEY_QUANTUM) for key, item in dict(value or {}).items()}

    @field_validator("decisions", "sections", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BoardPack:
        if not skip_digests(info) and self.pack_digest != sealed_digest(BoardPack, self, "pack_digest"):
            raise ValueError("pack_digest must commit the exact pack")
        return self

    def render(self) -> str:
        lines = [f"# {self.company_ref} — board pack, {self.month}", "", f"Revenue {self.revenue}, spend {self.spend}" + (f", gross margin {self.gross_margin_percent}%" if self.gross_margin_percent is not None else "") + f" across {self.periods} period(s); books verified in {self.books_verified_periods}.", f"Cash proven in: {self.revenue_cash_proven} ({self.revenue_cases_cleared} case(s)); cash proven out: {self.payables_cash_proven} ({self.payable_cases_cleared} case(s))." + (f" Net revenue retention {self.net_revenue_retention_percent}%." if self.net_revenue_retention_percent is not None else "") + (f" Runway {self.runway_weeks} week(s)." if self.runway_weeks is not None else ""), f"Exceptions: {self.exceptions_opened} opened, {self.exceptions_resolved_within_sla} resolved within SLA.", ""]
        if self.revenue_by_engine:
            lines.append("## By engine")
            for engine in sorted(set(self.revenue_by_engine) | set(self.spend_by_engine)):
                lines.append(f"- {engine}: revenue {self.revenue_by_engine.get(engine, Decimal('0'))}, spend {self.spend_by_engine.get(engine, Decimal('0'))}")
            lines.append("")
        if self.decisions:
            lines.append("## Decisions")
            lines.extend(f"- {item}" for item in self.decisions)
            lines.append("")
        for section in self.sections:
            lines.append(f"## {section.title}" + (" (synthetic)" if section.synthetic else ""))
            lines.extend(f"- {line}" for line in section.lines)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def _period_docs(periods: Sequence[Mapping[str, Any] | Any]) -> list[dict[str, Any]]:
    out = []
    for item in periods:
        raw = dict(detached(item))
        out.append(dict(raw.get("state") or raw))
    return out


def board_pack(*, company_ref: str, month: str, prepared_at: str, periods: Sequence[Mapping[str, Any] | Any] = (), revenue_cases: Sequence[Any] = (), payable_cases: Sequence[Any] = (), retention: Mapping[str, Any] | None = None, forecast: Mapping[str, Any] | None = None, exceptions: Mapping[str, Any] | None = None, decisions: Sequence[Mapping[str, Any]] = (), evals: Mapping[str, Any] | None = None, chain_sources: Sequence[Mapping[str, Any]] = ()) -> BoardPack:
    """The month from the persisted periods, the chains, retention, treasury, the exceptions desk, and the decisions taken."""

    stamp = timestamp(prepared_at, field_name="prepared_at")
    docs = [doc for doc in _period_docs(periods) if str(dict(doc.get("ledger") or {}).get("period_start", ""))[:7] == month[:7]]
    revenue = spend = Decimal("0")
    rev_by: dict[str, Decimal] = {}
    spend_by: dict[str, Decimal] = {}
    verified = 0
    digests: dict[str, str] = {}
    for doc in docs:
        ledger = dict(doc.get("ledger") or {})
        revenue += Decimal(str(ledger.get("total_revenue", "0")))
        spend += Decimal(str(ledger.get("total_spend", "0")))
        for engine, value in dict(ledger.get("revenue_by_engine") or {}).items():
            rev_by[engine] = rev_by.get(engine, Decimal("0")) + Decimal(str(value))
        for engine, value in dict(ledger.get("spend_by_engine") or {}).items():
            spend_by[engine] = spend_by.get(engine, Decimal("0")) + Decimal(str(value))
        verified += 1 if ledger.get("books_verified") else 0
    digests["periods"] = stable_digest([str(doc.get("state_digest")) for doc in docs])
    cleared = [case for case in revenue_cases if case.status == "receivable_cleared"]
    paid = [case for case in payable_cases if case.status in ("paid", "cleared")]
    cash_in = sum((Decimal(str(case.ledger.settled_amount)) for case in cleared), Decimal("0"))
    cash_out = sum((Decimal(str(case.ledger.applied_amount)) for case in paid), Decimal("0"))
    digests["revenue_cases"] = stable_digest([case.state_digest for case in cleared])
    digests["payable_cases"] = stable_digest([case.state_digest for case in paid])
    margin = None if revenue <= 0 else ((revenue - spend) / revenue * Decimal("100"))
    nrr = None
    if retention is not None:
        raw = dict(detached(retention))
        nrr = raw.get("net_revenue_retention_percent")
        digests["retention"] = stable_digest(raw)
    runway = None
    if forecast is not None:
        raw = dict(detached(forecast))
        runway = raw.get("runway_weeks")
        digests["forecast"] = str(raw.get("forecast_digest") or stable_digest(raw))
    opened = within = 0
    if exceptions is not None:
        raw = dict(detached(exceptions))
        opened = int(raw.get("open", 0) or 0) + int(raw.get("resolved", 0) or 0) + int(raw.get("escalated", 0) or 0) + int(raw.get("expired", 0) or 0)
        within = int(raw.get("resolved_within_sla", 0) or 0)
        digests["exceptions"] = str(raw.get("summary_digest") or stable_digest(raw))
    decision_lines = []
    for item in decisions[:30]:
        raw = dict(detached(item))
        decided = raw.get("decided_option") or raw.get("decided")
        line = f"{raw.get('engine')}.{raw.get('event')} on {raw.get('entity_ref')}: counterfactual recommended {raw.get('recommendation')}"
        if decided:
            line += f"; decided {decided}" + ("" if decided == raw.get("recommendation") else " (overrode the recommendation)")
        decision_lines.append(line)
    sections, chain_digests = _chain_sections(chain_sources, company_ref=company_ref)
    digests.update(chain_digests)
    if evals is not None:
        raw = dict(detached(evals))
        digests["evals"] = str(raw.get("scorecard_digest") or stable_digest(raw))
        sections.append({"title": "How good were the recommendations", "lines": [f"{raw.get('records', 0)} recommendation(s) scored: mean absolute error {raw.get('mean_abs_error_percent')}%, direction right {raw.get('direction_hit_rate_percent')}% of the time, followed {raw.get('followed_rate_percent')}%", f"regret when overridden: {raw.get('override_regret_total')}"], "evidence_refs": [f"evals:{digests['evals'][:16]}"], "synthetic": True})
    pack = {"company_ref": company_ref, "month": month[:7], "prepared_at": stamp, "periods": len(docs), "revenue": str(revenue), "spend": str(spend), "gross_margin_percent": None if margin is None else str(margin), "revenue_by_engine": {key: str(value) for key, value in rev_by.items()}, "spend_by_engine": {key: str(value) for key, value in spend_by.items()}, "books_verified_periods": verified, "revenue_cases_cleared": len(cleared), "revenue_cash_proven": str(cash_in), "payable_cases_cleared": len(paid), "payables_cash_proven": str(cash_out), "net_revenue_retention_percent": nrr, "runway_weeks": runway, "exceptions_opened": opened, "exceptions_resolved_within_sla": within, "decisions": decision_lines, "sections": sections, "source_digests": digests}
    return seal(BoardPack, pack, "pack_digest")


def _chain_sections(sources: Sequence[Mapping[str, Any]], *, company_ref: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    from lightbulb.company_plan_migration import lifecycle_for
    grouped: dict[str, list[str]] = {}
    refs: dict[str, list[str]] = {}
    digests: dict[str, str] = {}
    source_scope: tuple[Any, ...] | None = None
    for item in sources:
        engine = str(item["engine"])
        spec = lifecycle_for(engine).spec
        plan, state = spec.bind(item["source_plan"], item["state"])
        if getattr(plan, "company_ref", company_ref) != company_ref:
            raise ValueError("SCOPE_MISMATCH: the brief source belongs to another company")
        scope = tuple(getattr(state.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))
        if source_scope is not None and source_scope != scope:
            raise ValueError("SCOPE_MISMATCH: all brief sources must share the same company and project scope")
        source_scope = scope
        key = f"{engine}:{state.scope.entity_ref}"
        if key in digests:
            raise ValueError("SOURCE_ALREADY_RECORDED: one chain state per entity in a brief")
        digests[key] = state.state_digest
        ledger = state.ledger.to_dict()
        money = [f"{name} {ledger[name]}" for name in ("amount", "settled_amount", "cash_settled", "net_settled", "attributed_cash_out", "total_cost", "actual_cost", "liability_total", "operating_cash", "company_revenue_reversal", "balance") if name in ledger]
        grouped.setdefault(engine, []).append(f"{state.scope.entity_ref}: {state.status}" + ("; " + ", ".join(money) if money else ""))
        refs.setdefault(engine, []).append(f"state:{state.state_digest}")
    return ([{"title": engine.replace("_", " ").title(), "lines": lines[:60], "evidence_refs": refs[engine][:60]} for engine, lines in sorted(grouped.items())], digests)


BRIEF_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_brief",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["collect_console_documents", "assemble_sections", "seal", "render"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the brief and the pack are assembled from the console's own sealed documents and name their digests",
        "no number is computed that an engine did not already hold; synthetic sections say so",
        "attention items are derived (a breach, a past-SLA exception, a halted period, an overdue obligation), never typed",
    ],
}

__all__ = ["BOARD_PACK_SCHEMA", "BRIEF_MANIFEST", "BRIEF_SCHEMA", "BoardPack", "BriefSection", "OperatorBrief", "board_pack", "daily_brief"]
