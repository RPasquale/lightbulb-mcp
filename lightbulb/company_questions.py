"""Ask: an owner's question, in the owner's words, to the document that answers it.

The console has well over a hundred verbs.  An owner does not know that
"why did profit fall" is the contribution bridge or that "can I afford to
hire" is the cash calendar, and should not have to.  ``match_questions`` maps
a question to the catalogue below by the words it shares with each entry.
The matching is a fixed, inspectable score: a catalogue phrase found whole in
the question counts three, a single catalogue word counts one, ties go to
catalogue order.  No model reads the question, and the same question always
gets the same answer.

Each match names the verb that answers it and, given the company's
readiness, whether that document can be built now and what would unlock it
if not.  A question that shares no word with any entry gets no match and the
catalogue's topics instead, never a guess.  Nothing here reads a provider or
persists anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

QUESTION_CATALOGUE_SCHEMA = "lightbulb.company_question_matches.v1"

# id, the question as an owner would put it, the readiness kind that answers it, and the phrases and words that signal it.
QUESTION_CATALOGUE: tuple[dict[str, Any], ...] = (
    {"id": "how_are_we_doing", "question": "How is the business doing?", "kind": "books_snapshot", "signals": ("how are we doing", "how is the business", "overview", "summary", "health", "snapshot", "books", "profit and loss", "p&l")},
    {"id": "are_we_profitable", "question": "Are we making money?", "kind": "books_snapshot", "signals": ("making money", "profitable", "profit", "net profit", "margin", "loss", "losing money")},
    {"id": "what_is_wrong_with_the_books", "question": "What is missing or wrong in my books?", "kind": "books_snapshot", "signals": ("wrong with my books", "books complete", "missing", "bookkeeping", "suspense", "unreconciled", "accurate")},
    {"id": "how_much_tax_do_we_owe", "question": "How much tax do we owe?", "kind": "books_snapshot", "signals": ("tax", "gst", "vat", "bas", "owe the tax", "tax bill")},
    {"id": "will_we_run_out_of_cash", "question": "Will we run out of cash?", "kind": "cash_calendar", "signals": ("run out of cash", "run out of money", "cash flow", "cashflow", "runway", "make payroll", "afford", "13 week", "next quarter", "cash")},
    {"id": "can_we_afford_it", "question": "Can we afford this hire or purchase?", "kind": "cash_calendar", "signals": ("can we afford", "can i afford", "afford to hire", "afford", "spend")},
    {"id": "what_is_our_break_even", "question": "How much do we need to sell to break even?", "kind": "break_even", "signals": ("break even", "break-even", "breakeven", "cover our costs", "fixed costs", "how much do we need to sell", "margin of safety")},
    {"id": "where_is_cash_tied_up", "question": "Where is our cash tied up?", "kind": "working_capital", "signals": ("cash tied up", "working capital", "free up cash", "owed to us", "receivables", "debtors", "days to get paid", "getting paid", "payables", "creditors", "cash conversion")},
    {"id": "which_products_make_money", "question": "Which products make money?", "kind": "product_margin", "signals": ("which products make money", "product margin", "products", "sku", "best sellers", "landed cost", "contribution per product")},
    {"id": "what_should_we_stop_selling", "question": "What should we grow, fix or stop selling?", "kind": "product_portfolio", "signals": ("stop selling", "discontinue", "portfolio", "range", "what to grow", "overstock", "slow movers")},
    {"id": "should_we_change_prices", "question": "Should we change our prices?", "kind": "price_probes", "signals": ("change our prices", "raise prices", "price increase", "pricing", "price", "discount")},
    {"id": "why_did_profit_change", "question": "Why did profit change from last period?", "kind": "contribution_bridge", "signals": ("why did profit", "why did margin", "profit fall", "profit drop", "what changed", "versus last month", "compared to last", "bridge")},
    {"id": "which_customers_make_money", "question": "Which customers make money and which cost us?", "kind": "customer_profitability", "signals": ("which customers make money", "customer profitability", "unprofitable customers", "cost to serve")},
    {"id": "who_are_our_customers", "question": "Who are our biggest customers, and who owes us?", "kind": "customer_ledger", "signals": ("biggest customers", "best customers", "who owes us", "who owes", "customers", "concentration", "depend on one customer", "slow payers", "late payers", "overdue invoices")},
    {"id": "do_customers_come_back", "question": "Do customers come back, and what is a new one worth?", "kind": "customer_cohorts", "signals": ("come back", "repeat", "retention", "cohort", "lifetime value", "ltv", "payback", "acquisition cost", "cac")},
    {"id": "what_did_stockouts_cost", "question": "What did running out of stock cost us?", "kind": "stockouts", "signals": ("out of stock", "stockout", "stock outs", "ran out", "lost sales", "reorder point")},
    {"id": "what_do_returns_cost", "question": "What do returns cost us?", "kind": "returns_ledger", "signals": ("returns", "refunds", "return rate", "returned")},
    {"id": "what_stock_should_we_buy", "question": "What stock should we buy, and can we fund it?", "kind": "open_to_buy", "signals": ("what stock should we buy", "open to buy", "reorder", "purchase order", "buy stock", "inventory to buy")},
    {"id": "how_are_suppliers_doing", "question": "Which suppliers are letting us down?", "kind": "supplier_scorecard", "signals": ("suppliers", "supplier", "vendor performance", "late deliveries", "lead time")},
    {"id": "which_jobs_make_money", "question": "Which jobs and clients make money?", "kind": "services_margin", "signals": ("which jobs make money", "engagement margin", "services margin", "billable", "utilisation", "utilization", "projects make money")},
    {"id": "did_the_job_cost_what_we_quoted", "question": "Did the job cost what we quoted?", "kind": "job_costing", "signals": ("job cost", "job costing", "over budget", "overran", "quoted", "estimate versus actual", "actual cost")},
    {"id": "what_should_we_charge", "question": "What should we charge for our people's time?", "kind": "rate_card", "signals": ("what should we charge", "hourly rate", "day rate", "rate card", "bill rate", "charge out", "charge-out")},
    {"id": "who_can_do_this_job", "question": "Who has the skills for this job?", "kind": "skills_match", "signals": ("who can do", "who has the skills", "skills for", "staff the job", "assign", "right person", "qualified", "licence", "license")},
    {"id": "who_does_what_this_week", "question": "Who works on which job, without double-booking anyone?", "kind": "job_assignment", "signals": ("who works on", "double book", "double-book", "roster", "schedule the jobs", "allocate", "assignment", "staff all the jobs", "everyone booked")},
    {"id": "how_are_we_trending", "question": "How are we trending?", "kind": "intelligence_history", "signals": ("trend", "trending", "over time", "month on month", "quarter on quarter", "getting better", "getting worse", "compared to last", "history", "track record", "direction")},
    {"id": "are_the_thresholds_right", "question": "Are our thresholds set right for us?", "kind": "threshold_calibration", "signals": ("threshold", "thresholds", "calibrate", "too sensitive", "false alarm", "flagging everything", "set right", "tolerance", "our own normal")},
    {"id": "where_are_we_thin", "question": "Where are we one person deep, and whose licences lapse?", "kind": "skills_inventory", "signals": ("one person deep", "key person", "single point of failure", "licences lapse", "skills gap", "skills inventory", "bench strength")},
    {"id": "do_we_have_the_capacity", "question": "Do we have the people for the work coming?", "kind": "workforce_capacity", "signals": ("capacity", "enough people", "overbooked", "bench", "hours available", "workload")},
    {"id": "hire_contract_or_train", "question": "Should we hire, contract or train for this gap?", "kind": "labour_sourcing", "signals": ("hire or contract", "should we hire", "contractor or employee", "subcontract", "sourcing", "recruit", "hire")},
    {"id": "who_should_we_train", "question": "Who should we train, and in what?", "kind": "skills_development", "signals": ("train", "training", "upskill", "develop", "apprentice", "renew the licence")},
    {"id": "what_should_we_quote", "question": "What should we quote for this job?", "kind": "job_quotes", "signals": ("what should we quote", "quote for", "price this job", "quote", "tender", "bid")},
    {"id": "what_if_we_raise_prices", "question": "What happens if we raise prices?", "kind": "company_scenario", "signals": ("what if", "what happens if", "if we raise", "if we hire", "if we lose", "if we cut", "scenario", "model it", "would happen")},
    {"id": "do_the_numbers_agree", "question": "Do our sales numbers agree with the books?", "kind": "ledger_tie_out", "signals": ("agree with the books", "reconcile", "tie out", "tie-out", "match the books", "match the accountant", "discrepancy", "numbers agree")},
    {"id": "is_the_pipeline_enough", "question": "Is there enough in the pipeline to hit the target?", "kind": "pipeline_coverage", "signals": ("pipeline", "enough deals", "hit the target", "sales target", "coverage", "forecast sales")},
)
# documents declared in lightbulb.document_registry bring their own questions
from lightbulb.document_registry import question_entries as _registered_questions  # noqa: E402

QUESTION_CATALOGUE = QUESTION_CATALOGUE + tuple(_registered_questions())

_WORD = re.compile(r"[a-z0-9&]+")
_STOP = frozenset({"the", "a", "an", "is", "are", "we", "our", "my", "i", "do", "does", "did", "to", "of", "for", "in", "on", "and", "or", "what", "which", "how", "much", "many", "us", "it", "this", "that", "be", "will", "should", "can", "have", "has", "with", "from", "at", "me", "you"})


def _words(text: str) -> list[str]:
    out = []
    for word in _WORD.findall(str(text).casefold()):
        if word in _STOP:
            continue
        out.append(word[:-1] if len(word) > 3 and word.endswith("s") and not word.endswith("ss") else word)
    return out


def match_questions(question: str, *, readiness: Mapping[str, Any] | Any | None = None, limit: int = 3) -> dict[str, Any]:
    """The catalogue entries a question shares the most with, best first, each with its verb and, when readiness is given, whether it can be answered now."""

    text = " ".join(str(question or "").casefold().split())
    if not text:
        raise ValueError("QUESTION_EMPTY: ask a question")
    asked = set(_words(text))
    rows: dict[str, Any] = {}
    if readiness is not None:
        from lightbulb.intelligence_readiness import verify_intelligence_readiness

        rows = {row.kind: row for row in verify_intelligence_readiness(readiness).rows}
    from lightbulb.intelligence_readiness import DOCUMENT_REQUIREMENTS

    scored: list[tuple[int, int, dict[str, Any]]] = []
    for index, entry in enumerate(QUESTION_CATALOGUE):
        score = 0
        hits: list[str] = []
        for signal in entry["signals"]:
            if " " in signal or "-" in signal:
                if signal in text:
                    score += 3
                    hits.append(signal)
            elif set(_words(signal)) <= asked:
                score += 1
                hits.append(signal)
        if score:
            scored.append((-score, index, {**entry, "score": score, "matched_on": hits}))
    scored.sort(key=lambda item: (item[0], item[1]))
    matches = []
    for _negative, _index, entry in scored[: max(1, min(int(limit), 10))]:
        row = rows.get(entry["kind"])
        matches.append({"id": entry["id"], "question": entry["question"], "kind": entry["kind"], "verb": DOCUMENT_REQUIREMENTS[entry["kind"]]["verb"], "score": entry["score"], "matched_on": entry["matched_on"], "status": None if row is None else row.status, "basis": None if row is None else row.basis, "next_step": None if row is None else row.next_step})
    return {"schema": QUESTION_CATALOGUE_SCHEMA, "asked": text[:300], "matches": matches, "topics": [] if matches else [entry["question"] for entry in QUESTION_CATALOGUE]}


__all__ = ["QUESTION_CATALOGUE", "QUESTION_CATALOGUE_SCHEMA", "match_questions"]
