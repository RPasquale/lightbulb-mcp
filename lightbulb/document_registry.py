"""One declaration per intelligence document, and every integration point wired from it.

Adding a document used to mean editing about fifteen places by hand: the
console verb, the dispatch branch and its payload check, the MCP tool, the
operator and owner profiles, the readiness requirements, the ask
catalogue, the company reference and the count pins.  Each was a chance to
drift.  A ``Document`` here states all of it once:

* ``engine`` and ``verb`` become a ``CHAIN_VERBS`` entry, so
  ``console.chain(verb, ...)`` reaches it;
* ``operations`` map each operation name to a builder (a
  ``module:function`` path, imported only when called) with the payload
  keys it accepts and requires, so the dispatch and its refusal message
  come from one place;
* ``tool`` and ``tool_description`` register the ``company_<verb>`` MCP
  tool in the operator profile, and in the owner profile when ``owner``;
* ``readiness`` and ``questions`` extend the readiness requirements and
  the ask catalogue;
* ``reference_module`` is listed in the company reference.

Builders keep their own logic; the registry only wires them.  Documents
written before the registry keep their hand wiring.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class Operation:
    """One operation on a document: the builder it calls and the payload it takes."""

    builder: str
    accepts: frozenset[str] = frozenset()
    requires: frozenset[str] = frozenset()

    def call(self) -> Callable[..., dict[str, Any]]:
        module, _, name = self.builder.partition(":")
        return getattr(importlib.import_module(module), name)


@dataclass(frozen=True)
class Document:
    engine: str
    verb: str
    tool_description: str
    usage: str
    operations: Mapping[str, Operation]
    default_operation: str = "build"
    owner: bool = False
    readiness: Mapping[str, Any] | None = None
    questions: tuple[Mapping[str, Any], ...] = ()
    reference_module: str | None = None
    aliases: Mapping[str, str] = field(default_factory=dict)

    @property
    def tool(self) -> str:
        return f"company_{self.verb}"


def _op(builder: str, accepts: tuple[str, ...] = (), requires: tuple[str, ...] = ()) -> Operation:
    return Operation(builder=builder, accepts=frozenset(accepts) | frozenset(requires), requires=frozenset(requires))


_SURFACE = "lightbulb.company_operator_surface"

DOCUMENTS: tuple[Document, ...] = (
    Document(
        engine="books_backfill",
        verb="backfill",
        default_operation="plan",
        owner=True,
        reference_module="lightbulb.books_backfill",
        usage="backfill takes plan (months, balance_sheets, provider) or record (sources: the monthly reads, and optionally the plan they answer)",
        operations={
            "plan": _op(f"{_SURFACE}:plan_books_backfill_document", ("months", "balance_sheets", "provider")),
            "record": _op(f"{_SURFACE}:record_books_backfill", ("plan",), ("sources",)),
        },
        aliases={"build": "record"},
        readiness={"plans": ("books_snapshot",), "chains": (), "books": None, "connectors": ("xero", "quickbooks"), "input": "the monthly ledger reads the backfill plan lists"},
        questions=({"id": "fill_in_our_past", "question": "Can you look at our past months, not just this one?", "signals": ("past months", "last year", "last 12 months", "previous months", "back history", "backfill", "fill in", "history from", "since we started", "compared to last year")},),
        tool_description="Recover the company's past months so trends, warnings, calibrated thresholds and break-even work on day one. plan (payload months default 12, balance_sheets default true): the exact ledger reads to make, one profit and loss read per complete calendar month and one balance sheet at each month end, oldest first. record (payload sources: every read's {kind, provenance, payload}, and optionally the plan): each month is built only from the reports that state that month, persisted under its window (a re-read amends it by one version), months before the ledger's first activity are skipped, a month the books refuse is named with its reason, planned months with no read are listed, and the history across everything on record comes back. Deterministic; reads no provider itself.",
    ),
    Document(
        engine="owner_digest",
        verb="digest",
        owner=True,
        reference_module="lightbulb.owner_digest",
        usage="the digest takes an optional channel (email or slack) and recipient_ref (an opaque reference the platform resolves, never an address)",
        operations={"build": _op(f"{_SURFACE}:build_owner_digest_document", ("channel", "recipient_ref"))},
        aliases={"summary": "build", "list": "build"},
        readiness={"plans": ("books_snapshot",), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
        questions=({"id": "what_do_i_need_to_know", "question": "What do I need to know this week?", "signals": ("this week", "need to know", "catch me up", "update me", "what matters", "brief me", "digest", "what should i do", "what's important", "monday")},),
        tool_description="The owner's weekly digest in plain words: how the last month went against the one before, the figures that matter with their change, the three actions worth doing this week ranked by the money at stake (each keyed to the review's action so it can be accepted, deferred or declined with company_review_decisions), what has moved the wrong way three months running, what the books leave out, and what cannot be said yet and why. Built from the recorded books, history, cash calendar, latest weekly review and open decisions; every sentence is a fixed template over a sealed figure. payload: optional channel (email|slack) and recipient_ref (an opaque reference, never an address) returns the approval-gated send the platform would make; nothing is sent here.",
    ),
    Document(
        engine="books_hygiene",
        verb="hygiene",
        owner=True,
        reference_module="lightbulb.books_hygiene",
        usage="hygiene takes an optional bank_transactions read ({provenance, payload} from xero.list_bank_transactions)",
        operations={"build": _op(f"{_SURFACE}:build_books_hygiene_document", ("bank_transactions",))},
        aliases={"summary": "build", "list": "build"},
        readiness={"plans": ("books_snapshot",), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
        questions=({"id": "can_i_trust_these_numbers", "question": "Can I trust these numbers?", "signals": ("trust these numbers", "books right", "books up to date", "bookkeeping", "reconcile", "reconciled", "suspense", "uncategorised", "uncategorized", "missing costs", "clean up my books")},),
        tool_description="Where the owner's books make the numbers weaker than they look, in plain words with the fix: months that record sales and no costs, no wages or contractor costs in any month, money parked in suspense or uncategorised accounts, tax owed that the cash does not cover, and (with payload bank_transactions, a xero.list_bank_transactions read) bank lines over 30 days old and not reconciled. Reads every month on record; says what it could not check; grades trust good, fair or weak from the findings. Deterministic; reads and changes nothing.",
    ),
    Document(
        engine="worked_hours",
        verb="worked_hours",
        reference_module="lightbulb.worked_hours",
        usage="worked_hours takes timesheets (a xero.observe_timesheets read: {provenance, payload}), profiles (else the team recorded from payroll), and an optional tolerance_percent",
        operations={"build": _op(f"{_SURFACE}:build_worked_hours_document", ("tolerance_percent", "profiles"), ("timesheets",))},
        readiness={"plans": (), "chains": (), "books": None, "connectors": ("xero",), "input": "the payroll timesheets read and the worker profiles (else the team recorded from payroll)"},
        questions=({"id": "are_people_working_the_hours_we_plan", "question": "Are people working the hours we plan with?", "signals": ("overtime", "hours worked", "timesheets", "overworked", "burnout", "underused", "bench", "actual hours", "working too much")},),
        tool_description="What the timesheets say people actually worked, beside the weekly hours every staffing document plans with: reads the governed xero.observe_timesheets page (payload timesheets: {provenance, payload}) and the worker profiles, counts approved and processed hours per worker, and marks each over, under, as planned, unprofiled or without a timesheet, with a proposed hours_per_week where they part (proposals only). Workers join by the payroll commitment worker:<sha[:24]>; no identity is read. Deterministic.",
    ),
    Document(
        engine="payroll_team",
        verb="team",
        default_operation="show",
        owner=True,
        reference_module="lightbulb.payroll_team",
        usage="team takes show; build or record (headcount: a xero.observe_headcount read {provenance, payload}; payruns: xero.observe_payrun reads; timesheets: xero.observe_timesheets reads; and optionally basis_by_worker {worker_ref: full_time|part_time|casual}, hours_by_worker {worker_ref: weekly hours}, on_cost_percent, profiles)",
        operations={
            "show": _op(f"{_SURFACE}:show_payroll_team_document"),
            "build": _op(f"{_SURFACE}:build_payroll_team_document", ("payruns", "timesheets", "basis_by_worker", "hours_by_worker", "on_cost_percent", "profiles"), ("headcount",)),
            "record": _op(f"{_SURFACE}:record_payroll_team", ("payruns", "timesheets", "basis_by_worker", "hours_by_worker", "on_cost_percent", "profiles"), ("headcount",)),
        },
        aliases={"list": "show", "summary": "show"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": ("xero",), "input": "the governed payroll reads: the headcount page, the posted pay runs and the timesheet pages"},
        questions=({"id": "who_works_here_and_what_does_an_hour_cost", "question": "Who works here, and what does an hour of their time cost?", "signals": ("who works here", "our team", "staff cost", "cost of an hour", "cost per hour", "hourly cost", "payroll cost", "what do our people cost", "labour cost per hour", "headcount")},),
        tool_description="The team as the payroll records it, from the governed Xero Payroll AU pages whose identities are already sha256 commitments (no name, tax number, bank account or address reaches the SDK). build or record (payload headcount: a xero.observe_headcount read; payruns: xero.observe_payrun reads; timesheets: xero.observe_timesheets reads): every worker as worker:<sha[:24]>, active or left, the hours the approved timesheets show and their weekly average, and the cost of an hour (the wages and super the posted pay runs paid over the timesheet hours in the same pay periods, plus the on_cost_percent the owner states); a salaried worker is costed only on the weekly hours the owner states in hours_by_worker; the employment basis is the owner's to state in basis_by_worker. Each active worker with both figures gets a worker profile (employee, hours, cost rate, available from the start date) that skills, assignment, capacity, sourcing, quotes and worked hours use when no profiles are passed, and job costing prices each job's labour at; skills are carried over from the profiles given, never read from payroll. record keeps the team (a changed team amends it by one version); show returns the recorded team. QuickBooks payroll reads carry names and are refused until the platform observes them. Deterministic; reads no provider itself.",
    ),
    Document(
        engine="market_rates",
        verb="market_rates",
        reference_module="lightbulb.market_rates",
        usage="market_rates takes skills_by_contractor ({contractor_ref: skill_ref}) and an optional max_age_days, tolerance_percent and hours_per_day",
        operations={"build": _op(f"{_SURFACE}:build_market_rates_document", ("max_age_days", "tolerance_percent", "hours_per_day"), ("skills_by_contractor",))},
        readiness={"plans": ("labour_sourcing",), "chains": ("contractor_chain",), "books": None, "connectors": (), "input": None},
        questions=({"id": "what_do_contractors_really_cost", "question": "What do contractors really cost us?", "signals": ("market rate", "contractor rate", "going rate", "what do contractors cost", "paying contractors", "rate we pay", "hourly rate")},),
        tool_description="Market rates from what the company actually paid: realised hourly rates per skill from every contractor engagement with money paid (value over units; day rates over the stated hours per day; deliverable rates listed, never guessed), grouped by the skill named per contractor (payload skills_by_contractor), with median, low, high and latest payment beside the rate the sourcing plan types. Observations older than max_age_days (default 180) are left out; a proposed rate is returned where the median departs from the plan by more than the tolerance (proposals only). Deterministic; reads the persisted contractor chain.",
    ),
    Document(
        engine="sourcing_hand_offs",
        verb="hand_offs",
        owner=True,
        reference_module="lightbulb.sourcing_hand_offs",
        usage="hand_offs takes sourcing (the sealed labour sourcing document) and an optional budget_envelope for the hiring plan",
        operations={"build": _op(f"{_SURFACE}:build_sourcing_hand_offs_document", ("budget_envelope",), ("sourcing",))},
        readiness={"plans": ("labour_sourcing",), "chains": (), "books": None, "connectors": (), "input": "the labour sourcing document the owner decided on"},
        questions=({"id": "what_next_for_the_hire", "question": "I said yes to hiring or a contractor, what happens next?", "signals": ("next step for the hire", "open the requisition", "start hiring", "engage a contractor", "hand off", "hand-off", "draft the requisition")},),
        tool_description="Drafts the paperwork for every sourcing route the owner accepted: an accepted hire or requisition becomes the hiring chain's own opening receipt (built by headcount_receipt from the role, heads and banded rate the sourcing document chose, the decision's owner as requester), and an accepted contract becomes a brief for the contractor chain (skill, level, rate ceiling, monthly cap, end date, and the agreement step still needed). Routes deferred, declined or undecided are listed as waiting; a hire the hiring plan cannot fund is drafted as blocked with the chain's reason. Nothing is opened, persisted or sent.",
    ),
    Document(
        engine="owner_mandate",
        verb="mandate",
        default_operation="show",
        owner=True,
        reference_module="lightbulb.owner_mandate",
        usage="mandate takes show; set (owner_ref, rules [{action_kind, autonomy, cap_per_action?, note?}], monthly_envelope, default_autonomy, months_valid); check (action_kind, money, subject); record (decision, tool, effect_ref, note)",
        operations={
            "show": _op(f"{_SURFACE}:build_mandate_document"),
            "set": _op(f"{_SURFACE}:set_mandate", ("rules", "default_autonomy", "monthly_envelope", "months_valid"), ("owner_ref",)),
            "check": _op(f"{_SURFACE}:check_mandate", ("money", "subject"), ("action_kind",)),
            "record": _op(f"{_SURFACE}:record_mandate_action", ("tool", "effect_ref", "note"), ("decision",)),
        },
        aliases={"build": "show", "list": "show"},
        readiness={"plans": ("mandate",), "chains": (), "books": None, "connectors": (), "input": None},
        questions=({"id": "what_may_the_agent_do_alone", "question": "What may the agent do without asking me?", "signals": ("without asking", "on my behalf", "mandate", "autonomy", "may the agent", "allowed to", "permission to act", "standing instruction")},),
        tool_description="The owner's standing mandate for an agent running the company: per kind of action (chase overdue invoices, pay bills, reorder stock, change prices, open a requisition, spend on marketing...) whether the agent acts alone, asks, or never does it, a cap per action, a monthly envelope for everything done alone, and a renewal date; reads never need one. show: the mandate with this month's unattended actions and what is left of the envelope. set: seal a new mandate into the bundle (payload owner_ref, rules, monthly_envelope, default_autonomy ask|never, months_valid). check: one action through the gate (payload action_kind, money, subject) returns act, ask or never with the reason. record: log an action taken alone (payload decision from check, tool, effect_ref, note). Deterministic; executes nothing.",
    ),
    Document(
        engine="operating_loop",
        verb="next",
        owner=True,
        reference_module="lightbulb.operating_loop",
        usage="next takes no payload",
        operations={"build": _op(f"{_SURFACE}:build_operating_step_document")},
        aliases={"list": "build", "summary": "build"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": None},
        questions=({"id": "what_should_i_do_next", "question": "What should I do next?", "signals": ("do next", "what next", "next step", "where do i start", "start here", "what should i do", "priorities", "to do list", "todo")},),
        tool_description="What to do next, for an agent running the company: every open thread the recorded documents hold (the weekly review's undecided actions, the decisions the owner accepted and their due dates, stale books, the books' hygiene findings, the digest that is due) as one queue, each with the tool to call, the effect to verify afterwards, and the mandate's answer (act alone, ask the owner, never), ranked by urgency and the money at stake. Opens with a briefing (cash, revenue, what is open and overdue, the books' trust) and the last session's journal with its promises checked against the documents. Read it, do the head of the queue, record what you did with company_journal, and call it again. Deterministic; executes nothing.",
    ),
    Document(
        engine="operator_journal",
        verb="journal",
        default_operation="list",
        owner=True,
        reference_module="lightbulb.operating_loop",
        usage="journal takes list, or record (agent_ref, handover, did [{key, result}], promised [{check, subject}], step_digest)",
        operations={
            "list": _op(f"{_SURFACE}:list_operator_journals"),
            "record": _op(f"{_SURFACE}:record_operator_journal", ("did", "promised", "step_digest"), ("agent_ref", "handover")),
        },
        aliases={"build": "list"},
        tool_description="The agents' journal: each session records what it did (the keys it acted on and the results), what it promised to check next time (check: customer_paid|books_recorded|..., subject), and a handover in its own words; the next session's company_next opens with it and checks the promises it can. record: one entry per session (payload agent_ref, handover, did, promised, step_digest). list: every entry, newest first.",
    ),
    Document(
        engine="growth_goals",
        verb="goals",
        default_operation="progress",
        owner=True,
        reference_module="lightbulb.growth_goals",
        usage="goals takes set (goal_ref, metric revenue|net_profit, target_growth_percent, horizon_months, mix {driver: percent}), progress (goal_ref optional) or list",
        operations={
            "set": _op(f"{_SURFACE}:set_growth_goal_document", ("metric", "target_growth_percent", "horizon_months", "mix"), ("goal_ref",)),
            "progress": _op(f"{_SURFACE}:build_goal_progress_document", ("goal_ref",)),
            "list": _op(f"{_SURFACE}:list_growth_goals"),
        },
        aliases={"build": "progress", "summary": "progress"},
        readiness={"plans": (), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
        questions=({"id": "how_do_we_grow_30_percent", "question": "What would it take to grow 30%?", "signals": ("grow 30", "grow by", "growth target", "what would it take", "double the business", "growth goal", "hit the target", "revenue target")},),
        tool_description="The owner's growth goal as arithmetic from the recorded books: set (payload goal_ref, metric revenue|net_profit, target_growth_percent, horizon_months, optional mix) seals the baseline run rate per month, the run rate the horizon needs, the gap, and the drivers that must close it (customers x revenue per customer when a customer ledger is recorded; revenue x net margin for a net result goal), each with its target and the documents that move it. progress puts each driver's latest recorded value beside its target and where a straight line to the horizon would put it. Nothing is forecast; deterministic.",
    ),
    Document(
        engine="growth_bets",
        verb="bets",
        default_operation="judge",
        owner=True,
        reference_module="lightbulb.growth_bets",
        usage="bets takes place (bet_ref, driver, hypothesis, metric, target, spend_cap, baseline?, horizon_months, kill_drop_percent, kill_after_windows, goal_ref) or judge",
        operations={
            "place": _op(f"{_SURFACE}:place_growth_bet", ("baseline", "horizon_months", "kill_drop_percent", "kill_after_windows", "goal_ref"), ("bet_ref", "driver", "hypothesis", "metric", "target", "spend_cap")),
            "judge": _op(f"{_SURFACE}:judge_growth_bets"),
        },
        aliases={"build": "judge", "list": "judge", "summary": "judge"},
        readiness={"plans": (), "chains": (), "books": "recorded", "connectors": ("xero", "quickbooks"), "input": None},
        questions=({"id": "is_the_bet_working", "question": "Is the experiment working?", "signals": ("experiment working", "is it working", "the bet", "scale it", "kill it", "keep spending", "stop spending", "did it work")},),
        tool_description="Growth bets an agent runs to hit the goal, each preregistered before money moves: the hypothesis, the driver, the spend cap (the mandate's spend_marketing rule says whether the agent may commit it alone), the one history metric that judges it, baseline, target, horizon and kill rule. place records one; judge reads every bet against the recorded history and returns scale (target reached), kill (the kill rule fired, or the horizon passed without movement), extend (horizon passed but moving the right way) or running, with the reason. Verdicts are proposals; deterministic; spends nothing.",
    ),
    Document(
        engine="company_gym",
        verb="gym",
        default_operation="run",
        reference_module="lightbulb.company_gym",
        usage="gym takes run (scenario: a standard name or a full scenario, operator do_nothing|mandate|autopilot, months, overrides)",
        operations={"run": _op(f"{_SURFACE}:run_gym_document", ("scenario", "operator", "months", "overrides"))},
        aliases={"build": "run", "list": "run"},
        tool_description="The company gym: a synthetic small business (standard scenarios services_steady, cash_squeeze, growth_push, or a full scenario) run for simulated months through the real console, mandate and next step, with a built-in operator (do_nothing; mandate: does what next puts in front of it when the mandate lets it act alone; or autopilot: the real autopilot, turned on by the gym's owner, one tick a month through a platform that sends what the mandate lets it send alone and holds the rest for an approval that never comes). Every month the gym renders the books, balance sheet and invoice pages in the ledger's shapes, records them, asks the operator, passes each action through the mandate (refusing and counting what it does not cover), and applies the effects. Returns the sealed report: sales growth, cash and its low point, overdue at the end, actions by kind, violations, a score and a verdict; the same scenario and operator always give the same digest. Runs in its own in-memory company; this project is untouched.",
    ),
    Document(
        engine="collections_loop",
        verb="chase",
        owner=True,
        reference_module="lightbulb.collections_loop",
        usage="chase takes build (no payload) or outcomes",
        operations={"build": _op(f"{_SURFACE}:build_chase_plan_document"), "outcomes": _op(f"{_SURFACE}:build_chase_outcomes_document")},
        aliases={"list": "build", "summary": "build", "plan": "build"},
        readiness={"plans": ("customer_ledger",), "chains": (), "books": None, "connectors": ("xero", "quickbooks"), "input": None},
        questions=({"id": "who_do_i_chase_today", "question": "Who do I chase for money today?", "signals": ("chase", "reminder", "overdue invoice", "who owes", "get paid", "collect", "late payer", "send a reminder")},),
        tool_description="The get-paid loop. build: for every customer the recorded ledgers flag overdue, the reminder due now under the collections ladder (never a rung already sent, never sooner than its lead time), the message drafted from a fixed template, the mandate's answer (act alone, ask, never; a rung the plan marks for approval always asks), the send the platform would make (capability, opaque recipient_ref, subject, text) and exactly how to record it with company_mandate record once sent. outcomes: every reminder in the mandate log against the customer's overdue as the ledgers stand now: recovered, days since, and the recovery rate. Sends nothing; deterministic.",
    ),
    Document(
        engine="owner_action",
        verb="act",
        default_operation="list",
        owner=True,
        reference_module="lightbulb.owner_actions",
        usage="act takes list; plan (optionally digest_channel in_app, or email|slack with digest_recipient_ref, and hand_offs: a sealed hand-offs document); dispatch (connector_account_refs {tool: account ref}, optionally action_refs); decline (action_ref, reason, optionally owner_ref)",
        operations={
            "list": _op("lightbulb.company_act_surface:list_owner_actions_document"),
            "plan": _op("lightbulb.company_act_surface:plan_owner_actions_document", ("digest_channel", "digest_recipient_ref", "hand_offs")),
            "dispatch": _op("lightbulb.company_act_surface:dispatch_owner_actions_document", ("connector_account_refs", "action_refs")),
            "decline": _op("lightbulb.company_act_surface:decline_owner_action_document", ("owner_ref",), ("action_ref", "reason")),
        },
        aliases={"summary": "list", "build": "list"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": "the reminders due, the week's digest or the accepted hand-offs, and the project's connector accounts to send through"},
        questions=({"id": "what_has_been_sent", "question": "What has the agent sent or opened for me, and what is waiting on me?", "signals": ("what was sent", "waiting on me", "pending approval", "did you send", "sent reminders", "what did the agent do")},),
        tool_description="The act half of the owner loop: one durable record per effect, sent once. plan: records an action for every reminder due now (keyed by customer and rung, so a rung is never sent twice), for the week's digest (digest_channel in_app delivers it to the owner inside the platform, nothing leaves it; email or slack need digest_recipient_ref, an opaque reference, never an address), and for each hand-off in a supplied sealed hand-offs document (a hire opens the hiring chain on the owner's accepted decision; a contract waits on an agreement). dispatch: asks the mandate again (never stops it), then sends each open message through Governed Connector Execution with the action's own idempotency key (the platform asks the owner, answers pending_approval with the approval reference, and sends once when dispatched again after approval) and opens each hire; records the receipt, and logs sends made under act in the mandate log. connector_account_refs maps each tool (gmail.send_email, slack.post_message) to the project's exact account reference. decline: closes an action for good with the owner's reason. list: every action and its status.",
    ),
    Document(
        engine="company_autopilot",
        verb="autopilot",
        default_operation="status",
        owner=True,
        reference_module="lightbulb.company_autopilot",
        usage="autopilot takes status; start (owner_ref, and optionally days, reason and the limits tick_every_hours, max_actions_per_tick, max_actions_per_day, contact_cooldown_days, max_failures_in_a_row, read_books, send_digest); pause (reason, optionally by); resume (owner_ref, optionally reason); stop (reason, optionally by and withdraw); tick (optionally connector_account_refs); ticks (optionally limit)",
        operations={
            "status": _op("lightbulb.company_autopilot:autopilot_status_document"),
            "start": _op("lightbulb.company_autopilot:start_autopilot", ("days", "reason", "tick_every_hours", "max_actions_per_tick", "max_actions_per_day", "contact_cooldown_days", "max_failures_in_a_row", "read_books", "send_digest"), ("owner_ref",)),
            "pause": _op("lightbulb.company_autopilot:pause_autopilot", ("by",), ("reason",)),
            "resume": _op("lightbulb.company_autopilot:resume_autopilot", ("reason",), ("owner_ref",)),
            "stop": _op("lightbulb.company_autopilot:stop_autopilot", ("by", "withdraw"), ("reason",)),
            "tick": _op("lightbulb.company_autopilot:run_autopilot_tick", ("connector_account_refs",)),
            "ticks": _op("lightbulb.company_autopilot:list_autopilot_ticks", ("limit",)),
        },
        aliases={"build": "status", "list": "status", "summary": "status", "off": "stop", "history": "ticks"},
        readiness={"plans": ("mandate",), "chains": (), "books": None, "connectors": (), "input": "the owner's decision to turn it on, for how many days and within which limits"},
        questions=(
            {"id": "run_the_company_for_me", "question": "Can you run the company for me?", "signals": ("run the company for me", "autopilot", "run it for me", "on autopilot", "run on its own", "run the business for me", "hands off")},
            {"id": "what_runs_on_its_own", "question": "What is running on its own, and how do I stop it?", "signals": ("running on its own", "stop the agent", "turn it off", "switch it off", "kill switch", "stop everything", "what is running")},
        ),
        tool_description="The autopilot: the one loop that runs the company on a heartbeat, under a switch only the owner turns on. It is off until the mandate's owner starts it (payload owner_ref, days up to 90 and never past the mandate, and the limits), and then switches itself off when that grant ends. Anyone may pause or stop it (stop with withdraw true also withdraws every action still queued); only the owner resumes or starts it again; it pauses itself after failures in a row and never turns itself on. It creates no schedules or other loops: each tick works out what is due from the recorded documents (next), reads the books when they are stale and the host holds read accounts, plans the reminders and the week's in-app digest that are due and hands them to the platform (which still asks the owner before any write reaches a customer), answers its turn in exchanges with other businesses (quotes, order acknowledgements, orders; company_exchange) under the mandate, within a cap per tick and per day, one message per person per cooldown and one open request per person, re-reading the switch before every effect; then tells the owner once what needs them, writes the journal and seals the tick. One tick per interval however often it is called, one at a time. status: the switch, who set it and why, the grant, the limits and today's use, the recent ticks, what is queued, what waits on the owner, and how to stop it. tick: one pass (payload connector_account_refs {tool: account ref}). ticks: the sealed ticks, newest first.",
    ),
    Document(
        engine="commercial_exchange",
        verb="exchange",
        default_operation="status",
        owner=True,
        reference_module="lightbulb.company_exchange",
        usage="exchange takes status; card (optionally party_ref, display_name, contact_ref, terms_days, quote_valid_days, about: what the company does, keywords: the words it is found by, offer_names {item_ref: name}); receive (document); request (to_party, lines [{item_ref, quantity, unit?}], optionally needed_by, reply_by, exchange_ref, owner_ref, currency: the seller's, from its card); quote (exchange_ref, optionally valid_days, terms_days, owner_ref); order (exchange_ref, optionally owner_ref); acknowledge (exchange_ref, optionally accept, reason, owner_ref); invoice (exchange_ref, optionally owner_ref); remit (exchange_ref, optionally paid_at, payment_reference, owner_ref): tell the seller its invoice is paid, alone once the books show it paid; send (exchange_ref, optionally owner_ref, delivered_by_hand); withdraw (exchange_ref, reason); directory (optionally visibility platform or public, listed true to be found by search or false); find (address); search (query: what this company needs, optionally currency, country, kind plan, sku, service or rate, limit): listed companies that sell it, each with its track record; record: this company's track record as other companies see it; source (query and quantity, optionally unit, kind, currency, country, needed_by, reply_by, max_unit_price, budget, suppliers up to 5, for_ref; or sourcing_ref with owner_ref to approve a shortlist): find suppliers, ask each for a quote under the mandate, and the best is ordered once the quotes are in; sourcing (optionally sourcing_ref): the quotes compared; award (sourcing_ref, optionally exchange_ref, owner_ref): order from the best quote; drop (sourcing_ref, reason); standing (exchange_ref, every_days 7 to 92, owner_ref, optionally tolerance_percent, until, reply_days, first_due_at): the owner approves buying the same again on a schedule, each line at most the price paid plus the tolerance; standing_orders (optionally standing_ref); stop_standing (standing_ref, reason); credit (new_customer_limit, customer_limit, owner_ref, optionally trusted_after_paid): the owner's limit on what a customer may owe, past which its orders go to the owner; credit_status: what each customer owes; counter (exchange_ref, prices {item_ref: unit_price}, optionally reason, owner_ref): ask the seller for a better price instead of ordering, at most twice; answer_counter (exchange_ref, optionally prices and owner_ref, valid_days): the revised quote, within the discount policy alone; discount (max_discount_percent, owner_ref, optionally trusted_max_discount_percent): how far below list the agent may go; counterparty (address, optionally status active or blocked, note); counterparties; inbox (optionally limit); receipts (optionally exchange_ref, limit); book (optionally exchange_ref); books; ledger (optionally provider quickbooks or xero, suppliers {party_ref: ledger id}, customers {party_ref: ledger id}, bill_account, sales_item, sales_account, items {item_ref: ledger item}); post (optionally exchange_ref)",
        operations={
            "status": _op("lightbulb.company_exchange_surface:exchange_status_document"),
            "card": _op("lightbulb.company_exchange_surface:build_card_document", ("party_ref", "display_name", "contact_ref", "terms_days", "quote_valid_days", "about", "keywords", "offer_names")),
            "receive": _op("lightbulb.company_exchange_surface:receive_document", (), ("document",)),
            "request": _op("lightbulb.company_exchange_surface:request_quote", ("needed_by", "reply_by", "exchange_ref", "owner_ref", "currency"), ("to_party", "lines")),
            "quote": _op("lightbulb.company_exchange_surface:quote_request", ("valid_days", "terms_days", "owner_ref"), ("exchange_ref",)),
            "order": _op("lightbulb.company_exchange_surface:order_from_quote", ("owner_ref",), ("exchange_ref",)),
            "acknowledge": _op("lightbulb.company_exchange_surface:acknowledge_order", ("accept", "reason", "owner_ref"), ("exchange_ref",)),
            "invoice": _op("lightbulb.company_exchange_surface:invoice_order", ("owner_ref",), ("exchange_ref",)),
            "remit": _op("lightbulb.company_exchange_surface:remit_invoice", ("paid_at", "payment_reference", "owner_ref"), ("exchange_ref",)),
            "send": _op("lightbulb.company_exchange_surface:send_document", ("owner_ref", "delivered_by_hand"), ("exchange_ref",)),
            "withdraw": _op("lightbulb.company_exchange_surface:withdraw_document", (), ("exchange_ref", "reason")),
            "directory": _op("lightbulb.company_exchange_surface:publish_to_directory", ("visibility", "listed")),
            "find": _op("lightbulb.company_exchange_surface:find_in_directory", (), ("address",)),
            "search": _op("lightbulb.company_exchange_surface:search_directory", ("currency", "country", "kind", "limit"), ("query",)),
            "record": _op("lightbulb.company_exchange_surface:track_record_document"),
            "source": _op("lightbulb.company_exchange_sourcing:source_supplies", ("query", "quantity", "unit", "kind", "currency", "country", "needed_by", "reply_by", "max_unit_price", "budget", "suppliers", "for_ref", "sourcing_ref", "owner_ref")),
            "sourcing": _op("lightbulb.company_exchange_sourcing:sourcing_document", ("sourcing_ref",)),
            "award": _op("lightbulb.company_exchange_sourcing:award_sourcing", ("exchange_ref", "owner_ref"), ("sourcing_ref",)),
            "drop": _op("lightbulb.company_exchange_sourcing:drop_sourcing", (), ("sourcing_ref", "reason")),
            "standing": _op("lightbulb.company_exchange_standing:set_standing_order", ("owner_ref", "tolerance_percent", "until", "reply_days", "first_due_at"), ("exchange_ref", "every_days")),
            "standing_orders": _op("lightbulb.company_exchange_standing:standing_orders_document", ("standing_ref",)),
            "stop_standing": _op("lightbulb.company_exchange_standing:stop_standing_order", (), ("standing_ref", "reason")),
            "credit": _op("lightbulb.company_exchange_credit:set_credit_policy", ("owner_ref", "trusted_after_paid"), ("new_customer_limit", "customer_limit")),
            "counter": _op("lightbulb.company_exchange_negotiation:counter_quote", ("reason", "owner_ref"), ("exchange_ref", "prices")),
            "answer_counter": _op("lightbulb.company_exchange_negotiation:answer_counter", ("prices", "owner_ref", "valid_days"), ("exchange_ref",)),
            "discount": _op("lightbulb.company_exchange_negotiation:set_discount_policy", ("owner_ref", "trusted_max_discount_percent"), ("max_discount_percent",)),
            "credit_status": _op("lightbulb.company_exchange_credit:credit_document"),
            "counterparty": _op("lightbulb.company_exchange_surface:register_counterparty", ("status", "note"), ("address",)),
            "counterparties": _op("lightbulb.company_exchange_surface:list_counterparties"),
            "inbox": _op("lightbulb.company_exchange_surface:take_in_inbox", ("limit",)),
            "receipts": _op("lightbulb.company_exchange_surface:check_receipts", ("exchange_ref", "limit")),
            "book": _op("lightbulb.company_exchange_surface:book_exchange", ("exchange_ref",)),
            "books": _op("lightbulb.company_exchange_surface:exchange_books_document"),
            "ledger": _op("lightbulb.company_exchange_surface:set_ledger_map", ("provider", "suppliers", "customers", "bill_account", "sales_item", "sales_account", "items")),
            "post": _op("lightbulb.company_exchange_surface:post_exchange_to_ledger", ("exchange_ref",)),
        },
        aliases={"build": "status", "list": "status", "summary": "status", "publish_card": "card", "find_suppliers": "search", "discover": "search"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": "the company card (company_exchange card), from the published price catalog when the company sells"},
        questions=({"id": "trade_with_another_business", "question": "Can my agent trade with another business?", "signals": ("request a quote", "send a quote", "purchase order", "rfq", "trade with", "another business", "their agent", "supplier quote")},
                   {"id": "find_a_supplier", "question": "Who on the platform sells what my business needs?", "signals": ("find a supplier", "find suppliers", "who sells", "search the directory", "suppliers for", "source from", "be found by buyers")},
                   {"id": "source_what_we_need", "question": "Can my agent get quotes for what we need and buy from the best supplier?", "signals": ("get quotes", "sourcing", "compare quotes", "best supplier", "cheapest supplier", "procure", "buy from the best")},
                   {"id": "buy_again_on_a_schedule", "question": "Can my agent reorder what we buy every week or month?", "signals": ("standing order", "reorder", "every week", "every month", "repeat order", "recurring order", "buy again")},
                   {"id": "negotiate_a_price", "question": "Can my agent negotiate a better price with a supplier or customer?", "signals": ("negotiate", "counter-offer", "counter offer", "better price", "discount", "haggle", "lower price")}),
        tool_description="Trading with other businesses and their agents in five sealed documents, each answering the one before it by digest: rfq (buyer to seller), quote (seller, priced from the published catalog in force), purchase_order (buyer, the exact quote before it lapses), order_acknowledgement (seller accepts or declines) and invoice (seller bills the accepted order). card: the company card others read (party_ref, never an address; offers with list prices; terms; how long quotes hold; which documents its agent answers alone under the mandate). receive (payload document): a document another company's agent sent, checked (addressed here, answering the thread, same lines and prices) and recorded; the same document twice changes nothing. request, quote, order, acknowledge, invoice: this company's next document, each through the mandate with its value (message_supplier, send_quote, place_order, accept_order, send_invoice; never refuses, act lets the agent send it, ask keeps it waiting for the owner's send with owner_ref). A document goes through the host's transport, or is ready to deliver by hand (send with delivered_by_hand); withdraw takes back one not yet gone. On the platform: directory publishes the card under the company's exchange address (lbx_...; visibility platform, or public for anyone), find reads a company's card by its address, counterparty registers a company by its address (status active, once its card is published) or blocks it, counterparties lists them, and inbox takes in what other companies sent and settles each (received, or refused with the code); the platform checks each document's seal and that it comes from the company whose card it names. Documents go only to registered counterparties. The platform signs each delivery receipt and each settlement with its Ed25519 key (published at /api/public/company-exchange/keys): receipts checks them for what this company sent, and a delivery whose platform signature fails is not taken in. status: every exchange, whose turn it is and what waits on the owner. What the agent sent alone is logged under the mandate.",
    ),
    Document(
        engine="change_candidate",
        verb="changes",
        default_operation="status",
        owner=True,
        reference_module="lightbulb.change_candidate",
        usage="changes takes status; candidate (source feedback|chat|roadmap|incident|error_signal|owner, source_ref, text, reporter_ref, app_ref, repository_ref, evidence_refs, kind, received_at); compile (candidate_ref, acceptance_criteria [{criterion_id, description, required_evidence}], coding_budget, workspace_binding_ref, repository_binding_ref, change_type, change_risk, usd_rate, requesting_agent_ref, harness_families); decline (candidate_ref, reason)",
        operations={
            "status": _op(f"{_SURFACE}:build_changes_status_document"),
            "candidate": _op(f"{_SURFACE}:record_change_candidate", ("reporter_ref", "app_ref", "repository_ref", "evidence_refs", "kind", "received_at"), ("source", "source_ref", "text")),
            "compile": _op(f"{_SURFACE}:compile_change_document", ("repository_binding_ref", "change_type", "change_risk", "usd_rate", "requesting_agent_ref", "harness_families"), ("candidate_ref", "acceptance_criteria", "coding_budget", "workspace_binding_ref")),
            "decline": _op(f"{_SURFACE}:decline_change_candidate", (), ("candidate_ref", "reason")),
        },
        aliases={"build": "status", "list": "status", "record": "candidate"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": "what a user, the project chat, the roadmap or an incident said about the software"},
        questions=({"id": "what_did_users_ask_us_to_change", "question": "What have users asked us to change in the software?", "signals": ("feedback", "bug report", "users asked", "feature request", "what did users say", "change request", "software change", "build this", "fix this bug", "users want")},),
        tool_description="The software factory's intake. candidate: record what an app user, the project chat, the roadmap or an incident said about the software as a sealed candidate (kind classified from the words; phrases that read as instructions to an agent flagged, never followed; carries no authority). compile: turn a candidate into the platform's SoftwareProductionRequest (one repository, the reporter's words framed as evidence, at most a draft pull request; merge and deploy are never executable from here) and ask the mandate about the coding budget under open_change, which counts against the monthly envelope; the decision is a separate sealed record. The platform issues the execution grant and runs the change; the SDK only verifies grants (lightbulb.execution_grant). status: every candidate and compiled request with the mandate's answer and whether the platform has run it (the mandate log carries the run); the same rows reach next and the owner digest. decline: set a candidate aside with the reason. Builds nothing itself; deterministic.",
    ),
    Document(
        engine="app_signals",
        verb="signals",
        default_operation="summary",
        owner=True,
        reference_module="lightbulb.app_signals",
        usage="signals takes summary (window_days); record (app_ref, signals [{signal_ref, app_ref, kind feedback|error|usage|release, occurred_at, release_ref, page, text, error_signature, error_message, count, reporter_ref}], received_at); errors (window_days, threshold); candidates (window_days, threshold); releases (app_ref, release_ref, window_days, min_usage)",
        operations={
            "summary": _op(f"{_SURFACE}:build_app_signals_summary_document", ("window_days",)),
            "record": _op(f"{_SURFACE}:record_app_signals", ("received_at",), ("app_ref", "signals")),
            "errors": _op(f"{_SURFACE}:build_app_errors_document", ("window_days", "threshold")),
            "candidates": _op(f"{_SURFACE}:raise_error_candidates", ("window_days", "threshold")),
            "releases": _op(f"{_SURFACE}:build_release_health_document", ("app_ref", "release_ref", "window_days", "min_usage")),
        },
        aliases={"build": "summary", "list": "summary"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": "the signal batches the generated apps' bridge modules report"},
        questions=({"id": "what_are_our_apps_users_running_into", "question": "What are the users of our apps running into?", "signals": ("app errors", "what broke", "error spike", "app feedback", "crashes", "users hitting", "what users report", "app health")},),
        tool_description="What the company's generated apps report back. record: keep a batch of signals an app's bridge module sent (a user's feedback, an error with its signature, usage, the release it runs; bounded, no authority, no secrets; the same signal twice is one). summary: per app in the window, feedback, errors and signatures, usage, the release running. errors: every error signature counted across releases, the ones at or past the threshold marked. candidates: each signature past the threshold becomes a defect change candidate, and each user's feedback from inside an app a candidate, through the same joint as a submission (the same signature or signal again amends the same candidate), so a spike or a request becomes work under the mandate. releases: each app's latest release (or one named) against the one before by errors per thousand uses, never the raw count; under the usage floor there is not enough evidence yet; a regressed release names the release to roll back to, which is the owner's decision. Reaches nothing; deterministic.",
    ),
    Document(
        engine="product_review",
        verb="product",
        default_operation="review",
        owner=True,
        reference_module="lightbulb.product_review",
        usage="product takes review (window_days, platform_grants: the rows of LightbulbClient.factory_status)",
        operations={"review": _op(f"{_SURFACE}:build_product_review_document", ("window_days", "platform_grants"))},
        aliases={"build": "review", "summary": "review", "list": "review"},
        readiness={"plans": (), "chains": (), "books": None, "connectors": (), "input": "the change candidates, compiled requests and app signals on record"},
        questions=({"id": "how_is_our_software_doing", "question": "How is our software doing this week?", "signals": ("product review", "what shipped", "what broke", "software this week", "how is the app", "release regressed", "roll back", "product update")},),
        tool_description="The owner's product review of the company's software: what shipped (from the platform's grant ledger when its rows are passed, else what the mandate log says was dispatched), what users said (new feedback candidates), what broke (incidents, error spikes, releases that regressed against the one before), what is queued (changes waiting on the owner's budget or ready to build), and what needs the owner ranked by evidence: a rollback decision first, then errors to look at, then budgets to approve, then requests to build or decline. Builds, sends and deploys nothing; deterministic.",
    ),
)
_BY_ENGINE = {document.engine: document for document in DOCUMENTS}
_BY_VERB = {document.verb: document for document in DOCUMENTS}
assert len(_BY_ENGINE) == len(DOCUMENTS) and len(_BY_VERB) == len(DOCUMENTS), "each registered document has its own engine and verb"


def document_for_engine(engine: str) -> Document | None:
    return _BY_ENGINE.get(engine)


def document_for_verb(verb: str) -> Document | None:
    return _BY_VERB.get(verb)


def chain_verbs() -> dict[str, tuple[str, ...]]:
    return {document.verb: (document.engine,) for document in DOCUMENTS}


def readiness_requirements() -> dict[str, dict[str, Any]]:
    return {document.engine: {"verb": document.verb, **dict(document.readiness)} for document in DOCUMENTS if document.readiness is not None}


def question_entries() -> list[dict[str, Any]]:
    return [{"id": entry["id"], "question": entry["question"], "kind": document.engine, "signals": tuple(entry["signals"])} for document in DOCUMENTS for entry in document.questions]


def reference_modules() -> list[str]:
    return [document.reference_module for document in DOCUMENTS if document.reference_module]


def dispatch(console: Any, document: Document, operation: str, values: Mapping[str, Any], *, now: str) -> dict[str, Any]:
    """Run one operation: the payload is checked against what the operation accepts and requires, then its builder is called with ``now``."""

    name = document.aliases.get(operation, operation)
    chosen = document.operations.get(name)
    keys = set(values)
    if chosen is None or not chosen.requires <= keys or keys - chosen.accepts:
        raise ValueError(document.usage)
    return chosen.call()(console, now=now, **dict(values))


__all__ = ["DOCUMENTS", "Document", "Operation", "chain_verbs", "dispatch", "document_for_engine", "document_for_verb", "question_entries", "readiness_requirements", "reference_modules"]
