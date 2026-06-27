"""Curated descriptors for high-value MCP tools.

Adds rich, customer-facing descriptions and typed input fields for the most
commonly used domain-agent actions and connector operations. The codegen
(``scripts/generate_mcp_tools.py``) consumes this module at generation time:
when a descriptor exists for a (domain, action) or connector tool key, the
generated wrapper has typed parameters and a descriptive docstring instead
of the generic ``message + inputs JSON string`` shape.

Tools without a descriptor still generate fine — they fall back to the
generic ``inputs: str = "{}"`` JSON-string signature. So this file only
needs entries for the tools you want to *upgrade*; expand it over time.

Field shape:
    InputField(name, py_type, required, default, description)
    - py_type is one of: "str", "int", "float", "bool", "list[str]", "dict"
    - default is rendered verbatim into the function signature

Each descriptor produces one keyword-only optional parameter per InputField
(except the always-present ``message`` parameter for domain actions).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class InputField:
    name: str
    py_type: str = "str"
    required: bool = False
    default: str = "None"  # rendered into signature; "None" means Optional[T] = None
    description: str = ""


@dataclass(frozen=True)
class ToolDescriptor:
    description: str
    """Multi-line, customer-facing description; rendered as the tool docstring."""
    input_fields: Tuple[InputField, ...] = field(default_factory=tuple)
    """Typed structured-input fields. Become optional kwargs on the generated wrapper."""


# ---------------------------------------------------------------------------
# Domain agent actions
# ---------------------------------------------------------------------------

DOMAIN_ACTION_DESCRIPTORS: Dict[Tuple[str, str], ToolDescriptor] = {
    # ---- Finance ----
    ("finance", "finance_stripe_ledger_reconciliation"): ToolDescriptor(
        description=(
            "Reconcile Stripe payment activity against your accounting ledger.\n\n"
            "Surfaces missing entries, amount mismatches, and timing variances\n"
            "between Stripe payouts and your bookkeeping. Outputs a reconciliation\n"
            "summary plus an itemised exceptions list."
        ),
        input_fields=(
            InputField("month", "str", description="Period to reconcile (YYYY-MM)."),
            InputField("statement_url", "str", description="Optional bank/ledger statement URL to tie out against."),
            InputField("materiality_threshold_usd", "float", description="Skip differences smaller than this threshold."),
        ),
    ),
    ("finance", "finance_ap_invoice_intake"): ToolDescriptor(
        description=(
            "Ingest an accounts-payable invoice (PDF, image, or email body) and\n"
            "extract a structured payable: vendor, line items, totals, GL coding,\n"
            "due date, payment terms, and any anomalies (duplicate, off-contract,\n"
            "amount drift)."
        ),
        input_fields=(
            InputField("invoice_url", "str", description="Signed URL or platform artifact URI for the invoice file."),
            InputField("invoice_text", "str", description="Raw invoice text (alternative to invoice_url)."),
            InputField("expected_vendor", "str", description="Optional vendor name to validate against."),
        ),
    ),
    ("finance", "finance_forecasting"): ToolDescriptor(
        description=(
            "Build a rolling cash and P&L forecast from your ledger data and\n"
            "company drivers. Returns a month-by-month projection, scenario\n"
            "comparisons, and a written interpretation of inflection points."
        ),
        input_fields=(
            InputField("horizon_months", "int", default="12", description="Forecast horizon (default 12 months)."),
            InputField("scenario", "str", description="Scenario name: base, bull, bear, or a custom label."),
            InputField("driver_overrides", "dict", description="Override drivers as JSON dict (e.g. {\"revenue_growth\": 0.15})."),
        ),
    ),
    ("finance", "finance_lbo_model"): ToolDescriptor(
        description=(
            "Build a leveraged buyout model for a target company. Outputs sources\n"
            "& uses, debt schedule, returns waterfall (IRR, MOIC), sensitivity\n"
            "tables, and an investment-committee-ready summary memo."
        ),
        input_fields=(
            InputField("target_company", "str", required=True, description="Target company name or ticker."),
            InputField("entry_multiple", "float", description="Entry EV/EBITDA multiple."),
            InputField("leverage_ratio", "float", description="Net debt / EBITDA at close."),
            InputField("hold_period_years", "int", default="5", description="Investment hold period (default 5 years)."),
        ),
    ),
    ("finance", "finance_due_diligence"): ToolDescriptor(
        description=(
            "Run a finance due-diligence pass across a target's financials,\n"
            "uncovering quality-of-earnings adjustments, working-capital trends,\n"
            "customer concentration, and red flags. Produces a banker-grade memo."
        ),
        input_fields=(
            InputField("target_company", "str", required=True, description="Target company name."),
            InputField("data_room_url", "str", description="VDR root URL (Datasite, Intralinks, Drive, etc)."),
            InputField("focus_areas", "list[str]", description="Optional list of areas to emphasise."),
        ),
    ),
    ("finance", "xero_close_books"): ToolDescriptor(
        description=(
            "Run a month-end close on the connected Xero org. Reviews unreconciled\n"
            "transactions, accruals, prepayments, and intercompany eliminations,\n"
            "then proposes adjusting journals for human approval."
        ),
        input_fields=(
            InputField("period", "str", description="Period to close (YYYY-MM); defaults to last month."),
            InputField("auto_post_threshold_usd", "float", description="Auto-post journals smaller than this; queue larger ones for approval."),
        ),
    ),
    ("finance", "xero_ar_followup"): ToolDescriptor(
        description=(
            "Triage Xero accounts receivable and draft customer-facing follow-up\n"
            "messages for overdue invoices. Tone, urgency, and channel are tuned\n"
            "to the customer's payment history."
        ),
        input_fields=(
            InputField("aging_bucket", "str", description="One of: '1-30', '31-60', '61-90', '90+'. Empty = all overdue."),
            InputField("min_amount_usd", "float", description="Only follow up on invoices above this amount."),
            InputField("send", "bool", default="False", description="If true, send messages directly; otherwise return drafts for review."),
        ),
    ),
    ("finance", "xero_bank_reconciliation"): ToolDescriptor(
        description=(
            "Reconcile Xero bank-feed transactions against the ledger. Auto-matches\n"
            "where confidence is high; surfaces ambiguous matches for review."
        ),
        input_fields=(
            InputField("account_id", "str", description="Xero bank account ID; empty = all bank accounts."),
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End date (YYYY-MM-DD)."),
        ),
    ),
    # ---- CRM / Sales ----
    ("crm", "lead_qualification"): ToolDescriptor(
        description=(
            "Qualify a lead against your ICP and grade it (A/B/C/D). Pulls firmographic\n"
            "data, intent signals, and prior interactions; returns a fit score, the\n"
            "reasoning, and a suggested next-best-action."
        ),
        input_fields=(
            InputField("lead_id", "str", description="CRM lead/contact ID."),
            InputField("lead_email", "str", description="Lead email (alternative to lead_id)."),
            InputField("company_domain", "str", description="Company domain to enrich from."),
        ),
    ),
    ("crm", "outbound_messaging"): ToolDescriptor(
        description=(
            "Draft a personalised outbound message to a prospect (cold email,\n"
            "LinkedIn, follow-up, etc) tailored to your ICP, value props, and the\n"
            "prospect's role and recent activity."
        ),
        input_fields=(
            InputField("contact_id", "str", description="CRM contact ID."),
            InputField("channel", "str", default="\"email\"", description="One of: email, linkedin, sms."),
            InputField("intent", "str", description="Goal of the message: intro, demo_book, follow_up, reactivation, expansion."),
            InputField("tone", "str", description="Tone hint: warm, direct, technical, executive."),
        ),
    ),
    ("crm", "sales_call_intelligence"): ToolDescriptor(
        description=(
            "Analyse a sales call recording or transcript. Identifies stakeholders,\n"
            "objections, commitments, MEDDPICC signals, and produces a recap email\n"
            "draft plus next-step proposals."
        ),
        input_fields=(
            InputField("call_id", "str", description="Call ID from your dialer / recording platform."),
            InputField("transcript_url", "str", description="URL to the call transcript (alternative to call_id)."),
            InputField("framework", "str", default="\"MEDDPICC\"", description="Sales framework: MEDDPICC, BANT, SPICED."),
        ),
    ),
    ("crm", "customer_health_risk"): ToolDescriptor(
        description=(
            "Score post-sale customer health and surface churn risks. Combines\n"
            "product usage, support tickets, billing, and CRM activity into a\n"
            "0-100 score with the top 3 risk drivers and recommended actions."
        ),
        input_fields=(
            InputField("account_id", "str", required=True, description="CRM account ID."),
            InputField("lookback_days", "int", default="90", description="Activity window for the score."),
        ),
    ),
    ("crm", "expansion_upsell"): ToolDescriptor(
        description=(
            "Identify expansion and upsell opportunities for an account based on\n"
            "current product usage, peer benchmarks, and unmet jobs-to-be-done."
        ),
        input_fields=(
            InputField("account_id", "str", required=True, description="CRM account ID."),
            InputField("min_arr_usd", "float", description="Skip accounts below this ARR threshold."),
        ),
    ),
    ("crm", "assess_pipeline"): ToolDescriptor(
        description=(
            "Audit your active sales pipeline. Flags stalled deals, missing\n"
            "next-steps, optimistic close dates, and stage-fit mismatches; returns\n"
            "a prioritised action list for the rep and manager."
        ),
        input_fields=(
            InputField("owner_email", "str", description="Pipeline owner; empty = whole team."),
            InputField("min_amount_usd", "float", description="Filter to deals above this amount."),
        ),
    ),
    # ---- Legal ----
    ("legal", "matter_intake"): ToolDescriptor(
        description=(
            "Run a new-matter intake from a client message or file. Classifies\n"
            "matter type, conflicts-checks, drafts the engagement letter scope,\n"
            "and proposes a fee structure."
        ),
        input_fields=(
            InputField("client_message", "str", description="Initial client message or summary."),
            InputField("attachments", "list[str]", description="URLs of supporting documents."),
            InputField("jurisdiction", "str", description="Governing jurisdiction (e.g. 'NSW' or 'Delaware')."),
        ),
    ),
    ("legal", "contract_review"): ToolDescriptor(
        description=(
            "Review a contract and produce a redline-ready memo: deviations from\n"
            "your playbook, missing clauses, risk-flagged terms, and proposed\n"
            "edits with rationale."
        ),
        input_fields=(
            InputField("contract_url", "str", required=True, description="URL or platform artifact URI for the contract."),
            InputField("playbook", "str", description="Playbook label: 'enterprise_sales', 'partnership', 'employment', 'nda'."),
            InputField("counterparty_name", "str", description="Counterparty name for the memo."),
        ),
    ),
    ("legal", "compliance_monitoring"): ToolDescriptor(
        description=(
            "Monitor regulatory and compliance changes relevant to the firm/client\n"
            "and produce a digest of new obligations, deadlines, and action items."
        ),
        input_fields=(
            InputField("jurisdictions", "list[str]", description="Jurisdictions to monitor."),
            InputField("topics", "list[str]", description="Topic filters (e.g. 'privacy', 'AML', 'employment')."),
            InputField("since", "str", description="Lookback start date (YYYY-MM-DD)."),
        ),
    ),
    ("legal", "document_drafting"): ToolDescriptor(
        description=(
            "Draft a legal document (NDA, MSA, side letter, employment agreement,\n"
            "policy) from a brief plus your firm's templates and house style."
        ),
        input_fields=(
            InputField("document_type", "str", required=True, description="Document type label."),
            InputField("brief", "str", required=True, description="Plain-English brief of what the document needs to cover."),
            InputField("counterparty", "str", description="Counterparty name."),
        ),
    ),
    ("legal", "nda_packet"): ToolDescriptor(
        description=(
            "Generate a complete NDA packet (mutual or unilateral): NDA itself,\n"
            "side letter if needed, intake form, and an executive summary for\n"
            "the requesting party."
        ),
        input_fields=(
            InputField("variant", "str", default="\"mutual\"", description="One of: mutual, unilateral, employee_confidentiality."),
            InputField("counterparty", "str", required=True, description="Counterparty name."),
            InputField("term_months", "int", default="24", description="Confidentiality term length."),
        ),
    ),
    # ---- HR ----
    ("hr", "onboard"): ToolDescriptor(
        description=(
            "Run new-hire onboarding end-to-end: provision accounts, assign equipment,\n"
            "schedule day-1 meetings, send welcome packet, file employment paperwork."
        ),
        input_fields=(
            InputField("employee_name", "str", required=True, description="New hire full name."),
            InputField("role_title", "str", required=True, description="Role title."),
            InputField("start_date", "str", required=True, description="Start date (YYYY-MM-DD)."),
            InputField("manager_email", "str", description="Reporting manager email."),
        ),
    ),
    ("hr", "offboard"): ToolDescriptor(
        description=(
            "Run employee offboarding: revoke access, transfer ownership, schedule\n"
            "exit interviews, calculate final pay, archive records."
        ),
        input_fields=(
            InputField("employee_id", "str", required=True, description="Employee ID."),
            InputField("last_day", "str", required=True, description="Final day of employment (YYYY-MM-DD)."),
            InputField("voluntary", "bool", default="True", description="Voluntary departure (vs termination)."),
        ),
    ),
    ("hr", "headcount"): ToolDescriptor(
        description=(
            "Produce a current-headcount report: active employees by team, role, and\n"
            "location; flags pending starts and recent departures."
        ),
        input_fields=(
            InputField("as_of_date", "str", description="Snapshot date (YYYY-MM-DD); defaults to today."),
            InputField("group_by", "str", default="\"team\"", description="One of: team, role, location, manager."),
        ),
    ),
    # ---- Coding ----
    ("coding", "write_code"): ToolDescriptor(
        description=(
            "Plan and implement a code change end-to-end. Reads the relevant files,\n"
            "designs the change, writes the code, and runs tests. Returns a diff\n"
            "summary and test results."
        ),
        input_fields=(
            InputField("brief", "str", required=True, description="Plain-English description of the desired change."),
            InputField("repo_path", "str", description="Workspace-relative path to scope the change."),
            InputField("run_tests", "bool", default="True", description="Run the test suite after the change."),
        ),
    ),
    ("coding", "explain_code"): ToolDescriptor(
        description=(
            "Explain how a piece of code works, why it's structured this way, and\n"
            "what its inputs/outputs are. Tunes depth to the requested audience."
        ),
        input_fields=(
            InputField("path", "str", required=True, description="File path or symbol to explain."),
            InputField("audience", "str", default="\"engineer\"", description="One of: engineer, junior, product, executive."),
        ),
    ),
}


# ---------------------------------------------------------------------------
# Connector operations (platform tool keys)
# ---------------------------------------------------------------------------

CONNECTOR_OP_DESCRIPTORS: Dict[str, ToolDescriptor] = {
    # ---- Xero ----
    "xero.list_invoices": ToolDescriptor(
        description="List invoices in the connected Xero organisation. Supports filtering by status, contact, and date range.",
        input_fields=(
            InputField("status", "str", description="One of: DRAFT, SUBMITTED, AUTHORISED, PAID, VOIDED."),
            InputField("contact_id", "str", description="Filter to a specific Xero contact ID."),
            InputField("from_date", "str", description="Start of date range (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End of date range (YYYY-MM-DD)."),
        ),
    ),
    "xero.create_invoice": ToolDescriptor(
        description="Create a draft invoice in Xero. Use the contact ID from xero.list_contacts; line items reference Xero account codes.",
        input_fields=(
            InputField("contact_id", "str", required=True, description="Xero contact ID."),
            InputField("line_items", "list[str]", required=True, description="JSON-string list of line items: [{description, quantity, unit_amount, account_code}]."),
            InputField("due_date", "str", description="Due date (YYYY-MM-DD)."),
            InputField("reference", "str", description="Customer-facing invoice reference."),
        ),
    ),
    "xero.list_bank_transactions": ToolDescriptor(
        description="List bank-feed transactions on a Xero bank account.",
        input_fields=(
            InputField("bank_account_id", "str", required=True, description="Xero bank account ID."),
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End date (YYYY-MM-DD)."),
        ),
    ),
    # ---- QuickBooks ----
    "quickbooks.list_invoices": ToolDescriptor(
        description="List QuickBooks invoices for the active company.",
        input_fields=(
            InputField("status", "str", description="Filter by status (e.g. 'Open', 'Paid')."),
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End date (YYYY-MM-DD)."),
            InputField("max_results", "int", default="100", description="Maximum number of invoices to return."),
        ),
    ),
    "quickbooks.list_customers": ToolDescriptor(
        description="List QuickBooks customers for the active company.",
        input_fields=(
            InputField("query", "str", description="Optional name/email search filter."),
            InputField("max_results", "int", default="100", description="Maximum number of customers to return."),
        ),
    ),
    "quickbooks.list_vendors": ToolDescriptor(
        description="List QuickBooks vendors for the active company.",
        input_fields=(
            InputField("query", "str", description="Optional vendor name search filter."),
            InputField("max_results", "int", default="100", description="Maximum number of vendors to return."),
        ),
    ),
    "quickbooks.list_bills": ToolDescriptor(
        description="List QuickBooks vendor bills for AP analysis.",
        input_fields=(
            InputField("status", "str", description="Optional bill status filter."),
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End date (YYYY-MM-DD)."),
            InputField("max_results", "int", default="100", description="Maximum number of bills to return."),
        ),
    ),
    "quickbooks.list_payments": ToolDescriptor(
        description="List QuickBooks payments for cash movement and reconciliation analysis.",
        input_fields=(
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("to_date", "str", description="End date (YYYY-MM-DD)."),
            InputField("max_results", "int", default="100", description="Maximum number of payments to return."),
        ),
    ),
    "quickbooks.list_accounts": ToolDescriptor(
        description="List the QuickBooks chart of accounts for GL and statement analysis.",
        input_fields=(
            InputField("account_type", "str", description="Optional QuickBooks account type filter."),
            InputField("max_results", "int", default="500", description="Maximum number of accounts to return."),
        ),
    ),
    "quickbooks.company_info": ToolDescriptor(
        description="Fetch QuickBooks company information for the active company.",
        input_fields=(),
    ),
    "quickbooks.get_company_info": ToolDescriptor(
        description="Fetch QuickBooks company information for the active company.",
        input_fields=(),
    ),
    "quickbooks.report": ToolDescriptor(
        description="Fetch a named QuickBooks report such as profit_loss, balance_sheet, cash_flow, trial_balance, ar_aging, or ap_aging.",
        input_fields=(
            InputField("report_name", "str", required=True, description="QuickBooks report name or alias."),
            InputField("start_date", "str", description="Report start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Report end date (YYYY-MM-DD)."),
            InputField("as_of_date", "str", description="Report as-of date for balance/aging reports (YYYY-MM-DD)."),
            InputField("accounting_method", "str", description="Accounting method: Accrual or Cash."),
            InputField("summarize_column_by", "str", description="Optional QuickBooks summarize_column_by parameter."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.profit_loss_report": ToolDescriptor(
        description="Fetch the QuickBooks profit and loss report for income statement analysis.",
        input_fields=(
            InputField("start_date", "str", description="Report start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Report end date (YYYY-MM-DD)."),
            InputField("accounting_method", "str", description="Accounting method: Accrual or Cash."),
            InputField("summarize_column_by", "str", description="Optional QuickBooks summarize_column_by parameter."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.balance_sheet_report": ToolDescriptor(
        description="Fetch the QuickBooks balance sheet report as of a date.",
        input_fields=(
            InputField("as_of_date", "str", description="Report as-of date (YYYY-MM-DD)."),
            InputField("accounting_method", "str", description="Accounting method: Accrual or Cash."),
            InputField("summarize_column_by", "str", description="Optional QuickBooks summarize_column_by parameter."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.trial_balance_report": ToolDescriptor(
        description="Fetch the QuickBooks trial balance report for GL tie-out and close review.",
        input_fields=(
            InputField("start_date", "str", description="Report start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Report end date (YYYY-MM-DD)."),
            InputField("accounting_method", "str", description="Accounting method: Accrual or Cash."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.cash_flow_report": ToolDescriptor(
        description="Fetch the QuickBooks statement of cash flows for cash-flow analysis.",
        input_fields=(
            InputField("start_date", "str", description="Report start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Report end date (YYYY-MM-DD)."),
            InputField("accounting_method", "str", description="Accounting method: Accrual or Cash."),
            InputField("summarize_column_by", "str", description="Optional QuickBooks summarize_column_by parameter."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.aged_receivable_report": ToolDescriptor(
        description="Fetch the QuickBooks aged receivables report for AR aging and collections analysis.",
        input_fields=(
            InputField("as_of_date", "str", description="Aging as-of date (YYYY-MM-DD)."),
            InputField("start_date", "str", description="Optional start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Optional end date (YYYY-MM-DD)."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.aged_payable_report": ToolDescriptor(
        description="Fetch the QuickBooks aged payables report for AP aging and vendor cash planning.",
        input_fields=(
            InputField("as_of_date", "str", description="Aging as-of date (YYYY-MM-DD)."),
            InputField("start_date", "str", description="Optional start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Optional end date (YYYY-MM-DD)."),
            InputField("columns", "list[str]", description="Optional report columns to request."),
        ),
    ),
    "quickbooks.controller_snapshot": ToolDescriptor(
        description="Build a QuickBooks controller snapshot with company info, preferences, and core financial reports.",
        input_fields=(
            InputField("reports", "list[str]", description="Reports to include; defaults to core controller reports."),
            InputField("start_date", "str", description="Report start date (YYYY-MM-DD)."),
            InputField("end_date", "str", description="Report end date (YYYY-MM-DD)."),
            InputField("as_of_date", "str", description="Report as-of date (YYYY-MM-DD)."),
        ),
    ),
    "quickbooks.create_invoice": ToolDescriptor(
        description="Create a draft QuickBooks invoice for a customer.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="QuickBooks customer ID."),
            InputField("line_items", "list[str]", required=True, description="JSON-string list of line items."),
            InputField("due_date", "str", description="Due date (YYYY-MM-DD)."),
        ),
    ),
    # ---- Slack ----
    "slack.post_message": ToolDescriptor(
        description="Post a message to a Slack channel or DM under the bot's identity.",
        input_fields=(
            InputField("channel", "str", required=True, description="Channel ID (Cxxx), name (#channel), or user ID (Uxxx) for DM."),
            InputField("text", "str", required=True, description="Message body. Slack mrkdwn supported."),
            InputField("thread_ts", "str", description="Thread timestamp to reply to (omit for top-level)."),
        ),
    ),
    "slack.list_channels": ToolDescriptor(
        description="List channels the Slack workspace bot can see.",
        input_fields=(
            InputField("types", "str", default="\"public_channel\"", description="Comma-separated: public_channel, private_channel, mpim, im."),
            InputField("exclude_archived", "bool", default="True"),
        ),
    ),
    "slack.join_channel": ToolDescriptor(
        description="Join a public Slack channel the bot can access.",
        input_fields=(
            InputField("channel", "str", required=True, description="Channel ID or name."),
        ),
    ),
    "slack.search_messages": ToolDescriptor(
        description="Search Slack messages across channels the bot can see.",
        input_fields=(
            InputField("query", "str", required=True, description="Slack search query (supports operators: from:, in:, after:, before:)."),
            InputField("count", "int", default="20", description="Max results."),
        ),
    ),
    "slack.get_channel_history": ToolDescriptor(
        description="Fetch recent messages from a Slack channel.",
        input_fields=(
            InputField("channel", "str", required=True, description="Channel ID."),
            InputField("limit", "int", default="50", description="Max messages."),
            InputField("oldest", "str", description="Lower-bound timestamp (Slack ts format)."),
        ),
    ),
    # ---- GitHub ----
    "github.list_pull_requests": ToolDescriptor(
        description="List pull requests for a repo.",
        input_fields=(
            InputField("repo", "str", required=True, description="owner/repo format."),
            InputField("state", "str", default="\"open\"", description="One of: open, closed, all."),
            InputField("author", "str", description="Filter to PRs by this username."),
        ),
    ),
    "github.create_pull_request": ToolDescriptor(
        description="Create a pull request from a head branch into a base branch.",
        input_fields=(
            InputField("repo", "str", required=True, description="owner/repo format."),
            InputField("title", "str", required=True),
            InputField("head", "str", required=True, description="Head branch name."),
            InputField("base", "str", default="\"main\"", description="Base branch (default main)."),
            InputField("body", "str", description="PR body markdown."),
        ),
    ),
    "github.list_issues": ToolDescriptor(
        description="List issues for a repo.",
        input_fields=(
            InputField("repo", "str", required=True, description="owner/repo format."),
            InputField("state", "str", default="\"open\"", description="One of: open, closed, all."),
            InputField("labels", "list[str]", description="Filter to issues with all of these labels."),
        ),
    ),
    "github.create_issue": ToolDescriptor(
        description="Create an issue in a repo.",
        input_fields=(
            InputField("repo", "str", required=True, description="owner/repo format."),
            InputField("title", "str", required=True),
            InputField("body", "str", description="Issue body markdown."),
            InputField("labels", "list[str]", description="Labels to apply."),
            InputField("assignees", "list[str]", description="Usernames to assign."),
        ),
    ),
    # ---- Gmail (Google Workspace) ----
    "gmail.send_email": ToolDescriptor(
        description="Send an email from the connected Gmail account.",
        input_fields=(
            InputField("to", "str", required=True, description="Recipient address(es), comma-separated."),
            InputField("subject", "str", required=True),
            InputField("body", "str", required=True, description="Plain-text or HTML body."),
            InputField("cc", "str", description="CC address(es), comma-separated."),
            InputField("html", "bool", default="False", description="If true, body is treated as HTML."),
        ),
    ),
    "gmail.list_emails": ToolDescriptor(
        description="List / search Gmail messages in the connected mailbox.",
        input_fields=(
            InputField("query", "str", description="Gmail search query (e.g. 'from:alice has:attachment newer_than:7d')."),
            InputField("max_results", "int", default="20"),
            InputField("label_ids", "list[str]", description="Filter to messages with these labels (e.g. ['INBOX'])."),
        ),
    ),
    "gmail.get_email": ToolDescriptor(
        description="Fetch a single Gmail message by ID, including headers and body.",
        input_fields=(
            InputField("message_id", "str", required=True, description="Gmail message ID."),
            InputField("format", "str", default="\"full\"", description="One of: minimal, full, raw, metadata."),
        ),
    ),
    # ---- Notion ----
    "notion.search": ToolDescriptor(
        description="Search Notion pages and databases the integration has access to.",
        input_fields=(
            InputField("query", "str", required=True, description="Search text."),
            InputField("filter_type", "str", description="One of: page, database."),
        ),
    ),
    "notion.query_database": ToolDescriptor(
        description="Query rows in a Notion database with filters and sorts.",
        input_fields=(
            InputField("database_id", "str", required=True, description="Notion database ID."),
            InputField("filter_json", "str", description="Notion filter object as a JSON string."),
            InputField("sorts_json", "str", description="Notion sorts array as a JSON string."),
            InputField("page_size", "int", default="100"),
        ),
    ),
    "notion.create_page": ToolDescriptor(
        description="Create a new Notion page in the given parent (database or page).",
        input_fields=(
            InputField("parent_id", "str", required=True, description="Parent page or database ID."),
            InputField("title", "str", required=True),
            InputField("content_markdown", "str", description="Page content in Markdown (will be converted to Notion blocks)."),
        ),
    ),
    # ---- Jira ----
    "jira.search_issues": ToolDescriptor(
        description="Search Jira issues with JQL.",
        input_fields=(
            InputField("jql", "str", required=True, description="JQL query (e.g. 'project = ENG AND status = \"In Progress\"')."),
            InputField("max_results", "int", default="50"),
        ),
    ),
    "jira.create_issue": ToolDescriptor(
        description="Create a Jira issue in a project.",
        input_fields=(
            InputField("project_key", "str", required=True, description="Project key (e.g. 'ENG')."),
            InputField("summary", "str", required=True),
            InputField("issue_type", "str", default="\"Task\"", description="One of the project's configured issue types."),
            InputField("description", "str"),
            InputField("assignee", "str", description="Username or accountId."),
        ),
    ),
    # ---- Stripe ----
    "stripe.list_charges": ToolDescriptor(
        description="List recent Stripe charges.",
        input_fields=(
            InputField("customer_id", "str", description="Stripe customer ID to filter by."),
            InputField("from_date", "str", description="Start date (YYYY-MM-DD)."),
            InputField("limit", "int", default="100"),
        ),
    ),
    "stripe.list_invoices": ToolDescriptor(
        description="List Stripe invoices, optionally scoped to a customer.",
        input_fields=(
            InputField("customer_id", "str", description="Stripe customer ID."),
            InputField("status", "str", description="One of: draft, open, paid, uncollectible, void."),
            InputField("limit", "int", default="100"),
        ),
    ),
    # ---- Shopify (intelligence + analytics) ----
    "shopify.list_draft_orders": ToolDescriptor(
        description="List draft orders from the connected Shopify store.",
        input_fields=(
            InputField("limit", "int", default="50"),
            InputField("status", "str", description="One of: open, invoice_sent, completed."),
        ),
    ),
    "shopify.get_shop_info": ToolDescriptor(
        description="Fetch the connected Shopify shop's basic info (name, domain, currency, plan, timezone).",
        input_fields=(),
    ),
    "shopify.list_locations": ToolDescriptor(
        description="List the Shopify shop's locations (warehouses, retail locations, fulfillment centres).",
        input_fields=(
            InputField("limit", "int", default="20", description="Maximum locations to return (1-50)."),
        ),
    ),
    "shopify.list_collections": ToolDescriptor(
        description="List Shopify product collections (smart and custom).",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum collections to return (1-250)."),
        ),
    ),
    "shopify.list_abandoned_checkouts": ToolDescriptor(
        description=(
            "List the shop's recent abandoned checkouts with cart subtotals and customer\n"
            "context. Use to compute abandoned-revenue at risk and prioritise recovery."
        ),
        input_fields=(
            InputField("limit", "int", default="20", description="Maximum checkouts to return (1-250)."),
            InputField("query", "str", description="Optional Shopify search query (e.g. 'created_at:>=2026-04-01')."),
        ),
    ),
    "shopify.analytics_query": ToolDescriptor(
        description=(
            "Run a ShopifyQL analytics query against the shop's analytics warehouse.\n"
            "Use for revenue, AOV, sessions, conversion, and grouped time-series metrics.\n"
            "Defaults to net_sales + order_count by day for the last 30d when query is omitted."
        ),
        input_fields=(
            InputField(
                "query",
                "str",
                description=(
                    "ShopifyQL statement. Example: "
                    "'FROM sales SHOW sum(net_sales), count(orders) SINCE -14d UNTIL today GROUP BY week'."
                ),
            ),
        ),
    ),
    "shopify.list_fulfillment_orders": ToolDescriptor(
        description="List the fulfillment orders associated with a Shopify order, including locations and tracking.",
        input_fields=(
            InputField("order_id", "str", required=True, description="Shopify order ID (numeric or GID)."),
        ),
    ),
    "shopify.list_discounts": ToolDescriptor(
        description="List active and historical discount codes / automatic discounts in the shop.",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum discounts to return (1-250)."),
        ),
    ),
    "shopify.list_refunds": ToolDescriptor(
        description="List recent order refunds in the shop.",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum refunds to return (1-250)."),
            InputField("order_id", "str", description="Optional order ID to scope refunds to a single order."),
        ),
    ),
    "shopify.list_transactions": ToolDescriptor(
        description="List order transactions (authorisations, captures, voids, sales) for an order.",
        input_fields=(
            InputField("order_id", "str", required=True, description="Shopify order ID (numeric or GID)."),
        ),
    ),
    # ---- Shopify (segment execution) ----
    "shopify.tag_customers_bulk": ToolDescriptor(
        description=(
            "Apply tags to a batch of customers in a single call. Use after RFM/segment\n"
            "analysis to mark a cohort (e.g. 'segment:champion', 'campaign:spring-launch')."
        ),
        input_fields=(
            InputField("customer_ids", "list[str]", required=True, description="Customer IDs (numeric or GIDs)."),
            InputField("tags", "list[str]", required=True, description="Tags to apply."),
        ),
    ),
    "shopify.create_price_rule": ToolDescriptor(
        description=(
            "Create a Shopify price rule (the engine behind a discount code). Use to roll\n"
            "out a targeted promotion for a segment after tagging."
        ),
        input_fields=(
            InputField("title", "str", required=True, description="Internal price-rule title."),
            InputField(
                "value_type",
                "str",
                required=True,
                description="One of: percentage, fixed_amount.",
            ),
            InputField(
                "value",
                "str",
                required=True,
                description="Discount value as a string (e.g. '-15' for 15% off, '-10.00' for $10 off).",
            ),
            InputField("starts_at", "str", description="ISO-8601 start datetime (defaults to now)."),
            InputField("ends_at", "str", description="ISO-8601 end datetime (omit for open-ended)."),
            InputField("usage_limit", "int", description="Maximum total uses across all customers."),
        ),
    ),
    # ---- Shopify (metafields) ----
    "shopify.get_metafields": ToolDescriptor(
        description="Read metafields on a Shopify resource (product, customer, order, variant, collection, or shop).",
        input_fields=(
            InputField(
                "owner_type",
                "str",
                description="One of: PRODUCT, CUSTOMER, ORDER, VARIANT, COLLECTION, SHOP. Defaults to PRODUCT.",
            ),
            InputField("owner_id", "str", description="Resource ID (numeric or GID). Required unless owner_type=SHOP."),
            InputField("namespace", "str", description="Optional metafield namespace filter."),
            InputField("limit", "int", default="30", description="Maximum metafields to return (1-250)."),
        ),
    ),
    "shopify.update_metafield": ToolDescriptor(
        description="Create or update a metafield on a Shopify resource.",
        input_fields=(
            InputField(
                "owner_type",
                "str",
                description="One of: PRODUCT, CUSTOMER, ORDER, VARIANT, COLLECTION. Defaults to PRODUCT.",
            ),
            InputField("owner_id", "str", required=True, description="Resource ID (numeric or GID)."),
            InputField("namespace", "str", required=True, description="Metafield namespace."),
            InputField("key", "str", required=True, description="Metafield key."),
            InputField("value", "str", required=True, description="Metafield value (string-encoded per the type)."),
            InputField(
                "type",
                "str",
                description="Metafield type (e.g. single_line_text_field, number_integer, json). Defaults to single_line_text_field.",
            ),
        ),
    ),
    "shopify.list_metafield_definitions": ToolDescriptor(
        description="List declared metafield definitions for a given owner type.",
        input_fields=(
            InputField(
                "owner_type",
                "str",
                required=True,
                description="One of: PRODUCT, CUSTOMER, ORDER, VARIANT, COLLECTION, SHOP.",
            ),
            InputField("limit", "int", default="50", description="Maximum definitions to return (1-250)."),
        ),
    ),
    # ---- Shopify (bulk operations) ----
    "shopify.bulk_operation_create": ToolDescriptor(
        description=(
            "Submit a Shopify bulk-operation query to the asynchronous job runner.\n"
            "Returns a bulk operation ID; poll via shopify.bulk_operation_status."
        ),
        input_fields=(
            InputField(
                "query",
                "str",
                required=True,
                description="Bulk-operation GraphQL query (Shopify bulk-operation syntax).",
            ),
        ),
    ),
    "shopify.bulk_operation_status": ToolDescriptor(
        description="Get the current status of the most recent (or a specific) Shopify bulk operation.",
        input_fields=(
            InputField("bulk_operation_id", "str", description="Optional bulk-operation GID. Defaults to the latest."),
        ),
    ),
    "shopify.bulk_operation_result": ToolDescriptor(
        description="Fetch the JSONL result file of a completed Shopify bulk operation.",
        input_fields=(
            InputField("bulk_operation_id", "str", description="Optional bulk-operation GID. Defaults to the latest completed."),
        ),
    ),
    # ---- Ecommerce (provider-neutral; routes through the connected store, e.g. Shopify) ----
    "ecommerce.search_products": ToolDescriptor(
        description="Search products in the connected ecommerce store with optional filters.",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum products to return (1-250)."),
            InputField("query", "str", description="Free-text or store-native search query (e.g. 'tag:winter status:active')."),
            InputField("vendor", "str", description="Filter to a specific vendor / brand."),
            InputField("product_type", "str", description="Filter to a specific product type."),
        ),
    ),
    "ecommerce.search_orders": ToolDescriptor(
        description=(
            "Search orders in the connected ecommerce store. Returns orders with line\n"
            "items, customer, shipping address, and totals. Supports status and date-range filters."
        ),
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum orders to return (1-250)."),
            InputField(
                "status",
                "str",
                description="Filter by order status (e.g. 'open', 'closed', 'cancelled', 'paid', 'unfulfilled').",
            ),
            InputField("start_date", "str", description="Created-on or after (YYYY-MM-DD or ISO-8601)."),
            InputField("end_date", "str", description="Created-on or before (YYYY-MM-DD or ISO-8601)."),
            InputField("query", "str", description="Optional store-native search query for advanced filtering."),
            InputField("line_item_limit", "int", default="50", description="Max line items to fetch per order (1-250)."),
        ),
    ),
    "ecommerce.search_customers": ToolDescriptor(
        description="Search customers in the connected ecommerce store.",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum customers to return (1-250)."),
            InputField("query", "str", description="Free-text or store-native search query (e.g. 'email:*@acme.com')."),
        ),
    ),
    "ecommerce.get_inventory": ToolDescriptor(
        description=(
            "Get current inventory quantities (available, incoming, committed, reserved,\n"
            "on_hand) per SKU, optionally scoped to a single location."
        ),
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum inventory items to return (1-100)."),
            InputField("location_id", "str", description="Restrict to a single location ID."),
            InputField("sku", "str", description="Filter to a single SKU."),
            InputField("inventory_item_id", "str", description="Filter to a single inventory item (numeric or GID)."),
            InputField("query", "str", description="Optional store-native search query."),
            InputField(
                "levels_first",
                "int",
                default="25",
                description="Inventory levels per item to fetch (1-50).",
            ),
        ),
    ),
    "ecommerce.get_product_reviews": ToolDescriptor(
        description="Fetch product reviews for the connected store (where supported by the underlying provider).",
        input_fields=(
            InputField("product_id", "str", description="Filter to a single product (numeric or GID)."),
            InputField("limit", "int", default="50", description="Maximum reviews to return."),
        ),
    ),
    "ecommerce.create_discount": ToolDescriptor(
        description="Create a percentage-based discount code in the connected store.",
        input_fields=(
            InputField("title", "str", required=True, description="Internal discount title."),
            InputField("code", "str", required=True, description="Customer-facing discount code."),
            InputField(
                "percentage",
                "float",
                required=True,
                description="Percent off (0, 100]. Example: 15 for 15%.",
            ),
            InputField("starts_at", "str", description="ISO-8601 start datetime (defaults to now)."),
            InputField("ends_at", "str", description="ISO-8601 end datetime (omit for open-ended)."),
            InputField("usage_limit", "int", description="Maximum total uses across all customers."),
        ),
    ),
    "ecommerce.update_customer": ToolDescriptor(
        description="Update a single customer's tags, note, or email in the connected store.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Customer ID (numeric or GID)."),
            InputField("tags", "list[str]", description="Tags to set (replaces existing tags)."),
            InputField("note", "str", description="Internal note to attach to the customer."),
            InputField("email", "str", description="New email address."),
        ),
    ),
    # ---- Stripe extras ----
    "stripe.list_customers": ToolDescriptor(
        description="List Stripe customers.",
        input_fields=(
            InputField("email", "str", description="Filter by exact email."),
            InputField("limit", "int", default="100"),
        ),
    ),
    # ---- Square ----
    "square.list_payments": ToolDescriptor(
        description="List Square payments for the connected merchant account.",
        input_fields=(
            InputField("from_date", "str", description="Begin time (RFC 3339)."),
            InputField("to_date", "str", description="End time (RFC 3339)."),
            InputField("location_id", "str", description="Filter to a specific location."),
        ),
    ),
    "square.search_catalog": ToolDescriptor(
        description="Search the Square catalog (items, variations, categories).",
        input_fields=(
            InputField(
                "object_types",
                "list[str]",
                description="Catalog object types to include (e.g. ['ITEM', 'ITEM_VARIATION']).",
            ),
            InputField("query", "str", description="Free-text search query."),
            InputField("limit", "int", default="100", description="Maximum objects to return."),
        ),
    ),
    "square.search_orders": ToolDescriptor(
        description="Search Square orders by location, status, or date range.",
        input_fields=(
            InputField("location_id", "str", description="Square location ID."),
            InputField(
                "state",
                "str",
                description="Order state filter: OPEN, COMPLETED, or CANCELED.",
            ),
            InputField("start_date", "str", description="Created at or after (RFC 3339)."),
            InputField("end_date", "str", description="Created at or before (RFC 3339)."),
            InputField("limit", "int", default="50", description="Maximum orders to return."),
        ),
    ),
    "square.list_customers": ToolDescriptor(
        description="List customers in the connected Square account.",
        input_fields=(
            InputField("limit", "int", default="100", description="Maximum customers to return."),
            InputField("cursor", "str", description="Pagination cursor from a previous response."),
        ),
    ),
    "square.get_inventory": ToolDescriptor(
        description="Fetch Square inventory counts for one or more catalog items.",
        input_fields=(
            InputField(
                "catalog_object_ids",
                "list[str]",
                required=True,
                description="Catalog object IDs to fetch inventory counts for.",
            ),
            InputField("location_ids", "list[str]", description="Optional location IDs to restrict counts to."),
        ),
    ),
    # ---- Clio ----
    "clio.list_matters": ToolDescriptor(
        description="List Clio matters for the connected firm.",
        input_fields=(
            InputField("status", "str", description="One of: pending, open, closed."),
            InputField("client_id", "str", description="Filter to a specific Clio contact ID."),
        ),
    ),
    "clio.create_matter": ToolDescriptor(
        description="Create a new Clio matter.",
        input_fields=(
            InputField("display_number", "str", required=True, description="Matter display number."),
            InputField("description", "str", required=True),
            InputField("client_id", "str", required=True, description="Clio contact ID for the client."),
            InputField("practice_area_id", "str", description="Practice area ID."),
        ),
    ),
    # ---- Calendar ----
    "calendar.get_availability": ToolDescriptor(
        description="Check free/busy availability on the connected Google Calendar.",
        input_fields=(
            InputField("time_min", "str", required=True, description="Window start (RFC3339/ISO 8601)."),
            InputField("time_max", "str", required=True, description="Window end (RFC3339/ISO 8601)."),
            InputField("calendar_id", "str", default="\"primary\"", description="Calendar ID to check."),
        ),
    ),
    "calendar.list_events": ToolDescriptor(
        description="List upcoming events on the connected Google Calendar.",
        input_fields=(
            InputField("time_min", "str", description="Window start (RFC3339/ISO 8601). Defaults to now."),
            InputField("time_max", "str", description="Window end (RFC3339/ISO 8601). Defaults to +7 days."),
            InputField("calendar_id", "str", default="\"primary\"", description="Calendar ID to query."),
            InputField("max_results", "int", default="50", description="Maximum number of events to return (max 200)."),
        ),
    ),
    "calendar.create_event": ToolDescriptor(
        description="Create an event on the connected Google Calendar. Sends invites to attendees.",
        input_fields=(
            InputField("summary", "str", required=True, description="Event title."),
            InputField("start", "str", required=True, description="Start datetime (RFC3339, e.g. 2026-05-22T10:00:00+10:00)."),
            InputField("end", "str", required=True, description="End datetime (RFC3339)."),
            InputField("description", "str", description="Event description or agenda."),
            InputField("attendees", "array", description="List of attendee objects with 'email' and optional 'name'."),
            InputField("calendar_id", "str", default="\"primary\"", description="Calendar ID."),
            InputField("conference_type", "str", description="Set to 'googlemeet' to add a Google Meet link."),
        ),
    ),
    "calendar.update_event": ToolDescriptor(
        description="Update an existing event on the connected Google Calendar.",
        input_fields=(
            InputField("event_id", "str", required=True, description="Google Calendar event ID."),
            InputField("summary", "str", description="New event title."),
            InputField("start", "str", description="New start datetime (RFC3339)."),
            InputField("end", "str", description="New end datetime (RFC3339)."),
            InputField("description", "str", description="New event description."),
            InputField("attendees", "array", description="Updated attendee list."),
            InputField("calendar_id", "str", default="\"primary\"", description="Calendar ID."),
        ),
    ),
    "calendar.delete_event": ToolDescriptor(
        description="Delete an event from the connected Google Calendar.",
        input_fields=(
            InputField("event_id", "str", required=True, description="Google Calendar event ID to delete."),
            InputField("calendar_id", "str", default="\"primary\"", description="Calendar ID."),
        ),
    ),
    # ---- Microsoft 365 ----
    "microsoft.send_email": ToolDescriptor(
        description="Send an email from the connected Microsoft 365 mailbox.",
        input_fields=(
            InputField("to", "str", required=True, description="Recipient address(es), comma-separated."),
            InputField("subject", "str", required=True),
            InputField("body", "str", required=True, description="HTML body."),
            InputField("cc", "str", description="CC address(es), comma-separated."),
        ),
    ),
    "microsoft.list_emails": ToolDescriptor(
        description="List Outlook messages in the connected Microsoft 365 mailbox.",
        input_fields=(
            InputField("folder", "str", default="\"Inbox\"", description="Mailbox folder name."),
            InputField("top", "int", default="25", description="Max messages to return."),
            InputField("filter", "str", description="OData filter expression."),
        ),
    ),
    "microsoft.list_events": ToolDescriptor(
        description="List Outlook calendar events on the connected Microsoft 365 calendar.",
        input_fields=(
            InputField("start", "str", description="Window start (ISO 8601)."),
            InputField("end", "str", description="Window end (ISO 8601)."),
            InputField("top", "int", default="50"),
        ),
    ),
    "microsoft.create_event": ToolDescriptor(
        description="Create a calendar event in the user's Microsoft 365 (Outlook) calendar. Sends invites to attendees.",
        input_fields=(
            InputField("summary", "str", required=True, description="Event title / subject."),
            InputField("start", "str", required=True, description="Start datetime (ISO 8601, UTC)."),
            InputField("end", "str", required=True, description="End datetime (ISO 8601, UTC)."),
            InputField("description", "str", description="Event body / agenda."),
            InputField("attendees", "list", description="List of attendee objects with 'email' and optional 'name'."),
            InputField("calendar_id", "str", description="Outlook calendar ID (omit for default calendar)."),
            InputField("conference_type", "str", description="Set to 'teams' to add a Teams meeting link."),
        ),
    ),
    "microsoft.update_event": ToolDescriptor(
        description="Update an existing event in the user's Microsoft 365 (Outlook) calendar.",
        input_fields=(
            InputField("event_id", "str", required=True, description="ID of the event to update."),
            InputField("summary", "str", description="New event title / subject."),
            InputField("start", "str", description="New start datetime (ISO 8601, UTC)."),
            InputField("end", "str", description="New end datetime (ISO 8601, UTC)."),
            InputField("description", "str", description="Updated event body."),
            InputField("attendees", "list", description="Replacement attendee list."),
            InputField("calendar_id", "str", description="Outlook calendar ID (omit for default calendar)."),
        ),
    ),
    "microsoft.delete_event": ToolDescriptor(
        description="Permanently delete a calendar event from the user's Microsoft 365 (Outlook) calendar.",
        input_fields=(
            InputField("event_id", "str", required=True, description="ID of the event to delete."),
            InputField("calendar_id", "str", description="Outlook calendar ID (omit for default calendar)."),
        ),
    ),
}


def get_domain_descriptor(domain: str, action: str) -> Optional[ToolDescriptor]:
    return DOMAIN_ACTION_DESCRIPTORS.get((domain, action))


def get_connector_descriptor(tool_key: str) -> Optional[ToolDescriptor]:
    return CONNECTOR_OP_DESCRIPTORS.get(tool_key)


def descriptor_count() -> Dict[str, int]:
    return {
        "domain_actions": len(DOMAIN_ACTION_DESCRIPTORS),
        "connector_ops": len(CONNECTOR_OP_DESCRIPTORS),
        "total": len(DOMAIN_ACTION_DESCRIPTORS) + len(CONNECTOR_OP_DESCRIPTORS),
    }
