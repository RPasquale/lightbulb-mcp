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
from typing import Dict, Literal, Optional, Tuple


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
    effect_class: Optional[Literal["read", "action"]] = None
    """Declared domain-action effect when the implementation contract is explicit."""


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
        effect_class="read",
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
        effect_class="read",
    ),
}


# ---------------------------------------------------------------------------
# Connector operations (platform tool keys)
# ---------------------------------------------------------------------------

CONNECTOR_OP_DESCRIPTORS: Dict[str, ToolDescriptor] = {
    # ---- Governed social publishing ----
    "facebook.publish_post": ToolDescriptor(
        description=(
            "Publish one approved post to the exact Facebook Page bound to the "
            "authenticated project connector route."
        ),
        input_fields=(
            InputField("page_id", "str", required=True, description="Exact account-bound Facebook Page ID."),
            InputField("message", "str", required=True, description="Approved post body (maximum 10,000 characters)."),
            InputField("image_url", "str", description="Optional public HTTPS image URL."),
        ),
    ),
    "instagram.publish_post": ToolDescriptor(
        description=(
            "Publish one approved image post to the exact Instagram Business "
            "account bound to the authenticated project connector route."
        ),
        input_fields=(
            InputField(
                "instagram_business_account_id",
                "str",
                required=True,
                description="Exact account-bound Instagram Business Account ID.",
            ),
            InputField("caption", "str", required=True, description="Approved caption (maximum 10,000 characters)."),
            InputField("image_url", "str", required=True, description="Public HTTPS image URL."),
        ),
    ),
    "linkedin.publish_post": ToolDescriptor(
        description=(
            "Publish one approved post under the exact LinkedIn member or "
            "organization author bound to the authenticated project connector route."
        ),
        input_fields=(
            InputField("author_urn", "str", required=True, description="Exact account-bound LinkedIn author URN."),
            InputField("text", "str", required=True, description="Approved post text (maximum 3,000 characters)."),
            InputField("url", "str", description="Optional public HTTPS destination URL."),
            InputField("image_url", "str", description="Optional public HTTPS image URL."),
        ),
    ),
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
    "quickbooks.observe_invoice_issued": ToolDescriptor(
        description=(
            "Observe one exact QuickBooks invoice by its server-generated "
            "contract-to-cash correlation and return only bounded evidence commitments."
        ),
        input_fields=(
            InputField(
                "correlation_ref",
                "str",
                required=True,
                description="Exact Lightbulb invoice correlation (LB-CTC- plus 18 uppercase hex characters).",
            ),
        ),
    ),
    "quickbooks.observe_invoice_payment_applied": ToolDescriptor(
        description=(
            "Observe the payments QuickBooks links to one exact invoice by its "
            "contract-to-cash correlation: applied amount, payment count, and a "
            "zero-balance proof, as digests and amounts only."
        ),
        input_fields=(
            InputField(
                "correlation_ref",
                "str",
                required=True,
                description="Exact Lightbulb invoice correlation (LB-CTC- plus 18 uppercase hex characters).",
            ),
        ),
        effect_class="read",
    ),
    "quickbooks.observe_bill_payment_applied": ToolDescriptor(
        description=(
            "Observe the bill payments QuickBooks links to one exact bill by its "
            "payables correlation: applied amount, payment count, and a zero-balance "
            "proof, as digests and amounts only."
        ),
        input_fields=(
            InputField(
                "correlation_ref",
                "str",
                required=True,
                description="Exact Lightbulb payables correlation (LB-AP- plus 18 uppercase hex characters).",
            ),
        ),
        effect_class="read",
    ),
    "stripe.observe_cash_settlement": ToolDescriptor(
        description=(
            "Observe whether one correlated Stripe charge settled: paid, unrefunded, "
            "undisputed, contained in a paid payout, and past the reversal window. "
            "Digests, minor-unit amount, payout state, and timestamps only."
        ),
        input_fields=(
            InputField("correlation_ref", "str", required=True, description="Exact Lightbulb invoice correlation (LB-CTC- plus 18 uppercase hex characters)."),
            InputField("charge_id", "str", required=True, description="Stripe charge id (ch_...) carrying the correlation in its metadata."),
            InputField("payout_id", "str", required=True, description="Stripe payout id (po_...) expected to contain the charge."),
            InputField("reversal_window_days", "int", required=True, description="Whole days (1-180) that must elapse after payout arrival."),
        ),
        effect_class="read",
    ),
    "github.list_deployments": ToolDescriptor(
        description=(
            "Read one bounded page (30) of deployments for one exact GitHub repository, "
            "optionally for one environment, as release records: id, sha, ref, "
            "environment, task, and timestamps."
        ),
        input_fields=(
            InputField("owner", "str", required=True, description="Repository owner login."),
            InputField("repo", "str", required=True, description="Repository name."),
            InputField("environment", "str", description="Optional deployment environment name."),
            InputField("per_page", "int", required=True, default="30", description="Page size; the governed contract requires 30."),
        ),
        effect_class="read",
    ),
    "posthog.query_events": ToolDescriptor(
        description=(
            "Read one bounded page (100) of one PostHog event name for one exact project "
            "inside a window of at most 31 days, as usage rows with identity commitments only."
        ),
        input_fields=(
            InputField("project_id", "str", required=True, description="PostHog project id the connection may read."),
            InputField("event", "str", required=True, description="Exact event name."),
            InputField("after", "str", required=True, description="Window start (ISO-8601 timestamp)."),
            InputField("before", "str", required=True, description="Window end (ISO-8601 timestamp), at most 31 days after the start."),
            InputField("limit", "int", required=True, default="100", description="Page size; the governed contract requires 100."),
        ),
        effect_class="read",
    ),
    "google_ads.get_account": ToolDescriptor(
        description="Read the bound Google Ads customer (currency, time zone, manager and test-account flags) as commitments; closes the developer-token gate.",
        input_fields=(InputField("probe", "str", required=True, default="account", description="The governed contract requires account."),),
        effect_class="read",
    ),
    "google_ads.list_campaigns": ToolDescriptor(
        description="Read up to 200 non-removed campaigns of the bound customer with daily budgets, as commitments plus the minted LB-GA tag.",
        input_fields=(InputField("page_size", "int", required=True, default="200", description="The governed contract requires 200."),),
        effect_class="read",
    ),
    "google_ads.get_metrics": ToolDescriptor(
        description=(
            "Read exact daily spend, impressions, clicks and conversions per campaign for the bound customer "
            "inside a closed window of at most 92 days. Conversions cross as integral thousandths and are never summed with all_conversions."
        ),
        input_fields=(
            InputField("window_start", "str", required=True, description="First day (YYYY-MM-DD)."),
            InputField("window_end", "str", required=True, description="Last day (YYYY-MM-DD), at most 92 days after the start."),
            InputField("segment", "str", required=True, default="campaign_daily", description="The governed contract requires campaign_daily."),
        ),
        effect_class="read",
    ),
    "google_ads.create_campaign_budget": ToolDescriptor(
        description="Create one standard unshared campaign budget under approval; amount in micros, floor one unit, ceiling 5000 units and the connection ceiling.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Ten-digit customer id; must equal the bound customer."),
            InputField("name", "str", required=True, description="Minted LB-GA-<18 hex> tag followed by a label."),
            InputField("amount_micros", "int", required=True, description="Daily budget in micros (1000000 = one currency unit)."),
        ),
        effect_class="write",
    ),
    "google_ads.create_campaign": ToolDescriptor(
        description="Create one Search campaign PAUSED under approval with an explicit bidding strategy. No status input exists; going live is a human act in the Google Ads UI.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Ten-digit customer id; must equal the bound customer."),
            InputField("name", "str", required=True, description="Minted LB-GA-<18 hex> tag followed by a label."),
            InputField("campaign_budget_resource_name", "str", required=True, description="customers/<id>/campaignBudgets/<id> of the bound customer."),
            InputField("advertising_channel_type", "str", required=True, default="SEARCH", description="Only SEARCH this round."),
            InputField("bidding_strategy_type", "str", required=True, description="MANUAL_CPC, MAXIMIZE_CONVERSIONS, TARGET_CPA or TARGET_ROAS."),
            InputField("target_cpa_micros", "int", description="Required with TARGET_CPA."),
            InputField("target_roas", "float", description="Required with TARGET_ROAS."),
            InputField("start_date", "str", required=True, description="YYYYMMDD."),
            InputField("end_date", "str", required=True, description="YYYYMMDD."),
        ),
        effect_class="write",
    ),
    "google_ads.update_budget": ToolDescriptor(
        description="Update the amount of one existing campaign budget under approval inside the contract and connection ceilings.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Ten-digit customer id; must equal the bound customer."),
            InputField("resource_name", "str", required=True, description="customers/<id>/campaignBudgets/<id> of the bound customer."),
            InputField("amount_micros", "int", required=True, description="New daily budget in micros."),
        ),
        effect_class="write",
    ),
    "google_ads.pause_campaign": ToolDescriptor(
        description="Pause one campaign under approval; the only status change the platform performs.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Ten-digit customer id; must equal the bound customer."),
            InputField("resource_name", "str", required=True, description="customers/<id>/campaigns/<id> of the bound customer."),
        ),
        effect_class="write",
    ),
    "meta_ads.get_account": ToolDescriptor(
        description="Read the bound Meta ad account (currency and exponent, status, timezone, minimum daily budget, business) as commitments; closes the app-review and business-verification gates.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("probe", "str", required=True, default="account", description="The governed contract requires account."),
        ),
        effect_class="read",
    ),
    "meta_ads.list_campaigns": ToolDescriptor(
        description="Read up to 100 campaigns of the bound ad account with budgets and special ad categories, as commitments plus the minted LB-MA tag.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("limit", "int", required=True, default="100", description="The governed contract requires 100."),
        ),
        effect_class="read",
    ),
    "meta_ads.get_insights": ToolDescriptor(
        description=(
            "Read exact daily spend, impressions, clicks and conversions BY ACTION TYPE per campaign for the bound ad account "
            "inside a closed window of at most 92 days under the account unified attribution setting. There is no scalar conversion field."
        ),
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("window_start", "str", required=True, description="First day (YYYY-MM-DD)."),
            InputField("window_end", "str", required=True, description="Last day (YYYY-MM-DD), at most 92 days after the start."),
            InputField("level", "str", required=True, default="campaign", description="The governed contract requires campaign."),
            InputField("attribution", "str", required=True, default="unified", description="The governed contract requires unified."),
        ),
        effect_class="read",
    ),
    "meta_ads.create_campaign": ToolDescriptor(
        description="Create one campaign PAUSED under approval with an explicit objective and explicitly stated special ad categories. No status input exists; going live is a human act.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("name", "str", required=True, description="Minted LB-MA-<18 hex> tag followed by a label."),
            InputField("objective", "str", required=True, description="OUTCOME_SALES, OUTCOME_LEADS, OUTCOME_TRAFFIC, OUTCOME_AWARENESS, OUTCOME_ENGAGEMENT or OUTCOME_APP_PROMOTION."),
            InputField("special_ad_categories", "list[str]", required=True, description="Stated every time, never defaulted: NONE, HOUSING, EMPLOYMENT, CREDIT or ISSUES_ELECTIONS_POLITICS."),
        ),
        effect_class="write",
    ),
    "meta_ads.create_adset": ToolDescriptor(
        description="Create one ad set PAUSED under approval inside an existing campaign with a minor-unit daily budget and a closed targeting object that admits no audience identifiers.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("campaign_id", "str", required=True, description="Numeric campaign id."),
            InputField("name", "str", required=True, description="Minted LB-MA-<18 hex> tag followed by a label."),
            InputField("daily_budget_minor", "int", required=True, description="Daily budget in minor units under the connection exponent."),
            InputField("billing_event", "str", required=True, description="IMPRESSIONS or LINK_CLICKS."),
            InputField("optimization_goal", "str", required=True, description="LINK_CLICKS, LANDING_PAGE_VIEWS, OFFSITE_CONVERSIONS, LEAD_GENERATION, REACH or IMPRESSIONS."),
            InputField("bid_strategy", "str", required=True, description="LOWEST_COST_WITHOUT_CAP, COST_CAP or LOWEST_COST_WITH_BID_CAP."),
            InputField("bid_amount_minor", "int", description="Required with COST_CAP or LOWEST_COST_WITH_BID_CAP."),
            InputField("targeting", "dict", required=True, description="geo_locations (countries, regions, cities), age_min, age_max, genders, publisher_platforms only."),
            InputField("start_time", "str", required=True, description="ISO-8601 instant."),
            InputField("end_time", "str", required=True, description="ISO-8601 instant."),
        ),
        effect_class="write",
    ),
    "meta_ads.update_budget": ToolDescriptor(
        description="Update the daily budget of one campaign or ad set under approval in minor units inside the contract and connection ceilings; campaign-level budgets need campaign budget optimisation.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("object_id", "str", required=True, description="Numeric campaign or ad set id."),
            InputField("daily_budget_minor", "int", required=True, description="New daily budget in minor units."),
        ),
        effect_class="write",
    ),
    "meta_ads.pause_campaign": ToolDescriptor(
        description="Pause one campaign under approval; the only status change the platform performs.",
        input_fields=(
            InputField("ad_account_id", "str", required=True, description="act_<id>; must equal the bound account."),
            InputField("campaign_id", "str", required=True, description="Numeric campaign id."),
        ),
        effect_class="write",
    ),
    "gbp.list_locations": ToolDescriptor(
        description="Read up to 50 listings of the bound Business Profile account: title in clear, location ids and phones as commitments.",
        input_fields=(
            InputField("read_mask_version", "str", required=True, default="v1", description="The governed contract requires v1."),
            InputField("page_token", "str", description="Continuation token from a previous page."),
        ),
        effect_class="read",
    ),
    "gbp.get_voice_of_merchant_state": ToolDescriptor(
        description="Read the verification state of the bound listing; no API performs verification, this reports it and closes the listing_verified gate.",
        input_fields=(InputField("probe", "str", required=True, default="voice_of_merchant", description="The governed contract requires voice_of_merchant."),),
        effect_class="read",
    ),
    "gbp.get_location_performance": ToolDescriptor(
        description=(
            "Read exact daily local-presence metrics (calls, bookings, direction requests, impressions) of the bound listing "
            "inside a closed window of at most 92 days. A series the provider omits is an error, never a zero."
        ),
        input_fields=(
            InputField("daily_metrics", "list[str]", required=True, description="One to eleven DailyMetric names, unique."),
            InputField("window_start", "str", required=True, description="First day (YYYY-MM-DD), within the last 18 months."),
            InputField("window_end", "str", required=True, description="Last day (YYYY-MM-DD), at most 92 days after the start."),
        ),
        effect_class="read",
    ),
    "anthropic_admin.get_cost_report": ToolDescriptor(
        description=(
            "Read what Anthropic bills for a closed window of whole UTC days: one line per model, token type and service tier, "
            "amounts as exact integer micros, workspaces as commitments. The provider's money, not a price-catalog quote."
        ),
        input_fields=(
            InputField("window_start", "str", required=True, description="First day as a UTC midnight date-time (YYYY-MM-DDT00:00:00Z)."),
            InputField("window_end", "str", required=True, description="Exclusive end as a UTC midnight date-time, at most 93 days after the start."),
            InputField("bucket_width", "str", required=True, default="1d", description="The governed contract requires 1d."),
            InputField("group_by", "list[str]", required=True, description="Exactly [\"description\", \"workspace_id\"]."),
        ),
        effect_class="read",
    ),
    "anthropic_admin.get_usage_report": ToolDescriptor(
        description="Read Anthropic token usage by model, service tier and workspace for a closed window; cost is structurally zero and priced_externally is true.",
        input_fields=(
            InputField("window_start", "str", required=True, description="First day as a UTC midnight date-time (YYYY-MM-DDT00:00:00Z)."),
            InputField("window_end", "str", required=True, description="Exclusive end as a UTC midnight date-time, at most 93 days after the start."),
            InputField("bucket_width", "str", required=True, default="1d", description="The governed contract requires 1d."),
            InputField("group_by", "list[str]", required=True, description="Exactly [\"model\", \"service_tier\", \"workspace_id\"]."),
        ),
        effect_class="read",
    ),
    "openai_admin.get_costs": ToolDescriptor(
        description=(
            "Read what OpenAI bills for a closed window of whole UTC days grouped by line item and project: the line item names "
            "the model and token type; the float source amount lands as exact integer micros; projects as commitments."
        ),
        input_fields=(
            InputField("window_start", "str", required=True, description="First day as a UTC midnight date-time (YYYY-MM-DDT00:00:00Z)."),
            InputField("window_end", "str", required=True, description="Exclusive end as a UTC midnight date-time, at most 93 days after the start."),
            InputField("bucket_width", "str", required=True, default="1d", description="The governed contract requires 1d."),
            InputField("group_by", "list[str]", required=True, description="Exactly [\"line_item\", \"project_id\"]."),
        ),
        effect_class="read",
    ),
    "openai_admin.get_usage": ToolDescriptor(
        description="Read OpenAI completions usage by model, project and batch flag for a closed window; cost is structurally zero and priced_externally is true.",
        input_fields=(
            InputField("window_start", "str", required=True, description="First day as a UTC midnight date-time (YYYY-MM-DDT00:00:00Z)."),
            InputField("window_end", "str", required=True, description="Exclusive end as a UTC midnight date-time, at most 93 days after the start."),
            InputField("bucket_width", "str", required=True, default="1d", description="The governed contract requires 1d."),
            InputField("group_by", "list[str]", required=True, description="Exactly [\"model\", \"project_id\", \"batch\"]."),
        ),
        effect_class="read",
    ),
    "google_cloud_billing.query_ai_costs": ToolDescriptor(
        description=(
            "Read Gemini and Vertex AI cost for a closed window from the Cloud Billing export in BigQuery with a parameterised query "
            "the caller cannot shape; credits netted; an unmapped SKU is an error, never a dropped cost. Google exposes no per-model usage API."
        ),
        input_fields=(
            InputField("window_start", "str", required=True, description="First day as a UTC midnight date-time (YYYY-MM-DDT00:00:00Z)."),
            InputField("window_end", "str", required=True, description="Exclusive end as a UTC midnight date-time, at most 93 days after the start."),
            InputField("query_version", "str", required=True, default="v1", description="The governed contract requires v1."),
        ),
        effect_class="read",
    ),
    "gbp.get_location": ToolDescriptor(
        description="Read the bound listing profile as commitments plus a profile digest, so an edit made outside the loop is detectable.",
        input_fields=(InputField("probe", "str", required=True, default="location", description="The governed contract requires location."),),
        effect_class="read",
    ),
    "search_console.query_analytics": ToolDescriptor(
        description=(
            "Read the exact organic clicks, impressions, position and CTR per page and day for the "
            "bound Search Console property inside a closed window of at most 92 days; page URLs "
            "leave the platform only as sha256 commitments."
        ),
        input_fields=(
            InputField("window_start", "str", required=True, description="First day (YYYY-MM-DD)."),
            InputField("window_end", "str", required=True, description="Last day (YYYY-MM-DD), at most 92 days after the start."),
            InputField("dimensions", "list[str]", required=True, default='["date", "page"]', description="The governed contract requires exactly date and page."),
            InputField("data_state", "str", required=True, default="final", description="The governed contract requires final."),
        ),
        effect_class="read",
    ),
    "airwallex.list_balances": ToolDescriptor(
        description="Read the current Airwallex balances per currency. Takes no arguments.",
        effect_class="read",
    ),
    "airwallex.list_transactions": ToolDescriptor(
        description="Read one bounded page of Airwallex financial transactions inside an optional creation window.",
        input_fields=(
            InputField("from_created_at", "str", description="Window start (ISO-8601 timestamp)."),
            InputField("to_created_at", "str", description="Window end (ISO-8601 timestamp)."),
            InputField("page_num", "int", description="Zero-based page number."),
            InputField("page_size", "int", description="Page size, 1-100 (default 100)."),
        ),
        effect_class="read",
    ),
    "airwallex.list_payouts": ToolDescriptor(
        description="Read one bounded page of Airwallex payouts inside an optional creation window.",
        input_fields=(
            InputField("from_created_at", "str", description="Window start (ISO-8601 timestamp)."),
            InputField("to_created_at", "str", description="Window end (ISO-8601 timestamp)."),
            InputField("page_num", "int", description="Zero-based page number."),
            InputField("page_size", "int", description="Page size, 1-100 (default 100)."),
        ),
        effect_class="read",
    ),
    "airwallex.create_payment": ToolDescriptor(
        description=(
            "Create one Airwallex payment to a saved beneficiary with an exact idempotent "
            "request id. Approval required; every field is bounded and nothing else is forwarded."
        ),
        input_fields=(
            InputField("request_id", "str", required=True, description="Idempotent request id (8-64 URL-safe characters)."),
            InputField("beneficiary_id", "str", required=True, description="Saved Airwallex beneficiary id."),
            InputField("payment_amount", "str", required=True, description="Positive amount with at most two decimals."),
            InputField("payment_currency", "str", required=True, description="ISO-4217 currency the beneficiary receives."),
            InputField("source_currency", "str", required=True, description="ISO-4217 currency debited."),
            InputField("reason", "str", required=True, description="Payment reason code (lower snake case)."),
            InputField("reference", "str", required=True, description="Statement reference (up to 140 printable characters)."),
            InputField("payment_date", "str", description="Optional value date (YYYY-MM-DD)."),
        ),
        effect_class="action",
    ),
    "billcom.list_bills": ToolDescriptor(
        description="Read one Bill.com bill by id, or one bounded page of bills.",
        input_fields=(
            InputField("id", "str", description="Exact bill id (cannot be combined with a page)."),
            InputField("start", "int", description="Page offset (default 0)."),
            InputField("max", "int", description="Page size, 1-100 (default 100)."),
        ),
        effect_class="read",
    ),
    "billcom.list_payments": ToolDescriptor(
        description="Read one Bill.com sent payment by id, or one bounded page of sent payments.",
        input_fields=(
            InputField("id", "str", description="Exact payment id (cannot be combined with a page)."),
            InputField("start", "int", description="Page offset (default 0)."),
            InputField("max", "int", description="Page size, 1-100 (default 100)."),
        ),
        effect_class="read",
    ),
    "billcom.list_vendors": ToolDescriptor(
        description="Read one Bill.com vendor by id, or one bounded page of vendors.",
        input_fields=(
            InputField("id", "str", description="Exact vendor id (cannot be combined with a page)."),
            InputField("start", "int", description="Page offset (default 0)."),
            InputField("max", "int", description="Page size, 1-100 (default 100)."),
        ),
        effect_class="read",
    ),
    "billcom.create_bill": ToolDescriptor(
        description=(
            "Create one Bill.com bill for a saved vendor with exact dates and amount; "
            "optional line items must sum to the amount. Approval required."
        ),
        input_fields=(
            InputField("vendorId", "str", required=True, description="Saved Bill.com vendor id."),
            InputField("invoiceNumber", "str", required=True, description="Supplier invoice number."),
            InputField("invoiceDate", "str", required=True, description="Invoice date (YYYY-MM-DD)."),
            InputField("dueDate", "str", required=True, description="Due date (YYYY-MM-DD), not before the invoice date."),
            InputField("amount", "str", required=True, description="Positive amount with at most two decimals."),
            InputField("description", "str", description="Optional memo (up to 140 characters)."),
            InputField("billLineItems", "list[str]", description="Optional line items as JSON objects with amount, description, chartOfAccountId."),
        ),
        effect_class="action",
    ),
    "billcom.approve_bill": ToolDescriptor(
        description="Set one Bill.com bill to approved (4) or denied (5). Approval required.",
        input_fields=(
            InputField("objectId", "str", required=True, description="Exact bill id."),
            InputField("approvalStatus", "str", required=True, description="'4' approved or '5' denied."),
        ),
        effect_class="action",
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
            InputField("to", "str", required=True, description="Exactly one recipient address."),
            InputField("subject", "str", required=True),
            InputField("body", "str", required=True, description="Plain-text or HTML body."),
            InputField("html", "bool", default="False", description="If true, body is treated as HTML."),
            InputField("thread_id", "str", description="Exact Gmail thread ID for an in-thread reply."),
            InputField(
                "parent_message_id",
                "str",
                description="Exact RFC Message-ID parent; required with thread_id.",
            ),
        ),
    ),
    "gmail.get_thread": ToolDescriptor(
        description=(
            "Read up to ten messages from one exact Gmail thread. Private content is "
            "returned only on the fresh response and is not replayable."
        ),
        input_fields=(
            InputField("thread_id", "str", required=True, description="Exact Gmail thread ID."),
            InputField("max_messages", "int", default="10", description="Bounded message count from 1 to 10."),
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
        description=(
            "List Stripe invoices through the governed account route, optionally filtered by customer or status. "
            "Automatic billing recovery requires one customer_id, limit=100, no status filter and has_more=false. "
            "Governed results contain minimal invoice health facts."
        ),
        input_fields=(
            InputField("customer_id", "str", description="Stripe customer ID (cus_...). Required for automatic billing recovery."),
            InputField("status", "str", description="One of: draft, open, paid, uncollectible, void. Omit for billing recovery."),
            InputField("limit", "int", default="100", description="Maximum invoices (1-100); use 100 for automatic billing recovery."),
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
            InputField("limit", "int", default="20", description="Maximum checkouts in this provider page (1-20)."),
            InputField("query", "str", description="Optional Shopify search query (e.g. 'created_at:>=2026-04-01')."),
            InputField("cursor", "str", description="Opaque cursor from the previous page's next_cursor."),
        ),
    ),
    "shopify.analytics_query": ToolDescriptor(
        description=(
            "Read one fixed, account-bound Shopify analytics observation.\n"
            "The host constructs server-owned ShopifyQL for the requested metric and exact\n"
            "UTC-day window; callers cannot submit arbitrary ShopifyQL."
        ),
        input_fields=(
            InputField(
                "target_metric",
                "str",
                required=True,
                description=(
                    "One of conversion_rate, storefront_conversion_rate, "
                    "add_to_cart_rate, checkout_completion_rate, or average_order_value."
                ),
            ),
            InputField(
                "window_start",
                "str",
                required=True,
                description="Inclusive canonical UTC-midnight instant, for example 2026-08-01T00:00:00Z.",
            ),
            InputField(
                "window_end",
                "str",
                required=True,
                description="Exclusive canonical UTC-midnight instant, 1-366 whole days after window_start.",
            ),
            InputField(
                "currency",
                "str",
                description="Required uppercase ISO currency only for average_order_value.",
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
    # ---- Shopify (storefront: collections, publishing, pages, themes, webhooks) ----
    "shopify.create_collection": ToolDescriptor(
        description=(
            "Create a custom Shopify collection (optionally seeded with products) and\n"
            "publish it to the Online Store sales channel. Use to group sellables into\n"
            "a browsable storefront category."
        ),
        input_fields=(
            InputField("title", "str", required=True, description="Collection title."),
            InputField("description_html", "str", description="Collection description (HTML allowed)."),
            InputField("handle", "str", description="URL handle (defaults to a slug of the title)."),
            InputField("product_ids", "list[str]", description="Product IDs (numeric or GIDs) to add on creation."),
            InputField(
                "publish",
                "bool",
                default="True",
                description="Publish to the Online Store channel after creation (default true).",
            ),
        ),
    ),
    "shopify.update_collection": ToolDescriptor(
        description="Update a Shopify collection's title/description and/or add products to it.",
        input_fields=(
            InputField("collection_id", "str", required=True, description="Collection ID (numeric or GID)."),
            InputField("title", "str", description="New collection title."),
            InputField("description_html", "str", description="New collection description (HTML allowed)."),
            InputField("add_product_ids", "list[str]", description="Product IDs (numeric or GIDs) to add to the collection."),
        ),
    ),
    "shopify.list_publications": ToolDescriptor(
        description=(
            "List the shop's publications (sales channels such as Online Store, POS).\n"
            "Returns [{id, name}]; pass the IDs to shopify.publish_product."
        ),
        input_fields=(),
    ),
    "shopify.publish_product": ToolDescriptor(
        description=(
            "Publish a product to one or more sales channels. Defaults to publishing\n"
            "to all of the shop's publications when publication_ids is omitted."
        ),
        input_fields=(
            InputField("product_id", "str", required=True, description="Product ID (numeric or GID)."),
            InputField(
                "publication_ids",
                "list[str]",
                description="Publication IDs (numeric or GIDs) to publish to. Defaults to all publications.",
            ),
        ),
    ),
    "shopify.verify_product_readiness": ToolDescriptor(
        description=(
            "Read exact Shopify Admin and storefront evidence after publication. "
            "The governed host verifies the requested product, publications, title, "
            "price, currency, public landing page, and checkout surface without "
            "returning raw storefront HTML."
        ),
        input_fields=(
            InputField(
                "product_id",
                "str",
                required=True,
                description="Exact Shopify product ID (numeric or GID).",
            ),
            InputField(
                "publication_ids",
                "list[str]",
                required=True,
                description="Non-empty exact publication IDs that must contain the product.",
            ),
            InputField(
                "expected_title",
                "str",
                required=True,
                description="Approved product title expected in Admin and on the landing page.",
            ),
            InputField(
                "expected_price",
                "str",
                required=True,
                description="Approved canonical two-decimal variant price.",
            ),
            InputField(
                "expected_currency",
                "str",
                required=True,
                description="Approved uppercase ISO-4217 shop currency.",
            ),
            InputField(
                "landing_url",
                "str",
                required=True,
                description="Canonical HTTPS landing URL expected from Shopify Admin.",
            ),
            InputField(
                "publication_completed_at",
                "str",
                required=True,
                description="UTC completion time of the governed publication write.",
            ),
        ),
    ),
    "shopify.create_webhook_subscription": ToolDescriptor(
        description=(
            "Subscribe to a Shopify webhook topic (e.g. ORDERS_CREATE) delivered to an\n"
            "HTTPS callback URL. Use to sync order/product events back to the platform."
        ),
        input_fields=(
            InputField("topic", "str", required=True, description="Webhook topic (e.g. ORDERS_CREATE, PRODUCTS_UPDATE)."),
            InputField("callback_url", "str", required=True, description="HTTPS endpoint that receives the webhook payloads."),
            InputField("format", "str", default="\"JSON\"", description="Delivery format: JSON or XML (default JSON)."),
        ),
    ),
    "shopify.list_webhook_subscriptions": ToolDescriptor(
        description="List the shop's active webhook subscriptions ([{id, topic, callback_url}]).",
        input_fields=(),
    ),
    "shopify.delete_webhook_subscription": ToolDescriptor(
        description="Delete a Shopify webhook subscription by ID.",
        input_fields=(
            InputField(
                "webhook_subscription_id",
                "str",
                required=True,
                description="Webhook subscription ID (numeric or GID).",
            ),
        ),
    ),
    "shopify.list_themes": ToolDescriptor(
        description="List the shop's Online Store themes ([{id, name, role}]; role MAIN is the live theme).",
        input_fields=(),
    ),
    "shopify.publish_theme": ToolDescriptor(
        description=(
            "Publish a ready, immutable UNPUBLISHED release candidate. This operation is\n"
            "fail-closed until Spring can consume a server-retained duplicate-candidate\n"
            "content proof; role alone and caller-supplied digests are never publication\n"
            "authority. Once that custody bridge exists, provider readback verifies Shopify returns MAIN.\n"
            "The connector also re-reads the exact approved theme preimage immediately before dispatch.\n"
            "This live write remains approval-gated."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="UNPUBLISHED candidate theme ID (numeric or GID)."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for publication.",
            ),
        ),
    ),
    "shopify.create_page": ToolDescriptor(
        description="Create an Online Store content page (e.g. About, FAQ, Services).",
        input_fields=(
            InputField("title", "str", required=True, description="Page title."),
            InputField("body_html", "str", required=True, description="Page body (HTML)."),
            InputField("handle", "str", description="URL handle (defaults to a slug of the title)."),
            InputField("is_published", "bool", default="True", description="Publish immediately (default true)."),
        ),
    ),
    "shopify.update_page": ToolDescriptor(
        description="Update an Online Store page's title, body, or publish state.",
        input_fields=(
            InputField("page_id", "str", required=True, description="Page ID (numeric or GID)."),
            InputField("title", "str", description="New page title."),
            InputField("body_html", "str", description="New page body (HTML)."),
            InputField("is_published", "bool", description="Set the page's publish state."),
        ),
    ),
    "shopify.create_draft_order": ToolDescriptor(
        description=(
            "Create a Shopify draft order and return its invoice_url \u2014 an instant\n"
            "payment link the customer can pay online. Use for services, custom\n"
            "quotes, or any sellable without a fixed product variant."
        ),
        input_fields=(
            InputField(
                "line_items",
                "list[str]",
                required=True,
                description=(
                    "JSON-string list of line items: "
                    "[{variant_id?, title?, quantity, original_unit_price?, currency_code?, "
                    "requires_shipping?, taxable?}]. "
                    "Use variant_id for catalog products. Every custom line item requires "
                    "title and a positive original_unit_price; use requires_shipping=false "
                    "and taxable=false for non-taxable services. All priced lines must use "
                    "one presentment currency."
                ),
            ),
            InputField(
                "presentment_currency_code",
                "str",
                description=(
                    "Shopify CurrencyCode for the draft. When omitted for priced lines, "
                    "the connected shop's currency is used."
                ),
            ),
            InputField("customer_id", "str", description="Existing customer ID (numeric or GID) to attach."),
            InputField("email", "str", description="Customer email for the invoice (when no customer_id)."),
            InputField("note", "str", description="Internal note on the draft order."),
        ),
    ),
    # ---- Shopify (theme studio: development themes, release candidates, pages) ----
    "shopify.get_theme": ToolDescriptor(
        description=(
            "Fetch a single Online Store theme (id, name, role, processing state) and its\n"
            "canonical preimage_sha256 for approval-bound mutation race checks.\n"
            "For an accepted non-MAIN artifact, Spring may return an opaque, expiring\n"
            "preview_ref bound to the exact store, theme, project, run, and artifact digest.\n"
            "Clients must never construct a preview URL or nominate a host/account."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="Theme ID (numeric or GID)."),
        ),
    ),
    "shopify.list_theme_files": ToolDescriptor(
        description=(
            "List the filenames in a theme (templates/, sections/, assets/, config/, ...).\n"
            "Supports wildcard filename filters to scope the listing."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="Theme ID (numeric or GID)."),
            InputField(
                "filenames",
                "list[str]",
                description="Optional filename filters; wildcards supported (e.g. 'templates/*', 'config/settings_data.json').",
            ),
        ),
    ),
    "shopify.get_theme_files": ToolDescriptor(
        description=(
            "Fetch the bodies of up to 50 theme files by exact filename. Read files\n"
            "before editing them so upserts preserve the base theme's structure."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="Theme ID (numeric or GID)."),
            InputField("filenames", "list[str]", required=True, description="Exact filenames to fetch (1-50 per call)."),
        ),
    ),
    "shopify.upsert_theme_files": ToolDescriptor(
        description=(
            "Create or update up to 50 files on a DEVELOPMENT theme in one call.\n"
            "UNPUBLISHED release candidates and MAIN themes are immutable and refused with\n"
            "SHOPIFY_THEME_ROLE_PROTECTED. The connector waits for the bounded Shopify job\n"
            "and independently compares exact filename/body representation digests."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="DEVELOPMENT theme ID (numeric or GID)."),
            InputField(
                "files",
                "list[str]",
                required=True,
                description=(
                    "JSON-string list of files (max 50): "
                    "[{filename, content?, url?, base64?}]. "
                    "Use content for text bodies (Liquid/JSON/CSS); url or base64 for binary assets."
                ),
            ),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for this file mutation.",
            ),
        ),
    ),
    "shopify.delete_theme_files": ToolDescriptor(
        description=(
            "Delete up to 50 files from a DEVELOPMENT theme. This operation currently\n"
            "fails closed before dispatch until Spring can durably retain a complete\n"
            "recovery snapshot before the provider boundary. UNPUBLISHED release\n"
            "candidates and MAIN themes are immutable (SHOPIFY_THEME_ROLE_PROTECTED)."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="DEVELOPMENT theme ID (numeric or GID)."),
            InputField("filenames", "list[str]", required=True, description="Exact filenames to delete (1-50 per call)."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for deletion.",
            ),
        ),
    ),
    "shopify.create_theme": ToolDescriptor(
        description=(
            "Create a new DEVELOPMENT theme from a theme zip URL (defaults to Shopify's\n"
            "Horizon reference theme). Shopify may process the import asynchronously;\n"
            "provider acceptance requires get_theme readback before a release cut."
        ),
        input_fields=(
            InputField("name", "str", required=True, description="Theme name (e.g. 'Lightbulb Development - Spring Concept')."),
            InputField("source", "str", description="Public URL of a theme zip to import (defaults to Shopify Horizon)."),
            InputField("role", "str", description="Optional role; DEVELOPMENT is the only accepted value and the default."),
        ),
    ),
    "shopify.duplicate_theme": ToolDescriptor(
        description=(
            "Cut an immutable UNPUBLISHED release candidate from an explicit, ready\n"
            "DEVELOPMENT source. The connector pre-reads the source role/processing state\n"
            "and verifies the destination role; acceptance still requires get_theme readback."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="Explicit DEVELOPMENT source theme ID (numeric or GID)."),
            InputField("name", "str", description="Name for the UNPUBLISHED release candidate."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for the source theme.",
            ),
        ),
    ),
    "shopify.update_theme": ToolDescriptor(
        description=(
            "Rename a DEVELOPMENT theme. UNPUBLISHED release candidates and MAIN\n"
            "themes are immutable (SHOPIFY_THEME_ROLE_PROTECTED)."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="DEVELOPMENT theme ID (numeric or GID)."),
            InputField("name", "str", required=True, description="New theme name."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for this rename.",
            ),
        ),
    ),
    "shopify.delete_theme": ToolDescriptor(
        description=(
            "Permanently delete a DEVELOPMENT theme and all of its files. This operation\n"
            "currently fails closed before dispatch until Spring can durably retain a\n"
            "complete recovery snapshot before the provider boundary. UNPUBLISHED release\n"
            "candidates and MAIN themes are immutable (SHOPIFY_THEME_ROLE_PROTECTED)."
        ),
        input_fields=(
            InputField("theme_id", "str", required=True, description="DEVELOPMENT theme ID to delete (numeric or GID)."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description="Exact governed get_theme lifecycle digest approved for deletion.",
            ),
        ),
    ),
    "shopify.list_pages": ToolDescriptor(
        description="List Online Store content pages ([{id, title, handle, published}]).",
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum pages to return (1-250)."),
            InputField("query", "str", description="Optional Shopify search query (e.g. 'title:About')."),
        ),
    ),
    "shopify.get_page": ToolDescriptor(
        description="Fetch a single Online Store page including its body_html.",
        input_fields=(
            InputField("page_id", "str", required=True, description="Page ID (numeric or GID)."),
        ),
    ),
    # ---- Shopify (store media: shop files, staged uploads, product media) ----
    "shopify.stage_upload": ToolDescriptor(
        description=(
            "Reserve a Shopify-hosted upload target for binary you hold locally.\n"
            "Returns url + parameters to POST the bytes to, and a resource_url to\n"
            "hand to shopify.create_file / shopify.attach_product_media. Skip this\n"
            "entirely when the image already has a public URL."
        ),
        input_fields=(
            InputField("filename", "str", required=True, description="Filename to stage (e.g. 'hero.jpg')."),
            InputField("mime_type", "str", required=True, description="MIME type of the upload (e.g. 'image/jpeg')."),
            InputField("resource", "str", default="\"IMAGE\"", description="Staged resource type: IMAGE (default), FILE, VIDEO, MODEL_3D."),
            InputField("http_method", "str", default="\"POST\"", description="Upload method Shopify should prepare: POST (default) or PUT."),
            InputField("file_size", "str", description="Byte size of the upload; required by Shopify for VIDEO/MODEL_3D."),
        ),
    ),
    "shopify.create_file": ToolDescriptor(
        description=(
            "Create shop files (images/media) from public URLs or staged resource\n"
            "urls, so real imagery can be referenced from theme templates and pages.\n"
            "Pass a single file inline, or a files list for up to 50 per call."
        ),
        input_fields=(
            InputField("original_source", "str", description="Public URL or staged resource_url for a single file. Required unless files is given."),
            InputField("content_type", "str", default="\"IMAGE\"", description="Shopify file content type: IMAGE (default), FILE, VIDEO, EXTERNAL_VIDEO, MODEL_3D."),
            InputField("alt", "str", description="Alt text for the single-file form."),
            InputField("filename", "str", description="Filename override for the single-file form."),
            InputField(
                "files",
                "list[str]",
                description=(
                    "JSON-string list of files (max 50): "
                    "[{original_source, content_type?, alt?, filename?}]. "
                    "Replaces the single-file fields when provided."
                ),
            ),
        ),
    ),
    "shopify.attach_product_media": ToolDescriptor(
        description=(
            "Attach media (product shots) to an existing product from public URLs or\n"
            "staged resource urls. Up to 50 entries per call. Shopify processes media\n"
            "asynchronously, so freshly attached images may report status UPLOADED\n"
            "before they render on the storefront."
        ),
        input_fields=(
            InputField("product_id", "str", required=True, description="Product ID to attach media to (numeric or GID)."),
            InputField(
                "media",
                "list[str]",
                required=True,
                description=(
                    "JSON-string list of media (max 50): "
                    "[{original_source, media_content_type?, alt?}]. "
                    "original_source is a public URL or a staged resource_url."
                ),
            ),
        ),
    ),
    "shopify.list_files": ToolDescriptor(
        description=(
            "List shop files ([{id, status, url, alt, width, height, created_at}]).\n"
            "Use it to reuse imagery the store already owns instead of re-uploading."
        ),
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum files to return (1-250)."),
            InputField("query", "str", description="Optional Shopify search query (e.g. 'filename:hero*')."),
            InputField("after", "str", description="Pagination cursor from a previous call's next_cursor."),
        ),
    ),
    # ---- Shopify (storefront navigation: online-store menus) ----
    "shopify.list_menus": ToolDescriptor(
        description=(
            "List storefront navigation menus with their nested items\n"
            "([{id, handle, title, is_default, items}]).\n"
            "Requires the online-store-navigation scopes; a connection without them\n"
            "returns SHOPIFY_NAVIGATION_SCOPE_REQUIRED (offer a Shopify reconnect)."
        ),
        input_fields=(
            InputField("limit", "int", default="50", description="Maximum menus to return (1-250)."),
            InputField("after", "str", description="Pagination cursor from a previous call's next_cursor."),
        ),
    ),
    "shopify.get_menu": ToolDescriptor(
        description=(
            "Fetch a single storefront navigation menu with up to three item levels.\n"
            "Read the menu before updating it — menuUpdate replaces the whole item\n"
            "tree. The governed read returns preimage_sha256 for exact update/delete\n"
            "approval binding. Requires the online-store-navigation scopes; a connection without\n"
            "them returns SHOPIFY_NAVIGATION_SCOPE_REQUIRED."
        ),
        input_fields=(
            InputField("menu_id", "str", required=True, description="Menu ID (numeric or GID)."),
        ),
    ),
    "shopify.create_menu": ToolDescriptor(
        description=(
            "Create a storefront navigation menu (e.g. a 'main-menu' replacement or a\n"
            "footer menu) with at most three item levels. The connector independently\n"
            "reads back and compares the complete tree before success. Requires the online-store-navigation\n"
            "scopes; a connection without them returns\n"
            "SHOPIFY_NAVIGATION_SCOPE_REQUIRED (offer a Shopify reconnect)."
        ),
        input_fields=(
            InputField("title", "str", required=True, description="Menu title shown in the admin (e.g. 'Main menu')."),
            InputField("handle", "str", required=True, description="Menu handle referenced by the theme (e.g. 'main-menu', 'footer')."),
            InputField(
                "items",
                "list[str]",
                required=True,
                description=(
                    "JSON-string list of menu items: "
                    "[{title, type?, url?, resource_id?, items?}]. "
                    "type defaults to HTTP (a plain link); use COLLECTION/PRODUCT/PAGE/"
                    "CATALOG with resource_id (a GID) to link store resources. "
                    "Nested items may be at most three levels deep."
                ),
            ),
        ),
    ),
    "shopify.update_menu": ToolDescriptor(
        description=(
            "Replace a storefront navigation menu's title, handle, and full item tree.\n"
            "This is a whole-menu replacement — read the menu first with\n"
            "shopify.get_menu, approve its exact semantic preimage, and send back every\n"
            "item you want to keep. The connector re-reads the preimage immediately before\n"
            "dispatch and independently compares the complete result. Requires the\n"
            "online-store-navigation scopes; a connection without them returns\n"
            "SHOPIFY_NAVIGATION_SCOPE_REQUIRED (offer a Shopify reconnect)."
        ),
        input_fields=(
            InputField("menu_id", "str", required=True, description="Menu ID to update (numeric or GID)."),
            InputField("title", "str", required=True, description="Menu title (send the existing title to keep it)."),
            InputField("handle", "str", required=True, description="Menu handle (send the existing handle to keep it)."),
            InputField(
                "items",
                "list[str]",
                required=True,
                description=(
                    "JSON-string list of the menu's complete item tree: "
                    "[{title, type?, url?, resource_id?, items?}]. "
                    "Items omitted here are removed from the menu."
                ),
            ),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description=(
                    "Exact governed get_menu semantic-tree digest approved for replacement. "
                    "A changed digest fails before provider dispatch."
                ),
            ),
        ),
    ),
    "shopify.delete_menu": ToolDescriptor(
        description=(
            "Permanently delete a storefront navigation menu only while its exact governed\n"
            "semantic preimage still matches. The connector retains a sanitized recovery\n"
            "snapshot and independently proves provider-side absence. Destructive: any\n"
            "theme section bound to the menu handle loses its links. Requires the\n"
            "online-store-navigation scopes; a connection without them returns\n"
            "SHOPIFY_NAVIGATION_SCOPE_REQUIRED (offer a Shopify reconnect)."
        ),
        input_fields=(
            InputField("menu_id", "str", required=True, description="Menu ID to delete (numeric or GID)."),
            InputField(
                "expected_preimage_sha256",
                "str",
                required=True,
                description=(
                    "Exact governed get_menu semantic-tree digest approved for deletion. "
                    "The connector retains the sanitized preimage as recovery evidence."
                ),
            ),
        ),
    ),
    "shopify.send_draft_order_invoice": ToolDescriptor(
        description=(
            "Send a Shopify draft-order invoice email containing its secure checkout link. "
            "Omit `to` when the draft order already has an attached customer or email."
        ),
        input_fields=(
            InputField(
                "draft_order_id",
                "str",
                required=True,
                description="Draft order ID (numeric or GID).",
            ),
            InputField("to", "str", description="Optional recipient email override."),
            InputField("subject", "str", description="Optional invoice email subject."),
            InputField(
                "custom_message",
                "str",
                description="Optional message included in the invoice email.",
            ),
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
    # ---- Ecommerce (catalog / order / customer CRUD) ----
    "ecommerce.get_product": ToolDescriptor(
        description="Fetch a single product (with up to 10 variants incl. price, SKU, inventory) by ID.",
        input_fields=(
            InputField("product_id", "str", required=True, description="Product ID (numeric or GID)."),
        ),
    ),
    "ecommerce.create_product": ToolDescriptor(
        description="Create a product in the connected store. Returns the created product with its ID.",
        input_fields=(
            InputField("title", "str", required=True, description="Product title."),
            InputField("description", "str", description="Product description (HTML allowed)."),
            InputField("vendor", "str", description="Vendor / brand name."),
            InputField("product_type", "str", description="Product type / category label."),
            InputField("status", "str", description="One of: ACTIVE, DRAFT, ARCHIVED."),
            InputField("tags", "list[str]", description="Tags to apply to the product."),
            InputField(
                "price",
                "str",
                description=(
                    "Optional decimal price for the default product variant. "
                    "The connected store's currency applies."
                ),
            ),
            InputField("sku", "str", description="SKU for the default product variant."),
            InputField("taxable", "bool", description="Whether the default variant is taxable."),
            InputField(
                "requires_shipping",
                "bool",
                description="Whether the default variant requires physical shipping.",
            ),
        ),
    ),
    "ecommerce.update_product": ToolDescriptor(
        description=(
            "Update product fields and/or an explicitly identified product variant.\n"
            "Variant fields require variant_id; provide at least one product or variant field."
        ),
        input_fields=(
            InputField("product_id", "str", required=True, description="Product ID (numeric or GID)."),
            InputField(
                "variant_id",
                "str",
                description="Variant ID (numeric or GID), required when changing variant fields.",
            ),
            InputField("title", "str", description="New product title."),
            InputField("description", "str", description="New product description (HTML allowed)."),
            InputField("vendor", "str", description="New vendor / brand name."),
            InputField("product_type", "str", description="New product type."),
            InputField("status", "str", description="One of: ACTIVE, DRAFT, ARCHIVED."),
            InputField("tags", "list[str]", description="Tags to set (replaces existing tags)."),
            InputField("price", "str", description="New variant price in the shop's currency."),
            InputField("sku", "str", description="New variant SKU."),
            InputField("taxable", "bool", description="Whether the variant is taxable."),
            InputField(
                "requires_shipping",
                "bool",
                description="Whether the variant requires physical shipping.",
            ),
        ),
    ),
    "ecommerce.get_order": ToolDescriptor(
        description="Fetch a single order (line items, customer, shipping address, totals) by ID.",
        input_fields=(
            InputField("order_id", "str", required=True, description="Order ID (numeric or GID)."),
            InputField("line_item_limit", "int", default="50", description="Max line items to fetch (1-250)."),
        ),
    ),
    "ecommerce.update_order": ToolDescriptor(
        description=(
            "Update an order's email, note, tags, or shipping address.\n"
            "Provide at least one field beyond order_id."
        ),
        input_fields=(
            InputField("order_id", "str", required=True, description="Order ID (numeric or GID)."),
            InputField("email", "str", description="New contact email for the order."),
            InputField("note", "str", description="Internal note to set on the order."),
            InputField("tags", "list[str]", description="Tags to set (replaces existing tags)."),
            InputField(
                "shipping_address",
                "dict",
                description="Shipping address object (address1, city, province, zip, country, ...).",
            ),
        ),
    ),
    "ecommerce.get_customer": ToolDescriptor(
        description="Fetch a single customer (contact info, tags, order count, amount spent, default address) by ID.",
        input_fields=(
            InputField("customer_id", "str", required=True, description="Customer ID (numeric or GID)."),
        ),
    ),
    "ecommerce.create_customer": ToolDescriptor(
        description="Create a customer in the connected store. Provide at least one of email or phone.",
        input_fields=(
            InputField("email", "str", description="Customer email (required unless phone is provided)."),
            InputField("phone", "str", description="Customer phone in E.164 format (required unless email is provided)."),
            InputField("first_name", "str", description="Customer first name."),
            InputField("last_name", "str", description="Customer last name."),
            InputField("note", "str", description="Internal note to attach to the customer."),
            InputField("tags", "list[str]", description="Tags to apply to the customer."),
            InputField("tax_exempt", "bool", description="Mark the customer tax-exempt."),
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


def domain_action_effect(domain: str, action: str) -> Literal["read", "action"]:
    """Return declared domain effect, retaining action for undeclared contracts."""

    descriptor = get_domain_descriptor(domain, action)
    if descriptor is not None and descriptor.effect_class is not None:
        return descriptor.effect_class
    return "action"


def get_connector_descriptor(tool_key: str) -> Optional[ToolDescriptor]:
    return CONNECTOR_OP_DESCRIPTORS.get(tool_key)


def descriptor_count() -> Dict[str, int]:
    return {
        "domain_actions": len(DOMAIN_ACTION_DESCRIPTORS),
        "connector_ops": len(CONNECTOR_OP_DESCRIPTORS),
        "total": len(DOMAIN_ACTION_DESCRIPTORS) + len(CONNECTOR_OP_DESCRIPTORS),
    }
