"""Small cross-surface contracts for governed connector invocation."""

from __future__ import annotations

from typing import Any, Literal


EPHEMERAL_NON_REPLAYABLE_READ_TOOLS = frozenset(
    {
        "gmail.get_thread",
        "microsoft.get_conversation",
        "slack.get_conversation_thread",
        "microsoft.get_channel_thread",
        "shopify.list_abandoned_checkouts",
        "postgresql.get_customer_app_setup",
        "postgresql.get_customer_workspace",
        "stripe.get_subscription_financials",
        "stripe.get_commerce_environment",
        "stripe.get_referral_credit",
    }
)
EPHEMERAL_READ_IDEMPOTENCY_ERROR = "ephemeral_read_idempotency_unsupported"
CONNECTOR_SURFACE_EFFECT_CATALOG_VERSION = "2026-09-05.1"

# Exact reads reviewed by Spring's governed execution authority. This is an
# execution allowlist, not the MCP annotation catalog: a connector operation
# may be semantically read-only while remaining unavailable to hosted runtime
# execution until Spring admits its exact route and provenance contract.
GOVERNED_CONNECTOR_READ_TOOLS = frozenset(
    {
        "ecommerce.get_product",
        "shopify.get_shop_info",
        "shopify.verify_product_readiness",
        "shopify.analytics_query",
        "shopify.list_abandoned_checkouts",
        "google_analytics.fetch_metrics",
        "gmail.get_thread",
        "microsoft.get_conversation",
        "quickbooks.get_journal_entry",
        "quickbooks.get_period_status",
        "quickbooks.general_ledger_report",
        "quickbooks.list_accounts",
        "quickbooks.list_bills",
        "quickbooks.list_invoices",
        "quickbooks.list_payments",
        "quickbooks.observe_invoice_issued",
        "quickbooks.observe_invoice_payment_applied",
        "quickbooks.observe_bill_payment_applied",
        "stripe.list_balance_transactions",
        "stripe.list_invoices",
        "stripe.get_checkout_session",
        "stripe.get_subscription_checkout",
        "stripe.get_customer_subscription",
        "stripe.get_checkout_financials",
        "stripe.get_subscription_financials",
        "stripe.get_commerce_environment",
        "stripe.get_referral_credit",
        "postgresql.get_customer_app_setup",
        "postgresql.get_customer_workspace",
        "stripe.observe_cash_settlement",
        "stripe.observe_account_readiness",
        "github.list_deployments",
        "posthog.query_events",
        "search_console.query_analytics",
        "google_ads.get_account",
        "google_ads.list_campaigns",
        "google_ads.get_metrics",
        "meta_ads.get_account",
        "meta_ads.list_campaigns",
        "meta_ads.get_insights",
        "gbp.list_locations",
        "gbp.get_voice_of_merchant_state",
        "gbp.get_location_performance",
        "gbp.get_location",
        "anthropic_admin.get_cost_report",
        "anthropic_admin.get_usage_report",
        "openai_admin.get_costs",
        "openai_admin.get_usage",
        "google_cloud_billing.query_ai_costs",
        "docusign.observe_envelope_status",
        "airwallex.get_global_account",
        "square.observe_locations",
        "xero.list_accounts",
        "xero.list_bills",
        "xero.list_invoices",
        "xero.list_journals",
        "xero.list_payments",
        "xero.get_period_status",
        "xero.trial_balance_report",
        "xero.observe_payrun",
        "xero.observe_timesheets",
        "xero.observe_leave",
        "xero.observe_headcount",
        "xero.observe_quote",
        "square.observe_bookings",
        "square.observe_invoice_payment",
        "twilio.lookup_message_status",
        "twilio.lookup_call_status",
        "slack.get_conversation_thread",
        "microsoft.get_channel_thread",
    }
)

# Canonical effect metadata for generated connector surfaces. Operation verbs
# are deliberately closed: a new verb must be classified here (or overridden
# below) before code generation can expose it. This avoids both unsafe
# read-defaulting and the old behavior that mislabeled every unreviewed read as
# a destructive write.
CONNECTOR_EFFECT_READ_OPERATION_PREFIXES = frozenset(
    {
        "aged",
        "analytics",
        "balance",
        "bank",
        "bas",
        "branch",
        "budget",
        "canvas",
        "cash",
        "cdc",
        "company",
        "compare",
        "default",
        "download",
        "executive",
        "fetch",
        "get",
        "gst",
        "hr",
        "integrated",
        "list",
        "lookup",
        "offboarding",
        "onboarding",
        "payroll",
        "pipeline",
        "preferences",
        "profit",
        "query",
        "read",
        "report",
        "review",
        "sdlc",
        "search",
        "team",
        "trial",
        "usergroups",
        "verify",
        "who",
        "workspace",
    }
)

CONNECTOR_EFFECT_WRITE_OPERATION_PREFIXES = frozenset(
    {
        "access",
        "action",
        "add",
        "advance",
        "api",
        "app",
        "append",
        "approve",
        "archive",
        "assign",
        "assistant",
        "attach",
        "auto",
        "batch",
        "book",
        "bulk",
        "cancel",
        "change",
        "close",
        "complete",
        "controller",
        "create",
        "deep",
        "delete",
        "dismiss",
        "dispatch",
        "dispose",
        "duplicate",
        "edit",
        "files",
        "invite",
        "join",
        "kick",
        "link",
        "log",
        "me",
        "merge",
        "modify",
        "move",
        "oauth",
        "open",
        "pay",
        "pins",
        "post",
        "publish",
        "rank",
        "reject",
        "remove",
        "replace",
        "request",
        "rerun",
        "revert",
        "schedule",
        "send",
        "set",
        "stage",
        "start",
        "submit",
        "subscribe",
        "tag",
        "transition",
        "trash",
        "trigger",
        "unarchive",
        "unfurl",
        "update",
        "upload",
        "upsert",
        "users",
        "views",
        "workflows",
        "write",
    }
)

# Mixed families whose operation verb alone is insufficient. Generic API
# request helpers stay actions because their method/payload can perform writes.
CONNECTOR_EFFECT_OVERRIDES: dict[str, Literal["read", "write"]] = {
    "postgresql.apply_customer_workspace": "write",
    "stripe.reverse_referral_credit": "write",
    "airwallex.create_global_account": "write",
    "airwallex.create_beneficiary": "write",
    "airwallex.get_global_account": "read",
    "freshservice.observe_customer_confirmation": "read",
    "freshservice.reply_ticket_public": "write",
    # The current adapter forwards caller-authored GraphQL verbatim, so this
    # surface can execute mutations despite its query-shaped name.
    "monday.query_data": "write",
    "notion.oauth_introspect": "read",
    "quickbooks.controller_snapshot": "read",
    "quickbooks.general_ledger_report": "read",
    "quickbooks.observe_invoice_issued": "read",
    "quickbooks.observe_invoice_payment_applied": "read",
    "quickbooks.observe_bill_payment_applied": "read",
    "stripe.observe_cash_settlement": "read",
    "stripe.observe_account_readiness": "read",
    # Xero Payroll AU people observers: reviewed, identity-free projections whose
    # outputs carry sha256 worker commitments only (people-payroll-reads-v1).
    "xero.observe_payrun": "read",
    "xero.observe_timesheets": "read",
    "xero.observe_leave": "read",
    "xero.observe_headcount": "read",
    "posthog.query_events": "read",
    "search_console.query_analytics": "read",
    "google_ads.get_account": "read",
    "google_ads.list_campaigns": "read",
    "google_ads.get_metrics": "read",
    "meta_ads.get_account": "read",
    "meta_ads.list_campaigns": "read",
    "meta_ads.get_insights": "read",
    "gbp.list_locations": "read",
    "gbp.get_voice_of_merchant_state": "read",
    "gbp.get_location_performance": "read",
    "gbp.get_location": "read",
    "anthropic_admin.get_cost_report": "read",
    "anthropic_admin.get_usage_report": "read",
    "openai_admin.get_costs": "read",
    "openai_admin.get_usage": "read",
    "google_cloud_billing.query_ai_costs": "read",
    "google_ads.create_campaign_budget": "write",
    "google_ads.create_campaign": "write",
    "google_ads.update_budget": "write",
    "google_ads.pause_campaign": "write",
    "meta_ads.create_campaign": "write",
    "meta_ads.create_adset": "write",
    "meta_ads.update_budget": "write",
    "meta_ads.pause_campaign": "write",
    "docusign.observe_envelope_status": "read",
    "square.observe_locations": "read",
    "salesforce.bulk_ingest_results": "read",
    "salesforce.bulk_ingest_status": "read",
    "salesforce.bulk_query_results": "read",
    "salesforce.bulk_query_status": "read",
    "shopify.bulk_operation_result": "read",
    "shopify.bulk_operation_status": "read",
    "slack.files_info": "read",
    "slack.users_info": "read",
    # This GET mints upload authority for an existing provider file. Treat it
    # as an action even though the transport itself does not upload content.
    "smokeball.get_file_upload_url": "write",
}


def connector_surface_effect(tool_name: Any) -> Literal["read", "write"]:
    """Return MCP surface risk metadata or reject an unclassified operation.

    This classification controls generated discovery and tool annotations. It
    does not admit an operation to Spring's governed execution authority.
    """

    normalized = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    if not normalized or "." not in normalized:
        raise ValueError(f"connector effect is unclassified for {tool_name!r}")
    overridden = CONNECTOR_EFFECT_OVERRIDES.get(normalized)
    if overridden is not None:
        return overridden
    operation = normalized.partition(".")[2]
    operation_prefix = operation.partition("_")[0]
    if operation_prefix in CONNECTOR_EFFECT_READ_OPERATION_PREFIXES:
        return "read"
    if operation_prefix in CONNECTOR_EFFECT_WRITE_OPERATION_PREFIXES:
        return "write"
    raise ValueError(f"connector effect is unclassified for {normalized!r}")


def is_ephemeral_non_replayable_read(tool_name: Any) -> bool:
    """Return whether a Tool exposes private rows only on its fresh response."""

    return (
        isinstance(tool_name, str)
        and tool_name.strip().lower() in EPHEMERAL_NON_REPLAYABLE_READ_TOOLS
    )


def reject_ephemeral_read_idempotency(
    tool_name: Any,
    idempotency_key: Any,
    *,
    supplied: bool | None = None,
) -> None:
    """Reject caller replay identity for an exact ephemeral private-row read.

    ``supplied`` lets an interface with an empty-string default distinguish its
    omitted value from a real key. Direct SDK clients use the normal ``None``
    sentinel and therefore do not need to pass it.
    """

    was_supplied = idempotency_key is not None if supplied is None else supplied
    if is_ephemeral_non_replayable_read(tool_name) and was_supplied:
        normalized_tool = str(tool_name).strip().lower()
        raise ValueError(
            f"{EPHEMERAL_READ_IDEMPOTENCY_ERROR}: "
            f"{normalized_tool} must omit idempotency_key and always fetches "
            "a fresh private response"
        )
