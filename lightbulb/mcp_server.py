"""Lightbulb MCP Server — exposes the platform API as Claude Code tools.

SECURITY MODEL:
    The MCP server authenticates as the REAL USER via JWT login.
    Every API call goes through Spring Boot's full security chain:
    - JWT validation → user identity
    - TenantIsolationFilter → scoped to user's tenant
    - CompanyIsolationFilter → scoped to user's company
    - RBAC permission checks → only allowed actions
    - Rate limiting → per-user limits

    Claude Code gets exactly the same access as the user. No more, no less.

Configure in .mcp.json:
    {
      "mcpServers": {
        "lightbulb": {
          "command": "python3",
          "args": ["-m", "lightbulb.mcp_server"],
          "cwd": "/path/to/lightbulb-mcp",
          "env": {
            "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
            "LIGHTBULB_EMAIL": "user@company.com",
            "LIGHTBULB_PASSWORD": "their-password"
          }
        }
      }
    }

Alternative (direct JWT, e.g. from browser session):
    "env": {
      "LIGHTBULB_URL": "...",
      "LIGHTBULB_JWT": "eyJ...",
      "LIGHTBULB_TENANT_ID": "uuid"
    }

Local/CI fallback (service auth bootstrap, intended for localhost integration tests):
    "env": {
      "LIGHTBULB_URL": "http://localhost:8080",
      "LIGHTBULB_API_KEY": "...",
      "LIGHTBULB_TENANT_ID": "uuid",
      "LIGHTBULB_USER_ID": "uuid",
      "LIGHTBULB_COMPANY_ID": "uuid"
    }
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Annotated, Any

# Ensure lightbulb package is importable when run via `mcp run` or directly
_SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if _SDK_ROOT not in sys.path:
    sys.path.insert(0, _SDK_ROOT)

import mcp.server.fastmcp.utilities.func_metadata as _fastmcp_func_metadata
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from pydantic.errors import PydanticUserError
from pydantic_core import PydanticUndefined

from lightbulb.auth import (
    AuthStrategy,
    JwtAuth,
    device_login,
    exchange_local_api_key_for_jwt,
    login,
)
from lightbulb.client import LightbulbClient
from lightbulb.token_cache import load_cached_token, save_cached_token, clear_cached_token

logger = logging.getLogger(__name__)


def _install_fastmcp_required_field_compat() -> bool:
    """Patch FastMCP's model factory when required fields break on this Pydantic build."""
    if getattr(_fastmcp_func_metadata, "_lightbulb_required_field_compat", False):
        return True

    try:
        _fastmcp_func_metadata.create_model(
            "_LightbulbFastMcpCompatProbe",
            query=Annotated[str, Field()],
        )
        return False
    except PydanticUserError:
        pass

    original_create_model = _fastmcp_func_metadata.create_model

    def _compat_create_model(*args: Any, **kwargs: Any):
        normalized_kwargs: dict[str, Any] = {}
        for key, value in kwargs.items():
            if key.startswith("__") or isinstance(value, tuple):
                normalized_kwargs[key] = value
            else:
                normalized_kwargs[key] = (value, PydanticUndefined)
        return original_create_model(*args, **normalized_kwargs)

    _fastmcp_func_metadata.create_model = _compat_create_model
    _fastmcp_func_metadata._lightbulb_required_field_compat = True
    logger.info("Applied FastMCP/Pydantic required-field compatibility patch for Lightbulb MCP.")
    return True


_FASTMCP_REQUIRED_FIELD_COMPAT_ACTIVE = _install_fastmcp_required_field_compat()

# ── Configuration ────────────────────────────────────────────────────
#
# The MCP server authenticates as the REAL USER via JWT.
# This means every API call goes through the full RBAC chain —
# tenant isolation, company isolation, role checks, permission checks.
# Claude Code gets exactly the same access as the user, nothing more.
#
# Required env vars:
#   LIGHTBULB_URL       — Platform URL (default: https://agents.lightbulbpartners.com)
#   LIGHTBULB_EMAIL     — User's login email
#   LIGHTBULB_PASSWORD  — User's login password
#
# The server logs in at startup, obtains a JWT scoped to the user's
# tenant/company/roles, and uses it for all subsequent requests.

LIGHTBULB_URL = os.getenv("LIGHTBULB_URL", "https://agents.lightbulbpartners.com")
LIGHTBULB_EMAIL = os.getenv("LIGHTBULB_EMAIL", "")
LIGHTBULB_PASSWORD = os.getenv("LIGHTBULB_PASSWORD", "")

# Fallback: direct JWT if the user already has one (e.g. from browser cookie)
LIGHTBULB_JWT = os.getenv("LIGHTBULB_JWT", "")
LIGHTBULB_TENANT_ID = os.getenv("LIGHTBULB_TENANT_ID", "")
LIGHTBULB_API_KEY = os.getenv("LIGHTBULB_API_KEY", "")
LIGHTBULB_USER_ID = os.getenv("LIGHTBULB_USER_ID", "")
LIGHTBULB_COMPANY_ID = os.getenv("LIGHTBULB_COMPANY_ID", "")
LIGHTBULB_MCP_PROFILE = os.getenv("LIGHTBULB_MCP_PROFILE", "").strip().lower()

CONSULTING_WORKFLOW_TYPE = "consulting_project_workflow"
CONSULTING_LAUNCH_SCHEMA = "consulting_project_launch_experience.v1"
FIRST_CONSULTING_INTAKE_PROMPT = "What is this project trying to accomplish?"
CONSULTING_APPROVAL_GUARDRAIL = (
    "No specialist agents, Code Workspace execution, GitHub repository setup, "
    "draft PRs, deployment, or data mutation before requirements, scope, SOP impact "
    "or referenced SOPs, and work packets are approved; draft PR shipping also waits "
    "for QA/acceptance and change-management plans."
)
CONSULTING_OPENING_MESSAGE = (
    "I will open a guided Project Agent kickoff, keep the next step small, and make "
    "every approval gate visible before any specialist dispatch."
)


def _consulting_agent_routing_policy() -> dict[str, Any]:
    return {
        "schema": "consulting_agent_routing_policy.v1",
        "project_agent": (
            "Owns intake, discovery, requirements, scope, SOP impact, referenced SOPs, "
            "work-packet drafting, approvals, and Project File.md."
        ),
        "autocompany": (
            "Dispatches only approved specialist work packets and keeps approvals, "
            "blockers, and operating cases visible."
        ),
        "backbone_agent": (
            "Coordinates cross-domain reasoning and selects governed domain agents "
            "from the Lightbulb account."
        ),
        "domain_agents": [
            "coding",
            "crm",
            "content",
            "legal",
            "finance",
            "it_ops",
            "qa",
            "documentation",
            "change_management",
        ],
        "coding_agent": (
            "Receives only approved coding or IT/Ops packets with acceptance criteria, "
            "repo/workspace context, and draft PR policy."
        ),
        "dispatch_blockers": [
            "missing source facts on approved requirements",
            "missing acceptance criteria",
            "unapproved scope",
            "unapproved SOP impact or unresolved SOP references",
            "unapproved work packets",
            "open critical questions",
            "unconfirmed automation of a human approval step",
        ],
    }


def _consulting_launch_experience() -> dict[str, Any]:
    return {
        "schema": CONSULTING_LAUNCH_SCHEMA,
        "workflow_type": CONSULTING_WORKFLOW_TYPE,
        "target_surface": "product-machine",
        "first_prompt": FIRST_CONSULTING_INTAKE_PROMPT,
        "approval_guardrail": CONSULTING_APPROVAL_GUARDRAIL,
        "orchestrator": "backbone_agent",
        "orchestrator_summary": (
            "The Backbone agent coordinates cross-domain reasoning and selects governed "
            "Lightbulb domain agents only after approved work packets exist."
        ),
        "agent_routing": _consulting_agent_routing_policy(),
        "domain_agent_dispatch": {
            "allowed_after_state": "WORK_PACKETS_APPROVED",
            "routing_rule": (
                "Dispatch only approved specialist work packets with source requirements, "
                "SOP impact or referenced SOPs, acceptance criteria, and human approval flags."
            ),
            "no_generic_specialist_dispatch_from_mcp": True,
        },
        "no_surprise_dispatch": True,
        "opening_message": CONSULTING_OPENING_MESSAGE,
    }

mcp = FastMCP(
    "Lightbulb Agents",
    instructions=(
        "Lightbulb Partners Agents platform — full access to the user's account.\n\n"
        "IMPORTANT: ADMIN/TENANT users must call select_company first before using domain agents.\n\n"
        "PROJECT/CONSULTING WORKFLOW: For project ideas, custom-agent requests, workflow automation, "
        "SOP/process work, modernization, or build requests without approved scope, start or continue "
        "the consulting_project_workflow through start_consulting_project_workflow or backbone_execute. "
        "Do not jump straight to coding, "
        "GitHub, deployment, connector mutation, or customer-facing external writes. The workflow must "
        "collect intake facts with provenance, validate requirements and scope, identify SOP impact, generate SOPs/process "
        "maps, and create approved work packets before execution. When approved coding work exists, "
        "preserve workflow_type=consulting_project_workflow, dispatch_contract, code_delivery, approved "
        "requirements, approved SOPs when changed or referenced/process maps, and selected work packets in the Code Workspace "
        "executor context.\n\n"
        "DOMAIN AGENT REFERENCE (use dispatch_domain_agent with domain + action). Source of truth: agent-workers/agents/domain_registry.py.\n\n"
        "- finance: chat, query_data, finance_stripe_ledger_reconciliation, finance_ap_invoice_intake, "
        "finance_spreadsheet_tie_out, finance_forecasting, finance_forecast_interpretation, finance_risk_monitoring, "
        "finance_anomaly_investigation, finance_fraud_investigation, finance_due_diligence, "
        "finance_statement_ingest, finance_fsa_review, finance_corporate_issuers_review, "
        "finance_mna_pro_forma, finance_private_company_valuation, finance_project_valuation, "
        "finance_qoe_working_capital, finance_growth_equity_valuation, finance_lbo_model, "
        "finance_fund_metrics, finance_investment_committee_memo, finance_portfolio_monitoring, "
        "finance_revenue_leakage, finance_treasury_support, finance_payroll, "
        "xero_org_overview, xero_close_books, xero_ar_followup, xero_ap_intake_to_pay, "
        "xero_bank_reconciliation, xero_payroll_trueup, xero_reporting_pack, xero_consolidation, xero_reconciliation_review\n"
        "- intuit (QuickBooks controller): controller_snapshot, controller_review, reconcile_payments, "
        "cash_application_plan, close_packet, writeback_plan, execute_approved_action, health_check\n"
        "- crm: chat, query_data, lead_qualification, outbound_messaging, sales_call_intelligence, "
        "objection_handling, icp_intelligence, competitive_positioning, customer_health_risk, expansion_upsell, "
        "assess_pipeline, autonomous_source, strategize_lead, plan_sequence, classify_reply, verify_lead, "
        "enrich_contact, enrich_leads, propose_meeting_slots, book_meeting, agentic_plan\n"
        "- legal: matter_intake, contract_review, compliance_monitoring, document_drafting, "
        "sales_agreement_packet, partnership_agreement_packet, service_agreement_packet, nda_packet, "
        "incorporation_readiness, hr_onboarding_packet, employment_agreement_packet, "
        "smokeball_orchestration, smokeball_account_sync, smokeball_matter_operations, knowledge_assistant, ediscovery\n"
        "- engineering: chat, create_spec, engineering_design_loop, run_clash_analysis, "
        "sensor_anomaly_detection, compare_model_versions, search_project_drawings, query_analytics\n"
        "- content: chat, generate_plan, generate_content, refine, prepare_publish, seo_research, seo_optimize, "
        "competitor_analysis, sync_analytics, evolve_strategy, repurpose, schedule, dispatch, generate_variants, "
        "analyze_results, full_campaign, social_content_pipeline\n"
        "- it_ops: chat, github_repository_search, project_ops, incident_response, service_desk, deployment, qa, "
        "autocompany_software_engineering_loop, requirements_capture, plan_iteration, analysis_review, "
        "design_review, development_kickoff, testing_review, maintenance_cycle, monitoring_check, sdlc_engagement_status\n"
        "- commerce: chat, converse, knowledge_build, sync_status, sync_history, resume_sync, "
        "market_observation_ingest, market_observation_query, external_market_research, category_landscape, "
        "pricing_landscape, competitor_watchlist, trend_synthesis, assortment_gap_analysis, service_catalog, "
        "catalog_sync, inventory_check, product_analysis, pricing_intelligence, customer_segment, customer_profile, "
        "predict, personalize_campaign, campaign_brief, product_graph_query, cross_agent_insight, ab_test, "
        "order_to_invoice, customer_360, revenue_by_product, margin_analysis, inventory_valuation, "
        "reconcile_refunds, dashboard_summary, revenue_by_channel, cash_position, top_products_by_margin, "
        "customer_value_summary, economic_context, procurement_brief, supplier_search, trade_flow_lookup, "
        "tariff_lookup, supply_chain_analysis, sourcing_brief, vendor_onboarding, po_approval_workflow, "
        "supplier_evaluation, contract_to_pay, spend_analysis, vendor_risk_assessment\n"
        "- product: chat, feature_adoption, experimentation, experiment_design, feedback_synthesis, "
        "roadmap_prioritize, roadmap_plan, pricing_intelligence, customer_segment, predict, product_analysis, "
        "trend_synthesis, competitor_watchlist, assortment_gap_analysis\n"
        "- hr: chat, lookup, leave_request, onboard, offboard, headcount, compliance_check, hr_pulse "
        "(deep connectors: BambooHR, Greenhouse, Monday.com — see hr_live_* tools)\n"
        "- coding: chat, read_code, write_code, search, run_command, run_tests, build_codegraph, get_context, "
        "explain_code, propose_changes, git_status, format_code, generate_tickets, prioritize_backlog, "
        "run_pipeline, process_single_ticket, process_ticket_with_branch, watch_slack, build_page\n"
        "- document_intelligence: chat, search_documents, grep_content, list_folder, search_folder, write_document, "
        "create_report, create_marketing_document, create_marketing_collateral, create_sales_collateral, "
        "create_spreadsheet, create_slide_deck, update_document, publish_document\n"
        "- solver: chat, solve_optimization, schedule_optimization, assign_resources, constraint_satisfaction\n"
        "- customer_success: chat, churn_risk_scan, renewal_pipeline, nps_action_loop, onboarding_health, "
        "expansion_playbook, health_score_report, cs_agentic_plan\n"
        "- procurement: chat, vendor_onboarding, po_approval_workflow, supplier_evaluation, contract_to_pay, "
        "spend_analysis, vendor_risk_assessment\n"
        "- gtm: chat, launch_coordination, go_to_market_plan, launch_readiness, enablement_kit, "
        "market_entry_analysis, competitive_launch_response, gtm_intelligence_share\n"
        "- grc: chat, risk_register_scan, compliance_audit, policy_gap_analysis, regulatory_monitoring, "
        "control_testing, risk_score_report, audit_trail_export\n"
        "- smarthome: chat, status_report, command_plan, event_review, automation_review, scene_assist\n\n"
        "OTHER TOOLS:\n"
        "- Documents: search_documents, grep_documents, list_folder, search_folder, create_document, create_spreadsheet, create_slide_deck\n"
        "- Page Builder: page_builder_create, page_builder_chat, page_builder_deploy, page_builder_preview, "
        "page_builder_workspace_automation, page_builder_seo_report, page_builder_seo_optimize\n"
        "- Document Builder: doc_builder_create_session, doc_builder_send_message, doc_builder_get_messages, "
        "doc_builder_save, doc_builder_add_collaborator, doc_builder_create_share_link\n"
        "- Backbone: backbone_execute (Python REPL, research, analysis), start_consulting_project_workflow (guided consulting/project intake and dispatch)\n"
        "- Code workspace: list_code_workspaces, code_workspace_chat, code_workspace_get_run, code_workspace_wait_for_run, "
        "code_workspace_runs, code_workspace_runs_insights, code_workspace_run_review, code_workspace_proposal_apply, "
        "code_workspace_pull_request, code_workspace_collaborators, code_workspace_share_link, "
        "code_workspace_claude_sessions, code_workspace_claude_session_action (tag/fork/delete/interrupt/rewind/compact/mcp), "
        "code_workspace_codex_threads, code_workspace_codex_thread_action (rename/archive/compact/rollback/steer/interrupt)\n"
        "- HITL: list_pending_approvals, get_approval_details, approve_task, reject_task, list_approval_preferences, "
        "create_approval_auto_accept, set_approval_preference_state, delete_approval_preference\n"
        "- Voice/Phone: list_voice_executions, get_voice_execution, list_voice_pending_approvals, "
        "approve_voice_action, reject_voice_action, modify_voice_action\n"
        "- AutoCompany (AOC): list_aoc_runs, get_aoc_run, stop_aoc_run, validate_aoc_run_config, "
        "list_aoc_tasks, get_aoc_task, list_aoc_task_events, post_aoc_task_event, get_aoc_decision, "
        "list_aoc_decisions, list_aoc_ticks, get_aoc_tick\n"
        "- HR Live: hr_live_whos_out, hr_live_leave_balance, hr_live_monday_board, hr_live_cases, "
        "hr_live_recruiting_jobs, hr_live_recruiting_applications, hr_live_advance_application, "
        "hr_live_reject_application, hr_live_health\n"
        "- RAG: rag_query, rag_upload\n"
        "- Connectors: list_connectors, invoke_tool, list_connected_integrations\n"
        "- CRM: list_crm_contacts, list_crm_deals, create_crm_task, list_crm_tasks, update_crm_task, delete_crm_task\n"
        "- Artifacts: list_artifacts, get_artifact\n"
        "- Workflows: list_workflows, trigger_workflow\n"
        "- Software delivery loop: software_delivery_context, software_delivery_loop, software_spot_weld_fix "
        "(Lightbulb context bridge for Claude Code, Codex, Cursor, SDLC, CloudOps, PR, deployment, and user feedback)\n"
        "- Memory: memory_store, memory_recall, memory_search, memory_list_entries, memory_query, "
        "memory_graph, memory_projection_soul, memory_projection_memory, memory_list_identity, memory_create_identity, "
        "memory_list_events, memory_record_event, memory_list_links, memory_create_link, memory_list_skills\n"
        "- Notifications: list_notifications, mark_notification_read, mark_all_notifications_read\n"
        "- Workspace surfaces: workspace_bundle, workspace_trace, workspace_conversation, workspace_surface, "
        "it_ops_live_jira, it_ops_live_slack, it_ops_live_github, it_ops_live_notion, it_ops_mcp_manifest\n"
        "- Stripe (deep integration): stripe_dispatch, stripe_twin_list, stripe_list_pending_approvals, "
        "stripe_approve, stripe_reject, stripe_execute_approved, stripe_forecast_snapshot, stripe_account_health, stripe_run_workflow\n"
        "- Xero (deep integration): xero_agent_snapshot, xero_agent_proposals, xero_agent_create_proposal, "
        "xero_agent_approve_proposal, xero_agent_reject_proposal, xero_agent_run_sync, xero_agent_run_playbook, "
        "xero_agent_org_profile, xero_intake_invoice, xero_intake_bill, xero_intake_journal, xero_intake_payroll_trueup\n"
        "- Discovery: list_domains, list_domain_actions, list_companies, select_company, whoami\n\n"
        "All operations scoped to the user's RBAC permissions."
    ),
)

# Cached auth — login once, reuse across tool calls
_cached_auth: AuthStrategy | None = None


def _get_auth() -> AuthStrategy:
    """Get or create the JWT auth, scoped to the real user's permissions.

    Priority order:
    1. In-memory cache (already authenticated this session)
    2. Direct JWT from env var (advanced / testing)
    3. Localhost service API key (integration / CI fallback)
    4. Disk-cached token from prior device flow
    5. Device authorization flow (opens browser, user approves)
    6. Legacy email/password fallback (deprecated)
    """
    global _cached_auth
    if _cached_auth is not None:
        return _cached_auth

    # Option 1: Direct JWT provided via env
    if LIGHTBULB_JWT and LIGHTBULB_TENANT_ID:
        _cached_auth = JwtAuth(
            token=LIGHTBULB_JWT,
            tenant_id=LIGHTBULB_TENANT_ID,
            company_id=LIGHTBULB_COMPANY_ID or None,
        )
        return _cached_auth

    # Option 2: Localhost service auth bootstrap via internal API key
    if LIGHTBULB_API_KEY and LIGHTBULB_TENANT_ID and LIGHTBULB_USER_ID:
        _cached_auth = exchange_local_api_key_for_jwt(
            LIGHTBULB_URL,
            LIGHTBULB_API_KEY,
            LIGHTBULB_TENANT_ID,
            LIGHTBULB_USER_ID,
            LIGHTBULB_COMPANY_ID or None,
            purpose="lightbulb_mcp_localhost",
        )
        return _cached_auth

    # Option 3: Disk-cached token from prior device flow
    cached = load_cached_token(LIGHTBULB_URL)
    if cached:
        logger.info("Using cached token for tenant %s", cached.tenant_id)
        _cached_auth = cached
        return _cached_auth

    # Option 4: Device authorization flow (interactive)
    if sys.stderr.isatty():
        try:
            auth, expires_in = device_login(LIGHTBULB_URL, client_id="claude-code-mcp")
            save_cached_token(LIGHTBULB_URL, auth, expires_in=expires_in)
            _cached_auth = auth
            return _cached_auth
        except Exception as exc:
            logger.warning("Device flow failed: %s", exc)

    # Option 5: Legacy email/password fallback
    if LIGHTBULB_EMAIL and LIGHTBULB_PASSWORD:
        logger.warning("Using email/password auth (deprecated — use device flow instead)")
        _cached_auth = login(LIGHTBULB_URL, LIGHTBULB_EMAIL, LIGHTBULB_PASSWORD)
        return _cached_auth

    raise RuntimeError(
        "Authentication required. Either:\n"
        "  1. Run interactively (device flow will open your browser), or\n"
        "  2. Set LIGHTBULB_JWT + LIGHTBULB_TENANT_ID env vars, or\n"
        "  3. For localhost integration, set LIGHTBULB_API_KEY + LIGHTBULB_TENANT_ID + LIGHTBULB_USER_ID, or\n"
        "  4. Set LIGHTBULB_EMAIL + LIGHTBULB_PASSWORD env vars (deprecated)\n"
        "All API calls are scoped to the authenticated user's RBAC permissions."
    )


def _refresh_auth() -> None:
    """Clear cached auth and force re-authentication on next call."""
    global _cached_auth, _cached_client, _user_info
    _cached_auth = None
    _cached_client = None
    _user_info = None
    clear_cached_token(LIGHTBULB_URL)
    logger.info("Auth cleared — next tool call will re-authenticate")


_cached_client: LightbulbClient | None = None
_user_info: dict | None = None


def _get_client() -> LightbulbClient:
    """Get or create a singleton client authenticated as the real user.

    On first call, fetches user info to auto-detect role and company context.
    COMPANY users get their company set automatically from the JWT/user profile.
    ADMIN/TENANT users need to call select_company explicitly.
    """
    global _cached_client, _user_info
    if _cached_client is not None:
        return _cached_client

    auth = _get_auth()
    from lightbulb.validators import is_local_url
    is_local = is_local_url(LIGHTBULB_URL)
    client = LightbulbClient(LIGHTBULB_URL, auth=auth, enforce_https=not is_local)

    # Auto-detect user role and company
    try:
        _user_info = client.whoami()
        role = str(_user_info.get("role") or "").upper()
        company_id = str(_user_info.get("companyId") or "").strip()

        if role == "COMPANY" and company_id:
            # COMPANY users have their company baked into their identity
            client.active_company_id = company_id
            logger.info("COMPANY user — auto-set company %s", company_id)
        elif role in ("ADMIN", "TENANT"):
            # ADMIN/TENANT users must select a company before using domain agents
            if auth.company_id:
                client.active_company_id = auth.company_id
            logger.info("%s user — company selection required for domain agents", role)
    except Exception as exc:
        logger.warning("Could not fetch user info for auto-detection: %s", exc)

    _cached_client = client
    return client


def _call_with_retry(fn):
    """Call fn(); on 401 (expired JWT), refresh auth and retry once."""
    try:
        return fn()
    except Exception as exc:
        status = getattr(getattr(exc, 'response', None), 'status_code', None)
        if status == 401:
            logger.info("Got 401 — refreshing token and retrying")
            _refresh_auth()
            return fn()
        raise


def _format_result(result: Any) -> str:
    """Format a DispatchResult or dict into readable text for Claude."""
    if hasattr(result, "raw"):
        data = result.raw
        reply = getattr(result, "reply", "")
    elif isinstance(result, dict):
        data = result
        reply = data.get("reply", "")
    else:
        return str(result)

    parts = []
    if reply:
        parts.append(reply)

    outputs = data.get("outputs") or data.get("structuredOutputs") or {}

    # Search results
    if "top_hits" in outputs:
        parts.append(f"\n**{len(outputs['top_hits'])} search result(s):**")
        for hit in outputs["top_hits"][:10]:
            path = hit.get("source_path") or hit.get("document_id", "")
            snippet = (hit.get("snippet") or "")[:200]
            parts.append(f"- `{path}`: {snippet}")

    # Grep matches
    if "matches" in outputs:
        total = outputs.get("total_matches", 0)
        docs = outputs.get("total_documents", 0)
        parts.append(f"\n**{total} match(es) across {docs} document(s):**")
        for m in outputs["matches"][:10]:
            path = m.get("source_path") or m.get("document_id", "")
            count = m.get("match_count", 0)
            parts.append(f"- `{path}` — {count} match(es)")
            for line in (m.get("match_lines") or [])[:3]:
                parts.append(f"  L{line['line_number']}: {line['text'][:150]}")

    # Folder listing
    if "items" in outputs and "folder_tree" in outputs:
        parts.append(f"\n**{outputs.get('total_items', 0)} file(s) in {outputs.get('total_folders', 0)} folder(s):**")
        for item in outputs["items"][:20]:
            name = item.get("name", "Untitled")
            folder = item.get("folder_path", "")
            source = item.get("source_system", "library")
            parts.append(f"- `{folder}/{name}` ({source})")

    # Folder search results
    if "results" in outputs and "answer" in outputs:
        answer = outputs.get("answer", "")
        if answer:
            parts.append(f"\n**Answer:** {answer}")
        for r in outputs["results"][:10]:
            path = r.get("source_path") or r.get("document_id", "")
            snippet = (r.get("snippet") or "")[:200]
            parts.append(f"- `{path}`: {snippet}")

    # Write/publish result
    if "publish_result" in outputs:
        pr = outputs["publish_result"]
        doc_id = pr.get("document_id") or pr.get("documentId") or pr.get("id", "")
        url = pr.get("webUrl") or pr.get("webViewLink") or pr.get("source_url", "")
        parts.append(f"\nDocument ID: `{doc_id}`")
        if url:
            parts.append(f"URL: {url}")

    # Document details
    if "document" in outputs:
        doc = outputs["document"]
        parts.append(f"\nDocument: `{doc.get('document_id', '')}`")
        if doc.get("filename"):
            parts.append(f"File: {doc['filename']}")

    # Generic answer
    if "answer" in outputs and "results" not in outputs and "top_hits" not in outputs:
        parts.append(outputs["answer"])

    # Summary
    summary = data.get("summary") or outputs.get("summary", "")
    if summary and summary not in "\n".join(parts):
        parts.append(f"\n_{summary}_")

    return "\n".join(parts) if parts else json.dumps(data, indent=2, default=str)[:2000]


def _parse_json_argument(raw: str, field_name: str, default: Any) -> Any:
    """Parse an optional JSON string argument used by MCP tools."""
    text = str(raw or "").strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON ({exc.msg})") from exc


def _truncate_text(value: Any, limit: int = 2000) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


def _first_text(mapping: dict[str, Any] | None, *keys: str) -> str:
    if not isinstance(mapping, dict):
        return ""
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _first_dict(mapping: dict[str, Any] | None, *keys: str) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        return {}
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _first_list(mapping: dict[str, Any] | None, *keys: str) -> list[Any]:
    if not isinstance(mapping, dict):
        return []
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, list):
            return value
    return []


def _split_repository(repository: str = "", github_owner: str = "", github_repo: str = "") -> tuple[str, str, str]:
    """Normalize repository inputs into owner, repo, full_name."""
    owner = str(github_owner or "").strip()
    repo = str(github_repo or "").strip()
    full_name = str(repository or "").strip()
    full_name = full_name.removeprefix("https://github.com/")
    full_name = full_name.removeprefix("git@github.com:")
    full_name = full_name.removesuffix(".git").strip("/")
    if full_name and "/" in full_name and (not owner or not repo):
        parts = [part for part in full_name.split("/") if part]
        if len(parts) >= 2:
            owner = owner or parts[-2]
            repo = repo or parts[-1]
    if owner and repo:
        full_name = f"{owner}/{repo}"
    return owner, repo, full_name


def _parse_extra_inputs(extra_inputs: str) -> dict[str, Any] | str:
    try:
        parsed = _parse_json_argument(extra_inputs, "extra_inputs", {})
    except ValueError as exc:
        return f"Error: {exc}"
    return parsed if isinstance(parsed, dict) else {}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on", "approved", "ready"}


def _context_items(mapping: dict[str, Any] | None, *keys: str) -> list[Any]:
    if not isinstance(mapping, dict):
        return []
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, list):
            return [item for item in value if str(item or "").strip()]
        if isinstance(value, dict) and value:
            return [value]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
    return []


def _context_flag(mapping: dict[str, Any] | None, *keys: str) -> bool:
    if not isinstance(mapping, dict):
        return False
    for key in keys:
        if key in mapping:
            return _truthy(mapping.get(key))
    return False


def _context_explicit_false(mapping: dict[str, Any] | None, *keys: str) -> bool:
    if not isinstance(mapping, dict):
        return False
    for key in keys:
        if key not in mapping:
            continue
        value = mapping.get(key)
        if isinstance(value, bool):
            return not value
        if str(value).strip().lower() == "false":
            return True
    return False


def _status_reviewed(value: Any) -> bool:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return text in {
        "identified",
        "reviewed",
        "approved",
        "not_required",
        "not_applicable",
        "no_sop_needed",
        "no_sop_required",
        "no_changes",
        "none",
    }


def _sop_impact_reviewed(context: dict[str, Any], gates: dict[str, Any]) -> bool:
    for mapping in (gates, context):
        if not isinstance(mapping, dict):
            continue
        if _context_flag(
            mapping,
            "sop_impact_identified",
            "sopImpactIdentified",
            "sop_impact_reviewed",
            "sopImpactReviewed",
        ):
            return True
        if _context_explicit_false(mapping, "sop_approval_required", "sopApprovalRequired"):
            return True
        if _status_reviewed(
            _first_text(mapping, "sop_impact_status", "sopImpactStatus")
        ):
            return True
        sop_impact = _first_dict(mapping, "sop_impact", "sopImpact")
        if _status_reviewed(
            _first_text(sop_impact, "status", "review_status", "reviewStatus")
        ):
            return True
    return False


def _critical_questions_clear(gates: dict[str, Any]) -> bool:
    for key in ("open_critical_questions", "openCriticalQuestions"):
        if key in gates:
            try:
                count = int(gates.get(key))
            except (TypeError, ValueError):
                return False
            return count == 0
    return False


def _packet_sop_refs(packets: list[Any]) -> list[Any]:
    refs: list[Any] = []
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        refs.extend(_context_items(
            packet,
            "source_sop_ids",
            "sourceSopIds",
            "source_sops",
            "sourceSops",
            "related_sops",
            "relatedSops",
        ))
    return refs


def _sop_impact_or_referenced_sops_ready(
    context: dict[str, Any],
    gates: dict[str, Any],
    selected_packets: list[Any],
    source_sops: list[Any],
) -> bool:
    if (
        "sop_impact_or_referenced_sops_ready" in gates
        or "sopImpactOrReferencedSopsReady" in gates
    ):
        return _context_flag(
            gates,
            "sop_impact_or_referenced_sops_ready",
            "sopImpactOrReferencedSopsReady",
        )
    if _sop_impact_reviewed(context, gates):
        return True
    packet_sops = _packet_sop_refs(selected_packets)
    if not (source_sops or packet_sops):
        return False
    return _context_flag(gates, "sops_approved", "sopsApproved") and bool(
        _context_items(context, "approved_sops", "approvedSops") or source_sops
    )


def _approved_consulting_delivery_context_present(inputs: dict[str, Any]) -> bool:
    context = _first_dict(inputs, "project_product_machine_execution_context", "projectProductMachineExecutionContext")
    if not context:
        return False
    schema = str(context.get("schema") or "").strip()
    workflow_type = str(context.get("workflow_type") or context.get("workflowType") or "").strip()
    if schema != "project_product_machine_execution_context.v1":
        return False
    if workflow_type and workflow_type != "consulting_project_workflow":
        return False

    readiness = _first_dict(context, "delivery_readiness", "deliveryReadiness")
    if readiness and not (
        _context_flag(readiness, "delivery_setup_allowed", "deliverySetupAllowed")
        or _context_flag(readiness, "ready_for_build", "readyForBuild")
    ):
        return False

    gates = _first_dict(context, "approval_gates", "approvalGates")
    if not (
        _context_flag(gates, "requirements_approved", "requirementsApproved")
        and _context_flag(gates, "scope_approved", "scopeApproved")
        and _context_flag(gates, "work_packets_approved", "workPacketsApproved")
        and _critical_questions_clear(gates)
    ):
        return False

    selected_packets = _context_items(context, "selected_work_packets", "selectedWorkPackets")
    if not (
        _context_items(context, "approved_requirements", "approvedRequirements")
        and selected_packets
        and _context_items(context, "acceptance_criteria", "acceptanceCriteria")
        and _context_items(context, "source_requirement_ids", "sourceRequirementIds")
        and _context_items(context, "source_work_packet_ids", "sourceWorkPacketIds")
    ):
        return False

    source_sops = _context_items(context, "source_sop_ids", "sourceSopIds")
    sop_required = (
        _context_flag(gates, "sop_approval_required", "sopApprovalRequired")
        or bool(source_sops)
        or bool(_packet_sop_refs(selected_packets))
    )
    if sop_required and not (
        _context_flag(gates, "sops_approved", "sopsApproved")
        and (_context_items(context, "approved_sops", "approvedSops") or source_sops)
    ):
        return False
    if not _sop_impact_or_referenced_sops_ready(context, gates, selected_packets, source_sops):
        return False

    return True


def _consulting_shipping_governance_present(inputs: dict[str, Any]) -> bool:
    context = _first_dict(inputs, "project_product_machine_execution_context", "projectProductMachineExecutionContext")
    if not context:
        return False
    gates = _first_dict(context, "approval_gates", "approvalGates")
    qa_plan = _first_dict(context, "qa_plan", "qaPlan", "test_plan", "testPlan")
    change_plan = _first_dict(
        context,
        "change_plan",
        "changePlan",
        "change_management",
        "changeManagement",
        "rollout_plan",
        "rolloutPlan",
    )
    qa_gate = _context_flag(gates, "qa_plan_drafted", "qaPlanDrafted")
    change_gate = _context_flag(gates, "change_plan_drafted", "changePlanDrafted")
    qa_ready = (qa_gate and bool(qa_plan)) if qa_gate else bool(qa_plan)
    change_ready = (change_gate and bool(change_plan)) if change_gate else bool(change_plan)
    shipping_ready = _context_flag(gates, "shipping_gates_satisfied", "shippingGatesSatisfied")
    return qa_ready and change_ready and shipping_ready


def _request_requires_shipping_governance(request: str, inputs: dict[str, Any]) -> bool:
    if any(
        _truthy(inputs.get(key))
        for key in (
            "auto_push",
            "autoPush",
            "open_pr",
            "openPr",
            "open_pull_request",
            "openPullRequest",
            "draft_pull_request_requested",
            "draftPullRequestRequested",
        )
    ):
        return True
    text = _normalize_project_intent_text(
        " ".join([
            str(request or ""),
            json.dumps(inputs, default=str)[:3000] if inputs else "",
        ])
    )
    return _contains_any_text(
        text,
        "pull request",
        "draft pr",
        "create pull request",
        "merge pull request",
        "github create pull request",
        "github merge pull request",
    )


def _normalize_project_intent_text(value: Any) -> str:
    text = str(value or "").lower()
    for char in "\n\r\t.,;:!?()[]{}\"'`*_":
        text = text.replace(char, " ")
    return " ".join(text.split())


def _contains_any_text(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)


def _nested_dict(mapping: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = mapping
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _consulting_delivery_setup_allowed(inputs: dict[str, Any]) -> bool:
    return _approved_consulting_delivery_context_present(inputs)


def _should_route_delivery_to_consulting_workflow(
    request: str,
    inputs: dict[str, Any],
    workspace_id: str = "",
    repository_full_name: str = "",
    project_key: str = "",
) -> bool:
    """Protect rough project asks from jumping straight into repo/code execution."""
    workflow_type = str(
        inputs.get("workflow_type")
        or inputs.get("requested_workflow_type")
        or _nested_dict(inputs, "product_machine_plan").get("workflow_type")
        or ""
    ).strip().lower()
    text = _normalize_project_intent_text(
        " ".join([
            str(request or ""),
            json.dumps(inputs, default=str)[:3000] if inputs else "",
        ])
    )

    explicit_project_marker = _contains_any_text(
        text,
        "start consulting project",
        "consulting project workflow",
        "project agent",
        "product machine",
        "requirements spec",
        "requirements specification",
        "scope definition",
        "work packet",
        "work packets",
        "sop",
        "standard operating procedure",
        "github repo",
        "github repository",
        "create the repo",
        "create a repo",
        "pull request",
        "draft pr",
        "create pull request",
        "merge pull request",
        "deployment status",
        "custom agent",
        "project agent",
        "agentic workflow",
        "modernize",
        "modernization",
        "brownfield",
        "greenfield",
    )
    ready_for_direct_delivery = _consulting_delivery_setup_allowed(inputs)
    shipping_requested = _request_requires_shipping_governance(request, inputs)
    shipping_ready = _consulting_shipping_governance_present(inputs)
    if workflow_type == "consulting_project_workflow" or explicit_project_marker:
        return not ready_for_direct_delivery or (shipping_requested and not shipping_ready)
    if ready_for_direct_delivery:
        return shipping_requested and not shipping_ready
    if _truthy(inputs.get("force_software_delivery_loop")) or _truthy(inputs.get("existing_delivery_loop")):
        return False

    delivery_verb = _contains_any_text(
        text,
        "build",
        "create",
        "make",
        "ship",
        "implement",
        "develop",
        "automate",
        "launch",
        "migrate",
        "integrate",
        "refactor",
        "extend",
    )
    project_object = _contains_any_text(
        text,
        " app",
        "application",
        "software",
        "portal",
        "dashboard",
        "website",
        "workflow",
        "system",
        "tool",
        "platform",
        "integration",
        "automation",
        "project",
        "repository",
        " code",
    )
    if not delivery_verb or not project_object:
        return False

    # Existing repo/workspace/project-key loops are usually implementation feedback.
    # Route vague business ideas before those artifacts exist; require explicit
    # project markers above to reroute already-bound software loops.
    return not any(str(value or "").strip() for value in (workspace_id, repository_full_name, project_key))


def _delivery_tool_project_context(
    source_tool: str,
    request: str,
    inputs: dict[str, Any],
    workspace_id: str = "",
    repository_full_name: str = "",
    project_key: str = "",
    environment: str = "",
    mode_or_scope: str = "",
) -> str:
    context = {
        **inputs,
        "source_tool": source_tool,
        "lightbulb_mcp": {
            "schema": "lightbulb.mcp.delivery_to_consulting_reroute.v1",
            "source_tool": source_tool,
        },
        "requested_delivery": {
            "request": request,
            "workspace_id": workspace_id.strip(),
            "repository": repository_full_name.strip(),
            "project_key": project_key.strip(),
            "environment": environment.strip(),
            "mode_or_scope": mode_or_scope.strip(),
        },
    }
    context.setdefault("rerouted_from_delivery_tool", True)
    context.setdefault("routing_reason", "project_build_or_sop_intent_requires_consulting_workflow")
    return json.dumps(context, default=str)


def _repository_full_name_from_inputs(inputs: dict[str, Any]) -> str:
    repository = _first_text(inputs, "repository", "repo", "github_repository", "githubRepository")
    github_repository = _first_dict(inputs, "github_repository", "githubRepository")
    owner = _first_text(inputs, "github_owner", "githubOwner")
    repo = _first_text(inputs, "github_repo", "githubRepo")
    if github_repository:
        repository = repository or _first_text(github_repository, "full_name", "fullName", "repository")
        owner = owner or _first_text(github_repository, "owner")
        repo = repo or _first_text(github_repository, "repo", "name")
    _, _, full_name = _split_repository(repository, owner, repo)
    return full_name


def _should_route_domain_dispatch_to_consulting_workflow(
    domain: str,
    action: str,
    message: str,
    inputs: dict[str, Any],
) -> bool:
    normalized_domain = str(domain or "").strip().lower()
    normalized_action = str(action or "chat").strip().lower()
    if normalized_domain not in {"coding", "it_ops", "engineering", "product"}:
        return False

    delivery_actions = {
        "chat",
        "write_code",
        "run_command",
        "run_tests",
        "run_pipeline",
        "process_single_ticket",
        "process_ticket_with_branch",
        "create_spec",
        "engineering_design_loop",
        "project_ops",
        "deployment",
        "qa",
        "autocompany_software_engineering_loop",
        "software_engineering_loop",
        "requirements_capture",
        "development_kickoff",
        "testing_review",
        "maintenance_cycle",
        "github_repository_search",
        "build_page",
        "page_builder_web_development",
        "website_growth_loop_build",
        "website_sdlc_intake",
        "website_growth_loop_to_sdlc",
        "roadmap_plan",
        "roadmap_prioritize",
    }
    if normalized_action not in delivery_actions:
        return False

    return _should_route_delivery_to_consulting_workflow(
        message,
        inputs,
        workspace_id=_first_text(inputs, "workspace_id", "workspaceId", "code_workspace_id", "codeWorkspaceId"),
        repository_full_name=_repository_full_name_from_inputs(inputs),
        project_key=_first_text(inputs, "project_key", "projectKey", "jira_project_key", "jiraProjectKey"),
    )


def _should_route_page_builder_to_consulting_workflow(text: str) -> bool:
    normalized = _normalize_project_intent_text(text)
    if not normalized:
        return False
    return _contains_any_text(
        normalized,
        "custom agent",
        "project agent",
        "agentic workflow",
        "sop",
        "standard operating procedure",
        "workflow",
        "automation",
        "modernize",
        "modernization",
        "brownfield",
        "greenfield",
        "github",
        "repo",
        "repository",
        "app",
        "application",
        "software",
        "portal",
        "dashboard",
        "system",
        "platform",
        "integration",
        "product machine",
        "work packet",
        "requirements spec",
    )


def _should_route_connector_invoke_to_consulting_workflow(tool_name: str, inputs: dict[str, Any]) -> bool:
    normalized_tool = str(tool_name or "").strip().lower()
    risky_delivery_tools = {
        "github.create_repository",
        "github.create_pull_request",
        "github.merge_pull_request",
        "github.create_deployment_status",
        "github.dispatch_workflow",
        "github.trigger_workflow",
        "github.cancel_workflow_run",
        "aws_cli.ecr.create_repository",
        "aws_cli.ecs.update_service",
    }
    if normalized_tool not in risky_delivery_tools:
        return False
    return _should_route_delivery_to_consulting_workflow(
        f"{normalized_tool} {json.dumps(inputs, default=str)[:2000]}",
        inputs,
        workspace_id=_first_text(inputs, "workspace_id", "workspaceId", "code_workspace_id", "codeWorkspaceId"),
        repository_full_name=_repository_full_name_from_inputs(inputs),
        project_key=_first_text(inputs, "project_key", "projectKey", "jira_project_key", "jiraProjectKey"),
    )


def _route_to_consulting_from_domain_dispatch(
    domain: str,
    action: str,
    message: str,
    inputs: dict[str, Any],
) -> str:
    workspace_id = _first_text(inputs, "workspace_id", "workspaceId", "code_workspace_id", "codeWorkspaceId")
    repository_full_name = _repository_full_name_from_inputs(inputs)
    project_key = _first_text(inputs, "project_key", "projectKey", "jira_project_key", "jiraProjectKey")
    context_inputs = {
        **inputs,
        "requested_domain": str(domain or "").strip(),
        "requested_action": str(action or "chat").strip(),
    }
    return start_consulting_project_workflow(
        objective=message,
        project_context=_delivery_tool_project_context(
            "dispatch_domain_agent",
            message,
            context_inputs,
            workspace_id=workspace_id,
            repository_full_name=repository_full_name,
            project_key=project_key,
            mode_or_scope=f"{str(domain or '').strip()}.{str(action or 'chat').strip()}",
        ),
        project_id=str(inputs.get("project_id") or inputs.get("projectId") or ""),
        source="lightbulb_mcp.dispatch_domain_agent",
    )


def _route_to_consulting_from_connector_invoke(tool_name: str, inputs: dict[str, Any]) -> str:
    repository_full_name = _repository_full_name_from_inputs(inputs)
    project_key = _first_text(inputs, "project_key", "projectKey", "jira_project_key", "jiraProjectKey")
    context_inputs = {
        **inputs,
        "requested_connector_tool": str(tool_name or "").strip(),
    }
    objective = (
        _first_text(inputs, "objective", "message", "request", "title", "name")
        or f"Prepare approved consulting workflow before invoking {str(tool_name or '').strip()}"
    )
    return start_consulting_project_workflow(
        objective=objective,
        project_context=_delivery_tool_project_context(
            "invoke_tool",
            objective,
            context_inputs,
            workspace_id=_first_text(inputs, "workspace_id", "workspaceId", "code_workspace_id", "codeWorkspaceId"),
            repository_full_name=repository_full_name,
            project_key=project_key,
            mode_or_scope=str(tool_name or "").strip(),
        ),
        project_id=str(inputs.get("project_id") or inputs.get("projectId") or ""),
        source="lightbulb_mcp.invoke_tool",
    )


def _initial_consulting_workflow_gates(open_critical_questions: int = 1) -> dict[str, Any]:
    return {
        "schema": "consulting_workflow_gate_state.v1",
        "requirements_approved": False,
        "scope_approved": False,
        "sops_approved": False,
        "work_packets_approved": False,
        "sop_approval_required": True,
        "sop_impact_identified": False,
        "qa_plan_drafted": False,
        "change_plan_drafted": False,
        "shipping_gates_satisfied": False,
        "open_critical_questions": max(1, int(open_critical_questions or 1)),
        "source_authority": "lightbulb_mcp_seed_unvalidated",
        "approval_records_required": True,
    }


def _maybe_route_generated_domain_dispatch(
    domain: str,
    action: str,
    message: str,
    inputs: dict[str, Any] | None,
) -> str | None:
    safe_inputs = inputs if isinstance(inputs, dict) else {}
    if not _should_route_domain_dispatch_to_consulting_workflow(domain, action, message, safe_inputs):
        return None
    return _route_to_consulting_from_domain_dispatch(domain, action, message, safe_inputs)


def _maybe_route_generated_connector_invoke(tool_name: str, inputs: dict[str, Any] | None) -> str | None:
    safe_inputs = inputs if isinstance(inputs, dict) else {}
    if not _should_route_connector_invoke_to_consulting_workflow(tool_name, safe_inputs):
        return None
    return _route_to_consulting_from_connector_invoke(tool_name, safe_inputs)


def _software_delivery_response(result: Any) -> str:
    data = result.raw if hasattr(result, "raw") else result
    if not isinstance(data, dict):
        return str(data)
    outputs = data.get("outputs") or data.get("structuredOutputs") or {}
    payload = {
        "schema": "lightbulb.mcp.software_delivery_response.v1",
        "status": outputs.get("status") or data.get("status") or "unknown",
        "reply": data.get("reply") or outputs.get("summary") or "",
        "trace_id": data.get("traceId") or data.get("trace_id") or "",
        "conversation_id": data.get("conversationId") or data.get("conversation_id") or "",
        "outputs": outputs,
    }
    return json.dumps(payload, indent=2, default=str)[:9000]


def _is_terminal_code_workspace_run(run: dict[str, Any] | None) -> bool:
    if not isinstance(run, dict):
        return False
    status = _first_text(run, "status").lower()
    if status in {
        "completed",
        "failed",
        "cancelled",
        "canceled",
        "error",
        "success",
        "succeeded",
        "pending_approval",
        "approval_granted",
        "approval_rejected",
    }:
        return True
    return bool(_first_text(run, "finishedAt", "finished_at"))


def _format_code_workspace_result(result: Any) -> str:
    """Format a code workspace chat response or persisted run into readable text."""
    if not isinstance(result, dict):
        return json.dumps(result, indent=2, default=str)[:3000]

    output = _first_dict(result, "outputJson", "output_json")
    verification = (
        _first_dict(result, "verification", "verificationJson", "verification_json")
        or _first_dict(output, "verification", "verification_json")
    )
    approval_state = (
        _first_dict(result, "approval_state", "approvalState")
        or _first_dict(output, "approval_state", "approvalState")
    )
    runtime_session = (
        _first_dict(result, "runtime_session", "runtimeSession")
        or _first_dict(output, "runtime_session", "runtimeSession")
    )
    telemetry = (
        _first_dict(result, "telemetry", "telemetryJson", "telemetry_json")
        or _first_dict(output, "telemetry", "telemetry_json")
    )
    approval_requests = (
        _first_list(result, "approval_requests", "approvalRequests")
        or _first_list(output, "approval_requests", "approvalRequests")
    )
    suggestions = (
        _first_list(result, "suggestions")
        or _first_list(output, "suggestions")
    )
    changed_files = (
        _first_list(result, "changed_files", "changedFiles", "changedFilesJson")
        or _first_list(output, "changed_files", "changedFiles")
    )

    reply = _first_text(result, "reply", "replyText", "message")
    if not reply:
        reply = _first_text(output, "reply", "message", "response")
    diff = _first_text(result, "diff")
    if not diff:
        diff = _first_text(output, "diff")

    status = _first_text(result, "status") or _first_text(output, "status") or "unknown"
    phase = _first_text(result, "phase") or _first_text(telemetry, "run_phase")
    run_id = _first_text(result, "runId", "run_id", "id")
    conversation_id = _first_text(result, "conversationId", "conversation_id") or _first_text(output, "conversationId", "conversation_id")
    backend = _first_text(result, "backend") or _first_text(output, "backend")
    runtime_backend = _first_text(result, "runtimeBackend", "runtime_backend") or _first_text(output, "runtimeBackend", "runtime_backend")
    execution_path = _first_text(result, "executionPath", "execution_path") or _first_text(output, "executionPath", "execution_path")
    verification_status = _first_text(verification, "status", "state")
    verification_summary = _first_text(verification, "summary", "message")
    approval_status = _first_text(approval_state, "status", "state")
    runtime_label = (
        _first_text(runtime_session, "thread_name", "threadName", "title", "session_name", "sessionName")
        or _first_text(runtime_session, "thread_id", "threadId", "session_id", "sessionId")
    )

    header = [f"Status: `{status}`"]
    if phase:
        header.append(f"Phase: `{phase}`")
    if backend:
        header.append(f"Backend: `{backend}`")
    if runtime_backend:
        header.append(f"Runtime: `{runtime_backend}`")
    if execution_path:
        header.append(f"Execution: `{execution_path}`")

    parts = [" | ".join(header)]
    if run_id:
        parts.append(f"Run ID: `{run_id}`")
    if conversation_id:
        parts.append(f"Conversation: `{conversation_id}`")
    if runtime_label:
        parts.append(f"Runtime session: `{runtime_label}`")
    if reply:
        parts.append(_truncate_text(reply, 4000))
    if approval_status:
        parts.append(
            f"Approval: `{approval_status}`"
            + (f" ({len(approval_requests)} request(s))" if approval_requests else "")
        )
    if verification_status or verification_summary:
        suffix = f" — {_truncate_text(verification_summary, 400)}" if verification_summary else ""
        parts.append(f"Verification: `{verification_status or 'unknown'}`{suffix}")
    if suggestions:
        parts.append("Suggestions: " + "; ".join(str(item).strip() for item in suggestions[:5] if str(item).strip()))
    if changed_files:
        parts.append("Changed files: " + ", ".join(str(item) for item in changed_files[:20]))
    if diff:
        parts.append(f"```diff\n{diff[:2000]}\n```")

    return "\n".join(part for part in parts if part).strip() or json.dumps(result, indent=2, default=str)[:3000]


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool()
def search_documents(query: str, folder_path: str = "", top_k: int = 10) -> str:
    """Search across all documents using semantic search.

    Use this to find documents relevant to a topic, question, or keyword.
    Returns ranked results with snippets and source paths.

    Args:
        query: The search query (natural language or keywords)
        folder_path: Optional folder path to scope the search (e.g. "/contracts")
        top_k: Max number of results to return (default 10)
    """
    def _do():
        client = _get_client()
        return client.search_documents(query, folder_path=folder_path or None, top_k=top_k)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def grep_documents(pattern: str, regex: bool = True, case_sensitive: bool = False, folder_path: str = "", top_k: int = 20) -> str:
    """Grep across document content using pattern matching (like ripgrep).

    Use this to find exact text matches, regex patterns, or specific strings
    across all documents. Returns line-level matches with context.

    Args:
        pattern: The search pattern (regex by default, or exact string)
        regex: Whether to use regex matching (default True)
        case_sensitive: Whether the search is case-sensitive (default False)
        folder_path: Optional folder path to scope the search
        top_k: Max number of chunk results to return (default 20)
    """
    def _do():
        c = _get_client()
        return c.grep_documents(pattern, regex=regex, case_sensitive=case_sensitive, folder_path=folder_path or None, top_k=top_k)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def list_folder(folder_path: str = "/", source_system: str = "", max_items: int = 100) -> str:
    """List documents in a folder or the entire document library.

    Use this to browse the document library, see what files exist,
    and explore folder structures.

    Args:
        folder_path: Folder path to list (default "/" for root)
        source_system: Filter by source (e.g. "google_drive", "microsoft_graph", "workspace")
        max_items: Max number of items to return (default 100)
    """
    def _do():
        c = _get_client()
        return c.list_folder(folder_path, source_system=source_system or None, max_items=max_items)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def search_folder(query: str, folder_path: str = "/", search_mode: str = "semantic") -> str:
    """Search within a specific folder using semantic or keyword matching.

    Combines folder-scoped search with AI-synthesized answers.
    Good for asking questions about documents in a specific folder.

    Args:
        query: The search query or question
        folder_path: Folder path to search within
        search_mode: "semantic" (default) or "exact" or "regex"
    """
    def _do():
        c = _get_client()
        return c.dispatch("document_intelligence", action="search_folder", message=query, inputs={"message": query, "folder_path": folder_path, "search_mode": search_mode})
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def create_document(title: str, body: str, format: str = "docx", target_suite: str = "internal_library") -> str:
    """Create a new document (report, memo, brief, etc.).

    Generates and stores a document in the specified format and target.

    Args:
        title: Document title
        body: Document content/body text
        format: Output format — "docx", "pdf", "xlsx", "pptx", "gdoc", "gsheet", "gslides", "md"
        target_suite: Where to store — "internal_library", "google_workspace", "microsoft_365"
    """
    def _do():
        return _get_client().create_document(title, body, format=format, target_suite=target_suite)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def create_spreadsheet(title: str, body: str = "", target_suite: str = "internal_library") -> str:
    """Create a new spreadsheet.

    Args:
        title: Spreadsheet title
        body: Optional initial content or description
        target_suite: Where to store — "internal_library", "google_workspace", "microsoft_365"
    """
    def _do():
        return _get_client().create_spreadsheet(title, body=body, target_suite=target_suite)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def create_slide_deck(title: str, body: str = "", target_suite: str = "internal_library") -> str:
    """Create a new presentation / slide deck.

    Args:
        title: Presentation title
        body: Optional content description or outline
        target_suite: Where to store — "internal_library", "google_workspace", "microsoft_365"
    """
    def _do():
        return _get_client().create_slide_deck(title, body=body, target_suite=target_suite)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def ask_document_agent(message: str, action: str = "chat") -> str:
    """Send a message to the document intelligence agent.

    Use this for general document questions, analysis, comparisons,
    or any document operation not covered by the specific tools above.

    Args:
        message: Your message or question for the document agent
        action: Agent action — "chat", "compare_versions", "export_evidence_pack", etc.
    """
    def _do():
        return _get_client().dispatch("document_intelligence", action=action, message=message)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def dispatch_domain_agent(domain: str, message: str, action: str = "chat", inputs: str = "{}") -> str:
    """Dispatch a message to any domain agent on the platform.

    Available domains: finance, crm, engineering, legal, hr, it_ops,
    content, commerce, product, document_intelligence.

    Args:
        domain: The domain agent to talk to
        message: Your message or objective
        action: The action to perform (default "chat")
        inputs: Optional JSON string of additional structured inputs
    """
    parsed_inputs = {}
    if inputs and inputs.strip() != "{}":
        try:
            parsed_inputs = json.loads(inputs)
        except json.JSONDecodeError:
            return f"Error: 'inputs' must be valid JSON, got: {inputs[:200]}"

    routed = _maybe_route_generated_domain_dispatch(domain, action, message, parsed_inputs)
    if routed is not None:
        return routed

    def _do():
        return _get_client().dispatch(domain, action=action, message=message, inputs=parsed_inputs if parsed_inputs else None)
    return _format_result(_call_with_retry(_do))


# -- Software delivery loop bridge ------------------------------------------

@mcp.tool()
def software_delivery_context(
    repository: str = "",
    workspace_id: str = "",
    project_key: str = "",
    include_live: bool = True,
    include_memory: bool = True,
) -> str:
    """Get the Lightbulb software-delivery context packet before editing code.

    Use this from Claude Code, Codex, or Cursor before making a repo change. It
    gathers IT/Ops, coding workspace, project-management, deployment, CloudOps,
    connector, memory, and approval context under the authenticated user's RBAC
    scope.
    """
    owner, repo, full_name = _split_repository(repository)

    def _do():
        client = _get_client()
        packet: dict[str, Any] = {
            "schema": "lightbulb.mcp.software_delivery_context.v1",
            "repository": full_name,
            "github_owner": owner,
            "github_repo": repo,
            "workspace_id": workspace_id.strip(),
            "project_key": project_key.strip(),
            "sources": {},
            "errors": [],
            "recommended_next_tools": [
                "software_delivery_loop",
                "software_spot_weld_fix",
                "code_workspace_chat",
                "code_workspace_pull_request",
                "list_pending_approvals",
            ],
        }

        def capture(name: str, fn):
            try:
                packet["sources"][name] = fn()
            except Exception as exc:  # pragma: no cover - defensive aggregation
                packet["errors"].append({"source": name, "error": str(exc)[:240]})

        capture("it_ops_workspace", lambda: client.workspace_bundle("it_ops"))
        capture("coding_workspace", lambda: client.workspace_bundle("coding"))
        capture("it_ops_mcp_manifest", client.it_ops_mcp_manifest)
        if workspace_id.strip():
            capture("code_workspace_runs", lambda: client.list_code_workspace_runs(workspace_id.strip(), limit=10))
            capture("code_workspace_run_insights", lambda: client.code_workspace_runs_insights(workspace_id.strip()))
            capture("code_workspace_active_run", lambda: client.get_code_workspace_active_run(workspace_id.strip()))
        if include_live:
            for connector in ("github", "jira", "slack", "notion"):
                capture(f"it_ops_live_{connector}", lambda connector=connector: client.it_ops_live_connector(connector))
        if include_memory:
            query = " ".join(part for part in (full_name, project_key, "software delivery cloud deployment feedback") if part)
            capture("memory_search", lambda: client.memory_search(query or "software delivery", namespace="default", top_k=8))
        return packet

    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:12000]


@mcp.tool()
def software_delivery_loop(
    request: str,
    workspace_id: str = "",
    repository: str = "",
    github_owner: str = "",
    github_repo: str = "",
    project_key: str = "",
    environment: str = "staging",
    mode: str = "feedback_to_code",
    execute_coding: bool = True,
    open_pr: bool = False,
    auto_push: bool = False,
    trigger_deploy: bool = False,
    extra_inputs: str = "{}",
) -> str:
    """Run the governed software loop from MCP: feedback/SDLC -> coding -> PR -> deploy.

    This is the main bridge for external coding tools. It routes through
    Lightbulb's IT/Ops orchestrator so repo binding, SDLC context, CloudOps,
    GitHub, HITL, tests, container release, and deployment gates travel
    together.
    """
    parsed = _parse_extra_inputs(extra_inputs)
    if isinstance(parsed, str):
        return parsed
    owner, repo, full_name = _split_repository(repository, github_owner, github_repo)
    normalized_mode = str(mode or "").strip().lower()
    if _should_route_delivery_to_consulting_workflow(
        request,
        parsed,
        workspace_id=workspace_id,
        repository_full_name=full_name,
        project_key=project_key,
    ):
        return start_consulting_project_workflow(
            objective=request,
            project_context=_delivery_tool_project_context(
                "software_delivery_loop",
                request,
                parsed,
                workspace_id=workspace_id,
                repository_full_name=full_name,
                project_key=project_key,
                environment=environment,
                mode_or_scope=normalized_mode or "feedback_to_code",
            ),
            project_id=str(parsed.get("project_id") or parsed.get("projectId") or ""),
            source="lightbulb_mcp.software_delivery_loop",
        )
    action = (
        "cloud_delivery_setup"
        if normalized_mode in {"cloud", "cloud_delivery", "deployment", "deploy", "container"}
        else "autonomous_software_engineering_loop"
        if normalized_mode in {"autonomous", "software_engineering", "engineering"}
        else "feedback_to_code_loop"
    )
    inputs = {
        **parsed,
        "source": "lightbulb_mcp",
        "lightbulb_mcp": {
            "schema": "lightbulb.mcp.software_delivery_loop.v1",
            "host": "claude_code_codex_cursor",
            "mode": normalized_mode or "feedback_to_code",
        },
        "workspace_id": workspace_id.strip(),
        "project_key": project_key.strip(),
        "github_owner": owner,
        "github_repo": repo,
        "github_repository": {"owner": owner, "repo": repo, "full_name": full_name},
        "repo_binding_required": bool(full_name),
        "environment": environment.strip() or "staging",
        "execute_coding": execute_coding,
        "open_pr": open_pr,
        "auto_push": auto_push,
        "trigger_deploy": trigger_deploy,
        "software_delivery_loop": True,
        "software_engineering_agent": True,
    }

    def _do():
        return _get_client().dispatch("it_ops", action=action, message=request, inputs=inputs)

    return _software_delivery_response(_call_with_retry(_do))


@mcp.tool()
def software_spot_weld_fix(
    request: str,
    workspace_id: str,
    repository: str = "",
    github_owner: str = "",
    github_repo: str = "",
    project_key: str = "",
    environment: str = "staging",
    scope: str = "code",
    severity: str = "high",
    preview_mode: bool = True,
    open_pr: bool = True,
    auto_push: bool = False,
    trigger_deploy: bool = False,
    extra_inputs: str = "{}",
) -> str:
    """Request a bounded urgent production/cloud fix through the Lightbulb loop.

    Defaults are intentionally conservative: preview mode on, PR on, deploy off.
    Production or cloud-impacting fixes are routed with approval gates and
    CloudOps/deployment context rather than direct mutation.
    """
    parsed = _parse_extra_inputs(extra_inputs)
    if isinstance(parsed, str):
        return parsed
    owner, repo, full_name = _split_repository(repository, github_owner, github_repo)
    normalized_scope = str(scope or "code").strip().lower()
    if _should_route_delivery_to_consulting_workflow(
        request,
        parsed,
        workspace_id=workspace_id,
        repository_full_name=full_name,
        project_key=project_key,
    ):
        return start_consulting_project_workflow(
            objective=request,
            project_context=_delivery_tool_project_context(
                "software_spot_weld_fix",
                request,
                parsed,
                workspace_id=workspace_id,
                repository_full_name=full_name,
                project_key=project_key,
                environment=environment,
                mode_or_scope=normalized_scope,
            ),
            project_id=str(parsed.get("project_id") or parsed.get("projectId") or ""),
            source="lightbulb_mcp.software_spot_weld_fix",
        )
    prod_or_cloud = environment.strip().lower() == "production" or normalized_scope in {
        "cloud",
        "infra",
        "infrastructure",
        "deploy",
        "deployment",
        "container",
        "runtime",
    }
    action = "cloud_delivery_setup" if prod_or_cloud else "autonomous_software_engineering_loop"
    inputs = {
        **parsed,
        "source": "lightbulb_mcp",
        "workspace_id": workspace_id.strip(),
        "project_key": project_key.strip(),
        "github_owner": owner,
        "github_repo": repo,
        "github_repository": {"owner": owner, "repo": repo, "full_name": full_name},
        "repo_binding_required": bool(full_name),
        "environment": environment.strip() or "staging",
        "execute_coding": True,
        "preview_mode": preview_mode,
        "open_pr": open_pr,
        "auto_push": auto_push,
        "trigger_deploy": trigger_deploy,
        "run_delivery_loop": True,
        "software_delivery_loop": True,
        "software_engineering_agent": True,
        "cloud_ops_review_required": prod_or_cloud,
        "spot_weld_fix": {
            "schema": "lightbulb.mcp.spot_weld_fix.v1",
            "scope": normalized_scope,
            "severity": severity,
            "bounded": True,
            "default_preview_mode": preview_mode,
            "external_write_policy": "approval_required_for_prod_or_cloud",
            "requires_human_approval": prod_or_cloud or trigger_deploy,
        },
    }

    def _do():
        return _get_client().dispatch("it_ops", action=action, message=request, inputs=inputs)

    return _software_delivery_response(_call_with_retry(_do))


# ── Page Builder ─────────────────────────────────────────────────────

@mcp.tool()
def page_builder_create(brand_name: str = "", initial_prompt: str = "", force_page_builder: bool = False) -> str:
    """Create a new page builder session to build a website or landing page.

    Returns a session ID you can use with page_builder_chat to iteratively
    design and build pages.

    Args:
        brand_name: The brand/company name for the site
        initial_prompt: Optional initial instruction (e.g. "Build a landing page for our SaaS product")
        force_page_builder: If true, create a pure Page Builder design session instead of routing project-build intent to consulting workflow.
    """
    if not force_page_builder and _should_route_page_builder_to_consulting_workflow(
        f"{brand_name} {initial_prompt}"
    ):
        objective = initial_prompt.strip() or f"Build page or website experience for {brand_name.strip() or 'this project'}"
        return start_consulting_project_workflow(
            objective=objective,
            project_context=json.dumps({
                "source_tool": "page_builder_create",
                "brand_name": brand_name.strip(),
                "initial_prompt": initial_prompt.strip(),
                "routing_reason": "page_builder_project_intent_requires_consulting_workflow",
                "requested_delivery": {
                    "mode_or_scope": "page_builder_create",
                },
            }),
            source="lightbulb_mcp.page_builder_create",
        )
    def _do():
        return _get_client().create_page_builder_session(brand_name=brand_name, initial_prompt=initial_prompt)
    result = _call_with_retry(_do)
    session_id = result.get("id", "")
    return f"Page builder session created: `{session_id}`\nUse page_builder_chat to start building." if session_id else json.dumps(result, default=str)[:500]


@mcp.tool()
def page_builder_list_sessions() -> str:
    """List existing page builder sessions."""
    def _do():
        return _get_client().list_page_builder_sessions()
    result = _call_with_retry(_do)
    if not result:
        return "No page builder sessions found."
    lines = [f"**{len(result)} session(s):**"]
    for s in result[:15]:
        sid = s.get("id", "?")
        title = s.get("title") or s.get("brandName") or "Untitled"
        status = s.get("status", "")
        lines.append(f"- **{title}** (`{sid}`) {f'— {status}' if status else ''}")
    return "\n".join(lines)


@mcp.tool()
def page_builder_chat(session_id: str, message: str) -> str:
    """Send a message to a page builder session to design or modify pages.

    The page builder agent generates HTML/CSS/JS for your website.
    Use iterative messages to refine the design.

    Args:
        session_id: The session ID from page_builder_create
        message: Your instruction (e.g. "Add a pricing section with 3 tiers")
    """
    def _do():
        return _get_client().page_builder_send_message(session_id, message)
    result = _call_with_retry(_do)
    reply = result.get("reply") or result.get("content") or result.get("message", "")
    schemas = result.get("schemas") or result.get("pageSchemas")
    parts = []
    if reply:
        parts.append(reply[:1000])
    if schemas and isinstance(schemas, dict):
        parts.append(f"\nPages: {', '.join(schemas.keys())}")
    return "\n".join(parts) if parts else json.dumps(result, indent=2, default=str)[:2000]


@mcp.tool()
def page_builder_deploy(session_id: str, page_key: str = "") -> str:
    """Deploy a page builder session to make the site live.

    Args:
        session_id: The session ID
        page_key: Optional specific page to deploy (deploys all if empty)
    """
    def _do():
        return _get_client().page_builder_deploy(session_id, page_key=page_key)
    result = _call_with_retry(_do)
    url = result.get("url") or result.get("previewUrl") or result.get("deployUrl", "")
    if url:
        return f"Deployed! URL: {url}"
    return json.dumps(result, indent=2, default=str)[:1000]


@mcp.tool()
def page_builder_preview(session_id: str) -> str:
    """Get the preview URL for a page builder session.

    Args:
        session_id: The session ID
    """
    def _do():
        return _get_client().page_builder_get_preview(session_id)
    result = _call_with_retry(_do)
    url = result.get("url") or result.get("previewUrl", "")
    if url:
        return f"Preview: {url}"
    return json.dumps(result, indent=2, default=str)[:500]


# ── Backbone Agent ───────────────────────────────────────────────────

@mcp.tool()
def backbone_execute(objective: str, inputs: str = "{}") -> str:
    """Execute a research, analysis, or code generation task via the backbone agent.

    The backbone agent runs **server-side, scoped to your tenant** — it has a
    Python REPL, web search, and access to your account's connectors, all
    operating under your JWT and the platform's RBAC. This is *not* local code
    execution on the customer's machine; nothing leaves the platform's scope.

    Use it for complex multi-step analysis, data processing, or generating
    code/scripts.

    Args:
        objective: What you want the backbone agent to do
        inputs: Optional JSON string of structured inputs
    """
    parsed = {}
    if inputs and inputs.strip() != "{}":
        try:
            parsed = json.loads(inputs)
        except json.JSONDecodeError:
            return f"Error: inputs must be valid JSON"
    def _do():
        return _get_client().backbone_execute(objective, inputs=parsed if parsed else None)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


@mcp.tool()
def start_consulting_project_workflow(
    objective: str,
    project_context: str = "{}",
    project_id: str = "",
    source: str = "mcp",
) -> str:
    """Start or continue the Lightbulb consulting project workflow through Backbone.

    Use this instead of jumping directly to coding, GitHub, deployment, connector
    mutation, or external communications when a user has a project idea, custom
    agent request, workflow automation request, SOP/process change, modernization
    request, or build request that still needs discovery, requirements, scope,
    SOP impact or referenced SOPs, approval gates, and execution work packets.

    Args:
        objective: The project idea or business outcome the user wants to achieve.
        project_context: Optional JSON object with known facts, current systems,
            requirements, constraints, uploaded-doc references, or host context.
        project_id: Optional existing Lightbulb project identifier to continue.
        source: Host/source string such as codex, claude_code, chatgpt, cursor, or mcp.
    """
    try:
        parsed_context = _parse_json_argument(project_context, "project_context", {})
    except ValueError as exc:
        return f"Error: {exc}"
    if not isinstance(parsed_context, dict):
        return "Error: project_context must be a JSON object"

    cleaned_objective = str(objective or "").strip()
    if not cleaned_objective:
        return "Error: objective is required"

    cleaned_source = str(source or "mcp").strip() or "mcp"
    cleaned_project_id = str(project_id or "").strip()
    launch_experience = _consulting_launch_experience()

    inputs: dict[str, Any] = {
        "workflow_type": CONSULTING_WORKFLOW_TYPE,
        "requested_workflow_type": CONSULTING_WORKFLOW_TYPE,
        "consulting_project_workflow": True,
        "orchestrator_workflow_type": "backbone_agent",
        "assistant_mode": CONSULTING_WORKFLOW_TYPE,
        "source": cleaned_source,
        "project_context": parsed_context,
        "first_intake_prompt": FIRST_CONSULTING_INTAKE_PROMPT,
        "approval_guardrail": CONSULTING_APPROVAL_GUARDRAIL,
        "launch_experience": launch_experience,
        "workflow_gates": _initial_consulting_workflow_gates(),
        "onboarding_dispatch": {
            "schema": "onboarding_project_workflow_dispatch.v1",
            "source": cleaned_source,
            "setup_action_id": "start-consulting-project",
            "workflow_type": CONSULTING_WORKFLOW_TYPE,
            "project_workflow_start": True,
            "requested": True,
            "entrypoint": "autocompany_helper_onboarding",
            "tone": "concise_guided_project_intake",
            "next_best_action": "start_or_continue_consulting_project_workflow",
            "target_surface": "product-machine",
            "target_service_id": "project-agent",
            "target_tab": "product-machine",
            "first_intake_prompt": FIRST_CONSULTING_INTAKE_PROMPT,
            "approval_guardrail": CONSULTING_APPROVAL_GUARDRAIL,
            "launch_experience": launch_experience,
        },
        "dispatch_contract": {
            "schema": "onboarding_project_workflow_dispatch.v1",
            "primary_surface": "Project Product Machine cockpit",
            "first_intake_prompt": FIRST_CONSULTING_INTAKE_PROMPT,
            "approval_guardrail": CONSULTING_APPROVAL_GUARDRAIL,
            "launch_experience": launch_experience,
            "handoff_rule": (
                "Project Agent drafts and validates discovery, requirements, scope, SOP impact or referenced SOPs, "
                "and work packets before AutoCompany dispatches specialist agents."
            ),
            "specialist_dispatch_rule": (
                "Dispatch domain agents only after the relevant requirements, scope, SOP impact or referenced SOP, "
                "work-packet, and HITL approval gates have passed."
            ),
            "agent_routing": _consulting_agent_routing_policy(),
        },
        "code_delivery": {
            "schema": "project_code_delivery_setup_hint.v1",
            "code_workspace": "create_or_attach_from_product_machine",
            "github_repository": "create_or_attach_from_product_machine",
            "draft_pr_policy": "after_verification_user_request_and_shipping_governance",
            "execution_requires_approved_requirements_scope_sops_and_work_packets": True,
            "execution_requires_approved_requirements_scope_sop_impact_and_work_packets": True,
            "execution_requires_approved_sops_when_changed_or_referenced": True,
            "execution_requires_approved_sop_trace_when_referenced": True,
            "draft_pr_requires_qa_and_acceptance_plan": True,
            "draft_pr_requires_change_management_plan": True,
            "draft_pr_requires_shipping_governance": True,
        },
        "approval_gates_required": [
            "discovery_brief",
            "consolidation_brief",
            "scope",
            "requirements",
            "sops_when_changed_or_referenced",
            "work_packets",
            "qa_plan_for_critical_workflows",
            "change_plan_when_users_are_affected",
            "final_handoff",
        ],
    }
    if cleaned_project_id:
        inputs["project_id"] = cleaned_project_id

    wrapped_objective = (
        "Start or continue the consulting_project_workflow for this Lightbulb project. "
        "Run delightful, concise intake first; preserve fact provenance; ask the highest-impact "
        f"blocking question, starting with: {FIRST_CONSULTING_INTAKE_PROMPT} "
        "Validate requirements, scope, SOP impact or referenced SOPs, and work packets before execution; "
        "draft PR shipping also needs QA/acceptance and change-management plans. "
        f"{CONSULTING_APPROVAL_GUARDRAIL} "
        f"User objective: {cleaned_objective}"
    )

    def _do():
        return _get_client().backbone_execute(wrapped_objective, inputs=inputs)

    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


# ── Code Workspaces ──────────────────────────────────────────────────

@mcp.tool()
def list_code_workspaces() -> str:
    """List all code workspaces available to you.

    Code workspaces are persistent environments with file systems, git, and
    execution capabilities.
    """
    def _do():
        return _get_client().list_code_workspaces()
    result = _call_with_retry(_do)
    if not result:
        return "No code workspaces found."
    lines = ["**Code Workspaces:**"]
    for ws in (result if isinstance(result, list) else [result])[:20]:
        workspace_id = ws.get("id") or ws.get("workspaceRunnerId") or "?"
        name = ws.get("name") or ws.get("label") or workspace_id
        status = ws.get("status", "")
        branch = ws.get("branch") or ""
        source = ws.get("source") or ws.get("repositoryUrl") or ""
        extra = []
        if status:
            extra.append(status)
        if branch:
            extra.append(f"branch={branch}")
        if source:
            extra.append(str(source))
        suffix = f" ({'; '.join(extra)})" if extra else ""
        lines.append(f"- **{name}** (`{workspace_id}`){suffix}")
    return "\n".join(lines)


@mcp.tool()
def code_workspace_chat(
    workspace_id: str,
    message: str,
    action: str = "chat",
    conversation_id: str = "",
    active_file: str = "",
    history: str = "[]",
    attachments: str = "[]",
    context: str = "{}",
    policy: str = "{}",
    preview_mode: bool = False,
    auto_push: bool = False,
    idempotency_key: str = "",
    agent_model_selection_id: str = "",
    agent_provider_connection_id: str = "",
    agent_model_id: str = "",
    # Back-compat alias (renamed in v0.5.0 — was agent_model_profile_id):
    agent_model_profile_id: str = "",
) -> str:
    """Send a message to a code workspace — ask it to write code, run commands, analyze files.

    Args:
        workspace_id: The workspace ID to interact with
        message: Your instruction or question
        action: Optional coding action such as chat, explain_code, or propose_changes.
            propose_changes is normalized to preview chat mode for backend compatibility.
        conversation_id: Optional conversation/thread ID for continuity
        active_file: Optional active file path to bias the coding agent
        history: Optional JSON array of prior chat messages
        attachments: Optional JSON array of attachments
        context: Optional JSON object with structured coding context
        policy: Optional JSON object with workspace policy overrides
        preview_mode: If true, return proposed changes without mutating files
        auto_push: If true, allow the coding run to auto-push after verification
    """
    try:
        parsed_history = _parse_json_argument(history, "history", [])
        parsed_attachments = _parse_json_argument(attachments, "attachments", [])
        parsed_context = _parse_json_argument(context, "context", {})
        parsed_policy = _parse_json_argument(policy, "policy", {})
    except ValueError as exc:
        return f"Error: {exc}"

    requested_action = action.strip()
    normalized_action = requested_action.lower()
    effective_action = "chat" if normalized_action == "propose_changes" else requested_action
    effective_preview_mode = preview_mode or normalized_action == "propose_changes"
    routing_inputs = {
        **(parsed_context if isinstance(parsed_context, dict) else {}),
        "policy": parsed_policy,
        "workspace_id": workspace_id.strip(),
        "requested_action": requested_action,
        "preview_mode": effective_preview_mode,
        "auto_push": auto_push,
    }
    if _should_route_delivery_to_consulting_workflow(
        message,
        routing_inputs,
        workspace_id=workspace_id,
        repository_full_name=_repository_full_name_from_inputs(routing_inputs),
    ):
        return start_consulting_project_workflow(
            objective=message,
            project_context=_delivery_tool_project_context(
                "code_workspace_chat",
                message,
                routing_inputs,
                workspace_id=workspace_id,
                repository_full_name=_repository_full_name_from_inputs(routing_inputs),
                mode_or_scope=effective_action or "chat",
            ),
            project_id=str(routing_inputs.get("project_id") or routing_inputs.get("projectId") or ""),
            source="lightbulb_mcp.code_workspace_chat",
        )

    kwargs: dict[str, Any] = {}
    if effective_action:
        kwargs["action"] = effective_action
    if conversation_id.strip():
        kwargs["conversation_id"] = conversation_id.strip()
    if active_file.strip():
        kwargs["active_file"] = active_file.strip()
    if parsed_history:
        kwargs["history"] = parsed_history
    if parsed_attachments:
        kwargs["attachments"] = parsed_attachments
    if parsed_context:
        kwargs["context"] = parsed_context
    if parsed_policy:
        kwargs["policy"] = parsed_policy
    if effective_preview_mode:
        kwargs["preview_mode"] = True
    if auto_push:
        kwargs["auto_push"] = True
    if idempotency_key.strip():
        kwargs["idempotency_key"] = idempotency_key.strip()
    resolved_selection_id = agent_model_selection_id.strip() or agent_model_profile_id.strip()
    if resolved_selection_id:
        kwargs["agent_model_selection_id"] = resolved_selection_id
    if agent_provider_connection_id.strip():
        kwargs["agent_provider_connection_id"] = agent_provider_connection_id.strip()
    if agent_model_id.strip():
        kwargs["agent_model_id"] = agent_model_id.strip()

    def _do():
        return _get_client().code_workspace_chat(workspace_id, message, **kwargs)
    result = _call_with_retry(_do)
    return _format_code_workspace_result(result)


def _format_exec_run_result(result: Any, cmd: str = "") -> str:
    """Format a workspace ``exec.run`` response into readable stdout/stderr/exit_code.

    The REST tool endpoint returns ``{"result": <CommandResult>, "run": ...}``
    where CommandResult carries ``exit_code``, ``stdout``, ``stderr``,
    ``timed_out`` and ``duration_ms``.
    """
    data = result.raw if hasattr(result, "raw") else result
    if not isinstance(data, dict):
        return str(result)
    payload = data.get("result")
    if not isinstance(payload, dict):
        payload = data
    exit_code = payload.get("exit_code")
    stdout = payload.get("stdout") or ""
    stderr = payload.get("stderr") or ""
    lines: list[str] = []
    if cmd:
        lines.append(f"$ {cmd}")
    lines.append(f"exit_code: {exit_code}")
    if payload.get("timed_out"):
        lines.append("timed_out: true")
    if payload.get("cancelled"):
        lines.append("cancelled: true")
    duration_ms = payload.get("duration_ms")
    if duration_ms is not None:
        lines.append(f"duration_ms: {duration_ms}")
    lines.append("--- stdout ---")
    lines.append(stdout if stdout.strip() else "(empty)")
    lines.append("--- stderr ---")
    lines.append(stderr if stderr.strip() else "(empty)")
    return "\n".join(lines)


@mcp.tool()
def coding_run_command(
    workspace_id: str = "",
    cmd: str = "",
    cwd: str = ".",
    timeout_ms: int = 60000,
    message: str = "",
    inputs: str = "{}",
) -> str:
    """Run a shell command in a code workspace and get back its real output.

    Executes the command **synchronously** against the workspace's sandboxed
    runner via the proven ``exec.run`` tool and returns the command's
    ``exit_code``, ``stdout`` and ``stderr`` inline — there is no separate run
    to poll. Scoped to your JWT / tenant / company; the workspace's command
    allow-list and sandbox still apply (this does not widen exec capability).

    Typical call:
        coding_run_command(workspace_id="<uuid>", cmd="python3 --version")

    Args:
        workspace_id: The code workspace ID (UUID) to run the command in. Required.
        cmd: The shell command to execute, e.g. ``"python3 --version"`` or
            ``"pytest -q"``. Required.
        cwd: Working directory relative to the workspace root (default ``"."``).
        timeout_ms: Command timeout in milliseconds (default 60000).
        message: Back-compat alias for ``cmd`` (used only if ``cmd`` is empty).
        inputs: Back-compat JSON object that may carry
            ``{"workspace_id","cmd","cwd","timeout_ms"}`` (used only to fill
            args left empty above).

    Returns:
        The command's exit_code plus its stdout and stderr.
    """
    parsed_inputs: dict[str, Any] = {}
    if inputs and inputs.strip() not in ("", "{}"):
        try:
            loaded = json.loads(inputs)
            if isinstance(loaded, dict):
                parsed_inputs = loaded
        except json.JSONDecodeError:
            return f"Error: 'inputs' must be valid JSON, got: {inputs[:200]}"

    resolved_workspace = (
        workspace_id
        or parsed_inputs.get("workspace_id")
        or parsed_inputs.get("workspaceId")
        or ""
    ).strip()
    resolved_cmd = (
        cmd
        or parsed_inputs.get("cmd")
        or parsed_inputs.get("command")
        or message
        or ""
    ).strip()
    resolved_cwd = (cwd or parsed_inputs.get("cwd") or ".").strip() or "."
    try:
        resolved_timeout = int(timeout_ms or parsed_inputs.get("timeout_ms") or 60000)
    except (TypeError, ValueError):
        resolved_timeout = 60000

    if not resolved_workspace:
        return "Error: workspace_id is required (the code workspace UUID to run the command in)."
    if not resolved_cmd:
        return 'Error: cmd is required (the shell command to run, e.g. "python3 --version").'

    arguments = {
        "workspace_id": resolved_workspace,
        "cmd": resolved_cmd,
        "cwd": resolved_cwd,
        "timeout_ms": resolved_timeout,
    }

    def _do():
        return _get_client().code_workspace_invoke_tool(
            resolved_workspace, "exec.run", arguments
        )

    result = _call_with_retry(_do)
    return _format_exec_run_result(result, resolved_cmd)


@mcp.tool()
def code_workspace_get_active_run(workspace_id: str) -> str:
    """Get the active coding run for a workspace, if one exists."""
    def _do():
        return _get_client().get_code_workspace_active_run(workspace_id)
    result = _call_with_retry(_do)
    if not result:
        return "No active coding run for this workspace."
    return _format_code_workspace_result(result)


@mcp.tool()
def code_workspace_get_run(workspace_id: str, run_id: str) -> str:
    """Get the details for a specific coding run."""
    def _do():
        return _get_client().get_code_workspace_run(workspace_id, run_id)
    result = _call_with_retry(_do)
    return _format_code_workspace_result(result)


@mcp.tool()
def code_workspace_wait_for_run(
    workspace_id: str,
    run_id: str = "",
    timeout_seconds: int = 60,
    poll_interval_seconds: int = 2,
) -> str:
    """Wait for a coding run to finish and return its latest status.

    If run_id is omitted, the tool waits for the current active run.
    """
    client = _get_client()
    effective_run_id = run_id.strip()
    if not effective_run_id:
        active = _call_with_retry(lambda: client.get_code_workspace_active_run(workspace_id))
        if not active:
            return "No active coding run for this workspace."
        effective_run_id = _first_text(active, "runId", "run_id", "id")
        if not effective_run_id:
            return _format_code_workspace_result(active)

    deadline = time.time() + max(1, int(timeout_seconds))
    interval = max(1, int(poll_interval_seconds))
    latest: dict[str, Any] | None = None
    while time.time() <= deadline:
        latest = _call_with_retry(lambda: client.get_code_workspace_run(workspace_id, effective_run_id))
        if _is_terminal_code_workspace_run(latest):
            return _format_code_workspace_result(latest)
        time.sleep(interval)

    if latest is None:
        latest = _call_with_retry(lambda: client.get_code_workspace_run(workspace_id, effective_run_id))
    formatted = _format_code_workspace_result(latest)
    return formatted + "\nTimed out while waiting for the run to finish."


# ── Artifacts ────────────────────────────────────────────────────────

@mcp.tool()
def list_artifacts(artifact_type: str = "") -> str:
    """List artifacts — charts, reports, analyses, code, and other outputs from agent runs.

    Args:
        artifact_type: Optional filter by type (e.g. "chart", "report", "code", "csv")
    """
    def _do():
        filters = {}
        if artifact_type:
            filters["type"] = artifact_type
        return _get_client().list_artifacts(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No artifacts found."
    lines = [f"**{len(result)} artifact(s):**"]
    for a in result[:20]:
        name = a.get("name") or a.get("title") or a.get("id", "?")
        atype = a.get("type", "")
        lines.append(f"- `{name}` ({atype})" if atype else f"- `{name}`")
    return "\n".join(lines)


@mcp.tool()
def get_artifact(artifact_id: str) -> str:
    """Get the full content of a specific artifact.

    Args:
        artifact_id: The artifact UUID
    """
    def _do():
        return _get_client().get_artifact(artifact_id)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


@mcp.tool()
def register_external_artifact(
    type: str,
    title: str = "",
    summary: str = "",
    uri: str = "",
    content: str = "",
    project_id: str = "",
    source_agent: str = "external_agent",
    attach_workspace: bool = False,
) -> str:
    """Register an artifact you created OUTSIDE Lightbulb so Lightbulb's domain agents can
    discover, reference, and work on it.

    Use this whenever you (Claude, Claude Code, ChatGPT, Codex, Hermes, etc.) produce something
    external while orchestrating Lightbulb — a code repository, document, slide deck, spreadsheet,
    report, or any URL — and you want it to become a first-class, discoverable Lightbulb artifact
    (searchable via list_artifacts and routable to domain agents / code workspaces).

    Args:
        type: Artifact class — one of: codebase, document, slide_deck, spreadsheet, report, url.
        title: Human-readable title.
        summary: Short description of what it is and why it matters.
        uri: External reference (e.g. a GitHub repo URL, Google Doc URL, file link). Provide this
             OR content.
        content: Inline text content (for documents/reports) when there is no external URL.
        project_id: Optional Lightbulb project UUID to associate the artifact with.
        source_agent: The agent that created it (e.g. "claude_code", "codex", "chatgpt", "hermes").
        attach_workspace: For a codebase artifact with a repo uri, also clone it into a Lightbulb
            Code Workspace so domain agents can work on it (not just discover it).
    """
    if not uri and not content:
        return "Error: provide either 'uri' (an external reference) or 'content' (inline text)."

    def _do():
        return _get_client().register_external_artifact(
            type=type,
            title=title,
            summary=summary,
            uri=uri,
            content=content,
            project_id=project_id or None,
            source_agent=source_agent or "external_agent",
            attach_workspace=attach_workspace,
        )
    result = _call_with_retry(_do)
    handle = (result or {}).get("handle", "")
    klass = (result or {}).get("artifact_class", type)
    ref = (result or {}).get("external_reference") or uri
    proj = (result or {}).get("project_id") or project_id
    rag_indexed = (result or {}).get("rag_indexed")
    ws = (result or {}).get("workspace_attach_requested")
    lines = [f"Registered external {klass} artifact in Lightbulb."]
    if handle:
        lines.append(f"- handle: `{handle}`")
    if ref:
        lines.append(f"- reference: {ref}")
    if proj:
        lines.append(f"- project: {proj} (project-indexed)")
    if rag_indexed:
        lines.append("- semantically searchable via RAG")
    if ws:
        lines.append("- cloning into a Code Workspace so agents can work on it")
    lines.append("Lightbulb domain agents can now discover it via list_artifacts / get_artifact"
                 + (" and RAG retrieval." if rag_indexed else "."))
    return "\n".join(lines)


# ── Workflows ────────────────────────────────────────────────────────

@mcp.tool()
def list_workflows() -> str:
    """List workflow definitions available on the platform."""
    def _do():
        return _get_client().list_workflows()
    result = _call_with_retry(_do)
    if not result:
        return "No workflows found."
    lines = [f"**{len(result)} workflow(s):**"]
    for w in result[:20]:
        name = w.get("name") or w.get("type") or w.get("id", "?")
        desc = w.get("description", "")[:80]
        lines.append(f"- `{name}`{f' — {desc}' if desc else ''}")
    return "\n".join(lines)


@mcp.tool()
def trigger_workflow(workflow_type: str, objective: str, inputs: str = "{}") -> str:
    """Trigger a workflow execution.

    Args:
        workflow_type: The workflow type to trigger (e.g. "enterprise_document_intelligence")
        objective: What the workflow should accomplish
        inputs: Optional JSON string of structured inputs
    """
    parsed = {}
    if inputs and inputs.strip() != "{}":
        try:
            parsed = json.loads(inputs)
        except json.JSONDecodeError:
            return f"Error: inputs must be valid JSON"
    def _do():
        return _get_client().trigger_workflow(workflow_type, objective, inputs=parsed if parsed else None)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:3000]


# ── RAG / Knowledge Base ─────────────────────────────────────────────

@mcp.tool()
def rag_query(question: str, top_k: int = 5) -> str:
    """Query the RAG knowledge base directly with a question.

    Returns relevant passages from indexed documents with citations.

    Args:
        question: Your question
        top_k: Number of results to return (default 5)
    """
    def _do():
        return _get_client().rag_query(question, top_k=top_k)
    result = _call_with_retry(_do)
    answer = result.get("answer", "")
    chunks = result.get("chunks", [])
    parts = []
    if answer:
        parts.append(answer)
    if chunks:
        parts.append(f"\n**{len(chunks)} source(s):**")
        for c in chunks[:top_k]:
            path = c.get("source_path") or c.get("document_id", "")
            snippet = (c.get("content") or "")[:150]
            parts.append(f"- `{path}`: {snippet}")
    return "\n".join(parts) if parts else "No results found."


@mcp.tool()
def rag_upload(filename: str, content: str) -> str:
    """Upload a document to the RAG knowledge base for indexing.

    Args:
        filename: The filename (e.g. "meeting-notes.md")
        content: The document content (text)
    """
    def _do():
        return _get_client().rag_upload_document(filename, content)
    result = _call_with_retry(_do)
    doc_id = result.get("id") or result.get("document_id", "")
    return f"Uploaded `{filename}` — document ID: `{doc_id}`" if doc_id else json.dumps(result, default=str)[:500]


# ── Connectors & Tools ───────────────────────────────────────────────

@mcp.tool()
def list_connectors() -> str:
    """List all available connectors and their connection status.

    Shows which integrations (Slack, HubSpot, Stripe, etc.) are connected.
    """
    def _do():
        return _get_client().list_connectors()
    result = _call_with_retry(_do)
    if not result:
        return "No connectors found."
    lines = [f"**{len(result)} connector(s):**"]
    for c in result[:30]:
        name = c.get("name") or c.get("provider") or c.get("id", "?")
        status = c.get("status", "")
        lines.append(f"- `{name}` {f'({status})' if status else ''}")
    return "\n".join(lines)


@mcp.tool()
def invoke_tool(tool_name: str, arguments: str = "{}") -> str:
    """Invoke a platform tool directly by name.

    Tools include connector operations (e.g. "hubspot.list_contacts"),
    utility tools, and more. Use list_connectors to see available tools.

    Args:
        tool_name: The tool to invoke (e.g. "slack.post_message")
        arguments: JSON string of tool arguments
    """
    parsed = {}
    if arguments and arguments.strip() != "{}":
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError:
            return f"Error: arguments must be valid JSON"
    routed = _maybe_route_generated_connector_invoke(tool_name, parsed)
    if routed is not None:
        return routed
    def _do():
        return _get_client().invoke_tool(tool_name, parsed)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


# ── CRM ──────────────────────────────────────────────────────────────

@mcp.tool()
def list_crm_contacts(search: str = "", limit: int = 20) -> str:
    """List CRM contacts, optionally filtered by search query.

    Args:
        search: Optional search term to filter contacts
        limit: Max results (default 20)
    """
    def _do():
        filters = {"limit": limit}
        if search:
            filters["search"] = search
        return _get_client().list_contacts(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No contacts found."
    lines = [f"**{len(result)} contact(s):**"]
    for c in result[:limit]:
        name = c.get("name") or f"{c.get('firstName', '')} {c.get('lastName', '')}".strip() or c.get("email", "?")
        email = c.get("email", "")
        company = c.get("company") or c.get("companyName", "")
        parts = [f"- **{name}**"]
        if email:
            parts.append(f" ({email})")
        if company:
            parts.append(f" @ {company}")
        lines.append("".join(parts))
    return "\n".join(lines)


@mcp.tool()
def list_crm_deals(search: str = "", limit: int = 20) -> str:
    """List CRM deals/opportunities.

    Args:
        search: Optional search term
        limit: Max results (default 20)
    """
    def _do():
        filters = {"limit": limit}
        if search:
            filters["search"] = search
        return _get_client().list_deals(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No deals found."
    lines = [f"**{len(result)} deal(s):**"]
    for d in result[:limit]:
        name = d.get("name") or d.get("title", "?")
        stage = d.get("stage", "")
        value = d.get("value") or d.get("amount", "")
        lines.append(f"- **{name}** {f'— {stage}' if stage else ''} {f'(${value})' if value else ''}")
    return "\n".join(lines)


# ── Notifications & HITL ─────────────────────────────────────────────

@mcp.tool()
def list_notifications(limit: int = 20) -> str:
    """List recent notifications — HITL decisions, workflow alerts, system messages.

    Args:
        limit: Max results (default 20)
    """
    def _do():
        return _get_client().list_notifications(limit=limit)
    result = _call_with_retry(_do)
    if not result:
        return "No notifications."
    lines = [f"**{len(result)} notification(s):**"]
    for n in result[:limit]:
        title = n.get("title") or n.get("message", "?")[:80]
        ntype = n.get("type") or n.get("category", "")
        lines.append(f"- [{ntype}] {title}" if ntype else f"- {title}")
    return "\n".join(lines)


# ── HITL / Approvals ─────────────────────────────────────────────

@mcp.tool()
def list_pending_approvals() -> str:
    """List all pending approval tasks waiting for your decision.

    These are human-in-the-loop (HITL) decisions from agent workflows —
    things like purchase approvals, content sign-offs, or deployment gates
    that require a human to approve or reject before the agent continues.
    """
    def _do():
        return _get_client().list_pending_approvals()
    result = _call_with_retry(_do)
    if not result:
        return "No pending approvals."
    lines = [f"**{len(result)} pending approval(s):**"]
    for t in result[:20]:
        task_id = t.get("id") or t.get("taskId", "?")
        title = t.get("title") or t.get("summary") or t.get("objective", "Untitled task")
        agent = t.get("agentName") or t.get("workflowType", "")
        risk = t.get("riskLevel", "")
        line = f"- **{title}** (`{task_id}`)"
        if agent:
            line += f" — from {agent}"
        if risk:
            line += f" [{risk} risk]"
        lines.append(line)
    return "\n".join(lines)


@mcp.tool()
def get_approval_details(task_id: str) -> str:
    """Get full details of a pending approval task before deciding.

    Shows the agent's reasoning, proposed action, risk assessment,
    and any supporting evidence.

    Args:
        task_id: The approval task UUID
    """
    def _do():
        return _get_client().get_approval(task_id)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


@mcp.tool()
def approve_task(task_id: str, comments: str = "") -> str:
    """Approve a pending HITL task, allowing the agent workflow to continue.

    This is a real decision — the agent will proceed with the proposed action.
    Review the task details first with get_approval_details.

    Args:
        task_id: The approval task UUID
        comments: Optional reason for approval
    """
    def _do():
        return _get_client().approve_task(task_id, comments=comments)
    result = _call_with_retry(_do)
    status = result.get("status", "")
    title = result.get("title") or result.get("summary", "")
    return f"Approved: {title} (status: {status})" if title else json.dumps(result, default=str)[:500]


@mcp.tool()
def reject_task(task_id: str, comments: str = "") -> str:
    """Reject a pending HITL task, stopping the agent workflow.

    The agent will not proceed with the proposed action.

    Args:
        task_id: The approval task UUID
        comments: Reason for rejection
    """
    def _do():
        return _get_client().reject_task(task_id, comments=comments)
    result = _call_with_retry(_do)
    status = result.get("status", "")
    title = result.get("title") or result.get("summary", "")
    return f"Rejected: {title} (status: {status})" if title else json.dumps(result, default=str)[:500]


# ── Memory ───────────────────────────────────────────────────────────

@mcp.tool()
def memory_store(key: str, value: str, namespace: str = "default") -> str:
    """Store a value in the platform's agent memory.

    Use this to persist information across conversations and sessions.

    Args:
        key: Memory key (e.g. "user_preferences", "project_context")
        value: The value to store
        namespace: Memory namespace (default "default")
    """
    def _do():
        return _get_client().memory_store(key, value, namespace=namespace)
    result = _call_with_retry(_do)
    return f"Stored `{key}` in namespace `{namespace}`"


@mcp.tool()
def memory_recall(key: str, namespace: str = "default") -> str:
    """Recall a value from agent memory.

    Args:
        key: Memory key to recall
        namespace: Memory namespace (default "default")
    """
    def _do():
        return _get_client().memory_recall(key, namespace=namespace)
    result = _call_with_retry(_do)
    value = result.get("value", "")
    return value if value else f"No memory found for key `{key}` in namespace `{namespace}`"


@mcp.tool()
def memory_search(query: str, namespace: str = "default", top_k: int = 5) -> str:
    """Search agent memory semantically.

    Args:
        query: What to search for
        namespace: Memory namespace (default "default")
        top_k: Number of results (default 5)
    """
    def _do():
        return _get_client().memory_search(query, namespace=namespace, top_k=top_k)
    result = _call_with_retry(_do)
    if not result:
        return "No matching memories found."
    lines = [f"**{len(result)} memory match(es):**"]
    for m in result[:top_k]:
        key = m.get("key", "?")
        value = (m.get("value") or "")[:150]
        lines.append(f"- `{key}`: {value}")
    return "\n".join(lines)


# ── Company Context ──────────────────────────────────────────────────

@mcp.tool()
def list_companies() -> str:
    """List companies in the user's tenant.

    ADMIN and TENANT users need to select a company before using domain agents,
    CRM, finance, or other company-scoped operations. COMPANY users already
    have a company set automatically.
    """
    def _do():
        return _get_client().list_companies()
    result = _call_with_retry(_do)
    if not result:
        return "No companies found in your tenant."
    lines = [f"**{len(result)} company/companies:**"]
    for c in result[:20]:
        cid = c.get("id", "?")
        name = c.get("name", "Unnamed")
        lines.append(f"- **{name}** (`{cid}`)")
    active = _get_client().active_company_id
    if active:
        lines.append(f"\nCurrently selected: `{active}`")
    else:
        lines.append("\nNo company selected. Use select_company to choose one.")
    return "\n".join(lines)


@mcp.tool()
def select_company(company_id: str) -> str:
    """Select a company context for subsequent operations.

    ADMIN and TENANT users must select a company before using domain agents
    or other company-scoped features. This determines which CRM data,
    financial accounts, connectors, etc. you're working with.

    Args:
        company_id: The company UUID from list_companies
    """
    # Defense-in-depth: reject obvious garbage at the MCP boundary so the
    # value never reaches the X-Company-Id header (audit-id:
    # select_company_uuid_0_5_1). The platform's RBAC enforces this too;
    # this is a fast-fail on shape before the round-trip.
    cleaned = company_id.strip()
    if not cleaned:
        return "Error: company_id is required."
    try:
        import uuid
        uuid.UUID(cleaned)
    except (ValueError, AttributeError):
        return f"Error: company_id must be a UUID, got {cleaned[:40]!r}"
    client = _get_client()
    client.active_company_id = cleaned
    return f"Company context set to `{cleaned}`. All subsequent domain agent calls will use this company."


# ── Identity & Context ───────────────────────────────────────────────

@mcp.tool()
def whoami() -> str:
    """Show your identity, role, tenant, company, and what you can access.

    Use this to understand your current context — especially useful for
    debugging permission issues or confirming which company is selected.
    """
    def _do():
        return _get_client().whoami()
    result = _call_with_retry(_do)

    role = result.get("role", "?")
    email = result.get("email", "?")
    tenant_id = result.get("tenantId", "?")
    company_id = result.get("companyId")
    first = result.get("firstName", "")
    last = result.get("lastName", "")
    name = f"{first} {last}".strip() or email

    active_company = _get_client().active_company_id

    lines = [
        f"**{name}**",
        f"Role: `{role}`",
        f"Tenant: `{tenant_id}`",
    ]
    if company_id:
        lines.append(f"Company (from account): `{company_id}`")
    if active_company:
        lines.append(f"Active company context: `{active_company}`")
    elif role in ("ADMIN", "TENANT"):
        lines.append("No company selected — use `select_company` before dispatching to domain agents")

    perms = result.get("permissions", [])
    if perms:
        lines.append(f"Permissions: {len(perms)} granted")

    ai_ready = result.get("aiReady", False)
    lines.append(f"AI Ready: {'yes' if ai_ready else 'no'}")

    return "\n".join(lines)


@mcp.tool()
def list_connected_integrations() -> str:
    """List connected integrations for the current company context.

    Shows what data sources are connected — QuickBooks, Stripe, HubSpot,
    Google Drive, Slack, etc. Helps you understand what data is available
    before running domain agent actions.
    """
    def _do():
        return _get_client().list_connected_integrations()
    result = _call_with_retry(_do)
    if not result:
        active = _get_client().active_company_id
        if not active:
            return "No company selected. Use `select_company` first to see integrations."
        return "No integrations connected for this company."
    lines = [f"**{len(result)} connected integration(s):**"]
    for conn in result[:30]:
        provider = conn.get("provider", "?")
        status = conn.get("status", "")
        scope = conn.get("scope") or conn.get("scopes", "")
        if isinstance(scope, list):
            scope = ", ".join(scope[:3])
        line = f"- **{provider}**"
        if status:
            line += f" ({status})"
        if scope:
            line += f" — {str(scope)[:80]}"
        lines.append(line)
    return "\n".join(lines)


# ── Platform Discovery ───────────────────────────────────────────────

@mcp.tool()
def list_domains() -> str:
    """List all available domain agents and their capabilities.

    Shows every domain agent on the platform with their supported actions.
    """
    def _do():
        return _get_client().list_domains()
    result = _call_with_retry(_do)
    if not result:
        return "No domains found."
    if isinstance(result, dict):
        lines = []
        for domain_name, contract in result.items():
            desc = contract.get("description", "")[:80] if isinstance(contract, dict) else ""
            actions = list(contract.get("actions", {}).keys()) if isinstance(contract, dict) else []
            lines.append(f"**{domain_name}**{f' — {desc}' if desc else ''}")
            if actions:
                lines.append(f"  Actions: {', '.join(actions[:10])}")
        return "\n".join(lines)
    return json.dumps(result, indent=2, default=str)[:3000]


@mcp.tool()
def list_domain_actions(domain: str) -> str:
    """List available actions for a specific domain agent.

    Args:
        domain: The domain name (e.g. "finance", "crm", "legal")
    """
    def _do():
        return _get_client().list_domain_actions(domain)
    result = _call_with_retry(_do)
    if not result:
        return f"No actions found for domain `{domain}`."
    lines = [f"**Actions for `{domain}`:**"]
    for a in (result if isinstance(result, list) else [result])[:30]:
        name = a.get("action", "?")
        desc = a.get("description", "")[:100]
        lines.append(f"- `{name}`{f' — {desc}' if desc else ''}")
    return "\n".join(lines)


# ── Stripe Orchestrator (Pillar 11 — outbound MCP) ──────────────────


def _stripe_client():
    from lightbulb.stripe import StripeOrchestratorClient
    return StripeOrchestratorClient(_get_client())


@mcp.tool()
def stripe_dispatch(resource: str, verb: str, op_inputs: str = "{}",
                    stripe_account_id: str = "") -> str:
    """Run any Stripe-orchestrator (resource, verb) op.

    Routes through the policy → simulator → Merkle audit → execute/queue
    chokepoint, exactly like our internal agents.

    Args:
        resource: e.g. "customers", "subscriptions", "refunds", "tax_calculations"
        verb: e.g. "create", "retrieve", "update", "list", "cancel"
        op_inputs: JSON object of operation inputs as string.
        stripe_account_id: Optional connected-account id.
    """
    inputs = _parse_json_argument(op_inputs, "op_inputs", {})
    def _do():
        return _stripe_client().dispatch(
            resource, verb, inputs,
            stripe_account_id=stripe_account_id or None,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_raw_api_request(api_path: str, method: str = "GET", params: str = "{}",
                           stripe_account_id: str = "", base_address: str = "") -> str:
    """Governed long-tail Stripe API request for /v1 or /v2 endpoints.

    Non-GET requests still route through the platform's simulator, audit,
    idempotency, and human-approval gate before execution.

    Args:
        api_path: Stripe API path, e.g. "/v1/setup_intents".
        method: GET, POST, or DELETE.
        params: JSON object of request parameters.
        stripe_account_id: Optional connected-account id.
        base_address: Optional Stripe base address, e.g. "api", "connect", "files".
    """
    parsed = _parse_json_argument(params, "params", {})
    def _do():
        return _stripe_client().raw_api_request(
            api_path,
            method=method,
            params=parsed,
            stripe_account_id=stripe_account_id or None,
            base_address=base_address or None,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_twin_list(resource_kind: str, limit: int = 50) -> str:
    """Fast Postgres-backed read of the Stripe Digital Twin (no Stripe RTT).

    Args:
        resource_kind: e.g. "customer", "subscription", "invoice", "charge"
        limit: Max rows to return (default 50, cap 100).
    """
    def _do():
        return _stripe_client().twin_list(resource_kind, limit=limit)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_list_pending_approvals() -> str:
    """List Stripe-orchestrator approvals waiting for human action."""
    def _do():
        return _stripe_client().list_pending_approvals()
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_approve(approval_id: str) -> str:
    """Approve a pending Stripe orchestrator decision so it can execute."""
    def _do():
        return _stripe_client().approve(approval_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_reject(approval_id: str, reason: str = "") -> str:
    """Reject a pending Stripe orchestrator decision."""
    def _do():
        return _stripe_client().reject(approval_id, reason=reason)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_execute_approved(approval_id: str) -> str:
    """Execute a previously-approved Stripe decision (idempotent replay safe)."""
    def _do():
        return _stripe_client().execute(approval_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_forecast_snapshot() -> str:
    """Predictive forecast for the merchant: MRR, failed-payment rate,
    dispute risk band, payout cashflow band. Server-computed; no Stripe RTT."""
    def _do():
        return _stripe_client().forecast_snapshot()
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_account_health() -> str:
    """Composite health score per connected Stripe account, plus the
    at-risk subset (score < 60) for direct triage."""
    def _do():
        return _stripe_client().account_health()
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def stripe_run_workflow(workflow: str) -> str:
    """Run a high-level composite workflow.

    Args:
        workflow: One of workflow.failed_payment_recovery,
                  workflow.churn_save_outreach,
                  workflow.dispute_evidence_drafting,
                  workflow.subscription_health_audit
    """
    def _do():
        return _stripe_client().run_workflow(workflow)
    return _format_result(_call_with_retry(_do))


# ── Xero Deep Integration ────────────────────────────────────────────


def _xero_client():
    from lightbulb.xero import XeroAgentClient
    return XeroAgentClient(_get_client())


@mcp.tool()
def xero_agent_snapshot(body: str = "{}") -> str:
    """Multi-org Xero financial snapshot (cash, AR, AP, payroll, taxes).

    Args:
        body: Optional JSON object of filters (e.g. {"xero_tenant_ids": ["..."]})
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().snapshot(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_proposals(body: str = "{}") -> str:
    """Generate Xero proposals (reconciliation, AP, payroll, etc.).

    Args:
        body: Optional JSON object (e.g. {"kind": "bank_reconciliation"})
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().proposals(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_create_proposal(body: str) -> str:
    """Create a Xero proposal (queues an HITL approval). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().create_proposal(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_approve_proposal(proposal_id: str, body: str = "{}") -> str:
    """Approve a Xero proposal so it can execute."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().approve_proposal(proposal_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_reject_proposal(proposal_id: str, reason: str = "") -> str:
    """Reject a Xero proposal."""
    def _do():
        return _xero_client().reject_proposal(proposal_id, reason=reason)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_run_sync(body: str = "{}") -> str:
    """Trigger a Xero data sync (orgs, AR/AP, payroll, ledger)."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().run_sync(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_run_playbook(playbook_id: str, body: str = "{}") -> str:
    """Run a Xero playbook.

    Args:
        playbook_id: month_end_close, ar_followup, ap_intake_to_pay,
            bank_reconciliation, payroll_trueup, reporting_pack, consolidation.
        body: Optional JSON object of inputs.
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().run_playbook(playbook_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_agent_org_profile(xero_tenant_id: str) -> str:
    """Get the Xero org profile (chart of accounts, tax rates, branding)."""
    def _do():
        return _xero_client().org_profile(xero_tenant_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_intake_invoice(body: str) -> str:
    """Propose an AR invoice into Xero (HITL-gated). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().propose_invoice(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_intake_bill(body: str) -> str:
    """Propose an AP bill into Xero (HITL-gated). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().propose_bill(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_intake_journal(body: str) -> str:
    """Propose a manual journal into Xero (HITL-gated). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().propose_journal(parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def xero_intake_payroll_trueup(body: str) -> str:
    """Propose a payroll true-up into Xero (HITL-gated). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _xero_client().propose_payroll_trueup(parsed)
    return _format_result(_call_with_retry(_do))


# ── Voice / Phone Executions ─────────────────────────────────────────


@mcp.tool()
def list_voice_executions(status: str = "", limit: int = 20) -> str:
    """List voice agent executions (live and historical phone calls).

    Args:
        status: Optional filter (active, completed, failed, transferred)
        limit: Max results
    """
    def _do():
        filters: dict[str, Any] = {"limit": limit}
        if status.strip():
            filters["status"] = status.strip()
        return _get_client().list_voice_executions(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No voice executions found."
    lines = [f"**{len(result)} voice execution(s):**"]
    for ex in result[:limit]:
        eid = ex.get("id") or ex.get("executionId", "?")
        status_v = ex.get("status", "")
        caller = ex.get("callerPhoneNumber") or ex.get("from", "")
        agent = ex.get("agentName", "")
        line = f"- `{eid}`"
        if status_v:
            line += f" [{status_v}]"
        if caller:
            line += f" caller={caller}"
        if agent:
            line += f" agent={agent}"
        lines.append(line)
    return "\n".join(lines)


@mcp.tool()
def get_voice_execution(execution_id: str) -> str:
    """Get a voice execution detail (transcript, status, agent decisions)."""
    def _do():
        return _get_client().get_voice_execution(execution_id)
    result = _call_with_retry(_do)
    return json.dumps(result, indent=2, default=str)[:5000]


@mcp.tool()
def list_voice_pending_approvals() -> str:
    """List in-call HITL approvals waiting for caller-side decision."""
    def _do():
        return _get_client().list_voice_pending_approvals()
    result = _call_with_retry(_do)
    if not result:
        return "No pending voice approvals."
    lines = [f"**{len(result)} pending voice approval(s):**"]
    for t in result[:20]:
        tid = t.get("id") or t.get("approvalTaskId", "?")
        eid = t.get("executionId", "?")
        title = t.get("title") or t.get("summary") or "Voice action"
        lines.append(f"- `{tid}` (exec `{eid}`): {title}")
    return "\n".join(lines)


@mcp.tool()
def approve_voice_action(execution_id: str, approval_task_id: str, comments: str = "") -> str:
    """Approve a pending in-call voice action."""
    def _do():
        return _get_client().approve_voice_action(execution_id, approval_task_id, comments=comments)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def reject_voice_action(execution_id: str, approval_task_id: str, comments: str = "") -> str:
    """Reject a pending in-call voice action."""
    def _do():
        return _get_client().reject_voice_action(execution_id, approval_task_id, comments=comments)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def modify_voice_action(execution_id: str, approval_task_id: str, modifications: str) -> str:
    """Approve a voice action with modifications. modifications is a JSON object."""
    parsed = _parse_json_argument(modifications, "modifications", {})
    def _do():
        return _get_client().modify_voice_action(execution_id, approval_task_id, parsed)
    return _format_result(_call_with_retry(_do))


# ── HR Live Connectors (BambooHR / Greenhouse / Monday) ──────────────


@mcp.tool()
def hr_live_whos_out() -> str:
    """BambooHR who's-out roster (current and upcoming time-off)."""
    def _do():
        return _get_client().hr_live_whos_out()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def hr_live_leave_balance(bamboo_employee_id: str) -> str:
    """BambooHR leave balance for an employee."""
    def _do():
        return _get_client().hr_live_leave_balance(bamboo_employee_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:3000]


@mcp.tool()
def hr_live_monday_board(checklist_id: str) -> str:
    """Monday.com board for an HR onboarding checklist."""
    def _do():
        return _get_client().hr_live_monday_onboarding_board(checklist_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def hr_live_cases() -> str:
    """HR case-board items from Monday.com."""
    def _do():
        return _get_client().hr_live_cases()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def hr_live_recruiting_jobs(status: str = "") -> str:
    """List Greenhouse jobs."""
    def _do():
        filters: dict[str, Any] = {}
        if status.strip():
            filters["status"] = status.strip()
        return _get_client().hr_live_recruiting_jobs(**filters)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def hr_live_recruiting_applications(job_id: str = "", status: str = "") -> str:
    """List Greenhouse applications."""
    def _do():
        filters: dict[str, Any] = {}
        if job_id.strip():
            filters["job_id"] = job_id.strip()
        if status.strip():
            filters["status"] = status.strip()
        return _get_client().hr_live_recruiting_applications(**filters)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def hr_live_advance_application(application_id: str, body: str = "{}") -> str:
    """Advance a Greenhouse candidate to the next stage (HITL-gated)."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().hr_live_advance_application(application_id, body=parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def hr_live_reject_application(application_id: str, body: str = "{}") -> str:
    """Reject a Greenhouse application (HITL-gated)."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().hr_live_reject_application(application_id, body=parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def hr_live_health() -> str:
    """Health check for HR connector tokens (BambooHR / Greenhouse / Monday)."""
    def _do():
        return _get_client().hr_live_health()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:2000]


# ── Code Workspace: Collaboration & Sharing ──────────────────────────


@mcp.tool()
def code_workspace_collaboration(workspace_id: str) -> str:
    """Get collaboration info (members, share-links, pending requests)."""
    def _do():
        return _get_client().code_workspace_collaboration(workspace_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def code_workspace_add_collaborator(
    workspace_id: str,
    email: str = "",
    user_id: str = "",
    role: str = "viewer",
) -> str:
    """Add a collaborator to a workspace (role: viewer | editor | admin)."""
    if not email and not user_id:
        return "Error: provide either email or user_id"
    def _do():
        return _get_client().code_workspace_add_collaborator(
            workspace_id,
            email=email or None,
            user_id=user_id or None,
            role=role,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_update_collaborator(workspace_id: str, collaborator_id: str, role: str) -> str:
    """Change a collaborator's role."""
    def _do():
        return _get_client().code_workspace_update_collaborator(workspace_id, collaborator_id, role=role)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_remove_collaborator(workspace_id: str, collaborator_id: str) -> str:
    """Revoke a collaborator's access."""
    def _do():
        _get_client().code_workspace_remove_collaborator(workspace_id, collaborator_id)
        return {"removed": collaborator_id}
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_create_share_link(workspace_id: str, role: str = "viewer", expires_in_seconds: int = 0) -> str:
    """Create a share-link token granting access to the workspace."""
    def _do():
        return _get_client().code_workspace_create_share_link(
            workspace_id,
            role=role,
            expires_in_seconds=expires_in_seconds or None,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_revoke_share_link(workspace_id: str, link_id: str) -> str:
    """Revoke a share link."""
    def _do():
        _get_client().code_workspace_revoke_share_link(workspace_id, link_id)
        return {"revoked": link_id}
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_approve_access_request(workspace_id: str, request_id: str) -> str:
    """Approve a pending access request."""
    def _do():
        return _get_client().code_workspace_approve_access_request(workspace_id, request_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_deny_access_request(workspace_id: str, request_id: str) -> str:
    """Deny a pending access request."""
    def _do():
        return _get_client().code_workspace_deny_access_request(workspace_id, request_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_add_note(workspace_id: str, content: str) -> str:
    """Append a note to a workspace (visible to collaborators)."""
    def _do():
        return _get_client().code_workspace_add_note(workspace_id, content)
    return _format_result(_call_with_retry(_do))


# ── Code Workspace: Runs / Reviews / Proposals ───────────────────────


@mcp.tool()
def code_workspace_runs(workspace_id: str, limit: int = 20) -> str:
    """List historical coding runs for a workspace."""
    def _do():
        return _get_client().list_code_workspace_runs(workspace_id, limit=limit)
    result = _call_with_retry(_do)
    if not result:
        return "No runs found."
    lines = [f"**{len(result)} run(s):**"]
    for r in result[:limit]:
        rid = r.get("id") or r.get("runId", "?")
        status_v = r.get("status", "")
        phase = r.get("phase", "")
        lines.append(f"- `{rid}` [{status_v}]" + (f" phase={phase}" if phase else ""))
    return "\n".join(lines)


@mcp.tool()
def code_workspace_runs_insights(workspace_id: str) -> str:
    """Aggregate run-quality insights for a workspace."""
    def _do():
        return _get_client().code_workspace_runs_insights(workspace_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def code_workspace_run_review(workspace_id: str, run_id: str, verdict: str, feedback: str = "") -> str:
    """Submit a human review verdict for a run (accept | reject | request_changes)."""
    def _do():
        return _get_client().code_workspace_run_review(workspace_id, run_id, verdict=verdict, feedback=feedback)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_run_review_apply(workspace_id: str, run_id: str) -> str:
    """Apply review-suggested changes to the workspace."""
    def _do():
        return _get_client().code_workspace_run_review_apply(workspace_id, run_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_proposals(workspace_id: str) -> str:
    """List code-change proposals for a workspace."""
    def _do():
        return _get_client().list_code_workspace_proposals(workspace_id)
    result = _call_with_retry(_do)
    if not result:
        return "No proposals."
    lines = [f"**{len(result)} proposal(s):**"]
    for p in result[:20]:
        pid = p.get("id") or p.get("proposalId", "?")
        title = p.get("title") or p.get("summary", "")
        status_v = p.get("status", "")
        lines.append(f"- `{pid}` [{status_v}] {title}")
    return "\n".join(lines)


@mcp.tool()
def code_workspace_proposal_apply(workspace_id: str, proposal_id: str) -> str:
    """Apply a code-change proposal to workspace files."""
    def _do():
        return _get_client().apply_code_workspace_proposal(workspace_id, proposal_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_proposal_reject(workspace_id: str, proposal_id: str, reason: str = "") -> str:
    """Reject a code-change proposal."""
    def _do():
        return _get_client().reject_code_workspace_proposal(workspace_id, proposal_id, reason=reason)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_pull_request(workspace_id: str, body: str = "{}") -> str:
    """Open a GitHub pull request from the workspace branch."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().code_workspace_create_pull_request(workspace_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_cancel_run(workspace_id: str, run_id: str) -> str:
    """Cancel an in-flight coding run."""
    def _do():
        return _get_client().cancel_code_workspace_run(workspace_id, run_id)
    return _format_result(_call_with_retry(_do))


# ── Code Workspace: Claude SDK runtime sessions ──────────────────────


@mcp.tool()
def code_workspace_claude_sessions(workspace_id: str) -> str:
    """List Claude SDK sessions associated with a workspace."""
    def _do():
        return _get_client().list_code_workspace_claude_sessions(workspace_id)
    result = _call_with_retry(_do)
    if not result:
        return "No Claude sessions."
    lines = [f"**{len(result)} Claude session(s):**"]
    for s in result[:20]:
        sid = s.get("sessionId") or s.get("id", "?")
        name = s.get("threadName") or s.get("title", "")
        status_v = s.get("status", "")
        lines.append(f"- `{sid}` [{status_v}] {name}")
    return "\n".join(lines)


@mcp.tool()
def code_workspace_claude_session_action(
    workspace_id: str,
    session_id: str,
    action: str,
    body: str = "{}",
) -> str:
    """Perform a Claude SDK session action.

    Args:
        action: One of: tag, fork, delete, interrupt, mcp/reconnect, mcp/toggle,
            rewind, tasks/stop, compact, rename
        body: JSON object payload (action-specific, e.g. {"tag": "..."} for tag).
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().claude_session_action(workspace_id, session_id, action, parsed)
    return _format_result(_call_with_retry(_do))


# ── Code Workspace: Codex runtime threads ────────────────────────────


@mcp.tool()
def code_workspace_codex_threads(workspace_id: str, archived: str = "") -> str:
    """List Codex runtime threads for a workspace."""
    def _do():
        filters: dict[str, Any] = {}
        if archived.strip():
            filters["archived"] = archived.strip()
        return _get_client().list_code_workspace_codex_threads(workspace_id, **filters)
    result = _call_with_retry(_do)
    if not result:
        return "No Codex threads."
    lines = [f"**{len(result)} Codex thread(s):**"]
    for t in result[:20]:
        tid = t.get("threadId") or t.get("id", "?")
        title = t.get("title", "")
        status_v = t.get("status", "")
        lines.append(f"- `{tid}` [{status_v}] {title}")
    return "\n".join(lines)


@mcp.tool()
def code_workspace_codex_thread_action(
    workspace_id: str,
    thread_id: str,
    action: str,
    body: str = "{}",
) -> str:
    """Perform a thread-level Codex action.

    Args:
        action: One of: rename, archive, unarchive, compact, rollback
        body: JSON object payload.
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().codex_thread_action(workspace_id, thread_id, action, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def code_workspace_codex_turn_action(
    workspace_id: str,
    thread_id: str,
    turn_id: str,
    action: str,
    body: str = "{}",
) -> str:
    """Steer or interrupt a specific Codex turn.

    Args:
        action: steer | interrupt
        body: JSON object payload (e.g. {"guidance": "..."}).
    """
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().codex_turn_action(workspace_id, thread_id, turn_id, action, parsed)
    return _format_result(_call_with_retry(_do))


# ── AutoCompany / AOC ────────────────────────────────────────────────


@mcp.tool()
def list_aoc_runs(status: str = "", limit: int = 20) -> str:
    """List AutoCompany cognitive-loop runs."""
    def _do():
        filters: dict[str, Any] = {"limit": limit}
        if status.strip():
            filters["status"] = status.strip()
        return _get_client().list_aoc_runs(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No AutoCompany runs."
    lines = [f"**{len(result)} run(s):**"]
    for r in result[:limit]:
        rid = r.get("id") or r.get("runId", "?")
        status_v = r.get("status", "")
        objective = r.get("objective") or r.get("title", "")
        lines.append(f"- `{rid}` [{status_v}] {objective}"[:200])
    return "\n".join(lines)


@mcp.tool()
def get_aoc_run(run_id: str) -> str:
    """Get an AutoCompany run detail."""
    def _do():
        return _get_client().get_aoc_run(run_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def stop_aoc_run(run_id: str) -> str:
    """Stop an in-flight AutoCompany cognitive-loop run."""
    def _do():
        return _get_client().stop_aoc_run(run_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def validate_aoc_run_config(run_id: str) -> str:
    """Validate an AutoCompany run's configuration."""
    def _do():
        return _get_client().validate_aoc_run_config(run_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:3000]


@mcp.tool()
def list_aoc_tasks(run_id: str = "", limit: int = 20) -> str:
    """List AutoCompany tasks (optionally scoped to a run)."""
    def _do():
        filters: dict[str, Any] = {"limit": limit}
        if run_id.strip():
            filters["run_id"] = run_id.strip()
        return _get_client().list_aoc_tasks(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No tasks."
    lines = [f"**{len(result)} task(s):**"]
    for t in result[:limit]:
        tid = t.get("id") or t.get("taskId", "?")
        title = t.get("title") or t.get("objective", "")
        status_v = t.get("status", "")
        lines.append(f"- `{tid}` [{status_v}] {title}"[:200])
    return "\n".join(lines)


@mcp.tool()
def get_aoc_task(task_id: str) -> str:
    """Get an AutoCompany task detail."""
    def _do():
        return _get_client().get_aoc_task(task_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def list_aoc_task_events(task_id: str) -> str:
    """List events recorded against an AutoCompany task."""
    def _do():
        return _get_client().list_aoc_task_events(task_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def post_aoc_task_event(task_id: str, body: str) -> str:
    """Post a new event onto an AutoCompany task. Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().post_aoc_task_event(task_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def list_aoc_decisions(status: str = "", limit: int = 20) -> str:
    """List AutoCompany decisions (pending or resolved)."""
    def _do():
        filters: dict[str, Any] = {"limit": limit}
        if status.strip():
            filters["status"] = status.strip()
        return _get_client().list_aoc_decisions(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No decisions."
    lines = [f"**{len(result)} decision(s):**"]
    for d in result[:limit]:
        did = d.get("id") or d.get("decisionId", "?")
        title = d.get("title") or d.get("summary", "")
        status_v = d.get("status", "")
        lines.append(f"- `{did}` [{status_v}] {title}"[:200])
    return "\n".join(lines)


@mcp.tool()
def get_aoc_decision(decision_id: str) -> str:
    """Get a specific AutoCompany decision."""
    def _do():
        return _get_client().get_aoc_decision(decision_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def list_aoc_ticks(run_id: str = "", limit: int = 20) -> str:
    """List AutoCompany cognitive-loop ticks."""
    def _do():
        filters: dict[str, Any] = {"limit": limit}
        if run_id.strip():
            filters["run_id"] = run_id.strip()
        return _get_client().list_aoc_ticks(**filters)
    result = _call_with_retry(_do)
    if not result:
        return "No ticks."
    return json.dumps(result, indent=2, default=str)[:5000]


@mcp.tool()
def get_aoc_tick(tick_id: str) -> str:
    """Get a single AutoCompany tick."""
    def _do():
        return _get_client().get_aoc_tick(tick_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


# ── Memory Graph ─────────────────────────────────────────────────────


@mcp.tool()
def memory_list_entries(limit: int = 50) -> str:
    """List structured memory entries."""
    def _do():
        return _get_client().memory_list_entries(limit=limit)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_query(body: str) -> str:
    """Run a structured memory query (filters, time-windows, semantic). Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().memory_query(parsed)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_projection_soul() -> str:
    """Identity / personality projection of the agent."""
    def _do():
        return _get_client().memory_projection_soul()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_projection_memory() -> str:
    """Memory-structure projection of the agent."""
    def _do():
        return _get_client().memory_projection_memory()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_graph(focus: str = "", depth: int = 0) -> str:
    """Read the memory graph (or a filtered subgraph)."""
    def _do():
        filters: dict[str, Any] = {}
        if focus.strip():
            filters["focus"] = focus.strip()
        if depth:
            filters["depth"] = depth
        return _get_client().memory_graph(**filters)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_graph_node(node_id: str) -> str:
    """Get a single node from the memory graph."""
    def _do():
        return _get_client().memory_graph_node(node_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:3000]


@mcp.tool()
def memory_list_identity() -> str:
    """List identity records in the memory graph."""
    def _do():
        return _get_client().memory_list_identity()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_list_events(limit: int = 50) -> str:
    """List memory events (timeline of state changes)."""
    def _do():
        return _get_client().memory_list_events(limit=limit)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def memory_list_skills() -> str:
    """List skills/capabilities recorded in memory."""
    def _do():
        return _get_client().memory_list_skills()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


# ── CRM Tasks ────────────────────────────────────────────────────────


@mcp.tool()
def list_crm_tasks(tenant_id: str = "", limit: int = 20) -> str:
    """List CRM tasks (defaults to authed tenant)."""
    def _do():
        return _get_client().list_crm_tasks(tenant_id=tenant_id or None, limit=limit)
    result = _call_with_retry(_do)
    if not result:
        return "No CRM tasks."
    lines = [f"**{len(result)} CRM task(s):**"]
    for t in result[:limit]:
        tid = t.get("id") or t.get("taskId", "?")
        title = t.get("title") or t.get("subject", "")
        status_v = t.get("status", "")
        lines.append(f"- `{tid}` [{status_v}] {title}")
    return "\n".join(lines)


@mcp.tool()
def get_crm_task(task_id: str, tenant_id: str = "") -> str:
    """Get a CRM task detail."""
    def _do():
        return _get_client().get_crm_task(task_id, tenant_id=tenant_id or None)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:3000]


@mcp.tool()
def create_crm_task(body: str, tenant_id: str = "") -> str:
    """Create a CRM task. Body is JSON (title, status, assigneeId, dueDate, contactId, dealId, ...)."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().create_crm_task(parsed, tenant_id=tenant_id or None)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def update_crm_task(task_id: str, body: str, tenant_id: str = "") -> str:
    """Update a CRM task. Body is JSON of fields to change."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().update_crm_task(task_id, parsed, tenant_id=tenant_id or None)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def delete_crm_task(task_id: str, tenant_id: str = "") -> str:
    """Delete a CRM task."""
    def _do():
        _get_client().delete_crm_task(task_id, tenant_id=tenant_id or None)
        return {"deleted": task_id}
    return _format_result(_call_with_retry(_do))


# ── Approval Auto-Accept Preferences ─────────────────────────────────


@mcp.tool()
def list_approval_preferences() -> str:
    """List the user's HITL auto-accept rules."""
    def _do():
        return _get_client().list_approval_preferences()
    result = _call_with_retry(_do)
    if not result:
        return "No auto-accept rules."
    lines = [f"**{len(result)} rule(s):**"]
    for p in result[:20]:
        pid = p.get("id", "?")
        enabled = p.get("enabled", True)
        scope = p.get("scope") or p.get("workflowType", "")
        lines.append(f"- `{pid}` {'[enabled]' if enabled else '[disabled]'} {scope}")
    return "\n".join(lines)


@mcp.tool()
def create_approval_auto_accept(task_id: str, body: str = "{}") -> str:
    """Create an auto-accept rule from an existing approval task's shape."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().create_approval_auto_accept(task_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def delete_approval_preference(preference_id: str) -> str:
    """Remove an auto-accept rule."""
    def _do():
        return _get_client().delete_approval_preference(preference_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def set_approval_preference_state(preference_id: str, enabled: bool = True) -> str:
    """Enable or disable an auto-accept rule."""
    def _do():
        return _get_client().set_approval_preference_state(preference_id, enabled=enabled)
    return _format_result(_call_with_retry(_do))


# ── Notification read-state ──────────────────────────────────────────


@mcp.tool()
def mark_notification_read(notification_id: str) -> str:
    """Mark a notification as read."""
    def _do():
        return _get_client().mark_notification_read(notification_id)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def mark_all_notifications_read() -> str:
    """Mark all notifications as read."""
    def _do():
        return _get_client().mark_all_notifications_read()
    return _format_result(_call_with_retry(_do))


# ── Domain Workspaces ────────────────────────────────────────────────


@mcp.tool()
def workspace_bundle(domain: str) -> str:
    """Get a domain workspace data bundle (state, surfaces, recent runs)."""
    def _do():
        return _get_client().workspace_bundle(domain)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def workspace_trace(domain: str, trace_id: str) -> str:
    """Get a workspace trace (full agent execution log)."""
    def _do():
        return _get_client().workspace_trace(domain, trace_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def workspace_surface(domain: str, surface: str) -> str:
    """Read a domain workspace surface (e.g. internal_suite)."""
    def _do():
        return _get_client().workspace_surface(domain, surface)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def it_ops_live_jira() -> str:
    """Live Jira data passthrough for the IT-Ops workspace."""
    def _do():
        return _get_client().it_ops_live_connector("jira")
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def it_ops_live_slack() -> str:
    """Live Slack data passthrough for the IT-Ops workspace."""
    def _do():
        return _get_client().it_ops_live_connector("slack")
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def it_ops_live_github() -> str:
    """Live GitHub data passthrough for the IT-Ops workspace."""
    def _do():
        return _get_client().it_ops_live_connector("github")
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def it_ops_live_notion() -> str:
    """Live Notion data passthrough for the IT-Ops workspace."""
    def _do():
        return _get_client().it_ops_live_connector("notion")
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def it_ops_mcp_manifest() -> str:
    """Get the IT-Ops workspace MCP manifest."""
    def _do():
        return _get_client().it_ops_mcp_manifest()
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


# ── Page Builder: automation, capabilities, SEO ──────────────────────


@mcp.tool()
def page_builder_workspace_automation(session_id: str, body: str = "{}") -> str:
    """Run the page-builder workspace automation (auto-wire pages → agents → backend)."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().page_builder_workspace_automation(session_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def page_builder_capabilities(session_id: str) -> str:
    """List page capabilities (forms, search, auth, etc.)."""
    def _do():
        return _get_client().page_builder_capabilities(session_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def page_builder_install_artifact(session_id: str, body: str) -> str:
    """Install a component artifact into the page session. Body is JSON."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().page_builder_install_artifact(session_id, parsed)
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def page_builder_unpublish(session_id: str) -> str:
    """Unpublish a deployed page builder session."""
    def _do():
        return _get_client().page_builder_unpublish(session_id)
    return _format_result(_call_with_retry(_do))


# ── Document Builder: collaboration & messages ───────────────────────


@mcp.tool()
def doc_builder_collaboration(session_id: str) -> str:
    """Collaboration info for a document builder session."""
    def _do():
        return _get_client().document_builder_collaboration(session_id)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def doc_builder_add_collaborator(
    session_id: str,
    email: str = "",
    user_id: str = "",
    role: str = "viewer",
) -> str:
    """Add a collaborator to a document builder session."""
    if not email and not user_id:
        return "Error: provide either email or user_id"
    def _do():
        return _get_client().document_builder_add_collaborator(
            session_id,
            email=email or None,
            user_id=user_id or None,
            role=role,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def doc_builder_create_share_link(session_id: str, role: str = "viewer", expires_in_seconds: int = 0) -> str:
    """Create a share-link token for a document builder session."""
    def _do():
        return _get_client().document_builder_create_share_link(
            session_id,
            role=role,
            expires_in_seconds=expires_in_seconds or None,
        )
    return _format_result(_call_with_retry(_do))


@mcp.tool()
def doc_builder_get_messages(session_id: str, limit: int = 50) -> str:
    """Get message history for a document builder session."""
    def _do():
        return _get_client().document_builder_get_messages(session_id, limit=limit)
    return json.dumps(_call_with_retry(_do), indent=2, default=str)[:5000]


@mcp.tool()
def doc_builder_save(session_id: str, body: str = "{}") -> str:
    """Save the current state of a document builder session."""
    parsed = _parse_json_argument(body, "body", {})
    def _do():
        return _get_client().document_builder_save(session_id, parsed)
    return _format_result(_call_with_retry(_do))


# ── Tool-surface profiles ────────────────────────────────────────────

_BACKBONE_PROFILE_TOOLS = {
    "whoami",
    "list_companies",
    "select_company",
    "backbone_execute",
    "start_consulting_project_workflow",
    "dispatch_domain_agent",
    "list_pending_approvals",
    "get_approval_details",
    "approve_task",
    "reject_task",
    "list_approval_preferences",
    "list_connectors",
    "list_connected_integrations",
    "invoke_tool",
    "software_delivery_context",
    "software_delivery_loop",
    "software_spot_weld_fix",
    "workspace_bundle",
    "workspace_trace",
    "workspace_conversation",
    "workspace_surface",
}


def _profile_name() -> str:
    return LIGHTBULB_MCP_PROFILE.replace("_", "-")


def _is_backbone_profile() -> bool:
    return _profile_name() in {"backbone", "core", "backbone-first"}


def _remove_unlisted_tools(allowed: set[str]) -> None:
    """Trim FastMCP's registry for compact OpenAI/Codex-facing profiles."""
    tools = getattr(getattr(mcp, "_tool_manager", None), "_tools", None)
    if not isinstance(tools, dict):
        logger.warning("Could not apply Lightbulb MCP profile; FastMCP tool registry shape changed.")
        return
    for name in list(tools.keys()):
        if name not in allowed:
            del tools[name]


# ── Auto-generated tools ─────────────────────────────────────────────
# Imports the codegen module so its @mcp.tool decorators register
# against the FastMCP instance defined above. Generated tools cover
# every domain action in agent-workers/agents/domain_registry.py and
# every connector op in scripts/connector_tool_keys.txt. Re-run
# `python3 scripts/generate_mcp_tools.py` after platform changes.
if _is_backbone_profile():
    _remove_unlisted_tools(_BACKBONE_PROFILE_TOOLS)
    print(
        "lightbulb-mcp: profile 'backbone' active - exposing the compact backbone/control-plane tool surface",
        file=sys.stderr,
    )
else:
    from lightbulb import mcp_generated_tools  # noqa: F401,E402  (side-effect import)


# ── Entry point ──────────────────────────────────────────────────────

def main():
    """Run the MCP server over stdio."""
    has_login = bool(LIGHTBULB_EMAIL and LIGHTBULB_PASSWORD)
    has_jwt = bool(LIGHTBULB_JWT and LIGHTBULB_TENANT_ID)
    has_api_key = bool(LIGHTBULB_API_KEY and LIGHTBULB_TENANT_ID and LIGHTBULB_USER_ID)

    if not has_login and not has_jwt and not has_api_key:
        print(
            "Warning: No authentication configured. Set either:\n"
            "  LIGHTBULB_EMAIL + LIGHTBULB_PASSWORD (logs in as the user), or\n"
            "  LIGHTBULB_JWT + LIGHTBULB_TENANT_ID (direct JWT token), or\n"
            "  LIGHTBULB_API_KEY + LIGHTBULB_TENANT_ID + LIGHTBULB_USER_ID (localhost integration)\n"
            "Tools will fail until credentials are provided.",
            file=sys.stderr,
        )

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
