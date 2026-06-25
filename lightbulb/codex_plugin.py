"""Codex plugin templates for the Lightbulb MCP package."""

from __future__ import annotations

import json
from typing import Dict

from lightbulb._version import __version__


PLUGIN_NAME = "lightbulb-partners"
PLUGIN_DISPLAY_NAME = "Lightbulb Partners"
MARKETPLACE_NAME = "lightbulb-local"
MARKETPLACE_DISPLAY_NAME = "Lightbulb Partners Local"


def plugin_manifest() -> str:
    """Return the Codex plugin manifest JSON."""
    manifest = {
        "name": PLUGIN_NAME,
        "version": f"{__version__}+codex",
        "description": "Use the Lightbulb Partners backbone agent, project workflow engine, and governed domain agents from Codex.",
        "author": {
            "name": "Lightbulb Partners",
            "email": "robbie.pasquale@lightbulbpartners.com",
            "url": "https://agents.lightbulbpartners.com",
        },
        "homepage": "https://agents.lightbulbpartners.com",
        "repository": "https://github.com/lightbulb-partners/lightbulb-mcp",
        "license": "Apache-2.0",
        "keywords": ["lightbulb", "mcp", "agents", "backbone", "codex"],
        "skills": "./skills/",
        "mcpServers": "./.mcp.json",
        "interface": {
            "displayName": PLUGIN_DISPLAY_NAME,
            "shortDescription": "Route Codex work through your Lightbulb backbone agent.",
            "longDescription": (
                "Connect Codex to the Lightbulb Partners Agents platform. The plugin exposes a backbone-first MCP "
                "surface that runs as the authenticated Lightbulb user and preserves tenant, company, RBAC, approval "
                "controls, project workflow gates, Product Machine context, Code Workspace handoff, and governed "
                "domain-agent dispatch."
            ),
            "developerName": "Lightbulb Partners",
            "category": "Productivity",
            "capabilities": ["Read", "Write"],
            "websiteURL": "https://agents.lightbulbpartners.com",
            "brandColor": "#10A37F",
            "defaultPrompt": [
                "Use Lightbulb Partners to understand my company context and recommend the next operational actions.",
                "Use the Lightbulb backbone agent to coordinate this cross-functional request.",
                "Use Lightbulb Partners to call start_consulting_project_workflow from this idea, gather requirements, generate SOPs, create approved work packets, and draft QA/change plans before draft PR shipping.",
                "Check my Lightbulb approvals and explain what needs attention.",
            ],
        },
    }
    return json.dumps(manifest, indent=2) + "\n"


def plugin_mcp_config(base_url: str) -> str:
    """Return the plugin-scoped MCP config JSON."""
    config = {
        "mcpServers": {
            "lightbulb": {
                "command": "lightbulb-mcp",
                "args": [],
                "env": {
                    "LIGHTBULB_URL": base_url.rstrip("/"),
                    "LIGHTBULB_MCP_PROFILE": "backbone",
                },
            }
        }
    }
    return json.dumps(config, indent=2) + "\n"


def plugin_skill() -> str:
    """Return the bundled Codex skill instructions."""
    return """---
name: lightbulb
description: Use the Lightbulb Partners backbone agent, consulting project workflow engine, and governed domain agents from Codex.
---

# Lightbulb Partners

Use this skill when the user asks Codex to work through Lightbulb Partners, the Lightbulb backbone agent, domain agents, approvals, connectors, company operating context, consulting/project workflow setup, Product Machine, or Lightbulb code/workspace delivery.

## Operating Model

- Start with `whoami` when the current Lightbulb tenant, role, or company context is unclear.
- For ADMIN or TENANT users, call `list_companies` and then `select_company` before company-scoped work.
- Prefer `backbone_execute` for broad objectives, cross-domain requests, operating analysis, workflow orchestration, or work that should reuse Lightbulb memory, connectors, approvals, and domain agents.
- For project ideas, custom-agent requests, automation requests, SOP/process work, or build requests without approved scope, call `start_consulting_project_workflow` when available. If the host has not refreshed that tool yet, ask Backbone through `backbone_execute` to start or continue the `consulting_project_workflow`. It should collect intake, facts, requirements, SOP impact, referenced SOPs, approvals, and work packets before execution.
- Treat `software_delivery_loop` and `software_spot_weld_fix` as existing/approved engineering-loop tools. Rough project, custom-agent, SOP, modernization, or repo-creation requests must start the consulting workflow first unless Lightbulb provides explicit Product Machine delivery-readiness context or an intentional `force_software_delivery_loop=true` override.
- Treat direct `dispatch_domain_agent` calls to coding, IT/Ops, engineering, or product the same way. Use domain dispatch for normal analysis or approved work-packet execution, not to bypass Project Agent intake, scope, SOP impact or referenced-SOP approval, and work-packet approval.
- Treat generic `invoke_tool` repo/workflow/deployment writes such as `github.create_repository`, `github.create_pull_request`, `github.trigger_workflow`, and `github.create_deployment_status` as Product Machine delivery actions. They should not be used before the consulting workflow approves scope, requirements, SOP impact or referenced SOPs, work packets, and the relevant HITL gate. Draft PR shipping additionally requires QA/acceptance and change-management plans.
- Treat Page Builder as a pure design tool unless the prompt is really a project-like page, portal, app, SOP, workflow, custom-agent, repo, or GitHub-backed site build. For those, start the consulting workflow first; use `force_page_builder=true` only for intentionally standalone design sessions.
- Treat direct `code_workspace_chat` prompts the same way when they ask for a custom agent, SOP-backed build, or broad project implementation. Use Code Workspace directly for bounded fixes or approved work packets, not for first-pass project discovery.
- When the objective includes code delivery, keep Lightbulb as the control plane and Codex/Claude Code as executor lanes. Preserve `workflow_type=consulting_project_workflow`, `dispatch_contract`, `code_delivery`, approved requirements, approved SOPs when changed or referenced/process maps, selected work packets, `qa_plan`, and `change_plan` in Code Workspace before draft PR shipping.
- When the user arrives through onboarding, helper, AutoCompany, or an initial "build this" prompt, make the launch feel guided: create or select the company context, explain that Backbone will run the consulting workflow, call `start_consulting_project_workflow` or `backbone_execute` with `workflow_type=consulting_project_workflow`, and keep the user oriented around the next approval or missing fact instead of sending them to a generic domain agent.
- Domain agents should be dispatched by Backbone from the approved work-packet plan. Do not directly start coding, CRM, finance, legal, IT/Ops, content, or deployment execution from onboarding/helper context before approved requirements, scope, SOP impact or referenced SOPs, and work packets.
- Do not create GitHub repos, draft PRs, deploy, mutate customer data, send external communications, or assign work packets unless the relevant Lightbulb approval gate has passed or Lightbulb returns an explicit HITL-approved action. For draft PRs, require QA/acceptance and change-management planning evidence in addition to Code Workspace verification.
- Keep consequential writes behind Lightbulb's existing approval and HITL behavior. Do not bypass approval tools or claim execution completed when Lightbulb returns a pending approval state.
- Treat Lightbulb as the control plane. Codex can implement code locally when asked, but Lightbulb should own company context, domain-agent routing, approvals, and connector-backed operational actions.

## Auth And Setup

The bundled MCP server expects the `lightbulb-mcp` package to be installed and uses the authenticated user's Lightbulb token cache or environment credentials.

If the MCP server is not authenticated, guide the user to run:

```bash
pip install --upgrade lightbulb-mcp
lightbulb setup --target codex
```

The default plugin MCP profile is backbone-first. Power users can expose more generated domain or connector tools by changing `LIGHTBULB_MCP_PROFILE` or setting `LIGHTBULB_MCP_NAMESPACES` in their MCP config.
"""


def plugin_files(base_url: str) -> Dict[str, str]:
    """Return plugin files keyed by path relative to the plugin root."""
    return {
        ".codex-plugin/plugin.json": plugin_manifest(),
        ".mcp.json": plugin_mcp_config(base_url),
        "skills/lightbulb/SKILL.md": plugin_skill(),
    }


def marketplace_entry(source_path: str = "./.codex/plugins/lightbulb-partners") -> dict:
    """Return the marketplace entry for the local Lightbulb plugin."""
    return {
        "name": PLUGIN_NAME,
        "source": {
            "source": "local",
            "path": source_path,
        },
        "policy": {
            "installation": "AVAILABLE",
            "authentication": "ON_INSTALL",
        },
        "category": "Productivity",
    }
