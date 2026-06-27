# Lightbulb MCP server

The MCP server exposes the Lightbulb platform as tools for AI hosts (Claude Code, Codex CLI, Cursor, etc.). Every call runs as the **authenticated user** through Spring Boot: tenant isolation, company isolation, RBAC, and rate limits match the web app—there is no elevated “MCP service role.”

Companion CLI documentation: [README.md](README.md).

## Run

Install from the public GitHub repo with `pip install git+https://github.com/RPasquale/lightbulb-mcp.git`, then run:

```bash
lightbulb-mcp
```

Equivalent:

```bash
python -m lightbulb.mcp_server
```

The host should spawn this command with **stdio** transport (default MCP). Example `.mcp.json` fragment:

```json
{
  "mcpServers": {
    "lightbulb": {
      "command": "lightbulb-mcp",
      "env": {
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com"
      }
    }
  }
}
```

Use `command` + `args` if `lightbulb-mcp` is not on `PATH`:

```json
"command": "python",
"args": ["-m", "lightbulb.mcp_server"]
```

## Authentication

The server resolves credentials in an order similar to the CLI:

1. **`LIGHTBULB_JWT`** + **`LIGHTBULB_TENANT_ID`** (optional `LIGHTBULB_COMPANY_ID`) — e.g. token from a browser session.
2. **`LIGHTBULB_API_KEY`** + **`LIGHTBULB_TENANT_ID`** + **`LIGHTBULB_USER_ID`** — localhost / integration bootstrap.
3. **Cached device-flow token** under `~/.lightbulb/tokens/` (shared with `lightbulb` CLI).
4. **`LIGHTBULB_EMAIL`** + **`LIGHTBULB_PASSWORD`** — password login at startup (users with MFA must use device flow or JWT).

| Variable | Purpose |
|----------|---------|
| `LIGHTBULB_URL` | Platform URL (default `https://agents.lightbulbpartners.com`) |
| `LIGHTBULB_JWT` | Bearer JWT |
| `LIGHTBULB_TENANT_ID` | Tenant UUID (required with JWT) |
| `LIGHTBULB_COMPANY_ID` | Optional company scope |
| `LIGHTBULB_EMAIL` / `LIGHTBULB_PASSWORD` | Startup login (avoid for MFA-only accounts) |
| `LIGHTBULB_API_KEY` / `LIGHTBULB_USER_ID` | Local integration |
| `LIGHTBULB_MCP_PROFILE` | Optional profile. `backbone` exposes a compact control-plane surface for Codex/OpenAI hosts. |
| `LIGHTBULB_MCP_NAMESPACES` | Optional CSV of generated-tool namespaces to register (e.g. `finance,crm,gmail`). Hand-written tools always register. Unset = full 1005-tool surface. |

**HTTPS:** For non-loopback hostnames the SDK enforces HTTPS on the HTTP client unless the URL is explicitly local (`localhost`, `127.0.0.1`, etc.—parsed by hostname, not substring).

## Behaviour & scope

- **RBAC:** Tools map to platform endpoints the user is allowed to call; denied actions surface as errors (typically permission / validation), not silent success.
- **Company context:** Instructions remind admin users to select company when required (same as product behaviour).
- **Rate limits:** Platform rate limits apply per user/session like normal API usage.
- **Retries:** The MCP layer may retry on behalf of the host where documented in code (e.g. auth refresh paths); tools themselves do not bypass server-side throttling.

## Tool surface

The server registers a large set of tools (on the order of **150+**): domain `dispatch_domain_agent`, documents, page/document builders, code workspaces, voice/HITL, AOC, HR live, RAG, connectors (`invoke_tool`), CRM tasks, memory graph, approvals, notifications, domain workspace helpers, Xero/Stripe-oriented flows where exposed, etc.

Domain names and actions should follow `agent-workers/agents/domain_registry.py` on the platform; the MCP system prompt summarizes common domains.

Set `LIGHTBULB_MCP_PROFILE=backbone` for Codex plugins and OpenAI-facing
hosts that should start with the Lightbulb backbone as the main orchestration
surface. This keeps `whoami`, company selection, `backbone_execute`,
`start_consulting_project_workflow`, approvals, connector status, workspace
context, and software-delivery loop tools while omitting the generated long-tail
domain/connector tool list.

For Codex, `lightbulb setup --target codex` installs both surfaces:

- the `lightbulb` MCP server block in `~/.codex/config.toml`
- a local plugin copy under `~/.codex/plugins/lightbulb-partners/`
- a personal marketplace entry in `~/.agents/plugins/marketplace.json`

After setup, restart Codex, open Plugins, choose `Lightbulb Partners Local`, and
install or enable `Lightbulb Partners`. The bundled skill keeps project,
custom-agent, SOP, modernization, repo, and code-delivery requests on the
`start_consulting_project_workflow` front door until the Product Machine
approval gates produce execution-ready work packets.

### Consulting project workflow

Use the backbone profile as the default entrypoint when a user asks to create a
project, build a custom agent, automate an operating workflow, modernize an
existing process, or turn a rough idea into code. The host should call
`start_consulting_project_workflow` to start or continue the
`consulting_project_workflow`, not immediately dispatch coding or connector
mutations. If the host has not refreshed the latest tool surface yet, call
`backbone_execute` with `workflow_type=consulting_project_workflow`.

The consulting workflow is approval-gated. It starts with intake and project
classification, then captures facts, requirements, process maps, SOP impact,
referenced SOPs, scope, QA/change plans, and execution-ready work packets. Code Workspace and GitHub
repository setup happen from the Project Product Machine only after the required
requirements, scope, and work-packet approvals exist. The executor context should
preserve `workflow_type=consulting_project_workflow`, `dispatch_contract`,
`code_delivery`, approved requirements, approved SOPs when changed or
referenced/process maps, and selected work packets.

The MCP software-delivery tools follow that same rule. `software_delivery_loop`
and `software_spot_weld_fix` are intended for existing or approved engineering
loops; when they receive rough project, custom-agent, SOP, modernization, or
repo-creation intent without Product Machine delivery readiness, they route into
`start_consulting_project_workflow` first. Pass an explicit approved readiness
context only when the host is deliberately continuing an already approved
delivery loop; user-supplied readiness flags or force flags alone do not bypass
the consulting workflow for project/SOP/repo-build intent. The approved context
must include the server-provided `project_product_machine_execution_context`
with approved requirements, scope, selected work packets, acceptance criteria,
and SOP approval evidence when a selected packet references an SOP.

The compact backbone profile exposes `dispatch_domain_agent`, so that tool has
the same front-door guard for coding, IT/Ops, engineering, and product actions.
Normal analysis and already approved delivery work still dispatches to the
requested domain; rough build/repo/SOP/custom-agent intent starts the consulting
workflow first.
The generic `invoke_tool` surface also protects repo, workflow, and deployment
writes such as `github.create_repository`, `github.create_pull_request`,
`github.trigger_workflow`, and `github.create_deployment_status` with the same
Product Machine boundary.
Full-profile generated MCP tools inherit the same guard, including generated
`coding_*` domain actions and generated `github_*` repo/PR/deployment tools.
Page Builder remains available for pure design sessions with
`force_page_builder=true`; project-like page, portal, app, SOP, workflow, or
GitHub-backed site requests start in the consulting workflow first.
Direct `code_workspace_chat` calls also route explicit custom-agent, SOP, or
project-build prompts into the consulting workflow first; normal bounded
workspace fixes continue to the selected code workspace.

### ChatGPT app / connector endpoint

For ChatGPT Apps/Connectors, use the hosted streamable HTTP MCP endpoint:

```text
https://agents.lightbulbpartners.com/mcp/lightbulb
```

`GET /mcp/lightbulb` returns health and protected-resource metadata hints.
Unauthenticated MCP calls receive an OAuth challenge pointing at
`/.well-known/oauth-protected-resource`, and the authorization flow bounces
users through the Lightbulb login/onboarding path before issuing a bearer token
for the MCP resource.

The ChatGPT-facing tool surface is a curated orchestration surface over the
same account-scoped Lightbulb control plane. It includes identity and company
selection helpers; `lightbulb_status` for current work, blockers, approvals,
projects, workflows, and next actions; `lightbulb_capabilities` and
`list_agents` for tool and agent discovery; project tools; workflow tools;
approval tools; and AutoCompany loop/run tools. Use `lightbulb_status` first
when the user asks what Lightbulb is working on, what needs attention, or what
to do next.

Use `start_consulting_project` for project/workflow/custom-agent/SOP/build
requests that need guided intake, approval gates, and work packets. Use
`lightbulb_chat` for general backbone analysis after checking status or when no
more specific orchestration tool fits. The `start_consulting_project` tool also
registers the `ui://lightbulb/project-start.html` resource so ChatGPT can render
a small project-start component and call the same approval-gated workflow from
UI.

The hosted endpoint advertises the component through current Apps SDK metadata:
tool descriptors include `_meta["openai/outputTemplate"]`, and the resource
metadata includes `_meta["openai/widgetDescription"]`,
`_meta["openai/widgetPrefersBorder"]`, and `_meta["openai/widgetCSP"]`.
The older `ui.resourceUri` and `ui.csp` fields are kept for compatibility with
existing hosts.

### Local runtime documents

The local runtime installer creates a user-facing document folder at
`<root>/Lightbulb Documents` with `Inbox`, `Exports`, and `Templates`
subfolders. Hidden indexed copies and uploads are managed under
`<root>/.lightbulb/rag/assets/uploads`. See
`docs/local-runtime-documents-and-autocompany.md` in the platform repo for the
full folder and environment-variable contract.

### Software delivery loop tools

Claude Code, Codex, Cursor, and other MCP hosts can use these tools as the
preferred bridge into Lightbulb's software/user-feedback/deployment loop:

- `software_delivery_context` — read the current IT/Ops, coding workspace,
  GitHub/Jira/Slack/Notion, memory, approval, CloudOps, and deployment context
  before editing code.
- `software_delivery_loop` — route a user-feedback or engineering request into
  the governed loop: SDLC context, CodingAgent, repo binding, PR, container
  release, CloudOps, deployment gates, and HITL.
- `software_spot_weld_fix` — request a bounded urgent code/prod/cloud fix. It
  defaults to preview mode, opens a PR, keeps deploy disabled, and marks
  production/cloud work as approval-gated.

The MCP layer does not grant elevated privileges. All three tools run as the
authenticated user and rely on the same tenant/company/RBAC and approval gates
as the web application.

## Troubleshooting

| Symptom | Things to check |
|---------|------------------|
| **401 / AuthenticationError** | JWT expired → run `lightbulb setup` or refresh env JWT; MFA users should prefer device flow / cached token / JWT, not raw password. |
| **403** | Missing RBAC permission for that endpoint; confirm role in admin UI. |
| **HTTPS errors** | Use `https://` for production hosts; for local dev use `http://localhost:...`. |
| **Module not found (`mcp`)** | Reinstall: `pip install --upgrade git+https://github.com/RPasquale/lightbulb-mcp.git`. |
| **Stale config** | `lightbulb` / `lightbulb setup` status shows whether MCP entries exist for each host editor. |

## Security posture (MCP)

- Secrets live in **host env** or OS token cache—never commit `.mcp.json` with passwords or JWTs.
- Token cache files are user-private and written atomically (see SDK README).
- Error paths avoid echoing full HTTP bodies to logs/tracebacks where the SDK controls messaging.

## Version history (MCP-facing)

### 0.4.0

- Same transport and env vars; underlying HTTP client aligns with SDK security fixes (URLs, localhost detection, error sanitization).
- Tool count and names unchanged from 0.3.x series unless platform endpoints moved (regenerate from server package when upgrading).

### 0.3.0

- Major expansion of tool families (voice, HR live, code workspace collaboration/runtimes, AOC, memory graph, CRM tasks, approvals, notifications, domain workspaces, Xero helpers, page/document automation, etc.).
- `lightbulb-mcp` console script added for portable configs.

### 0.2.0

- Broad domain registry alignment and Xero-oriented tooling alongside existing Stripe/workflows surface.
