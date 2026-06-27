# Lightbulb MCP

MCP server and helper CLI for the [Lightbulb Partners Agents](https://agents.lightbulbpartners.com) platform. Connect your **Claude Code, Codex, or Cursor** account to your Lightbulb workspace — domain agents, code workspaces, connectors, document/page builders, voice, AutoCompany (AOC), and more.

For the **MCP host integration** details (authentication, tool surface, troubleshooting), see [MCP.md](MCP.md).

> The Python SDK (`LightbulbClient`, `AsyncLightbulbClient`, etc.) ships in this package as **preview / unstable internals**. The supported product right now is the MCP server and helper CLI — direct Python API consumers should expect changes between minor versions.

## Install

Installs the `lightbulb-mcp` package directly from the public GitHub repo:

```bash
pip install git+https://github.com/RPasquale/lightbulb-mcp.git
```

Console scripts:

- `lightbulb-mcp` — runs the MCP server over stdio for Claude Code / Codex / Cursor (see [MCP.md](MCP.md)).
- `lightbulb` — helper CLI for status, login, and one-shot platform commands.

## Quick start — wire up Claude Code

```bash
pip install git+https://github.com/RPasquale/lightbulb-mcp.git
lightbulb setup
```

`lightbulb setup` is an interactive wizard: device-flow login (browser handles MFA), probe `/api/users/me`, then merge a `lightbulb` MCP server entry into Claude Code (`.mcp.json` / `.claude.json`), Codex (`~/.codex/config.toml`), or Cursor (`~/.cursor/mcp.json`). Existing servers are preserved; backups use `.bak`.

Flags: `--target codex`, `--yes` / `--no-write`, `--skip-login`, `--url`.

### Manual `.mcp.json`

If you'd rather wire Claude Code by hand:

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

The MCP server resolves credentials from a cached device-flow token (`~/.lightbulb/tokens/`) by default, or from env (`LIGHTBULB_JWT` + `LIGHTBULB_TENANT_ID`, etc.). Full auth precedence in [MCP.md](MCP.md).

## CLI

Running **`lightbulb` with no arguments** prints **status**: platform URL, cached token hint, detected Claude/Codex/Cursor configs, and next steps.

```bash
lightbulb                    # status (default)
lightbulb setup              # guided auth + MCP config merge
lightbulb whoami
lightbulb dispatch finance --action chat --message "Quick AR aging summary"
lightbulb search-documents "quarterly revenue" --top-k 5
lightbulb approvals list
```

### Environment variables (CLI & MCP)

| Variable | Purpose |
|----------|---------|
| `LIGHTBULB_URL` | Platform base URL (default `https://agents.lightbulbpartners.com`) |
| `LIGHTBULB_JWT` | Bearer JWT |
| `LIGHTBULB_TENANT_ID` | Required with JWT |
| `LIGHTBULB_COMPANY_ID` | Optional company scope |
| `LIGHTBULB_EMAIL` / `LIGHTBULB_PASSWORD` | Legacy password login |
| `LIGHTBULB_API_KEY` / `LIGHTBULB_USER_ID` | Localhost integration bootstrap |
| `LIGHTBULB_MCP_PROFILE` | Optional MCP profile. Use `backbone` for a compact OpenAI/Codex-facing control-plane surface. |
| `LIGHTBULB_MCP_NAMESPACES` | Optional comma-separated allow-list of generated-tool namespaces (e.g. `finance,crm,gmail`). Hand-written tools always register. Unset = all 1005 tools. |

### Backbone-first profile for OpenAI hosts

For Codex plugins and other OpenAI-facing installs, use the compact backbone
profile:

```json
{
  "mcpServers": {
    "lightbulb": {
      "command": "lightbulb-mcp",
      "env": {
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
        "LIGHTBULB_MCP_PROFILE": "backbone"
      }
    }
  }
}
```

This profile exposes the Lightbulb control plane rather than every generated
domain/connector tool: identity and company selection, the backbone agent,
approvals, connector status, workspace context, and the software delivery loop.
The backbone agent can still orchestrate domain agents under the user's normal
tenant, company, RBAC, and approval rules.

When targeting Codex, `lightbulb setup --target codex` also installs the local
Codex plugin surface. It writes:

- `~/.codex/config.toml` with the `lightbulb` MCP server.
- `~/.codex/plugins/lightbulb-partners/` with the bundled plugin manifest,
  MCP config, and Lightbulb skill.
- `~/.agents/plugins/marketplace.json` with a `Lightbulb Partners Local`
  marketplace entry pointing at `./.codex/plugins/lightbulb-partners`.

Restart Codex after setup, open Plugins, choose `Lightbulb Partners Local`, and
install or enable `Lightbulb Partners` if it is not already enabled. The plugin
skill teaches Codex to use `start_consulting_project_workflow` for project,
custom-agent, SOP, modernization, repo, and code-delivery requests before any
domain-agent execution or GitHub writes.

### Project and consulting workflow starts

For Codex, Claude Code, Cursor, and ChatGPT connector-style hosts, route broad
project ideas through the Lightbulb backbone instead of jumping straight to code
or connector writes. Use `start_consulting_project_workflow` to start or
continue the `consulting_project_workflow` when the user wants to build an app,
automate a workflow, create a custom agent, rewrite SOPs, modernize operations,
or turn an idea into implementation work. If a host has not refreshed the latest
tool surface yet, call `backbone_execute` with `workflow_type` set to
`consulting_project_workflow`.

That workflow collects intake facts with provenance, validates requirements and
scope, identifies SOP impact, generates SOPs/process maps when changed or
referenced, then creates approved work packets. Code
Workspace, GitHub repository setup, draft PRs, deployments, customer messages,
and connector mutations remain behind the Product Machine approval gates. When
approved coding packets exist, the Project Product Machine plan should carry
`workflow_type=consulting_project_workflow`, `dispatch_contract`,
`code_delivery`, approved requirements, approved SOPs when changed or
referenced/process maps, and selected work packets into the coding executor
context.

The hand-written MCP software-delivery tools apply the same boundary. If
`software_delivery_loop` or `software_spot_weld_fix` receives a rough project,
custom-agent, SOP, modernization, or repo-creation request without explicit
delivery-readiness context, it starts `consulting_project_workflow` instead of
dispatching directly to IT/Ops. Existing approved delivery loops should pass the
server-provided `project_product_machine_execution_context`; user-supplied
delivery-readiness flags or `force_software_delivery_loop=true` alone do not
bypass the consulting workflow for project/SOP/repo-build intent.

The compact backbone profile also applies that boundary to
`dispatch_domain_agent` for coding, IT/Ops, engineering, and product actions.
Project-build intent goes to the consulting workflow first; ordinary domain
analysis and explicitly approved delivery loops still dispatch normally.
Generic connector invocation follows the same policy for repo, workflow, and
deployment writes such as `github.create_repository`,
`github.create_pull_request`, `github.trigger_workflow`, and
`github.create_deployment_status`.
Full-profile generated tools inherit the same guard, including generated
`coding_*` domain actions and generated `github_*` repo/PR/deployment tools.
Page Builder keeps a pure design-session escape hatch with
`force_page_builder=true`, but project-like page, portal, app, SOP, workflow, or
GitHub-backed site builds start in the consulting workflow first.
Direct `code_workspace_chat` calls follow the same front-door rule for explicit
custom-agent/SOP/project-build prompts, while ordinary bounded bug fixes and
existing workspace tasks continue to the selected workspace.

### ChatGPT app / connector

Use the hosted MCP endpoint when adding Lightbulb Partners as a ChatGPT app or
connector:

```text
https://agents.lightbulbpartners.com/mcp/lightbulb
```

The endpoint advertises OAuth protected-resource metadata and sends users
through the Lightbulb login/onboarding flow when they are not already
authenticated. After auth, ChatGPT can call `start_consulting_project` to create
a Lightbulb Project Agent workspace, seed the Product Machine plan, start the
backbone consulting workflow, and open guided intake with the first question:
`Map the first workflow: trigger, owner, systems, handoffs, pain point, approver, and proof it worked.`

The ChatGPT component is advertised with current Apps SDK metadata:
`_meta["openai/outputTemplate"]` on the tool descriptor and
`_meta["openai/widgetDescription"]`, `_meta["openai/widgetPrefersBorder"]`, and
`_meta["openai/widgetCSP"]` on the `ui://lightbulb/project-start.html` resource.
Legacy `ui.resourceUri` and `ui.csp` metadata remain for host compatibility.

Use `lightbulb_chat` for general account analysis. Project-like requests,
custom-agent builds, SOP/process changes, repo creation, Code Workspace work,
deployments, and connector mutations should route to `start_consulting_project`
so requirements, scope, SOP impact or referenced SOPs, work packets, and HITL
approval gates are established before execution.

### Local runtime documents

The managed local runtime creates `<root>/Lightbulb Documents` with `Inbox`,
`Exports`, and `Templates` for user-visible files, plus hidden service storage
under `<root>/.lightbulb`. See
`docs/local-runtime-documents-and-autocompany.md` in the platform repo for the
folder initialization and AutoCompany/RAG environment contract.

### Trimming the tool surface (0.6.0+)

The MCP server registers ~1005 tools by default. For Claude Code that's ~80k tokens spent on `tools/list` per conversation before the LLM does anything. Most customers only need a handful of integrations, so set `LIGHTBULB_MCP_NAMESPACES` to scope the generated tools:

```json
{
  "mcpServers": {
    "lightbulb": {
      "command": "lightbulb-mcp",
      "env": {
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
        "LIGHTBULB_MCP_NAMESPACES": "finance,crm,gmail,slack,jira,github,notion"
      }
    }
  }
}
```

Valid namespace tags include all 18 domains (`finance`, `intuit`, `crm`, `legal`, `engineering`, `content`, `it_ops`, `commerce`, `product`, `hr`, `coding`, `document_intelligence`, `solver`, `customer_success`, `procurement`, `gtm`, `grc`, `smarthome`) and every connector prefix (`gmail`, `microsoft`, `teams`, `calendar`, `docs`, `drive`, `sheets`, `slides`, `notion`, `slack`, `jira`, `github`, `salesforce`, `hubspot`, `shopify`, `square`, `stripe`, `xero`, `quickbooks`, `clio`, `smokeball`, `monday`, `excel`, `iam`, `ecommerce`, `tasks`, `tickets`, `notifications`). The 156 hand-written tools (whoami, search_documents, dispatch_domain_agent, etc.) always register regardless.

## Python API (preview)

The package also ships a Python client used internally by the MCP server. **Not yet a stable product surface** — expect breaking changes between minor versions. Pin exactly if you depend on it.

```python
from lightbulb import LightbulbClient, device_login

BASE = "https://agents.lightbulbpartners.com"

# Recommended for humans: OAuth2-style device flow (browser handles MFA)
auth, _expires = device_login(BASE, client_id="my-app")

client = LightbulbClient(BASE, auth=auth)
print(client.whoami())

result = client.dispatch("finance", action="chat", message="Summarize cash this week")
print(result.reply)
```

### Email / password and 2FA

```python
from lightbulb import login, complete_2fa_login, TwoFactorRequired

try:
    auth = login(BASE, "you@company.com", "secret")
except TwoFactorRequired as exc:
    code = input("Authenticator code: ").strip()
    auth = complete_2fa_login(exc.base_url, exc.email, code)

client = LightbulbClient(BASE, auth=auth)
```

For MFA accounts, **device login** is usually simpler.

### Async

```python
from lightbulb import AsyncLightbulbClient, JwtAuth

async def main():
    auth = JwtAuth(token="...", tenant_id="...", company_id=None)
    async with AsyncLightbulbClient(BASE, auth=auth) as client:
        me = await client.whoami()
```

Coverage in `AsyncLightbulbClient` is curated for hot paths; use `LightbulbClient` for full surface area.

### Refreshing expired JWTs

Pass `auth_refresh` and call `refresh_auth()` after an `AuthenticationError`, then retry:

```python
from lightbulb import LightbulbClient, AuthenticationError
from lightbulb.auth import device_login

def refresh():
    auth, _ = device_login(BASE, client_id="my-worker")
    return auth

client = LightbulbClient(BASE, auth=initial_auth, auth_refresh=refresh)

try:
    client.dispatch("crm", action="chat", message="hello")
except AuthenticationError:
    if client.refresh_auth():
        client.dispatch("crm", action="chat", message="hello")
```

Same pattern on `AsyncLightbulbClient` with `await client.refresh_auth()`.

## Exceptions (`lightbulb.errors`)

HTTP failures from **`LightbulbClient`** and **`AsyncLightbulbClient`** raise **`LightbulbError`** subclasses (not raw `httpx.HTTPStatusError`):

| Type | Typical status |
|------|----------------|
| `AuthenticationError` | 401 |
| `PermissionDenied` | 403 |
| `NotFoundError` | 404 |
| `ValidationError` | 400 / 422 (also subclasses `ValueError`) |
| `RateLimitedError` | 429 (`retry_after` when present) |
| `ServerError` | 5xx |

Helpers: `from_response`, `wrap_http_error`, `raise_if_error` (used internally; safe to call on any `httpx.Response`).

Messages avoid leaking raw response bodies; structured JSON fields like `message` / `error` are capped.

Deep wrappers (`XeroAgentClient`, connector clients) use the same HTTP stack and raise the same types.

## Typed integrations

- **Stripe:** `StripeOrchestratorClient`, `StripeWorkflow`
- **Xero:** `XeroAgentClient`, `XeroPlaybook`
- **Connectors:** `SlackClient`, `JiraClient`, `BambooHRClient`, `GreenhouseClient`, `MondayClient` (thin `invoke_tool` / HR-live helpers)

## Security posture

- HTTPS enforced for non-local hosts by default (`enforce_https=False` only for dev).
- Path segments and risky inputs validated (`validators` module); SSO / device-flow URLs validated before opening a browser.
- Token cache: atomic write, restrictive permissions, symlink and ownership checks.
- `lightbulb setup`: atomic config writes, safe TOML escaping for Codex, backups chmod-restricted.

Regression tests live in `tests/test_security.py` (audit IDs in docstrings).

## Types (PEP 561)

The wheel ships `py.typed` for Pyright/mypy consumers.

## Version history

### 0.8.0

- **Full typed coverage for the commerce surface.** `lightbulb/tool_descriptors.py` now carries descriptors for every connector op in the commerce domain — Shopify intelligence (`shopify.analytics_query`, `shopify.list_abandoned_checkouts`, `shopify.list_locations`, `shopify.list_collections`, `shopify.list_fulfillment_orders`, `shopify.list_discounts`, `shopify.list_refunds`, `shopify.list_transactions`, `shopify.bulk_operation_*`), metafields (`shopify.get_metafields`, `shopify.update_metafield`, `shopify.list_metafield_definitions`), segment execution (`shopify.tag_customers_bulk`, `shopify.create_price_rule`), the storefront-neutral `ecommerce.*` ops (`search_products`, `search_orders`, `search_customers`, `get_inventory`, `get_product_reviews`, `create_discount`, `update_customer`), and the Square POS ops (`search_catalog`, `search_orders`, `list_payments`, `list_customers`, `get_inventory`). MCP consumers — Claude Code, Codex, Cursor — now see proper Python signatures with documented params instead of the generic `arguments: str = "{}"` JSON blob.
- Codegen log: `24 typed via descriptor` for domain actions, `53 typed via descriptor` for connector ops (up from 32). Total descriptor surface: 84 (24 domain + 60 connector).
- This release pairs with a platform-side rework that exposes each connector op as a top-level OpenAI function tool (encoded `connector__action`) inside the commerce domain agent, ending the silent `Unknown tool` failures from earlier versions where the prompt advertised dotted op names that the function-call schema couldn't accept.

### 0.7.0

- **Typed signatures + curated descriptions for the highest-value tools.** A new `lightbulb/tool_descriptors.py` carries hand-curated metadata (multi-line description + per-field types) for 56 priority tools across finance, CRM, legal, HR, coding, plus the most-used connector ops (Xero, QuickBooks, Stripe, Square, Slack, GitHub, Gmail, Microsoft 365, Notion, Jira, Clio, Shopify). When a descriptor exists, codegen emits a typed Python signature like `def finance_lbo_model(message: str = "", target_company: Optional[str] = None, entry_multiple: Optional[float] = None, …)` and a rich docstring; FastMCP picks these up so Claude Code / Codex see proper input schemas instead of an opaque `inputs: str` JSON-string parameter.
- Tools without a descriptor still generate fine via the original `message + inputs JSON` shape — descriptor coverage expands incrementally over future patches without breaking existing flows.
- Codegen log: `24 typed via descriptor` for domain actions, `32 typed via descriptor` for connector ops. Total surface unchanged at 849 generated + 156 hand-written = 1005 tools.

### 0.6.2

- **`lightbulb connect <provider>`** — best-effort CLI to hook up a personal Slack / HubSpot / Notion / Gmail / GitHub / etc. account to the user's tenant. Validates the provider against `list_connectors()`, opens the platform's OAuth flow in a browser. `lightbulb connect --check <provider>` verifies the connection landed (post-auth confirmation step until the platform supports `?return_to=cli`).
- **`lightbulb tools`** — list the MCP tool surface this install actually exposes (with namespace-filter awareness). `--filter SUBSTR` to narrow, `--count-only` for scripting. Useful for diagnosing which connector ops are reachable when the platform hasn't finished provisioning the full connector tool catalog yet.

### 0.6.1

- **Bug fix: device-flow login surfacing localhost verification URLs.** When a platform deployment's base URL is misconfigured, the device-flow verification link could come back pointing at `localhost`, producing a confusing "Refusing to open verification URL … does not match platform host" error. The SDK now detects that case and surfaces an actionable hint ("ask your Lightbulb admin to set `APP_BASE_URL`") so users know who to contact instead of seeing a bare host-mismatch error.
- Regression test: `tests/test_security.py::TestRedirectUrlValidator::test_localhost_mismatch_surfaces_actionable_hint`.

### 0.6.0

- **Namespace filtering** for the generated tool surface. Set `LIGHTBULB_MCP_NAMESPACES=finance,crm,gmail` (or any comma-separated subset) to register only the matching generated tools — typically cuts the cold-start `tools/list` payload from ~1005 tools / ~80k tokens to ~200 tools / ~15k tokens. Hand-written tools (whoami, dispatch_domain_agent, etc.) always register. See README "Trimming the tool surface".
- Codegen at `scripts/generate_mcp_tools.py` now tags each generated tool with its explicit namespace (e.g. `it_ops`, `document_intelligence`) so multi-word namespaces filter correctly without underscore-split ambiguity.
- Regression tests for the filter behaviour: `tests/test_mcp_server.py::test_namespace_filter_*`.

### 0.5.1

- **Critical: fix `invoke_tool` wire shape.** Earlier versions sent the wrong request body to `/api/tools/invoke`, so the 565 generated connector-op tools in 0.5.0 all failed silently. The client now sends the `toolName` + `inputs` (plus tenant/company scope) shape the platform expects. Sync + async clients fixed; regression tests added in `tests/test_client.py::TestInvokeTool` and `tests/test_async_client.py::TestAsyncInvokeTool`.
- **Security**: collapse inline `is_local` checks in `client.py`/`async_client.py` onto canonical `validators.is_local_url` (now covers IPv6 `::1`); add UUID validation in `select_company` MCP tool; assert `JwtAuth` in `save_cached_token`; clarify `backbone_execute` runs server-side.
- Depends on a platform-side rollout that registers the connector tool catalog; once that rollout is live, the 565 generated connector tools become reachable end-to-end.

### 0.5.0

- **Massive tool surface expansion (~1000 tools, up from 156).** Every domain agent action and every registered platform connector op now has a direct MCP tool — Claude Code / Codex / Cursor see them in the picker without indirection.
- 284 domain action tools auto-generated from `agent-workers/agents/domain_registry.py`: finance, intuit, crm, legal, engineering, content, it_ops, commerce, product, hr, coding, document_intelligence, solver, customer_success, procurement, gtm, grc, smarthome.
- 565 connector op tools auto-generated from the platform's tool registry: deep coverage of Xero (127), Clio (63), GitHub (58), Slack (57), Commerce (51), QuickBooks (44), Smokeball (39), Monday (31), Jira (27), Notion (21), Shopify (18), Stripe, Square, Salesforce, Microsoft, Gmail, and more.
- Codegen lives at `scripts/generate_mcp_tools.py`. Re-run after platform changes.
- Hand-written 156 tools kept as-is; no API changes there.

### 0.4.0

- Renamed package to `lightbulb-mcp`; MCP deps (`mcp`, `pydantic`, `pydantic-settings`) are now hard dependencies. Python API ships as preview/unstable internals.
- Defaults updated to production: `LIGHTBULB_URL` defaults to `https://agents.lightbulbpartners.com`. CLI / MCP server / setup wizard all use the plural production hostname.
- Security hardening: redirect URL validation, token/config atomic writes, TOML injection fixes, SSE size limits, localhost detection via hostname parsing, preview proxy header merging.
- `errors` module and **`raise_if_error`**: platform HTTP errors map to `LightbulbError` subclasses from the sync/async clients and Xero wrapper.
- `refresh_auth` / optional `auth_refresh` callback; setup wizard retries once on stale cached token.
- `py.typed` + README/MCP docs consolidation.

### 0.3.0

- 2FA (`TwoFactorRequired`, `complete_2fa_login`), SSO URL helper, SSE streaming for code/page/document builders, code workspace tools & preview, marketing connector setup methods, typed connector clients, `AsyncLightbulbClient`, `lightbulb` CLI, guided `lightbulb setup` / `lightbulb status`, `lightbulb-mcp` entry point.

### 0.2.0

- Large MCP tool expansion, domain registry alignment, `XeroAgentClient`, expanded platform surface in MCP.
