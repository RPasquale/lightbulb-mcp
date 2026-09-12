# Lightbulb SDK and MCP

Python SDK, MCP server, CLI, and governed company worker for the [Lightbulb Partners](https://www.lightbulbpartners.com) platform. Build typed business process primitives and custom project workflows, or connect **Claude Code, Codex, or Cursor** to Lightbulb domain agents, workspaces, connectors, builders, approvals, and AutoCompany.

> **Product boundary:** this release line is suitable for controlled internal
> pilots. It is not yet a generally available external developer platform, and
> a locally verified capability is not a production-certified provider outcome.
> Spring remains the sole authority for tenant scope, RBAC, approvals,
> credentials, and live writes. See [stability and support policy](https://www.lightbulbpartners.com/developers#stability) for the support
> and deprecation policy.

For the **MCP host integration** details (authentication, tool surface, troubleshooting), see [MCP integration guide](https://www.lightbulbpartners.com/developers#mcp).
For partner-facing setup, governance, and hosted MCP guidance, see the Lightbulb Partners Docs:
https://www.lightbulbpartners.com/developers

> Starting in 0.14, Connector Execution, executable primitives, durable custom-project runtime contracts, runtime telemetry, and connector conformance are supported SDK surfaces. The broad endpoint client remains beta. `AsyncLightbulbClient` provides complete behavioral parity, with hot paths async-native and long-tail methods thread-forwarded. Pin a minor version for production projects.

## Start here

- [Install and verify your package](#install), then [connect an MCP host](#quick-start--connect-an-mcp-host).
- [Use the curated Python namespaces](#curated-sdk-namespaces) and [typed custom projects](https://www.lightbulbpartners.com/developers#custom-projects).
- [Run a governed company worker](#company-worker-023-source-line) when the corresponding package release and host services are available.
- Browse the [developer reference](https://www.lightbulbpartners.com/developers) for the capability catalog, operational guides, release provenance, and [support](https://www.lightbulbpartners.com/developers#support).

The developer reference separates the published PyPI package, public source,
and reviewed source candidate. A release-note entry below can describe changes
that have not been published yet. Check the [PyPI release history](https://pypi.org/project/lightbulb-mcp/#history)
for the versions available to install. Installing a package does not provision
or start a Lightbulb host.

| Build or operate | Guide |
|---|---|
| Typed, governed business actions | [Primitives](https://www.lightbulbpartners.com/developers#primitives) and [Golden Loops](https://www.lightbulbpartners.com/developers#golden-loops) |
| Declare a company and persist its work | [Company Blueprints](https://www.lightbulbpartners.com/developers#company-blueprints) and [Projects](https://www.lightbulbpartners.com/developers#custom-projects) |
| Run scheduled observations and cadence | [Company worker](https://www.lightbulbpartners.com/developers#company-worker) and [complete pagination](https://www.lightbulbpartners.com/developers#pagination) |
| Establish growth and cost evidence | [Trusted ingestion](https://www.lightbulbpartners.com/developers#trusted-ingestion) and [growth economics](https://www.lightbulbpartners.com/developers#growth-economics) |
| Turn churn signals into retention work and suppress existing prospects | [Retention signal execution (source candidate)](docs/retention-signal-execution.md) |
| Reuse sales playbooks, follow up, and intake expansion or win-back opportunities | [Company sales automation (source candidate)](docs/company-sales-automation.md) |
| Detect overdue invoices and track later observed payments | [Billing retention loop (source candidate)](docs/billing-retention-loop.md) |
| Govern pacing, reallocation, and provider work | [Pacing and reallocation](https://www.lightbulbpartners.com/developers#pacing-reallocation), [BYOK](https://www.lightbulbpartners.com/developers#byok), and [code execution](https://www.lightbulbpartners.com/developers#code-execution) |

## Work without the local runtime

Choose your starting path:

| Journey | Start here | Requires an enabled host? |
|---|---|---|
| Connect an assistant | `lightbulb setup` and the MCP guide | Yes, for login and hosted operations |
| Build a typed workflow | Curated namespaces and custom-project previews | No, for local validation and preview |
| Configure company operations | Worker source template and offline preflight | No, until connected validation or execution |
| Deploy and certify | Operational readiness and execution runbooks | Yes, or a representative validation stack |

The following commands require a package containing the 0.24 additions. They do
not read credentials, register work, or call providers:

```bash
lightbulb-company-worker --source-template
lightbulb-company-worker --bundle company-bundle.json --sources company-sources.json --preflight
```

A successful preflight means the configuration passed offline checks. Host
permissions, account custody, engine-record existence and provider certification
remain explicitly unchecked. Never interpret that report as deployment approval.

On an enabled host, add `--status` to the normal worker configuration to read
operational evidence without claiming work. Add `--report-html status.html` for
a portable report. Reports can contain private company references; retain them
under the same access policy as other company artifacts.

## One governed developer journey

Use the SDK through one five-step path:

1. Declare a typed primitive or Company Blueprint and select its exact version.
2. Validate it and preview it locally with external effects disabled.
3. Publish the immutable definition digest; publication does not grant effect authority.
4. Start or resume the exact hosted run, where Spring resolves scope, permission, approval, idempotency, and any Connector Tool Binding.
5. Observe sanitized events, evidence references, and the terminal outcome; treat missing or ambiguous provider observation as unresolved, never as success.

The compact seven-operation Golden Loop protocol is the primary model-facing
interface. Raw domain and connector operations are an advanced surface and do
not bypass the same Spring authority.

## Curated SDK namespaces

New code should use the small lazy namespaces instead of adding package-root
imports:

```python
from lightbulb.core import JwtAuth, PermissionDenied
from lightbulb.hosted import AsyncLightbulbClient, LightbulbClient
from lightbulb.runtime import BusinessProcessPrimitive, ExecutablePrimitiveRuntime
from lightbulb.domains.finance import (
    PrepareJournalEntryInput,
    ReconcileJournalPostResult,
)
```

`lightbulb.core` and `lightbulb.runtime` are Supported. `lightbulb.hosted` and
`lightbulb.domains.finance` are Beta; pin the SDK minor version. Importing a
namespace is lazy and does not import its owning implementation modules. The
finance namespace is the bounded journal-to-close lighthouse contract, not
live-write authority: provider-backed operations remain quarantined until the
exact capability version has current Spring-owned certification evidence.

## Install

Install the latest **published** package from PyPI, then inspect its version:

```bash
python -m pip install --upgrade lightbulb-mcp
lightbulb version
python -m pip index versions lightbulb-mcp
```

For reproducible projects, pin the exact version reported by `lightbulb version`
in your dependency lock. Beta API consumers should remain within that minor
version until they have reviewed the migration notes. The package targets
Python 3.10 and later; clean installation and upgrade acceptance currently
covers Python 3.10–3.13.

The public repository is the source mirror. Prefer PyPI for installation.
For source installs, select an immutable release tag or commit. The live
developer documentation distinguishes the published version from a reviewed
candidate; development source does not establish publication.

| Command | Purpose |
|---|---|
| `lightbulb` | Installed-version checks, authentication, setup, and platform commands |
| `lightbulb-mcp` | MCP server over stdio for Claude Code, Codex, Cursor, and other MCP hosts |
| `lightbulb-company-worker` | Durable observation and cadence worker; introduced in the 0.23 source line |

## Quick start — connect an MCP host

```bash
python -m pip install --upgrade lightbulb-mcp
lightbulb setup
lightbulb version
```

`lightbulb setup` is an interactive wizard: device-flow login (browser handles MFA), probe `/api/users/me`, then merge a `lightbulb` MCP server entry into Claude Code (`.mcp.json` / `.claude.json`), Codex (`~/.codex/config.toml`), or Cursor (`~/.cursor/mcp.json`). For Claude Code it also installs Lightbulb Continuum lifecycle hooks in `~/.claude/settings.json` (user target) or `.claude/settings.json` (project target). Existing servers, Claude settings, and unrelated hooks are preserved; backups use `.bak`.

Choose `--target claude-code-user`, `--target claude-code-project`,
`--target codex`, `--target cursor`, or `--target generic`. Setup also accepts
`--yes` / `--no-write`, `--skip-login`, and `--url`. Use `lightbulb setup --help`
to inspect the installed version's supported options.

### Manual `.mcp.json`

If you'd rather wire Claude Code by hand:

```json
{
  "mcpServers": {
    "lightbulb": {
      "command": "lightbulb-mcp",
      "env": {
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
        "LIGHTBULB_MCP_PROFILE": "adaptive"
      }
    }
  }
}
```

The MCP server resolves credentials from a cached device-flow token (`~/.lightbulb/tokens/`) by default, or from env (`LIGHTBULB_JWT` + `LIGHTBULB_TENANT_ID`, etc.). Full auth precedence in [MCP integration guide](https://www.lightbulbpartners.com/developers#mcp).

### Lightbulb Continuum for Claude Code

The installed Claude hooks open or resume a private Context Space at session
start, load a bounded relevant context pack with each user prompt, and
checkpoint prompt, assistant, and compaction-boundary events. This gives
Claude Code durable searchable working history; it does not change Claude's
native context-window limit. Run `/hooks` in Claude Code to inspect the active
hooks.

Each Context Space has a default 10,000,000-token indexed-storage ceiling. The
host still receives only a small prompt-aware pack (up to its requested bounded
budget); it can search and read deeper evidence by opaque reference. In other
words, Continuum virtualizes a much larger working set behind the model rather
than pretending the provider accepted a 10-million-token prompt. Repository
continuity fingerprints let Codex and Claude Code resume the same private space
without uploading a raw repository path or remote URL; an explicit
`LIGHTBULB_CONTEXT_REF` can link other sessions.
At the storage ceiling, automatic capture changes to read-only mode while pack,
search, and read continue; a rejected append never disables recall of the full
existing corpus.

For user custody and lifecycle control, the SDK exposes `context_export(...)`,
`context_archive(...)`, and `context_delete(...)`. Export is cursor/item/byte
bounded; deletion is exact-scope and enters the server's grace-period purge
workflow. These destructive lifecycle controls are intentionally not delegated
to the model-facing MCP tool catalog.

Set `LIGHTBULB_CONTEXT_CAPTURE=0` to disable all automatic capture, or
explicitly set `LIGHTBULB_CONTEXT_CAPTURE_TOOLS=1` to opt into storing redacted
tool inputs and outputs. Tool capture is off by default because tool results can
contain credentials or company-scoped data. Re-running `lightbulb setup`
updates only Lightbulb's own handlers and leaves other Claude hooks intact.

To share one project-scoped Continuum across supported coding harnesses, run
`lightbulb setup --context-company-ref <company:...> --context-project-ref
<project:...>` for each host. Both selectors are rename-stable public refs and
are reauthorized against the signed-in account on every hook invocation.
When hooks are disabled or unavailable, the local stdio `context_*` MCP tools
accept the same optional `company_ref` + `project_ref` pair and resolve it
through authenticated discovery; they never accept tenant/user/internal-ID
scope from the model.

### Cross-harness Dynamic Workflows

Protocol 1.4 gives Claude, Claude Code, Codex, ChatGPT, and the Lightbulb
harness one durable planner → builder → fresh-evaluator loop. The sync and
async clients expose exactly eight operations:
`dynamic_workflow_start`, `dynamic_workflow_attach`,
`dynamic_workflow_status`, `dynamic_workflow_next_assignment`,
`dynamic_workflow_submit_plan`, `dynamic_workflow_submit_builder_result`,
`dynamic_workflow_submit_evaluator_verdict`, and
`dynamic_workflow_cancel`. The stdio and hosted HTTP MCP surfaces delegate
those operations to the same Spring authority; neither keeps a competing local
hosted checkpoint.

Every mutation is exact-project scoped, revision-checked, idempotent, and
receipt-bound. Evaluator acceptance defaults to failure and requires a binding
distinct from the builder. MCP session separation is reported honestly as
transport assurance; only a Lightbulb-controlled executable runtime can issue
the stronger fresh-model-context attestation.

## CLI

Running **`lightbulb` with no arguments** prints **status**: platform URL, cached token hint, detected Claude/Codex/Cursor configs, and next steps.

```bash
lightbulb                    # status (default)
lightbulb setup              # guided auth + MCP config merge
lightbulb version            # installed package version
lightbulb whoami
lightbulb dispatch finance --action chat --message "Quick AR aging summary"
lightbulb search-documents "quarterly revenue" --top-k 5
lightbulb approvals list
```

### Company worker

The company worker, introduced in 0.23.0, runs on a trusted host with
authenticated access to the company's Spring services. Inspect the installed
command before configuring a deployment:

```bash
lightbulb-company-worker --help
```

Prepare a validated company bundle, exact connector-source bindings, and a
host-only receipt-signing key file. The bundle names the project; Spring
reauthorizes the selected company, project and user. Recurring source intake
requires a whole UTC-day boundary. Keep receipt keys in the host's secret
custody and out of MCP configuration, repositories, prompts, and logs.

The following is a deployment command template; its files and company ID must
be supplied by your configured host:

```bash
lightbulb-company-worker \
  --bundle company-bundle.json \
  --sources observation-sources.json \
  --company-id YOUR_AUTHORIZED_COMPANY_ID \
  --worker-ref company-ops-1 \
  --receipt-key-file /run/secrets/company-receipts \
  --register --once
```

`--register` creates missing cadence state and its schedule; `--once` attempts
one due cycle and exits. Omit `--once` under a process supervisor to continue
checking due work. Restart with the same bundle, worker reference and signing
key to resume the persisted schedule and authenticated journals. The polling
loop does not grant approvals: connector reads and writes still pass through
Spring, and an ambiguous provider write requires reconciliation.

Optional `--growth-config` enables the configured growth host.
Optional `--sales-config` adds reusable business playbooks, existing-thread sales
follow-up, expansion and win-back intake, and invoice-reminder coordination.
See [company sales automation](docs/company-sales-automation.md) for its exact
configuration and connected Communication prerequisites. Sales approvals are
polled independently of a retrying daily observation window.
`--reallocation-ref` selects an existing reallocation journal instead; these
options are mutually exclusive. The default cadence interval is 86,400 seconds
and `--interval-seconds` accepts 60–604,800 seconds. Daily intake, demand pacing,
reallocation, content observations, channel spend, attribution and growth
aggregation retain their own evidence and freshness requirements. Complete
engine inventory is scoped and bounded; missing coverage is refused.

See the [company-worker and operations guide](https://www.lightbulbpartners.com/developers#company-worker)
for configuration shapes, durable recovery and deployment prerequisites.
Local package checks work without a host; authenticated operations require the
configured host and approved provider connections to be available.

### Environment variables (CLI & MCP)

| Variable | Purpose |
|----------|---------|
| `LIGHTBULB_URL` | Platform base URL (default `https://agents.lightbulbpartners.com`) |
| `LIGHTBULB_JWT` | Bearer JWT |
| `LIGHTBULB_TENANT_ID` | Required with JWT |
| `LIGHTBULB_COMPANY_ID` | Optional company scope |
| `LIGHTBULB_EMAIL` / `LIGHTBULB_PASSWORD` | Legacy password login |
| `LIGHTBULB_API_KEY` / `LIGHTBULB_USER_ID` | Localhost integration bootstrap |
| `LIGHTBULB_MCP_PROFILE` | Optional MCP profile. `adaptive` is the four-tool, on-demand default; `sovereign` adds the preview-locked Local capability catalog. Read and action invokers are separate so MCP hosts can enforce risk policy before a call. |
| `LIGHTBULB_LOCAL_RUNTIME_SECURITY_PROFILE` | Set to `sovereign` by Local setup. Activates fail-closed endpoint, proxy, tool-surface, and authentication boundaries. |
| `LIGHTBULB_HOOK_AUTH_ORIGIN` | Optional exact HTTP(S) origin binding for ambient hook credentials in sovereign mode. When unset, lifecycle hooks ignore ambient JWT/API/password credentials and use the protected token cache for the configured customer URL. |
| `LIGHTBULB_CONTEXT_CAPTURE` | Set to `0` to disable automatic Continuum capture in Codex and Claude Code hooks. |
| `LIGHTBULB_CONTEXT_CAPTURE_TOOLS` | Set to `1` to opt into redacted tool-event capture. Default `0`; prompt/response continuity remains active. |
| `LIGHTBULB_CONTEXT_COMPANY_REF` + `LIGHTBULB_CONTEXT_PROJECT_REF` | Optional public refs that pin automatic Continuum hooks to one authenticated hosted project. Configure both; setup resolves them through the signed-in account and never accepts a model-supplied scope. |
| `LIGHTBULB_CONTEXT_COMPANY_ID` | Legacy trusted local-only company scope for a personal Context Space when no project refs are configured. Prefer the public-ref pair above for project continuity. |
| `LIGHTBULB_ENABLE_PRIVATE_RUNTIME_ACTION_MCP` | Trusted local-developer opt-in for the three UUID-backed runtime-action MCP tools. Default `false`; never use on a hosted/OpenAI-facing surface. |
| `LIGHTBULB_ENABLE_PRIVATE_PROJECT_LEARNING_MCP` | Trusted non-public operator opt-in for the three Project learning preparation/admission mutation tools. Default `false`; the compact `backbone` profile always excludes them. |
| `LIGHTBULB_MCP_NAMESPACES` | Optional comma-separated allow-list of generated-tool namespaces (e.g. `finance,crm,gmail`). Hand-written control-plane tools always register. Unset = full non-private generated surface. Use `lightbulb tools --count-only` for the installed profile and the [developer reference](https://www.lightbulbpartners.com/developers) for the source-bound capability inventory. |
| `LIGHTBULB_RUNTIME_OUTCOMES_FILE` | Optional JSONL queue shared by SDK execution and `improve-workflows`; when unset, each client uses bounded in-memory telemetry. |

### Adaptive discovery for MCP hosts

Use adaptive discovery for an on-demand tool surface:

```json
{
  "mcpServers": {
    "lightbulb": {
      "command": "lightbulb-mcp",
      "env": {
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
        "LIGHTBULB_MCP_PROFILE": "adaptive"
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

### Governed runtime domain actions

The sync and async clients expose an explicit project-scoped lifecycle for
runtime ACTION registration:

```python
from lightbulb import RecursiveAgentPolicy

client.active_company_id = company_id
pending = client.register_runtime_domain_action(
    "finance",
    "review_invoice",
    project_id=project_id,
    idempotency_key="runtime-action:review-invoice:v1",
    component_ids=["finance-dashboard"],
    agent_spec={
        "name": "Invoice reviewer",
        "system_prompt": "Review invoices and return evidence.",
        "allowed_tools": ["xero.list_invoices"],
        "model": "gpt-5-mini",
        "domain": "finance",
    },
    execution_policy={"max_iterations": 3, "max_output_tokens": 512},
)
review = client.get_runtime_domain_action(pending["id"], project_id=project_id)
# After explicit human review, an authorized ADMIN/TENANT SDK client may approve.
approved = client.approve_runtime_domain_action(review["id"], project_id=project_id)
assert approved["status"] == "approved"
assert approved["recursive_spawnable"] is True

# Approval does not activate ordinary domain dispatch. Provision this exact,
# opaque revision only for a finite recursive run.
policy = RecursiveAgentPolicy(
    max_depth=2,
    max_total_nodes=4,
    max_cost_usd=1.00,
    max_delegation_context_bytes=4096,
    max_total_delegation_context_bytes=16384,
    allowed_agent_ids=(approved["recursive_agent_id"],),
)
result = client.recursive_agent_execute(
    "Review the selected project's invoices and state missing evidence.",
    inputs={"project_id": project_id},
    policy=policy,
)
```

Registration requires a selected company, an explicit project UUID, and a
caller-owned idempotency key of 1-128 visible ASCII characters. Scope, status,
owner, workflow selection, version, digest, and idempotency fields are never
accepted in the JSON body. This first contract is immutable v1-only; changing a
registered action requires a future revision lifecycle rather than mutating it.
Authored specs use only `name`, `system_prompt`, `allowed_tools`, `model`, and
`domain`; prompts are capped at 16,000 characters, specs at 32 KiB, and tool
allow-lists at 16 entries. The example uses a seeded active read-only tool;
replace it only with dotted tool names discovered as active in the platform
registry. Execution policy accepts only bounded iteration,
output-token, runtime, and cost values. Register always lands as
`pending_approval`; list/get are review reads, and approve/reject are separate
permissioned SDK transitions. Approval lands in `approved` and remains absent
from ordinary domain dispatch. An approved dynamic-agent workspace response now
includes `recursive_agent_id` plus `recursive_spawnable`; only that opaque
revision may be named in an explicit finite recursive policy. During root
preflight and before any authored child can spawn, the worker performs one
Spring resolution that rechecks the
current actor, exact tenant/company/project access, component RBAC, approval,
revision digest, and execution policy. The run then freezes the spec and the
intersection of its approved tools with the root's provisioned tool catalog.
When a parent delegates, `agent.spawn_child` and `agent.spawn_children` accept an
optional `delegation_context` JSON object. Parents should select only the facts,
constraints, evidence references, decisions, open questions, and success
criteria the child needs. Lightbulb deterministically compacts each packet,
binds it to the inherited scope, returns a digest/compaction receipt without the
packet contents, and atomically charges it against both policy byte ceilings.
Child prompts label the packet as untrusted task data rather than instructions.
Runtime-authored children cannot delegate, cannot poll the mutable control
plane, and fail closed on unresolved scope, model substitution, or integrity
drift. The durable tree enforces finite node/depth/token/cost/deadline limits,
and authored children additionally clamp model, tools, runtime, iteration,
output-token, and cost authority. The pinned Codex app-server has no request
fields for `max_iterations` or `max_output_tokens`, so the worker enforces them
as an online outer guard: it consumes the exact per-call `last` values from
`thread/tokenUsage/updated`, interrupts the turn at the approved boundary, and
closes the per-node app-server process before another ungoverned run can be
reused. Token/cost authority comes from the private atomic tree rollout
allocation; the model-visible node budget is only a consistency check and
cannot increase it. Missing/malformed telemetry or a changed SDK observation
hook fails closed. Because one provider response is already in flight when its
usage becomes observable, that response can overshoot a token or estimated-cost
boundary; the `lightbulb.codex_turn_resource_guard.v1` receipt records the observed usage
and overshoot. Guard cost is an explicitly conservative estimate that charges
all input at the uncached rate and applies a 1.25 safety multiplier. Each node
retains at most 16 raw usage notifications, and
an incomplete result returns `partial` with
`finish_reason=resource_limit`. There is no end-user runtime-action review UI
yet.
The UUID-backed register/list/get MCP tools are excluded by default and always
excluded from the compact, OpenAI-facing Backbone profile. A trusted,
non-public local developer surface must set
`LIGHTBULB_ENABLE_PRIVATE_RUNTIME_ACTION_MCP=true` to expose them. None of these
lifecycle methods directly dispatches or executes the action. SDK responses retain the server's snake-case
scope/version/digest fields; registration also reports `idempotent_replay` and
returns the same resource on an exact replay.

Deployment invariant: V1709 is additive at the schema level, but this feature
is not safe across mixed application versions. Keep
`AGENTS_RUNTIME_REGISTRATION_ENABLED=false` until every pre-V1709 server is
drained, and disable it before any rollback to a pre-V1709 binary.

### Success-aware least-active-memory regulation

The sync and native async clients can preview or execute active-memory
regulation with an empirical success-evidence floor:

```python
preview = client.memory_regulate(
    budget=500,
    dry_run=True,
    empirical_success_floor_ppm=950_000,
    empirical_success_min_samples=40,
    empirical_success_lookback_days=90,
    optimize_for_least_active_memory=True,
)
```

The server counts only exact-owner Memory references from retained successful
skill-execution receipts and selects the smallest budget that clears the floor.
It rejects insufficient, over-limit, or below-floor evidence before a
consequential mutation. The returned quality gate says
`empirical_reference_retention_not_task_success`: compacted digests receive no
credit, and this is not a substitute for a held-out task-success evaluator.
Mutating calls still require a caller-owned `idempotency_key`; the MCP tool is
preview-only. The monorepo architecture note
`docs/memory-success-aware-regulation.md` defines the metric and authority
contract.

For held-out task quality, first request exact virtual candidate bindings:

```python
preview = client.memory_regulate(
    budget=500,
    dry_run=True,
    optimize_for_least_active_memory=True,
    held_out_task_evaluation={
        "task_success_floor_ppm": 850_000,
        "minimum_sample_count": 200,
        "candidate_budgets": [100, 200, 300, 500],
        "authenticated_receipts": [],
    },
)
```

A trusted evaluator runs the same held-out cohort against the baseline and each
returned candidate, then the mutating SDK call supplies its aggregate signed
receipts plus an `idempotency_key`. The server recomputes the current source and
candidate plans, rejects drift or any failed success/safety/cost gate, and
selects the least active eligible candidate. Empirical reference evidence and
held-out task evaluation are mutually exclusive in one request. See
`docs/memory-held-out-regulation.md`; production verification is unavailable
until the purpose-specific evaluator key and exact evaluator identities are
provisioned.

### Governed account-shell customization

The sync and async clients expose the tenant-scoped account-shell lifecycle:
read, draft, preview, explicit publish, immutable history, and rollback. MCP
exposes only read, draft, and preview so an agent can propose a change without
crossing the human publication boundary.

New component placements should use `component_version: 2`. The closed
registry fixes the React implementation and route. A document can set only
emphasis, a narrowing `page_scope` (`any`, `tenant`, or `company`), and the
exact registry capability with `operation: navigate`:

```python
client.create_account_shell_customization_draft({
    "schema": "lightbulb.frontend_customization.v1",
    "surface": "account_shell",
    "name": "Operations",
    "tokens": {"colors": {"primary": "#315efb", "secondary": "#6366f1"}},
    "components": [{
        "component_id": "projects_launcher",
        "component_version": 2,
        "region": "header_actions",
        "props": {
            "emphasis": "primary",
            "visibility": {"page_scope": "company"},
            "action": {
                "capability_id": "service.projects-workspace",
                "operation": "navigate",
            },
        },
    }],
}, base_revision_id=None)
```

Historical version-1 placements remain readable. Rendering still checks the
current viewer's service/RBAC capability; a stored placement never grants
access. Routes, URLs, scripts, event handlers, raw CSS, Tailwind code, and
iframes are rejected rather than interpreted.

### Business primitives and Agent Builder

`search_agent_marketplace` is the normalized discovery front door for both
action listings and domain-worker listings. It keeps business primitives and
domain actions as distinct stable IDs, exposes only whitelisted contract
metadata, and reports undeclared price/evaluation/risk fields as unknown rather
than guessing. Without a domain filter, domain contracts are global discovery
metadata and remain `unverified`. With a domain filter, the SDK performs one
authenticated action lookup for that domain and marks only returned rows
`rbac_visible`—never `executable`. Dispatch still re-checks tenant, selected
company, RBAC, plan entitlement, connectors, and HITL policy.

The same contract is available from sync and async Python clients through
`search_agent_marketplace(...)` and from the compact Backbone MCP profile.
These discovery rows use stable synthetic IDs, not persisted UUIDs. Every row
therefore reports `installable=false`, `lifecycle_installable=false`, and the
stable reason `synthetic_discovery_listing_not_persisted`. Never pass a
synthetic ID to install, pin, or invoke methods.

#### Publishing a governed action

Publication is tenant-scoped and must start with a preview. The preview resolves
an existing server-authoritative action contract and returns the digest for the
exact contract bytes the server would publish. Pass that digest back on publish
as a compare-and-set guard:

```python
publication = {
    "slug": "invoice-drafter",
    "name": "Invoice Drafter",
    "version": "1.0.0",
    "domain": "finance",
    "action": "create_invoice",
    "visibility": "PRIVATE",
    "pricing_model": "INCLUDED",
    "changelog": "Initial governed release",
}

preview = client.preview_marketplace_action_publication(**publication)
if not preview["publishable"]:
    raise RuntimeError(preview["blockers"])

published = client.publish_marketplace_action(
    **publication,
    expected_contract_digest=preview["expected_contract_digest"],
    idempotency_key="publish-invoice-drafter-1.0.0",
)

final = client.wait_for_marketplace_action_publication(
    published["publication_id"],
    timeout_seconds=120,
)

client.archive_marketplace_action(
    published["listing_id"],
    idempotency_key="archive-invoice-drafter",
    reason="Superseded",
)
```

The publication allowlist is `slug`, `name`, `version`, `domain`, `action`,
`visibility`, `pricing_model`, and `changelog`; publish adds only
`expected_contract_digest`. Raw manifests, agent or worker packages, prompts,
models, tool policies, and scope IDs are not accepted. `PRIVATE` is the default.
Shared `UNLISTED` or `PUBLIC` publication requires a portable platform contract,
and `PUBLIC` is publisher-tier gated. Only `INCLUDED` pricing is implemented;
there is no checkout publication path.

Use `get_marketplace_action_publication(publication_id)` for one status read, or
the bounded `wait_for_marketplace_action_publication(...)` helper to poll until
`ready`, `failed`, or `archived`; an initial `scanning` response can accompany
an already-`succeeded` publication operation. Publish and archive are replay-safe
only when each request carries a stable idempotency key. Archive preserves
immutable revisions and audit history and does not uninstall existing company
installations.

All five method names are identical on `LightbulbClient` and
`AsyncLightbulbClient` (await the async calls):
`preview_marketplace_action_publication`, `publish_marketplace_action`,
`get_marketplace_action_publication`,
`wait_for_marketplace_action_publication`, and
`archive_marketplace_action`.

The Backbone MCP names are
`preview_agent_marketplace_action_publication`,
`publish_agent_marketplace_action`,
`get_agent_marketplace_action_publication`, and
`archive_agent_marketplace_action`. MCP has no wait tool; poll with its get tool.

Persisted marketplace actions use a separate, server-authoritative lifecycle:
start with `list_marketplace_listings(...)` (or the MCP tool
`list_agent_marketplace_listings`) and use the returned UUID `listing_id` and
`revision_id`.

```python
listings = client.list_marketplace_listings(kind="action")
listing = listings["items"][0]

installed = client.install_marketplace_action(
    listing["listing_id"],
    listing["revision_id"],
    idempotency_key="install-invoice-drafter-2026-07-10",
    deployment_targets=["codex_backbone", "claude_code_domain:finance"],
)
installation_id = installed["installation"]["installation_id"]

# Installation is deliberately inactive until a separate governed decision.
client.activate_marketplace_action(
    installation_id,
    idempotency_key="activate-invoice-drafter-2026-07-10",
)

preview = client.invoke_marketplace_action(
    installation_id,
    {"invoice_id": "invoice-123"},
    dry_run=True,
    idempotency_key="preview-invoice-123",
)

# Live execution is fail-closed unless it binds the exact successful preview
# and the caller explicitly confirms the reviewed request.
live = client.invoke_marketplace_action(
    installation_id,
    {"invoice_id": "invoice-123"},
    dry_run=False,
    preview_invocation_id=preview["invocation_id"],
    confirm_live=True,
    idempotency_key="invoke-invoice-123",
)
```

The tenant is derived from authentication and the company from the selected
company header; neither is accepted in lifecycle request bodies. Every mutation
and invocation requires an idempotency key. Invocation defaults to dry-run;
live execution requires the successful preview ID for the exact inputs plus an
explicit confirmation. Installs pin one immutable scanned
revision, activation never auto-approves a separate HITL task, and receipts bind
the exact installation, revision digest, request hash, trace/workflow IDs, cost
state, and bounded redacted output. Use the matching async methods on
`AsyncLightbulbClient`.

`deployment_targets` is an optional sequence of governed agent bindings. Its
canonical vocabulary is `codex_backbone`, `claude_code_domain` (all Claude Code
domain agents), and `claude_code_domain:<domain>` (for example,
`claude_code_domain:finance`). The client rejects unsupported values and allows
at most 16 unique targets. Omitting the argument, passing `None`, or passing an
empty sequence installs the action for direct lifecycle invocation only; it is
not projected into an agent's automatic tool catalog. The same argument and
semantics apply to `AsyncLightbulbClient.install_marketplace_action(...)`.

Worker listings remain discovery-only and report `installable=false` until a
signed package, runtime ABI, SBOM, isolation declaration, and attestations exist.

#### Governed training-pair readiness (no launcher)

The SDK exposes the bounded Spring agent-ops gateway for one active company's
exact pinned marketplace **action** revision:

```python
readiness = client.inspect_training_pair_readiness(
    installation_id,
    listing["revision_id"],
    project_id=project_id,  # optional exact-scope constraint
)

# Inspect the server-derived custody association. A verified response contains
# only a bounded receipt summary; it is evidence, not training readiness.
custody = client.inspect_training_pair_input_custody(
    installation_id,
    listing["revision_id"],
    project_id=project_id,
)

# The backward-compatible flat preflight remains available.
preflight = client.preflight_training_pair(
    installation_id,
    listing["revision_id"],
    project_id=project_id,
)

# This is an explicit request, not a successful admission. Production returns
# the structured lightbulb.training_pair_admission.v1 body with HTTP 503.
unavailable = client.request_training_pair_admission(
    installation_id,
    listing["revision_id"],
    project_id=project_id,
    idempotency_key="training-pair-invoice-drafter-1",
)

# Only a previously persisted, exact-owner pair with an immutable marketplace
# source row can be read. Archived retained projects remain readable.
status = client.get_training_pair_status(pair_handle, project_id=project_id)
```

The same method names exist on `AsyncLightbulbClient`. Every call requires a
valid selected company. Request bodies contain only `installation_id`,
`revision_id`, and optional `project_id`; tenant, company, and actor authority
come from authentication and server-side RBAC. Admission additionally requires
a 1-200 character visible-ASCII `Idempotency-Key`. Preflight and status are
read-only. Structured readiness returns exact source validity, ordered authority
stages, blocked `puffer_v4` and `prime_verifiers` lanes, and one next action.
It cannot report admission or execution authority. Status is privacy-minimized
and does not return datasets, artifacts,
receipts, secrets, or storage locations.

Input-custody inspection is also read-only. The server derives the exact owner
and associated receipt; callers cannot provide an owner binding, receipt,
storage handle, tenant, company, or actor. The strict
`lightbulb.training_pair_input_custody.v2` response reports one of five states:
`authority_unavailable`, `not_associated`, `verification_failed`, `expired`, or
`verified`. Only `verified` includes a privacy-minimized receipt summary with
digests, counts, timestamps, cost, the pinned framework commit for both lanes,
and the aggregate signed snapshot binding/dataset identity needed for exact
workflow-learning reconciliation. It never returns raw receipt evidence,
signatures, storage locations, or lane artifact/partition digests, and it
always reports admission and execution as unavailable.

The target-company policy overlay is fail-closed. `COMPANY` has read-only
preflight/status access by default and needs an explicit company-scoped
`agent-ops.training.execute` grant for admission requests. The structured 503
is reached only after authentication, target-company RBAC, idempotency-key,
project-scope, and marketplace-source validation succeed. It is not an auth or
validation fallback.

This is not a training runtime. There is no production admission assembler,
scheduler, launcher, or worker persistence/install lifecycle. The gateway's six
authoritative blockers are `training_profile_unavailable`,
`budget_authority_unavailable`, `snapshot_authority_unavailable`,
`scheduler_unavailable`, `metering_unavailable`, and
`artifact_storage_unavailable`. The SDK preserves only that exact structured
hard-503 admission body; unrelated errors and schema mismatches raise normally.
The newer structured-readiness schema additionally reports
`input_attestation_unavailable` because Spring has no trusted production input
attestation authority wired to the offline dual-lane registry.

The matching MCP tools are `inspect_agent_learning_readiness`,
`inspect_agent_training_input_custody`, `preflight_agent_training_pair`,
`request_agent_training_pair_admission`, and `get_agent_training_pair_status`.
The compact Backbone profile exposes custody inspection instead of the
currently impossible admission request; the full profile retains the guarded
admission tool for compatibility.
The admission tool first returns a v2 request-bound confirmation receipt. After
an explicit user request, return that exact `confirmation_receipt` together with
`confirm_admission_request=true`. The receipt binds installation, revision,
optional project, and the idempotency-key digest, so a bare boolean cannot be
reused for a different future live request. The server still performs zero
writes today.

Lightbulb MCP exposes business primitives as backend Lego blocks over the
existing domain-agent and connector surface:

- `list_business_primitives` discovers primitives such as invoices, supplier
  invoice intake, email, contracts, meetings, lead qualification, and onboarding.
- `run_business_primitive` is the canonical MCP entry to the same versioned
  `ExecutablePrimitiveRuntime` used by the SDK. The Python surface executes
  locally eligible implementations; the hosted surface resolves authenticated
  company/project scope and fails closed until its managed Python runtime bridge
  is available. It never substitutes a Backbone workflow for primitive execution.
- `list_executable_business_primitives` discovers primitive implementation code
  shipped in the Python package, including exact typed input/output schemas.
- `run_sdk_business_primitive` is the explicit compatibility alias for that same
  runtime and remains useful for typed local validation and preview. A
  caller-provided project, approval, or idempotency value cannot turn a preview
  into a live write. Consequential effects must return through Spring's governed
  Connector Execution authority; neither primitive entry point self-authorizes.
- `compile_business_workflow` creates a portable
  `lightbulb.business_workflow_definition.v1` draft from selected primitives.
- `validate_business_workflow` checks primitive order, scope, RBAC, hidden
  setup, approval gates, state transitions, recovery, and test coverage.
- `simulate_business_workflow` dry-runs one synthetic iteration without agents,
  connectors, network calls, or external writes.
- `compose_business_workflow` compiles one SDK source definition and, when
  publishing is requested, sends its exact executable projection (steps,
  triggers, and bounded defaults) through the governed one-shot authoring
  spine. It never turns the definition back into prose for a second compile.
  The SDK hashes that projection and reports server verification/normalization
  separately; richer source metadata stays in the returned client artifact and
  is not claimed as persisted by the current server schema.
- `get_workflow_trigger_catalog` and `author_workflow_trigger` expose the
  principal-scoped schedule/event trigger allow-list and governed trigger
  authoring endpoint. MCP trigger authoring is staging-only and cannot activate
  a trigger; activation belongs to an explicit human-controlled SDK/product
  surface. Direct SDK trigger authoring also defaults to disabled. Unknown
  filters and implicit schedules fail closed.
- Convenience wrappers include `business_create_invoice`,
  `business_write_email`, `business_draft_contract`,
  `business_review_contract`, and `business_schedule_meeting`.

Primitives are more than raw connector calls. Each primitive includes setup
requirements, trigger events, emitted events, follow-up primitives, and builder
guidance, plus a `lightbulb.primitive_runtime_contract.v1` runtime contract.
Workflow composition carries `lightbulb.workflow_compiler_contract.v1` so Agent
Builder can sequence primitives, add hidden setup, and preserve approval,
observability, retry, and recovery behavior. For example, the email primitive
tells Agent Builder to include reply webhooks or polling watchers, thread
context capture, reply classification, and follow-up branches so the user does
not need to know what a webhook is.

The backend ownership model is: Backbone plans and reasons across primitives;
Agent Builder compiles workflow or loop definitions; installed typed SDK
implementations execute provider-free previews; AutoCompany/workflow runtime
runs repeatable loops; Coding Agent is used only for implementation gaps such
as new adapters, new primitives, or approved code-delivery packets. Backbone's
`action=execute` route never treats `preview_only` as advisory: reply
classification, email, invoice, and meeting steps are Pydantic-validated and
run with the in-memory connector preview runtime. Consequential catalog entries
without a typed implementation (currently contract drafting and employee
onboarding) fail closed instead of delegating to an LLM or domain route. An
approved external write must use the separately governed hosted connector
runtime.

The same SDK-first authoring loop is available directly in Python:

```python
from datetime import timedelta

from lightbulb import (
    compile_business_workflow_definition,
    simulate_business_workflow,
    validate_business_workflow_definition,
)

workflow = compile_business_workflow_definition(
    "Email overdue customers and schedule meetings when they reply",
    primitive_ids=["communication.write_email", "calendar.schedule_meeting"],
    trigger_event="invoice.overdue",
    owner_role="finance_manager",
    inputs={
        "attendees": ["customer@example.com"],
        "title": "Invoice follow-up",
    },
    loop=True,
    max_iterations=5,
)
assert validate_business_workflow_definition(workflow)["valid"]

dry_run = simulate_business_workflow(
    workflow,
    approvals={
        "communication.write_email": True,
        "calendar.schedule_meeting": True,
    },
)
assert dry_run["status"] == "completed"
assert dry_run["side_effects"] == "none_simulation_only"

# A false publish flag is a zero-write local draft. Publishing sends this
# validated definition projection through the governed user-plane endpoint (JWT) or
# internal service-plane endpoint (ApiKeyAuth); the server is still the
# validation gate of record and only publishes a valid version.
artifact = client.author_agentic_workflow(
    workflow["objective"],
    definition=workflow,
    publish=True,
)
assert artifact["authoring"]["definitionRecompiled"] is False

trigger = client.author_workflow_trigger(
    artifact["workflowDefinitionId"],
    trigger_type="event",
    event_type="email.received",
    enabled=False,  # stage first; activate only after explicit user confirmation
)
```

The `inputs` argument declares additional runtime input keys only. Its values
are deliberately not copied into the persisted workflow DSL, so customer data
and credentials cannot be multiplied across versioned step configuration.
Supply actual values when starting a workflow instance; connector credentials
must come from Lightbulb's scoped connector vault, never workflow inputs.

`loop=True` emits a persisted `lightbulb.bounded_workflow_loop.v1` contract.
The final action has one exact back edge guarded by
`$.payload.outputs.continue_loop == true` and an unconditional terminal edge.
The compiler limits the graph to `len(steps) * max_iterations <= 100`; Spring
validates the mirrored contract and persists iteration/transition counters so
a crash or resume cannot mint a fresh budget. Local simulation is deterministic
and accepts `loop_iterations=max_iterations + 1` only to demonstrate the
fail-closed exhaustion result. Authored cost and timeout values still stop the
next dispatch; hard cancellation of an already-running provider call remains a
separate watchdog concern.

New catalog entries belong in `lightbulb.business_primitives`. Executable
implementations belong behind `BusinessProcessPrimitive` with Pydantic models
and runtime tests. MCP consumes those SDK modules; it is not a second primitive
implementation registry.

### Executable primitives and custom projects

Version 0.14 adds actual business process implementation code rather than only
primitive metadata and Backbone prompts:

- `ConnectorExecutionRequest` / `ConnectorExecutionResult` normalize Tool
  invocation, errors, approval state, preview behavior, and idempotency.
- `HostedConnectorExecutor` uses the authenticated Lightbulb control plane for
  reads, safe previews, and the staged governed-write contract. The ordinary
  project API at `/api/tools/governed-invoke` remains on an explicit production
  rollout hold: it requires both
  `GOVERNED_CONNECTOR_EFFECT_BOUNDARY_ENFORCED=true` and
  `GOVERNED_CONNECTOR_EXECUTION_ENABLED=true`, and otherwise fails before
  dispatch. The verified-envelope hosted-worker lane is a distinct endpoint,
  `/api/internal/tools/governed-invoke`, with its own
  `GOVERNED_CONNECTOR_WORKER_ENABLED` gate plus exact write/read Tool allowlists
  and pinned catalog versions. Enabling one lane never enables or certifies the
  other. In either lane Spring binds dispatch to the exact project account,
  tenant binding, native adapter/handler, target digest, request, and governed
  journal/provenance contract.
  `InMemoryConnectorExecutor` provides deterministic project tests and
  local-only idempotent simulation.
- `BusinessProcessPrimitive` and `business_process_primitive` provide typed,
  versioned implementation contracts that custom projects can extend.
- `LightbulbProject` declares allowed primitives, allowed connector Tools,
  secret references, policy, and event-routed workflows.
- `ProjectRuntime` resolves deterministic input bindings, routes structured
  events, bounds loops, preserves exact project-bound connector account aliases,
  and pauses on approval, missing input, or policy blocks.
- `DurableProjectRuntime` adds revisioned pause/resume, schedules, idempotent
  event ingestion, expiring worker leases, and crash-safe custody of opaque
  connector account aliases. Hosted projects persist this state under
  authenticated tenant/company/project scope.
- `RuntimeOutcome` recorders automatically capture sanitized status, latency,
  approval state, and failure kind without retaining inputs or outputs.
- Connector conformance covers every provider Tool declared by the shipped
  executable primitives and can compare those contracts with the live hosted
  Tool schemas. Production certification additionally requires provider
  readback, replay/conflict, error, and ambiguous-recovery attestations.
- The initial twelve-tool finance production-conformance packet is explicitly
  write-only. It does not certify the governed `quickbooks.list_accounts` or
  `quickbooks.get_journal_entry` READ; each Tool requires its own schema/effect, exact
  route/account isolation, READ-provenance, output-commitment, and
  normalized-error evidence without a fabricated approval or write
  attestation.

The SDK ships executable primitive implementations across communication,
finance, calendar, legal, CRM, people, documents, approvals, project delivery,
GTM, learning, physical operations, and regulated controls.
Writes are preview-only by default. In-memory connector writes require an
approval reference and all write requests require derived idempotency keys.
Hosted writes additionally require a platform Project UUID. An apply call with
no approval reference returns `pending_approval` plus the opaque ApprovalTask
UUID created by Spring. After a human approves it through the normal approvals
surface, retry the same run/request with that reference; Spring accepts it once
only when Tool, canonical inputs, idempotency identity, scope, and actor match.
Caller-declared effects are drift assertions only; uncatalogued or mismatched
Tools fail closed. `project_ref` is correlation metadata only and can never
substitute for the authenticated, company-bound Project UUID.

The major operating-domain additions are typed, deterministic control
evaluators and bounded lifecycle projections over normalized snapshots. They do
not pretend to be an ERP, WMS, MES, HCM, PLM, or GRC system of record. A
`ready`, `candidate_validated`, or locally advanced result is evidence that the
supplied package passed the declared SDK policy; it is never posting,
fulfillment, employment, safety, regulatory, or deployment authority.

| Operating area | Executable SDK surface | Covered control package | Authority boundary |
| --- | --- | --- | --- |
| Finance and accounting | `finance.discover_ledger_accounts`, `finance.evaluate_journal_entry_controls`, `finance.prepare_journal_entry`, `finance.post_journal_entry`, `finance.reconcile_journal_post`, `finance.evaluate_period_close_readiness`, `finance.evaluate_operating_subledger_controls`, `finance.propose_period_close_transition` | Governed chart-of-accounts discovery; content-bound QuickBooks/Xero journal preparation, approval-gated posting and independently evidenced readback; operating controls plus a bounded trial-balance → reconciliation → adjustment → subledger-lock → elimination/consolidation → approval → close proposal lifecycle | Spring owns authenticated scope, connector-account custody, RBAC, approvals, the governed execution journal, ledger/subledger writes, close, persistence, recovery settlement and audit. Ambiguous journal or close effects never auto-retry. |
| Procure-to-pay | `procurement.propose_vendor_onboarding_transition`, `procurement.evaluate_purchase_to_pay_controls`, `procurement.propose_procure_to_pay_transition` | An exact-scope identity → due-diligence → qualification → approval → bank-control → setup-readiness → activation-candidate vendor lifecycle, plus a revision-, evidence- and idempotency-bound requisition → approval → PO → receiving → three-way match → exception/closure proposal lifecycle | The SDK produces validated candidates/proposals only; Spring owns private-artifact checks, KYC/AML and sanctions facts, approval custody, bank-data verification, durable idempotency, vendor-master and procurement persistence, provider writes, monitoring and audit. Caller-authored authority evidence cannot activate a vendor or produce an authoritative `applied` result. |
| Supply chain | `supply_chain.evaluate_plan_fulfillment_controls`, `supply_chain.propose_execution_transition` | Supplier performance/risk controls plus a bounded demand forecast → S&OP → MRP → allocation → replenishment → warehouse release → shipment/custody → delivery or exception-resolution → closure candidate lifecycle | No optimizer, ERP, WMS, TMS, carrier, customs, custody, delivery or inventory authority is granted; Spring and source systems retain approvals, facts, persistence and audit. |
| Manufacturing and field quality | `operations.verify_bom_inventory_traceability`, `manufacturing.advance_execution_lifecycle`, `manufacturing.evaluate_ehs_recall_field_quality_controls`, `maintenance.propose_work_order_transition` | Exact-scope released BOM/routing evidence; scheduled production orders; ordered shop-floor completion; UOM-safe lot/serial genealogy; full-scrap closure; quality holds; nonconformance/CAPA/concession evidence; EHS, recall and field-quality controls; and a bounded request → plan → authorization/schedule → execution → independent inspection → return-to-service → close candidate maintenance lifecycle with LOTO, parts, tools, labor and custody checks | Lifecycle output is an immutable SDK projection. Spring must authenticate roles and approvals and owns MES/QMS/EAM/CMMS/ERP persistence, permits and LOTO facts, labor and inventory effects, product release, quarantine, reporting, recall, maintenance dispatch, return to service and closure. |
| Commercial operations | `commercial.evaluate_quote_order_contract_controls`, `commercial.propose_operations_transition` | A bounded CPQ/quote → contract/order review → subscription/entitlement → billing-model-specific flat, seat, usage, or hybrid proposal → renewal → channel attribution → commission/RevOps handoff lifecycle | The SDK materializes only a candidate projection. Cadence proration, tiering, credits, tax, invoice materialization, pricing, booking, contracting, billing, entitlement, channel and commission writes remain governed Spring/hosted operations. |
| Customer service | `service.intake_and_classify_case`, `service.route_and_escalate_case`, `service.submit_resolution_for_verification`, `service.verify_case_resolution`, `service.propose_remedy_authorization`, `service.evaluate_case_resolution_controls`, `service.propose_asset_remedy_transition` | Evidence-custodied intake/classification, deterministic SLA clocks, escalation floors, resolution/customer verification, and risk/SoD-bound refund, credit and RMA proposals; plus bounded warranty-entitlement → depot-custody or field-plan → diagnosis → work preparation/completion → independent verification → return/reinstallation → customer verification → closure-candidate repair or replacement lifecycles | Standalone mode only validates read-only candidates. Spring owns authentication, RBAC, approval, persistence and audit; governed case, warranty, depot, field-service, inventory and carrier systems own every refund, credit, return, repair, replacement, dispatch, custody, case mutation and customer-outcome effect. |
| People operations | `people.evaluate_worker_lifecycle_controls`, `people.propose_operations_transition` | A bounded recruiting/candidate → worker activation → shift/time/leave → performance/compensation → learning/certification → payroll-handoff → offboarding/access-revocation candidate lifecycle with exact pay-period and evidence lineage, including deterministic full-period annual-salary handoff | The SDK produces a content-bound candidate only. Salary proration, overtime, adjustments, deductions, tax, net pay, HCM/payroll/IAM writes, employment decisions, approvals, persistence, provider effects and audit remain Spring/host-authoritative. |
| Product and engineering | `product.evaluate_release_governance_controls`, `product_engineering.propose_lifecycle_transition` | A bounded requirements → roadmap/release target → specification/BOM baseline → independent design review → engineering change → V&V → release candidate → telemetry → vulnerability/defect disposition lifecycle with exact genealogy | The SDK cannot approve a change, release a product, accept risk or close a defect; PLM/ALM writes, approval, persistence and audit remain hosted-system responsibilities. |
| Compliance and regulated operations | `compliance.evaluate_regulated_controls`, `compliance.propose_regulated_operations_transition` | Seven exact-scope independent case tracks for policy/control/assessment, incident/breach, KYC/AML, applicable-domain regulated quality, export control, retention with conditional legal hold, and model risk. Only the policy track is an ordered establish → test → assess chain; unrelated regulated cases are never forced into fictional predecessor relationships. | Legal/regulatory determinations, filings, holds, account decisions, approvals, persistence and audit stay outside the SDK. |
| Omnichannel communication | `communication.resolve_cross_channel_identity`, `communication.evaluate_jurisdiction_channel_policy`, `communication.plan_governed_voice_call`, `communication.normalize_provider_outcome`, `observe_whatsapp_delivery` | Cross-channel identity, jurisdiction/channel consent and suppression, governed SMS/WhatsApp materialization, voice planning, signed Spring-custodied WhatsApp webhook observation, and normalized delivery/outcome states | Spring signs short-lived policy decisions and owns sender/account custody, routes, writes, webhook signature verification, private payload retention, durable replay protection and authenticated observations; provider acceptance is never promoted to delivery or business outcome. |
| Production closure | `operations.evaluate_production_connector_conformance`, `operations.evaluate_production_connector_read_conformance`, `operations.evaluate_production_execution_readiness` | Exact route/schema/journal/provider readback/replay/conflict/error/recovery evidence, hosted writes, governed reads, bounded loops, transactional workflow/HITL publication recovery, transport recovery, SLO/replay/incident evidence and measured business outcomes | All only propose exact per-Tool certification candidates that retain the complete bounded proof; production and deployment authorization remain false. A write packet cannot satisfy an exact required-Tool gate for `quickbooks.list_accounts` or `quickbooks.get_journal_entry`. |

This change set does not provide live provider-conformance attestations,
qualifying SLO or business-outcome measurements, or operator certification. SMS,
voice, and WhatsApp transport recovery and the production-disabled worker-side
subagent `STEP_REQUESTS` producer paths also remain uncertified; company-running
readiness is false.

Every result is content-bound by deterministic operation/evidence digests and
the executable runtime emits versioned receipts. The production evidence and
incident contract is in
[`docs/lightbulb-sdk-production-execution-runbook.md`](https://www.lightbulbpartners.com/developers#company-worker).

The canonical governed voice Tools are `twilio.place_call_turn` and
`twilio.lookup_call_status`. The SDK materializer/observer keeps the raw call
SID in private dispatch custody and exposes only an HMAC-bound public receipt.
The Spring SMS/voice routes remain dark unless operators install both a reviewed
Twilio HTTP transport and a production vault resolver; neither implementation is
included here, and a catalog row or test fake is not transport certification.
WhatsApp has SDK policy/materialization contracts plus a zero-write observer for
short-lived, HMAC-sealed Spring webhook artifacts. It still has no native Spring
adapter, Meta signature-verification endpoint, provider HTTP transport, or
durable replay journal. Crash-safe private provider-ID recovery is therefore
uncertified for SMS, voice, and WhatsApp, and ambiguous provider acceptance is
never auto-replayed.

The encrypted workflow publication outbox protects orchestrator-owned requests
and 13 of the 15 audited Spring direct `STEP_REQUESTS` lanes, including
integration, internal-tool, legal, voice/receptionist, explicitly authorized
scheduled-finance and CRM, and feedback dispatch. Commerce-intelligence and
finance-market-data schedules remain deliberately undispatched because their
profiles do not identify an authorized actor or service principal; they never
substitute an arbitrary enabled user. The direct registrar joins an existing
business transaction when present, persists an exact-scope running workflow
receipt and outbox row, and leaves Kafka publication to the fenced relay.

Immediately before Kafka publication, the relay locks and rechecks the workflow,
exact step generation, selected agent, and current actor authority.
Definition-backed envelopes must match a fresh full-RBAC snapshot. Direct
`AppUser` envelopes remain canonical identity-only claims (`roles=[]`,
`permissions_scope=[]`, and no component claims); the relay verifies current
identity and tenant/company scope without copying RBAC into the model-visible
envelope. The exact external receptionist exception remains limited to sole role
`EXTERNAL_CONTACT` and receives no runtime-authority token.

For every authoritative signature-v3 step, the worker repeats
`POST /api/internal/workflows/instances/{traceId}/state-preflight` after context
hydration and immediately before `executor.dispatch`, sending only a digest of
the signed actor claims. Spring derives full-RBAC, identity-only, or external
authority from the locked Workflow Instance. A deterministic mismatch
terminalizes workflow/control and skips execution; a Spring or RBAC-store outage
leaves the Kafka record uncommitted for retry.

`HITL_REQUESTS` and `HITL_DECISIONS` now use the same encrypted transactional
outbox, binding the waiting Workflow Instance and terminal ApprovalTask update
to the exact resume generation. Authoritative Spring lifecycle facts on
`agent.workflow.lifecycle.v1` and workflow-owned DLQ facts on
`agent.workflow.dlq.v1` use the separate encrypted V1865 transactional outbox.
The legacy source topic `agent.workflow.events` remains non-authoritative and
best-effort: V1867 makes an accepted record durably replayable, but cannot make
its source publication transactional or crash-safe. V1866 initializes the
generation authority in `LEGACY_DIRECT` so mixed-version rolling releases keep
one writer. The release controller transitions that authority to `OUTBOX` only
after the live Spring replica carries the exact
`v1865-workflow-event-publication-v1` generation and the active V1865 queue is
empty. In `OUTBOX`, the canonical orchestrator transaction persists the
encrypted lifecycle or DLQ fact and the relay waits for a complete broker
acknowledgement. Stable event id and publication order headers are inputs to
the database materializer, which suppresses duplicates and assigns cursor
order. A `PARKED` head retains ciphertext and active capacity until an
authenticated, exact-scope operator commits append-only `RETRY` or
`ABANDON_TAIL` evidence through the resolution controller. `PARKED` is
exclusively a pre-publish poison or integrity failure, and operator `RETRY` is
only for poison that was repaired before another publish attempt. Broker
failure, timeout, or ACK-metadata uncertainty remains `PENDING` for stable
automatic retry and never becomes `PARKED`.

Before any local SSE fan-out, V1867 durably materializes the
security-sanitized canonical event in PostgreSQL under the exact
tenant/company/trace scope. Using a stable event id when present and broker
coordinates for pre-header records, the database materializer suppresses
duplicate acceptances and assigns per-scope cursor order; any identity,
semantic, coordinate, or scope conflict fails closed. The independent
materialization transaction commits the canonical row, broker observation, and
cursor before fan-out or Kafka offset advancement. If the JVM fails after that
commit, the retried Kafka record resolves to the same row and cursor and safely
retries delivery instead of creating a second event. Strict, lossless JSON
parsing preserves exact decimal and integer values from Kafka through
PostgreSQL replay.

Authorized SSE reconnects pass `Last-Event-ID` into a bounded,
repeatable-read PostgreSQL snapshot/replay and receive rows in cursor order
through one captured high-water mark before joining live delivery. Live
delivery uses bounded async fan-out and bounded per-scope, per-tenant, and
global subscriptions; saturation closes the affected streams so clients
recover through durable replay. SSE frames carry the stable event id. The
per-JVM broadcast consumer starts an ephemeral group at `earliest`, uses a
bounded poll interval with a pausing backoff handler, and consumes the canonical
lifecycle topic's 35-day window so a restarted replica can rematerialize
retained records idempotently.

V1867 scrubs canonical event content after 15 minutes while retaining bounded
identity, scope, cursor, and hash metadata for exactly 35 days.
The database duplicate-suppression and replay evidence is therefore bounded to
exactly 35 days. Global and per-tenant row/byte reservations fail closed,
scheduled scrub/purge work is batch-bounded, and event metadata purges
unconditionally at that exact boundary. Only independent cursor retirement is
fenced by nonterminal or recent workflow state and active or parked outbox
references. A content-free health indicator reports capacity consistency,
exhaustion, scrub lag, purge lag, and reconciliation age from bounded summaries
plus scheduled exact reconciliation. This closes the bounded `COMPLETE_SLICE5`
durable materialization contract; it does not change the released authority's
production-dark `DARK_BASELINE`/`DISABLED` posture.

V1865/V1866 objects are owned by the governed-writer database role. The
existing Spring datasource login must be the exact `project401_runtime` member,
while Flyway and release transition use a distinct migrator login. The Spring
runtime database credential must be exclusive to Spring; activation fails
closed if the rendered Compose topology shares it with another service.
Runtime receives only the pinned SECURITY DEFINER authority row-lock/read
function and cannot read or mutate the backing authority/audit tables directly.

The two Python worker-side subagent-spawn/resume producers are outside Spring
authority and are fixed off in production with `SUBAGENT_SPAWN_ENABLED=false`;
enabling them is unsupported until they gain Spring-owned signing, generation,
and durable publication. This SDK evaluation never upgrades those remaining
boundaries to production certification. The reserved automatic-trigger lane is admitted only
from a consumed durable `WorkflowTrigger` receipt and is revalidated against its
exact definition, scope, and current role or creator access. The bounded public
Client Page lane is limited to `receptionist_booking` and `call_center_routing`;
Spring derives it from one enabled page configuration, a published definition,
and current `CLIENT` component access, then persists and revalidates a versioned
receipt at relay and worker preflight. That public lane receives no connector
runtime-authority token. Every other generic public/synthetic or unmarked
principal lacks a reviewed persisted contract and fails closed before Kafka.
Any stale or legacy worker delivery is rejected by the execution preflight;
never substitute an arbitrary enabled user.

Hosted workers must derive both client authentication and execution identity
from the same verified project envelope. Caller-supplied tenant, company,
project, approval, or connector-account claims are rejected as authority:

```python
from lightbulb import HostedConnectorExecutor, LightbulbClient

worker_client = LightbulbClient.from_verified_envelope(
    "https://agents.lightbulbpartners.com",
    verified_project_envelope,
)
executor = HostedConnectorExecutor.from_verified_envelope(
    worker_client,
    verified_project_envelope,
)
result = executor.execute(request)
```

The server verifies the envelope again, resolves the exact cataloged Tool and
account alias, consumes any approval, and journals the effect. An ambiguous
provider result becomes `in_doubt`: recovery/readback must prove the outcome
and Spring must settle the governed journal before any retry. The generic
durable SDK runtime never accepts caller-authored recovery attestations or
replays an unresolved external operation, so a timeout cannot become a
duplicate financial effect.

```python
from lightbulb import (
    InMemoryConnectorExecutor,
    LightbulbProject,
    ProjectRuntime,
    default_primitive_registry,
)

project = LightbulbProject.model_validate({
    "project_ref": "reply-router",
    "name": "Reply router",
    "primitive_refs": [
        "communication.classify_reply",
        "calendar.schedule_meeting",
    ],
    "workflows": [{
        "key": "route_reply",
        "title": "Route reply",
        "entry_step": "classify",
        "steps": [
            {
                "id": "classify",
                "primitive_ref": "communication.classify_reply",
                "input_mapping": {"reply_text": "$input.reply_text"},
                "routes": {"meeting.requested": "schedule"},
            },
            {
                "id": "schedule",
                "primitive_ref": "calendar.schedule_meeting",
                "input_mapping": {
                    "attendees": "$input.attendees",
                    "title": "$input.title",
                },
            },
        ],
    }],
})

runtime = ProjectRuntime(
    project,
    default_primitive_registry(),
    InMemoryConnectorExecutor(),
)
run = runtime.run_workflow(
    "route_reply",
    {
        "reply_text": "Can we schedule a call next week?",
        "attendees": ["buyer@example.test"],
        "title": "Renewal follow-up",
    },
)
assert run.status == "completed"
```

For durable execution, wrap the same validated runtime and resume the exact
paused step after approval or missing input is supplied:

```python
durable = runtime.durable()
pending = durable.start_workflow(
    "choose_window",
    inputs,
    preview_only=False,
    run_ref="launch-42",
)
completed = durable.resume_workflow(
    "launch-42",
    input_updates={"decision": "August 15"},
    approval_refs={"approval.request_decision": "approval-123"},
)
```

`LightbulbClient.build_durable_project_runtime(project)` uses the hosted
checkpoint ledger when `hosted_project_id` is set and an atomic local JSON store
otherwise. Use `schedule_workflow`, `ingest_event`, and `run_next` for timers,
idempotent event dispatch, and distributed worker claims. Durable retry is
opt-in (`policy.retry_policy.max_attempts` defaults to `1`): retryable failures
are revision-saved before invocation, scheduled with capped exponential
backoff, and keep stable per-step-visit connector identities. Approval and
missing-input resumptions do not consume retry attempts. While a synchronous
primitive is active, the runtime renews its lease at a bounded cadence with an
owner/revision fence. Hosted claims and renewals use the control-plane clock;
lost ownership or renewal failures are surfaced before any stale completion
can be persisted.

See [custom project guide](https://www.lightbulbpartners.com/developers#custom-projects) for hosted execution, custom
primitive authoring, connector fakes, approval retries, input bindings, MCP
tools, status semantics, and the current runtime limits.

### Continuous workflow improvement

Version 0.14 combines the local supervisor with the durable, authenticated
control plane and executable SDK catalog. The supervisor scores every catalog
contract and every shipped implementation, measures executable coverage,
records trend history, merges a deduplicated improvement queue, and prepares
one SDK-first work packet for the coding harness:

```bash
# One evaluation cycle
lightbulb improve-workflows run --output-dir .lightbulb/workflow-improvement

# Finite supervisor; create .lightbulb/workflow-improvement/STOP to stop earlier
lightbulb improve-workflows watch \
  --output-dir .lightbulb/workflow-improvement \
  --interval-seconds 900 \
  --max-iterations 96 \
  --max-elapsed-seconds 86400 \
  --max-no-progress-runs 2 \
  --sync-server

lightbulb improve-workflows status --output-dir .lightbulb/workflow-improvement
lightbulb improve-workflows queue --output-dir .lightbulb/workflow-improvement

# Persist the latest run and packets under authenticated tenant/company scope
lightbulb improve-workflows sync --output-dir .lightbulb/workflow-improvement
lightbulb improve-workflows server-status
lightbulb improve-workflows server-queue
```

Each cycle writes `latest.json`, `state.json`, bounded `history.jsonl`, and
`improvement-queue.json`; `history-compaction.json` accounts for retired rows by
count, source bytes, and rolling digest, while `next-work-packet.json` exists
only while actionable work is queued. The watcher has no unbounded mode:
omitted SDK limits use 96 cycles, 24 hours, and two stable no-progress runs,
with lower storage/intake caps and non-overridable hard ceilings. Its final
`supervisor-stop.json` receipt records the exact stop reason and budget.

Primitive execution records runtime outcomes automatically, and
`LightbulbClient.run_workflow_improvement_cycle()` consumes the queued
observations by default. Manual `--observed-outcomes outcomes.json` remains
available with a 1 MiB file limit. Each evaluator cycle inspects at most 256
rows by default. Only allow-listed status, error-kind, latency, validation,
approval, timestamp, primitive, and harness fields are retained; malformed or
overflowing input produces a blocking finding instead of being silently
coerced or ignored.

The evaluator is deliberately proposal-only. It never edits code, invokes an
agent or connector, publishes, deploys, or performs an external write. The
server derives tenant, company, and actor scope from authentication, stores only
allow-listed outcomes, and records one immutable hash-chained decision per
`implementation`, `publish`, or `deploy` scope.

After explicit implementation approval, delivery can run on the server-issued
`codex/` branch through the `workflow_authoring` Harness contract:

```bash
lightbulb improve-workflows decide <packet-id> implementation approved \
  --rationale "Reviewed tests and SDK contract"
lightbulb improve-workflows deliver <packet-id> \
  --environment disposable-staging-123 --repository-ref github.com/acme/repo
lightbulb improve-workflows delivery-event <delivery-id> branch_created \
  --evidence '{"branch_name":"codex/workflow-improvement-example"}'
lightbulb improve-workflows audit <packet-id>
lightbulb improve-workflows delivery-status <delivery-id>
```

The delivery state machine enforces isolated branch, passing acceptance checks,
draft PR, CI, disposable staging, bounded canary, metric comparison, rollback on
regression, and cleanup in order. It cannot deploy production. Publish and
deploy each require separate immutable decisions after a passing staging canary;
deploy approval additionally requires publish approval. Contract and executable
implementation regressions outrank implementation gaps. Existing catalog
primitives without Python implementation code are completed before the loop
proposes a new catalog capability. The current 13/13 catalog is green and emits
no speculative work packet until contract checks or real outcomes identify a
gap.

A staging-validated improvement can now become a content-free learning
nomination without gaining training authority. Harness implementations may
return a bounded `lightbulb.workflow_learning_candidate_manifest.v1`; Harness
stores only its SHA-256, candidate kind, and Git commit in the immutable
`IMPLEMENTATION_COMPLETED` audit event. The sync/async SDK method
`prepare_workflow_learning_handoff(...)` then reads the exact scoped packet,
delivery, complete hash-linked audit trail, and installed-action readiness. The
MCP equivalent is `prepare_workflow_learning_handoff`.

The legacy `lightbulb.workflow_learning_handoff.v1` remains a content-free
nomination. When the trusted custody workload is provisioned, omit
`episode_manifest` (or supply the SDK-derived
`lightbulb.workflow_learning_episode_manifest.v2`) to perform one explicit
read-only custody verification. The SDK then derives the only accepted v2
episode manifest from the authenticated snapshot dataset digest, counts, cost,
lifetime, receipt, and bundle and emits
`lightbulb.workflow_learning_handoff.v2`. Only the episode-input, artifact-
  storage, and input-attestation blockers are resolved.

When Harness has a producer signing key, the same implementation event also
contains an Ed25519 attestation over the exact candidate artifact digest and a
scope hash covering packet, delivery, candidate-manifest digest, artifact
contract, and repository commit. The SDK notices signed evidence and performs
one additional authenticated read. Spring revalidates the signature against its
current public rotation registry, recomputes the scope from the immutable audit
event, and returns only a content-free verification summary. The SDK reconciles
that summary byte-for-byte with the caller's candidate manifest and emits
`lightbulb.workflow_learning_handoff.v3`; missing, expired, revoked, tampered,
or cross-scoped evidence remains v1/v2 with
`candidate_artifact_attestation_required`.

All three versions deliberately remain `status=blocked`: raw artifacts and
episodes are excluded, every funding, artifact-write, scheduling, training,
evaluation, promotion, and serving flag is false, and approved
success-contract selection, least-cost campaign admission, and every later
authority stay separate server-side operations. The candidate verification
read itself cannot admit or execute a campaign.

`LIGHTBULB_WORKFLOW_CANDIDATE_SIGNING_REQUIRED` and
`LIGHTBULB_WORKFLOW_CANDIDATE_ATTESTATION_REQUIRED` are independently
default-off in the development compose path and set to `true` in the production
template. The producer uses the existing Agent Workers artifact-signing key;
Spring receives only the corresponding public rotation registry. If either side
is unavailable, the nomination remains inspectable and blocked instead of
falling back to an unsigned caller claim.

Runtime setup is exposed as backend account configuration, not UI components:

- `list_agent_runtime_options`
- `get_agent_runtime_config`
- `configure_coding_agent_runtime`
- `configure_backbone_agent_surface`
- `test_agent_runtime_config`
- `start_codex_account_link`
- `get_codex_account_link_status`
- `cancel_codex_account_link`

Use these from Codex, Claude Code, or ChatGPT-style MCP hosts when the user
wants Codex or Claude Code to be their Lightbulb coding agent, or ChatGPT MCP to
be their Backbone host surface.

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

Project creation has a local World Ready inspection followed by a strict
two-step review/create front door plus a separate explicit feedback tool in
both the compact Backbone MCP profile and the sync/async Python clients:

For an existing project, `get_project_game_snapshot(project_id)` fetches the
server-owned `lightbulb.project_game_snapshot.v1` protocol shared with human and
agent workers. It binds the authenticated tenant, selected company, and exact
project UUID to the public JWT route or the separately guarded internal API-key
route. The SDK validates the schema, bounded finite JSON, canonical resource
paths, evidence counts, truth boundary, and locked human-gated authority before
returning it. Caller-supplied project or plan JSON can never become canonical
score, scope, evidence, or authority.

`inspect_project_game_campaign` remains available in the pure Python client as
an explicitly offline, unverified preview over an observed project, plan, and
optional business-cockpit payload. MCP does not expose that local-input path;
its compatibility alias accepts only a project UUID and performs the same
server fetch as `get_project_game_snapshot`. The local preview's ten phases
route to the real AutoResearch, Search, data-engineering,
AutoML, model-serving, Solver/AOC, approval, action, outcome, and improvement
tools. Its derived `lightbulb.project_mission_briefing.v1` turns the current
mission into one fresh human/agent handoff: why it matters, what counts as done,
lead specialist, observed context, exact capability route, next no-skill/
single-skill/combination trial, expected receipt, and the selected play-style
posture. Opening or inspecting the briefing does not activate preparation,
schedule a shadow quest, dispatch a worker, call a tool, or authorize a live
action. Its sibling `lightbulb.project_game_checkpoint.v1` is the truthful
results/save screen: it summarizes verified science receipts, shadow strategy
evidence, reported skill-arm observations, and real business-score
observations, then routes the next quest. It remains a project checkpoint and
never infers a mission win, causal result, admitted lesson, or agent level-up.
When an exact current Mission Run, later action binding, and linked outcome
receipt are all present, the campaign separately derives
`lightbulb.project_mission_debrief.v1`. That debrief reports only that evidence
returned; it still does not infer completion, victory, causal effect, learning,
or new authority. The nested
`lightbulb.skill_tournament.v1` counts only explicitly labeled
shadow evidence for `no_skill`, `single_skill`, and `skill_combination`; it does
not verify comparability or outcome authenticity, select a winner, or authorize
promotion. It points every arm at the preferred
`automl_run_skill_tournament` worker tool and retains
`automl_evaluate_skill_tournament` for already-captured observations. The
preferred tool derives tenant/company/user/project scope and RBAC from the
parent `AgentContextEnvelope`, checks the task and provider budget, validates
producer signing before provider work, and owns the exact no-skill, one-skill,
and incremental-combination matrix. It runs Claude domain episodes through the
provider-only shadow lane, signs the capture once, submits it once to Artifact
Service, and returns an authenticated scoreboard plus a non-production skill
recommendation. Agents must not fabricate arm observations.

The signed `lightbulb.skill_tournament_shadow_capture_bundle.v1` carries an
exact `lightbulb.skill_tournament_runtime_contract.v1`. Every episode must
prove complete provider/tool/mutation interception for coverage ID
`lightbulb.claude-domain-tournament-provider-only.v1`, at least one provider
call, no tool or mutation path, and no coverage violation. Artifact Service
independently verifies that contract along with the producer's Ed25519 key,
scope, digests, task matrix, skill pins, zero tool/write counters, and embedded
evaluator request. This authenticates the Lightbulb producer and its audited
domain-worker lane; it does not authenticate business outcomes, independently
attest the execution environment, select a production winner, promote a skill,
or authorize an action.

The orchestrator is code-available but deployment-configuration-gated. Agent
workers require either `LIGHTBULB_ARTIFACT_SIGNING_KEY_FILE` or the paired
`LIGHTBULB_ARTIFACT_SIGNING_KEY_ID` and
`LIGHTBULB_ARTIFACT_SIGNING_PRIVATE_KEY_PKCS8_BASE64`; Artifact Service must
trust the matching public key. Equivalent Coding, Backbone, Codex, Cursor, and
direct-connector runtime coverage is still required. Project-level offline
policy evaluation now has a separate Strategy Lab contract described below;
it verifies assignment/action/outcome receipt pairing but does not extend the
skill-tournament runtime-coverage claim, independently verify an external data
source, or prove causality.

Mission Runs add the durable save-before-action chain shared by the human campaign,
sync/async clients, compact Backbone MCP, and project-scoped workers:

- `list_project_mission_runs(project_id)` reads the exact-project
  `lightbulb.project_mission_run_ledger.v1`.
- `start_project_mission_run(...)` requires `confirm_start=True` and locks the
  exact current `lightbulb.project_mission_briefing.v1`, play style, shadow
  skill arm and pins, context references, run UUID, and idempotency boundary
  before any separately authorized action. It does not open a runtime, dispatch
  a worker, call a provider/tool, approve an action, or perform a write outside
  the Mission Run ledger.
- `bind_project_mission_action(...)` requires `confirm_bind=True` and binds only
  a later durable action event in the same tenant/company/project scope. It
  rejects mission bookkeeping and outcome events as action sources. The
  resulting `lightbulb.project_mission_action_receipt.v1` verifies scope and
  chronology only, not action semantics or external effect.
- A later Project Outcome receipt may cite both the Mission Run receipt and
  Mission Action receipt. Only that exact chain can produce the derived Mission
  Debrief, and even then currentness, mission completion, causality, learning,
  promotion, dispatch, and action authority remain false.

The Project Training Arena preserves what the skill tournament actually tested
before anyone proposes learning:

- Sync and async clients plus MCP expose
  `list_project_skill_matches(project_id, limit)`, which reads the exact-project
  `lightbulb.project_skill_match_ledger.v1`.
- Only the internal project worker has `record_project_skill_match`. It derives
  tenant, company, user, and project from `AgentContextEnvelope`, requires
  `automl.experiments.execute`, explicit confirmation, the exact Mission Run
  loadout, and the unmodified authenticated tournament orchestration receipt.
  There is deliberately no public or MCP record tool.
- The receipt verifies a bounded provider-only capture and a common no-skill,
  one-skill, and skill-combination suite. The project control plane does not
  independently replay the Artifact Service signature, authenticate a business
  outcome, prove causality or skill attribution, construct a training dataset,
  train, update confidence/routing, promote, dispatch, act, or write production
  data.
- Training remains unavailable from this receipt until it is paired with an
  exact human-admitted Level-Up lesson and then crosses the separate governed
  dataset-custody and durable learning-run admission bridge.

The governed Level-Up Review is the separate human learning gate after the
mission debrief:

- `list_project_learning_reviews(project_id)` reads the exact-project
  `lightbulb.project_learning_review_ledger.v1`.
- `record_project_learning_review(...)` requires `confirm_record=True` and an
  authenticated human. It accepts only the exact Mission Run, Mission Action,
  and Outcome receipt chain and the exact no-skill/single-skill/combination
  loadout recorded by those receipts. The human may keep it as a positive or
  negative shadow lesson, reject it, or defer for more evidence.
- An admitted `lightbulb.project_shadow_training_observation.v1` is graded
  future training input only. It does not prove the outside result is true,
  prove causality or skill attribution, mutate live skill confidence or the
  online learner, change routing, activate/promote policy, dispatch work,
  authorize an action, or write production data.
- Project workers expose only `list_project_learning_reviews`; they have no
  review-write tool and are explicitly forbidden from substituting the older
  live-mutating `record_skill_outcome` path for project mission evidence.

The Project Learning Lab joins those two independently governed proofs without
pretending that packaging evidence is training:

- Sync/async clients and MCP expose
  `list_project_training_packs(project_id, limit)`. The human cockpit renders
  the same exact-project `lightbulb.project_training_pack_ledger.v1` as a
  simple three-check quest: Arena match verified, human lesson admitted, and
  exact Mission Run plus loadout verified.
- Only the internal project worker has `record_project_training_pack`. It
  derives scope and `automl.experiments.execute` from `AgentContextEnvelope`,
  requires explicit confirmation, and pairs exactly one authenticated
  worker-recorded Arena receipt with exactly one authenticated human-admitted
  Level-Up receipt. The Mission Run and no/single/combination skill loadout
  must match. Public SDK and MCP surfaces deliberately have no record tool.
- The resulting `lightbulb.project_training_pack.v1` contains one graded
  candidate observation, both receipt digests, bounded lineage, the Arena
  evidence, and a deterministic pack digest. Its adjacent
  `lightbulb.project_learning_run_admission_plan.v1` is an admission checklist,
  not a trainer: runtime selection, dataset custody, holdout/evaluation,
  budget, durable run creation, capacity, commercial reservation, operator
  approval, and claimability all remain false.
- The next authoritative boundary is the existing Memory learning-run ledger.
  The candidate pack does not publish/register a dataset, select AutoML,
  PufferLib, or PRIME-RL, create/admit/claim/execute a run, update an online
  learner or routing, promote/activate a skill or policy, dispatch, act, or
  write production data.

The Project Training Quest carries that candidate through a fenced runtime:

- `list_project_learning_runs(project_id)` returns the receipt-backed
  twelve-stage
  quest. Preparation creates immutable dataset custody and a durable queued
  Memory run; admission separately reserves exact capacity and commercial
  budget.
- A project-scoped agent worker—not public SDK or MCP—uses
  `claim_project_learning_run`, `heartbeat_project_learning_run`,
  `checkpoint_project_learning_run`, and `finish_project_learning_run`. The raw
  Memory lease token stays inside that worker process behind an opaque handle.
- Spring independently rereads Memory and appends a sanitized
  `lightbulb.project_learning_run_execution_receipt.v1`. The shared Python and
  JavaScript projection rejects a wrong actor, forged authority, mismatched
  scope, inconsistent counts/status, or any nested `lease_token`/`token_hash`.
- A terminal `succeeded` receipt completes the runtime-result stage only. It
  does not prove training effectiveness, complete independent evaluation,
  admit a learner/routing/model/policy change, promote anything, authorize an
  action, or prove business value.
- `list_project_learning_result_evaluations(project_id)` reads an independent
  replay ledger. A separate evaluator worker may complete the technical gate;
  an authenticated human must then separately admit or reject the exact
  candidate. Neither receipt changes a learner.
- `list_project_shadow_learner_updates(project_id)` is the only public
  SDK/MCP operation for stage 12. Apply and rollback stay worker-only, derive
  exact scope and `learning.runs.execute` from `AgentContextEnvelope`, require
  explicit confirmation, and accept only the exact human-admitted
  `gepa_champion_manifest` chain.
- The worker can change only Memory's isolated Project shadow slot and three
  approved paths, with a maximum revision delta of one. Exact retries are
  digest-bound and zero-mutation; conflicting retry IDs fail closed. Rollback
  is bound to the exact apply receipt and stored snapshot. The active learner,
  active instruction revision, routing, promotion, policy activation,
  dispatch, production writes, and business-effectiveness claims remain false.

`project_learning_receipt_to_workflow_event(...)` is the SDK bridge from a
complete raw Spring preparation, admission, or execution receipt into a
sanitized `WorkflowEventEnvelope`. The receipt ID becomes the deterministic
event ID, and the adapter validates the full nested project/run scope, actor
attestation, and lifecycle bindings before excluding actor, budget, provider,
worker, credential, and lease fields. A normalized
`ProjectLearningRunPreparedReceipt` or `ProjectLearningRunAdmittedReceipt` is
intentionally rejected: those freely constructible SDK projections omit the
scope and actor evidence required by this boundary. The event's `source` is a
receipt-contract routing label, not cryptographic proof that an arbitrary
Python object came from Spring. Preserve the authenticated Spring response
boundary, then pass the projected event to
`DurableProjectRuntime.ingest_event(...)`; with `HostedCheckpointStore`, the
write also uses Spring's authenticated project-event endpoint and its
RBAC/scope checks. This is a bounded receipt projection, not a Kafka stream: it
exposes no topic, partition, offset, cursor, total ordering, complete history,
or exactly-once broker claim.

Projects now share one append-only real-score contract across the human UI,
sync/async SDK clients, MCP hosts, and project-scoped agent workers:

- `list_project_business_outcomes(project_id)` reads
  `lightbulb.project_business_outcome_ledger.v1`.
- `record_project_business_outcome(...)` requires `confirm_record=True`, a
  selected company, an explicit baseline and observed value, and a stable
  observation/idempotency ID. Human calls create an
  `actor_authenticated_attestation` receipt. A caller may instead bind an
  existing same-project event to receive the stronger
  `same_scope_project_event_bound` tier.
- Domain workers use the identically named worker tool. Their path derives
  tenant, company, user, and project from `AgentContextEnvelope`, requires
  `automl.experiments.execute`, requires a durable same-project source event,
  and re-verifies the returned scope and source binding.

Both tiers classify metric movement only. They explicitly leave external source
truth, causal attribution, learning admission, skill-confidence changes, policy
promotion, and production action authority false. Those require separate
evidence and governance steps.

The Project Science Ledger gives the campaign and every worker one durable
context spine from business question to shadow policy candidate:

- `list_project_science_evidence(project_id)` reads the exact-project
  `lightbulb.project_science_ledger.v1` before research, data, AutoML,
  model-serving, solver, or control work.
- `record_project_science_evidence(...)` records one hypothesis, search,
  data-engineering, ML/serving, or solver/control artifact. Later stages require
  the exact predecessor receipt; agent workers must also bind a durable
  same-project source event and explicitly confirm the write.
- Each receipt binds tenant, company, project, actor, artifact reference and
  SHA-256 identity, predecessor receipts, business metric, reported tools, and
  reported skills. Tool and skill lists are not runtime attestations.
- The shared Science Quest turns only scope/predecessor-verified receipts into
  green campaign evidence. Existing plan fields remain visible as amber claims
  until a receipt exists.

This ledger proves identity and lineage, not artifact contents, hypothesis
validity, model quality, policy optimality, causality, learning admission, or
action authority. Dataset registration, training, deployment, policy
activation, and production actions continue through their existing gates.

The Project Strategy Lab connects decision-time policy logging to those real
score receipts without pretending that correlation is learning:

- `record_project_policy_assignment(...)` records 2-20 action alternatives,
  the chosen action, one behavior distribution, 1-8 candidate distributions,
  the objective metric, and the decision timestamp while the outcome is still
  unknown. Agent workers must bind a durable same-project decision event.
- The eventual `record_project_business_outcome(...)` call links the immutable
  assignment receipt and exact action event through
  `policy_assignment_receipt_id` and `action_receipt_id`.
- `evaluate_project_offline_policy(...)` accepts 20-2,000 unique assignment and
  outcome receipt pairs. Spring reconstructs and scope-checks every assignment,
  chosen action event, metric, and outcome before sending only bounded numeric
  episodes to Artifact Service.
- Artifact Service returns deterministic IPS/SNIPS estimates, a seeded
  bootstrap interval, effective sample size, support, and importance-weight
  diagnostics. Passing all readiness gates creates only a
  `shadow_learning_candidate`; it never proves the propensities or causal
  assumptions, admits learning, changes skill confidence, promotes/activates a
  policy, or authorizes an action.

Sync and async clients also expose `list_project_policy_assignments(...)` and
`list_project_policy_evaluations(...)`. All writes require an explicit
confirmation flag, a selected company, and stable UUID/idempotency identity.

1. `inspect_project_creation_world_ready` evaluates locally and the Python
   client method makes no network call. The MCP wrapper may perform its normal
   authentication/account-context bootstrap on first use, but it never calls a
   project or preflight endpoint. It returns
   `lightbulb.project_start_readiness.v1` with bounded checks, blockers, one
   next action, and a `lightbulb.project_game_start.v1` projection shared with
   the human New Campaign view. The projection names the reviewed win condition,
   one bounded play style, a planned-but-undispatched Project Agent starter,
   read-only first mission, and the planned data/ML/solver campaign. The three
   play styles are `guided_human_in_the_loop` (wait for each mission),
   `proactive_copilot` (propose and prepare), and `autonomous_shadow` (run
   read-only or sandbox shadow quests on a schedule). Guided is the default.
   A play style is an initiative preference only: runtime activation still
   needs separate authority, and the projection keeps dispatch, live actions,
   production writes, and approval authority false. Its skill
   trials are shadow-only (`no_skill`, `single_skill`, and `skill_combination`),
   and policy learning is explicitly `not_admitted`. Participant role and
   experience lens are presentation/protocol choices only: the manifest never
   includes scope IDs, a backend grant, create authority, downstream action
   authority, worker dispatch authority, or model-promotion authority.
2. `preflight_project_creation` sends only the normalized project `name` and
   `instructions` to `/api/enterprise-copilot/project-preflight`. The SDK forces
   `shadow` mode, disables project/action/external writes, validates the full
   `project_creation_preflight.v1` event, and accepts the receipt UUID only
   from the separate `execution` SSE event. A selected company is required so
   the trusted episode receipt has one exact tenant/company namespace. When
   bounded public research runs, the review surfaces only exact retrieved
   excerpts bound to a URL in the mechanically observed public-source
   inventory. Model paraphrases, composite provider answers, uncited text, and
   invented references are omitted rather than presented as facts. Before any
   model-authored search reaches a public provider, its terms must match the
   bounded public-research vocabulary or a proper noun the user explicitly
   marked as `public topic <name>` (equivalent public entity labels are also
   accepted). Private/unknown terms and unapproved numeric identifiers are
   withheld; one rejected proposal does not discard a separate safe query.
   Current receipts also include a bounded `criticality_findings` ledger. Each
   finding binds its plan impact, evidence references, calibrated confidence,
   cheapest resolution, and `block`, `warn`, `assume`, or `ignore`
   disposition. `critical_gaps`, `open_questions`, and `next_question` are
   derived only from `block` and `warn`; assumptions and already-covered facts
   cannot manufacture a user question. An `ignore` disposition must carry a
   field-matched contextual draft span bound by UTF-8 byte offsets and SHA-256;
   the SDK revalidates it against the receipt-bound draft. Historical parser-v2
   receipts remain readable, while newly produced ledger receipts are parser
   v3. A receipt chain permits at most four explicit user-answer refinements;
   a fifth is rejected by the SDK, server, and database.
3. `create_project_from_preflight` accepts the complete receipt returned by
   step 2 and requires literal `confirm_create=true` plus a selected company.
   It posts only the receipt-bound name, instructions, execution UUID, optional
   bounded `play_style`, optional workspace/repository UUIDs, and optional
   `Idempotency-Key` to `/api/projects`. A retry cannot silently change the
   selected play style.
4. `submit_project_creation_preflight_feedback` accepts that same complete
   receipt, the three literal values `pass`, `fail`, or `not_assessed` for
   helpfulness, calibrated criticality, and factual grounding, plus a stable
   8-128 character idempotency key. For MCP it also requires literal
   `confirm_user_feedback=true`. The SDK takes the episode only from the
   trusted `agent_episode` SSE event and sends no tenant, company, project,
   user, execution, reward, rubric, or training fields.

For MCP, pass `preflight_project_creation`'s complete JSON as `receipt_json` to
`create_project_from_preflight`. Do not synthesize an execution ID, edit the embedded draft, answer the
preflight's `next_question` automatically, or treat preflight as permission to
create. Product Machine plans, inferred scope, and approval state are not
accepted by this create path.

Feedback is append-only and must reflect judgments the user actually supplied.
Never infer positive feedback from project creation, approval, acceptance, or
the absence of a complaint. A unanimous pass is a user preference/usefulness
signal for the governed evaluator; it is not independent factual proof or a
business-outcome claim. A `409` means the one decision already conflicts, and
a `422` can mean the neutral episode has not finished server evaluation yet;
the SDK surfaces both rather than turning either into success.

The equivalent preview Python API is:

```python
readiness = client.inspect_project_creation_world_ready(
    "Customer onboarding",
    "Automate the handoff after Closed Won.",
    play_style="proactive_copilot",
)
if not readiness["ready"]:
    raise RuntimeError(readiness["next_action"]["label"])

print(readiness["game_start"]["win_condition"])
print(readiness["game_start"]["first_mission"])

campaign = client.inspect_project_game_campaign(
    project={"id": "project-id", "name": "Customer onboarding"},
    plan={"game_start": readiness["game_start"]},
    business_cockpit={},
)
print(campaign["current_mission"])
print(campaign["mission_briefing"])
print(campaign["game_checkpoint"])
print(campaign["campaign_map"][0]["capability_route"])
print(campaign["skill_lab"]["tournament"])

receipt = client.preflight_project_creation(
    "Customer onboarding",
    "Automate the handoff after Closed Won.",
)

# Present receipt.preflight.next_question to the user when present. A separate
# explicit user decision is required before this call.
project = client.create_project_from_preflight(
    receipt,
    confirm_create=True,
    play_style="proactive_copilot",
    idempotency_key="create-customer-onboarding-v1",
)

# Canonical state comes from the authenticated server, not the local preview.
snapshot = client.get_project_game_snapshot(project["id"])
print(snapshot["campaign"]["current_phase"])
print(snapshot["wealth"])
print(snapshot["mission"])
print(snapshot["authority"])

# Only after the user explicitly judges each dimension. This call is never
# triggered by create_project_from_preflight.
feedback = client.submit_project_creation_preflight_feedback(
    receipt,
    helpfulness="pass",
    calibrated_criticality="pass",
    factual_grounding="not_assessed",
    idempotency_key="customer-onboarding-review-feedback-v1",
)
```

`ProjectCreationDraft`, `ProjectCreationPreflight`,
`ProjectCreationPreflightReceipt`, `ProjectCreationPreflightError`,
`ProjectPreflightFeedbackDimensions`, and
`ProjectPreflightSemanticFeedbackReceipt` are public typed contracts. The
async client exposes the same network methods; await them. Its explicitly
offline `inspect_project_game_campaign` preview remains synchronous.

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
The compact profile does not expose generic `invoke_tool`, so it cannot perform
a direct live connector write. Generic connector invocation on the trusted full
local profile follows the same policy for repo, workflow, and deployment writes
such as `github.create_repository`,
`github.create_pull_request`, `github.trigger_workflow`, and
`github.create_deployment_status`.
Every direct generated connector operation and generic `invoke_tool` call also
requires the exact governed custody envelope: authenticated Project UUID,
correlation `project_ref`, project-bound `connector_account_ref`, stable
business-action idempotency key, and claimed effect for server verification.
Missing custody returns `governed_connector_context_required`; writes still
pause for a Spring-owned approval and never fall back to legacy/default routing.
Only operations in Spring's versioned reviewed effect catalog are dispatchable;
unknown or unreviewed generated Tools remain fail-closed as WRITE until their
provider contract is audited.
Full-profile generated tools inherit the same guard, including generated
`coding_*` domain actions and generated `github_*` repo/PR/deployment tools.
Page Builder keeps a pure design-session escape hatch with
`force_page_builder=true`, but project-like page, portal, app, SOP, workflow, or
GitHub-backed site builds start in the consulting workflow first.
Direct `code_workspace_chat` calls follow the same front-door rule for explicit
custom-agent/SOP/project-build prompts, while ordinary bounded bug fixes and
existing workspace tasks continue to the selected workspace.

### Hosted MCP for ChatGPT and Claude

Use the same hosted Streamable HTTP MCP endpoint when adding Lightbulb Partners
to ChatGPT Apps/Connectors or to Claude web/desktop as a remote MCP server:

```text
https://agents.lightbulbpartners.com/mcp/lightbulb
```

The endpoint advertises OAuth protected-resource metadata and sends users
through the Lightbulb login/onboarding flow when they are not already
authenticated. ChatGPT and Claude receive the same authenticated, scoped
Context Space and Dynamic Workflow authority. UI hosts do not run local
lifecycle hooks, so they should call `context_open` at session/task start,
`context_pack` before substantial reasoning, and `context_checkpoint` at stable
handoff or compaction boundaries. Every recalled result is explicitly framed
as untrusted historical evidence.

After auth, ChatGPT can call `start_consulting_project` to create
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

The MCP server can register a large non-private generated surface. Exact profile
counts and their source digests are generated in
`../api-specs/lightbulb.capability-inventory.v1.json`; documentation does not
maintain a second count. Most hosts should use the adaptive four-tool surface.
When a flat advanced catalog is required, set `LIGHTBULB_MCP_NAMESPACES` to
scope the generated tools:

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

Valid namespace tags include all 18 domains (`finance`, `intuit`, `crm`, `legal`, `engineering`, `content`, `it_ops`, `commerce`, `product`, `hr`, `coding`, `document_intelligence`, `solver`, `customer_success`, `procurement`, `gtm`, `grc`, `smarthome`) and every connector prefix (`gmail`, `microsoft`, `teams`, `calendar`, `docs`, `drive`, `sheets`, `slides`, `notion`, `slack`, `jira`, `github`, `salesforce`, `hubspot`, `shopify`, `square`, `stripe`, `xero`, `quickbooks`, `clio`, `smokeball`, `monday`, `excel`, `iam`, `ecommerce`, `tasks`, `tickets`, `notifications`). Hand-written control-plane tools (whoami, search_documents, dispatch_domain_agent, etc.) always register regardless.

## Python SDK

The package ships versioned Connector Execution, executable primitive, and
custom project contracts plus the platform client used by MCP. Those runtime
contracts follow SemVer beginning in 0.14. The broad endpoint client remains
beta, so pin a minor version and review release notes before upgrading.

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

### Company runtime: execution bridge, workers, simulator (0.17.0+)

```python
from lightbulb import (
    LightbulbClient, compile_company_operating_blueprint, compile_workforce,
    standard_roster, plan_dispatch, simulate_company, standard_scenario,
    engine_approval_request, bind_approval, command_with_approval,
)

plan = compile_company_operating_blueprint("b2b_saas")
workforce = compile_workforce(plan, standard_roster("b2b_saas"))   # workers fit inside envelopes
result = simulate_company(plan, standard_scenario("steady_state"))  # deterministic, sealed

# An engine rejected a transition with APPROVAL_REQUIRED: bind a human decision to it.
request = engine_approval_request(rejected, command, engine="company_operating_system",
                                  entity_ref="period-1", plan_digest=plan.plan_digest,
                                  summary="Shift 20% to SaaS", description="...", risk_level=6)
task = client.request_engine_transition_approval(request)
binding = bind_approval(client.get_approval(task["id"]), request)   # only if APPROVED and bound
reissued = command_with_approval(binding, command, state=state, occurred_at=now)
```

### Company engines and formation (0.16.0+)

Four company-engine packs sit on one replay-fenced core: the growth engine,
the pipeline engine, the SaaS operating engine, and the company operating
system that binds engines to budget envelopes, a period cadence, and typed
`signals.*` routes. Every primitive is read-only and returns `PREVIEW`; Spring
authorizes publishing, sending, deploying, spending, and reallocation.

```python
from lightbulb import LightbulbClient, compile_company_operating_blueprint

plan = compile_company_operating_blueprint("b2b_saas", {"name": "Maple Analytics"})
plan.envelopes            # per-engine budget and dispatch cadence
plan.signal_routes        # typed cross-loop signals and their consumers
plan.formation            # the guided formation request preview (CA)

client = LightbulbClient("https://agents.lightbulbpartners.com", auth=auth)
formed = client.create_company(name="Maple Analytics", country="Canada", industry="Software")
formed.company_id, formed.region, formed.workspace_ready
```

`create_company` is available in Australia and Canada only (`AU`/`Australia`,
`CA`/`Canada`); any other country is rejected before a request is made. The
tenant comes from the credential, never from the caller.

### Accounting control evaluators

Two deterministic, read-only finance primitives evaluate accounting packages
without changing a ledger:

- `finance.evaluate_journal_entry_controls` checks double-entry balance,
  company/chart/currency/period scope, evidence freshness, segregation of
  duties, approval state, and required control gates.
- `finance.evaluate_period_close_readiness` checks the trial balance, required
  reconciliations, consolidation entity packages, currency translation,
  intercompany matching, eliminations, evidence, and approval state.

```python
from lightbulb import (
    JournalEntryControlInput,
    evaluate_journal_entry_controls,
)

inputs = JournalEntryControlInput.model_validate(accounting_control_packet)
evaluation = evaluate_journal_entry_controls(inputs)
print(evaluation.disposition)       # blocked, indeterminate, or ready
print(evaluation.operation_digest)  # content-bound operation input
print(evaluation.evidence_digest)   # ordered evidence lineage
assert evaluation.posting_authorized is False
```

The typed results always keep `posting_authorized=False` or
`close_authorized=False`, including a `ready` result. The SDK evaluates the
supplied snapshot and carries operation/evidence digests; execution through the
primitive runtime also emits a completed read receipt with evidence lineage.
Spring remains the authority for tenant/company scope, persistence, RBAC,
approvals, audit, posting, and period close.

### Stripe-to-ledger reconciliation

The typed reconciliation client reuses Spring's authenticated Stripe and
QuickBooks/Xero path. The SDK validates the request and response; Spring owns
company scope, connector selection and credentials, execution, persistence,
and run IDs.

```python
from lightbulb import FinanceReconciliationRequest

run = client.run_finance_reconciliation(
    FinanceReconciliationRequest(
        ledger_provider="auto",
        simulation_mode="auto",
        include_details=True,
    ),
    company_id="00000000-0000-0000-0000-000000000003",
)
print(run.run_id, run.authority_level, run.control_summary.match_rate)

recent = client.list_finance_reconciliation_runs(
    company_id="00000000-0000-0000-0000-000000000003",
    limit=25,
)
stored = client.get_finance_reconciliation_run(
    str(recent[0].run_id),
    company_id="00000000-0000-0000-0000-000000000003",
)
```

`simulation_mode="auto"` preserves Spring's connector-aware fallback,
`"simulation"` forces synthetic scenario-grade data, and `"live"` fails if
the required live connections are unavailable. Live results remain
`controlled_partial` unless the server explicitly supplies stronger authority;
provider acceptance alone is not promoted. The same method names are available
through `AsyncLightbulbClient`'s managed async bridge.

The production-dark journal-to-close lighthouse uses the separate
`finance.reconcile_stripe_settlements` Business Process Primitive. Its
deterministic candidate accepts a Spring-custodied complete-month QuickBooks or
Xero General Ledger plus Stripe settlement movements. V1892 provides the
distinct internal Spring/PostgreSQL materialization and readback boundary: it
independently reproduces the candidate and can persist immutable automatic-match
evidence, review proposals, and exception cases. This does not authorize
proposal acceptance, exception disposition, journal creation or posting,
period transition, close, connector certification, or production execution;
the hosted-worker gate remains disabled.

### Investment and trading agent

The investment facade exposes the complete research, feature, AutoML,
Prime/Puffer, portfolio, broker-readiness, paper-observation, and cash-request
workflow surface without accepting tenant or user IDs from the caller. Scope
continues to come from the authenticated client and selected company.

```python
from lightbulb import InvestmentAgentClient

investment = InvestmentAgentClient(client)

features = investment.feature_engineering({
    "symbols": ["AAPL", "MSFT"],
    "feature_config": {"features": ["return_5d", "volatility_20d"]},
})
evidence = investment.alpha_discovery({
    "symbols": ["AAPL", "MSFT"],
    "feature_config": {"features": ["return_5d", "volatility_20d"]},
    "label_definition": {"target": "forward_return", "horizon_days": 5},
    "validation_plan": {"split": "purged_walk_forward", "embargo_days": 5},
})
training_plan = investment.plan_alpha_training({"strategy_id": "slow-alpha-v1"})
```

Effect-capable requests fail locally unless the caller supplies a granular
`InvestmentEffectIntent`. This is only a deliberate SDK acknowledgement; it is
never forwarded as approval and cannot bypass server-side RBAC, institutional
risk certificates, commercial admission, broker idempotency, or cash controls.
`plan_alpha_training()` and `stage_cash_movement()` always force their execution
flags off. Use `AsyncInvestmentAgentClient` for native async dispatch.

The same 20 actions are generated as direct MCP tools under the `finance`
namespace. Set `LIGHTBULB_MCP_NAMESPACES=finance` to expose them without loading
unrelated connector namespaces.

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

Hot paths use native `httpx.AsyncClient` I/O. Every remaining public sync-client
operation is awaitable through a managed `asyncio.to_thread` bridge, and sync
generators are adapted for `async for`. Verify releases with:

```python
assert AsyncLightbulbClient.async_parity_report()["parity_percent"] == 100.0
```

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
- **Project AutoResearch:** `ProjectAutoResearchClient` for a typed,
  company-pinned paid-run lifecycle
- **Project learning runs:** `ProjectLearningClient` for selected-company
  inspect, prepare, and admission calls with scope/contract/request-digest
  validation over authenticated Spring responses
- **Shopify storefront planning:** `plan_shopify_storefront` and
  `PlanShopifyStorefrontPrimitive` for deterministic, proposal-only plans
- **Omnichannel launch planning:** `plan_omnichannel_product_launch`,
  `compile_product_launch_portfolio`, `create_product_launch_evaluation_loop`,
  and
  `evaluate_product_launch_iteration` for proposal compilation, bounded
  portfolio partitioning, control-state seeding, and verified post-launch
  decisions across Shopify, CRM, and social surfaces; these APIs do not execute
  a live connector loop
- **Connectors:** `SlackClient`, `JiraClient`, `BambooHRClient`, `GreenhouseClient`, `MondayClient` (thin `invoke_tool` / HR-live helpers)

Project AutoResearch accepts only a project ID (or run ID for status/cancel).
Spring derives the objective, connected data, provider, immutable budgets,
tenant, company, and actor from authenticated state. Starting a paid run and
cancelling one both require literal caller confirmation; the SDK serializes
those confirmations into the request and Spring verifies them alongside the
actor's `automl.experiments.execute` permission:

```python
from lightbulb import ProjectAutoResearchClient

research = ProjectAutoResearchClient(client)  # client has a selected company
started = research.start(
    project_id,
    idempotency_key="research-q3-market-1",
    confirm_paid_run=True,
)
current = research.status(started.run_id)
cancelled = research.cancel(
    started.run_id,
    reason="Superseded by the approved brief",
    confirm_cancel=True,
)
```

`ProjectLearningClient.list()` (also exposed as `inspect()`) reads the latest
persisted receipt snapshot; it is not live worker telemetry. `prepare()` binds
an immutable training dataset to a queued durable run, and `admit()` reserves
capacity and makes that run eligible for a fenced worker claim. Neither method
executes training, claims a worker, promotes a model, or grants production
authority. The returned prepared/admitted models are sanitized local summaries,
not authenticated receipt containers, and cannot be passed to
`project_learning_receipt_to_workflow_event(...)`.

Normalized learning receipts and ledgers expose `actor_binding`. It is
`verified_against_auth_strategy` only when the configured auth strategy exposes
a user ID and the returned receipt owner matches it. JWT sessions, empty
ledgers, and authorized colleague-owned ledger rows report
`spring_enforced_not_locally_reverified`: Spring remains the RBAC and actor
authority, and the SDK does not add a hidden `whoami` request.

```python
from lightbulb import (
    LearningCapacityAdmission,
    ProjectLearningClient,
    ProjectLearningRunAdmissionInput,
    ProjectLearningRunPrepareInput,
)

learning = ProjectLearningClient(client)  # selected company is mandatory
prepared = learning.prepare(
    project_id,
    ProjectLearningRunPrepareInput(
        training_pack_receipt_id=training_pack_receipt_id,
        primary_metric="validation_accuracy",
        runtime="spark_feature_matrix",
        confirmation="publish_dataset_and_create_queued_learning_run",
        idempotency_key="feature-matrix-2026-07-30",
    ),
)
admitted = learning.admit(
    project_id,
    prepared.learning_run_id,
    ProjectLearningRunAdmissionInput(
        runtime="spark_feature_matrix",
        capacity_admission=LearningCapacityAdmission(
            schema="lightbulb.learning-capacity-plan.v1",
            decision_id="capacity-decision-42",
            runtime="spark",
            admission="admit",
            target_instances=2,
            expires_at=capacity_expires_at,
            secrets_redacted=True,
        ),
        confirmation="reserve_budget_and_admit_durable_learning_run",
    ),
)
```

The Shopify primitive converts a typed storefront brief into ordered draft
product, collection, and page proposals. A coding agent may turn a natural
language prompt into that typed input, but the primitive itself makes zero
connector calls. It does not generate/upload a custom theme, mutate a live
store, deploy, or publish. Default product prices are preserved; additional
variant creation remains an explicit capability gap. The requested currency is
also retained in the plan, but materialization must read and verify the
connected shop currency before applying prices.

```python
from lightbulb import plan_shopify_storefront

plan = plan_shopify_storefront(
    {
        "brief": {
            "storefront_name": "North Star Goods",
            "brand_summary": "Practical tools for focused teams.",
            "target_audience": "Professional-services teams.",
            "business_goal": "Prepare a storefront for human review.",
            "default_currency": "CAD",
            "locale": "en-CA",
        },
        "products": [
            {
                "product_ref": "focus-kit",
                "title": "Focus Kit",
                "price": {"amount": "49.00", "currency": "CAD"},
            }
        ],
        "collection": {
            "collection_ref": "featured",
            "title": "Featured",
            "product_refs": ["focus-kit"],
        },
        "pages": [],
        "existing_theme": {
            "strategy": "retain_existing",
            "reference_name": "Current storefront theme",
        },
    }
)
assert plan.live_store_changed is False
```

### Omnichannel product-launch proposals and governed control-state seeds

`gtm.plan_omnichannel_product_launch` turns one reviewed product, sales
campaign, social campaign, and set of normalized analytics snapshots into a
deterministic cross-surface proposal graph. The Shopify path is ordered
`DRAFT` create -> `ACTIVE` update -> explicit `shopify.publish_product` for the
brief's `publication_ids` -> `gtm.verify_landing_readiness`. Analytics-ranked
social proposals remain blocked behind that landing-readiness evidence gate.
HubSpot campaign creation is a domain action that creates a container only,
and every proposed write has a content-bound approval unit. Compilation makes
zero connector or domain calls.

```python
from lightbulb import (
    PlanOmnichannelProductLaunchPrimitive,
    create_product_launch_evaluation_loop,
    plan_omnichannel_product_launch,
)

launch = plan_omnichannel_product_launch(
    PlanOmnichannelProductLaunchPrimitive.example_inputs
)
assert launch.proposal_only is True
assert launch.effect_boundary.writes_executed == 0

operations = {operation.capability: operation for operation in launch.operations}
draft = operations["ecommerce.create_product"]
activation = operations["ecommerce.update_product"]
publication = operations["shopify.publish_product"]
readiness = operations["gtm.verify_landing_readiness"]
assert draft.arguments.status == "DRAFT"
assert activation.arguments.status == "ACTIVE"
assert publication.depends_on == (activation.operation_id,)
assert readiness.depends_on == (publication.operation_id,)

provider_inputs = activation.connector_inputs({
    draft.operation_id: {"product_id": "gid://shopify/Product/123"},
})
assert provider_inputs == {
    "status": "ACTIVE",
    "product_id": "gid://shopify/Product/123",
}

# The control-state seed is intentionally stricter than proposal compilation.
# Re-plan with host-HMAC snapshots, destination bindings, and exact authority.
host_bound_launch = plan_omnichannel_product_launch(
    reviewed_launch_input,
    verified_scope=authenticated_dynamic_workflow_scope,
    scope_keyring=host_receipt_keyring,
    connector_account_bindings=host_account_bindings,
)
loop = create_product_launch_evaluation_loop(
    host_bound_launch,
    scope=authenticated_dynamic_workflow_scope,
    scope_keyring=host_receipt_keyring,
    created_at=workflow_start_time,
)
assert loop.limits.max_iterations <= 4
```

`ProductLaunchOperation.connector_inputs(...)` removes internal SDK
discriminators and resolves declared output-to-input bindings before a host
dispatches an approved connector or domain operation. Evidence-gate operations
are not connector calls and reject this conversion.

Trusted hosts can execute the complete Shopify storefront tracer with
`run_shopify_product_launch(...)`: DRAFT creation, ACTIVE transition, explicit
publication IDs, then a read-only live-landing readiness gate. Preview mode
does not query either the connector executor or readiness reader. Apply mode
stops at the first missing approval, blocked operation, failed operation, or
unproven read and can be resumed with no caller-owned checkpoint. Earlier
writes replay through stable per-operation idempotency keys and their outputs
and provenance are verified again before an output binding reaches the next
operation.

`bind_product_launch_operation_approval(...)` binds a different opaque
platform approval reference and platform-verified approval receipt digest to
each exact write's plan, scope, account, operation digest, and approval unit,
then HMAC-seals the grant. The older
`bind_shopify_draft_product_approval(...)` convenience wrapper remains for the
single-DRAFT API. Spring remains authoritative for ApprovalTask approval and
consumption.

A nominal connector `COMPLETED` status is deliberately insufficient. The
executor must return `ConnectorExecutionProvenance` containing the immutable
server request and receipt digests, authenticated project UUID, Tool version,
actual connector account and Tenant Connector, exact lowercase route digest,
approval reference and receipt digest, journal reference, authoritative
completion time, and provider response digest. Creation output must prove `DRAFT`;
activation output must prove the same product is `ACTIVE`; the native
publication response must then prove the same product, `success=true`, and
exactly the signed publication IDs. ACTIVE remains dependency-proven by the
immediately preceding activation receipt because Shopify's publication response
does not repeat product status.
Missing, contradictory, or mismatched provenance produces a failed result and
no launch receipt.

The final gate calls `ConnectorLandingReadinessVerifier` (or another trusted
`LandingReadinessVerifier`) with a sealed `LandingReadinessRequest`. The
connector-backed implementation invokes the governed
`shopify.verify_product_readiness` read and verifies its exact provenance and
closed payload. Its typed observation must match the exact request,
project, connector account, URL, product ID/title, price, currency, publication
IDs, and post-publication time, and must prove page reachability, product
visibility, price/currency agreement, and checkout availability. Missing or
generic connector output cannot fabricate readiness. CRM and social operations
are never dispatched by this runner and remain held until that receipt exists.
After readiness, the result exposes only the next graph-eligible downstream
operation: a configured CRM campaign becomes eligible first, while social
publication remains held until that campaign also has evidence. Even after
readiness, `omnichannel_launch_completed` remains false.

```python
from lightbulb import (
    bind_product_launch_operation_approval,
    run_shopify_product_launch,
)

write_operations = [
    operation
    for operation in host_bound_launch.operations
    if operation.capability in {
        "ecommerce.create_product",
        "ecommerce.update_product",
        "shopify.publish_product",
    }
]
grants = [
    bind_product_launch_operation_approval(
        host_bound_launch,
        scope=authenticated_dynamic_workflow_scope,
        scope_keyring=host_receipt_keyring,
        operation_id=operation.operation_id,
        approval_ref=approved_platform_tasks[operation.operation_id].ref,
        approval_receipt_digest=(
            approved_platform_tasks[operation.operation_id].receipt_sha256
        ),
    )
    for operation in write_operations
]
storefront_result = run_shopify_product_launch(
    host_bound_launch,
    scope=authenticated_dynamic_workflow_scope,
    scope_keyring=host_receipt_keyring,
    execution_scope=authenticated_project_execution_scope,
    executor=account_bound_governed_executor,
    run_ref="focus-kit-launch-1",
    preview_only=False,
    approval_grants=grants,
    readiness_verifier=trusted_live_storefront_reader,
)
assert storefront_result.storefront_ready is True
assert storefront_result.omnichannel_launch_completed is False
```

Hosted completion requires the Spring authority to route the exact signed
`connector_account_ref` and return the complete custody envelope. Any older or
partially deployed authority fails closed. The in-memory adapter can exercise
the contract in tests and sandbox host implementations without weakening
production custody. The SDK never infers readiness from write success.

Discover the exact account alias from the authenticated project instead of
guessing a default:

```python
bound_accounts = client.list_project_connector_accounts(
    project_id,
    company_id=company_id,
)
shopify_account = next(
    row for row in bound_accounts if row["provider"] == "shopify"
)
connector_account_ref = shopify_account["connectorAccountRef"]
```

`list_available_project_connector_accounts(project_id, provider)` mirrors the
trusted account-selector read for a binding UI. Both client methods delegate
tenant/company/project access and RBAC enforcement to Spring. For agent use,
the read-only MCP tool `list_project_connector_accounts` emits a compact
whitelist containing only provider, alias, account label, target resource, and
status; it never returns OAuth connection IDs or credentials. Its sanitized
rows are sorted deterministically and paged with bounded `offset`/`limit`
arguments (maximum 40 per page). Continue with the returned `next_offset` while
`has_more` is true; `total_count` is computed after sanitization and the optional
provider filter, so fleets larger than 40 accounts remain completely discoverable
without overlapping pages.

Resolve the execution coordinates from Spring rather than reading platform
tables or guessing a Tool version:

```python
from uuid import UUID

readiness_descriptor = client.get_project_connector_route_descriptor(
    project_id,
    connector_account_ref,
    "shopify.verify_product_readiness",
    company_id=company_id,
)
analytics_descriptor = client.get_project_connector_route_descriptor(
    project_id,
    connector_account_ref,
    "shopify.analytics_query",
    company_id=company_id,
)

trusted_live_storefront_reader = ConnectorLandingReadinessVerifier(
    account_bound_governed_executor,
    execution_scope=authenticated_project_execution_scope,
    tenant_connector_id=UUID(readiness_descriptor["tenantConnectorId"]),
    expected_tool_version=readiness_descriptor["toolVersion"],
    expected_route_digest=readiness_descriptor["routeDigest"],
)

storefront_observation_route = StorefrontObservationRoute(
    provider="shopify",
    connector_account_ref=connector_account_ref,
    tenant_connector_id=UUID(analytics_descriptor["tenantConnectorId"]),
    expected_tool_version=analytics_descriptor["toolVersion"],
    expected_route_digest=analytics_descriptor["routeDigest"],
)
```

`AsyncLightbulbClient.get_project_connector_route_descriptor(...)` provides the
same read through the managed async bridge. The authenticated endpoint resolves
the same project/account/Tool authority used for governed execution and returns
only `projectId`, `connectorAccountRef`, optional `targetResourceRef`, `toolName`,
`toolVersion`, `tenantConnectorId`, and `routeDigest`. The read-only MCP tool
`get_project_connector_route_descriptor` exposes a snake-case allowlist of those
fields and discards OAuth IDs, credentials, connector configuration, and any
unexpected response fields. Pass its `route_digest` back as expected route
custody for that exact Tool; never infer, synthesize, or reuse one Tool's route
digest for another Tool. Discovery is available only when the
governed connector boundary is enabled: authentication/scope failures remain
401/403, inactive or missing routes remain 404, ambiguous/drifted custody
remains 409, and a Tool without a server-owned effect classification remains
422. Hosts must surface those failures rather than falling back to database
lookups or a generic connector adapter.

The verified analytics path requires every normalized snapshot to name its
`connector_account_ref` and evidence digest. After validating the underlying
connector receipt, the trusted host calls
`mint_product_launch_analytics_snapshot(...)`; its HMAC covers the complete
provider/account/window/metrics/evidence payload and the exact authenticated
scope. The host separately seals every Shopify, CRM, and social destination
with `mint_product_launch_connector_account_binding(...)`. Pass the complete
set as `connector_account_bindings=` with that same `verified_scope=` and
`scope_keyring=` when planning. Merely copying a visible scope digest, account
ref, or evidence digest cannot produce a trusted plan. The host-bound plan is
itself HMAC-sealed, so reconstructing or editing its graph, policy, accounts, or
receipt obligations invalidates trusted loop admission.

For a host-HMAC-bound plan, a trusted host can mint one
`mint_product_launch_receipt(...)` per required criterion after it validates
the underlying live artifacts. Each receipt is HMAC-sealed and bound to the
exact scope, immutable plan digest, and, where applicable, operation ID and
digest. A write receipt additionally binds the exact `approval_unit` and a
host-verified approval receipt digest; non-write receipts cannot carry one.
Receipts are also bound to one loop `run_ref` and iteration.
`verify_product_launch_receipts(...)` requires the complete exact
receipt set, fails closed on binding, timing, freshness, sample, or HMAC
mismatches, and returns the `EvidenceRef` values that may be admitted to
Dynamic Workflow. Performance receipts carry an explicit observation window;
its duration must meet `measurement_window_hours`, so an immediate metric sample
cannot prematurely satisfy a multi-day policy, and its start must follow every
required operation and landing-readiness gate completion.

`evaluate_product_launch_iteration(...)` first performs that complete receipt
verification, then deterministically compares the verified performance metric
with the immutable target. It returns `target_met`, `revise_plan`, or
`iteration_limit_reached` plus the next iteration when applicable. The returned
evaluation is host-HMAC sealed; later iterations require that exact prior
`revise_plan` evaluation and newly attested evidence after its timestamp. KPI
comparison is produced by the evaluator rather than circularly required as an
input receipt. Replaying one receipt set produces the same signed evaluation
and deterministic `commitment_ref`; a durable host must accept only one digest
for each commitment. It does not revise a plan, grant a new approval,
materialize a connector, or schedule its own next run.

`create_product_launch_evaluation_loop(...)` seeds the existing generic
planner-builder-evaluator state machine with finite limits and receipt-kind
acceptance criteria. It rejects caller-unverified plans; pass `scope_keyring=`
with a host-HMAC-bound plan so the seed rechecks the exact scope. The seed still
does not materialize connectors,
validate approvals, mint or verify receipts on its own, schedule the
observation-window event, fetch post-launch analytics, or automatically revise
a campaign.

`compile_product_launch_portfolio(...)` partitions proposal records into at
most 12 launches and at most 100 estimated initial operations per shard. The
estimate covers only the initial graph. Serialized budgets are 256 KiB per job,
4 MiB per shard, and 64 MiB per portfolio. Distinct supplied
`scope_fingerprint` plus `project_ref` pairs remain separate, but those values
are partition keys rather than authority; a trusted host must derive or verify
them against the active authenticated scope before dispatch. The 10,000-launch
limit remains a count-validation ceiling, and byte budgets can reject a
portfolio earlier. Compilation is eager and in-memory and does not enforce
connector rate limits, spend limits, retries, or approvals. It never launches
stores, products, or campaigns.

The plan also records current execution gaps. The generated SDK/MCP connector
surface now describes reviewed Facebook, Instagram, and LinkedIn publish
operations, while paid-ad budget mutation and several broader ecommerce/social
operations remain unavailable. Instagram native scheduling is unsupported;
LinkedIn's current schedule route publishes immediately; and no typed action
authors a complete HubSpot sales sequence. Agents can therefore use the plan
without overstating what was materialized.

The SDK also ships the post-action observation rail. `ObservationRuntime`
schedules a full measurement window after the latest verified operation,
executes an exact-account governed `shopify.analytics_query` or
`google_analytics.fetch_metrics` read, normalizes the closed provider envelope,
and HMAC-seals its provenance. Connector schedules require the exact
`expected_route_digest` returned by descriptor discovery; the digest is sealed
inside `ObservationJobSpec.job_digest` and must equal the completed execution's
`provenance.route_digest`. Host-only observations omit route custody entirely.
`schedule_storefront_phase(...)` consumes exactly
the four real create, activate, publish, and landing-readiness receipts and
produces a distinct `StorefrontPhaseEvaluation`; that artifact reports only the
Shopify storefront phase and never claims omnichannel completion. The original
`schedule_gtm(...)` path remains closed-world and invokes the full launch
evaluator only after CRM, social, scope, and storefront receipts all exist. A
`revise_plan` verdict emits one idempotent phase-appropriate next-iteration
event; it never grants new write approvals itself.
`JsonFileObservationArtifactRepository` and `ObservationWorker` provide a
private, restart-safe single-host reference implementation. A production
application must still start that worker (or an equivalent queue/cron consumer)
and supply its authenticated scope partition; merely creating a checkpoint does
not wake a process.

`LightbulbSoftwareFactoryRuntime.run_storefront_launch(...)` is the durable
execution-to-learning join. After the exact storefront runner returns
`storefront_ready`, it immediately stores the content-addressed storefront
observation job before returning. Preview, approval waits, failures, and
unproven readiness schedule nothing. The same facade can drive the bounded
worker, but the embedding service must still start that process.

The remaining omnichannel work is narrower: CRM campaign materialization and
the remaining social operations must consume the readiness receipt, and every
new iteration still requires fresh approvals. The Shopify storefront tracer
and its Shopify-or-GA evaluation path are executable through the shared
governed connector rail; the SDK does not claim that a real store changed
unless Spring returns exact route and execution provenance from a connected
sandbox or production account.

### Governed CRM communication engine

`communication.plan_crm_conversation_turn` is the proposal-only, Gmail-first
entry point for the communication engine. The sealed execution, observation,
replay, and CRM evidence rail also has closed provider adapters for Outlook,
Slack, and Teams; those adapters do not change the primitive's current Gmail
capability plan. The primitive accepts opaque CRM conversation, contact,
inbound-message, connector-account, and optional Growth artifact references
plus their content digests. It stores no recipient address, subject, message
body, or provider payload, invokes no connector, and returns an immutable plan
for these phases:

1. resolve the canonical CRM context and exact Gmail route;
2. evaluate consent, suppression, quiet hours, and frequency policy;
3. draft private content outside durable workflow state;
4. bind human approval to the exact content, audience, thread, route, and time;
5. atomically reserve the contact slot;
6. dispatch one governed in-thread Gmail message;
7. observe a verified provider reply;
8. classify it deterministically and propose review-only next actions; and
9. append idempotent outbound, inbound, and reply touchpoints to CRM.

```python
from lightbulb import PlanCrmConversationTurnInput, plan_crm_conversation_turn

turn = plan_crm_conversation_turn(
    PlanCrmConversationTurnInput(
        analysis_as_of="2026-08-19T16:00:00Z",
        plan_ref="acme-reply-turn-1",
        objective_ref="crm-objective-acme-reply",
        objective_digest="c" * 64,
        turn_kind="reply_to_inbound",
        purpose="sales",
        crm_conversation_ref="crm-conversation-acme",
        crm_contact_ref="crm-contact-acme",
        source_message_ref="crm-message-42",
        source_message_digest="a" * 64,
        connector_account_ref="gmail-sales-primary",
    )
)

assert turn.live_systems_changed is False
assert turn.durable_private_content_allowed is False
assert "gmail.send_email" in turn.required_capabilities
assert "gmail.get_thread" in turn.required_capabilities
```

Trusted hosts mint the sealed context, party, endpoint, thread, draft, contact
policy, approval, reservation, provider-event, and CRM receipt artifacts with a
`CommunicationScopeKeyRing`. `materialize_gmail_communication_turn(...)`
revalidates exact tenant/company/user/project UUID custody before I/O. Preview
makes zero connector calls. An approved send consumes its single-use contact
reservation immediately before connector execution, requires Spring provenance
for the exact Tool version, Tenant Connector, account alias, project, route,
request, approval, and completion time. The approval binds the exact thread
digest, version, state, participants, and RFC parent Message-ID; Gmail receives
`thread_id` and `parent_message_id` together. Contact slots are keyed to the
company, canonical contact/address, and contact window, so two agents or
projects cannot independently win the same outreach slot.

`gmail.get_thread` is a real reviewed READ Tool, not a catalog placeholder. Its
generated MCP function requires project UUID/ref, connector-account alias, and
`effect="read"`; it intentionally exposes no idempotency key. Spring returns at
most ten bounded messages only on the fresh response while durable journals and
provider audits retain commitments and counts. `GmailCommunicationRuntime`
is fed by `GmailCommunicationObserver.poll_once(...)`, which performs one
fresh, non-replayable read through a separately attested read route. The
observer requires the read and sealed write routes to resolve to the same
project, connector account, and Tenant Connector. It derives the outbound RFC
Message-ID from the exact sent Gmail message in that fresh response, then
accepts a reply only when `In-Reply-To` or `References` names that parent. It
fails closed on truncation or ambiguity and persists no raw body, address,
message ID, or provider payload. The runtime then admits only a host-HMAC event
with verified authenticity, the exact
account/route/thread/outbound-message bindings, post-dispatch timing, and
matching transient content commitments. It deduplicates provider events and
messages across retries, records three content-free CRM touchpoint receipts,
and emits a `CommunicationOutcomeObservation` with
`causal_claim_ready=False`.

Provider truth is deliberately layered. `materialize_gmail_communication_turn`
marks a write complete only after validating Gmail's exact message and thread
response, but "complete" does not mean SMTP delivery, inbox placement, an open,
or a human read. For Outlook, `materialize_outlook_communication_turn` treats
Graph `accepted=true` as provider acceptance; only `sentItemsObserved=true`
upgrades that result to completed provider observation. A later bounded
`OutlookCommunicationObserver` read can independently establish that exact
outbound object and a threaded reply. It still does not prove transport
delivery or a human read.

`materialize_slack_communication_turn` and
`materialize_teams_communication_turn` validate one exact provider-created
message object. `SlackCommunicationObserver` and `TeamsCommunicationObserver`
then use separately attested, bounded thread reads to establish provider
observation and an inbound turn. Their public observation result fixes both
`delivery_claimed` and `human_read_claimed` to `False`. Across all four
providers, connector acceptance, provider observation, transport delivery, and
human reading are distinct facts; the SDK never upgrades one into another.

Reply interpretation never performs a business effect. Explicit unsubscribe,
legal/security, payment-dispute, meeting, positive, negative, and general
language produce deterministic scores and proposed capabilities, all marked for
human review. CRM remains the canonical customer timeline; this SDK does not
create another conversation database. The optional `GrowthSourceBinding` is
only an opaque, reviewed input binding. Funnel measurement, experiments,
learnings, transfer, and Growth re-planning remain owned by the Growth Engine.

The in-memory reservation, replay, and CRM sink implementations are reference
adapters for tests and single-process hosts. A production deployment still
needs configured durable custody adapters and a separately operated host
worker/poller for bounded observations; this public SDK surface does not claim
that a remote production worker is complete or start an autonomous scheduler.
Hosted Gmail, Outlook, Slack, and Teams execution remains behind Spring feature
flags that are off by default. Adding these APIs and tests changed no live
mailbox or channel.

### Ten-workflow contribution-profit flywheel

The SDK ships ten proposal-first workflows around the omnichannel launch. They
optimize contribution profit instead of revenue, clicks, or headline ROAS. The
shared ledger derives profit as gross sales minus discounts, refunds, COGS,
fulfillment, payment fees, incremental acquisition, and incremental service
costs.

| Order | Primitive | Profit job |
| --- | --- | --- |
| 1 | `finance.allocate_launch_portfolio_profit` | Attribute profit and issue bounded scale, hold, revise, or retire envelopes. |
| 2 | `product.discover_profitable_opportunities` | Rank product/segment/store pilots and cheapest valid kill tests. |
| 3 | `gtm.optimize_offer_price_and_margin` | Guard price, bundle, shipping, and discount experiments with margin floors. |
| 4 | `commerce.govern_inventory_and_fulfillment` | Gate launch and acquisition on stock, cash, lead time, and fulfillment capacity. |
| 5 | `commerce.optimize_storefront_conversion` | Plan previewable storefront experiments against profit per session. |
| 6 | `content.run_creative_experiment_factory` | Select channel-native creative using downstream profit and fatigue evidence. |
| 7 | `growth.allocate_incremental_acquisition` | Allocate only the next capped acquisition tranche with a stop-loss. |
| 8 | `crm.orchestrate_profit_aware_lifecycle` | Choose consent-safe next-best actions by expected profit per contact. |
| 9 | `commerce.recover_abandoned_revenue` | Recover checkout demand with the least costly valid intervention. |
| 10 | `customer_success.prevent_returns_and_expand_ltv` | Prevent avoidable harm/returns and grow profitable repeat purchase. |

Every primitive uses the same bounded economics engine but a different
code-owned blueprint: exact evidence sources, allowed action capabilities,
required KPIs, direction, handoffs, and connector-truth gaps. Candidate
economics are risk-adjusted for confidence, downside, and implementation cost.
The bounded global selector maximizes total risk-adjusted contribution profit;
capital efficiency and time-to-value are deterministic tie-breakers after the
profit objective, while dependencies, mutual exclusion, cash budget, and action
count remain hard constraints. Unverified evidence receives a configurable
confidence haircut. No workflow accepts arbitrary connector tools or effects.

```python
from lightbulb import (
    PROFIT_WORKFLOW_DEFINITIONS,
    compile_profit_flywheel,
    plan_profit_workflow,
    profit_workflow_example_inputs,
)

workflow_id = "commerce.recover_abandoned_revenue"
inputs = profit_workflow_example_inputs(workflow_id)
plan = plan_profit_workflow(workflow_id, inputs)

assert plan.effect_boundary.external_systems_changed is False
assert plan.effect_boundary.materialization_supported is False
assert all(action.dispatchable_by_planner is False for action in plan.actions)

# The manifest stores ten compact content-addressed nodes, not ten copied plans.
all_inputs = {
    workflow_id: profit_workflow_example_inputs(workflow_id)
    for workflow_id in (
        definition.workflow_id for definition in PROFIT_WORKFLOW_DEFINITIONS
    )
}
flywheel = compile_profit_flywheel(all_inputs)
assert len(flywheel.nodes) == 10
assert flywheel.external_workflow_refs == (
    "gtm.plan_omnichannel_product_launch",
)
assert flywheel.estimates_are_non_additive is True
```

The public primitive path remains deliberately caller-unverified. A trusted
host first verifies connector receipts and exact tenant/company/user/project
scope. It HMAC-seals each opaque account reference with
`mint_profit_connector_account_binding(...)`, seals account-scoped observations
with `mint_profit_metric_evidence(...)`, and re-plans with `verified_scope=` plus
`scope_keyring=`. The host-bound plan and every content-bound approval are then
scope-specific. After each exact action is approved and executes elsewhere,
`mint_profit_action_execution_receipt(...)` binds its provider/artifact receipt,
approval receipt (mandatory for writes), account, operation digest, plan, run,
and iteration. `mint_profit_outcome_evidence(...)` requires the complete action
receipt set and a measurement window that starts after every action completed.
`evaluate_profit_workflow_iteration(...)` then returns `target_met`,
`revise_plan`, or `iteration_limit_reached`. Later revisions require the prior
signed `revise_plan` evaluation and a new post-evaluation window. A durable host
must enforce one `commitment_ref`/outcome digest per plan/run/iteration.

The planner never dispatches its `intent_parameters`; they are business intent,
not connector arguments. For the closed connector subset, typed candidate
builders commit the exact payload digest and `run_profit_workflow_actions(...)`
preflights the complete graph before its first effect. It then executes in
dependency order through `materialize_profit_action(...)`, stops at the first
approval wait or failure, and resumes only from exact plan/run/iteration
receipts. Every write binds tenant, company, user, project UUID, project account
alias, Tool, arguments, approval receipt, idempotency identity, and Spring
execution provenance. Completed runs expose an observation-not-before time but
keep `causal_claim_ready=False` until `ObservationRuntime` evaluates the full
window.

The materializable adjacent subset now includes reviewed Shopify product
updates for offer/storefront optimization; Facebook, Instagram, and LinkedIn
creative cells; consent-safe Gmail lifecycle messages; and bounded Shopify
discount plus Gmail recovery graphs. Recovery shares the exact materializer and
provenance rail but the generic runner rejects it; use the recovery facade so a
fresh dispatch safety attestation cannot be bypassed. Use
`build_offer_product_update_candidate(...)`,
`build_creative_publish_candidate(...)`, or
`build_lifecycle_email_candidate(...)` to create the exact plan candidate.
`LightbulbSoftwareFactoryRuntime.run_profit_workflow(...)` joins a completed
offer, creative, or lifecycle action graph to its exact post-action observation
job. It schedules nothing for preview, approval waits, or failed effects.
Paid-ad budget mutation, a universal inventory mutation, and HubSpot sequence
authoring remain explicit gaps rather than simulated effects.

Abandoned-revenue recovery adds stricter business gates on top of that rail.
`RecoveryIngestionWorker` scans the exact governed Shopify account in at most
20-row cursor pages and at most 250 rows per run. It validates every page's
provenance and strict connector output, obtains short-lived host-HMAC
consent/inventory/frequency/economics facts, resolves email, recovery URL, and
code only transiently, and atomically checkpoints a scoped case and plan
without approving or dispatching writes. Hosts persist its returned
`next_cursor` to continue larger scans.

`mint_abandoned_recovery_case(...)` seals a privacy-minimized case; raw recipient,
recovery URL, and one-time discount code stay only at the execution boundary.
`plan_abandoned_revenue_recovery(...)` retains randomized holdouts and suppresses
unknown/withdrawn consent, exhausted frequency caps, expired or out-of-stock
checkouts, unprofitable outreach, and margin-eroding discounts. An eligible
treatment requires a fresh, short-lived
`mint_recovery_dispatch_attestation(...)` immediately before I/O; this
scope-HMAC proof rechecks consent, inventory, frequency count, case expiry, and
discount expiry. Live dispatch also requires a single-use transactional
`RecoveryContactReservationAuthority`, consumed only at the exact Gmail send;
the included in-memory authority is for tests and single-process hosts, while a
production host must supply durable atomic storage. It then runs an optional
one-use expiring discount before one approved Gmail message.
`schedule_abandoned_recovery_observation(...)` schedules a trusted
`host.checkout_recovery_snapshot`; its randomized-holdout ledger must cover all
targeted Shopify/Gmail accounts before the profit evaluator may report recovered
incremental contribution.

```python
from lightbulb import (
    LightbulbSoftwareFactoryRuntime,
    mint_recovery_dispatch_attestation,
    plan_abandoned_revenue_recovery,
)

recovery_plan = plan_abandoned_revenue_recovery(
    host_attested_case,
    resolved_secrets=execution_boundary_secrets,
    analysis_as_of=host_clock,
    scope=authenticated_scope,
    scope_keyring=host_keyring,
)
dispatch_attestation = mint_recovery_dispatch_attestation(
    recovery_plan,
    host_attested_case,
    consent_status=current_consent,
    inventory_available=current_inventory_available,
    prior_recovery_contacts=current_recovery_count,
    observed_at=host_clock,
    valid_until=host_clock + timedelta(minutes=5),
    scope=authenticated_scope,
    scope_keyring=host_keyring,
)
factory = LightbulbSoftwareFactoryRuntime(observation_runtime)
loop_result = factory.run_abandoned_recovery(
    recovery_plan,
    host_attested_case,
    resolved_secrets=execution_boundary_secrets,
    scope=authenticated_scope,
    scope_keyring=host_keyring,
    execution_scope=authenticated_project_execution_scope,
    executor=governed_executor,
    run_ref="checkout-recovery-1",
    preview_only=False,
    dispatch_at=host_clock,
    dispatch_attestation=dispatch_attestation,
    contact_reservation=transactional_contact_reservation,
    contact_reservation_authority=durable_contact_reservation_authority,
    approval_grants=approved_action_grants,
    experiment_ref="checkout_holdout_1",
)
assert loop_result.status == "observation_scheduled"
assert loop_result.recovery.causal_claim_ready is False
```

For 100 stores by 100 products, use pilot-to-scale tranches rather than treating
the existing 10,000-launch validation ceiling as permission or throughput.
Per-store currency, tax, shipping, inventory, consent, connector quota, spend,
dedupe, causal holdout, and automatic stop-loss gates remain mandatory.

Executable discovery is paged so these schemas remain usable by coding agents.
Both MCP catalogs default to bounded summary pages. Executable full-schema
queries return one primitive per page; business full-contract queries retain as
many matches as fit below the MCP payload ceiling. Follow `next_offset` for
broader queries, or request an explicit summary page. Direct Python catalog
callers retain the full-schema default and may request up to ten schemas per
page. Summary results expose searchable
`capability_hints`; exact executable results also expose a structured
`profit_blueprint`. Both are discovery contracts only—the proposal primitives
declare no connector tools and cannot dispatch the capabilities they describe.

## Growth Engine

The Growth Engine is the SDK's analytics-to-action layer for cross-connector
growth work (Shopify, HubSpot, Salesforce, Meta, LinkedIn, Google Analytics).
It closes the loop *measure → diagnose → experiment → learn → plan* with
sealed, tamper-evident artifacts at every step. Full design:
`docs/growth-engine-design.md`; implementation contracts:
`docs/growth-engine-build-contract-map.md`.

Modules (naming note: `growth_primitives.py` predates this layer and is
unrelated catalog code):

| Module | What it owns |
|---|---|
| `growth_ingestion` | The engine's front door. `normalize_connector_response` turns a real connector analytics response (Shopify's columns/rows ShopifyQL table, GA's per-day metrics list, Meta/LinkedIn's nested vendor insight objects, HubSpot's deals list, Salesforce's aggregated report — mapped from the platform's own in-repo adapter contracts) into an *unsealed* `GrowthFunnelEvidence` body the host then seals. Only recognized fields map (others reported in a `MetricCoverage`); missing metrics stay absent (unknown ≠ zero); rates emit only from a provider's own [0,1] rate field, never derived; shape mismatches fail loudly; `evidence_digest` is the SHA-256 of the raw response so the evidence is bound to the exact bytes. HubSpot emits no `won_deals` (its search has no `is_won` flag — we don't guess). Capability-keyed and discoverable; sealing stays host-side. |
| `growth_funnel` | Canonical six-stage funnel (audience→traffic→engagement→conversion→revenue→retention) built from sealed `GrowthFunnelEvidence` envelopes. Unknown stages stay unknown; measurement bases never silently mix; exclusions are visible with reasons; bottlenecks name the reference they used. |
| `growth_experiments` | Preregistered experiments where the HMAC seal *is* the preregistration. Stdlib-only statistics (two-proportion z, Welch's t, chi-square SRM checks, Acklam+Newton quantiles), keyed deterministic assignment, fixed-horizon readouts that refuse peeking; `causal=true` is structurally impossible without a sealed design. |
| `growth_learnings` | Append-only, hash-chained, scope-bound growth memory. `experimental` entries can only be recorded from verified causal readouts; `observational` entries require evidence digests; `heuristic` entries rank last. Supersession, expiry, grade-ranked queries; loads fail closed on tampering. |
| `demand_gen_primitives` | Deterministic content-calendar and audience-growth planners aimed at the verified funnel bottleneck. Every item is a content brief bound to a rail-style approval unit over its content digest; planners never dispatch. |
| `growth_cockpit` | `diagnose_growth(...)`: one ranked answer to "what should I do next" — bottleneck, opportunities with the exact next primitive and argument hints, evidence gaps with the connector capabilities that fill them, applicable learnings, data-quality notes. |
| `growth_portfolio` | The fleet layer for the N-store case (host-side only; inputs carry member scopes). Sealed portfolio rollups over per-store verified snapshots, `portfolio_sibling` benchmark references from fleet medians, honest cross-store learning transfer (always observational — the experiment didn't run there), and portfolio diagnosis: cluster stores by shared bottleneck, run ONE experiment on representative test stores, transfer the learning, roll out. |
| `growth_workspace` | Durable, scope-bound persistence for the whole engine. Content-addressed artifact files + a revisioned index; sealed artifacts verified on save AND on every load (verified in, verified out); coherence rules (design before evidence/readout, exactly one readout per design, dispatch before receipts); deterministic lifecycle queries (`experiment_status(as_of)`, `pending_readouts(as_of)`, `status(as_of)`); owns the scope's learnings ledger. Seal a design today, read it out at the horizon weeks later — across sessions. |
| `growth_rail_bridge` | The two-way seam with the governed execution rail, strictly at the dict boundary (no imports either way). Outbound: `author_calendar_item` binds byte-exact copy to a plan brief, `compile_content_calendar_dispatch` emits a sealed package of rail-shaped `social_publish` operations using the rail's exact capability names, argument models, content-digest recipe, and approval units. Inbound: rail receipts verify under the rail's own HMAC domain and `reconcile_dispatch_receipts` matches them by exact operation digest, reporting completed/pending honestly and deriving `measure_after` (measurement opens after the LAST completed action). Nothing here executes; dispatch belongs to the rail behind its own approvals. |
| `growth_operating` | The conductor. `compile_growth_agenda` joins workspace state into one ranked, argument-hinted agenda under a fixed precedence — due readouts (a missed fixed-horizon readout is paid-for traffic earning zero learnings), unrecorded causal learnings, receipts to reconcile, post-action measurement windows (opening strictly after `measure_after`), stale evidence per a caller-supplied heuristic `GrowthCadencePolicy`, then opportunities cited verbatim from the stored diagnosis and profit review — with duplicate experiments emitted *blocked* (naming the in-flight design), `source_digests` on every item, and `idle`/`wake_at` so a scheduler knows exactly when to bring the agent back. `compare_funnel_snapshots` answers the operator's weekly question — did last week's work move anything — with every delta structurally labeled `observational_movement_not_attribution`, unknown staying unknown, and cross-scope comparison refused. `GrowthWorkspace.compile_agenda(as_of)` is the one-call session bootstrap; a kind-coverage test guarantees every workspace artifact kind is either consumed by the agenda or explicitly declared exempt. |
| `growth_objectives` | The destination. A sealed `GrowthObjective` commits the scope to a contribution-profit run-rate by a deadline, with the baseline DERIVED from verified unit economics at commit time (the seal is the commitment — goalposts cannot quietly move; a new target names what it supersedes). `assess_objective_progress` judges the current window-normalized run-rate against a labeled linear glide path (on_track / at_risk / off_track / achieved / expired_missed), prices the remaining money gap, and — given the profit and customer-value reviews — reports what their dollar-ranked opportunities could fund versus the unfunded shortfall. The conductor demands assessment when it is missing or stale, frames every agenda with the gap, and treats a missed deadline as a demand for a superseding objective, never a quiet re-baseline. |
| `growth_mandate` | Bounded autonomy. A sealed `GrowthMandate` is the human's delegation contract: which action kinds the agent may take without asking (`adjust_channel_budget`, `launch_experiment`, `publish_content`, `price_move`), a money ceiling per action and a rolling-window ceiling per kind, guardrails pinned to sealed evidence (economics-component floors/ceilings, and objective-verdict allowlists whose verdict the gate derives itself from the verified objective and economics — advisory assessments are caller-forgeable, so it accepts none), and a mandatory expiry — open-ended authority is structurally refused. `authorize_growth_action` (host path) verifies everything sealed and mints a sealed `ActionAuthorization` for every verdict — `authorized`, `escalate`, or `refused` — so denials leave the same audit trail as approvals. Silence never authorizes: an unevaluable guardrail escalates; a prior receipt that fails verification escalates; over-ceiling asks escalate (the human can still say yes personally). `GrowthWorkspace.authorize_action` is the one-call agent gate with complete stored-receipt window accounting, and the conductor surfaces expired/expiring mandates and pending escalations as `mandate_attention`. Authorization is not execution — a receipt says "within delegated bounds at decision time", never "it happened". |
| `growth_briefing` | Session rehydration for a mind that reboots. `compile_growth_briefing` (and the one-call `GrowthWorkspace.compile_briefing`) renders the compiled agenda plus the scope's sealed artifacts — objective status, the ranked do-this-now list, remaining mandate authority per action kind, unit economics, funnel state, in-flight experiments, banked learnings — into deterministic plain text that fits a stated character budget. The briefing renders, it never re-decides: every number is quoted from a digest-pinned artifact, the only added arithmetic (`summarize_mandate_spend`) is test-pinned to the sealed gate's receipts, dropped sections are named with where to fetch them, a budget below the honesty floor is refused, and trust is echoed from the agenda's join, never upgraded. |
| `growth_money_ingestion` | The front door for the money envelopes. `normalize_contribution_ledger_response` maps a Shopify ShopifyQL ledger table to unsealed `ProfitContributionEvidence` (costs Shopify cannot see — ad spend, service costs — stay absent, never zero); `normalize_customer_cohorts_response` maps a cohort-grouped table (one row per cohort-month × age bucket) to unsealed `CustomerCohortEvidence` with month-derived acquisition windows and per-cohort provenance digests. Same honesty rules as `growth_ingestion`: recognized columns only, unmapped numerics reported, loud shape mismatches, digests bound to the raw response. Finance-side capabilities are refused loudly until their response shapes are pinned. Sealing stays host-side. |
| `growth_customers` | The repeat-purchase dollar. Sealed `CustomerCohortEvidence` (acquisition cohorts with half-open age buckets) pools into horizon-bounded observed customer value — net revenue and orders per customer at 30/90/180/360 days, contribution LTV via a verified economics margin (`cross_artifact`-labeled, digest-pinned), and the CAC ceiling it supports. Right-censoring is structural: cohorts too young for a horizon are excluded with a reason, never averaged in, and value beyond the observed horizons stays unknown. `review_customer_value` prices ceiling headroom in contribution dollars against the ledger's CAC (raise or cut, with scenario intervals), demands missing evidence, and hooks a preregistered `purchase_to_repeat` experiment where the pooled reorder curve fades. The payback horizon is labeled a finance-policy heuristic everywhere it appears. |
| `growth_profit` | The money model. Sealed `ProfitContributionEvidence` envelopes (rail-vocabulary ledger fields: gross_sales, discounts, refunds, cogs, fulfillment_cost, payment_fees, acquisition_cost, service_cost) roll up into a `UnitEconomicsSnapshot` — net revenue, contribution profit/margin, AOV, CAC, breakeven ROAS, CAC payback — with per-metric completeness (unknown is not zero), currency and basis separation, and visible exclusions. `review_profit` prices funnel-rate gaps in contribution dollars with scenario intervals, screens cost leaks against labeled heuristics, and names the exact next primitive. `plan_price_move` plans one bounded price change (protect a breached margin floor / probe elasticity / grow contribution under a measured elasticity) — the margin floor is structurally enforced, the move is bound to a content-digest approval unit, and the plan embeds the exact preregistered `revenue_per_session` experiment to run. `estimate_price_elasticity` turns that experiment's causal readout into an arc-elasticity estimate with a propagated interval, ready for the learnings ledger (`lever="pricing"`). |

Agent-discoverable executable primitives (also reachable through the generic
MCP primitive tools): `growth.build_funnel_snapshot`, `growth.diagnose`,
`growth.build_unit_economics`, `growth.review_profit`,
`growth.plan_price_move`, `growth.compile_agenda`,
`growth.compare_funnel_snapshots`, `growth.build_customer_value`,
`growth.review_customer_value`, `growth.assess_objective`,
`growth.preflight_action`, `growth.compile_briefing`,
`demand_gen.plan_content_calendar`,
`demand_gen.plan_audience_growth`. They
run the honest *unverified* path (`caller_supplied_unverified`); sealing
happens host-side through the module functions with a
`DynamicWorkflowReceiptKeyRing`.

The compounding loop, end to end:

```python
from lightbulb import (
    GrowthLearningsLedger, InMemoryLedgerStore,
    build_growth_funnel_snapshot, design_growth_experiment, diagnose_growth,
    mint_growth_funnel_evidence, read_out_growth_experiment,
)

# 1. Seal connector observations, build the funnel (host-side, keyed).
evidence = mint_growth_funnel_evidence(raw_observation, scope=scope, scope_keyring=ring)
snapshot = build_growth_funnel_snapshot(
    {"analysis_as_of": now, "snapshot_ref": "week-34", "evidence": (evidence, ...)},
    scope=scope, scope_keyring=ring,
)

# 2. Diagnose: ranked opportunities with the exact next call.
diagnosis = diagnose_growth({"as_of": now, "funnel_snapshot": snapshot})

# 3. Preregister the experiment the diagnosis suggested (the seal IS the
#    preregistration; required sample size is recomputed and enforced).
design = design_growth_experiment({...}, scope=scope, scope_keyring=ring)

# 4. After the horizon: honest readout (SRM-checked, no peeking, CI + verdict).
readout = read_out_growth_experiment(design, arm_evidence, readout_ref="r1",
                                     analysis_as_of=later, scope=scope, scope_keyring=ring)

# 5. Record it — future plans across the whole portfolio can now cite it.
ledger = GrowthLearningsLedger(InMemoryLedgerStore(), scope=scope, scope_keyring=ring)
ledger.record_experiment_learning(design=design, readout=readout, entry_ref="anchor-pricing",
                                  lever="price_anchoring", claim="...", recorded_at=later)
```

Boundary (stated, not hidden): the Growth Engine plans, measures, and learns.
Live connector *execution* of its plans flows through the governed execution
rail (approvals, receipts, provenance) — plan items carry rail-compatible
content-digest approval units so they become executable there without
re-planning.

## Security posture

- HTTPS enforced for non-local hosts by default (`enforce_https=False` only for dev).
- Path segments and risky inputs validated (`validators` module); SSO / device-flow URLs validated before opening a browser.
- Token cache: atomic write, restrictive permissions, symlink and ownership checks.
- `lightbulb setup`: atomic config writes, safe TOML escaping for Codex, backups chmod-restricted.

Regression tests live in `tests/test_security.py` (audit IDs in docstrings).

## Types (PEP 561)

The wheel ships `py.typed` for Pyright/mypy consumers.

## Version history

<details>
<summary>Expand release history and migration notes</summary>


These notes describe source versions. Publication dates and downloadable
artifacts are recorded in the [PyPI release history](https://pypi.org/project/lightbulb-mcp/#history)
and the developer reference's release panel.

### 0.24.0 candidate

- Added offline company-worker configuration preflight and source templates.
- Added authenticated worker health, read-only status and portable HTML reports.
- Added source-census review and permanent historical-correction holds checked before budget execution.
- Extended package upgrade acceptance with previous-wheel persisted state and resume checks.
- Added a pipeline-neutral offline acceptance command, executable guide examples and synthetic capacity evidence.
- New operator helpers are Beta. No local runtime or provider certification is implied.

### 0.23.0

- **Integrated company operations:** a runnable company worker binds recurring observations, local-presence cadence, demand pacing, approved reallocation, content lifecycle, channel-spend ingestion, trusted attribution and growth-period aggregation to authenticated durable journals. Host identity, stale inputs, approvals and incomplete provider reads remain enforced.
- **Complete bounded inventory:** scoped immutable snapshot pagination removes the old 200-state intake ceiling. Cadence consumes the complete snapshot; closure rejects truncated inventory and states explicitly which persisted sources were covered.
- **Verified economic inputs:** inference billing enters the protected company cost register. Canonical Shopify first-purchase observations support verified zero customers while leaving unobserved customer value unknown. PostHog reads retain the exact original scope across authenticated bounded continuation pages.
- **Package compatibility:** Python 3.10 setup and typed imports receive explicit compatibility dependencies. CI verifies clean installation and upgrade from the 0.22 baseline on Python 3.10–3.13, including public clients, the CLI, worker entry point and actual MCP stdio.

- **Source-backed money paths:** subscriptions and dunning, storefront settlement, collections, card spend and vendor commitments, payroll, disbursements, seller payouts, and refunds retain their observations, execution receipts, and source plans. Consuming engines replay the source lifecycle and check amount, currency, correlation, company scope, and time.
- **Authority and paper:** `authority_matrix` binds a platform decision to the exact command, amount, category, and scope. Agreements, standing documents, consent, and approved claims gate the operations they protect. A typed approval reference grants no authority.
- **Actual company costs:** `company_cost_centres` attributes distinct economic sources to engines and overhead within a real accounting window. Coverage ties those costs to actual bank matches; payroll separates gross expense and employer costs from net cash paid. Refunds reverse the proven company revenue share once.
- **Complete operating domains:** people, marketplace supply, engagements, WIP billing, custodial funds, and unit economics join the operating loop. Marketplace take revenue and seller liabilities remain separate, and treasury derives operating cash after custody.
- **Archetypes:** added `founder_led_saas`, `local_services`, and `two_sided_marketplace`; repaired existing profile/currency bindings and missing rosters. Compiled engine profiles must agree with the company's currency.
- **Operator access:** all 60 console verbs, including 41 chain verbs, share matching CLI and `company_*` MCP routes; the company-operator profile has 93 tools. Cadence work items name required receipts and the artifacts that satisfy them. The operator skill covers money in, money out, authority, paper, payroll, payouts, refunds, and costs.
- **Compatibility:** source-state builders and projections now require the corresponding `source_plan`; cost registers also require `period_start` and `period_end`. Rebuild derived receipts from retained source artifacts when upgrading. Caller-entered totals or a state digest alone cannot replace that evidence.
- These are SDK lifecycle, proof, and preview contracts. Provider operations remain governed by the platform; new host observation contracts do not establish hosted adapter availability, certification, or production readiness.

### 0.22.0

- **Payables chain** (`lightbulb.payables_chain`): `bill_received → approved → scheduled → paid → cleared`, each hop from a sealed artifact (supplier invoice intake, the platform's approved task, a treasury cash cover with the bill write's `LB-AP-` correlation, an APPLIED bill-payment observation, a close that reconciled payables). Paid cash becomes the engine's period spend.
- **Retention chain** (`lightbulb.retention_chain`): renewals flagged from the billing observation and the SaaS plan's tier prices, churn risk from the usage snapshot, outreach from an approved execution receipt, and `renew` / `expand` / `churn` classified from the next billing observation; renewed cash enters the revenue chain.
- **Compliance calendar** (`lightbulb.compliance_calendar`): obligations derived per jurisdiction (AU, CA, US, UK, NZ) from payroll and registration facts; reservations from Xero BAS/GST and payroll reads flow into the treasury forecast as `tax_reservation`; lodgements are operator-supplied evidence and say so.
- **Exceptions desk** (`lightbulb.exceptions_desk`): one lifecycle for everything refused (ambiguous writes, non-unique / non-exhaustive / not-found observations, chain reconciliation, tick rejections, stale reads, cash shortfalls, overdue obligations) with a resolution path and SLA per kind.
- **Operator brief and board pack** (`lightbulb.company_brief`): one sealed page per tick and one per month, assembled from the console's own documents with their digests; attention items are derived, synthetic sections marked.
- **Company evals** (`lightbulb.company_evals`): recommendations scored against the periods that followed (error, direction, followed, regret when overridden), the simulator scored against the standard scenarios, errors learned into memory.
- **Recorded provider corpus** (`lightbulb.provider_fixtures`): sixteen fixtures shaped to the platform's read contracts with pinned digests, a byte-identical Spring copy, and contract tests on both sides.
- Console verbs `exceptions`, `compliance`, `brief`, `board_pack`, `evals`; matching `company_*` MCP tools (operator profile 49 tools). `lightbulb company exceptions`, `compliance`, `brief`, `board-pack`, and `evals` wrap the same console verbs from the terminal over the hosted engine-state store; `exceptions` exits 2 for past-SLA cases and `evals` exits 2 when a standard simulator scenario fails.

### 0.21.1

- The platform-admitted reads are governed reads in the SDK: `github.list_deployments`, `posthog.query_events`, the QuickBooks settlement observers, and `stripe.observe_cash_settlement` plan on the governed lane, so their receipts carry journal provenance instead of host provenance.
- Typed descriptors for the settlement observers, the GitHub deployments page, the PostHog event page, and every Airwallex and Bill.com operation, matching the closed argument contracts the platform now enforces.
- `docs/lightbulb-live-run.md`: the runbook for the first revenue chain on real provider reads.

### 0.21.0

- Went deep on operating a company rather than wider. The revenue chain
  (`lightbulb.revenue_chain`) is one replay-fenced lifecycle from a handed-off
  deal through the executed agreement, the issued invoice, the applied
  payment, and the settled cash to the receivable cleared in the close; every
  hop consumes the sealed artifact of the pack that produced it, and settled
  cash becomes the period's pipeline revenue. `lightbulb.company_explain`
  answers "why is this number what it is" by replaying any engine state to
  the transitions, receipts, and sources behind a ledger field.
  `lightbulb.company_decisions` briefs an approval with forecasts for approve,
  reject, and the alternative from the persisted periods, ranked, with the
  return change that would flip the recommendation.
  `lightbulb.company_treasury` forecasts cash week by week from a balance
  read, payables, receivables, payroll, fixed costs, and the operating
  budget, and judges whether an outflow is covered. `lightbulb.company_operating_memory`
  is a persisted lifecycle of calibrated priors learned once per sealed state
  and fed to the simulator, the replanner, and workforce grading.
  `lightbulb.company_workforce_learning` grades workers from their ledgers
  against those priors and revises the roster behind the release and
  migration fences. `lightbulb.company_chaos` injects connector outages, stale
  and partial reads, replays, overspend, clock skew, and mid-period migration
  into a real cadence run and seals which refusals held.
- `lightbulb.company_console` is the operator console (work items, tick,
  supply, explain, decide, simulate, migrate, portfolio, treasury, readiness,
  bring-up, memory, grades, chaos); the `company-operator` MCP profile exposes
  it as `company_*` tools (44 tools) and the tracked plugin ships a
  `lightbulb-company-operator` skill that teaches the weekly loop.

### 0.20.0

- Deepened five verticals so the engines are fed by the platform instead of
  by hand. Finance close on real books
  (`lightbulb.finance_close_observations`): Xero and QuickBooks trial
  balances, open invoices, Stripe settlements, and provider period locks
  become the close engine's own receipts through an explicit operator account
  map, with material variances named as exceptions. Company bring-up
  (`lightbulb.company_bring_up`): a replay-fenced lifecycle from a formed
  company to a live, scheduled cadence behind connector-readiness gates
  computed from the account's active OAuth connections, walked by
  `BringUpOrchestrator`. Pipeline closed loop (`lightbulb.pipeline_execution`):
  classifier and agent results into reply, enrichment, and meeting receipts
  through explicit tables, a sealed consent registry for voice and SMS, and
  the next touch as an exact platform request with a derived idempotency key.
  Growth execution (`lightbulb.growth_execution`): creatives from the content
  agents, launches as exact requests on executable channels (email today;
  paid channels are refused, not simulated), and approved reallocations
  applied through the engine's own portfolio planner. Live signals
  (`lightbulb.live_signal_observations`): Stripe invoices into per-account
  MRR and past-due churn risk, merged with PostHog usage for
  `saas_ops.observe_usage`; Gmail threads into case intake and Freshservice
  confirmations and statuses into verification and closure.
- Five new read-only primitives (`company.assess_bring_up_readiness`,
  `finance_close.plan_close_reads`, `pipeline.plan_next_touch`,
  `growth.plan_launch`, `saas_ops.observe_billing`) bring the registry to
  228; `lightbulb company readiness` and `lightbulb company bring-up`
  (`--dry-run`) join the CLI. See `docs/lightbulb-company-runtime.md` in the
  monorepo.

### 0.19.0

- Deepened the company runtime end to end. Observation jobs
  (`lightbulb.company_observation_jobs`) plan the exact platform reads that
  satisfy a cadence tick's evidence items and feed the engines, with the lane
  derived from the governed-read allowlist, and convert completed reads back
  into cadence inputs through the bridge adapters. Metered dispatch
  (`lightbulb.company_dispatch_metering`) settles a worker's open dispatch from
  the platform's workflow instance telemetry at an explicit currency rate. The
  hosted cadence scheduler (`lightbulb.company_hosted_scheduler`) ticks each
  company on an exclusively claimed project-runtime checkpoint. Blueprint
  migration (`lightbulb.company_plan_migration`) replays an in-flight state
  under a revised plan and proves it; the engine state store gained a
  `migrate` fence (`POST .../states/{engine}/{entityRef}/migrations` on
  Spring) and `EngineRuntime.migrate`. The multi-company operator view
  (`lightbulb.company_portfolio`) ranks companies by cited attention reasons.
- Operator MCP tools accept `output="json"` and return sealed objects;
  `list_engine_states` joins the `company-operator` profile (thirty-three
  tools). `lightbulb company ...` runs compile, simulate, goldens, tick and
  observation planning, signal consumption, migration preview, portfolio, and
  the generated reference from the terminal, plus `form`, `inbox`, and
  `states` through the signed-in account.
- Regression evidence: sixteen golden archetype-by-scenario trajectories
  (`lightbulb.company_scenario_goldens`) and Hypothesis fuzzing of all seven
  replay-fenced lifecycles. `docs/lightbulb-company-reference.md` is
  generated from the live engines. Four new read-only primitives bring the
  registry to 223. See `docs/lightbulb-company-runtime.md` in the monorepo.

### 0.18.0

- Added the operating cadence runner (`lightbulb.company_cadence_runner`,
  `company.operating_cadence_unattended@0.1.0`): the loop that makes a company
  run unattended. On each tick it reads the persisted engine states, applies
  the moves whose inputs the engines already hold (open a period, open the
  finance close after period end, reconcile on the verified-books proof,
  replan inside the approval threshold, close, roll over), and raises typed
  work items for everything else (dispatch receipts, sealed observations,
  close steps, approvals, overdue cases), including the exact prepared
  `LightbulbClient.dispatch` payload when a worker is bound to the engine. It
  never invents an input. The cadence itself is a replay-fenced lifecycle
  persisted in the engine state store; `CadenceWorker` runs it on a clock.
  Primitives `company.plan_cadence_tick` and `company.advance_cadence`.
- Added signal consumers (`lightbulb.company_signal_consumers`,
  `company.consume_signal`): the engines act on each other's `signals.*`. A
  churn-risk account suppresses the prospects on that account and raises
  suppression, look-alike exclusion, and retention-case intents; a rolled-back
  release pauses only the live campaigns promoting its affected claims (a
  review intent when none are named); an exhausted envelope holds unlaunched
  campaigns and asks for a replan; qualified pipeline, expansion candidates,
  verified books, resolved cases, company formation, and attributed revenue
  produce typed intents. `CompanyCadenceRunner.consume` applies the commands
  through the bound engine runtimes.
- Added the operator approval inbox (`lightbulb.company_approval_inbox`,
  `company.render_approval_inbox`, MCP `list_engine_approvals` and
  `decide_engine_approval`): engine transition approvals rendered for a
  person (which engine wants which transition on which entity, why it
  stopped, what approving does, whether the binding is still current against
  the persisted state), and `InboxOperator` that approves or rejects through
  the platform and resumes the engine with the bound approval
  (`EngineRuntime.resume_pending`).

### 0.17.0

- Closed the loop between the company engines and the platform
  (`lightbulb.company_execution_bridge`): execution receipts that accept only
  completed, provenance-bound connector results and bind the platform's
  journal reference into engine events; observation adapters from Shopify,
  Google Analytics, Gmail, Stripe, PostHog, and GitHub payloads into engine
  receipts through the sealed read lanes; and an approval bridge that turns an
  `APPROVAL_REQUIRED` rejection into a platform approval bound to the exact
  transition (`LightbulbClient.request_engine_transition_approval`,
  `bind_approval`, `command_with_approval`).
- Added the finance close engine (`finance.period_close_to_verified_books@0.1.0`)
  and the service delivery engine
  (`service.case_intake_to_verified_resolution@0.1.0`) on the shared engine
  core. The company operating system now reconciles a period only with the
  finance engine's sealed `close_state_digest`.
- Added the workforce loop (`workforce.roster_to_governed_dispatch@0.1.0`):
  Lightbulb domain agents as workers with per-period budgets, dispatch caps,
  and ceilings fitted inside engine envelopes; `workforce.plan_dispatch`
  returns the exact `LightbulbClient.dispatch` payload.
- Added the company simulator (`company.simulate_operating_periods`,
  `company.evaluate_scenario`): deterministic multi-period runs through the
  real period lifecycle with sealed results and golden-expectation checks.
- Persisted engine state: `LightbulbClient.put_engine_state`,
  `get_engine_state`, and `list_engine_states` (async twins included) talk to
  Spring's `/api/sdk-engine/projects/{projectId}/states` endpoints, which refuse
  stale, replayed, skipped, or out-of-scope writes with 409.
  `lightbulb.company_engine_store.EngineRuntime` loads, seals, advances,
  persists, and routes approvals for any engine on a hosted or in-memory
  store. Spring also gained `POST /api/workflows/approvals/engine-transitions`
  for the approval bridge.
- Added the `company-operator` MCP profile (thirty tools, preview-locked)
  and a `create_company` MCP tool (Australia and Canada only).
- Thirteen new read-only primitives bring the registry to 215; three new
  golden loops bring the count to 20.
- Fixed the finance observers' non-completed path, which referenced a
  connector status that does not exist. See
  `docs/lightbulb-company-runtime.md` in the monorepo.

### 0.16.0

- Added four company-engine Golden Operating Loop packs on a shared
  replay-fenced engine core (`lightbulb.company_engine_core`): the growth
  engine (`growth.store_truth_to_attributed_revenue@0.1.0`), the pipeline
  engine (`revenue.icp_to_qualified_pipeline@0.1.0`), the SaaS operating
  engine (`saas.launched_product_to_compounding_revenue@0.1.0`), and the
  company operating system
  (`company.blueprint_to_governed_operating_cadence@0.1.0`). Twenty-one new
  read-only executable primitives (`growth_engine.*`, `pipeline.*`,
  `saas_ops.*`, `company.*`, and their `blueprint.compile_*` entries) bring
  the registry to 202; the MCP catalogs project them to Claude Code, Codex,
  Cursor, and ChatGPT unchanged.
- Added `LightbulbClient.create_company` and
  `AsyncLightbulbClient.create_company`: form a company through the
  signed-in user's own Lightbulb account via `POST /api/companies/guided`.
  Australia and Canada only; the tenant always comes from the credential and
  Spring authorizes the caller as a tenant admin.
- Added typed cross-loop signals (`signals.*`) with producers, enabled
  consumers, and required payload keys; routing advises and never executes.
- Regenerated the released-authority manifest, the primitive capability
  manifest, and the capability inventory. See
  `docs/lightbulb-company-engines.md` in the monorepo for the full contract.

### 0.15.0

- Expanded the SDK to 93 evidence-bound executable primitives across accounting,
  procure-to-pay, supply chain, manufacturing/field quality, commercial,
  customer service, people, product, compliance, omnichannel policy/outcomes,
  connector certification, and production readiness. This includes governed
  journal discovery/preparation/post/readback plus bounded vendor-onboarding, procure-to-pay,
  finance-close, supply-chain execution, manufacturing-execution,
  commercial-operations with exact flat/seat/usage/hybrid billing branches,
  customer-service,
  people-operations, product-engineering, and compliance-risk lifecycle
  surfaces.
- Added verified project-envelope worker identity, exact connector-account
  custody, versioned operation/evidence/recovery receipts, no-replay handling
  for ambiguous writes, and a Spring-authoritative reviewed finance-write lane.
- Added self-binding result digests and completed read-only operation receipts
  across the operating-domain evaluators; receipts attest deterministic SDK
  evaluation only and never provider truth, approval, persistence, or authority.
- Added persisted bounded workflow loops with exact continue/terminal edges and
  crash-resume budgets, plus governed SMS/WhatsApp materializers, a sealed
  WhatsApp webhook observer, cross-channel identity and consent policy,
  normalized provider outcomes, and voice-call planning/observation contracts.
- Added exact project-account connector routing and Spring execution provenance,
  a resumable Shopify DRAFT → ACTIVE → publication → landing-readiness runner,
  durable Shopify/Google Analytics observation workers with automatic signed
  evaluation, and randomized-holdout abandoned-revenue recovery.
- Added a shared approved profit-action execution rail plus materializable offer,
  storefront, creative, lifecycle-email, and recovery candidates. External
  effects remain separately approved and outcome claims remain evidence-gated.
- Added ten typed contribution-profit workflows, exact-scope account,
  metric, plan, approval/action, outcome, and evaluation receipts, a globally
  profit-maximizing bounded selector, a compact launch-anchored flywheel
  manifest, and paged capability-searchable primitive discovery.
- Added the omnichannel Shopify/CRM/social launch compiler with destination
  account attestations, per-write approval receipts, post-action measurement
  windows, deterministic evaluation commitments, and bounded portfolio shards.
- Added governed default skill search with verified lifecycle metadata, outcome receipts, and tenant/company/project scope preservation.
- Added typed learning primitives, project AutoResearch, durable project-learning events, workflow improvement integration, and Shopify business primitives.
- Added durable retries and executable business-primitive discovery so agentic workflows can learn from AutoML, GEPA, Prime, and Puffer-backed execution without bypassing platform governance.
- Added the Growth Engine: twelve modules closing the loop measure → diagnose → preregister → read out → learn → transfer → price → plan → conduct → dispatch, with HMAC-sealed artifacts, structural causal honesty (no causal claim without a sealed preregistration), and unknown-never-zero semantics throughout.
- Added the canonical six-stage funnel from sealed cross-connector evidence (`growth_funnel`), the preregistered experiment engine with stdlib-only statistics and fixed-horizon readouts (`growth_experiments`), and the hash-chained learnings ledger with structural evidence grades (`growth_learnings`).
- Added the money models: unit economics with contribution margin/CAC/breakeven ROAS and margin-floor-enforced price experiments with measured elasticity (`growth_profit`); horizon-bounded observed customer LTV under a structural right-censoring law, CAC ceilings, and reorder-timing curves (`growth_customers`).
- Added the operators: ranked diagnosis (`growth_cockpit`), bottleneck-aimed demand-gen planners with content-digest approval units (`demand_gen_primitives`), the one-call operating agenda with duplicate-experiment blocking and scheduler wake semantics (`growth_operating`), fleet rollups and observational learning transfer (`growth_portfolio`), and durable verified-in/verified-out persistence (`growth_workspace`).
- Added evidence ingestion for real connector responses — funnel envelopes (`growth_ingestion`, Meta field maps live-validated) and the money envelopes for contribution ledgers and acquisition cohorts (`growth_money_ingestion`) — plus the dict-boundary execution-rail bridge with byte-exact mirrored contracts (`growth_rail_bridge`).
- Added 12 read-only executable growth primitives (bringing the then-current communication/GTM/profit/growth subset to 39), 19 workspace artifact kinds, and full public exports; four adversarial audit rounds (79 confirmed findings) closed with regression tests.

### 0.14.1

- Added opaque `runtime_agent.<uuid>` references for approved authored-agent revisions, strict recursive policy validation, and the governed author → review/approve → explicitly provisioned recursive-spawn contract.
- Added exact-scope Spring preflight, digest/model/policy verification, immutable per-run manifests, least-privilege tool intersection, disabled child delegation, and public SDK/MCP guidance without activating ordinary domain dispatch.

### 0.14.0

- Added typed Connector Execution requests/results with hosted and in-memory adapters, normalized failures, preview-only writes, approval enforcement, request recording, and idempotent replay protection.
- Added 13 executable business process primitives with Pydantic input/output contracts, including reply classification, email, invoice, meeting scheduling, governed payment collection, decision requests, business artifact generation, and implementation work packets.
- Added `LightbulbProject`, `ProjectRuntime`, and `DurableProjectRuntime` for project capability declarations, connector Tool allow-lists, deterministic bindings, revisioned pause/resume, schedules, idempotent events, and distributed worker leases.
- Added automatic sanitized runtime-outcome telemetry, tenant/company hosted persistence, and direct improvement-loop ingestion.
- Added conformance contracts for all 28 provider Tools used by shipped primitives, including live hosted-schema drift detection.
- Added complete behavioral async parity while preserving native async hot paths.
- Added client and MCP entrypoints for executable catalog discovery, SDK execution, project validation, event-routed and durable project operations, outcome flush, connector conformance, and the governed investment-agent facade. The default non-private MCP surface reports 1360 tools (1363 with the private runtime-action opt-in), and the compact Backbone profile reports 88.
- Added [custom project guide](https://www.lightbulbpartners.com/developers#custom-projects) with local, hosted, connector, custom primitive, workflow binding, and testing guidance.

### 0.13.0

- Added a durable tenant/company-scoped workflow-improvement ledger, authenticated outcome ingestion, scoped repositories, and RBAC permissions for read, write, approval, and delivery.
- Added immutable hash-chained implementation/publish/deploy decisions protected from update/delete in Postgres.
- Added SDK, async SDK, CLI, and MCP operations for sync, server status/queue, decisions, audit, delivery start, and delivery evidence. The full surface reports 1278 tools and the compact backbone profile reports 52.
- Added the Harness delivery contract and executor for isolated `codex/` branches, implementation checks, draft PRs, CI, disposable staging, bounded canaries, automatic rollback, and cleanup.
- Added `communication.classify_reply` to the Python and hosted MCP primitive catalogs with privacy-aware telemetry and human-review fallback.

### 0.12.0

- Added a proposal-only continuous workflow-improvement engine with synthetic evaluation of every primitive, score/trend history, sanitized observed outcomes, queue deduplication, overlap locking, stop-file support, and no-progress tracking.
- Added `lightbulb improve-workflows run|watch|status|queue` plus SDK/client APIs. Generated work packets route through `workflow_authoring`, require human implementation approval, and cannot automatically edit, publish, deploy, or invoke connectors.
- Added MCP tools `run_workflow_improvement_cycle`, `get_workflow_improvement_status`, and `list_workflow_improvement_packets`. The full surface reports 1269 tools and the compact backbone profile reports 43.

### 0.11.0

- Added an SDK-first custom workflow authoring loop: deterministic primitive recommendation, portable `lightbulb.business_workflow_definition.v1` compilation, fail-closed validation, and side-effect-free simulation.
- Added `compile_business_workflow`, `validate_business_workflow`, and `simulate_business_workflow` to MCP. The full surface now reports 1266 tools and the compact backbone profile reports 40.
- Added a harness `workflow_authoring` route and Codex prompt profile that teaches coding agents to extend business primitives in the SDK first, prove compile/validate/simulate behavior, and keep MCP as a thin adapter.

### 0.10.1

- Documentation refresh for the Lightbulb MCP page and partner docs route, including current `lightbulb-mcp` install/setup guidance, `LIGHTBULB_MCP_PROFILE=backbone` defaults, hosted MCP endpoint notes, and full-vs-namespace-filtered tool-surface guidance. The current full local surface reports 1263 tools via `lightbulb tools --count-only`; the backbone profile reports 37.
- Added `lightbulb version` so partners and support can verify the installed SDK/MCP package without a Python one-liner.

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

</details>

### Connected native coding

Projects can queue human-approved work for user-owned Codex, Claude Code, and Cursor runtimes through the same durable SDK channel. See [the native coding integration contract](NATIVE_CODING.md) for typed clients, driver requirements, cancellation and recovery. Live runtime integration remains to be validated when the new local runtime is available.
