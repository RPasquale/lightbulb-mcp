# Lightbulb MCP server

The MCP server exposes the Lightbulb platform as tools for AI hosts (Claude Code, Codex CLI, Cursor, etc.). Every call runs as the **authenticated user** through Spring Boot: tenant isolation, company isolation, RBAC, and rate limits match the web app—there is no elevated “MCP service role.”

Companion CLI documentation: [CLI and Python SDK guide](https://www.lightbulbpartners.com/developers).
Partner-facing setup, governance, and hosted MCP documentation:
https://www.lightbulbpartners.com/developers

## Run

Install a published PyPI release and verify the local package:

```bash
python -m pip install --upgrade lightbulb-mcp
lightbulb version
```

For reproducible host configuration, pin the reported package version in your
dependency lock. A source branch may contain an unpublished candidate; the
[PyPI release history](https://pypi.org/project/lightbulb-mcp/#history) establishes
which versions can be installed. Source checkout, package installation and
host deployment are separate operations.

Then run the stdio MCP server:

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
        "LIGHTBULB_URL": "https://agents.lightbulbpartners.com",
        "LIGHTBULB_MCP_PROFILE": "adaptive"
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

For Claude Code, `lightbulb setup --target claude-code-user` installs both the
user-scoped MCP entry and Lightbulb Continuum hooks in
`~/.claude/settings.json`. Use `--target claude-code-project` for a shared
project MCP entry and `.claude/settings.json` hooks. The setup merge preserves
unrelated settings and hook handlers. The hooks capture bounded prompt,
assistant, and compaction lifecycle events and rehydrate relevant private
history; they do not increase Claude's native model context window. Raw tool
capture is off by default and requires `LIGHTBULB_CONTEXT_CAPTURE_TOOLS=1`.
Inspect the result with Claude Code's `/hooks` command.

Continuum Context Spaces default to a 10,000,000-token indexed-storage ceiling.
Hosts retrieve only bounded prompt-aware packs, then use `context_search` and
`context_read` for deeper evidence. This is external context virtualization,
not a request to place all stored tokens into one provider prompt.
When a space reaches capacity, lifecycle capture degrades to read-only and
retrieval continues; quota exhaustion does not make the stored context
unavailable.
The local stdio `context_*` tools accept optional public `company_ref` and
`project_ref` together for an exact project scope; authenticated discovery
resolves their internal scope, and model-supplied tenant/user/UUID fields are
not part of the tool contract.

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
| `LIGHTBULB_MCP_PROFILE` | Optional profile. `adaptive` (default) exposes four search/describe/risk-matched invoke tools and loads capability schemas on demand; `sovereign` uses the same lean surface with the preview-locked Local catalog. |
| `LIGHTBULB_ENABLE_PRIVATE_RUNTIME_ACTION_MCP` | Explicit trusted local-developer opt-in for the three UUID-backed runtime-action tools. Default `false`; never enable on hosted/OpenAI-facing MCP. |
| `LIGHTBULB_ENABLE_PRIVATE_PROJECT_LEARNING_MCP` | Explicit trusted non-public operator opt-in for the three Project learning preparation/admission mutation tools. Default `false`; the compact `backbone` profile always excludes them. |
| `LIGHTBULB_MCP_NAMESPACES` | Optional CSV of generated-tool namespaces to register (e.g. `finance,crm,gmail`). Hand-written control-plane tools always register. Unset = full non-private generated surface. Use `lightbulb tools --count-only` for the installed profile; the [developer reference](https://www.lightbulbpartners.com/developers) provides the source-bound capability inventory. |
| `LIGHTBULB_RUNTIME_OUTCOMES_FILE` | Optional durable JSONL queue for sanitized primitive outcomes consumed by the improvement supervisor. |

**HTTPS:** For non-loopback hostnames the SDK enforces HTTPS on the HTTP client unless the URL is explicitly local (`localhost`, `127.0.0.1`, etc.—parsed by hostname, not substring).

## Behaviour & scope

- **RBAC:** Tools map to platform endpoints the user is allowed to call; denied actions surface as errors (typically permission / validation), not silent success.
- **Company context:** Instructions remind admin users to select company when required (same as product behaviour).
- **Rate limits:** Platform rate limits apply per user/session like normal API usage.
- **Retries:** The MCP layer may retry on behalf of the host where documented in code (e.g. auth refresh paths); tools themselves do not bypass server-side throttling.

## Tool surface

The default setup wizard writes `LIGHTBULB_MCP_PROFILE=adaptive`. Hosts initially receive only `lightbulb_find_capabilities`, `lightbulb_describe_capability`, `lightbulb_use_read_capability`, and `lightbulb_use_action_capability`; the server keeps the permitted catalog private and returns one schema only when requested. The separate read/action invokers preserve host-enforceable MCP safety policy: only explicitly read-only targets can use the read invoker, while unknown or mutating targets use conservative destructive/open-world hints. This avoids spending tens of thousands of context tokens on unrelated tools without hiding invocation risk from the harness. The legacy `backbone` flat catalog and the full generated surface remain explicit opt-ins for compatible hosts.

Domain names and actions should follow `agent-workers/agents/domain_registry.py` on the platform; the MCP system prompt summarizes common domains.

The `finance` generated namespace includes the complete governed investment
surface: feature engineering, alpha discovery, costed portfolio backtests,
Prime/Puffer training plans, capital + compute allocation, trader orchestration,
broker readiness and snapshots, paper observation, execution/reconciliation,
and deposit or withdrawal requests. Broker orders, provider spend, model
promotion, and cash movement remain subject to their server-side approvals and
risk controls; exposing a tool never grants authority.

Set `LIGHTBULB_MCP_PROFILE=adaptive` for Codex plugins and OpenAI-facing
hosts that should start with the Lightbulb backbone as the main orchestration
surface. This keeps `whoami`, company selection, `backbone_execute`,
`start_consulting_project_workflow`, approvals, connector status, workspace
context, and software-delivery loop tools while omitting the generated long-tail
domain/connector tool list.

The compact/OpenAI-facing profile excludes the UUID-backed governed
runtime-action tools: `register_runtime_domain_action`,
`list_runtime_domain_actions`, and `get_runtime_domain_action`. They require
`LIGHTBULB_ENABLE_PRIVATE_RUNTIME_ACTION_MCP=true` on a trusted, non-public
local developer MCP surface; their raw project/action
UUID contract is not eligible for the public profile. Select a company and pass
the exact project UUID when using that developer surface. Register requires an
explicit idempotency key and produces only a `pending_approval` registration.
Its component IDs, optional authored-agent spec, and optional execution policy
are parsed as bounded canonical JSON; scope, status, owner, workflow selection,
version, and digest remain server-owned. The initial contract is immutable
v1-only. After explicit human review, an authorized ADMIN/TENANT user may
approve or reject through the sync/async SDK; there is no end-user runtime-action
review UI yet. Approval produces `approved`, not `active`, and never adds the
action to ordinary domain dispatch. For approved dynamic-agent workspaces the
response includes an opaque `recursive_agent_id`. The compact
`run_recursive_agent` tool may accept that reference only in its explicit
comma-separated `allowed_agent_ids` policy. Spring then rechecks exact actor,
tenant/company/project, component RBAC, approval, digest, and policy in one
bounded preflight before the run starts; the worker freezes the manifest and
tool intersection for that run, with delegation disabled. These lifecycle
operations do not themselves execute a runtime action, and the server feature
gate, exact-scope checks, RBAC, and audit policy remain authoritative. Developer MCP list results expose bounded review metadata with
`offset`, `limit` (maximum 50), and `next_offset`; fetch an ID with the get tool
for its full spec. Server-side pagination remains a follow-up, so the SDK
currently downloads the scoped status list before the MCP projection is paged.

### Governed account-shell drafts

`get_account_shell_customization`,
`create_account_shell_customization_draft`, and
`preview_account_shell_customization` let the Lightbulb agent read, propose,
and preview a tenant account-shell change. They cannot publish or roll back.
Prefer closed-registry component version 2: its only configurable props are a
bounded emphasis, `visibility.page_scope` (`any`, `tenant`, or `company`), and
the exact registry-owned `action.capability_id` with `operation: navigate`.
The rendered launcher is hidden unless the viewer currently has that
capability and the page scope matches. The document cannot carry a route, URL,
script, event handler, component code, raw CSS, or iframe policy.

### Success-aware Memory preview

`memory_regulation_preview` is a dry-run-only view of bounded compaction. Set
`empirical_success_floor_ppm` to require a minimum share of exact-owner Memory
references from retained successful skill executions. With
`optimize_for_least_active_memory=true`, the server reports the smallest active
budget that clears that floor. Insufficient, over-limit, and below-floor
evidence are explicit non-mutating states.

The gate's guarantee is
`empirical_reference_retention_not_task_success`: it does not claim a compacted
digest has passed held-out task evaluation. MCP cannot execute compaction;
consequential calls require an SDK idempotency key or a governed operating loop.

For the stronger held-out path, pass a JSON object in
`held_out_task_evaluation_json` with the success/safety/cost policy and up to 16
candidate budgets. MCP returns their exact content-free baseline/candidate
bindings for an external trusted evaluator. The compact MCP surface refuses
authenticated receipt transport and remains unable to mutate Memory; submit
signed aggregate receipts through the sync/async SDK. Empirical and held-out
evidence cannot be combined in one request. The full verifier contract and
default-off production boundary are documented in
`docs/memory-held-out-regulation.md`.

### Business primitives and Agent Builder

The compact profile also keeps Lightbulb business primitives visible. These are
backend task blocks for real operating work, not UI components and not raw
connector shortcuts:

- `search_agent_marketplace` returns a bounded
  `lightbulb.agent_marketplace_catalog.v1` discovery contract for action and
  worker listings. Static domain contracts remain `unverified`; with an exact
  domain filter, only actions returned by the authenticated tenant/company/RBAC
  lookup are marked `rbac_visible`. Pricing, evaluation, lifecycle, and risk
  are never inferred when the source does not declare them. These are synthetic
  discovery rows: each reports `installable=false`,
  `lifecycle_installable=false`, and
  `synthetic_discovery_listing_not_persisted`. Never pass their IDs to a
  lifecycle tool.
- Governed action publication uses exactly
  `preview_agent_marketplace_action_publication`,
  `publish_agent_marketplace_action`,
  `get_agent_marketplace_action_publication`, and
  `archive_agent_marketplace_action`. These tools are tenant-scoped and do not
  require a selected company. Always preview first, then pass the returned
  `expected_contract_digest` to publish as a compare-and-set guard; a stale
  digest is rejected if the action contract changed. The only publication
  fields are `slug`, `name`, `version`, `domain`, `action`, `visibility`,
  `pricing_model`, and `changelog`, with `expected_contract_digest` added for
  publish. Raw manifests, agent or worker packages, prompts, models, tool
  policies, and tenant/company IDs are not accepted. `PRIVATE` is the default;
  shared `UNLISTED` and `PUBLIC` visibility requires a portable platform
  contract, and `PUBLIC` is publisher-tier gated. Pricing is `INCLUDED` only;
  no checkout publisher path is implemented. Publish returns a
  `publication_id`; poll it with
  `get_agent_marketplace_action_publication` while status is `scanning` until
  it becomes `ready`, `failed`, or `archived`. There is no MCP wait tool.
  Publish and archive require replay keys. Archive uses the publisher-owned
  `listing_id`, preserves revisions and audit history, and does not uninstall
  existing company installations.
- Persisted lifecycle tools are
  `list_agent_marketplace_listings`, `get_agent_marketplace_listing`,
  `list_agent_marketplace_installations`, `get_agent_marketplace_installation`,
  `install_agent_marketplace_action`, `activate_agent_marketplace_action`,
  `pin_agent_marketplace_action`, `uninstall_agent_marketplace_action`,
  `invoke_agent_marketplace_action`,
  `get_agent_marketplace_invocation_status`, and
  `get_agent_marketplace_invocation_receipt`. Select a company before any
  company-scoped call. Start with `list_agent_marketplace_listings` and use its
  server-authoritative UUID `listing_id` and `revision_id`. Mutations require an
  idempotency key; install pins an explicit revision and remains inactive.
  `install_agent_marketplace_action` accepts `deployment_targets` as a JSON
  array string, for example
  `["codex_backbone", "claude_code_domain:finance"]`. The canonical target
  vocabulary is `codex_backbone`, `claude_code_domain` (all Claude Code domain
  agents), and `claude_code_domain:<domain>` (one domain). Omit the argument or
  pass `[]` for direct lifecycle invocation only; without an explicit binding,
  the action is not projected into an agent's automatic tool catalog. Invoke
  defaults to a side-effect-free dry run. Review its bounded receipt before a
  live call with the exact same inputs, `dry_run=false`, the returned
  `preview_invocation_id`, and `confirm_live=true`. The server rejects missing,
  failed, stale-revision, or input-mismatched previews. MCP never selects an
  approval decision automatically.
- Worker rows are honest discovery placeholders (`installable=false`) until a
  signed artifact ABI, SBOM, isolation contract, and attestation chain exist.
- Governed training readiness uses
  `inspect_agent_learning_readiness`,
  `inspect_agent_training_input_custody`,
  `preflight_agent_training_pair`,
  `request_agent_training_pair_admission`, and
  `get_agent_training_pair_status`. Select a company first. The preflight and
  structured-readiness, preflight, and exact-owner status tools are read-only;
  they cannot list or launch pairs and
  return no dataset, artifact, receipt, secret, or storage location. Their only
  caller-selected scope is `installation_id`, `revision_id`, and optional
  `project_id`; the server derives tenant, company, and actor authority.
  Structured readiness returns ordered source/authority stages, both blocked
  `puffer_v4` and `prime_verifiers` lanes, and one critical next action. It
  includes `input_attestation_unavailable` and cannot report readiness,
  admission, or execution as available. After a workflow-improvement packet has
  passed disposable-staging canary, `get_server_workflow_improvement_packet`
  reads that one exact scoped packet and `prepare_workflow_learning_handoff`
  binds its immutable approval/delivery audit, content-free candidate and
  episode manifests, and exact installed-action readiness. Omit the episode
  manifest to derive a v2 manifest from one verified custody read; this binds
  the exact snapshot dataset/count/cost/lifetime and clears only the input-
  custody blockers. Preparation remains a read-only blocked nomination: it
  grants no artifact, spend, scheduling, training, evaluation, promotion, or
  serving authority. Status requires an immutable marketplace source row and can read an archived
  retained project only with the exact tenant/company/user/project binding.
  `COMPANY` is read-only by default; admission requires an explicit
  target-company `agent-ops.training.execute` grant. Admission requires a
  visible-ASCII 1-200 character idempotency key. Its first call returns a v2
  request-bound `confirmation_receipt`; after an explicit user request, return
  that exact receipt with `confirm_admission_request=true`. A bare boolean is
  insufficient. Production currently performs zero writes and returns the
  structured hard-503 schema `lightbulb.training_pair_admission.v1`. There is no admission
  assembler, scheduler, launcher, or persisted/installable worker surface.
  The six authoritative blockers are `training_profile_unavailable`,
  `budget_authority_unavailable`, `snapshot_authority_unavailable`,
  `scheduler_unavailable`, `metering_unavailable`, and
  `artifact_storage_unavailable`. The confirmation requirement remains if the
  backend later becomes consequential. The 503 is returned only after
  authentication, target-company RBAC, idempotency-key, project-scope, and
  marketplace-source validation; it never substitutes for those failures.
  Input-custody inspection is a separate read-only contract. Its only inputs
  are installation, revision, and optional project constraints; the server
  derives owner scope and receipt association. Only a verified association
  returns a bounded v2 summary of receipt/manifest digests, sizes, timestamps,
  source cost, both framework pins, and the content-free snapshot binding,
  dataset digest, and aggregate split counts needed to reconcile a workflow
  episode set. It returns no raw receipt, signature, owner binding, storage
  location, or lane artifact/partition digest, and verified custody never means
  readiness, admission, scheduling, or execution. The
  compact Backbone profile exposes this inspector instead of the currently
  impossible admission request; the full profile keeps that guarded tool for
  compatibility.
- `list_business_primitives` returns a bounded summary catalog by default. A
  filtered full-contract query retains as many matching primitives as fit under
  the MCP payload ceiling and exposes `next_offset` when it must trim the page;
  set `summary_only=true` for a broader compact page.
- Query `communication.plan_crm_conversation_turn` for the exact Gmail-first
  CRM communication blueprint. It is a proposal-only executable primitive:
  capability hints describe policy, reservation, Gmail, observation, and CRM
  seams but grant no dispatch authority. Inputs are opaque CRM/account refs and
  digests; addresses and message text are not accepted.
- `run_business_primitive` enters the canonical versioned Executable Primitive
  Runtime on Python MCP. Hosted MCP resolves authenticated scope and fails closed
  while the managed runtime bridge is unavailable; it never relabels Backbone
  orchestration as primitive execution.
- `compile_business_workflow` emits a portable, inspectable workflow definition
  from selected primitives.
- `validate_business_workflow` fails closed on missing scope, RBAC, hidden
  setup, approval, state-machine, recovery, or test-plan contracts.
- `simulate_business_workflow` runs one synthetic iteration with no agent,
  connector, network, or external side effects.
- `compose_business_workflow` asks Agent Builder to compose a workflow or
  Agentic loop from the primitive plan and prepare server-side authoring.
- Named shortcuts include `business_create_invoice`, `business_write_email`,
  `business_draft_contract`, `business_review_contract`, and
  `business_schedule_meeting`.

### SDK-native custom projects

Version 0.14 adds MCP adapters over executable Python SDK modules:

- `list_executable_business_primitives` defaults to a bounded 20-item summary
  page. A non-empty query defaults to full schemas and returns at most one schema
  per MCP page so responses remain below the transport ceiling; follow
  `next_offset` for broader searches. Direct Python catalog callers may request
  up to ten full schemas per page.
- `run_sdk_business_primitive` executes SDK business process code for typed
  local validation and preview. The project reference is correlation data, not
  a server-enforced authorization claim.
- `validate_sdk_project` checks a project definition against the executable
  primitive registry and declared connector Tool readiness.
- `run_sdk_project_workflow` runs deterministic input bindings and structured
  event routes through the project runtime.
- `manage_sdk_project_runtime` starts, schedules, dispatches, resumes, worker-claims,
  and inspects revisioned durable workflow checkpoints.
- `list_sdk_runtime_outcomes` and `flush_sdk_runtime_outcomes` expose sanitized
  local telemetry and authenticated tenant/company persistence.
- `run_connector_conformance` checks all built-in provider contracts and can
  compare them with the hosted Tool schemas without invoking a vendor.

The generated `gmail_get_thread` function is the reviewed private-response read
used by the communication runtime. It requires exact `project_id`,
`project_ref`, `connector_account_ref`, and `effect="read"`. Its schema omits
`idempotency_key`: Spring always performs a fresh bounded read, returns at most
ten messages on that response, and durably stores only commitments and counts.
Use the separate route-descriptor discovery Tool first; neither the account
alias nor Tool version should be guessed.

For an in-thread write, `gmail_send_email` requires `thread_id` and the exact
RFC `parent_message_id` together; direct sends omit both. The generated wrapper
rejects a partial pair before connector I/O, and Spring independently enforces
the same closed schema and one-recipient audience.

The Python SDK also publishes closed Outlook materializer, observer, shared
runtime, and poll-artifact types, plus Slack and Teams materializer and observer
types. Their presence is not a claim that an MCP host has admitted a route.
Outlook provider acceptance is distinct from a later Sent Items observation;
Slack or Teams provider-object observation is distinct from delivery or a human
read. Bounded reads can establish an exact outbound object and a reply, but
never upgrade those facts into delivery/open/read claims. Hosted Gmail,
Outlook, Slack, and Teams execution remains feature-flagged off by default,
requires deployment-owned durable custody and a host-run poller, and no live
mailbox or channel is changed by installing this SDK.

The MCP functions do not reimplement primitive or workflow behavior. They parse
JSON and call `LightbulbClient`, `ProjectRuntime`, and the SDK registry. The
compact Backbone profile exposes these paths for discovery, validation, and
preview-safe execution, but not generic `invoke_tool`. The non-preview hosted
write contract targets `/api/tools/governed-invoke`. Spring binds the
authenticated project account to an exact tenant Tool Binding, Tenant
Connector, native adapter/handler, immutable target digest, approval, request,
and journal. Production still defaults this endpoint to a rollout hold:
operators must enable both
`GOVERNED_CONNECTOR_EFFECT_BOUNDARY_ENFORCED=true` and
`GOVERNED_CONNECTOR_EXECUTION_ENABLED=true`. With the default false/false
posture it fails closed with HTTP 503 and
`governed_connector_execution_disabled`; caller effect labels or approval
references cannot activate it.
`project_ref` remains correlation-only and never establishes Project scope.

Profit-workflow summaries expose searchable `capability_hints`; exact executable
results additionally expose a structured `profit_blueprint` with evidence,
action, guardrail, handoff, and connector-gap contracts. These fields describe
what a trusted host may collect or materialize. They do not grant connector
authority, and the ten proposal primitives themselves make zero connector
calls.

See [custom project guide](https://www.lightbulbpartners.com/developers#custom-projects) for project definitions, connector
test adapters, custom primitive authoring, bindings, statuses, and examples.

Each primitive advertises preferred connector ops plus setup requirements,
trigger events, emitted events, follow-up primitives, and hidden builder
guidance. For example, an email workflow should include reply webhook/watch or
polling setup, thread context, reply classification, no-response handling, and
approval gates before sends. The user should be able to ask for the business
outcome without knowing these infrastructure details.

Backbone owns cross-domain primitive planning. Agent Builder compiles workflows
or loops. Domain agents execute approved primitive steps. AutoCompany/workflow
runtime runs repeatable loops. Coding Agent is reserved for implementation
gaps, new adapters, new primitives, or approved software-delivery packets.

The recommended authoring sequence is `list_business_primitives` ->
`compile_business_workflow` -> `validate_business_workflow` ->
`simulate_business_workflow` -> `compose_business_workflow`. A successful local
simulation is evidence about the draft contract, not proof that any real agent
or connector executed. Publication and real execution remain server-side,
tenant/company scoped, RBAC checked, and approval gated.

### Continuous improvement tools

The backbone profile exposes local proposal-only supervisor tools plus the
authenticated server control plane:

- `run_workflow_improvement_cycle` evaluates every SDK primitive, records a
  score/trend, and updates a deduplicated local work-packet queue.
- `get_workflow_improvement_status` reads iteration, score, trend, green-run,
  no-progress, and pending-approval state.
- `list_workflow_improvement_packets` returns proposed or human-approved
  SDK-first packets for the coding harness.
- `sync_workflow_improvement_report` writes the latest allow-listed report and
  deduplicated packets to the current tenant/company ledger.
- `get_server_workflow_improvement_status` and
  `list_server_workflow_improvement_packets` read durable scoped state.
- `decide_workflow_improvement_packet` records one immutable human decision for
  implementation, publish, or deploy; it cannot overwrite a prior scope decision.
- `start_workflow_improvement_delivery` admits an implementation-approved packet
  to a server-issued `codex/` branch in staging only.
- `record_workflow_improvement_delivery_event` enforces implementation, draft
  PR, CI, staging, canary, rollback, and cleanup order.
- `get_workflow_improvement_audit` and
  `get_workflow_improvement_delivery` expose hash-chained evidence and state.
- `business_classify_reply` classifies inbound replies read-only and routes
  low-confidence or sensitive cases to human review.

MCP intentionally runs one cycle at a time. Start the finite CLI watcher via
`lightbulb improve-workflows watch --sync-server`; this avoids tying up an MCP
request while persisting each completed cycle to the authenticated ledger. The
CLI supervisor is finite by contract: default termination is 96 cycles, 24
hours, or two stable no-progress runs, whichever occurs first. Observed-outcome
intake, the work-packet queue, JSON artifacts, and retained JSONL history are
bounded; retired history is represented by a count/byte/digest receipt, and the
status surface exposes the final stop reason. `None` does not grant an
unbounded SDK watch. The supervisor never mutates code or calls an
agent/connector. The Harness may
implement only after an immutable implementation approval, and may use only the
server-issued isolated branch and disposable staging contract. Canary regression
forces rollback. Production publication and deployment remain separately gated
and are never performed by the improvement delivery tool.

### Agent runtime configuration

The compact profile exposes account-level runtime configuration tools so hosts
can set up Lightbulb without requiring the user to understand internal
`CODE_WORKSPACE` or `ASSISTANT_GLOBAL` bindings:

- `list_agent_runtime_options` lists Codex, Claude Code, and Backbone host
  surface options.
- `get_agent_runtime_config` shows the effective user/company/tenant runtime.
- `configure_coding_agent_runtime` sets Codex or Claude Code as the account's
  Lightbulb coding agent runtime.
- `start_codex_account_link`, `get_codex_account_link_status`, and
  `cancel_codex_account_link` wrap the Codex device-auth flow without exposing
  tokens to the MCP host.
- `configure_backbone_agent_surface` records ChatGPT MCP, Lightbulb hosted, or
  Codex Backbone as the preferred Backbone surface.
- `test_agent_runtime_config` resolves the configured path as a dry run without
  code or connector writes.

For example, a Codex host can call `start_codex_account_link`, poll
`get_codex_account_link_status`, then call
`configure_coding_agent_runtime(runtime_backend="codex_app_server",
use_codex_account="true")`. A Claude Code host can call
`configure_coding_agent_runtime(runtime_backend="claude_agent_sdk")`.

For Codex, `lightbulb setup --target codex` installs both surfaces:

- the `lightbulb` MCP server block in `~/.codex/config.toml`
- a local plugin copy under `~/.codex/plugins/lightbulb-partners/`
- a personal marketplace entry in `~/.agents/plugins/marketplace.json`

After setup, restart Codex, open Plugins, choose `Lightbulb Partners Local`, and
install or enable `Lightbulb Partners`. The bundled skill keeps project,
custom-agent, SOP, modernization, repo, and code-delivery requests on the
`start_consulting_project_workflow` front door until the Product Machine
approval gates produce execution-ready work packets.

### Project-creation preflight

The compact Backbone profile includes a deliberately separate
readiness/review/create journey and an independent explicit-feedback action:

- `get_project_game_snapshot(project_id)` accepts only a canonical project UUID
  and fetches the server-owned `lightbulb.project_game_snapshot.v1` projection.
  Tenant and company identity come from authenticated MCP context, and the SDK
  rejects a response whose tenant, company, project, schema, endpoint resources,
  truth boundary, or locked authority differs from the request. JWT users use
  the public project route; trusted API-key workers use the separately guarded
  internal route. The bounded snapshot reports the campaign, receipt-backed
  wealth evidence, explicit absence of exact project telemetry, current mission,
  shadow skill trial, evidence counts, and canonical follow-up resources. It is
  orientation-only: dispatch, live action, mutation, learning admission, and
  skill or policy promotion remain false and human-gated.
- `inspect_project_game_campaign(project_id)` is a temporary compatibility alias
  for that exact authenticated fetch. It no longer accepts project, plan, or
  cockpit JSON and never falls back to caller-supplied local derivation. The
  pure Python client's similarly named local helper remains available only as an
  explicitly offline, unverified preview and is not an MCP input path.
- `list_project_mission_runs(project_id, limit)` reads the exact-project
  `lightbulb.project_mission_run_ledger.v1` shared by the human campaign, SDK
  clients, and project workers.
- `start_project_mission_run(...)` requires `confirm_start=true` and the exact
  current `lightbulb.project_mission_briefing.v1`. It locks the briefing, play
  style, shadow skill arm and pins, bounded context references, run UUID, and
  idempotency boundary before action. It does not open a runtime, dispatch a
  worker, call a provider/tool, approve an action, or grant action authority.
- `bind_project_mission_action(...)` requires `confirm_bind=true` and accepts
  only a later durable action event in the same tenant/company/project scope;
  mission bookkeeping and outcome events are not accepted as action sources.
  The receipt verifies chronology and scope, not action semantics or external
  effect.
- A Project Outcome receipt may link the exact Mission Run and Mission Action
  receipts. That chain makes a derived Mission Debrief available, but it still
  cannot declare the mission completed or won, prove causality, admit learning,
  promote a skill/policy, dispatch a worker, or authorize another action.
- `list_project_skill_matches(project_id, limit)` reads the exact-project
  Training Arena ledger through MCP. It shows the worker-verified no-skill,
  one-skill, and skill-combination scores from one common shadow suite.
- Recording is intentionally internal-worker-only: it requires exact
  `AgentContextEnvelope` scope, `automl.experiments.execute`, explicit
  confirmation, the locked Mission Run loadout, and the unmodified authenticated
  orchestration receipt. MCP has no record tool.
- A saved match does not independently replay the Artifact signature, bind a
  business outcome, prove causality or skill attribution, create training data,
  authorize `automl_train_skill`, mutate confidence/routing, promote, activate
  policy, dispatch, act, or write production data. It must first be paired with
  an exact human-admitted lesson, then cross the separate dataset-custody and
  governed durable learning-run admission bridge.
- `list_project_learning_reviews(project_id, limit)` reads authenticated human
  decisions over exact Mission Run, Mission Action, and Outcome receipt chains.
- `record_project_learning_review(...)` requires `confirm_record=true`, a
  stable review UUID, and the exact recorded skill loadout. A human may admit a
  positive/negative shadow-training observation, reject the candidate, or
  defer it. Admission is training input only: no external truth, causality, or
  skill attribution is proven, and no live confidence, online learner,
  routing, policy, promotion, dispatch, action, or production-write authority
  changes. Agent workers can list these reviews but intentionally have no
  corresponding record tool and must never use `record_skill_outcome` for
  project mission evidence.
- `list_project_training_packs(project_id, limit)` reads the exact-project
  Learning Lab ledger. Each accepted pack joins one worker-verified Arena
  receipt and one human-admitted Level-Up receipt only when their Mission Run
  and no/single/combination skill loadout match exactly.
- Recording remains internal-worker-only and requires exact
  `AgentContextEnvelope` scope, `automl.experiments.execute`, explicit
  confirmation, verified upstream truth/authority boundaries, and both stored
  receipt digests. MCP has no training-pack record tool.
- A `lightbulb.project_training_pack.v1` is one reproducible candidate
  observation plus lineage. Its learning-run plan leaves runtime selection,
  dataset publication/custody, holdout verification, budget, durable run,
  capacity, commercial reservation, operator approval, and claimability false.
  The existing Memory learning-run ledger must perform those later admission
  steps; the pack does not train, update, promote, activate, dispatch, act, or
  write production data.
- `list_project_learning_runs(project_id, limit)` reads the receipt-backed
  twelve-stage Training Quest. A sanitized Memory execution receipt may complete
  worker-claim and terminal-result stages, but status remains last-observed
  evidence rather than live telemetry.
- Public MCP deliberately exposes no claim, heartbeat, checkpoint, finish, or
  raw lease-credential operation. Those fenced mutations stay inside an exact
  `AgentContextEnvelope` worker; the raw Memory lease token is kept behind a
  process-local opaque handle and never enters MCP arguments or responses.
- A runtime-reported successful result is not independent evaluation, training
  effectiveness, a learner/routing/model/policy update, promotion, business
  causality, action authority, or a production write. Those remain separate
  governed gates.
- `list_project_learning_result_evaluations(project_id, limit)` exposes the
  independent replay and human-admission receipts. The evaluator is a distinct
  scoped worker; admitting the exact candidate is a separate authenticated
  human decision. Neither step updates a learner.
- `list_project_shadow_learner_updates(project_id, limit)` exposes stage-12
  apply and rollback receipts to MCP and the human cockpit. It is deliberately
  read-only. Apply/rollback remain internal-worker operations with exact
  `AgentContextEnvelope` scope, `learning.runs.execute`, explicit confirmation,
  a human-admitted `gepa_champion_manifest`, and a one-revision/three-path
  Memory shadow-slot ceiling.
- Idempotent retries must match the original digest and report zero mutation;
  reused IDs with drift fail closed. Rollback is bound to the exact apply
  receipt and stored snapshot. The active learner, routing, promotion,
  activation, dispatch, production writes, and business-effectiveness claims
  stay false before, during, and after the shadow update.
- `list_project_science_evidence(project_id, limit)` reads the exact-project
  `lightbulb.project_science_ledger.v1`. Agents inspect it before research,
  data, AutoML, model-serving, solver, or control work so the next quest and
  predecessor receipt are shared context rather than prompt memory.
- `record_project_science_evidence(...)` requires `confirm_record=true` and
  records one digest-bound artifact for hypothesis, search, data engineering,
  ML/serving, or solver/control. Later stages require the exact predecessor
  receipt. The receipt records reported tools and skills but does not attest
  their runtime use, validate artifact contents or scientific claims, prove
  model quality or policy optimality, admit learning, or authorize any action.
  Loose project-plan fields remain claims and do not become verified campaign
  progress.
- `list_project_business_outcomes(project_id, limit)` reads the append-only
  `lightbulb.project_business_outcome_ledger.v1` shared by the human campaign view,
  SDK clients, and project workers.
- `record_project_business_outcome(...)` requires `confirm_record=true` plus
  explicit baseline and observed values. With no `source_event_id`, it records
  an actor-authenticated human attestation. With `source_event_id`, Spring binds
  the receipt to an existing event in the same tenant/company/project scope.
  The receipt may say `improved`, `regressed`, or `unchanged`; it never proves
  the linked action caused that movement, admits learning, changes skill
  confidence, promotes a policy, dispatches a worker, or authorizes an action.
- `list_project_policy_assignments(project_id, limit)` reads the immutable
  decision-time action and propensity ledger.
- `record_project_policy_assignment(...)` requires `confirm_record=true` and
  bounded JSON for 2-20 actions, one behavior policy, and 1-8 candidates. With
  a source event it binds the exact same-project decision record. The receipt
  logs what was known before the outcome and grants no execution authority.
- `list_project_policy_evaluations(project_id, limit)` reads deterministic
  offline estimates and their identification/authority boundaries.
- `evaluate_project_offline_policy(...)` requires `confirm_evaluate=true` and
  20-2,000 unique assignment/outcome receipt pairs. Spring verifies every
  assignment, exact action event, metric, outcome, and scope before Artifact
  Service computes IPS/SNIPS and diagnostics. A supported shadow candidate
  still requires separate human-reviewed learning admission; the tool cannot
  mutate skill confidence, promote/activate a policy, or authorize an action.
- `inspect_project_creation_world_ready(name, instructions, play_style)` invokes
  no project or preflight endpoint. Normal MCP authentication/account-context
  bootstrap may occur on first use before the local evaluation. It returns the bounded
  `lightbulb.project_start_readiness.v1` manifest shared with the human campaign
  view: participant, experience lens, locked authority, checks, blockers, one
  next action, and a `lightbulb.project_game_start.v1` projection. The game
  projection is a non-authoritative view of the reviewed win condition, one
  bounded initiative style, planned Project Agent loadout, read-only first
  mission, and planned data/ML/solver campaign. Accepted styles are
  `guided_human_in_the_loop` (default), `proactive_copilot`, and
  `autonomous_shadow`. They change only whether agents wait, prepare proposals,
  or run separately authorized read-only/sandbox shadow quests. They never
  authorize dispatch, live actions, production writes, or approval. Skill comparisons stay shadow-only,
  policy learning is `not_admitted`, and promotion requires authenticated
  outcome evidence plus explicit human approval. `ready=true` authorizes only
  entry into read-only review; it never means the project, worker dispatch,
  downstream action, RL policy, or model promotion is authorized.
- `preflight_project_creation(name, instructions)` is read-only. It sends no
  plan, approval state, project ID, or connector payload. It requires a
  selected company and returns bounded,
  valid JSON with schema `project_creation_preflight_receipt.v1`, containing
  the normalized draft, the strict `project_creation_preflight.v1` review, and
  the execution UUID observed on the trusted `execution` SSE event. It also
  carries a deterministic episode ID and exact company-level episode scope
  observed only on the dedicated `agent_episode` SSE event. IDs written by the
  model inside its result are never accepted as receipts. This tool does not
  create anything and does not auto-answer `next_question`. Optional public
  research findings are exact retrieved excerpts, never model paraphrases:
  every retained excerpt is mechanically matched to per-URL evidence in the
  runtime-observed public-source inventory, and unmatched or composite-provider
  text is withheld. Proposed public searches cross the provider boundary only
  when every term is in the bounded research vocabulary or the user explicitly
  marked the proper noun as `public topic <name>` (or an equivalent public
  entity label). Unknown/private terms and unapproved numeric identifiers are
  withheld, while an independent safe proposal may still run.
  Current receipts include a bounded `criticality_findings` ledger whose
  evidence references, confidence, resolution mode/cost, and `block`, `warn`,
  `assume`, or `ignore` disposition are validated against the trusted episode.
  Only `block` and `warn` findings become `critical_gaps`, `open_questions`, or
  `next_question`. `ignore` requires a field-matched contextual draft span
  bound by UTF-8 byte offsets and SHA-256, so a coverage bit alone cannot erase
  a question. Parser-v2 receipts remain readable for historical replay;
  current ledger receipts use parser v3.
- `create_project_from_preflight(receipt_json, confirm_create, play_style, ...)` requires
  the complete, unchanged JSON from `preflight_project_creation`, literal
  `confirm_create=true`, and a selected company. Optional inputs are limited to
  bounded play style, workspace UUID, repository-connection UUID, and
  idempotency key. It performs one `/api/projects` POST with the exact
  receipt-bound draft; it accepts no Product Machine plan, inferred scope, or
  approval state. An idempotent retry cannot silently select a different play
  style.
- `submit_project_creation_preflight_feedback(receipt_json, helpfulness,
  calibrated_criticality, factual_grounding, idempotency_key,
  confirm_user_feedback)` requires the complete typed preflight receipt,
  literal `confirm_user_feedback=true`, and a selected company. Each judgment
  must be `pass`, `fail`, or `not_assessed`. It addresses only the episode
  already bound to the receipt and cannot accept actor/scope IDs, reward,
  rubric pass, or training eligibility. Its success JSON is privacy-minimized.

Preflight is evidence for a later user decision, not authorization. If its
review identifies a useful next question, ask the user and run a new preflight
for the revised draft. Never silently fill the answer or call create merely
because preflight completed.

Feedback must come from the user's explicit judgments; project creation,
approval, or acceptance is never a substitute. It is append-only and one-shot:
an identical retry with the same key is idempotent, while changed dimensions or
a new key conflict. A unanimous pass remains a preference/usefulness signal,
not independent factual or business-outcome proof.

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
All generic and generated connector calls additionally require `project_id`,
`project_ref`, `connector_account_ref`, `idempotency_key`, and `effect`.
Spring verifies the effect and exact project/account route; missing custody is
blocked as `governed_connector_context_required`, and writes return the
Spring-owned approval proof required for an approved resume. There is no
legacy/default connector fallback. Unknown or unreviewed generated Tools retain
the conservative WRITE classification and remain fail-closed until promoted by
a versioned Spring effect-catalog migration.
Call `list_project_connector_accounts(project_id, provider)` before execution
when the bound alias is not already known. It reads Spring's project-scoped
binding authority and returns only provider, `connector_account_ref`, account
label, target resource, and status. OAuth connection IDs, credentials, tokens,
and unexpected response fields are omitted. The underlying endpoint rechecks
the authenticated tenant, selected company, project access, and RBAC; the MCP
server does not synthesize or accept an account alias from model context.
Full-profile generated MCP tools inherit the same guard, including generated
`coding_*` domain actions and generated `github_*` repo/PR/deployment tools.
Page Builder remains available for pure design sessions with
`force_page_builder=true`; project-like page, portal, app, SOP, workflow, or
GitHub-backed site requests start in the consulting workflow first.
Direct `code_workspace_chat` calls also route explicit custom-agent, SOP, or
project-build prompts into the consulting workflow first; normal bounded
workspace fixes continue to the selected code workspace.

### Hosted MCP endpoint for ChatGPT and Claude

For ChatGPT Apps/Connectors and Claude web/desktop remote MCP, use the hosted
Streamable HTTP MCP endpoint:

```text
https://agents.lightbulbpartners.com/mcp/lightbulb
```

`GET /mcp/lightbulb` returns health and protected-resource metadata hints.
Unauthenticated MCP calls receive an OAuth challenge pointing at
`/.well-known/oauth-protected-resource`, and the authorization flow bounces
users through the Lightbulb login/onboarding path before issuing a bearer token
for the MCP resource.

The hosted tool surface is a curated orchestration surface over the
same account-scoped Lightbulb control plane. It includes identity and company
selection helpers; `lightbulb_status` for current work, blockers, approvals,
projects, workflows, and next actions; `lightbulb_capabilities` and
`list_agents` for tool and agent discovery; project tools; workflow tools;
approval tools; and AutoCompany loop/run tools. Use `lightbulb_status` first
when the user asks what Lightbulb is working on, what needs attention, or what
to do next.

Claude Code normally uses the installed stdio MCP plus Continuum hooks. Claude
web/desktop and ChatGPT cannot run those local hooks; call `context_open`,
`context_pack`, `context_search`, `context_read`, and `context_checkpoint`
explicitly instead. These tools return bounded evidence and never enlarge the
provider's native context window. Their recalled payloads carry a per-result
untrusted-evidence boundary even if a host omits the server instructions.

The hosted endpoint also publishes the generated `dynamic_workflow_*` protocol.
Those eight tools delegate through a thin schema/alias adapter to one Spring
Dynamic Workflow authority with exact authenticated project scope, sealed
host/assignment custody, Context Space continuity, pessimistic checkpoint
locking, idempotent replay, and atomic Execution Run cancellation
acknowledgement. The local stdio server does not start a second Dynamic Workflow
lifecycle or reuse generic SDK checkpoints: its same eight tools call the
authenticated Spring control-plane endpoints through the SDK. Hosts may
therefore use either the installed stdio MCP server or `/mcp/lightbulb` without
splitting workflow authority or persistence.

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
| **Module not found (`mcp`)** | Reinstall: `python -m pip install --upgrade lightbulb-mcp`. |
| **Stale config** | `lightbulb` / `lightbulb setup` status shows whether MCP entries exist for each host editor. |

## Security posture (MCP)

- Secrets live in **host env** or OS token cache—never commit `.mcp.json` with passwords or JWTs.
- Token cache files are user-private and written atomically (see SDK README).
- Error paths avoid echoing full HTTP bodies to logs/tracebacks where the SDK controls messaging.

## Version history (MCP-facing)

### 0.15.0

- Added governed skill discovery, project AutoResearch and learning events, typed learning and Shopify primitives, durable retry operations, and the new adaptive workflow-learning surface.
- Exact profile counts are published by the generated capability inventory; this
  document does not maintain a second count.

### 0.14.1

- `run_recursive_agent` accepts approved runtime-authored agents only through their opaque `runtime_agent.<uuid>` references in the finite allowlist; exact scope, RBAC, approval, digest, model, policy, and frozen tool authority remain server-controlled.
- Runtime-action lifecycle tools remain private/read-authoring surfaces and never activate or directly execute ordinary domain dispatch.

### 0.14.0

- Added 13-primitive discovery and project-scoped SDK execution tools.
- Added custom project validation, event-routed execution, revisioned durable workflow operations, outcome telemetry/flush, and connector schema conformance through thin MCP adapters.
- The default non-private tool surface reports 1381 tools (1384 with private runtime actions, 1384 with private Project learning mutations, or 1387 with both opt-ins); the current compact Backbone profile contains 109 tools, including the Project Mission Run, Training Arena, Learning Lab, twelve-stage Training Quest, independent result evaluation, bounded shadow-update ledger, Science, Outcome, Strategy, and governed Level-Up Review ledgers.

### 0.13.0

- Added authenticated durable improvement sync, status, queue, immutable decisions, audit, and delivery-state tools.
- Added the guarded Harness branch/draft-PR/CI/staging/canary/rollback contract and `business_classify_reply`.
- The full tool surface reports 1278 tools; the compact backbone profile reports 52.

### 0.12.0

- Added local continuous-improvement cycle, status, and packet-list tools backed by the SDK evaluator. The full tool surface reports 1269 tools; the compact backbone profile reports 43.
- Improvement artifacts are proposal-only, sanitize observed runtime summaries, and fail closed on code mutation, connector execution, publish, and deploy.

### 0.11.0

- Added SDK-backed workflow compile, validate, and synthetic simulation tools. The full tool surface reports 1266 tools; the compact backbone profile reports 40.
- Added `lightbulb.business_workflow_definition.v1` as the portable draft shape between external harnesses, Agent Builder, and the governed runtime.

### 0.10.1

- Documentation refresh for partner setup, hosted MCP, backbone profile defaults, and full-vs-filtered tool surfaces. The current full local surface reports 1263 tools; the backbone profile reports 37.
- Added `lightbulb version` for quick package verification in support and partner onboarding flows.

### 0.4.0

- Same transport and env vars; underlying HTTP client aligns with SDK security fixes (URLs, localhost detection, error sanitization).
- Tool count and names unchanged from 0.3.x series unless platform endpoints moved (regenerate from server package when upgrading).

### 0.3.0

- Major expansion of tool families (voice, HR live, code workspace collaboration/runtimes, AOC, memory graph, CRM tasks, approvals, notifications, domain workspaces, Xero helpers, page/document automation, etc.).
- `lightbulb-mcp` console script added for portable configs.

### 0.2.0

- Broad domain registry alignment and Xero-oriented tooling alongside existing Stripe/workflows surface.
