# Custom projects with the Lightbulb SDK

Lightbulb 0.14 introduces an SDK-native runtime for projects that need reusable
business process code, typed connector access, and event-routed workflows.

The SDK and MCP project one canonical primitive runtime contract:

| Path | Use it for |
|------|------------|
| `run_business_primitive` | Canonical versioned primitive execution; Python runs eligible implementations and hosted MCP fails closed until its managed runtime bridge exists |
| `run_sdk_business_primitive` | Explicit compatibility alias for the same packaged Executable Primitive Runtime |
| `ProjectRuntime` | A custom project's declared primitives, connector allow-list, policy, and workflows |
| `DurableProjectRuntime` | Revisioned pause/resume, schedules, idempotent events, and distributed worker claims |

SDK-native execution never calls a vendor directly. `HostedConnectorExecutor`
uses the authenticated `LightbulbClient` for governed reads and writes. A write
can dispatch only after Spring exact-binds the authenticated Project UUID,
tenant Tool Binding and connector account, catalogued effect and Tool version,
immutable target/input digest, stable idempotency identity, and a matching
single-use approval. Unsupported routes, missing authority, and contract drift
fail closed before vendor I/O. Use previews or `InMemoryConnectorExecutor` for
deterministic development; enabled dispatch does not itself constitute
production connector certification or company-running readiness.

## Built-in implementations

Examples from the executable catalog include:

- `communication.classify_reply`
- `communication.write_email`
- `finance.create_invoice`
- `finance.ingest_supplier_invoice`
- `legal.draft_contract`
- `legal.review_contract`
- `calendar.schedule_meeting`
- `crm.qualify_lead`
- `hr.onboard_employee`
- `finance.collect_payment`
- `approval.request_decision`
- `documents.generate_business_artifact`
- `project.create_work_packet`
- `learning.plan_optimization_sweep`
- `commerce.plan_shopify_storefront`
- `gtm.plan_omnichannel_product_launch`

Inspect exact Pydantic input/output schemas at runtime:

```python
from lightbulb import executable_business_primitive_catalog

catalog = executable_business_primitive_catalog()
for implementation in catalog["implementations"]:
    print(implementation["primitive_ref"], implementation["version"])
```

## Plan and shard omnichannel product launches

`gtm.plan_omnichannel_product_launch` is a proposal-only compiler for one
product brief intended for one project/store. It emits a deterministic Shopify
`DRAFT` create -> `ACTIVE` update -> explicit publication -> landing-readiness
gate graph, followed by analytics-ranked social proposals. A HubSpot campaign
container is included when selected. Writes have separate content-bound
approval units, and the plan declares required receipts and a bounded
evaluation contract. Compilation never calls a connector, authenticates a
store, or claims that a campaign, sequence, product, or post was launched.

```python
from lightbulb import (
    PlanOmnichannelProductLaunchPrimitive,
    plan_omnichannel_product_launch,
)

plan = plan_omnichannel_product_launch(
    PlanOmnichannelProductLaunchPrimitive.example_inputs
)
assert plan.live_systems_changed is False
operations = {operation.capability: operation for operation in plan.operations}
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
```

Use `operation.connector_inputs(resolved_outputs)` to strip SDK-only
discriminators and resolve declared bindings from earlier operation outputs
before governed dispatch. The landing-readiness operation is an evidence gate,
not a connector call, and rejects `connector_inputs(...)`.

For verified analytics, the trusted host validates the source connector receipt
and calls `mint_product_launch_analytics_snapshot(...)`. The resulting HMAC
covers the full provider/account/window/metrics/evidence payload plus the exact
authenticated tenant/company/user/project scope. Independently seal every
Shopify, CRM, and social destination with
`mint_product_launch_connector_account_binding(...)`, then pass the complete
set as `connector_account_bindings=` together with the same `verified_scope=`
and `scope_keyring=` when planning. Trusted planning rejects a missing,
cross-scope, or extra destination binding. Copying a scope digest onto
caller-created metrics or account refs is not sufficient; caller-supplied
evidence and partition fingerprints stay explicitly unverified.

For a host-HMAC-bound plan, once the host has checked the underlying live
artifacts, `mint_product_launch_receipt(...)` creates HMAC-sealed receipts bound
to the exact scope, loop run, iteration, plan digest, criterion, and relevant
operation ID/digest. Every write receipt additionally carries the exact
`approval_unit` and a host-verified approval receipt digest; non-write receipts
cannot carry approval evidence. The host-bound plan is also HMAC-sealed.
Performance receipts include a measured window whose duration must satisfy the
immutable `measurement_window_hours` policy and whose start must follow every
required launch operation's completion time.
`verify_product_launch_receipts(...)` requires the complete receipt set and
returns verified `EvidenceRef` values for Dynamic Workflow admission; it fails
closed on scope, plan, operation, timing, freshness, sample, or HMAC mismatch.

`evaluate_product_launch_iteration(...)` performs that verification and then
compares the verified performance metric with the plan's immutable target. Its
bounded decision is `target_met`, `revise_plan`, or
`iteration_limit_reached`, with a next iteration only for `revise_plan`. The
host-HMAC-sealed evaluation is the KPI-comparison evidence; a later iteration
requires that exact prior evaluation plus newly attested evidence. It
does not revise the plan, approve work, materialize connectors, or schedule
itself. Replaying one receipt set produces the same signed evaluation and
deterministic `commitment_ref`; a durable host must accept only one evaluation
digest for each commitment.

`create_product_launch_evaluation_loop(...)` intentionally rejects the
proposal primitive's caller-unverified plan. The host must first re-plan the
reviewed input with HMAC-sealed analytics and destination-account bindings,
`verified_scope=`, and `scope_keyring=`, then pass the same keyring when seeding
control state.

Portfolio proposals are partitioned by the supplied `scope_fingerprint` plus
`project_ref`. The SDK ensures that one shard contains only one such pair, but
the fingerprint is a caller-supplied partition key, not an authenticated scope
attestation or permission grant. A trusted host must derive or verify it against
the active tenant/company/project scope before dispatch. The default limit is
12 launch records and at most 100 estimated initial operations per shard:

```python
from lightbulb import compile_product_launch_portfolio

portfolio = compile_product_launch_portfolio(scoped_launch_jobs)
for shard in portfolio.shards:
    assert {
        (job.scope_fingerprint, job.project_ref) for job in shard.jobs
    } == {(shard.scope_fingerprint, shard.project_ref)}
    proposal_payload = shard.to_dict()
```

The operation estimate covers the initial graph only. Serialized budgets are
256 KiB per job, 4 MiB per shard, and 64 MiB per portfolio. The compiler still
eagerly builds an in-memory manifest and accepts at most 10,000 launch records
as a count-validation ceiling; byte budgets can reject a portfolio earlier.
Neither ceiling is a production throughput, scheduling, connector-rate, or
safe-execution guarantee. Page large portfolios into smaller externally
bounded batches. Partitioning creates no products or campaigns.

The catalog/MCP primitive deliberately returns a caller-unverified proposal and
cannot seed trusted control state. After review, HMAC-seal the analytics and
every destination account, then re-plan through
`plan_omnichannel_product_launch(..., verified_scope=..., scope_keyring=...,
connector_account_bindings=...)`. Seed a generic planner-builder-evaluator
state from that host-bound plan and pass the same `scope_keyring=`. This creates
bounded state and receipt-kind acceptance criteria only; it does not
materialize connectors, verify approvals, mint or verify receipts on its own,
schedule observation events, fetch post-launch metrics, or run an evaluator:

```python
from lightbulb import create_product_launch_evaluation_loop

state = create_product_launch_evaluation_loop(
    host_bound_plan,
    scope=authenticated_dynamic_workflow_scope,
    scope_keyring=host_receipt_keyring,
    created_at=workflow_start_time,
)
assert state.limits.max_iterations <= 4
```

A resumable host-side storefront runner now exists:
`run_shopify_product_launch(...)` previews with zero executor/verifier calls or
executes the signed DRAFT → ACTIVE → explicit-publication chain. Each write has
its own HMAC-sealed platform approval grant and stable idempotency identity.
Every completion needs `ConnectorExecutionProvenance` binding the authenticated
project UUID, actual Tool version, account/Tenant Connector, exact request,
approval, journal, receipt, completion time, returned state, and the exact
lowercase route digest discovered for that project/account/Tool. A descriptor
for one Tool must never be reused for another Tool.

The final `LandingReadinessVerifier` read must independently prove the exact
URL, product ID/title, price, currency, publication IDs, page visibility, and
checkout availability after publication. No generic success is accepted. CRM
and social stay held until that receipt exists. The runner then releases only
the next operation whose signed graph dependencies are met; social remains
held when it still depends on CRM evidence. It does not claim omnichannel
completion. Hosted use requires the exact-account provenance authority and a
genuine live-storefront reader; missing surfaces fail closed.

`ObservationRuntime` now schedules the post-action window, performs an
exact-account Shopify or Google Analytics read, seals the normalized evidence,
and evaluates the appropriate boundary. Connector schedules must pass the
exact descriptor `routeDigest` as `expected_route_digest`; it becomes part of
the sealed job digest and is compared with Spring provenance before any
evaluator artifact is minted. Host observations pass no route digest. Use
`schedule_storefront_phase(...)`
with the exact four Shopify/readiness receipts for a sealed
`StorefrontPhaseEvaluation`; it is explicitly a storefront-phase result, not
omnichannel completion. Use `schedule_gtm(...)` only after the full CRM, social,
scope, and storefront receipt set exists. `ObservationWorker` is the bounded
polling host; `JsonFileObservationArtifactRepository` plus a scoped
`JsonFileCheckpointStore` provide restart-safe single-host persistence. The
application must actually start that worker (or an equivalent queue/cron
consumer); scheduling a checkpoint alone does not create a background process.
CRM campaign execution, remaining social releases, account rate/spend controls,
and newly approved revision materialization remain separate follow-on actions.

Use `LightbulbSoftwareFactoryRuntime.run_storefront_launch(...)` when launch
completion and observation commitment must be one resumable application step.
It schedules only after the four exact Shopify/readiness receipts exist. Use
`run_abandoned_recovery(...)` on the same facade for the recovery graph; it
schedules the host holdout evaluator only after every approved recovery action
has a verified execution receipt.

## Compose the ten-workflow profit flywheel

The proposal-only profit family wraps the product launch with ten adjacent
workflows: portfolio allocation, opportunity discovery, offer/margin,
inventory/fulfillment, storefront conversion, creative experiments,
incremental acquisition, CRM lifecycle, abandoned-revenue recovery, and
returns/LTV. Use `PROFIT_WORKFLOW_DEFINITIONS` as the code-owned ordered registry
and `PROFIT_EXECUTABLE_PRIMITIVES` when building a custom registry.

```python
from lightbulb import (
    PROFIT_WORKFLOW_DEFINITIONS,
    compile_profit_flywheel,
    plan_profit_workflow,
    profit_workflow_example_inputs,
)

inputs_by_workflow = {
    definition.workflow_id: profit_workflow_example_inputs(definition.workflow_id)
    for definition in PROFIT_WORKFLOW_DEFINITIONS
}
plans = {
    workflow_id: plan_profit_workflow(workflow_id, inputs)
    for workflow_id, inputs in inputs_by_workflow.items()
}
manifest = compile_profit_flywheel(inputs_by_workflow)

assert len(plans) == len(manifest.nodes) == 10
assert manifest.external_workflow_refs == (
    "gtm.plan_omnichannel_product_launch",
)
assert all(plan.effect_boundary.connector_writes == 0 for plan in plans.values())
```

The manifest is compact: it retains immutable plan digests, readiness summaries,
and an eighteen-edge code-owned handoff graph rather than embedding ten full
plans. The existing omnichannel launch is an explicit external anchor between
the readiness/creative workflows and the acquisition/lifecycle/recovery/LTV
workflows. Workflow profit projections overlap and therefore must not be
summed. Each plan selects at most ten actions from at most twenty candidates
inside one declared cash budget. The bounded global selector maximizes total
risk-adjusted contribution profit; capital efficiency and time-to-value break
ties after dependency bundles, mutual exclusion, capability availability,
confidence, downside, cash budget, and action-count constraints are enforced.

For a real multi-step `LightbulbProject`, pass a prior output digest as a nested
binding such as
`source_plan_digests: ["$steps.allocate.output.plan_digest"]`. Do not copy a
full plan into another step or weaken the SDK-only Backbone rejection. The
project runtime composes proposal steps synchronously; a trusted durable host is
still responsible for approvals, multi-day observation windows, connector
receipts, and invoking the signed evaluator.

Verified mode is intentionally unavailable through ordinary primitive inputs.
The authenticated host must HMAC-seal every connector account with
`mint_profit_connector_account_binding(...)`, mint account-scoped metric
evidence from source receipts with `mint_profit_metric_evidence(...)`, and call
`plan_profit_workflow(..., verified_scope=..., scope_keyring=...)`. After each
approved action executes, `mint_profit_action_execution_receipt(...)` binds the
provider receipt, action digest, account, plan, run, iteration, and the mandatory
approval receipt for writes. `mint_profit_outcome_evidence(...)` accepts only a
complete execution-receipt set and a measurement window that begins after all
actions completed. The host can then call
`evaluate_profit_workflow_iteration(...)`. A durable host must enforce one
outcome digest for each deterministic `commitment_ref`. Scope, key IDs, HMACs,
connector accounts, approvals, and authority never come from user-authored
input fields.

For the closed connector subset, use `run_profit_workflow_actions(...)` rather
than inventing a per-workflow dispatcher. It validates every exact connector
payload before the first live call, executes only dependency-ready operations,
pauses at approvals/failures, and resumes from signed receipts. Offer and
storefront product updates, reviewed social experiment cells, consent-safe
Gmail lifecycle messages, and the discount→email recovery graph use this rail.
Every completed run remains `causal_claim_ready=False` until its scheduled
observation is accepted.
`LightbulbSoftwareFactoryRuntime.run_profit_workflow(...)` performs that join
for the materializable offer, creative, and lifecycle subset: it persists the
exact observation commitment only after the complete signed action graph has
receipt-backed completion.

`commerce.recover_abandoned_revenue` has an additional privacy/experiment
facade: `mint_abandoned_recovery_case(...)`,
`plan_abandoned_revenue_recovery(...)`,
`run_abandoned_revenue_recovery(...)`, then
`schedule_abandoned_recovery_observation(...)`. It keeps recipient, recovery
URL, and one-time code out of persisted artifacts, reserves holdouts, applies
consent/frequency/stock/expiry/margin gates, requires a fresh short-lived
`mint_recovery_dispatch_attestation(...)` before any live write, and evaluates only a trusted
randomized-holdout ledger covering every targeted Shopify/Gmail account.
The generic `run_profit_workflow_actions(...)` route intentionally rejects this
workflow so callers cannot bypass those live consent, inventory, frequency, and
expiry checks.

`RecoveryIngestionWorker` supplies the governed trigger before that facade. It
scans one exact Shopify account in cursor pages of at most 20 rows (at most 250
rows per run), validates every page's provenance and strict output, obtains
short-lived host-HMAC enrichment, and checkpoints the scoped case and plan.
Raw email, recovery URL, and code are resolved only transiently. Persist its
returned `next_cursor` to continue larger scans. Live sends additionally require
a durable transactional `RecoveryContactReservationAuthority`; the included
in-memory implementation is single-process/test-only, and preview consumes no
reservation.

Catalog `capability_hints` and the executable catalog's structured
`profit_blueprint` make connector evidence and action capabilities searchable.
They are discovery metadata, not execution authority: the planner itself
declares no connector tools and performs zero connector calls.

The current connector gaps stay machine-readable in each plan. In particular,
paid-ad budget updates and universal inventory mutation need new governed host
services; the reviewed social-publish subset is governed, but broader
Shopify/social operations remain provider-specific; HubSpot workflow/campaign
actions are domain-agent surfaces rather than a typed sales-sequence executor.
A proposal must never be reported as a live effect.

The output distinguishes connector tools from domain actions. In particular,
`hubspot.create_campaign` is a domain-agent action that creates only a campaign
container; it does not author a sales sequence. Instagram native scheduling is
currently unsupported, and the current LinkedIn schedule route publishes
immediately, so the planner represents both as unscheduled publish proposals.

## Run an event-routed project locally

This workflow classifies an inbound reply. A `meeting.requested` event routes
to the meeting primitive; other classifications end after the first step.

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
                "input_mapping": {
                    "reply_text": "$input.reply_text",
                },
                "routes": {
                    "meeting.requested": "schedule",
                },
            },
            {
                "id": "schedule",
                "primitive_ref": "calendar.schedule_meeting",
                "input_mapping": {
                    "attendees": "$input.attendees",
                    "title": "$input.title",
                    "time_window": "$input.time_window",
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

validation = runtime.validate()
assert validation.valid

run = runtime.run_workflow(
    "route_reply",
    {
        "reply_text": "Can we schedule a call next week?",
        "attendees": ["buyer@example.test"],
        "title": "Renewal follow-up",
        "time_window": "next week",
    },
)

assert run.status == "completed"
assert [step.step_id for step in run.step_runs] == ["classify", "schedule"]
```

The classifier's result and evidence do not retain the raw reply text. Custom
primitives should apply the same rule to sensitive content: return the minimum
structured output needed by later steps.

## Test connector writes without credentials

`InMemoryConnectorExecutor` is a real adapter at the Connector Execution seam.
It supports preview blocking, approval enforcement, request recording,
idempotent replay, and payload-conflict detection.

```python
from lightbulb import InMemoryConnectorExecutor

sent = []

def send_email(request):
    sent.append(request.arguments)
    return {"messageId": "msg-test-1"}

connectors = InMemoryConnectorExecutor({
    "gmail.send_email": send_email,
})
```

A project must also allow the Tool:

```python
project = LightbulbProject.model_validate({
    "project_ref": "customer-follow-up",
    "hosted_project_id": "00000000-0000-0000-0000-000000000044",
    "name": "Customer follow-up",
    "primitive_refs": ["communication.write_email"],
    "connector_tools": ["gmail.send_email"],
    "workflows": [{
        "key": "send_email",
        "title": "Send email",
        "entry_step": "email",
        "steps": [{
            "id": "email",
            "primitive_ref": "communication.write_email",
        }],
    }],
})
```

Without approval, a non-preview write pauses before the handler:

```python
runtime = ProjectRuntime(project, default_primitive_registry(), connectors)

inputs = {
    "to": ["customer@example.test"],
    "subject": "Checking in",
    "body": "Hello",
    "send": True,
}

pending = runtime.run_workflow(
    "send_email",
    inputs,
    preview_only=False,
    connector_account_refs={"gmail": "gmail-primary"},
    run_ref="follow-up-42",
)
assert pending.status == "pending_approval"
assert sent == []
```

An approved retry uses the same `run_ref`. The runtime derives a stable
per-step connector idempotency key:

```python
completed = runtime.run_workflow(
    "send_email",
    inputs,
    preview_only=False,
    approval_refs={
        "communication.write_email": "00000000-0000-0000-0000-000000000066"
    },
    connector_account_refs={"gmail": "gmail-primary"},
    run_ref="follow-up-42",
)
assert completed.status == "completed"
assert len(sent) == 1
```

Re-running the same approved request with `follow-up-42` returns the cached
connector result. Reusing that key with different connector arguments fails
with `idempotency_conflict`.

## Use hosted connectors

Build the same runtime from an authenticated client:

```python
from lightbulb import LightbulbClient

client = LightbulbClient(BASE_URL, auth=auth)
runtime = client.build_project_runtime(project)

result = runtime.run_workflow(
    "send_email",
    inputs,
    preview_only=True,
)
```

Preview writes do not call `client.invoke_tool`. A non-preview hosted write with
`hosted_project_id` targets `/api/tools/governed-invoke`. Spring resolves the
exact authenticated project account and native Tool route; production still
defaults the rollout flags to false. While that gate is closed, the SDK surfaces
the server's non-retryable 503 instead of fabricating `pending_approval` or
falling back to the legacy route. Operators activate the route only by setting
both `GOVERNED_CONNECTOR_EFFECT_BOUNDARY_ENFORCED=true` and
`GOVERNED_CONNECTOR_EXECUTION_ENABLED=true`.
For safe hosted reads, `hosted_project_id` activates Spring's authenticated
project-scope check and project connector binding.
`project_ref` remains a local correlation value and must not be interpreted as
server-enforced tenant, company, or project scope.
Apply-mode Project runs must also supply the exact project-bound connector
account alias in `connector_account_refs`, keyed by operation ref, Tool, or
provider. These values are opaque routing aliases, never credentials. Durable
checkpoints retain them across approval, retry, scheduling, worker restart, and
resume so a recovered write cannot silently drift to another account; Spring
still revalidates the alias against authenticated project scope.

Convenience methods are also available:

```python
client.list_executable_business_primitives(query="invoice")
client.run_sdk_business_primitive(
    "finance.create_invoice",
    {
        "customer_name": "Acme",
        "amount": "250.00",
        "commit": True,
    },
    project_ref="billing-automation",
    preview_only=True,
)
client.validate_sdk_project(project)
client.run_sdk_project_workflow(project, "send_email", inputs)
```

## Durable pause, resume, schedules, and events

`ProjectRuntime.run_workflow` remains the smallest synchronous execution path.
Use `DurableProjectRuntime` when a run may outlive one process or pause for a
decision. A checkpoint is saved before execution and after every step transition;
updates use an expected revision so stale workers fail instead of overwriting
new state.

```python
from lightbulb import InMemoryCheckpointStore

durable = runtime.durable(InMemoryCheckpointStore())
pending = durable.start_workflow(
    "request_decision",
    {
        "subject": "Launch window",
        "question": "Which approved date should we use?",
        "options": ["August 1", "August 15"],
        "submit": True,
    },
    preview_only=False,
    run_ref="launch-42",
)
assert pending.status == "pending_approval"

completed = durable.resume_workflow(
    "launch-42",
    input_updates={"decision": "August 15"},
    approval_refs={"approval.request_decision": "approval-123"},
)
assert completed.status == "completed"
```

Available stores:

- `InMemoryCheckpointStore` for deterministic tests.
- `JsonFileCheckpointStore` for atomic single-host durability.
- `HostedCheckpointStore` for tenant/company/project-scoped Postgres storage,
  optimistic revisions, and expiring worker leases.

`client.build_durable_project_runtime(project)` selects the hosted store when
`hosted_project_id` is present and a local JSON store otherwise. Use
`schedule_workflow(..., resume_at=...)`, `dispatch_workflow`, `run_next`, and
`run_ready` for queued execution. `ingest_event(WorkflowEventEnvelope(...))`
deduplicates `event_id` and dispatches every workflow whose `trigger_event`
matches. A worker claim moves one ready checkpoint to `running` with a bounded
lease. While a synchronous primitive remains active, the runtime renews that
lease at a bounded cadence through an owner- and revision-fenced store
operation. A failed renewal is surfaced instead of allowing the stale worker
to write completion. An expired lease can be reclaimed after a worker failure;
custom checkpoint stores must implement the same `renew_lease` fence. Hosted
claims and renewals use the control-plane clock, so a caller's skewed or future
timestamp cannot expire another worker's live lease early.

Automatic failure retries are explicit project policy. Existing projects keep
`retry_policy.max_attempts=1`; opt in by setting a larger bounded value plus
`initial_delay_seconds`, `backoff_multiplier`, and `max_delay_seconds`. Only a
`failed` primitive result marked retryable (directly or by a blocker) is
scheduled again. Approval, required-input, and policy-blocked results never
auto-retry. A receipt whose recovery plan explicitly permits a safe retry can
use that bounded retry policy. An in-doubt, status-probe, compensation, or
manual-reconciliation receipt instead pauses as `waiting_for_recovery`; it is
not claimable by a normal worker and generic resume cannot accept a
caller-authored recovery attestation. Spring's hosted recovery authority must
settle the exact request and route before the workflow can continue.

Before every invocation, the runtime revision-saves its attempt and invocation
counters. A retry becomes `scheduled` with an observable `resume_at`, uses
capped deterministic backoff, and retains the same logical step-visit identity
and connector idempotency keys. A later workflow loop visit receives a new
identity. Human approval/input resumptions stay within the same attempt.
`operation_ref` can partition several proposed writes to the same Tool inside
one primitive without making retry keys unstable. Each operation still needs
its own exact approval receipt, supplied under
`<primitive_ref>#<operation_ref>` in `approval_refs`; a primitive-level approval
is never reused across operation-scoped writes. Retry control events contain
only step, primitive, visit, attempt, delay, and due-time fields; failed
business events never replace `$last_event` while an automatic retry is
pending.

## Runtime outcomes and the improvement loop

Primitive execution automatically records `RuntimeOutcome` rows at the typed
primitive boundary. Outcomes include only primitive reference, status, latency,
approval state, failure kind, timestamp, harness, and correlation references.
Inputs, connector arguments, outputs, evidence payloads, and exception messages
are never recorded.

```python
from lightbulb import JsonlOutcomeRecorder, LightbulbClient

client = LightbulbClient(
    BASE_URL,
    auth=auth,
    outcome_recorder=JsonlOutcomeRecorder(".lightbulb/runtime-outcomes.jsonl"),
)
runtime = client.build_project_runtime(project)
runtime.run_workflow("send_email", inputs)

# Consumes queued outcomes unless observed_outcomes is supplied explicitly.
report = client.run_workflow_improvement_cycle()
client.flush_runtime_outcomes()  # authenticated tenant/company ledger
```

The recorder is fail-open for business execution and bounded for memory/disk
safety. Failed uploads are restored to the local queue.

`run_workflow_improvement_cycle()` accepts a
`WorkflowImprovementSupervisorBudget` for finite intake, queue, history, and
managed-state limits. `run_continuous_workflow_improvement()` is finite even
when its optional limits are omitted: the SDK defaults to 96 cycles, 24 hours,
and two stable no-progress runs. It writes a `supervisor-stop.json` receipt and
records the same reason in `state.json`. Retired JSONL history is replaced by a
content-free count/source-byte/rolling-digest proof; corrupt managed state fails
closed instead of silently resetting the loop.

## Connector conformance

Every connector Tool declared by the 13 built-in implementations has a
`ConnectorToolContract`. The deterministic suite verifies preview isolation,
approval pause, approved completion, cached replay, changed-payload conflict,
read behavior, and output reference shape. It makes no vendor calls.

```python
from lightbulb import run_connector_conformance

assert run_connector_conformance().passed

# Authenticated, read-only comparison with the hosted Tool registry.
report = client.run_connector_conformance(check_live_schemas=True)
assert report["passed"], report["failed_tools"]
```

Live mode detects removed SDK arguments, newly required provider arguments,
missing Tools, and incompatible output-reference fields. Add or update a
contract whenever a primitive adopts a new provider Tool.

## Async client parity

`AsyncLightbulbClient` implements high-throughput operations with native async
I/O and exposes every remaining `LightbulbClient` method through a managed
thread bridge. The one sync generator is adapted to a true async iterator.

```python
from lightbulb import AsyncLightbulbClient

assert AsyncLightbulbClient.async_parity_report()["missing_methods"] == []
result = await async_client.run_connector_conformance(check_live_schemas=True)
```

## Author a custom primitive

Use Pydantic models for the public input/output contract. The decorator returns
a registry-ready primitive implementation.

```python
from pydantic import BaseModel, Field
from lightbulb import business_process_primitive, default_primitive_registry

class DiscountInput(BaseModel):
    subtotal: int = Field(ge=0)
    percent: int = Field(ge=0, le=100)

class DiscountOutput(BaseModel):
    total: int

@business_process_primitive(
    primitive_ref="commerce.apply_discount",
    title="Apply discount",
    input_model=DiscountInput,
    output_model=DiscountOutput,
    version="1.0.0",
)
def apply_discount(context, inputs):
    return {
        "total": inputs.subtotal * (100 - inputs.percent) // 100,
    }

registry = default_primitive_registry([apply_discount])
```

For primitives with complex orchestration, subclass
`BusinessProcessPrimitive` and implement `_execute`. Use
`context.connector_request(...)` for connector work so write idempotency,
preview behavior, project Tool policy, and approvals remain enforceable.

## Workflow input bindings

`ProjectWorkflowStep.input_mapping` supports deterministic references only. It
does not evaluate Python or template expressions.

| Binding | Meaning |
|---------|---------|
| `$input` | Entire workflow input object |
| `$input.customer.email` | Path within workflow input |
| `$steps.classify.output.intent` | Path within an earlier primitive result |
| `$last_event` | Most recent structured event |
| `$last_event.payload.intent` | Path within the most recent event |
| `{"*": "$input"}` | Merge all workflow inputs before field overrides |

Lists and objects may contain bindings recursively. Missing paths pause the
workflow with `binding_resolution_failed`; arbitrary code execution is not
supported.

## Execution statuses

| Status | Meaning |
|--------|---------|
| `completed` | The primitive or workflow completed |
| `preview` | A proposed write was returned without a connector mutation |
| `pending_approval` | A write is waiting for an approval reference |
| `needs_input` | Pydantic validation or input binding failed |
| `waiting_for_recovery` | An external effect is paused for authoritative hosted recovery |
| `blocked` | Project policy, Tool readiness, or loop limits stopped execution |
| `failed` | Connector Execution returned a normalized failure |

Each primitive result includes typed output, structured events, evidence,
blockers, connector Tool, approval reference, and retryability.

## MCP tools

The compact Backbone profile includes these SDK-native project controls:

- `list_executable_business_primitives`
- `run_sdk_business_primitive`
- `validate_sdk_project`
- `run_sdk_project_workflow`
- `manage_sdk_project_runtime`
- `list_sdk_runtime_outcomes`
- `flush_sdk_runtime_outcomes`
- `run_connector_conformance`

The MCP functions parse JSON and call the Python SDK. On the compact profile,
these tools are for discovery, validation, and preview-safe local execution;
caller approval/project/idempotency values cannot authorize a hosted write.
The generic `invoke_tool` escape hatch exists only on the trusted full local
MCP surface. Even there, generic and generated connector calls fail closed
unless they carry the authenticated Project UUID, correlation project ref,
project-bound connector account alias, stable business-action idempotency key,
and server-verified effect. Governed writes pause for Spring-owned approval and
never fall back to a default connector route.

## Current runtime limits

Version 0.14 now provides durable sequential execution, pause/resume, schedules,
event ingestion, and distributed worker leases. The graph remains deliberately
sequential: parallel branches, joins, foreach, subworkflows, compensation,
cancellation, and dead-letter administration still belong to the hosted Agent
Builder runtime. Primitive execution itself is synchronous; async callers use
the complete thread-backed client bridge for these local CPU/blocking paths.

## Project test checklist

- Validate the project before execution.
- Test every event route and terminal state.
- Assert preview writes never call a handler.
- Assert unsupported hosted writes fail closed and never fall back to legacy invocation.
- Assert governed writes first return Spring-owned approval state, then dispatch only with the exact approved scope and request.
- Assert mismatched/expired/consumed approvals, caller-mislabeled effects, and binding/adapter/target drift fail before vendor I/O.
- Replay the same governed idempotency key and assert the stored receipt is returned without another dispatch.
- Assert in-memory approval-gated writes pause without an approval reference.
- Retry the same `run_ref` and assert one connector mutation.
- Reuse an idempotency key with changed inputs and assert failure.
- Keep raw messages, documents, credentials, and secrets out of events.
- Assert stale checkpoint revisions fail and expired leases are reclaimable.
- Replay the same event ID and assert no duplicate workflow is dispatched.
- Run connector conformance, including hosted schema comparison in sandbox CI.
- Assert runtime outcomes contain no primitive inputs or connector payloads.
- Assert `AsyncLightbulbClient.async_parity_report()` remains at 100 percent.
- Run hosted integration tests only against a sandbox Tenant Connector.


## Offline company preparation and operations

The 0.24 candidate adds offline preparation and operator helpers. It does not
activate the local runtime, restore AWS, certify a provider, or change CI
orchestration. New helpers are Beta; pin the SDK minor version.

### Prepare the worker

1. Compile a company bundle using the existing company blueprint/cadence API.
2. Run `lightbulb-company-worker --source-template` to inspect a non-secret source
   example. Replace the connector reference and provider object selectors with
   company-owned values. Empty identity mappings deliberately leave attribution
   unresolved. Never put provider credentials in these files.
3. Run the executable validator before connecting:

   ```sh
   lightbulb-company-worker --bundle company-bundle.json \
     --sources company-sources.json --growth-config company-growth.json \
     --preflight --report-html preflight.html
   ```

   `--growth-config` is optional. Exit 0 means configuration validation passed;
   exit 2 means it failed. Both reports retain `deployment_ready: false`.
   No identity, key file, provider call or work registration is needed.
4. Review warnings for missing customer identity mappings and pacing targets.
5. On an enabled host, verify the exact company/project permission, connector
   custody, required engine records, renewable identity and receipt-key custody.
   Current host compatibility is checked through the actual authenticated routes
   and strict result schemas; there is no invented host-version discovery API.
6. Only then use the ordinary registered worker, initially with `--once` under
   supervision. Registration cannot resume an operator-paused company.

The validator is shared with `build_worker` and runs before authentication.
It checks the bundle, interval, unique bounded source list, daily boundary,
executable observation job, cohort currency, touch mapping commitments, demand
destination, portfolio binding and declared period source references. Provider
ownership, live tool schemas and engine-record existence remain connected checks.

### Inspect and alert

Use the normal connected worker arguments with `--status`, optionally adding
`--report-html company-status.html`. The command authenticates and reads but
never claims a lease, registers a run or dispatches a connector.

The report contains a heartbeat observation, schedule, last successful tick,
daily backlog, latest closed-day source coverage, economic eligibility and
unresolved decisions. An unknown value is not a successful observation. A
heartbeat older than 120 seconds is stale; long calls can also produce that
condition, so consult the supervisor before attempting recovery.

The trusted worker records at most one unchanged heartbeat per minute; state
changes are recorded immediately. Failed health writes do not change the
authoritative scheduling/effect result. If the journal is unavailable, the
supervisor log and stale heartbeat provide the failure signal. The HTML report
contains no scripts, remote assets or approval buttons. Treat its company
references and financial readiness as private artifacts.

| Alert | Operator response |
|---|---|
| WORKER_HEARTBEAT_STALE / CADENCE_OVERDUE | Inspect process, clock, connectivity and renewable identity. Restart with the same bundle/run/key; do not create a replacement effect identity. |
| INTAKE_BACKLOG / SOURCE_WINDOW_MISSING | Inspect provider errors and source availability. Drain existing frozen windows; never advance a watermark manually. |
| DECISION_UNRESOLVED | Inspect exact approval tasks, source expiry and per-unit proofs. Do not approve a stale decision. |
| ECONOMIC_ACCEPTANCE_PENDING | Resolve missing intake, touch lookback, cohorts, cost closure and correction holds. |
| WORKER_ERROR | Retain the exception type, operation reference and scoped logs. Do not publish raw provider payloads. |

A supervisor/alerting system may consume the JSON `alerts` array. This change
does not provision notification delivery. Per-unit pending approval age and unreconciled unit counts come from the
authenticated execution journal. Legacy rows without timestamps remain unknown.
Workspace quarantine remains explicitly unobserved until its scoped service
provides an authoritative feed.

### Source census

`CompanySourceCensus` covers a half-open accounting period. Each account has an
opaque reference, category, source references, reconciliation disposition and
supporting evidence references. Categories include bank, payments, advertising,
payroll, vendor, custody and customer history. A reconciled assertion requires
evidence references; the SDK does not independently validate the external books
merely because the operator supplies those references.

Use `--record-census census.json` with the normal connected worker arguments to
retain an immutable census. Reuse of the reference with changed content refuses;
use a reviewed new reference. A growth-period specification may name
`source_census_ref`; the host checks its exact window and source coverage and
retains the assessment alongside the normal economic acceptance criteria.

```json
{
  "census_ref": "october-accounts-v1",
  "period_start": "2026-10-01T00:00:00Z",
  "period_end": "2026-11-01T00:00:00Z",
  "accounts": [{
    "account_ref": "primary-bank",
    "category": "bank",
    "source_refs": [],
    "reconciliation": "partial",
    "evidence_refs": ["statement-october"]
  }],
  "operator_attests_account_inventory": false
}
```

Missing accounts cannot be discovered from an SDK inventory alone. Every report
continues to state `external_liabilities_proven_complete: false`, even when an
operator attests inventory completeness. Empty observation source references
are allowed for accounts reconciled through other governed business paths.

### Historical corrections

1. Identify every affected economic period, including touch lookback and any
   overlapping reporting periods. The caller must enumerate the affected
   periods; the SDK cannot infer a complete external dependency graph.
2. Construct `HistoricalCorrection` with the original configuration digest,
   a new replacement period reference and exact replacement configuration digest,
   evidence references, timestamp and correction kind. Include
   `supersedes_period_ref` in the replacement specification before calculating
   its digest with `stable_digest`.
3. Use `--record-correction correction.json` with the trusted host configuration.
   This creates a permanent authenticated hold before replacement work begins.
   It neither edits the original report nor erases already executed effects.
4. Reingest revised touch evidence under a reviewed new source binding. Mapping
   changes require a new binding identity. For provider spend/cost revisions,
   reconcile/reverse the original economic source through its owning lifecycle
   before admitting replacement costs. Do not repost a changed report as a new
   independent expense.
5. Run the replacement period through ordinary evidence and cost acceptance.
   Its `supersedes_period_ref` must match the retained replacement commitment.
6. Create a fresh budget decision against the accepted replacement. Never resume
   an old partially executed decision using new economics. Prior unit proofs
   remain available for reconciliation.

The host checks correction holds before using an economic period and at each
execution fence between budget units. This does not recall an already dispatched
provider operation or create a transaction across remote systems. The standalone
`--reallocation-ref` lane now requires a retained `economic_period_ref`; missing
legacy context refuses rather than bypassing the correction check.

Bulk/export import remains a provider-specific integration. Files alone are not
trusted touch evidence. The current PostHog path follows bounded authenticated
pagination and refuses unsafe/incomplete results. Late-arrival completeness
requires provider export/reconciliation evidence; no offline fixture certifies it.

### Retention and receipt keys

Keep original source observations, approvals, execution/recovery proofs and
correction holds for the company's reviewed retention period. Do not delete
them merely because a new SDK version is installed. The health record replaces
one bounded per-run document; operational journals retain their existing rules.

For receipt-key rotation, use the existing `DynamicWorkflowReceiptKeyRing` with
both the old verification key and the new active signing key in the trusted
host. Verify representative old journals before switching. New writes use the
active key. Retire an old key only after its retained evidence has been handled
under a reviewed migration/retention policy. Losing the key must produce an
explicit verification failure, not unsigned fallback. The simple CLI still
accepts one key file; multi-key rotation requires the host API configuration.

Provider custody rotation is separate from receipt signing. Verify current
custody and provider-object ownership through Spring. No raw provider secret
belongs in an SDK report, source file, checkpoint or correction document.

### Compatibility and acceptance boundaries

| Combination | Evidence / required action |
|---|---|
| 0.23 wheel to 0.24 candidate | Retain previous-wheel state, upgrade the same environment, bind protected costs, resume an in-flight worker transition and claim the authenticated pending-window checkpoint. |
| SDK with the compatible 0.23 host routes | Strict snapshot, checkpoint and connector request/result contracts remain in use; 0.24 helpers introduce no backend endpoint or permission. Live deployment validation is still required. |
| Host missing snapshots or exact checkpoint claims | Refuse unavailable/incomplete operations. Do not silently fall back to the first 200 states or another run. |
| Older source plans/derived receipts | Use existing lifecycle replay/migration, retaining source artifacts. Package installation alone does not migrate business state. |
| Current Cursor cloud contract | Remains unavailable until hard budget enforcement can be established. |

See `sdk-offline-ci-handoff.md` for pipeline-independent executable checks and
`sdk-operational-completion-acceptance.md` for the live-provider acceptance list.
This runbook does not change deployment authority or enable unavailable runtimes.

### Customer growth intake and bounded execution

The company worker accepts `customer_lifecycle=` (CLI: `--customer-lifecycle`). Configure `CustomerLifecycleConfiguration` with reviewed `CustomerLifecycleEnrollment` records, existing sales bindings, and recurring `customer_events` sources. Product events are read through governed PostHog queries; accepted CRM inquiries use `crm_sources` and the scoped project API. Identity mapping is explicit. These are closed-window cadence reads, not immediate webhook delivery.

```python
from lightbulb import CustomerLifecycleConfiguration, CustomerLifecycleEnrollment

# sales_binding, reviewed_facts and the event sources belong to this company.
configuration = CustomerLifecycleConfiguration(enrollments=(
    CustomerLifecycleEnrollment(
        enrollment_ref="activation-trial-1",
        binding_ref=sales_binding.binding_ref,
        goal="activation",
        facts=reviewed_facts,
        facts_evidence_refs=("reviewed-customer-profile",),
        required_source_refs=("product-signups", "product-activations"),
        activation_delay_hours=24,
        trial_days=14,
        max_touches=2,
    ),
))
# build_worker(..., sales_config=sales_config, customer_lifecycle=configuration)
```

Activation requires complete signup/activation coverage. Expansion listens for capacity or upgrade intent. Inbound requests enter the existing permission-governed sales and booking workflow. Renewal risk requires complete inactivity coverage, an existing retention case and an explicitly bound invoice. Follow-ups ask for human approval; removing configuration retains a hold.

`CompanyPaymentRecoveryActions`, also available through `sales_host.progression.payment_recovery(policy_ref)`, requests a governed Stripe payment-method update session. Its fresh URL is private and is never retained in journals or returned on replay. Stripe keeps retry ownership. Payment confirmation comes from invoice readback, not portal creation.

Use `export_customer_outcome_template(...)` for observed activation, expansion, booking or retained-subscription evidence. `instantiate_customer_outcome_trial(...)` requires destination mappings, adaptation evidence and explicit time/enrollment/touch limits. Pending or uncertain sends consume reserved trial capacity. Templates make no causal-uplift claim and do not carry approvals across companies.


### Launch previews, purchases, fast intake and customer coordination

`CompanyBusinessLaunch(client, company_id=...)` composes project account discovery,
exact source/read and sales-send route checks, proposed identity mappings and the
existing worker preflight. `prepare(BusinessLaunchRequest(...))` returns a typed
proposal. Optional `probe_start` and `probe_end` inspect a closed PostHog window;
unobserved events and unmatched opaque identities remain explicit review items.
`materialize_reviewed(proposal, expected_digest=...)` rechecks discovery and returns
worker configuration without registering or authorizing effects. The installed
`lightbulb-business-launch` CLI exposes the same preview/review path.

Use `sales_host.progression.commerce` under the host lease:

1. `prepare(CustomerOffer(...), now=..., fence=...)` binds a qualified prospect to
   an explicit billing customer, reviewed fixed Price, amount/currency/quantity,
   HTTPS URLs, expiry and `CustomerFulfillmentPlan`.
2. `checkout(...)` requests human-approved creation. A fresh private URL is never
   retained in checkpoints. Unknown writes require original-result reconciliation
   or `recover_checkout(offer_ref, session_id, ...)`, never another automatic create.
3. `observe_payment(...)` verifies the exact provider session. `fulfill(...)`
   additionally requires a fresh full captured, unrefunded and undisputed payment.
4. Fulfillment uses a separately approved, destination-bound Tool and readback.
   The written resource and customer must match verification. Configure actual
   provision/onboarding Tools; the SDK does not invent an entitlement provider.

Checkout currently supports fixed one-time Prices and exact expirations 30 minutes
to 24 hours after dispatch. Recurring subscriptions, coupons, automatic taxes and
adjustable quantities are refused. Payment evidence is not settlement or a promise
against a future reversal.

Set `CustomerLifecycleConfiguration.fast_intake=CustomerFastIntakePolicy(...)`
for rapid intake under the existing scheduler lease. The default is 60-second
polling of persisted scoped Stripe webhook hints, accepted CRM inquiries and
customer/invoice provider reads. Webhook hints establish neither payment nor
inactivity coverage. Daily polling remains reconciliation; parked cadences stay
parked. The sync/async `list_customer_webhook_hints` client returns minimal,
received-time-paginated events without raw provider payloads.

`CustomerLifecycleConfiguration.experiments` connects signed customer experiment
designs to stable account assignment, actual exposure and control/treatment
outcomes. Register before exposure begins; activation and expansion are supported.
Incomplete source coverage and insufficient samples cannot become a causal win.
Meeting and renewal experiment adapters are not yet supported.

`sales_host.progression.customer_profit.report(...)` consumes canonical verified
financial evidence. `CustomerFinancialAllocationPlan` supplies reviewed shares of
specific source evidence for customer/workflow contribution reports. Allocations
are operator-reviewed; delivery/tool estimates remain separate from verified costs.
They do not establish provider-level customer attribution or causal profit uplift.

`CompanySalesConfiguration.customer_actions` coordinates all configured owners
within one company bundle by account reference, with shared touch limits, purpose
priority and reply ownership. Pending/uncertain sends consume capacity; scoped
historical sends retain their cooldown during adoption. Final dispatch checks
competing threads, current permission, trial limits and lifecycle stops.


### Customer conversations and recurring commerce

The existing sales progression now exposes `conversations`, `subscriptions` and
`checkout_recovery`. `commerce.financials` joins exact checkout charge/refund
evidence to recorded workflow costs; `commerce.fulfillment` reports delivery
deadlines and recovery. `CompanyBusinessLaunch.packages` composes reviewed SaaS,
service and digital-product launch configurations.

Public typed declarations include `CustomerConversationAction`,
`CustomerSubscriptionOffer`, `CustomerSubscriptionChange`,
`CustomerSubscriptionAccessPolicy`, `CheckoutRecoveryRequest`,
`CustomerFinancialRequest`, `CustomerCostAllocation`, `CustomerFulfillmentPackage`
and `BusinessLaunchPackage`. Use these under the existing company host lease;
each consequential effect retains the platform's separate approval.

Concrete delivery adapters support existing GitHub identity repository access,
specific-user Drive file access and Notion service onboarding. Recurring commerce
supports fixed licensed prices, trials, same-interval proration changes and
scheduled cancellation. Checkout recovery and direct charge/refund reconciliation
currently follow fixed one-time checkout. Metered cost estimates remain separate
from recorded contribution; previews do not certify live execution.

See [workflow contracts and examples](../docs/sdk-customer-conversations-subscriptions.md)
for exact supported scopes, approval/reconciliation behavior and launch scenarios.
# Customer operations

The sales host now exposes support resolution, trial conversion, referral programs
and registered subscription financial reports through its durable cadence. Launch
packages provide executable test-mode verification, and fulfillment packages can
provision application workspaces with destination entitlement readback.

See [customer operations](../docs/sdk-customer-operations.md) for contracts, examples,
approval boundaries and evidence limits, and [SaaS provisioning](../docs/sdk-customer-saas-provisioning.md)
for the application database and identity integration contract.

### Customer launch completion

The SaaS integration kit adds an Auth0 reference application, invitation delivery,
verified membership and feature access. Customer self-service composes reviewed
billing and team actions with fresh entitlement reconciliation. Support cases can
stage approved fixes in connected application repositories; referral acquisition
can qualify recurring purchases and reconcile reviewed billing credits. Customer
experiment and contribution evidence can propose bounded growth allocations.

See [customer launch completion](../docs/sdk-customer-launch-completion.md) for
entry points, workflow ownership and the distinction between local verification
and live provider readiness.
