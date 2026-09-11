# Lightbulb SDK stability policy

Lightbulb currently targets controlled internal pilots. Stability describes an
SDK contract; it does not certify a provider integration, deployment, Golden
Loop, customer outcome, or authorization to perform a live write.

The [developer guide](https://www.lightbulbpartners.com/developers#version-status)
reports the published PyPI version, public source, and reviewed source candidate
separately. A candidate version, release note, generated capability catalog, or
green package check does not establish publication or promote a contract's
stability level. Install a version that is present in the
[PyPI release history](https://pypi.org/project/lightbulb-mcp/#history), and use
that release's support and migration policy. Contact
[developer support](https://www.lightbulbpartners.com/developers#support) for
account, host, and compatibility issues.

## Contract levels

- **Supported:** typed primitive/runtime contracts, governed Connector Execution
  request contracts, durable Project Runtime contracts, and the compact Golden
  Loop protocol. Breaking changes require a documented migration and at least
  one minor release of deprecation where a safe compatibility path exists.
- **Beta:** the broad hosted endpoint client, expanded MCP profiles, Company
  Blueprint compilation, and capability-contract compiler projections. These
  may change in a minor release; pin the SDK minor version.
- **Quarantined:** provider-backed capabilities and Golden Loops without current,
  source-bound certification evidence. Quarantined capability metadata is for
  discovery, validation, simulation, and governed approval requests—not a claim
  of production availability.
- **Private:** generated raw operations, UUID-backed runtime controls, operator
  certification, and activation surfaces. These are not a stable model-facing
  API and may require explicit local opt-in.

## Package facade

The `lightbulb` package root is a compatibility facade. Its existing names are
resolved lazily, but new functionality should be imported from its owning
module instead of adding another root export. The facade preserves existing
imports; presence at the root alone does not promote a beta or quarantined
contract to Supported.

The curated public namespaces are:

| Namespace | Level | Boundary |
|---|---|---|
| `lightbulb.core` | Supported | Authentication strategies, login entry points, and public errors |
| `lightbulb.runtime` | Supported | Primitive definition, execution, evidence, and recovery contracts |
| `lightbulb.hosted` | Beta | Sync/async clients and their public dispatch/event results |
| `lightbulb.domains.finance` | Beta | Journal-to-close lighthouse contracts; provider effects remain Quarantined |

These namespaces resolve a deliberately small list of canonical objects lazily;
they do not copy business logic or create a second execution authority. Broader
contracts remain available from their owning modules without an implied
stability promotion.

Deprecations must name the replacement, emit a runtime warning where practical,
and remain documented through the compatibility window. Security or authority
defects may be closed immediately and fail closed.

## Effect and certification boundary

The SDK may declare, validate, preview, and request an effect. Spring alone
resolves tenant/company/project/user scope, RBAC, entitlement, approval,
idempotency, Connector Tool Binding, credentials, and dispatch authority.
Unknown or uncertified capabilities fail closed. A write is complete only when
the governing contract's independent observation and terminal evidence are
present; a lost response after the provider boundary remains ambiguous until
governed reconciliation resolves it.

## Installation and upgrade acceptance

`SDK Package Acceptance` builds the wheel and source distribution twice with a
fixed `SOURCE_DATE_EPOCH`, checks their byte equality and archive contents, and
retains the exact artifacts and checksums. Its separate Python 3.10, 3.11, 3.12
and 3.13 jobs install the retained wheel into a fresh environment with an isolated
home directory. Each job executes the public sync and async identity clients
against an in-process HTTP transport, verifies tenant/company/user headers,
loads the curated namespaces, runs `lightbulb version` and
`lightbulb-company-worker --help`, and initializes the actual `lightbulb-mcp`
console process over MCP stdio. No provider account or running host is needed.

The build job resolves the latest published PyPI release and retains its actual
wheel with the index-reported version, size, and SHA-256 digest. It verifies the
downloaded bytes and refuses reuse of an already published package version.
Each Python job rechecks that retained baseline, installs it, exercises its
public clients, and upgrades that same environment to the candidate wheel
before repeating the acceptance checks. Evidence records both wheel identities
and installed versions. This covers package replacement, public imports, and
these executable contracts; it does not establish compatibility for every
persisted domain document or certify a provider journey. Keep the Beta and
Quarantined boundaries above unchanged.

To reproduce from an environment containing `build`, `hatchling`, `packaging`
and the SDK's declared dependencies:

```sh
python lightbulb-sdk/scripts/verify_sdk_distribution.py --output-dir candidate
python lightbulb-sdk/scripts/verify_sdk_distribution.py \
  --smoke-candidate-install candidate --python /path/to/python --allow-index
python lightbulb-sdk/scripts/verify_sdk_distribution.py \
  --smoke-candidate-install candidate --python /path/to/python --allow-index \
  --upgrade-from-wheel /path/to/lightbulb_mcp-0.23.0-py3-none-any.whl
```

`--allow-index` explicitly permits dependency resolution for compatibility
acceptance. The evidence records the resolved versions; it is not a hash-locked
offline installation bundle. The acceptance workflow has read-only repository
permissions and does not publish to PyPI or enable the public mirror.

## Offline operator helpers (0.24 candidate)

`company_preflight`, `company_operations` and `company_data_review` are Beta
host/operator interfaces. Preflight never certifies a deployment. Status reads
existing authenticated journals without claiming work. Source census records
separate operator evidence references from independently verified business
truth. Historical correction holds prevent future budget use of affected
periods and preserve earlier effects; they do not reverse a provider write.

The standalone upgrade command also captures representative state using the
installed previous wheel (0.23 or later), upgrades that same environment, then
binds and resumes the exact records. This covers an in-flight workforce record,
a protected cost register, the bundle and an authenticated pending observation
checkpoint. It does not certify all persisted schemas or live providers.

The pipeline-neutral `lightbulb-sdk/scripts/verify_sdk_offline.py` command runs
selected executable documentation, recovery/migration/custody suites and
synthetic capacity checks. CI orchestration may change without changing this
command's contract. See the offline operations section of CUSTOM_PROJECTS.md.
