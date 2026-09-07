"""Shared MCP protocol catalog for governed dynamic workflows.

This module deliberately contains no transport or workflow-engine code.  It is
the contract shared by the local Python MCP adapter and hosted implementations:

* one canonical snake_case wire shape;
* explicit transport aliases instead of silently accepting two spellings;
* exact OAuth scope requirements;
* optimistic concurrency and idempotency on every mutation; and
* bounded, fail-closed input and output validation.

The authenticated principal supplies tenant and user identity.  Clients may
select only public ``company_ref`` / ``project_ref`` scope handles; raw actor,
tenant, company, project, workflow, or database identifiers are not protocol
fields.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import json
import math
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


PROTOCOL_VERSION = "1.4"
MANIFEST_SCHEMA = "lightbulb.dynamic_workflow_mcp_manifest.v1"
READ_SCOPE = "lightbulb:dynamic_workflow.read"
WRITE_SCOPE = "lightbulb:dynamic_workflow.write"
TOOL_PREFIX = "dynamic_workflow_"

_EXPECTED_OPERATIONS = (
    "start",
    "attach",
    "status",
    "next_assignment",
    "submit_plan",
    "submit_builder_result",
    "submit_evaluator_verdict",
    "cancel",
)
_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_OPAQUE_PATTERNS = {
    "run_ref": r"^dwr_[A-Za-z0-9_-]{16,64}$",
    "host_binding_ref": r"^dwh_[a-f0-9]{64}$",
    "session_receipt": r"^dws_[A-Za-z0-9_-]{24,128}$",
    "assignment_ref": r"^dwa_[A-Za-z0-9_-]{16,64}$",
    "assignment_receipt": r"^dwl_[A-Za-z0-9_-]{24,128}$",
    "submission_ref": r"^dwb_[A-Za-z0-9_-]{16,64}$",
    "context_ref": r"^ctx_[A-Za-z0-9_-]{16,48}$",
    "context_binding_ref": r"^cxs_[A-Za-z0-9_-]{16,48}$",
    "context_checkpoint_ref": r"^cxp_[A-Za-z0-9_-]{16,48}$",
    "context_item_ref": r"^(?:cxe|cxp)_[A-Za-z0-9_-]{16,48}$",
}
_HOST_ROLES = ("planner", "builder", "evaluator")
_HOSTS = ("claude", "claude_code", "codex", "chatgpt", "lightbulb")
_ACCEPTANCE_POLICIES = ("distinct_binding", "runtime_attested_required")
_EVALUATOR_FRESHNESS_ASSURANCES = (
    "not_evaluated",
    "distinct_binding_external_ref",
    "distinct_mcp_session",
    "runtime_attested_fresh_context",
)
_ACCEPTANCE_ASSURANCES = (
    "not_accepted",
    "distinct_binding",
    "distinct_mcp_session",
    "runtime_attested",
)


class DynamicWorkflowMcpProtocolError(ValueError):
    """Base class for catalog, authorization, and payload failures."""


class UnknownDynamicWorkflowOperation(DynamicWorkflowMcpProtocolError):
    """Raised when an operation/tool name is not exactly cataloged."""


class DynamicWorkflowScopeError(DynamicWorkflowMcpProtocolError):
    """Raised when every required OAuth scope is not present."""


class DynamicWorkflowPayloadError(DynamicWorkflowMcpProtocolError):
    """Raised when an input or output fails its declared schema."""


class DynamicWorkflowCatalogError(DynamicWorkflowMcpProtocolError):
    """Raised when a catalog violates protocol invariants."""


@dataclass(frozen=True, slots=True)
class DynamicWorkflowMcpOperation:
    """Immutable declarative operation contract."""

    operation: str
    tool_name: str
    title: str
    description: str
    required_scopes: tuple[str, ...]
    mutating: bool
    destructive: bool
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    input_aliases: Mapping[str, tuple[str, ...]]
    output_aliases: Mapping[str, tuple[str, ...]]
    state_preconditions: tuple[str, ...] = ()

    @property
    def read_only(self) -> bool:
        return not self.mutating


@dataclass(frozen=True, slots=True)
class ValidatedDynamicWorkflowCall:
    """Authorized operation and canonical payload ready for an adapter."""

    operation: DynamicWorkflowMcpOperation
    payload: Mapping[str, Any]


def _string(
    description: str,
    *,
    min_length: int = 1,
    max_length: int = 512,
    pattern: str | None = None,
    enum: Sequence[str] | None = None,
    format_: str | None = None,
    sensitive: bool = False,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "string",
        "description": description,
        "minLength": min_length,
        "maxLength": max_length,
    }
    if pattern is not None:
        schema["pattern"] = pattern
    if enum is not None:
        schema["enum"] = list(enum)
    if format_ is not None:
        schema["format"] = format_
    if sensitive:
        schema["x-lightbulb-sensitive"] = True
    return schema


def _integer(
    description: str,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
    const: int | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "integer",
        "description": description,
        "minimum": minimum,
        "maximum": maximum,
    }
    if const is not None:
        schema["const"] = const
    return schema


def _boolean(description: str, *, const: bool | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "boolean", "description": description}
    if const is not None:
        schema["const"] = const
    return schema


def _object(
    description: str,
    properties: Mapping[str, Any] | None = None,
    *,
    required: Sequence[str] = (),
    additional_properties: bool | Mapping[str, Any] = False,
    max_json_bytes: int | None = None,
    max_depth: int | None = None,
    max_nodes: int | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "description": description,
        "properties": dict(properties or {}),
        "required": list(required),
        "additionalProperties": additional_properties,
    }
    if max_json_bytes is not None:
        schema["x-lightbulb-max-json-bytes"] = max_json_bytes
    if max_depth is not None:
        schema["x-lightbulb-max-depth"] = max_depth
    if max_nodes is not None:
        schema["x-lightbulb-max-nodes"] = max_nodes
    return schema


def _array(
    description: str,
    items: Mapping[str, Any],
    *,
    min_items: int = 0,
    max_items: int = 50,
    unique: bool = False,
) -> dict[str, Any]:
    return {
        "type": "array",
        "description": description,
        "items": dict(items),
        "minItems": min_items,
        "maxItems": max_items,
        "uniqueItems": unique,
    }


def _bounded_json_object(description: str, *, max_bytes: int = 65_536) -> dict[str, Any]:
    return _object(
        description,
        additional_properties=True,
        max_json_bytes=max_bytes,
        max_depth=8,
        max_nodes=500,
    )


def _opaque_ref(field: str, description: str, *, sensitive: bool = False) -> dict[str, Any]:
    return _string(
        description,
        max_length=132,
        pattern=_OPAQUE_PATTERNS[field],
        sensitive=sensitive,
    )


def _evidence_ref(description: str) -> dict[str, Any]:
    return _string(
        description,
        max_length=2_000,
        pattern=(
            r"^(?:dwe_[A-Za-z0-9_-]{16,64}|"
            r"[a-z][a-z0-9+.-]*://[A-Za-z0-9][A-Za-z0-9._/-]{0,1960})$"
        ),
    )


def _scope_properties() -> dict[str, Any]:
    public_ref_pattern = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
    return {
        "company_ref": _string(
            "Required public company scope handle; tenant and actor come from authentication.",
            max_length=160,
            pattern=public_ref_pattern,
        ),
        "project_ref": _string(
            "Required public project scope handle resolved within the authenticated actor scope.",
            max_length=160,
            pattern=public_ref_pattern,
        ),
    }


def _criterion_id(description: str = "Stable acceptance-criterion identifier.") -> dict[str, Any]:
    return _string(
        description,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    )


def _acceptance_criterion_schema() -> dict[str, Any]:
    return _object(
        "Immutable acceptance criterion established when the run starts.",
        {
            "criterion_id": _criterion_id(),
            "description": _string(
                "Observable condition the evaluator must decide independently.",
                max_length=4_000,
            ),
            "required_evidence": _array(
                "Nonempty evidence-kind slugs required to decide this criterion.",
                _string(
                    "Evidence kind slug.",
                    max_length=64,
                    pattern=r"^[a-z][a-z0-9._-]{0,63}$",
                ),
                min_items=1,
                max_items=50,
                unique=True,
            ),
        },
        required=("criterion_id", "description", "required_evidence"),
    )


def _host_role_schema(
    description: str,
    *,
    const: str | None = None,
    roles: Sequence[str] = _HOST_ROLES,
) -> dict[str, Any]:
    schema = _string(description, max_length=16, enum=roles)
    if const is not None:
        schema["const"] = const
    return schema


def _mutation_properties(*, start: bool = False) -> dict[str, Any]:
    return {
        "expected_revision": _integer(
            "Last observed workflow revision; start must use zero.",
            const=0 if start else None,
        ),
        "idempotency_key": _string(
            "Stable key reused only when retrying this exact mutation.",
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        ),
    }


def _continuation_properties(*, role: str | None = None) -> dict[str, Any]:
    properties = {
        "run_ref": _opaque_ref("run_ref", "Opaque dynamic-workflow run handle."),
        "host_binding_ref": _opaque_ref(
            "host_binding_ref", "Opaque binding for the host session that owns this call."
        ),
        "session_receipt": _opaque_ref(
            "session_receipt",
            "Secret continuation receipt proving custody of the host binding.",
            sensitive=True,
        ),
        "host_role": _host_role_schema(
            "Role whose custody is proven by this host binding and receipt.",
            const=role,
        ),
    }
    return properties


def _continuation_required() -> tuple[str, ...]:
    return ("run_ref", "host_binding_ref", "session_receipt", "host_role")


def _assignment_custody_properties() -> dict[str, Any]:
    return {
        "assignment_ref": _opaque_ref(
            "assignment_ref", "Opaque assignment handle returned by next_assignment."
        ),
        "assignment_receipt": _opaque_ref(
            "assignment_receipt",
            "Secret lease receipt returned with the assignment and consumed on submission.",
            sensitive=True,
        ),
    }


def _scope_output_schema() -> dict[str, Any]:
    return _object(
        "Resolved actor scope with rename-stable public selectors and no internal identifiers.",
        {
            "company_scoped": _boolean("Whether the run is company scoped."),
            "project_scoped": _boolean("Whether the run is project scoped."),
            **_scope_properties(),
        },
        required=(
            "company_scoped",
            "project_scoped",
            "company_ref",
            "project_ref",
        ),
    )


def _base_output_properties() -> dict[str, Any]:
    return {
        "run_ref": _opaque_ref("run_ref", "Opaque dynamic-workflow run handle."),
        "revision": _integer("Committed workflow revision."),
        "status": _string(
            "Current bounded workflow status slug.",
            max_length=64,
            pattern=r"^[a-z][a-z0-9_]{0,63}$",
        ),
        "scope": _scope_output_schema(),
        "context_linked": _boolean(
            "Whether this run is sealed to a Context Broker space. This does not "
            "claim that the model's native context window was extended."
        ),
        "context_revision": _integer(
            "Context Broker revision committed for this response; omitted for offline runs."
        ),
    }


def _context_anchor_schema() -> dict[str, Any]:
    return _object(
        "Small untrusted-evidence anchor for Context Broker retrieval. It contains no "
        "Context Pack content and does not attest model-context freshness.",
        {
            "context_ref": _opaque_ref(
                "context_ref", "Opaque Context Broker space reference."
            ),
            "context_binding_ref": _opaque_ref(
                "context_binding_ref",
                "Opaque Context Broker binding for the caller's workflow role binding.",
            ),
            "context_revision": _integer("Context revision visible to this assignment."),
            "checkpoint_ref": _opaque_ref(
                "context_checkpoint_ref",
                "Latest opaque Context Broker checkpoint reference, when one exists.",
            ),
            "supporting_refs": _array(
                "Opaque event/checkpoint refs supporting the latest checkpoint; never content.",
                _opaque_ref(
                    "context_item_ref",
                    "Opaque Context Broker event or checkpoint reference.",
                ),
                max_items=256,
                unique=True,
            ),
            "evidence_trust": {
                **_string(
                    "Marks these refs as untrusted evidence until retrieved and evaluated.",
                    max_length=16,
                    enum=("untrusted",),
                ),
                "const": "untrusted",
            },
            "contains_context_pack": _boolean(
                "Always false: assignment anchors never embed Context Pack content.",
                const=False,
            ),
        },
        required=(
            "context_ref",
            "context_binding_ref",
            "context_revision",
            "supporting_refs",
            "evidence_trust",
            "contains_context_pack",
        ),
    )


def _evaluator_freshness_assurance_schema() -> dict[str, Any]:
    return _string(
        "Honest evaluator-isolation assurance. A distinct MCP session is a transport "
        "claim, not a claim that the model context is fresh.",
        max_length=48,
        enum=_EVALUATOR_FRESHNESS_ASSURANCES,
    )


def _acceptance_assurance_schema() -> dict[str, Any]:
    return _string(
        "Acceptance assurance actually established by the committed evaluator binding; "
        "distinct_mcp_session is transport isolation, not fresh model-context attestation.",
        max_length=32,
        enum=_ACCEPTANCE_ASSURANCES,
    )


def _start_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    properties = {
        **_scope_properties(),
        **_mutation_properties(start=True),
        "objective": _string(
            "The bounded objective the builder/evaluator loop must satisfy.",
            max_length=8_192,
        ),
        "acceptance_criteria": _array(
            "Immutable criteria the evaluator must cover with evidence.",
            _acceptance_criterion_schema(),
            min_items=1,
            max_items=100,
        ),
        "host": _string(
            "Calling harness slug such as codex, claude_code, or chatgpt.",
            max_length=40,
            pattern=r"^[a-z0-9][a-z0-9._-]{0,39}$",
            enum=_HOSTS,
        ),
        "host_session_ref": _string(
            "Optional host thread/session handle; servers must fingerprint rather than persist it raw.",
            min_length=0,
            max_length=512,
            sensitive=True,
        ),
        "acceptance_policy": _string(
            "Immutable acceptance policy. runtime_attested_required prevents an accept "
            "verdict unless the server attests a fresh evaluator runtime context.",
            max_length=32,
            enum=_ACCEPTANCE_POLICIES,
        ),
        "workflow_spec": _bounded_json_object(
            "Optional versioned builder/evaluator workflow configuration.", max_bytes=65_536
        ),
        "inputs": _bounded_json_object(
            "Optional initial structured inputs available to the first assignment.",
            max_bytes=65_536,
        ),
    }
    properties["acceptance_policy"]["default"] = "distinct_binding"
    input_schema = _object(
        "Start one private, actor-scoped dynamic workflow run.",
        properties,
        required=(
            "company_ref",
            "project_ref",
            "objective",
            "acceptance_criteria",
            "host",
            "expected_revision",
            "idempotency_key",
        ),
    )
    output = {
        **_base_output_properties(),
        "host_binding_ref": _opaque_ref(
            "host_binding_ref", "Opaque binding created for the calling host session."
        ),
        "session_receipt": _opaque_ref(
            "session_receipt",
            "Secret continuation receipt returned once to the host adapter.",
            sensitive=True,
        ),
        "bound_role": _host_role_schema(
            "The start binding has planner custody.", const="planner"
        ),
        "created_at": _string(
            "Run creation timestamp.", max_length=64, format_="date-time"
        ),
        "acceptance_policy": _string(
            "Immutable acceptance policy committed for this run.",
            max_length=32,
            enum=_ACCEPTANCE_POLICIES,
        ),
    }
    output_schema = _object(
        "Started workflow receipt.",
        output,
        required=(
            "run_ref",
            "revision",
            "status",
            "scope",
            "host_binding_ref",
            "session_receipt",
            "bound_role",
            "created_at",
            "acceptance_policy",
            "context_linked",
        ),
    )
    return input_schema, output_schema


def _attach_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = _object(
        "Attach a new role-specific host session to an existing scoped run.",
        {
            **_scope_properties(),
            **_mutation_properties(),
            "run_ref": _opaque_ref("run_ref", "Opaque dynamic-workflow run handle."),
            "host": _string(
                "Calling harness slug such as codex, claude_code, chatgpt, claude, or lightbulb.",
                max_length=40,
                pattern=r"^[a-z0-9][a-z0-9._-]{0,39}$",
                enum=_HOSTS,
            ),
            "host_session_ref": _string(
                "Host thread/session handle; servers must fingerprint rather than persist it raw.",
                max_length=512,
                sensitive=True,
            ),
            "host_role": _host_role_schema(
                "Role this fresh binding will hold. Evaluator binding is unavailable until evaluation is pending."
            ),
        },
        required=(
            "company_ref",
            "project_ref",
            "run_ref",
            "host",
            "host_session_ref",
            "host_role",
            "expected_revision",
            "idempotency_key",
        ),
    )
    output_schema = _object(
        "Fresh role-bound host continuation receipt.",
        {
            **_base_output_properties(),
            "host_binding_ref": _opaque_ref(
                "host_binding_ref", "Opaque newly attached host binding."
            ),
            "session_receipt": _opaque_ref(
                "session_receipt",
                "Secret continuation receipt returned once to the newly attached host.",
                sensitive=True,
            ),
            "bound_role": _host_role_schema("Role held by the fresh binding."),
            "attached_at": _string(
                "Host attachment timestamp.", max_length=64, format_="date-time"
            ),
        },
        required=(
            "run_ref",
            "revision",
            "status",
            "scope",
            "host_binding_ref",
            "session_receipt",
            "bound_role",
            "attached_at",
            "context_linked",
        ),
    )
    return input_schema, output_schema


def _status_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = _object(
        "Read current workflow state for the bound host session.",
        {**_scope_properties(), **_continuation_properties()},
        required=("company_ref", "project_ref", *_continuation_required()),
    )
    output = {
        **_base_output_properties(),
        "terminal": _boolean("Whether no further assignments may be leased."),
        "assignment_available": _boolean(
            "Whether next_assignment may currently establish a lease."
        ),
        "active_role": _string(
            "Current role when work remains.",
            max_length=16,
            enum=_HOST_ROLES,
        ),
        "iteration": _integer("Current builder/evaluator iteration.", maximum=10_000),
        "updated_at": _string(
            "Latest durable state transition timestamp.",
            max_length=64,
            format_="date-time",
        ),
        "evaluator_freshness_assurance": _evaluator_freshness_assurance_schema(),
        "acceptance_assurance": _acceptance_assurance_schema(),
        "acceptance_policy": _string(
            "Immutable acceptance policy committed for this run.",
            max_length=32,
            enum=_ACCEPTANCE_POLICIES,
        ),
    }
    output_schema = _object(
        "Current workflow status.",
        output,
        required=(
            "run_ref",
            "revision",
            "status",
            "scope",
            "terminal",
            "assignment_available",
            "iteration",
            "updated_at",
            "evaluator_freshness_assurance",
            "acceptance_assurance",
            "acceptance_policy",
            "context_linked",
        ),
    )
    return input_schema, output_schema


def _next_assignment_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = _object(
        "Lease the next planner, builder, or evaluator assignment exclusively.",
        {
            **_scope_properties(),
            **_continuation_properties(),
            **_mutation_properties(),
        },
        required=(
            "company_ref",
            "project_ref",
            *_continuation_required(),
            "expected_revision",
            "idempotency_key",
        ),
    )
    assignment_schema = _object(
        "Exclusive builder/evaluator assignment lease.",
        {
            "assignment_ref": _opaque_ref(
                "assignment_ref", "Opaque leased assignment handle."
            ),
            "assignment_receipt": _opaque_ref(
                "assignment_receipt",
                "Secret lease receipt required when submitting this assignment.",
                sensitive=True,
            ),
            "role": _string(
                "Agent role responsible for this assignment.",
                max_length=16,
                enum=_HOST_ROLES,
            ),
            "attempt": _integer("One-based assignment attempt.", minimum=1, maximum=10_000),
            "instructions": _string(
                "Bounded assignment instructions; current host/user policy still takes precedence.",
                max_length=32_768,
            ),
            "payload": _bounded_json_object(
                "Structured assignment inputs.", max_bytes=131_072
            ),
            "lease_expires_at": _string(
                "Exclusive lease expiration timestamp.",
                max_length=64,
                format_="date-time",
            ),
            "context_anchor": _context_anchor_schema(),
        },
        required=(
            "assignment_ref",
            "assignment_receipt",
            "role",
            "attempt",
            "instructions",
            "payload",
            "lease_expires_at",
        ),
    )
    output = {
        **_base_output_properties(),
        "assignment_available": _boolean(
            "Whether an assignment was leased in this response."
        ),
        "assignment": assignment_schema,
    }
    output_schema = _object(
        "Assignment lease result; assignment is present only when assignment_available is true.",
        output,
        required=(
            "run_ref",
            "revision",
            "status",
            "scope",
            "assignment_available",
            "context_linked",
        ),
    )
    return input_schema, output_schema


def _plan_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    properties = {
        **_scope_properties(),
        **_continuation_properties(role="planner"),
        **_assignment_custody_properties(),
        **_mutation_properties(),
        "required_criterion_ids": _array(
            "Complete immutable criterion set from the planner assignment.",
            _criterion_id(),
            min_items=1,
            max_items=100,
            unique=True,
        ),
        "plan": _object(
            "PlannerPlan fields supplied by the planner; the server injects exact scope, run, revision, binding, timestamp, and usage.",
            {
                "objective": _string(
                    "The immutable workflow objective.", max_length=20_000
                ),
                "acceptance_criteria": _array(
                    "The complete immutable AcceptanceCriterion set from start.",
                    _acceptance_criterion_schema(),
                    min_items=1,
                    max_items=100,
                ),
                "work_items": _array(
                    "Ordered, nonblank PlannerPlan work items.",
                    _string("Bounded work item.", max_length=20_000),
                    min_items=1,
                    max_items=1_000,
                ),
            },
            required=("objective", "acceptance_criteria", "work_items"),
        ),
    }
    input_schema = _object(
        "Submit the PlannerPlan for the exclusively leased planner assignment.",
        properties,
        required=(
            "company_ref",
            "project_ref",
            *_continuation_required(),
            "assignment_ref",
            "assignment_receipt",
            "expected_revision",
            "idempotency_key",
            "required_criterion_ids",
            "plan",
        ),
    )
    return input_schema, _submission_output_schema("Accepted planner submission.")


def _submission_output_schema(
    description: str,
    *,
    evaluator_assurance: bool = False,
) -> dict[str, Any]:
    properties = {
        **_base_output_properties(),
        "accepted": _boolean("Whether this idempotent submission was accepted."),
        "submission_ref": _opaque_ref(
            "submission_ref", "Opaque durable submission receipt."
        ),
        "next_role": _string(
            "Next role when more work remains.",
            max_length=16,
            enum=_HOST_ROLES,
        ),
        "context_checkpoint_ref": _opaque_ref(
            "context_checkpoint_ref",
            "Opaque Context Broker checkpoint committed before this linked submission.",
        ),
    }
    required = [
        "run_ref",
        "revision",
        "status",
        "scope",
        "accepted",
        "submission_ref",
        "context_linked",
    ]
    if evaluator_assurance:
        properties.update(
            evaluator_freshness_assurance=_evaluator_freshness_assurance_schema(),
            acceptance_assurance=_acceptance_assurance_schema(),
        )
        required.extend(
            ("evaluator_freshness_assurance", "acceptance_assurance")
        )
    return _object(
        description,
        properties,
        required=required,
    )


def _builder_result_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    evidence_schema = _object(
        "Content-addressed EvidenceRef artifact mapped to acceptance criteria.",
        {
            "kind": _string(
                "Evidence kind slug declared by an acceptance criterion.",
                max_length=64,
                pattern=r"^[a-z][a-z0-9._-]{0,63}$",
            ),
            "ref": _evidence_ref("Opaque or governed URI evidence handle."),
            "sha256": _string(
                "Lowercase SHA-256 digest of the evidence content.",
                min_length=64,
                max_length=64,
                pattern=r"^[0-9a-f]{64}$",
            ),
            "criterion_ids": _array(
                "Acceptance criteria this evidence supports or disproves.",
                _criterion_id(),
                min_items=1,
                max_items=100,
                unique=True,
            ),
            "media_type": _string(
                "Optional evidence media type.", min_length=0, max_length=200
            ),
        },
        required=("ref", "sha256", "kind", "criterion_ids"),
    )
    properties = {
        **_scope_properties(),
        **_continuation_properties(role="builder"),
        **_assignment_custody_properties(),
        **_mutation_properties(),
        "outcome": _string(
            "Builder outcome.",
            max_length=16,
            enum=("completed", "blocked", "failed"),
        ),
        "summary": _string("Bounded builder summary.", max_length=16_384),
        "plan_digest": _string(
            "Lowercase SHA-256 digest of the PlannerPlan this result implements.",
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
        "iteration": _integer(
            "One-based builder iteration from the leased assignment.",
            minimum=1,
            maximum=10_000,
        ),
        "evidence_refs": _array(
            "Content-addressed EvidenceRef artifacts for evaluator review.",
            evidence_schema,
            max_items=1_000,
        ),
        "progress_digest": _string(
            "Lowercase SHA-256 digest used to detect repeated no-progress results.",
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
    }
    input_schema = _object(
        "Submit a result for the exclusively leased builder assignment.",
        properties,
        required=(
            "company_ref",
            "project_ref",
            *_continuation_required(),
            "assignment_ref",
            "assignment_receipt",
            "expected_revision",
            "idempotency_key",
            "outcome",
            "summary",
            "plan_digest",
            "iteration",
            "evidence_refs",
            "progress_digest",
        ),
    )
    return input_schema, _submission_output_schema("Accepted builder submission.")


def _evaluator_verdict_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    criterion_evidence_schema = _object(
        "EvidenceRef used for one criterion and its declared kind.",
        {
            "kind": _string(
                "Evidence kind slug declared by the acceptance criterion.",
                max_length=64,
                pattern=r"^[a-z][a-z0-9._-]{0,63}$",
            ),
            "ref": _evidence_ref("Evidence handle from the builder result."),
            "sha256": _string(
                "Lowercase SHA-256 digest of the cited evidence content.",
                min_length=64,
                max_length=64,
                pattern=r"^[0-9a-f]{64}$",
            ),
            "media_type": _string(
                "Optional evidence media type.", min_length=0, max_length=200
            ),
        },
        required=("ref", "sha256", "kind"),
    )
    criterion_evaluation_schema = _object(
        "One default-fail CriterionEvaluation backed by explicit evidence.",
        {
            "criterion_id": _criterion_id(),
            "accepted": _boolean(
                "Explicit per-criterion assertion; defaults fail when omitted by the core."
            ),
            "reason": _string(
                "Bounded CriterionEvaluation reason.", max_length=4_000
            ),
            "required_evidence": _array(
                "Exact immutable evidence-kind set declared by this criterion.",
                _string(
                    "Required evidence kind slug.",
                    max_length=64,
                    pattern=r"^[a-z][a-z0-9._-]{0,63}$",
                ),
                min_items=1,
                max_items=50,
                unique=True,
            ),
            "evidence_refs": _array(
                "Evidence handles already available to the evaluator. Passing criteria "
                "must exactly cover required_evidence; failing criteria may cite a subset.",
                criterion_evidence_schema,
                min_items=0,
                max_items=100,
            ),
        },
        required=(
            "criterion_id",
            "accepted",
            "reason",
            "required_evidence",
            "evidence_refs",
        ),
    )
    properties = {
        **_scope_properties(),
        **_continuation_properties(role="evaluator"),
        **_assignment_custody_properties(),
        **_mutation_properties(),
        "decision": _string(
            "EvaluatorVerdict decision.",
            max_length=32,
            enum=("accept", "retry_build", "revise_plan", "reject", "block"),
        ),
        "accepted": _boolean(
            "Explicit EvaluatorVerdict accepted assertion; true only with decision=accept."
        ),
        "summary": _string(
            "Bounded EvaluatorVerdict summary.", max_length=20_000
        ),
        "plan_digest": _string(
            "Lowercase SHA-256 digest of the evaluated PlannerPlan.",
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
        "builder_result_digest": _string(
            "Lowercase SHA-256 digest of the evaluated BuilderResult.",
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
        "required_criterion_ids": _array(
            "Complete immutable criterion set from the evaluator assignment.",
            _criterion_id(),
            min_items=1,
            max_items=100,
            unique=True,
        ),
        "criterion_results": _array(
            "Explicit criterion decisions. Omitted criteria default to failure; an accept "
            "verdict must include every required criterion exactly once.",
            criterion_evaluation_schema,
            min_items=0,
            max_items=100,
        ),
    }
    input_schema = _object(
        "Submit a verdict for the exclusively leased evaluator assignment.",
        properties,
        required=(
            "company_ref",
            "project_ref",
            *_continuation_required(),
            "assignment_ref",
            "assignment_receipt",
            "expected_revision",
            "idempotency_key",
            "decision",
            "accepted",
            "summary",
            "plan_digest",
            "builder_result_digest",
            "required_criterion_ids",
            "criterion_results",
        ),
    )
    return input_schema, _submission_output_schema(
        "Accepted evaluator submission.", evaluator_assurance=True
    )


def _cancel_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = _object(
        "Cancel a non-terminal workflow run using optimistic concurrency.",
        {
            **_scope_properties(),
            **_continuation_properties(),
            **_mutation_properties(),
            "reason": _string("Bounded cancellation reason.", max_length=2_048),
        },
        required=(
            "company_ref",
            "project_ref",
            *_continuation_required(),
            "expected_revision",
            "idempotency_key",
            "reason",
        ),
    )
    output_schema = _object(
        "Cancelled workflow state.",
        {
            **_base_output_properties(),
            "cancelled": _boolean("Confirms cancellation.", const=True),
            "cancelled_at": _string(
                "Cancellation timestamp.", max_length=64, format_="date-time"
            ),
        },
        required=(
            "run_ref",
            "revision",
            "status",
            "scope",
            "cancelled",
            "cancelled_at",
            "context_linked",
        ),
    )
    return input_schema, output_schema


def _camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(piece[:1].upper() + piece[1:] for piece in tail)


def _top_level_aliases(schema: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}
    for name in schema.get("properties", {}):
        alias = _camel_case(name)
        if alias != name:
            aliases[name] = (alias,)
    return aliases


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)


def _operation(
    operation: str,
    title: str,
    description: str,
    *,
    required_scopes: Sequence[str],
    mutating: bool,
    destructive: bool,
    schemas: tuple[dict[str, Any], dict[str, Any]],
    state_preconditions: Sequence[str] = (),
) -> DynamicWorkflowMcpOperation:
    input_schema, output_schema = schemas
    input_schema.setdefault("x-lightbulb-max-json-bytes", 1_048_576)
    input_schema.setdefault("x-lightbulb-max-depth", 12)
    input_schema.setdefault("x-lightbulb-max-nodes", 10_000)
    output_schema.setdefault("x-lightbulb-max-json-bytes", 1_048_576)
    output_schema.setdefault("x-lightbulb-max-depth", 12)
    output_schema.setdefault("x-lightbulb-max-nodes", 10_000)
    return DynamicWorkflowMcpOperation(
        operation=operation,
        tool_name=TOOL_PREFIX + operation,
        title=title,
        description=description,
        required_scopes=tuple(required_scopes),
        mutating=mutating,
        destructive=destructive,
        input_schema=_freeze(input_schema),
        output_schema=_freeze(output_schema),
        input_aliases=_freeze(_top_level_aliases(input_schema)),
        output_aliases=_freeze(_top_level_aliases(output_schema)),
        state_preconditions=tuple(state_preconditions),
    )


_OPERATIONS = (
    _operation(
        "start",
        "Start dynamic workflow",
        "Start an actor-scoped, revisioned planner/builder/evaluator workflow and bind planner custody to this host session.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_start_schemas(),
        state_preconditions=("authenticated_scope_exact", "acceptance_criteria_immutable"),
    ),
    _operation(
        "attach",
        "Attach dynamic workflow host",
        "Bind a new planner, builder, or evaluator host session to an existing run for cross-host continuation.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_attach_schemas(),
        state_preconditions=(
            "authenticated_scope_exact",
            "expected_revision_current",
            "requested_role_available",
            "evaluator_role_requires_awaiting_evaluation",
            "fresh_role_binding_required",
        ),
    ),
    _operation(
        "status",
        "Dynamic workflow status",
        "Read bounded status for a workflow run using its host-session continuation receipt.",
        required_scopes=(READ_SCOPE,),
        mutating=False,
        destructive=False,
        schemas=_status_schemas(),
        state_preconditions=("binding_receipt_valid", "authenticated_scope_exact"),
    ),
    _operation(
        "next_assignment",
        "Lease next dynamic-workflow assignment",
        "Establish exclusive custody of the next planner, builder, or evaluator assignment.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_next_assignment_schemas(),
        state_preconditions=(
            "binding_receipt_valid",
            "binding_role_matches_assignment",
            "expected_revision_current",
            "no_active_assignment_lease",
        ),
    ),
    _operation(
        "submit_plan",
        "Submit planner plan",
        "Commit the PlannerPlan from an exclusively leased planner assignment.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_plan_schemas(),
        state_preconditions=(
            "planner_binding_receipt_valid",
            "assignment_lease_valid",
            "expected_revision_current",
            "plan_covers_all_acceptance_criteria",
        ),
    ),
    _operation(
        "submit_builder_result",
        "Submit builder result",
        "Commit the result of an exclusively leased builder assignment.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_builder_result_schemas(),
        state_preconditions=(
            "builder_binding_receipt_valid",
            "assignment_lease_valid",
            "expected_revision_current",
            "evidence_content_digests_valid",
            "evidence_criteria_known",
        ),
    ),
    _operation(
        "submit_evaluator_verdict",
        "Submit evaluator verdict",
        "Commit the verdict for an exclusively leased evaluator assignment.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=False,
        schemas=_evaluator_verdict_schemas(),
        state_preconditions=(
            "evaluator_binding_receipt_valid",
            "evaluator_binding_distinct_from_builder_binding",
            "assignment_lease_valid",
            "expected_revision_current",
            "criterion_set_matches_run",
            "criterion_evidence_exists",
            "missing_criterion_defaults_to_failure",
        ),
    ),
    _operation(
        "cancel",
        "Cancel dynamic workflow",
        "Cancel a non-terminal workflow run with optimistic concurrency.",
        required_scopes=(WRITE_SCOPE,),
        mutating=True,
        destructive=True,
        schemas=_cancel_schemas(),
        state_preconditions=("binding_receipt_valid", "expected_revision_current"),
    ),
)


def validate_catalog(
    operations: Iterable[DynamicWorkflowMcpOperation],
    *,
    require_complete: bool = True,
) -> tuple[DynamicWorkflowMcpOperation, ...]:
    """Validate catalog invariants and return the materialized operations.

    The validator is intentionally strict so an adapter cannot accidentally
    publish an unscoped mutation or a permissive top-level envelope.
    """

    materialized = tuple(operations)
    by_operation: dict[str, DynamicWorkflowMcpOperation] = {}
    tool_names: set[str] = set()
    for item in materialized:
        if not isinstance(item, DynamicWorkflowMcpOperation):
            raise DynamicWorkflowCatalogError("catalog entries must be DynamicWorkflowMcpOperation")
        if not _SNAKE_CASE.fullmatch(item.operation):
            raise DynamicWorkflowCatalogError(f"invalid operation name: {item.operation!r}")
        if item.operation in by_operation or item.tool_name in tool_names:
            raise DynamicWorkflowCatalogError("operation and tool names must be unique")
        if item.tool_name != TOOL_PREFIX + item.operation:
            raise DynamicWorkflowCatalogError(
                f"tool name for {item.operation!r} must be {TOOL_PREFIX + item.operation!r}"
            )
        if not item.required_scopes or any(
            scope not in {READ_SCOPE, WRITE_SCOPE} for scope in item.required_scopes
        ):
            raise DynamicWorkflowCatalogError(
                f"{item.operation} has missing or unknown scope requirements"
            )
        if item.mutating and WRITE_SCOPE not in item.required_scopes:
            raise DynamicWorkflowCatalogError(
                f"mutating operation {item.operation} must require the write scope"
            )
        if not item.mutating and item.required_scopes != (READ_SCOPE,):
            raise DynamicWorkflowCatalogError(
                f"read-only operation {item.operation} must require only the read scope"
            )
        if item.destructive and not item.mutating:
            raise DynamicWorkflowCatalogError("destructive operations must be mutating")
        if any(
            not isinstance(value, str) or not _SNAKE_CASE.fullmatch(value)
            for value in item.state_preconditions
        ):
            raise DynamicWorkflowCatalogError(
                f"{item.operation} has invalid state precondition names"
            )
        if item.mutating and not item.state_preconditions:
            raise DynamicWorkflowCatalogError(
                f"mutating operation {item.operation} must declare state preconditions"
            )
        for direction, schema in (
            ("input", item.input_schema),
            ("output", item.output_schema),
        ):
            if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
                raise DynamicWorkflowCatalogError(
                    f"{item.operation} {direction} must be a closed object schema"
                )
            properties = schema.get("properties")
            if not isinstance(properties, Mapping):
                raise DynamicWorkflowCatalogError(
                    f"{item.operation} {direction} properties are required"
                )
            if any(not _SNAKE_CASE.fullmatch(str(name)) for name in properties):
                raise DynamicWorkflowCatalogError(
                    f"{item.operation} {direction} fields must use canonical snake_case"
                )
            missing_schema = set(schema.get("required", ())) - set(properties)
            if missing_schema:
                raise DynamicWorkflowCatalogError(
                    f"{item.operation} {direction} requires undeclared fields: {sorted(missing_schema)}"
                )
        input_required = set(item.input_schema.get("required", ()))
        if not {"company_ref", "project_ref"}.issubset(input_required):
            raise DynamicWorkflowCatalogError(
                f"operation {item.operation} must require public company and project scope"
            )
        if item.mutating and not {"expected_revision", "idempotency_key"}.issubset(input_required):
            raise DynamicWorkflowCatalogError(
                f"mutating operation {item.operation} must require revision and idempotency"
            )
        if not item.mutating and {"expected_revision", "idempotency_key"} & set(
            item.input_schema.get("properties", {})
        ):
            raise DynamicWorkflowCatalogError(
                f"read-only operation {item.operation} cannot expose mutation controls"
            )
        if item.operation == "start" and "acceptance_criteria" not in input_required:
            raise DynamicWorkflowCatalogError(
                "start must require immutable acceptance criteria"
            )
        if item.operation not in {"start", "attach"} and not set(
            _continuation_required()
        ).issubset(input_required):
            raise DynamicWorkflowCatalogError(
                f"operation {item.operation} must require role-bound host custody"
            )
        _validate_alias_catalog(item, "input", item.input_aliases, item.input_schema)
        _validate_alias_catalog(item, "output", item.output_aliases, item.output_schema)
        by_operation[item.operation] = item
        tool_names.add(item.tool_name)

    if require_complete and tuple(by_operation) != _EXPECTED_OPERATIONS:
        raise DynamicWorkflowCatalogError(
            f"catalog operations must be exactly {_EXPECTED_OPERATIONS!r} in protocol order"
        )
    return materialized


def _validate_alias_catalog(
    operation: DynamicWorkflowMcpOperation,
    direction: str,
    aliases: Mapping[str, tuple[str, ...]],
    schema: Mapping[str, Any],
) -> None:
    properties = schema.get("properties", {})
    seen: set[str] = set(properties)
    for canonical, transport_aliases in aliases.items():
        if canonical not in properties:
            raise DynamicWorkflowCatalogError(
                f"{operation.operation} {direction} aliases unknown field {canonical!r}"
            )
        if not transport_aliases:
            raise DynamicWorkflowCatalogError("transport alias lists cannot be empty")
        for alias in transport_aliases:
            if alias in seen:
                raise DynamicWorkflowCatalogError(
                    f"ambiguous {direction} transport alias {alias!r}"
                )
            seen.add(alias)


OPERATIONS = validate_catalog(_OPERATIONS)
OPERATION_CATALOG: Mapping[str, DynamicWorkflowMcpOperation] = MappingProxyType(
    {item.operation: item for item in OPERATIONS}
)
TOOL_CATALOG: Mapping[str, DynamicWorkflowMcpOperation] = MappingProxyType(
    {item.tool_name: item for item in OPERATIONS}
)


def get_operation(identifier: str) -> DynamicWorkflowMcpOperation:
    """Resolve an exact operation key or exact MCP tool name; never guess."""

    if not isinstance(identifier, str) or not identifier:
        raise UnknownDynamicWorkflowOperation("operation identifier must be a non-empty string")
    operation = OPERATION_CATALOG.get(identifier) or TOOL_CATALOG.get(identifier)
    if operation is None:
        raise UnknownDynamicWorkflowOperation(f"unknown dynamic-workflow operation: {identifier!r}")
    return operation


def require_operation_scopes(
    identifier: str,
    granted_scopes: str | Iterable[str],
) -> DynamicWorkflowMcpOperation:
    """Require every exact scope declared by an operation.

    Blank/legacy scope claims fail closed for this protocol.
    """

    operation = get_operation(identifier)
    if isinstance(granted_scopes, str):
        granted = {scope for scope in granted_scopes.split() if scope}
    else:
        try:
            supplied = tuple(granted_scopes)
        except TypeError as exc:
            raise DynamicWorkflowScopeError("granted scopes must be a string or iterable") from exc
        if any(not isinstance(scope, str) or not scope for scope in supplied):
            raise DynamicWorkflowScopeError(
                "granted scope iterables may contain only non-empty strings"
            )
        granted = set(supplied)
    missing = [scope for scope in operation.required_scopes if scope not in granted]
    if missing:
        raise DynamicWorkflowScopeError(
            f"{operation.tool_name} requires scope(s): {', '.join(missing)}"
        )
    return operation


def normalize_transport_payload(
    identifier: str,
    payload: Mapping[str, Any],
    *,
    direction: str = "input",
) -> dict[str, Any]:
    """Translate only explicitly declared top-level aliases to canonical fields.

    Canonical and aliased spellings in the same payload are rejected as
    ambiguous.  Nested fields always remain canonical snake_case.
    """

    operation = get_operation(identifier)
    if direction not in {"input", "output"}:
        raise DynamicWorkflowPayloadError("direction must be 'input' or 'output'")
    if not isinstance(payload, Mapping):
        raise DynamicWorkflowPayloadError(f"{direction} payload must be an object")
    alias_catalog = operation.input_aliases if direction == "input" else operation.output_aliases
    alias_to_canonical = {
        alias: canonical
        for canonical, aliases in alias_catalog.items()
        for alias in aliases
    }
    normalized: dict[str, Any] = {}
    for raw_key, value in payload.items():
        if not isinstance(raw_key, str):
            raise DynamicWorkflowPayloadError(f"{direction} object keys must be strings")
        canonical = alias_to_canonical.get(raw_key, raw_key)
        if canonical in normalized:
            raise DynamicWorkflowPayloadError(
                f"ambiguous {direction} field supplied more than once: {canonical}"
            )
        normalized[canonical] = deepcopy(value)
    return normalized


def validate_operation_input(
    identifier: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an already-canonical input payload and return a defensive copy."""

    operation = get_operation(identifier)
    canonical = deepcopy(dict(payload)) if isinstance(payload, Mapping) else payload
    _validate_schema(operation.input_schema, canonical, f"{operation.tool_name}.input")
    if operation.operation == "start":
        criterion_ids = [
            item["criterion_id"] for item in canonical["acceptance_criteria"]
        ]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.input acceptance criterion IDs must be unique"
            )
    elif operation.operation == "submit_plan":
        _validate_plan_coverage(operation, canonical)
    elif operation.operation == "submit_evaluator_verdict":
        _validate_evaluator_coverage(operation, canonical)
    return canonical


def _validate_plan_coverage(
    operation: DynamicWorkflowMcpOperation,
    payload: Mapping[str, Any],
) -> None:
    required_ids = set(payload["required_criterion_ids"])
    criteria = list(payload["plan"]["acceptance_criteria"])
    criterion_ids = [criterion["criterion_id"] for criterion in criteria]
    if len(criterion_ids) != len(set(criterion_ids)):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input plan criterion IDs must be unique"
        )
    if set(criterion_ids) != required_ids:
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input plan must preserve every required criterion exactly"
        )


def validate_operation_output(
    identifier: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an already-canonical adapter result before returning it to an MCP host."""

    operation = get_operation(identifier)
    canonical = deepcopy(dict(payload)) if isinstance(payload, Mapping) else payload
    _validate_schema(operation.output_schema, canonical, f"{operation.tool_name}.output")
    context_linked = canonical.get("context_linked", False)
    has_context_revision = "context_revision" in canonical
    if context_linked is not has_context_revision:
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.output context revision presence must match context_linked"
        )
    if operation.operation == "next_assignment":
        available = canonical.get("assignment_available")
        has_assignment = "assignment" in canonical
        if available is not has_assignment:
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.output assignment presence must match assignment_available"
            )
        if has_assignment:
            has_anchor = "context_anchor" in canonical["assignment"]
            if context_linked is not has_anchor:
                raise DynamicWorkflowPayloadError(
                    f"{operation.tool_name}.output context anchor presence must match "
                    "context_linked"
                )
    if operation.operation in {
        "submit_plan",
        "submit_builder_result",
        "submit_evaluator_verdict",
    }:
        has_checkpoint = "context_checkpoint_ref" in canonical
        if context_linked is not has_checkpoint:
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.output context checkpoint presence must match "
                "context_linked"
            )
    return canonical


def validate_operation_exchange(
    identifier: str,
    input_payload: Mapping[str, Any],
    output_payload: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate both envelopes plus request/response custody invariants."""

    operation = get_operation(identifier)
    validated_input = validate_operation_input(identifier, input_payload)
    validated_output = validate_operation_output(identifier, output_payload)
    if operation.operation == "attach" and (
        validated_output["bound_role"] != validated_input["host_role"]
    ):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name} output binding role does not match the requested role"
        )
    if operation.operation == "next_assignment" and validated_output[
        "assignment_available"
    ] and (
        validated_output["assignment"]["role"] != validated_input["host_role"]
    ):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name} leased assignment role does not match binding custody"
        )
    return validated_input, validated_output


def _validate_evaluator_coverage(
    operation: DynamicWorkflowMcpOperation,
    payload: Mapping[str, Any],
) -> None:
    required_ids = list(payload["required_criterion_ids"])
    evaluations = list(payload["criterion_results"])
    evaluated_ids = [item["criterion_id"] for item in evaluations]
    if len(evaluated_ids) != len(set(evaluated_ids)):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input criterion evaluations must be unique"
        )
    unknown_ids = sorted(set(evaluated_ids) - set(required_ids))
    if unknown_ids:
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input contains unknown criterion evaluations: "
            + ", ".join(unknown_ids)
        )
    if payload["decision"] == "accept" and set(evaluated_ids) != set(required_ids):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input accept must evaluate every required criterion "
            "exactly once"
        )
    for evaluation in evaluations:
        required_kinds = set(evaluation["required_evidence"])
        evidence_kinds = {item["kind"] for item in evaluation["evidence_refs"]}
        if evaluation["accepted"] and evidence_kinds != required_kinds:
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.input passing evidence kinds must exactly cover criterion "
                f"{evaluation['criterion_id']}"
            )
        if not evaluation["accepted"] and not evidence_kinds.issubset(required_kinds):
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.input failing evidence kinds must be a subset of "
                f"criterion {evaluation['criterion_id']}"
            )
        evidence_refs = [item["ref"] for item in evaluation["evidence_refs"]]
        if len(evidence_refs) != len(set(evidence_refs)):
            raise DynamicWorkflowPayloadError(
                f"{operation.tool_name}.input evidence refs must be unique per criterion"
            )
    if payload["decision"] == "accept" and (
        not payload["accepted"] or any(not item["accepted"] for item in evaluations)
    ):
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input cannot accept with a non-passing criterion"
        )
    if payload["decision"] != "accept" and payload["accepted"]:
        raise DynamicWorkflowPayloadError(
            f"{operation.tool_name}.input only an accept decision may assert accepted=true"
        )


def authorize_and_validate_call(
    identifier: str,
    payload: Mapping[str, Any],
    granted_scopes: str | Iterable[str],
    *,
    transport_aliases: bool = False,
) -> ValidatedDynamicWorkflowCall:
    """Fail-closed adapter entry point for authorization plus input validation."""

    operation = require_operation_scopes(identifier, granted_scopes)
    candidate = (
        normalize_transport_payload(identifier, payload, direction="input")
        if transport_aliases
        else payload
    )
    validated = validate_operation_input(identifier, candidate)
    return ValidatedDynamicWorkflowCall(
        operation=operation,
        payload=_freeze(validated),
    )


def _validate_schema(schema: Mapping[str, Any], value: Any, path: str) -> None:
    if "const" in schema and value != schema["const"]:
        raise DynamicWorkflowPayloadError(f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise DynamicWorkflowPayloadError(f"{path} is not an allowed value")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, Mapping):
            raise DynamicWorkflowPayloadError(f"{path} must be an object")
        _validate_json_limits(schema, value, path)
        properties = schema.get("properties", {})
        required = set(schema.get("required", ()))
        missing = sorted(required - set(value))
        if missing:
            raise DynamicWorkflowPayloadError(
                f"{path} is missing required field(s): {', '.join(missing)}"
            )
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if not isinstance(key, str):
                raise DynamicWorkflowPayloadError(f"{path} object keys must be strings")
            child_schema = properties.get(key)
            if child_schema is None:
                if additional is False:
                    raise DynamicWorkflowPayloadError(f"{path} contains unknown field: {key}")
                if isinstance(additional, Mapping):
                    _validate_schema(additional, item, f"{path}.{key}")
                else:
                    _validate_json_value(item, f"{path}.{key}")
            else:
                _validate_schema(child_schema, item, f"{path}.{key}")
        return

    if expected_type == "array":
        if not isinstance(value, list | tuple):
            raise DynamicWorkflowPayloadError(f"{path} must be an array")
        if len(value) < int(schema.get("minItems", 0)):
            raise DynamicWorkflowPayloadError(f"{path} has too few items")
        if len(value) > int(schema.get("maxItems", 2_147_483_647)):
            raise DynamicWorkflowPayloadError(f"{path} has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, allow_nan=False) for item in value]
            if len(encoded) != len(set(encoded)):
                raise DynamicWorkflowPayloadError(f"{path} items must be unique")
        item_schema = schema.get("items", {})
        for index, item in enumerate(value):
            _validate_schema(item_schema, item, f"{path}[{index}]")
        return

    if expected_type == "string":
        if not isinstance(value, str):
            raise DynamicWorkflowPayloadError(f"{path} must be a string")
        if len(value) < int(schema.get("minLength", 0)):
            raise DynamicWorkflowPayloadError(f"{path} is too short")
        if len(value) > int(schema.get("maxLength", 2_147_483_647)):
            raise DynamicWorkflowPayloadError(f"{path} is too long")
        pattern = schema.get("pattern")
        if pattern is not None and re.search(str(pattern), value) is None:
            raise DynamicWorkflowPayloadError(f"{path} has an invalid format")
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise DynamicWorkflowPayloadError(f"{path} must be an ISO-8601 date-time") from exc
            if parsed.tzinfo is None:
                raise DynamicWorkflowPayloadError(f"{path} date-time must include an offset")
        return

    if expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise DynamicWorkflowPayloadError(f"{path} must be an integer")
        _validate_numeric_bounds(schema, value, path)
        return

    if expected_type == "number":
        if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
            raise DynamicWorkflowPayloadError(f"{path} must be a finite number")
        _validate_numeric_bounds(schema, value, path)
        return

    if expected_type == "boolean":
        if not isinstance(value, bool):
            raise DynamicWorkflowPayloadError(f"{path} must be a boolean")
        return

    raise DynamicWorkflowCatalogError(f"unsupported schema type at {path}: {expected_type!r}")


def _validate_numeric_bounds(schema: Mapping[str, Any], value: int | float, path: str) -> None:
    if "minimum" in schema and value < schema["minimum"]:
        raise DynamicWorkflowPayloadError(f"{path} is below its minimum")
    if "maximum" in schema and value > schema["maximum"]:
        raise DynamicWorkflowPayloadError(f"{path} exceeds its maximum")


def _validate_json_limits(schema: Mapping[str, Any], value: Mapping[str, Any], path: str) -> None:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DynamicWorkflowPayloadError(f"{path} must contain JSON values only") from exc
    max_bytes = schema.get("x-lightbulb-max-json-bytes")
    if max_bytes is not None and len(encoded) > int(max_bytes):
        raise DynamicWorkflowPayloadError(f"{path} exceeds its encoded byte limit")
    max_depth = int(schema.get("x-lightbulb-max-depth", 64))
    max_nodes = int(schema.get("x-lightbulb-max-nodes", 100_000))
    depth, nodes = _json_stats(value, 0)
    if depth > max_depth or nodes > max_nodes:
        raise DynamicWorkflowPayloadError(f"{path} is too deeply nested or complex")


def _json_stats(value: Any, depth: int) -> tuple[int, int]:
    if isinstance(value, Mapping):
        max_depth = depth
        nodes = 1
        for item in value.values():
            child_depth, child_nodes = _json_stats(item, depth + 1)
            max_depth = max(max_depth, child_depth)
            nodes += child_nodes
        return max_depth, nodes
    if isinstance(value, list | tuple):
        max_depth = depth
        nodes = 1
        for item in value:
            child_depth, child_nodes = _json_stats(item, depth + 1)
            max_depth = max(max_depth, child_depth)
            nodes += child_nodes
        return max_depth, nodes
    return depth, 1


def _validate_json_value(value: Any, path: str) -> None:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise DynamicWorkflowPayloadError(f"{path} must be a JSON value") from exc


def render_mcp_tool(identifier: str) -> dict[str, Any]:
    """Render one standard MCP tool descriptor with protocol extensions."""

    operation = get_operation(identifier)
    security_schemes = [{"type": "oauth2", "scopes": list(operation.required_scopes)}]
    metadata = {
        "securitySchemes": deepcopy(security_schemes),
        "lightbulb/protocol": MANIFEST_SCHEMA,
        "lightbulb/protocolVersion": PROTOCOL_VERSION,
        "lightbulb/operation": operation.operation,
        "lightbulb/requiredScopes": list(operation.required_scopes),
        "lightbulb/statePreconditions": list(operation.state_preconditions),
        "lightbulb/transportAliases": {
            "input": _thaw(operation.input_aliases),
            "output": _thaw(operation.output_aliases),
        },
        "lightbulb/actorScope": {
            "identitySource": "authenticated_principal",
            "tenantSource": "authenticated_principal",
            "companyField": "company_ref",
            "projectField": "project_ref",
            "clientActorIdsAllowed": False,
            "resolution": "fail_closed",
        },
    }
    return {
        "name": operation.tool_name,
        "title": operation.title,
        "description": operation.description,
        "inputSchema": _thaw(operation.input_schema),
        "outputSchema": _thaw(operation.output_schema),
        "annotations": {
            "readOnlyHint": operation.read_only,
            "destructiveHint": operation.destructive,
            "idempotentHint": operation.mutating,
            "openWorldHint": False,
        },
        "securitySchemes": security_schemes,
        "_meta": metadata,
    }


def render_manifest() -> dict[str, Any]:
    """Render a deterministic Python/Java parity manifest."""

    return {
        "schema": MANIFEST_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "canonical_field_style": "snake_case",
        "tool_prefix": TOOL_PREFIX,
        "scope_vocabulary": {
            "read": READ_SCOPE,
            "write": WRITE_SCOPE,
        },
        "actor_scope": {
            "identity_source": "authenticated_principal",
            "tenant_source": "authenticated_principal",
            "company_field": "company_ref",
            "project_field": "project_ref",
            "client_actor_ids_allowed": False,
            "resolution": "fail_closed",
        },
        "operations": [
            {
                "operation": operation.operation,
                "tool_name": operation.tool_name,
                "required_scopes": list(operation.required_scopes),
                "mutating": operation.mutating,
                "read_only": operation.read_only,
                "destructive": operation.destructive,
                "state_preconditions": list(operation.state_preconditions),
                "input_aliases": _thaw(operation.input_aliases),
                "output_aliases": _thaw(operation.output_aliases),
            }
            for operation in OPERATIONS
        ],
        "tools": [render_mcp_tool(operation.operation) for operation in OPERATIONS],
    }


def render_manifest_json(*, pretty: bool = False) -> str:
    """Render stable JSON suitable for checked parity fixtures in other runtimes."""

    separators = None if pretty else (",", ":")
    return json.dumps(
        render_manifest(),
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=separators,
        sort_keys=True,
    )


__all__ = [
    "MANIFEST_SCHEMA",
    "OPERATION_CATALOG",
    "OPERATIONS",
    "PROTOCOL_VERSION",
    "READ_SCOPE",
    "TOOL_CATALOG",
    "TOOL_PREFIX",
    "WRITE_SCOPE",
    "DynamicWorkflowCatalogError",
    "DynamicWorkflowMcpOperation",
    "DynamicWorkflowMcpProtocolError",
    "DynamicWorkflowPayloadError",
    "DynamicWorkflowScopeError",
    "UnknownDynamicWorkflowOperation",
    "ValidatedDynamicWorkflowCall",
    "authorize_and_validate_call",
    "get_operation",
    "normalize_transport_payload",
    "render_manifest",
    "render_manifest_json",
    "render_mcp_tool",
    "require_operation_scopes",
    "validate_catalog",
    "validate_operation_input",
    "validate_operation_exchange",
    "validate_operation_output",
]
