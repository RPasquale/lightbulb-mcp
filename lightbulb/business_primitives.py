"""Business primitive catalog and executor helpers for Lightbulb MCP hosts.

The primitives in this module are user-facing business tasks such as creating
an invoice, writing an email, or reviewing a contract. They are intentionally
above raw connector operations: execution routes through Backbone/domain
orchestration with the authenticated user's tenant, company, RBAC, connector,
and HITL approval rules intact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from lightbulb.profit_workflow_blueprints import (
    PROFIT_WORKFLOW_DEFINITIONS,
    ProfitWorkflowDefinition,
)

CATALOG_SCHEMA = "lightbulb.business_primitive_catalog.v1"
EXECUTION_SCHEMA = "lightbulb.business_primitive_execution.v1"
WORKFLOW_BUILDER_SCHEMA = "lightbulb.business_primitive_workflow_builder.v1"
PRIMITIVE_RUNTIME_CONTRACT_SCHEMA = "lightbulb.primitive_runtime_contract.v1"
PRIMITIVE_CAPABILITY_PROJECTION_SCHEMA = "lightbulb.business_primitive_capability.v1"
WORKFLOW_COMPILER_CONTRACT_SCHEMA = "lightbulb.workflow_compiler_contract.v1"
WORKFLOW_DEFINITION_SCHEMA = "lightbulb.business_workflow_definition.v1"
WORKFLOW_VALIDATION_SCHEMA = "lightbulb.business_workflow_validation.v1"
WORKFLOW_SIMULATION_SCHEMA = "lightbulb.business_workflow_simulation.v1"
BOUNDED_WORKFLOW_LOOP_SCHEMA = "lightbulb.bounded_workflow_loop.v1"

_DEFAULT_LOOP_ITERATIONS = 10
_MAX_LOOP_ITERATIONS = 100
_MAX_WORKFLOW_STEP_TRANSITIONS = 100
_LOOP_CONTINUE_CONDITION = "$.payload.outputs.continue_loop == true"
_LOOP_EXIT_CONDITION = "always"
_LOOP_EXHAUSTION_POLICY = "fail_closed"

_WORKFLOW_INPUT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SENSITIVE_WORKFLOW_INPUT_KEYS = frozenset(
    {
        "access_token",
        "apikey",
        "api_key",
        "authorization",
        "bearer_token",
        "clientsecret",
        "client_secret",
        "connector_secret",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "private_key",
        "refreshtoken",
        "refresh_token",
        "secret",
        "token",
    }
)
_SENSITIVE_WORKFLOW_INPUT_SUFFIXES = (
    "_access_token",
    "_api_key",
    "_auth_token",
    "_bearer_token",
    "_client_secret",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_token",
)
_RESERVED_WORKFLOW_INPUT_KEYS = frozenset(
    {
        "action",
        "approval_required",
        "connector_hints",
        "contract_schema",
        "execution_policy",
        "mode",
        "objective",
        "preferred_domain_action",
        "preview_only",
        "primitive_id",
        "primitive_ref",
        "primitive_runtime_contract",
        "requested_inputs",
        "schema",
    }
)


def _workflow_input_json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _workflow_input_key_is_sensitive(key: str) -> bool:
    normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
    compact = normalized.replace("_", "")
    return (
        normalized in _SENSITIVE_WORKFLOW_INPUT_KEYS
        or normalized.endswith(_SENSITIVE_WORKFLOW_INPUT_SUFFIXES)
        or compact in _SENSITIVE_WORKFLOW_INPUT_KEYS
    )


def _workflow_input_metadata(inputs: Dict[str, Any] | None) -> Dict[str, Any]:
    """Describe workflow inputs without retaining caller-supplied values.

    Auth material belongs in governed connector storage, never in an immutable
    workflow version. Restricting keys to simple identifiers also keeps the
    generated ``$.payload.inputs.<key>`` paths unambiguous for the runtime JSON
    path resolver.
    """
    clean_inputs = inputs or {}
    keys: List[str] = []
    provided_keys: List[str] = []
    json_types: Dict[str, str] = {}
    for raw_key, value in clean_inputs.items():
        if not isinstance(raw_key, str) or not _WORKFLOW_INPUT_KEY_RE.fullmatch(
            raw_key
        ):
            raise ValueError(
                "workflow input keys must match ^[A-Za-z_][A-Za-z0-9_]{0,63}$ "
                "so runtime JSON paths remain unambiguous"
            )
        if _workflow_input_key_is_sensitive(raw_key):
            raise ValueError(
                f"workflow input key '{raw_key}' looks like credential or secret material; "
                "store authentication in a governed connector instead"
            )
        if raw_key.lower() in _RESERVED_WORKFLOW_INPUT_KEYS:
            raise ValueError(
                f"workflow input key '{raw_key}' is reserved by the governed execution contract"
            )
        keys.append(raw_key)
        json_types[raw_key] = _workflow_input_json_type(value)
        if value not in (None, "", []):
            provided_keys.append(raw_key)
    return {
        "keys": keys,
        "provided_keys": provided_keys,
        "json_types": json_types,
        "runtime_value_source": "workflow_instance.inputs",
        "values_persisted": False,
    }


def _registered_executable_input_fields(primitive_ref: str) -> set[str] | None:
    """Return the exact typed runtime fields when an SDK implementation exists."""
    try:
        from lightbulb.executable_primitives import default_primitive_registry

        registry = default_primitive_registry()
        if not registry.supports(primitive_ref):
            return None
        return set(registry.get(primitive_ref).input_model.model_fields)
    except Exception:
        # Catalog-only primitives keep their existing domain-agent input
        # projection. Consequential catalog-only entries still fail closed in
        # Backbone until a typed implementation is installed.
        return None


@dataclass(frozen=True)
class PrimitiveField:
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "required": self.required,
        }


@dataclass(frozen=True)
class BusinessPrimitive:
    id: str
    title: str
    category: str
    summary: str
    description: str
    risk_level: str = "low"
    approval_required: bool = False
    default_mode: str = "draft"
    domain: str = ""
    action: str = "chat"
    connector_tools: Tuple[str, ...] = field(default_factory=tuple)
    capability_hints: Tuple[str, ...] = field(default_factory=tuple)
    additional_inputs_allowed: bool = True
    setup_requirements: Tuple[str, ...] = field(default_factory=tuple)
    trigger_events: Tuple[str, ...] = field(default_factory=tuple)
    emits: Tuple[str, ...] = field(default_factory=tuple)
    follow_up_primitives: Tuple[str, ...] = field(default_factory=tuple)
    agent_builder_guidance: str = ""
    input_fields: Tuple[PrimitiveField, ...] = field(default_factory=tuple)
    example_prompt: str = ""
    backbone_fallback_available: bool = True

    def to_dict(self, *, include_inputs: bool = True) -> Dict[str, Any]:
        agentic_workflow = {
            "setup_requirements": list(self.setup_requirements),
            "trigger_events": list(self.trigger_events),
            "emits": list(self.emits),
            "follow_up_primitives": list(self.follow_up_primitives),
            "agent_builder_guidance": self.agent_builder_guidance,
        }
        agentic_workflow = {
            key: value
            for key, value in agentic_workflow.items()
            if value not in ("", [])
        }
        data: Dict[str, Any] = {
            "id": self.id,
            "primitive_ref": self.id,
            "title": self.title,
            "category": self.category,
            "summary": self.summary,
            "description": self.description,
            "risk_level": self.risk_level,
            "approval_required": self.approval_required,
            "default_mode": self.default_mode,
            "preferred_domain_action": (
                {
                    "domain": self.domain,
                    "action": self.action,
                }
                if self.domain
                else None
            ),
            "preferred_connector_tools": list(self.connector_tools),
            "capability_hints": list(self.capability_hints),
            "agentic_workflow": agentic_workflow or None,
            "contract_schemas": {
                "runtime_contract": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
            },
            "runtime_contract": primitive_runtime_contract(
                self, include_inputs=include_inputs
            ),
            "backbone_fallback_available": self.backbone_fallback_available,
            "example_prompt": self.example_prompt,
        }
        if include_inputs:
            data["input_fields"] = [field.to_dict() for field in self.input_fields]
        return {
            key: value for key, value in data.items() if value not in (None, "", [])
        }


def primitive_runtime_contract(
    primitive: BusinessPrimitive,
    *,
    include_inputs: bool = True,
) -> Dict[str, Any]:
    """Return the versioned runtime contract for a business primitive."""
    fields = (
        [field.to_dict() for field in primitive.input_fields] if include_inputs else []
    )
    required_fields = [field.name for field in primitive.input_fields if field.required]
    return {
        "schema": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
        "primitive_ref": primitive.id,
        "title": primitive.title,
        "version": "1.0",
        "input_contract": {
            "fields": fields,
            "required_fields": required_fields,
            "additional_inputs_allowed": primitive.additional_inputs_allowed,
            "missing_required_fields_policy": "ask_or_return_needs_input",
        },
        "execution_contract": {
            "default_mode": primitive.default_mode,
            "executor": (
                "backbone_domain_agent"
                if primitive.backbone_fallback_available
                else "typed_sdk_primitive_runtime"
            ),
            "backbone_fallback_available": primitive.backbone_fallback_available,
            "preferred_domain_action": (
                {
                    "domain": primitive.domain,
                    "action": primitive.action,
                }
                if primitive.domain
                else None
            ),
            "preferred_connector_tools": list(primitive.connector_tools),
            "capability_hints": list(primitive.capability_hints),
            "capability_hints_are_dispatch_authority": False,
            "raw_connector_bypass_allowed": False,
            "preserve_tenant_company_rbac": True,
        },
        "setup_contract": {
            "requirements": list(primitive.setup_requirements),
            "agent_builder_must_infer_hidden_setup": True,
            "user_must_not_need_to_name_technical_infrastructure": True,
        },
        "event_contract": {
            "trigger_events": list(primitive.trigger_events),
            "emits": list(primitive.emits),
            "follow_up_primitives": list(primitive.follow_up_primitives),
        },
        "risk_contract": {
            "risk_level": primitive.risk_level,
            "approval_required": primitive.approval_required,
            "consequential_writes_require_hitl": primitive.approval_required,
            "direct_connector_write_without_approval": False,
            "return_pending_approval_when_required": True,
        },
        "observability_contract": {
            "correlation_keys": [
                "tenant_ref",
                "company_ref",
                "primitive_ref",
                "workflow_run_ref",
                "approval_ref",
                "external_object_ref",
            ],
            "audit_events": [
                "primitive.requested",
                "primitive.context_resolved",
                "primitive.approval_requested",
                "primitive.executed_or_staged",
                "primitive.event_emitted",
            ],
            "evidence_required": [
                "source_request",
                "resolved_business_context",
                "connector_or_domain_action_selected",
                "approval_decision_when_required",
                "draft_or_external_write_result",
            ],
            "must_not_expose": [
                "tenant_id",
                "company_id",
                "workflow_instance_id",
                "trace_id",
                "connector_secret",
            ],
        },
        "recovery_contract": {
            "idempotency_key_required": True,
            "retry_policy": "idempotent_retry_with_backoff",
            "compensation_policy": "return_reversible_draft_or_escalate_for_human_resolution",
            "dead_letter_policy": "record_blocker_with_business_context_and_next_action",
        },
        "composition_contract": {
            "agent_builder_guidance": primitive.agent_builder_guidance,
            "chainable_after_events": list(primitive.trigger_events),
            "chainable_before_primitives": list(primitive.follow_up_primitives),
        },
        "acceptance_contract": {
            "must_return_status": True,
            "must_return_summary": True,
            "must_return_next_events": True,
            "must_return_follow_up_options": True,
            "must_return_missing_connector_or_permission_blockers": True,
        },
    }


def _profit_business_primitive(
    definition: ProfitWorkflowDefinition,
) -> BusinessPrimitive:
    """Project one code-owned profit blueprint into the public business catalog."""

    return BusinessPrimitive(
        id=definition.workflow_id,
        title=definition.title,
        category=definition.category,
        summary=(f"Profit workflow: {definition.promise}"),
        description=(
            f"{definition.promise} The SDK derives and ranks risk-adjusted contribution "
            "profit from bounded evidence and candidate economics, emits a reviewable "
            "proposal, and changes no live system."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        setup_requirements=(
            "authenticated_project_and_exact_connector_account_scope",
            "normalized_contribution_profit_cost_ledger",
            "host_hmac_keyring_for_verified_evidence_and_evaluation",
            "per_action_approval_before_external_materialization",
            "post_action_measurement_window_and_holdout_where_causal_lift_is_claimed",
        ),
        trigger_events=(definition.trigger_event,),
        emits=(definition.emits_event,),
        follow_up_primitives=definition.feeds,
        capability_hints=tuple(
            dict.fromkeys(
                (
                    *definition.evidence_capabilities,
                    *(item.capability for item in definition.action_capabilities),
                )
            )
        ),
        additional_inputs_allowed=False,
        agent_builder_guidance=(
            "Run this typed SDK primitive proposal-first. Treat all projected economics "
            "as assumptions until host-HMAC evidence and the bounded outcome evaluator "
            "verify them. Never dispatch intent_parameters as connector arguments. Route "
            "each proposed action through a separate typed primitive, connector/domain "
            "materializer, project allow-list, idempotency key, and content-bound approval. "
            "The standard MCP planner cannot mint authenticated scope or execute actions. "
            "Preserve the launch_ref and source plan digests across adjacent workflows."
        ),
        input_fields=(
            PrimitiveField(
                "analysis_as_of",
                "string",
                "Explicit ISO-8601 cutoff for deterministic evidence freshness.",
                True,
            ),
            PrimitiveField("plan_ref", "string", "Portable workflow plan key.", True),
            PrimitiveField(
                "launch_ref",
                "string",
                "Shared key that joins this workflow to the product launch flywheel.",
                True,
            ),
            PrimitiveField(
                "objective",
                "string",
                "Reviewed profit objective and business context.",
                True,
            ),
            PrimitiveField(
                "account_bindings",
                "array",
                "Opaque connector account references; never credentials or authority IDs.",
                False,
            ),
            PrimitiveField(
                "baseline",
                "object",
                "Gross sales and attributable discount, refund, COGS, fulfillment, fee, acquisition, and service costs.",
                True,
            ),
            PrimitiveField(
                "evidence",
                "array",
                "Provider/account/window-bound normalized metric evidence.",
                False,
            ),
            PrimitiveField(
                "candidates",
                "array",
                "Bounded profit-lever candidates with economics, downside, dependencies, and measurement metric.",
                True,
            ),
            PrimitiveField(
                "policy",
                "object",
                "Target, budget, confidence, freshness, sample, window, and iteration bounds.",
                True,
            ),
            PrimitiveField(
                "source_plan_digests",
                "array",
                "Content digests of reviewed upstream workflow artifacts.",
                False,
            ),
        ),
        example_prompt=(
            f"Use {definition.title.lower()} to maximize verified contribution profit "
            "for this launch, rank bounded actions, and return the evidence gaps and "
            "measurement loop without changing live systems."
        ),
        backbone_fallback_available=False,
    )


BUSINESS_PRIMITIVES: Tuple[BusinessPrimitive, ...] = (
    BusinessPrimitive(
        id="service.prepare_productised_assessment",
        title="Prepare a productised assessment",
        category="service",
        summary="Turn customer intake and evidence into findings and separately priced continuation offers.",
        description="Prepare an exact company/project-scoped draft assessment, implementation proposal, managed monitoring and software access options using supplied evidence and prices.",
        additional_inputs_allowed=False,
        setup_requirements=("Explicit selected company and project", "Customer goals, scoped evidence, findings and commercial terms"),
        trigger_events=("assessment.intake_ready",),
        emits=("service.productised_assessment_prepared",),
        follow_up_primitives=("documents.render_productised_assessment", "service.assess_engagement"),
        agent_builder_guidance="Use the selected operating Company even for an ADMIN or a company named Lightbulb. Supply fresh typed intake; the SDK seals it and preserves all readiness gaps. Review evidence and prices before governed downstream effects. Large dossiers use the direct Python compile_productised_assessment function.",
        input_fields=(
            PrimitiveField("scope", "object", "Exact ServiceEngagementScope matching execution context.", True),
            PrimitiveField("requested_by_ref", "string", "Requesting actor matching execution context.", True),
            PrimitiveField("assessment_ref", "string", "Assessment reference.", True),
            PrimitiveField("prepared_at", "string", "Explicit evidence cutoff timestamp.", True),
            PrimitiveField("title", "string", "Customer-facing assessment title.", True),
            PrimitiveField("executive_summary", "string", "Supplied summary for review."),
            PrimitiveField("brand", "object", "Selected company brand context."),
            PrimitiveField("customer", "object", "Exact engagement customer."),
            PrimitiveField("goals", "array", "Customer goals and success criteria."),
            PrimitiveField("evidence", "array", "Scoped evidence references with digests and validity windows."),
            PrimitiveField("findings", "array", "Findings linked to evidence and goals."),
            PrimitiveField("offers", "array", "Assessment, implementation, managed monitoring and software access offers."),
            PrimitiveField("engagement_snapshot", "object", "Optional exact canonical engagement snapshot."),
            PrimitiveField("input_digest", "string", "Existing exact input seal, if continuing an earlier draft."),
        ),
        example_prompt="Prepare the selected company's evidence-backed assessment and separately priced implementation, monitoring and software access options.",
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="documents.render_productised_assessment",
        title="Present an assessment or commercial proposal",
        category="documents",
        summary="Render a client report or one exact commercial offer from a sealed assessment.",
        description="Produce client Markdown from the scoped dossier. Direct SDK rendering also produces responsive, printable HTML. Content remains a draft until the canonical artifact workflow approves and publishes it.",
        additional_inputs_allowed=False,
        setup_requirements=("A sealed assessment for the selected company and project",),
        trigger_events=("service.productised_assessment_prepared",),
        emits=("documents.productised_assessment_rendered",),
        follow_up_primitives=("documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "documents.generate_business_artifact"),
        agent_builder_guidance="Omit offer_ref for the client report; select a single offer_ref for a proposal. Use direct Python render_productised_assessment_report or render_productised_assessment_proposal for full HTML or large documents, then prepare_productised_assessment_document for the canonical Markdown artifact candidate. Rendering never saves files, invoices, collects payment or activates access.",
        input_fields=(
            PrimitiveField("dossier", "object", "Exact sealed dossier returned by service.prepare_productised_assessment.", True),
            PrimitiveField("requested_by_ref", "string", "Requesting actor matching dossier and execution scope.", True),
            PrimitiveField("offer_ref", "string", "Exact proposed commercial offer; omit for assessment report."),
        ),
        example_prompt="Show the client assessment report, then prepare a separate proposal for the selected implementation offer.",
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_ledger_accounts",
        title="Discover governed ledger accounts",
        category="finance",
        summary=(
            "Read and normalize a complete bounded QuickBooks or Xero chart of "
            "accounts."
        ),
        description=(
            "Uses the reviewed provider-specific account-read route with exact "
            "project and connector-account custody, rejecting overlap, total drift, "
            "truncation, malformed rows, or missing Spring provenance."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_ledger_accounts",
        connector_tools=("quickbooks.list_accounts", "xero.list_accounts"),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_provider_connector_account_binding",
            "spring_governed_read_provenance",
        ),
        trigger_events=(
            "finance.journal_entry_requested",
            "finance.period_close_started",
        ),
        emits=("finance.ledger_accounts_discovered",),
        follow_up_primitives=(
            "finance.materialize_ledger_snapshot",
            "finance.prepare_journal_entry",
        ),
        agent_builder_guidance=(
            "Use the typed normalized account references as evidence for journal controls; "
            "never treat a partial provider page as a complete chart of accounts."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed ledger provider: quickbooks or xero.",
                False,
            ),
        ),
        example_prompt=(
            "Discover the complete governed chart of accounts from the bound "
            "QuickBooks or Xero ledger."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_trial_balance",
        title="Discover governed trial balance",
        category="finance",
        summary=(
            "Read and normalize one complete monthly QuickBooks or Xero Trial Balance."
        ),
        description=(
            "Calls the reviewed provider-specific Trial Balance route with an exact "
            "calendar-month scope and connector account, validates Spring provenance "
            "and provider structure, and rejects malformed, duplicate, incomplete, "
            "unbalanced, or over-bound results."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_trial_balance",
        connector_tools=(
            "quickbooks.trial_balance_report",
            "xero.trial_balance_report",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_provider_connector_account_binding",
            "spring_governed_read_provenance",
            "complete_calendar_month",
        ),
        trigger_events=("finance.period_close_started",),
        emits=("finance.trial_balance_discovered",),
        follow_up_primitives=("finance.materialize_ledger_snapshot",),
        agent_builder_guidance=(
            "Pair this result with finance.discover_ledger_accounts under the same "
            "provider binding before constructing a canonical ledger snapshot; never "
            "treat an unbalanced or provenance-free report as close evidence."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed ledger provider: quickbooks or xero.",
                False,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First calendar day of the monthly fiscal period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final calendar day of the same monthly fiscal period (YYYY-MM-DD).",
                True,
            ),
        ),
        example_prompt=(
            "Read the governed Trial Balance from the bound QuickBooks or Xero ledger "
            "for August 2026 and reject anything incomplete or unbalanced."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_close_source_transactions",
        title="Discover governed monthly close source transactions",
        category="finance",
        summary=(
            "Read and normalize every QuickBooks invoice, bill, and payment for one month."
        ),
        description=(
            "Pages the three reviewed QuickBooks source-read routes through explicit "
            "empty terminal pages, requires one exact project/account/route, and "
            "seals exact-decimal records with source revisions, update times, links, "
            "cursor checkpoints, and Spring provenance. Completion grants no "
            "reconciliation, posting, persistence, or close-transition authority."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_close_source_transactions",
        connector_tools=(
            "quickbooks.list_invoices",
            "quickbooks.list_bills",
            "quickbooks.list_payments",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "same_exact_quickbooks_connector_account_binding_for_all_tools",
            "spring_governed_read_provenance",
            "complete_calendar_month",
            "one_base_currency",
        ),
        trigger_events=("finance.period_close_started",),
        emits=("finance.close_source_transactions_discovered",),
        follow_up_primitives=("finance.prepare_close_evidence_bundle",),
        agent_builder_guidance=(
            "Treat the sealed result as bounded provider observation only. Retain "
            "all source revisions and terminal checkpoints; never infer period-close "
            "authority or payment-to-document reconciliation from these reads."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed close-source provider; currently quickbooks.",
                False,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First calendar day of the monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final calendar day of the same monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "currency",
                "string",
                "Exact three-letter uppercase base currency.",
                True,
            ),
        ),
        example_prompt=(
            "Read every governed QuickBooks invoice, bill, and payment for August "
            "2026 with source revisions, without reconciling or advancing close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_xero_close_source_transactions",
        title="Discover governed Xero monthly close source transactions",
        category="finance",
        summary=(
            "Read and normalize every Xero sales invoice, purchase bill, and payment "
            "for one month."
        ),
        description=(
            "Consumes Xero's bounded provider pagination through three reviewed "
            "exact-organisation reads, verifies canonical content revisions, and "
            "seals exact-decimal records, provider observation times, completeness "
            "counts, and Spring provenance. Completion grants no reconciliation, "
            "posting, persistence, or close-transition authority."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_xero_close_source_transactions",
        connector_tools=(
            "xero.list_invoices",
            "xero.list_bills",
            "xero.list_payments",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "same_exact_xero_organisation_binding_for_all_tools",
            "spring_governed_read_provenance",
            "complete_calendar_month",
            "one_base_currency",
        ),
        trigger_events=("finance.period_close_started",),
        emits=("finance.xero_close_source_transactions_discovered",),
        follow_up_primitives=("finance.prepare_close_evidence_bundle",),
        agent_builder_guidance=(
            "Treat Xero pageCount and itemCount as completeness claims that must stay "
            "stable across contiguous pages. Preserve every content revision and "
            "provider observation; never infer reconciliation or close authority."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed close-source provider; exactly xero.",
                False,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First calendar day of the monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final calendar day of the same monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "currency",
                "string",
                "Exact three-letter uppercase base currency.",
                True,
            ),
        ),
        example_prompt=(
            "Read every governed Xero sales invoice, purchase bill, and payment for "
            "August 2026 with source revisions, without reconciling or advancing close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_provider_period_status",
        title="Discover governed provider period status",
        category="finance",
        summary=("Read QuickBooks books-close or Xero period-lock configuration."),
        description=(
            "Normalizes provider-specific lock controls for one complete month, "
            "retains source revision and timestamp evidence, and classifies the "
            "month relative to the configured lock boundary. Completion grants "
            "no reconciliation, provider mutation, or close-transition authority."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_provider_period_status",
        connector_tools=(
            "quickbooks.get_period_status",
            "xero.get_period_status",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_provider_connector_account_binding",
            "spring_governed_read_provenance",
            "complete_calendar_month",
        ),
        trigger_events=("finance.period_close_started",),
        emits=("finance.provider_period_status_discovered",),
        follow_up_primitives=("finance.prepare_close_workspace",),
        agent_builder_guidance=(
            "Preserve each provider lock kind and source revision. Treat the "
            "result as provider configuration evidence, never as authorization "
            "to close, reopen, post, or mutate either accounting system."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Accounting provider: quickbooks or xero.",
                True,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First calendar day of the monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final calendar day of the same monthly period (YYYY-MM-DD).",
                True,
            ),
        ),
        example_prompt=(
            "Read Xero lock-date status for August 2026 without changing the "
            "provider or advancing the Lightbulb close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_stripe_settlement_movements",
        title="Discover governed Stripe settlement movements",
        category="finance",
        summary=(
            "Read and normalize every Stripe balance transaction for one UTC month."
        ),
        description=(
            "Consumes exact 100-record pages from the reviewed Stripe settlement "
            "route, validates one project/account/credential route through Spring "
            "provenance, rejects cursor loops, overlap, scope or currency drift, "
            "lossy minor units, and incomplete pagination, then emits a deterministic "
            "observation with no reconciliation or close authority."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_stripe_settlement_movements",
        connector_tools=("stripe.list_balance_transactions",),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_stripe_connector_account_binding",
            "spring_governed_read_provenance",
            "complete_utc_calendar_month",
            "one_base_currency",
        ),
        trigger_events=("finance.close_workspace_prepared",),
        emits=("finance.stripe_settlement_movements_discovered",),
        follow_up_primitives=("finance.prepare_close_workspace",),
        agent_builder_guidance=(
            "Treat the completed result as a source observation only. It does not "
            "reconcile Stripe to the ledger, persist evidence, certify the connector, "
            "or authorize a period-close transition."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed settlement provider; currently stripe.",
                False,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First UTC calendar day of the monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final UTC calendar day of the same monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "currency",
                "string",
                "Exact three-letter uppercase base currency.",
                True,
            ),
        ),
        example_prompt=(
            "Read every governed Stripe USD balance transaction for August 2026 "
            "without reconciling or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.discover_general_ledger_activity",
        title="Discover governed General Ledger activity",
        category="finance",
        summary=(
            "Read and normalize one complete month of QuickBooks or Xero General Ledger activity."
        ),
        description=(
            "Calls the reviewed provider route with exact project and connector-account "
            "custody. QuickBooks validates one complete monthly report; Xero reads "
            "bounded ordered journal pages through an empty terminal page before "
            "month filtering. Both emit exact-decimal restricted canonical rows with "
            "Spring provenance and no reconciliation, close-transition, or "
            "certification authority."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="discover_general_ledger_activity",
        connector_tools=("quickbooks.general_ledger_report", "xero.list_journals"),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_provider_connector_account_binding",
            "spring_governed_read_provenance",
            "complete_calendar_month",
            "one_base_currency",
        ),
        trigger_events=("finance.close_workspace_prepared",),
        emits=("finance.general_ledger_activity_discovered",),
        follow_up_primitives=("finance.prepare_close_workspace",),
        agent_builder_guidance=(
            "Treat the completed result as bounded provider activity only. Pair it "
            "with the exact-period Stripe observation before proposing deterministic "
            "matches, and never infer reconciliation or close authority from a read."
        ),
        input_fields=(
            PrimitiveField(
                "provider",
                "string",
                "Reviewed ledger provider: quickbooks or xero.",
                False,
            ),
            PrimitiveField(
                "start_date",
                "string",
                "First calendar day of the monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "end_date",
                "string",
                "Final calendar day of the same monthly period (YYYY-MM-DD).",
                True,
            ),
            PrimitiveField(
                "currency",
                "string",
                "Configured three-letter base currency; required for Xero and omitted for QuickBooks.",
                False,
            ),
        ),
        example_prompt=(
            "Read and normalize the governed QuickBooks or Xero General Ledger "
            "activity for August 2026 without reconciling or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.reconcile_stripe_settlements",
        title="Reconcile Stripe settlements to ledger activity",
        category="finance",
        summary=(
            "Derive exact Stripe payout matches and bounded ledger exceptions for one month."
        ),
        description=(
            "Consumes one sealed close workspace, one complete governed Stripe "
            "settlement observation, and one complete canonical General Ledger "
            "observation. Exact payout-reference, amount, and date matches are "
            "sealed deterministically; weaker amount/date candidates require human "
            "review. The primitive performs no connector operation, persistence, "
            "exception disposition, certification, journal post, or close transition."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="reconcile_stripe_settlements",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_tenant_company_project_scope",
            "sealed_monthly_close_workspace",
            "complete_governed_stripe_settlement_observation",
            "complete_canonical_general_ledger_observation",
            "exact_period_currency_and_project_alignment",
            "independent_review_for_proposals_and_exceptions",
            "spring_host_authority_for_persistence_or_close_transition",
        ),
        trigger_events=(
            "finance.stripe_settlement_movements_discovered",
            "finance.general_ledger_activity_discovered",
        ),
        emits=("finance.stripe_ledger_reconciliation_evaluated",),
        follow_up_primitives=("finance.evaluate_close_reconciliation_readiness",),
        agent_builder_guidance=(
            "Only exact payout-reference, amount, and date matches are automatic. "
            "Treat amount/date-only candidates as proposals, retain all exceptions "
            "for independent review, and never infer persistence or close authority "
            "from close_reconciliation_ready. QuickBooks is the current reference "
            "read adapter; the canonical ledger observation also admits governed "
            "Xero activity once that provider read is certified."
        ),
        input_fields=(
            PrimitiveField(
                "workspace",
                "object",
                "Structurally sealed one-entity monthly close workspace.",
                True,
            ),
            PrimitiveField(
                "stripe_observation",
                "object",
                "Complete governed Stripe settlement observation for the exact month.",
                True,
            ),
            PrimitiveField(
                "ledger_observation",
                "object",
                "Complete canonical ledger activity observation for the exact month.",
                True,
            ),
            PrimitiveField(
                "reconciled_at",
                "string",
                "UTC evaluation time after both source observations.",
                True,
            ),
            PrimitiveField(
                "minor_unit_exponent",
                "integer",
                "Currency minor-unit exponent used for exact Stripe conversion.",
                False,
            ),
            PrimitiveField(
                "settlement_date_tolerance_days",
                "integer",
                "Maximum date distance for an exact reference match or proposal.",
                False,
            ),
        ),
        example_prompt=(
            "Reconcile the sealed August 2026 Stripe payout observation to canonical "
            "ledger activity and return exact matches, proposals, and exceptions "
            "without advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.evaluate_close_reconciliation_readiness",
        title="Evaluate close reconciliation readiness",
        category="finance",
        summary=(
            "Verify retained close prerequisites before full balance reconciliation begins."
        ),
        description=(
            "Binds the exact sealed workspace, retained open-period and trial-balance "
            "lifecycle candidates, and Stripe settlement activity result. It projects "
            "whether account and subledger balance reconciliation may begin while "
            "explicitly refusing to treat payout activity as ending-balance evidence."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="evaluate_close_reconciliation_readiness",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_tenant_company_project_scope",
            "sealed_monthly_close_workspace",
            "retained_open_period_transition_candidate",
            "retained_trial_balance_transition_candidate",
            "exact_settlement_activity_reconciliation_result",
            "separate_reviewed_account_and_subledger_balance_evidence",
            "spring_host_authority_for_any_lifecycle_transition",
        ),
        trigger_events=("finance.stripe_ledger_reconciliation_evaluated",),
        emits=("finance.close_reconciliation_readiness_evaluated",),
        follow_up_primitives=("finance.prepare_reconciliation_package",),
        agent_builder_guidance=(
            "Use a ready result only to begin preparation of the separately reviewed "
            "ReconciliationPackage. Stripe payout matches are supporting activity "
            "evidence; they are not the Stripe or control-account ending balance and "
            "do not authorize a lifecycle transition."
        ),
        input_fields=(
            PrimitiveField(
                "workspace",
                "object",
                "Structurally sealed one-entity monthly close workspace.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained close snapshot through capture_trial_balance, when available.",
                False,
            ),
            PrimitiveField(
                "settlement_reconciliation",
                "object",
                "Exact Stripe-to-ledger settlement activity result.",
                True,
            ),
            PrimitiveField(
                "evaluated_at",
                "string",
                "UTC evaluation time after all retained prerequisites.",
                True,
            ),
        ),
        example_prompt=(
            "Check whether the retained August close candidates and exact Stripe "
            "settlement result allow reviewed account reconciliation to begin, "
            "without preparing or advancing a lifecycle package."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_reconciliation_package",
        title="Prepare reviewed reconciliation package candidate",
        category="finance",
        summary=(
            "Validate ending-balance records for the period-close reconciliation stage."
        ),
        description=(
            "Consumes an exact ready close projection and validates every Trial Balance "
            "account plus every scoped subledger/control-account pair. It seals a "
            "ReconciliationPackage candidate while leaving reviewer authentication, "
            "evidence custody, persistence, and lifecycle admission to Spring."
        ),
        risk_level="medium",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_reconciliation_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_close_reconciliation_readiness",
            "every_trial_balance_account_reconciled",
            "every_scoped_subledger_reconciled",
            "exact_control_account_balances",
            "globally_separate_preparers_and_reviewers",
            "bounded_aggregate_unexplained_variance",
            "spring_reviewer_rbac_revalidation",
            "spring_evidence_custody_and_retention",
        ),
        trigger_events=("finance.close_reconciliation_readiness_evaluated",),
        emits=("finance.reconciliation_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_reconciliation_transition_command",),
        agent_builder_guidance=(
            "Treat reviewer references as unauthenticated claims until Spring validates "
            "current RBAC and retains the account/subledger artifact plus independent "
            "review attestation. A candidate never advances the close by itself."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "readiness", "object", "Ready reconciliation projection.", True
            ),
            PrimitiveField(
                "reconciliation_set_ref",
                "string",
                "Stable reconciliation-set reference.",
                True,
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact artifact and review evidence-use references.",
                True,
            ),
            PrimitiveField(
                "account_reconciliations",
                "array",
                "Reviewed record for every Trial Balance account.",
                True,
            ),
            PrimitiveField(
                "subledger_reconciliations",
                "array",
                "Reviewed record for every scoped subledger.",
                True,
            ),
            PrimitiveField(
                "review_completed_at", "string", "UTC review completion time.", True
            ),
        ),
        example_prompt=(
            "Prepare the August account and Stripe subledger reconciliation package "
            "candidate without authenticating reviewers or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_reconciliation_transition_command",
        title="Prepare evidence-bound reconciliation transition command",
        category="finance",
        summary=(
            "Seal reviewed reconciliation evidence to the exact retained close state."
        ),
        description=(
            "Consumes the exact reconciliation package candidate and retained "
            "version-two close snapshot, derives every lifecycle and evidence-lineage "
            "fence, and emits a sealed reconcile_accounts command candidate. Spring "
            "still owns reviewer authentication, evidence custody, persistence, and "
            "lifecycle admission."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_reconciliation_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_sealed_close_workspace",
            "exact_reconciliation_package_candidate",
            "retained_version_two_close_snapshot",
            "account_subledger_reconciliation_artifact",
            "spring_reconciliation_review_attestation",
            "requester_reviewer_separation",
            "spring_evidence_authentication_and_retention",
        ),
        trigger_events=("finance.reconciliation_package_candidate_prepared",),
        emits=("finance.reconciliation_transition_command_prepared",),
        follow_up_primitives=("finance.propose_period_close_transition",),
        agent_builder_guidance=(
            "Use only Spring-custodied artifact and review claims. The primitive "
            "derives version, state, lineage, and command digests but cannot "
            "authenticate evidence or advance the close; pass its lifecycle_input "
            "to finance.propose_period_close_transition only after Spring revalidation."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact reviewed reconciliation package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained close snapshot through capture_trial_balance.",
                True,
            ),
            PrimitiveField(
                "transition_ref", "string", "Stable transition reference.", True
            ),
            PrimitiveField(
                "idempotency_key", "string", "Exact request identity.", True
            ),
            PrimitiveField(
                "occurred_at", "string", "UTC command preparation time.", True
            ),
            PrimitiveField(
                "requested_by_ref", "string", "Separated requester reference.", True
            ),
            PrimitiveField(
                "artifact_evidence",
                "object",
                "Attested exact reconciliation artifact claim.",
                True,
            ),
            PrimitiveField(
                "review_evidence",
                "object",
                "Verified Spring review-attestation claim.",
                True,
            ),
        ),
        example_prompt=(
            "Seal the reviewed August account reconciliation package to the exact "
            "retained close snapshot without authenticating evidence or advancing "
            "the lifecycle."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.materialize_ledger_snapshot",
        title="Materialize canonical ledger snapshot",
        category="finance",
        summary=(
            "Seal provider-neutral ledger facts against two evidence-bound observations."
        ),
        description=(
            "Deterministically validates and seals a canonical chart of accounts and "
            "balanced Trial Balance against complete chart_of_accounts and "
            "trial_balance observation envelopes. The primitive performs no connector "
            "operation, persistence, posting, certification, or authority grant."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="materialize_ledger_snapshot",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_finance_ledger_scope",
            "complete_attested_or_verified_chart_of_accounts_observation",
            "complete_attested_or_verified_trial_balance_observation",
            "one_exact_provider_binding",
            "fresh_unexpired_source_evidence",
            "balanced_canonical_trial_balance",
            "spring_host_authority_for_any_persistence",
        ),
        trigger_events=(
            "finance.ledger_accounts_discovered",
            "finance.trial_balance_discovered",
        ),
        emits=("finance.ledger_snapshot_materialized",),
        follow_up_primitives=("finance.prepare_close_workspace",),
        agent_builder_guidance=(
            "Invoke only after a hosted authority has constructed and verified both "
            "source observation envelopes. Treat the result as a structurally sealed "
            "candidate; it does not certify a provider read or authorize persistence, "
            "posting, or period close."
        ),
        input_fields=(
            PrimitiveField(
                "snapshot_ref",
                "string",
                "Stable source-bound canonical ledger snapshot reference.",
                True,
            ),
            PrimitiveField(
                "snapshot_revision",
                "integer",
                "Positive immutable ledger snapshot revision.",
                True,
            ),
            PrimitiveField(
                "scope",
                "object",
                "Exact tenant, company, project, entity, ledger, and period scope.",
                True,
            ),
            PrimitiveField(
                "materialized_at",
                "string",
                "UTC timestamp for deterministic snapshot materialization.",
                True,
            ),
            PrimitiveField(
                "account_discovery",
                "object",
                "Completed governed chart-of-accounts discovery result.",
                True,
            ),
            PrimitiveField(
                "trial_balance_discovery",
                "object",
                "Completed governed Trial Balance discovery result.",
                True,
            ),
            PrimitiveField(
                "source_observations",
                "array",
                (
                    "Exactly two retained source-observation envelopes for the chart "
                    "of accounts and Trial Balance."
                ),
                True,
            ),
        ),
        example_prompt=(
            "Materialize a canonical August 2026 ledger snapshot from the attested "
            "chart-of-accounts and Trial Balance observations."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_adjusting_entries_package",
        title="Prepare controlled adjusting-entries package candidate",
        category="finance",
        summary=(
            "Bind controlled journal posts and readbacks into the close adjustment stage."
        ),
        description=(
            "Consumes the exact reconciled close snapshot and either an explicit "
            "no-adjustment conclusion or canonical journal control evaluations, "
            "completed governed post receipts, and independent matching readbacks. "
            "Non-empty journals require provider-stable semantic effect commitments "
            "plus matching project, tenant-connector, and connector-account lineage; "
            "raw WRITE and READ payload digests and route custody stay separate. "
            "It prepares an AdjustingEntriesPackage candidate while leaving Spring "
            "settlement, actor authority, evidence custody, and lifecycle admission "
            "outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_adjusting_entries_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_reconciliations_validated_snapshot",
            "canonical_journal_control_evaluation",
            "independent_batch_approval",
            "completed_governed_journal_post_receipt",
            "matching_independent_provider_readback",
            "canonical_provider_effect_fingerprint",
            "governed_read_execution_journal_and_source_custody",
            "matching_write_read_project_connector_account_lineage",
            "spring_execution_journal_settlement",
            "spring_actor_and_evidence_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.adjusting_entries_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_adjusting_entries_transition_command",),
        agent_builder_guidance=(
            "Never convert a proposal, preview, pending approval, ambiguous post, or "
            "unmatched readback into a reported adjustment. A structural candidate "
            "still requires Spring to settle the exact execution journal and retain "
            "the adjustment batch plus posting attestation before transition admission."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained close snapshot through reconcile_accounts.",
                True,
            ),
            PrimitiveField(
                "adjustment_batch_ref",
                "string",
                "Stable adjustment batch reference.",
                True,
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact batch and posting-attestation evidence-use references.",
                True,
            ),
            PrimitiveField(
                "no_adjustments_required",
                "boolean",
                "Explicit conclusion that the controlled journal batch is empty.",
                True,
            ),
            PrimitiveField(
                "journals",
                "array",
                "Controlled journal preparation, post, and readback evidence bundles.",
                False,
            ),
            PrimitiveField(
                "reported_posted_at",
                "string",
                "UTC batch conclusion or completed-readback time.",
                True,
            ),
            PrimitiveField(
                "prepared_by_ref", "string", "Batch preparer reference.", True
            ),
            PrimitiveField(
                "posted_by_ref", "string", "Governed posting actor reference.", True
            ),
            PrimitiveField(
                "reviewed_by_ref", "string", "Independent reviewer reference.", True
            ),
        ),
        example_prompt=(
            "Prepare the August adjusting-entry close package from controlled, "
            "posted, independently read-back journals without advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_adjusting_entries_transition_command",
        title="Prepare evidence-bound adjusting-entries transition command",
        category="finance",
        summary=(
            "Seal an exact controlled adjustment package to close-state evidence fences."
        ),
        description=(
            "Consumes the exact adjusting-entries package candidate, retained "
            "reconciliations-validated snapshot, and separate adjustment-batch and "
            "Spring posting-attestation claims. It derives every lifecycle fence and "
            "command seal while leaving journal settlement, evidence authentication, "
            "persistence, and transition authority outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_adjusting_entries_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_adjusting_entries_package_candidate",
            "exact_reconciliations_validated_snapshot",
            "spring_settled_governed_journal_posts_when_required",
            "retained_adjusting_entry_batch_evidence",
            "spring_adjustment_posting_attestation",
            "requester_separate_from_posting_and_review_actors",
            "spring_actor_evidence_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.adjusting_entries_package_candidate_prepared",),
        emits=("finance.adjusting_entries_transition_command_prepared",),
        follow_up_primitives=("finance.propose_period_close_transition",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed command candidate. Spring "
            "must settle every governed journal execution, authenticate both evidence "
            "claims, and admit the transition against the unchanged retained snapshot."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact controlled adjusting-entries package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-three close snapshot through reconciliations.",
                True,
            ),
            PrimitiveField(
                "transition_ref", "string", "Stable transition reference.", True
            ),
            PrimitiveField(
                "idempotency_key", "string", "Stable transition idempotency key.", True
            ),
            PrimitiveField(
                "occurred_at", "string", "Proposed UTC transition time.", True
            ),
            PrimitiveField(
                "requested_by_ref", "string", "Transition requester reference.", True
            ),
            PrimitiveField(
                "artifact_evidence",
                "object",
                "Adjustment-batch evidence claim bound to the candidate digest.",
                True,
            ),
            PrimitiveField(
                "review_evidence",
                "object",
                "Exact Spring adjustment-posting attestation claim.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the sealed August record_adjusting_entries transition command "
            "without advancing the close or claiming Spring evidence authority."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_subledger_lock_package",
        title="Prepare controlled subledger-lock package candidate",
        category="finance",
        summary=("Bind every scoped subledger to a causal reported-lock observation."),
        description=(
            "Consumes the exact adjustments-validated close snapshot and one distinct "
            "reported lock observation for every scoped subledger/control-account pair. "
            "It derives the retained reconciliation and adjustment transition digests "
            "and prepares a SubledgerLockPackage candidate while leaving current lock "
            "authentication, actor authority, evidence custody, and lifecycle admission "
            "outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_subledger_lock_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_adjustments_validated_snapshot",
            "one_lock_observation_per_scoped_subledger_and_control_account",
            "causal_distinct_lock_receipts",
            "authorized_lock_evidence_issuers",
            "distinct_lock_owner_and_reviewer",
            "spring_current_lock_actor_and_evidence_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.subledger_lock_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_subledger_lock_transition_command",),
        agent_builder_guidance=(
            "Never treat a source lock flag or caller claim as authoritative. Require "
            "one exact causal receipt for every scoped subledger, then let Spring "
            "revalidate current lock state, actors, and retained evidence before any "
            "transition admission."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-four close snapshot through adjustments.",
                True,
            ),
            PrimitiveField(
                "lock_set_ref", "string", "Stable subledger lock-set reference.", True
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact lock-record and lock-attestation evidence-use references.",
                True,
            ),
            PrimitiveField(
                "lock_observations",
                "array",
                "One exact reported-lock observation per scoped subledger.",
                True,
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC package preparation time.", True
            ),
            PrimitiveField(
                "lock_owner_ref", "string", "Subledger locking actor reference.", True
            ),
            PrimitiveField(
                "lock_reviewer_ref",
                "string",
                "Independent lock reviewer reference.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the August subledger-lock package from exact retained lock "
            "receipts without authenticating the locks or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_subledger_lock_transition_command",
        title="Prepare evidence-bound subledger-lock transition command",
        category="finance",
        summary=(
            "Seal an exact subledger-lock package to close-state evidence fences."
        ),
        description=(
            "Consumes the exact subledger-lock package candidate, retained "
            "adjustments-validated snapshot, and separate lock-record and Spring "
            "lock-attestation claims. It derives every lifecycle fence and command "
            "seal while leaving current lock authentication, evidence custody, "
            "persistence, and transition authority outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_subledger_lock_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_subledger_lock_package_candidate",
            "exact_adjustments_validated_snapshot",
            "retained_subledger_lock_record",
            "spring_subledger_lock_attestation",
            "requester_separate_from_lock_reviewer",
            "spring_current_lock_actor_evidence_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.subledger_lock_package_candidate_prepared",),
        emits=("finance.subledger_lock_transition_command_prepared",),
        follow_up_primitives=("finance.prepare_consolidation_package",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed command candidate. Spring "
            "must revalidate that every scoped subledger remains locked, authenticate "
            "both evidence claims, and admit the transition against the unchanged "
            "retained snapshot."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact controlled subledger-lock package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-four close snapshot through adjustments.",
                True,
            ),
            PrimitiveField(
                "transition_ref", "string", "Stable transition reference.", True
            ),
            PrimitiveField(
                "idempotency_key", "string", "Stable transition idempotency key.", True
            ),
            PrimitiveField(
                "occurred_at", "string", "Proposed UTC transition time.", True
            ),
            PrimitiveField(
                "requested_by_ref", "string", "Transition requester reference.", True
            ),
            PrimitiveField(
                "artifact_evidence",
                "object",
                "Subledger-lock artifact claim bound to the candidate digest.",
                True,
            ),
            PrimitiveField(
                "review_evidence",
                "object",
                "Exact Spring subledger-lock attestation claim.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the sealed August lock_subledgers transition command without "
            "advancing the close or claiming Spring lock authority."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_consolidation_package",
        title="Prepare controlled consolidation package candidate",
        category="finance",
        summary=("Bind exact no-activity or elimination workpapers to retained locks."),
        description=(
            "Consumes the exact subledger-locks-validated close snapshot and canonical "
            "consolidation workpaper facts. It derives entity, currency, adjustment, "
            "and lock fences before preparing a ConsolidationPackage candidate while "
            "leaving elimination settlement, actor authority, evidence custody, and "
            "lifecycle admission outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_consolidation_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_subledger_locks_validated_snapshot",
            "exact_entity_and_functional_currency_scope",
            "canonical_balanced_elimination_entries_or_explicit_no_activity",
            "residual_within_scoped_materiality",
            "distinct_consolidation_preparer_and_reviewer",
            "spring_elimination_actor_and_evidence_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.consolidation_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_consolidation_transition_command",),
        agent_builder_guidance=(
            "For the initial one-entity lighthouse, require an explicit zero-activity "
            "workpaper. Never treat SDK arithmetic as proof that an elimination journal "
            "posted; Spring must authenticate actors, settlement, and retained evidence."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-five snapshot through subledger locking.",
                True,
            ),
            PrimitiveField(
                "consolidation_workpaper_ref",
                "string",
                "Stable consolidation workpaper reference.",
                True,
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact workpaper and elimination-attestation evidence references.",
                True,
            ),
            PrimitiveField(
                "no_intercompany_activity",
                "boolean",
                "Explicit no-activity conclusion.",
                True,
            ),
            PrimitiveField(
                "elimination_entries",
                "array",
                "Canonical balanced elimination entries, empty only for no activity.",
                True,
            ),
            PrimitiveField(
                "intercompany_input_balance",
                "decimal",
                "Gross intercompany balance entering consolidation.",
                True,
            ),
            PrimitiveField(
                "eliminated_amount",
                "decimal",
                "Amount represented by exact elimination entries.",
                True,
            ),
            PrimitiveField(
                "residual_balance",
                "decimal",
                "Uneliminated residual balance.",
                True,
            ),
            PrimitiveField(
                "residual_materiality_threshold",
                "decimal",
                "Residual threshold bounded by close scope.",
                True,
            ),
            PrimitiveField(
                "consolidated_at", "string", "UTC workpaper conclusion time.", True
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC package preparation time.", True
            ),
            PrimitiveField(
                "consolidator_ref", "string", "Consolidation preparer reference.", True
            ),
            PrimitiveField(
                "reviewed_by_ref", "string", "Independent reviewer reference.", True
            ),
        ),
        example_prompt=(
            "Prepare the August single-entity zero-intercompany consolidation package "
            "without posting journals or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_consolidation_transition_command",
        title="Prepare evidence-bound consolidation transition command",
        category="finance",
        summary=("Seal an exact consolidation package to close-state evidence fences."),
        description=(
            "Consumes the exact consolidation package candidate, retained "
            "subledger-locks-validated snapshot, and separate workpaper and Spring "
            "elimination-attestation claims. It derives every lifecycle fence and "
            "command seal while leaving settlement, evidence custody, persistence, "
            "and transition authority outside the SDK."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_consolidation_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_consolidation_package_candidate",
            "exact_subledger_locks_validated_snapshot",
            "retained_consolidation_workpaper",
            "spring_intercompany_elimination_attestation",
            "requester_separate_from_consolidation_reviewer",
            "spring_elimination_actor_evidence_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.consolidation_package_candidate_prepared",),
        emits=("finance.consolidation_transition_command_prepared",),
        follow_up_primitives=("finance.prepare_close_approval_package",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed command candidate. Spring "
            "must authenticate the exact workpaper and attestation, settle any "
            "elimination effects, and admit the transition against the unchanged state."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact controlled consolidation package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-five snapshot through subledger locking.",
                True,
            ),
            PrimitiveField(
                "transition_ref", "string", "Stable transition reference.", True
            ),
            PrimitiveField(
                "idempotency_key", "string", "Stable transition idempotency key.", True
            ),
            PrimitiveField(
                "occurred_at", "string", "Proposed UTC transition time.", True
            ),
            PrimitiveField(
                "requested_by_ref", "string", "Transition requester reference.", True
            ),
            PrimitiveField(
                "artifact_evidence",
                "object",
                "Consolidation workpaper claim bound to the candidate digest.",
                True,
            ),
            PrimitiveField(
                "review_evidence",
                "object",
                "Exact Spring elimination-attestation claim.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the sealed August consolidate transition command without posting "
            "eliminations, advancing the close, or claiming Spring authority."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_approval_package",
        title="Prepare independent close-approval package candidate",
        category="finance",
        summary=(
            "Bind exact close-review content to a current independent approval claim."
        ),
        description=(
            "Consumes the exact consolidation-validated snapshot, a close-review "
            "workpaper commitment, and a Spring-reported approval observation. It "
            "derives every prerequisite transition and approval-request digest while "
            "leaving reviewer qualification, current RBAC, authentication, single-use "
            "consumption, evidence custody, and lifecycle admission to Spring."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_approval_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_consolidation_validated_snapshot",
            "content_addressed_close_review_workpaper",
            "spring_reported_independent_close_approval",
            "current_reviewer_qualification_and_rbac",
            "unexpired_single_use_approval",
            "approver_separate_from_every_retained_lifecycle_actor",
            "spring_evidence_custody_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.close_approval_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_close_approval_transition_command",),
        agent_builder_guidance=(
            "Treat the observation as an unauthenticated claim until Spring revalidates "
            "the exact policy, qualification, actor, request digest, expiry, and unused "
            "state. Never infer approval from prose or let a retained lifecycle actor "
            "serve as the independent approver."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-six snapshot through consolidation.",
                True,
            ),
            PrimitiveField(
                "review_workpaper_ref",
                "string",
                "Stable close-review workpaper reference.",
                True,
            ),
            PrimitiveField(
                "review_workpaper_digest",
                "string",
                "SHA-256 commitment to exact review content.",
                True,
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact review and Spring approval evidence references.",
                True,
            ),
            PrimitiveField(
                "review_prepared_by_ref",
                "string",
                "Close review preparer reference.",
                True,
            ),
            PrimitiveField(
                "approval_observation",
                "object",
                "Spring-reported, expiring, independently reviewed approval claim.",
                True,
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC package preparation time.", True
            ),
        ),
        example_prompt=(
            "Prepare the August independent close-approval package from the exact "
            "review workpaper and Spring approval observation without consuming the "
            "approval or advancing the close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_approval_transition_command",
        title="Prepare evidence-bound close-approval transition command",
        category="finance",
        summary=(
            "Seal exact review and independent-approval evidence into an approve-close command."
        ),
        description=(
            "Consumes the exact version-six consolidation snapshot, close-approval "
            "package candidate, retained review workpaper, and Spring approval "
            "attestation. It derives lifecycle and evidence-lineage fences while "
            "leaving reviewer RBAC, approval authentication and single-use consumption, "
            "evidence custody, persistence, and lifecycle admission to Spring."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_approval_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_consolidation_validated_snapshot",
            "exact_close_approval_package_candidate",
            "retained_close_review_workpaper",
            "spring_close_approval_attestation",
            "current_reviewer_qualification_and_rbac",
            "unexpired_unused_approval",
            "requester_separate_from_independent_approver",
            "spring_approval_consumption_evidence_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.close_approval_package_candidate_prepared",),
        emits=("finance.close_approval_transition_command_prepared",),
        follow_up_primitives=("finance.propose_period_close_transition",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed command candidate. Spring "
            "must revalidate the exact reviewer qualification and approval state, "
            "consume the approval once, retain both evidence artifacts, and admit the "
            "transition against the unchanged version-six snapshot."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact close-approval package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-six consolidation snapshot.",
                True,
            ),
            PrimitiveField(
                "transition_ref",
                "string",
                "Stable approve-close transition reference.",
                True,
            ),
            PrimitiveField(
                "idempotency_key",
                "string",
                "Exact transition idempotency identity.",
                True,
            ),
            PrimitiveField(
                "occurred_at", "string", "UTC transition preparation time.", True
            ),
            PrimitiveField(
                "requested_by_ref", "string", "Transition requester reference.", True
            ),
            PrimitiveField(
                "workpaper_evidence",
                "object",
                "Portable claim for the exact retained close-review workpaper.",
                True,
            ),
            PrimitiveField(
                "approval_evidence",
                "object",
                "Portable claim for the exact Spring approval observation.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the sealed August approve-close transition command without "
            "consuming approval, advancing the close, or claiming Spring authority."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_period_package",
        title="Prepare readiness-bound final close package candidate",
        category="finance",
        summary=(
            "Bind deterministic close controls and Spring readiness to an approved close."
        ),
        description=(
            "Recomputes close controls from typed source facts and binds the exact ready "
            "evaluation, version-seven approval transition, close request, hosted-close "
            "operator, and Spring readiness observation. Spring retains attestation "
            "authentication, current operator RBAC, evidence custody, hosted execution, "
            "persistence, and final lifecycle admission."
        ),
        risk_level="critical",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_period_package",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_independent_approval_evidence_validated_snapshot",
            "complete_typed_close_readiness_inputs",
            "deterministic_ready_close_control_evaluation",
            "exact_close_request_and_operator",
            "spring_close_readiness_attestation",
            "unexpired_readiness_window",
            "spring_operator_rbac_evidence_execution_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.close_period_package_candidate_prepared",),
        follow_up_primitives=("finance.prepare_close_period_transition_command",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed final-close package. Spring "
            "must authenticate the exact readiness observation, revalidate the current "
            "operator and state, retain evidence, execute the hosted close, persist the "
            "result, and admit the final transition."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-seven approved close snapshot.",
                True,
            ),
            PrimitiveField(
                "readiness_input",
                "object",
                "Typed facts for deterministic final close controls.",
                True,
            ),
            PrimitiveField(
                "readiness_observation",
                "object",
                "Spring-reported observation of the exact ready result.",
                True,
            ),
            PrimitiveField(
                "close_candidate_ref",
                "string",
                "Stable final-close candidate reference.",
                True,
            ),
            PrimitiveField(
                "close_request_ref",
                "string",
                "Stable hosted close request reference.",
                True,
            ),
            PrimitiveField(
                "close_requested_at", "string", "UTC close request time.", True
            ),
            PrimitiveField(
                "close_operator_ref",
                "string",
                "Proposed hosted-close operator reference.",
                True,
            ),
            PrimitiveField(
                "evidence_use_refs",
                "array",
                "Exact close-request and readiness evidence use references.",
                True,
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC package preparation time.", True
            ),
        ),
        example_prompt=(
            "Prepare the August final-close package from the exact approved snapshot "
            "and ready controls without executing or persisting the period close."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_period_transition_command",
        title="Prepare evidence-bound final close transition command",
        category="finance",
        summary=(
            "Seal the exact close request and Spring readiness into a final close command."
        ),
        description=(
            "Consumes the exact readiness-bound close package, version-seven approved "
            "snapshot, close-request artifact, and typed Spring readiness observation. "
            "It derives lifecycle and evidence-lineage fences while Spring retains "
            "attestation authentication, current operator RBAC, evidence custody, hosted "
            "execution, persistence, and final lifecycle admission."
        ),
        risk_level="critical",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_period_transition_command",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_independent_approval_evidence_validated_snapshot",
            "exact_readiness_bound_close_package_candidate",
            "retained_close_request_artifact",
            "typed_spring_close_readiness_attestation",
            "unexpired_readiness_window",
            "exact_hosted_close_operator",
            "spring_operator_rbac_evidence_execution_persistence_and_lifecycle_revalidation",
        ),
        trigger_events=("finance.close_period_package_candidate_prepared",),
        emits=("finance.close_period_transition_command_prepared",),
        follow_up_primitives=("finance.propose_period_close_transition",),
        agent_builder_guidance=(
            "Treat the result only as a structurally sealed final-close command. Spring "
            "must authenticate readiness, revalidate the exact operator and state, "
            "retain both artifacts, execute and persist the hosted close, and admit the "
            "unchanged version-seven transition."
        ),
        input_fields=(
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "package_candidate",
                "object",
                "Exact readiness-bound final-close package candidate.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Retained version-seven approved close snapshot.",
                True,
            ),
            PrimitiveField(
                "transition_ref",
                "string",
                "Stable final-close transition reference.",
                True,
            ),
            PrimitiveField(
                "idempotency_key",
                "string",
                "Exact transition idempotency identity.",
                True,
            ),
            PrimitiveField(
                "occurred_at", "string", "UTC transition preparation time.", True
            ),
            PrimitiveField(
                "requested_by_ref",
                "string",
                "Exact proposed hosted-close operator.",
                True,
            ),
            PrimitiveField(
                "close_request_evidence",
                "object",
                "Portable claim for the exact retained close request.",
                True,
            ),
            PrimitiveField(
                "readiness_evidence",
                "object",
                "Portable typed claim for the exact Spring readiness observation.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the sealed August final-close command without authenticating "
            "readiness, executing the hosted close, persisting state, or advancing the "
            "lifecycle."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.build_close_audit_packet",
        title="Build complete close audit packet candidate",
        category="finance",
        summary=(
            "Bind all close transitions, hosted execution/readback, and nine outcomes."
        ),
        description=(
            "Re-materializes the exact version-eight close candidate from the final "
            "command, binds a typed Spring execution and independent-readback "
            "observation, and requires the nine canonical finance lighthouse outcome "
            "measurements. Structural metrics are recomputed from retained history; "
            "Spring retains evidence authentication, custody, persistence, and any "
            "production certification authority."
        ),
        risk_level="high",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="build_close_audit_packet",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "exact_version_eight_close_candidate",
            "exact_final_close_transition_command",
            "spring_hosted_execution_and_persistence_observation",
            "independent_period_state_readback",
            "all_nine_canonical_business_outcome_measurements",
            "scoped_attested_or_verified_outcome_evidence",
            "spring_execution_outcome_custody_and_certification_revalidation",
        ),
        trigger_events=("finance.period_close_candidate_evaluated",),
        emits=("finance.close_audit_packet_candidate_built",),
        follow_up_primitives=(),
        agent_builder_guidance=(
            "Treat the packet as a content-bound audit candidate, not proof of hosted "
            "execution or production readiness. Spring must authenticate the execution, "
            "readback, outcome measurements, evidence custody, and certification state."
        ),
        input_fields=(
            PrimitiveField(
                "packet_ref", "string", "Stable finance close audit packet ref.", True
            ),
            PrimitiveField(
                "workspace", "object", "Exact sealed close workspace.", True
            ),
            PrimitiveField(
                "final_transition",
                "object",
                "Exact sealed final-close transition result.",
                True,
            ),
            PrimitiveField(
                "lifecycle_snapshot",
                "object",
                "Exact materialized version-eight close candidate.",
                True,
            ),
            PrimitiveField(
                "execution_observation",
                "object",
                "Spring-reported hosted execution, persistence, and readback observation.",
                True,
            ),
            PrimitiveField(
                "business_outcomes",
                "array",
                "All nine canonical evidence-bound close outcome measurements.",
                True,
            ),
            PrimitiveField(
                "prepared_by_ref", "string", "Audit packet preparer reference.", True
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC audit packet preparation time.", True
            ),
        ),
        example_prompt=(
            "Build the August close audit packet with all eight transitions and nine "
            "measured outcomes without persisting or certifying production execution."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_evidence_bundle",
        title="Prepare monthly close evidence bundle",
        category="finance",
        summary=(
            "Seal aligned accounting, Stripe, and provider-lock evidence for close."
        ),
        description=(
            "Requires one exact project, accounting provider/account, complete month, "
            "currency, and observation timeline across a canonical ledger snapshot, "
            "governed source transactions, Stripe settlements, and provider period "
            "status. Provider lock conflicts make the bundle workspace-ineligible. "
            "It performs no connector call, reconciliation, persistence, or close."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_evidence_bundle",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "sealed_canonical_ledger_snapshot",
            "governed_complete_month_source_transactions",
            "governed_complete_month_stripe_settlements",
            "governed_provider_period_status",
            "exact_project_provider_account_month_and_currency_alignment",
            "spring_host_authority_for_any_persistence_or_transition",
        ),
        trigger_events=(
            "finance.close_source_transactions_discovered",
            "finance.xero_close_source_transactions_discovered",
            "finance.stripe_settlement_movements_discovered",
            "finance.provider_period_status_discovered",
        ),
        emits=("finance.close_evidence_bundle_prepared",),
        follow_up_primitives=("finance.prepare_close_workspace",),
        agent_builder_guidance=(
            "Use after all four governed source artifacts exist. Accounting evidence "
            "may be entirely QuickBooks or entirely Xero, but provider and exact-account "
            "evidence must never be mixed within one bundle."
        ),
        input_fields=(
            PrimitiveField(
                "bundle_ref", "string", "Stable close-evidence bundle reference.", True
            ),
            PrimitiveField(
                "bundle_revision", "integer", "Positive immutable revision.", True
            ),
            PrimitiveField(
                "prepared_at", "string", "UTC evidence-bundle preparation time.", True
            ),
            PrimitiveField(
                "ledger_materialization",
                "object",
                (
                    "Source-bound ledger materialization result containing the sealed "
                    "canonical snapshot and governed read custody."
                ),
                True,
            ),
            PrimitiveField(
                "close_source_transactions",
                "object",
                "Governed complete-month invoice, bill, and payment observation.",
                True,
            ),
            PrimitiveField(
                "stripe_settlement_observation",
                "object",
                "Governed complete-month Stripe settlement observation.",
                True,
            ),
            PrimitiveField(
                "provider_period_status",
                "object",
                "Governed accounting-provider period-lock observation.",
                True,
            ),
        ),
        example_prompt=(
            "Bind the August ledger, source transactions, Stripe settlements, and "
            "provider period locks into one source-complete close evidence bundle."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_close_workspace",
        title="Prepare monthly close workspace",
        category="finance",
        summary=("Build the one-entity close checklist from source-complete evidence."),
        description=(
            "Validates exact snapshot, close scope, evidence-bundle lineage, provider "
            "lock eligibility, and Stripe control-account binding; then derives "
            "reviewed open-period and Trial Balance packages plus a fail-closed "
            "checklist. It performs no effect."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_close_workspace",
        connector_tools=(),
        additional_inputs_allowed=False,
        setup_requirements=(
            "sealed_canonical_ledger_snapshot",
            "source_complete_close_evidence_bundle",
            "provider_period_lock_eligible",
            "exact_one_entity_monthly_close_scope",
            "fresh_unexpired_source_evidence",
            "exact_stripe_settlement_control_account_binding",
            "distinct_period_open_preparer_and_reviewer",
            "distinct_trial_balance_preparer_and_reviewer",
            "spring_host_authority_for_any_transition_or_persistence",
        ),
        trigger_events=("finance.close_evidence_bundle_prepared",),
        emits=("finance.close_workspace_prepared",),
        follow_up_primitives=("finance.propose_period_close_transition",),
        agent_builder_guidance=(
            "Use this only for the first one-entity, one-base-currency monthly-close "
            "lighthouse after the source evidence bundle is eligible. The result "
            "prepares lifecycle packages but does not run open_period, reconcile "
            "Stripe, or authorize a close effect."
        ),
        input_fields=(
            PrimitiveField(
                "workspace_ref",
                "string",
                "Stable initial close-workspace reference.",
                True,
            ),
            PrimitiveField(
                "workspace_revision",
                "integer",
                "Positive immutable workspace revision.",
                True,
            ),
            PrimitiveField(
                "prepared_at",
                "string",
                "UTC time at which the fresh snapshot is used to prepare the workspace.",
                True,
            ),
            PrimitiveField(
                "ledger_materialization",
                "object",
                (
                    "Source-bound ledger materialization result containing the sealed "
                    "canonical snapshot and governed read custody."
                ),
                True,
            ),
            PrimitiveField(
                "close_evidence_bundle",
                "object",
                "Source-complete, provider-lock-eligible close evidence bundle.",
                True,
            ),
            PrimitiveField(
                "close_scope",
                "object",
                "Exact Spring-authority period-close scope.",
                True,
            ),
            PrimitiveField(
                "stripe_subledger_ref",
                "string",
                "Required Stripe settlement subledger reference.",
                True,
            ),
            PrimitiveField(
                "stripe_control_account_ref",
                "string",
                "Canonical ledger control account for Stripe settlements.",
                True,
            ),
            PrimitiveField(
                "period_open_candidate_ref",
                "string",
                "Stable open-period transition candidate reference.",
                True,
            ),
            PrimitiveField(
                "prior_period_state",
                "string",
                "closed or not_applicable.",
                True,
            ),
            PrimitiveField(
                "opened_at",
                "string",
                "Exact fiscal-period start timestamp.",
                True,
            ),
            PrimitiveField(
                "opened_by_ref",
                "string",
                "Period-opening preparer reference.",
                True,
            ),
            PrimitiveField(
                "open_reviewed_by_ref",
                "string",
                "Independent period-opening reviewer reference.",
                True,
            ),
            PrimitiveField(
                "period_open_evidence_use_refs",
                "array",
                "Sorted retained evidence-use references for period opening.",
                True,
            ),
            PrimitiveField(
                "trial_balance_ref",
                "string",
                "Stable Trial Balance package reference.",
                True,
            ),
            PrimitiveField(
                "trial_balance_prepared_by_ref",
                "string",
                "Trial Balance preparer reference.",
                True,
            ),
            PrimitiveField(
                "trial_balance_reviewed_by_ref",
                "string",
                "Independent Trial Balance reviewer reference.",
                True,
            ),
            PrimitiveField(
                "trial_balance_evidence_use_refs",
                "array",
                "Sorted retained evidence-use references for the Trial Balance.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare the August 2026 one-entity monthly close workspace from the "
            "sealed ledger and source-complete accounting and Stripe evidence bundle."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.prepare_journal_entry",
        title="Prepare controlled journal entry",
        category="finance",
        summary="Evaluate journal controls and compile a content-bound provider proposal.",
        description=(
            "Reuses the typed journal-entry control contract, produces an exact "
            "QuickBooks or Xero payload only when controls are ready, and grants no "
            "posting authority."
        ),
        risk_level="medium",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="prepare_journal_entry",
        additional_inputs_allowed=False,
        setup_requirements=(
            "complete_chart_of_accounts_control_snapshot",
            "open_accounting_period_and_control_evidence",
            "content_bound_accounting_approval_gate",
        ),
        trigger_events=(
            "finance.ledger_accounts_discovered",
            "finance.journal_entry_requested",
        ),
        emits=("finance.journal_entry_prepared",),
        follow_up_primitives=("finance.post_journal_entry",),
        agent_builder_guidance=(
            "Persist and review the preparation digest; posting must re-evaluate the "
            "same typed journal and match that digest exactly."
        ),
        input_fields=(
            PrimitiveField("provider", "string", "quickbooks or xero.", True),
            PrimitiveField(
                "journal",
                "object",
                "Typed JournalEntryControlInput with accounts, lines, period, approval, controls, and evidence.",
                True,
            ),
        ),
        example_prompt="Prepare this approved balanced journal for governed posting to QuickBooks.",
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.post_journal_entry",
        title="Post governed journal entry",
        category="finance",
        summary="Request one approved, idempotent QuickBooks or Xero journal write.",
        description=(
            "Re-evaluates the journal, verifies its reviewed preparation digest, and "
            "routes one exact write through Spring. Ambiguous provider outcomes become "
            "in-doubt receipts that cannot be retried automatically."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="preview",
        domain="finance",
        action="post_journal_entry",
        connector_tools=(
            "quickbooks.create_journal_entry",
            "xero.create_manual_journal",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_project_scope",
            "exact_provider_connector_account_binding",
            "content_bound_spring_approval",
            "spring_governed_execution_journal",
        ),
        trigger_events=("finance.journal_entry_prepared",),
        emits=(
            "finance.journal_entry_post_previewed",
            "finance.journal_entry_pending_approval",
            "finance.journal_entry_posted",
            "finance.journal_entry_post_in_doubt",
        ),
        follow_up_primitives=("finance.reconcile_journal_post",),
        agent_builder_guidance=(
            "Default to preview, require the exact reviewed preparation digest, and "
            "never resend an in-doubt write until Spring settles its execution journal."
        ),
        input_fields=(
            PrimitiveField("provider", "string", "quickbooks or xero.", True),
            PrimitiveField(
                "journal",
                "object",
                "The exact typed journal that produced the reviewed preparation.",
                True,
            ),
            PrimitiveField(
                "expected_preparation_digest",
                "string",
                "SHA-256 digest returned by journal preparation.",
                True,
            ),
            PrimitiveField(
                "commit",
                "boolean",
                "False previews locally; true requests the governed write.",
                False,
            ),
        ),
        example_prompt="Post this unchanged approved journal through the governed QuickBooks route.",
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.reconcile_journal_post",
        title="Reconcile journal post readback",
        category="finance",
        summary="Evaluate independent readback for a completed or in-doubt journal post.",
        description=(
            "Binds provider readback evidence to the exact post receipt and proposes a "
            "manual recovery disposition. Confirmation compares provider-stable effect "
            "digests and record identity only inside the same project, tenant connector, "
            "and connector account; it never compares raw WRITE and READ response digests, "
            "settles Spring authority, or permits replay."
        ),
        risk_level="medium",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="reconcile_journal_post",
        additional_inputs_allowed=False,
        setup_requirements=(
            "completed_or_in_doubt_journal_post_receipt",
            "independently_attested_provider_readback",
            "canonical_provider_effect_fingerprint",
            "exact_governed_read_custody",
            "matching_write_read_project_connector_account_lineage",
            "spring_execution_journal_settlement_authority",
        ),
        trigger_events=(
            "finance.journal_entry_posted",
            "finance.journal_entry_post_in_doubt",
        ),
        emits=("finance.journal_post_readback_evaluated",),
        agent_builder_guidance=(
            "Use only attested or independently verified readback. A matching result is "
            "a settlement candidate, not permission to replay or continue the write."
        ),
        input_fields=(
            PrimitiveField("provider", "string", "quickbooks or xero.", True),
            PrimitiveField(
                "entry_ref", "string", "Canonical journal entry reference.", True
            ),
            PrimitiveField(
                "post_receipt",
                "object",
                "Exact completed or in-doubt journal post operation receipt.",
                True,
            ),
            PrimitiveField(
                "expected_provider_record_ref",
                "string",
                "Expected provider record reference when the write completed.",
                False,
            ),
            PrimitiveField(
                "expected_effect_sha256",
                "string",
                "Expected provider-stable semantic effect digest when supported.",
                False,
            ),
            PrimitiveField(
                "readback",
                "object",
                "Provider-bound readback with independently verified evidence references.",
                True,
            ),
        ),
        example_prompt="Evaluate this provider readback against the in-doubt journal receipt.",
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="finance.create_invoice",
        title="Create invoice",
        category="finance",
        summary="Prepare a customer invoice across Xero, QuickBooks, Stripe, Square, or the connected finance system.",
        description=(
            "Creates or stages a sales invoice from customer, line-item, due-date, and memo details. "
            "High-risk provider writes must remain draft/proposal or HITL-approved."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="draft_for_approval",
        domain="finance",
        action="chat",
        connector_tools=(
            "xero.create_invoice",
            "quickbooks.create_invoice",
            "stripe.create_invoice",
            "square.create_invoice",
        ),
        setup_requirements=(
            "connected_accounting_or_billing_connector",
            "customer_or_contact_resolution",
            "invoice_write_approval_policy",
            "invoice_status_webhook_or_polling_watch",
            "payment_or_collection_event_context",
        ),
        trigger_events=(
            "deal.closed_won",
            "project.milestone_approved",
            "manual_invoice_request",
            "recurring_billing_date",
        ),
        emits=(
            "invoice.draft_created",
            "invoice.pending_approval",
            "invoice.sent",
            "invoice.paid",
            "invoice.overdue",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "calendar.schedule_meeting",
        ),
        agent_builder_guidance=(
            "When this primitive is used in a workflow, include customer/contact lookup, line-item validation, "
            "HITL approval before provider writes, and a status listener so paid/overdue events can trigger follow-up."
        ),
        input_fields=(
            PrimitiveField(
                "provider", "string", "Preferred accounting or billing provider.", False
            ),
            PrimitiveField("customer_name", "string", "Customer display name.", False),
            PrimitiveField(
                "customer_id",
                "string",
                "Provider customer/contact ID when known.",
                False,
            ),
            PrimitiveField(
                "line_items",
                "array",
                "Invoice line items with description, quantity, unit amount, and account code.",
                False,
            ),
            PrimitiveField(
                "amount",
                "number",
                "Invoice total when line items are not supplied.",
                False,
            ),
            PrimitiveField(
                "currency",
                "string",
                "Currency code, such as USD, CAD, AUD, or GBP.",
                False,
            ),
            PrimitiveField("due_date", "string", "Due date in YYYY-MM-DD form.", False),
            PrimitiveField(
                "reference", "string", "Customer-facing invoice reference.", False
            ),
        ),
        example_prompt="Create a draft Xero invoice for Acme for the June implementation milestone.",
    ),
    BusinessPrimitive(
        id="finance.ingest_supplier_invoice",
        title="Ingest supplier invoice",
        category="finance",
        summary="Extract, classify, and route an accounts-payable supplier invoice.",
        description=(
            "Reads a PDF, image, or email body and extracts vendor, line items, totals, GL coding, "
            "payment terms, duplicate flags, and approval routing."
        ),
        risk_level="medium",
        approval_required=False,
        default_mode="analysis",
        domain="finance",
        action="finance_ap_invoice_intake",
        connector_tools=("xero.create_bill", "quickbooks.create_bill"),
        setup_requirements=(
            "document_or_email_invoice_intake_source",
            "vendor_master_lookup",
            "duplicate_invoice_detection",
            "ap_approval_policy",
        ),
        trigger_events=(
            "invoice.email_received",
            "invoice.file_uploaded",
            "supplier_portal_invoice_created",
        ),
        emits=(
            "supplier_invoice.extracted",
            "supplier_invoice.exception_found",
            "supplier_invoice.pending_approval",
            "supplier_invoice.ready_for_payment",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "finance.create_invoice",
        ),
        agent_builder_guidance=(
            "Attach OCR/document parsing, vendor matching, duplicate checks, and approval routing before any bill creation."
        ),
        input_fields=(
            PrimitiveField(
                "invoice_url",
                "string",
                "Signed URL or Lightbulb artifact URI for the invoice.",
                False,
            ),
            PrimitiveField(
                "invoice_text",
                "string",
                "Raw invoice text when no file URL is available.",
                False,
            ),
            PrimitiveField(
                "expected_vendor", "string", "Vendor name to validate against.", False
            ),
        ),
        example_prompt="Extract the AP fields from this supplier invoice and flag anything unusual.",
    ),
    BusinessPrimitive(
        id="communication.plan_crm_conversation_turn",
        title="Plan governed CRM conversation turn",
        category="communication",
        summary=(
            "Plan a Gmail-first CRM reply or follow-up with sealed context, policy, "
            "approval, dispatch, reply observation, and CRM touchpoint phases."
        ),
        description=(
            "Builds an immutable proposal from opaque CRM references and content "
            "digests. The planner invokes no connector and stores no address or message "
            "body. A trusted host must resolve the exact CRM thread and Gmail route, "
            "evaluate contact policy, reserve the contact slot, obtain content-bound "
            "approval, and run the governed materializer and reply runtime."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        connector_tools=(),
        capability_hints=(
            "crm.resolve_conversation_context",
            "host.evaluate_communication_policy",
            "host.reserve_communication_contact",
            "gmail.send_email",
            "gmail.get_thread",
            "crm.append_communication_touchpoint",
        ),
        additional_inputs_allowed=False,
        setup_requirements=(
            "authenticated_exact_tenant_company_user_project_scope",
            "canonical_crm_conversation_contact_and_channel_identity",
            "exact_governed_gmail_route_descriptor",
            "host_hmac_keyring_for_communication_artifacts",
            "consent_suppression_quiet_hours_and_frequency_authorities",
            "content_bound_human_approval_before_external_send",
            "provider_thread_observation_and_crm_touchpoint_adapter",
        ),
        trigger_events=(
            "crm.verified_message_received",
            "crm.follow_up_due",
            "growth.reviewed_plan_available",
        ),
        emits=("communication.turn_planned",),
        follow_up_primitives=(
            "communication.classify_reply",
            "crm.qualify_lead",
            "calendar.schedule_meeting",
        ),
        agent_builder_guidance=(
            "Use this typed proposal primitive before external CRM email. Pass only "
            "opaque CRM references and digests. Capability hints are discovery metadata, "
            "not dispatch authority. The trusted host must use CommunicationScopeKeyRing, "
            "materialize_gmail_communication_turn, and CommunicationRuntime. Never place "
            "addresses, message bodies, or provider payloads in durable workflow state. "
            "An optional Growth source is an opaque reviewed artifact binding only; this "
            "primitive does not calculate lift, learn, or re-plan Growth experiments."
        ),
        input_fields=(
            PrimitiveField(
                "analysis_as_of",
                "string",
                "Explicit ISO-8601 cutoff for a deterministic plan.",
                True,
            ),
            PrimitiveField("plan_ref", "string", "Portable turn plan key.", True),
            PrimitiveField(
                "objective_ref",
                "string",
                "Opaque reference to the reviewed business objective.",
                True,
            ),
            PrimitiveField(
                "objective_digest",
                "string",
                "SHA-256 binding for the reviewed objective; no objective text.",
                True,
            ),
            PrimitiveField(
                "turn_kind",
                "string",
                "reply_to_inbound or outbound_follow_up.",
                True,
            ),
            PrimitiveField("purpose", "string", "Policy purpose such as sales.", True),
            PrimitiveField(
                "crm_conversation_ref",
                "string",
                "Opaque canonical CRM conversation reference.",
                True,
            ),
            PrimitiveField(
                "crm_contact_ref",
                "string",
                "Opaque canonical CRM contact reference.",
                True,
            ),
            PrimitiveField(
                "source_message_ref",
                "string",
                "Opaque inbound CRM message reference for a reply.",
                False,
            ),
            PrimitiveField(
                "source_message_digest",
                "string",
                "SHA-256 binding for the source message.",
                False,
            ),
            PrimitiveField(
                "connector_account_ref",
                "string",
                "Exact project Gmail account alias, never a credential.",
                True,
            ),
            PrimitiveField(
                "growth_source_ref",
                "string",
                "Optional opaque reviewed Growth artifact reference.",
                False,
            ),
            PrimitiveField(
                "growth_source_digest",
                "string",
                "Required content digest when a Growth source is supplied.",
                False,
            ),
        ),
        example_prompt=(
            "Plan a governed reply to this verified CRM message, preserve the CRM "
            "timeline, and require policy, approval, delivery, and reply evidence."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="communication.write_email",
        title="Write email",
        category="communication",
        summary="Draft or send a business email through Gmail, Microsoft 365, or the configured mail connector.",
        description=(
            "Composes business email for sales, finance, support, operations, or project updates. "
            "External sends are treated as consequential writes and should require approval."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="draft",
        domain="crm",
        action="outbound_messaging",
        connector_tools=(
            "gmail.send_email",
            "microsoft.send_email",
            "notifications.send_email",
            "ses.send_email",
        ),
        setup_requirements=(
            "connected_mailbox_or_email_provider",
            "send_approval_policy_when_external",
            "email_reply_webhook_or_polling_watch",
            "thread_context_store",
            "reply_classifier_and_next_action_router",
        ),
        trigger_events=(
            "manual_email_request",
            "invoice.overdue",
            "crm.lead_needs_followup",
            "approval.completed",
            "support.case_updated",
        ),
        emits=(
            "email.draft_created",
            "email.pending_approval",
            "email.sent",
            "email.reply_received",
            "email.bounced",
            "email.thread_context_updated",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "crm.qualify_lead",
            "calendar.schedule_meeting",
            "finance.create_invoice",
        ),
        agent_builder_guidance=(
            "For CRM conversation loops, prefer communication.plan_crm_conversation_turn. "
            "For lower-level outbound loops, Agent Builder should add reply capture automatically. A sent email is not complete "
            "without a webhook/watch or polling fallback, thread context persistence, reply classification, and a branch "
            "for response, bounce, no-response, and escalation."
        ),
        input_fields=(
            PrimitiveField(
                "to", "array", "Exactly one recipient email address.", False
            ),
            PrimitiveField("subject", "string", "Email subject.", False),
            PrimitiveField(
                "body", "string", "Draft body or facts to turn into a body.", False
            ),
            PrimitiveField(
                "intent",
                "string",
                "Purpose: invoice_reminder, follow_up, intro, update, approval_request, etc.",
                False,
            ),
            PrimitiveField("tone", "string", "Tone guidance.", False),
            PrimitiveField(
                "thread_id",
                "string",
                "Exact Gmail thread ID when replying in-thread; pair with parent_message_id.",
                False,
            ),
            PrimitiveField(
                "parent_message_id",
                "string",
                "Exact RFC Message-ID parent when replying in-thread; pair with thread_id.",
                False,
            ),
            PrimitiveField(
                "send",
                "boolean",
                "Whether the user is asking to send rather than draft.",
                False,
            ),
        ),
        example_prompt="Write a polite invoice reminder email for the overdue Acme invoice.",
    ),
    BusinessPrimitive(
        id="communication.classify_reply",
        title="Classify inbound reply",
        category="communication",
        summary="Classify an inbound business reply and route the next governed action.",
        description=(
            "Interprets a normalized inbound email or message in its thread context, assigns a business intent, "
            "records confidence and evidence labels, and proposes the next workflow event. Classification is "
            "read-only; low-confidence or sensitive replies are routed to human review."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="crm",
        action="classify_reply",
        connector_tools=("gmail.get_thread",),
        setup_requirements=(
            "inbound_email_webhook_or_polling_watch",
            "thread_context_store",
            "tenant_reply_taxonomy",
            "confidence_threshold_and_human_review_fallback",
            "pii_safe_message_normalization",
        ),
        trigger_events=(
            "email.reply_received",
            "message.inbound_received",
            "support.customer_replied",
        ),
        emits=(
            "email.reply_classified",
            "reply.needs_human_review",
            "crm.intent_detected",
            "meeting.requested",
            "unsubscribe.requested",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "crm.qualify_lead",
            "calendar.schedule_meeting",
        ),
        agent_builder_guidance=(
            "Classify only inside the authenticated thread context. Return intent, confidence, evidence labels, "
            "and a proposed next event without retaining raw reply text in workflow-improvement telemetry. Route "
            "low confidence, legal threats, payment disputes, security reports, and ambiguous opt-outs to human review."
        ),
        input_fields=(
            PrimitiveField(
                "reply_text",
                "string",
                "Normalized inbound reply text. Excluded from improvement telemetry.",
                True,
            ),
            PrimitiveField(
                "thread_context",
                "object",
                "Prior thread facts and business state.",
                False,
            ),
            PrimitiveField(
                "taxonomy", "array", "Optional tenant-approved intent labels.", False
            ),
            PrimitiveField(
                "confidence_threshold",
                "number",
                "Threshold below which human review is required.",
                False,
            ),
            PrimitiveField(
                "channel",
                "string",
                "Inbound channel, such as gmail, outlook, or support.",
                False,
            ),
        ),
        example_prompt="Classify this customer reply and route meeting requests or opt-outs safely.",
    ),
    BusinessPrimitive(
        id="legal.draft_contract",
        title="Draft contract",
        category="legal",
        summary="Draft an NDA, MSA, SOW, sales agreement, service agreement, or policy document.",
        description=(
            "Creates a legal document packet from a plain-English brief plus templates, jurisdiction, "
            "counterparty, and house-style context. Legal review remains expected before external use."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="draft",
        domain="legal",
        action="document_drafting",
        connector_tools=("docs.create_document", "microsoft.create_document"),
        setup_requirements=(
            "template_or_playbook_resolution",
            "document_storage_destination",
            "legal_review_approval_policy",
            "signature_or_counterparty_response_tracking_when_external",
        ),
        trigger_events=(
            "deal.requires_contract",
            "vendor_onboarding.requires_agreement",
            "manual_contract_request",
        ),
        emits=(
            "contract.draft_created",
            "contract.pending_legal_review",
            "contract.sent_for_signature",
            "contract.counterparty_response_received",
        ),
        follow_up_primitives=(
            "legal.review_contract",
            "communication.write_email",
        ),
        agent_builder_guidance=(
            "When a drafted contract leaves Lightbulb, add review approval and a response/signature tracker so revisions "
            "or counterparty comments come back into the same matter/thread context."
        ),
        input_fields=(
            PrimitiveField(
                "document_type",
                "string",
                "Document type, such as NDA, MSA, SOW, or policy.",
                True,
            ),
            PrimitiveField("brief", "string", "Plain-English drafting brief.", True),
            PrimitiveField("counterparty", "string", "Counterparty name.", False),
            PrimitiveField("jurisdiction", "string", "Governing jurisdiction.", False),
            PrimitiveField("playbook", "string", "Template or playbook label.", False),
        ),
        example_prompt="Draft a mutual NDA for Acme under Delaware law.",
    ),
    BusinessPrimitive(
        id="legal.review_contract",
        title="Review contract",
        category="legal",
        summary="Review a contract against a playbook and produce a risk memo or redline-ready notes.",
        description=(
            "Analyzes uploaded or linked contract text for deviations, missing clauses, business risk, "
            "and proposed edits with rationale."
        ),
        risk_level="medium",
        approval_required=False,
        default_mode="analysis",
        domain="legal",
        action="contract_review",
        connector_tools=(
            "docs.read_document",
            "drive.download_file",
            "microsoft.download_file",
        ),
        setup_requirements=(
            "contract_file_access",
            "legal_playbook_or_fallback_review_standard",
            "matter_or_project_context_store",
        ),
        trigger_events=(
            "contract.uploaded",
            "contract.counterparty_response_received",
            "manual_review_request",
        ),
        emits=(
            "contract.review_completed",
            "contract.risk_flagged",
            "contract.revision_requested",
        ),
        follow_up_primitives=(
            "legal.draft_contract",
            "communication.write_email",
        ),
        agent_builder_guidance=(
            "Preserve source document, playbook, risk memo, and requested revisions so the next draft/email step has full context."
        ),
        input_fields=(
            PrimitiveField(
                "contract_url",
                "string",
                "Contract URL or Lightbulb artifact URI.",
                True,
            ),
            PrimitiveField("playbook", "string", "Playbook label.", False),
            PrimitiveField("counterparty_name", "string", "Counterparty name.", False),
            PrimitiveField("focus", "string", "Specific review focus.", False),
        ),
        example_prompt="Review this MSA against our enterprise sales playbook.",
    ),
    BusinessPrimitive(
        id="calendar.schedule_meeting",
        title="Schedule meeting",
        category="calendar",
        summary="Find availability and create a calendar invite with agenda and conferencing.",
        description=(
            "Schedules a meeting on Google Calendar or Microsoft 365. Creating or updating invites is "
            "treated as a user-visible write and should preserve confirmation/approval behavior."
        ),
        risk_level="medium",
        approval_required=True,
        default_mode="proposal",
        domain="crm",
        action="propose_meeting_slots",
        connector_tools=(
            "calendar.get_availability",
            "calendar.create_event",
            "microsoft.create_event",
        ),
        setup_requirements=(
            "calendar_availability_access",
            "calendar_write_approval_policy",
            "meeting_response_or_decline_tracking",
            "agenda_context_store",
        ),
        trigger_events=(
            "email.reply_requests_meeting",
            "crm.next_step_meeting",
            "manual_meeting_request",
        ),
        emits=(
            "meeting.slots_proposed",
            "meeting.invite_pending_approval",
            "meeting.invite_sent",
            "meeting.accepted",
            "meeting.declined",
        ),
        follow_up_primitives=("communication.write_email",),
        agent_builder_guidance=(
            "Prefer availability proposal first; if an invite is sent, track accept/decline and feed the outcome back into the workflow."
        ),
        input_fields=(
            PrimitiveField("attendees", "array", "Attendee emails or objects.", True),
            PrimitiveField("title", "string", "Meeting title.", True),
            PrimitiveField(
                "time_window", "string", "Preferred date/time window.", False
            ),
            PrimitiveField("duration_minutes", "number", "Meeting length.", False),
            PrimitiveField("agenda", "string", "Agenda or notes.", False),
        ),
        example_prompt="Find a time next week with Casey and send a 30-minute kickoff invite.",
    ),
    BusinessPrimitive(
        id="crm.qualify_lead",
        title="Qualify lead",
        category="crm",
        summary="Score a lead against ICP and suggest the next best action.",
        description=(
            "Uses CRM and enrichment context to produce a fit score, reasons, missing data, and next step."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        domain="crm",
        action="lead_qualification",
        connector_tools=("hubspot.get_contact", "salesforce.get_contact"),
        setup_requirements=(
            "crm_contact_or_lead_lookup",
            "icp_scoring_rules",
            "next_action_policy",
        ),
        trigger_events=(
            "crm.lead_created",
            "form.submitted",
            "email.reply_received",
            "manual_qualification_request",
        ),
        emits=(
            "lead.qualified",
            "lead.disqualified",
            "lead.needs_research",
            "lead.next_action_recommended",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "calendar.schedule_meeting",
        ),
        agent_builder_guidance=(
            "Use qualification output to branch: high-fit leads get personalized follow-up, meeting intent gets scheduling, "
            "and missing data gets enrichment before outreach."
        ),
        input_fields=(
            PrimitiveField("lead_id", "string", "CRM lead/contact ID.", False),
            PrimitiveField("lead_email", "string", "Lead email.", False),
            PrimitiveField(
                "company_domain", "string", "Company domain for enrichment.", False
            ),
        ),
        example_prompt="Qualify this lead and tell me the next best action.",
    ),
    BusinessPrimitive(
        id="hr.onboard_employee",
        title="Onboard employee",
        category="hr",
        summary="Prepare a new-hire onboarding plan across HRIS, IT, calendar, and document tasks.",
        description=(
            "Coordinates account provisioning, equipment, documents, welcome communications, and day-one meetings. "
            "Actual access changes stay behind Lightbulb approval and connector policies."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="plan_for_approval",
        domain="hr",
        action="onboard",
        connector_tools=(
            "bamboohr.create_employee",
            "google_workspace.create_user",
            "microsoft.create_user",
        ),
        setup_requirements=(
            "hris_connection",
            "identity_provider_or_workspace_admin_connection",
            "manager_approval_policy",
            "equipment_and_document_task_templates",
        ),
        trigger_events=(
            "candidate.marked_hired",
            "offer.accepted",
            "manual_onboarding_request",
        ),
        emits=(
            "employee.onboarding_plan_created",
            "employee.access_pending_approval",
            "employee.accounts_provisioned",
            "employee.day_one_ready",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "calendar.schedule_meeting",
            "legal.draft_contract",
        ),
        agent_builder_guidance=(
            "Create the plan first, then branch into approvals for access, docs, equipment, manager comms, and day-one meetings."
        ),
        input_fields=(
            PrimitiveField("employee_name", "string", "New hire full name.", True),
            PrimitiveField("role_title", "string", "Role title.", True),
            PrimitiveField(
                "start_date", "string", "Start date in YYYY-MM-DD form.", True
            ),
            PrimitiveField("manager_email", "string", "Manager email.", False),
        ),
        example_prompt="Create an onboarding plan for Jordan Lee starting July 15.",
    ),
    BusinessPrimitive(
        id="finance.collect_payment",
        title="Collect approved payment",
        category="finance",
        summary="Propose and record an approved customer payment against a Xero invoice.",
        description=(
            "Validates invoice, bank account, amount, currency, and date before recording a payment. "
            "The accounting write is idempotent and remains behind HITL approval."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="proposal",
        domain="finance",
        action="payment_collection",
        connector_tools=("xero.create_payment",),
        setup_requirements=(
            "xero_accounting_connection",
            "invoice_and_bank_account_resolution",
            "payment_write_approval_policy",
            "payment_reconciliation_listener",
        ),
        trigger_events=(
            "invoice.approved_for_payment",
            "payment.received",
            "manual_payment_request",
        ),
        emits=(
            "payment.proposed",
            "payment.pending_approval",
            "payment.recorded",
            "payment.failed",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "documents.generate_business_artifact",
        ),
        agent_builder_guidance=(
            "Resolve the invoice and bank account, validate currency and amount, require approval, "
            "record with a stable idempotency key, and reconcile the resulting provider reference."
        ),
        input_fields=(
            PrimitiveField("invoice_id", "string", "Xero invoice identifier.", True),
            PrimitiveField(
                "account_id", "string", "Xero bank account identifier.", True
            ),
            PrimitiveField("amount", "number", "Approved payment amount.", True),
            PrimitiveField("currency", "string", "Three-letter currency code.", False),
            PrimitiveField(
                "payment_date", "string", "Payment date in YYYY-MM-DD form.", False
            ),
            PrimitiveField(
                "commit", "boolean", "Whether to record the approved payment.", False
            ),
        ),
        example_prompt="Record the approved $125 payment against the Acme Xero invoice.",
    ),
    BusinessPrimitive(
        id="approval.request_decision",
        title="Request governed decision",
        category="approval",
        summary="Pause a workflow for an owned, bounded, evidence-backed human decision.",
        description=(
            "Creates a decision request with allowed options, owner, deadline, and context. "
            "Only a verified approval reference can resume the workflow with a selected decision."
        ),
        risk_level="medium",
        approval_required=True,
        default_mode="draft",
        domain="operations",
        action="request_decision",
        setup_requirements=(
            "decision_owner_resolution",
            "approval_notification_and_escalation_policy",
            "durable_workflow_checkpoint",
        ),
        trigger_events=(
            "workflow.decision_required",
            "exception.needs_owner",
            "manual_decision_request",
        ),
        emits=("approval.draft_created", "approval.requested", "approval.decided"),
        follow_up_primitives=(
            "communication.write_email",
            "project.create_work_packet",
        ),
        agent_builder_guidance=(
            "Persist the paused workflow before requesting a decision. Do not infer approval from prose; "
            "resume only with a verified approval reference and one declared option."
        ),
        input_fields=(
            PrimitiveField("subject", "string", "Decision title.", True),
            PrimitiveField("question", "string", "Decision question.", True),
            PrimitiveField("options", "array", "Allowed decision options.", True),
            PrimitiveField("owner", "string", "Responsible decision owner.", False),
            PrimitiveField(
                "submit", "boolean", "Whether to pause and request the decision.", False
            ),
            PrimitiveField(
                "decision", "string", "Selected option supplied on resume.", False
            ),
        ),
        example_prompt="Ask the finance owner which approved launch date to use.",
    ),
    BusinessPrimitive(
        id="documents.generate_business_artifact",
        title="Generate business artifact",
        category="documents",
        summary="Create an inspectable DOCX, PDF, XLSX, PPTX, or Markdown business artifact.",
        description=(
            "Validates bounded structured content and creates the requested artifact through governed "
            "Google Docs, Sheets, or Slides connector execution."
        ),
        risk_level="medium",
        approval_required=True,
        default_mode="draft",
        domain="document_intelligence",
        action="artifact_generation",
        connector_tools=(
            "docs.create_document",
            "sheets.create_spreadsheet",
            "slides.create_presentation",
        ),
        setup_requirements=(
            "artifact_storage_destination",
            "document_connector_readiness",
            "artifact_write_approval_policy",
        ),
        trigger_events=(
            "workflow.artifact_requested",
            "analysis.completed",
            "manual_artifact_request",
        ),
        emits=(
            "artifact.draft_created",
            "artifact.pending_approval",
            "artifact.created",
        ),
        follow_up_primitives=(
            "communication.write_email",
            "project.create_work_packet",
        ),
        agent_builder_guidance=(
            "Choose the artifact type from downstream use, preserve source evidence, preview first, "
            "and attach the created artifact reference to the workflow checkpoint."
        ),
        input_fields=(
            PrimitiveField(
                "artifact_type", "string", "docx, pdf, xlsx, pptx, or markdown.", True
            ),
            PrimitiveField("title", "string", "Artifact title.", True),
            PrimitiveField(
                "content", "object", "Bounded structured artifact content.", True
            ),
            PrimitiveField(
                "destination",
                "string",
                "Optional folder or destination reference.",
                False,
            ),
            PrimitiveField(
                "create", "boolean", "Whether to create the external artifact.", False
            ),
        ),
        example_prompt="Create an XLSX operating review from the approved workflow results.",
    ),
    BusinessPrimitive(
        id="project.create_work_packet",
        title="Create implementation work packet",
        category="project",
        summary="Turn an approved capability gap into a bounded implementation packet.",
        description=(
            "Creates deterministic scope, acceptance, dependency, target-file, and risk contracts. "
            "Implementation, publication, and deployment remain separate approval stages."
        ),
        risk_level="high",
        approval_required=True,
        default_mode="draft",
        domain="product",
        action="create_work_packet",
        setup_requirements=(
            "project_scope_and_repository_context",
            "requirements_and_sop_impact",
            "implementation_approval_policy",
            "coding_harness_handoff",
        ),
        trigger_events=(
            "capability.gap_approved",
            "workflow.improvement_approved",
            "manual_work_packet_request",
        ),
        emits=(
            "project.work_packet_created",
            "project.work_packet_pending_approval",
            "project.work_packet_approved",
        ),
        follow_up_primitives=(
            "approval.request_decision",
            "documents.generate_business_artifact",
        ),
        agent_builder_guidance=(
            "Produce a tracer-sized packet with explicit acceptance and tests. Keep implementation, "
            "publish, and deploy decisions independent and never treat packet creation as execution."
        ),
        input_fields=(
            PrimitiveField("title", "string", "Work packet title.", True),
            PrimitiveField(
                "implementation_objective",
                "string",
                "Concrete implementation objective.",
                True,
            ),
            PrimitiveField("scope", "array", "Included implementation scope.", True),
            PrimitiveField(
                "acceptance_criteria", "array", "Verifiable acceptance criteria.", True
            ),
            PrimitiveField(
                "target_files",
                "array",
                "Expected code and documentation targets.",
                False,
            ),
            PrimitiveField(
                "submit_for_approval",
                "boolean",
                "Whether to request implementation approval.",
                False,
            ),
        ),
        example_prompt="Create a work packet for adding a governed customer health event.",
    ),
    BusinessPrimitive(
        id="learning.plan_optimization_sweep",
        title="Plan optimization sweep",
        category="learning",
        summary=(
            "Select and budget AutoResearch, Spark, AutoML, PufferLib, and "
            "PRIME-RL runtimes for one governed learning objective."
        ),
        description=(
            "Compiles a deterministic, typed runtime plan from a Project training "
            "pack, business metric, target policy type, data scale, and total "
            "budget. Planning never publishes data, reserves capacity, starts "
            "training, promotes a model, or authorizes a production action."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        setup_requirements=(
            "project_training_pack_receipt",
            "business_outcome_metric",
            "authenticated_project_scope_for_later_execution",
            "learning_capacity_and_commercial_admission_policy",
            "independent_evaluation_and_promotion_policy",
        ),
        trigger_events=(
            "project.training_pack_ready",
            "business.metric_regressed",
            "manual_optimization_request",
        ),
        emits=(
            "learning.optimization_sweep_planned",
            "learning.optimization_sweep_needs_input",
        ),
        follow_up_primitives=("approval.request_decision",),
        agent_builder_guidance=(
            "Use the local executable primitive to select runtimes and divide one "
            "bounded budget. Then call the existing Project learning-run preparation "
            "and admission surfaces separately for each stage. Preserve explicit "
            "confirm_prepare/confirm_admission gates, provider-account custody for "
            "billable lanes, independent evaluation, and human promotion decisions. "
            "Do not ask the user for Kafka brokers, Spark clusters, tenant IDs, "
            "company IDs, or provider credentials."
        ),
        input_fields=(
            PrimitiveField(
                "training_pack_receipt_id",
                "string",
                "Exact governed Project training-pack receipt UUID.",
                True,
            ),
            PrimitiveField(
                "optimization_objective",
                "string",
                "Business learning objective.",
                True,
            ),
            PrimitiveField(
                "primary_metric",
                "string",
                "Business outcome metric used for evaluation.",
                True,
            ),
            PrimitiveField(
                "direction",
                "string",
                "Whether to maximize or minimize the primary metric.",
                False,
            ),
            PrimitiveField(
                "target",
                "string",
                "predictive_model, numeric_control_policy, llm_agent_policy, or hybrid_agent.",
                False,
            ),
            PrimitiveField(
                "data_profile",
                "object",
                "Bounded row, feature, event-rate, and streaming scale signals.",
                False,
            ),
            PrimitiveField(
                "feature_backend",
                "string",
                "auto, local, or spark.",
                False,
            ),
            PrimitiveField(
                "include_auto_research",
                "boolean",
                "Whether to include the governed GEPA AutoResearch lane.",
                False,
            ),
            PrimitiveField(
                "include_feature_engineering",
                "boolean",
                "Whether the sweep should include feature engineering.",
                False,
            ),
            PrimitiveField(
                "minimum_improvement",
                "number",
                "Minimum metric improvement required from a candidate.",
                False,
            ),
            PrimitiveField(
                "budget",
                "object",
                "One bounded platform/provider/GPU/token/step budget to divide across stages.",
                False,
            ),
        ),
        example_prompt=(
            "Plan a hybrid retention-agent optimization sweep from this approved "
            "training pack, using Spark for the streaming feature matrix."
        ),
    ),
    BusinessPrimitive(
        id="commerce.plan_shopify_storefront",
        title="Plan Shopify storefront",
        category="commerce",
        summary=(
            "Compile a typed proposal for draft Shopify products, an unpublished "
            "collection, pages, and retained-theme adjustments."
        ),
        description=(
            "Plans a deterministic, reviewable Shopify storefront without reading "
            "a shop, invoking a connector, publishing content, or changing a live "
            "store. Materialization remains a separate governed workflow."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        setup_requirements=(
            "storefront_business_brief",
            "draft_product_and_price_content",
            "human_review_before_any_materialization",
        ),
        trigger_events=(
            "commerce.shopify_storefront_planning_requested",
            "manual_storefront_proposal_request",
        ),
        emits=("commerce.shopify_storefront_proposal_compiled",),
        follow_up_primitives=("approval.request_decision",),
        agent_builder_guidance=(
            "Use the local executable primitive for proposal-only planning. Keep "
            "credentials, shop identity, connector calls, publication, and theme "
            "deployment out of this primitive; route any later materialization "
            "through exact project scope, connector policy, and human approval."
        ),
        input_fields=(
            PrimitiveField(
                "brief",
                "object",
                "Storefront identity, audience, business goal, currency, and locale.",
                True,
            ),
            PrimitiveField(
                "products",
                "array",
                "Bounded draft product definitions with prices and optional variants.",
                True,
            ),
            PrimitiveField(
                "collection",
                "object",
                "One unpublished collection referencing the declared products.",
                True,
            ),
            PrimitiveField(
                "pages",
                "array",
                "Optional unpublished storefront pages.",
                False,
            ),
            PrimitiveField(
                "existing_theme",
                "object",
                "A retain-existing-theme plan and desired adjustments.",
                True,
            ),
        ),
        example_prompt=(
            "Prepare a reviewable draft Shopify storefront proposal for these "
            "products without connecting to or changing the live store."
        ),
        backbone_fallback_available=False,
    ),
    BusinessPrimitive(
        id="gtm.plan_omnichannel_product_launch",
        title="Plan omnichannel product launch",
        category="growth",
        summary=(
            "Compile a deterministic Shopify, CRM, and social proposal graph "
            "with exact-scope evidence contracts and bounded fan-out."
        ),
        description=(
            "Creates a Shopify DRAFT-create, ACTIVE-update, explicit-publication, "
            "and landing-readiness-gate proposal before analytics-ranked social "
            "publishes, plus a HubSpot campaign container when selected. It preserves "
            "analytics provenance and never claims a live launch."
        ),
        risk_level="low",
        approval_required=False,
        default_mode="analysis",
        setup_requirements=(
            "authenticated_project_store_and_connector_account_scope",
            "shopify_publication_ids",
            "normalized_connector_analytics_with_account_refs_and_evidence_digests",
            "host_hmac_keyring_for_verified_analytics_and_receipt_admission",
            "public_media_for_instagram",
            "trusted_landing_readiness_evidence_issuer",
            "per_operation_human_approval_before_external_materialization",
            "trusted_post_launch_metrics_receipt_issuer",
        ),
        trigger_events=(
            "gtm.product_launch_planning_requested",
            "commerce.product_launch_requested",
        ),
        emits=("gtm.omnichannel_product_launch_planned",),
        follow_up_primitives=(
            "approval.request_decision",
            "learning.plan_optimization_sweep",
        ),
        agent_builder_guidance=(
            "Compile one launch per declared project/store scope: DRAFT create, ACTIVE "
            "update, explicit Shopify publication, landing-readiness evidence gate, "
            "then analytics-ranked social. Dispatch only connector_inputs resolved "
            "from prior outputs; never dispatch the evidence gate. Host-verify exact "
            "scope and connector accounts, HMAC-seal each analytics snapshot, and re-plan "
            "through the trusted host API; the catalog/MCP primitive deliberately emits a "
            "caller-unverified proposal that cannot seed the loop. Then mint and verify the "
            "complete HMAC-sealed, run/iteration/plan/operation-bound receipt set before "
            "Dynamic Workflow admission. "
            "Use evaluate_product_launch_iteration for the bounded target_met, "
            "revise_plan, or iteration_limit_reached decision; it neither schedules "
            "nor materializes work. Shard "
            "at most 12 launches and 100 initial operations, with 256 KiB job, 4 MiB "
            "shard, and 64 MiB portfolio budgets; 10,000 launches is only a validation "
            "ceiling. scope_fingerprint plus project_ref is a caller partition key that "
            "requires host verification. The control-state seed does not materialize "
            "connectors. hubspot.create_campaign is a campaign-container domain action, "
            "and Instagram and LinkedIn are not natively scheduled. Never put credentials, "
            "tenant IDs, or company IDs in inputs."
        ),
        input_fields=(
            PrimitiveField(
                "analysis_as_of",
                "string",
                "Explicit ISO-8601 evidence cutoff used for deterministic freshness.",
                True,
            ),
            PrimitiveField("launch_ref", "string", "Portable launch key.", True),
            PrimitiveField(
                "business_goal",
                "string",
                "Business outcome the launch should produce.",
                True,
            ),
            PrimitiveField(
                "target_audience",
                "string",
                "Audience shared across product, sales, and social planning.",
                True,
            ),
            PrimitiveField(
                "value_proposition",
                "string",
                "Reviewed value proposition; the primitive does not invent one.",
                True,
            ),
            PrimitiveField(
                "product",
                "object",
                "Reviewed Shopify product, price, SKU, landing page, and publication IDs.",
                True,
            ),
            PrimitiveField(
                "sales_campaign",
                "object",
                "HubSpot or Salesforce campaign brief and bounded sales touches.",
                True,
            ),
            PrimitiveField(
                "social_drafts",
                "array",
                "Reviewed channel-specific drafts for Facebook, Instagram, or LinkedIn.",
                True,
            ),
            PrimitiveField(
                "analytics_snapshots",
                "array",
                "Optional connector-account-bound metrics with evidence and scope digests.",
                False,
            ),
            PrimitiveField(
                "optimization_policy",
                "object",
                "KPI, freshness, sample, observation-window, and iteration bounds.",
                False,
            ),
        ),
        example_prompt=(
            "Plan a Shopify product launch with a HubSpot campaign and LinkedIn, "
            "Facebook, and Instagram posts, prioritized from fresh connector analytics."
        ),
        backbone_fallback_available=False,
    ),
) + tuple(
    _profit_business_primitive(definition) for definition in PROFIT_WORKFLOW_DEFINITIONS
)


_PRIMITIVES_BY_ID = {primitive.id: primitive for primitive in BUSINESS_PRIMITIVES}


def normalize_primitive_id(primitive_id: str) -> str:
    return str(primitive_id or "").strip().lower().replace(" ", "_")


def get_business_primitive(primitive_id: str) -> BusinessPrimitive:
    normalized = normalize_primitive_id(primitive_id)
    try:
        return _PRIMITIVES_BY_ID[normalized]
    except KeyError as exc:
        raise KeyError(f"Unknown Lightbulb business primitive: {primitive_id}") from exc


def list_business_primitives(
    *,
    category: str | None = None,
    query: str | None = None,
    include_inputs: bool = True,
) -> List[Dict[str, Any]]:
    category_filter = str(category or "").strip().lower()
    query_filter = str(query or "").strip().lower()
    candidates = [
        primitive
        for primitive in BUSINESS_PRIMITIVES
        if not category_filter or primitive.category.lower() == category_filter
    ]
    exact_query = False
    if query_filter:
        exact_matches = [
            primitive
            for primitive in BUSINESS_PRIMITIVES
            if primitive.id.lower() == query_filter
        ]
        if exact_matches:
            exact_query = True
            candidates = [
                primitive
                for primitive in exact_matches
                if not category_filter or primitive.category.lower() == category_filter
            ]
    rows: List[Dict[str, Any]] = []
    for primitive in candidates:
        haystack = " ".join(
            [
                primitive.id,
                primitive.title,
                primitive.category,
                primitive.summary,
                primitive.description,
                " ".join(primitive.connector_tools),
                " ".join(primitive.capability_hints),
            ]
        ).lower()
        if query_filter and not exact_query and query_filter not in haystack:
            continue
        rows.append(primitive.to_dict(include_inputs=include_inputs))
    return rows


def business_primitive_catalog(
    *,
    category: str | None = None,
    query: str | None = None,
    include_inputs: bool = True,
    summary_only: bool = False,
    offset: int = 0,
    limit: int | None = None,
) -> Dict[str, Any]:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if limit is not None and (limit < 1 or limit > 100):
        raise ValueError("limit must be between 1 and 100")
    if not summary_only and limit is not None and limit > 10:
        raise ValueError("full business-primitive pages are limited to 10 entries")
    rows = list_business_primitives(
        category=category, query=query, include_inputs=include_inputs
    )
    total_count = len(rows)
    end = None if limit is None else offset + limit
    rows = rows[offset:end]
    if summary_only:
        rows = [
            {
                "id": row["id"],
                "primitive_ref": row["primitive_ref"],
                "title": row["title"],
                "category": row["category"],
                "summary": row["summary"],
                "risk_level": row["risk_level"],
                "approval_required": row["approval_required"],
                "default_mode": row["default_mode"],
                "backbone_fallback_available": row["backbone_fallback_available"],
                "capability_hints": row.get("capability_hints", []),
            }
            for row in rows
        ]
    next_offset = offset + len(rows)
    return {
        "schema": CATALOG_SCHEMA,
        "contracts": {
            "primitive_runtime_contract": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
            "primitive_capability_projection": (PRIMITIVE_CAPABILITY_PROJECTION_SCHEMA),
            "workflow_compiler_contract": WORKFLOW_COMPILER_CONTRACT_SCHEMA,
        },
        "count": len(rows),
        "total_count": total_count,
        "offset": offset,
        "has_more": next_offset < total_count,
        "next_offset": next_offset if next_offset < total_count else None,
        "summary_only": summary_only,
        "primitives": rows,
    }


def _catalog_input_schema(primitive: BusinessPrimitive) -> Dict[str, Any]:
    """Build a conservative JSON Schema when no SDK implementation exists."""
    json_types = {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }
    properties = {
        field.name: {
            "type": field.type if field.type in json_types else "string",
            "description": field.description,
        }
        for field in primitive.input_fields
    }
    return {
        "type": "object",
        "properties": properties,
        "required": [field.name for field in primitive.input_fields if field.required],
        # Catalog-only primitives are executed through Backbone, whose
        # governed domain agent may accept additional business context.
        "additionalProperties": True,
    }


def _executable_implementation_contracts() -> Dict[str, Dict[str, Any]]:
    """Load executable metadata once and surface malformed contracts."""
    from lightbulb.executable_primitives import default_primitive_registry

    return {
        contract["primitive_ref"]: contract
        for contract in default_primitive_registry().catalog()
    }


def _business_primitive_capability_projection(
    primitive: BusinessPrimitive,
    implementation: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Project one primitive into an agent-discoverable execution descriptor.

    The catalog remains the source of business semantics and governance. When a
    typed SDK implementation exists, this projection adds its exact Pydantic
    schemas and routes execution through the generic SDK primitive runner. No
    connector credential, tenant identifier, or caller-supplied authority is
    included in the descriptor.
    """
    executable = implementation is not None
    execution_target = (
        "run_sdk_business_primitive" if executable else "run_business_primitive"
    )
    input_schema = (
        dict(implementation["input_schema"])
        if implementation is not None
        else _catalog_input_schema(primitive)
    )
    connector_tools = (
        list(implementation.get("connector_tools") or [])
        if implementation is not None
        else list(primitive.connector_tools)
    )
    primitive_annotations = (
        dict(implementation.get("mcp_annotations") or {})
        if implementation is not None
        else {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        }
    )
    search_terms = list(
        dict.fromkeys(
            [
                primitive.id,
                primitive.title,
                primitive.category,
                primitive.summary,
                primitive.description,
                primitive.domain,
                primitive.action,
                *primitive.connector_tools,
                *primitive.setup_requirements,
                *primitive.trigger_events,
                *primitive.emits,
                *primitive.follow_up_primitives,
            ]
        )
    )
    execution: Dict[str, Any] = {
        "target": execution_target,
        "invoker": "lightbulb_use_action_capability",
        "caller_must_preserve": {
            "primitive_id": primitive.id,
            **(
                {"primitive_version": str(implementation["version"])}
                if implementation is not None
                else {}
            ),
        },
        "required_arguments": (["project_ref", "inputs"] if executable else ["inputs"]),
        "defaults": {"preview_only": True},
        "input_encoding": (
            "Encode inputs as a JSON object string matching input_schema."
        ),
        # Both generic runners are intentionally action-classified. The exact
        # primitive effect metadata is separate below so an adaptive host never
        # mistakes a read-only descriptor for execution authority.
        "target_annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "authority": (
            "Authenticated Spring scope is authoritative. project_ref is a "
            "public correlation reference, never tenant or company authority."
        ),
    }
    invocation_arguments: Dict[str, Any] = {
        "primitive_id": primitive.id,
        "inputs": "{...JSON matching input_schema...}",
        "preview_only": True,
    }
    if executable:
        invocation_arguments["primitive_version"] = str(implementation["version"])
        invocation_arguments["project_ref"] = "<public-project-reference>"
    execution["adaptive_invocation"] = {
        "name": execution_target,
        "arguments": invocation_arguments,
        "arguments_json_encoding": (
            "Serialize the entire arguments object as arguments_json for "
            "lightbulb_use_action_capability."
        ),
    }
    if executable and primitive.backbone_fallback_available:
        execution["fallback_target"] = "run_business_primitive"

    return {
        "schema": PRIMITIVE_CAPABILITY_PROJECTION_SCHEMA,
        "kind": "business_process_primitive",
        "capability_name": f"business_primitive.{primitive.id}",
        "primitive_ref": primitive.id,
        "title": primitive.title,
        "summary": primitive.summary,
        "description": primitive.description,
        "category": primitive.category,
        "search_terms": [term for term in search_terms if term],
        "input_schema": input_schema,
        "output_schema": (
            dict(implementation["output_schema"])
            if implementation is not None
            else None
        ),
        "example_inputs": (
            dict(implementation.get("example_inputs") or {})
            if implementation is not None
            else {}
        ),
        "runtime_contract": primitive_runtime_contract(
            primitive,
            include_inputs=True,
        ),
        "implementation": {
            "executable": executable,
            "catalog_backbone_fallback_available": (
                primitive.backbone_fallback_available
            ),
            "version": (
                str(implementation.get("version"))
                if implementation is not None
                else None
            ),
            "connector_tools": connector_tools,
            "primitive_annotations": primitive_annotations,
        },
        "risk": {
            "risk_level": primitive.risk_level,
            "approval_required": primitive.approval_required,
        },
        "execution": execution,
    }


def business_primitive_capability_projection(
    primitive: BusinessPrimitive,
) -> Dict[str, Any]:
    """Project one catalog primitive with its exact executable metadata."""
    implementations = _executable_implementation_contracts()
    return _business_primitive_capability_projection(
        primitive,
        implementations.get(primitive.id),
    )


def business_primitive_capability_projections(
    *,
    category: str | None = None,
    query: str | None = None,
) -> List[Dict[str, Any]]:
    """Return MCP-ready descriptors for matching catalog primitives."""
    matching_ids = {
        row["primitive_ref"]
        for row in list_business_primitives(
            category=category,
            query=query,
            include_inputs=False,
        )
    }
    implementations = _executable_implementation_contracts()
    return [
        _business_primitive_capability_projection(
            primitive,
            implementations.get(primitive.id),
        )
        for primitive in BUSINESS_PRIMITIVES
        if primitive.id in matching_ids
    ]


def _sdk_only_primitive_capability_projection(
    implementation: Dict[str, Any],
) -> Dict[str, Any]:
    """Project one executable-only primitive without inventing Backbone semantics."""

    primitive_ref = str(implementation["primitive_ref"])
    title = str(implementation["title"])
    description = str(implementation.get("description") or title)
    connector_tools = list(implementation.get("connector_tools") or [])
    annotations = dict(implementation.get("mcp_annotations") or {})
    return {
        "schema": PRIMITIVE_CAPABILITY_PROJECTION_SCHEMA,
        "kind": "sdk_business_process_primitive",
        "capability_name": f"business_primitive.{primitive_ref}",
        "primitive_ref": primitive_ref,
        "title": title,
        "summary": description,
        "description": description,
        "category": primitive_ref.partition(".")[0],
        "search_terms": list(
            dict.fromkeys(
                [
                    primitive_ref,
                    title,
                    description,
                    primitive_ref.replace(".", " "),
                    *connector_tools,
                ]
            )
        ),
        "input_schema": dict(implementation["input_schema"]),
        "output_schema": dict(implementation["output_schema"]),
        "example_inputs": dict(implementation.get("example_inputs") or {}),
        "implementation": {
            "executable": True,
            "catalog_backbone_fallback_available": False,
            "version": str(implementation["version"]),
            "connector_tools": connector_tools,
            "primitive_annotations": annotations,
        },
        "risk": {
            "risk_level": str(implementation["risk_level"]),
            "approval_required": bool(implementation["approval_required"]),
        },
        "execution": {
            "target": "run_sdk_business_primitive",
            "invoker": "lightbulb_use_action_capability",
            "caller_must_preserve": {
                "primitive_id": primitive_ref,
                "primitive_version": str(implementation["version"]),
            },
            "required_arguments": ["project_ref", "inputs"],
            "defaults": {"preview_only": True},
            "input_encoding": (
                "Encode inputs as a JSON object string matching input_schema."
            ),
            "target_annotations": {
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": True,
            },
            "authority": (
                "Authenticated Spring scope is authoritative. project_ref is a "
                "public correlation reference, never tenant or company authority."
            ),
            "adaptive_invocation": {
                "name": "run_sdk_business_primitive",
                "arguments": {
                    "primitive_id": primitive_ref,
                    "primitive_version": str(implementation["version"]),
                    "project_ref": "<public-project-reference>",
                    "inputs": "{...JSON matching input_schema...}",
                    "preview_only": True,
                },
                "arguments_json_encoding": (
                    "Serialize the entire arguments object as arguments_json for "
                    "lightbulb_use_action_capability."
                ),
            },
        },
    }


def sdk_only_business_primitive_capability_projections() -> List[Dict[str, Any]]:
    """Expose typed SDK primitives that intentionally lack Backbone catalog routes.

    This keeps proposal-only or otherwise SDK-local implementations discoverable
    without creating a misleading fallback to a domain agent that does not
    implement the same contract.
    """

    catalog_refs = {primitive.id for primitive in BUSINESS_PRIMITIVES}
    implementations = _executable_implementation_contracts()
    return [
        _sdk_only_primitive_capability_projection(implementations[primitive_ref])
        for primitive_ref in sorted(set(implementations) - catalog_refs)
    ]


def build_business_primitive_execution(
    primitive_id: str,
    inputs: Dict[str, Any] | None = None,
    *,
    source: str = "sdk",
    mode: str | None = None,
    preview_only: bool = True,
) -> tuple[BusinessPrimitive, Dict[str, Any]]:
    primitive = get_business_primitive(primitive_id)
    if not primitive.backbone_fallback_available:
        raise ValueError(
            f"primitive {primitive.id!r} has no Backbone fallback; "
            "use its typed SDK execution target"
        )
    if inputs is not None and not isinstance(inputs, dict):
        raise ValueError("inputs must be a JSON object")
    clean_inputs = dict(inputs or {})
    execution_mode = (
        str(mode or clean_inputs.get("mode") or primitive.default_mode).strip()
        or primitive.default_mode
    )
    runtime_contract = primitive_runtime_contract(primitive, include_inputs=True)
    payload: Dict[str, Any] = {
        "schema": EXECUTION_SCHEMA,
        "action": "execute",
        "contract_schema": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
        "primitive": primitive.to_dict(include_inputs=True),
        "primitive_id": primitive.id,
        "primitive_ref": primitive.id,
        "primitive_runtime_contract": runtime_contract,
        "category": primitive.category,
        "mode": execution_mode,
        "preview_only": bool(preview_only),
        "source": str(source or "sdk").strip() or "sdk",
        "requested_inputs": clean_inputs,
        "routing": {
            "preferred_domain_action": (
                {
                    "domain": primitive.domain,
                    "action": primitive.action,
                }
                if primitive.domain
                else None
            ),
            "preferred_connector_tools": list(primitive.connector_tools),
        },
        "execution_policy": {
            "use_lightbulb_tenant_company_rbac": True,
            "use_existing_connectors": True,
            "consequential_writes_require_hitl": primitive.approval_required,
            "direct_connector_write_without_approval": False,
            "return_pending_approval_when_required": True,
        },
        "output_contract": {
            "return_status": True,
            "return_draft_or_proposal": True,
            "return_missing_connector_or_permission_blockers": True,
            "do_not_expose_internal_ids": True,
        },
        "observability_contract": runtime_contract["observability_contract"],
        "recovery_contract": runtime_contract["recovery_contract"],
    }
    if payload["routing"]["preferred_domain_action"] is None:
        payload["routing"].pop("preferred_domain_action")
    return primitive, payload


def business_primitive_objective(
    primitive: BusinessPrimitive,
    *,
    request: str = "",
    mode: str = "",
) -> str:
    mode_text = str(mode or primitive.default_mode).strip() or primitive.default_mode
    request_text = str(request or "").strip()
    parts = [
        f"Run the Lightbulb business primitive `{primitive.id}` ({primitive.title}).",
        primitive.summary,
        (
            "Use existing Lightbulb domain agents and connected app connectors as needed, "
            "under the authenticated user's tenant, company, RBAC, rate-limit, and HITL approval rules."
        ),
        (
            "Do not directly mutate external systems unless the platform returns an approved action; "
            "for consequential writes, return a draft, proposal, or pending approval state."
        ),
        f"Requested mode: {mode_text}.",
    ]
    if request_text:
        parts.append(f"User request: {request_text}")
    return " ".join(parts)


def execute_business_primitive(
    client: Any,
    primitive_id: str,
    inputs: Dict[str, Any] | None = None,
    *,
    source: str = "sdk",
    mode: str | None = None,
    preview_only: bool = True,
    request: str = "",
) -> Dict[str, Any]:
    primitive, payload = build_business_primitive_execution(
        primitive_id,
        inputs,
        source=source,
        mode=mode,
        preview_only=preview_only,
    )
    objective = business_primitive_objective(
        primitive,
        request=request,
        mode=str(payload.get("mode") or primitive.default_mode),
    )
    return client.backbone_execute(objective, inputs=payload)


def business_workflow_builder_context(
    objective: str,
    *,
    primitive_ids: Iterable[str] | None = None,
    inputs: Dict[str, Any] | None = None,
    loop: bool = False,
    source: str = "sdk",
) -> Dict[str, Any]:
    selected: List[BusinessPrimitive] = []
    for primitive_id in primitive_ids or []:
        text = str(primitive_id or "").strip()
        if text:
            selected.append(get_business_primitive(text))
    if not selected:
        selected = list(BUSINESS_PRIMITIVES)
    compiler_contract = workflow_compiler_contract(
        objective,
        selected,
        inputs=inputs,
        loop=loop,
        source=source,
    )
    return {
        "schema": WORKFLOW_BUILDER_SCHEMA,
        "contract_schema": WORKFLOW_COMPILER_CONTRACT_SCHEMA,
        "objective": str(objective or "").strip(),
        "source": str(source or "sdk").strip() or "sdk",
        "loop_requested": bool(loop),
        "business_primitives": [
            primitive.to_dict(include_inputs=True) for primitive in selected
        ],
        "workflow_compiler_contract": compiler_contract,
        "builder_policy": {
            "compose_from_primitives": True,
            "include_hidden_setup_steps": True,
            "include_webhooks_or_polling_watchers": True,
            "include_response_context_capture": True,
            "include_state_machine": True,
            "include_idempotency_and_retry_policy": True,
            "include_human_approval_gates_for_consequential_writes": True,
            "prefer_agentic_loop_when_trigger_response_followup_cycle_exists": bool(
                loop
            ),
            "do_not_require_user_to_name_technical_infrastructure": True,
        },
        "examples_of_hidden_setup": [
            "If the workflow sends email, add reply webhook/watch or polling fallback, thread context, and reply classification.",
            "If the workflow creates invoices, add invoice status sync for paid, overdue, voided, and disputed states.",
            "If the workflow drafts or sends contracts, add document storage, review approval, and signature/counterparty response tracking.",
            "If the workflow schedules meetings, add invite response tracking and a no-response branch.",
        ],
        "input_contract": _workflow_input_metadata(inputs),
    }


def workflow_compiler_contract(
    objective: str,
    primitives: Iterable[BusinessPrimitive],
    *,
    inputs: Dict[str, Any] | None = None,
    loop: bool = False,
    source: str = "sdk",
) -> Dict[str, Any]:
    """Return the versioned contract Agent Builder must satisfy when composing primitives."""
    selected = list(primitives)
    primitive_refs = [primitive.id for primitive in selected]
    setup_requirements = _unique(
        requirement
        for primitive in selected
        for requirement in primitive.setup_requirements
    )
    trigger_events = _unique(
        event for primitive in selected for event in primitive.trigger_events
    )
    emitted_events = _unique(
        event for primitive in selected for event in primitive.emits
    )
    follow_up_primitives = _unique(
        primitive_ref
        for primitive in selected
        for primitive_ref in primitive.follow_up_primitives
    )
    return {
        "schema": WORKFLOW_COMPILER_CONTRACT_SCHEMA,
        "version": "1.0",
        "objective": str(objective or "").strip(),
        "source": str(source or "sdk").strip() or "sdk",
        "compiler": "lightbulb.agent_builder",
        "workflow_type": "business_primitive_workflow",
        "loop_requested": bool(loop),
        "primitive_refs": primitive_refs,
        "primitive_runtime_contract_schema": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
        "primitive_runtime_contracts": [
            primitive_runtime_contract(primitive, include_inputs=True)
            for primitive in selected
        ],
        "compiler_requirements": {
            "sequence_primitives_by_business_state": True,
            "infer_hidden_setup_from_primitive_contracts": True,
            "set_up_webhooks_or_polling_watchers_when_events_require_them": True,
            "capture_response_context_for_external_threads": True,
            "add_human_approval_gates_for_consequential_writes": True,
            "prefer_existing_domain_agents_and_connector_adapters": True,
            "use_coding_agent_only_for_missing_adapters_or_new_primitive_implementation": True,
            "publish_only_after_validation_and_required_approval": True,
        },
        "hidden_infrastructure_contract": {
            "setup_requirements": setup_requirements,
            "user_visible_jargon_allowed": False,
            "compiler_must_add_missing_watchers_or_context_stores": True,
        },
        "state_contract": {
            "trigger_events": trigger_events,
            "handled_events": emitted_events,
            "terminal_states": [
                "completed",
                "blocked",
                "cancelled",
                "needs_input",
                "needs_approval",
            ],
            "must_model_event_to_primitive_transitions": True,
        },
        "loop_contract": {
            "prefer_agentic_loop": bool(loop),
            "loop_candidates": follow_up_primitives,
            "must_define_continue_pause_escalate_conditions": True,
        },
        "risk_contract": {
            "combined_risk_level": _combined_risk_level(selected),
            "approval_required": any(
                primitive.approval_required for primitive in selected
            ),
            "direct_connector_write_without_approval": False,
            "respect_tenant_company_scope": True,
            "respect_rbac": True,
        },
        "observability_contract": {
            "must_emit_workflow_trace": True,
            "must_record_primitive_run_refs": True,
            "must_record_approval_refs": True,
            "must_record_external_event_refs": True,
            "must_preserve_business_evidence_for_each_transition": True,
            "must_not_expose_internal_ids_to_end_user": True,
        },
        "acceptance_contract": {
            "workflow_has_named_trigger": True,
            "workflow_has_ordered_primitive_steps": True,
            "workflow_has_hidden_setup_steps": bool(setup_requirements),
            "workflow_has_state_machine": True,
            "workflow_has_retry_and_idempotency_policy": True,
            "workflow_has_test_plan": True,
            "workflow_has_owner_or_approval_policy": True,
        },
        "input_contract": _workflow_input_metadata(inputs),
    }


def recommend_business_primitives(
    objective: str,
    *,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Rank catalog primitives for a plain-language business objective.

    This is deterministic catalog matching, not an LLM decision. It gives
    external harnesses a safe starting point while keeping the final primitive
    selection explicit and inspectable.
    """
    clean_objective = str(objective or "").strip()
    if not clean_objective:
        raise ValueError("objective is required")
    try:
        clean_limit = max(1, min(int(limit), len(BUSINESS_PRIMITIVES)))
    except (TypeError, ValueError):
        clean_limit = min(5, len(BUSINESS_PRIMITIVES))

    terms = _meaningful_terms(clean_objective)
    ranked: List[tuple[int, int, BusinessPrimitive, List[str]]] = []
    for catalog_position, primitive in enumerate(BUSINESS_PRIMITIVES):
        weighted_fields = (
            (primitive.title, 6),
            (primitive.id.replace(".", " ").replace("_", " "), 5),
            (primitive.summary, 3),
            (primitive.description, 2),
            (" ".join(primitive.trigger_events), 2),
            (" ".join(primitive.emits), 2),
            (" ".join(primitive.follow_up_primitives), 1),
            (" ".join(primitive.connector_tools), 1),
        )
        score = 0
        matched: List[str] = []
        for text, weight in weighted_fields:
            field_terms = _meaningful_terms(text)
            overlap = sorted(terms.intersection(field_terms))
            if overlap:
                score += weight * len(overlap)
                matched.extend(overlap)
        if score:
            ranked.append((score, catalog_position, primitive, _unique(matched)))

    ranked.sort(key=lambda row: (-row[0], row[1]))
    return [
        {
            "primitive_ref": primitive.id,
            "title": primitive.title,
            "category": primitive.category,
            "score": score,
            "matched_terms": matched,
            "approval_required": primitive.approval_required,
        }
        for score, _, primitive, matched in ranked[:clean_limit]
    ]


def _normalize_loop_iterations(loop: bool, max_iterations: int | None) -> int:
    if max_iterations is None:
        return _DEFAULT_LOOP_ITERATIONS if loop else 1
    if isinstance(max_iterations, bool) or not isinstance(max_iterations, int):
        raise ValueError("max_iterations must be an integer")
    if not 1 <= max_iterations <= _MAX_LOOP_ITERATIONS:
        raise ValueError(f"max_iterations must be between 1 and {_MAX_LOOP_ITERATIONS}")
    if not loop and max_iterations != 1:
        raise ValueError("max_iterations greater than 1 requires loop=True")
    return max_iterations


def compile_business_workflow_definition(
    objective: str,
    *,
    primitive_ids: Iterable[str] | None = None,
    inputs: Dict[str, Any] | None = None,
    workflow_name: str | None = None,
    workflow_type: str | None = None,
    trigger_event: str | None = None,
    owner_role: str = "workflow_owner",
    loop: bool = False,
    max_iterations: int | None = None,
    source: str = "sdk",
) -> Dict[str, Any]:
    """Compile primitives into a portable, validated draft workflow definition."""
    clean_objective = str(objective or "").strip()
    if not clean_objective:
        raise ValueError("objective is required")
    if inputs is not None and not isinstance(inputs, dict):
        raise ValueError("inputs must be a JSON object")
    workflow_input_contract = _workflow_input_metadata(inputs)
    workflow_input_keys = list(workflow_input_contract["keys"])
    provided_input_keys = set(workflow_input_contract["provided_keys"])

    requested_refs = _unique(str(value or "").strip() for value in primitive_ids or [])
    recommendations: List[Dict[str, Any]] = []
    if not requested_refs:
        recommendations = recommend_business_primitives(clean_objective)
        requested_refs = [row["primitive_ref"] for row in recommendations]
    if not requested_refs:
        raise ValueError(
            "No business primitives matched the objective; call list_business_primitives "
            "and provide primitive_ids explicitly"
        )

    selected = [
        get_business_primitive(primitive_ref) for primitive_ref in requested_refs
    ]
    sdk_only_refs = [
        primitive.id
        for primitive in selected
        if not primitive.backbone_fallback_available
    ]
    if sdk_only_refs:
        raise ValueError(
            "These primitives have no Backbone workflow executor: "
            f"{', '.join(sdk_only_refs)}. Run them through the typed SDK "
            "ProjectRuntime instead of compiling an invented Backbone step."
        )
    name = str(workflow_name or "").strip() or _default_workflow_name(clean_objective)
    workflow_key = _slugify(str(workflow_type or "").strip() or name)
    owner = str(owner_role or "").strip() or "workflow_owner"
    loop_iterations = _normalize_loop_iterations(loop, max_iterations)
    first_trigger = str(trigger_event or "").strip()
    if not first_trigger:
        first_trigger = next(iter(selected[0].trigger_events), "manual.requested")

    step_triggers = [first_trigger]
    for previous, current in zip(selected, selected[1:]):
        shared_event = next(
            (event for event in previous.emits if event in current.trigger_events),
            "",
        )
        step_triggers.append(
            shared_event or f"workflow.step.{len(step_triggers):02d}.completed"
        )

    steps: List[Dict[str, Any]] = []
    for index, primitive in enumerate(selected, start=1):
        runtime_contract = primitive_runtime_contract(primitive, include_inputs=True)
        step_id = _workflow_step_id(index, primitive.id)
        next_event = (
            step_triggers[index]
            if index < len(selected)
            else f"workflow.step.{index:02d}.completed"
        )
        required_fields = runtime_contract["input_contract"]["required_fields"]
        preferred_domain_action = runtime_contract["execution_contract"].get(
            "preferred_domain_action"
        )
        if primitive.approval_required:
            approval_step_id = f"approve_{step_id}"
            steps.append(
                {
                    "id": approval_step_id,
                    "name": f"Approve {primitive.title}",
                    "type": "hitl_step",
                    "hitl_queue": owner,
                    "primitive_ref": primitive.id,
                    "trigger_event": step_triggers[index - 1],
                    "success_event": "approval.approved",
                    "config": {
                        "reason": (
                            f"{primitive.title} can create an external, financial, or otherwise "
                            "consequential side effect and requires explicit human approval."
                        ),
                        "primitive_ref": primitive.id,
                        "owner_role": owner,
                    },
                    # A rejected approval must terminate instead of falling through to the
                    # consequential action. WorkflowOrchestrator evaluates these against the
                    # approval decision payload before selecting the next step.
                    "transitions": [
                        {
                            "to": step_id,
                            "condition": "$.payload.outputs.approved == true",
                        },
                        {
                            "to": "end",
                            "condition": "$.payload.outputs.rejected == true",
                        },
                    ],
                    "approval_gate": {
                        "required": True,
                        "policy": "lightbulb_hitl",
                        "owner_role": owner,
                        "rejection_state": "blocked",
                    },
                }
            )

        # A workflow version is immutable and broadly inspectable by authorized
        # operators, so compile-time values must never be copied into its step
        # config. The runtime supplies values through input_mapping from the
        # workflow instance; only key/schema metadata is retained in the draft.
        step_config: Dict[str, Any] = {
            "action": "execute",
            "objective": business_primitive_objective(
                primitive,
                request=clean_objective,
                mode=primitive.default_mode,
            ),
            "schema": EXECUTION_SCHEMA,
            "contract_schema": PRIMITIVE_RUNTIME_CONTRACT_SCHEMA,
            "primitive_id": primitive.id,
            "primitive_ref": primitive.id,
            "mode": primitive.default_mode,
            # Backbone's governed action=execute route is always a provider-free
            # typed preview. Approved connector writes use the separate hosted
            # SDK runtime, including for otherwise low-risk primitives.
            "preview_only": True,
            "preferred_domain_action": preferred_domain_action,
            "connector_hints": list(primitive.connector_tools),
            "primitive_runtime_contract": runtime_contract,
            "approval_required": primitive.approval_required,
            "execution_policy": {
                "use_lightbulb_tenant_company_rbac": True,
                "use_existing_connectors": True,
                "consequential_writes_require_hitl": primitive.approval_required,
                "direct_connector_write_without_approval": False,
                "return_pending_approval_when_required": True,
            },
        }
        executable_input_fields = _registered_executable_input_fields(primitive.id)
        step_workflow_input_keys = [
            field_name
            for field_name in workflow_input_keys
            if executable_input_fields is None or field_name in executable_input_fields
        ]
        mapped_input_fields = list(
            dict.fromkeys([*required_fields, *step_workflow_input_keys])
        )
        steps.append(
            {
                "id": step_id,
                "name": primitive.title,
                "type": "agent_step",
                "agent_name": "backbone_agent",
                "reasoning_mode": "plan_execute",
                "requires_approval": primitive.approval_required,
                "primitive_ref": primitive.id,
                "title": primitive.title,
                "trigger_event": step_triggers[index - 1],
                "success_event": next_event,
                "emits": list(primitive.emits),
                # WorkflowDefinitionService requires mapping values to be JSON paths.
                # Rich input metadata lives under input_contract so the portable
                # executable projection can pass the server gate without retaining values.
                "input_mapping": {
                    field_name: f"$.payload.inputs.{field_name}"
                    for field_name in mapped_input_fields
                },
                "input_contract": {
                    "source": "workflow.inputs",
                    "required_fields": required_fields,
                    "mapped_fields": mapped_input_fields,
                    "provided_fields": [
                        field_name
                        for field_name in mapped_input_fields
                        if field_name in provided_input_keys
                    ],
                    "additional_inputs_allowed": True,
                    "runtime_value_source": "workflow_instance.inputs",
                    "values_persisted": False,
                },
                "config": step_config,
                "execution": {
                    "executor": "backbone_domain_agent",
                    "preferred_domain_action": preferred_domain_action,
                    "connector_hints": list(primitive.connector_tools),
                    "default_mode": primitive.default_mode,
                    "raw_connector_bypass_allowed": False,
                },
                "approval_gate": {
                    "required": primitive.approval_required,
                    "policy": (
                        "lightbulb_hitl"
                        if primitive.approval_required
                        else "not_required"
                    ),
                    "owner_role": owner,
                    "rejection_state": "blocked",
                },
                "recovery": dict(runtime_contract["recovery_contract"]),
                "acceptance": dict(runtime_contract["acceptance_contract"]),
            }
        )

    bounded_loop_contract: Dict[str, Any] | None = None
    if loop:
        transition_budget = len(steps) * loop_iterations
        if transition_budget > _MAX_WORKFLOW_STEP_TRANSITIONS:
            raise ValueError(
                "bounded loop requires "
                f"{transition_budget} step transitions, exceeding the "
                f"{_MAX_WORKFLOW_STEP_TRANSITIONS}-transition runtime limit"
            )
        bounded_loop_contract = {
            "schema": BOUNDED_WORKFLOW_LOOP_SCHEMA,
            "enabled": True,
            "max_iterations": loop_iterations,
            "max_step_transitions": transition_budget,
            "entry_step_id": steps[0]["id"],
            "back_edge_from_step_id": steps[-1]["id"],
            "continue_condition": _LOOP_CONTINUE_CONDITION,
            "exit_condition": _LOOP_EXIT_CONDITION,
            "exhaustion_policy": _LOOP_EXHAUSTION_POLICY,
        }

    # Materialize the executable transition graph only after approval steps
    # have been inserted. A loop has one exact back edge from the final action
    # to the workflow entry and one unconditional terminal fallback. Spring
    # persists and independently validates the mirrored bounded-loop contract.
    for position, step in enumerate(steps, start=1):
        step["position"] = position
        if step.get("type") != "hitl_step":
            if position < len(steps):
                step["next"] = steps[position]["id"]
            elif bounded_loop_contract is not None:
                step["transitions"] = [
                    {
                        "to": bounded_loop_contract["entry_step_id"],
                        "condition": bounded_loop_contract["continue_condition"],
                    },
                    {
                        "to": "end",
                        "condition": bounded_loop_contract["exit_condition"],
                    },
                ]
            else:
                step["next"] = "end"

    hidden_infrastructure = _hidden_infrastructure(selected)
    compiler_contract = workflow_compiler_contract(
        clean_objective,
        selected,
        inputs=inputs,
        loop=loop,
        source=source,
    )
    definition: Dict[str, Any] = {
        "schema": WORKFLOW_DEFINITION_SCHEMA,
        "version": "1.0",
        "workflow_key": workflow_key,
        "workflow_type": str(workflow_type or "").strip()
        or "business_primitive_workflow",
        "name": name,
        "objective": clean_objective,
        "status": "draft",
        "source": str(source or "sdk").strip() or "sdk",
        "primitive_refs": [primitive.id for primitive in selected],
        "scope_contract": {
            "tenant_scope_required": True,
            "company_scope_required": True,
            "rbac_enforced_by_control_plane": True,
            "scope_ids_embedded": False,
        },
        "trigger": {
            "type": "event",
            "event": first_trigger,
        },
        "triggers": [
            {
                "type": "event",
                "event": first_trigger,
            }
        ],
        "input_contract": workflow_input_contract,
        "steps": steps,
        "defaults": {
            "max_depth": (
                bounded_loop_contract["max_step_transitions"]
                if bounded_loop_contract is not None
                else 20
            ),
            "max_cost_usd": 2.0,
            "max_iterations": loop_iterations,
            "timeout_seconds": 300,
            "fail_closed_on_missing_approval": True,
            "loop_requested": bool(loop),
            **(
                {"bounded_loop": dict(bounded_loop_contract)}
                if bounded_loop_contract is not None
                else {}
            ),
        },
        "hidden_infrastructure": hidden_infrastructure,
        "state_machine": _workflow_state_machine(steps, bounded_loop_contract),
        "loop_contract": {
            "schema": BOUNDED_WORKFLOW_LOOP_SCHEMA,
            "enabled": bool(loop),
            "max_iterations": loop_iterations,
            "max_step_transitions": (
                bounded_loop_contract["max_step_transitions"]
                if bounded_loop_contract is not None
                else 1
            ),
            "entry_step_id": (
                bounded_loop_contract["entry_step_id"]
                if bounded_loop_contract is not None
                else None
            ),
            "back_edge_from_step_id": (
                bounded_loop_contract["back_edge_from_step_id"]
                if bounded_loop_contract is not None
                else None
            ),
            "continue_condition": _LOOP_CONTINUE_CONDITION if loop else None,
            "exit_condition": _LOOP_EXIT_CONDITION if loop else None,
            "exhaustion_policy": _LOOP_EXHAUSTION_POLICY if loop else None,
            "continue_when": [_LOOP_CONTINUE_CONDITION] if loop else [],
            "pause_when": ["required approval is pending", "required input is missing"],
            "escalate_when": [
                "retry budget is exhausted",
                "policy or connector readiness blocks execution",
                "the bounded iteration limit is exhausted",
            ],
            "simulation_mode": "bounded_deterministic",
        },
        "risk_contract": {
            "combined_risk_level": _combined_risk_level(selected),
            "approval_required": any(
                primitive.approval_required for primitive in selected
            ),
            "direct_connector_write_without_approval": False,
            "respect_tenant_company_scope": True,
            "respect_rbac": True,
        },
        "observability_contract": {
            "emit_workflow_trace": True,
            "record_primitive_run_refs": True,
            "record_approval_refs": True,
            "record_external_event_refs": True,
            "preserve_transition_evidence": True,
            "must_not_expose": [
                "tenant_id",
                "company_id",
                "workflow_instance_id",
                "trace_id",
                "connector_secret",
            ],
        },
        "test_plan": {
            "simulator": "lightbulb.simulate_business_workflow",
            "scenarios": _workflow_test_scenarios(selected, first_trigger),
            "publish_gate": "validation_passes_and_required_human_approval_is_recorded",
        },
        "authoring_contract": {
            "sdk_is_source_of_truth": True,
            "mcp_is_thin_adapter": True,
            "extend_sdk_catalog_before_exposing_new_mcp_primitive": True,
            "publish_requires_server_side_validation": True,
            "publish_exact_executable_projection": True,
            "executable_projection_fields": [
                "name",
                "workflow_type",
                "objective_as_description",
                "steps",
                "triggers",
                "defaults",
            ],
            "source_metadata_persisted": False,
            "metadata_not_persisted": True,
            "governed_author_endpoint": "/api/workflow-designer/author",
        },
        "compiler_contract": compiler_contract,
    }
    if recommendations:
        definition["primitive_recommendations"] = recommendations

    validation = validate_business_workflow_definition(definition)
    blocking_errors = list(validation["errors"])
    if blocking_errors:
        errors = ", ".join(error["code"] for error in blocking_errors)
        raise ValueError(f"compiled workflow failed validation: {errors}")
    definition["validation"] = {
        "schema": WORKFLOW_VALIDATION_SCHEMA,
        "valid": validation["valid"],
        "errors": validation["errors"],
        "warnings": validation["warnings"],
        "source": "sdk_business_workflow_preflight",
        "error_count": len(validation["errors"]),
        "warning_count": len(validation["warnings"]),
    }
    return definition


def validate_business_workflow_definition(definition: Any) -> Dict[str, Any]:
    """Validate a workflow draft without making network calls or changing state."""
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []
    checks: Dict[str, bool] = {}
    if not isinstance(definition, dict):
        _add_contract_issue(
            errors, "definition_type", "$", "workflow definition must be a JSON object"
        )
        return _workflow_validation_result({}, errors, warnings, checks)

    checks["schema"] = definition.get("schema") == WORKFLOW_DEFINITION_SCHEMA
    if not checks["schema"]:
        _add_contract_issue(
            errors,
            "schema_mismatch",
            "schema",
            f"schema must be {WORKFLOW_DEFINITION_SCHEMA}",
        )

    for key in ("workflow_key", "name", "objective"):
        checks[key] = bool(str(definition.get(key) or "").strip())
        if not checks[key]:
            _add_contract_issue(errors, f"{key}_required", key, f"{key} is required")

    primitive_refs = definition.get("primitive_refs")
    refs_valid = isinstance(primitive_refs, list) and bool(primitive_refs)
    checks["primitive_refs"] = refs_valid
    if not refs_valid:
        _add_contract_issue(
            errors,
            "primitive_refs_required",
            "primitive_refs",
            "primitive_refs must be a non-empty array",
        )
        primitive_refs = []
    normalized_refs = [normalize_primitive_id(value) for value in primitive_refs]
    if len(normalized_refs) != len(set(normalized_refs)):
        _add_contract_issue(
            errors,
            "duplicate_primitive_ref",
            "primitive_refs",
            "primitive_refs must not contain duplicates",
        )
    for index, primitive_ref in enumerate(normalized_refs):
        if primitive_ref not in _PRIMITIVES_BY_ID:
            _add_contract_issue(
                errors,
                "unknown_primitive_ref",
                f"primitive_refs[{index}]",
                f"unknown business primitive: {primitive_ref}",
            )

    scope = definition.get("scope_contract")
    required_scope = {
        "tenant_scope_required": True,
        "company_scope_required": True,
        "rbac_enforced_by_control_plane": True,
        "scope_ids_embedded": False,
    }
    checks["scope_contract"] = isinstance(scope, dict) and all(
        scope.get(key) is value for key, value in required_scope.items()
    )
    if not checks["scope_contract"]:
        _add_contract_issue(
            errors,
            "scope_contract_invalid",
            "scope_contract",
            "tenant/company scope and RBAC must be required without embedding scope IDs",
        )

    workflow_inputs = definition.get("input_contract")
    workflow_input_keys = (
        list(workflow_inputs.get("keys") or [])
        if isinstance(workflow_inputs, dict)
        else []
    )
    provided_input_keys = (
        list(workflow_inputs.get("provided_keys") or [])
        if isinstance(workflow_inputs, dict)
        else []
    )
    workflow_input_types = (
        workflow_inputs.get("json_types") if isinstance(workflow_inputs, dict) else None
    )
    checks["input_values_not_persisted"] = (
        isinstance(workflow_inputs, dict)
        and definition.get("inputs") is None
        and workflow_inputs.get("values_persisted") is False
        and workflow_inputs.get("runtime_value_source") == "workflow_instance.inputs"
        and all(
            isinstance(key, str)
            and bool(_WORKFLOW_INPUT_KEY_RE.fullmatch(key))
            and not _workflow_input_key_is_sensitive(key)
            and key.lower() not in _RESERVED_WORKFLOW_INPUT_KEYS
            for key in workflow_input_keys
        )
        and set(provided_input_keys).issubset(set(workflow_input_keys))
        and isinstance(workflow_input_types, dict)
        and set(workflow_input_types) == set(workflow_input_keys)
    )
    if not checks["input_values_not_persisted"]:
        _add_contract_issue(
            errors,
            "workflow_input_contract_invalid",
            "input_contract",
            "workflow drafts may retain input keys and schema only; values must come from workflow_instance.inputs",
        )

    trigger = definition.get("trigger")
    checks["trigger"] = isinstance(trigger, dict) and bool(
        str(trigger.get("event") or "").strip()
    )
    if not checks["trigger"]:
        _add_contract_issue(
            errors,
            "trigger_required",
            "trigger.event",
            "a named trigger event is required",
        )

    steps = definition.get("steps")
    executable_steps = (
        [
            step
            for step in steps
            if isinstance(step, dict) and step.get("type") == "agent_step"
        ]
        if isinstance(steps, list)
        else []
    )
    checks["steps"] = (
        isinstance(steps, list)
        and bool(steps)
        and len(executable_steps) == len(normalized_refs)
    )
    if not checks["steps"]:
        _add_contract_issue(
            errors,
            "steps_invalid",
            "steps",
            "steps must contain one executable primitive step per primitive_ref",
        )
        steps = steps if isinstance(steps, list) else []

    loop_contract = definition.get("loop_contract")
    loop_enabled = (
        isinstance(loop_contract, dict) and loop_contract.get("enabled") is True
    )
    loop_back_edge_from_step_id = (
        str(loop_contract.get("back_edge_from_step_id") or "") if loop_enabled else ""
    )

    step_ids: List[str] = []
    executable_index = 0
    for index, step in enumerate(steps):
        path = f"steps[{index}]"
        if not isinstance(step, dict):
            _add_contract_issue(errors, "step_type", path, "step must be a JSON object")
            continue
        step_id = str(step.get("id") or "").strip()
        step_ids.append(step_id)
        if not step_id:
            _add_contract_issue(
                errors, "step_id_required", f"{path}.id", "step id is required"
            )
        if step.get("position") != index + 1:
            _add_contract_issue(
                errors,
                "step_position",
                f"{path}.position",
                "step positions must be consecutive",
            )
        primitive_ref = normalize_primitive_id(step.get("primitive_ref"))
        primitive = _PRIMITIVES_BY_ID.get(primitive_ref)
        step_type = step.get("type")
        if step_type == "hitl_step":
            transitions = step.get("transitions")
            transition_pairs = [
                (str(row.get("to") or ""), str(row.get("condition") or ""))
                for row in transitions or []
                if isinstance(row, dict)
            ]
            expected_execution = (
                steps[index + 1]
                if index + 1 < len(steps) and isinstance(steps[index + 1], dict)
                else {}
            )
            expected_execution_id = str(expected_execution.get("id") or "")
            approval_config = step.get("config")
            approval_gate = step.get("approval_gate")
            expected_transition_pairs = {
                (expected_execution_id, "$.payload.outputs.approved == true"),
                ("end", "$.payload.outputs.rejected == true"),
            }
            approval_valid = (
                bool(expected_execution_id)
                and expected_execution.get("type") == "agent_step"
                and expected_execution.get("primitive_ref") == primitive_ref
                and primitive is not None
                and primitive.approval_required
                and step.get("primitive_ref") == primitive.id
                and len(transition_pairs) == 2
                and set(transition_pairs) == expected_transition_pairs
                and bool(str(step.get("hitl_queue") or "").strip())
                and isinstance(approval_config, dict)
                and approval_config.get("primitive_ref") == primitive_ref
                and isinstance(approval_gate, dict)
                and approval_gate.get("required") is True
                and approval_gate.get("policy") == "lightbulb_hitl"
                and approval_gate.get("rejection_state") == "blocked"
            )
            if not approval_valid:
                _add_contract_issue(
                    errors,
                    "executable_approval_gate_required",
                    path,
                    "HITL steps must immediately precede their catalog primitive and route approval to it and rejection to end",
                )
            continue

        expected_ref = (
            normalized_refs[executable_index]
            if executable_index < len(normalized_refs)
            else ""
        )
        executable_index += 1
        catalog_primitive = _PRIMITIVES_BY_ID.get(expected_ref)
        if step.get("primitive_ref") != expected_ref:
            _add_contract_issue(
                errors,
                "step_primitive_order",
                f"{path}.primitive_ref",
                "executable step primitive_ref must match primitive_refs order",
            )
        if step_type != "agent_step" or step.get("agent_name") != "backbone_agent":
            _add_contract_issue(
                errors,
                "server_execution_contract_invalid",
                path,
                "primitive steps must publish as backbone_agent agent_step entries",
            )
        is_loop_back_edge_step = loop_enabled and step_id == loop_back_edge_from_step_id
        if is_loop_back_edge_step:
            expected_loop_transitions = [
                {
                    "to": str(loop_contract.get("entry_step_id") or ""),
                    "condition": str(loop_contract.get("continue_condition") or ""),
                },
                {
                    "to": "end",
                    "condition": str(loop_contract.get("exit_condition") or ""),
                },
            ]
            if (
                step.get("next") is not None
                or step.get("transitions") != expected_loop_transitions
            ):
                _add_contract_issue(
                    errors,
                    "bounded_loop_transition_invalid",
                    path,
                    "the bounded loop back-edge step must expose the exact continue and terminal transitions",
                )
        else:
            expected_next = (
                steps[index + 1].get("id") if index + 1 < len(steps) else "end"
            )
            if step.get("next") != expected_next:
                _add_contract_issue(
                    errors,
                    "server_transition_invalid",
                    f"{path}.next",
                    "step next must point to the following step or end",
                )
        input_mapping = step.get("input_mapping")
        if not isinstance(input_mapping, dict) or any(
            not isinstance(value, str) or not value.startswith("$.payload.inputs.")
            for value in input_mapping.values()
        ):
            _add_contract_issue(
                errors,
                "server_input_mapping_invalid",
                f"{path}.input_mapping",
                "input mapping values must resolve from $.payload.inputs",
            )
        config = step.get("config")
        if (
            not isinstance(config, dict)
            or config.get("action") != "execute"
            or not str(config.get("objective") or "").strip()
        ):
            _add_contract_issue(
                errors,
                "backbone_action_invalid",
                f"{path}.config",
                "Backbone primitive steps require action=execute and a concrete objective",
            )
        if catalog_primitive is not None:
            expected_runtime_contract = primitive_runtime_contract(
                catalog_primitive,
                include_inputs=True,
            )
            expected_preferred_domain_action = expected_runtime_contract[
                "execution_contract"
            ]["preferred_domain_action"]
            expected_execution_policy = {
                "use_lightbulb_tenant_company_rbac": True,
                "use_existing_connectors": True,
                "consequential_writes_require_hitl": catalog_primitive.approval_required,
                "direct_connector_write_without_approval": False,
                "return_pending_approval_when_required": True,
            }
            catalog_config_valid = (
                isinstance(config, dict)
                and config.get("schema") == EXECUTION_SCHEMA
                and config.get("contract_schema") == PRIMITIVE_RUNTIME_CONTRACT_SCHEMA
                and config.get("primitive_id") == catalog_primitive.id
                and config.get("primitive_ref") == catalog_primitive.id
                and config.get("mode") == catalog_primitive.default_mode
                and config.get("preview_only") is True
                and config.get("preferred_domain_action")
                == expected_preferred_domain_action
                and config.get("connector_hints")
                == list(catalog_primitive.connector_tools)
                and config.get("primitive_runtime_contract")
                == expected_runtime_contract
                and config.get("approval_required")
                is catalog_primitive.approval_required
                and config.get("execution_policy") == expected_execution_policy
            )
            if not catalog_config_valid:
                _add_contract_issue(
                    errors,
                    "primitive_catalog_config_mismatch",
                    f"{path}.config",
                    (
                        "primitive config identity, routing, runtime, and risk metadata must "
                        f"exactly match the SDK catalog entry for {catalog_primitive.id}"
                    ),
                )
        if isinstance(config, dict) and (
            "requested_inputs" in config
            or any(field_name in config for field_name in workflow_input_keys)
        ):
            _add_contract_issue(
                errors,
                "workflow_input_values_persisted",
                f"{path}.config",
                "workflow input values must be supplied at runtime, not persisted in step config",
            )
        step_input_contract = step.get("input_contract")
        if (
            not isinstance(step_input_contract, dict)
            or step_input_contract.get("values_persisted") is not False
            or step_input_contract.get("runtime_value_source")
            != "workflow_instance.inputs"
        ):
            _add_contract_issue(
                errors,
                "step_input_contract_invalid",
                f"{path}.input_contract",
                "step inputs must resolve from runtime workflow instance inputs without persisted values",
            )
        execution = step.get("execution")
        if (
            not isinstance(execution, dict)
            or execution.get("executor") != "backbone_domain_agent"
        ):
            _add_contract_issue(
                errors,
                "executor_invalid",
                f"{path}.execution.executor",
                "primitive steps must execute through backbone_domain_agent",
            )
        if (
            not isinstance(execution, dict)
            or execution.get("raw_connector_bypass_allowed") is not False
        ):
            _add_contract_issue(
                errors,
                "raw_connector_bypass_denied",
                f"{path}.execution.raw_connector_bypass_allowed",
                "raw connector bypass must be false",
            )
        gate = step.get("approval_gate")
        if catalog_primitive is not None:
            expected_execution = {
                "executor": "backbone_domain_agent",
                "preferred_domain_action": expected_preferred_domain_action,
                "connector_hints": list(catalog_primitive.connector_tools),
                "default_mode": catalog_primitive.default_mode,
                "raw_connector_bypass_allowed": False,
            }
            if execution != expected_execution:
                _add_contract_issue(
                    errors,
                    "primitive_catalog_execution_mismatch",
                    f"{path}.execution",
                    (
                        "execution metadata must exactly match the SDK catalog entry for "
                        f"{catalog_primitive.id}"
                    ),
                )
            expected_required_fields = expected_runtime_contract["input_contract"][
                "required_fields"
            ]
            executable_input_fields = _registered_executable_input_fields(
                catalog_primitive.id
            )
            expected_workflow_input_keys = [
                field_name
                for field_name in workflow_input_keys
                if executable_input_fields is None
                or field_name in executable_input_fields
            ]
            expected_mapped_fields = list(
                dict.fromkeys(
                    [*expected_required_fields, *expected_workflow_input_keys]
                )
            )
            expected_provided_fields = [
                field_name
                for field_name in expected_mapped_fields
                if field_name in provided_input_keys
            ]
            mapped_fields = (
                step_input_contract.get("mapped_fields")
                if isinstance(step_input_contract, dict)
                else None
            )
            expected_gate_policy = (
                "lightbulb_hitl"
                if catalog_primitive.approval_required
                else "not_required"
            )
            primitive_metadata_valid = (
                step.get("title") == catalog_primitive.title
                and step.get("emits") == list(catalog_primitive.emits)
                and step.get("reasoning_mode") == "plan_execute"
                and step.get("requires_approval") is catalog_primitive.approval_required
                and isinstance(step_input_contract, dict)
                and step_input_contract.get("source") == "workflow.inputs"
                and step_input_contract.get("required_fields")
                == expected_required_fields
                and step_input_contract.get("mapped_fields") == expected_mapped_fields
                and step_input_contract.get("provided_fields")
                == expected_provided_fields
                and step_input_contract.get("additional_inputs_allowed") is True
                and mapped_fields == expected_mapped_fields
                and isinstance(input_mapping, dict)
                and input_mapping
                == {
                    field_name: f"$.payload.inputs.{field_name}"
                    for field_name in expected_mapped_fields
                }
                and isinstance(gate, dict)
                and gate.get("required") is catalog_primitive.approval_required
                and gate.get("policy") == expected_gate_policy
                and bool(str(gate.get("owner_role") or "").strip())
                and gate.get("rejection_state") == "blocked"
                and step.get("recovery")
                == expected_runtime_contract["recovery_contract"]
                and step.get("acceptance")
                == expected_runtime_contract["acceptance_contract"]
            )
            if not primitive_metadata_valid:
                _add_contract_issue(
                    errors,
                    "primitive_catalog_step_mismatch",
                    path,
                    (
                        "step inputs, risk flags, events, recovery, and acceptance metadata "
                        f"must match the SDK catalog entry for {catalog_primitive.id}"
                    ),
                )
        if catalog_primitive and catalog_primitive.approval_required:
            if not isinstance(gate, dict) or gate.get("required") is not True:
                _add_contract_issue(
                    errors,
                    "approval_gate_required",
                    f"{path}.approval_gate.required",
                    f"{expected_ref} requires a human approval gate",
                )
            previous_step = steps[index - 1] if index > 0 else None
            previous_transitions = (
                previous_step.get("transitions")
                if isinstance(previous_step, dict)
                else None
            )
            previous_transition_pairs = [
                (str(row.get("to") or ""), str(row.get("condition") or ""))
                for row in previous_transitions or []
                if isinstance(row, dict)
            ]
            previous_config = (
                previous_step.get("config") if isinstance(previous_step, dict) else None
            )
            previous_gate = (
                previous_step.get("approval_gate")
                if isinstance(previous_step, dict)
                else None
            )
            immediately_preceded_by_approval = (
                isinstance(previous_step, dict)
                and previous_step.get("type") == "hitl_step"
                and previous_step.get("primitive_ref") == catalog_primitive.id
                and isinstance(previous_config, dict)
                and previous_config.get("primitive_ref") == catalog_primitive.id
                and bool(str(previous_step.get("hitl_queue") or "").strip())
                and len(previous_transition_pairs) == 2
                and set(previous_transition_pairs)
                == {
                    (step_id, "$.payload.outputs.approved == true"),
                    ("end", "$.payload.outputs.rejected == true"),
                }
                and isinstance(previous_gate, dict)
                and previous_gate.get("required") is True
                and previous_gate.get("policy") == "lightbulb_hitl"
                and previous_gate.get("rejection_state") == "blocked"
            )
            if not immediately_preceded_by_approval:
                _add_contract_issue(
                    errors,
                    "immediate_hitl_approval_required",
                    path,
                    (
                        f"{catalog_primitive.id} must be immediately preceded by its "
                        "approve/reject HITL step"
                    ),
                )
        if not bool(str(step.get("trigger_event") or "").strip()):
            _add_contract_issue(
                errors,
                "step_trigger_required",
                f"{path}.trigger_event",
                "step trigger is required",
            )
    if len(step_ids) != len(set(step_ids)):
        _add_contract_issue(
            errors, "duplicate_step_id", "steps", "step ids must be unique"
        )

    risk = definition.get("risk_contract")
    checks["risk_contract"] = (
        isinstance(risk, dict)
        and risk.get("direct_connector_write_without_approval") is False
        and risk.get("respect_tenant_company_scope") is True
        and risk.get("respect_rbac") is True
    )
    if not checks["risk_contract"]:
        _add_contract_issue(
            errors,
            "risk_contract_invalid",
            "risk_contract",
            "workflow risk policy must preserve approvals, tenant/company scope, and RBAC",
        )

    hidden = definition.get("hidden_infrastructure")
    hidden_requirements = {
        str(row.get("requirement") or "").strip()
        for row in hidden or []
        if isinstance(row, dict)
    }
    expected_hidden = {
        requirement
        for primitive_ref in normalized_refs
        for requirement in (
            _PRIMITIVES_BY_ID[primitive_ref].setup_requirements
            if primitive_ref in _PRIMITIVES_BY_ID
            else ()
        )
    }
    checks["hidden_infrastructure"] = expected_hidden.issubset(hidden_requirements)
    if not checks["hidden_infrastructure"]:
        missing = sorted(expected_hidden - hidden_requirements)
        _add_contract_issue(
            errors,
            "hidden_infrastructure_missing",
            "hidden_infrastructure",
            "missing setup requirements: " + ", ".join(missing),
        )

    state_machine = definition.get("state_machine")
    checks["state_machine"] = (
        isinstance(state_machine, dict)
        and bool(state_machine.get("states"))
        and bool(state_machine.get("transitions"))
        and state_machine.get("initial_state") == "waiting_for_trigger"
    )
    if not checks["state_machine"]:
        _add_contract_issue(
            errors,
            "state_machine_invalid",
            "state_machine",
            "workflow must include states, transitions, and waiting_for_trigger as its initial state",
        )

    test_plan = definition.get("test_plan")
    checks["test_plan"] = isinstance(test_plan, dict) and bool(
        test_plan.get("scenarios")
    )
    if not checks["test_plan"]:
        _add_contract_issue(
            errors,
            "test_plan_required",
            "test_plan",
            "workflow test scenarios are required",
        )

    authoring = definition.get("authoring_contract")
    checks["authoring_contract"] = (
        isinstance(authoring, dict)
        and authoring.get("sdk_is_source_of_truth") is True
        and authoring.get("mcp_is_thin_adapter") is True
        and authoring.get("publish_exact_executable_projection") is True
        and authoring.get("source_metadata_persisted") is False
        and authoring.get("metadata_not_persisted") is True
        and authoring.get("governed_author_endpoint") == "/api/workflow-designer/author"
    )
    if not checks["authoring_contract"]:
        _add_contract_issue(
            errors,
            "authoring_contract_invalid",
            "authoring_contract",
            "workflow authoring must preserve the exact executable projection without claiming source metadata persistence",
        )

    defaults = definition.get("defaults")
    persisted_loop_contract = (
        defaults.get("bounded_loop") if isinstance(defaults, dict) else None
    )
    first_step_id = (
        str(steps[0].get("id") or "") if steps and isinstance(steps[0], dict) else ""
    )
    last_step_id = (
        str(steps[-1].get("id") or "") if steps and isinstance(steps[-1], dict) else ""
    )
    loop_bound = (
        loop_contract.get("max_iterations") if isinstance(loop_contract, dict) else None
    )
    loop_bound_valid = (
        isinstance(loop_bound, int)
        and not isinstance(loop_bound, bool)
        and 1 <= loop_bound <= _MAX_LOOP_ITERATIONS
    )
    transition_budget = len(steps) * loop_bound if loop_bound_valid else 0
    expected_persisted_loop_contract = {
        "schema": BOUNDED_WORKFLOW_LOOP_SCHEMA,
        "enabled": True,
        "max_iterations": loop_bound,
        "max_step_transitions": transition_budget,
        "entry_step_id": first_step_id,
        "back_edge_from_step_id": last_step_id,
        "continue_condition": _LOOP_CONTINUE_CONDITION,
        "exit_condition": _LOOP_EXIT_CONDITION,
        "exhaustion_policy": _LOOP_EXHAUSTION_POLICY,
    }
    if loop_enabled:
        bounded_loop_valid = (
            loop_bound_valid
            and transition_budget <= _MAX_WORKFLOW_STEP_TRANSITIONS
            and isinstance(loop_contract, dict)
            and loop_contract.get("schema") == BOUNDED_WORKFLOW_LOOP_SCHEMA
            and loop_contract.get("max_step_transitions") == transition_budget
            and loop_contract.get("entry_step_id") == first_step_id
            and loop_contract.get("back_edge_from_step_id") == last_step_id
            and loop_contract.get("continue_condition") == _LOOP_CONTINUE_CONDITION
            and loop_contract.get("exit_condition") == _LOOP_EXIT_CONDITION
            and loop_contract.get("exhaustion_policy") == _LOOP_EXHAUSTION_POLICY
            and loop_contract.get("simulation_mode") == "bounded_deterministic"
            and bool(loop_contract.get("pause_when"))
            and bool(loop_contract.get("escalate_when"))
            and persisted_loop_contract == expected_persisted_loop_contract
            and isinstance(defaults, dict)
            and defaults.get("loop_requested") is True
            and defaults.get("max_iterations") == loop_bound
            and defaults.get("max_depth") == transition_budget
            and last_step_id == loop_back_edge_from_step_id
        )
        checks["bounded_loop_contract"] = bounded_loop_valid
        if not bounded_loop_valid:
            _add_contract_issue(
                errors,
                "bounded_loop_contract_invalid",
                "loop_contract",
                "loops require one versioned persisted bound, exact back edge, terminal fallback, transition budget, and fail-closed exhaustion policy",
            )
    else:
        non_loop_contract_valid = (
            isinstance(loop_contract, dict)
            and loop_contract.get("schema") == BOUNDED_WORKFLOW_LOOP_SCHEMA
            and loop_contract.get("enabled") is False
            and loop_contract.get("max_iterations") == 1
            and persisted_loop_contract is None
            and isinstance(defaults, dict)
            and defaults.get("loop_requested") is False
            and defaults.get("max_iterations") == 1
        )
        checks["bounded_loop_contract"] = non_loop_contract_valid
        if not non_loop_contract_valid:
            _add_contract_issue(
                errors,
                "bounded_loop_contract_invalid",
                "loop_contract",
                "non-loop workflows must not persist or expose an enabled loop contract",
            )

    return _workflow_validation_result(definition, errors, warnings, checks)


def simulate_business_workflow(
    definition: Any,
    *,
    events: Iterable[str] | None = None,
    approvals: Dict[str, Any] | None = None,
    loop_iterations: int | None = None,
) -> Dict[str, Any]:
    """Dry-run a workflow within its declared bounds without invoking live systems."""
    validation = validate_business_workflow_definition(definition)
    base: Dict[str, Any] = {
        "schema": WORKFLOW_SIMULATION_SCHEMA,
        "workflow_schema": (
            definition.get("schema") if isinstance(definition, dict) else None
        ),
        "workflow_key": (
            definition.get("workflow_key") if isinstance(definition, dict) else None
        ),
        "side_effects": "none_simulation_only",
        "validation": validation,
        "timeline": [],
        "completed_primitive_refs": [],
    }
    if not validation["valid"]:
        base.update(
            {
                "status": "invalid",
                "final_state": "invalid",
                "next_action": "fix validation errors before simulation or publish",
            }
        )
        return base

    loop_contract = definition.get("loop_contract", {})
    loop_enabled = loop_contract.get("enabled") is True
    max_loop_iterations = int(loop_contract.get("max_iterations") or 1)
    requested_iterations = 1 if loop_iterations is None else loop_iterations
    if isinstance(requested_iterations, bool) or not isinstance(
        requested_iterations, int
    ):
        raise ValueError("loop_iterations must be an integer")
    if requested_iterations < 1:
        raise ValueError("loop_iterations must be positive")
    if not loop_enabled and requested_iterations != 1:
        raise ValueError("loop_iterations greater than 1 requires a loop workflow")
    if loop_enabled and requested_iterations > max_loop_iterations + 1:
        raise ValueError(
            "loop_iterations may exceed the compiled max_iterations by at most one "
            "to simulate fail-closed exhaustion"
        )

    trigger_event = str(definition["trigger"]["event"])
    observed_events = _unique(
        str(event or "").strip() for event in events or [trigger_event]
    )
    if trigger_event not in observed_events:
        base.update(
            {
                "status": "waiting_for_trigger",
                "final_state": "waiting_for_trigger",
                "observed_events": observed_events,
                "next_action": f"emit {trigger_event} to start the workflow",
            }
        )
        return base

    approval_map = approvals if isinstance(approvals, dict) else {}
    timeline: List[Dict[str, Any]] = [
        {
            "sequence": 1,
            "event": trigger_event,
            "state": "triggered",
            "evidence": "synthetic_event",
        }
    ]
    completed: List[str] = []
    workflow_input_contract = definition.get("input_contract")
    provided_input_keys = set(
        workflow_input_contract.get("provided_keys") or []
        if isinstance(workflow_input_contract, dict)
        else []
    )
    completed_iterations = 0
    iterations_to_run = min(requested_iterations, max_loop_iterations)
    for iteration in range(1, iterations_to_run + 1):
        approved_primitives: set[str] = set()
        for step in definition["steps"]:
            primitive_ref = step["primitive_ref"]
            step_id = step["id"]
            ready_entry: Dict[str, Any] = {
                "sequence": len(timeline) + 1,
                "event": "workflow.step.ready",
                "state": f"{step_id}.ready",
                "step_id": step_id,
                "primitive_ref": primitive_ref,
                "evidence": "compiled_transition",
            }
            if loop_enabled:
                ready_entry["iteration"] = iteration
            timeline.append(ready_entry)
            if step.get("type") == "hitl_step":
                approval = approval_map.get(step_id, approval_map.get(primitive_ref))
                if approval is not True:
                    approval_entry: Dict[str, Any] = {
                        "sequence": len(timeline) + 1,
                        "event": "primitive.approval_requested",
                        "state": "needs_approval" if approval is None else "blocked",
                        "step_id": step_id,
                        "primitive_ref": primitive_ref,
                        "evidence": "executable_hitl_step",
                    }
                    if loop_enabled:
                        approval_entry["iteration"] = iteration
                    timeline.append(approval_entry)
                    base.update(
                        {
                            "status": (
                                "needs_approval" if approval is None else "blocked"
                            ),
                            "final_state": (
                                "needs_approval" if approval is None else "blocked"
                            ),
                            "observed_events": observed_events,
                            "timeline": timeline,
                            "completed_primitive_refs": completed,
                            "blocked_step": {
                                "id": step_id,
                                "primitive_ref": primitive_ref,
                                "reason": (
                                    "approval_pending"
                                    if approval is None
                                    else "approval_rejected"
                                ),
                            },
                            "next_action": (
                                "record approval and rerun simulation"
                                if approval is None
                                else "review rejection and revise workflow"
                            ),
                        }
                    )
                    if loop_enabled:
                        base.update(
                            {
                                "completed_iterations": completed_iterations,
                                "current_iteration": iteration,
                                "loop_disposition": "paused_within_bound",
                            }
                        )
                    return base
                approved_primitives.add(primitive_ref)
                recorded_entry: Dict[str, Any] = {
                    "sequence": len(timeline) + 1,
                    "event": "primitive.approval_recorded",
                    "state": f"{step_id}.completed",
                    "step_id": step_id,
                    "primitive_ref": primitive_ref,
                    "evidence": "synthetic_human_approval",
                }
                if loop_enabled:
                    recorded_entry["iteration"] = iteration
                timeline.append(recorded_entry)
                continue

            required_fields = list(
                step.get("input_contract", {}).get("required_fields") or []
            )
            missing_fields = [
                field_name
                for field_name in required_fields
                if field_name not in provided_input_keys
            ]
            if missing_fields:
                input_entry: Dict[str, Any] = {
                    "sequence": len(timeline) + 1,
                    "event": "primitive.input_required",
                    "state": "needs_input",
                    "step_id": step_id,
                    "primitive_ref": primitive_ref,
                    "missing_required_fields": missing_fields,
                    "evidence": "compiled_input_contract",
                }
                if loop_enabled:
                    input_entry["iteration"] = iteration
                timeline.append(input_entry)
                base.update(
                    {
                        "status": "needs_input",
                        "final_state": "needs_input",
                        "observed_events": observed_events,
                        "timeline": timeline,
                        "completed_primitive_refs": completed,
                        "blocked_step": {
                            "id": step_id,
                            "primitive_ref": primitive_ref,
                            "reason": "missing_required_input",
                            "missing_required_fields": missing_fields,
                        },
                        "next_action": "provide the missing workflow inputs and rerun simulation",
                    }
                )
                if loop_enabled:
                    base.update(
                        {
                            "completed_iterations": completed_iterations,
                            "current_iteration": iteration,
                            "loop_disposition": "paused_within_bound",
                        }
                    )
                return base
            if (
                step["approval_gate"]["required"]
                and primitive_ref not in approved_primitives
            ):
                approval = approval_map.get(step_id, approval_map.get(primitive_ref))
                if approval is not True:
                    synthetic_entry: Dict[str, Any] = {
                        "sequence": len(timeline) + 1,
                        "event": "primitive.approval_requested",
                        "state": "needs_approval" if approval is None else "blocked",
                        "step_id": step_id,
                        "primitive_ref": primitive_ref,
                        "evidence": "synthetic_approval_gate",
                    }
                    if loop_enabled:
                        synthetic_entry["iteration"] = iteration
                    timeline.append(synthetic_entry)
                    base.update(
                        {
                            "status": (
                                "needs_approval" if approval is None else "blocked"
                            ),
                            "final_state": (
                                "needs_approval" if approval is None else "blocked"
                            ),
                            "observed_events": observed_events,
                            "timeline": timeline,
                            "completed_primitive_refs": completed,
                            "blocked_step": {
                                "id": step_id,
                                "primitive_ref": primitive_ref,
                                "reason": (
                                    "approval_pending"
                                    if approval is None
                                    else "approval_rejected"
                                ),
                            },
                            "next_action": (
                                "record approval and rerun simulation"
                                if approval is None
                                else "review rejection and revise workflow"
                            ),
                        }
                    )
                    if loop_enabled:
                        base.update(
                            {
                                "completed_iterations": completed_iterations,
                                "current_iteration": iteration,
                                "loop_disposition": "paused_within_bound",
                            }
                        )
                    return base
            simulated_entry: Dict[str, Any] = {
                "sequence": len(timeline) + 1,
                "event": "primitive.simulated",
                "state": f"{step_id}.completed",
                "step_id": step_id,
                "primitive_ref": primitive_ref,
                "would_emit": list(step.get("emits") or []),
                "evidence": "no_connector_or_agent_invocation",
            }
            if loop_enabled:
                simulated_entry["iteration"] = iteration
            timeline.append(simulated_entry)
            completed.append(primitive_ref)

        completed_iterations = iteration
        if loop_enabled and iteration < iterations_to_run:
            timeline.append(
                {
                    "sequence": len(timeline) + 1,
                    "event": "workflow.loop.continue_requested",
                    "state": f"{loop_contract['entry_step_id']}.ready",
                    "iteration": iteration,
                    "next_iteration": iteration + 1,
                    "evidence": "synthetic_bounded_loop_instruction",
                }
            )

    if loop_enabled and requested_iterations > max_loop_iterations:
        timeline.append(
            {
                "sequence": len(timeline) + 1,
                "event": "workflow.loop.limit_exhausted",
                "state": "blocked",
                "iteration": completed_iterations,
                "max_iterations": max_loop_iterations,
                "evidence": "compiled_fail_closed_bound",
            }
        )
        base.update(
            {
                "status": "blocked",
                "final_state": "loop_limit_exhausted",
                "observed_events": observed_events,
                "timeline": timeline,
                "completed_primitive_refs": completed,
                "completed_iterations": completed_iterations,
                "loop_disposition": "fail_closed_max_iterations_exhausted",
                "next_action": "review the exhausted run and start a separately authorized workflow if more work is required",
            }
        )
        return base

    if loop_enabled:
        timeline.append(
            {
                "sequence": len(timeline) + 1,
                "event": "workflow.loop.exit",
                "state": "completed",
                "iteration": completed_iterations,
                "evidence": "synthetic_terminal_fallback",
            }
        )

    base.update(
        {
            "status": "completed",
            "final_state": "completed",
            "observed_events": observed_events,
            "timeline": timeline,
            "completed_primitive_refs": completed,
            "loop_disposition": (
                "completed_within_bound" if loop_enabled else "not_a_loop"
            ),
            "next_action": "submit the validated draft for server-side validation and approval before publish",
        }
    )
    if loop_enabled:
        base["completed_iterations"] = completed_iterations
    return base


def business_workflow_builder_prompt(context: Dict[str, Any]) -> str:
    objective = str(context.get("objective") or "").strip()
    loop_text = (
        "Design this as an Agentic loop when the trigger/response/follow-up cycle supports it."
        if context.get("loop_requested")
        else "Design this as an operational workflow; identify whether it should become an Agentic loop."
    )
    return (
        "Use the Lightbulb business primitive catalog as Lego blocks to build an operational agentic workflow. "
        f"Conform to {PRIMITIVE_RUNTIME_CONTRACT_SCHEMA} for every primitive and {WORKFLOW_COMPILER_CONTRACT_SCHEMA} for the workflow. "
        "Choose the correct primitive sequence, add hidden setup the user would not know to request, and preserve "
        "tenant/company/RBAC/HITL behavior. Include triggers, webhook or polling watchers, response context capture, "
        "state transitions, retries, idempotency, approval gates, and follow-up branches. "
        f"{loop_text} "
        f"User objective: {objective}"
    )


def compose_business_workflow(
    client: Any,
    objective: str,
    *,
    primitive_ids: Iterable[str] | None = None,
    inputs: Dict[str, Any] | None = None,
    loop: bool = False,
    max_iterations: int | None = None,
    workflow_name: str | None = None,
    workflow_type: str | None = None,
    trigger_event: str | None = None,
    owner_role: str = "workflow_owner",
    publish: bool = False,
    source: str = "sdk",
) -> Dict[str, Any]:
    definition = compile_business_workflow_definition(
        objective,
        primitive_ids=primitive_ids,
        inputs=inputs,
        workflow_name=workflow_name,
        workflow_type=workflow_type,
        trigger_event=trigger_event,
        owner_role=owner_role,
        loop=loop,
        max_iterations=max_iterations,
        source=source,
    )
    return client.author_agentic_workflow(
        str(objective).strip(),
        name=workflow_name,
        workflow_type=workflow_type,
        include_approval_gates=True,
        publish=publish,
        definition=definition,
    )


def _preferred_domains_for_primitives(
    primitives: Iterable[Dict[str, Any]],
) -> List[str]:
    domains: List[str] = []
    for primitive in primitives:
        category = str(primitive.get("category") or "").strip()
        if category and category not in domains:
            domains.append(category)
        domain_action = primitive.get("preferred_domain_action")
        if isinstance(domain_action, dict):
            domain = str(domain_action.get("domain") or "").strip()
            if domain and domain not in domains:
                domains.append(domain)
    return domains


def _unique(items: Iterable[str]) -> List[str]:
    values: List[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in values:
            values.append(text)
    return values


def _combined_risk_level(primitives: Iterable[BusinessPrimitive]) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    selected = list(primitives)
    if not selected:
        return "low"
    return max(
        (primitive.risk_level for primitive in selected),
        key=lambda level: order.get(str(level), -1),
    )


_TERM_STOP_WORDS = {
    "a",
    "an",
    "and",
    "as",
    "at",
    "be",
    "build",
    "by",
    "for",
    "from",
    "in",
    "into",
    "it",
    "of",
    "on",
    "or",
    "our",
    "the",
    "their",
    "to",
    "when",
    "with",
    "workflow",
}


def _meaningful_terms(value: str) -> set[str]:
    return {
        term
        for term in re.findall(r"[a-z0-9]+", str(value or "").lower())
        if len(term) > 1 and term not in _TERM_STOP_WORDS
    }


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    return slug[:80] or "custom_business_workflow"


def _default_workflow_name(objective: str) -> str:
    words = str(objective or "").strip().split()
    candidate = " ".join(words[:10]).strip(" .,:;-_")
    return (candidate[:72] or "Custom business workflow").capitalize()


def _workflow_step_id(position: int, primitive_ref: str) -> str:
    return f"step_{position:02d}_{_slugify(primitive_ref)}"


def _hidden_infrastructure(
    primitives: Iterable[BusinessPrimitive],
) -> List[Dict[str, Any]]:
    sources: Dict[str, List[str]] = {}
    for primitive in primitives:
        for requirement in primitive.setup_requirements:
            sources.setdefault(requirement, []).append(primitive.id)
    return [
        {
            "requirement": requirement,
            "source_primitive_refs": primitive_refs,
            "user_visible": False,
            "readiness_check_required": True,
        }
        for requirement, primitive_refs in sources.items()
    ]


def _workflow_state_machine(
    steps: Iterable[Dict[str, Any]],
    bounded_loop_contract: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    selected = list(steps)
    states = [
        "waiting_for_trigger",
        "completed",
        "blocked",
        "cancelled",
        "needs_input",
        "needs_approval",
    ]
    transitions: List[Dict[str, str]] = []
    for index, step in enumerate(selected):
        ready_state = f"{step['id']}.ready"
        running_state = f"{step['id']}.running"
        completed_state = f"{step['id']}.completed"
        states.extend([ready_state, running_state, completed_state])
        source_state = (
            "waiting_for_trigger"
            if index == 0
            else f"{selected[index - 1]['id']}.completed"
        )
        transitions.append(
            {
                "from": source_state,
                "on": step["trigger_event"],
                "to": ready_state,
            }
        )
        if step["approval_gate"]["required"]:
            transitions.extend(
                [
                    {
                        "from": ready_state,
                        "on": "approval.required",
                        "to": "needs_approval",
                    },
                    {
                        "from": "needs_approval",
                        "on": "approval.approved",
                        "to": running_state,
                    },
                    {
                        "from": "needs_approval",
                        "on": "approval.rejected",
                        "to": "blocked",
                    },
                ]
            )
        else:
            transitions.append(
                {"from": ready_state, "on": "step.start", "to": running_state}
            )
        transitions.append(
            {"from": running_state, "on": step["success_event"], "to": completed_state}
        )
    if selected and bounded_loop_contract is not None:
        transitions.extend(
            [
                {
                    "from": f"{selected[-1]['id']}.completed",
                    "on": "workflow.loop.continue_requested",
                    "guard": bounded_loop_contract["continue_condition"],
                    "to": f"{selected[0]['id']}.ready",
                },
                {
                    "from": f"{selected[-1]['id']}.completed",
                    "on": "workflow.loop.exit",
                    "guard": bounded_loop_contract["exit_condition"],
                    "to": "completed",
                },
                {
                    "from": f"{selected[-1]['id']}.completed",
                    "on": "workflow.loop.limit_exhausted",
                    "to": "blocked",
                },
            ]
        )
    elif selected:
        transitions.append(
            {
                "from": f"{selected[-1]['id']}.completed",
                "on": "workflow.completed",
                "to": "completed",
            }
        )
    return {
        "initial_state": "waiting_for_trigger",
        "terminal_states": ["completed", "blocked", "cancelled"],
        "states": _unique(states),
        "transitions": transitions,
    }


def _workflow_test_scenarios(
    primitives: Iterable[BusinessPrimitive],
    trigger_event: str,
) -> List[Dict[str, Any]]:
    selected = list(primitives)
    scenarios: List[Dict[str, Any]] = [
        {
            "id": "happy_path",
            "given": [trigger_event, "all required inputs", "all required approvals"],
            "expect": "completed",
        },
        {
            "id": "tenant_or_company_scope_missing",
            "given": ["missing tenant or company execution scope"],
            "expect": "blocked before primitive execution",
        },
        {
            "id": "connector_not_ready",
            "given": ["required connector readiness check fails"],
            "expect": "blocked with setup next action",
        },
        {
            "id": "idempotent_retry",
            "given": ["transient primitive failure"],
            "expect": "bounded retry with the same idempotency key",
        },
    ]
    if any(primitive.approval_required for primitive in selected):
        scenarios.append(
            {
                "id": "approval_pending",
                "given": ["consequential primitive without approval"],
                "expect": "needs_approval with no external write",
            }
        )
    return scenarios


def _add_contract_issue(
    target: List[Dict[str, str]],
    code: str,
    path: str,
    message: str,
) -> None:
    target.append({"code": code, "path": path, "message": message})


def _workflow_validation_result(
    definition: Dict[str, Any],
    errors: List[Dict[str, str]],
    warnings: List[Dict[str, str]],
    checks: Dict[str, bool],
) -> Dict[str, Any]:
    return {
        "schema": WORKFLOW_VALIDATION_SCHEMA,
        "workflow_schema": definition.get("schema"),
        "workflow_key": definition.get("workflow_key"),
        "valid": not errors,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


def compact_inputs(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    """Drop empty optional values while preserving false booleans and numeric zero."""
    compact: Dict[str, Any] = {}
    for key, value in items:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        compact[key] = value
    return compact
