"""Lightbulb MCP exposure for Service Business Operations and Artifact Production.

``register_service_operations(mcp)`` attaches tools and resources to a FastMCP
server.  The final integration commit calls it from ``lightbulb.mcp_server``;
until then it is testable on a standalone ``FastMCP`` instance.

Model-powered generation stays behind the SDK executor interface
(``lightbulb.business_artifact_production.ArtifactGenerationExecutor``).  The
MCP adapter ``McpHostModelDelegationExecutor`` chooses at runtime:

* **tool round-trip** (always available): return the ``HostGenerationTicket``;
  the connected host model produces the sections itself and calls
  ``artifact_submit_generated``;
* **session sampling** (only when the client advertises the sampling
  capability): ask the host model through the session, then validate the
  reply exactly like a submitted round-trip.

Either way the SDK validates the content and returns the artifact candidate
as part of the engagement; no single protocol operation is required by the
business domain.  These tools are local previews: file writes still go
through ``documents.generate_business_artifact`` and Spring approval, and
invoices through ``finance.create_invoice``.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from lightbulb.business_artifact_production import (
    ALLOWED_FORMATS,
    REQUIRED_SECTIONS,
    ArtifactGenerationRequest,
    ArtifactGenerationSubmission,
    GeneratedBusinessArtifact,
    GenerationProvenance,
    HostGenerationTicket,
    LegalDocumentPolicy,
    prepare_business_artifact_generation,
    validate_generated_business_artifact,
)
from lightbulb.service_engagement import (
    TERMINAL_STAGES,
    assess_service_engagement,
    materialize_service_engagement_transition,
    propose_service_engagement_invoice,
)

ARTIFACT_KINDS_RESOURCE = "lightbulb://artifact-production/kinds"
LEGAL_POLICY_SCHEMA_RESOURCE = "lightbulb://artifact-production/legal-policy-schema"
ENGAGEMENT_STAGES_RESOURCE = "lightbulb://service-engagement/stages"
MAX_RESULT_CHARS = 60_000

ENGAGEMENT_STAGES: tuple[str, ...] = (
    "opened",
    "quote_proposed",
    "quote_approved",
    "legal_review",
    "agreement_executed",
    "delivery_planned",
    "delivery_in_progress",
    "accepted",
    "invoiced",
    "paid",
    "closed",
    "cancelled",
)


def _json(payload: Any) -> str:
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(text) > MAX_RESULT_CHARS:
        return json.dumps(
            {"error": "result exceeds the bounded MCP payload; narrow the request", "chars": len(text)},
            separators=(",", ":"),
        )
    return text


def _parse_object(raw: str, field_name: str) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return value


def _error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ()))}: {error.get('msg')}"
            for error in exc.errors(include_url=False, include_input=False)[:8]
        )
        return _json({"error": "validation_error", "detail": detail})
    return _json({"error": type(exc).__name__, "detail": str(exc)[:1000]})


# --------------------------------------------------------------------------- #
# Host-model delegation adapter
# --------------------------------------------------------------------------- #


class McpHostModelDelegationExecutor:
    """SDK executor backed by the connected MCP host model.

    ``generate`` (sync, protocol contract) always defers to a ticket.
    ``generate_async`` may use session sampling when the client advertises it
    and otherwise defers to the same ticket.
    """

    executor_kind = "mcp_host"

    def __init__(self, session: Any | None = None, *, allow_sampling: bool = True, max_tokens: int = 4000) -> None:
        self._session = session
        self._allow_sampling = allow_sampling
        self._max_tokens = max(256, min(max_tokens, 32_000))

    def generate(self, request: ArtifactGenerationRequest) -> HostGenerationTicket:
        if request.host_ticket is None:
            raise ValueError("host-model generation requires a host ticket")
        return request.host_ticket

    def client_supports_sampling(self) -> bool:
        session = self._session
        if session is None or not self._allow_sampling:
            return False
        try:
            from mcp import types

            capability = types.ClientCapabilities(sampling=types.SamplingCapability())
            return bool(session.check_client_capability(capability))
        except Exception:
            return False

    async def generate_async(self, request: ArtifactGenerationRequest) -> ArtifactGenerationSubmission | HostGenerationTicket:
        ticket = self.generate(request)
        if not self.client_supports_sampling():
            return ticket
        try:
            from mcp import types

            prompt = json.dumps(
                {"ticket_ref": ticket.ticket_ref, "brief": ticket.prompt_sections, "response_contract": ticket.response_contract},
                ensure_ascii=False,
            )
            result = await self._session.create_message(
                messages=[types.SamplingMessage(role="user", content=types.TextContent(type="text", text=prompt))],
                max_tokens=self._max_tokens,
                system_prompt=(
                    "You produce business artifact sections for Lightbulb. Return only a JSON object whose "
                    "keys are exactly the required section names and whose values are the section text. "
                    "Use only the amounts in the brief. Never include credentials or legal conclusions."
                ),
            )
            text = getattr(getattr(result, "content", None), "text", None)
            if not isinstance(text, str):
                return ticket
            sections = _sections_from_model_text(text)
            if sections is None:
                return ticket
            provenance = GenerationProvenance(
                generator_kind="host_model",
                host_ref="mcp-session-sampling",
                model_ref=str(getattr(result, "model", "") or "unknown-model")[:200],
                ticket_digest=ticket.ticket_digest,
                generated_at=ticket.issued_at,
            )
            return ArtifactGenerationSubmission(brief_digest=ticket.brief_digest, sections=sections, provenance=provenance)
        except Exception:
            # Sampling is optional; a failed or unsupported attempt never blocks the round-trip path.
            return ticket


def _sections_from_model_text(text: str) -> dict[str, str] | None:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if candidate.lower().startswith("json"):
            candidate = candidate[4:]
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()):
        return None
    return parsed


def _session_from_context(ctx: Any) -> Any | None:
    try:
        return ctx.session if ctx is not None else None
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def register_service_operations(mcp: Any) -> None:
    """Register Service Business Operations and Artifact Production tools and resources."""

    @mcp.tool()
    def artifact_list_kinds() -> str:
        """List governed business artifact kinds, their required sections, and allowed formats.

        Kinds cover proposals, quote summaries, estimates, statements of work, contracts,
        invoices, brochures, presentations, one-pagers, case studies, and cover letters.
        """
        return _json(artifact_kinds_catalog())

    @mcp.tool()
    def artifact_prepare_generation(inputs_json: str = "{}") -> str:
        """Assemble context and issue a host generation ticket for a business artifact.

        inputs_json is an ArtifactGenerationInput: scope, artifact_kind, artifact_format,
        title, purpose, generation_mode (host_model|template), optional brand, commercial,
        legal (policy + template + jurisdiction), customer, engagement contexts, prior_version,
        requested_at, requested_by_ref. Returns the sealed ArtifactGenerationRequest. When a
        host ticket is present, produce the sections yourself and call
        artifact_submit_generated with the request and your submission. Legal-policy blocks
        return blocked_reasons and no ticket.
        """
        try:
            request = prepare_business_artifact_generation(_parse_object(inputs_json, "inputs_json"))
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        payload = request.to_dict()
        payload["next_step"] = (
            "Produce every required section and call artifact_submit_generated(request_json, submission_json, artifact_ref, validated_at, requested_by_ref)."
            if request.host_ticket
            else ("Blocked by legal policy; adjust template, jurisdiction, or deviations." if request.blocked_reasons else "Template mode: call artifact_submit_generated with template-rendered sections.")
        )
        return _json(payload)

    @mcp.tool()
    async def artifact_generate_with_host_model(inputs_json: str = "{}", ctx: Any = None) -> str:
        """Prepare a business artifact and delegate generation to the connected host model.

        Uses the SDK executor interface: if the MCP client advertises sampling, the server asks
        the host model through the session and returns a validated artifact candidate in one
        call. Otherwise it returns the host generation ticket and prompt sections; produce the
        sections and call artifact_submit_generated. The SDK validates either path identically.
        """
        try:
            inputs = _parse_object(inputs_json, "inputs_json")
            request = prepare_business_artifact_generation(inputs)
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        if request.blocked_reasons or request.host_ticket is None:
            payload = request.to_dict()
            payload["delegation"] = "not_attempted"
            return _json(payload)
        executor = McpHostModelDelegationExecutor(_session_from_context(ctx))
        produced = await executor.generate_async(request)
        if isinstance(produced, HostGenerationTicket):
            return _json(
                {
                    "delegation": "tool_round_trip",
                    "request": request.to_dict(),
                    "ticket": produced.to_dict(),
                    "next_step": "Produce the sections and call artifact_submit_generated.",
                }
            )
        artifact = validate_generated_business_artifact(
            {
                "request": request.to_dict(),
                "submission": produced.to_dict(),
                "artifact_ref": f"artifact:{request.brief.brief_digest[:16]}",
                "validated_at": request.brief.requested_at,
                "requested_by_ref": request.brief.requested_by_ref,
            }
        )
        return _json({"delegation": "session_sampling", "artifact": artifact.to_dict(), "next_step": _next_step(artifact)})

    @mcp.tool()
    def artifact_submit_generated(
        request_json: str,
        submission_json: str,
        artifact_ref: str,
        validated_at: str,
        requested_by_ref: str,
    ) -> str:
        """Validate host- or template-produced sections and bind the artifact candidate.

        request_json is the ArtifactGenerationRequest returned by artifact_prepare_generation;
        submission_json is {brief_digest, sections{section: text}, provenance{generator_kind,
        host_ref, model_ref, ticket_digest, generated_at}}. Returns the GeneratedBusinessArtifact
        with state validated | review_required | blocked, findings, provenance, version, required
        approvals, and engagement linkage, plus the documents.generate_business_artifact input to
        use for the governed file write.
        """
        try:
            artifact = validate_generated_business_artifact(
                {
                    "request": _parse_object(request_json, "request_json"),
                    "submission": _parse_object(submission_json, "submission_json"),
                    "artifact_ref": artifact_ref,
                    "validated_at": validated_at,
                    "requested_by_ref": requested_by_ref,
                }
            )
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        return _json({"artifact": artifact.to_dict(), "next_step": _next_step(artifact)})

    @mcp.tool()
    def service_engagement_propose_transition(inputs_json: str = "{}") -> str:
        """Propose one replay-fenced service engagement transition.

        inputs_json is a ServiceEngagementTransitionInput: scope, sealed command (kind, refs,
        expected_version, expected_state_digest, occurred_at, requested_by_ref, package), and
        optional current_snapshot. Links quote, approval, legal packet, executed agreement,
        delivery plan, bindings, accepted value, invoice candidates, issued invoices, payments;
        closes or cancels. Proposal only; Spring owns the engagement of record.
        """
        try:
            result = materialize_service_engagement_transition(_parse_object(inputs_json, "inputs_json"))
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        return _json(result.to_dict())

    @mcp.tool()
    def service_engagement_propose_invoice(inputs_json: str = "{}") -> str:
        """Shape uninvoiced accepted value into a finance.create_invoice candidate.

        inputs_json is a ServiceEngagementInvoiceInput: scope, snapshot, invoice_candidate_ref,
        accepted_values, due_days, requested_by_ref. Returns the candidate and the
        create_invoice input; issuing remains a governed finance write.
        """
        try:
            candidate = propose_service_engagement_invoice(_parse_object(inputs_json, "inputs_json"))
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        return _json({"candidate": candidate.to_dict(), "create_invoice_input": candidate.to_create_invoice_input()})

    @mcp.tool()
    def service_engagement_assess(inputs_json: str = "{}") -> str:
        """Assess a service engagement: stage, value totals, receivable, unbound deliverables, next action."""
        try:
            assessment = assess_service_engagement(_parse_object(inputs_json, "inputs_json"))
        except (ValueError, ValidationError) as exc:
            return _error(exc)
        return _json(assessment.to_dict())

    @mcp.resource(ARTIFACT_KINDS_RESOURCE, name="artifact_kinds", mime_type="application/json")
    def artifact_kinds_resource() -> str:
        return _json(artifact_kinds_catalog())

    @mcp.resource(LEGAL_POLICY_SCHEMA_RESOURCE, name="legal_document_policy_schema", mime_type="application/json")
    def legal_policy_schema_resource() -> str:
        return _json(legal_policy_schema())

    @mcp.resource(ENGAGEMENT_STAGES_RESOURCE, name="service_engagement_stages", mime_type="application/json")
    def engagement_stages_resource() -> str:
        return _json(engagement_stage_catalog())


def _next_step(artifact: GeneratedBusinessArtifact) -> dict[str, Any]:
    if artifact.state == "blocked":
        return {"action": "revise", "detail": [item.to_dict() for item in artifact.findings]}
    write_input = artifact.to_generate_business_artifact_input().model_dump(mode="json")
    return {
        "action": "review" if artifact.state == "review_required" else "write",
        "required_approvals": [item.to_dict() for item in artifact.required_approvals],
        "generate_business_artifact_input": write_input,
        "note": "Call run_sdk_business_primitive('documents.generate_business_artifact', ...) with create=true only after approvals; preview_only stays true until then.",
    }


def artifact_kinds_catalog() -> dict[str, Any]:
    return {
        "schema": "lightbulb.business_artifact_kind_catalog.v1",
        "kinds": [
            {"kind": kind, "required_sections": list(REQUIRED_SECTIONS[kind]), "allowed_formats": list(ALLOWED_FORMATS[kind])}
            for kind in REQUIRED_SECTIONS
        ],
        "generation_modes": ["host_model", "template"],
        "delegation": ["tool_round_trip", "session_sampling_when_advertised"],
    }


def legal_policy_schema() -> dict[str, Any]:
    return {
        "schema": "lightbulb.legal_document_policy_schema.v1",
        "policy_schema": LegalDocumentPolicy.model_json_schema(),
        "guidance": [
            "Legal artifacts (contract, statement_of_work) require an approved template for the jurisdiction unless the policy allows untemplated documents.",
            "Risk classes: none, low, standard, elevated, restricted; review is mandatory from review_required_from_risk_class and always for deviations or blocked classes.",
            "The SDK never asserts legal sufficiency; it decides whether policy allows the draft and who must review it.",
        ],
    }


def engagement_stage_catalog() -> dict[str, Any]:
    return {
        "schema": "lightbulb.service_engagement_stage_catalog.v1",
        "stages": list(ENGAGEMENT_STAGES),
        "terminal_stages": sorted(TERMINAL_STAGES),
        "transitions": [
            "link_quote",
            "approve_quote",
            "link_legal_review_packet",
            "link_executed_agreement",
            "link_delivery_plan",
            "link_deliverable_binding",
            "link_accepted_value",
            "propose_invoice",
            "link_issued_invoice",
            "link_payment",
            "close",
            "cancel",
        ],
    }


__all__ = [
    "ARTIFACT_KINDS_RESOURCE",
    "ENGAGEMENT_STAGES",
    "ENGAGEMENT_STAGES_RESOURCE",
    "LEGAL_POLICY_SCHEMA_RESOURCE",
    "McpHostModelDelegationExecutor",
    "artifact_kinds_catalog",
    "engagement_stage_catalog",
    "legal_policy_schema",
    "register_service_operations",
]
