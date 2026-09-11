"""Company-scoped assessment previews on the canonical primitive runtime."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from lightbulb.primitive_runtime import PrimitiveBlocker, PrimitiveExecutionContext
from lightbulb.productised_assessment import (
    AssessmentNextAction,
    ProductisedAssessmentDossier,
    ProductisedAssessmentInput,
    compile_productised_assessment,
    example_productised_assessment_input,
)
from lightbulb.productised_assessment_presentation import (
    render_productised_assessment_proposal,
    render_productised_assessment_report,
)
from lightbulb.service_business_loop import SERVICE_BUSINESS_GOLDEN_LOOP
from lightbulb.service_engagement import OpaqueRef, Sha256Digest, _StrictModel
from lightbulb.service_operations_primitives import (
    _ServiceOpsPrimitive, _read_operation, _request_digest, _scope_matches,
)


class RenderProductisedAssessmentInput(_StrictModel):
    dossier: ProductisedAssessmentDossier
    requested_by_ref: OpaqueRef
    offer_ref: OpaqueRef | None = None


class AssessmentMarkdownPreview(_StrictModel):
    """Agent-sized presentation; full HTML is available through direct Python."""

    schema_id: Literal["lightbulb.assessment_markdown_preview.v1"] = Field(
        default="lightbulb.assessment_markdown_preview.v1", alias="schema"
    )
    title: str
    document_kind: str
    markdown: str
    dossier_digest: Sha256Digest
    content_digest: Sha256Digest
    next_actions: tuple[AssessmentNextAction, ...]
    disposition: Literal["draft_for_review"] = "draft_for_review"
    persisted: Literal[False] = False
    provider_effect_executed: Literal[False] = False


class _AssessmentExample(Mapping[str, Any]):
    def __init__(self, *, render: bool = False) -> None:
        self.render = render

    def _payload(self) -> dict[str, Any]:
        payload = example_productised_assessment_input()
        if self.render:
            return {
                "dossier": compile_productised_assessment(payload).to_dict(),
                "requested_by_ref": payload["requested_by_ref"],
            }
        return payload

    def __getitem__(self, key: str) -> Any:
        return self._payload()[key]

    def __iter__(self):
        return iter(self._payload())

    def __len__(self) -> int:
        return len(self._payload())


class _AssessmentPrimitive(_ServiceOpsPrimitive):
    golden_loop = SERVICE_BUSINESS_GOLDEN_LOOP

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["scope_policy"] = {
            "explicit_selected_company_required": True,
            "admin_bypass": False,
            "local_scope_match_proves_hosted_access": False,
        }
        return contract

    def _matches(self, inputs: ProductisedAssessmentInput, actor: str, context: PrimitiveExecutionContext) -> bool:
        scope = inputs.scope
        try:
            if str(UUID(scope.company_ref)) != scope.company_ref:
                return False
        except ValueError:
            return False
        return inputs.requested_by_ref == actor and _scope_matches(
            scope.tenant_ref, scope.company_ref, scope.project_ref,
            scope.project_id, actor, context,
        )

    def _bounded_preview(self, *, python_function: str, **kwargs: Any):
        result = self._preview(**kwargs)
        # Generic MCP limits its complete envelope to 20,000 characters. Keep
        # room for runtime metadata and never silently truncate a sealed dossier.
        if len(json.dumps(result.to_dict(), ensure_ascii=True, indent=2)) > 18_000:
            return self._blocked(
                request_digest=kwargs["request_digest"], code="USE_DIRECT_SDK",
                message=(f"This complete document exceeds the agent response budget. Use "
                         f"{python_function} in Python with the same input to retain all content. "
                         "No document was saved or published."),
            )
        return result


class PrepareProductisedAssessmentPrimitive(_AssessmentPrimitive):
    primitive_ref = "service.prepare_productised_assessment"
    version = "0.1.0"
    title = "Prepare a productised assessment and commercial options"
    description = "Compile company-scoped intake, declared evidence, findings and separately priced service and software offers for review."
    input_model = ProductisedAssessmentInput
    output_model = ProductisedAssessmentDossier
    risk_level = "low"
    operation_spec = _read_operation("productised_assessment_prepare", "sdk.service.prepare_productised_assessment")
    example_inputs = _AssessmentExample()

    def _execute(self, context: PrimitiveExecutionContext, inputs: ProductisedAssessmentInput):
        digest = _request_digest(inputs.to_dict())
        if not self._matches(inputs, inputs.requested_by_ref, context):
            return self._blocked(request_digest=digest, code="SCOPE_MISMATCH", message="Select the exact company, project and requesting actor. Admin status grants no exception.")
        dossier = compile_productised_assessment(inputs)
        blockers = [PrimitiveBlocker(code=b.code, field=b.field, message=b.message, retryable=False) for b in dossier.blockers]
        result = self._bounded_preview(
            python_function="lightbulb.compile_productised_assessment",
            output=dossier, request_digest=digest,
            external_refs={"assessment_ref": inputs.assessment_ref, "dossier_digest": dossier.dossier_digest},
            event_type="service.productised_assessment_prepared", event_payload={"status": dossier.status, "persisted": False},
            evidence_kind="productised_assessment_draft", evidence_summary="Deterministic draft from declared evidence; source bytes were not independently fetched or verified.",
            summary=f"Assessment {dossier.status}; {len(dossier.blockers)} prerequisites; no publication, billing or access effects.",
            blocker=blockers[0] if blockers else None,
        )
        if result.output is not None:
            result = result.model_copy(update={"blockers": blockers})
            # Check the complete list, not only the first blocker in the receipt.
            if len(json.dumps(result.to_dict(), ensure_ascii=True, indent=2)) > 18_000:
                return self._blocked(request_digest=digest, code="USE_DIRECT_SDK", message="Use lightbulb.compile_productised_assessment in Python with the same input for the complete dossier and prerequisite list; no effects occurred.")
        return result


class RenderProductisedAssessmentPrimitive(_AssessmentPrimitive):
    primitive_ref = "documents.render_productised_assessment"
    version = "0.1.0"
    title = "Render an assessment report or selected commercial proposal"
    description = "Render a sealed company-scoped dossier into client Markdown; omit offer_ref for the report or select one exact proposed offer."
    input_model = RenderProductisedAssessmentInput
    output_model = AssessmentMarkdownPreview
    risk_level = "low"
    operation_spec = _read_operation("productised_assessment_render", "sdk.documents.render_productised_assessment")
    example_inputs = _AssessmentExample(render=True)

    def _execute(self, context: PrimitiveExecutionContext, inputs: RenderProductisedAssessmentInput):
        digest = _request_digest(inputs.to_dict())
        if not self._matches(inputs.dossier.inputs, inputs.requested_by_ref, context):
            return self._blocked(request_digest=digest, code="SCOPE_MISMATCH", message="The dossier must belong to the exact selected company, project and requesting actor.")
        try:
            document = (render_productised_assessment_report(inputs.dossier) if inputs.offer_ref is None
                        else render_productised_assessment_proposal(inputs.dossier, offer_ref=inputs.offer_ref))
        except ValueError as exc:
            return self._blocked(request_digest=digest, code="DOCUMENT_INVALID", message=str(exc)[:500])
        output = AssessmentMarkdownPreview(
            title=document.title, document_kind=document.document_kind, markdown=document.markdown,
            dossier_digest=document.dossier_digest,
            content_digest=hashlib.sha256(document.markdown.encode("utf-8")).hexdigest(),
            next_actions=inputs.dossier.next_actions,
        )
        return self._bounded_preview(
            python_function="lightbulb.render_productised_assessment_report / render_productised_assessment_proposal",
            output=output, request_digest=digest,
            external_refs={"dossier_digest": output.dossier_digest, "content_digest": output.content_digest},
            event_type="documents.productised_assessment_rendered", event_payload={"document_kind": output.document_kind, "persisted": False},
            evidence_kind="productised_assessment_presentation", evidence_summary="Client presentation preview; no artifact was stored or published.",
            summary="Client Markdown prepared for review; no publication or commercial effects.",
            blocker=(PrimitiveBlocker(code="ASSESSMENT_INCOMPLETE", message="Resolve the dossier prerequisites before customer delivery.", retryable=False)
                     if inputs.dossier.blockers else None),
        )


PRODUCTISED_ASSESSMENT_EXECUTABLE_PRIMITIVES = (
    PrepareProductisedAssessmentPrimitive(), RenderProductisedAssessmentPrimitive(),
)

__all__ = [
    "AssessmentMarkdownPreview", "PrepareProductisedAssessmentPrimitive",
    "RenderProductisedAssessmentInput", "RenderProductisedAssessmentPrimitive",
    "PRODUCTISED_ASSESSMENT_EXECUTABLE_PRIMITIVES",
]
