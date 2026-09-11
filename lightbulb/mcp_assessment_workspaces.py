"""Thin saved-assessment tools over the canonical SDK checkpoint client."""

from __future__ import annotations

import json
from typing import Any, Callable

from mcp.types import ToolAnnotations

from lightbulb.assessment_workspace import AssessmentWorkspaceRecord, create_assessment_workspace
from lightbulb.productised_assessment_presentation import (
    render_productised_assessment_proposal, render_productised_assessment_report,
)


ASSESSMENT_WORKSPACE_MCP_TOOLS = frozenset({
    "save_assessment_workspace", "read_assessment_workspace", "recover_assessment_workspace",
})
_LIMIT = 20_000


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    parsed = AssessmentWorkspaceRecord.model_validate(record)
    dossier = parsed.workspace.dossier
    return {
        "schema": "lightbulb.assessment_workspace_summary.v1",
        "project_id": parsed.project_id, "run_ref": parsed.run_ref, "revision": parsed.revision,
        "workspace_digest": parsed.workspace.workspace_digest, "dossier_digest": dossier.dossier_digest,
        "assessment_ref": dossier.inputs.assessment_ref, "title": dossier.inputs.title,
        "selected_offer_ref": parsed.workspace.selected_offer_ref,
        "selection_status": "proposed_only", "status": dossier.status,
        "created_at": parsed.created_at, "updated_at": parsed.updated_at,
        "counts": {field: len(getattr(dossier.inputs, field)) for field in ("goals", "evidence", "findings", "offers")},
        "blocker_count": len(dossier.blockers), "persisted": True,
        "provider_effect_executed": False, "acceptance_recorded": False,
        "next_action": "Use read_assessment_workspace with report, proposal, findings, evidence, offers or blockers view.",
    }


def _json(payload: dict[str, Any], *, summary: dict[str, Any] | None = None) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) <= _LIMIT:
        return encoded
    return json.dumps({
        "error": "USE_DIRECT_SDK", "message": "This view exceeds the agent response limit. Use a smaller page or client.get_assessment_workspace(project_id, run_ref) in Python for the complete saved record.",
        "workspace": summary,
    }, separators=(",", ":"))


def _workspace(raw: str, selected_offer_ref: str):
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("dossier must be a JSON object")
    return create_assessment_workspace(payload, selected_offer_ref=selected_offer_ref or None)


def register_assessment_workspace_tools(mcp: Any, *, get_client: Callable[[], Any]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def save_assessment_workspace(
        dossier: str, run_ref: str, expected_revision: int, selected_offer_ref: str = "",
    ) -> str:
        """Save a sealed assessment draft in the selected company's Project.

        Use revision 0 to create; updates require the last read revision. This
        persists working data only. Selecting an offer records no acceptance.
        If a save is uncertain, use recover_assessment_workspace with these same
        inputs before deciding on any further write.
        """
        try:
            workspace = _workspace(dossier, selected_offer_ref)
            record = get_client().save_assessment_workspace(
                workspace, run_ref=run_ref, expected_revision=expected_revision,
            )
            return _json(_summary(record))
        except Exception as exc:
            return _json({"error": getattr(exc, "code", type(exc).__name__), "message": str(exc)[:600],
                          "persisted": None, "run_ref": run_ref,
                          "next_action": "For an uncertain transport result, use recover_assessment_workspace with the same dossier, selection and expected revision. Do not blindly retry a write."})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    def recover_assessment_workspace(
        dossier: str, run_ref: str, expected_revision: int, selected_offer_ref: str = "",
    ) -> str:
        """Read back an uncertain save and verify its exact content and revision; performs no write."""
        try:
            record = get_client().recover_assessment_workspace(
                _workspace(dossier, selected_offer_ref), run_ref=run_ref, expected_revision=expected_revision,
            )
            return _json(_summary(record) if record is not None else {
                "status": "not_found", "persisted": False, "run_ref": run_ref,
            })
        except Exception as exc:
            return _json({"error": getattr(exc, "code", type(exc).__name__), "message": str(exc)[:600], "persisted": None})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    def read_assessment_workspace(
        project_id: str, run_ref: str, view: str = "summary", offer_ref: str = "",
        offset: int = 0, limit: int = 5, expected_revision: int | None = None, costing: str = "",
    ) -> str:
        """Resume a saved assessment by reference or render its client report/proposal.

        Views: summary, dossier, report, proposal, goals, evidence, findings,
        offers, blockers, economics. Economics requires costing JSON (as_of,
        requested_by_ref, tax_basis, costs) and is internal operator data.
        Lists are paged; pass the returned revision on later
        pages to reject mixed revisions. Proposal defaults to the saved selected
        offer. Rendered output is draft Markdown; this call never publishes it.
        """
        try:
            if view not in {"summary", "dossier", "report", "proposal", "goals", "evidence", "findings", "offers", "blockers", "economics"}:
                raise ValueError("Unknown assessment workspace view")
            if offset < 0 or not 1 <= limit <= 10:
                raise ValueError("offset must be non-negative and limit between 1 and 10")
            record = get_client().get_assessment_workspace(project_id, run_ref)
            if record is None:
                return _json({"status": "not_found", "project_id": project_id, "run_ref": run_ref})
            summary = _summary(record)
            if expected_revision is not None and expected_revision != summary["revision"]:
                return _json({"error": "REVISION_CONFLICT", "message": "The workspace changed; restart from its current revision.", "workspace": summary})
            parsed = AssessmentWorkspaceRecord.model_validate(record)
            dossier = parsed.workspace.dossier
            if view == "summary":
                return _json(summary)
            if view == "dossier":
                content: Any = dossier.to_dict()
            elif view == "economics":
                from lightbulb.assessment_costing import review_assessment_offer_costs
                declared = json.loads(costing)
                if not isinstance(declared, dict) or "dossier" in declared:
                    raise ValueError("costing must be an object without a dossier; the saved revision supplies it")
                review = review_assessment_offer_costs({**declared, "dossier": dossier.to_dict()})
                content = {key: value for key, value in review.to_dict().items() if key != "inputs"}
            elif view in {"report", "proposal"}:
                if view == "report":
                    document = render_productised_assessment_report(dossier)
                else:
                    selected = offer_ref or parsed.workspace.selected_offer_ref
                    if not selected:
                        raise ValueError("Select an exact offer for the proposal view")
                    document = render_productised_assessment_proposal(dossier, offer_ref=selected)
                content = {"title": document.title, "markdown": document.markdown,
                           "markdown_digest": document.markdown_digest, "disposition": document.disposition,
                           "published": False}
            else:
                values = dossier.blockers if view == "blockers" else getattr(dossier.inputs, view)
                content = {"items": [item.to_dict() for item in values[offset:offset + limit]],
                           "offset": offset, "total": len(values),
                           "next_offset": offset + limit if offset + limit < len(values) else None}
            return _json({"workspace": summary, "view": view, "content": content}, summary=summary)
        except Exception as exc:
            return _json({"error": getattr(exc, "code", type(exc).__name__), "message": str(exc)[:600]})
