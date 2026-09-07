"""Exact connector request checks shared by protected outbound messages."""
from lightbulb.connector_execution import ConnectorExecutionRequest
from lightbulb.company_engine_core import detached


def exact_request(request, execution, *, tool, arguments, idempotency_key):
    call = ConnectorExecutionRequest.model_validate(detached(request))
    if not (call.tool == execution.tool == tool and call.arguments == detached(arguments)
            and call.idempotency_key == idempotency_key and call.effect == execution.effect == "write"
            and call.approval_required and not call.preview_only and call.approval_ref
            and execution.approval_ref == call.approval_ref
            and execution.project_id == str(call.scope.project_id)
            and execution.request_digest == call.custody_fingerprint()):
        raise ValueError("EXECUTION_REQUEST_MISMATCH: the execution must bind the approved destination, content, scope and exact request")
    return call
