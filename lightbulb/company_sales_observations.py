"""Minimize one fresh governed Gmail read before durable sales coordination.

The raw thread is ephemeral. Only direction, bounded counts and the existing
execution commitments leave this function; no message text or addresses do.
Any inbound or ambiguous activity holds follow-up for the communication agent.
"""
from __future__ import annotations

from datetime import timedelta
from email.utils import getaddresses
from typing import Literal

from pydantic import Field

from lightbulb.company_engine_core import Sha256Digest, StrictModel, parsed, stable_digest
from lightbulb.company_execution_bridge import execution_receipt_from_connector


class SalesObservationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise SalesObservationError(code)


class SalesThreadObservation(StrictModel):
    schema_id: Literal["lightbulb.company_sales_thread_observation.v1"] = Field(
        default="lightbulb.company_sales_thread_observation.v1", alias="schema")
    binding_digest: Sha256Digest
    execution_digest: Sha256Digest
    request_digest: Sha256Digest
    output_digest: Sha256Digest
    observed_at: str
    message_count: int = Field(ge=0, le=10)
    disposition: Literal["no_reply", "reply", "bounce", "ambiguous"]


def _addresses(value):
    if not isinstance(value, str) or not value or any(char in value for char in "\r\n\0"):
        return ()
    entries = getaddresses([value])
    if not entries or any(not address or address.count("@") != 1 for _, address in entries):
        return ()
    return tuple(address.lower() for _, address in entries)


def sales_thread_observation(request, result, *, binding, scope, now):
    """Refuse stale/wrong-scope reads; conservatively stop on incomplete threads."""
    _require(request.tool == "gmail.get_thread" and request.effect.value == "read"
             and request.idempotency_key is None and binding.thread_ref is not None,
             "SALES_FRESH_THREAD_READ_REQUIRED")
    _require(request.connector_account_ref == binding.connector_account_ref
             and request.scope.model_dump(mode="json") == scope
             and request.arguments == {"thread_id": binding.thread_ref, "max_messages": 10},
             "SALES_THREAD_REQUEST_MISMATCH")
    receipt = execution_receipt_from_connector(result, request)
    at = parsed(now)
    _require(at - timedelta(seconds=60) <= parsed(receipt.completed_at) <= at,
             "SALES_THREAD_READ_STALE")
    output = result.output
    _require(isinstance(output, dict) and output.get("schema") == "lightbulb.gmail_thread.v1"
             and output.get("threadId") == binding.thread_ref
             and output.get("privateData") is True and output.get("retention") == "ephemeral_response_only",
             "SALES_THREAD_RESPONSE_MISMATCH")
    rows = output.get("messages")
    _require(isinstance(rows, list) and len(rows) <= 10
             and type(output.get("messageCount")) is int
             and type(output.get("returnedMessageCount")) is int
             and output["returnedMessageCount"] == len(rows) <= output["messageCount"]
             and type(output.get("truncated")) is bool
             and output["truncated"] == (output["messageCount"] > len(rows)),
             "SALES_THREAD_COVERAGE_INVALID")
    ours, customer = binding.from_address.lower(), binding.to_address.lower()
    disposition = "ambiguous" if output["truncated"] or not rows else "no_reply"
    seen = set()
    anchor_seen = False
    last_time = -1
    for row in rows:
        _require(isinstance(row, dict) and isinstance(row.get("id"), str)
                 and 0 < len(row["id"]) <= 200 and row["id"] not in seen,
                 "SALES_THREAD_MESSAGE_INVALID")
        seen.add(row["id"])
        headers = row.get("headers")
        if not isinstance(headers, dict):
            disposition = "ambiguous"
            continue
        normalized = {str(key).lower(): value for key, value in headers.items()}
        if len(normalized) != len(headers):
            disposition = "ambiguous"
            continue
        internal_date = row.get("internalDate")
        if (not isinstance(internal_date, str) or not internal_date.isascii() or not internal_date.isdigit()
                or len(internal_date) > 20 or not last_time <= int(internal_date) <= int(at.timestamp() * 1000)):
            disposition = "ambiguous"
        else:
            last_time = int(internal_date)
        if normalized.get("messageid") == binding.parent_message_id:
            if anchor_seen:
                disposition = "ambiguous"
            anchor_seen = True
            # The explicitly bound parent establishes the reviewed history.
            # Earlier customer messages cannot count as a reply to this run.
            continue
        if not anchor_seen:
            continue
        sender = _addresses(normalized.get("from"))
        recipients = _addresses(normalized.get("to"))
        if len(sender) != 1:
            disposition = "ambiguous"
        elif sender[0] == ours and customer in recipients:
            continue
        elif sender[0] == customer and ours in recipients:
            if disposition not in {"ambiguous", "bounce"}:
                disposition = "reply"
        elif sender[0].split("@", 1)[0] in {"mailer-daemon", "postmaster"} and ours in recipients:
            if disposition != "ambiguous":
                disposition = "bounce"
        else:
            disposition = "ambiguous"
    if not anchor_seen:
        disposition = "ambiguous"
    return SalesThreadObservation(binding_digest=stable_digest(binding.to_dict()),
        execution_digest=receipt.execution_digest, request_digest=receipt.request_digest,
        output_digest=receipt.output_digest, observed_at=receipt.completed_at,
        message_count=len(rows), disposition=disposition)


__all__ = ["SalesObservationError", "SalesThreadObservation", "sales_thread_observation"]
