"""Outlook types on the provider-neutral communication CRM/replay runtime."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from lightbulb.communication_runtime import (
    CommunicationPrivateInbound,
    CommunicationRuntime,
    CommunicationTraceResult,
)


COMMUNICATION_PRIVATE_OUTLOOK_INBOUND_SCHEMA = (
    "lightbulb.communication_private_outlook_inbound.v1"
)
# Compatibility name only. Outlook and Gmail now return the exact same
# provider-neutral result type; its serialized identifier remains stable.
COMMUNICATION_OUTLOOK_TRACE_RESULT_SCHEMA = (
    "lightbulb.communication_gmail_trace_result.v1"
)


class CommunicationPrivateOutlookInbound(CommunicationPrivateInbound):
    """Validated transient Outlook content accepted directly by the shared rail."""

    schema_id: Literal[
        "lightbulb.communication_private_outlook_inbound.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_OUTLOOK_INBOUND_SCHEMA, alias="schema")


# Exact aliases, not translating wrappers. Replay custody and CRM sink
# semantics therefore cannot diverge between email providers.
CommunicationOutlookTraceResult = CommunicationTraceResult
OutlookCommunicationRuntime = CommunicationRuntime


__all__ = [
    "COMMUNICATION_OUTLOOK_TRACE_RESULT_SCHEMA",
    "COMMUNICATION_PRIVATE_OUTLOOK_INBOUND_SCHEMA",
    "CommunicationOutlookTraceResult",
    "CommunicationPrivateOutlookInbound",
    "OutlookCommunicationRuntime",
]
