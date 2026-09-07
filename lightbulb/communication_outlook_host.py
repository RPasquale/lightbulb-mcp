"""Closed Outlook artifact shape for the shared communication poll host.

The Spring custody rail encrypts this complete object and persists only its
opaque reference and commitments.  A worker resolves it once per leased
attempt, validates this exact provider shape, and passes it to the shared
email observer.  This module deliberately owns no queue or conversation
state machine.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lightbulb.communication_contracts import (
    CommunicationDispatchState,
    CommunicationEndpointBinding,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationThreadBinding,
    CommunicationThreadState,
    communication_canonical_json,
    communication_private_value_digest,
)
from lightbulb.communication_materializer import (
    CommunicationExternalEffectState,
    CommunicationMaterializationResult,
    CommunicationMaterializationStatus,
)
from lightbulb.communication_outlook import CommunicationOutlookRoute
from lightbulb.communication_outlook_observation import (
    CommunicationOutlookReadRoute,
    CommunicationPrivateOutlookDispatch,
)
from lightbulb.communication_runtime import CommunicationCrmTraceBinding


COMMUNICATION_OUTLOOK_POLL_ARTIFACTS_SCHEMA = (
    "lightbulb.communication_outlook_poll_artifacts.v1"
)


class CommunicationOutlookPollArtifacts(BaseModel):
    """One transient, exact-route Outlook poll payload.

    Sealed artifact verification remains the observer/runtime authority.  The
    host model closes the provider boundary before any connector execution:
    Gmail routes or private dispatch fields cannot be parsed as Outlook.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
        allow_inf_nan=False,
    )

    schema_id: Literal[
        "lightbulb.communication_outlook_poll_artifacts.v1"
    ] = Field(default=COMMUNICATION_OUTLOOK_POLL_ARTIFACTS_SCHEMA, alias="schema")
    read_route: CommunicationOutlookReadRoute
    communication_route: CommunicationOutlookRoute
    materialization: CommunicationMaterializationResult
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding
    private_dispatch: CommunicationPrivateOutlookDispatch

    @model_validator(mode="after")
    def _exact_bindings(self) -> "CommunicationOutlookPollArtifacts":
        read = self.read_route
        write = self.communication_route
        if (
            read.project_id != write.project_id
            or read.project_ref != write.project_ref
            or read.connector_account_ref != write.connector_account_ref
            or read.tenant_connector_id != write.tenant_connector_id
        ):
            raise ValueError("Outlook poll routes do not share one exact account")

        materialized = self.materialization
        accepted = (
            materialized.status == CommunicationMaterializationStatus.ACCEPTED
            and materialized.effect_state
            == CommunicationExternalEffectState.ACCEPTED
        )
        completed = (
            materialized.status == CommunicationMaterializationStatus.COMPLETED
            and materialized.effect_state
            == CommunicationExternalEffectState.COMPLETED
        )
        if (not accepted and not completed) or materialized.receipt is None:
            raise ValueError(
                "Outlook polling requires an accepted or freshly observed dispatch"
            )
        dispatch = materialized.receipt
        if dispatch.state != CommunicationDispatchState.ACCEPTED:
            raise ValueError("Outlook polling requires an accepted dispatch receipt")

        route = (write.connector_account_ref, write.route_digest)
        if any(
            bound != route
            for bound in (
                (dispatch.connector_account_ref, dispatch.route_digest),
                (self.thread.connector_account_ref, self.thread.route_digest),
                (
                    self.outbound_sender_endpoint.connector_account_ref,
                    self.outbound_sender_endpoint.route_digest,
                ),
                (
                    self.contact_endpoint.connector_account_ref,
                    self.contact_endpoint.route_digest,
                ),
            )
        ):
            raise ValueError("Outlook poll artifacts do not bind the write route")
        if (
            self.thread.state != CommunicationThreadState.AWAITING_REPLY
            or dispatch.thread_ref != self.thread.thread_ref
            or dispatch.thread_digest != self.thread.artifact_digest
            or dispatch.thread_version != self.thread.version
            or dispatch.thread_state != self.thread.state
            or dispatch.thread_participant_party_refs
            != self.thread.participant_party_refs
            or dispatch.parent_message_sha256 != self.thread.parent_message_sha256
            or materialized.thread_ref != self.thread.thread_ref
            or materialized.draft_digest != dispatch.draft_digest
        ):
            raise ValueError("Outlook poll dispatch does not bind the sealed thread")
        if (
            self.outbound_sender_endpoint.party_ref
            not in self.thread.participant_party_refs
            or self.contact_party.party_ref
            not in self.thread.participant_party_refs
            or self.outbound_sender_endpoint.party_ref
            == self.contact_party.party_ref
            or self.contact_party.party_kind != CommunicationPartyKind.CRM_CONTACT
            or self.contact_endpoint.party_ref != self.contact_party.party_ref
            or self.contact_endpoint.party_digest != self.contact_party.artifact_digest
            or self.crm.contact_party_ref != self.contact_party.party_ref
            or self.crm.contact_party_digest != self.contact_party.artifact_digest
            or self.crm.contact_endpoint_ref != self.contact_endpoint.endpoint_ref
            or self.crm.contact_endpoint_digest != self.contact_endpoint.artifact_digest
            or self.crm.crm_contact_ref != self.contact_party.crm_contact_ref
            or self.crm.crm_account_ref != self.contact_party.crm_account_ref
            or self.thread.crm_trace_binding_digest != self.crm.artifact_digest
        ):
            raise ValueError("Outlook poll CRM binding is inconsistent")

        message_digest = communication_private_value_digest(
            self.private_dispatch.provider_message_id
        )
        conversation_digest = communication_private_value_digest(
            self.private_dispatch.provider_conversation_id
        )
        if (
            dispatch.provider_message_sha256 is None
            or not hmac.compare_digest(
                dispatch.provider_message_sha256,
                message_digest,
            )
            or dispatch.provider_thread_sha256 is None
            or self.thread.provider_thread_sha256 is None
            or not hmac.compare_digest(
                dispatch.provider_thread_sha256,
                conversation_digest,
            )
            or not hmac.compare_digest(
                self.thread.provider_thread_sha256,
                conversation_digest,
            )
        ):
            raise ValueError(
                "Outlook private identifiers do not match sealed commitments"
            )
        return self


def parse_outlook_poll_artifacts(
    value: CommunicationOutlookPollArtifacts | Mapping[str, object] | str | bytes,
) -> CommunicationOutlookPollArtifacts:
    """Parse one bounded Spring wire payload through Pydantic's JSON boundary."""

    if isinstance(value, CommunicationOutlookPollArtifacts):
        return CommunicationOutlookPollArtifacts.model_validate(value)
    if isinstance(value, Mapping):
        encoded = communication_canonical_json(value)
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise TypeError("Outlook poll artifacts must be an object or JSON document")
    if len(encoded) > 1_000_000:
        raise ValueError("Outlook poll artifacts exceed the host custody limit")
    return CommunicationOutlookPollArtifacts.model_validate_json(encoded)


__all__ = [
    "COMMUNICATION_OUTLOOK_POLL_ARTIFACTS_SCHEMA",
    "CommunicationOutlookPollArtifacts",
    "parse_outlook_poll_artifacts",
]
