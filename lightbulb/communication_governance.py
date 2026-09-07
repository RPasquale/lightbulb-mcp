"""Host-authority checks for governed communication artifacts.

This module contains no connector I/O. It verifies that a message draft is
covered by a current fail-closed policy decision, an exact content-bound human
approval, and one atomically consumed contact reservation before a runtime is
allowed to attempt an external effect.
"""

from __future__ import annotations

import hmac
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol, runtime_checkable

from lightbulb.communication_contracts import (
    CommunicationApprovalDisposition,
    CommunicationApprovalGrant,
    CommunicationContactPolicyDecision,
    CommunicationContactReservation,
    CommunicationContactReservationConsumption,
    CommunicationContactReservationRequest,
    CommunicationMessageDraft,
    CommunicationPolicyDisposition,
    CommunicationScopeKeyRing,
    _parse_timestamp,
    _workflow_scope,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


class CommunicationContactReservationConflict(RuntimeError):
    """Another run owns, or already consumed, the exact contact slot."""


@runtime_checkable
class CommunicationContactReservationAuthority(Protocol):
    """Transactional host boundary for a short-lived, one-use contact slot."""

    contact_token_key_id: str

    def reserve(
        self,
        request: CommunicationContactReservationRequest,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: CommunicationScopeKeyRing,
        reserved_at: datetime,
        ttl_seconds: int = 900,
    ) -> CommunicationContactReservation: ...

    def consume(
        self,
        reservation: CommunicationContactReservation,
        *,
        request: CommunicationContactReservationRequest,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: CommunicationScopeKeyRing,
        consumed_at: datetime,
    ) -> CommunicationContactReservationConsumption: ...


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _same_digest(left: str, right: str, *, label: str) -> None:
    if not hmac.compare_digest(left, right):
        raise ValueError(f"{label} digest mismatch")


def mint_communication_contact_reservation_request(
    *,
    request_ref: str,
    draft: CommunicationMessageDraft,
    policy_decision: CommunicationContactPolicyDecision,
    contact_window_ref: str,
    run_ref: str,
    requested_at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    scope_key_id: str | None = None,
) -> CommunicationContactReservationRequest:
    """Mint a run request whose slot excludes run and mutable message content."""

    timestamp = _utc(requested_at, label="requested_at")
    trusted_draft = verify_communication_artifact(
        draft,
        artifact_type=CommunicationMessageDraft,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_policy = verify_communication_contact_policy_decision(
        policy_decision,
        draft=trusted_draft,
        at=timestamp,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    return mint_communication_artifact(
        CommunicationContactReservationRequest,
        {
            "request_ref": request_ref,
            "draft_digest": trusted_draft.artifact_digest,
            "policy_decision_digest": trusted_policy.artifact_digest,
            "purpose": trusted_draft.purpose,
            "channel": trusted_draft.channel,
            "recipient_endpoint_digests": (trusted_draft.recipient_endpoint_digests),
            "contact_token_key_id": trusted_draft.contact_token_key_id,
            "company_contact_scope_digest": (
                trusted_draft.company_contact_scope_digest
            ),
            "recipient_contact_digests": trusted_draft.recipient_contact_digests,
            "recipient_address_digests": trusted_draft.recipient_address_digests,
            "contact_window_ref": contact_window_ref,
            "run_ref": run_ref,
            "requested_at": timestamp.isoformat(),
        },
        scope=scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )


def verify_communication_contact_policy_decision(
    value: CommunicationContactPolicyDecision | Mapping[str, Any],
    *,
    draft: CommunicationMessageDraft,
    at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationContactPolicyDecision:
    """Admit only a fresh allow decision bound to the exact draft audience."""

    trusted_draft = verify_communication_artifact(
        draft,
        artifact_type=CommunicationMessageDraft,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    decision = verify_communication_artifact(
        value,
        artifact_type=CommunicationContactPolicyDecision,
        scope=scope,
        scope_keyring=scope_keyring,
        at=at,
    )
    if decision.disposition != CommunicationPolicyDisposition.ALLOW:
        raise ValueError("contact policy does not authorize dispatch")
    _same_digest(
        decision.draft_digest,
        trusted_draft.artifact_digest,
        label="policy draft",
    )
    if (
        decision.purpose != trusted_draft.purpose
        or decision.channel != trusted_draft.channel
        or decision.recipient_endpoint_digests
        != trusted_draft.recipient_endpoint_digests
    ):
        raise ValueError(
            "contact policy does not match draft purpose, channel, and audience"
        )
    return decision


def verify_communication_approval_grant(
    value: CommunicationApprovalGrant | Mapping[str, Any],
    *,
    draft: CommunicationMessageDraft,
    policy_decision: CommunicationContactPolicyDecision,
    connector_account_ref: str,
    route_digest: str,
    schedule_digest: str,
    at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationApprovalGrant:
    """Verify human authority over exact content, audience, route, and schedule."""

    trusted_draft = verify_communication_artifact(
        draft,
        artifact_type=CommunicationMessageDraft,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_policy = verify_communication_contact_policy_decision(
        policy_decision,
        draft=trusted_draft,
        at=at,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    approval = verify_communication_artifact(
        value,
        artifact_type=CommunicationApprovalGrant,
        scope=scope,
        scope_keyring=scope_keyring,
        at=at,
    )
    if approval.disposition != CommunicationApprovalDisposition.APPROVED:
        raise ValueError("communication approval was not granted")
    expected = (
        approval.draft_digest == trusted_draft.artifact_digest,
        approval.policy_decision_digest == trusted_policy.artifact_digest,
        approval.thread_digest == trusted_draft.thread_digest,
        approval.thread_version == trusted_draft.thread_version,
        approval.thread_state == trusted_draft.thread_state,
        approval.thread_participant_party_refs
        == trusted_draft.thread_participant_party_refs,
        approval.parent_message_sha256 == trusted_draft.parent_message_sha256,
        approval.purpose == trusted_draft.purpose,
        approval.channel == trusted_draft.channel,
        approval.sender_endpoint_digest == trusted_draft.sender_endpoint_digest,
        approval.recipient_endpoint_digests == trusted_draft.recipient_endpoint_digests,
        approval.subject_sha256 == trusted_draft.subject_sha256,
        approval.body_sha256 == trusted_draft.body_sha256,
        approval.attachment_sha256s == trusted_draft.attachment_sha256s,
        approval.connector_account_ref == connector_account_ref,
        hmac.compare_digest(approval.route_digest, route_digest),
        hmac.compare_digest(approval.schedule_digest, schedule_digest),
    )
    if not all(expected):
        raise ValueError(
            "communication approval does not bind the exact draft, audience, route, and schedule"
        )
    return approval


def verify_communication_contact_reservation(
    value: CommunicationContactReservation | Mapping[str, Any],
    *,
    request: CommunicationContactReservationRequest,
    at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationContactReservation:
    """Verify the current reservation belongs to the exact sealed request."""

    trusted_request = verify_communication_artifact(
        request,
        artifact_type=CommunicationContactReservationRequest,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    reservation = verify_communication_artifact(
        value,
        artifact_type=CommunicationContactReservation,
        scope=scope,
        scope_keyring=scope_keyring,
        at=at,
    )
    _same_digest(
        reservation.request_digest,
        trusted_request.artifact_digest,
        label="reservation request",
    )
    _same_digest(
        reservation.slot_digest,
        trusted_request.slot_digest,
        label="reservation slot",
    )
    return reservation


def verify_communication_contact_reservation_consumption(
    value: CommunicationContactReservationConsumption | Mapping[str, Any],
    *,
    reservation: CommunicationContactReservation,
    request: CommunicationContactReservationRequest,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationContactReservationConsumption:
    """Verify the single-use proof for one exact reservation and request."""

    trusted_request = verify_communication_artifact(
        request,
        artifact_type=CommunicationContactReservationRequest,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_reservation = verify_communication_artifact(
        reservation,
        artifact_type=CommunicationContactReservation,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    consumption = verify_communication_artifact(
        value,
        artifact_type=CommunicationContactReservationConsumption,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    if (
        consumption.reservation_ref != trusted_reservation.reservation_ref
        or not hmac.compare_digest(
            consumption.request_digest,
            trusted_request.artifact_digest,
        )
        or not hmac.compare_digest(
            consumption.slot_digest,
            trusted_request.slot_digest,
        )
        or not hmac.compare_digest(
            trusted_reservation.request_digest,
            trusted_request.artifact_digest,
        )
        or not hmac.compare_digest(
            trusted_reservation.slot_digest,
            trusted_request.slot_digest,
        )
    ):
        raise ValueError("contact reservation consumption does not match request")
    consumed_at = _parse_timestamp(consumption.consumed_at, label="consumed_at")
    reserved_at = _parse_timestamp(trusted_reservation.reserved_at, label="reserved_at")
    valid_until = _parse_timestamp(
        trusted_reservation.valid_until,
        label="valid_until",
    )
    if consumed_at < reserved_at or consumed_at >= valid_until:
        raise ValueError("contact reservation was not current when consumed")
    return consumption


def verify_communication_dispatch_authority(
    *,
    draft: CommunicationMessageDraft,
    policy_decision: CommunicationContactPolicyDecision,
    approval_grant: CommunicationApprovalGrant,
    reservation_request: CommunicationContactReservationRequest,
    reservation: CommunicationContactReservation,
    reservation_consumption: CommunicationContactReservationConsumption,
    connector_account_ref: str,
    route_digest: str,
    schedule_digest: str,
    at: datetime,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    max_consumption_age: timedelta = timedelta(minutes=1),
) -> tuple[
    CommunicationMessageDraft,
    CommunicationContactPolicyDecision,
    CommunicationApprovalGrant,
    CommunicationContactReservationConsumption,
]:
    """Verify the complete authority bundle immediately before connector I/O."""

    timestamp = _utc(at, label="at")
    if max_consumption_age <= timedelta(0) or max_consumption_age > timedelta(
        minutes=5
    ):
        raise ValueError(
            "max_consumption_age must be greater than zero and at most 5 minutes"
        )
    trusted_draft = verify_communication_artifact(
        draft,
        artifact_type=CommunicationMessageDraft,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_policy = verify_communication_contact_policy_decision(
        policy_decision,
        draft=trusted_draft,
        at=timestamp,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_approval = verify_communication_approval_grant(
        approval_grant,
        draft=trusted_draft,
        policy_decision=trusted_policy,
        connector_account_ref=connector_account_ref,
        route_digest=route_digest,
        schedule_digest=schedule_digest,
        at=timestamp,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    trusted_request = verify_communication_artifact(
        reservation_request,
        artifact_type=CommunicationContactReservationRequest,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    if (
        trusted_request.draft_digest != trusted_draft.artifact_digest
        or trusted_request.policy_decision_digest != trusted_policy.artifact_digest
        or trusted_request.purpose != trusted_draft.purpose
        or trusted_request.channel != trusted_draft.channel
        or trusted_request.recipient_endpoint_digests
        != trusted_draft.recipient_endpoint_digests
        or trusted_request.company_contact_scope_digest
        != trusted_draft.company_contact_scope_digest
        or trusted_request.contact_token_key_id
        != trusted_draft.contact_token_key_id
        or trusted_request.recipient_contact_digests
        != trusted_draft.recipient_contact_digests
        or trusted_request.recipient_address_digests
        != trusted_draft.recipient_address_digests
    ):
        raise ValueError("contact reservation request does not match dispatch draft")
    trusted_consumption = verify_communication_contact_reservation_consumption(
        reservation_consumption,
        reservation=reservation,
        request=trusted_request,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    consumed_at = _parse_timestamp(trusted_consumption.consumed_at, label="consumed_at")
    if consumed_at > timestamp or timestamp - consumed_at > max_consumption_age:
        raise ValueError(
            "contact reservation was not consumed immediately before dispatch"
        )
    return (
        trusted_draft,
        trusted_policy,
        trusted_approval,
        trusted_consumption,
    )


class InMemoryCommunicationContactReservationAuthority:
    """Thread-safe reference authority; production hosts require durable storage."""

    def __init__(self, *, contact_token_key_id: str) -> None:
        clean_key_id = contact_token_key_id.strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,79}", clean_key_id) is None:
            raise ValueError("contact_token_key_id must contain 8-80 safe characters")
        self.contact_token_key_id = clean_key_id
        self._active: dict[str, CommunicationContactReservation] = {}
        self._closed_slots: set[str] = set()
        self._consumptions: dict[
            str,
            CommunicationContactReservationConsumption,
        ] = {}
        self._lock = threading.RLock()

    def reserve(
        self,
        request: CommunicationContactReservationRequest,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: CommunicationScopeKeyRing,
        reserved_at: datetime,
        ttl_seconds: int = 900,
    ) -> CommunicationContactReservation:
        timestamp = _utc(reserved_at, label="reserved_at")
        if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 900:
            raise ValueError("ttl_seconds must be an integer from 1 through 900")
        until = timestamp + timedelta(seconds=ttl_seconds)
        workflow_scope = _workflow_scope(scope)
        trusted_request = verify_communication_artifact(
            request,
            artifact_type=CommunicationContactReservationRequest,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if trusted_request.contact_token_key_id != self.contact_token_key_id:
            raise ValueError(
                "contact reservation does not use the authority tokenization key"
            )
        with self._lock:
            if trusted_request.slot_digest in self._closed_slots:
                raise CommunicationContactReservationConflict(
                    "the communication contact slot was already consumed"
                )
            active = self._active.get(trusted_request.slot_digest)
            if active is not None:
                active_expiry = _parse_timestamp(
                    active.valid_until,
                    label="valid_until",
                )
                if timestamp < active_expiry:
                    if hmac.compare_digest(
                        active.request_digest,
                        trusted_request.artifact_digest,
                    ):
                        return active
                    raise CommunicationContactReservationConflict(
                        "another communication run owns the contact slot"
                    )
                self._active.pop(trusted_request.slot_digest, None)
            reservation = mint_communication_artifact(
                CommunicationContactReservation,
                {
                    "reservation_ref": (
                        f"reservation_{trusted_request.artifact_digest[:40]}"
                    ),
                    "request_digest": trusted_request.artifact_digest,
                    "slot_digest": trusted_request.slot_digest,
                    "reserved_at": timestamp.isoformat(),
                    "valid_until": until.isoformat(),
                },
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            )
            self._active[trusted_request.slot_digest] = reservation
            return reservation

    def consume(
        self,
        reservation: CommunicationContactReservation,
        *,
        request: CommunicationContactReservationRequest,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: CommunicationScopeKeyRing,
        consumed_at: datetime,
    ) -> CommunicationContactReservationConsumption:
        timestamp = _utc(consumed_at, label="consumed_at")
        workflow_scope = _workflow_scope(scope)
        trusted_request = verify_communication_artifact(
            request,
            artifact_type=CommunicationContactReservationRequest,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if trusted_request.contact_token_key_id != self.contact_token_key_id:
            raise ValueError(
                "contact reservation does not use the authority tokenization key"
            )
        trusted_reservation = verify_communication_contact_reservation(
            reservation,
            request=trusted_request,
            at=timestamp,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        with self._lock:
            existing = self._consumptions.get(trusted_reservation.reservation_ref)
            if existing is not None:
                return verify_communication_contact_reservation_consumption(
                    existing,
                    reservation=trusted_reservation,
                    request=trusted_request,
                    scope=workflow_scope,
                    scope_keyring=scope_keyring,
                )
            active = self._active.get(trusted_request.slot_digest)
            if active is None or not hmac.compare_digest(
                active.artifact_digest,
                trusted_reservation.artifact_digest,
            ):
                raise CommunicationContactReservationConflict(
                    "contact reservation is not the active transactional slot"
                )
            consumption = mint_communication_artifact(
                CommunicationContactReservationConsumption,
                {
                    "consumption_ref": (
                        f"consumed_{trusted_reservation.artifact_digest[:40]}"
                    ),
                    "reservation_ref": trusted_reservation.reservation_ref,
                    "request_digest": trusted_request.artifact_digest,
                    "slot_digest": trusted_request.slot_digest,
                    "consumed_at": timestamp.isoformat(),
                },
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            )
            self._consumptions[trusted_reservation.reservation_ref] = consumption
            self._closed_slots.add(trusted_request.slot_digest)
            self._active.pop(trusted_request.slot_digest, None)
            return consumption


__all__ = [
    "CommunicationContactReservationAuthority",
    "CommunicationContactReservationConflict",
    "InMemoryCommunicationContactReservationAuthority",
    "mint_communication_contact_reservation_request",
    "verify_communication_approval_grant",
    "verify_communication_contact_policy_decision",
    "verify_communication_contact_reservation",
    "verify_communication_contact_reservation_consumption",
    "verify_communication_dispatch_authority",
]
