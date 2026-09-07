"""Durable single-host custody and bounded Gmail communication polling.

This module is a durable single-host reference adapter for the privacy-minimised
communication rail.  One SQLite database implements contact reservations,
reply replay claims, observed-event first-evidence custody, CRM touchpoint
projection, and poll-job leasing.  Raw provider identifiers and the sealed
poll artifacts are deliberately excluded from the queue: a host-supplied,
trusted loader returns them only after a worker has claimed an exact-scope job.

SQLite WAL plus ``BEGIN IMMEDIATE`` provides process-safe compare-and-swap for
one host.  Multi-host deployments must use a transactional control-plane
authority (the Spring V1822 rail), not this standalone SQLite adapter.  The
database must also live in a host-controlled directory; every existing symlink
or Windows junction component is rejected before it is opened.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationContactReservation,
    CommunicationContactReservationConsumption,
    CommunicationContactReservationRequest,
    CommunicationDispatchReceipt,
    CommunicationDispatchState,
    CommunicationEndpointBinding,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationProviderEvent,
    CommunicationScopeKeyRing,
    CommunicationThreadBinding,
    CommunicationThreadState,
    CrmTouchpointReceipt,
    communication_canonical_digest,
    communication_private_value_digest,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.communication_governance import (
    CommunicationContactReservationAuthority,
    CommunicationContactReservationConflict,
    verify_communication_contact_reservation,
    verify_communication_contact_reservation_consumption,
)
from lightbulb.communication_materializer import (
    CommunicationExternalEffectState,
    CommunicationGmailRoute,
    CommunicationMaterializationResult,
    CommunicationMaterializationStatus,
)
from lightbulb.communication_observation import (
    CommunicationGmailObservationResult,
    CommunicationGmailObservationStatus,
    CommunicationGmailReadRoute,
    CommunicationObservedEventRepository,
    CommunicationPrivateGmailDispatch,
    GmailCommunicationObserver,
)
from lightbulb.communication_runtime import (
    CommunicationCrmTraceBinding,
    CommunicationGmailTraceResult,
    CommunicationReplayCapacityExceeded,
    CommunicationReplayClaim,
    CommunicationReplayConflict,
    CommunicationReplayInProgress,
    CommunicationReplayRepository,
    CrmTouchpointSink,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_GMAIL_POLL_JOB_SCHEMA = "lightbulb.communication_gmail_poll_job.v1"
COMMUNICATION_GMAIL_POLL_RUN_SCHEMA = "lightbulb.communication_gmail_poll_run.v1"

_SCHEMA_VERSION = 2
_SCOPE_DOMAIN = "lightbulb.communication_host_scope.v1"
_POLL_ARTIFACTS_DOMAIN = "lightbulb.communication_poll_artifacts_commitment.v1"
_POLL_JOB_DOMAIN = "lightbulb.communication_poll_job_commitment.v1"
_POLL_LEASE_DOMAIN = "lightbulb.communication_poll_lease_commitment.v1"
_POLL_ROUTE_SCHEMA = "lightbulb.communication_poll_route_commitment.v1"
_POLL_ARTIFACTS_SCHEMA = "lightbulb.communication_gmail_poll_artifacts.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_POLL_JOB_COLUMNS = frozenset(
    {
        "scope_token",
        "job_ref",
        "route_digest",
        "artifacts_ref",
        "artifacts_digest",
        "job_digest",
        "state",
        "first_due_at",
        "due_at",
        "deadline_at",
        "attempt_count",
        "max_attempts",
        "poll_interval_seconds",
        "max_messages",
        "lease_owner",
        "lease_token_digest",
        "lease_expires_at",
        "last_error_code",
        "created_at",
        "updated_at",
    }
)


class CommunicationHostPersistenceError(RuntimeError):
    """The local durable communication store is unsafe or inconsistent."""


class CommunicationHostLeaseConflict(RuntimeError):
    """A poll worker lost its compare-and-swap lease."""


class CommunicationGmailPollState(str, Enum):
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    EXHAUSTED = "exhausted"


class CommunicationGmailPollRunStatus(str, Enum):
    PROCESSED = "processed"
    NO_REPLY_RESCHEDULED = "no_reply_rescheduled"
    EXHAUSTED = "exhausted"
    RETRY_SCHEDULED = "retry_scheduled"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
        allow_inf_nan=False,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _utc(value, label="timestamp").isoformat().replace("+00:00", "Z")


def _timestamp(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label)


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    raw = (
        value.model_dump(mode="python")
        if isinstance(value, DynamicWorkflowScope)
        else value
    )
    return DynamicWorkflowScope.model_validate(raw)


def _safe_ref(value: str, *, label: str) -> str:
    clean = str(value).strip()
    if _SAFE_REF_RE.fullmatch(clean) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return clean


def _json_model(value: BaseModel) -> str:
    return json.dumps(
        value.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _reject_unsafe_path_components(path: Path) -> None:
    """Reject aliases inside an otherwise trusted local host directory."""

    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        is_junction = getattr(component, "is_junction", lambda: False)
        if component.is_symlink() or is_junction():
            raise CommunicationHostPersistenceError(
                "refusing a communication database under a symlink or junction"
            )


class CommunicationGmailPollJob(_StrictModel):
    """Privacy-minimised durable status for one bounded Gmail poll schedule."""

    schema_id: Literal["lightbulb.communication_gmail_poll_job.v1"] = Field(
        default=COMMUNICATION_GMAIL_POLL_JOB_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(min_length=1, max_length=200)
    scope_token: str = Field(pattern=r"^[0-9a-f]{64}$")
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifacts_ref: str = Field(min_length=1, max_length=200)
    artifacts_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: CommunicationGmailPollState
    first_due_at: str
    due_at: str
    deadline_at: str
    attempt_count: int = Field(ge=0)
    max_attempts: int = Field(ge=1, le=100)
    poll_interval_seconds: int = Field(ge=1, le=86_400)
    max_messages: int = Field(ge=1, le=10)
    lease_owner: str | None = Field(default=None, max_length=200)
    lease_expires_at: str | None = None
    last_error_code: str | None = Field(default=None, max_length=80)

    @field_validator("job_ref", "artifacts_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _safe_ref(value, label=info.field_name)

    @field_validator("first_due_at", "due_at", "deadline_at", "lease_expires_at")
    @classmethod
    def _times(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _utc_text(_timestamp(value, label=info.field_name))

    @model_validator(mode="after")
    def _shape(self) -> "CommunicationGmailPollJob":
        first_due = _timestamp(self.first_due_at, label="first_due_at")
        due = _timestamp(self.due_at, label="due_at")
        deadline = _timestamp(self.deadline_at, label="deadline_at")
        if deadline <= first_due:
            raise ValueError("poll deadline must follow its first due time")
        if due < first_due:
            raise ValueError("current poll due time cannot precede its first due time")
        leased = (self.lease_owner, self.lease_expires_at)
        if self.state == CommunicationGmailPollState.RUNNING:
            if not all(item is not None for item in leased):
                raise ValueError("running poll jobs require a complete lease")
        elif any(item is not None for item in leased):
            raise ValueError("only running poll jobs may carry a lease")
        return self


class CommunicationGmailPollRun(_StrictModel):
    """One worker attempt; connector errors are represented only by safe codes."""

    schema_id: Literal["lightbulb.communication_gmail_poll_run.v1"] = Field(
        default=COMMUNICATION_GMAIL_POLL_RUN_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(min_length=1, max_length=200)
    status: CommunicationGmailPollRunStatus
    attempt_count: int = Field(ge=1)
    next_due_at: str | None = None
    error_code: str | None = Field(default=None, max_length=80)
    observation: CommunicationGmailObservationResult | None = None

    @field_validator("job_ref")
    @classmethod
    def _job_ref(cls, value: str) -> str:
        return _safe_ref(value, label="job_ref")

    @field_validator("next_due_at")
    @classmethod
    def _next_due(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _utc_text(_timestamp(value, label="next_due_at"))

    @model_validator(mode="after")
    def _run_shape(self) -> "CommunicationGmailPollRun":
        if self.status == CommunicationGmailPollRunStatus.PROCESSED:
            if (
                self.observation is None
                or self.observation.status
                != CommunicationGmailObservationStatus.PROCESSED
                or self.next_due_at is not None
                or self.error_code is not None
            ):
                raise ValueError(
                    "processed poll runs require one processed observation"
                )
        elif self.status == CommunicationGmailPollRunStatus.NO_REPLY_RESCHEDULED:
            if (
                self.observation is None
                or self.observation.status
                != CommunicationGmailObservationStatus.NO_REPLY
                or self.next_due_at is None
                or self.error_code is not None
            ):
                raise ValueError("no-reply run requires its evidence and next due time")
        elif self.status == CommunicationGmailPollRunStatus.RETRY_SCHEDULED:
            if self.next_due_at is None or self.error_code is None:
                raise ValueError("retry run requires safe error and next due time")
        elif self.next_due_at is not None:
            raise ValueError("exhausted poll runs cannot carry a next due time")
        return self


class CommunicationGmailPollArtifacts(_StrictModel):
    """Transient secret-store value committed by a durable poll job.

    Instances can contain provider identifiers through ``private_dispatch``.
    The SQLite queue stores only a host-HMAC commitment and opaque loader ref.
    """

    schema_id: Literal["lightbulb.communication_gmail_poll_artifacts.v1"] = Field(
        default=_POLL_ARTIFACTS_SCHEMA,
        alias="schema",
    )
    read_route: CommunicationGmailReadRoute
    communication_route: CommunicationGmailRoute
    materialization: CommunicationMaterializationResult
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding
    private_dispatch: CommunicationPrivateGmailDispatch


class _PollClaim(_StrictModel):
    job: CommunicationGmailPollJob
    lease_token: str = Field(min_length=32, max_length=64)


TrustedPollArtifactsLoader = Callable[
    [str, DynamicWorkflowScope],
    CommunicationGmailPollArtifacts | Mapping[str, Any],
]

AuthenticatedCommunicationScopeSource = Callable[
    [],
    Iterable[DynamicWorkflowScope | Mapping[str, Any]],
]


class SqliteCommunicationHostStore(
    CommunicationContactReservationAuthority,
    CommunicationReplayRepository,
    CommunicationObservedEventRepository,
    CrmTouchpointSink,
):
    """One transactional SQLite adapter implementing all host custody rails."""

    def __init__(
        self,
        database: str | Path,
        *,
        scope_keyring: CommunicationScopeKeyRing,
        contact_token_key_id: str,
        scope_token_key_id: str,
        max_replay_keys: int = 1_000_000,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if max_replay_keys < 2:
            raise ValueError("max_replay_keys must be at least two")
        if not 0.1 <= busy_timeout_seconds <= 60:
            raise ValueError("busy_timeout_seconds must be between 0.1 and 60")
        contact_key = str(contact_token_key_id).strip()
        scope_key = str(scope_token_key_id).strip()
        if _KEY_ID_RE.fullmatch(contact_key) is None:
            raise ValueError("contact_token_key_id must contain 8-80 safe characters")
        if _KEY_ID_RE.fullmatch(scope_key) is None:
            raise ValueError("scope_token_key_id must contain 8-80 safe characters")
        if contact_key == scope_key:
            raise ValueError("contact and scope tokenization keys must be distinct")
        requested = Path(database).expanduser().absolute()
        _reject_unsafe_path_components(requested)
        requested.parent.mkdir(parents=True, exist_ok=True)
        _reject_unsafe_path_components(requested)
        self.database = requested
        self.scope_keyring = scope_keyring
        self.contact_token_key_id = contact_key
        self.scope_token_key_id = scope_key
        self._max_replay_keys = max_replay_keys
        self._busy_timeout_ms = int(busy_timeout_seconds * 1_000)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database),
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS communication_host_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    contact_token_key_id TEXT NOT NULL,
                    scope_token_key_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS communication_contact_slots (
                    slot_digest TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    reservation_ref TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active', 'consumed')),
                    reservation_json TEXT NOT NULL,
                    consumption_json TEXT,
                    reserved_at TEXT NOT NULL,
                    valid_until TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS communication_replay_keys (
                    dedupe_key TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    claim_ref TEXT,
                    lease_expires_at TEXT,
                    result_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_communication_replay_claim
                    ON communication_replay_keys(claim_ref);

                CREATE TABLE IF NOT EXISTS communication_observed_events (
                    identity_digest TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS communication_crm_touchpoints (
                    touchpoint_ref TEXT PRIMARY KEY,
                    semantic_identity TEXT NOT NULL UNIQUE,
                    exact_scope_digest TEXT NOT NULL,
                    artifact_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS communication_gmail_poll_jobs (
                    scope_token TEXT NOT NULL,
                    job_ref TEXT NOT NULL,
                    route_digest TEXT NOT NULL,
                    artifacts_ref TEXT NOT NULL,
                    artifacts_digest TEXT NOT NULL,
                    job_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('scheduled', 'running', 'completed', 'exhausted')
                    ),
                    first_due_at TEXT NOT NULL,
                    due_at TEXT NOT NULL,
                    deadline_at TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    poll_interval_seconds INTEGER NOT NULL,
                    max_messages INTEGER NOT NULL,
                    lease_owner TEXT,
                    lease_token_digest TEXT,
                    lease_expires_at TEXT,
                    last_error_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (scope_token, job_ref)
                );
                CREATE INDEX IF NOT EXISTS idx_communication_poll_due
                    ON communication_gmail_poll_jobs(scope_token, state, due_at);
                """
            )
            poll_columns = frozenset(
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(communication_gmail_poll_jobs)"
                ).fetchall()
            )
            if poll_columns != _POLL_JOB_COLUMNS:
                raise CommunicationHostPersistenceError(
                    "communication poll queue schema is not privacy-safe"
                )
            row = connection.execute(
                "SELECT * FROM communication_host_meta WHERE singleton = 1"
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO communication_host_meta(
                        singleton, schema_version,
                        contact_token_key_id, scope_token_key_id
                    ) VALUES (1, ?, ?, ?)
                    """,
                    (
                        _SCHEMA_VERSION,
                        self.contact_token_key_id,
                        self.scope_token_key_id,
                    ),
                )
            elif (
                int(row["schema_version"]) != _SCHEMA_VERSION
                or row["contact_token_key_id"] != self.contact_token_key_id
                or row["scope_token_key_id"] != self.scope_token_key_id
            ):
                raise CommunicationHostPersistenceError(
                    "communication database authority metadata does not match host"
                )
        finally:
            connection.close()
        try:
            os.chmod(self.database.parent, 0o700)
            os.chmod(self.database, 0o600)
        except OSError:
            pass

    def scope_token(
        self,
        scope: DynamicWorkflowScope | Mapping[str, Any],
    ) -> str:
        workflow_scope = _workflow_scope(scope)
        return self.scope_keyring.sign(
            self.scope_token_key_id,
            _SCOPE_DOMAIN,
            {
                "schema": _SCOPE_DOMAIN,
                "scope": workflow_scope.model_dump(mode="json"),
            },
        ).hex()

    def poll_artifacts_digest(
        self,
        *,
        artifacts_ref: str,
        artifacts: CommunicationGmailPollArtifacts | Mapping[str, Any],
        scope: DynamicWorkflowScope | Mapping[str, Any],
    ) -> str:
        clean_ref = _safe_ref(artifacts_ref, label="artifacts_ref")
        trusted = CommunicationGmailPollArtifacts.model_validate(artifacts)
        return self.scope_keyring.sign(
            self.scope_token_key_id,
            _POLL_ARTIFACTS_DOMAIN,
            {
                "schema": _POLL_ARTIFACTS_DOMAIN,
                "scope_token": self.scope_token(scope),
                "artifacts_ref": clean_ref,
                "artifacts": trusted.model_dump(mode="json", by_alias=True),
            },
        ).hex()

    def poll_route_digest(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        read_route: CommunicationGmailReadRoute,
        communication_route: CommunicationGmailRoute,
    ) -> str:
        return self.scope_keyring.sign(
            self.scope_token_key_id,
            _POLL_ROUTE_SCHEMA,
            {
                "schema": _POLL_ROUTE_SCHEMA,
                "scope_token": self.scope_token(scope),
                "read_route": read_route.model_dump(mode="json", by_alias=True),
                "communication_route": communication_route.model_dump(
                    mode="json",
                    by_alias=True,
                ),
            },
        ).hex()

    def _poll_job_digest(
        self,
        *,
        scope_token: str,
        job_ref: str,
        route_digest: str,
        artifacts_ref: str,
        artifacts_digest: str,
        first_due_at: str,
        deadline_at: str,
        poll_interval_seconds: int,
        max_attempts: int,
        max_messages: int,
    ) -> str:
        return self.scope_keyring.sign(
            self.scope_token_key_id,
            _POLL_JOB_DOMAIN,
            {
                "schema": _POLL_JOB_DOMAIN,
                "scope_token": scope_token,
                "job_ref": job_ref,
                "route_digest": route_digest,
                "artifacts_ref": artifacts_ref,
                "artifacts_digest": artifacts_digest,
                "first_due_at": first_due_at,
                "deadline_at": deadline_at,
                "poll_interval_seconds": poll_interval_seconds,
                "max_attempts": max_attempts,
                "max_messages": max_messages,
            },
        ).hex()

    def _poll_lease_digest(
        self,
        *,
        scope_token: str,
        job_ref: str,
        lease_token: str,
    ) -> str:
        return self.scope_keyring.sign(
            self.scope_token_key_id,
            _POLL_LEASE_DOMAIN,
            {
                "schema": _POLL_LEASE_DOMAIN,
                "scope_token": scope_token,
                "job_ref": job_ref,
                "lease_token": lease_token,
            },
        ).hex()

    def verify_poll_job(
        self,
        job: CommunicationGmailPollJob,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
    ) -> CommunicationGmailPollJob:
        trusted = CommunicationGmailPollJob.model_validate(job)
        expected_scope = self.scope_token(scope)
        expected_job = self._poll_job_digest(
            scope_token=expected_scope,
            job_ref=trusted.job_ref,
            route_digest=trusted.route_digest,
            artifacts_ref=trusted.artifacts_ref,
            artifacts_digest=trusted.artifacts_digest,
            first_due_at=trusted.first_due_at,
            deadline_at=trusted.deadline_at,
            poll_interval_seconds=trusted.poll_interval_seconds,
            max_attempts=trusted.max_attempts,
            max_messages=trusted.max_messages,
        )
        if not hmac.compare_digest(trusted.scope_token, expected_scope) or not (
            hmac.compare_digest(trusted.job_digest, expected_job)
        ):
            raise CommunicationHostPersistenceError(
                "poll job failed exact-scope host commitment verification"
            )
        return trusted

    # -- CommunicationContactReservationAuthority -------------------------

    def reserve(
        self,
        request: CommunicationContactReservationRequest,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        scope_keyring: CommunicationScopeKeyRing,
        reserved_at: datetime,
        ttl_seconds: int = 900,
    ) -> CommunicationContactReservation:
        # Protocol compatibility carries a keyring argument, but persistence
        # authority is fixed at construction and is never caller-delegated.
        del scope_keyring
        current = _utc(reserved_at, label="reserved_at")
        if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 900:
            raise ValueError("ttl_seconds must be an integer from 1 through 900")
        trusted = verify_communication_artifact(
            request,
            artifact_type=CommunicationContactReservationRequest,
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        if trusted.contact_token_key_id != self.contact_token_key_id:
            raise ValueError(
                "contact reservation does not use the host tokenization key"
            )
        reservation = mint_communication_artifact(
            CommunicationContactReservation,
            {
                "reservation_ref": f"reservation_{trusted.artifact_digest[:40]}",
                "request_digest": trusted.artifact_digest,
                "slot_digest": trusted.slot_digest,
                "reserved_at": _utc_text(current),
                "valid_until": _utc_text(current + timedelta(seconds=ttl_seconds)),
            },
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM communication_contact_slots WHERE slot_digest = ?",
                (trusted.slot_digest,),
            ).fetchone()
            if row is not None:
                if row["state"] == "consumed":
                    raise CommunicationContactReservationConflict(
                        "the communication contact slot was already consumed"
                    )
                if _timestamp(row["valid_until"], label="valid_until") > current:
                    if not hmac.compare_digest(
                        row["request_digest"],
                        trusted.artifact_digest,
                    ):
                        raise CommunicationContactReservationConflict(
                            "another communication run owns the contact slot"
                        )
                    return verify_communication_artifact(
                        json.loads(row["reservation_json"]),
                        artifact_type=CommunicationContactReservation,
                        scope=scope,
                        scope_keyring=self.scope_keyring,
                    )
                connection.execute(
                    "DELETE FROM communication_contact_slots WHERE slot_digest = ?",
                    (trusted.slot_digest,),
                )
            connection.execute(
                """
                INSERT INTO communication_contact_slots(
                    slot_digest, request_digest, reservation_ref, state,
                    reservation_json, consumption_json, reserved_at, valid_until
                ) VALUES (?, ?, ?, 'active', ?, NULL, ?, ?)
                """,
                (
                    trusted.slot_digest,
                    trusted.artifact_digest,
                    reservation.reservation_ref,
                    _json_model(reservation),
                    reservation.reserved_at,
                    reservation.valid_until,
                ),
            )
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
        del scope_keyring
        current = _utc(consumed_at, label="consumed_at")
        trusted_request = verify_communication_artifact(
            request,
            artifact_type=CommunicationContactReservationRequest,
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        if trusted_request.contact_token_key_id != self.contact_token_key_id:
            raise ValueError(
                "contact reservation does not use the host tokenization key"
            )
        trusted_reservation = verify_communication_contact_reservation(
            reservation,
            request=trusted_request,
            at=current,
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        candidate = mint_communication_artifact(
            CommunicationContactReservationConsumption,
            {
                "consumption_ref": (
                    f"consumed_{trusted_reservation.artifact_digest[:40]}"
                ),
                "reservation_ref": trusted_reservation.reservation_ref,
                "request_digest": trusted_request.artifact_digest,
                "slot_digest": trusted_request.slot_digest,
                "consumed_at": _utc_text(current),
            },
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM communication_contact_slots WHERE slot_digest = ?",
                (trusted_request.slot_digest,),
            ).fetchone()
            if row is None:
                raise CommunicationContactReservationConflict(
                    "contact reservation is not the active transactional slot"
                )
            if row["state"] == "consumed":
                return verify_communication_contact_reservation_consumption(
                    json.loads(row["consumption_json"]),
                    reservation=trusted_reservation,
                    request=trusted_request,
                    scope=scope,
                    scope_keyring=self.scope_keyring,
                )
            if (
                row["reservation_ref"] != trusted_reservation.reservation_ref
                or not hmac.compare_digest(
                    row["request_digest"],
                    trusted_request.artifact_digest,
                )
                or _timestamp(row["valid_until"], label="valid_until") <= current
            ):
                raise CommunicationContactReservationConflict(
                    "contact reservation lost exact slot custody"
                )
            connection.execute(
                """
                UPDATE communication_contact_slots
                SET state = 'consumed', consumption_json = ?
                WHERE slot_digest = ? AND state = 'active'
                """,
                (_json_model(candidate), trusted_request.slot_digest),
            )
        return candidate

    # -- CommunicationReplayRepository -----------------------------------

    def claim(
        self,
        *,
        dedupe_keys: tuple[str, ...],
        request_digest: str,
        claimed_at: datetime,
        lease_for: timedelta,
    ) -> CommunicationReplayClaim:
        current = _utc(claimed_at, label="claimed_at")
        if not dedupe_keys or len(dedupe_keys) != len(set(dedupe_keys)):
            raise ValueError("dedupe_keys must be non-empty and unique")
        if any(_SHA256_RE.fullmatch(key) is None for key in dedupe_keys):
            raise ValueError("dedupe_keys must be SHA-256 digests")
        if _SHA256_RE.fullmatch(request_digest) is None:
            raise ValueError("request_digest must be a SHA-256 digest")
        if lease_for <= timedelta(0) or lease_for > timedelta(minutes=15):
            raise ValueError(
                "lease_for must be greater than zero and at most 15 minutes"
            )
        placeholders = ",".join("?" for _ in dedupe_keys)
        with self._transaction() as connection:
            rows = connection.execute(
                f"SELECT * FROM communication_replay_keys WHERE dedupe_key IN ({placeholders})",
                dedupe_keys,
            ).fetchall()
            for row in rows:
                if not hmac.compare_digest(row["request_digest"], request_digest):
                    raise CommunicationReplayConflict(
                        "communication dedupe identity is bound to different evidence"
                    )
            completed = [row for row in rows if row["result_json"] is not None]
            if completed:
                if len(rows) != len(dedupe_keys) or len(completed) != len(rows):
                    raise CommunicationReplayConflict(
                        "communication dedupe keys do not resolve to one completed result"
                    )
                results = [
                    CommunicationGmailTraceResult.model_validate_json(
                        row["result_json"]
                    )
                    for row in completed
                ]
                canonical = communication_canonical_digest(
                    results[0].model_dump(mode="json", by_alias=True)
                )
                if any(
                    communication_canonical_digest(
                        item.model_dump(mode="json", by_alias=True)
                    )
                    != canonical
                    for item in results[1:]
                ):
                    raise CommunicationReplayConflict(
                        "communication dedupe keys resolve to different results"
                    )
                return CommunicationReplayClaim(
                    claim_ref=f"replay:{request_digest[:48]}",
                    dedupe_keys=dedupe_keys,
                    request_digest=request_digest,
                    lease_expires_at=_utc_text(current),
                    replayed_result=results[0].model_copy(update={"replayed": True}),
                )
            for row in rows:
                if (
                    row["claim_ref"] is not None
                    and row["lease_expires_at"] is not None
                    and _timestamp(
                        row["lease_expires_at"],
                        label="lease_expires_at",
                    )
                    > current
                ):
                    raise CommunicationReplayInProgress(
                        "communication message already has a live processing lease"
                    )
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM communication_replay_keys"
                ).fetchone()[0]
            )
            missing = len(dedupe_keys) - len(rows)
            if count + missing > self._max_replay_keys:
                raise CommunicationReplayCapacityExceeded(
                    "communication replay repository is full; no evidence was evicted"
                )
            claim_ref = f"claim:{uuid4()}"
            expires = _utc_text(current + lease_for)
            for key in dedupe_keys:
                connection.execute(
                    """
                    INSERT INTO communication_replay_keys(
                        dedupe_key, request_digest, claim_ref,
                        lease_expires_at, result_json
                    ) VALUES (?, ?, ?, ?, NULL)
                    ON CONFLICT(dedupe_key) DO UPDATE SET
                        request_digest = excluded.request_digest,
                        claim_ref = excluded.claim_ref,
                        lease_expires_at = excluded.lease_expires_at,
                        result_json = NULL
                    """,
                    (key, request_digest, claim_ref, expires),
                )
        return CommunicationReplayClaim(
            claim_ref=claim_ref,
            dedupe_keys=dedupe_keys,
            request_digest=request_digest,
            lease_expires_at=expires,
        )

    def complete(
        self,
        claim: CommunicationReplayClaim,
        *,
        result: CommunicationGmailTraceResult,
    ) -> None:
        trusted_claim = CommunicationReplayClaim.model_validate(claim)
        if trusted_claim.replayed_result is not None:
            raise CommunicationReplayConflict(
                "a replay claim cannot be completed again"
            )
        stored = CommunicationGmailTraceResult.model_validate(result).model_copy(
            update={"replayed": False}
        )
        placeholders = ",".join("?" for _ in trusted_claim.dedupe_keys)
        with self._transaction() as connection:
            rows = connection.execute(
                f"SELECT * FROM communication_replay_keys WHERE dedupe_key IN ({placeholders})",
                trusted_claim.dedupe_keys,
            ).fetchall()
            if len(rows) != len(trusted_claim.dedupe_keys) or any(
                row["claim_ref"] != trusted_claim.claim_ref
                or not hmac.compare_digest(
                    row["request_digest"],
                    trusted_claim.request_digest,
                )
                or row["result_json"] is not None
                for row in rows
            ):
                raise CommunicationReplayConflict(
                    "communication replay claim lost custody before completion"
                )
            connection.execute(
                f"""
                UPDATE communication_replay_keys
                SET claim_ref = NULL, lease_expires_at = NULL, result_json = ?
                WHERE dedupe_key IN ({placeholders})
                """,
                (_json_model(stored), *trusted_claim.dedupe_keys),
            )

    def release(self, claim: CommunicationReplayClaim) -> None:
        trusted = CommunicationReplayClaim.model_validate(claim)
        if trusted.replayed_result is not None:
            return
        placeholders = ",".join("?" for _ in trusted.dedupe_keys)
        with self._transaction() as connection:
            connection.execute(
                f"""
                DELETE FROM communication_replay_keys
                WHERE claim_ref = ? AND dedupe_key IN ({placeholders})
                """,
                (trusted.claim_ref, *trusted.dedupe_keys),
            )

    # -- CommunicationObservedEventRepository ----------------------------

    def get(self, identity_digest: str) -> CommunicationProviderEvent | None:
        if _SHA256_RE.fullmatch(identity_digest) is None:
            raise ValueError("observed event identity must be a SHA-256 digest")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT event_json FROM communication_observed_events
                WHERE identity_digest = ?
                """,
                (identity_digest,),
            ).fetchone()
        finally:
            connection.close()
        return (
            CommunicationProviderEvent.model_validate_json(row["event_json"])
            if row is not None
            else None
        )

    def put(
        self,
        identity_digest: str,
        event: CommunicationProviderEvent,
    ) -> CommunicationProviderEvent:
        if _SHA256_RE.fullmatch(identity_digest) is None:
            raise ValueError("observed event identity must be a SHA-256 digest")
        trusted = CommunicationProviderEvent.model_validate(event)
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT event_json FROM communication_observed_events
                WHERE identity_digest = ?
                """,
                (identity_digest,),
            ).fetchone()
            if row is not None:
                existing = CommunicationProviderEvent.model_validate_json(
                    row["event_json"]
                )
                stable_existing = (
                    existing.dispatch_receipt_digest,
                    existing.provider_message_sha256,
                    existing.provider_thread_sha256,
                    existing.connector_account_ref,
                    existing.route_digest,
                )
                stable_candidate = (
                    trusted.dispatch_receipt_digest,
                    trusted.provider_message_sha256,
                    trusted.provider_thread_sha256,
                    trusted.connector_account_ref,
                    trusted.route_digest,
                )
                if stable_existing != stable_candidate:
                    raise CommunicationReplayConflict(
                        "observed Gmail identity is bound to different evidence"
                    )
                return existing
            connection.execute(
                """
                INSERT INTO communication_observed_events(identity_digest, event_json)
                VALUES (?, ?)
                """,
                (identity_digest, _json_model(trusted)),
            )
        return trusted

    # -- CrmTouchpointSink -------------------------------------------------

    def append(
        self,
        receipt: CrmTouchpointReceipt,
        *,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> CrmTouchpointReceipt:
        del scope_keyring
        trusted = verify_communication_artifact(
            receipt,
            artifact_type=CrmTouchpointReceipt,
            scope=scope,
            scope_keyring=self.scope_keyring,
        )
        identity = communication_canonical_digest(
            {
                "schema": "lightbulb.crm_touchpoint_identity.v1",
                "exact_scope_digest": trusted.exact_scope_digest,
                "crm_contact_ref": trusted.crm_contact_ref,
                "thread_ref": trusted.thread_ref,
                "touchpoint_type": trusted.touchpoint_type,
                "message_artifact_digest": trusted.message_artifact_digest,
            }
        )
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT artifact_json FROM communication_crm_touchpoints
                WHERE touchpoint_ref = ? OR semantic_identity = ?
                """,
                (trusted.touchpoint_ref, identity),
            ).fetchall()
            for row in rows:
                prior = CrmTouchpointReceipt.model_validate_json(row["artifact_json"])
                if not hmac.compare_digest(
                    prior.artifact_digest,
                    trusted.artifact_digest,
                ):
                    raise CommunicationReplayConflict(
                        "CRM touchpoint identity is bound to different evidence"
                    )
            if rows:
                return CrmTouchpointReceipt.model_validate_json(
                    rows[0]["artifact_json"]
                )
            connection.execute(
                """
                INSERT INTO communication_crm_touchpoints(
                    touchpoint_ref, semantic_identity,
                    exact_scope_digest, artifact_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    trusted.touchpoint_ref,
                    identity,
                    trusted.exact_scope_digest,
                    _json_model(trusted),
                ),
            )
        return trusted

    def count_touchpoints(self, *, scope: DynamicWorkflowScope) -> int:
        """Return a scope-isolated projection count for host diagnostics."""

        token_digests = {
            self.scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
            for key_id in self._receipt_key_ids()
        }
        if not token_digests:
            return 0
        placeholders = ",".join("?" for _ in token_digests)
        connection = self._connect()
        try:
            return int(
                connection.execute(
                    f"""
                    SELECT COUNT(*) FROM communication_crm_touchpoints
                    WHERE exact_scope_digest IN ({placeholders})
                    """,
                    tuple(token_digests),
                ).fetchone()[0]
            )
        finally:
            connection.close()

    def _receipt_key_ids(self) -> tuple[str, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT DISTINCT json_extract(artifact_json, '$.receipt_key_id') AS key_id
                FROM communication_crm_touchpoints
                """
            ).fetchall()
        finally:
            connection.close()
        return tuple(str(row["key_id"]) for row in rows if row["key_id"])

    # -- Durable poll jobs -------------------------------------------------

    def schedule_poll(
        self,
        *,
        job_ref: str,
        scope: DynamicWorkflowScope,
        route_digest: str,
        artifacts_ref: str,
        artifacts_digest: str,
        due_at: datetime,
        deadline_at: datetime,
        poll_interval_seconds: int,
        max_attempts: int,
        max_messages: int,
        scheduled_at: datetime,
    ) -> CommunicationGmailPollJob:
        clean_ref = _safe_ref(job_ref, label="job_ref")
        due = _utc(due_at, label="due_at")
        deadline = _utc(deadline_at, label="deadline_at")
        created = _utc(scheduled_at, label="scheduled_at")
        if due < created:
            raise ValueError("poll due_at cannot precede scheduled_at")
        if deadline <= due or deadline - due > timedelta(days=30):
            raise ValueError("poll deadline must follow due_at by at most 30 days")
        if (
            isinstance(poll_interval_seconds, bool)
            or not 1 <= poll_interval_seconds <= 86_400
        ):
            raise ValueError("poll_interval_seconds must be from 1 through 86400")
        if isinstance(max_attempts, bool) or not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be from 1 through 100")
        if isinstance(max_messages, bool) or not 1 <= max_messages <= 10:
            raise ValueError("max_messages must be from 1 through 10")
        if _SHA256_RE.fullmatch(route_digest) is None:
            raise ValueError("route_digest must be a SHA-256 digest")
        if _SHA256_RE.fullmatch(artifacts_digest) is None:
            raise ValueError("artifacts_digest must be a SHA-256 digest")
        clean_artifacts_ref = _safe_ref(artifacts_ref, label="artifacts_ref")
        scope_token = self.scope_token(scope)
        job_digest = self._poll_job_digest(
            scope_token=scope_token,
            job_ref=clean_ref,
            route_digest=route_digest,
            artifacts_ref=clean_artifacts_ref,
            artifacts_digest=artifacts_digest,
            first_due_at=_utc_text(due),
            deadline_at=_utc_text(deadline),
            poll_interval_seconds=poll_interval_seconds,
            max_attempts=max_attempts,
            max_messages=max_messages,
        )
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM communication_gmail_poll_jobs
                WHERE scope_token = ? AND job_ref = ?
                """,
                (scope_token, clean_ref),
            ).fetchone()
            if row is not None:
                if not hmac.compare_digest(row["job_digest"], job_digest):
                    raise CommunicationReplayConflict(
                        "poll job identity is bound to different sealed evidence"
                    )
                return self.verify_poll_job(
                    self._job_from_row(row),
                    scope=scope,
                )
            connection.execute(
                """
                INSERT INTO communication_gmail_poll_jobs(
                    scope_token, job_ref, route_digest, artifacts_ref,
                    artifacts_digest, job_digest,
                    state, first_due_at, due_at, deadline_at,
                    attempt_count, max_attempts,
                    poll_interval_seconds, max_messages,
                    lease_owner, lease_token_digest, lease_expires_at,
                    last_error_code, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, ?, 0, ?, ?, ?,
                          NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    scope_token,
                    clean_ref,
                    route_digest,
                    clean_artifacts_ref,
                    artifacts_digest,
                    job_digest,
                    _utc_text(due),
                    _utc_text(due),
                    _utc_text(deadline),
                    max_attempts,
                    poll_interval_seconds,
                    max_messages,
                    _utc_text(created),
                    _utc_text(created),
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM communication_gmail_poll_jobs
                WHERE scope_token = ? AND job_ref = ?
                """,
                (scope_token, clean_ref),
            ).fetchone()
        assert row is not None
        return self._job_from_row(row)

    def claim_due_polls(
        self,
        *,
        scope: DynamicWorkflowScope,
        worker_ref: str,
        now: datetime,
        lease_for: timedelta,
        limit: int,
    ) -> tuple[_PollClaim, ...]:
        worker = _safe_ref(worker_ref, label="worker_ref")
        current = _utc(now, label="now")
        if lease_for <= timedelta(0) or lease_for > timedelta(minutes=15):
            raise ValueError(
                "poll lease must be greater than zero and at most 15 minutes"
            )
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("poll worker limit must be from 1 through 100")
        scope_token = self.scope_token(scope)
        claims: list[_PollClaim] = []
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE communication_gmail_poll_jobs
                SET state = 'exhausted', lease_owner = NULL,
                    lease_token_digest = NULL, lease_expires_at = NULL,
                    last_error_code = 'poll_window_exhausted', updated_at = ?
                WHERE scope_token = ?
                  AND (
                    (state = 'scheduled' AND (
                        attempt_count >= max_attempts OR deadline_at < ?
                    ))
                    OR (state = 'running' AND lease_expires_at <= ? AND (
                        attempt_count >= max_attempts OR deadline_at < ?
                    ))
                  )
                """,
                (
                    _utc_text(current),
                    scope_token,
                    _utc_text(current),
                    _utc_text(current),
                    _utc_text(current),
                ),
            )
            rows = connection.execute(
                """
                SELECT * FROM communication_gmail_poll_jobs
                WHERE scope_token = ?
                  AND attempt_count < max_attempts
                  AND due_at <= ?
                  AND deadline_at >= ?
                  AND (
                    state = 'scheduled'
                    OR (state = 'running' AND lease_expires_at <= ?)
                  )
                ORDER BY due_at, job_ref
                LIMIT ?
                """,
                (
                    scope_token,
                    _utc_text(current),
                    _utc_text(current),
                    _utc_text(current),
                    limit,
                ),
            ).fetchall()
            for row in rows:
                lease_token = uuid4().hex
                lease_token_digest = self._poll_lease_digest(
                    scope_token=scope_token,
                    job_ref=row["job_ref"],
                    lease_token=lease_token,
                )
                expires = _utc_text(current + lease_for)
                updated = connection.execute(
                    """
                    UPDATE communication_gmail_poll_jobs
                    SET state = 'running', lease_owner = ?,
                        lease_token_digest = ?,
                        lease_expires_at = ?, attempt_count = attempt_count + 1,
                        updated_at = ?
                    WHERE scope_token = ? AND job_ref = ?
                      AND (
                        state = 'scheduled'
                        OR (state = 'running' AND lease_expires_at <= ?)
                      )
                    """,
                    (
                        worker,
                        lease_token_digest,
                        expires,
                        _utc_text(current),
                        scope_token,
                        row["job_ref"],
                        _utc_text(current),
                    ),
                )
                if updated.rowcount != 1:
                    continue
                claimed_row = connection.execute(
                    """
                    SELECT * FROM communication_gmail_poll_jobs
                    WHERE scope_token = ? AND job_ref = ?
                    """,
                    (scope_token, row["job_ref"]),
                ).fetchone()
                assert claimed_row is not None
                claims.append(
                    _PollClaim(
                        job=self._job_from_row(claimed_row),
                        lease_token=lease_token,
                    )
                )
        return tuple(claims)

    def settle_poll(
        self,
        claim: _PollClaim,
        *,
        now: datetime,
        observation: CommunicationGmailObservationResult | None,
        error_code: str | None,
    ) -> CommunicationGmailPollRun:
        current = _utc(now, label="now")
        if error_code is not None and _ERROR_CODE_RE.fullmatch(error_code) is None:
            raise ValueError("error_code must be a privacy-safe opaque code")
        job = claim.job
        next_due = current + timedelta(seconds=job.poll_interval_seconds)
        processed = (
            observation is not None
            and observation.status == CommunicationGmailObservationStatus.PROCESSED
        )
        exhausted = not processed and (
            job.attempt_count >= job.max_attempts
            or next_due > _timestamp(job.deadline_at, label="deadline_at")
        )
        if processed:
            state = CommunicationGmailPollState.COMPLETED
            status = CommunicationGmailPollRunStatus.PROCESSED
            due_value = job.due_at
        elif exhausted:
            state = CommunicationGmailPollState.EXHAUSTED
            status = CommunicationGmailPollRunStatus.EXHAUSTED
            due_value = job.due_at
        elif error_code is not None:
            state = CommunicationGmailPollState.SCHEDULED
            status = CommunicationGmailPollRunStatus.RETRY_SCHEDULED
            due_value = _utc_text(next_due)
        else:
            state = CommunicationGmailPollState.SCHEDULED
            status = CommunicationGmailPollRunStatus.NO_REPLY_RESCHEDULED
            due_value = _utc_text(next_due)
        run = CommunicationGmailPollRun(
            job_ref=job.job_ref,
            status=status,
            attempt_count=job.attempt_count,
            next_due_at=(
                _utc_text(next_due)
                if status
                in {
                    CommunicationGmailPollRunStatus.NO_REPLY_RESCHEDULED,
                    CommunicationGmailPollRunStatus.RETRY_SCHEDULED,
                }
                else None
            ),
            error_code=error_code,
            observation=observation,
        )
        expected_lease_digest = self._poll_lease_digest(
            scope_token=job.scope_token,
            job_ref=job.job_ref,
            lease_token=claim.lease_token,
        )
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT state, lease_owner, lease_token_digest
                FROM communication_gmail_poll_jobs
                WHERE scope_token = ? AND job_ref = ?
                """,
                (job.scope_token, job.job_ref),
            ).fetchone()
            if (
                row is None
                or row["state"] != CommunicationGmailPollState.RUNNING.value
                or row["lease_owner"] != job.lease_owner
                or row["lease_token_digest"] is None
                or not hmac.compare_digest(
                    row["lease_token_digest"],
                    expected_lease_digest,
                )
            ):
                raise CommunicationHostLeaseConflict(
                    "poll worker lost exact lease custody before settlement"
                )
            updated = connection.execute(
                """
                UPDATE communication_gmail_poll_jobs
                SET state = ?, due_at = ?, lease_owner = NULL,
                    lease_token_digest = NULL, lease_expires_at = NULL,
                    last_error_code = ?, updated_at = ?
                WHERE scope_token = ? AND job_ref = ? AND state = 'running'
                  AND lease_owner = ?
                """,
                (
                    state.value,
                    due_value,
                    error_code,
                    _utc_text(current),
                    job.scope_token,
                    job.job_ref,
                    job.lease_owner,
                ),
            )
            if updated.rowcount != 1:
                raise CommunicationHostLeaseConflict(
                    "poll worker lost exact lease custody before settlement"
                )
        return run

    def get_poll_job(
        self,
        *,
        scope: DynamicWorkflowScope,
        job_ref: str,
    ) -> CommunicationGmailPollJob | None:
        scope_token = self.scope_token(scope)
        clean_ref = _safe_ref(job_ref, label="job_ref")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM communication_gmail_poll_jobs
                WHERE scope_token = ? AND job_ref = ?
                """,
                (scope_token, clean_ref),
            ).fetchone()
        finally:
            connection.close()
        return self._job_from_row(row) if row is not None else None

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> CommunicationGmailPollJob:
        return CommunicationGmailPollJob(
            job_ref=row["job_ref"],
            scope_token=row["scope_token"],
            route_digest=row["route_digest"],
            artifacts_ref=row["artifacts_ref"],
            artifacts_digest=row["artifacts_digest"],
            job_digest=row["job_digest"],
            state=CommunicationGmailPollState(row["state"]),
            first_due_at=row["first_due_at"],
            due_at=row["due_at"],
            deadline_at=row["deadline_at"],
            attempt_count=int(row["attempt_count"]),
            max_attempts=int(row["max_attempts"]),
            poll_interval_seconds=int(row["poll_interval_seconds"]),
            max_messages=int(row["max_messages"]),
            lease_owner=row["lease_owner"],
            lease_expires_at=row["lease_expires_at"],
            last_error_code=row["last_error_code"],
        )


class DurableGmailCommunicationPoller:
    """Schedule and run bounded, exact-scope Gmail observation jobs.

    ``artifacts_loader`` is a trusted host boundary.  It must resolve the
    opaque ref from an authenticated, secret-capable store and return nothing
    for a mismatched scope.  The returned value is still re-verified against
    all sealed artifacts and the queue's host-HMAC before any provider read.
    """

    def __init__(
        self,
        *,
        store: SqliteCommunicationHostStore,
        observer: GmailCommunicationObserver,
        artifacts_loader: TrustedPollArtifactsLoader,
    ) -> None:
        self.store = store
        self.observer = observer
        self.artifacts_loader = artifacts_loader

    def _trusted_artifacts(
        self,
        *,
        scope: DynamicWorkflowScope,
        artifacts: CommunicationGmailPollArtifacts | Mapping[str, Any],
    ) -> CommunicationGmailPollArtifacts:
        candidate = CommunicationGmailPollArtifacts.model_validate(artifacts)
        read = CommunicationGmailReadRoute.model_validate(candidate.read_route)
        write = CommunicationGmailRoute.model_validate(candidate.communication_route)
        materialized = CommunicationMaterializationResult.model_validate(
            candidate.materialization
        )
        trusted_thread = verify_communication_artifact(
            candidate.thread,
            artifact_type=CommunicationThreadBinding,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        trusted_sender = verify_communication_artifact(
            candidate.outbound_sender_endpoint,
            artifact_type=CommunicationEndpointBinding,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        trusted_party = verify_communication_artifact(
            candidate.contact_party,
            artifact_type=CommunicationPartyRef,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        trusted_contact = verify_communication_artifact(
            candidate.contact_endpoint,
            artifact_type=CommunicationEndpointBinding,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        trusted_crm = verify_communication_artifact(
            candidate.crm,
            artifact_type=CommunicationCrmTraceBinding,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        private = CommunicationPrivateGmailDispatch.model_validate(
            candidate.private_dispatch
        )
        if (
            materialized.status != CommunicationMaterializationStatus.COMPLETED
            or materialized.effect_state != CommunicationExternalEffectState.COMPLETED
            or materialized.receipt is None
        ):
            raise ValueError("durable Gmail polling requires a completed dispatch")
        dispatch = verify_communication_artifact(
            materialized.receipt,
            artifact_type=CommunicationDispatchReceipt,
            scope=scope,
            scope_keyring=self.store.scope_keyring,
        )
        if dispatch.state != CommunicationDispatchState.ACCEPTED:
            raise ValueError("durable Gmail polling requires an accepted dispatch")
        if (
            read.project_ref != scope.project_ref
            or write.project_ref != scope.project_ref
            or read.project_id != write.project_id
            or read.connector_account_ref != write.connector_account_ref
            or read.tenant_connector_id != write.tenant_connector_id
        ):
            raise ValueError(
                "poll routes do not match exact authenticated scope/account"
            )
        exact_route = (write.connector_account_ref, write.route_digest)
        if any(
            route != exact_route
            for route in (
                (dispatch.connector_account_ref, dispatch.route_digest),
                (trusted_thread.connector_account_ref, trusted_thread.route_digest),
                (trusted_sender.connector_account_ref, trusted_sender.route_digest),
                (trusted_contact.connector_account_ref, trusted_contact.route_digest),
            )
        ):
            raise ValueError("poll artifacts do not bind the exact communication route")
        if (
            dispatch.thread_ref != trusted_thread.thread_ref
            or dispatch.thread_digest != trusted_thread.artifact_digest
            or dispatch.thread_version != trusted_thread.version
            or dispatch.thread_state != trusted_thread.state
            or dispatch.thread_participant_party_refs
            != trusted_thread.participant_party_refs
            or dispatch.parent_message_sha256 != trusted_thread.parent_message_sha256
            or materialized.thread_ref != trusted_thread.thread_ref
            or materialized.draft_digest != dispatch.draft_digest
        ):
            raise ValueError("poll dispatch does not bind the exact thread artifact")
        if trusted_thread.state != CommunicationThreadState.AWAITING_REPLY:
            raise ValueError("durable Gmail polling requires an awaiting-reply thread")
        if (
            trusted_sender.party_ref not in trusted_thread.participant_party_refs
            or trusted_party.party_ref not in trusted_thread.participant_party_refs
            or trusted_sender.party_ref == trusted_party.party_ref
        ):
            raise ValueError(
                "poll endpoints do not match the sealed thread participants"
            )
        if (
            trusted_party.party_kind != CommunicationPartyKind.CRM_CONTACT
            or trusted_contact.party_ref != trusted_party.party_ref
            or trusted_contact.party_digest != trusted_party.artifact_digest
            or trusted_crm.contact_party_ref != trusted_party.party_ref
            or trusted_crm.contact_party_digest != trusted_party.artifact_digest
            or trusted_crm.contact_endpoint_ref != trusted_contact.endpoint_ref
            or trusted_crm.contact_endpoint_digest != trusted_contact.artifact_digest
            or trusted_crm.crm_contact_ref != trusted_party.crm_contact_ref
            or trusted_crm.crm_account_ref != trusted_party.crm_account_ref
            or trusted_thread.crm_trace_binding_digest != trusted_crm.artifact_digest
        ):
            raise ValueError("poll CRM binding does not match the exact sealed contact")
        if dispatch.provider_message_sha256 is None or not hmac.compare_digest(
            dispatch.provider_message_sha256,
            communication_private_value_digest(private.provider_message_id),
        ):
            raise ValueError("private dispatch message does not match sealed receipt")
        provider_thread_digest = communication_private_value_digest(
            private.provider_thread_id
        )
        if any(
            value is None or not hmac.compare_digest(value, provider_thread_digest)
            for value in (
                dispatch.provider_thread_sha256,
                trusted_thread.provider_thread_sha256,
            )
        ):
            raise ValueError("private dispatch thread does not match sealed receipt")
        return CommunicationGmailPollArtifacts(
            read_route=read,
            communication_route=write,
            materialization=materialized.model_copy(update={"receipt": dispatch}),
            thread=trusted_thread,
            outbound_sender_endpoint=trusted_sender,
            contact_party=trusted_party,
            contact_endpoint=trusted_contact,
            crm=trusted_crm,
            private_dispatch=private,
        )

    def schedule(
        self,
        *,
        job_ref: str,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        artifacts_ref: str,
        artifacts: CommunicationGmailPollArtifacts | Mapping[str, Any],
        due_at: datetime,
        deadline_at: datetime,
        scheduled_at: datetime,
        poll_interval_seconds: int = 300,
        max_attempts: int = 12,
        max_messages: int = 10,
    ) -> CommunicationGmailPollJob:
        workflow_scope = _workflow_scope(scope)
        clean_artifacts_ref = _safe_ref(artifacts_ref, label="artifacts_ref")
        trusted = self._trusted_artifacts(
            scope=workflow_scope,
            artifacts=artifacts,
        )
        route_digest = self.store.poll_route_digest(
            scope=workflow_scope,
            read_route=trusted.read_route,
            communication_route=trusted.communication_route,
        )
        artifacts_digest = self.store.poll_artifacts_digest(
            artifacts_ref=clean_artifacts_ref,
            artifacts=trusted,
            scope=workflow_scope,
        )
        return self.store.schedule_poll(
            job_ref=job_ref,
            scope=workflow_scope,
            route_digest=route_digest,
            artifacts_ref=clean_artifacts_ref,
            artifacts_digest=artifacts_digest,
            due_at=due_at,
            deadline_at=deadline_at,
            poll_interval_seconds=poll_interval_seconds,
            max_attempts=max_attempts,
            max_messages=max_messages,
            scheduled_at=scheduled_at,
        )

    def run_once(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        worker_ref: str,
        now: datetime,
        limit: int = 10,
        lease_seconds: int = 120,
    ) -> tuple[CommunicationGmailPollRun, ...]:
        workflow_scope = _workflow_scope(scope)
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 900:
            raise ValueError("lease_seconds must be from 1 through 900")
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("poll worker limit must be from 1 through 100")
        current = _utc(now, label="now")
        runs: list[CommunicationGmailPollRun] = []
        for _ in range(limit):
            claims = self.store.claim_due_polls(
                scope=workflow_scope,
                worker_ref=worker_ref,
                now=current,
                lease_for=timedelta(seconds=lease_seconds),
                limit=1,
            )
            if not claims:
                break
            claim = claims[0]
            try:
                job = self.store.verify_poll_job(
                    claim.job,
                    scope=workflow_scope,
                )
                resolved = self._trusted_artifacts(
                    scope=workflow_scope,
                    artifacts=self.artifacts_loader(
                        job.artifacts_ref,
                        workflow_scope,
                    ),
                )
                actual_route_digest = self.store.poll_route_digest(
                    scope=workflow_scope,
                    read_route=resolved.read_route,
                    communication_route=resolved.communication_route,
                )
                actual_artifacts_digest = self.store.poll_artifacts_digest(
                    artifacts_ref=job.artifacts_ref,
                    artifacts=resolved,
                    scope=workflow_scope,
                )
                if not (
                    hmac.compare_digest(actual_route_digest, job.route_digest)
                    and hmac.compare_digest(
                        actual_artifacts_digest,
                        job.artifacts_digest,
                    )
                ):
                    raise ValueError(
                        "loaded poll artifacts do not match scheduled commitments"
                    )
                observation = self.observer.poll_once(
                    scope=workflow_scope,
                    read_route=resolved.read_route,
                    communication_route=resolved.communication_route,
                    materialization=resolved.materialization,
                    thread=resolved.thread,
                    outbound_sender_endpoint=resolved.outbound_sender_endpoint,
                    contact_party=resolved.contact_party,
                    contact_endpoint=resolved.contact_endpoint,
                    private_dispatch=resolved.private_dispatch,
                    crm=resolved.crm,
                    now=current,
                    max_messages=job.max_messages,
                )
            except Exception as exc:
                error_code = (
                    "poll_error_"
                    + hashlib.sha256(
                        f"{type(exc).__module__}.{type(exc).__qualname__}".encode(
                            "utf-8"
                        )
                    ).hexdigest()[:16]
                )
                runs.append(
                    self.store.settle_poll(
                        claim,
                        now=current,
                        observation=None,
                        error_code=error_code,
                    )
                )
                continue
            runs.append(
                self.store.settle_poll(
                    claim,
                    now=current,
                    observation=observation,
                    error_code=None,
                )
            )
        return tuple(runs)

    def run_forever(
        self,
        *,
        authenticated_scope_source: AuthenticatedCommunicationScopeSource,
        worker_ref: str,
        stop_event: threading.Event,
        clock: Callable[[], datetime],
        idle_wait_seconds: float = 5.0,
        limit_per_scope: int = 10,
        lease_seconds: int = 120,
        max_scopes_per_cycle: int = 100,
        run_handler: Callable[[tuple[CommunicationGmailPollRun, ...]], None]
        | None = None,
    ) -> None:
        """Serve bounded cycles until ``stop_event`` is set.

        The source is invoked for every cycle so authentication can be revoked
        between cycles.  A scope is never reconstructed from queue state.
        """

        _safe_ref(worker_ref, label="worker_ref")
        if isinstance(limit_per_scope, bool) or not 1 <= limit_per_scope <= 100:
            raise ValueError("limit_per_scope must be from 1 through 100")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 900:
            raise ValueError("lease_seconds must be from 1 through 900")
        if isinstance(idle_wait_seconds, bool) or not 0.01 <= idle_wait_seconds <= 60:
            raise ValueError("idle_wait_seconds must be from 0.01 through 60")
        if isinstance(max_scopes_per_cycle, bool) or not (
            1 <= max_scopes_per_cycle <= 10_000
        ):
            raise ValueError("max_scopes_per_cycle must be from 1 through 10000")
        while not stop_event.is_set():
            seen_scope_tokens: set[str] = set()
            scope_count = 0
            for raw_scope in authenticated_scope_source():
                scope_count += 1
                if scope_count > max_scopes_per_cycle:
                    raise ValueError("authenticated scope source exceeded cycle bound")
                workflow_scope = _workflow_scope(raw_scope)
                scope_token = self.store.scope_token(workflow_scope)
                if scope_token in seen_scope_tokens:
                    continue
                seen_scope_tokens.add(scope_token)
                if stop_event.is_set():
                    break
                runs = self.run_once(
                    scope=workflow_scope,
                    worker_ref=worker_ref,
                    now=clock(),
                    limit=limit_per_scope,
                    lease_seconds=lease_seconds,
                )
                if runs and run_handler is not None:
                    run_handler(runs)
            if stop_event.wait(idle_wait_seconds):
                break


def serve_durable_gmail_communication_poller(
    poller: DurableGmailCommunicationPoller,
    *,
    authenticated_scope_source: AuthenticatedCommunicationScopeSource,
    worker_ref: str,
    stop_event: threading.Event,
    clock: Callable[[], datetime],
    idle_wait_seconds: float = 5.0,
    limit_per_scope: int = 10,
    lease_seconds: int = 120,
    max_scopes_per_cycle: int = 100,
    run_handler: Callable[[tuple[CommunicationGmailPollRun, ...]], None] | None = None,
) -> None:
    """Public host entry point for a supervised standalone worker process."""

    poller.run_forever(
        authenticated_scope_source=authenticated_scope_source,
        worker_ref=worker_ref,
        stop_event=stop_event,
        clock=clock,
        idle_wait_seconds=idle_wait_seconds,
        limit_per_scope=limit_per_scope,
        lease_seconds=lease_seconds,
        max_scopes_per_cycle=max_scopes_per_cycle,
        run_handler=run_handler,
    )


__all__ = [
    "COMMUNICATION_GMAIL_POLL_JOB_SCHEMA",
    "COMMUNICATION_GMAIL_POLL_RUN_SCHEMA",
    "AuthenticatedCommunicationScopeSource",
    "CommunicationGmailPollArtifacts",
    "CommunicationGmailPollJob",
    "CommunicationGmailPollRun",
    "CommunicationGmailPollRunStatus",
    "CommunicationGmailPollState",
    "CommunicationHostLeaseConflict",
    "CommunicationHostPersistenceError",
    "DurableGmailCommunicationPoller",
    "SqliteCommunicationHostStore",
    "TrustedPollArtifactsLoader",
    "serve_durable_gmail_communication_poller",
]
