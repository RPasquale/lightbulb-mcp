"""Hosted cadence scheduling on the platform's project-runtime checkpoints.

``CadenceWorker`` ticks a company when something calls ``run_once``.  This
module makes the *when* durable and exclusive without a second runtime: each
company cadence is one project-runtime checkpoint whose ``resume_at`` is the
next due tick and whose lease is claimed atomically by exactly one worker at
a time.  The platform already provides the claim, renew, and revision fences
(``/api/sdk-project-runtime/.../checkpoints``); the SDK only chooses the
document and the schedule.

* ``register`` writes the cadence checkpoint (status ``scheduled``, resume at
  the first tick) behind the checkpoint revision fence.
* ``run_once`` claims one due checkpoint for this worker, ticks the cadence
  through ``CadenceWorker``, then re-schedules the checkpoint with the next
  due time and the tick digest, at the revision the claim returned.  A
  checkpoint claimed by another worker, not yet due, or belonging to a
  different bundle is left alone.
* A paused or stopped cadence is parked (no ``resume_at``) so the platform
  stops offering it; ``resume`` re-arms it.

Every checkpoint write carries the bundle digest and the cadence ref, so a
worker can never tick a company whose bundle it does not hold.  The store
behind ``CheckpointGateway`` is either the hosted client or an in-memory twin
with the same fences, used by tests and local runs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_cadence_runner import CadenceTickResult, CadenceWorker
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

CADENCE_CHECKPOINT_SCHEMA = "lightbulb.company_cadence_checkpoint.v1"
SCHEDULER_TICK_SCHEMA = "lightbulb.company_scheduler_tick.v1"
TickOutcome = Literal["ticked", "not_due", "claimed_elsewhere", "parked", "foreign_checkpoint", "cadence_not_running", "observation_pending", "reallocation_pending"]


class CheckpointConflict(RuntimeError):
    """The checkpoint revision or lease fence refused the write."""


class CheckpointGateway(Protocol):
    """The four platform checkpoint operations the scheduler needs; hosted or in-memory."""

    def put(self, run_ref: str, checkpoint: Mapping[str, Any], *, expected_revision: int | None) -> Mapping[str, Any]: ...

    def get(self, run_ref: str) -> Mapping[str, Any] | None: ...

    def claim(self, *, worker_ref: str, ready_at: str, lease_seconds: int, run_ref: str | None = None) -> Mapping[str, Any] | None: ...

    def renew(self, run_ref: str, *, worker_ref: str, expected_revision: int, lease_seconds: int) -> Mapping[str, Any]: ...


class CadenceCheckpoint(StrictModel):
    """The checkpoint document the scheduler keeps per company cadence (platform fields added on write)."""

    schema_id: str = Field(default=CADENCE_CHECKPOINT_SCHEMA, alias="schema")
    kind: Literal["company_cadence"] = "company_cadence"
    run_ref: OpaqueRef
    cadence_ref: OpaqueRef
    company_ref: OpaqueRef
    bundle_digest: Sha256Digest
    status: Literal["scheduled", "running", "blocked", "completed"]
    interval_seconds: int = Field(ge=60, le=604800)
    resume_at: str | None = None
    last_tick_at: str | None = None
    last_observation_at: str | None = None
    pending_observation_end: str | None = None
    last_tick_digest: Sha256Digest | None = None
    ticks: int = Field(default=0, ge=0)
    note: BoundedText | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value):
        return str(value).lower()

    @field_validator("resume_at", "last_tick_at", "last_observation_at", "pending_observation_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class SchedulerTick(StrictModel):
    schema_id: str = Field(default=SCHEDULER_TICK_SCHEMA, alias="schema")
    run_ref: OpaqueRef
    worker_ref: OpaqueRef
    now: str
    outcome: TickOutcome
    revision: int | None = Field(default=None, ge=0)
    next_resume_at: str | None = None
    tick_result_digest: Sha256Digest | None = None
    applied: int = Field(default=0, ge=0)
    outstanding: int = Field(default=0, ge=0)
    detail: BoundedText | None = None
    tick_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SchedulerTick:
        if not skip_digests(info) and self.tick_digest != sealed_digest(SchedulerTick, self, "tick_digest"):
            raise ValueError("tick_digest must commit the exact scheduler tick")
        return self


def _add_seconds(stamp: str, seconds: int) -> str:
    when = parsed(stamp) + timedelta(seconds=seconds)
    return when.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _platform_fields(document: Mapping[str, Any]) -> dict[str, Any]:
    """Strip the platform-added checkpoint fields so the SDK document validates strictly."""

    keep = {"schema", "kind", "run_ref", "cadence_ref", "company_ref", "bundle_digest", "status", "interval_seconds", "resume_at", "last_tick_at", "last_tick_digest", "ticks", "note", "last_observation_at", "pending_observation_end"}
    return {key: value for key, value in document.items() if key in keep}


@dataclass
class InMemoryCheckpointGateway:
    """The platform's checkpoint fences in memory: revision, readiness, exclusive lease."""

    records: dict[str, dict[str, Any]] = field(default_factory=dict)

    def put(self, run_ref: str, checkpoint: Mapping[str, Any], *, expected_revision: int | None) -> Mapping[str, Any]:
        existing = self.records.get(run_ref)
        if existing is None:
            if expected_revision not in (None, 0):
                raise CheckpointConflict(f"checkpoint does not exist at expected revision {expected_revision}")
            revision = 1
        else:
            if expected_revision != existing["revision"]:
                raise CheckpointConflict(f"checkpoint revision is {existing['revision']}, expected {expected_revision}")
            revision = existing["revision"] + 1
        document = {**dict(checkpoint), "run_ref": run_ref, "revision": revision, "lease_owner": dict(checkpoint).get("lease_owner"), "lease_until": dict(checkpoint).get("lease_until")}
        self.records[run_ref] = document
        return dict(document)

    def get(self, run_ref: str) -> Mapping[str, Any] | None:
        record = self.records.get(run_ref)
        return dict(record) if record is not None else None

    def claim(self, *, worker_ref: str, ready_at: str, lease_seconds: int, run_ref: str | None = None) -> Mapping[str, Any] | None:
        now = parsed(ready_at)
        selected_ref = run_ref
        for run_ref in sorted(self.records, key=lambda ref: (self.records[ref].get("resume_at") or "", ref)):
            if selected_ref is not None and run_ref != selected_ref:
                continue
            record = self.records[run_ref]
            resume_at = record.get("resume_at")
            lease_until = record.get("lease_until")
            expired = str(record.get("status")).lower() == "running" and lease_until is not None and parsed(lease_until) <= now
            if not expired and (resume_at is None or parsed(resume_at) > now):
                continue
            if lease_until is not None and parsed(lease_until) > now and record.get("lease_owner") != worker_ref:
                continue
            record["status"] = "running"
            record["lease_owner"] = worker_ref
            record["lease_until"] = _add_seconds(ready_at, lease_seconds)
            record["resume_at"] = None
            record["revision"] += 1
            return dict(record)
        return None

    def renew(self, run_ref: str, *, worker_ref: str, expected_revision: int, lease_seconds: int) -> Mapping[str, Any]:
        record = self.records.get(run_ref)
        if record is None:
            raise LookupError("checkpoint not found")
        if record["revision"] != expected_revision or record.get("lease_owner") != worker_ref:
            raise CheckpointConflict("checkpoint lease is not owned by the requesting worker")
        record["lease_until"] = _add_seconds(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), lease_seconds)
        record["revision"] += 1
        return dict(record)


@dataclass
class HostedCheckpointGateway:
    """The platform checkpoint routes through a ``LightbulbClient``; 409s surface as ``CheckpointConflict``."""

    client: Any
    project_id: str
    company_id: str | None = None

    def _conflict(self, exc: Exception) -> Exception:
        if getattr(exc, "status_code", None) == 409:
            return CheckpointConflict(str(exc))
        return exc

    def put(self, run_ref: str, checkpoint: Mapping[str, Any], *, expected_revision: int | None) -> Mapping[str, Any]:
        try:
            return self.client.put_sdk_project_checkpoint(self.project_id, run_ref, {**dict(checkpoint), "run_ref": run_ref}, expected_revision=expected_revision, company_id=self.company_id)
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the fence
            raise self._conflict(exc) from exc

    def get(self, run_ref: str) -> Mapping[str, Any] | None:
        return self.client.get_sdk_project_checkpoint(self.project_id, run_ref, company_id=self.company_id)

    def claim(self, *, worker_ref: str, ready_at: str, lease_seconds: int, run_ref: str | None = None) -> Mapping[str, Any] | None:
        return self.client.claim_sdk_project_checkpoint(self.project_id, worker_ref=worker_ref, ready_at=ready_at, lease_seconds=lease_seconds, company_id=self.company_id, **({"run_ref":run_ref} if run_ref is not None else {}))

    def renew(self, run_ref: str, *, worker_ref: str, expected_revision: int, lease_seconds: int) -> Mapping[str, Any]:
        try:
            return self.client.renew_sdk_project_checkpoint_lease(self.project_id, run_ref, worker_ref=worker_ref, expected_revision=expected_revision, lease_seconds=lease_seconds, company_id=self.company_id)
        except Exception as exc:  # noqa: BLE001
            raise self._conflict(exc) from exc


@dataclass
class HostedCadenceScheduler:
    """Tick one company cadence on the platform's checkpoint schedule, exclusively, at a fixed interval."""

    worker: CadenceWorker
    gateway: CheckpointGateway
    worker_ref: str
    interval_seconds: int = 3600
    lease_seconds: int = 300
    observation_host: Any = None
    reallocation_step: Any = None

    @property
    def run_ref(self) -> str:
        return f"cadence-{self.worker.runner.bundle.company_ref}"

    def _document(self, **fields: Any) -> dict[str, Any]:
        bundle = self.worker.runner.bundle
        base = {"run_ref": self.run_ref, "cadence_ref": self.worker.cadence_ref, "company_ref": bundle.company_ref, "bundle_digest": bundle.plan_digest, "status": "scheduled", "interval_seconds": self.interval_seconds}
        return CadenceCheckpoint.model_validate({**base, **fields}).to_dict()

    def register(self, *, first_tick_at: str) -> Mapping[str, Any]:
        """Create the cadence checkpoint due at ``first_tick_at``; refuses to clobber an existing one."""

        if self.gateway.get(self.run_ref) is not None:
            raise CheckpointConflict(f"checkpoint {self.run_ref} already exists; use resume to re-arm it")
        return self.gateway.put(self.run_ref, self._document(resume_at=timestamp(first_tick_at, field_name="first_tick_at")), expected_revision=0)

    def resume(self, *, next_tick_at: str) -> Mapping[str, Any]:
        """Re-arm a parked checkpoint at the revision it currently holds."""

        current = self.gateway.get(self.run_ref)
        if current is None:
            raise LookupError(f"checkpoint {self.run_ref} is not registered")
        document = self._document(**{**_platform_fields(current), "status": "scheduled", "resume_at": timestamp(next_tick_at, field_name="next_tick_at"), "note": None})
        return self.gateway.put(self.run_ref, document, expected_revision=int(current["revision"]))

    def run_once(self, *, now: str) -> SchedulerTick:
        """Claim the due checkpoint for this worker, tick, and reschedule; never ticks what it did not claim."""

        stamp = timestamp(now, field_name="now")
        claimed = self.gateway.claim(worker_ref=self.worker_ref, ready_at=stamp, lease_seconds=self.lease_seconds)
        if claimed is None:
            return self._tick(stamp, "not_due", detail="no checkpoint is due for this worker")
        if str(claimed.get("run_ref")) != self.run_ref or str(claimed.get("bundle_digest")) != self.worker.runner.bundle.plan_digest:
            self._release(claimed, note="claimed by a worker holding a different bundle; released untouched")
            return self._tick(stamp, "foreign_checkpoint", revision=int(claimed.get("revision", 0)), detail=f"claim returned {claimed.get('run_ref')} for bundle {str(claimed.get('bundle_digest'))[:12]}; released")
        current = _platform_fields(claimed)
        revision = int(claimed["revision"])
        # Spring's scheduling columns are mutable project checkpoint metadata.
        # A platform claim does not authenticate a change to the host's signed
        # due time or revive a signed parked/completed document. Check before
        # observation, reallocation or cadence effects, then repair the plain
        # projection behind the same revision fence if it was advanced early.
        from lightbulb.company_host_journal import AuthenticatedCheckpointGateway
        if isinstance(self.gateway, AuthenticatedCheckpointGateway):
            signed_status = str(current.get("status", "")).lower()
            signed_due = current.get("resume_at")
            due = (signed_status == "scheduled" and signed_due is not None
                   and parsed(signed_due) <= parsed(stamp))
            # A legitimately interrupted cycle has already signed its running
            # state with no resume_at. Spring still owns the expiry/claim fence;
            # this permits recovery without treating an old scheduled due time
            # as authority for an earlier start.
            recovering = signed_status == "running" and signed_due is None
            if not (due or recovering):
                restored = self.gateway.put(self.run_ref, self._document(**current),
                                            expected_revision=revision)
                return self._tick(stamp, "not_due" if signed_status == "scheduled" else "parked",
                                  revision=int(restored["revision"]), next_resume_at=signed_due,
                                  detail="Platform scheduling projection did not match the authenticated host schedule; restored without effects")
        cadence_state = self.worker.runner.store.get("company_cadence", self.worker.cadence_ref)
        if cadence_state is None or cadence_state["status"] != "running":
            document = self._document(**{**current, "status": "blocked", "resume_at": None, "note": f"cadence is {cadence_state['status'] if cadence_state else 'not started'}; parked until resumed"})
            self.gateway.put(self.run_ref, document, expected_revision=revision)
            return self._tick(stamp, "cadence_not_running", revision=revision, detail=document["note"])
        def fence():
            nonlocal revision, claimed
            claimed = dict(self.gateway.renew(self.run_ref, worker_ref=self.worker_ref,
                expected_revision=revision, lease_seconds=self.lease_seconds))
            revision = int(claimed["revision"])
            return claimed

        if self.observation_host is not None:
            # Daily providers use a closed UTC-day watermark. Freeze the end
            # before reads so retries on later days never overlap a partial cycle.
            start = current.get("last_observation_at") or self.worker.runner.bundle.start_at
            end = current.get("pending_observation_end") or min(parsed(start) + timedelta(days=1), parsed(stamp).replace(hour=0,minute=0,second=0,microsecond=0)).isoformat().replace("+00:00","Z")
            if parsed(start) < parsed(end):
                current = {**current, "pending_observation_end":end, "status":"running", "resume_at":None}
                claimed = dict(self.gateway.put(self.run_ref, {**self._document(**current),
                    "lease_owner":claimed.get("lease_owner"), "lease_until":claimed.get("lease_until")}, expected_revision=revision))
                revision = int(claimed["revision"])
                cycle = self.observation_host.cycle(start=start,end=end,now=stamp,fence=fence)
                if not cycle["complete"]:
                    retry = _add_seconds(stamp,60)
                    written = self.gateway.put(self.run_ref,self._document(**{**current,"status":"scheduled","resume_at":retry,"note":"Observation intake requires retry or source reconciliation"}),expected_revision=revision)
                    return self._tick(stamp,"observation_pending",revision=int(written["revision"]),next_resume_at=retry,detail=str(cycle["failures"])[:900])
                current = {**current,"last_observation_at":end,"pending_observation_end":None}
        reallocation_pending = False
        if self.reallocation_step is not None:
            report = self.reallocation_step(now=stamp,fence=fence)
            reallocation_pending = report is not None and not report.get("ready_for_cadence",report.get("all_applied",False))
        fence()
        result = self.worker.run_once()
        if result is None:
            document = self._document(**{**current, "status": "blocked", "resume_at": None, "note": "cadence stopped ticking; parked"})
            self.gateway.put(self.run_ref, document, expected_revision=revision)
            return self._tick(stamp, "parked", revision=revision, detail=document["note"])
        next_at = _add_seconds(stamp, 60 if reallocation_pending else 1 if self.observation_host is not None and current.get("last_observation_at") and parsed(current["last_observation_at"]) < parsed(stamp).replace(hour=0,minute=0,second=0,microsecond=0) else self.interval_seconds)
        document = self._document(**{**current, "status": "scheduled", "resume_at": next_at, "last_tick_at": stamp, "last_tick_digest": result.result_digest, "ticks": int(current.get("ticks", 0)) + 1, "note": None})
        written = self.gateway.put(self.run_ref, document, expected_revision=revision)
        return self._tick(stamp, "reallocation_pending" if reallocation_pending else "ticked", revision=int(written.get("revision", revision + 1)), next_resume_at=next_at, result=result, detail="Company cadence continued; provider decisions await approval or reconciliation" if reallocation_pending else None)

    def _release(self, claimed: Mapping[str, Any], *, note: str) -> None:
        try:
            document = {**_platform_fields(claimed), "resume_at": claimed.get("resume_at") or _add_seconds(str(claimed.get("last_tick_at") or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")), 60), "note": note}
            self.gateway.put(str(claimed["run_ref"]), document, expected_revision=int(claimed["revision"]))
        except (CheckpointConflict, LookupError, ValueError):
            return

    def _tick(self, now: str, outcome: TickOutcome, *, revision: int | None = None, next_resume_at: str | None = None, result: CadenceTickResult | None = None, detail: str | None = None) -> SchedulerTick:
        return seal(SchedulerTick, {"run_ref": self.run_ref, "worker_ref": self.worker_ref, "now": now, "outcome": outcome, "revision": revision, "next_resume_at": next_resume_at, "tick_result_digest": result.result_digest if result is not None else None, "applied": len(result.applied) if result is not None else 0, "outstanding": len(result.outstanding) if result is not None else 0, "detail": detail}, "tick_digest")


HOSTED_SCHEDULER_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_hosted_scheduler",
    "golden_loop": "company_cadence",
    "stages": ["register_checkpoint", "claim_due", "tick", "reschedule", "park_when_not_running"],
    "required_connectors": ["lightbulb.sdk_project_runtime_checkpoints", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "one checkpoint per company cadence; the platform's claim is the only way a worker obtains the right to tick",
        "a claim for a different run ref or bundle digest is released untouched",
        "a cadence that is paused or stopped parks its checkpoint; only an explicit resume re-arms it",
        "every reschedule is written at the revision the claim returned, so two workers cannot both tick",
    ],
}

__all__ = [
    "CADENCE_CHECKPOINT_SCHEMA",
    "HOSTED_SCHEDULER_MANIFEST",
    "SCHEDULER_TICK_SCHEMA",
    "CadenceCheckpoint",
    "CheckpointConflict",
    "CheckpointGateway",
    "HostedCadenceScheduler",
    "HostedCheckpointGateway",
    "InMemoryCheckpointGateway",
    "SchedulerTick",
]
