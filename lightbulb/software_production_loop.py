"""Approved change to verified production: the SDK loop runtime (Work Package 1B).

This module is the tracer-bullet vertical slice over the Work Package 1A
contract.  It owns:

* **Execution Run admission** — ``ExecutionRunAdmission`` mirrors Spring's
  ``RegisterRun`` command (kind, executor ref, parent run, cancel and control
  modes, admission key and digest) so Spring can register the loop run through
  ``SpringExecutionRunAuthority`` without a second identity scheme, and
  ``ExecutionRunControl`` mirrors its cancellation fence.
* **Loop state** — ``SoftwareProductionLoopState`` is a digest-chained,
  replay-fenced transition history bound to one compilation and one Execution
  Run.  Every transition carries typed evidence receipts and classified
  effect receipts; budget, cancellation, duplicate delivery, response loss,
  and ambiguous effects are all handled fail-closed.
* **Ports** — provider-neutral protocols for the harness grant, source
  custody, CI/policy, deployment, production observation, and rollback.
  ``InMemory*`` adapters are deterministic references for tests and local
  simulation; ``GitHubConnectorReleaseAdapter`` is the one real adapter and
  performs every effect through the governed Connector Runtime (the existing
  ``github.*`` Tools via ``PrimitiveExecutionContext.connector_request``), so
  approvals, idempotency, previews, and provenance stay Spring-owned.  It is
  never a direct GitHub client.
* **Runner** — ``SoftwareProductionLoopRunner`` executes at most one stage per
  call, requires approval references for approved writes, converts connector
  ``in_doubt``/failed outcomes into typed loop exits, and never claims
  production success from a deployment receipt alone.

Spring remains the authority for scope, RBAC, persistence, harness
resolution, grants, approvals, and effects.  The loop state is a candidate
projection Spring persists; the SDK never persists it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import re
from typing import Annotated, Any, Literal, Protocol
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionResult, ConnectorExecutionStatus
from lightbulb.primitive_runtime import PrimitiveExecutionContext
from lightbulb.software_production import (
    SOFTWARE_PRODUCTION_GOLDEN_LOOP,
    TERMINAL_STATUSES,
    EvidenceReceipt,
    HarnessFamily,
    RunEvent,
    RunStatus,
    SoftwareProductionCompilation,
    SoftwareProductionReceiptSet,
    SoftwareProductionRunHandle,
    advance_software_production_status,
)


LOOP_STATE_SCHEMA = "lightbulb.software_production_loop_state.v1"
LOOP_COMMAND_SCHEMA = "lightbulb.software_production_loop_command.v1"
LOOP_RESULT_SCHEMA = "lightbulb.software_production_loop_transition_result.v1"
EXECUTION_RUN_ADMISSION_SCHEMA = "lightbulb.execution_run_admission.v1"
GENESIS_DIGEST = "0" * 64
MAX_LOOP_TRANSITIONS = 120

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_AUTHORITY_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id", "control_capability")


_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
)


def _reject_authority_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _AUTHORITY_LIKE_KEYS) and not lowered.endswith("_tokens"):
                raise ValueError(f"{path}.{key} is a credential-, capability-, or authority-like field and is never accepted")
            _reject_authority_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_authority_like_payload(item, path=f"{path}[{index}]")


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN), AfterValidator(_visible_ref)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]

ExecutionRunKind = Literal["WORKFLOW", "RECURSIVE", "SDK_PROJECT", "AGENT_TASK", "PRIMITIVE_EXECUTION", "RESEARCH", "AUTOML", "DATA_SPARK"]
CancelMode = Literal["COOPERATIVE", "FENCE_ONLY", "CASCADE"]
ControlMode = Literal["AUTHORITATIVE", "OBSERVATION_ONLY"]
CancellationState = Literal["ACTIVE", "CANCEL_REQUESTED", "CANCELLED"]
EffectOutcome = Literal["preview", "pending_approval", "completed", "blocked", "failed", "in_doubt"]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "await_approval", "manual_reconciliation"]

_EFFECT_KIND_BY_STAGE: dict[str, tuple[str, ...]] = {
    "form_release_candidate": ("branch_create", "pull_request_open"),
    "verify_staging": ("staging_deploy",),
    "execute_production": ("production_deploy",),
    "roll_back": ("rollback",),
}
_STAGE_RECEIPTS: dict[str, tuple[str, ...]] = {
    "compile_work_packet": ("work_packet",),
    "authorize_builder": ("provider_grant",),
    "produce_change": ("builder_result",),
    "accept": ("evaluator_verdict",),
    "reject": ("evaluator_verdict",),
    "form_release_candidate": ("branch", "commit"),
    "verify_ci_and_policy": ("ci",),
    "verify_staging": ("staging",),
    "authorize_production": ("release_approval",),
    "execute_production": ("deployment",),
    "fail_deployment": ("deployment",),
    "observe_production": ("production_health", "business_outcome"),
    "roll_back": ("rollback",),
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_authority_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _digest_without(payload: Mapping[str, Any], *fields: str) -> str:
    return _stable_digest({key: value for key, value in payload.items() if key not in fields})


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_loop_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_loop_digests": True})
    return _digest_without(parsed.to_dict(), field)


def _canonical_uuid(value: str, *, label: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return value


# --------------------------------------------------------------------------- #
# Execution Run admission (mirrors Spring RegisterRun / CancellationFence)
# --------------------------------------------------------------------------- #


class ExecutionRunAdmission(_StrictModel):
    """SDK-side mirror of Spring's ``RegisterRun``; the raw capability is never carried."""

    schema_id: Literal["lightbulb.execution_run_admission.v1"] = Field(default=EXECUTION_RUN_ADMISSION_SCHEMA, alias="schema")
    kind: ExecutionRunKind = "SDK_PROJECT"
    trace_id: OpaqueRef
    executor_ref: OpaqueRef
    parent_run_id: str | None = None
    cancel_mode: CancelMode = "CASCADE"
    control_mode: ControlMode = "AUTHORITATIVE"
    admission_key: OpaqueRef
    admission_digest: Sha256Digest
    capability_digest: Sha256Digest | None = None

    @field_validator("parent_run_id")
    @classmethod
    def _parent(cls, value: str | None) -> str | None:
        return None if value is None else _canonical_uuid(value, label="parent_run_id")


def admission_for_compilation(compilation: SoftwareProductionCompilation, *, executor_ref: str = "lightbulb-sdk:software_production_loop", parent_run_id: str | None = None, capability_digest: str | None = None) -> ExecutionRunAdmission:
    """Derive the Execution Run admission from the compiled request: key = origin idempotency key, digest = compilation digest."""

    return ExecutionRunAdmission(
        trace_id=compilation.origin.originating_run_ref,
        executor_ref=executor_ref,
        parent_run_id=parent_run_id,
        admission_key=compilation.origin.idempotency_key,
        admission_digest=compilation.compilation_digest,
        capability_digest=capability_digest,
    )


class ExecutionRunControl(_StrictModel):
    """Mirror of Spring's registered run and cancellation fence."""

    execution_run_id: str
    revision: int = Field(ge=1)
    cancellation_fence: int = Field(ge=0)
    cancellation_state: CancellationState = "ACTIVE"
    replayed: bool = False

    @field_validator("execution_run_id")
    @classmethod
    def _run_id(cls, value: str) -> str:
        return _canonical_uuid(value, label="execution_run_id")


# --------------------------------------------------------------------------- #
# Effects, receipts, commands
# --------------------------------------------------------------------------- #


class EffectReceipt(_StrictModel):
    effect: Literal["branch_create", "pull_request_open", "merge", "staging_deploy", "production_deploy", "rollback"]
    tool: ShortText
    classification: Literal["preview", "proposed_write", "approved_write"]
    outcome: EffectOutcome
    approval_ref: OpaqueRef | None = None
    idempotency_key: OpaqueRef | None = None
    external_ref: OpaqueRef | None = None
    provenance_digest: Sha256Digest | None = None
    recovery_locator: str | None = None
    message: BoundedText | None = None

    @model_validator(mode="after")
    def _completed_requires_authority(self) -> "EffectReceipt":
        if self.outcome == "completed" and self.classification == "approved_write" and self.approval_ref is None:
            raise ValueError("a completed approved write must carry its approval reference")
        return self


class HarnessGrant(_StrictModel):
    """One-use provider grant receipt; the grant token itself never enters the SDK."""

    grant_ref: OpaqueRef
    harness_family: HarnessFamily
    assignment_ref: OpaqueRef
    workspace_binding_ref: OpaqueRef
    grant_digest: Sha256Digest
    issued_at: str
    expires_at: str
    single_use: Literal[True] = True

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _window(self) -> "HarnessGrant":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.issued_at):
            raise ValueError("grant expiry must follow issuance")
        return self


class LoopCommand(_StrictModel):
    schema_id: Literal["lightbulb.software_production_loop_command.v1"] = Field(default=LOOP_COMMAND_SCHEMA, alias="schema")
    event: RunEvent
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_LOOP_TRANSITIONS)
    expected_state_digest: Sha256Digest
    expected_cancellation_fence: int = Field(ge=0)
    occurred_at: str
    actor_ref: OpaqueRef
    actor_role: Literal["orchestrator", "spring", "builder", "evaluator", "release_connector", "observer", "approver"]
    host_outcome_report: Literal["reported_certain", "reported_in_doubt", "unreported"] = "reported_certain"
    receipts: tuple[EvidenceReceipt, ...] = Field(default_factory=tuple, max_length=50)
    effects: tuple[EffectReceipt, ...] = Field(default_factory=tuple, max_length=10)
    grant: HarnessGrant | None = None
    selected_harness_family: HarnessFamily | None = None
    evaluator_accepted: bool | None = None
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "LoopCommand":
        if _skip(info):
            return self
        if self.request_digest != loop_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def loop_command_digest(command: LoopCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(LoopCommand, command, "request_digest")


def seal_loop_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = loop_command_digest(raw)
    return LoopCommand.model_validate(raw).to_dict()


# --------------------------------------------------------------------------- #
# Loop state
# --------------------------------------------------------------------------- #


class LoopTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_LOOP_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: RunStatus
    transition_digest: Sha256Digest
    command: LoopCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "LoopTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: LoopCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key, "event": command.event})


class BudgetLedger(_StrictModel):
    build_attempts: int = Field(default=0, ge=0)
    evaluation_attempts: int = Field(default=0, ge=0)
    used_tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)


class SoftwareProductionLoopState(_StrictModel):
    schema_id: Literal["lightbulb.software_production_loop_state.v1"] = Field(default=LOOP_STATE_SCHEMA, alias="schema")
    compilation_digest: Sha256Digest
    request_digest: Sha256Digest
    acceptance_contract_digest: Sha256Digest
    admission: ExecutionRunAdmission
    control: ExecutionRunControl
    status: RunStatus
    version: int = Field(ge=1, le=MAX_LOOP_TRANSITIONS)
    transition_history: tuple[LoopTransition, ...] = Field(min_length=1, max_length=MAX_LOOP_TRANSITIONS)
    receipt_set: SoftwareProductionReceiptSet
    budget: BudgetLedger = Field(default_factory=BudgetLedger)
    builder_context_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self) -> "SoftwareProductionLoopState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("loop version must equal a contiguous transition history")
        refs = [item.command.transition_ref for item in history]
        keys = [item.command.idempotency_key for item in history]
        digests = [item.command.request_digest for item in history]
        if len(set(refs)) != len(refs) or len(set(keys)) != len(keys) or len(set(digests)) != len(digests):
            raise ValueError("historical transitions must be unique")
        status: str = "request_admitted"
        prefix: tuple[LoopTransition, ...] = ()
        for index, transition in enumerate(history):
            if transition.prior_state_digest != _state_digest(self.compilation_digest, self.admission, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            if index == 0 and transition.command.event != "admit":
                raise ValueError("the first transition must be the admission")
            if index > 0:
                status = advance_software_production_status(status, transition.command.event)  # type: ignore[arg-type]
            if transition.to_status != status:
                raise ValueError("historical transition status does not match the lifecycle table")
            prefix = (*prefix, transition)
        if self.status != status:
            raise ValueError("loop status must be derived from history")
        if self.state_digest != _state_digest(self.compilation_digest, self.admission, history):
            raise ValueError("state_digest must commit the exact loop state")
        if self.receipt_set.compilation_digest != self.compilation_digest or self.receipt_set.acceptance_contract_digest != self.acceptance_contract_digest:
            raise ValueError("receipt set must bind the loop's compilation and acceptance contract")
        return self

    def handle(self, updated_at: str) -> SoftwareProductionRunHandle:
        handle = {"request_digest": self.request_digest, "compilation_digest": self.compilation_digest, "dynamic_workflow_run_ref": self.receipt_set.dynamic_workflow_run_ref, "execution_run_ref": self.control.execution_run_id, "status": self.status, "updated_at": _timestamp(updated_at, field_name="updated_at")}
        from lightbulb.software_production import _sealed_digest as _sp_digest

        handle["handle_digest"] = _sp_digest(SoftwareProductionRunHandle, handle, "handle_digest")
        return SoftwareProductionRunHandle.model_validate(handle)


def _state_digest(compilation_digest: str, admission: ExecutionRunAdmission, history: Sequence[LoopTransition]) -> str:
    return _stable_digest({"compilation_digest": compilation_digest, "admission": admission.to_dict(), "transitions": [item.transition_digest for item in history]})


def genesis_loop_state_digest(compilation_digest: str, admission: ExecutionRunAdmission | Mapping[str, Any]) -> str:
    return _state_digest(compilation_digest, ExecutionRunAdmission.model_validate(_detached(admission)), ())


class LoopRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "LoopRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class LoopTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: RunEvent
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: RunStatus
    to_status: RunStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: LoopRecovery

    @model_validator(mode="after")
    def _coherent(self) -> "LoopTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1 or self.rejection_code is not None or self.recovery.disposition != "not_required":
                raise ValueError("a materialized transition advances one version without rejection")
        else:
            if self.to_version != self.from_version or self.to_status != self.from_status or self.to_state_digest != self.from_state_digest or self.rejection_code is None:
                raise ValueError("a rejected or in-doubt transition changes nothing and carries a code")
        if self.status == "in_doubt" and self.recovery.disposition != "manual_reconciliation":
            raise ValueError("in-doubt transitions require manual reconciliation")
        return self


class LoopEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_called_directly: Literal[False] = False
    production_success_from_receipt_alone: Literal[False] = False


class LoopTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.software_production_loop_transition_result.v1"] = Field(default=LOOP_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: SoftwareProductionLoopState | None = None
    receipt: LoopTransitionReceipt
    effect_boundary: LoopEffectBoundary = Field(default_factory=LoopEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "LoopTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        if self.state is not None and (self.state.version != self.receipt.to_version or self.state.state_digest != self.receipt.to_state_digest):
            raise ValueError("result state must match its receipt")
        return self


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition, *, in_doubt: bool = False) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery, self.in_doubt = code, instructions, recovery, in_doubt


def admit_software_production_run(compilation: SoftwareProductionCompilation | Mapping[str, Any], control: ExecutionRunControl | Mapping[str, Any], admission: ExecutionRunAdmission | Mapping[str, Any] | None = None, *, admitted_at: str, actor_ref: str) -> SoftwareProductionLoopState:
    """Create the genesis loop state from a compilation and Spring's registered run control."""

    parsed = SoftwareProductionCompilation.model_validate(_detached(compilation))
    parsed_control = ExecutionRunControl.model_validate(_detached(control))
    parsed_admission = ExecutionRunAdmission.model_validate(_detached(admission)) if admission is not None else admission_for_compilation(parsed)
    if parsed_admission.admission_digest != parsed.compilation_digest or parsed_admission.admission_key != parsed.origin.idempotency_key:
        raise ValueError("admission must bind the exact compilation digest and origin idempotency key")
    genesis = _state_digest(parsed.compilation_digest, parsed_admission, ())
    command = LoopCommand.model_validate(seal_loop_command({"event": "admit", "transition_ref": f"admit:{parsed.compilation_digest[:16]}", "idempotency_key": parsed.origin.idempotency_key, "expected_version": 0, "expected_state_digest": genesis, "expected_cancellation_fence": parsed_control.cancellation_fence, "occurred_at": admitted_at, "actor_ref": actor_ref, "actor_role": "spring"}))
    transition = LoopTransition(to_version=1, prior_state_digest=genesis, to_status="request_admitted", transition_digest=_transition_digest(1, genesis, "request_admitted", command), command=command)
    receipt_set = SoftwareProductionReceiptSet(request_digest=parsed.request_digest, compilation_digest=parsed.compilation_digest, acceptance_contract_digest=parsed.acceptance_contract_digest, execution_run_ref=parsed_control.execution_run_id)
    return SoftwareProductionLoopState(compilation_digest=parsed.compilation_digest, request_digest=parsed.request_digest, acceptance_contract_digest=parsed.acceptance_contract_digest, admission=parsed_admission, control=parsed_control, status="request_admitted", version=1, transition_history=(transition,), receipt_set=receipt_set, state_digest=_state_digest(parsed.compilation_digest, parsed_admission, (transition,)))


def _validate_stage_semantics(compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, command: LoopCommand) -> None:
    event = command.event
    kinds = {item.kind for item in command.receipts}
    expected_effects = _EFFECT_KIND_BY_STAGE.get(event, ())
    if expected_effects:
        by_kind = {item.effect: item for item in command.effects}
        policy = {item.effect: item for item in compilation.effects}
        for effect_kind in expected_effects:
            receipt = by_kind.get(effect_kind)
            if receipt is None:
                raise _Rejected("EFFECT_RECEIPT_MISSING", f"{event} requires an effect receipt for {effect_kind}", "correct_input")
            declared = policy[effect_kind]
            if declared.classification == "preview" and receipt.outcome == "completed":
                raise _Rejected("EFFECT_NOT_PERMITTED", f"{effect_kind} is preview-only under this release policy", "correct_input")
            if receipt.outcome == "in_doubt":
                raise _Rejected("EFFECT_IN_DOUBT", f"{effect_kind} outcome is ambiguous; reconcile in Spring before continuing", "manual_reconciliation", in_doubt=True)
            if receipt.outcome == "pending_approval":
                raise _Rejected("APPROVAL_PENDING", f"{effect_kind} awaits approval", "await_approval")
            if receipt.outcome in {"blocked", "failed"}:
                raise _Rejected("EFFECT_FAILED", f"{effect_kind} did not complete: {receipt.message or receipt.outcome}", "correct_input")
            if declared.approval_required and receipt.outcome == "completed" and receipt.approval_ref is None:
                raise _Rejected("APPROVAL_REQUIRED", f"{effect_kind} requires an approval reference", "await_approval")
    required = set(_STAGE_RECEIPTS.get(event, ()))
    if required - kinds:
        raise _Rejected("EVIDENCE_MISSING", f"{event} requires evidence: {', '.join(sorted(required - kinds))}", "correct_input")
    if event == "select_harness":
        if command.selected_harness_family is None or command.selected_harness_family not in compilation.dynamic_workflow_start.allowed_hosts:
            raise _Rejected("HARNESS_OUTSIDE_POLICY", "selected harness must be one Spring resolved from the allowed families", "correct_input")
        if command.actor_role != "spring":
            raise _Rejected("HARNESS_NOT_SPRING_RESOLVED", "only Spring resolves the harness under Company Execution Host Policy", "correct_input")
    if event == "authorize_builder":
        if command.grant is None or command.grant.assignment_ref != f"assignment:{compilation.compilation_digest[:16]}":
            raise _Rejected("GRANT_NOT_BOUND", "a one-use grant bound to this exact assignment is required", "correct_input")
        if command.grant.harness_family != state.receipt_set.selected_harness_family:
            raise _Rejected("GRANT_HARNESS_MISMATCH", "grant must target the selected harness", "correct_input")
        if _parsed_timestamp(command.grant.expires_at) <= _parsed_timestamp(command.occurred_at):
            raise _Rejected("GRANT_EXPIRED", "the grant expired before use", "correct_input")
    if event == "produce_change":
        if command.actor_role != "builder":
            raise _Rejected("BUILDER_ROLE_REQUIRED", "change production is submitted by the builder", "correct_input")
        if state.budget.build_attempts + 1 > int(compilation.workflow_limits["max_build_attempts"]):
            raise _Rejected("BUDGET_EXHAUSTED", "build attempts exceed the compiled budget", "manual_reconciliation")
    if event in {"accept", "reject"}:
        if command.actor_role != "evaluator":
            raise _Rejected("EVALUATOR_ROLE_REQUIRED", "acceptance is decided by the independent evaluator", "correct_input")
        if command.actor_ref in state.builder_context_refs:
            raise _Rejected("BUILDER_SELF_ACCEPTANCE", "the builder cannot evaluate its own work", "correct_input")
        if event == "accept" and command.evaluator_accepted is not True:
            raise _Rejected("ACCEPTANCE_NOT_ASSERTED", "accept requires an explicit accepted verdict", "correct_input")
        if state.budget.evaluation_attempts + 1 > int(compilation.workflow_limits["max_evaluation_attempts"]):
            raise _Rejected("BUDGET_EXHAUSTED", "evaluation attempts exceed the compiled budget", "manual_reconciliation")
    if event == "authorize_production":
        release = compilation.dynamic_workflow_start.workflow_spec["release_policy"]
        if release["production_approval"] == "human_required" and command.actor_role != "approver":
            raise _Rejected("HUMAN_APPROVAL_REQUIRED", "this release policy requires a human approver", "await_approval")
        if "production" not in release["allowed_environments"]:
            raise _Rejected("PRODUCTION_NOT_ALLOWED", "release policy does not allow production", "correct_input")
    if event == "verify_production":
        if command.actor_role != "observer":
            raise _Rejected("OBSERVER_ROLE_REQUIRED", "production verification comes from the independent observer", "correct_input")
        have = state.receipt_set.kinds() | kinds
        for required_kind in ("deployment", "production_health", "business_outcome"):
            if required_kind not in have:
                raise _Rejected("PRODUCTION_EVIDENCE_MISSING", f"production verification requires {required_kind} evidence", "correct_input")
        if state.receipt_set.evaluator_accepted is not True:
            raise _Rejected("ACCEPTANCE_MISSING", "production cannot be verified without an accepting evaluator verdict", "correct_input")
        observations = [item for item in state.transition_history if item.command.event == "observe_production"]
        if not observations or observations[-1].command.reason is not None:
            raise _Rejected("OBSERVATION_NOT_HEALTHY", "the independent observer reported a breach; roll back or reconcile instead of verifying", "manual_reconciliation")


def apply_software_production_event(compilation: SoftwareProductionCompilation | Mapping[str, Any], state: SoftwareProductionLoopState | Mapping[str, Any], command: LoopCommand | Mapping[str, Any]) -> LoopTransitionResult:
    """Materialize one replay-fenced loop transition; never persists, never calls a provider."""

    parsed_compilation = SoftwareProductionCompilation.model_validate(_detached(compilation))
    parsed_state = SoftwareProductionLoopState.model_validate(_detached(state))
    parsed_command = LoopCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> LoopTransitionResult:
        receipt = LoopTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="in_doubt" if exc.in_doubt else "rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=LoopRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return LoopTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        if parsed_state.compilation_digest != parsed_compilation.compilation_digest:
            raise _Rejected("COMPILATION_MISMATCH", "loop state belongs to a different compilation", "correct_input")
        if parsed_command.host_outcome_report != "reported_certain":
            raise _Rejected("OUTCOME_IN_DOUBT", "the host reported an uncertain outcome; reconcile before replay", "manual_reconciliation", in_doubt=True)
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if parsed_command.expected_cancellation_fence != parsed_state.control.cancellation_fence:
            raise _Rejected("CANCELLATION_FENCE_MISMATCH", "Spring's cancellation fence advanced; re-read control before continuing", "refresh_state")
        if parsed_state.control.cancellation_state != "ACTIVE" and parsed_command.event != "cancel":
            raise _Rejected("RUN_CANCELLING", "the Execution Run is cancelling; only the cancel transition may proceed", "do_not_replay")
        if from_status in TERMINAL_STATUSES:
            raise _Rejected("RUN_TERMINAL", f"run is already {from_status}", "do_not_replay")
        if from_version >= MAX_LOOP_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the loop reached its bounded transition count", "manual_reconciliation")
        if _parsed_timestamp(parsed_command.occurred_at) < _parsed_timestamp(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        try:
            next_status = advance_software_production_status(from_status, parsed_command.event)
        except ValueError as exc:
            raise _Rejected("ILLEGAL_TRANSITION", str(exc), "correct_input") from exc
        _validate_stage_semantics(parsed_compilation, parsed_state, parsed_command)
    except _Rejected as exc:
        return rejected(exc)

    transition = LoopTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    receipts = parsed_state.receipt_set.to_dict()
    receipts["receipts"] = [*receipts.get("receipts", []), *[item.to_dict() for item in parsed_command.receipts]]
    if parsed_command.event == "compile_work_packet":
        receipts["work_packet_ref"] = next(item.ref for item in parsed_command.receipts if item.kind == "work_packet")
    if parsed_command.selected_harness_family is not None:
        receipts["selected_harness_family"] = parsed_command.selected_harness_family
    if parsed_command.event == "authorize_builder" and parsed_command.grant is not None:
        receipts["builder_assignment_ref"] = parsed_command.grant.assignment_ref
    if parsed_command.event in {"accept", "reject"}:
        receipts["evaluator_accepted"] = parsed_command.event == "accept"
        receipts["evaluator_binding_ref"] = parsed_command.actor_ref
    budget = parsed_state.budget.to_dict()
    if parsed_command.event == "produce_change":
        budget["build_attempts"] += 1
    if parsed_command.event in {"accept", "reject"}:
        budget["evaluation_attempts"] += 1
    builders = list(parsed_state.builder_context_refs)
    if parsed_command.event == "produce_change" and parsed_command.actor_ref not in builders:
        builders.append(parsed_command.actor_ref)
    new_state = SoftwareProductionLoopState(compilation_digest=parsed_state.compilation_digest, request_digest=parsed_state.request_digest, acceptance_contract_digest=parsed_state.acceptance_contract_digest, admission=parsed_state.admission, control=parsed_state.control, status=next_status, version=from_version + 1, transition_history=history, receipt_set=SoftwareProductionReceiptSet.model_validate(receipts), budget=BudgetLedger.model_validate(budget), builder_context_refs=tuple(builders), state_digest=_state_digest(parsed_state.compilation_digest, parsed_state.admission, history))
    receipt = LoopTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=new_state.status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=LoopRecovery(disposition="not_required"))
    return LoopTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


def apply_control_update(state: SoftwareProductionLoopState | Mapping[str, Any], control: ExecutionRunControl | Mapping[str, Any]) -> SoftwareProductionLoopState:
    """Adopt Spring's newer cancellation fence without rewriting history (fence is not part of the digest chain)."""

    parsed = SoftwareProductionLoopState.model_validate(_detached(state))
    parsed_control = ExecutionRunControl.model_validate(_detached(control))
    if parsed_control.execution_run_id != parsed.control.execution_run_id:
        raise ValueError("control update must belong to the same Execution Run")
    if parsed_control.revision < parsed.control.revision or parsed_control.cancellation_fence < parsed.control.cancellation_fence:
        raise ValueError("control updates cannot move the fence backwards")
    return SoftwareProductionLoopState.model_validate({**parsed.to_dict(), "control": parsed_control.to_dict()})


def loop_result_input(compilation: SoftwareProductionCompilation | Mapping[str, Any], state: SoftwareProductionLoopState | Mapping[str, Any], *, assessed_at: str) -> dict[str, Any]:
    """Build the ``assess_software_production_result`` input from a loop state (failure reason = last retained reason)."""

    parsed_compilation = SoftwareProductionCompilation.model_validate(_detached(compilation))
    parsed_state = SoftwareProductionLoopState.model_validate(_detached(state))
    if parsed_state.compilation_digest != parsed_compilation.compilation_digest:
        raise ValueError("loop state belongs to a different compilation")
    last = parsed_state.transition_history[-1].command
    failure_reason: str | None = None
    if parsed_state.status in TERMINAL_STATUSES and parsed_state.status not in {"production_verified", "cancelled"}:
        failure_reason = last.reason or f"run ended in {parsed_state.status} after {last.event}"
    return {
        "compilation": parsed_compilation.to_dict(),
        "handle": parsed_state.handle(last.occurred_at).to_dict(),
        "receipt_set": parsed_state.receipt_set.to_dict(),
        "failure_reason": failure_reason,
        "assessed_at": _timestamp(assessed_at, field_name="assessed_at"),
    }


# --------------------------------------------------------------------------- #
# Ports and adapters
# --------------------------------------------------------------------------- #


class HarnessGrantPort(Protocol):
    def issue_grant(self, *, compilation: SoftwareProductionCompilation, harness_family: HarnessFamily, at: str) -> HarnessGrant: ...


class SourceCustodyPort(Protocol):
    def form_release_candidate(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]: ...


class CiPolicyPort(Protocol):
    def verify(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[EvidenceReceipt, ...]: ...


class DeploymentPort(Protocol):
    def deploy(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, environment: Literal["staging", "production"], at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]: ...

    def roll_back(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]: ...


class ProductionObservationPort(Protocol):
    def observe(self, *, compilation: SoftwareProductionCompilation, at: str) -> tuple[EvidenceReceipt, ...]: ...


def _receipt(kind: str, ref: str, issuer: str, at: str, *, independent: bool = True, digest: str | None = None) -> EvidenceReceipt:
    return EvidenceReceipt(kind=kind, ref=ref, issuer_ref=issuer, observed_at=at, independent_of_builder=independent, digest=digest)  # type: ignore[arg-type]


class InMemoryHarnessGrantPort:
    """Reference adapter: mints deterministic one-use grant receipts (no token)."""

    issuer_ref = "in-memory-grant-authority"

    def issue_grant(self, *, compilation: SoftwareProductionCompilation, harness_family: HarnessFamily, at: str) -> HarnessGrant:
        assignment = f"assignment:{compilation.compilation_digest[:16]}"
        expires = _parsed_timestamp(at).replace(hour=23, minute=59)
        return HarnessGrant(grant_ref=f"grant:{compilation.compilation_digest[:12]}", harness_family=harness_family, assignment_ref=assignment, workspace_binding_ref=compilation.dynamic_workflow_start.inputs["workspace_binding_ref"], grant_digest=_stable_digest({"assignment": assignment, "harness": harness_family}), issued_at=at, expires_at=expires.isoformat().replace("+00:00", "Z"))


class InMemoryReleaseAdapter:
    """Reference adapter for custody, CI, deployment, rollback, and observation."""

    issuer_ref = "in-memory-release"

    def __init__(self, *, ci_pass: bool = True, healthy: bool = True, outcome_met: bool = True, deploy_outcome: EffectOutcome = "completed") -> None:
        self.ci_pass, self.healthy, self.outcome_met, self.deploy_outcome = ci_pass, healthy, outcome_met, deploy_outcome

    def form_release_candidate(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        digest = compilation.compilation_digest[:12]
        policy = {item.effect: item for item in compilation.effects}
        effects = [EffectReceipt(effect="branch_create", tool="in-memory.branch", classification=policy["branch_create"].classification, outcome="completed", external_ref=f"branch:{digest}"), EffectReceipt(effect="pull_request_open", tool="in-memory.pull_request", classification=policy["pull_request_open"].classification, outcome="completed" if policy["pull_request_open"].classification != "preview" else "preview", external_ref=f"pr:{digest}")]
        receipts = [_receipt("branch", f"branch:{digest}", self.issuer_ref, at), _receipt("commit", f"commit:{digest}", self.issuer_ref, at, digest=_stable_digest(digest))]
        if effects[1].outcome == "completed":
            receipts.append(_receipt("pull_request", f"pr:{digest}", self.issuer_ref, at))
        return tuple(receipts), tuple(effects)

    def verify(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[EvidenceReceipt, ...]:
        if not self.ci_pass:
            return ()
        return (_receipt("ci", f"ci:{compilation.compilation_digest[:12]}", self.issuer_ref, at), _receipt("review", f"review:{compilation.compilation_digest[:12]}", self.issuer_ref, at), _receipt("security_scan", f"scan:{compilation.compilation_digest[:12]}", self.issuer_ref, at))

    def deploy(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, environment: Literal["staging", "production"], at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        kind = "staging_deploy" if environment == "staging" else "production_deploy"
        policy = {item.effect: item for item in compilation.effects}[kind]
        approval = context.approval_ref_for("project.request_software_production", operation_ref=kind)
        outcome: EffectOutcome = self.deploy_outcome
        if policy.classification == "preview":
            outcome = "preview"
        elif policy.approval_required and approval is None:
            outcome = "pending_approval"
        effect = EffectReceipt(effect=kind, tool=f"in-memory.deploy.{environment}", classification=policy.classification, outcome=outcome, approval_ref=approval, external_ref=f"deploy:{environment}:{compilation.compilation_digest[:12]}")
        receipts: list[EvidenceReceipt] = []
        if outcome == "completed":
            receipts.append(_receipt("staging" if environment == "staging" else "deployment", f"deploy:{environment}:{compilation.compilation_digest[:12]}", self.issuer_ref, at))
            if environment == "staging" and compilation.effective_evidence.rollback_verification:
                receipts.append(_receipt("rollback", f"rollback-rehearsal:staging:{compilation.compilation_digest[:12]}", self.issuer_ref, at))
        elif outcome == "failed" and environment == "production":
            receipts.append(_receipt("deployment", f"deploy:production:failed:{compilation.compilation_digest[:12]}", self.issuer_ref, at))
        return tuple(receipts), (effect,)

    def roll_back(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        policy = {item.effect: item for item in compilation.effects}["rollback"]
        approval = context.approval_ref_for("project.request_software_production", operation_ref="rollback")
        outcome: EffectOutcome = "completed" if (not policy.approval_required or approval) else "pending_approval"
        return ((_receipt("rollback", f"rollback:{compilation.compilation_digest[:12]}", self.issuer_ref, at),) if outcome == "completed" else ()), (EffectReceipt(effect="rollback", tool="in-memory.rollback", classification=policy.classification, outcome=outcome, approval_ref=approval),)

    def observe(self, *, compilation: SoftwareProductionCompilation, at: str) -> tuple[EvidenceReceipt, ...]:
        receipts = []
        if self.healthy:
            receipts.append(_receipt("production_health", f"health:{compilation.compilation_digest[:12]}", "in-memory-observer", at))
        if self.outcome_met:
            receipts.append(_receipt("business_outcome", f"outcome:{compilation.compilation_digest[:12]}", "in-memory-observer", at))
        return tuple(receipts)


def _connector_outcome(result: ConnectorExecutionResult) -> EffectOutcome:
    return {ConnectorExecutionStatus.COMPLETED: "completed", ConnectorExecutionStatus.PREVIEW: "preview", ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval", ConnectorExecutionStatus.BLOCKED: "blocked", ConnectorExecutionStatus.FAILED: "failed"}[result.status]  # type: ignore[return-value]


class GitHubConnectorReleaseAdapter:
    """The one real adapter: every effect goes through the governed ``github.*`` Tools.

    Effects are issued with ``PrimitiveExecutionContext.connector_request`` so
    the Connector Runtime keeps approval, idempotency, preview, and provenance
    authority.  An unverified recovery locator or a failed status becomes an
    ``in_doubt``/``failed`` effect receipt; the loop then exits to
    reconciliation or failure instead of guessing.
    """

    issuer_ref = "connector:github"
    primitive_ref = "project.request_software_production"

    def __init__(self, *, repository: str, base_branch: str = "main", deploy_workflow: str = "deploy.yml", github_account_ref: str | None = None) -> None:
        if "/" not in repository or repository.strip() != repository:
            raise ValueError("repository must be owner/name")
        self.repository, self.base_branch, self.deploy_workflow, self.github_account_ref = repository, base_branch, deploy_workflow, github_account_ref

    def _call(self, context: PrimitiveExecutionContext, *, tool: str, arguments: Mapping[str, Any], effect: ConnectorEffect, operation_ref: str, approval_required: bool) -> ConnectorExecutionResult:
        request = context.connector_request(primitive_ref=self.primitive_ref, tool=tool, arguments=dict(arguments), effect=effect, approval_required=approval_required, operation_ref=operation_ref, connector_account_ref=self.github_account_ref, metadata={"golden_loop": SOFTWARE_PRODUCTION_GOLDEN_LOOP})
        return context.connectors.execute(request)

    def _effect(self, kind: str, tool: str, classification: str, result: ConnectorExecutionResult, approval_ref: str | None) -> EffectReceipt:
        outcome = _connector_outcome(result)
        if getattr(result, "unverified_recovery_journal_locator", None) is not None or result.error_code == "GOVERNED_EXECUTION_AMBIGUOUS":
            outcome = "in_doubt"
        external = None
        for key in ("id", "number", "html_url", "sha", "ref", "run_id", "deployment_id"):
            value = result.output.get(key)
            if value not in (None, ""):
                external = str(value)[:200]
                break
        import re as _re

        safe_external = external if external and _re.fullmatch(_REF_PATTERN, external) else None
        provenance_digest = getattr(result.provenance, "request_digest", None) if result.provenance is not None else None
        if not (isinstance(provenance_digest, str) and _re.fullmatch(_SHA256_PATTERN, provenance_digest)):
            provenance_digest = None
        return EffectReceipt(effect=kind, tool=tool, classification=classification, outcome=outcome, approval_ref=result.approval_ref or approval_ref, external_ref=safe_external, provenance_digest=provenance_digest, recovery_locator=getattr(result, "unverified_recovery_journal_locator", None), message=result.message[:2000] if result.message else None)  # type: ignore[arg-type]

    def form_release_candidate(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        policy = {item.effect: item for item in compilation.effects}
        digest = compilation.compilation_digest[:12]
        branch = f"lightbulb/software-production-{digest}"
        branch_result = self._call(context, tool="github.create_branch_ref", arguments={"repository": self.repository, "ref": f"refs/heads/{branch}", "from_branch": self.base_branch}, effect=ConnectorEffect.WRITE, operation_ref="branch_create", approval_required=policy["branch_create"].approval_required)
        effects = [self._effect("branch_create", "github.create_branch_ref", policy["branch_create"].classification, branch_result, context.approval_ref_for(self.primitive_ref, operation_ref="branch_create"))]
        receipts: list[EvidenceReceipt] = []
        if effects[0].outcome == "completed":
            receipts.append(_receipt("branch", branch, self.issuer_ref, at))
            sha = str(branch_result.output.get("sha") or branch_result.output.get("object", {}).get("sha") or "")
            if sha:
                receipts.append(_receipt("commit", sha[:200], self.issuer_ref, at))
        if policy["pull_request_open"].classification != "preview" and effects[0].outcome == "completed":
            pr_result = self._call(context, tool="github.create_pull_request", arguments={"repository": self.repository, "title": compilation.work_packet_input["title"], "head": branch, "base": self.base_branch, "body": f"Lightbulb software production {compilation.compilation_digest}"}, effect=ConnectorEffect.WRITE, operation_ref="pull_request_open", approval_required=policy["pull_request_open"].approval_required)
            effects.append(self._effect("pull_request_open", "github.create_pull_request", policy["pull_request_open"].classification, pr_result, context.approval_ref_for(self.primitive_ref, operation_ref="pull_request_open")))
            if effects[-1].outcome == "completed" and effects[-1].external_ref:
                receipts.append(_receipt("pull_request", effects[-1].external_ref, self.issuer_ref, at))
        else:
            effects.append(EffectReceipt(effect="pull_request_open", tool="github.create_pull_request", classification=policy["pull_request_open"].classification, outcome="preview", message="pull request not opened under this release policy"))
        return tuple(receipts), tuple(effects)

    def verify(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[EvidenceReceipt, ...]:
        branch = f"lightbulb/software-production-{compilation.compilation_digest[:12]}"
        result = self._call(context, tool="github.list_check_runs", arguments={"repository": self.repository, "ref": branch}, effect=ConnectorEffect.READ, operation_ref="ci_verify", approval_required=False)
        if result.status != ConnectorExecutionStatus.COMPLETED:
            return ()
        runs = result.output.get("check_runs") or result.output.get("items") or []
        if not runs or any(str(run.get("conclusion", "")).lower() not in {"success", "neutral", "skipped"} for run in runs):
            return ()
        return (_receipt("ci", f"checks:{branch}", self.issuer_ref, at),)

    def deploy(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, environment: Literal["staging", "production"], at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        kind = "staging_deploy" if environment == "staging" else "production_deploy"
        policy = {item.effect: item for item in compilation.effects}[kind]
        if policy.classification == "preview":
            return (), (EffectReceipt(effect=kind, tool="github.dispatch_workflow", classification="preview", outcome="preview", message="deployment is preview-only under this release policy"),)
        approval = context.approval_ref_for(self.primitive_ref, operation_ref=kind)
        rehearse = environment == "staging" and compilation.effective_evidence.rollback_verification
        inputs: dict[str, Any] = {"environment": environment, "compilation_digest": compilation.compilation_digest}
        if rehearse:
            inputs["rollback_rehearsal"] = True
        result = self._call(context, tool="github.dispatch_workflow", arguments={"repository": self.repository, "workflow": self.deploy_workflow, "ref": f"lightbulb/software-production-{compilation.compilation_digest[:12]}", "inputs": inputs}, effect=ConnectorEffect.WRITE, operation_ref=kind, approval_required=policy.approval_required)
        effect = self._effect(kind, "github.dispatch_workflow", policy.classification, result, approval)
        receipts: list[EvidenceReceipt] = []
        if effect.outcome == "completed":
            run_ref = effect.external_ref or f"dispatch:{environment}"
            receipts.append(_receipt("staging" if environment == "staging" else "deployment", run_ref, self.issuer_ref, at))
            if rehearse:
                receipts.append(_receipt("rollback", f"rollback-rehearsal:{run_ref}", self.issuer_ref, at))
        elif effect.outcome == "failed" and environment == "production":
            receipts.append(_receipt("deployment", f"dispatch:production:failed:{effect.external_ref or compilation.compilation_digest[:12]}", self.issuer_ref, at))
        return tuple(receipts), (effect,)

    def roll_back(self, *, compilation: SoftwareProductionCompilation, context: PrimitiveExecutionContext, at: str) -> tuple[tuple[EvidenceReceipt, ...], tuple[EffectReceipt, ...]]:
        policy = {item.effect: item for item in compilation.effects}["rollback"]
        approval = context.approval_ref_for(self.primitive_ref, operation_ref="rollback")
        result = self._call(context, tool="github.dispatch_workflow", arguments={"repository": self.repository, "workflow": self.deploy_workflow, "ref": self.base_branch, "inputs": {"environment": "production", "rollback_of": compilation.compilation_digest}}, effect=ConnectorEffect.WRITE, operation_ref="rollback", approval_required=policy.approval_required)
        effect = self._effect("rollback", "github.dispatch_workflow", policy.classification, result, approval)
        return ((_receipt("rollback", effect.external_ref or "rollback", self.issuer_ref, at),) if effect.outcome == "completed" else ()), (effect,)


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


class SoftwareProductionLoopRunner:
    """Executes at most one stage per call through the ports; state stays a candidate."""

    def __init__(self, *, grants: HarnessGrantPort, release: Any, observation: ProductionObservationPort | None = None, actor_ref: str = "lightbulb-sdk:loop-runner") -> None:
        self.grants, self.release, self.observation, self.actor_ref = grants, release, observation or release, actor_ref

    def _command(self, state: SoftwareProductionLoopState, event: RunEvent, at: str, *, role: str, actor_ref: str | None = None, **extra: Any) -> dict[str, Any]:
        return seal_loop_command({"event": event, "transition_ref": f"{event}:{state.compilation_digest[:12]}:{state.version + 1}", "idempotency_key": f"{state.admission.admission_key}:{event}:{state.version + 1}", "expected_version": state.version, "expected_state_digest": state.state_digest, "expected_cancellation_fence": state.control.cancellation_fence, "occurred_at": at, "actor_ref": actor_ref or self.actor_ref, "actor_role": role, **extra})

    def compile_work_packet(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, work_packet_ref: str, at: str) -> LoopTransitionResult:
        """Record the Spring-created Work Packet (project.create_work_packet) bound to the compiled digest."""

        return apply_software_production_event(compilation, state, self._command(state, "compile_work_packet", at, role="spring", actor_ref="spring:work-packet", receipts=[_receipt("work_packet", work_packet_ref, "spring:work-packet", at, digest=compilation.work_packet_digest).to_dict()]))

    def select_harness(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, resolved_by_spring: HarnessFamily, at: str) -> LoopTransitionResult:
        return apply_software_production_event(compilation, state, self._command(state, "select_harness", at, role="spring", actor_ref="spring:execution-host-policy", selected_harness_family=resolved_by_spring))

    def authorize_builder(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, at: str) -> LoopTransitionResult:
        family = state.receipt_set.selected_harness_family
        if family is None:
            raise ValueError("harness must be selected before a grant is issued")
        grant = self.grants.issue_grant(compilation=compilation, harness_family=family, at=at)
        return apply_software_production_event(compilation, state, self._command(state, "authorize_builder", at, role="spring", actor_ref="spring:grant-authority", grant=grant.to_dict(), receipts=[_receipt("provider_grant", grant.grant_ref, getattr(self.grants, "issuer_ref", "grant-authority"), at, digest=grant.grant_digest).to_dict()]))

    def record_builder_result(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, builder_ref: str, result_ref: str, result_digest: str, at: str) -> LoopTransitionResult:
        return apply_software_production_event(compilation, state, self._command(state, "produce_change", at, role="builder", actor_ref=builder_ref, receipts=[_receipt("builder_result", result_ref, builder_ref, at, independent=False, digest=result_digest).to_dict()]))

    def record_verdict(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, evaluator_ref: str, verdict_ref: str, accepted: bool, at: str) -> LoopTransitionResult:
        return apply_software_production_event(compilation, state, self._command(state, "accept" if accepted else "reject", at, role="evaluator", actor_ref=evaluator_ref, evaluator_accepted=accepted, receipts=[_receipt("evaluator_verdict", verdict_ref, evaluator_ref, at).to_dict()], reason=None if accepted else "independent evaluator rejected the change"))

    def form_release_candidate(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, context: PrimitiveExecutionContext, *, at: str) -> LoopTransitionResult:
        receipts, effects = self.release.form_release_candidate(compilation=compilation, context=context, at=at)
        return apply_software_production_event(compilation, state, self._command(state, "form_release_candidate", at, role="release_connector", receipts=[r.to_dict() for r in receipts], effects=[e.to_dict() for e in effects]))

    def verify_ci_and_policy(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, context: PrimitiveExecutionContext, *, at: str) -> LoopTransitionResult:
        receipts = self.release.verify(compilation=compilation, context=context, at=at)
        if not receipts:
            return apply_software_production_event(compilation, state, self._command(state, "block", at, role="release_connector", reason="CI or policy verification did not pass"))
        return apply_software_production_event(compilation, state, self._command(state, "verify_ci_and_policy", at, role="release_connector", receipts=[r.to_dict() for r in receipts]))

    def verify_staging(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, context: PrimitiveExecutionContext, *, at: str) -> LoopTransitionResult:
        receipts, effects = self.release.deploy(compilation=compilation, context=context, environment="staging", at=at)
        return apply_software_production_event(compilation, state, self._command(state, "verify_staging", at, role="release_connector", receipts=[r.to_dict() for r in receipts], effects=[e.to_dict() for e in effects]))

    def authorize_production(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, approver_ref: str, approval_ref: str, role: str, at: str) -> LoopTransitionResult:
        return apply_software_production_event(compilation, state, self._command(state, "authorize_production", at, role=role, actor_ref=approver_ref, receipts=[_receipt("release_approval", approval_ref, approver_ref, at).to_dict()]))

    def execute_production(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, context: PrimitiveExecutionContext, *, at: str) -> LoopTransitionResult:
        receipts, effects = self.release.deploy(compilation=compilation, context=context, environment="production", at=at)
        result = apply_software_production_event(compilation, state, self._command(state, "execute_production", at, role="release_connector", receipts=[r.to_dict() for r in receipts], effects=[e.to_dict() for e in effects]))
        if not result.candidate_validated and result.receipt.rejection_code == "EFFECT_FAILED":
            return apply_software_production_event(compilation, state, self._command(state, "fail_deployment", at, role="release_connector", reason=result.receipt.recovery.instructions, receipts=[r.to_dict() for r in receipts], effects=[e.to_dict() for e in effects]))
        return result

    def observe_production(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, at: str) -> LoopTransitionResult:
        """Record the independent observation; a breach is retained as the observer's reason and blocks verification."""

        receipts = self.observation.observe(compilation=compilation, at=at)
        kinds = {r.kind for r in receipts}
        payload = [r.to_dict() for r in receipts]
        missing = [kind for kind in ("production_health", "business_outcome") if kind not in kinds]
        for kind in missing:
            payload.append(_receipt(kind, f"{kind}:not_confirmed", "observer:production", at).to_dict())
        reason = f"independent observation did not confirm {', '.join(missing)}" if missing else None
        return apply_software_production_event(compilation, state, self._command(state, "observe_production", at, role="observer", actor_ref="observer:production", receipts=payload, reason=reason))

    def verify_production(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, at: str) -> LoopTransitionResult:
        return apply_software_production_event(compilation, state, self._command(state, "verify_production", at, role="observer", actor_ref="observer:production"))

    def roll_back(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, context: PrimitiveExecutionContext, *, at: str, reason: str) -> LoopTransitionResult:
        receipts, effects = self.release.roll_back(compilation=compilation, context=context, at=at)
        return apply_software_production_event(compilation, state, self._command(state, "roll_back", at, role="release_connector", receipts=[r.to_dict() for r in receipts], effects=[e.to_dict() for e in effects], reason=reason))

    def cancel(self, compilation: SoftwareProductionCompilation, state: SoftwareProductionLoopState, *, control: ExecutionRunControl, at: str, reason: str) -> LoopTransitionResult:
        current = apply_control_update(state, control)
        return apply_software_production_event(compilation, current, self._command(current, "cancel", at, role="spring", actor_ref="spring:execution-run-authority", reason=reason))


__all__ = [
    "EXECUTION_RUN_ADMISSION_SCHEMA",
    "LOOP_COMMAND_SCHEMA",
    "LOOP_RESULT_SCHEMA",
    "LOOP_STATE_SCHEMA",
    "MAX_LOOP_TRANSITIONS",
    "BudgetLedger",
    "CiPolicyPort",
    "DeploymentPort",
    "EffectReceipt",
    "ExecutionRunAdmission",
    "ExecutionRunControl",
    "GitHubConnectorReleaseAdapter",
    "HarnessGrant",
    "HarnessGrantPort",
    "InMemoryHarnessGrantPort",
    "InMemoryReleaseAdapter",
    "LoopCommand",
    "LoopEffectBoundary",
    "LoopRecovery",
    "LoopTransition",
    "LoopTransitionReceipt",
    "LoopTransitionResult",
    "ProductionObservationPort",
    "SoftwareProductionLoopRunner",
    "SoftwareProductionLoopState",
    "SourceCustodyPort",
    "admission_for_compilation",
    "admit_software_production_run",
    "apply_control_update",
    "apply_software_production_event",
    "genesis_loop_state_digest",
    "loop_command_digest",
    "loop_result_input",
    "seal_loop_command",
]
