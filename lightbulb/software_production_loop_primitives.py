"""Executable primitives for the software-production loop slice (Work Package 1B).

``project.admit_software_production_run`` turns a compilation plus Spring's
registered Execution Run control into the genesis loop state.
``project.apply_software_production_event`` materializes exactly one
replay-fenced loop transition from a sealed command.  Both are pure
mechanics: they never persist, never call a provider, harness, CI, or
deployment platform, and never mint authority.  Spring remains the source of
truth for the Execution Run, the cancellation fence, approvals, and effects.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import field_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
)
from lightbulb.software_production import SOFTWARE_PRODUCTION_GOLDEN_LOOP, SoftwareProductionCompilation, compile_software_production_request
from lightbulb.software_production_loop import (
    ExecutionRunAdmission,
    ExecutionRunControl,
    LoopCommand,
    LoopTransitionResult,
    OpaqueRef,
    SoftwareProductionLoopState,
    _StrictModel,
    _timestamp,
    admit_software_production_run,
    apply_software_production_event,
    seal_loop_command,
)
from lightbulb.software_production_primitives import _request_digest, _scope_matches, _SoftwareProductionPrimitive, example_software_production_request


ADMIT_OPERATION = PrimitiveOperationSpec(
    operation_ref="software_production_admit_run",
    tool="sdk.project.admit_software_production_run",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
APPLY_EVENT_OPERATION = PrimitiveOperationSpec(
    operation_ref="software_production_apply_event",
    tool="sdk.project.apply_software_production_event",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)

EXAMPLE_EXECUTION_RUN_ID = "7d3b6e2e-3b2b-4b4e-9d0a-2f9f6d7e5a11"


class AdmitSoftwareProductionRunInput(_StrictModel):
    """Compilation plus Spring's registered run; the admission defaults to the compilation binding."""

    compilation: SoftwareProductionCompilation
    control: ExecutionRunControl
    admission: ExecutionRunAdmission | None = None
    admitted_at: str
    actor_ref: OpaqueRef = "spring:execution-run-authority"

    @field_validator("admitted_at")
    @classmethod
    def _admitted(cls, value: str) -> str:
        return _timestamp(value, field_name="admitted_at")


class ApplySoftwareProductionEventInput(_StrictModel):
    """One sealed loop command against the exact current loop state."""

    compilation: SoftwareProductionCompilation
    state: SoftwareProductionLoopState
    command: LoopCommand


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        compilation = compile_software_production_request(example_software_production_request())
        control = {"execution_run_id": EXAMPLE_EXECUTION_RUN_ID, "revision": 1, "cancellation_fence": 0}
        state = admit_software_production_run(compilation, control, admitted_at="2026-09-11T00:00:00Z", actor_ref="spring:execution-run-authority")
        command = seal_loop_command(
            {
                "event": "compile_work_packet",
                "transition_ref": f"compile_work_packet:{compilation.compilation_digest[:12]}:2",
                "idempotency_key": f"{compilation.origin.idempotency_key}:compile_work_packet:2",
                "expected_version": state.version,
                "expected_state_digest": state.state_digest,
                "expected_cancellation_fence": 0,
                "occurred_at": "2026-09-11T00:05:00Z",
                "actor_ref": "spring:work-packet",
                "actor_role": "spring",
                "receipts": [{"kind": "work_packet", "ref": "work-packet-example", "issuer_ref": "spring:work-packet", "observed_at": "2026-09-11T00:05:00Z", "independent_of_builder": True, "digest": compilation.work_packet_digest}],
            }
        )
        self._built = {
            "admit": {"compilation": compilation.to_dict(), "control": control, "admitted_at": "2026-09-11T00:00:00Z", "actor_ref": "spring:execution-run-authority"},
            "apply": {"compilation": compilation.to_dict(), "state": state.to_dict(), "command": command},
        }
        return self._built


_EXAMPLES = _ExampleBundle()


class _LazyExample(Mapping[str, Any]):
    def __init__(self, key: str) -> None:
        self._key = key

    def _payload(self) -> dict[str, Any]:
        return _EXAMPLES.get()[self._key]

    def __getitem__(self, key: str) -> Any:
        return self._payload()[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._payload())

    def __len__(self) -> int:
        return len(self._payload())

    def keys(self):  # type: ignore[no-untyped-def]
        return self._payload().keys()

    def items(self):  # type: ignore[no-untyped-def]
        return self._payload().items()

    def values(self):  # type: ignore[no-untyped-def]
        return self._payload().values()


def example_loop_inputs() -> dict[str, Any]:
    """Deterministic example admit/apply inputs (built lazily, safe to call repeatedly)."""

    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class AdmitSoftwareProductionRunPrimitive(_SoftwareProductionPrimitive[AdmitSoftwareProductionRunInput, SoftwareProductionLoopState]):
    primitive_ref = "project.admit_software_production_run"
    version = "0.1.0"
    title = "Admit a software-production run against Spring's Execution Run"
    description = (
        "Bind a compiled software-production request to the Execution Run Spring registered (run id, "
        "revision, cancellation fence) and materialize the genesis loop state. The admission key is the "
        "origin idempotency key and the admission digest is the compilation digest; nothing is persisted "
        "and no harness, provider, or deployment platform is called."
    )
    input_model = AdmitSoftwareProductionRunInput
    output_model = SoftwareProductionLoopState
    risk_level = "medium"
    operation_spec = ADMIT_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("admit")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdmitSoftwareProductionRunInput) -> PrimitiveExecutionResult[SoftwareProductionLoopState]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.compilation.scope, inputs.actor_ref, context, idempotency_key=inputs.compilation.origin.idempotency_key):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope, admitting actor, and idempotency key must exactly match the compiled request and its origin key.")
        try:
            state = admit_software_production_run(inputs.compilation, inputs.control, inputs.admission, admitted_at=inputs.admitted_at, actor_ref=inputs.actor_ref)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="ADMISSION_NOT_BOUND", message=str(exc)[:500])
        return self._preview(
            output=state, request_digest=request_digest,
            external_refs={"execution_run_ref": state.control.execution_run_id, "compilation_digest": state.compilation_digest, "state_digest": state.state_digest},
            event_type="project.software_production_run_admitted",
            event_payload={"execution_run_ref": state.control.execution_run_id, "status": state.status, "version": state.version, "cancellation_fence": state.control.cancellation_fence, "persisted": False},
            evidence_kind="software_production_loop_state", evidence_summary="Genesis loop state bound to the Spring Execution Run; candidate only until Spring persists it.",
            summary=f"Admitted software-production run {state.control.execution_run_id[:8]} at version {state.version} ({state.status}).",
        )


class ApplySoftwareProductionEventPrimitive(_SoftwareProductionPrimitive[ApplySoftwareProductionEventInput, LoopTransitionResult]):
    primitive_ref = "project.apply_software_production_event"
    version = "0.1.0"
    title = "Apply one replay-fenced software-production loop event"
    description = (
        "Materialize exactly one lifecycle transition from a sealed loop command against the exact current "
        "loop state. Duplicate delivery, stale revisions, cancellation-fence drift, uncertain host outcomes, "
        "role violations, unbound grants, budget exhaustion, and unauthorized or ambiguous effects are "
        "rejected with a typed recovery disposition. Never persists; never calls a provider."
    )
    input_model = ApplySoftwareProductionEventInput
    output_model = LoopTransitionResult
    risk_level = "high"
    operation_spec = APPLY_EVENT_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("apply")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ApplySoftwareProductionEventInput) -> PrimitiveExecutionResult[LoopTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.compilation.scope, inputs.command.actor_ref, context, idempotency_key=inputs.command.idempotency_key):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope, acting actor, and idempotency key must exactly match the compiled request and the command.")
        result = apply_software_production_event(inputs.compilation, inputs.state, inputs.command)
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(
            output=result, request_digest=request_digest,
            external_refs={"execution_run_ref": inputs.state.control.execution_run_id, "transition_ref": receipt.transition_ref, "from_state_digest": receipt.from_state_digest, "to_state_digest": receipt.to_state_digest},
            event_type="project.software_production_event_applied",
            event_payload={"event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "from_version": receipt.from_version, "to_version": receipt.to_version, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition, "persisted": False},
            evidence_kind="software_production_loop_transition", evidence_summary="Replay-fenced transition receipt; the state is a candidate until Spring retains it.",
            summary=(f"{receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.event} {receipt.status}: {receipt.rejection_code} ({receipt.recovery.disposition})."),
            blocker=blocker,
        )


SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    AdmitSoftwareProductionRunPrimitive(),
    ApplySoftwareProductionEventPrimitive(),
)

SOFTWARE_PRODUCTION_LOOP_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "software_production_golden_loop",
    "work_package": "1B",
    "golden_loop": SOFTWARE_PRODUCTION_GOLDEN_LOOP,
    "stacked_on": "fable/software-production-contract (Work Package 1A)",
    "modules": {"domain": "lightbulb.software_production_loop", "primitives": "lightbulb.software_production_loop_primitives"},
    "reuses": [
        "lightbulb.software_production (compilation, lifecycle table, receipt set, run handle, assessment)",
        "lightbulb.primitive_runtime.PrimitiveExecutionContext.connector_request / approval_ref_for",
        "lightbulb.connector_execution (ConnectorEffect, ConnectorExecutionResult, InMemoryConnectorExecutor)",
        "Spring SpringExecutionRunAuthority records (RegisterRun -> ExecutionRunAdmission, CancellationFence -> ExecutionRunControl) mirrored, not edited",
    ],
    "primitive_refs": [item.primitive_ref for item in SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.software_production_loop_primitives import SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES", "splice": "*SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES", "SOFTWARE_PRODUCTION_LOOP_INTEGRATION_MANIFEST", "AdmitSoftwareProductionRunPrimitive", "ApplySoftwareProductionEventPrimitive", "ExecutionRunAdmission", "ExecutionRunControl", "HarnessGrant", "EffectReceipt", "LoopCommand", "LoopTransitionResult", "SoftwareProductionLoopState", "SoftwareProductionLoopRunner", "GitHubConnectorReleaseAdapter", "InMemoryReleaseAdapter", "InMemoryHarnessGrantPort", "admit_software_production_run", "apply_software_production_event", "apply_control_update", "seal_loop_command"]},
    "connector_tools_used_by_reference_adapter": ["github.create_branch_ref", "github.create_pull_request", "github.list_check_runs", "github.dispatch_workflow"],
    "spring": {
        "execution_run": "Spring registers the run (RegisterRun) and owns its id, revision, and cancellation fence; the SDK carries ExecutionRunControl mirrors only.",
        "harness": "Spring resolves the harness family under Company Execution Host Policy and issues one-use grants; the grant token never enters the SDK.",
        "effects": "Every branch, pull request, deployment, and rollback goes through the Connector Runtime with approval, idempotency, and provenance authority; ambiguous outcomes exit to reconciliation.",
        "persistence": "Loop state is a digest-chained candidate; Spring retains transitions and replays duplicates as TRANSITION_ALREADY_APPLIED.",
    },
    "mcp": {"note": "Work Package 1C generates the lifecycle projection (start/status/supply_input/approve_checkpoint/cancel/resolve_reconciliation) from these schemas."},
    "non_goals": ["no Java or Spring edits", "no direct GitHub, CI, or cloud client", "no automatic production authority", "no claim of hosted execution, certification, or production readiness"],
}

__all__ = [
    "ADMIT_OPERATION",
    "APPLY_EVENT_OPERATION",
    "EXAMPLE_EXECUTION_RUN_ID",
    "SOFTWARE_PRODUCTION_LOOP_EXECUTABLE_PRIMITIVES",
    "SOFTWARE_PRODUCTION_LOOP_INTEGRATION_MANIFEST",
    "AdmitSoftwareProductionRunInput",
    "AdmitSoftwareProductionRunPrimitive",
    "ApplySoftwareProductionEventInput",
    "ApplySoftwareProductionEventPrimitive",
    "example_loop_inputs",
]
