"""Continuous, proposal-only improvement loop for Lightbulb workflows.

The loop evaluates the local business-primitive contracts, records trends, and
emits SDK-first work packets. It never edits code, invokes an agent or connector,
publishes a workflow, or performs an external write. A human must approve a work
packet before a coding harness is allowed to implement it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from collections import deque
from collections.abc import Mapping
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, List

from pydantic import BaseModel

from lightbulb.business_primitives import (
    BUSINESS_PRIMITIVES,
    BusinessPrimitive,
    PrimitiveField,
    compile_business_workflow_definition,
    primitive_runtime_contract,
    sdk_only_business_primitive_capability_projections,
    simulate_business_workflow,
    validate_business_workflow_definition,
)
from lightbulb.connector_execution import ExecutionScope, InMemoryConnectorExecutor
from lightbulb.executable_primitives import default_primitive_registry
from lightbulb.primitive_runtime import (
    ExecutablePrimitiveRuntime,
    PrimitiveCall,
    PrimitiveCorrelation,
    PrimitiveRegistry,
    StandalonePrimitiveRun,
)


IMPROVEMENT_REPORT_SCHEMA = "lightbulb.workflow_improvement_report.v1"
IMPROVEMENT_STATE_SCHEMA = "lightbulb.workflow_improvement_state.v1"
IMPROVEMENT_QUEUE_SCHEMA = "lightbulb.workflow_improvement_queue.v1"
IMPROVEMENT_PACKET_SCHEMA = "lightbulb.workflow_improvement_packet.v1"
IMPROVEMENT_STATUS_SCHEMA = "lightbulb.workflow_improvement_status.v1"
IMPROVEMENT_HISTORY_SCHEMA = "lightbulb.workflow_improvement_history_entry.v1"
IMPROVEMENT_HISTORY_COMPACTION_SCHEMA = (
    "lightbulb.workflow_improvement_history_compaction.v1"
)
IMPROVEMENT_SUPERVISOR_BUDGET_SCHEMA = (
    "lightbulb.workflow_improvement_supervisor_budget.v1"
)
IMPROVEMENT_SUPERVISOR_STOP_SCHEMA = "lightbulb.workflow_improvement_supervisor_stop.v1"

DEFAULT_SUPERVISOR_MAX_ITERATIONS = 96
DEFAULT_SUPERVISOR_MAX_ELAPSED_SECONDS = 24 * 60 * 60
DEFAULT_SUPERVISOR_MAX_NO_PROGRESS_RUNS = 2
DEFAULT_MAX_OBSERVED_OUTCOMES = 256
DEFAULT_MAX_HISTORY_ENTRIES = 256
DEFAULT_MAX_HISTORY_BYTES = 512 * 1024
DEFAULT_MAX_QUEUE_PACKETS = 1_024
DEFAULT_MAX_MANAGED_JSON_BYTES = 8 * 1024 * 1024
MAX_OBSERVED_OUTCOME_FILE_BYTES = 1 * 1024 * 1024

_HARD_MAX_SUPERVISOR_ITERATIONS = 10_000
_HARD_MAX_SUPERVISOR_ELAPSED_SECONDS = 7 * 24 * 60 * 60
_HARD_MAX_SUPERVISOR_NO_PROGRESS_RUNS = 100
_HARD_MAX_OBSERVED_OUTCOMES = 1_024
_HARD_MAX_HISTORY_ENTRIES = 4_096
_HARD_MAX_HISTORY_BYTES = 4 * 1024 * 1024
_HARD_MAX_QUEUE_PACKETS = 4_096
_HARD_MAX_MANAGED_JSON_BYTES = 16 * 1024 * 1024

_LOCK_NAME = ".continuous-improvement.lock"
_ACTIVE_PACKET_STATUSES = {"proposed", "approved"}
_OBSERVED_FAILURE_STATUSES = {"failed", "error", "timed_out", "timeout"}
_SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
_OBSERVED_OUTCOME_FIELDS = {
    "primitive_ref",
    "status",
    "error_kind",
    "latency_ms",
    "approval_state",
    "validation_valid",
    "occurred_at",
    "harness",
}
_MISSING = object()


GROWTH_CANDIDATES = (
    {
        "primitive_ref": "communication.classify_reply",
        "title": "Classify inbound reply",
        "domain": "crm",
        "rationale": (
            "The email primitive already requires reply capture and classification, "
            "but classification is hidden infrastructure instead of a reusable primitive."
        ),
    },
    {
        "primitive_ref": "finance.collect_payment",
        "title": "Collect approved payment",
        "domain": "finance",
        "rationale": (
            "Invoice creation emits paid and overdue events, but the catalog has no "
            "governed payment-collection primitive with explicit approval policy."
        ),
    },
    {
        "primitive_ref": "approval.request_decision",
        "title": "Request governed decision",
        "domain": "operations",
        "rationale": (
            "A reusable decision primitive would let workflows model approval ownership, "
            "deadlines, escalation, and evidence without embedding custom gate logic."
        ),
    },
    {
        "primitive_ref": "documents.generate_business_artifact",
        "title": "Generate business artifact",
        "domain": "document_intelligence",
        "rationale": (
            "Custom workflows need a governed primitive for producing inspectable DOCX, "
            "XLSX, PPTX, or PDF evidence from prior workflow state."
        ),
    },
    {
        "primitive_ref": "project.create_work_packet",
        "title": "Create implementation work packet",
        "domain": "product",
        "rationale": (
            "Capability gaps should become approved implementation packets that preserve "
            "scope, tests, SOP impact, and delivery evidence."
        ),
    },
)


class ImprovementLoopAlreadyRunning(RuntimeError):
    """Raised when another continuous improvement supervisor owns the output dir."""


class WorkflowImprovementBudgetExceeded(RuntimeError):
    """Raised before an improvement cycle can exceed a hard local resource cap."""


class WorkflowImprovementStateError(RuntimeError):
    """Raised when persisted supervisor state is unreadable or structurally unsafe."""


@dataclass(frozen=True, slots=True)
class WorkflowImprovementSupervisorBudget:
    """Finite resource authority for one local proposal-only supervisor run.

    The local evaluator makes no model, connector, or external-write calls, but
    it still consumes CPU, wall time, and storage.  Every field is therefore
    finite and subject to a non-overridable SDK ceiling.
    """

    max_iterations: int = DEFAULT_SUPERVISOR_MAX_ITERATIONS
    max_elapsed_seconds: int = DEFAULT_SUPERVISOR_MAX_ELAPSED_SECONDS
    max_no_progress_runs: int = DEFAULT_SUPERVISOR_MAX_NO_PROGRESS_RUNS
    max_observed_outcomes: int = DEFAULT_MAX_OBSERVED_OUTCOMES
    max_history_entries: int = DEFAULT_MAX_HISTORY_ENTRIES
    max_history_bytes: int = DEFAULT_MAX_HISTORY_BYTES
    max_queue_packets: int = DEFAULT_MAX_QUEUE_PACKETS
    max_managed_json_bytes: int = DEFAULT_MAX_MANAGED_JSON_BYTES

    def __post_init__(self) -> None:
        self._require_bounded_int(
            "max_iterations",
            self.max_iterations,
            minimum=1,
            maximum=_HARD_MAX_SUPERVISOR_ITERATIONS,
        )
        self._require_bounded_int(
            "max_elapsed_seconds",
            self.max_elapsed_seconds,
            minimum=1,
            maximum=_HARD_MAX_SUPERVISOR_ELAPSED_SECONDS,
        )
        self._require_bounded_int(
            "max_no_progress_runs",
            self.max_no_progress_runs,
            minimum=1,
            maximum=_HARD_MAX_SUPERVISOR_NO_PROGRESS_RUNS,
        )
        self._require_bounded_int(
            "max_observed_outcomes",
            self.max_observed_outcomes,
            minimum=1,
            maximum=_HARD_MAX_OBSERVED_OUTCOMES,
        )
        self._require_bounded_int(
            "max_history_entries",
            self.max_history_entries,
            minimum=1,
            maximum=_HARD_MAX_HISTORY_ENTRIES,
        )
        self._require_bounded_int(
            "max_history_bytes",
            self.max_history_bytes,
            minimum=4_096,
            maximum=_HARD_MAX_HISTORY_BYTES,
        )
        self._require_bounded_int(
            "max_queue_packets",
            self.max_queue_packets,
            minimum=1,
            maximum=_HARD_MAX_QUEUE_PACKETS,
        )
        self._require_bounded_int(
            "max_managed_json_bytes",
            self.max_managed_json_bytes,
            minimum=64 * 1024,
            maximum=_HARD_MAX_MANAGED_JSON_BYTES,
        )

    @staticmethod
    def _require_bounded_int(
        name: str,
        value: Any,
        *,
        minimum: int,
        maximum: int,
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if not minimum <= value <= maximum:
            raise ValueError(f"{name} must be between {minimum} and {maximum}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": IMPROVEMENT_SUPERVISOR_BUDGET_SCHEMA,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "max_history_bytes": self.max_history_bytes,
            "max_history_entries": self.max_history_entries,
            "max_iterations": self.max_iterations,
            "max_managed_json_bytes": self.max_managed_json_bytes,
            "max_no_progress_runs": self.max_no_progress_runs,
            "max_observed_outcomes": self.max_observed_outcomes,
            "max_queue_packets": self.max_queue_packets,
        }


def default_workflow_improvement_dir() -> Path:
    configured = os.getenv("LIGHTBULB_WORKFLOW_IMPROVEMENT_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.cwd() / ".lightbulb" / "workflow-improvement"


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(now: datetime | None = None) -> str:
    return _utc_now(now).isoformat()


def _run_id(now: datetime) -> str:
    return "workflow-improvement-" + now.strftime("%Y%m%dT%H%M%S%fZ")


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _strict_json_loads(payload: str | bytes) -> Any:
    return json.loads(payload, parse_constant=_reject_nonfinite_json)


def _read_json(
    path: Path,
    default: Any,
    *,
    max_bytes: int = DEFAULT_MAX_MANAGED_JSON_BYTES,
) -> Any:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return default
    except OSError as exc:
        raise WorkflowImprovementStateError(f"could not inspect {path}: {exc}") from exc
    if size > max_bytes:
        raise WorkflowImprovementBudgetExceeded(
            f"{path.name} exceeds its {max_bytes}-byte managed-state limit"
        )
    try:
        return _strict_json_loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError) as exc:
        raise WorkflowImprovementStateError(f"could not parse {path}: {exc}") from exc


def _json_bytes(payload: Any) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise WorkflowImprovementStateError(
            f"managed state is not strict JSON: {exc}"
        ) from exc
    return (rendered + "\n").encode("utf-8")


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _bounded_json_bytes(path: Path, payload: Any, *, max_bytes: int) -> bytes:
    serialized = _json_bytes(payload)
    if len(serialized) > max_bytes:
        raise WorkflowImprovementBudgetExceeded(
            f"{path.name} would exceed its {max_bytes}-byte managed-state limit"
        )
    return serialized


def _atomic_write_json(
    path: Path,
    payload: Any,
    *,
    max_bytes: int = DEFAULT_MAX_MANAGED_JSON_BYTES,
) -> None:
    serialized = _bounded_json_bytes(path, payload, max_bytes=max_bytes)
    _atomic_write_bytes(path, serialized)


def _history_line(payload: Any) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise WorkflowImprovementStateError(
            f"history entry is not strict JSON: {exc}"
        ) from exc
    return (rendered + "\n").encode("utf-8")


def _load_history_compaction(
    path: Path,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    default = {
        "schema": IMPROVEMENT_HISTORY_COMPACTION_SCHEMA,
        "algorithm": "sha256_length_prefixed_chain.v1",
        "retired_entry_count": 0,
        "retired_source_bytes": 0,
        "retired_sha256": "0" * 64,
        "last_retired_run_id": None,
    }
    value = _read_json(path, default, max_bytes=max_bytes)
    if not isinstance(value, dict):
        raise WorkflowImprovementStateError(
            "history-compaction.json must contain an object"
        )
    if value.get("schema") != IMPROVEMENT_HISTORY_COMPACTION_SCHEMA:
        raise WorkflowImprovementStateError(
            "history-compaction.json has an unsupported schema"
        )
    if value.get("algorithm") != "sha256_length_prefixed_chain.v1":
        raise WorkflowImprovementStateError(
            "history-compaction.json has an unsupported digest algorithm"
        )
    for field in ("retired_entry_count", "retired_source_bytes"):
        parsed = value.get(field)
        if isinstance(parsed, bool) or not isinstance(parsed, int) or parsed < 0:
            raise WorkflowImprovementStateError(
                f"history-compaction.json has an invalid {field}"
            )
    digest = value.get("retired_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise WorkflowImprovementStateError(
            "history-compaction.json has an invalid retired_sha256"
        )
    last_run_id = value.get("last_retired_run_id")
    if last_run_id is not None and (
        not isinstance(last_run_id, str) or len(last_run_id) > 180
    ):
        raise WorkflowImprovementStateError(
            "history-compaction.json has an invalid last_retired_run_id"
        )
    return value


def _fold_retired_history_digest(previous_digest: str, line: bytes) -> str:
    return hashlib.sha256(
        bytes.fromhex(previous_digest)
        + len(line).to_bytes(8, byteorder="big", signed=False)
        + line
    ).hexdigest()


def _plan_bounded_history(
    output_dir: Path,
    entry: dict[str, Any],
    *,
    budget: WorkflowImprovementSupervisorBudget,
    updated_at: str,
) -> tuple[bytes, dict[str, Any]]:
    history_path = output_dir / "history.jsonl"
    receipt_path = output_dir / "history-compaction.json"
    prior = _load_history_compaction(
        receipt_path,
        max_bytes=budget.max_managed_json_bytes,
    )
    try:
        existing_size = history_path.stat().st_size
    except FileNotFoundError:
        existing_size = 0
    except OSError as exc:
        raise WorkflowImprovementStateError(
            f"could not inspect {history_path}: {exc}"
        ) from exc
    if existing_size > budget.max_managed_json_bytes:
        raise WorkflowImprovementBudgetExceeded(
            "history.jsonl exceeds the managed-state read ceiling"
        )
    try:
        existing = history_path.read_bytes() if existing_size else b""
    except OSError as exc:
        raise WorkflowImprovementStateError(
            f"could not read {history_path}: {exc}"
        ) from exc

    retained: deque[bytes] = deque()
    retained_bytes = 0
    for raw_line in existing.splitlines(keepends=True):
        if not raw_line.strip():
            continue
        line = raw_line if raw_line.endswith(b"\n") else raw_line + b"\n"
        try:
            retained_row = _strict_json_loads(line)
        except (ValueError, UnicodeError) as exc:
            raise WorkflowImprovementStateError(
                "history.jsonl contains an invalid retained entry"
            ) from exc
        if (
            not isinstance(retained_row, dict)
            or retained_row.get("schema") != IMPROVEMENT_HISTORY_SCHEMA
        ):
            raise WorkflowImprovementStateError(
                "history.jsonl contains an unsupported retained entry"
            )
        retained.append(line)
        retained_bytes += len(line)
    new_line = _history_line(entry)
    if len(new_line) > budget.max_history_bytes:
        raise WorkflowImprovementBudgetExceeded(
            "one workflow-improvement history entry exceeds the full history byte budget"
        )
    retained.append(new_line)
    retained_bytes += len(new_line)

    retired_count = int(prior["retired_entry_count"])
    retired_source_bytes = int(prior["retired_source_bytes"])
    retired_digest = str(prior["retired_sha256"])
    last_retired_run_id = prior.get("last_retired_run_id")
    while (
        len(retained) > budget.max_history_entries
        or retained_bytes > budget.max_history_bytes
    ):
        retired = retained.popleft()
        retained_bytes -= len(retired)
        retired_count += 1
        retired_source_bytes += len(retired)
        retired_digest = _fold_retired_history_digest(retired_digest, retired)
        try:
            retired_row = _strict_json_loads(retired)
        except (ValueError, UnicodeError) as exc:
            raise WorkflowImprovementStateError(
                "history.jsonl contains an invalid retained entry"
            ) from exc
        candidate_run_id = (
            retired_row.get("run_id") if isinstance(retired_row, dict) else None
        )
        if isinstance(candidate_run_id, str) and len(candidate_run_id) <= 180:
            last_retired_run_id = candidate_run_id

    history = b"".join(retained)
    receipt = {
        "schema": IMPROVEMENT_HISTORY_COMPACTION_SCHEMA,
        "algorithm": "sha256_length_prefixed_chain.v1",
        "updated_at": updated_at,
        "retired_entry_count": retired_count,
        "retired_source_bytes": retired_source_bytes,
        "retired_sha256": retired_digest,
        "last_retired_run_id": last_retired_run_id,
        "retained_entry_count": len(retained),
        "retained_bytes": len(history),
        "raw_retired_content_retained": False,
    }
    return history, receipt


@contextmanager
def _improvement_lock(output_dir: Path) -> Iterator[None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / _LOCK_NAME
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise ImprovementLoopAlreadyRunning(
            f"workflow improvement loop already owns {lock_path}; remove it only after confirming no supervisor is running"
        ) from exc
    try:
        os.write(
            descriptor,
            json.dumps({"pid": os.getpid(), "started_at": _iso()}).encode("utf-8"),
        )
        os.close(descriptor)
        yield
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _synthetic_value(field: PrimitiveField) -> Any:
    field_type = str(field.type or "string").strip().lower()
    name = field.name.lower()
    if field_type in {"array", "list"}:
        if "email" in name or "attendee" in name or "recipient" in name:
            return ["synthetic@example.test"]
        return ["synthetic-value"]
    if field_type in {"boolean", "bool"}:
        return False
    if field_type in {"number", "integer", "float"}:
        return 1
    if field_type in {"object", "dict", "map"}:
        return {"synthetic": True}
    if "date" in name:
        return "2099-01-01"
    if "email" in name:
        return "synthetic@example.test"
    if "url" in name:
        return "https://example.test/synthetic"
    return f"synthetic-{field.name.replace('_', '-')}"


def synthetic_inputs_for_primitive(primitive: BusinessPrimitive) -> dict[str, Any]:
    """Generate non-sensitive inputs sufficient for contract simulation."""
    return {
        field.name: _synthetic_value(field)
        for field in primitive.input_fields
        if field.required
    }


def _evaluate_primitive(primitive: BusinessPrimitive) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    details: dict[str, Any] = {}
    error = ""
    try:
        if not primitive.backbone_fallback_available:
            runtime_contract = primitive_runtime_contract(
                primitive,
                include_inputs=True,
            )
            execution = runtime_contract["execution_contract"]
            implementation = default_primitive_registry().get(primitive.id)
            implementation_fields = set(implementation.input_model.model_fields)
            required_fields = set(runtime_contract["input_contract"]["required_fields"])
            checks = {
                "typed_sdk_executor_declared": (
                    execution.get("executor") == "typed_sdk_primitive_runtime"
                ),
                "backbone_fallback_denied": (
                    execution.get("backbone_fallback_available") is False
                ),
                "typed_implementation_registered": (
                    implementation.primitive_ref == primitive.id
                ),
                "required_inputs_match_implementation": (
                    required_fields <= implementation_fields
                ),
                "catalog_risk_matches": (
                    implementation.risk_level == primitive.risk_level
                ),
                "catalog_approval_matches": (
                    implementation.approval_required == primitive.approval_required
                ),
                "raw_connector_bypass_denied": (
                    execution.get("raw_connector_bypass_allowed") is False
                ),
                "tenant_company_rbac_preserved": (
                    execution.get("preserve_tenant_company_rbac") is True
                ),
                "hidden_setup_declared": bool(primitive.setup_requirements),
                "events_declared": bool(primitive.trigger_events and primitive.emits),
            }
            details = {
                "evaluation_mode": "typed_sdk_primitive",
                "implementation_version": implementation.version,
                "required_fields": sorted(required_fields),
            }
            return {
                "primitive_ref": primitive.id,
                "title": primitive.title,
                "category": primitive.category,
                "risk_level": primitive.risk_level,
                "approval_required": primitive.approval_required,
                "passed": all(checks.values()),
                "checks": checks,
                "details": details,
                "error": None,
            }

        inputs = synthetic_inputs_for_primitive(primitive)
        trigger = next(iter(primitive.trigger_events), "manual.requested")
        definition = compile_business_workflow_definition(
            f"Continuously verify {primitive.title}",
            primitive_ids=[primitive.id],
            inputs=inputs,
            workflow_name=f"Verify {primitive.title}",
            trigger_event=trigger,
            owner_role="workflow_improvement_reviewer",
            source="workflow_improvement",
        )
        validation = validate_business_workflow_definition(definition)
        approval_map = {primitive.id: True}
        without_approval = simulate_business_workflow(definition)
        approved = simulate_business_workflow(definition, approvals=approval_map)

        checks["compiles"] = (
            definition.get("schema") == "lightbulb.business_workflow_definition.v1"
        )
        checks["validates"] = validation.get("valid") is True
        checks["tenant_company_rbac"] = definition.get("scope_contract") == {
            "tenant_scope_required": True,
            "company_scope_required": True,
            "rbac_enforced_by_control_plane": True,
            "scope_ids_embedded": False,
        }
        checks["raw_connector_bypass_denied"] = all(
            step.get("execution", {}).get("raw_connector_bypass_allowed") is False
            for step in definition.get("steps", [])
            if step.get("type") == "agent_step"
        )
        checks["approved_simulation_completes"] = approved.get("status") == "completed"
        checks["approval_guard"] = (
            without_approval.get("status") == "needs_approval"
            if primitive.approval_required
            else without_approval.get("status") == "completed"
        )

        required_fields = [
            field.name for field in primitive.input_fields if field.required
        ]
        if required_fields:
            missing_definition = compile_business_workflow_definition(
                f"Verify missing input for {primitive.title}",
                primitive_ids=[primitive.id],
                inputs={},
                workflow_name=f"Missing input for {primitive.title}",
                trigger_event=trigger,
                owner_role="workflow_improvement_reviewer",
                source="workflow_improvement",
            )
            missing = simulate_business_workflow(
                missing_definition,
                approvals=approval_map,
            )
            checks["required_input_guard"] = (
                missing.get("status") == "needs_input"
                and missing.get("blocked_step", {}).get("missing_required_fields")
                == required_fields
            )
            details["missing_input_status"] = missing.get("status")
        else:
            checks["required_input_guard"] = True
            details["missing_input_status"] = "not_applicable"

        checks["hidden_setup_declared"] = bool(primitive.setup_requirements)
        checks["events_declared"] = bool(primitive.trigger_events and primitive.emits)
        details.update(
            {
                "trigger_event": trigger,
                "without_approval_status": without_approval.get("status"),
                "approved_status": approved.get("status"),
                "required_fields": required_fields,
            }
        )
    except Exception as exc:  # noqa: BLE001 - evaluator must report, not crash the loop
        error = f"{type(exc).__name__}: {exc}"
        checks.setdefault("evaluation_completed", False)

    passed = bool(checks) and all(checks.values())
    return {
        "primitive_ref": primitive.id,
        "title": primitive.title,
        "category": primitive.category,
        "risk_level": primitive.risk_level,
        "approval_required": primitive.approval_required,
        "passed": passed,
        "checks": checks,
        "details": details,
        "error": error or None,
    }


def _contract_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, BaseModel):
        return {
            name: getattr(value, name)
            for name in type(value).model_fields
        }
    return {}


def _contract_at(value: Any, *path: str) -> Any:
    current = value
    for field_name in path:
        current = _contract_mapping(current).get(field_name, _MISSING)
        if current is _MISSING:
            return None
    return current


def _nested_contract_values(value: Any, field_name: str) -> list[Any]:
    """Collect named values from mappings and validated Pydantic contracts."""

    found: list[Any] = []
    pending = [value]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if isinstance(current, (Mapping, BaseModel)):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            fields = _contract_mapping(current)
            if field_name in fields:
                found.append(fields[field_name])
            pending.extend(fields.values())
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(current)
    return found


def _example_execution_profile(
    example_inputs: Mapping[str, Any] | BaseModel,
) -> tuple[ExecutionScope, str | None]:
    """Derive the trusted context declared by one synthetic primitive example."""

    def first_text(*values: Any) -> str | None:
        for value in values:
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    root = _contract_mapping(example_inputs)
    workspace = root.get("workspace")
    command = root.get("command")
    evidence = root.get("evidence")
    scope_candidates = (
        root.get("scope"),
        _contract_at(root.get("dossier"), "inputs", "scope"),
        root.get("close_scope"),
        _contract_at(workspace, "scope"),
        _contract_at(workspace, "close_scope"),
        _contract_at(command, "scope"),
        _contract_at(command, "close_scope"),
        _contract_at(command, "workspace", "close_scope"),
        evidence,
        _contract_at(evidence, "scope"),
        _contract_at(evidence, "close_scope"),
        _contract_at(root.get("ledger_materialization"), "snapshot", "scope"),
        _contract_at(root.get("ledger_materialization"), "source_inputs", "scope"),
        root.get("close_evidence_bundle"),
        _contract_at(root.get("lifecycle_snapshot"), "scope"),
        _contract_at(root.get("final_transition"), "lifecycle_input", "scope"),
        _contract_at(
            root.get("final_transition"),
            "lifecycle_input",
            "command",
            "scope",
        ),
        example_inputs,
    )
    scope: Mapping[str, Any] = {}
    for candidate in scope_candidates:
        mapped = _contract_mapping(candidate)
        if all(
            first_text(mapped.get(field_name)) is not None
            for field_name in ("tenant_ref", "company_ref", "project_ref")
        ):
            scope = mapped
            break

    command_contract = _contract_mapping(command)
    command_scope = _contract_mapping(command_contract.get("scope"))
    actor_ref = first_text(
        root.get("requested_by_ref"),
        root.get("prepared_by_ref"),
        root.get("acting_ref"),
        root.get("actor_ref"),
        scope.get("actor_ref"),
        command_contract.get("requested_by_ref"),
        command_contract.get("prepared_by_ref"),
        command_contract.get("requester_ref"),
        command_contract.get("acting_ref"),
        command_contract.get("actor_ref"),
        command_contract.get("operator_ref"),
        command_scope.get("actor_ref"),
    )
    idempotency_key = first_text(
        root.get("idempotency_key"),
        command_contract.get("idempotency_key"),
    )
    fence = _contract_mapping(root.get("fence"))
    if idempotency_key is None and fence:
        transition_ref = first_text(fence.get("transition_ref"))
        if transition_ref is not None:
            idempotency_key = f"idempotency-{transition_ref}"

    project_id = scope.get("project_id")
    if project_id is None:
        project_ids = {
            str(value).strip()
            for value in _nested_contract_values(example_inputs, "project_id")
            if value is not None and str(value).strip()
        }
        if len(project_ids) > 1:
            raise ValueError(
                "synthetic example contains conflicting project_id evidence"
            )
        if project_ids:
            project_id = next(iter(project_ids))

    return (
        ExecutionScope(
            tenant_ref=first_text(
                scope.get("tenant_ref"), root.get("tenant_id")
            )
            or "authenticated",
            company_ref=first_text(
                scope.get("company_ref"), root.get("company_id")
            )
            or "selected",
            project_ref=first_text(scope.get("project_ref")) or "workflow-improvement",
            project_id=project_id,
            actor_ref=actor_ref,
        ),
        idempotency_key,
    )


@lru_cache(maxsize=2048)
def _cached_executable_implementation(primitive: Any, sdk_only_refs: frozenset[str]) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    details: dict[str, Any] = {}
    error = ""
    try:
        catalog_primitive = next(
            (
                item
                for item in BUSINESS_PRIMITIVES
                if item.id == primitive.primitive_ref
            ),
            None,
        )
        contract = primitive.implementation_contract()
        connectors = InMemoryConnectorExecutor()
        runtime = ExecutablePrimitiveRuntime(
            PrimitiveRegistry([primitive]),
            connectors,
        )
        example_inputs = dict(primitive.example_inputs)
        typed_example_inputs = primitive.input_model.model_validate(example_inputs)
        scope, idempotency_key = _example_execution_profile(typed_example_inputs)
        session = runtime.open(
            StandalonePrimitiveRun(
                scope=scope,
                run_ref=f"evaluate-{primitive.primitive_ref}",
                idempotency_key=idempotency_key,
                correlation=PrimitiveCorrelation(source="workflow_improvement"),
            )
        )
        result = session.execute(
            PrimitiveCall(
                primitive_ref=primitive.primitive_ref,
                inputs=example_inputs,
            )
        )
        checks["example_inputs_declared"] = bool(primitive.example_inputs)
        checks["typed_input_schema"] = (
            contract.get("input_schema", {}).get("type") == "object"
        )
        checks["typed_output_schema"] = (
            contract.get("output_schema", {}).get("type") == "object"
        )
        if catalog_primitive is not None:
            checks["catalog_entry_exists"] = True
            checks["catalog_risk_matches"] = (
                catalog_primitive.risk_level == primitive.risk_level
            )
            checks["catalog_approval_matches"] = (
                catalog_primitive.approval_required == primitive.approval_required
            )
            checks["catalog_connector_tools_match"] = set(
                catalog_primitive.connector_tools
            ) == set(primitive.connector_tools)
        else:
            # SDK-only executables intentionally lack Backbone catalog routes;
            # parity is satisfied by the sdk-only capability projection that
            # keeps them discoverable without a misleading domain-agent
            # fallback (see sdk_only_business_primitive_capability_projections).
            checks["sdk_only_projection_exists"] = (
                primitive.primitive_ref in sdk_only_refs
            )
        expected_source_quarantine = (
            result.status.value == "blocked"
            and bool(result.blockers)
            and all(
                blocker.code
                == "golden_loop.verified_improvement.source_authority_quarantined"
                and blocker.retryable is False
                for blocker in result.blockers
            )
        )
        checks["preview_execution_completes_or_fails_closed"] = (
            result.status.value in {"completed", "preview"}
            or expected_source_quarantine
        )
        checks["preview_has_no_connector_calls"] = len(connectors.requests) == 0
        checks["structured_result_schema"] = (
            result.to_dict().get("schema") == "lightbulb.primitive_execution_result.v1"
        )
        details = {
            "version": primitive.version,
            "execution_status": result.status.value,
            "connector_request_count": len(connectors.requests),
            "expected_source_quarantine": expected_source_quarantine,
        }
    except Exception as exc:  # noqa: BLE001 - evaluator must report, not crash the loop
        error = f"{type(exc).__name__}: {exc}"
        checks.setdefault("evaluation_completed", False)
    return {
        "primitive_ref": primitive.primitive_ref,
        "title": primitive.title,
        "version": primitive.version,
        "passed": bool(checks) and all(checks.values()),
        "checks": checks,
        "details": details,
        "error": error or None,
    }


def _evaluate_executable_implementation(primitive: Any, *, sdk_only_refs: frozenset[str] | None = None) -> dict[str, Any]:
    """Return an isolated copy of the deterministic cached implementation audit."""

    if sdk_only_refs is None:
        sdk_only_refs = frozenset(str(row.get("primitive_ref") or row.get("id") or "")
            for row in sdk_only_business_primitive_capability_projections())
    return deepcopy(_cached_executable_implementation(primitive, sdk_only_refs))


def _sanitize_observed_outcomes(
    values: Iterable[Any] | None,
    *,
    limit: int,
) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    sanitized: List[dict[str, Any]] = []
    inspected_count = 0
    rejected_count = 0
    overflow_detected = False
    for value in values or []:
        inspected_count += 1
        if inspected_count > limit:
            overflow_detected = True
            break
        if not isinstance(value, dict):
            rejected_count += 1
            continue
        row = {
            key: value[key]
            for key in _OBSERVED_OUTCOME_FIELDS
            if key in value and value[key] is not None
        }
        raw_primitive_ref = row.get("primitive_ref")
        raw_status = row.get("status")
        if not isinstance(raw_primitive_ref, str) or not isinstance(raw_status, str):
            rejected_count += 1
            continue
        primitive_ref = raw_primitive_ref.strip().lower()
        status = raw_status.strip().lower()
        if (
            not primitive_ref
            or len(primitive_ref) > 200
            or not status
            or len(status) > 80
        ):
            rejected_count += 1
            continue
        row["primitive_ref"] = primitive_ref
        row["status"] = status
        if "error_kind" in row:
            if not isinstance(row["error_kind"], str) or len(row["error_kind"]) > 120:
                rejected_count += 1
                continue
            row["error_kind"] = row["error_kind"].strip()
        for field, maximum in (
            ("approval_state", 80),
            ("occurred_at", 64),
            ("harness", 120),
        ):
            if field not in row:
                continue
            if not isinstance(row[field], str) or len(row[field]) > maximum:
                rejected_count += 1
                row = {}
                break
            row[field] = row[field].strip()
        if not row:
            continue
        if "validation_valid" in row and not isinstance(row["validation_valid"], bool):
            rejected_count += 1
            continue
        if "latency_ms" in row:
            raw_latency_ms = row["latency_ms"]
            if isinstance(raw_latency_ms, bool) or not isinstance(
                raw_latency_ms,
                (int, float),
            ):
                rejected_count += 1
                continue
            latency_ms = float(raw_latency_ms)
            if not math.isfinite(latency_ms) or not 0 <= latency_ms <= 604_800_000:
                rejected_count += 1
                continue
            row["latency_ms"] = latency_ms
        sanitized.append(row)
    return sanitized, {
        "limit": limit,
        "inspected_count": inspected_count,
        "accepted_count": len(sanitized),
        "rejected_count": rejected_count,
        "overflow_detected": overflow_detected,
        "complete": not overflow_detected and rejected_count == 0,
    }


def _finding(
    *,
    severity: str,
    category: str,
    title: str,
    summary: str,
    primitive_refs: Iterable[str],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    refs = [str(ref).strip() for ref in primitive_refs if str(ref).strip()]
    digest = hashlib.sha256(
        f"{category}|{'|'.join(refs)}|{title}".encode("utf-8")
    ).hexdigest()[:12]
    return {
        "id": f"finding-{digest}",
        "severity": severity,
        "category": category,
        "title": title,
        "summary": summary,
        "primitive_refs": refs,
        "evidence": evidence,
    }


def _growth_finding(existing_refs: set[str]) -> dict[str, Any] | None:
    for candidate in GROWTH_CANDIDATES:
        if candidate["primitive_ref"] in existing_refs:
            continue
        return _finding(
            severity="P3",
            category="capability_growth",
            title=f"Add business primitive: {candidate['title']}",
            summary=candidate["rationale"],
            primitive_refs=[candidate["primitive_ref"]],
            evidence={
                "candidate_domain": candidate["domain"],
                "catalog_gap": True,
            },
        )
    return None


def _implementation_gap_finding(executable_refs: set[str]) -> dict[str, Any] | None:
    for primitive in BUSINESS_PRIMITIVES:
        if primitive.id in executable_refs:
            continue
        return _finding(
            severity="P2",
            category="missing_executable_implementation",
            title=f"Implement business process primitive: {primitive.title}",
            summary=(
                f"{primitive.id} has a catalog/runtime contract but no executable Python SDK "
                "implementation for custom projects."
            ),
            primitive_refs=[primitive.id],
            evidence={
                "catalog_entry": True,
                "executable_implementation": False,
                "risk_level": primitive.risk_level,
                "approval_required": primitive.approval_required,
            },
        )
    return None


def _packet_from_finding(finding: dict[str, Any], created_at: str) -> dict[str, Any]:
    refs = list(finding.get("primitive_refs") or [])
    packet_id = (
        "workflow-improvement-"
        + hashlib.sha256(str(finding.get("id") or "").encode("utf-8")).hexdigest()[:12]
    )
    domain = str(finding.get("evidence", {}).get("candidate_domain") or "").strip()
    if not domain:
        domain = refs[0].split(".", 1)[0] if refs else "operations"
    needs_implementation = finding.get("category") in {
        "capability_growth",
        "missing_executable_implementation",
    }
    acceptance = [
        "All workflow-improvement evaluator checks pass for the affected primitives.",
        "The SDK remains the source of truth and MCP remains a thin adapter.",
        "Tenant/company scope, RBAC, required inputs, idempotency, evidence, and HITL policy fail closed.",
        "Focused SDK, MCP, harness, documentation, and dogfood-loop checks pass.",
    ]
    if needs_implementation:
        acceptance.insert(
            0,
            "Add catalog metadata plus a typed BusinessProcessPrimitive implementation, Pydantic input/output models, safe example inputs, and SDK runtime tests.",
        )
    return {
        "schema": IMPROVEMENT_PACKET_SCHEMA,
        "id": packet_id,
        "status": "proposed",
        "priority": finding.get("severity") or "P3",
        "created_at": created_at,
        "title": finding.get("title"),
        "objective": finding.get("summary"),
        "task_kind": "workflow_authoring",
        "assigned_domain": domain,
        "target_primitive_refs": refs,
        "source_finding": finding,
        "target_files": [
            "lightbulb-sdk/lightbulb/business_primitives.py",
            "lightbulb-sdk/lightbulb/executable_primitives.py",
            "lightbulb-sdk/lightbulb/primitive_runtime.py",
            "lightbulb-sdk/lightbulb/connector_execution.py",
            "lightbulb-sdk/lightbulb/project_runtime.py",
            "lightbulb-sdk/tests/test_business_primitives.py",
            "lightbulb-sdk/tests/test_sdk_runtime.py",
            "lightbulb-sdk/lightbulb/mcp_server.py",
            "lightbulb-sdk/tests/test_mcp_server.py",
            "agent-workers/agents/harness_prompt_composer.py",
            "lightbulb-sdk/CUSTOM_PROJECTS.md",
            "docs/business-primitive-runtime-and-workflow-compiler-contracts-v1.md",
        ],
        "acceptance_criteria": acceptance,
        "approval_gate": {
            "required": True,
            "verdict_source": "human_current_session",
            "approval_scope": "implementation_only",
            "publish_or_deploy_requires_separate_approval": True,
        },
        "execution_policy": {
            "automatic_code_mutation": False,
            "automatic_publish": False,
            "automatic_deploy": False,
            "automatic_connector_write": False,
            "allowed_before_approval": [
                "read local source",
                "run local read-only evaluation",
                "prepare this work packet",
            ],
        },
        "harness_handoff": {
            "coding_agent_handoff": {
                "selected_work_packets": [
                    {
                        "id": packet_id,
                        "type": "workflow_authoring",
                        "phase": "implementation",
                        "title": finding.get("title"),
                        "objective": finding.get("summary"),
                        "primitive_refs": refs,
                        "assigned_domain": domain,
                        "acceptance_criteria": acceptance,
                    }
                ]
            }
        },
    }


def evaluate_workflow_improvement(
    *,
    observed_outcomes: Iterable[Any] | None = None,
    previous_report: dict[str, Any] | None = None,
    now: datetime | None = None,
    budget: WorkflowImprovementSupervisorBudget | None = None,
) -> dict[str, Any]:
    """Evaluate contracts and propose approval-gated SDK work packets."""
    resolved_budget = budget or WorkflowImprovementSupervisorBudget()
    timestamp = _iso(now)
    evaluations = [_evaluate_primitive(primitive) for primitive in BUSINESS_PRIMITIVES]
    executable_registry = default_primitive_registry()
    # A full projection generates every model schema. Compute its membership
    # once per audit, rather than regenerating the catalog for each primitive.
    sdk_only_refs = frozenset(str(row.get("primitive_ref") or row.get("id") or "")
        for row in sdk_only_business_primitive_capability_projections())
    implementation_evaluations = [
        _evaluate_executable_implementation(
            executable_registry.get(row["primitive_ref"]), sdk_only_refs=sdk_only_refs
        )
        for row in executable_registry.catalog()
    ]
    check_count = sum(len(row["checks"]) for row in evaluations)
    passed_checks = sum(
        sum(1 for passed in row["checks"].values() if passed) for row in evaluations
    )
    score = round((passed_checks / check_count) * 100.0, 2) if check_count else 0.0
    observed, observed_intake = _sanitize_observed_outcomes(
        observed_outcomes,
        limit=resolved_budget.max_observed_outcomes,
    )
    implementation_check_count = sum(
        len(row["checks"]) for row in implementation_evaluations
    )
    passed_implementation_checks = sum(
        sum(1 for passed in row["checks"].values() if passed)
        for row in implementation_evaluations
    )
    implementation_score = (
        round(
            (passed_implementation_checks / implementation_check_count) * 100.0,
            2,
        )
        if implementation_check_count
        else 0.0
    )

    findings: List[dict[str, Any]] = []
    if observed_intake["overflow_detected"]:
        findings.append(
            _finding(
                severity="P1",
                category="observed_outcome_budget_exceeded",
                title="Split observed runtime outcomes into bounded batches",
                summary=(
                    "Runtime outcome intake exceeded the finite evaluator limit; "
                    "uninspected outcomes may contain failures, so this cycle cannot be green."
                ),
                primitive_refs=[],
                evidence=observed_intake,
            )
        )
    if observed_intake["rejected_count"]:
        findings.append(
            _finding(
                severity="P1",
                category="invalid_observed_outcome",
                title="Repair malformed runtime outcome evidence",
                summary=(
                    "One or more runtime outcomes failed the bounded allow-listed contract; "
                    "they were excluded rather than coerced into training evidence."
                ),
                primitive_refs=[],
                evidence=observed_intake,
            )
        )
    for row in evaluations:
        if row["passed"]:
            continue
        failed_checks = [name for name, passed in row["checks"].items() if not passed]
        findings.append(
            _finding(
                severity="P1",
                category="contract_regression",
                title=f"Repair primitive contract: {row['primitive_ref']}",
                summary=(
                    "The continuous contract evaluator found failing SDK workflow invariants: "
                    + ", ".join(failed_checks or ["evaluation error"])
                ),
                primitive_refs=[row["primitive_ref"]],
                evidence={"failed_checks": failed_checks, "error": row.get("error")},
            )
        )

    for row in implementation_evaluations:
        if row["passed"]:
            continue
        failed_checks = [name for name, passed in row["checks"].items() if not passed]
        findings.append(
            _finding(
                severity="P1",
                category="implementation_regression",
                title=f"Repair executable primitive: {row['primitive_ref']}",
                summary=(
                    "The executable SDK evaluator found failing implementation invariants: "
                    + ", ".join(failed_checks or ["evaluation error"])
                ),
                primitive_refs=[row["primitive_ref"]],
                evidence={"failed_checks": failed_checks, "error": row.get("error")},
            )
        )

    known_refs = {primitive.id for primitive in BUSINESS_PRIMITIVES}
    for outcome in observed:
        primitive_ref = outcome["primitive_ref"]
        status = outcome["status"]
        validation_failed = outcome.get("validation_valid") is False
        if status in _OBSERVED_FAILURE_STATUSES or validation_failed:
            findings.append(
                _finding(
                    severity="P1",
                    category="observed_runtime_failure",
                    title=f"Investigate observed primitive failure: {primitive_ref}",
                    summary=(
                        f"Observed outcome ended as {status}; diagnose the SDK contract, "
                        "runtime adapter, approval path, and evidence before expanding capability."
                    ),
                    primitive_refs=[primitive_ref],
                    evidence=outcome,
                )
            )
        elif primitive_ref not in known_refs:
            findings.append(
                _finding(
                    severity="P2",
                    category="unknown_observed_primitive",
                    title=f"Register observed primitive: {primitive_ref}",
                    summary="Runtime evidence referenced a primitive that is absent from the SDK catalog.",
                    primitive_refs=[primitive_ref],
                    evidence=outcome,
                )
            )

    executable_refs = {row["primitive_ref"] for row in implementation_evaluations}
    implementation_gap = _implementation_gap_finding(executable_refs)
    if implementation_gap is not None:
        findings.append(implementation_gap)
    else:
        growth = _growth_finding(known_refs)
        if growth is not None:
            findings.append(growth)
    findings.sort(
        key=lambda row: (
            _SEVERITY_ORDER.get(str(row.get("severity")), 99),
            str(row.get("id")),
        )
    )
    packets = [_packet_from_finding(finding, timestamp) for finding in findings]

    previous_score = None
    if isinstance(previous_report, dict):
        try:
            previous_score = float(
                previous_report.get("metrics", {}).get("contract_score")
            )
        except (TypeError, ValueError):
            previous_score = None
    if previous_score is None:
        direction = "baseline"
        delta = None
    else:
        delta = round(score - previous_score, 2)
        direction = "improved" if delta > 0 else "regressed" if delta < 0 else "stable"

    return {
        "schema": IMPROVEMENT_REPORT_SCHEMA,
        "generated_at": timestamp,
        "mode": "proposal_only",
        "metrics": {
            "primitive_count": len(BUSINESS_PRIMITIVES),
            "evaluation_count": len(evaluations),
            "passed_primitive_count": sum(1 for row in evaluations if row["passed"]),
            "failed_primitive_count": sum(
                1 for row in evaluations if not row["passed"]
            ),
            "check_count": check_count,
            "passed_check_count": passed_checks,
            "contract_score": score,
            "executable_primitive_count": len(implementation_evaluations),
            # Coverage compares catalog entries against executables as SETS:
            # SDK-only executables (no catalog route by design) must not
            # produce negative gaps or >100% coverage.
            "missing_executable_primitive_count": len(
                {primitive.id for primitive in BUSINESS_PRIMITIVES} - executable_refs
            ),
            "executable_coverage_percent": round(
                (
                    len(
                        {primitive.id for primitive in BUSINESS_PRIMITIVES}
                        & executable_refs
                    )
                    / len(BUSINESS_PRIMITIVES)
                )
                * 100.0,
                2,
            )
            if BUSINESS_PRIMITIVES
            else 0.0,
            "implementation_check_count": implementation_check_count,
            "passed_implementation_check_count": passed_implementation_checks,
            "implementation_score": implementation_score,
            "observed_outcome_count": len(observed),
            "observed_outcome_limit": resolved_budget.max_observed_outcomes,
            "observed_outcome_overflow_detected": observed_intake["overflow_detected"],
            "rejected_observed_outcome_count": observed_intake["rejected_count"],
            "finding_count": len(findings),
        },
        "trend": {
            "direction": direction,
            "previous_score": previous_score,
            "delta": delta,
        },
        "primitive_evaluations": evaluations,
        "implementation_evaluations": implementation_evaluations,
        "observed_outcomes": observed,
        "observed_outcome_intake": observed_intake,
        "findings": findings,
        "proposed_packets": packets,
        "safety": {
            "tenant_company_scope_evaluated": True,
            "rbac_contract_evaluated": True,
            "synthetic_inputs_only": True,
            "network_calls": False,
            "agent_invocations": False,
            "connector_invocations": False,
            "external_writes": False,
            "code_mutations": False,
            "publish_or_deploy": False,
            "human_approval_required_before_implementation": True,
            "finite_supervisor_budget": resolved_budget.to_dict(),
        },
    }


def _merge_queue(
    output_dir: Path,
    proposed_packets: List[dict[str, Any]],
    updated_at: str,
    *,
    budget: WorkflowImprovementSupervisorBudget,
) -> dict[str, Any]:
    existing = _read_json(
        output_dir / "improvement-queue.json",
        {"schema": IMPROVEMENT_QUEUE_SCHEMA, "packets": []},
        max_bytes=budget.max_managed_json_bytes,
    )
    if (
        not isinstance(existing, dict)
        or existing.get("schema") != IMPROVEMENT_QUEUE_SCHEMA
    ):
        raise WorkflowImprovementStateError(
            "improvement-queue.json has an unsupported contract"
        )
    existing_rows = existing.get("packets")
    if not isinstance(existing_rows, list):
        raise WorkflowImprovementStateError(
            "improvement-queue.json packets must be an array"
        )
    if len(existing_rows) > budget.max_queue_packets:
        raise WorkflowImprovementBudgetExceeded(
            "workflow-improvement queue already exceeds its packet budget"
        )
    if any(
        not isinstance(row, dict)
        or not isinstance(row.get("id"), str)
        or not row["id"]
        or len(row["id"]) > 180
        for row in existing_rows
    ):
        raise WorkflowImprovementStateError(
            "improvement-queue.json contains an invalid packet"
        )
    existing_by_id = {str(row.get("id")): row for row in existing_rows}
    merged_by_id = dict(existing_by_id)
    for packet in proposed_packets:
        prior = existing_by_id.get(packet["id"])
        if prior:
            packet["created_at"] = prior.get("created_at") or packet["created_at"]
            packet["status"] = prior.get("status") or packet["status"]
            if "human_decision" in prior:
                packet["human_decision"] = prior["human_decision"]
        packet["last_observed_at"] = updated_at
        merged_by_id[packet["id"]] = packet

    packets = sorted(
        merged_by_id.values(),
        key=lambda row: (
            _SEVERITY_ORDER.get(str(row.get("priority")), 99),
            str(row.get("id")),
        ),
    )
    if len(packets) > budget.max_queue_packets:
        raise WorkflowImprovementBudgetExceeded(
            "workflow-improvement queue packet budget is exhausted; "
            "resolve or export existing packets before another cycle"
        )
    return {
        "schema": IMPROVEMENT_QUEUE_SCHEMA,
        "updated_at": updated_at,
        "packet_count": len(packets),
        "active_packet_count": sum(
            1 for packet in packets if packet.get("status") in _ACTIVE_PACKET_STATUSES
        ),
        "packets": packets,
    }


def _state_nonnegative_int(
    state: dict[str, Any],
    field: str,
    *,
    default: int = 0,
) -> int:
    value = state.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkflowImprovementStateError(f"state.json has an invalid {field} value")
    return value


def _run_cycle_unlocked(
    output_dir: Path,
    *,
    observed_outcomes: Iterable[Any] | None,
    now: datetime | None,
    budget: WorkflowImprovementSupervisorBudget,
) -> dict[str, Any]:
    timestamp = _utc_now(now)
    generated_at = timestamp.isoformat()
    persisted_report = _read_json(
        output_dir / "latest.json",
        _MISSING,
        max_bytes=budget.max_managed_json_bytes,
    )
    if persisted_report is _MISSING:
        previous_report: dict[str, Any] = {}
    elif not isinstance(persisted_report, dict) or (
        persisted_report.get("schema") != IMPROVEMENT_REPORT_SCHEMA
    ):
        raise WorkflowImprovementStateError(
            "latest.json has an unsupported workflow-improvement report contract"
        )
    else:
        previous_report = persisted_report
        previous_metrics = previous_report.get("metrics")
        previous_score = (
            previous_metrics.get("contract_score")
            if isinstance(previous_metrics, dict)
            else None
        )
        if (
            isinstance(previous_score, bool)
            or not isinstance(previous_score, (int, float))
            or not math.isfinite(float(previous_score))
            or not 0 <= float(previous_score) <= 100
        ):
            raise WorkflowImprovementStateError(
                "latest.json has an invalid contract_score value"
            )
    previous_state = _read_json(
        output_dir / "state.json",
        {"schema": IMPROVEMENT_STATE_SCHEMA, "iterations": 0},
        max_bytes=budget.max_managed_json_bytes,
    )
    if (
        not isinstance(previous_state, dict)
        or previous_state.get("schema") != IMPROVEMENT_STATE_SCHEMA
    ):
        raise WorkflowImprovementStateError(
            "state.json has an unsupported workflow-improvement state contract"
        )
    previous_iterations = _state_nonnegative_int(previous_state, "iterations")
    prior_green_runs = _state_nonnegative_int(
        previous_state,
        "consecutive_green_runs",
    )
    prior_no_progress_runs = _state_nonnegative_int(
        previous_state,
        "no_progress_runs",
    )
    raw_previous_best = previous_state.get("best_contract_score", 0.0)
    if isinstance(raw_previous_best, bool) or not isinstance(
        raw_previous_best,
        (int, float),
    ):
        raise WorkflowImprovementStateError(
            "state.json has an invalid best_contract_score value"
        )
    previous_best = float(raw_previous_best)
    if not math.isfinite(previous_best) or not 0 <= previous_best <= 100:
        raise WorkflowImprovementStateError(
            "state.json has an invalid best_contract_score value"
        )
    prior_packet_id = previous_state.get("next_work_packet_id")
    if prior_packet_id is not None and (
        not isinstance(prior_packet_id, str) or len(prior_packet_id) > 180
    ):
        raise WorkflowImprovementStateError(
            "state.json has an invalid next_work_packet_id value"
        )
    prior_progress_digest = previous_state.get("progress_digest")
    if prior_progress_digest is not None and (
        not isinstance(prior_progress_digest, str)
        or len(prior_progress_digest) != 64
        or any(
            character not in "0123456789abcdef" for character in prior_progress_digest
        )
    ):
        raise WorkflowImprovementStateError(
            "state.json has an invalid progress_digest value"
        )
    report = evaluate_workflow_improvement(
        observed_outcomes=observed_outcomes,
        previous_report=previous_report,
        now=timestamp,
        budget=budget,
    )
    iteration = previous_iterations + 1
    queue = _merge_queue(
        output_dir,
        report["proposed_packets"],
        generated_at,
        budget=budget,
    )
    active_packets = [
        packet
        for packet in queue["packets"]
        if packet.get("status") in _ACTIVE_PACKET_STATUSES
    ]
    next_packet = active_packets[0] if active_packets else None
    score = float(report["metrics"]["contract_score"])
    has_blocking_finding = any(
        finding.get("severity") in {"P0", "P1"} for finding in report["findings"]
    )
    green = score == 100.0 and not has_blocking_finding
    next_packet_id = next_packet.get("id") if next_packet else None
    progress_digest = hashlib.sha256(
        _json_bytes(
            {
                "active_packets": [
                    {
                        "id": packet.get("id"),
                        "status": packet.get("status"),
                    }
                    for packet in active_packets
                ],
                "contract_score": score,
                "finding_ids": [finding.get("id") for finding in report["findings"]],
            }
        )
    ).hexdigest()
    no_progress = (
        prior_no_progress_runs + 1
        if previous_iterations > 0
        and prior_progress_digest == progress_digest
        and report["trend"]["direction"] == "stable"
        else 0
    )
    state = {
        "schema": IMPROVEMENT_STATE_SCHEMA,
        "iterations": iteration,
        "last_run_id": _run_id(timestamp),
        "last_run_at": generated_at,
        "last_contract_score": score,
        "best_contract_score": max(previous_best, score),
        "trend_direction": report["trend"]["direction"],
        "consecutive_green_runs": prior_green_runs + 1 if green else 0,
        "no_progress_runs": no_progress,
        "progress_digest": progress_digest,
        "pending_packet_count": len(active_packets),
        "next_work_packet_id": next_packet_id,
        "implementation_requires_human_approval": True,
        "automatic_mutation_enabled": False,
        "supervisor_budget": budget.to_dict(),
    }
    report["cycle"] = {
        "run_id": state["last_run_id"],
        "iteration": iteration,
        "pending_packet_count": len(active_packets),
        "next_work_packet_id": next_packet_id,
        "no_progress_runs": no_progress,
        "progress_digest": progress_digest,
        "supervisor_budget": budget.to_dict(),
    }
    history, history_compaction = _plan_bounded_history(
        output_dir,
        {
            "schema": IMPROVEMENT_HISTORY_SCHEMA,
            "run_id": state["last_run_id"],
            "generated_at": generated_at,
            "iteration": iteration,
            "contract_score": score,
            "trend_direction": report["trend"]["direction"],
            "finding_count": report["metrics"]["finding_count"],
            "next_work_packet_id": next_packet_id,
            "blocking_finding": has_blocking_finding,
        },
        budget=budget,
        updated_at=generated_at,
    )
    history_projection = {
        key: history_compaction[key]
        for key in (
            "retired_entry_count",
            "retired_source_bytes",
            "retired_sha256",
            "retained_entry_count",
            "retained_bytes",
        )
    }
    state["history"] = history_projection
    report["cycle"]["history"] = history_projection

    latest_path = output_dir / "latest.json"
    state_path = output_dir / "state.json"
    queue_path = output_dir / "improvement-queue.json"
    next_packet_path = output_dir / "next-work-packet.json"
    compaction_path = output_dir / "history-compaction.json"
    latest_bytes = _bounded_json_bytes(
        latest_path,
        report,
        max_bytes=budget.max_managed_json_bytes,
    )
    state_bytes = _bounded_json_bytes(
        state_path,
        state,
        max_bytes=budget.max_managed_json_bytes,
    )
    queue_bytes = _bounded_json_bytes(
        queue_path,
        queue,
        max_bytes=budget.max_managed_json_bytes,
    )
    next_packet_bytes = (
        _bounded_json_bytes(
            next_packet_path,
            next_packet,
            max_bytes=budget.max_managed_json_bytes,
        )
        if next_packet is not None
        else None
    )
    compaction_bytes = _bounded_json_bytes(
        compaction_path,
        history_compaction,
        max_bytes=budget.max_managed_json_bytes,
    )

    _atomic_write_bytes(latest_path, latest_bytes)
    _atomic_write_bytes(state_path, state_bytes)
    _atomic_write_bytes(queue_path, queue_bytes)
    if next_packet is not None:
        assert next_packet_bytes is not None
        _atomic_write_bytes(next_packet_path, next_packet_bytes)
    else:
        try:
            next_packet_path.unlink()
        except FileNotFoundError:
            pass
    _atomic_write_bytes(output_dir / "history.jsonl", history)
    _atomic_write_bytes(compaction_path, compaction_bytes)
    return report


def run_workflow_improvement_cycle(
    output_dir: str | Path | None = None,
    *,
    observed_outcomes: Iterable[Any] | None = None,
    now: datetime | None = None,
    budget: WorkflowImprovementSupervisorBudget | None = None,
    _lock: bool = True,
) -> dict[str, Any]:
    """Run one local evaluation cycle and persist its proposal-only artifacts."""
    resolved_budget = budget or WorkflowImprovementSupervisorBudget()
    target = (
        Path(output_dir)
        if output_dir is not None
        else default_workflow_improvement_dir()
    )
    if not _lock:
        target.mkdir(parents=True, exist_ok=True)
        return _run_cycle_unlocked(
            target,
            observed_outcomes=observed_outcomes,
            now=now,
            budget=resolved_budget,
        )
    with _improvement_lock(target):
        return _run_cycle_unlocked(
            target,
            observed_outcomes=observed_outcomes,
            now=now,
            budget=resolved_budget,
        )


def run_continuous_workflow_improvement(
    output_dir: str | Path | None = None,
    *,
    interval_seconds: float = 900,
    max_iterations: int | None = None,
    max_elapsed_seconds: int | None = None,
    max_no_progress_runs: int | None = None,
    budget: WorkflowImprovementSupervisorBudget | None = None,
    observed_outcomes_provider: Callable[[], Iterable[Any] | None] | None = None,
    stop_file: str | Path | None = None,
    on_cycle: Callable[[dict[str, Any]], None] | None = None,
    retain_reports: bool = True,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> List[dict[str, Any]]:
    """Run a finite, proposal-only supervisor and persist why it stopped.

    Omitted limits inherit finite SDK defaults (or the supplied ``budget``);
    ``None`` never grants unbounded execution. Create ``stop_file`` to request a
    clean stop between cycles. The supervisor owns a lock for its full lifetime
    so two watches cannot write the same history or queue concurrently.
    """
    if isinstance(interval_seconds, bool):
        raise ValueError("interval_seconds must be a finite number")
    try:
        parsed_interval = float(interval_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("interval_seconds must be a finite number") from exc
    if not math.isfinite(parsed_interval) or parsed_interval < 0:
        raise ValueError("interval_seconds must be a finite non-negative number")
    resolved_budget = budget or WorkflowImprovementSupervisorBudget()
    overrides: dict[str, int] = {}
    if max_iterations is not None:
        overrides["max_iterations"] = max_iterations
    if max_elapsed_seconds is not None:
        overrides["max_elapsed_seconds"] = max_elapsed_seconds
    if max_no_progress_runs is not None:
        overrides["max_no_progress_runs"] = max_no_progress_runs
    if overrides:
        resolved_budget = replace(resolved_budget, **overrides)
    target = (
        Path(output_dir)
        if output_dir is not None
        else default_workflow_improvement_dir()
    )
    stop_path = Path(stop_file) if stop_file is not None else None
    reports: List[dict[str, Any]] = []
    completed = 0
    stop_reason: str | None = None
    started_at = monotonic_fn()
    if isinstance(started_at, bool) or not isinstance(started_at, (int, float)):
        raise ValueError("monotonic_fn must return a finite number")
    started_at = float(started_at)
    if not math.isfinite(started_at):
        raise ValueError("monotonic_fn must return a finite number")

    def elapsed_seconds() -> float:
        current = monotonic_fn()
        if isinstance(current, bool) or not isinstance(current, (int, float)):
            raise WorkflowImprovementStateError(
                "monotonic clock returned a non-numeric value"
            )
        value = float(current) - started_at
        if not math.isfinite(value) or value < 0:
            raise WorkflowImprovementStateError(
                "monotonic clock moved backwards or returned a non-finite value"
            )
        return value

    with _improvement_lock(target):
        while completed < resolved_budget.max_iterations:
            if stop_path is not None and stop_path.exists():
                stop_reason = "stop_file"
                break
            if elapsed_seconds() >= resolved_budget.max_elapsed_seconds:
                stop_reason = "max_elapsed_seconds"
                break
            observed = (
                observed_outcomes_provider() if observed_outcomes_provider else None
            )
            report = run_workflow_improvement_cycle(
                target,
                observed_outcomes=observed,
                now=now_fn(),
                budget=resolved_budget,
                _lock=False,
            )
            completed += 1
            if retain_reports:
                reports.append(report)
            if on_cycle is not None:
                on_cycle(report)
            if (
                int(report.get("cycle", {}).get("no_progress_runs") or 0)
                >= resolved_budget.max_no_progress_runs
            ):
                stop_reason = "no_progress"
                break
            if completed >= resolved_budget.max_iterations:
                stop_reason = "max_iterations"
                break
            if elapsed_seconds() >= resolved_budget.max_elapsed_seconds:
                stop_reason = "max_elapsed_seconds"
                break
            if stop_path is not None and stop_path.exists():
                stop_reason = "stop_file"
                break
            remaining = resolved_budget.max_elapsed_seconds - elapsed_seconds()
            if remaining <= 0:
                stop_reason = "max_elapsed_seconds"
                break
            sleep_fn(min(parsed_interval, remaining))
        if stop_reason is None:
            stop_reason = "max_iterations"
        _record_supervisor_stop(
            target,
            budget=resolved_budget,
            stop_reason=stop_reason,
            cycles_completed=completed,
            elapsed_seconds=elapsed_seconds(),
            external_outcomes_provider_configured=(
                observed_outcomes_provider is not None
            ),
            external_cycle_callback_configured=on_cycle is not None,
        )
    return reports


def _record_supervisor_stop(
    output_dir: Path,
    *,
    budget: WorkflowImprovementSupervisorBudget,
    stop_reason: str,
    cycles_completed: int,
    elapsed_seconds: float,
    external_outcomes_provider_configured: bool,
    external_cycle_callback_configured: bool,
) -> dict[str, Any]:
    allowed_reasons = {
        "max_iterations",
        "max_elapsed_seconds",
        "no_progress",
        "stop_file",
    }
    if stop_reason not in allowed_reasons:
        raise ValueError(f"unsupported workflow-improvement stop reason: {stop_reason}")
    if (
        isinstance(cycles_completed, bool)
        or not isinstance(cycles_completed, int)
        or cycles_completed < 0
    ):
        raise ValueError("cycles_completed must be a non-negative integer")
    if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
        raise ValueError("elapsed_seconds must be a finite non-negative number")
    state = _read_json(
        output_dir / "state.json",
        {
            "schema": IMPROVEMENT_STATE_SCHEMA,
            "iterations": 0,
            "pending_packet_count": 0,
            "implementation_requires_human_approval": True,
            "automatic_mutation_enabled": False,
        },
        max_bytes=budget.max_managed_json_bytes,
    )
    if not isinstance(state, dict) or state.get("schema") != IMPROVEMENT_STATE_SCHEMA:
        raise WorkflowImprovementStateError(
            "state.json has an unsupported workflow-improvement state contract"
        )
    stopped_at = _iso()
    receipt = {
        "schema": IMPROVEMENT_SUPERVISOR_STOP_SCHEMA,
        "stopped_at": stopped_at,
        "stop_reason": stop_reason,
        "cycles_completed": cycles_completed,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "budget": budget.to_dict(),
        "proposal_only": True,
        "core_provider_calls": False,
        "core_network_calls": False,
        "external_outcomes_provider_configured": (
            external_outcomes_provider_configured
        ),
        "external_cycle_callback_configured": external_cycle_callback_configured,
        "connector_writes": False,
        "automatic_code_mutation": False,
        "automatic_publish_or_deploy": False,
    }
    state["supervisor_budget"] = budget.to_dict()
    state["supervisor"] = receipt
    state_path = output_dir / "state.json"
    receipt_path = output_dir / "supervisor-stop.json"
    state_bytes = _bounded_json_bytes(
        state_path,
        state,
        max_bytes=budget.max_managed_json_bytes,
    )
    receipt_bytes = _bounded_json_bytes(
        receipt_path,
        receipt,
        max_bytes=budget.max_managed_json_bytes,
    )
    _atomic_write_bytes(state_path, state_bytes)
    _atomic_write_bytes(receipt_path, receipt_bytes)
    return receipt


def list_workflow_improvement_packets(
    output_dir: str | Path | None = None,
    *,
    status: str | None = None,
) -> List[dict[str, Any]]:
    target = (
        Path(output_dir)
        if output_dir is not None
        else default_workflow_improvement_dir()
    )
    queue = _read_json(
        target / "improvement-queue.json",
        {"schema": IMPROVEMENT_QUEUE_SCHEMA, "packets": []},
        max_bytes=_HARD_MAX_MANAGED_JSON_BYTES,
    )
    if not isinstance(queue, dict) or queue.get("schema") != IMPROVEMENT_QUEUE_SCHEMA:
        raise WorkflowImprovementStateError(
            "improvement-queue.json has an unsupported contract"
        )
    packets = queue.get("packets")
    if not isinstance(packets, list):
        raise WorkflowImprovementStateError(
            "improvement-queue.json packets must be an array"
        )
    if len(packets) > _HARD_MAX_QUEUE_PACKETS or any(
        not isinstance(row, dict)
        or not isinstance(row.get("id"), str)
        or not row["id"]
        or len(row["id"]) > 180
        for row in packets
    ):
        raise WorkflowImprovementStateError(
            "improvement-queue.json exceeds or violates the packet contract"
        )
    rows = list(packets)
    status_filter = str(status or "").strip().lower()
    if status_filter:
        rows = [
            row for row in rows if str(row.get("status") or "").lower() == status_filter
        ]
    return rows


def load_workflow_improvement_status(
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    target = (
        Path(output_dir)
        if output_dir is not None
        else default_workflow_improvement_dir()
    )
    budget = WorkflowImprovementSupervisorBudget()
    state = _read_json(
        target / "state.json",
        {
            "schema": IMPROVEMENT_STATE_SCHEMA,
            "iterations": 0,
            "pending_packet_count": 0,
            "implementation_requires_human_approval": True,
            "automatic_mutation_enabled": False,
            "supervisor_budget": budget.to_dict(),
        },
        max_bytes=_HARD_MAX_MANAGED_JSON_BYTES,
    )
    if not isinstance(state, dict) or state.get("schema") != IMPROVEMENT_STATE_SCHEMA:
        raise WorkflowImprovementStateError(
            "state.json has an unsupported workflow-improvement state contract"
        )
    persisted_latest = _read_json(
        target / "latest.json",
        _MISSING,
        max_bytes=_HARD_MAX_MANAGED_JSON_BYTES,
    )
    if persisted_latest is _MISSING:
        latest: dict[str, Any] = {}
    elif not isinstance(persisted_latest, dict) or (
        persisted_latest.get("schema") != IMPROVEMENT_REPORT_SCHEMA
    ):
        raise WorkflowImprovementStateError(
            "latest.json has an unsupported workflow-improvement report contract"
        )
    else:
        latest = persisted_latest
    return {
        "schema": IMPROVEMENT_STATUS_SCHEMA,
        "output_dir": str(target.resolve()),
        "state": state,
        "latest": {
            "generated_at": latest.get("generated_at")
            if isinstance(latest, dict)
            else None,
            "metrics": latest.get("metrics") if isinstance(latest, dict) else None,
            "trend": latest.get("trend") if isinstance(latest, dict) else None,
        },
        "artifacts": {
            "latest": str(target / "latest.json"),
            "state": str(target / "state.json"),
            "history": str(target / "history.jsonl"),
            "history_compaction": str(target / "history-compaction.json"),
            "queue": str(target / "improvement-queue.json"),
            "next_work_packet": str(target / "next-work-packet.json"),
            "supervisor_stop": str(target / "supervisor-stop.json"),
        },
        "safety": {
            "proposal_only": True,
            "human_approval_required_before_implementation": True,
            "automatic_code_mutation": False,
            "automatic_publish_or_deploy": False,
            "finite_supervisor_budget": state.get(
                "supervisor_budget",
                budget.to_dict(),
            ),
            "last_stop_reason": (
                state.get("supervisor", {}).get("stop_reason")
                if isinstance(state.get("supervisor"), dict)
                else None
            ),
        },
    }
