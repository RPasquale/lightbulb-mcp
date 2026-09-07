"""Governed Project Training Quest request contracts.

Preparing a run publishes one immutable dataset and creates one durable Memory
run in ``queued`` state. Admission is a separate, cost-bearing operation. These
builders never claim a worker lease, execute training, update a learner, promote
a model/policy/skill, dispatch an action, or authorize a production write.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from uuid import UUID, uuid4


PROJECT_LEARNING_RUN_PREPARE_REQUEST_SCHEMA = (
    "lightbulb.project_learning_run_prepare_request.v1"
)
PROJECT_LEARNING_RUN_ADMISSION_REQUEST_SCHEMA = (
    "lightbulb.project_learning_run_admission_request.v1"
)
PROJECT_LEARNING_RUN_RECEIPT_SCHEMA = "lightbulb.project_learning_run_receipt.v1"
PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA = (
    "lightbulb.project_learning_run_admission_receipt.v1"
)
PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA = (
    "lightbulb.project_learning_run_execution_receipt.v1"
)
PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA = (
    "lightbulb.project_learning_run_execution_snapshot.v1"
)
PROJECT_LEARNING_RUN_LEDGER_SCHEMA = "lightbulb.project_learning_run_ledger.v1"
PROJECT_TRAINING_DATASET_SCHEMA = "lightbulb.project_training_dataset.v1"
PROJECT_LEARNING_QUEST_SCHEMA = "lightbulb.project_learning_quest.v1"

PROJECT_LEARNING_RUN_PREPARE_CONFIRMATION = (
    "publish_dataset_and_create_queued_learning_run"
)
PROJECT_LEARNING_RUN_ADMISSION_CONFIRMATION = (
    "reserve_budget_and_admit_durable_learning_run"
)

PROJECT_LEARNING_RUNTIMES = frozenset(
    {"automl", "spark_feature_matrix", "gepa_autoresearch", "pufferlib_v4", "prime_rl"}
)
PROJECT_BILLABLE_LEARNING_RUNTIMES = frozenset(
    {"gepa_autoresearch", "pufferlib_v4", "prime_rl"}
)
PROJECT_CAPACITY_RUNTIMES = {
    "automl": "automl",
    "spark_feature_matrix": "spark",
    "gepa_autoresearch": "prime",
    "pufferlib_v4": "puffer",
    "prime_rl": "prime",
}
_CAPACITY_KEYS = frozenset(
    {
        "schema",
        "decision_id",
        "runtime",
        "admission",
        "target_instances",
        "expires_at",
        "secrets_redacted",
    }
)


def _uuid_text(value: Any, label: str) -> str:
    try:
        return str(UUID(str(value).strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a UUID") from exc


def _bounded_text(value: Any, label: str, maximum: int = 256) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise ValueError(f"{label} must be non-empty printable text up to {maximum} characters")
    return normalized


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}") from exc
    if normalized < minimum or normalized > maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    return normalized


def _decimal6(value: Any, label: str, *, positive: bool = False) -> str:
    try:
        normalized = Decimal(str(value))
        scaled = normalized.quantize(Decimal("0.000001"))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a finite decimal with at most 6 places") from exc
    if not normalized.is_finite() or normalized != scaled or normalized < 0:
        raise ValueError(f"{label} must be a finite non-negative decimal with at most 6 places")
    if positive and normalized <= 0:
        raise ValueError(f"{label} must be greater than zero")
    return format(scaled, "f")


def _future_timestamp(value: Any, label: str) -> str:
    normalized = _bounded_text(value, label, 128)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise ValueError(f"{label} must be a future timezone-aware timestamp")
    return normalized


def build_project_learning_run_prepare_request(
    training_pack_receipt_id: Any,
    primary_metric: Any,
    *,
    runtime: str = "automl",
    request_id: Any = None,
    direction: str = "maximize",
    minimum_improvement: Any = "0.010000",
    max_cost_usd: Any = "0.000000",
    max_platform_cost_usd: Any = "5.000000",
    max_gpu_seconds: Any = 3600,
    max_tokens: Any = 100_000,
    max_steps: Any = 10_000,
    provider_account_fingerprint: Any = None,
    provider_binding_expires_at: Any = None,
    max_attempts: Any = 3,
    lease_seconds: Any = 300,
    preemptible: bool = True,
    confirm_prepare: bool = False,
) -> dict[str, Any]:
    """Build one exact, explicitly confirmed queued-run preparation request."""

    if confirm_prepare is not True:
        raise ValueError(
            "confirm_prepare=True is required because this publishes an immutable dataset "
            "and creates a durable queued learning run"
        )
    normalized_runtime = str(runtime or "").strip().lower()
    if normalized_runtime not in PROJECT_LEARNING_RUNTIMES:
        raise ValueError(f"runtime must be one of {sorted(PROJECT_LEARNING_RUNTIMES)}")
    normalized_direction = str(direction or "").strip().lower()
    if normalized_direction not in {"maximize", "minimize"}:
        raise ValueError("direction must be maximize or minimize")
    if not isinstance(preemptible, bool):
        raise ValueError("preemptible must be a boolean")

    billable = normalized_runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES
    provider_binding: dict[str, Any] | None = None
    if billable:
        fingerprint = str(provider_account_fingerprint or "").strip().lower()
        if not 16 <= len(fingerprint) <= 128 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError(
                "billable runtimes require a 16-128 character hexadecimal provider account fingerprint"
            )
        provider_binding = {
            "account_fingerprint": fingerprint,
            "expires_at": _future_timestamp(
                provider_binding_expires_at, "provider_binding_expires_at"
            ),
        }
    elif provider_account_fingerprint is not None or provider_binding_expires_at is not None:
        raise ValueError("platform runtimes must not include a provider account binding")

    payload: dict[str, Any] = {
        "schema": PROJECT_LEARNING_RUN_PREPARE_REQUEST_SCHEMA,
        "request_id": _uuid_text(request_id or uuid4(), "request_id"),
        "training_pack_receipt_id": _uuid_text(
            training_pack_receipt_id, "training_pack_receipt_id"
        ),
        "runtime": normalized_runtime,
        "objective": {
            "primary_metric": _bounded_text(primary_metric, "primary_metric"),
            "direction": normalized_direction,
            "minimum_improvement": _decimal6(
                minimum_improvement, "minimum_improvement"
            ),
        },
        "budget": {
            "max_cost_usd": _decimal6(
                max_cost_usd, "max_cost_usd", positive=billable
            ),
            "max_platform_cost_usd": _decimal6(
                max_platform_cost_usd,
                "max_platform_cost_usd",
                positive=not billable,
            ),
            "max_gpu_seconds": _bounded_int(
                max_gpu_seconds, "max_gpu_seconds", 0, 31_536_000
            ),
            "max_tokens": _bounded_int(max_tokens, "max_tokens", 0, 1_000_000_000_000),
            "max_steps": _bounded_int(max_steps, "max_steps", 0, 1_000_000_000_000),
        },
        "max_attempts": _bounded_int(max_attempts, "max_attempts", 1, 10),
        "lease_seconds": _bounded_int(lease_seconds, "lease_seconds", 60, 7200),
        "preemptible": preemptible,
        "confirmation": PROJECT_LEARNING_RUN_PREPARE_CONFIRMATION,
    }
    if provider_binding is not None:
        payload["provider_account_binding"] = provider_binding
    return payload


def build_project_learning_run_admission_request(
    runtime: Any,
    capacity_admission: Mapping[str, Any],
    *,
    operator_approved: bool = False,
    confirm_admission: bool = False,
) -> dict[str, Any]:
    """Build a separate cost/capacity admission request for an existing queued run."""

    if confirm_admission is not True:
        raise ValueError(
            "confirm_admission=True is required because this reserves budget and admits "
            "a durable learning run for worker claim"
        )
    normalized_runtime = str(runtime or "").strip().lower()
    if normalized_runtime not in PROJECT_LEARNING_RUNTIMES:
        raise ValueError(f"runtime must be one of {sorted(PROJECT_LEARNING_RUNTIMES)}")
    if not isinstance(operator_approved, bool):
        raise ValueError("operator_approved must be a boolean")
    if normalized_runtime in PROJECT_BILLABLE_LEARNING_RUNTIMES and not operator_approved:
        raise ValueError("billable learning runtimes require operator_approved=True")
    if not isinstance(capacity_admission, Mapping):
        raise ValueError("capacity_admission must be a mapping")
    normalized_capacity = dict(capacity_admission)
    unexpected = sorted(set(normalized_capacity) - _CAPACITY_KEYS)
    missing = sorted(_CAPACITY_KEYS - set(normalized_capacity))
    if unexpected or missing:
        raise ValueError(
            f"capacity_admission keys must match the capacity plan contract; "
            f"missing={missing}, unexpected={unexpected}"
        )
    if normalized_capacity.get("schema") != "lightbulb.learning-capacity-plan.v1":
        raise ValueError("capacity_admission schema is unsupported")
    if normalized_capacity.get("admission") != "admit":
        raise ValueError("capacity_admission must contain admission='admit'")
    if normalized_capacity.get("runtime") != PROJECT_CAPACITY_RUNTIMES[normalized_runtime]:
        raise ValueError("capacity_admission runtime does not match the learning runtime")
    if normalized_capacity.get("secrets_redacted") is not True:
        raise ValueError("capacity_admission must attest secrets_redacted=true")
    normalized_capacity["decision_id"] = _bounded_text(
        normalized_capacity.get("decision_id"), "capacity_admission.decision_id", 128
    )
    normalized_capacity["target_instances"] = _bounded_int(
        normalized_capacity.get("target_instances"),
        "capacity_admission.target_instances",
        1,
        10_000,
    )
    normalized_capacity["expires_at"] = _future_timestamp(
        normalized_capacity.get("expires_at"), "capacity_admission.expires_at"
    )
    return {
        "schema": PROJECT_LEARNING_RUN_ADMISSION_REQUEST_SCHEMA,
        "operator_approved": operator_approved,
        "capacity_admission": normalized_capacity,
        "confirmation": PROJECT_LEARNING_RUN_ADMISSION_CONFIRMATION,
    }


__all__ = [
    "PROJECT_BILLABLE_LEARNING_RUNTIMES",
    "PROJECT_CAPACITY_RUNTIMES",
    "PROJECT_LEARNING_QUEST_SCHEMA",
    "PROJECT_LEARNING_RUN_ADMISSION_CONFIRMATION",
    "PROJECT_LEARNING_RUN_ADMISSION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_ADMISSION_REQUEST_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUN_EXECUTION_SNAPSHOT_SCHEMA",
    "PROJECT_LEARNING_RUN_LEDGER_SCHEMA",
    "PROJECT_LEARNING_RUN_PREPARE_CONFIRMATION",
    "PROJECT_LEARNING_RUN_PREPARE_REQUEST_SCHEMA",
    "PROJECT_LEARNING_RUN_RECEIPT_SCHEMA",
    "PROJECT_LEARNING_RUNTIMES",
    "PROJECT_TRAINING_DATASET_SCHEMA",
    "build_project_learning_run_admission_request",
    "build_project_learning_run_prepare_request",
]
