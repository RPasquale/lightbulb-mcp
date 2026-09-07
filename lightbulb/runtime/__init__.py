"""Lazy supported contracts for defining and running executable primitives.

The SDK runtime validates and executes typed local mechanics. It does not own
hosted scope, approval, credentials, persistence, or connector-write authority.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lightbulb.primitive_runtime import (
        BusinessProcessPrimitive,
        ExecutablePrimitiveRuntime,
        FunctionBusinessProcessPrimitive,
        PrimitiveBlocker,
        PrimitiveCall,
        PrimitiveCorrelation,
        PrimitiveEvent,
        PrimitiveEvidence,
        PrimitiveEvidenceRef,
        PrimitiveExecutionContext,
        PrimitiveExecutionResult,
        PrimitiveExecutionStatus,
        PrimitiveOperationReceipt,
        PrimitiveOperationRecoveryPolicy,
        PrimitiveOperationReplayClass,
        PrimitiveOperationSpec,
        PrimitiveOperationStatus,
        PrimitiveRecoveryPlan,
        PrimitiveRegistry,
        PrimitiveRunMode,
        PrimitiveRunSession,
        ProjectPrimitiveRun,
        StandalonePrimitiveRun,
        business_process_primitive,
    )


_RUNTIME_MODULE = "lightbulb.primitive_runtime"
_EXPORTS: dict[str, tuple[str, str]] = {
    name: (_RUNTIME_MODULE, name)
    for name in (
        "BusinessProcessPrimitive",
        "FunctionBusinessProcessPrimitive",
        "business_process_primitive",
        "ExecutablePrimitiveRuntime",
        "PrimitiveRegistry",
        "PrimitiveRunSession",
        "PrimitiveRunMode",
        "StandalonePrimitiveRun",
        "ProjectPrimitiveRun",
        "PrimitiveCall",
        "PrimitiveCorrelation",
        "PrimitiveExecutionContext",
        "PrimitiveExecutionResult",
        "PrimitiveExecutionStatus",
        "PrimitiveEvent",
        "PrimitiveEvidence",
        "PrimitiveEvidenceRef",
        "PrimitiveBlocker",
        "PrimitiveOperationSpec",
        "PrimitiveOperationReceipt",
        "PrimitiveOperationStatus",
        "PrimitiveOperationReplayClass",
        "PrimitiveOperationRecoveryPolicy",
        "PrimitiveRecoveryPlan",
    )
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a declared primitive-runtime contract on first access."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
