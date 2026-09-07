"""Provider-free adapter over the Executable Primitive Runtime.

Agent harnesses use this adapter when they need a typed, deterministic preview
without credentials, network access, or external side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import BaseModel

from lightbulb.connector_execution import (
    ConnectorExecutionRequest,
    ExecutionScope,
    InMemoryConnectorExecutor,
)
from lightbulb.executable_primitives import default_primitive_registry
from lightbulb.primitive_runtime import (
    ExecutablePrimitiveRuntime,
    PrimitiveCall,
    PrimitiveCorrelation,
    PrimitiveExecutionResult,
    PrimitiveRegistry,
    StandalonePrimitiveRun,
)
from lightbulb.runtime_outcomes import RuntimeOutcomeRecorder


@dataclass(frozen=True)
class PrimitivePreview:
    result: PrimitiveExecutionResult[Any]
    connector_requests: tuple[ConnectorExecutionRequest, ...]


def preview_executable_primitive(
    *,
    primitive_ref: str,
    inputs: Mapping[str, Any] | BaseModel,
    scope: ExecutionScope,
    run_ref: str,
    source: str,
    registry: PrimitiveRegistry | None = None,
    outcome_recorder: RuntimeOutcomeRecorder | None = None,
) -> PrimitivePreview:
    """Execute one primitive through the shared preview-only run profile."""
    connectors = InMemoryConnectorExecutor()
    runtime = ExecutablePrimitiveRuntime(
        registry or default_primitive_registry(),
        connectors,
        outcome_recorder=outcome_recorder,
    )
    session = runtime.open(
        StandalonePrimitiveRun(
            scope=scope,
            run_ref=run_ref,
            correlation=PrimitiveCorrelation(source=source),
        )
    )
    result = session.execute(PrimitiveCall(primitive_ref=primitive_ref, inputs=inputs))
    return PrimitivePreview(
        result=result,
        connector_requests=tuple(connectors.requests),
    )


__all__ = ["PrimitivePreview", "preview_executable_primitive"]
