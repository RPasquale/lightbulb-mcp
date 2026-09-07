"""Typed public contract for governed recursive Lightbulb agent runs."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Tuple


RECURSIVE_AGENT_POLICY_SCHEMA = "lightbulb-recursive-agent-policy.v1"
RECURSIVE_AGENT_RUN_SCHEMA = "lightbulb-recursive-agent-run.v1"
RECURSIVE_EXECUTION_ID_KEY = "recursive_execution_id"
RUNTIME_AGENT_ID_PREFIX = "runtime_agent."

_AGENT_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_RESERVED_RECURSIVE_INPUT_KEYS = frozenset(
    {
        "backbone_execution_runtime",
        "backboneExecutionRuntime",
        "recursive",
        "recursive_enabled",
        "enable_recursive_agents",
        "recursive_agent_policy",
        "recursiveAgentPolicy",
        "recursive_session_id",
        RECURSIVE_EXECUTION_ID_KEY,
        "recursive_node_id",
        "recursive_parent_id",
        "recursive_capability",
        "recursive_callback_url",
        "recursive_agent_catalog",
        "delegation_context",
        "delegation_context_receipt",
        "runtime_agent_execution_policy",
        "runtime_agent_expected_model",
        "_recursive_agent_mode",
    }
)


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer") from exc
    if not minimum <= normalized <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return normalized


def _bounded_float(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a number")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number") from exc
    if not minimum <= normalized <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return normalized


def _agent_ids(values: Iterable[Any] | None) -> Tuple[str, ...]:
    result = []
    for raw in values or ():
        agent_id = str(raw or "").strip()
        if not _AGENT_ID_RE.fullmatch(agent_id):
            raise ValueError(f"Invalid recursive agent id: {agent_id!r}")
        if agent_id.startswith(RUNTIME_AGENT_ID_PREFIX):
            try:
                expected = runtime_agent_id(
                    agent_id[len(RUNTIME_AGENT_ID_PREFIX) :]
                )
            except ValueError as exc:
                raise ValueError(
                    "Runtime-authored recursive agent ids must use "
                    "runtime_agent.<canonical-lowercase-uuid>"
                ) from exc
            if agent_id != expected:
                raise ValueError(
                    "Runtime-authored recursive agent ids must use "
                    "runtime_agent.<canonical-lowercase-uuid>"
                )
        if agent_id not in result:
            result.append(agent_id)
    if len(result) > 32:
        raise ValueError("allowed_agent_ids may contain at most 32 entries")
    return tuple(result)


def runtime_agent_id(runtime_action_id: Any) -> str:
    """Build the opaque recursive reference returned for an approved action."""
    try:
        parsed = (
            runtime_action_id
            if isinstance(runtime_action_id, uuid.UUID)
            else uuid.UUID(str(runtime_action_id or "").strip())
        )
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("runtime_action_id must be a UUID") from exc
    return RUNTIME_AGENT_ID_PREFIX + str(parsed)


@dataclass(frozen=True)
class RecursiveAgentPolicy:
    """Finite limits and an optional agent allowlist for one recursive run.

    Token and dollar ceilings are provider-dependent boundaries. The runtime
    receipt reports whether a provider could enforce or only meter them. Codex
    subscription runs may not expose dollar cost, so ``max_cost_usd`` remains a
    declared ceiling rather than a falsely claimed in-turn guard in that lane.
    """

    max_depth: int = 2
    max_total_nodes: int = 8
    max_children: int = 3
    max_tokens: int = 120_000
    max_cost_usd: float = 25.0
    max_runtime_seconds: int = 300
    max_repl_steps: int = 12
    max_delegation_context_bytes: int = 4_096
    max_total_delegation_context_bytes: int = 32_768
    root_budget_fraction: float = 0.5
    child_budget_fraction: float = 0.3
    allowed_agent_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "max_depth", _bounded_int(self.max_depth, "max_depth", 1, 4)
        )
        object.__setattr__(
            self,
            "max_total_nodes",
            _bounded_int(self.max_total_nodes, "max_total_nodes", 2, 32),
        )
        object.__setattr__(
            self, "max_children", _bounded_int(self.max_children, "max_children", 1, 8)
        )
        object.__setattr__(
            self,
            "max_tokens",
            _bounded_int(self.max_tokens, "max_tokens", 1_000, 2_000_000),
        )
        object.__setattr__(
            self,
            "max_cost_usd",
            _bounded_float(self.max_cost_usd, "max_cost_usd", 0.01, 1_000.0),
        )
        object.__setattr__(
            self,
            "max_runtime_seconds",
            _bounded_int(self.max_runtime_seconds, "max_runtime_seconds", 30, 1_800),
        )
        object.__setattr__(
            self,
            "max_repl_steps",
            _bounded_int(self.max_repl_steps, "max_repl_steps", 1, 64),
        )
        object.__setattr__(
            self,
            "max_delegation_context_bytes",
            _bounded_int(
                self.max_delegation_context_bytes,
                "max_delegation_context_bytes",
                2_048,
                8_192,
            ),
        )
        object.__setattr__(
            self,
            "max_total_delegation_context_bytes",
            _bounded_int(
                self.max_total_delegation_context_bytes,
                "max_total_delegation_context_bytes",
                2_048,
                131_072,
            ),
        )
        object.__setattr__(
            self,
            "root_budget_fraction",
            _bounded_float(
                self.root_budget_fraction, "root_budget_fraction", 0.1, 0.9
            ),
        )
        object.__setattr__(
            self,
            "child_budget_fraction",
            _bounded_float(
                self.child_budget_fraction, "child_budget_fraction", 0.05, 0.8
            ),
        )
        object.__setattr__(
            self, "allowed_agent_ids", _agent_ids(self.allowed_agent_ids)
        )
        if self.max_total_nodes < self.max_depth + 1:
            raise ValueError(
                "max_total_nodes must allow at least one node at every configured depth"
            )
        if self.max_total_delegation_context_bytes < self.max_delegation_context_bytes:
            raise ValueError(
                "max_total_delegation_context_bytes must be greater than or equal "
                "to max_delegation_context_bytes"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": RECURSIVE_AGENT_POLICY_SCHEMA,
            "max_depth": self.max_depth,
            "max_total_nodes": self.max_total_nodes,
            "max_children": self.max_children,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_repl_steps": self.max_repl_steps,
            "max_delegation_context_bytes": self.max_delegation_context_bytes,
            "max_total_delegation_context_bytes": (
                self.max_total_delegation_context_bytes
            ),
            "root_budget_fraction": self.root_budget_fraction,
            "child_budget_fraction": self.child_budget_fraction,
            "allowed_agent_ids": list(self.allowed_agent_ids),
        }

    @classmethod
    def from_value(
        cls, value: "RecursiveAgentPolicy | Dict[str, Any] | None"
    ) -> "RecursiveAgentPolicy":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise TypeError("policy must be RecursiveAgentPolicy, a dict, or None")
        unknown = set(value).difference(
            {
                "schema",
                "max_depth",
                "max_total_nodes",
                "max_children",
                "max_tokens",
                "max_cost_usd",
                "max_runtime_seconds",
                "max_repl_steps",
                "max_delegation_context_bytes",
                "max_total_delegation_context_bytes",
                "root_budget_fraction",
                "child_budget_fraction",
                "allowed_agent_ids",
            }
        )
        if unknown:
            raise ValueError(
                "Unknown recursive policy fields: " + ", ".join(sorted(unknown))
            )
        schema = value.get("schema")
        if schema is not None and schema != RECURSIVE_AGENT_POLICY_SCHEMA:
            raise ValueError("schema must be " + RECURSIVE_AGENT_POLICY_SCHEMA)
        kwargs = {key: item for key, item in value.items() if key != "schema"}
        return cls(**kwargs)


def build_recursive_agent_inputs(
    inputs: Dict[str, Any] | None,
    policy: RecursiveAgentPolicy | Dict[str, Any] | None,
    *,
    execution_id: str | uuid.UUID | None = None,
) -> Dict[str, Any]:
    if inputs is not None and not isinstance(inputs, dict):
        raise TypeError("inputs must be a dict or None")
    normalized = dict(inputs or {})
    reserved = sorted(_RESERVED_RECURSIVE_INPUT_KEYS.intersection(normalized))
    if reserved:
        raise ValueError(
            "Recursive execution inputs must not override runtime authority fields: "
            + ", ".join(reserved)
        )
    normalized["backbone_execution_runtime"] = "recursive_codex"
    try:
        normalized[RECURSIVE_EXECUTION_ID_KEY] = str(
            execution_id if isinstance(execution_id, uuid.UUID) else uuid.UUID(
                str(execution_id).strip()
            )
        ) if execution_id is not None else str(uuid.uuid4())
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("execution_id must be a UUID") from exc
    normalized["recursive_agent_policy"] = RecursiveAgentPolicy.from_value(
        policy
    ).to_dict()
    return normalized


__all__ = [
    "RECURSIVE_AGENT_POLICY_SCHEMA",
    "RECURSIVE_AGENT_RUN_SCHEMA",
    "RECURSIVE_EXECUTION_ID_KEY",
    "RUNTIME_AGENT_ID_PREFIX",
    "RecursiveAgentPolicy",
    "build_recursive_agent_inputs",
    "runtime_agent_id",
]
