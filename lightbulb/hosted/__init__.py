"""Lazy beta client surface for the hosted Lightbulb control plane.

These clients call Spring-owned APIs. Their presence does not grant tenant
scope, connector credentials, approval, or live-effect authority.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lightbulb.async_client import AsyncLightbulbClient
    from lightbulb.client import DispatchResult, LightbulbClient, SSEEvent


_EXPORTS: dict[str, tuple[str, str]] = {
    "LightbulbClient": ("lightbulb.client", "LightbulbClient"),
    "AsyncLightbulbClient": ("lightbulb.async_client", "AsyncLightbulbClient"),
    "DispatchResult": ("lightbulb.client", "DispatchResult"),
    "SSEEvent": ("lightbulb.client", "SSEEvent"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a declared hosted-client contract on first access."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
