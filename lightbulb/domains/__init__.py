"""Curated domain SDK namespaces.

Domain packages expose bounded product journeys, not the complete internal
capability inventory.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lightbulb.domains import finance


__all__ = ["finance"]


def __getattr__(name: str) -> ModuleType:
    if name != "finance":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = import_module("lightbulb.domains.finance")
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
