"""Lightbulb Partners Agents SDK — lazy package-root compatibility facade."""

from __future__ import annotations

from importlib import import_module

from lightbulb._root_exports import ROOT_EXPORTS as _ROOT_EXPORTS


__all__ = list(_ROOT_EXPORTS)


def __getattr__(name: str) -> object:
    """Resolve one declared compatibility export on first access."""

    target = _ROOT_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
