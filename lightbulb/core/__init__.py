"""Small supported SDK foundation: authentication and public errors.

Importing this namespace does not load the owning implementation modules. Each
declared name resolves on first access and retains identity with its canonical
module.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lightbulb.auth import (
        ApiKeyAuth,
        AuthStrategy,
        JwtAuth,
        TwoFactorRequired,
        complete_2fa_login,
        device_login,
        login,
        sso_redirect_url,
    )
    from lightbulb.errors import (
        AuthenticationError,
        LightbulbError,
        NotFoundError,
        PermissionDenied,
        RateLimitedError,
        ServerError,
        ValidationError,
    )


_EXPORTS: dict[str, tuple[str, str]] = {
    "AuthStrategy": ("lightbulb.auth", "AuthStrategy"),
    "ApiKeyAuth": ("lightbulb.auth", "ApiKeyAuth"),
    "JwtAuth": ("lightbulb.auth", "JwtAuth"),
    "TwoFactorRequired": ("lightbulb.auth", "TwoFactorRequired"),
    "login": ("lightbulb.auth", "login"),
    "complete_2fa_login": ("lightbulb.auth", "complete_2fa_login"),
    "device_login": ("lightbulb.auth", "device_login"),
    "sso_redirect_url": ("lightbulb.auth", "sso_redirect_url"),
    "LightbulbError": ("lightbulb.errors", "LightbulbError"),
    "AuthenticationError": ("lightbulb.errors", "AuthenticationError"),
    "PermissionDenied": ("lightbulb.errors", "PermissionDenied"),
    "NotFoundError": ("lightbulb.errors", "NotFoundError"),
    "ValidationError": ("lightbulb.errors", "ValidationError"),
    "RateLimitedError": ("lightbulb.errors", "RateLimitedError"),
    "ServerError": ("lightbulb.errors", "ServerError"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Resolve a declared public contract on first access."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
