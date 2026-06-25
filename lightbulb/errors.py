"""Friendly exception hierarchy for the Lightbulb SDK.

Callers can catch any platform-side failure with a single ``LightbulbError``
or narrow to a specific subclass (``AuthenticationError``,
``RateLimitedError``, etc.).

Usage::

    from lightbulb import LightbulbClient
    from lightbulb.errors import AuthenticationError, RateLimitedError

    try:
        client.dispatch("finance", action="chat", message="hello")
    except AuthenticationError:
        ...  # token expired
    except RateLimitedError as exc:
        ...  # back off

The factory :func:`from_response` wraps an :class:`httpx.HTTPStatusError` into
the appropriate subclass. :func:`raise_if_error` calls
:class:`~httpx.Response.raise_for_status` and converts failures the same way —
used by :class:`~lightbulb.client.LightbulbClient` on every platform response.

Auth-flow helpers (login, 2FA, device flow) raise :class:`RuntimeError` /
:class:`ValueError` with sanitized messages where applicable.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx


__all__ = [
    "LightbulbError",
    "AuthenticationError",
    "PermissionDenied",
    "NotFoundError",
    "ValidationError",
    "RateLimitedError",
    "ServerError",
    "from_response",
    "wrap_http_error",
    "raise_if_error",
]


class LightbulbError(Exception):
    """Base for all Lightbulb SDK exceptions raised against the platform.

    Attributes:
        status_code: HTTP status (or None for client-side validation errors).
        path: Request path that triggered the error (best-effort).
        request_id: Server-supplied trace ID, if any.
    """

    status_code: Optional[int] = None

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        path: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.path = path
        self.request_id = request_id


class AuthenticationError(LightbulbError):
    """401 — credentials missing or invalid (token expired, bad password, etc.)."""
    status_code = 401


class PermissionDenied(LightbulbError):
    """403 — caller is authenticated but lacks permission for the action."""
    status_code = 403


class NotFoundError(LightbulbError):
    """404 — resource does not exist or is outside the caller's scope."""
    status_code = 404


class ValidationError(LightbulbError, ValueError):
    """400 / 422 — request was malformed or rejected by server validation.

    Also raised by client-side validators (``_validate_domain`` etc.) when the
    SDK can detect a bad input before hitting the network.

    Multiply-inherits from :class:`ValueError` so existing ``except ValueError``
    clauses keep working — the rest of the SDK has historically raised
    ``ValueError`` for input rejection.
    """
    status_code = 400


class RateLimitedError(LightbulbError):
    """429 — too many requests. Back off and retry."""
    status_code = 429

    def __init__(
        self,
        message: str,
        *,
        retry_after: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(LightbulbError):
    """5xx — the platform itself is unhappy. Usually transient."""
    status_code = 500


_STATUS_TO_CLASS = {
    400: ValidationError,
    401: AuthenticationError,
    403: PermissionDenied,
    404: NotFoundError,
    422: ValidationError,
    429: RateLimitedError,
}


def _safe_message(response: httpx.Response, default: str) -> str:
    """Pull a short, sanitized message from a response without leaking secrets.

    We DO NOT include arbitrary response bodies — only the server's "message"
    or "error" field if it's a JSON object, capped at 200 chars. This prevents
    accidentally bubbling up echoed credentials in tracebacks.
    """
    try:
        data = response.json()
    except Exception:
        return default
    if isinstance(data, dict):
        for key in ("message", "error", "detail", "title"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value[:200]
    return default


def _retry_after(response: httpx.Response) -> Optional[float]:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def from_response(response: httpx.Response, *, default_message: str = "") -> LightbulbError:
    """Map an HTTP response to the matching LightbulbError subclass.

    The error message is drawn from the server's ``message`` / ``error`` /
    ``detail`` field when present, NEVER from the raw body.
    """
    status = response.status_code
    cls = _STATUS_TO_CLASS.get(status) or (ServerError if status >= 500 else LightbulbError)
    message = _safe_message(response, default_message or f"Request failed with HTTP {status}")
    request_id = response.headers.get("x-request-id") or response.headers.get("x-trace-id")
    path = str(response.request.url.path) if response.request is not None else None
    if cls is RateLimitedError:
        return RateLimitedError(message, status_code=status, path=path, request_id=request_id, retry_after=_retry_after(response))
    return cls(message, status_code=status, path=path, request_id=request_id)


def wrap_http_error(exc: httpx.HTTPStatusError) -> LightbulbError:
    """Convert an ``httpx.HTTPStatusError`` to a LightbulbError without leaking the body."""
    return from_response(exc.response, default_message=str(exc.__class__.__name__))


def raise_if_error(response: httpx.Response) -> None:
    """Raise a :class:`LightbulbError` subclass if ``response`` has an error status.

    Safe to use on any :class:`~httpx.Response`; does nothing on 2xx/3xx.
    """
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise wrap_http_error(exc) from None
