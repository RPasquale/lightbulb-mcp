"""Authentication strategies for the Lightbulb API.

Security design:
- API keys and JWTs are never logged, serialised to repr, or included in exceptions.
- Credentials are stored as private attributes and only emitted into outbound headers.
- All credential values are validated on construction (fail-fast).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from abc import ABC, abstractmethod
from typing import Dict, Optional

import httpx

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_MIN_API_KEY_LENGTH = 16
_MIN_JWT_LENGTH = 20


def is_local_url(base_url: str) -> bool:
    """True only when ``base_url``'s host is loopback (localhost / 127.0.0.1 / ::1).

    Parses the hostname so it can't be fooled by substring tricks like
    ``https://localhost.attacker.com`` or ``https://attacker.com/?ref=localhost``.
    Any port is allowed. Bracketed IPv6 loopback (``[::1]``) is accepted.

    This is used to hard-gate auth paths that must never reach a remote host.
    """
    from urllib.parse import urlparse

    host = urlparse(base_url or "").hostname
    return host in ("localhost", "127.0.0.1", "::1")


def _normalize_2fa_code(code: str) -> str:
    return re.sub(r"[\s-]+", "", str(code).strip())


def _validate_uuid(value: str, label: str) -> str:
    value = str(value).strip()
    if not _UUID_RE.match(value):
        raise ValueError(f"{label} must be a valid UUID, got length-{len(value)} value")
    return value


def _validate_nonempty_secret(value: str, label: str, min_length: int) -> str:
    if not isinstance(value, str) or len(value.strip()) < min_length:
        raise ValueError(
            f"{label} must be at least {min_length} characters "
            f"(got {len(value) if isinstance(value, str) else 0})"
        )
    return value.strip()


class AuthStrategy(ABC):
    """Base class for authentication strategies."""

    @abstractmethod
    def apply(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Inject credentials into an outbound header dict (returns a new dict)."""

    @property
    @abstractmethod
    def tenant_id(self) -> str:
        """The tenant UUID this auth context is scoped to."""

    @property
    def company_id(self) -> str | None:
        """Optional company UUID scope."""
        return None


class ApiKeyAuth(AuthStrategy):
    """Authenticate with a service API key + tenant context.

    This is the service-to-service auth path. The key is sent with a tenant
    (and optional company) scope header and is only intended for trusted,
    loopback/local integration use.
    """

    __slots__ = ("_api_key", "_tenant_id", "_company_id", "_user_id")

    def __init__(
        self,
        api_key: str,
        tenant_id: str,
        user_id: str,
        company_id: str | None = None,
    ) -> None:
        self._api_key = _validate_nonempty_secret(api_key, "api_key", _MIN_API_KEY_LENGTH)
        self._tenant_id = _validate_uuid(tenant_id, "tenant_id")
        self._user_id = _validate_uuid(user_id, "user_id")
        self._company_id = _validate_uuid(company_id, "company_id") if company_id else None

    def apply(self, headers: Dict[str, str]) -> Dict[str, str]:
        out = {**headers}
        out["X-Internal-API-Key"] = self._api_key
        out["X-Tenant-Id"] = self._tenant_id
        out["X-User-Id"] = self._user_id
        if self._company_id:
            out["X-Company-Id"] = self._company_id
        return out

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def company_id(self) -> str | None:
        return self._company_id

    def __repr__(self) -> str:
        return f"ApiKeyAuth(tenant_id={self._tenant_id!r}, user_id={self._user_id!r})"


class JwtAuth(AuthStrategy):
    """Authenticate with a JWT Bearer token.

    This is the user-facing auth path.  The JWT must contain tenantId and
    userId claims.
    """

    __slots__ = ("_token", "_tenant_id", "_company_id")

    def __init__(
        self,
        token: str,
        tenant_id: str,
        company_id: str | None = None,
    ) -> None:
        self._token = _validate_nonempty_secret(token, "jwt_token", _MIN_JWT_LENGTH)
        self._tenant_id = _validate_uuid(tenant_id, "tenant_id")
        self._company_id = _validate_uuid(company_id, "company_id") if company_id else None

    def apply(self, headers: Dict[str, str]) -> Dict[str, str]:
        out = {**headers}
        out["Authorization"] = f"Bearer {self._token}"
        out["X-Tenant-Id"] = self._tenant_id
        if self._company_id:
            out["X-Company-Id"] = self._company_id
        return out

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def company_id(self) -> str | None:
        return self._company_id

    def __repr__(self) -> str:
        return f"JwtAuth(tenant_id={self._tenant_id!r})"


class TwoFactorRequired(RuntimeError):
    """Raised by login() when the user has 2FA enabled and no code was provided.

    The caller should prompt for a 6-digit TOTP (or 8-digit backup) code and call
    ``complete_2fa_login(base_url, email, code)``.

    Attributes:
        base_url: The platform URL (so the caller can pass it back).
        email: The email address to use when completing the challenge.
        message: Server-supplied prompt (e.g. "Enter your authenticator code").
    """

    def __init__(self, base_url: str, email: str, message: str = ""):
        self.base_url = base_url
        self.email = email
        self.message = message or "Two-factor authentication code required"
        super().__init__(self.message)


def login(
    base_url: str,
    email: str,
    password: str,
    *,
    code: str | None = None,
    timeout: float = 15.0,
    interactive: bool = False,
) -> JwtAuth:
    """Authenticate with email/password and return a JwtAuth with the user's real permissions.

    The returned JwtAuth goes through the normal JWT auth path in Spring Boot,
    meaning all requests are scoped to the user's actual tenant, company, roles,
    and RBAC permissions — no privilege escalation.

    2FA handling:
        - If the account has 2FA enabled and ``code`` is provided, the SDK
          performs the two-step flow automatically.
        - If 2FA is enabled and no code is provided, the SDK raises
          :class:`TwoFactorRequired`. Catch it, prompt for the code, then call
          :func:`complete_2fa_login` (or call :func:`login` again with ``code``).
        - Pass ``interactive=True`` to read the code from stdin if the platform
          asks for it (suitable for CLIs).

    Args:
        base_url: Platform URL (e.g. "https://agents.lightbulbpartners.com")
        email: User's login email
        password: User's password
        code: Optional 6-digit TOTP or 8-digit backup code. Pass this if you
            already know the user has 2FA enabled.
        interactive: If True and stdin is a TTY, prompt for the 2FA code when
            the server reports requires2FA.

    Returns:
        JwtAuth configured with the user's JWT, tenant ID, and company ID.

    Raises:
        TwoFactorRequired: If the account has 2FA enabled and no code was
            provided (and interactive=False).
        RuntimeError: If login fails (invalid credentials, server error, etc.)
        ValueError: If the response is missing required fields.
    """
    url = f"{base_url.rstrip('/')}/api/auth/login"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json={"email": email, "password": password})
    except httpx.RequestError as exc:
        raise RuntimeError(f"Connection to {base_url} failed: {exc}") from exc

    if resp.status_code == 401:
        raise RuntimeError("Login failed: invalid email or password.")
    if resp.status_code == 429:
        raise RuntimeError("Login failed: rate limited. Try again later.")
    if resp.status_code >= 400:
        raise RuntimeError(f"Login failed with status {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        raise RuntimeError("Login response was not JSON.")

    # 2FA branch: server didn't issue a token, just confirmed the password and
    # signaled that an authenticator code is required.
    requires_2fa = bool(data.get("requires2FA") or data.get("requires_2fa"))
    if requires_2fa:
        if code:
            return complete_2fa_login(base_url, email, code, timeout=timeout)
        if interactive:
            import sys as _sys
            if _sys.stderr.isatty() and _sys.stdin.isatty():
                prompt_msg = data.get("message") or "Enter your 2FA code: "
                try:
                    entered = input(prompt_msg).strip()
                except EOFError:
                    entered = ""
                if entered:
                    return complete_2fa_login(base_url, email, entered, timeout=timeout)
        raise TwoFactorRequired(
            base_url=base_url.rstrip("/"),
            email=email,
            message=data.get("message") or "",
        )

    # Token may be in the JSON body OR in a Set-Cookie header (HttpOnly cookie auth)
    token = data.get("token") or data.get("accessToken") or ""
    if not token:
        # Extract from httpx cookies jar
        for cookie_name in ("PROJECT401_AUTH", "jwt", "auth_token"):
            val = resp.cookies.get(cookie_name, "")
            if val and val.startswith("eyJ"):
                token = val
                break
    if not token:
        # Fallback: parse Set-Cookie header directly
        for header_val in resp.headers.get_list("set-cookie"):
            for cookie_name in ("PROJECT401_AUTH=", "jwt=", "auth_token="):
                if cookie_name in header_val:
                    raw = header_val.split(cookie_name, 1)[1].split(";")[0].strip()
                    if raw.startswith("eyJ"):
                        token = raw
                        break
            if token:
                break
    if not token:
        raise ValueError("Login response missing JWT token (checked body and cookies).")

    user = data.get("user") or data
    tenant_id = str(user.get("tenantId") or "").strip()
    company_id = str(user.get("companyId") or "").strip() or None

    # If tenantId not in response body, decode from JWT claims
    if not tenant_id and token:
        try:
            import base64 as _b64
            payload_b64 = token.split(".")[1]
            # Add padding
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            claims = json.loads(_b64.urlsafe_b64decode(payload_b64))
            tenant_id = str(claims.get("tenantId") or "").strip()
            if not company_id:
                company_id = str(claims.get("companyId") or "").strip() or None
        except Exception:
            pass

    if not tenant_id:
        raise ValueError("Login response missing tenantId — cannot establish tenant scope.")

    return JwtAuth(token=token, tenant_id=tenant_id, company_id=company_id)


def complete_2fa_login(
    base_url: str,
    email: str,
    code: str,
    *,
    timeout: float = 15.0,
) -> JwtAuth:
    """Complete a two-factor login challenge.

    Call this after :func:`login` raises :class:`TwoFactorRequired`, passing the
    6-digit TOTP code from the user's authenticator app or an 8-digit backup code.

    Args:
        base_url: Platform URL.
        email: The same email used in the initial login call.
        code: 6-digit TOTP code or 8-digit backup code.
        timeout: HTTP timeout.

    Returns:
        JwtAuth scoped to the user's permissions.

    Raises:
        RuntimeError: If verification fails (bad code, expired, rate-limited).
    """
    code = _normalize_2fa_code(code)
    if not re.match(r"^\d{6}$|^\d{8}$", code):
        raise ValueError("2FA code must be 6 digits (TOTP) or 8 digits (backup code).")

    url = f"{base_url.rstrip('/')}/api/auth/login/2fa"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json={"email": email, "code": code})
    except httpx.RequestError as exc:
        raise RuntimeError(f"Connection to {base_url} failed during 2FA: {exc}") from exc

    if resp.status_code == 401:
        raise RuntimeError("2FA verification failed: invalid or expired code.")
    if resp.status_code == 429:
        raise RuntimeError("2FA verification rate-limited. Try again later.")
    if resp.status_code >= 400:
        raise RuntimeError(f"2FA verification failed with status {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        raise RuntimeError("2FA response was not JSON.")

    token = data.get("token") or data.get("accessToken") or ""
    if not token:
        # Token may live in a Set-Cookie header (HttpOnly cookie auth)
        for cookie_name in ("PROJECT401_AUTH", "jwt", "auth_token"):
            val = resp.cookies.get(cookie_name, "")
            if val and val.startswith("eyJ"):
                token = val
                break
    if not token:
        raise ValueError("2FA response missing JWT token.")

    user = data.get("user") or data
    tenant_id = str(user.get("tenantId") or "").strip()
    company_id = str(user.get("companyId") or "").strip() or None

    if not tenant_id and token:
        try:
            import base64 as _b64
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            claims = json.loads(_b64.urlsafe_b64decode(payload_b64))
            tenant_id = str(claims.get("tenantId") or "").strip()
            if not company_id:
                company_id = str(claims.get("companyId") or "").strip() or None
        except Exception:
            pass

    if not tenant_id:
        raise ValueError("2FA response missing tenantId — cannot establish tenant scope.")

    return JwtAuth(token=token, tenant_id=tenant_id, company_id=company_id)


def exchange_local_api_key_for_jwt(
    base_url: str,
    api_key: str,
    tenant_id: str,
    user_id: str,
    company_id: str | None = None,
    *,
    timeout: float = 15.0,
    purpose: str = "lightbulb_mcp_local",
) -> JwtAuth:
    """Exchange a localhost-only service credential for a short-lived JWT.

    This is a **local-development convenience**: a service credential is swapped
    for a normal bearer token so the SDK/MCP can call the same user-facing routes
    a browser session would, going through the platform's normal JWT + RBAC path.

    The service credential is privileged, so this helper refuses to send it
    anywhere but a loopback host. ``base_url`` MUST resolve to localhost /
    127.0.0.1 / ::1 — calling it against a remote or production host raises
    :class:`ValueError` before any network request is made.

    Returns a standard :class:`JwtAuth`.

    Raises:
        ValueError: If ``base_url`` is not a loopback host.
        RuntimeError: On connection failure or a non-2xx response.
    """
    if not is_local_url(base_url):
        raise ValueError(
            "exchange_local_api_key_for_jwt() is restricted to loopback hosts "
            "(localhost / 127.0.0.1 / ::1). It refuses to send the local service "
            f"credential to a non-local host. Got base_url={base_url!r}. For "
            "remote/production hosts use device login (device_login) or a JWT."
        )
    service_auth = ApiKeyAuth(
        api_key=api_key,
        tenant_id=tenant_id,
        user_id=user_id,
        company_id=company_id,
    )
    url = f"{base_url.rstrip('/')}/api/internal/demo-token/mint"
    payload: Dict[str, str] = {"purpose": str(purpose or "lightbulb_mcp_local")}
    if company_id:
        payload["company_id"] = company_id

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                url,
                json=payload,
                headers=service_auth.apply({"Accept": "application/json"}),
            )
    except httpx.RequestError as exc:
        raise RuntimeError(f"Connection to {base_url} failed during localhost JWT bootstrap: {exc}") from exc

    if resp.status_code == 401:
        raise RuntimeError("Localhost JWT bootstrap failed: invalid internal API key or scope headers.")
    if resp.status_code == 429:
        raise RuntimeError("Localhost JWT bootstrap failed: rate limited. Try again later.")
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Localhost JWT bootstrap failed with status {resp.status_code}"
        )

    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError("Localhost JWT bootstrap response was not JSON.") from exc

    token = str(data.get("token") or "").strip()
    if not token:
        raise ValueError("Localhost JWT bootstrap response missing token.")

    resolved_tenant_id = str(data.get("tenant_id") or tenant_id).strip()
    resolved_company_id = company_id
    if not resolved_company_id:
        resolved_company_id = str(data.get("company_id") or "").strip() or None

    return JwtAuth(
        token=token,
        tenant_id=resolved_tenant_id,
        company_id=resolved_company_id,
    )


def _validate_redirect_url(candidate: str, base_url: str) -> str:
    """Validate that ``candidate`` is safe to open in a browser.

    Rules:
    - Reject anything that isn't http(s).
    - Reject protocol-relative URLs (``//evil.com``) — they default to the
      current scheme and are commonly used to bypass same-origin checks.
    - For absolute URLs, the hostname must match ``base_url``'s hostname.
    - Relative URLs must start with a single slash and not escape via
      ``..`` or ``//``.

    This blocks ``javascript:``, ``data:``, ``file://``, UNC paths, and
    open-redirect bypasses — all of which were viable in the original code.
    """
    from urllib.parse import urljoin, urlparse

    candidate = (candidate or "").strip()
    if not candidate:
        raise RuntimeError("SSO response missing redirect URL.")

    base_parsed = urlparse(base_url.rstrip("/"))

    # Protocol-relative (//evil.com/...) — reject outright.
    if candidate.startswith("//"):
        raise RuntimeError("SSO redirect URL is protocol-relative — refusing.")

    # Detect scheme even when no // follows (e.g. ``javascript:alert(1)`` or
    # ``data:text/html,...``). RFC 3986 §3.1: scheme is `[A-Za-z][A-Za-z0-9+.-]*`
    # followed by ':'. urlparse won't notice without ``//``, so do it manually.
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", candidate)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ("http", "https"):
            raise RuntimeError(f"SSO redirect URL has disallowed scheme {scheme!r}")
        # http(s) — must include `://` and match platform host.
        if "://" not in candidate:
            raise RuntimeError("SSO redirect URL is malformed (missing '://')")
        ru = urlparse(candidate)
        if not ru.hostname:
            raise RuntimeError("SSO redirect URL has no hostname.")
        if base_parsed.hostname and ru.hostname != base_parsed.hostname:
            # When the platform returns a localhost-flavored URL but the
            # caller is hitting a non-localhost host, the platform's
            # base-URL config is almost certainly missing or wrong (it can
            # default to a localhost value when unset).
            # Surface that as a hint instead of a bare host-mismatch error
            # — otherwise the user has no idea why login is broken.
            # Audit-id: device_flow_localhost_hint_0_6_1.
            if ru.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
                raise RuntimeError(
                    f"SSO redirect URL points at {ru.hostname!r}, but the "
                    f"platform host is {base_parsed.hostname!r}. This is "
                    f"almost certainly a platform misconfiguration — the "
                    f"server's `app.base-url` is unset or pointing at "
                    f"localhost. Ask your Lightbulb admin to set "
                    f"APP_BASE_URL on the prod deployment."
                )
            raise RuntimeError(
                f"SSO redirect URL host {ru.hostname!r} does not match platform host {base_parsed.hostname!r}"
            )
        return candidate

    # Relative URL — must be a clean absolute path on the same origin.
    if not candidate.startswith("/"):
        raise RuntimeError("SSO redirect URL must be absolute or start with '/'")
    parts = candidate.split("/")
    if ".." in parts:
        raise RuntimeError("SSO redirect URL must not contain '..' segments")
    return urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))


def sso_redirect_url(base_url: str, provider: str = "google", *, timeout: float = 5.0) -> str:
    """Resolve the OAuth2 SSO start URL for the given provider.

    The platform exposes ``GET /api/auth/oauth2/{provider}`` which returns a
    JSON envelope ``{"url": "/oauth2/authorization/{provider}"}``. This helper
    fetches that envelope, validates it (must be on the same host as
    ``base_url``, must be http(s), no protocol-relative bypasses), and returns
    the absolute URL the caller should redirect to.

    Args:
        base_url: Platform base URL.
        provider: Either ``"google"`` or ``"microsoft"``.
        timeout: HTTP timeout.

    Returns:
        Fully-qualified SSO start URL on the platform's host.
    """
    provider = str(provider).strip().lower()
    if provider not in {"google", "microsoft"}:
        raise ValueError("provider must be 'google' or 'microsoft'")
    base = base_url.rstrip("/")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base}/api/auth/oauth2/{provider}")
    except httpx.RequestError as exc:
        raise RuntimeError(f"Failed to resolve SSO URL: {exc}") from exc
    if resp.status_code >= 400:
        raise RuntimeError(f"SSO lookup failed with status {resp.status_code}")
    try:
        body = resp.json()
    except Exception:
        raise RuntimeError("SSO lookup response was not JSON.")
    relative = (body.get("url") or "").strip() if isinstance(body, dict) else ""
    if not relative:
        raise RuntimeError("SSO response missing 'url' field.")
    return _validate_redirect_url(relative, base)


def device_login(
    base_url: str,
    client_id: str = "claude-code",
    *,
    poll_interval: float = 5.0,
    open_browser: bool = True,
    timeout: float = 15.0,
) -> tuple[JwtAuth, int]:
    """Authenticate via OAuth2 Device Authorization Grant (RFC 8628).

    1. POST /api/auth/device/authorize → device_code + user_code + verification_uri
    2. Print instructions, optionally open browser
    3. Poll POST /api/auth/device/token until approved/denied/expired
    4. Return (JwtAuth, expires_in)

    Args:
        base_url: Platform URL
        client_id: Client identifier (default "claude-code")
        poll_interval: Seconds between polls (default 5)
        open_browser: Whether to auto-open the verification URL
        timeout: HTTP request timeout

    Returns:
        Tuple of (JwtAuth scoped to user's permissions, expires_in seconds)

    Raises:
        RuntimeError: If auth is denied, expired, or fails.
    """
    import sys
    import time
    import webbrowser

    url = base_url.rstrip("/")

    # Step 1: Initiate device authorization
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{url}/api/auth/device/authorize",
            json={"client_id": client_id},
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Device authorization failed (HTTP {resp.status_code})")

    data = resp.json()
    device_code = data.get("device_code", "")
    user_code = data.get("user_code", "")
    verification_uri = data.get("verification_uri", "")
    verification_uri_complete = data.get("verification_uri_complete", "")
    expires_in = data.get("expires_in", 900)
    interval = data.get("interval", 5)
    poll_interval = max(poll_interval, interval)

    if not device_code or not user_code or not verification_uri:
        raise RuntimeError(f"Invalid device authorization response: {data}")

    # Step 2: Display instructions
    print(f"\n  To authorize, visit: {verification_uri}", file=sys.stderr)
    print(f"  Enter code: {user_code}\n", file=sys.stderr)

    if open_browser and verification_uri_complete:
        try:
            safe_url = _validate_redirect_url(verification_uri_complete, url)
            webbrowser.open(safe_url)
        except RuntimeError as exc:
            # Don't auto-open something we can't vouch for. The URL is still
            # printed above so the user can copy it manually if they trust it.
            logger.warning("Refusing to open verification URL: %s", exc)
        except Exception:
            pass  # Browser open is best-effort

    # Step 3: Poll until approved, denied, or expired
    deadline = time.time() + expires_in

    while time.time() < deadline:
        time.sleep(poll_interval)

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(
                    f"{url}/api/auth/device/token",
                    json={"device_code": device_code},
                )
        except httpx.RequestError as exc:
            logger.warning("Poll request failed: %s", exc)
            continue

        if resp.status_code == 200:
            token_data = resp.json()
            token = token_data.get("access_token", "")
            tenant_id = token_data.get("tenant_id", "")
            company_id = token_data.get("company_id")
            token_expires = token_data.get("expires_in", 86400)

            if not token or not tenant_id:
                raise RuntimeError("Token response missing access_token or tenant_id")

            print("  Authorized successfully.\n", file=sys.stderr)
            return JwtAuth(token=token, tenant_id=tenant_id, company_id=company_id), token_expires

        # Parse error response
        try:
            err = resp.json()
        except Exception:
            err = {"error": "unknown", "error_description": f"HTTP {resp.status_code}"}

        error_code = err.get("error", "")

        if error_code == "authorization_pending":
            continue
        elif error_code == "slow_down":
            poll_interval = min(poll_interval + 1, 30)
            continue
        elif error_code == "access_denied":
            raise RuntimeError("Authorization was denied by the user.")
        elif error_code == "expired_token":
            raise RuntimeError("Device code expired. Please try again.")
        else:
            raise RuntimeError(f"Device auth error: {error_code} — {err.get('error_description', '')}")

    raise RuntimeError("Device authorization timed out. Please try again.")
