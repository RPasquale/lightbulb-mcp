"""Protected local JWT cache for the Lightbulb SDK.

JWT bytes are protected by the current user's OS credential service (or by an
explicit governed headless keyring).  The on-disk JSON contains only public
scope/expiry metadata and a versioned protection envelope.  Legacy plaintext
records are migrated atomically after a protected round trip succeeds.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from lightbulb.auth import JwtAuth
from lightbulb.local_secret_store import (
    LocalSecretProtectionError,
    delete_protected_secret,
    is_protected_secret_envelope,
    protect_secret,
    unprotect_secret,
)

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".lightbulb" / "tokens"
_MAX_TOKEN_AGE_SECONDS = 86400
_CACHE_SCHEMA = "lightbulb.jwt-token-cache.v2"
_TOKEN_PURPOSE = "sdk-jwt-token"
_MAX_CACHE_BYTES = 128 * 1024


class TokenCacheSecurityError(RuntimeError):
    """Raised when cached credentials cannot be handled without weakening policy."""


def _url_hash(base_url: str) -> str:
    return hashlib.sha256(base_url.encode()).hexdigest()[:16]


def _cache_path(base_url: str) -> Path:
    return CACHE_DIR / f"{_url_hash(base_url)}.json"


def _is_secure(path: Path) -> bool:
    """Return whether ``path`` is a private, current-user regular file."""
    try:
        _require_secure_file(path)
    except FileNotFoundError:
        return False
    except TokenCacheSecurityError as exc:
        logger.warning("%s", exc)
        return False
    return True


def load_cached_token(base_url: str) -> Optional[JwtAuth]:
    """Load a cached token, migrating a secure legacy plaintext record once."""
    path = _cache_path(base_url)
    try:
        payload = _read_cache_json(path)
    except FileNotFoundError:
        return None

    if "access_token" in payload:
        payload = _migrate_legacy_cache(path, base_url, payload)
    if payload.get("schema") != _CACHE_SCHEMA:
        raise TokenCacheSecurityError(f"Token cache has an unsupported schema: {path}")
    metadata = _validated_metadata(payload, expected_base_url=base_url)
    protected = payload.get("credential")
    if not is_protected_secret_envelope(protected):
        raise TokenCacheSecurityError(
            f"Token cache is missing its protected credential envelope: {path}"
        )

    if time.time() >= metadata["expires_at"]:
        logger.info("Cached token expired, clearing protected credential")
        clear_cached_token(base_url)
        return None

    try:
        token = unprotect_secret(
            protected,
            purpose=_TOKEN_PURPOSE,
            context=_token_context(metadata),
        ).decode("utf-8")
    except (UnicodeDecodeError, LocalSecretProtectionError) as exc:
        raise TokenCacheSecurityError(
            "Cached JWT could not be recovered from the approved credential backend"
        ) from exc
    if not token:
        raise TokenCacheSecurityError("Cached JWT is empty")
    try:
        return JwtAuth(
            token=token,
            tenant_id=metadata["tenant_id"],
            company_id=metadata["company_id"],
        )
    except ValueError as exc:
        raise TokenCacheSecurityError("Cached JWT scope metadata is invalid") from exc


def save_cached_token(
    base_url: str,
    auth: JwtAuth,
    expires_in: int = _MAX_TOKEN_AGE_SECONDS,
) -> None:
    """Protect and atomically cache a JWT, cleaning any rotated OS reference."""
    if not isinstance(auth, JwtAuth):
        raise TypeError(
            f"save_cached_token requires JwtAuth, got {type(auth).__name__}. "
            "API-key auth is not cacheable; reuse the env-loaded credentials."
        )
    path = _cache_path(base_url)
    _prepare_cache_directory()
    _require_safe_destination(path)
    token = auth.apply({}).get("Authorization", "").removeprefix("Bearer ")
    if not token:
        raise TokenCacheSecurityError("JwtAuth did not provide a bearer token")
    metadata: dict[str, Any] = {
        "base_url": base_url,
        "tenant_id": auth.tenant_id,
        "company_id": auth.company_id,
        "expires_at": time.time() + _validated_expires_in(expires_in),
    }

    prior = _read_existing_protected_envelope(
        path,
        expected_base_url=base_url,
    )
    try:
        protected = protect_secret(
            token.encode("utf-8"),
            purpose=_TOKEN_PURPOSE,
            context=_token_context(metadata),
        )
    except LocalSecretProtectionError as exc:
        raise TokenCacheSecurityError(
            "JWT caching requires an approved OS credential backend or governed "
            "headless keyring; plaintext fallback is prohibited"
        ) from exc

    payload = {
        "schema": _CACHE_SCHEMA,
        "version": 2,
        **metadata,
        "credential": protected,
    }
    published = False
    try:
        _atomic_write_cache_json(path, payload)
        published = True
        written = _read_cache_json(path)
        written_metadata = _validated_metadata(
            written,
            expected_base_url=base_url,
        )
        recovered = unprotect_secret(
            written["credential"],
            purpose=_TOKEN_PURPOSE,
            context=_token_context(written_metadata),
        )
        if recovered != token.encode("utf-8"):
            raise TokenCacheSecurityError(
                "Protected JWT verification did not reproduce the original credential"
            )
    except Exception:
        if not published:
            _delete_envelope_best_effort(protected, metadata)
        raise

    if prior is not None:
        prior_envelope, prior_metadata = prior
        try:
            delete_protected_secret(
                prior_envelope,
                purpose=_TOKEN_PURPOSE,
                context=_token_context(prior_metadata),
            )
        except LocalSecretProtectionError as exc:
            raise TokenCacheSecurityError(
                "JWT rotated successfully, but the previous OS credential reference "
                "could not be deleted"
            ) from exc
    logger.info(
        "Protected token metadata cached at %s (expires in %ds)", path, expires_in
    )


def clear_cached_token(base_url: str) -> None:
    """Clear both the protected OS credential and its public JSON metadata."""
    path = _cache_path(base_url)
    try:
        payload = _read_cache_json(path)
    except FileNotFoundError:
        return
    if payload.get("schema") == _CACHE_SCHEMA:
        metadata = _validated_metadata(payload, expected_base_url=base_url)
        protected = payload.get("credential")
        if not is_protected_secret_envelope(protected):
            raise TokenCacheSecurityError(
                "Refusing to clear malformed protected token metadata"
            )
        try:
            delete_protected_secret(
                protected,
                purpose=_TOKEN_PURPOSE,
                context=_token_context(metadata),
            )
        except LocalSecretProtectionError as exc:
            raise TokenCacheSecurityError(
                "OS credential backend refused to clear the cached JWT"
            ) from exc
    elif "access_token" not in payload:
        raise TokenCacheSecurityError(
            "Refusing to clear token cache with an unsupported schema"
        )
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TokenCacheSecurityError(
            f"Unable to remove token cache metadata: {path}"
        ) from exc


def _migrate_legacy_cache(
    path: Path,
    base_url: str,
    legacy: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = _validated_metadata(legacy, expected_base_url=base_url)
    token = legacy.get("access_token")
    if not isinstance(token, str) or not token:
        raise TokenCacheSecurityError("Legacy token cache is missing its JWT")
    try:
        JwtAuth(
            token=token,
            tenant_id=metadata["tenant_id"],
            company_id=metadata["company_id"],
        )
    except ValueError as exc:
        raise TokenCacheSecurityError(
            "Legacy token cache contains invalid JWT scope or credential material"
        ) from exc
    try:
        protected = protect_secret(
            token.encode("utf-8"),
            purpose=_TOKEN_PURPOSE,
            context=_token_context(metadata),
        )
    except LocalSecretProtectionError as exc:
        raise TokenCacheSecurityError(
            "Legacy plaintext JWT cannot be migrated because no approved credential "
            "backend is available"
        ) from exc
    migrated = {
        "schema": _CACHE_SCHEMA,
        "version": 2,
        **metadata,
        "credential": protected,
    }
    published = False
    try:
        # Verify the protected material before replacing the only legacy copy.
        if (
            unprotect_secret(
                protected,
                purpose=_TOKEN_PURPOSE,
                context=_token_context(metadata),
            ).decode("utf-8")
            != token
        ):
            raise TokenCacheSecurityError(
                "Legacy JWT protection verification failed before migration"
            )
        _atomic_write_cache_json(path, migrated)
        published = True
        persisted = _read_cache_json(path)
        persisted_metadata = _validated_metadata(
            persisted,
            expected_base_url=base_url,
        )
        if (
            unprotect_secret(
                persisted["credential"],
                purpose=_TOKEN_PURPOSE,
                context=_token_context(persisted_metadata),
            ).decode("utf-8")
            != token
        ):
            raise TokenCacheSecurityError(
                "Legacy JWT migration failed post-write verification"
            )
    except Exception:
        if not published:
            _delete_envelope_best_effort(protected, metadata)
        raise
    logger.info(
        "Migrated legacy plaintext token cache to protected schema v2: %s", path
    )
    return migrated


def _validated_metadata(
    payload: Mapping[str, Any],
    *,
    expected_base_url: str,
) -> dict[str, Any]:
    base_url = payload.get("base_url")
    tenant_id = payload.get("tenant_id")
    company_id = payload.get("company_id")
    expires_at = payload.get("expires_at")
    if base_url != expected_base_url:
        raise TokenCacheSecurityError(
            "Token cache metadata does not match the requested Lightbulb URL"
        )
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise TokenCacheSecurityError("Token cache tenant metadata is invalid")
    if company_id is not None and not isinstance(company_id, str):
        raise TokenCacheSecurityError("Token cache company metadata is invalid")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(expires_at)
    ):
        raise TokenCacheSecurityError("Token cache expiry metadata is invalid")
    return {
        "base_url": base_url,
        "tenant_id": tenant_id.strip(),
        "company_id": company_id.strip() if isinstance(company_id, str) else None,
        "expires_at": float(expires_at),
    }


def _token_context(metadata: Mapping[str, Any]) -> str:
    return json.dumps(
        {
            "schema": _CACHE_SCHEMA,
            "base_url": metadata["base_url"],
            "tenant_id": metadata["tenant_id"],
            "company_id": metadata["company_id"],
            "expires_at": metadata["expires_at"],
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _validated_expires_in(value: int | float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise TokenCacheSecurityError("Token cache lifetime must be a finite number")
    if value > _MAX_TOKEN_AGE_SECONDS:
        raise TokenCacheSecurityError(
            f"Token cache lifetime may not exceed {_MAX_TOKEN_AGE_SECONDS} seconds"
        )
    return float(value)


def _read_existing_protected_envelope(
    path: Path,
    *,
    expected_base_url: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    try:
        payload = _read_cache_json(path)
    except FileNotFoundError:
        return None
    if payload.get("schema") != _CACHE_SCHEMA:
        # Saving a new credential is also the supported legacy migration path;
        # the atomic replacement removes plaintext without needing to recover it.
        if "access_token" in payload:
            return None
        raise TokenCacheSecurityError(
            f"Refusing to replace token cache with an unsupported schema: {path}"
        )
    protected = payload.get("credential")
    if not is_protected_secret_envelope(protected):
        raise TokenCacheSecurityError(
            "Existing token cache credential envelope is invalid"
        )
    metadata = _validated_metadata(
        payload,
        expected_base_url=expected_base_url,
    )
    return dict(protected), metadata


def _delete_envelope_best_effort(
    envelope: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> None:
    try:
        delete_protected_secret(
            envelope,
            purpose=_TOKEN_PURPOSE,
            context=_token_context(metadata),
        )
    except LocalSecretProtectionError:
        logger.error("Unable to clean an uncommitted OS credential reference")


def _read_cache_json(path: Path) -> dict[str, Any]:
    _require_no_symlink_ancestors(path.parent)
    metadata = _require_secure_file(path)
    if metadata.st_size > _MAX_CACHE_BYTES:
        raise TokenCacheSecurityError(
            f"Token cache exceeds {_MAX_CACHE_BYTES} bytes: {path}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise TokenCacheSecurityError(f"Unable to open token cache: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise TokenCacheSecurityError(f"Token cache changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_CACHE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_CACHE_BYTES:
        raise TokenCacheSecurityError(
            f"Token cache exceeds {_MAX_CACHE_BYTES} bytes: {path}"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise TokenCacheSecurityError(
            f"Token cache is not valid UTF-8 JSON: {path}"
        ) from exc
    if not isinstance(payload, dict):
        raise TokenCacheSecurityError(f"Token cache must contain a JSON object: {path}")
    return payload


def _atomic_write_cache_json(path: Path, payload: Mapping[str, Any]) -> None:
    _prepare_cache_directory()
    _require_safe_destination(path)
    encoded = (
        json.dumps(dict(payload), indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(CACHE_DIR),
        prefix=".tok-",
        suffix=".json",
    )
    temporary = Path(temporary_name)
    try:
        _chmod_required(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _require_safe_destination(path)
        os.replace(temporary, path)
        _chmod_required(path, 0o600)
        _fsync_directory_best_effort(CACHE_DIR)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field {key!r}")
        result[key] = value
    return result


def _prepare_cache_directory() -> None:
    _require_no_symlink_ancestors(CACHE_DIR)
    if CACHE_DIR.is_symlink():
        raise TokenCacheSecurityError(
            f"Refusing symlinked token cache directory: {CACHE_DIR}"
        )
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TokenCacheSecurityError(
            f"Unable to create token cache directory: {CACHE_DIR}"
        ) from exc
    try:
        metadata = CACHE_DIR.lstat()
    except OSError as exc:
        raise TokenCacheSecurityError(
            f"Unable to inspect token cache directory: {CACHE_DIR}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise TokenCacheSecurityError(
            f"Token cache directory is not a safe directory: {CACHE_DIR}"
        )
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise TokenCacheSecurityError(
            f"Token cache directory is not owned by the current user: {CACHE_DIR}"
        )
    _chmod_required(CACHE_DIR, 0o700)


def _require_no_symlink_ancestors(path: Path) -> None:
    ancestor = path.expanduser().absolute()
    while True:
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise TokenCacheSecurityError(
                f"Unable to inspect token cache directory ancestor: {ancestor}"
            ) from exc
        if metadata is not None and stat.S_ISLNK(metadata.st_mode):
            raise TokenCacheSecurityError(
                f"Refusing token cache beneath symlinked directory: {ancestor}"
            )
        if ancestor.parent == ancestor:
            return
        ancestor = ancestor.parent


def _require_safe_destination(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TokenCacheSecurityError(f"Unable to inspect token cache: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise TokenCacheSecurityError(f"Refusing symlinked token cache: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise TokenCacheSecurityError(f"Token cache is not a regular file: {path}")
    _require_secure_owner_and_mode(path, metadata)


def _require_secure_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise TokenCacheSecurityError(f"Unable to inspect token cache: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise TokenCacheSecurityError(
            f"Token cache is a symlink; refusing access: {path}"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise TokenCacheSecurityError(f"Token cache is not a regular file: {path}")
    _require_secure_owner_and_mode(path, metadata)
    return metadata


def _require_secure_owner_and_mode(path: Path, metadata: os.stat_result) -> None:
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise TokenCacheSecurityError(
            f"Token cache is not owned by the current user: {path}"
        )
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise TokenCacheSecurityError(
            f"Token cache has insecure permissions "
            f"({stat.S_IMODE(metadata.st_mode):o}): {path}"
        )


def _chmod_required(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as exc:
        if os.name != "nt":
            raise TokenCacheSecurityError(
                f"Unable to secure token cache path: {path}"
            ) from exc


def _fsync_directory_best_effort(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return
