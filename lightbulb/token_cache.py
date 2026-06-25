"""Secure local token cache for the Lightbulb SDK.

Stores JWTs on disk at ~/.lightbulb/tokens/<url_hash>.json with 0o600 permissions.
Refuses to read files with group/other permissions (prevents permission escalation).
Uses atomic write (tmpfile + rename) and refuses to follow symlinks.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Optional

from lightbulb.auth import JwtAuth

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".lightbulb" / "tokens"
_MAX_TOKEN_AGE_SECONDS = 86400  # 24 hours (matches JWT expiry)


def _url_hash(base_url: str) -> str:
    return hashlib.sha256(base_url.encode()).hexdigest()[:16]


def _cache_path(base_url: str) -> Path:
    return CACHE_DIR / f"{_url_hash(base_url)}.json"


def _is_secure(path: Path) -> bool:
    """Check that the file is owned by us, not a symlink, and 0o600.

    Uses ``lstat`` so a symlink at ``path`` doesn't get followed to a
    target with permissive perms. On Windows POSIX permissions don't fully
    apply; the check still rejects symlinks but trusts the user-profile ACL
    for confidentiality.
    """
    try:
        st = path.lstat()
    except OSError:
        return False

    if stat.S_ISLNK(st.st_mode):
        logger.warning("Token cache %s is a symlink; refusing to read.", path)
        return False

    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        logger.warning(
            "Token cache %s is owned by uid %d, not the current user; refusing to read.",
            path, st.st_uid,
        )
        return False

    # POSIX permission bits are unreliable on Windows; ACLs apply instead.
    if os.name != "nt" and st.st_mode & (
        stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
    ):
        logger.warning(
            "Token cache %s has insecure permissions (%o). Ignoring.",
            path, stat.S_IMODE(st.st_mode),
        )
        return False
    return True


def load_cached_token(base_url: str) -> Optional[JwtAuth]:
    """Load a cached token from disk if it exists and is still valid."""
    path = _cache_path(base_url)
    if not path.exists():
        return None

    if not _is_secure(path):
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read token cache: %s", exc)
        return None

    expires_at = data.get("expires_at", 0)
    if time.time() >= expires_at:
        logger.info("Cached token expired, removing")
        try:
            path.unlink()
        except OSError:
            pass
        return None

    token = data.get("access_token", "")
    tenant_id = data.get("tenant_id", "")
    company_id = data.get("company_id")

    if not token or not tenant_id:
        return None

    try:
        return JwtAuth(token=token, tenant_id=tenant_id, company_id=company_id)
    except ValueError:
        return None


def save_cached_token(
    base_url: str,
    auth: JwtAuth,
    expires_in: int = _MAX_TOKEN_AGE_SECONDS,
) -> None:
    """Save a token to the disk cache atomically with secure permissions.

    Writes to a temporary file (chmod 0o600 BEFORE writing the JWT), fsyncs,
    then atomically renames into place. This prevents a torn-read window
    where another process could see a half-written cache file, and prevents
    a TOCTOU window where the token sits on disk with default umask perms
    before being chmodded.
    """
    # Audit-id: save_cached_token_jwtauth_assert_0_5_1.
    # Fail loudly on misuse — the cache layout is JWT-only (extracts the
    # bearer string out of auth.apply()). Passing ApiKeyAuth would silently
    # write an empty access_token; assert at the boundary.
    if not isinstance(auth, JwtAuth):
        raise TypeError(
            f"save_cached_token requires JwtAuth, got {type(auth).__name__}. "
            "API-key auth is not cacheable; reuse the env-loaded credentials."
        )
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Secure the directory
    try:
        os.chmod(CACHE_DIR, 0o700)
    except OSError:
        pass

    path = _cache_path(base_url)

    # Refuse to write to a symlink — could redirect token to attacker location.
    if path.is_symlink():
        logger.warning("Refusing to write token to symlink: %s", path)
        return

    data = {
        "access_token": auth.apply({}).get("Authorization", "").removeprefix("Bearer "),
        "tenant_id": auth.tenant_id,
        "company_id": auth.company_id,
        "expires_at": time.time() + expires_in,
        "base_url": base_url,
    }

    fd, tmp_path = tempfile.mkstemp(dir=str(CACHE_DIR), prefix=".tok-", suffix=".json")
    tmp = Path(tmp_path)
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data))
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    logger.info("Token cached at %s (expires in %ds)", path, expires_in)


def clear_cached_token(base_url: str) -> None:
    """Remove the cached token for a URL."""
    path = _cache_path(base_url)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
