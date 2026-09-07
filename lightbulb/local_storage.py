"""Shared exact-scope helpers for customer-controlled local persistence."""

from __future__ import annotations

import hashlib
from pathlib import Path


def local_scope_fingerprint(tenant_id: str, company_id: str | None = None) -> str:
    """Return a non-reversible exact tenant/company local-storage binding."""

    # Scope identifiers are authority-bearing values. Preserve their exact
    # spelling instead of case-folding two potentially distinct principals
    # into the same local namespace.
    clean_tenant = str(tenant_id or "").strip()
    clean_company = str(company_id or "tenant-wide").strip()
    if not clean_tenant or any(ord(value) < 0x20 for value in clean_tenant):
        raise ValueError("tenant_id is required for scoped local storage")
    if not clean_company or any(ord(value) < 0x20 for value in clean_company):
        raise ValueError("company_id has an invalid format")
    return hashlib.sha256(
        f"{clean_tenant}\0{clean_company}".encode("utf-8")
    ).hexdigest()


def scoped_file_path(path: str | Path, scope_fingerprint: str) -> Path:
    """Place one logical local file in a rename-stable exact-scope filename."""

    base = Path(path).expanduser()
    fingerprint = str(scope_fingerprint or "").strip().lower()
    if len(fingerprint) != 64 or any(
        value not in "0123456789abcdef" for value in fingerprint
    ):
        raise ValueError("scope_fingerprint must be a lowercase SHA-256 value")
    suffix = "".join(base.suffixes)
    stem = base.name[: -len(suffix)] if suffix else base.name
    return base.with_name(f"{stem}.scope-{fingerprint[:32]}{suffix}")


__all__ = ["local_scope_fingerprint", "scoped_file_path"]
