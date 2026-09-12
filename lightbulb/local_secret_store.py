"""OS-backed protection for credentials persisted by local Lightbulb runtimes.

The JSON envelope returned by this module contains no credential plaintext.
Interactive desktops use the account-bound operating-system credential store:

* Windows: DPAPI with ``CRYPTPROTECT_UI_FORBIDDEN`` and current-user scope.
* macOS: the login Keychain through the vetted ``keyring`` backend.
* Linux: Secret Service through the vetted ``keyring`` backend.

Headless Linux devices must explicitly provide
``LIGHTBULB_LOCAL_SECRET_KEYRING_FILE``.  That file is a strictly-owned,
non-symlinked JSON keyring normally supplied by a host secret manager.  Its
active AES-256-GCM key protects new records while retained keys permit governed
rotation.  There is deliberately no plaintext or machine-derived fallback.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import importlib
import json
import os
import re
import stat
import sys
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping

_PROTECTION_SCHEMA = "lightbulb.local-protected-secret.v1"
_NATIVE_RECORD_SCHEMA = "lightbulb.local-native-secret-record.v1"
_HEADLESS_KEYRING_SCHEMA = "lightbulb.local-secret-keyring.v1"
_KEYRING_ENV = "LIGHTBULB_LOCAL_SECRET_KEYRING_FILE"
_BACKEND_ENV = "LIGHTBULB_LOCAL_SECRET_BACKEND"
_MAX_KEYRING_BYTES = 64 * 1024
_MAX_KEYS = 16
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PURPOSE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")


class LocalSecretProtectionError(RuntimeError):
    """Raised when a local secret cannot be protected without weakening policy."""


def protect_secret(
    secret: bytes,
    *,
    purpose: str,
    context: str,
) -> dict[str, Any]:
    """Protect ``secret`` and return a versioned, plaintext-free JSON envelope."""
    if not isinstance(secret, bytes) or not secret:
        raise LocalSecretProtectionError("Local secret must be non-empty bytes")
    normalized_purpose = _validate_purpose(purpose)
    context_digest = _context_digest(context)
    backend = _selected_backend()
    if backend == "windows-dpapi-current-user":
        protected = _dpapi_protect(
            secret,
            entropy=_associated_material(normalized_purpose, context_digest),
        )
        return {
            "schema": _PROTECTION_SCHEMA,
            "backend": backend,
            "context_sha256": context_digest,
            "ciphertext": base64.b64encode(protected).decode("ascii"),
        }
    if backend in {"macos-keychain", "linux-secret-service"}:
        reference = uuid.uuid4().hex
        service = _native_service(normalized_purpose, context_digest)
        record = _native_record(secret, normalized_purpose, context_digest)
        native = _required_native_keyring(backend)
        try:
            native.set_password(service, reference, record)
        except Exception as exc:
            raise LocalSecretProtectionError(
                f"{backend} refused to store the local credential"
            ) from exc
        return {
            "schema": _PROTECTION_SCHEMA,
            "backend": backend,
            "context_sha256": context_digest,
            "reference": reference,
        }
    if backend == "headless-aes256-gcm":
        active_key_id, keys = _load_headless_keyring()
        nonce = os.urandom(12)
        aad = _associated_material(
            normalized_purpose,
            context_digest,
            key_id=active_key_id,
        )
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            ciphertext = AESGCM(keys[active_key_id]).encrypt(nonce, secret, aad)
        except Exception as exc:
            raise LocalSecretProtectionError(
                "Unable to protect the local credential with the governed headless key"
            ) from exc
        return {
            "schema": _PROTECTION_SCHEMA,
            "backend": backend,
            "context_sha256": context_digest,
            "key_id": active_key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
    raise LocalSecretProtectionError(f"Unsupported local secret backend: {backend}")


def unprotect_secret(
    envelope: Mapping[str, Any],
    *,
    purpose: str,
    context: str,
) -> bytes:
    """Recover a secret after validating its schema and associated context."""
    normalized_purpose = _validate_purpose(purpose)
    context_digest = _context_digest(context)
    backend = _validate_envelope(envelope, context_digest)
    if backend == "windows-dpapi-current-user":
        ciphertext = _required_b64(envelope, "ciphertext")
        return _dpapi_unprotect(
            ciphertext,
            entropy=_associated_material(normalized_purpose, context_digest),
        )
    if backend in {"macos-keychain", "linux-secret-service"}:
        reference = _required_reference(envelope)
        service = _native_service(normalized_purpose, context_digest)
        native = _required_native_keyring(backend)
        try:
            record = native.get_password(service, reference)
        except Exception as exc:
            raise LocalSecretProtectionError(
                f"{backend} refused to read the local credential"
            ) from exc
        if not record:
            raise LocalSecretProtectionError(
                f"The {backend} credential reference is missing or inaccessible"
            )
        return _decode_native_record(
            record,
            purpose=normalized_purpose,
            context_digest=context_digest,
        )
    if backend == "headless-aes256-gcm":
        key_id = _required_key_id(envelope)
        _, keys = _load_headless_keyring()
        key = keys.get(key_id)
        if key is None:
            raise LocalSecretProtectionError(
                f"Governed headless keyring does not contain key id {key_id!r}"
            )
        nonce = _required_b64(envelope, "nonce", expected_length=12)
        ciphertext = _required_b64(envelope, "ciphertext")
        aad = _associated_material(
            normalized_purpose,
            context_digest,
            key_id=key_id,
        )
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise LocalSecretProtectionError(
                "Protected local credential failed authentication"
            ) from exc
    raise LocalSecretProtectionError(f"Unsupported local secret backend: {backend}")


def delete_protected_secret(
    envelope: Mapping[str, Any],
    *,
    purpose: str,
    context: str,
) -> None:
    """Delete an external OS credential reference, if the envelope uses one."""
    normalized_purpose = _validate_purpose(purpose)
    context_digest = _context_digest(context)
    backend = _validate_envelope(envelope, context_digest)
    if backend not in {"macos-keychain", "linux-secret-service"}:
        return
    reference = _required_reference(envelope)
    native = _required_native_keyring(backend)
    try:
        native.delete_password(
            _native_service(normalized_purpose, context_digest),
            reference,
        )
    except Exception as exc:
        # A missing reference is already the desired cleared state.  Some
        # backends expose a backend-specific delete error, so verify by read.
        try:
            remaining = native.get_password(
                _native_service(normalized_purpose, context_digest),
                reference,
            )
        except Exception as verification_exc:
            raise LocalSecretProtectionError(
                f"{backend} deletion failed and the result could not be verified"
            ) from verification_exc
        if remaining:
            raise LocalSecretProtectionError(
                f"{backend} refused to delete the rotated local credential"
            ) from exc


def is_protected_secret_envelope(value: object) -> bool:
    return isinstance(value, dict) and value.get("schema") == _PROTECTION_SCHEMA


def _selected_backend() -> str:
    configured = os.getenv(_BACKEND_ENV, "auto").strip().lower()
    if configured not in {"auto", "native", "headless"}:
        raise LocalSecretProtectionError(
            f"{_BACKEND_ENV} must be one of auto, native, or headless"
        )
    if configured == "headless":
        if not sys.platform.startswith("linux"):
            raise LocalSecretProtectionError(
                "The governed headless backend is supported only on Linux; "
                "Windows must use DPAPI and macOS must use Keychain"
            )
        _require_headless_keyring_path()
        return "headless-aes256-gcm"
    if sys.platform == "win32":
        return "windows-dpapi-current-user"
    if sys.platform == "darwin":
        _required_native_keyring("macos-keychain")
        return "macos-keychain"
    if sys.platform.startswith("linux"):
        try:
            _required_native_keyring("linux-secret-service")
            return "linux-secret-service"
        except LocalSecretProtectionError:
            if configured == "native":
                raise
            if os.getenv(_KEYRING_ENV, "").strip():
                _require_headless_keyring_path()
                return "headless-aes256-gcm"
            raise LocalSecretProtectionError(
                "No Linux Secret Service is available. Headless sovereign devices "
                f"must mount a governed keyring and set {_KEYRING_ENV}; plaintext "
                "credential storage is prohibited."
            ) from None
    raise LocalSecretProtectionError(
        "This platform has no approved local secret backend; plaintext credential "
        "storage is prohibited"
    )


def _required_native_keyring(expected: str) -> Any:
    backend_classes = {
        "macos-keychain": ("keyring.backends.macOS", "Keyring"),
        "linux-secret-service": ("keyring.backends.SecretService", "Keyring"),
    }
    try:
        module_name, class_name = backend_classes[expected]
        backend_class = getattr(importlib.import_module(module_name), class_name)
        backend = backend_class()
    except Exception as exc:
        raise LocalSecretProtectionError(
            f"The approved {expected} credential backend is unavailable"
        ) from exc
    identity = f"{backend.__class__.__module__}.{backend.__class__.__name__}"
    expected_identity = f"{module_name}.{class_name}"
    if identity != expected_identity:
        raise LocalSecretProtectionError(
            f"Refusing unapproved credential backend {identity!r}; expected {expected}"
        )
    try:
        priority = float(backend.priority)
    except Exception as exc:
        raise LocalSecretProtectionError(
            f"The approved {expected} credential backend is unavailable"
        ) from exc
    if priority <= 0:
        raise LocalSecretProtectionError(
            f"The approved {expected} credential backend is unavailable"
        )
    return backend


def _load_headless_keyring() -> tuple[str, dict[str, bytes]]:
    path = _require_headless_keyring_path()
    _require_no_symlink_ancestors(path.parent)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LocalSecretProtectionError(
            f"Unable to inspect governed headless keyring {path}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LocalSecretProtectionError(
            "Governed headless keyring must be a non-symlinked regular file"
        )
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise LocalSecretProtectionError(
            "Governed headless keyring is not owned by the current user"
        )
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise LocalSecretProtectionError(
            "Governed headless keyring has group or other permissions"
        )
    if metadata.st_size <= 0 or metadata.st_size > _MAX_KEYRING_BYTES:
        raise LocalSecretProtectionError(
            "Governed headless keyring has an invalid size"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LocalSecretProtectionError(
            "Unable to open governed headless keyring"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise LocalSecretProtectionError(
                "Governed headless keyring changed while opening"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_KEYRING_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LocalSecretProtectionError(
            "Governed headless keyring is not valid UTF-8 JSON"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "active_key_id", "keys"}
        or payload.get("schema") != _HEADLESS_KEYRING_SCHEMA
    ):
        raise LocalSecretProtectionError("Governed headless keyring schema is invalid")
    active_key_id = payload.get("active_key_id")
    raw_keys = payload.get("keys")
    if (
        not isinstance(active_key_id, str)
        or not _KEY_ID_RE.fullmatch(active_key_id)
        or not isinstance(raw_keys, dict)
        or not 1 <= len(raw_keys) <= _MAX_KEYS
    ):
        raise LocalSecretProtectionError(
            "Governed headless keyring metadata is invalid"
        )
    keys: dict[str, bytes] = {}
    for key_id, encoded in raw_keys.items():
        if (
            not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
            or not isinstance(encoded, str)
        ):
            raise LocalSecretProtectionError(
                "Governed headless keyring contains an invalid key entry"
            )
        try:
            key = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise LocalSecretProtectionError(
                "Governed headless keyring contains invalid key encoding"
            ) from exc
        if len(key) != 32:
            raise LocalSecretProtectionError(
                "Governed headless keys must be exactly 32 bytes"
            )
        keys[key_id] = key
    if active_key_id not in keys:
        raise LocalSecretProtectionError(
            "Governed headless keyring active key is missing"
        )
    return active_key_id, keys


def _require_headless_keyring_path() -> Path:
    configured = os.getenv(_KEYRING_ENV, "").strip()
    if not configured:
        raise LocalSecretProtectionError(
            f"Headless local secret protection requires {_KEYRING_ENV}"
        )
    path = Path(configured).expanduser()
    if not path.is_absolute():
        raise LocalSecretProtectionError(f"{_KEYRING_ENV} must be an absolute path")
    return path


def _validate_envelope(
    envelope: Mapping[str, Any],
    expected_context_digest: str,
) -> str:
    if (
        not isinstance(envelope, Mapping)
        or envelope.get("schema") != _PROTECTION_SCHEMA
    ):
        raise LocalSecretProtectionError("Protected local credential schema is invalid")
    if envelope.get("context_sha256") != expected_context_digest:
        raise LocalSecretProtectionError(
            "Protected local credential does not match its associated context"
        )
    backend = envelope.get("backend")
    allowed = {
        "windows-dpapi-current-user",
        "macos-keychain",
        "linux-secret-service",
        "headless-aes256-gcm",
    }
    if not isinstance(backend, str) or backend not in allowed:
        raise LocalSecretProtectionError(
            "Protected local credential backend is invalid"
        )
    fields_by_backend = {
        "windows-dpapi-current-user": {
            "schema",
            "backend",
            "context_sha256",
            "ciphertext",
        },
        "macos-keychain": {
            "schema",
            "backend",
            "context_sha256",
            "reference",
        },
        "linux-secret-service": {
            "schema",
            "backend",
            "context_sha256",
            "reference",
        },
        "headless-aes256-gcm": {
            "schema",
            "backend",
            "context_sha256",
            "key_id",
            "nonce",
            "ciphertext",
        },
    }
    if set(envelope) != fields_by_backend[backend]:
        raise LocalSecretProtectionError(
            "Protected local credential envelope fields are invalid"
        )
    return backend


def _native_record(secret: bytes, purpose: str, context_digest: str) -> str:
    return json.dumps(
        {
            "schema": _NATIVE_RECORD_SCHEMA,
            "purpose": purpose,
            "context_sha256": context_digest,
            "secret_b64": base64.b64encode(secret).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_native_record(
    raw: str,
    *,
    purpose: str,
    context_digest: str,
) -> bytes:
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_object_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise LocalSecretProtectionError(
            "OS credential record is not valid JSON"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "purpose", "context_sha256", "secret_b64"}
        or payload.get("schema") != _NATIVE_RECORD_SCHEMA
        or payload.get("purpose") != purpose
        or payload.get("context_sha256") != context_digest
    ):
        raise LocalSecretProtectionError(
            "OS credential record failed associated-context validation"
        )
    return _required_b64(payload, "secret_b64")


def _native_service(purpose: str, context_digest: str) -> str:
    return f"com.lightbulb.local-secrets.{purpose}.{context_digest[:24]}"


def _context_digest(context: str) -> str:
    if not isinstance(context, str) or not context.strip():
        raise LocalSecretProtectionError(
            "Local secret associated context must be non-empty"
        )
    return hashlib.sha256(context.encode("utf-8")).hexdigest()


def _require_no_symlink_ancestors(path: Path) -> None:
    ancestor = path.expanduser().absolute()
    while True:
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise LocalSecretProtectionError(
                f"Unable to inspect governed keyring directory ancestor: {ancestor}"
            ) from exc
        if metadata is not None and (
            stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_reparse_tag", None)
            == getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
        ):
            raise LocalSecretProtectionError(
                f"Governed headless keyring is beneath a symlinked directory or junction: {ancestor}"
            )
        if ancestor.parent == ancestor:
            return
        ancestor = ancestor.parent


def _associated_material(
    purpose: str,
    context_digest: str,
    *,
    key_id: str | None = None,
) -> bytes:
    payload = {
        "schema": _PROTECTION_SCHEMA,
        "purpose": purpose,
        "context_sha256": context_digest,
    }
    if key_id is not None:
        payload["key_id"] = key_id
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _validate_purpose(purpose: str) -> str:
    normalized = str(purpose or "").strip().lower()
    if not _PURPOSE_RE.fullmatch(normalized):
        raise LocalSecretProtectionError("Local secret purpose is invalid")
    return normalized


def _required_reference(envelope: Mapping[str, Any]) -> str:
    reference = envelope.get("reference")
    if (
        not isinstance(reference, str)
        or len(reference) != 32
        or not all(char in "0123456789abcdef" for char in reference)
    ):
        raise LocalSecretProtectionError(
            "Protected local credential reference is invalid"
        )
    return reference


def _required_key_id(envelope: Mapping[str, Any]) -> str:
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise LocalSecretProtectionError("Protected local credential key id is invalid")
    return key_id


def _required_b64(
    payload: Mapping[str, Any],
    field: str,
    *,
    expected_length: int | None = None,
) -> bytes:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise LocalSecretProtectionError(
            f"Protected local credential {field} is missing"
        )
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise LocalSecretProtectionError(
            f"Protected local credential {field} is invalid"
        ) from exc
    if not decoded or (expected_length is not None and len(decoded) != expected_length):
        raise LocalSecretProtectionError(
            f"Protected local credential {field} has an invalid length"
        )
    return decoded


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field {key!r}")
        result[key] = value
    return result


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob(raw: bytes) -> tuple[_DataBlob, Any]:
    buffer = ctypes.create_string_buffer(raw)
    return (
        _DataBlob(
            len(raw),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        ),
        buffer,
    )


def _dpapi_protect(secret: bytes, *, entropy: bytes) -> bytes:
    if sys.platform != "win32":
        raise LocalSecretProtectionError(
            "Windows DPAPI credential cannot be used on this platform"
        )
    secret_blob, secret_buffer = _blob(secret)
    entropy_blob, entropy_buffer = _blob(entropy)
    output_blob = _DataBlob()
    protect, _, local_free = _windows_dpapi_functions()
    try:
        success = protect(
            ctypes.byref(secret_blob),
            "Lightbulb local credential",
            ctypes.byref(entropy_blob),
            None,
            None,
            0x1,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    except OSError as exc:
        raise LocalSecretProtectionError(
            "Windows DPAPI refused to protect the local credential"
        ) from exc
    finally:
        ctypes.memset(secret_buffer, 0, len(secret) + 1)
        del secret_buffer, entropy_buffer
        if output_blob.pbData:
            local_free(output_blob.pbData)


def _dpapi_unprotect(ciphertext: bytes, *, entropy: bytes) -> bytes:
    if sys.platform != "win32":
        raise LocalSecretProtectionError(
            "Windows DPAPI credential cannot be used on this platform"
        )
    ciphertext_blob, ciphertext_buffer = _blob(ciphertext)
    entropy_blob, entropy_buffer = _blob(entropy)
    output_blob = _DataBlob()
    _, unprotect, local_free = _windows_dpapi_functions()
    try:
        success = unprotect(
            ctypes.byref(ciphertext_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            0x1,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    except OSError as exc:
        raise LocalSecretProtectionError(
            "Windows DPAPI refused to decrypt the local credential"
        ) from exc
    finally:
        del ciphertext_buffer, entropy_buffer
        if output_blob.pbData:
            ctypes.memset(output_blob.pbData, 0, output_blob.cbData)
            local_free(output_blob.pbData)


def _windows_dpapi_functions() -> tuple[Any, Any, Any]:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    protect = crypt32.CryptProtectData
    protect.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    protect.restype = wintypes.BOOL
    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    unprotect.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    return protect, unprotect, local_free
