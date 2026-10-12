"""Checking the company exchange's signed receipts: what the platform took, and what the recipient did with it.

The platform signs two things with its Ed25519 key, each over the SDK's canonical JSON
(``stable_digest``'s bytes):

* each **delivery receipt**: which sealed document went from which exchange address to
  which, and when the platform took it;
* each **settlement**: whether the recipient took the document in or refused it, with its
  code.

Its public keys are published at ``/api/public/company-exchange/keys``. Anyone holding a
receipt and those keys can check it without the platform: the counterparty, an auditor, a
court.

``verify_delivery_receipt`` and ``verify_settlement`` recompute the digest from the fields,
then check the signature with the key the signature names.

* A receipt from a platform with no receipt key is unsigned: checking it gives
  ``signed: False``, never ``verified: True``.
* A digest or signature that does not check out raises ``ExchangeError``:
  ``RECEIPT_DIGEST_MISMATCH``, ``RECEIPT_SIGNATURE_INVALID`` or ``RECEIPT_KEY_UNKNOWN``.
* Checking a signature needs the ``cryptography`` package; without it the answer is
  ``RECEIPT_UNVERIFIABLE``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from typing import Any

RECEIPT_SCHEMA = "lightbulb.company_exchange_receipt.v1"
SETTLEMENT_SCHEMA = "lightbulb.company_exchange_settlement.v1"
KEYS_SCHEMA = "lightbulb.company_exchange_receipt_keys.v1"
ALGORITHM = "Ed25519"
RECEIPT_FIELDS = ("delivery_id", "from_address", "from_party", "to_address", "to_party", "exchange_ref", "kind", "document_digest")


def canonical_bytes(body: Mapping[str, Any]) -> bytes:
    """The bytes a receipt's digest and signature commit to: the SDK's canonical JSON."""

    return json.dumps(dict(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def receipt_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """What a delivery receipt commits to, from a receipt or any view of the delivery."""

    body: dict[str, Any] = {"schema": RECEIPT_SCHEMA, **{field: str(receipt[field]) for field in RECEIPT_FIELDS}}
    body["accepted_at"] = str(receipt.get("accepted_at") or receipt["sent_at"])
    return body


def settlement_body(delivery: Mapping[str, Any]) -> dict[str, Any]:
    """What a settlement commits to: the recipient's outcome for one delivery receipt."""

    settlement = dict(delivery["settlement"])
    body: dict[str, Any] = {"schema": SETTLEMENT_SCHEMA, "delivery_id": str(delivery["delivery_id"]), "receipt_digest": str(delivery["receipt_digest"]),
                            "document_digest": str(delivery["document_digest"]), "status": str(settlement["status"]), "settled_at": str(settlement["settled_at"])}
    if settlement.get("refusal_code") is not None:
        body["refusal_code"] = str(settlement["refusal_code"])
    return body


def _refuse(code: str, message: str) -> Exception:
    from lightbulb.company_exchange import ExchangeError

    return ExchangeError(code, message)


def _public_key(keys: Mapping[str, Any], key_id: str) -> str:
    for key in keys.get("keys") or ():
        if str(key.get("key_id")) == key_id:
            return str(key["public_key"])
    raise _refuse("RECEIPT_KEY_UNKNOWN", f"the platform publishes no receipt key {key_id}")


def _signature_holds(public_key: str, signature: str, message: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - cryptography is a dependency; a broken install says so
        raise _refuse("RECEIPT_UNVERIFIABLE", "checking a signed receipt needs the cryptography package") from exc
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(base64.b64decode(signature, validate=True), message)
    except (InvalidSignature, ValueError, binascii.Error):
        return False
    return True


def _check(body: Mapping[str, Any], digest: str, signature: Mapping[str, Any] | None, keys: Mapping[str, Any], *, what: str, mismatch: str) -> dict[str, Any]:
    message = canonical_bytes(body)
    computed = hashlib.sha256(message).hexdigest()
    if computed != digest:
        raise _refuse(mismatch, f"the {what}'s fields no longer match its digest")
    if not signature:
        return {"digest": computed, "signed": False, "verified": False}
    if signature.get("algorithm") != ALGORITHM:
        raise _refuse("RECEIPT_SIGNATURE_INVALID", f"the {what} is signed with {signature.get('algorithm')}, not {ALGORITHM}")
    key_id = str(signature.get("key_id"))
    if not _signature_holds(_public_key(keys, key_id), str(signature.get("value")), message):
        raise _refuse("RECEIPT_SIGNATURE_INVALID", f"the platform's signature on the {what} does not check out with key {key_id}")
    return {"digest": computed, "signed": True, "verified": True, "key_id": key_id}


def verify_delivery_receipt(receipt: Mapping[str, Any], keys: Mapping[str, Any]) -> dict[str, Any]:
    """Check a delivery receipt (or a delivery view) against the platform's published keys."""

    signature = receipt.get("signature") if "signature" in receipt else receipt.get("receipt_signature")
    return _check(receipt_body(receipt), str(receipt["receipt_digest"]), signature, keys, what="delivery receipt", mismatch="RECEIPT_DIGEST_MISMATCH")


def verify_settlement(delivery: Mapping[str, Any], keys: Mapping[str, Any]) -> dict[str, Any] | None:
    """Check a delivery's settlement against the platform's published keys; ``None`` while it waits in the inbox."""

    settlement = delivery.get("settlement")
    if not settlement:
        return None
    return _check(settlement_body(delivery), str(settlement["settlement_digest"]), settlement.get("signature"), keys, what="settlement", mismatch="RECEIPT_DIGEST_MISMATCH")


__all__ = ["ALGORITHM", "KEYS_SCHEMA", "RECEIPT_SCHEMA", "SETTLEMENT_SCHEMA", "canonical_bytes", "receipt_body", "settlement_body", "verify_delivery_receipt", "verify_settlement"]
