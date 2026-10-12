"""The company exchange in the books: a sale booked, an invoice owed to this company, a bill it owes, each re-derived from the sealed documents.

Trading through the exchange left the books where they were: the seller's accepted
order and its invoice, and the buyer's bill, lived only in the exchange's threads.
Every document is sealed and answers the one before it (``verify_thread``), so the
books can take the documents themselves as their evidence:

* **the seller's sale**: an order this company accepted (the buyer's purchase order and
  this company's acknowledgement) opens a ``revenue_chain`` case, handed off and agreed
  at the order's total;
* **the seller's invoice**: the invoice this company sent issues that case's invoice.
  The case carries the ledger reference a posting of the invoice gives as its document
  number (``LB-CTC-`` and eighteen hex digits of the invoice's digest), so the
  platform's payment observers can find it;
* **the buyer's bill**: an invoice this company received opens a ``payables_chain``
  case at ``bill_received``, due its terms after its date.  From there the chain's own
  rules apply: approval, cash cover, and a payment that needs the bill in the ledger
  (its posting gives ``LB-AP-`` and the same digits as its document number).

An exchange source is the thread's documents up to the one the hop consumes, the party
this company trades as, and, when the document the other company sent came through the
platform, the platform's signed delivery receipt with the published key it names.  The
chains re-derive every field from the source; a source that no longer checks out is
refused with the exchange's own code.  Nothing here posts to a ledger, moves money or
reads a provider.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any

from lightbulb.company_engine_core import detached, iso, parsed

EXCHANGE_BOOKS_SOURCE_SCHEMA = "lightbulb.company_exchange_books_source.v1"
PAYABLE_REFERENCE_PREFIX = "LB-AP-"
RECEIVABLE_REFERENCE_PREFIX = "LB-CTC-"
#: Where the other company's document comes from: the platform signed its delivery, the platform delivered it unsigned, or only this console recorded it.
ORIGINS: tuple[str, ...] = ("platform_signed", "platform_unsigned", "recorded")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_KEYS = frozenset({"schema", "party_ref", "documents", "platform_receipt"})


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        from lightbulb.company_exchange import ExchangeError

        raise ExchangeError(code, message)


def ledger_reference(document_digest: str, *, side: str) -> str:
    """The document number a ledger posting of this invoice carries: ``LB-AP-`` on the buyer's bill, ``LB-CTC-`` on the seller's invoice, then eighteen uppercase hex digits of the invoice's digest."""

    _require(side in ("payable", "receivable"), "LEDGER_SIDE_INVALID", "a ledger reference is for the payable or the receivable side")
    _require(bool(_DIGEST.match(str(document_digest))), "DOCUMENT_DIGEST_INVALID", "a ledger reference comes from a sealed document's digest")
    return (PAYABLE_REFERENCE_PREFIX if side == "payable" else RECEIVABLE_REFERENCE_PREFIX) + str(document_digest)[:18].upper()


def ledger_correlation(reference: str) -> str:
    """The correlation the platform binds a ledger posting to: the SHA-256 of its exact reference, as ``GovernedConnectorProviderCorrelation`` computes it."""

    return hashlib.sha256(str(reference).encode("utf-8")).hexdigest()


def platform_evidence(receipt: Mapping[str, Any], keys: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What the books keep of the platform's delivery receipt: its signed fields, its signature, and the one published key the signature names."""

    from lightbulb.company_exchange_receipts import RECEIPT_FIELDS

    raw = dict(detached(receipt))
    kept: dict[str, Any] = {field: str(raw[field]) for field in RECEIPT_FIELDS}
    kept["accepted_at"] = str(raw.get("accepted_at") or raw["sent_at"])
    kept["receipt_digest"] = str(raw["receipt_digest"])
    signature = raw.get("signature") if "signature" in raw else raw.get("receipt_signature")
    evidence: dict[str, Any] = {"receipt": kept}
    if signature:
        kept["signature"] = {key: str(value) for key, value in dict(signature).items() if value is not None}
        named = str(kept["signature"].get("key_id"))
        key = next((dict(item) for item in dict(keys or {}).get("keys") or () if str(dict(item).get("key_id")) == named), None)
        if key is not None:
            evidence["key"] = {"key_id": named, "public_key": str(key["public_key"])}
    return evidence


def exchange_source(documents: Sequence[Any], *, party_ref: str, platform_receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The evidence a books hop consumes: the thread's documents, the party this company trades as, and the platform's receipt when there is one; checked now, not only at the chain."""

    from lightbulb.company_exchange import verify_document

    source: dict[str, Any] = {"schema": EXCHANGE_BOOKS_SOURCE_SCHEMA, "party_ref": str(party_ref), "documents": [verify_document(document).to_dict() for document in documents]}
    if platform_receipt is not None:
        source["platform_receipt"] = dict(detached(platform_receipt))
    verify_exchange_source(source)
    return source


def verify_exchange_source(source: Mapping[str, Any] | Any) -> tuple[Any, str, str]:
    """The thread the source's documents make, this company's role in it, and the origin of the document the other company sent."""

    from lightbulb.company_exchange import verify_thread
    from lightbulb.company_exchange_receipts import verify_delivery_receipt

    raw = dict(detached(source))
    _require(raw.get("schema") == EXCHANGE_BOOKS_SOURCE_SCHEMA, "EXCHANGE_SOURCE_SCHEMA_MISMATCH", f"expected {EXCHANGE_BOOKS_SOURCE_SCHEMA}")
    _require(set(raw) <= _SOURCE_KEYS, "EXCHANGE_SOURCE_INVALID", "an exchange source holds its documents, the party and the platform's receipt, nothing else")
    try:
        thread = verify_thread(list(raw.get("documents") or ()))
    except ValueError as exc:
        if getattr(exc, "code", None):
            raise
        _require(False, "EXCHANGE_DOCUMENT_INVALID", f"a document in the source no longer matches its seal: {str(exc).splitlines()[-1] if str(exc) else exc}"[:300])
    party = str(raw.get("party_ref") or "")
    _require(party in (thread.buyer, thread.seller), "EXCHANGE_PARTY_NOT_IN_THREAD", f"{party or 'the party'} neither buys nor sells in {thread.exchange_ref}")
    role = "buyer" if party == thread.buyer else "seller"
    evidence = raw.get("platform_receipt")
    if evidence is None:
        return thread, role, "recorded"
    evidence = dict(evidence)
    _require(set(evidence) <= {"receipt", "key"}, "EXCHANGE_SOURCE_INVALID", "the platform's receipt is kept with the one key it names")
    receipt = dict(evidence.get("receipt") or {})
    key = evidence.get("key")
    verdict = verify_delivery_receipt(receipt, {"keys": [dict(key)] if key else []})
    inbound = next((document for document in thread.documents if document.document_digest == receipt.get("document_digest")), None)
    _require(inbound is not None and inbound.to_party == party and receipt.get("to_party") == party and receipt.get("from_party") == inbound.from_party
             and receipt.get("kind") == inbound.kind and receipt.get("exchange_ref") == thread.exchange_ref,
             "EXCHANGE_RECEIPT_MISMATCH", "the platform's receipt must be for a document this company received in this exchange")
    return thread, role, "platform_signed" if verdict["verified"] else "platform_unsigned"


def _origin_of(source: Mapping[str, Any], thread: Any, origin: str, kind: str) -> str:
    """The origin of the document of ``kind`` the other company sent: the platform's receipt speaks only for the document it names."""

    evidence = dict(dict(detached(source)).get("platform_receipt") or {})
    named = dict(evidence.get("receipt") or {}).get("document_digest")
    document = thread.document(kind)
    return origin if document is not None and named == document.document_digest else "recorded"


def exchange_bill_receipt(source: Mapping[str, Any] | Any, *, engine: str | None = None) -> dict[str, Any]:
    """The payables chain's opening receipt from an invoice this company received through the exchange, due its terms after its date."""

    thread, role, origin = verify_exchange_source(source)
    _require(role == "buyer", "EXCHANGE_NOT_THE_BUYER", f"a bill opens from an invoice this company received; it sells in {thread.exchange_ref}")
    invoice = thread.last()
    _require(invoice.kind == "invoice", "EXCHANGE_NOT_INVOICED", f"the exchange's last document is the {invoice.kind.replace('_', ' ')}; a bill opens from the invoice")
    return {"intake_source": detached(source), "supplier_ref": f"exchange:{thread.seller}", "bill_ref": f"exchange:{thread.exchange_ref}", "invoice_number": thread.exchange_ref,
            "amount": str(invoice.total), "currency": thread.currency, "due_at": invoice_due_at(invoice), "engine": engine, "intake_digest": invoice.document_digest, "correlation_sha256": None,
            "evidence_refs": [f"exchange:{thread.exchange_ref}", f"invoice:{invoice.document_digest[:24]}", f"origin:{_origin_of(source, thread, origin, 'invoice')}"]}


def exchange_sale_receipt(source: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The revenue chain's facts from an order this company accepted through the exchange: hand-off and agreement at the acknowledgement, and the invoice once the source holds it."""

    thread, role, origin = verify_exchange_source(source)
    _require(role == "seller", "EXCHANGE_NOT_THE_SELLER", f"a sale books an order this company accepted; it buys in {thread.exchange_ref}")
    order = thread.document("purchase_order")
    acknowledgement = thread.document("order_acknowledgement")
    _require(order is not None and acknowledgement is not None and acknowledgement.accepted is True, "EXCHANGE_ORDER_NOT_ACCEPTED", f"{thread.exchange_ref} has no accepted order to book")
    assert order is not None and acknowledgement is not None
    ref = f"exchange:{thread.exchange_ref}"
    facts: dict[str, Any] = {
        "exchange_source": detached(source),
        "prospect_ref": f"exchange:{thread.buyer}", "deal_ref": ref, "deal_value": str(acknowledgement.total), "prospect_state_digest": order.document_digest,
        "agreement_ref": ref, "contract_ref": ref, "custody_candidate_digest": acknowledgement.document_digest, "executed_at": acknowledgement.issued_at,
        "contract_value": str(acknowledgement.total), "accepted_amount": str(acknowledgement.total), "acceptance_ref": f"acknowledgement:{acknowledgement.document_digest[:24]}",
        "evidence_refs": [ref, f"order:{order.document_digest[:24]}", f"acknowledgement:{acknowledgement.document_digest[:24]}", f"origin:{_origin_of(source, thread, origin, 'purchase_order')}"],
    }
    invoice = thread.document("invoice")
    if invoice is not None:
        reference = ledger_reference(invoice.document_digest, side="receivable")
        facts.update({"invoice_ref": ref, "invoice_total": str(invoice.total), "invoice_evidence_sha256": invoice.document_digest, "correlation_sha256": ledger_correlation(reference),
                      "write_journal_ref": f"exchange:{invoice.document_digest[:24]}", "issued_at": invoice.issued_at})
        facts["evidence_refs"].append(f"invoice:{invoice.document_digest[:24]}")
    return facts


def invoice_due_at(invoice: Any) -> str:
    """An exchange invoice falls due its terms after its date."""

    return iso(parsed(invoice.issued_at) + timedelta(days=int(invoice.terms_days or 0)))


__all__ = [
    "EXCHANGE_BOOKS_SOURCE_SCHEMA",
    "ORIGINS",
    "PAYABLE_REFERENCE_PREFIX",
    "RECEIVABLE_REFERENCE_PREFIX",
    "exchange_bill_receipt",
    "exchange_sale_receipt",
    "exchange_source",
    "invoice_due_at",
    "ledger_correlation",
    "ledger_reference",
    "platform_evidence",
    "verify_exchange_source",
]
