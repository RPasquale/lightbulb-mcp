"""The company exchange on the Lightbulb platform: the transport the console sends documents through.

Two companies' agents trade in five sealed documents (``lightbulb.company_exchange``).
On the platform:

* a company publishes its card in the exchange directory and is given an exchange
  address (``lbx_...``), the only name other companies use to find it and send to it;
* a counterparty is registered by its address, which ties its card's party ref to
  where its documents go; one can also be blocked, so its documents are refused;
* a document goes to the registered counterparty whose card carries its
  ``to_party``. The platform recomputes the seal, requires the ``from_party`` to be
  this company's card and the ``to_party`` the recipient's, keeps it once, and answers
  a receipt;
* what other companies sent waits in the company's inbox until the console takes it
  in (``receive_document``) and settles it: received, or refused with the console's
  code, which the sender reads as its receipt.

``PlatformExchange`` is the console's ``exchange_transport``. When the platform refuses
a document (a blocked sender, a kind the recipient doesn't take, a lapsed card), the
transport raises ``ExchangeError`` with the platform's code. The console and the
autopilot treat that like any other refusal, and nothing is recorded as sent.

Every receipt is checked against the platform's published keys
(``company_exchange_receipts``):

* a sent document's receipt is kept verified or not;
* a delivery whose platform signature fails in the inbox is refused, since the
  signature is the platform's word for who sent it;
* ``receipts`` checks what this company sent, and each recipient's signed settlement.

The keys are read when a receipt first names one the transport doesn't hold (the first
signed receipt, or one after a rotation), so an unsigned platform is never asked. When
they can't be read (the platform is down or busy) the check is
``RECEIPT_KEYS_UNAVAILABLE``: a sent document's receipt is kept unchecked, and an inbox
delivery waits for the next pass. Neither is refused on that account.

A document from a company this one has not registered is still taken in: it can
open a thread with a request for quote. Nothing is sent back until the owner registers
that company (``company_exchange counterparty``), so the agent never answers an unknown
company on its own.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from lightbulb.company_engine_core import timestamp

PLATFORM_TRANSPORT = "lightbulb_platform"
RECEIPT_KEYS_UNAVAILABLE = "RECEIPT_KEYS_UNAVAILABLE"
_PLATFORM_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,79}$")
_SETTLEMENT_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,79}$")
# the statuses the platform answers a refusal with; anything else (a 5xx, a network failure) is not a refusal
_REFUSALS = frozenset({400, 403, 404, 409, 429})
_RECEIPT_FIELDS = ("delivery_id", "receipt_digest", "accepted_at", "status", "replayed", "signature")


def platform_refusal(exc: BaseException) -> BaseException:
    """The platform's refusal as the console's own ``ExchangeError`` with the platform's code; anything else unchanged."""

    from lightbulb.company_exchange import ExchangeError
    from lightbulb.errors import LightbulbError

    if isinstance(exc, LightbulbError) and exc.status_code in _REFUSALS:
        message = str(exc).strip()
        code = message.upper() if _PLATFORM_CODE.match(message) else "PLATFORM_REFUSED"
        return ExchangeError(code, f"the platform refused it (HTTP {exc.status_code}): {message}"[:300])
    return exc


def _refusal_code(exc: BaseException) -> str:
    code = str(getattr(exc, "code", "") or "").upper()
    return code if _SETTLEMENT_CODE.match(code) else "DOCUMENT_INVALID"


@dataclass
class PlatformExchange:
    """One company's exchange transport on the platform (``company_id`` names the selected company, else the client's own)."""

    client: Any
    company_id: str | None = None
    _parties: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _keys: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        try:
            return getattr(self.client, method)(*args, company_id=self.company_id, **kwargs)
        except Exception as exc:
            refusal = platform_refusal(exc)
            if refusal is exc:
                raise
            raise refusal from exc

    # -- the directory ------------------------------------------------------------------------

    def publish(self, console: Any, *, visibility: str = "platform", listed: bool | None = None) -> dict[str, Any]:
        """Publish the console's card, listed in the directory's search or not (None keeps it as it was); answers the directory record with the company's address."""

        from lightbulb.company_exchange_surface import _require_card

        return dict(self._call("publish_exchange_card", _require_card(console).to_dict(), visibility=visibility, listed=listed))

    def search(self, query: str, *, currency: str | None = None, country: str | None = None, kind: str | None = None, limit: int = 20) -> dict[str, Any]:
        """Listed companies whose cards match ``query``, best first, never this company: {match, results}."""

        return dict(self._call("search_exchange_directory", query, currency=currency, country=country, kind=kind, limit=limit))

    def find(self, address: str) -> dict[str, Any]:
        return dict(self._call("find_exchange_card", address))

    def own_card(self) -> dict[str, Any] | None:
        """This company's card as the platform keeps it, with its track record as other companies see it; None before it is published."""

        card = self._call("get_exchange_card")
        return None if card is None else dict(card)

    def register(self, address: str, *, status: str = "active", note: str | None = None) -> dict[str, Any]:
        row = dict(self._call("set_exchange_counterparty", address, status=status, note=note))
        self._parties.clear()
        return row

    def counterparties(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._call("list_exchange_counterparties")]

    def address_for(self, party_ref: str) -> str:
        """The address of the active, published counterparty whose card carries ``party_ref``."""

        from lightbulb.company_exchange import ExchangeError

        if party_ref not in self._parties:
            self._parties = {str(row["party_ref"]): str(row["address"]) for row in self.counterparties()
                             if row.get("status") == "active" and row.get("published") and row.get("party_ref")}
        address = self._parties.get(party_ref)
        if address is None:
            raise ExchangeError("COUNTERPARTY_UNKNOWN", f"no registered counterparty trades as {party_ref}: register the company by its exchange address first (company_exchange counterparty)")
        return address

    # -- receipts ----------------------------------------------------------------------------

    def keys(self, *, refresh: bool = False) -> dict[str, Any]:
        """The platform's published receipt keys; ``RECEIPT_KEYS_UNAVAILABLE`` when the platform can't answer them."""

        import httpx

        from lightbulb.company_exchange import ExchangeError
        from lightbulb.errors import LightbulbError

        if self._keys is None or refresh:
            try:
                self._keys = dict(self.client.get_exchange_receipt_keys(company_id=self.company_id))
            except (LightbulbError, httpx.HTTPError, OSError, ValueError) as exc:
                raise ExchangeError(RECEIPT_KEYS_UNAVAILABLE, f"the platform's receipt keys could not be read: {exc}"[:300]) from exc
        return self._keys

    def check(self, verify: Any, subject: Any) -> dict[str, Any]:
        """``verify(subject, keys)`` with the keys held; they're read again only when the receipt names one not held."""

        from lightbulb.company_exchange import ExchangeError

        try:
            return verify(subject, self._keys or {})
        except ExchangeError as exc:
            if exc.code != "RECEIPT_KEY_UNKNOWN":
                raise
        return verify(subject, self.keys(refresh=True))

    def _verified(self, verify: Any, subject: Any) -> dict[str, Any]:
        """A verdict to keep beside a receipt: ``verified`` true, or false with the code; a receipt is never dropped."""

        from lightbulb.company_exchange import ExchangeError

        try:
            verdict = self.check(verify, subject)
        except ExchangeError as exc:
            return {"verified": False, "code": exc.code}
        return {key: verdict[key] for key in ("signed", "verified", "key_id") if key in verdict}

    def receipts(self, *, exchange_ref: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """What this company sent, each receipt and each recipient's settlement checked against the platform's keys."""

        from lightbulb.company_exchange_receipts import verify_delivery_receipt, verify_settlement

        rows = []
        for delivery in self._call("list_exchange_deliveries", exchange_ref=exchange_ref, limit=limit):
            settlement = dict(delivery.get("settlement") or {})
            rows.append({"delivery_id": delivery["delivery_id"], "exchange_ref": delivery["exchange_ref"], "kind": delivery["kind"], "to_address": delivery["to_address"],
                         "to_party": delivery["to_party"], "sent_at": delivery.get("sent_at"), "status": delivery["status"], "receipt": self._verified(verify_delivery_receipt, delivery),
                         "settlement": None if not settlement else {"status": settlement.get("status"), "refusal_code": settlement.get("refusal_code"),
                                                                    "settled_at": settlement.get("settled_at"), **self._verified(verify_settlement, delivery)}})
        return rows

    # -- the transport -----------------------------------------------------------------------

    def __call__(self, document: Mapping[str, Any]) -> dict[str, Any]:
        """Send one sealed document; the receipt this returns is kept on the thread's delivery row."""

        from lightbulb.company_exchange_receipts import verify_delivery_receipt

        address = self.address_for(str(document["to_party"]))
        receipt = dict(self._call("deliver_exchange_document", address, dict(document)))
        # the platform took it either way; the receipt says whether its signature checks out
        return {"transport": PLATFORM_TRANSPORT, "to_address": address, **{key: receipt[key] for key in _RECEIPT_FIELDS if key in receipt},
                "receipt_check": self._verified(verify_delivery_receipt, receipt)}

    # -- the inbox ---------------------------------------------------------------------------

    def drain(self, console: Any, *, now: str, limit: int = 50) -> dict[str, Any]:
        """Take in what waits in the inbox and settle each delivery: received, or refused with the console's code.

        Taking a document in twice changes nothing, so a delivery that was taken in but not
        settled (the settlement was lost) is simply settled on the next pass.
        """

        from lightbulb.company_exchange import ExchangeError
        from lightbulb.company_exchange_books import platform_evidence
        from lightbulb.company_exchange_receipts import verify_delivery_receipt
        from lightbulb.company_exchange_surface import receive_document

        at = timestamp(now, field_name="now")
        received: list[dict[str, Any]] = []
        refused: list[dict[str, Any]] = []
        unsettled: list[dict[str, Any]] = []
        for row in self._call("list_exchange_inbox", limit=max(1, min(200, int(limit)))):
            delivery_id = str(row["delivery_id"])
            document = dict(row.get("document") or {})
            facts = {"delivery_id": delivery_id, "exchange_ref": row.get("exchange_ref"), "kind": row.get("kind"),
                     "from_address": row.get("from_address"), "from_party": row.get("from_party"), "sender_registered": bool(row.get("sender_registered")),
                     "sender_track_record": row.get("sender_track_record")}
            try:
                if document.get("from_party") != row.get("from_party") or document.get("to_party") != row.get("to_party"):
                    raise ExchangeError("ENVELOPE_MISMATCH", "the delivery names other parties than its document")
                # the platform's signed receipt is its word for who sent this: one that fails is not taken in
                facts["receipt_signed"] = bool(self.check(verify_delivery_receipt, row)["signed"])
                view = receive_document(console, now=at, document=document, platform_receipt=platform_evidence(row, self._keys))
            except ValueError as exc:
                if getattr(exc, "code", None) == RECEIPT_KEYS_UNAVAILABLE:
                    # who sent it can't be checked now: it waits in the inbox for the next pass
                    unsettled.append({**facts, "settlement": None, "code": RECEIPT_KEYS_UNAVAILABLE, "detail": str(exc)[:300]})
                    continue
                settlement = {"status": "refused", "refusal_code": _refusal_code(exc)}
                outcome = {**facts, "code": settlement["refusal_code"], "detail": str(exc)[:300]}
            else:
                settlement = {"status": "received"}
                outcome = {**facts, "our_turn": bool(view.get("our_turn")), "unchanged": bool(dict(view.get("stored") or {}).get("unchanged")), "books": view.get("books")}
            try:
                self._call("settle_exchange_delivery", delivery_id, **settlement)
            except ExchangeError as exc:
                unsettled.append({**outcome, "settlement": settlement["status"], "code": exc.code, "detail": str(exc)[:300]})
                continue
            (received if settlement["status"] == "received" else refused).append(outcome)
        new = [row for row in received if not row["sender_registered"]]
        bills = [row for row in received if dict(row.get("books") or {}).get("applied")]
        summary = f"**Exchange inbox**: {len(received)} taken in, {len(refused)} refused" + (f", {len(unsettled)} left for the next pass" if unsettled else "") + (f"; {len(bills)} bill(s) put in the books" if bills else "")
        if new:
            summary += f"; {len(new)} from companies not yet registered: register them (company_exchange counterparty) before the agent answers"
        return {"schema": "lightbulb.company_exchange_inbox_pass.v1", "as_of": at, "received": received, "refused": refused, "unsettled": unsettled,
                "summary": summary, "provider_effect_executed": False}


__all__ = ["PLATFORM_TRANSPORT", "RECEIPT_KEYS_UNAVAILABLE", "PlatformExchange", "platform_refusal"]
