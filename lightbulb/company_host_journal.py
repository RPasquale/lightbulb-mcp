"""Scoped integrity for host artifacts held in writable project checkpoints.

RBAC controls access to Spring records; it does not make an arbitrary stored
JSON document a provider observation. Only a trusted host with its receipt
keyring can authenticate an observation, decision or completed write journal.

A company's journals outlive the bundle version they were written under. The
owner amends the bundle (a mandate, a plan), and a prospect's thread, a billing
ledger, a queued signal or a checkout started under the earlier version carries
on under the amendment:

* every record is signed under the bundle the host runs, and one signed under
  an earlier version the project keeps is still this company's own
  (``accepted_bundle_digests``);
* journal keys derive from the company's journal root (``journal_root``), the
  bundle digest its journals were first written under, so they do not move
  when the bundle does.
"""
from dataclasses import dataclass, field
import hmac
from typing import Any
from lightbulb.company_engine_core import stable_digest, detached
from lightbulb.dynamic_workflow_control import DynamicWorkflowControlPersistenceError

DOMAIN = "lightbulb.company_host_journal.v1"
_PLATFORM = {"revision", "lease_owner", "lease_until", "updated_at", "created_at"}


class HostAuthorityError(ValueError):
    """Host identity or checkpoint integrity failed; stop the worker boundary."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)

@dataclass
class AuthenticatedCheckpointGateway:
    gateway: object
    authority_scope: object
    keyring: object = field(repr=False)
    bundle_digest: str
    claim_run_ref: str | None = None
    # The earlier versions of the running bundle the project keeps (``company_bootstrap.earlier_bundle_digests``):
    # a record signed under one of them was written by this company before the owner amended its bundle.
    # Writes are always signed under ``bundle_digest``.
    accepted_bundle_digests: tuple[str, ...] = ()
    # Pinned by ``pin_journal_root``; see ``journal_root``.
    journal_root_digest: str | None = None

    def _read(self, ref, stored):
        if stored is None:
            return None
        if not isinstance(stored, dict):
            raise HostAuthorityError("HOST_JOURNAL_UNAUTHENTICATED")
        payload = stored.get("host_document")
        proof = stored.get("host_receipt")
        if not isinstance(payload, dict) or not isinstance(proof, dict):
            raise HostAuthorityError("HOST_JOURNAL_UNAUTHENTICATED")
        written_elsewhere = False
        try:
            key_id, signature = proof.get("key_id"), proof.get("signature")
            valid = isinstance(signature, str) and any(
                hmac.compare_digest(signature, self._signature(ref, payload, key_id, digest))
                for digest in (self.bundle_digest, *self.accepted_bundle_digests))
            claimed = payload.get("bundle_digest")
            if not valid and isinstance(signature, str) and isinstance(claimed, str):
                written_elsewhere = hmac.compare_digest(signature, self._signature(ref, payload, key_id, claimed))
        except (ValueError, TypeError, KeyError, AttributeError, DynamicWorkflowControlPersistenceError) as error:
            raise HostAuthorityError("HOST_JOURNAL_SIGNATURE_INVALID") from error
        if not valid:
            # Authentic but written under a bundle this host neither runs nor keeps as an earlier version of its
            # own (a newer amendment, or a bundle the project never kept); still refused, and said so.
            raise HostAuthorityError("HOST_JOURNAL_BUNDLE_NOT_ACCEPTED" if written_elsewhere else "HOST_JOURNAL_SIGNATURE_INVALID")
        return {**detached(payload), **{k:v for k,v in stored.items() if k in _PLATFORM}}

    def _signature(self, ref, document, key_id, bundle_digest):
        return self.keyring.sign(key_id, DOMAIN, self._body(ref, document, key_id, bundle_digest)).hex()

    def _body(self, ref, document, key_id, bundle_digest=None):
        return {"schema":DOMAIN,"run_ref":ref,"bundle_digest":bundle_digest or self.bundle_digest,
                "scope_digest":self.keyring.exact_scope_digest(key_id=key_id,scope=self.authority_scope),
                "document_digest":stable_digest(document)}

    def get(self, ref):
        return self._read(ref, self.gateway.get(ref))

    def put(self, ref, document, *, expected_revision):
        payload = {k:detached(v) for k,v in document.items() if k not in _PLATFORM}
        key_id = self.keyring.active_key_id
        body = self._body(ref,payload,key_id)
        stored = self.gateway.put(ref,{"schema":DOMAIN,"run_ref":ref,
            "status":document.get("status","RUNNING"),"resume_at":document.get("resume_at"),
            **{k:v for k,v in document.items() if k in {"lease_owner","lease_until"}},
            "host_document":payload,"host_receipt":{"key_id":key_id,
                "signature":self.keyring.sign(key_id,DOMAIN,body).hex()}},expected_revision=expected_revision)
        return self._read(ref,stored)

    def claim(self, *, worker_ref, ready_at, lease_seconds):
        if self.claim_run_ref is None:
            raise ValueError("HOST_JOURNAL_EXACT_CLAIM_REQUIRED")
        stored=self.gateway.claim(worker_ref=worker_ref,ready_at=ready_at,lease_seconds=lease_seconds,run_ref=self.claim_run_ref)
        return self._read(self.claim_run_ref,stored)

    def renew(self, ref, *, worker_ref, expected_revision, lease_seconds):
        return self._read(ref,self.gateway.renew(ref,worker_ref=worker_ref,expected_revision=expected_revision,lease_seconds=lease_seconds))


def journal_root(gateway: Any, bundle: Any) -> str:
    """The digest a company's journal keys derive from: the bundle digest its journals were first written under.

    Unpinned it is the running bundle's own digest, the key every journal had
    before a bundle could be amended under it.
    """
    return str(getattr(gateway, "journal_root_digest", None) or bundle.plan_digest)


def own_bundle_digests(gateway: Any, bundle: Any) -> tuple[str, ...]:
    """The bundle digests a record of this company's journals may name: the running bundle's, then the earlier versions of it the project keeps."""
    return (str(bundle.plan_digest), *(str(item) for item in getattr(gateway, "accepted_bundle_digests", ()) or ()))


def pin_journal_root(gateway: AuthenticatedCheckpointGateway) -> str:
    """Pin the journal root from the company's cadence checkpoint, before anything derives a key from it.

    The checkpoint names the root once the bundle has been amended under it;
    until then the root is the bundle it names, which for a checkpoint written
    before roots existed is the bundle it was registered under, the one every
    journal of the company was keyed by. With no checkpoint yet it is the
    running bundle.
    """
    checkpoint = gateway.get(gateway.claim_run_ref) if gateway.claim_run_ref else None
    root = (checkpoint or {}).get("journal_root_digest") or (checkpoint or {}).get("bundle_digest") or gateway.bundle_digest
    gateway.journal_root_digest = str(root)
    return gateway.journal_root_digest
