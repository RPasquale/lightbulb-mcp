"""Scoped integrity for host artifacts held in writable project checkpoints.

RBAC controls access to Spring records; it does not make an arbitrary stored
JSON document a provider observation. Only a trusted host with its receipt
keyring can authenticate an observation, decision or completed write journal.
"""
from dataclasses import dataclass, field
import hmac
from lightbulb.company_engine_core import stable_digest, detached

DOMAIN = "lightbulb.company_host_journal.v1"
_PLATFORM = {"revision", "lease_owner", "lease_until", "updated_at", "created_at"}

@dataclass
class AuthenticatedCheckpointGateway:
    gateway: object
    authority_scope: object
    keyring: object = field(repr=False)
    bundle_digest: str
    claim_run_ref: str | None = None

    def _read(self, ref, stored):
        if stored is None:
            return None
        payload = stored.get("host_document")
        proof = stored.get("host_receipt")
        if not isinstance(payload, dict) or not isinstance(proof, dict):
            raise ValueError("HOST_JOURNAL_UNAUTHENTICATED")
        expected = self._body(ref, payload, proof.get("key_id"))
        signature = proof.get("signature")
        if not isinstance(signature, str) or not hmac.compare_digest(
                signature, self.keyring.sign(proof.get("key_id"), DOMAIN, expected).hex()):
            raise ValueError("HOST_JOURNAL_SIGNATURE_INVALID")
        return {**detached(payload), **{k:v for k,v in stored.items() if k in _PLATFORM}}

    def _body(self, ref, document, key_id):
        return {"schema":DOMAIN,"run_ref":ref,"bundle_digest":self.bundle_digest,
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
