"""Trusted host intake of marketing touches; source hashes alone grant no credit.

The host injects its existing scoped receipt keyring. Neither bundle JSON nor
MCP arguments can install a verifier. Receipt verification is repeated when an
attribution ledger (including one nested in content history) is replayed.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hmac
import re
from typing import Any, Mapping

from lightbulb.company_engine_core import detached, stable_digest, same_scope, parsed
from lightbulb.company_execution_bridge import execution_receipt_from_connector
from lightbulb.connector_execution import ConnectorExecutionRequest, ConnectorExecutionResult

DOMAIN = "lightbulb.marketing_touch_source.v1"
_CURRENT = ContextVar("lightbulb_trusted_touch_verifier", default=None)
_FIELDS = ("touch_ref", "company_ref", "scope", "unit_commitment", "channel", "asset_commitment",
           "occurred_at", "basis", "claim_source", "provenance_digest")


def _require(value, code):
    if not value:
        raise ValueError(code)


def current_touch_verifier():
    return _CURRENT.get()


@contextmanager
def using_touch_verifier(verifier):
    """Host-only execution context, isolated between concurrent companies/tasks."""
    token = _CURRENT.set(verifier)
    try:
        yield
    finally:
        _CURRENT.reset(token)


@dataclass(frozen=True)
class TrustedTouchVerifier:
    authority_scope: Any
    engine_scope: Any
    company_ref: str
    keyring: Any = field(repr=False)

    def verify(self, claim):
        proof = claim.source_evidence
        _require(isinstance(proof, dict) and set(proof) == {"schema", "key_id", "scope_digest", "source", "signature"}, "TOUCH_SOURCE_UNVERIFIED")
        _require(proof["schema"] == DOMAIN, "TOUCH_SOURCE_UNVERIFIED")
        _require(claim.company_ref == self.company_ref and same_scope(claim.scope, self.engine_scope), "TOUCH_AUTHORITY_SCOPE_MISMATCH")
        _require(self.authority_scope.project_ref == claim.scope.project_ref, "TOUCH_AUTHORITY_SCOPE_MISMATCH")
        expected_scope = self.keyring.exact_scope_digest(key_id=proof["key_id"], scope=self.authority_scope)
        _require(hmac.compare_digest(expected_scope, proof["scope_digest"]), "TOUCH_AUTHORITY_SCOPE_MISMATCH")
        source = proof["source"]
        _require(isinstance(source, dict) and set(source) == {"claim_digest", "request_digest", "output_digest", "journal_ref", "row_digest", "completed_at", "binding_digest"}, "TOUCH_SOURCE_UNVERIFIED")
        fields = {key: claim.to_dict().get(key) for key in _FIELDS}
        _require(source["claim_digest"] == stable_digest(fields), "TOUCH_SOURCE_MISMATCH")
        _require(parsed(claim.occurred_at) <= parsed(source["completed_at"]), "TOUCH_SOURCE_NOT_OBSERVED")
        body = {key: proof[key] for key in ("schema", "key_id", "scope_digest", "source")}
        expected = self.keyring.sign(proof["key_id"], DOMAIN, body).hex()
        _require(isinstance(proof["signature"], str) and hmac.compare_digest(expected, proof["signature"]), "TOUCH_SOURCE_SIGNATURE_INVALID")
        return claim


def touches_from_posthog(request, result, *, verifier: TrustedTouchVerifier,
                         event_bindings: Mapping[str, Mapping[str, Any]], identity_links: Mapping[str, str], require_complete: bool = True):
    """Normalize the actual governed PostHog event page using host-held mappings.

    Event-to-channel policy and customer identity joins must come from the
    authenticated company's retained configuration, never inferred from UTM
    strings or supplied by a model. Unknown identities are explicitly unmatched.
    """
    from lightbulb.conversion_attribution import touch_claim
    request = ConnectorExecutionRequest.model_validate(detached(request))
    result = ConnectorExecutionResult.model_validate(detached(result))
    receipt = execution_receipt_from_connector(result, request)
    _require(receipt.tool == "posthog.query_events" and receipt.effect == "read", "TOUCH_SOURCE_TOOL_UNSUPPORTED")
    _require(receipt.project_id == str(verifier.engine_scope.project_id)
             and receipt.connector_account_ref == request.connector_account_ref, "TOUCH_AUTHORITY_SCOPE_MISMATCH")
    _require(all(str(getattr(request.scope, key)) == str(getattr(verifier.engine_scope, key)) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "TOUCH_AUTHORITY_SCOPE_MISMATCH")
    output = dict(result.output)
    _require(output.get("schema") == "lightbulb.posthog_event_page.v1" and type(output.get("has_more")) is bool and (not require_complete or output["has_more"] is False), "TOUCH_READ_INCOMPLETE")
    rows = output.get("events")
    _require(isinstance(rows, list) and type(output.get("record_count")) is int
             and output["record_count"] == len(rows) and len(rows) <= 100, "TOUCH_READ_INCOMPLETE")
    event = request.arguments.get("event")
    _require(event == output.get("event") and event in event_bindings, "TOUCH_EVENT_POLICY_MISSING")
    binding = dict(event_bindings[event])
    _require(set(binding) <= {"channel", "asset_commitment"} and "channel" in binding, "TOUCH_EVENT_POLICY_INVALID")
    _require(parsed(output["after"]) == parsed(request.arguments["after"])
             and parsed(output["before"]) == parsed(request.arguments["before"])
             and parsed(output["before"]) <= parsed(receipt.completed_at), "TOUCH_WINDOW_MISMATCH")
    from hashlib import sha256
    _require(output.get("project_id_sha256") == sha256(str(request.arguments["project_id"]).encode()).hexdigest(), "TOUCH_PROVIDER_PROJECT_MISMATCH")
    seen, touches, unmatched = set(), [], []
    for row in rows:
        identity, event_id = row.get("distinct_id_sha256"), row.get("uuid_sha256")
        _require(isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{64}", event_id) is not None and event_id not in seen, "TOUCH_EVENT_ID_REQUIRED")
        seen.add(event_id)
        _require(row.get("event") == event and parsed(output["after"]) <= parsed(row["timestamp"]) < parsed(output["before"]), "TOUCH_EVENT_OUTSIDE_WINDOW")
        if identity not in identity_links:
            unmatched.append(event_id)
            continue
        fields = {"touch_ref": "touch-" + event_id, "company_ref": verifier.company_ref,
                  "scope": detached(verifier.engine_scope), "unit_commitment": identity_links[identity],
                  "channel": binding["channel"], "asset_commitment": binding.get("asset_commitment"),
                  "occurred_at": row["timestamp"], "basis": "site_measured",
                  "claim_source": receipt.journal_ref, "provenance_digest": receipt.execution_digest}
        # Normalize timestamps/defaults before committing the exact claim fields.
        draft = touch_claim(fields)
        fields = {key: draft.to_dict().get(key) for key in _FIELDS}
        key_id = verifier.keyring.active_key_id
        body = {"schema": DOMAIN, "key_id": key_id,
                "scope_digest": verifier.keyring.exact_scope_digest(key_id=key_id, scope=verifier.authority_scope),
                "source": {"claim_digest": stable_digest(fields), "request_digest": receipt.request_digest,
                           "output_digest": receipt.output_digest, "journal_ref": receipt.journal_ref,
                           "row_digest": stable_digest(row), "completed_at": receipt.completed_at,
                           "binding_digest": stable_digest({"event": event, "binding": binding, "source_identity": identity, "customer_identity": identity_links[identity]})}}
        proof = {**body, "signature": verifier.keyring.sign(key_id, DOMAIN, body).hex()}
        claim = touch_claim({**fields, "source_evidence": proof})
        verifier.verify(claim)
        touches.append(claim)
    return {"touches": touches, "unmatched_event_refs": unmatched, "complete": output["has_more"] is False,
            "request_digest": receipt.request_digest, "source_digest": receipt.output_digest}
