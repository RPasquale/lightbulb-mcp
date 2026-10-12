"""An execution grant: the platform's signed, run-scoped permission to act on one software production request.

The owner's mandate is policy; a mandate decision that says ``act`` is not
yet permission to push code.  The platform (Spring) issues the grant after it
has recorded the decision, reserved the budget and bound the run: exact
tenant, company, project, repository and workspace, the request digest, the
effects allowed, a risk ceiling, the money reserved, when it expires, the
idempotency key, and an HMAC under a key only the platform holds.  The SDK
never issues a grant; it verifies one.  A digest alone proves nothing, so
verification needs the platform's signature (a key ring that can recompute
the HMAC) or an authoritative lookup of the grant as the platform holds it,
and refuses with a reason when it has neither.

In this slice only a branch and a draft pull request are executable.  A
grant that names ``merge`` or a deploy is refused however it was signed, and
so is one issued for another company, another request, an expired window, a
risk above its ceiling, or a decision that did not say ``act``.  Nothing here
executes anything.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from decimal import Decimal
from typing import Any, Literal, Protocol

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, canonical_uuid, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

EXECUTION_GRANT_SCHEMA = "lightbulb.execution_grant.v1"
GRANT_VERDICT_SCHEMA = "lightbulb.grant_verdict.v1"
GRANT_HMAC_DOMAIN = "lightbulb.execution_grant.hmac.v1"
EXECUTION_GRANT_MANIFEST: dict[str, Any] = {"engine": "execution_grant", "kind": "verification", "reads": (), "writes": ()}
GrantEffect = Literal["branch_create", "pull_request_open", "merge", "staging_deploy", "production_deploy", "rollback"]
RiskLevel = Literal["low", "medium", "high", "critical"]
# the effects a run may execute in this slice; merge and deploy are modelled in the mandate and refused here
EXECUTABLE_EFFECTS: frozenset[str] = frozenset({"branch_create", "pull_request_open"})
# the mandate action kind each effect is answered under
ACTION_KIND_FOR_EFFECT: dict[str, str] = {"branch_create": "open_change", "pull_request_open": "open_pr", "merge": "merge_pr", "staging_deploy": "deploy", "production_deploy": "deploy", "rollback": "deploy"}
NON_EXECUTABLE_ACTION_KINDS: frozenset[str] = frozenset({"merge_pr", "deploy"})
_RISK_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CHECKS: tuple[str, ...] = ("signature", "on_record", "scope", "request", "window", "effects_executable", "effects_in_policy", "risk_ceiling", "decision", "effect_granted")


class GrantError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GrantError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class GrantKeyRing(Protocol):
    """What the platform's signing key ring must do: recompute an HMAC for a key id, a domain and a payload; the SDK never sees the key."""

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


class ExecutionGrant(StrictModel):
    schema_id: str = Field(default=EXECUTION_GRANT_SCHEMA, alias="schema")
    grant_ref: OpaqueRef
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    app_ref: OpaqueRef | None = None
    repository_binding_ref: OpaqueRef
    workspace_binding_ref: OpaqueRef
    request_digest: Sha256Digest
    decision_digest: Sha256Digest
    mandate_digest: Sha256Digest
    allowed_effects: tuple[GrantEffect, ...] = Field(min_length=1, max_length=6)
    risk_ceiling: RiskLevel
    spend_reserved: Decimal
    currency: CurrencyCode
    issued_at: str
    expires_at: str
    idempotency_key: OpaqueRef
    issuer_ref: OpaqueRef
    grant_key_id: ShortText
    grant_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("allowed_effects", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("project_id")
    @classmethod
    def _uuid(cls, value: str) -> str:
        return canonical_uuid(value)

    @field_validator("spend_reserved", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="spend_reserved")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> "ExecutionGrant":
        if tuple(sorted(set(self.allowed_effects))) != self.allowed_effects:
            raise ValueError("allowed_effects are sorted and unique")
        if parsed(self.expires_at) <= parsed(self.issued_at):
            raise ValueError("a grant expires after it is issued")
        return self

    def hmac_payload(self) -> dict[str, Any]:
        """Exactly what the platform signs: every field but the signature, None included, in the wire spelling."""

        return self.model_dump(mode="json", by_alias=True, exclude={"grant_hmac"})


def grant_signature(payload: Mapping[str, Any], *, keyring: GrantKeyRing) -> str:
    """The reference HMAC over an unsigned grant: the domain, a NUL, the canonical JSON of the payload, under the key the grant names. The platform computes this when it issues; the SDK recomputes it to verify."""

    unsigned = ExecutionGrant.model_validate({**dict(detached(payload)), "grant_hmac": "0" * 64})
    return keyring.sign(unsigned.grant_key_id, GRANT_HMAC_DOMAIN, unsigned.hmac_payload()).hex()


def verify_grant_shape(value: Any) -> ExecutionGrant:
    """The grant parsed and shape-checked only; this proves nothing about who issued it."""

    return value if isinstance(value, ExecutionGrant) else ExecutionGrant.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


class GrantVerdict(StrictModel):
    schema_id: str = Field(default=GRANT_VERDICT_SCHEMA, alias="schema")
    grant_ref: OpaqueRef
    company_ref: OpaqueRef
    request_digest: Sha256Digest
    allowed_effects: tuple[GrantEffect, ...] = Field(min_length=1, max_length=6)
    effect: GrantEffect | None = None
    verified_by: Literal["signature", "lookup", "signature+lookup"]
    checks: tuple[ShortText, ...] = Field(min_length=1, max_length=len(CHECKS))
    verified_at: str
    expires_at: str
    verdict_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("allowed_effects", "checks", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GrantVerdict":
        if not skip_digests(info) and self.verdict_digest != sealed_digest(GrantVerdict, self, "verdict_digest"):
            raise ValueError("verdict_digest must commit the exact verdict")
        return self

    def render(self) -> str:
        return f"grant {self.grant_ref} verified by {self.verified_by} for request {self.request_digest[:12]}: may {', '.join(self.allowed_effects)} until {self.expires_at[:16]}Z" + (f"; {self.effect} permitted" if self.effect else "")


def verify_execution_grant(grant: ExecutionGrant | Mapping[str, Any], *, request: Mapping[str, Any], now: str, keyring: GrantKeyRing | None = None, lookup: Callable[[str], Mapping[str, Any] | None] | None = None, decision: Mapping[str, Any] | None = None, effect: str | None = None) -> GrantVerdict:
    """The one check before a run acts: the signature or the record, then the exact scope, the request, the window, the effects, the risk, the decision, and the effect asked for now. Refuses with a code; returns the sealed verdict."""

    from lightbulb.software_production import SoftwareProductionRequest, compile_software_production_request

    _require(keyring is not None or lookup is not None, "GRANT_UNVERIFIABLE", "a grant is trusted only by the platform's signature or an authoritative lookup; a digest alone proves nothing")
    parsed_grant = verify_grant_shape(grant)
    at = timestamp(now, field_name="now")
    passed: list[str] = []
    if keyring is not None:
        try:
            expected = keyring.sign(parsed_grant.grant_key_id, GRANT_HMAC_DOMAIN, parsed_grant.hmac_payload()).hex()
        except Exception:
            raise GrantError("GRANT_KEY_UNAVAILABLE", f"the signing key {parsed_grant.grant_key_id} is not in the ring") from None
        _require(hmac.compare_digest(parsed_grant.grant_hmac, expected), "GRANT_SIGNATURE_INVALID", "the grant's signature does not match the platform's key")
        passed.append("signature")
    if lookup is not None:
        held = lookup(parsed_grant.grant_ref)
        _require(held is not None, "GRANT_NOT_ON_RECORD", f"the platform holds no grant {parsed_grant.grant_ref}")
        assert held is not None
        _require(verify_grant_shape(held).to_dict() == parsed_grant.to_dict(), "GRANT_NOT_ON_RECORD", "the grant presented differs from the one the platform holds")
        passed.append("on_record")
    parsed_request = SoftwareProductionRequest.model_validate({key: value for key, value in dict(detached(request)).items() if key not in {"summary", "provider_effect_executed"}})
    scope = parsed_request.scope
    for label, mine, theirs in (("tenant", parsed_grant.tenant_ref, scope.tenant_ref), ("company", parsed_grant.company_ref, scope.company_ref), ("project", parsed_grant.project_ref, scope.project_ref), ("project id", parsed_grant.project_id, scope.project_id), ("workspace", parsed_grant.workspace_binding_ref, parsed_request.change_scope.workspace_binding_ref)):
        _require(mine == theirs, "GRANT_SCOPE_MISMATCH", f"the grant's {label} is not the request's")
    _require(parsed_grant.repository_binding_ref in parsed_request.change_scope.repository_binding_refs, "GRANT_SCOPE_MISMATCH", "the grant's repository is not one the request names")
    passed.append("scope")
    _require(parsed_grant.request_digest == parsed_request.request_digest, "GRANT_REQUEST_MISMATCH", "the grant was issued for another request")
    passed.append("request")
    _require(parsed(at) >= parsed(parsed_grant.issued_at), "GRANT_NOT_YET_VALID", f"the grant is issued at {parsed_grant.issued_at}")
    _require(parsed(at) <= parsed(parsed_grant.expires_at), "GRANT_EXPIRED", f"the grant expired at {parsed_grant.expires_at}")
    passed.append("window")
    beyond = [item for item in parsed_grant.allowed_effects if item not in EXECUTABLE_EFFECTS]
    _require(not beyond, "EFFECT_NOT_EXECUTABLE", f"{', '.join(beyond)} cannot be executed from the SDK yet; only {', '.join(sorted(EXECUTABLE_EFFECTS))} can")
    passed.append("effects_executable")
    compilation = compile_software_production_request(parsed_request)
    proposed = {item.effect for item in compilation.effects if item.classification == "proposed_write"}
    outside = [item for item in parsed_grant.allowed_effects if item not in proposed]
    _require(not outside, "EFFECT_NOT_IN_POLICY", f"the request's release policy does not propose {', '.join(outside)}")
    passed.append("effects_in_policy")
    _require(_RISK_RANK[compilation.effective_risk] <= _RISK_RANK[parsed_grant.risk_ceiling], "RISK_OVER_CEILING", f"the change is {compilation.effective_risk} risk; the grant's ceiling is {parsed_grant.risk_ceiling}")
    passed.append("risk_ceiling")
    if decision is not None:
        from lightbulb.owner_mandate import MandateDecision

        parsed_decision = MandateDecision.model_validate({key: value for key, value in dict(detached(decision)).items() if key not in {"summary", "provider_effect_executed"}})
        _require(parsed_decision.decision_digest == parsed_grant.decision_digest and parsed_decision.mandate_digest == parsed_grant.mandate_digest, "DECISION_MISMATCH", "the grant does not cite this decision under this mandate")
        _require(parsed_decision.company_ref == parsed_grant.company_ref, "DECISION_MISMATCH", "the decision belongs to another company")
        _require(parsed_decision.autonomy == "act", "DECISION_MISMATCH", f"the mandate said {parsed_decision.autonomy}, not act")
        _require(parsed_decision.action_kind == "open_change", "DECISION_MISMATCH", f"the decision is about {parsed_decision.action_kind}, not open_change")
        _require(parsed_grant.spend_reserved <= parsed_decision.money, "DECISION_MISMATCH", f"{parsed_grant.spend_reserved} reserved is more than the {parsed_decision.money} the mandate allowed")
        passed.append("decision")
    if effect is not None:
        _require(effect in parsed_grant.allowed_effects, "EFFECT_NOT_GRANTED", f"the grant does not allow {effect}; it allows {', '.join(parsed_grant.allowed_effects)}")
        passed.append("effect_granted")
    verified_by = "signature+lookup" if keyring is not None and lookup is not None else "signature" if keyring is not None else "lookup"
    return seal(GrantVerdict, {"grant_ref": parsed_grant.grant_ref, "company_ref": parsed_grant.company_ref, "request_digest": parsed_grant.request_digest, "allowed_effects": list(parsed_grant.allowed_effects), "effect": effect, "verified_by": verified_by, "checks": passed, "verified_at": at, "expires_at": parsed_grant.expires_at}, "verdict_digest")


def verify_grant_verdict(value: Any) -> GrantVerdict:
    return value if isinstance(value, GrantVerdict) else GrantVerdict.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


__all__ = ["ACTION_KIND_FOR_EFFECT", "CHECKS", "EXECUTABLE_EFFECTS", "EXECUTION_GRANT_MANIFEST", "EXECUTION_GRANT_SCHEMA", "GRANT_HMAC_DOMAIN", "GRANT_VERDICT_SCHEMA", "NON_EXECUTABLE_ACTION_KINDS", "ExecutionGrant", "GrantError", "GrantKeyRing", "GrantVerdict", "grant_signature", "verify_execution_grant", "verify_grant_shape", "verify_grant_verdict"]
