"""Licence verification: the authority a plan holds, checked against a register snapshot the operator supplies, by commitment.

The SDK never sees a licence number. An advice plan carries a commitment (the sha256 of the
normalised number, computed by the operator outside the SDK) and the operator reads the public
register (ASIC's professional registers in Australia, the provincial regulators' registers in
Canada) and hands over a snapshot whose entries carry the same commitment computed by the same
rule. Verification is then a comparison of commitments plus the register's own words: the status
the register states, the authorisations it lists, the expiry it gives, and when the register was
read. A missing entry, a suspended or cancelled licence, an expired one, a licence whose
authorisations do not reach the vertical's family, or a snapshot older than the operator allows
all refuse.

A verified authority is a receipt an adviser approval can cite. It is not a licence, and it does
not make anything the platform produces into advice: the licensed person still approves.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, StrictModel, detached, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_engine import Authority, AuthorityKind

REGISTER_SCHEMA = "lightbulb.finance_advice_licence_register.v1"
VERIFICATION_SCHEMA = "lightbulb.finance_advice_authority_verification.v1"
DEFAULT_REGISTER_MAX_AGE_HOURS = 24 * 35
DEFAULT_EXPIRING_SOON_DAYS = 30
FORBIDDEN_REGISTER_KEYS = frozenset({"licence_number", "license_number", "licence_no", "registration_number", "abn", "acn", "email", "phone", "address"})

RegisterStatus = Literal["current", "suspended", "cancelled", "expired", "unknown"]
Finding = Literal["not_found", "kind_mismatch", "jurisdiction_mismatch", "status_suspended", "status_cancelled", "status_expired", "status_unknown", "expired", "expiring_soon", "scope_gap", "authorisation_gap", "authorisations_unstated", "register_stale"]
Verdict = Literal["verified", "refused"]

# the words a register's authorisations use for each product family; a plain table, not an interpretation
_FAMILY_WORDS: dict[str, tuple[str, ...]] = {
    "credit": ("credit",),
    "deposits": ("deposit", "basic banking", "banking"),
    "insurance": ("insurance", "life", "general insurance", "risk"),
}
_REFUSING: frozenset[str] = frozenset({"not_found", "kind_mismatch", "jurisdiction_mismatch", "status_suspended", "status_cancelled", "status_expired", "status_unknown", "expired", "scope_gap", "authorisation_gap", "register_stale"})


def _when(value: str) -> Any:
    return parsed(value if "T" in value else f"{value}T23:59:59Z")


def _refuse_numbers(value: Any) -> Any:
    if isinstance(value, Mapping):
        bad = sorted(str(key) for key in value if str(key) in FORBIDDEN_REGISTER_KEYS)
        if bad:
            raise ValueError(f"register entries carry commitments, not numbers or contact details: {', '.join(bad)}")
    return value


class RegisterEntry(StrictModel):
    """One row of a public register as the operator read it, with the licence number replaced by its commitment."""

    kind: AuthorityKind
    jurisdiction: Literal["AU", "CA"]
    licence_ref_sha256: Sha256Digest
    holder_name_as_stated: str = Field(min_length=1)
    status: RegisterStatus = "unknown"
    authorisations: tuple[str, ...] = Field(default_factory=tuple)
    effective_from: str | None = None
    expires_on: str | None = None
    source_url: str = Field(min_length=1)
    quote: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_numbers(cls, value: Any) -> Any:
        return _refuse_numbers(value)

    @field_validator("authorisations", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class LicenceRegisterSnapshot(StrictModel):
    """A register as read at one moment: which register, when, and its entries by commitment."""

    schema_id: Literal["lightbulb.finance_advice_licence_register.v1"] = REGISTER_SCHEMA
    register_name: str = Field(min_length=1)
    jurisdiction: Literal["AU", "CA"]
    retrieved_at: str
    entries: tuple[RegisterEntry, ...] = Field(default_factory=tuple)
    snapshot_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> LicenceRegisterSnapshot:
        if not skip_digests(info) and self.snapshot_digest != sealed_digest(LicenceRegisterSnapshot, self, "snapshot_digest"):
            raise ValueError("snapshot_digest does not match the snapshot")
        return self

    def find(self, kind: str, commitment: str) -> RegisterEntry | None:
        for entry in self.entries:
            if entry.licence_ref_sha256 == commitment and entry.kind == kind:
                return entry
        return None


def licence_register(register: str, *, jurisdiction: str, retrieved_at: str, entries: Sequence[RegisterEntry | Mapping[str, Any]]) -> LicenceRegisterSnapshot:
    """Seal a register snapshot the operator read."""
    return seal(LicenceRegisterSnapshot, {"register_name": register, "jurisdiction": jurisdiction, "retrieved_at": timestamp(retrieved_at, field_name="retrieved_at"), "entries": [dict(detached(item)) for item in entries]}, "snapshot_digest")


class AuthorityVerification(StrictModel):
    """The outcome of checking one authority against one register snapshot, sealed."""

    schema_id: Literal["lightbulb.finance_advice_authority_verification.v1"] = VERIFICATION_SCHEMA
    authority_kind: AuthorityKind
    holder_ref: OpaqueRef
    authority_ref_sha256: Sha256Digest
    jurisdiction: Literal["AU", "CA"]
    vertical_id: str | None = None
    family: str | None = None
    register_name: str
    register_retrieved_at: str
    verdict: Verdict
    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    status_as_stated: RegisterStatus | None = None
    holder_name_as_stated: str | None = None
    authorisations: tuple[str, ...] = Field(default_factory=tuple)
    expires_on: str | None = None
    verified_at: str
    verification_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("findings", "reasons", "authorisations", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> AuthorityVerification:
        if not skip_digests(info) and self.verification_digest != sealed_digest(AuthorityVerification, self, "verification_digest"):
            raise ValueError("verification_digest does not match the verification")
        return self

    @property
    def verified(self) -> bool:
        return self.verdict == "verified"


def verify_authority(authority: Authority | Mapping[str, Any], snapshot: LicenceRegisterSnapshot | Mapping[str, Any], *, as_of: str, vertical_id: str | None = None, family: str | None = None, max_register_age_hours: int = DEFAULT_REGISTER_MAX_AGE_HOURS, expiring_soon_days: int = DEFAULT_EXPIRING_SOON_DAYS) -> AuthorityVerification:
    """Compare the plan's authority commitment with the register snapshot and read the register's words.

    Every refusal names its finding. ``family`` (credit, deposits, insurance) is checked against the
    authorisations the register lists when it is given; a register that lists no authorisations is
    noted as unstated rather than refused, because silence in a register is not a restriction.
    """
    a = authority if isinstance(authority, Authority) else Authority.model_validate(dict(authority))
    s = snapshot if isinstance(snapshot, LicenceRegisterSnapshot) else LicenceRegisterSnapshot.model_validate(dict(snapshot))
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    findings: list[str] = []
    reasons: list[str] = []
    if s.jurisdiction != a.jurisdiction:
        findings.append("jurisdiction_mismatch")
        reasons.append(f"the register is {s.jurisdiction}; the authority is {a.jurisdiction}")
    age = now - parsed(s.retrieved_at)
    if age > timedelta(hours=max_register_age_hours):
        findings.append("register_stale")
        reasons.append(f"the register was read {age.days} days ago; the operator allows {max_register_age_hours // 24} days")
    entry = s.find(a.kind, a.authority_ref_sha256)
    if entry is None:
        other_kind = next((item for item in s.entries if item.licence_ref_sha256 == a.authority_ref_sha256), None)
        if other_kind is not None:
            findings.append("kind_mismatch")
            reasons.append(f"the register lists this commitment as {other_kind.kind}, not {a.kind}")
        else:
            findings.append("not_found")
            reasons.append("no entry in the register carries this commitment")
    else:
        if entry.status != "current":
            findings.append(f"status_{entry.status}")  # type: ignore[arg-type]
            reasons.append(f"the register states the licence is {entry.status}")
        if entry.expires_on is not None:
            expiry = _when(entry.expires_on)
            if expiry < now:
                findings.append("expired")
                reasons.append(f"the register gives an expiry of {entry.expires_on}")
            elif expiry - now <= timedelta(days=expiring_soon_days):
                findings.append("expiring_soon")
                reasons.append(f"the register gives an expiry of {entry.expires_on}, within {expiring_soon_days} days")
        if family:
            words = _FAMILY_WORDS.get(family, (family,))
            if not entry.authorisations:
                findings.append("authorisations_unstated")
                reasons.append("the register lists no authorisations; the operator confirms the scope by hand")
            elif not any(any(word in item.lower() for word in words) for item in entry.authorisations):
                findings.append("authorisation_gap")
                reasons.append(f"the authorisations listed do not reach {family}: " + "; ".join(entry.authorisations))
    if a.expires_at is not None and _when(a.expires_at) < now:
        findings.append("expired")
        reasons.append(f"the plan's own expiry for this authority is {a.expires_at}")
    if vertical_id and vertical_id not in a.scope_verticals:
        findings.append("scope_gap")
        reasons.append(f"the plan does not scope this authority to {vertical_id}")
    unique = list(dict.fromkeys(findings))
    verdict: str = "refused" if any(item in _REFUSING for item in unique) else "verified"
    if verdict == "verified":
        reasons.insert(0, f"the {s.register_name} entry with this commitment is current" + (f" for {entry.holder_name_as_stated}" if entry else ""))
    return seal(AuthorityVerification, {"authority_kind": a.kind, "holder_ref": a.holder_ref, "authority_ref_sha256": a.authority_ref_sha256, "jurisdiction": a.jurisdiction, "vertical_id": vertical_id, "family": family, "register_name": s.register_name, "register_retrieved_at": s.retrieved_at, "verdict": verdict, "findings": unique, "reasons": reasons, "status_as_stated": entry.status if entry else None, "holder_name_as_stated": entry.holder_name_as_stated if entry else None, "authorisations": list(entry.authorisations) if entry else [], "expires_on": entry.expires_on if entry else None, "verified_at": stamp}, "verification_digest")


def verifications_for_plan(plan_authorities: Sequence[Authority | Mapping[str, Any]], snapshots: Sequence[LicenceRegisterSnapshot | Mapping[str, Any]], *, as_of: str, vertical_id: str | None = None, family: str | None = None) -> tuple[AuthorityVerification, ...]:
    """Verify every authority a plan holds against the snapshot of its jurisdiction; missing snapshots refuse as stale."""
    by_jurisdiction: dict[str, LicenceRegisterSnapshot] = {}
    for item in snapshots:
        s = item if isinstance(item, LicenceRegisterSnapshot) else LicenceRegisterSnapshot.model_validate(dict(item))
        by_jurisdiction[s.jurisdiction] = s
    out: list[AuthorityVerification] = []
    for item in plan_authorities:
        a = item if isinstance(item, Authority) else Authority.model_validate(dict(item))
        snapshot = by_jurisdiction.get(a.jurisdiction)
        if snapshot is None:
            snapshot = licence_register("no register supplied", jurisdiction=a.jurisdiction, retrieved_at="2000-01-01T00:00:00Z", entries=[])
        out.append(verify_authority(a, snapshot, as_of=as_of, vertical_id=vertical_id, family=family))
    return tuple(out)


LICENCE_MANIFEST: dict[str, Any] = {
    "schemas": {"register": REGISTER_SCHEMA, "verification": VERIFICATION_SCHEMA},
    "commitment_rule": "sha256 of the normalised licence number, computed by the operator outside the SDK; the SDK compares commitments and never holds a number",
    "refusing_findings": sorted(_REFUSING),
    "advisory_findings": ["expiring_soon", "authorisations_unstated"],
    "register_max_age_hours": DEFAULT_REGISTER_MAX_AGE_HOURS,
    "family_words": {key: list(value) for key, value in _FAMILY_WORDS.items()},
    "not_claimed": "a verification is a receipt the approval cites; it is not a licence and it does not make the platform's output advice",
}

__all__ = ["DEFAULT_EXPIRING_SOON_DAYS", "DEFAULT_REGISTER_MAX_AGE_HOURS", "FORBIDDEN_REGISTER_KEYS", "LICENCE_MANIFEST", "REGISTER_SCHEMA", "VERIFICATION_SCHEMA", "AuthorityVerification", "LicenceRegisterSnapshot", "RegisterEntry", "licence_register", "verifications_for_plan", "verify_authority"]
