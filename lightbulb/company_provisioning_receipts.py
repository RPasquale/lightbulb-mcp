"""Sealed provisioning receipts: one thin document per instrument outcome, built only from the platform artifact that produced it.

Instruments that do not exist yet cannot be reached through the governed
connector rail, so the platform owns one Company Provisioning Authority that
*mints* an instrument behind an approval task and a journal (a Stripe Connect
account, a site, a phone number) and writes the connector rows the rail then
governs.  Everything after minting is ordinary: an approval-required governed
WRITE with a closed contract (``docusign.create_envelope``,
``airwallex.create_global_account``, ``airwallex.create_beneficiary``) or a
digest-only governed READ (``stripe.observe_account_readiness``,
``square.observe_locations``, ``docusign.observe_envelope_status``,
``airwallex.get_global_account``).

What this module proves, and from which artifact:

* ``platform_receipt`` — from the durable ``lightbulb.company_provisioning_receipt.v1``
  the provisioning authority sealed (the caller strips the one-shot onboarding
  URL before it is ever handed here); it names the approval and the journal that
  authorized the mint, recomputes the receipt's evidence digest, and carries the
  human gates the platform opened.
* ``governed_write_receipt`` — from a SUCCESS
  ``lightbulb.governed_connector_execution_receipt.v1`` whose metadata proves the
  write was governed and approved, and whose output carries the exact closed
  contract of that instrument.
* ``approval_pending_receipt`` — from a HITL_REQUIRED
  ``lightbulb.governed_connector_execution_approval_receipt.v1``: the write is a
  proposal a human has not decided yet.
* ``observation_receipt`` — from a digest-only observation whose
  ``evidence_sha256`` is recomputed here and refused on drift.
* ``booking_verified`` — re-seals a site receipt once a governed
  ``square.observe_locations`` read proved an ACTIVE location.
* ``executed_agreement_evidence`` — turns a COMPLETED envelope observation into
  the executed-agreement custody candidate ``revenue_chain.agreement_receipt``
  consumes, so a signed contract becomes revenue only through the counterparty's
  own act.

What it hands on: sealed ``lightbulb.company_provisioning_receipt.v1``
documents for the per-instrument lifecycle and the launch gate that runs before
``verify_connectors``, and the custody candidate the revenue chain accepts.

Hard boundary: no credential, identity, bank material, one-shot URL, or platform
id is accepted; provider ids never appear in an ``instrument_ref`` (digest
prefixes only); every human step is *named*, never performed; nothing here
reads, writes, or dispatches anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    reject_secret_like_payload,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

RECEIPT_SCHEMA = "lightbulb.company_provisioning_receipt.v1"
PLATFORM_RECEIPT_SCHEMA = "lightbulb.company_provisioning_receipt.v1"
GOVERNED_RECEIPT_SCHEMA = "lightbulb.governed_connector_execution_receipt.v1"
APPROVAL_RECEIPT_SCHEMA = "lightbulb.governed_connector_execution_approval_receipt.v1"
CUSTODY_CANDIDATE_SCHEMA = "lightbulb.commercial_legal_handoff_custody_candidate.v1"
CORRELATION_PREFIX = "LB-PRV"
PLATFORM_SOURCE_TOOL = "POST /api/companies/{companyId}/provisioning"

MAX_HUMAN_STEPS = 4
MAX_FACTS = 24
MAX_EVIDENCE_REFS = 20

InstrumentKind = Literal["payments", "web_presence", "phone", "esign", "treasury_account", "payee", "registration"]
Lane = Literal["platform_approval", "governed_write", "governed_read", "operator_attestation"]
Disposition = Literal["provisioned", "partial", "awaiting_approval", "awaiting_human", "observed_active", "observed_inactive", "prepared_only", "refused"]
HumanGateKind = Literal["stripe_hosted_onboarding", "custom_domain_dns", "square_location_setup", "twilio_regulatory_bundle", "sms_registration", "counterparty_signature", "beneficiary_verification", "registrar_filing", "tax_registration"]
HumanActor = Literal["owner", "director", "signer", "accountant", "operator", "company_representative", "counterparty"]

INSTRUMENTS: tuple[str, ...] = ("payments", "web_presence", "phone", "esign", "treasury_account", "payee", "registration")
LANES: tuple[str, ...] = ("platform_approval", "governed_write", "governed_read", "operator_attestation")
DISPOSITIONS: tuple[str, ...] = ("provisioned", "partial", "awaiting_approval", "awaiting_human", "observed_active", "observed_inactive", "prepared_only", "refused")

# The fixed (actor, action, legal basis) of every named human step; the platform opens the gate, a person closes it.
HUMAN_STEP_TEXT: dict[str, tuple[str, str, str]] = {
    "stripe_hosted_onboarding": ("company_representative", "complete Stripe hosted onboarding: identity, bank account, Stripe Connected Account Agreement", "KYC/KYB and the ToS are the account owner's to complete"),
    "custom_domain_dns": ("operator", "point DNS at the registrar and provision TLS", "no DNS or registrar connector exists"),
    "square_location_setup": ("company_representative", "create the location and enable online booking in the Square dashboard", "the platform grant lacks MERCHANT_PROFILE_WRITE"),
    "twilio_regulatory_bundle": ("company_representative", "complete the Twilio regulatory bundle / address", "provider-reviewed identity documents"),
    "sms_registration": ("company_representative", "complete 10DLC/CNAM registration", "carrier registration requires the business's documents"),
    "counterparty_signature": ("counterparty", "sign the envelope", "the signature is the counterparty's act"),
    "beneficiary_verification": ("accountant", "verify the beneficiary's bank details out of band", "an approver who is not the proposer confirms payee bank details"),
    "registrar_filing": ("director", "lodge the incorporation or registration with the registrar", "nothing here files with a registrar"),
    "tax_registration": ("director", "lodge the tax registration with the revenue authority", "a director or registered agent lodges the registration"),
}

# The platform instrument name each SDK instrument kind is minted under.
PLATFORM_INSTRUMENTS: dict[str, str] = {"payments": "stripe_connect_account", "web_presence": "site", "phone": "phone_number"}
PLATFORM_STATUSES: dict[str, str] = {"PROVISIONED": "provisioned", "PARTIAL": "partial"}
# Live-only or identity fields the SDK never sees; the caller strips the one-shot URL before sealing.
LIVE_ONLY_KEYS: tuple[str, ...] = ("onboardingUrl", "tenantId", "companyId", "userId", "sid", "twilioSid")

WRITE_TOOLS: dict[str, str] = {"esign": "docusign.create_envelope", "treasury_account": "airwallex.create_global_account", "payee": "airwallex.create_beneficiary"}
WRITE_OUTPUT_SCHEMAS: dict[str, str] = {"esign": "lightbulb.docusign_envelope_send_receipt.v1", "treasury_account": "lightbulb.airwallex_global_account.v1", "payee": "lightbulb.airwallex_beneficiary.v1"}
REF_SHA_KEY: dict[str, str] = {"esign": "envelope_id_sha256", "treasury_account": "global_account_id_sha256", "payee": "beneficiary_id_sha256"}
BANK_MATERIAL_KEYS: tuple[str, ...] = ("account_number", "account_routing", "swift_code", "iban")
URL_KEYS: tuple[str, ...] = ("url",)

OBSERVATION_SCHEMAS: dict[str, str] = {"payments": "lightbulb.stripe_account_readiness_observation.v1", "web_presence": "lightbulb.square_location_page.v1", "esign": "lightbulb.docusign_envelope_observation.v1", "treasury_account": "lightbulb.airwallex_global_account_observation.v1"}
OBSERVER_TOOLS: dict[str, str] = {"payments": "stripe.observe_account_readiness", "web_presence": "square.observe_locations", "esign": "docusign.observe_envelope_status", "treasury_account": "airwallex.get_global_account"}
OBSERVATION_REF_KEYS: dict[str, str] = {"payments": "account_id_sha256", "web_presence": "merchant_ref_sha256", "esign": "envelope_id_sha256", "treasury_account": "global_account_id_sha256"}
DISPOSITION_MAPS: dict[str, dict[str, str]] = {
    "payments": {"READY": "observed_active", "ONBOARDING_PENDING": "awaiting_human", "RESTRICTED": "observed_inactive", "REJECTED": "observed_inactive", "NOT_FOUND": "refused"},
    "esign": {"COMPLETED": "observed_active", "SENT": "awaiting_human", "DELIVERED": "awaiting_human", "CREATED": "awaiting_human", "DECLINED": "observed_inactive", "VOIDED": "observed_inactive", "NOT_FOUND": "refused"},
    "treasury_account": {"ACTIVE": "observed_active", "INACTIVE": "observed_inactive", "NOT_FOUND": "refused"},
}
# The instrument-ref prefix per kind; a provider id is never carried, only the digest's first 24 hex.
REF_PREFIXES: dict[str, str] = {"payments": "stripe-account", "web_presence": "merchant", "esign": "envelope", "treasury_account": "global-account", "payee": "beneficiary"}
# The exact instrument_ref a platform mint must carry: (prefix, the receipt field it derives from, take the first 24 hex of that digest).
PLATFORM_REF_SOURCES: dict[str, tuple[str, str, bool]] = {"payments": ("stripe-account", "accountIdSha256", True), "web_presence": ("site", "siteProjectRef", False), "phone": ("phone", "phoneNumber", False)}
GATE_STATUSES: tuple[str, ...] = ("not_required", "not_started", "pending", "satisfied")


class ProvisioningError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ProvisioningError(code, message)


class HumanStep(StrictModel):
    """A legally-human step the platform names and never performs."""

    kind: HumanGateKind
    actor: HumanActor
    action: BoundedText
    legal_basis: ShortText
    status: Literal["not_required", "not_started", "pending", "satisfied"]
    expires_at: str | None = None

    @field_validator("expires_at")
    @classmethod
    def _expiry(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="expires_at")


class ProvisioningReceipt(StrictModel):
    """One sealed provisioning outcome: digests, dispositions, and named human steps only."""

    schema_id: str = Field(default=RECEIPT_SCHEMA, alias="schema")
    instrument: InstrumentKind
    provider: ShortText
    lane: Lane
    source_tool: ShortText | None = None
    disposition: Disposition
    journal_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    correlation_sha256: Sha256Digest | None = None
    instrument_ref: OpaqueRef | None = None
    instrument_sha256: Sha256Digest | None = None
    evidence_sha256: Sha256Digest
    provider_output_sha256: Sha256Digest | None = None
    human_steps: tuple[HumanStep, ...] = Field(default_factory=tuple, max_length=MAX_HUMAN_STEPS)
    facts: dict[str, str | int | bool | None] = Field(default_factory=dict, max_length=MAX_FACTS)
    observed_at: str
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=MAX_EVIDENCE_REFS)
    receipt_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("schema_id")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != RECEIPT_SCHEMA:
            raise ValueError(f"schema must be {RECEIPT_SCHEMA}")
        return value

    @field_validator("human_steps", "evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ProvisioningReceipt:
        if self.disposition == "awaiting_human" and not any(step.status == "pending" for step in self.human_steps):
            raise ValueError("awaiting_human must name at least one pending human step")
        if self.disposition in ("provisioned", "observed_active") and self.instrument_sha256 is None:
            raise ValueError(f"{self.disposition} must commit the instrument it provisioned")
        if self.disposition == "awaiting_approval":
            if self.approval_ref is None or self.journal_ref is not None:
                raise ValueError("awaiting_approval names the approval and no journal; nothing was dispatched")
        elif self.lane == "governed_write" and (self.journal_ref is None or self.approval_ref is None or self.source_tool is None):
            raise ValueError("a governed write names its journal, its approval task, and the tool that ran")
        if self.lane == "governed_read" and (self.source_tool is None or self.approval_ref is not None):
            raise ValueError("a governed read names its observer tool and carries no approval")
        if self.lane == "platform_approval" and (self.approval_ref is None or self.journal_ref is None):
            raise ValueError("a platform mint names the approval task and the provisioning journal")
        if self.lane == "operator_attestation" and self.provider not in ("ato", "cra"):
            raise ValueError("an operator attestation is admitted only for a named revenue authority")
        if not skip_digests(info) and self.receipt_digest != sealed_digest(ProvisioningReceipt, self, "receipt_digest"):
            raise ValueError("receipt_digest must commit the exact normalized receipt")
        return self


def _seal(payload: Mapping[str, Any]) -> ProvisioningReceipt:
    return seal(ProvisioningReceipt, payload, "receipt_digest")


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _digest(raw: Mapping[str, Any], key: str, code: str) -> str:
    value = raw.get(key)
    _require(isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value), code, f"{key} must be a sha256 digest")
    return str(value)


def _reject_nested_keys(payload: Any, keys: tuple[str, ...], code: str, label: str) -> None:
    """Refuse a banned key at *any* depth; a nested bank block or identity is still bank material."""

    banned = set(keys)
    found: set[str] = set()
    stack: list[Any] = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, Mapping):
            for key, item in node.items():
                if str(key) in banned:
                    found.add(str(key))
                stack.append(item)
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    _require(not found, code, f"{', '.join(sorted(found))} is {label} and never reaches the SDK")


def _human_steps(gates: Any, *, expires_at: str | None = None) -> tuple[dict[str, Any], ...]:
    steps: list[dict[str, Any]] = []
    for gate in list(gates or []):
        raw = dict(detached(gate))
        kind = str(raw.get("kind"))
        _require(kind in HUMAN_STEP_TEXT, "PLATFORM_GATE_UNKNOWN", f"human gate {kind!r} is outside the named set")
        actor, action, legal_basis = HUMAN_STEP_TEXT[kind]
        owner = str(raw.get("owner") or actor)
        _require(owner == actor, "PLATFORM_GATE_ACTOR_MISMATCH", f"gate {kind!r} names {owner!r}; only {actor!r} may perform it, and no artifact reassigns that")
        status = str(raw.get("status") or "not_started")
        _require(status in GATE_STATUSES, "PLATFORM_GATE_STATUS_UNKNOWN", f"gate status {status!r} is outside the named set")
        steps.append({"kind": kind, "actor": actor, "action": action, "legal_basis": legal_basis, "status": status, "expires_at": expires_at if kind == "stripe_hosted_onboarding" else None})
    _require(len(steps) <= MAX_HUMAN_STEPS, "PLATFORM_GATES_UNBOUNDED", f"a receipt carries at most {MAX_HUMAN_STEPS} human steps")
    return tuple(steps)


def _platform_instrument_ref(raw: Mapping[str, Any], instrument: str) -> str:
    """Re-derive the instrument reference from the receipt's own instrument facts.

    ``instrument`` sits in the platform receipt's envelope and is therefore outside the
    evidence digest, so a receipt minted for one instrument could otherwise be relabelled
    as another and still verify.  Deriving the reference from the fields only that
    instrument carries ties the receipt back to its kind.
    """

    prefix, source_key, digest_prefixed = PLATFORM_REF_SOURCES[instrument]
    claimed = _text(raw.get("instrumentRef"))
    _require(isinstance(claimed, str) and claimed.startswith(f"{prefix}:"), "PLATFORM_INSTRUMENT_REF_MISMATCH", f"a {instrument} mint carries a {prefix}: reference, not {claimed!r}")
    claimed = str(claimed)
    source = raw.get(source_key)
    if digest_prefixed:
        derived = f"{prefix}:{_digest(raw, source_key, 'PLATFORM_INSTRUMENT_REF_MISMATCH')[:24]}"
    elif source is None:
        # SiteInstrument falls back to a 24-hex session digest when a site has no project ref.
        tail = claimed.split(":", 1)[1]
        _require(instrument == "web_presence" and len(tail) == 24 and all(character in "0123456789abcdef" for character in tail), "PLATFORM_INSTRUMENT_REF_MISMATCH", f"{source_key} is absent and no digest stands in for it")
        return claimed
    else:
        derived = f"{prefix}:{source}"
    _require(claimed == derived, "PLATFORM_INSTRUMENT_REF_MISMATCH", f"{claimed!r} is not the reference {source_key} derives")
    return claimed


# --------------------------------------------------------------------------- #
# Receipts from the platform artifacts
# --------------------------------------------------------------------------- #


def platform_receipt(receipt: Mapping[str, Any] | Any, *, instrument: Literal["payments", "web_presence", "phone"]) -> ProvisioningReceipt:
    """From the durable company-provisioning receipt Spring sealed when it minted the instrument."""

    raw = dict(detached(receipt))
    _require(raw.get("schema") == PLATFORM_RECEIPT_SCHEMA, "PLATFORM_RECEIPT_SCHEMA_MISMATCH", f"expected a {PLATFORM_RECEIPT_SCHEMA} document")
    _reject_nested_keys(raw, LIVE_ONLY_KEYS, "LIVE_FIELD_NOT_ACCEPTED", "live-only or an identity field")
    _reject_nested_keys(raw, BANK_MATERIAL_KEYS, "BANK_MATERIAL_NOT_ACCEPTED", "bank material")
    reject_secret_like_payload(raw, path="provisioning_receipt")
    _require(str(raw.get("instrument")) == PLATFORM_INSTRUMENTS[instrument], "PLATFORM_INSTRUMENT_MISMATCH", f"the receipt is for {raw.get('instrument')!r}, not {PLATFORM_INSTRUMENTS[instrument]!r}")
    status = str(raw.get("status"))
    _require(status in PLATFORM_STATUSES, "PLATFORM_NOT_PROVISIONED", f"the provisioning journal is {status}; only PROVISIONED or PARTIAL seals a receipt")
    _require(bool(raw.get("approvalRef")) and bool(raw.get("journalId")), "PLATFORM_UNAPPROVED", "a minted instrument names the approval task that authorized it and the journal that recorded it")
    _digest(raw, "approvedBySha256", "PLATFORM_UNAPPROVED")
    evidence = _digest(raw, "evidenceSha256", "EVIDENCE_DIGEST_MISMATCH")
    _require(evidence == stable_digest({key: value for key, value in raw.items() if key not in _PLATFORM_ENVELOPE_KEYS}), "EVIDENCE_DIGEST_MISMATCH", "the receipt's evidence digest does not commit its own instrument facts")

    _require(bool(raw.get("provider")), "PLATFORM_RECEIPT_SCHEMA_MISMATCH", "the receipt must name the provider that minted the instrument")
    _require(bool(raw.get("provisionedAt")), "PLATFORM_RECEIPT_SCHEMA_MISMATCH", "the receipt must carry the moment the instrument was minted")
    instrument_ref = _platform_instrument_ref(raw, instrument)
    _digest(raw, "instrumentRefSha256", "PLATFORM_INSTRUMENT_REF_MISMATCH")

    steps = _human_steps(raw.get("humanGates"), expires_at=_text(raw.get("onboardingExpiresAt")))
    # ``humanGates`` and ``status`` sit in the receipt envelope, so the evidence digest -- which
    # the provisioning authority takes over the instrument facts alone -- does not commit them.
    # Both are therefore held against what each instrument is documented to emit, so neither can
    # be edited into a stronger claim than the mint actually made.
    _require(
        instrument != "payments"
        or any(step["kind"] == "stripe_hosted_onboarding" and step["status"] == "pending" for step in steps),
        "PLATFORM_ONBOARDING_GATE_MISSING",
        "a minted Stripe account always hands hosted onboarding back to its owner; only stripe.observe_account_readiness may call it ready",
    )
    _require(
        instrument != "phone"
        or status == "PARTIAL"
        or not any(step["kind"] == "sms_registration" and step["status"] == "pending" for step in steps),
        "PLATFORM_STATUS_CONTRADICTS_GATE",
        "a number whose 10DLC/CNAM registration is still pending is PARTIAL, never PROVISIONED",
    )
    disposition = PLATFORM_STATUSES[status]
    if instrument == "payments" and any(step["status"] == "pending" for step in steps):
        disposition = "awaiting_human"
    payload = {
        "instrument": instrument,
        "provider": str(raw["provider"]),
        "lane": "platform_approval",
        "source_tool": PLATFORM_SOURCE_TOOL,
        "disposition": disposition,
        "journal_ref": f"journal:{raw['journalId']}",
        "approval_ref": f"approval:{raw['approvalRef']}",
        "instrument_ref": instrument_ref,
        "instrument_sha256": _text(raw.get("instrumentRefSha256")),
        "evidence_sha256": evidence,
        "human_steps": steps,
        "facts": _PLATFORM_FACTS[instrument](raw),
        "observed_at": str(raw["provisionedAt"]),
        "evidence_refs": [f"journal:{raw['journalId']}", f"approval:{raw['approvalRef']}", f"evidence:{evidence[:24]}"],
    }
    return _seal(payload)


_PLATFORM_ENVELOPE_KEYS = frozenset({"schema", "instrument", "provider", "custody", "status", "journalId", "approvalRef", "approvedBySha256", "requestSha256", "humanGates", "provisionedAt", "evidenceSha256"})


def _payments_facts(raw: Mapping[str, Any]) -> dict[str, Any]:
    account_ref = _text(raw.get("accountRef"))
    _require(account_ref is None or "acct_" not in account_ref, "PLATFORM_PROVIDER_ID_NOT_ACCEPTED", "accountRef is an operator alias or a digest, never the live Stripe account id")
    return {"account_ref": account_ref, "charges_enabled": bool(raw.get("chargesEnabled")), "payouts_enabled": bool(raw.get("payoutsEnabled")), "details_submitted": bool(raw.get("detailsSubmitted")), "currently_due_count": int(raw.get("currentlyDueCount") or 0), "country": _text(raw.get("country")), "livemode": bool(raw.get("livemode")), "onboarding_expires_at": _text(raw.get("onboardingExpiresAt"))}


def _web_presence_facts(raw: Mapping[str, Any]) -> dict[str, Any]:
    booking = dict(raw.get("booking") or {})
    return {"published_url": _text(raw.get("publishedUrl")), "subdomain": _text(raw.get("subdomain")), "page_count": int(raw.get("pageCount") or 0), "pages_failed": int(raw.get("pagesFailed") or 0), "release_number": int(raw.get("releaseNumber") or 0), "booking_provider": _text(booking.get("provider")), "booking_url": _text(booking.get("bookingUrl")), "booking_location_verified": bool(booking.get("locationVerified")), "custom_domain": _text(raw.get("customDomain"))}


def _phone_facts(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {"phone_number": _text(raw.get("phoneNumber")), "channel": _text(raw.get("channel")), "country_code": _text(raw.get("countryCode")), "routing": _text(raw.get("routing")), "estimated_monthly_cost_minor": int(raw.get("estimatedMonthlyCostMinor") or 0), "estimate_currency": _text(raw.get("estimateCurrency"))}


_PLATFORM_FACTS = {"payments": _payments_facts, "web_presence": _web_presence_facts, "phone": _phone_facts}


def governed_write_receipt(receipt: Mapping[str, Any] | Any, *, instrument: Literal["esign", "treasury_account", "payee"]) -> ProvisioningReceipt:
    """From a SUCCESS governed connector execution receipt whose output carries the instrument's closed contract."""

    raw = dict(detached(receipt))
    _require(raw.get("schema") == GOVERNED_RECEIPT_SCHEMA, "RECEIPT_SCHEMA_MISMATCH", f"expected a {GOVERNED_RECEIPT_SCHEMA} document")
    _reject_nested_keys(raw, LIVE_ONLY_KEYS, "LIVE_FIELD_NOT_ACCEPTED", "live-only or an identity field")
    output = dict(raw.get("output") or {})
    _reject_nested_keys(output, BANK_MATERIAL_KEYS, "BANK_MATERIAL_NOT_ACCEPTED", "bank material")
    _reject_nested_keys(output, URL_KEYS, "URL_NOT_ACCEPTED", "a live provider link")
    reject_secret_like_payload(raw, path="execution_receipt")
    _require(str(raw.get("status")) == "SUCCESS", "WRITE_NOT_SUCCEEDED", f"the execution is {raw.get('status')}; only a succeeded write seals an instrument")
    metadata = dict(raw.get("metadata") or {})
    _require(metadata.get("governed") is True and str(metadata.get("serverEffect")) == "write", "WRITE_NOT_GOVERNED", "only a governed server-effect write seals an instrument")
    approval_task = str(metadata.get("approvalTaskId") or "").strip()
    _require(bool(approval_task), "WRITE_NOT_APPROVED", "a provisioning write names the approval task a human decided")
    _require(str(output.get("schema")) == WRITE_OUTPUT_SCHEMAS[instrument], "RESULT_SCHEMA_MISMATCH", f"expected a {WRITE_OUTPUT_SCHEMAS[instrument]} output")
    instrument_sha = _digest(output, REF_SHA_KEY[instrument], "RESULT_SCHEMA_MISMATCH")
    journal_id = str(raw.get("journalId") or "").strip()
    _require(bool(journal_id), "WRITE_NOT_GOVERNED", "a governed write is recorded in an execution journal")
    provenance = dict(raw.get("provenance") or {})
    observed_at = provenance.get("completed_at") or output.get("sent_at") or output.get("created_at")
    _require(observed_at is not None, "RESULT_SCHEMA_MISMATCH", "the output must carry the provider timestamp its contract declares")

    steps: tuple[dict[str, Any], ...] = ()
    disposition = "provisioned"
    if instrument == "esign":
        actor, action, legal_basis = HUMAN_STEP_TEXT["counterparty_signature"]
        steps = ({"kind": "counterparty_signature", "actor": actor, "action": action, "legal_basis": legal_basis, "status": "pending"},)
        disposition = "awaiting_human"
    evidence = stable_digest({"journal": journal_id, "output": output})
    payload = {
        "instrument": instrument,
        "provider": WRITE_TOOLS[instrument].split(".", 1)[0],
        "lane": "governed_write",
        "source_tool": WRITE_TOOLS[instrument],
        "disposition": disposition,
        "journal_ref": f"journal:{journal_id}",
        "approval_ref": f"approval:{approval_task}",
        "correlation_sha256": _text(output.get("correlation_sha256")),
        "instrument_ref": f"{REF_PREFIXES[instrument]}:{instrument_sha[:24]}",
        "instrument_sha256": instrument_sha,
        "evidence_sha256": evidence,
        "provider_output_sha256": stable_digest(output),
        "human_steps": steps,
        "facts": _WRITE_FACTS[instrument](output),
        "observed_at": str(observed_at),
        "evidence_refs": [f"journal:{journal_id}", f"approval:{approval_task}", f"evidence:{evidence[:24]}"],
    }
    return _seal(payload)


_WRITE_FACTS = {
    "esign": lambda output: {"status": _text(output.get("status")), "signer_count": int(output.get("signer_count") or 0), "sent_at": _text(output.get("sent_at")), "document_sha256": _text(output.get("document_sha256"))},
    "treasury_account": lambda output: {"status": _text(output.get("status")), "country_code": _text(output.get("country_code")), "currency": _text(output.get("currency")), "nick_name": _text(output.get("nick_name")), "bank_name": _text(output.get("bank_name"))},
    "payee": lambda output: {"nickname": _text(output.get("nickname")), "entity_type": _text(output.get("entity_type")), "bank_country_code": _text(output.get("bank_country_code")), "account_currency": _text(output.get("account_currency")), "account_number_last4": _text(output.get("account_number_last4")), "payment_method": _text(output.get("payment_method"))},
}


def approval_pending_receipt(approval_receipt: Mapping[str, Any] | Any, *, instrument: InstrumentKind, source_tool: str, proposed_at: str) -> ProvisioningReceipt:
    """From a HITL_REQUIRED proposal receipt: the write waits on a human, and nothing was dispatched.

    Spring's proposal receipt carries no timestamp, so ``proposed_at`` is an explicit
    operator input; the sealed receipt names it as such in ``facts.observed_at_source``.
    """

    raw = dict(detached(approval_receipt))
    _require(raw.get("schema") == APPROVAL_RECEIPT_SCHEMA and str(raw.get("status")) == "HITL_REQUIRED", "APPROVAL_RECEIPT_MISMATCH", f"expected a HITL_REQUIRED {APPROVAL_RECEIPT_SCHEMA} document")
    _reject_nested_keys(raw, LIVE_ONLY_KEYS, "LIVE_FIELD_NOT_ACCEPTED", "live-only or an identity field")
    reject_secret_like_payload(raw, path="approval_receipt")
    approval_status = str(raw.get("approvalStatus"))
    _require(approval_status != "CONSUMED", "APPROVAL_CONSUMED", "this exact connector approval has already been consumed; propose again rather than replaying it")
    _require(approval_status == "PENDING", "APPROVAL_NOT_PENDING", f"the approval task is {approval_status}; only a pending proposal seals an awaiting_approval receipt")
    _require(bool(raw.get("approvalRef")), "APPROVAL_RECEIPT_MISMATCH", "a proposal names the approval task a human must decide")
    tool = str(source_tool).strip()
    _require(tool in set(WRITE_TOOLS.values()), "APPROVAL_RECEIPT_MISMATCH", f"source_tool must name one of the provisioning write tools {sorted(set(WRITE_TOOLS.values()))}; a governed read is never proposed")
    _require(instrument not in WRITE_TOOLS or tool == WRITE_TOOLS[instrument], "APPROVAL_RECEIPT_MISMATCH", f"a {instrument} proposal runs {WRITE_TOOLS.get(instrument)!r}, not {tool!r}")
    proposed_tool = dict(raw.get("output") or {}).get("tool")
    _require(proposed_tool is None or str(proposed_tool) == tool, "APPROVAL_RECEIPT_MISMATCH", f"the proposal is for {proposed_tool!r}, not {tool!r}")
    evidence = _digest(raw, "approvalReceiptDigest", "APPROVAL_RECEIPT_MISMATCH")
    payload = {
        "instrument": instrument,
        "provider": tool.split(".", 1)[0],
        "lane": "governed_write",
        "source_tool": tool,
        "disposition": "awaiting_approval",
        "approval_ref": f"approval:{raw['approvalRef']}",
        "evidence_sha256": evidence,
        "facts": {"approval_status": approval_status, "message": _text(raw.get("message")), "observed_at_source": "operator_supplied"},
        "observed_at": str(proposed_at),
        "evidence_refs": [f"approval:{raw['approvalRef']}", f"proposal:{evidence[:24]}"],
    }
    return _seal(payload)


def observation_receipt(observation: Mapping[str, Any] | Any, *, instrument: Literal["payments", "web_presence", "esign", "treasury_account"], correlation_sha256: str | None = None) -> ProvisioningReceipt:
    """From a digest-only governed read; the evidence digest is recomputed here and drift is refused."""

    raw = dict(detached(observation))
    _require(raw.get("schema") == OBSERVATION_SCHEMAS[instrument], "OBSERVATION_SCHEMA_MISMATCH", f"expected a {OBSERVATION_SCHEMAS[instrument]} observation")
    _reject_nested_keys(raw, LIVE_ONLY_KEYS, "LIVE_FIELD_NOT_ACCEPTED", "live-only or an identity field")
    _reject_nested_keys(raw, BANK_MATERIAL_KEYS, "BANK_MATERIAL_NOT_ACCEPTED", "bank material")
    _reject_nested_keys(raw, URL_KEYS, "URL_NOT_ACCEPTED", "a live provider link")
    reject_secret_like_payload(raw, path="observation")
    evidence = _digest(raw, "evidence_sha256", "EVIDENCE_DIGEST_MISMATCH")
    _require(evidence == stable_digest({key: value for key, value in raw.items() if key not in ("evidence_sha256", "observed_at")}), "EVIDENCE_DIGEST_MISMATCH", "the observation's evidence digest does not commit its own fields")
    if correlation_sha256 is not None:
        _require(str(raw.get("correlation_sha256")) == str(correlation_sha256), "CORRELATION_MISMATCH", "the observation does not carry the expected correlation")
    _require(bool(raw.get("observed_at")), "OBSERVATION_SCHEMA_MISMATCH", "an observation names the moment it was taken")
    if instrument == "web_presence":
        locations = [dict(detached(row)) for row in list(raw.get("locations") or [])]
        active = sum(1 for row in locations if str(row.get("status")) == "ACTIVE")
        _require(int(raw.get("active_count") or 0) == active and int(raw.get("record_count") or 0) == len(locations), "OBSERVATION_COUNT_MISMATCH", "the page's counts do not match the location records it carries")
        disposition = "observed_active" if active >= 1 else "observed_inactive"
    else:
        provider_disposition = str(raw.get("disposition"))
        _require(provider_disposition in DISPOSITION_MAPS[instrument], "OBSERVATION_DISPOSITION_UNKNOWN", f"{provider_disposition!r} is outside the documented disposition set")
        disposition = DISPOSITION_MAPS[instrument][provider_disposition]
    _require(disposition != "refused", "INSTRUMENT_NOT_FOUND", "the governed read found no such instrument")
    instrument_sha = _digest(raw, OBSERVATION_REF_KEYS[instrument], "OBSERVATION_SCHEMA_MISMATCH")
    steps: tuple[dict[str, Any], ...] = ()
    if disposition == "awaiting_human":
        kind = "stripe_hosted_onboarding" if instrument == "payments" else "counterparty_signature"
        actor, action, legal_basis = HUMAN_STEP_TEXT[kind]
        steps = ({"kind": kind, "actor": actor, "action": action, "legal_basis": legal_basis, "status": "pending"},)
    payload = {
        "instrument": instrument,
        "provider": OBSERVER_TOOLS[instrument].split(".", 1)[0],
        "lane": "governed_read",
        "source_tool": OBSERVER_TOOLS[instrument],
        "disposition": disposition,
        "correlation_sha256": _text(raw.get("correlation_sha256")),
        "instrument_ref": f"{REF_PREFIXES[instrument]}:{instrument_sha[:24]}",
        "instrument_sha256": instrument_sha,
        "evidence_sha256": evidence,
        "provider_output_sha256": stable_digest(raw),
        "human_steps": steps,
        "facts": _OBSERVATION_FACTS[instrument](raw),
        "observed_at": str(raw["observed_at"]),
        "evidence_refs": [f"observation:{evidence[:24]}"],
    }
    return _seal(payload)


_OBSERVATION_FACTS = {
    "payments": lambda raw: {"charges_enabled": bool(raw.get("charges_enabled")), "payouts_enabled": bool(raw.get("payouts_enabled")), "details_submitted": bool(raw.get("details_submitted")), "currently_due_count": int(raw.get("currently_due_count") or 0), "past_due_count": int(raw.get("past_due_count") or 0), "country": _text(raw.get("country")), "default_currency": _text(raw.get("default_currency"))},
    "esign": lambda raw: {"status": _text(raw.get("status")), "signer_count": int(raw.get("signer_count") or 0), "signers_completed": int(raw.get("signers_completed") or 0), "completed_at": _text(raw.get("completed_at"))},
    "web_presence": lambda raw: {"active_count": int(raw.get("active_count") or 0), "record_count": int(raw.get("record_count") or 0)},
    "treasury_account": lambda raw: {"status": _text(raw.get("status")), "country_code": _text(raw.get("country_code")), "currency": _text(raw.get("currency"))},
}


def booking_verified(site_receipt: ProvisioningReceipt, location_observation: ProvisioningReceipt) -> ProvisioningReceipt:
    """Re-seal a site receipt once a governed ``square.observe_locations`` read proved an ACTIVE location."""

    _require(site_receipt.instrument == "web_presence" and site_receipt.lane == "platform_approval", "BOOKING_RECEIPT_MISMATCH", "booking verification re-seals the minted site receipt")
    _require(location_observation.instrument == "web_presence" and location_observation.lane == "governed_read", "BOOKING_OBSERVATION_MISMATCH", f"expected a {OBSERVER_TOOLS['web_presence']} observation receipt")
    opened = [step for step in site_receipt.human_steps if step.kind == "square_location_setup" and step.status != "not_required"]
    _require(bool(opened), "BOOKING_RECEIPT_MISMATCH", "the minted site opened no Square booking gate; an ACTIVE location verifies nothing")
    booking_provider = site_receipt.facts.get("booking_provider")
    _require(str(booking_provider) == "square", "BOOKING_PROVIDER_MISMATCH", f"the site books through {booking_provider!r}; a square.observe_locations page proves nothing about it")
    _require(location_observation.disposition == "observed_active", "LOCATION_NOT_ACTIVE", "no ACTIVE Square location was observed; the booking location stays unverified")
    steps = [{**step.to_dict(), "status": "satisfied"} if step.kind == "square_location_setup" else step.to_dict() for step in site_receipt.human_steps]
    refs = [*site_receipt.evidence_refs, f"observation:{location_observation.evidence_sha256[:24]}"]
    payload = {**site_receipt.to_dict(), "facts": {**site_receipt.facts, "booking_location_verified": True}, "human_steps": steps, "evidence_refs": [ref for index, ref in enumerate(refs) if ref not in refs[:index]]}
    payload.pop("receipt_digest", None)
    return _seal(payload)


def executed_agreement_evidence(envelope_receipt: ProvisioningReceipt, *, contract_ref: str, contract_revision: int = 1, document_kind: str = "msa") -> dict[str, Any]:
    """An observed completed envelope, awaiting full legal custody reconciliation.

    A signer count cannot establish signer identities, signed document digests,
    reviewed terms or independently accepted value. This is not a revenue-chain
    custody candidate and must never manufacture one from those counts.
    """

    _require(envelope_receipt.instrument == "esign" and envelope_receipt.lane == "governed_read", "AGREEMENT_NOT_EXECUTED", "an executed agreement comes from a governed envelope observation")
    _require(int(contract_revision) >= 1, "AGREEMENT_REVISION_INVALID", "a contract revision starts at 1")
    completed_at = envelope_receipt.facts.get("completed_at")
    signers = int(envelope_receipt.facts.get("signers_completed") or 0)
    _require(envelope_receipt.disposition == "observed_active" and bool(completed_at) and signers >= 1, "AGREEMENT_NOT_EXECUTED", f"the envelope is {envelope_receipt.disposition} with {signers} completed signers; the counterparty has not signed")
    return {
        "schema": "lightbulb.company_executed_envelope_evidence.v1",
        "contract_ref": str(contract_ref),
        "contract_revision": int(contract_revision),
        "completed_at": str(completed_at),
        "completed_signer_count": signers,
        "envelope_commitment": envelope_receipt.instrument_sha256,
        "source_receipt": envelope_receipt.to_dict(),
        "requires_legal_custody_reconciliation": True,
        "authoritative_revenue_evidence": False,
    }


def receipt_summary(receipt: ProvisioningReceipt) -> dict[str, Any]:
    return {"instrument": receipt.instrument, "provider": receipt.provider, "lane": receipt.lane, "disposition": receipt.disposition, "instrument_ref": receipt.instrument_ref, "source_tool": receipt.source_tool, "journal_ref": receipt.journal_ref, "approval_ref": receipt.approval_ref, "pending_human_steps": [step.kind for step in receipt.human_steps if step.status == "pending"], "observed_at": receipt.observed_at, "receipt_digest": receipt.receipt_digest}


PROVISIONING_RECEIPT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_provisioning_receipts",
    "instruments": list(INSTRUMENTS),
    "lanes": list(LANES),
    "dispositions": list(DISPOSITIONS),
    "human_gates": sorted(HUMAN_STEP_TEXT),
    "hops": {
        "platform_approval": "the durable company provisioning receipt of an approved mint",
        "governed_write": "a SUCCESS governed connector execution receipt with the instrument's closed output contract",
        "awaiting_approval": "a HITL_REQUIRED governed connector approval receipt",
        "governed_read": "a digest-only observation whose evidence digest is recomputed here",
    },
    "required_connectors": ["stripe", "square", "docusign", "airwallex", "twilio_platform", "lightbulb_pages"],
    "hard_rules": [
        "a receipt is derived only from the platform artifact named by its lane; nothing is asserted by the caller",
        "no credential, identity, bank material, URL, or platform id is accepted; digests and dispositions only",
        "every observation digest is recomputed and drift is refused",
        "human steps are named, never performed",
    ],
}

__all__ = [
    "APPROVAL_RECEIPT_SCHEMA",
    "BANK_MATERIAL_KEYS",
    "CORRELATION_PREFIX",
    "CUSTODY_CANDIDATE_SCHEMA",
    "DISPOSITIONS",
    "DISPOSITION_MAPS",
    "GOVERNED_RECEIPT_SCHEMA",
    "HUMAN_STEP_TEXT",
    "HumanStep",
    "INSTRUMENTS",
    "LANES",
    "LIVE_ONLY_KEYS",
    "OBSERVATION_SCHEMAS",
    "OBSERVER_TOOLS",
    "PLATFORM_REF_SOURCES",
    "PLATFORM_INSTRUMENTS",
    "PLATFORM_RECEIPT_SCHEMA",
    "PLATFORM_SOURCE_TOOL",
    "PROVISIONING_RECEIPT_MANIFEST",
    "ProvisioningError",
    "ProvisioningReceipt",
    "RECEIPT_SCHEMA",
    "WRITE_OUTPUT_SCHEMAS",
    "WRITE_TOOLS",
    "approval_pending_receipt",
    "booking_verified",
    "executed_agreement_evidence",
    "governed_write_receipt",
    "observation_receipt",
    "platform_receipt",
    "receipt_summary",
]
