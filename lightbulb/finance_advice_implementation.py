"""Implementation after approval: the application pack, the provider write as a proposal, the provider's outcome, and the reconciliation of the terms.

Approval is the adviser's act; implementation is the paperwork that follows it. This module
prepares the provider's own application checklist and the documents the client must sign, from
decision facts only; describes any provider write as a governed-write proposal the platform's
approval lane executes (the SDK never contacts a provider); records the provider's outcome as a
receipt with the terms exactly as the provider stated them; and reconciles those terms against
the cited facts the recommendation rested on, so a rate or a fee that came out different triggers
the adviser's acknowledgement or a new recommendation instead of silently standing.

Only the recommended product, under an approval of that exact recommendation, is implemented.
Nothing here advises: every object is arithmetic, a checklist or a receipt, sealed by digest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, TypeAdapter, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, detached, parsed, reject_secret_like_payload, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_catalog import provider_ref as catalog_provider_ref
from lightbulb.finance_advice_engine import ClientState, Recommendation
from lightbulb.finance_advice_record import RecordOfAdviceEvidence

APPLICATION_SCHEMA = "lightbulb.finance_advice_application_pack.v1"
OUTCOME_SCHEMA = "lightbulb.finance_advice_provider_outcome.v1"
RECONCILIATION_SCHEMA = "lightbulb.finance_advice_terms_reconciliation.v1"
WRITE_PROPOSAL_SCHEMA = "lightbulb.finance_advice_provider_write_proposal.v1"

FORBIDDEN_APPLICATION_KEYS: frozenset[str] = frozenset({
    "name", "first_name", "last_name", "full_name", "date_of_birth", "dob", "address", "street", "email", "phone", "mobile",
    "tfn", "tax_file_number", "sin", "social_insurance_number", "ssn", "account_number", "policy_number", "member_number", "bsb", "iban", "card_number",
    "signature", "signature_image", "id_document", "passport", "driver_licence", "drivers_licence", "licence_number", "license_number",
    "tenant_id", "company_id", "user_id",
})
MATERIAL_RATE_DELTA_PP = Decimal("0.05")
RANKED_TERM_ITEMS: frozenset[str] = frozenset({"rate", "comparison rate", "apr", "annual fee", "premium", "benefit", "sum insured"})

OutcomeKind = Literal["submitted", "conditional", "approved", "declined", "settled", "policy_issued", "account_opened", "withdrawn"]
COMPLETING_OUTCOMES: frozenset[str] = frozenset({"approved", "settled", "policy_issued", "account_opened"})
CLOSING_OUTCOMES: frozenset[str] = frozenset({"declined", "withdrawn"})
ItemKind = Literal["form", "document_to_sign", "supporting_evidence", "provider_step", "adviser_step", "client_step"]
ItemWho = Literal["client", "adviser", "provider"]
ItemStatus = Literal["pending", "provided", "signed", "not_required"]
WriteOperation = Literal["submit_application", "request_quote", "cancel_holding"]
ReconciliationVerdict = Literal["as_recommended", "differs", "unassessed"]

_CENTS = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.0001")
_WORDS = re.compile(r"[a-z0-9]+")
_RANKED_WORDS: tuple[frozenset[str], ...] = tuple(frozenset(_WORDS.findall(item)) for item in sorted(RANKED_TERM_ITEMS))
_FORBIDDEN_WORDS: tuple[tuple[str, ...], ...] = tuple(tuple(_WORDS.findall(key.replace("_", " "))) for key in sorted(FORBIDDEN_APPLICATION_KEYS))
# 'name' on its own is a product or provider name as often as a person's; it is refused alone or with one of these in front
_NAME_QUALIFIERS = frozenset({"first", "last", "full", "given", "family", "middle", "applicant", "client", "customer", "borrower", "insured", "holder", "contact", "person", "individual", "guarantor", "beneficiary", "director", "signatory", "spouse", "partner", "dependant", "dependent"})
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[A-Za-z]{2,}")
_OPAQUE_REF = TypeAdapter(OpaqueRef)

# the provider's own application steps, per family; a table the operator extends, never a rule engine
DEFAULT_ITEMS: dict[str, tuple[dict[str, Any], ...]] = {
    "credit": (
        {"key": "application_form", "kind": "form", "label": "The lender's application form", "who": "client", "required": True},
        {"key": "identity_verification", "kind": "adviser_step", "label": "Identity verification, performed outside the platform; nothing identifying enters the pack", "who": "adviser", "required": True},
        {"key": "income_evidence", "kind": "supporting_evidence", "label": "Income evidence the lender asks for", "who": "client", "required": True},
        {"key": "credit_guide_acknowledged", "kind": "client_step", "label": "The credit guide was given and acknowledged", "who": "client", "required": True},
        {"key": "loan_contract", "kind": "document_to_sign", "label": "The loan contract", "who": "client", "required": True},
        {"key": "direct_debit_authority", "kind": "document_to_sign", "label": "The direct debit authority", "who": "client", "required": True},
    ),
    "insurance": (
        {"key": "application_form", "kind": "form", "label": "The insurer's application form", "who": "client", "required": True},
        {"key": "duty_of_disclosure_statement", "kind": "document_to_sign", "label": "The duty of disclosure statement", "who": "client", "required": True},
        {"key": "medical_evidence", "kind": "supporting_evidence", "label": "Medical evidence, where the insurer asks for it", "who": "client", "required": False},
        {"key": "beneficiary_nomination", "kind": "document_to_sign", "label": "The beneficiary nomination", "who": "client", "required": True},
        {"key": "policy_schedule_received", "kind": "provider_step", "label": "The policy schedule issued by the insurer", "who": "provider", "required": True},
    ),
    "investments": (
        {"key": "pds_received", "kind": "client_step", "label": "The product disclosure statement was received before the application", "who": "client", "required": True},
        {"key": "application_form", "kind": "form", "label": "The issuer's application form", "who": "client", "required": True},
        {"key": "risk_profile_acknowledgement", "kind": "document_to_sign", "label": "The risk profile acknowledgement", "who": "client", "required": True},
        {"key": "aml_identification", "kind": "adviser_step", "label": "Anti-money-laundering identification, performed outside the platform", "who": "adviser", "required": True},
        {"key": "registered_plan_election", "kind": "document_to_sign", "label": "The registered plan election", "who": "client", "required": True, "jurisdictions": ("CA",)},
    ),
    "deposits": (
        {"key": "account_application", "kind": "form", "label": "The account application", "who": "client", "required": True},
        {"key": "identification", "kind": "adviser_step", "label": "Identification, performed outside the platform", "who": "adviser", "required": True},
    ),
}


class AdviceImplementationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceImplementationError(code, message)


def _forbidden_key(key: Any) -> bool:
    """A key is refused when a forbidden key appears in it as whole words ('applicant_email', 'bank account number'), not only when it equals one."""

    words = tuple(_WORDS.findall(str(key).lower().replace("_", " ")))
    if not words:
        return False
    for sequence in _FORBIDDEN_WORDS:
        size = len(sequence)
        for start in range(len(words) - size + 1):
            if words[start:start + size] != sequence:
                continue
            if sequence == ("name",) and len(words) > 1 and (start == 0 or words[start - 1] not in _NAME_QUALIFIERS):
                continue
            return True
    return False


def _refuse_personal_data(value: Any, *, path: str) -> None:
    """Decision facts only: a key that names a person, a contact, an identifier or a signature is refused wherever it sits, as is a value that carries an address, a credential or a card-like number."""

    try:
        reject_secret_like_payload(value, path=path)
    except ValueError as exc:
        raise AdviceImplementationError("PERSONAL_DATA_REFUSED", str(exc)) from exc
    _refuse_personal_keys(value, path=path)


def _refuse_personal_keys(value: Any, *, path: str) -> None:
    if isinstance(value, str):
        if _EMAIL.search(value):
            raise AdviceImplementationError("PERSONAL_DATA_REFUSED", f"{path} carries an email address; the pack carries decision facts and opaque refs only")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if _forbidden_key(key):
                raise AdviceImplementationError("PERSONAL_DATA_REFUSED", f"{path}.{key} is personal data; the pack carries decision facts and opaque refs only")
            _refuse_personal_keys(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _refuse_personal_keys(item, path=f"{path}[{index}]")


def _opaque_ref(value: Any, *, field_name: str) -> str:
    """A ref is opaque: it matches the platform's ref shape and never carries an email address."""

    try:
        ref = _OPAQUE_REF.validate_python(value)
    except ValueError as exc:
        raise AdviceImplementationError("REF_INVALID", f"{field_name} is not an opaque ref") from exc
    _refuse_personal_data(ref, path=field_name)
    return ref


def _normalise_item(item: str) -> str:
    return " ".join(_WORDS.findall(str(item).lower().replace("_", " ")))


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = Decimal(str(value).replace(",", "").replace("%", "").replace("$", "").strip())
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() else None


def _normalise_unit(unit: str | None) -> str:
    """Units compare loosely: '% p.a.', '% per annum' and '%pa' are one unit; 'AUD/year' and 'AUD per year' are one unit."""

    text = (unit or "").lower().strip()
    for old, new in (("per annum", "pa"), ("p.a.", "pa"), ("p.a", "pa"), ("per year", "/year"), ("per month", "/month"), ("per week", "/week"), ("per fortnight", "/fortnight"), ("annually", "/year"), ("monthly", "/month")):
        text = text.replace(old, new)
    return re.sub(r"[\s.]+", "", text)


def _units_agree(cited: str | None, stated: str | None) -> bool:
    """Units compare loosely, and a bare '%' agrees with any percentage unit: an offer letter's '5.91%' is the cited '5.91 % p.a.', with the period read from the record."""

    if not cited or not stated:
        return True
    a, b = _normalise_unit(cited), _normalise_unit(stated)
    return a == b or (a == "%" and b.startswith("%")) or (b == "%" and a.startswith("%"))


def _is_rate(item: str, unit: str | None) -> bool:
    words = set(_WORDS.findall(_normalise_item(item)))
    return "%" in (unit or "") or "rate" in words or "apr" in words


def _is_ranked(item: str) -> bool:
    words = frozenset(_WORDS.findall(_normalise_item(item)))
    return any(ranked <= words for ranked in _RANKED_WORDS)


def _tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


# --------------------------------------------------------------------------- #
# The application pack
# --------------------------------------------------------------------------- #


class ApplicationItem(StrictModel):
    """One step of the provider's application, who does it, and where it stands."""

    item_ref: OpaqueRef
    kind: ItemKind
    label: ShortText
    required: bool = True
    who: ItemWho
    source_url: str | None = None
    status: ItemStatus = "pending"

    @model_validator(mode="after")
    def _guard(self) -> ApplicationItem:
        # however the item was built, its text carries no email address, credential or card-like number
        _refuse_personal_data({"label": self.label, "source_url": self.source_url}, path="item")
        return self


class ProviderWriteProposal(StrictModel):
    """A provider write described, never performed: the platform's governed-write lane executes it after its own approval."""

    schema_id: Literal["lightbulb.finance_advice_provider_write_proposal.v1"] = Field(default=WRITE_PROPOSAL_SCHEMA, alias="schema")
    proposal_ref: OpaqueRef
    provider_ref: OpaqueRef
    connector: ShortText | None = None
    operation: WriteOperation
    payload_digest: Sha256Digest
    approval_required: Literal[True] = True
    executes: Literal[False] = False
    performed_by: Literal["platform_governed_write"] = "platform_governed_write"


class RecommendedTerm(StrictModel):
    """A term of the recommended product as the record cited it."""

    item: str
    value: str | None = None
    unit: str | None = None
    fact_ref: str


class ApplicationPack(StrictModel):
    """What implementing the recommended product asks of the client, the adviser and the provider, sealed against the approval."""

    schema_id: Literal["lightbulb.finance_advice_application_pack.v1"] = Field(default=APPLICATION_SCHEMA, alias="schema")
    case_ref: OpaqueRef | None = None
    recommendation_digest: Sha256Digest
    record_digest: Sha256Digest
    approval_ref: OpaqueRef
    product_ref: OpaqueRef
    provider_ref: OpaqueRef
    vertical_id: str
    jurisdiction: str
    family: str
    terms: tuple[RecommendedTerm, ...] = Field(default_factory=tuple)
    decision_facts: dict[str, Any] = Field(default_factory=dict)
    items: tuple[ApplicationItem, ...] = Field(default_factory=tuple)
    signatures_required: tuple[str, ...] = Field(default_factory=tuple)
    client_must_do: tuple[str, ...] = Field(default_factory=tuple)
    write_proposals: tuple[ProviderWriteProposal, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    prepared_at: str
    prepared_by_ref: OpaqueRef
    pack_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("terms", "items", "signatures_required", "client_must_do", "write_proposals", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("decision_facts", mode="before")
    @classmethod
    def _facts(cls, value: Any) -> Any:
        _refuse_personal_data(value, path="decision_facts")
        return value

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ApplicationPack:
        refs = [item.item_ref for item in self.items]
        if len(refs) != len(set(refs)):
            raise ValueError("application items are named once each")
        if any(item.executes or not item.approval_required for item in self.write_proposals):
            raise ValueError("a write proposal never executes and always needs the platform's approval")
        if not skip_digests(info) and self.pack_digest != sealed_digest(ApplicationPack, self, "pack_digest"):
            raise ValueError("pack_digest must commit the exact pack")
        return self

    def item(self, item_ref: str) -> ApplicationItem | None:
        return next((item for item in self.items if item.item_ref == item_ref), None)


def write_proposal(*, provider_ref: str, operation: WriteOperation, payload: Mapping[str, Any], connector: str | None = None) -> ProviderWriteProposal:
    """Describe a provider write for the platform's governed-write lane: the payload is scanned for personal data and only its digest is kept."""

    body = dict(detached(payload))
    _refuse_personal_data({"payload": body, "connector": connector}, path="write_proposal")
    owner = _opaque_ref(provider_ref, field_name="provider_ref")
    digest = stable_digest({"provider_ref": owner, "operation": operation, "connector": connector, "payload": body})
    return ProviderWriteProposal(proposal_ref=f"proposal:{operation}:{digest[:16]}", provider_ref=owner, connector=connector, operation=operation, payload_digest=digest)


def _default_items(family: str, jurisdiction: str) -> list[ApplicationItem]:
    out: list[ApplicationItem] = []
    for row in DEFAULT_ITEMS.get(family, ()):
        jurisdictions = row.get("jurisdictions")
        if jurisdictions and jurisdiction not in jurisdictions:
            continue
        out.append(ApplicationItem(item_ref=f"item:{row['key']}", kind=row["kind"], label=row["label"], required=bool(row.get("required", True)), who=row["who"]))
    return out


def _parse_item(raw: ApplicationItem | Mapping[str, Any]) -> ApplicationItem:
    if isinstance(raw, ApplicationItem):
        return raw
    payload = dict(detached(raw))
    _refuse_personal_data(payload, path="items")
    if "item_ref" not in payload and payload.get("key"):
        payload["item_ref"] = f"item:{payload.pop('key')}"
    return ApplicationItem.model_validate(payload)


def _decision_facts(state: ClientState) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("amount", "lvr_percent", "term_years", "residency", "age_band", "income_band", "purpose", "region"):
        value = getattr(state, key)
        if value not in (None, "", "unstated"):
            out[key] = str(value) if isinstance(value, Decimal) else value
    for key, value in sorted(state.facts.items()):
        if key == "holdings":
            continue
        out[key] = detached(value)
    if state.preferences:
        out["preferences"] = list(state.preferences)
    return out


def application_pack(recommendation: Recommendation | Mapping[str, Any], record: RecordOfAdviceEvidence | Mapping[str, Any], state: ClientState | Mapping[str, Any], *, prepared_at: str, prepared_by_ref: str, items: Sequence[ApplicationItem | Mapping[str, Any]] = (), write_proposals: Sequence[ProviderWriteProposal | Mapping[str, Any]] = (), approval: Mapping[str, Any] | None = None, holdings: Sequence[Mapping[str, Any]] = (), case_ref: str | None = None, provider_ref: str | None = None) -> ApplicationPack:
    """The application pack for the recommended product under an approval of that exact recommendation; every term cites the record."""

    rec = recommendation if isinstance(recommendation, Recommendation) else Recommendation.model_validate(dict(detached(recommendation)))
    rc = record if isinstance(record, RecordOfAdviceEvidence) else RecordOfAdviceEvidence.model_validate(dict(detached(record)))
    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    _refuse_personal_data({"prepared_by_ref": prepared_by_ref, "case_ref": case_ref, "provider_ref": provider_ref}, path="pack")
    approved = dict(detached(approval)) if approval is not None else {}
    _require(bool(approved.get("approval_ref")) and bool(approved.get("adviser_ref")) and approved.get("recommendation_digest") == rec.recommendation_digest, "APPROVAL_MISSING", "implementation follows the licensed adviser's approval of this exact recommendation, naming the approval and the adviser; none was given for it")
    _require(rc.recommendation_digest == rec.recommendation_digest, "RECORD_MISMATCH", "the record of advice was assembled for a different recommendation")
    _require(rc.state_digest == s.state_digest and rec.state_digest == s.state_digest, "STATE_MISMATCH", "the record and the recommendation rest on a different client state")
    _require(rc.recommended is not None and rc.recommended.product_ref == rec.primary_product_ref, "RECORD_INCOMPLETE", "the record does not carry the recommended product's evidence")
    assert rc.recommended is not None
    _refuse_personal_data(list(holdings), path="holdings")
    terms = [RecommendedTerm(item=fact.item, value=fact.value, unit=fact.unit, fact_ref=f"fact:{rc.recommended.product_ref}#{fact.item}") for fact in rc.recommended.facts if fact.value is not None]
    missing: list[str] = []
    if not terms:
        missing.append("the record cites no term with a value for the recommended product; the provider's stated terms cannot be reconciled against it")
    if rc.family not in DEFAULT_ITEMS:
        missing.append(f"no default application items for the {rc.family} family; the operator supplies the provider's own steps")
    if not rc.complete:
        missing.append("the record of advice is not complete: " + "; ".join(rc.missing()))
    parsed_items = _default_items(rc.family, rc.jurisdiction)
    for raw in items:
        parsed_items.append(_parse_item(raw))
    switching = {str(row.get("holding_ref")): row for row in rc.switching if isinstance(row, Mapping)}
    for index, holding in enumerate(holdings):
        row = dict(detached(holding))
        ref = _opaque_ref(row.get("holding_ref") or f"holding:{s.client_ref}:{index + 1}", field_name=f"holdings[{index}].holding_ref")
        verdict = switching.get(ref, {}).get("verdict")
        _require(verdict in (None, "switch"), "HOLDING_NOT_REPLACED", f"the record's stay-or-switch analysis for {ref} says {verdict}; a holding the advice keeps is not cancelled under it")
        if verdict is None:
            missing.append(f"no stay-or-switch analysis in the record for {ref}; its cancellation rests on the adviser's instruction, not on the record")
        what = " ".join(str(row.get(key)) for key in ("provider_name", "product_name") if row.get(key))
        parsed_items.append(ApplicationItem(item_ref=f"cancel:{ref}", kind="document_to_sign", label=f"Cancellation instruction for the replaced holding {ref}" + (f" ({what})" if what else ""), required=True, who="client"))
    refs = [item.item_ref for item in parsed_items]
    duplicates = sorted({ref for ref in refs if refs.count(ref) > 1})
    _require(not duplicates, "ITEM_DUPLICATE", "application items are named once each; " + ", ".join(duplicates) + " appears more than once")
    proposals = [item if isinstance(item, ProviderWriteProposal) else ProviderWriteProposal.model_validate(dict(detached(item))) for item in write_proposals]
    owner = provider_ref or next((item.provider_ref for item in proposals), None) or catalog_provider_ref(rc.jurisdiction, rc.recommended.provider_name)
    signatures = [item.item_ref for item in parsed_items if item.kind == "document_to_sign" and item.required and item.status not in ("signed", "not_required")]
    must_do = [item.label for item in parsed_items if item.who == "client" and item.required and item.status == "pending"]
    return seal(ApplicationPack, {
        "case_ref": case_ref, "recommendation_digest": rec.recommendation_digest, "record_digest": rc.record_digest, "approval_ref": str(approved["approval_ref"]), "product_ref": rec.primary_product_ref, "provider_ref": owner,
        "vertical_id": rc.vertical_id, "jurisdiction": rc.jurisdiction, "family": rc.family, "terms": [item.to_dict() for item in terms], "decision_facts": _decision_facts(s), "items": [item.to_dict() for item in parsed_items],
        "signatures_required": signatures, "client_must_do": must_do, "write_proposals": [item.to_dict() for item in proposals], "missing": missing, "prepared_at": stamp, "prepared_by_ref": prepared_by_ref,
    }, "pack_digest")


# --------------------------------------------------------------------------- #
# The provider's outcome and the reconciliation of the terms
# --------------------------------------------------------------------------- #


class StatedTerm(StrictModel):
    """A term exactly as the provider stated it in the offer, the contract or the policy schedule."""

    item: ShortText
    value: ShortText
    unit: str | None = None
    source_url: str | None = None
    quote: str | None = None

    @model_validator(mode="after")
    def _guard(self) -> StatedTerm:
        _refuse_personal_data({"item": self.item, "value": self.value, "quote": self.quote, "source_url": self.source_url}, path="stated_term")
        return self


class ProviderOutcome(StrictModel):
    """What the provider did with the application, as a receipt: the outcome, the terms as stated, the conditions."""

    schema_id: Literal["lightbulb.finance_advice_provider_outcome.v1"] = Field(default=OUTCOME_SCHEMA, alias="schema")
    pack_digest: Sha256Digest
    product_ref: OpaqueRef
    outcome: OutcomeKind
    stated_terms: tuple[StatedTerm, ...] = Field(default_factory=tuple)
    conditions: tuple[str, ...] = Field(default_factory=tuple)
    reason: ShortText | None = None
    occurred_at: str
    recorded_by_ref: OpaqueRef
    evidence_ref: OpaqueRef | None = None
    outcome_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("stated_terms", "conditions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("occurred_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ProviderOutcome:
        if self.outcome in CLOSING_OUTCOMES and not (self.reason or "").strip():
            raise ValueError(f"a {self.outcome} outcome names its reason")
        _refuse_personal_data({"reason": self.reason, "conditions": list(self.conditions), "evidence_ref": self.evidence_ref}, path="outcome")
        if not skip_digests(info) and self.outcome_digest != sealed_digest(ProviderOutcome, self, "outcome_digest"):
            raise ValueError("outcome_digest must commit the exact outcome")
        return self


def record_outcome(pack: ApplicationPack | Mapping[str, Any], *, outcome: OutcomeKind, stated_terms: Sequence[StatedTerm | Mapping[str, Any]] = (), occurred_at: str, recorded_by_ref: str, evidence_ref: str | None = None, reason: str | None = None, conditions: Sequence[str] = ()) -> ProviderOutcome:
    """Record the provider's outcome against one pack; a decline or a withdrawal names its reason."""

    p = pack if isinstance(pack, ApplicationPack) else ApplicationPack.model_validate(dict(detached(pack)))
    _require(outcome not in CLOSING_OUTCOMES or bool((reason or "").strip()), "OUTCOME_REASON_REQUIRED", f"a {outcome} outcome names the provider's reason")
    _refuse_personal_data({"recorded_by_ref": recorded_by_ref, "evidence_ref": evidence_ref, "reason": reason, "conditions": list(conditions), "stated_terms": [detached(item) for item in stated_terms]}, path="outcome")
    terms = [item if isinstance(item, StatedTerm) else StatedTerm.model_validate(dict(detached(item))) for item in stated_terms]
    return seal(ProviderOutcome, {"pack_digest": p.pack_digest, "product_ref": p.product_ref, "outcome": outcome, "stated_terms": [item.to_dict() for item in terms], "conditions": list(conditions), "reason": reason, "occurred_at": timestamp(occurred_at, field_name="occurred_at"), "recorded_by_ref": recorded_by_ref, "evidence_ref": evidence_ref}, "outcome_digest")


class TermDifference(StrictModel):
    item: str
    recommended_value: str | None = None
    implemented_value: str
    unit: str | None = None
    delta: Decimal | None = None
    material: bool
    ranked: bool = False
    reason: ShortText

    @field_validator("delta", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Any:
        return None if value is None else (value if isinstance(value, Decimal) else Decimal(str(value)))


class TermsReconciliation(StrictModel):
    """The provider's stated terms against the cited terms the recommendation rested on, item by item."""

    schema_id: Literal["lightbulb.finance_advice_terms_reconciliation.v1"] = Field(default=RECONCILIATION_SCHEMA, alias="schema")
    pack_digest: Sha256Digest
    outcome_digest: Sha256Digest
    recommendation_digest: Sha256Digest
    compared: int = Field(ge=0)
    differences: tuple[TermDifference, ...] = Field(default_factory=tuple)
    unstated_in_record: tuple[str, ...] = Field(default_factory=tuple)
    verdict: ReconciliationVerdict
    material: bool
    readvice_required: bool
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    disclosure: str = "The terms are compared as stated by the provider and as cited in the record; a material difference is for the licensed adviser to acknowledge or re-advise on. Nothing here decides."
    reconciliation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("differences", "unstated_in_record", "assumptions", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> TermsReconciliation:
        if self.readvice_required and not self.material:
            raise ValueError("re-advice follows a material difference")
        if not skip_digests(info) and self.reconciliation_digest != sealed_digest(TermsReconciliation, self, "reconciliation_digest"):
            raise ValueError("reconciliation_digest must commit the exact reconciliation")
        return self


def _difference(term: RecommendedTerm, stated: StatedTerm) -> TermDifference | None:
    rate = _is_rate(term.item, term.unit or stated.unit)
    ranked = _is_ranked(term.item)
    if not _units_agree(term.unit, stated.unit):
        return TermDifference(item=term.item, recommended_value=term.value, implemented_value=stated.value, unit=stated.unit, delta=None, material=True, ranked=ranked, reason=f"{term.item} is stated in {stated.unit} against the cited {term.unit}; the figures are not comparable until the units agree"[:300])
    recommended = _decimal(term.value)
    implemented = _decimal(stated.value)
    if recommended is not None and implemented is not None:
        delta = (implemented - recommended).quantize(_RATE_QUANTUM if rate else _CENTS, rounding=ROUND_HALF_UP)
        if delta == 0:
            return None
        if rate:
            material = abs(delta) >= MATERIAL_RATE_DELTA_PP
            reason = f"{term.item} came out at {stated.value} against the cited {term.value}: {'+' if delta > 0 else ''}{delta} percentage points, " + (f"at or above the {MATERIAL_RATE_DELTA_PP} point threshold" if material else f"below the {MATERIAL_RATE_DELTA_PP} point threshold")
        else:
            material = True
            reason = f"{term.item} came out at {stated.value} against the cited {term.value} ({'+' if delta > 0 else ''}{delta}{(' ' + term.unit) if term.unit else ''})"
        return TermDifference(item=term.item, recommended_value=term.value, implemented_value=stated.value, unit=term.unit or stated.unit, delta=delta, material=material, ranked=ranked, reason=reason[:300])
    if (term.value or "").strip().casefold() == stated.value.strip().casefold():
        return None
    return TermDifference(item=term.item, recommended_value=term.value, implemented_value=stated.value, unit=term.unit or stated.unit, delta=None, material=True, ranked=ranked, reason=f"{term.item} is stated as '{stated.value}' against the cited '{term.value}'"[:300])


def reconcile_terms(pack: ApplicationPack | Mapping[str, Any], outcome: ProviderOutcome | Mapping[str, Any], record: RecordOfAdviceEvidence | Mapping[str, Any]) -> TermsReconciliation:
    """Compare the provider's stated terms with the record's cited terms; name every difference, its size and whether it is material."""

    p = pack if isinstance(pack, ApplicationPack) else ApplicationPack.model_validate(dict(detached(pack)))
    o = outcome if isinstance(outcome, ProviderOutcome) else ProviderOutcome.model_validate(dict(detached(outcome)))
    rc = record if isinstance(record, RecordOfAdviceEvidence) else RecordOfAdviceEvidence.model_validate(dict(detached(record)))
    _require(o.pack_digest == p.pack_digest, "PACK_MISMATCH", "the outcome was recorded against a different application pack")
    _require(rc.record_digest == p.record_digest and rc.recommendation_digest == p.recommendation_digest, "RECORD_MISMATCH", "the record is not the one the pack was prepared from")
    by_item: dict[str, list[RecommendedTerm]] = {}
    for term in p.terms:
        by_item.setdefault(_normalise_item(term.item), []).append(term)
    differences: list[TermDifference] = []
    unstated: list[str] = []
    assumptions = ["stated terms are matched to the record's cited terms by item name with case, underscores and punctuation folded; a stated term with no cited counterpart is listed under unstated_in_record and is not assessed"]
    if not p.terms:
        assumptions.append("the pack carries no cited term with a value, so no stated term can be assessed")
    for name, cited in by_item.items():
        if len(cited) > 1:
            assumptions.append(f"the record cites {len(cited)} values for '{cited[0].item}' (" + ", ".join(f"{term.value}{(' ' + term.unit) if term.unit else ''}" for term in cited) + "); a stated figure that equals any of them is as recommended, otherwise it is compared with the first")
    compared = 0
    for stated in o.stated_terms:
        key = _normalise_item(stated.item)
        cited = by_item.get(key)
        if cited is None and key:
            # a decorated label ('Comparison Rate (variable)') is read as the one cited term whose every word it carries; two candidates are ambiguous and the term stays unstated
            words = set(key.split())
            candidates = [(name, terms) for name, terms in by_item.items() if name and set(name.split()) <= words]
            if len(candidates) == 1:
                cited = candidates[0][1]
                assumptions.append(f"'{stated.item}' is read as the cited '{cited[0].item}'")
            elif candidates:
                assumptions.append(f"'{stated.item}' could be the cited " + " or ".join(f"'{terms[0].item}'" for _, terms in candidates) + "; it is not assessed")
        if cited is None:
            unstated.append(stated.item)
            continue
        compared += 1
        if stated.unit and cited[0].unit and _normalise_unit(stated.unit) != _normalise_unit(cited[0].unit) and _units_agree(cited[0].unit, stated.unit):
            assumptions.append(f"'{stated.item}' is stated in '{stated.unit}' and read in the cited unit '{cited[0].unit}'")
        found = [_difference(term, stated) for term in cited]
        if all(found) and found[0] is not None:
            differences.append(found[0])
    material = any(item.material for item in differences)
    readvice = any(item.material and item.ranked for item in differences)
    verdict: ReconciliationVerdict = "unassessed" if compared == 0 else ("differs" if differences else "as_recommended")
    return seal(TermsReconciliation, {"pack_digest": p.pack_digest, "outcome_digest": o.outcome_digest, "recommendation_digest": p.recommendation_digest, "compared": compared, "differences": [item.to_dict() for item in differences], "unstated_in_record": unstated, "verdict": verdict, "material": material, "readvice_required": readvice, "assumptions": assumptions}, "reconciliation_digest")


# --------------------------------------------------------------------------- #
# The lifecycle receipt and the tracker
# --------------------------------------------------------------------------- #


def implementation_receipt(pack: ApplicationPack | Mapping[str, Any], outcome: ProviderOutcome | Mapping[str, Any], *, reconciliation: TermsReconciliation | Mapping[str, Any] | None = None, differences_acknowledged_ref: str | None = None) -> dict[str, Any]:
    """The receipt the case's ``implement`` transition carries: only a completing outcome, only reconciled terms, only acknowledged differences, never a ranked figure that differs."""

    p = pack if isinstance(pack, ApplicationPack) else ApplicationPack.model_validate(dict(detached(pack)))
    o = outcome if isinstance(outcome, ProviderOutcome) else ProviderOutcome.model_validate(dict(detached(outcome)))
    r = None if reconciliation is None else (reconciliation if isinstance(reconciliation, TermsReconciliation) else TermsReconciliation.model_validate(dict(detached(reconciliation))))
    _require(o.pack_digest == p.pack_digest, "PACK_MISMATCH", "the outcome was recorded against a different application pack")
    acknowledged = None if differences_acknowledged_ref is None else _opaque_ref(differences_acknowledged_ref, field_name="differences_acknowledged_ref")
    _require(o.outcome in COMPLETING_OUTCOMES, "IMPLEMENTATION_NOT_COMPLETE", f"the provider's outcome is {o.outcome}; the case is implemented on " + ", ".join(sorted(COMPLETING_OUTCOMES)))
    _require(r is not None or not o.stated_terms, "RECONCILIATION_REQUIRED", "the provider stated terms; reconcile them against the record before the case is implemented")
    if r is not None:
        _require(r.outcome_digest == o.outcome_digest and r.pack_digest == p.pack_digest, "RECONCILIATION_MISMATCH", "the reconciliation was prepared for a different outcome or pack")
        _require(not r.readvice_required, "TERMS_DIFFER_MATERIALLY", "a ranked figure came out different from the one the recommendation rested on: " + "; ".join(item.reason for item in r.differences if item.material and item.ranked) + "; the adviser re-advises, the case is not implemented on these terms")
        _require(not r.material or bool(acknowledged), "TERMS_DIFFER_UNACKNOWLEDGED", "the terms differ materially from the record: " + "; ".join(item.reason for item in r.differences if item.material) + "; the adviser acknowledges the differences by ref before the case is implemented")
        # stated terms that match nothing the record cites were never compared; they do not stand silently either
        _require(r.compared > 0 or bool(acknowledged), "TERMS_UNASSESSED_UNACKNOWLEDGED", "the provider stated " + ", ".join(r.unstated_in_record) + " and none of it matches a term the record cites; the adviser acknowledges by ref that the stated terms were read against the record before the case is implemented")
    needs_acknowledgement = r is not None and (r.material or r.compared == 0)
    evidence = [f"pack:{p.pack_digest}"] + ([f"reconciliation:{r.reconciliation_digest}"] if r is not None else [])
    return {
        "implementation_ref": f"impl:{o.outcome_digest}", "product_ref": p.product_ref, "implementation_digest": o.outcome_digest,
        "reconciliation_digest": r.reconciliation_digest if r is not None else None, "reconciliation_verdict": r.verdict if r is not None else "unassessed",
        "differences_acknowledged_ref": acknowledged if needs_acknowledgement else None, "evidence_refs": evidence,
    }


def implementation_tracker(pack: ApplicationPack | Mapping[str, Any], outcomes: Sequence[ProviderOutcome | Mapping[str, Any]], *, item_updates: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Where the implementation stands: items by status, the latest outcome, the signatures outstanding, days open, complete. No clock is read; time comes from the outcomes."""

    p = pack if isinstance(pack, ApplicationPack) else ApplicationPack.model_validate(dict(detached(pack)))
    parsed_outcomes = [item if isinstance(item, ProviderOutcome) else ProviderOutcome.model_validate(dict(detached(item))) for item in outcomes]
    for item in parsed_outcomes:
        _require(item.pack_digest == p.pack_digest, "PACK_MISMATCH", "an outcome was recorded against a different application pack")
    updates = {str(key): str(value) for key, value in dict(item_updates or {}).items()}
    for ref, status in updates.items():
        _require(p.item(ref) is not None, "ITEM_UNKNOWN", f"{ref} is not an item of this pack")
        _require(status in ("pending", "provided", "signed", "not_required"), "ITEM_STATUS_UNKNOWN", f"{status} is not an item status")
    statuses = {item.item_ref: updates.get(item.item_ref, item.status) for item in p.items}
    by_status: dict[str, list[str]] = {}
    for item in p.items:
        by_status.setdefault(statuses[item.item_ref], []).append(item.item_ref)
    ordered = sorted(enumerate(parsed_outcomes), key=lambda pair: (parsed(pair[1].occurred_at), pair[0]))
    latest = ordered[-1][1] if ordered else None
    outstanding = [{"item_ref": item.item_ref, "label": item.label} for item in p.items if item.kind == "document_to_sign" and item.required and statuses[item.item_ref] not in ("signed", "not_required")]
    pending = [item.item_ref for item in p.items if item.required and statuses[item.item_ref] == "pending"]
    days_open = None if latest is None else max((parsed(latest.occurred_at) - parsed(p.prepared_at)).days, 0)
    complete = latest is not None and latest.outcome in COMPLETING_OUTCOMES
    closed = latest is not None and latest.outcome in CLOSING_OUTCOMES
    return {
        "schema": "lightbulb.finance_advice_implementation_tracker.v1", "pack_digest": p.pack_digest, "product_ref": p.product_ref, "items_by_status": by_status, "items_pending": pending,
        "signatures_outstanding": outstanding, "outcomes": [{"outcome": item.outcome, "occurred_at": item.occurred_at, "outcome_digest": item.outcome_digest} for _, item in ordered],
        "latest_outcome": None if latest is None else {"outcome": latest.outcome, "occurred_at": latest.occurred_at, "outcome_digest": latest.outcome_digest, "conditions": list(latest.conditions), "reason": latest.reason},
        "days_open": days_open, "complete": complete, "closed": closed, "write_proposals": [{"proposal_ref": item.proposal_ref, "operation": item.operation, "executes": item.executes, "approval_required": item.approval_required} for item in p.write_proposals],
    }


IMPLEMENTATION_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_implementation.v1",
    "schemas": [APPLICATION_SCHEMA, WRITE_PROPOSAL_SCHEMA, OUTCOME_SCHEMA, RECONCILIATION_SCHEMA],
    "default_items": {family: [row["key"] for row in rows] for family, rows in DEFAULT_ITEMS.items()},
    "outcomes": {"kinds": ["submitted", "conditional", "approved", "declined", "settled", "policy_issued", "account_opened", "withdrawn"], "completing": sorted(COMPLETING_OUTCOMES), "closing": sorted(CLOSING_OUTCOMES)},
    "materiality": {"rate_items": f"a difference of {MATERIAL_RATE_DELTA_PP} percentage points or more is material", "other_items": "any difference is material, as is a figure stated in a different unit", "units": "units compare with spacing, punctuation and 'per annum'/'p.a.' folded; a bare '%' agrees with any percentage unit and the period is read from the record", "ranked_items": sorted(RANKED_TERM_ITEMS), "ranked_match": "every word of a ranked item appears in the term's name", "readvice": "a material difference in a ranked item", "label_match": "a stated label is read as the one cited term whose every word it carries; an ambiguous or unmatched label is unstated_in_record and never material", "duplicate_citations": "where the record cites more than one value for an item, a stated figure equal to any of them is as recommended, otherwise it is compared with the first; every such fold is written into assumptions", "unassessed": "stated terms that match nothing the record cites implement only with the adviser's acknowledgement by ref"},
    "hard_rules": [
        "the SDK never writes to a provider: a write is a proposal with approval_required True and executes False for the platform's governed-write lane",
        "personal data never enters: FORBIDDEN_APPLICATION_KEYS refuse names, contacts, identifiers and signatures on decision facts, items, holdings and write payloads; identity verification is an adviser step performed outside",
        "only the recommended product under an approval of that exact recommendation is implemented; the pack binds the recommendation, record and approval digests",
        "a decline or a withdrawal names its reason; only approved, settled, policy_issued and account_opened outcomes implement the case",
        "terms the provider stated are reconciled against the record before the case is implemented; a material difference, or a set of stated terms none of which the record cites, needs the adviser's acknowledgement by ref; a ranked figure that differs materially needs re-advice",
        "the models refuse personal data however they are built: an item's label, a stated term's text and an outcome's reason and conditions are scanned on validation, not only at the function entry",
        "deterministic Decimal arithmetic; no model, no clock: time comes from prepared_at and occurred_at",
    ],
    "not_claimed": "the pack is a checklist and the reconciliation is arithmetic; neither advises, submits, cancels or certifies anything",
}

__all__ = [
    "APPLICATION_SCHEMA",
    "CLOSING_OUTCOMES",
    "COMPLETING_OUTCOMES",
    "DEFAULT_ITEMS",
    "FORBIDDEN_APPLICATION_KEYS",
    "IMPLEMENTATION_MANIFEST",
    "MATERIAL_RATE_DELTA_PP",
    "OUTCOME_SCHEMA",
    "RANKED_TERM_ITEMS",
    "RECONCILIATION_SCHEMA",
    "WRITE_PROPOSAL_SCHEMA",
    "AdviceImplementationError",
    "ApplicationItem",
    "ApplicationPack",
    "OutcomeKind",
    "ProviderOutcome",
    "ProviderWriteProposal",
    "RecommendedTerm",
    "StatedTerm",
    "TermDifference",
    "TermsReconciliation",
    "application_pack",
    "implementation_receipt",
    "implementation_tracker",
    "reconcile_terms",
    "record_outcome",
    "write_proposal",
]
