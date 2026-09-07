"""Registration readiness: the tax and registry registrations only a director may lodge, prepared and never filed.

Company formation through the platform is guide-only — nothing here files with
a registrar — and the registrations that follow it (ABN/TFN/GST/PAYG
withholding/superannuation with the ATO in Australia; the Business Number,
GST/HST, payroll program account and provincial registration with the CRA and
the provincial registrars in Canada) are lodged by the applicant or a
registered agent in person.  There is no connector, and there will not be one.

What this module proves, and from which artifact:

* ``prepare_registrations`` — from the operator's own facts (does the company
  pay employees, what does it expect to turn over in a period) plus, optionally,
  the guide-only incorporation package, it derives a sealed
  ``lightbulb.registration_readiness.v1`` checklist: which registrations this
  country requires, why each one is or is not required, which *field names* have
  to be prepared before lodging, and the named human step that lodges it.
* ``filing_guide_receipt`` — from the agent-run ``incorporation_document_package``
  output of ``legal_doc_generator``; it admits the package only while
  ``guide_only`` is true, refuses a country that is not the one being prepared,
  refuses any registration number at any depth, and keeps a digest of the filing
  guide rather than its text.
* ``formation_receipt`` — from ``company_formation.parse_guided_response``; it
  requires the company to sit in the residency region its country implies and
  returns a *derived* company reference (a digest prefix of name and country),
  never the platform's company id.
* ``attestation_receipt`` — from an explicit, self-naming
  ``lightbulb.registration_attestation.v1``: an operator states that a
  registration was lodged and confirmed, names themself and the evidence, and
  carries the sha256 of the registrar's confirmation document computed outside
  the SDK.  No registration number is ever accepted or stored.

What it hands on: ``ProvisioningReceipt`` documents for the ``registration``
instrument (``prepared_only`` before lodgement, ``observed_active`` after an
attestation) that the per-instrument lifecycle and its launch gate consume, and
``open_obligation``-shaped openings the compliance calendar schedules.

Hard boundary: nothing is lodged, nothing is read, nothing is written; a
registration number never enters the SDK; an attestation is always an explicit
operator act that names its author, never something inferred from a document.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    reject_secret_like_payload,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_formation import (
    CompanyFormationResult,
    UnsupportedFormationCountryError,
    normalize_formation_country,
)
from lightbulb.company_provisioning_receipts import HumanStep, ProvisioningReceipt
from lightbulb.compliance_calendar import ComplianceCalendarPlan, ObligationKind

READINESS_SCHEMA = "lightbulb.registration_readiness.v1"
ATTESTATION_SCHEMA = "lightbulb.registration_attestation.v1"
PACKAGE_ACTION = "legal_doc_generator.incorporation_document_package"
ATTESTATION_STATEMENT = "I confirm this registration was lodged and confirmed by the registrar"

MAX_ITEMS = 12
_YEAR_DAYS = Decimal("365")

FormationCountry = Literal["AU", "CA"]
RegistrationKind = Literal[
    "au_abn",
    "au_tfn",
    "au_gst",
    "au_payg_withholding",
    "au_superannuation",
    "ca_bn",
    "ca_gst_hst",
    "ca_payroll_account",
    "ca_provincial_registration",
]
Registrar = Literal["ATO", "ASIC", "CRA", "provincial registrar"]
RequiredWhen = Literal["always", "has_employees", "revenue_threshold"]

REGISTRATION_KINDS: tuple[str, ...] = (
    "au_abn",
    "au_tfn",
    "au_gst",
    "au_payg_withholding",
    "au_superannuation",
    "ca_bn",
    "ca_gst_hst",
    "ca_payroll_account",
    "ca_provincial_registration",
)
# Only field *names* are prepared here; no value of any of them is ever carried.
PREPARED_INPUT_NAMES: tuple[str, ...] = ("legal_name", "registered_office", "director_count", "expected_turnover_band")
# The revenue authority a receipt names per country: module 7 admits an operator
# attestation only for a named revenue authority, so a provincial registry filing
# is still attested to the country's authority and keeps its registrar in facts.
AUTHORITY_BY_COUNTRY: Mapping[str, str] = {"AU": "ato", "CA": "cra"}
# The readiness names a registration's downstream obligation in its own
# country's words -- the CRA registers a GST/HST account and an RP payroll
# program account -- while ``compliance_calendar`` names the same statutory
# filings with one shared vocabulary across jurisdictions.  This is the
# translation, and only where the two demonstrably name the same filing: the CA
# calendar's quarterly 5% ``gst_bas`` row *is* the GST/HST return, and its
# monthly 15-day ``payg_withholding`` row *is* the CRA source-deduction
# remittance.  Without it a Canadian company that registers for GST/HST and
# payroll would be handed no openings for either.
CALENDAR_KIND_BY_COUNTRY: Mapping[str, Mapping[str, str]] = {
    "AU": {},
    "CA": {"sales_tax": "gst_bas", "payroll_tax": "payg_withholding"},
}
# The legal basis is the same for every one of them, and it is the whole point.
LODGEMENT_BASIS = "only the applicant or a registered agent may lodge"

# A registration number is 9 or 11 digits (ABN/ACN/TFN/BN) or a CRA program
# account (9 digits + a 2-letter program + a 4-digit reference); the core's
# card-like guard only catches 13-19 digit runs, so these are refused here.
_NUMBER_KEY = re.compile(r"^(?:.*_)?(abn|acn|tfn|bn|gst_number|hst_number|business_number)$")
_NUMBER_VALUE = re.compile(r"^\d{9}$|^\d{11}$|^\d{9}[A-Z]{2}\d{4}$")
# A registration number is still one when a label sits beside it ("ABN 51 824
# 753 556") or when JSON carries it as a number rather than a string, so every
# self-contained digit group in a string is normalized and tested on its own,
# and an integer is tested as the digits it is.
_NUMBER_RUN = re.compile(r"(?<![0-9A-Za-z])\d[\d\s-]*\d(?![0-9A-Za-z])")
_PROGRAM_ACCOUNT = re.compile(r"(?<![0-9A-Za-z])\d{9}[\s-]?[A-Z]{2}[\s-]?\d{4}(?![0-9A-Za-z])")
# Platform and provider JSON is camelCase; businessNumber is the same field as
# business_number, and an ABN is quoted "51 824 753 556" as often as bare.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NUMBER_SEPARATORS = re.compile(r"[\s-]+")
# formation_receipt derives this reference; the platform company id is never it.
_FORMED_REF = re.compile(r"^company:[0-9a-f]{24}$")
# A mapping still carrying any of its own package markers is re-validated in full,
# so a typed filing_guide_digest can never carry a package past the guards.
_PACKAGE_MARKERS = frozenset({"status", "guide_only", "filing_guide", "content", "document_type", "document_id"})


class RegistrationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RegistrationError(code, message)


def _normalized_key(key: Any) -> str:
    """businessNumber and business_number name the same field."""

    return _CAMEL_BOUNDARY.sub("_", str(key).strip()).lower()


def _numeric_text(value: str) -> bool:
    """True when a string carries a registration number, labelled, spaced, or bare."""

    if _NUMBER_VALUE.match(_NUMBER_SEPARATORS.sub("", value)):
        return True
    if _PROGRAM_ACCOUNT.search(value):
        return True
    return any(_NUMBER_VALUE.match(_NUMBER_SEPARATORS.sub("", run)) for run in _NUMBER_RUN.findall(value))


def reject_registration_numbers(value: Any, *, path: str = "input") -> None:
    """Refuse a registration number by key or by value at any depth.

    The SDK holds no ABN, ACN, TFN, Business Number, or GST/HST program account;
    an attestation carries the sha256 of the registrar's confirmation instead.
    """

    if isinstance(value, bool):
        return
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, str):
        _require(not _numeric_text(value), "REGISTRATION_NUMBER_NOT_ACCEPTED", f"{path} looks like a registration number; the SDK never accepts one")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require(not _NUMBER_KEY.match(_normalized_key(key)), "REGISTRATION_NUMBER_NOT_ACCEPTED", f"{path}.{key} is a registration number field and is never accepted")
            reject_registration_numbers(item, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            reject_registration_numbers(item, path=f"{path}[{index}]")


def _digest(value: Any, *, code: str, label: str) -> str:
    _require(isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value), code, f"{label} must be a sha256 digest")
    return str(value)


def _mapping(value: Any, *, code: str, label: str) -> dict[str, Any]:
    _require(isinstance(value, Mapping), code, f"{label} must be a mapping; got {type(value).__name__}")
    return dict(detached(value))


def _country(value: Any) -> str:
    try:
        return normalize_formation_country(value)
    except UnsupportedFormationCountryError as exc:
        raise RegistrationError("COUNTRY_UNSUPPORTED", f"registrations are prepared for Australia (AU) and Canada (CA) only; got {exc.value!r}") from exc


# --------------------------------------------------------------------------- #
# The rules: what each country registers, and who lodges it
# --------------------------------------------------------------------------- #


class RegistrationRule(StrictModel):
    """One registration a country requires, and the human step that lodges it."""

    kind: RegistrationKind
    registrar: Registrar
    required_when: RequiredWhen
    threshold_per_year: Decimal | None = None
    obligation_kind: ObligationKind | None = None
    prepared_inputs: tuple[ShortText, ...] = Field(min_length=1, max_length=len(PREPARED_INPUT_NAMES))
    human_step: HumanStep

    @field_validator("threshold_per_year", mode="before")
    @classmethod
    def _threshold(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="threshold_per_year")

    @field_validator("prepared_inputs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self) -> RegistrationRule:
        unknown = [name for name in self.prepared_inputs if name not in PREPARED_INPUT_NAMES]
        if unknown:
            raise ValueError(f"prepared_inputs names field names only; {unknown} is outside {list(PREPARED_INPUT_NAMES)}")
        if (self.required_when == "revenue_threshold") != (self.threshold_per_year is not None):
            raise ValueError("a revenue-threshold registration names its threshold, and only that kind carries one")
        return self


def _step(action: str, *, kind: str = "tax_registration") -> HumanStep:
    return HumanStep.model_validate({"kind": kind, "actor": "director", "action": action, "legal_basis": LODGEMENT_BASIS, "status": "not_started"})


def _rule(kind: str, registrar: str, required_when: str, action: str, *, threshold: str | None = None, obligation_kind: str | None = None, inputs: tuple[str, ...], step_kind: str = "tax_registration") -> RegistrationRule:
    return RegistrationRule.model_validate({"kind": kind, "registrar": registrar, "required_when": required_when, "threshold_per_year": threshold, "obligation_kind": obligation_kind, "prepared_inputs": inputs, "human_step": _step(action, kind=step_kind).to_dict()})


REGISTRATIONS_BY_COUNTRY: Mapping[str, tuple[RegistrationRule, ...]] = {
    "AU": (
        _rule("au_abn", "ATO", "always", "lodge the ABN application via the ATO Business Registration Service", inputs=("legal_name", "registered_office", "director_count", "expected_turnover_band")),
        _rule("au_tfn", "ATO", "always", "lodge the company TFN application via the ATO Business Registration Service", obligation_kind="annual_return", inputs=("legal_name", "registered_office", "director_count")),
        _rule("au_gst", "ATO", "revenue_threshold", "add GST registration to the ABN via the ATO Business Registration Service", threshold="75000", obligation_kind="gst_bas", inputs=("legal_name", "expected_turnover_band")),
        _rule("au_payg_withholding", "ATO", "has_employees", "register for PAYG withholding with the ATO before the first payday", obligation_kind="payg_withholding", inputs=("legal_name", "registered_office")),
        _rule("au_superannuation", "ATO", "has_employees", "nominate the default super fund and enrol in SuperStream clearing", obligation_kind="superannuation", inputs=("legal_name", "registered_office")),
    ),
    "CA": (
        _rule("ca_bn", "CRA", "always", "register the Business Number via CRA Business Registration Online", obligation_kind="annual_return", inputs=("legal_name", "registered_office", "director_count")),
        _rule("ca_gst_hst", "CRA", "revenue_threshold", "add the GST/HST program account via CRA Business Registration Online", threshold="30000", obligation_kind="sales_tax", inputs=("legal_name", "expected_turnover_band")),
        _rule("ca_payroll_account", "CRA", "has_employees", "add the RP payroll program account via CRA Business Registration Online", obligation_kind="payroll_tax", inputs=("legal_name", "registered_office")),
        _rule("ca_provincial_registration", "provincial registrar", "always", "register the corporation extra-provincially with the provincial registrar", inputs=("legal_name", "registered_office", "director_count"), step_kind="registrar_filing"),
    ),
}


# --------------------------------------------------------------------------- #
# The sealed checklist
# --------------------------------------------------------------------------- #


class RegistrationItem(StrictModel):
    """One registration, decided: required or not, why, and the step that lodges it."""

    kind: RegistrationKind
    registrar: Registrar
    required: bool
    reason: ShortText
    obligation_kind: ObligationKind | None = None
    prepared_inputs: tuple[ShortText, ...] = Field(min_length=1, max_length=len(PREPARED_INPUT_NAMES))
    human_step: HumanStep

    @field_validator("prepared_inputs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class RegistrationReadiness(StrictModel):
    """The sealed checklist of what this company must register, and who lodges each one."""

    schema_id: str = Field(default=READINESS_SCHEMA, alias="schema")
    country: FormationCountry
    formed_company_ref: OpaqueRef
    filing_guide_digest: Sha256Digest | None = None
    items: tuple[RegistrationItem, ...] = Field(min_length=1, max_length=MAX_ITEMS)
    assessed_at: str
    readiness_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("schema_id")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != READINESS_SCHEMA:
            raise ValueError(f"schema must be {READINESS_SCHEMA}")
        return value

    @field_validator("formed_company_ref")
    @classmethod
    def _formed(cls, value: str) -> str:
        if not _FORMED_REF.match(value):
            raise ValueError("formed_company_ref is the reference formation_receipt derives; a platform company id is never one")
        return value

    @field_validator("items", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RegistrationReadiness:
        kinds = [item.kind for item in self.items]
        if len(kinds) != len(set(kinds)):
            raise ValueError("a readiness names each registration kind once")
        if any(not item.kind.startswith(self.country.lower()) for item in self.items):
            raise ValueError("every item belongs to the country the readiness was assessed for")
        if not skip_digests(info) and self.readiness_digest != sealed_digest(RegistrationReadiness, self, "readiness_digest"):
            raise ValueError("readiness_digest must commit the exact checklist")
        return self

    def item(self, kind: str) -> RegistrationItem | None:
        return next((item for item in self.items if item.kind == kind), None)

    @property
    def required_kinds(self) -> tuple[str, ...]:
        return tuple(item.kind for item in self.items if item.required)


class OperatorAttestation(StrictModel):
    """An operator's own statement that a registration was lodged and confirmed.

    It names its author and its evidence.  It carries the sha256 of the
    registrar's confirmation document, computed outside the SDK, and never the
    registration number that document contains.
    """

    schema_id: str = Field(default=ATTESTATION_SCHEMA, alias="schema")
    kind: RegistrationKind
    attested_by_ref: OpaqueRef
    evidence_ref: OpaqueRef
    registered_at: str
    registrar_confirmation_sha256: Sha256Digest
    statement: Literal["I confirm this registration was lodged and confirmed by the registrar"]
    attestation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("schema_id")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != ATTESTATION_SCHEMA:
            raise ValueError(f"schema must be {ATTESTATION_SCHEMA}")
        return value

    @field_validator("registered_at")
    @classmethod
    def _registered(cls, value: str) -> str:
        return timestamp(value, field_name="registered_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> OperatorAttestation:
        reject_registration_numbers({"attested_by_ref": self.attested_by_ref, "evidence_ref": self.evidence_ref}, path="attestation")
        if not skip_digests(info) and self.attestation_digest != sealed_digest(OperatorAttestation, self, "attestation_digest"):
            raise ValueError("attestation_digest must commit the exact attestation")
        return self


def operator_attestation(*, kind: str, attested_by_ref: str, evidence_ref: str, registered_at: str, registrar_confirmation_sha256: str) -> OperatorAttestation:
    """Seal an operator attestation; the statement is fixed so the operator cannot be quoted saying anything else."""

    payload = {"kind": kind, "attested_by_ref": attested_by_ref, "evidence_ref": evidence_ref, "registered_at": registered_at, "registrar_confirmation_sha256": registrar_confirmation_sha256, "statement": ATTESTATION_STATEMENT}
    reject_registration_numbers(payload, path="attestation")
    return seal(OperatorAttestation, payload, "attestation_digest")


# --------------------------------------------------------------------------- #
# Receipts from the artifacts that precede a registration
# --------------------------------------------------------------------------- #


def filing_guide_receipt(outputs: Mapping[str, Any] | Any, *, country: str | None = None) -> dict[str, Any]:
    """From the guide-only ``incorporation_document_package`` output of a direct ``legal_doc_generator`` run.

    ``incorporation_document_package`` is not a registry dispatch action, so this
    is optional: it only ever adds the filing guide's digest to the readiness.
    The package's drafted document text is never carried; only the guide's shape.
    """

    raw = _mapping(outputs, code="PACKAGE_SCHEMA_MISMATCH", label="an incorporation package")
    reject_registration_numbers(raw, path="incorporation_package")
    _require(str(raw.get("status")) == "generated", "PACKAGE_SCHEMA_MISMATCH", f"expected a generated {PACKAGE_ACTION} output; got status {raw.get('status')!r}")
    _require(raw.get("guide_only") is True, "GUIDE_ONLY_REQUIRED", "only a guide-only incorporation package is admitted; nothing here files with a registrar")
    package_country = _country(raw.get("country"))
    if country is not None:
        _require(package_country == _country(country), "COUNTRY_MISMATCH", f"the package is for {package_country}, not {_country(country)}")
    guide = raw.get("filing_guide")
    _require(isinstance(guide, list) and bool(guide), "PACKAGE_SCHEMA_MISMATCH", "an incorporation package carries a filing guide")
    _require(all(isinstance(entry, Mapping) for entry in list(guide)), "PACKAGE_SCHEMA_MISMATCH", "each filing-guide entry is a mapping of its step and its action")
    steps = [dict(detached(entry)) for entry in list(guide)]
    _require(all({"step", "action"} <= set(entry) for entry in steps), "PACKAGE_SCHEMA_MISMATCH", "each filing-guide entry names its step and its action")
    registrar = str(raw.get("registrar") or "").strip()
    template = str(raw.get("template") or "").strip()
    _require(bool(registrar) and bool(template), "PACKAGE_SCHEMA_MISMATCH", "an incorporation package names the registrar it prepares for and the template it rendered")
    facts = {"country": package_country, "registrar": registrar, "template": template, "step_count": len(steps)}
    reject_secret_like_payload(facts, path="incorporation_package")
    return {"filing_guide_digest": stable_digest(steps), **facts}


def formation_receipt(result: CompanyFormationResult | Mapping[str, Any] | Any) -> dict[str, Any]:
    """From ``company_formation.parse_guided_response``: a derived company reference, never the platform's company id."""

    raw = result.to_dict() if isinstance(result, CompanyFormationResult) else _mapping(result, code="FORMATION_SCHEMA_MISMATCH", label="a formation result")
    country = _country(raw.get("country"))
    name = str(raw.get("name") or "").strip()
    _require(bool(name), "FORMATION_SCHEMA_MISMATCH", "a formation result names the company that was formed")
    _require(raw.get("region_matches_country") is True, "RESIDENCY_MISMATCH", f"the company sits in {raw.get('region')!r}, which is not the residency region {country} implies")
    return {"formed_company_ref": f"company:{stable_digest({'name': name, 'country': country})[:24]}", "country": country}


# --------------------------------------------------------------------------- #
# Preparing the checklist
# --------------------------------------------------------------------------- #


def _annualised(expected_revenue_per_period: Any, period_days: int) -> Decimal:
    _require(isinstance(period_days, int) and not isinstance(period_days, bool) and 1 <= period_days <= 366, "PERIOD_INVALID", "period_days must be a whole number of days between 1 and 366")
    revenue = decimal_value(expected_revenue_per_period, field_name="expected_revenue_per_period")
    return (revenue * _YEAR_DAYS / Decimal(period_days)).quantize(MONEY_QUANTUM)


def _decide(rule: RegistrationRule, *, has_employees: bool, annualised: Decimal) -> tuple[bool, str]:
    if rule.required_when == "always":
        return True, f"{rule.registrar} requires this of every company at formation"
    if rule.required_when == "has_employees":
        if has_employees:
            return True, "the company pays employees"
        return False, "no employees are paid yet; required before the first payday"
    threshold = Decimal(str(rule.threshold_per_year))
    if annualised >= threshold:
        return True, f"annualised turnover {annualised} is at or above the {threshold} registration threshold"
    return False, f"annualised turnover {annualised} is below the {threshold} registration threshold; registration is voluntary until it is reached"


def prepare_registrations(*, country: str, formed_company_ref: str, has_employees: bool, expected_revenue_per_period: Any, period_days: int, now: str, incorporation_package: Mapping[str, Any] | None = None) -> RegistrationReadiness:
    """Derive the sealed registration checklist for a formed company.

    ``has_employees`` and ``expected_revenue_per_period`` are explicit operator
    inputs — the SDK has no payroll or revenue read at formation time — and the
    reason on every item says which of them decided it.  Nothing is lodged.
    """

    code = _country(country)
    formed_ref = str(formed_company_ref)
    _require(bool(_FORMED_REF.match(formed_ref)), "FORMED_REF_NOT_DERIVED", "formed_company_ref is the company:<digest> reference formation_receipt derives; a platform company id is never accepted")
    _require(isinstance(has_employees, bool), "OPERATOR_INPUT_INVALID", "has_employees is an explicit operator statement, true or false")
    annualised = _annualised(expected_revenue_per_period, period_days)
    guide_digest: str | None = None
    if incorporation_package is not None:
        package = dict(detached(incorporation_package))
        # Stripping a package's markers and pinning a digest on must not buy a
        # way past the boundary: a registration number is refused before the
        # mapping is classified at all, not merely dropped when it is ignored.
        reject_registration_numbers(package, path="incorporation_package")
        prepared = "filing_guide_digest" in package and not (_PACKAGE_MARKERS & {_normalized_key(key) for key in package})
        receipt = package if prepared else filing_guide_receipt(package, country=code)
        _require(_country(receipt.get("country")) == code, "COUNTRY_MISMATCH", f"the incorporation package is for {receipt.get('country')!r}, not {code}")
        guide_digest = _digest(receipt.get("filing_guide_digest"), code="PACKAGE_SCHEMA_MISMATCH", label="filing_guide_digest")
    items: list[dict[str, Any]] = []
    for rule in REGISTRATIONS_BY_COUNTRY[code]:
        required, reason = _decide(rule, has_employees=has_employees, annualised=annualised)
        items.append({"kind": rule.kind, "registrar": rule.registrar, "required": required, "reason": reason, "obligation_kind": rule.obligation_kind, "prepared_inputs": list(rule.prepared_inputs), "human_step": rule.human_step.to_dict()})
    payload = {"country": code, "formed_company_ref": formed_ref, "filing_guide_digest": guide_digest, "items": items, "assessed_at": timestamp(str(now), field_name="now")}
    return seal(RegistrationReadiness, payload, "readiness_digest")


# --------------------------------------------------------------------------- #
# What the checklist hands on
# --------------------------------------------------------------------------- #


def _receipt(payload: Mapping[str, Any]) -> ProvisioningReceipt:
    return seal(ProvisioningReceipt, payload, "receipt_digest")


def _instrument_facts(item: RegistrationItem) -> dict[str, Any]:
    return {"kind": item.kind, "registrar": item.registrar, "required": item.required, "obligation_kind": item.obligation_kind}


def prepared_receipt(readiness: RegistrationReadiness, kind: str) -> ProvisioningReceipt:
    """The ``prepared_only`` receipt for one registration: prepared, named, and not lodged."""

    item = readiness.item(str(kind))
    _require(item is not None, "KIND_NOT_IN_READINESS", f"{kind!r} is not on this readiness; prepare it before a receipt names it")
    assert item is not None
    payload = {
        "instrument": "registration",
        "provider": AUTHORITY_BY_COUNTRY[readiness.country],
        "lane": "operator_attestation",
        "disposition": "prepared_only",
        "instrument_ref": f"registration:{item.kind}",
        "evidence_sha256": readiness.readiness_digest,
        "human_steps": [{**item.human_step.to_dict(), "status": "pending"}],
        "facts": _instrument_facts(item),
        "observed_at": readiness.assessed_at,
        "evidence_refs": [f"readiness:{readiness.readiness_digest[:24]}"],
    }
    return _receipt(payload)


def attestation_receipt(attestation: OperatorAttestation | Mapping[str, Any] | Any, *, readiness: RegistrationReadiness, formed_at: str | None = None) -> ProvisioningReceipt:
    """The ``observed_active`` receipt for one registration, from the operator's own attestation.

    A registration case never goes active on a platform write: there is none.  It
    goes active only here, on an attestation that names its author, its evidence,
    and the digest of the registrar's confirmation.
    """

    if not isinstance(attestation, OperatorAttestation):
        raw = _mapping(attestation, code="ATTESTATION_INCOMPLETE", label="an attestation")
        reject_registration_numbers(raw, path="attestation")
        for field in ("attested_by_ref", "evidence_ref"):
            _require(bool(str(raw.get(field) or "").strip()), "ATTESTATION_INCOMPLETE", f"an attestation names its {field}; it is never inferred")
        attestation = OperatorAttestation.model_validate(raw)
    item = readiness.item(attestation.kind)
    _require(item is not None, "ATTESTATION_NOT_PREPARED", f"{attestation.kind!r} was never prepared on this readiness; an attestation cannot introduce a registration")
    assert item is not None
    if formed_at is not None:
        _require(parsed(attestation.registered_at) >= parsed(timestamp(str(formed_at), field_name="formed_at")), "ATTESTATION_BEFORE_FORMATION", f"the registration is attested at {attestation.registered_at}, before the company was formed at {formed_at}")
    payload = {
        "instrument": "registration",
        "provider": AUTHORITY_BY_COUNTRY[readiness.country],
        "lane": "operator_attestation",
        "disposition": "observed_active",
        "instrument_ref": f"registration:{item.kind}",
        "instrument_sha256": attestation.registrar_confirmation_sha256,
        "evidence_sha256": attestation.attestation_digest,
        "human_steps": [{**item.human_step.to_dict(), "status": "satisfied"}],
        "facts": {**_instrument_facts(item), "attested_by_ref": attestation.attested_by_ref, "registered_at": attestation.registered_at, "statement": ATTESTATION_STATEMENT},
        "observed_at": attestation.registered_at,
        "evidence_refs": [f"attestation:{attestation.evidence_ref}", f"readiness:{readiness.readiness_digest[:24]}"],
    }
    return _receipt(payload)


def obligations_from_readiness(readiness: RegistrationReadiness, *, plan: ComplianceCalendarPlan, period_start: str) -> list[dict[str, Any]]:
    """The obligation openings a required registration implies, from the calendar's own schedule.

    Nothing is opened here: each row names the ``obligation_ref``
    ``compliance_calendar.open_obligation`` accepts, with the period and due date
    the calendar derived.  The item's own ``obligation_kind`` is translated into
    the kind this country's calendar schedules it under
    (``CALENDAR_KIND_BY_COUNTRY``); a required registration the calendar does not
    schedule at all — a payroll account against a calendar compiled with
    ``has_payroll=False``, say — is left out, because the calendar, not the
    readiness, decides what a jurisdiction files.
    """

    _require(str(plan.jurisdiction) == readiness.country, "JURISDICTION_MISMATCH", f"the calendar is for {plan.jurisdiction}; this readiness was assessed for {readiness.country}")
    start = parsed(timestamp(str(period_start), field_name="period_start"))
    openings: list[dict[str, Any]] = []
    aliases = CALENDAR_KIND_BY_COUNTRY[readiness.country]
    for item in readiness.items:
        if not item.required or item.obligation_kind is None:
            continue
        scheduled_kind = aliases.get(str(item.obligation_kind), str(item.obligation_kind))
        rows = [row for row in plan.schedule if row.kind == scheduled_kind and parsed(row.period_end) > start]
        if not rows:
            continue
        row = min(rows, key=lambda candidate: (candidate.due_at, candidate.obligation_ref))
        openings.append({
            "obligation_ref": row.obligation_ref,
            "kind": row.kind,
            "registration_obligation_kind": item.obligation_kind,
            "jurisdiction": plan.jurisdiction,
            "period_start": row.period_start,
            "period_end": row.period_end,
            "due_at": row.due_at,
            "registration_kind": item.kind,
            "registrar": item.registrar,
            "source": READINESS_SCHEMA,
            "readiness_digest": readiness.readiness_digest,
        })
    openings.sort(key=lambda opening: (opening["due_at"], opening["obligation_ref"]))
    return openings


def readiness_summary(readiness: RegistrationReadiness) -> dict[str, Any]:
    return {
        "country": readiness.country,
        "formed_company_ref": readiness.formed_company_ref,
        "required": [item.kind for item in readiness.items if item.required],
        "optional": [item.kind for item in readiness.items if not item.required],
        "obligation_kinds": sorted({str(item.obligation_kind) for item in readiness.items if item.required and item.obligation_kind}),
        "human_steps": [item.human_step.action for item in readiness.items if item.required],
        "filing_guide_digest": readiness.filing_guide_digest,
        "assessed_at": readiness.assessed_at,
        "readiness_digest": readiness.readiness_digest,
    }


REGISTRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "registration_readiness",
    "countries": sorted(REGISTRATIONS_BY_COUNTRY),
    "kinds": list(REGISTRATION_KINDS),
    "registrars": ["ATO", "ASIC", "CRA", "provincial registrar"],
    "prepared_inputs": list(PREPARED_INPUT_NAMES),
    "produces": [READINESS_SCHEMA, ATTESTATION_SCHEMA, "lightbulb.company_provisioning_receipt.v1"],
    "hops": {
        "filing_guide": f"the guide-only {PACKAGE_ACTION} output of a direct agent run (optional)",
        "formation": "company_formation.parse_guided_response, for a derived company reference",
        "prepared": "a prepared_only provisioning receipt for the registration instrument",
        "attestation": f"an explicit {ATTESTATION_SCHEMA} carrying the registrar confirmation digest",
        "obligations": "open_obligation-shaped rows the compliance calendar schedules",
    },
    "required_connectors": [],
    "hard_rules": [
        "nothing is lodged; lodgement is the director's or registered agent's act",
        "no registration number is accepted or stored; the attestation carries the confirmation digest only",
        "an attestation names itself and its author; it is never inferred from a document",
    ],
}

__all__ = [
    "ATTESTATION_SCHEMA",
    "ATTESTATION_STATEMENT",
    "AUTHORITY_BY_COUNTRY",
    "CALENDAR_KIND_BY_COUNTRY",
    "LODGEMENT_BASIS",
    "OperatorAttestation",
    "PACKAGE_ACTION",
    "PREPARED_INPUT_NAMES",
    "READINESS_SCHEMA",
    "REGISTRATIONS_BY_COUNTRY",
    "REGISTRATION_KINDS",
    "REGISTRATION_MANIFEST",
    "RegistrationError",
    "RegistrationItem",
    "RegistrationReadiness",
    "RegistrationRule",
    "attestation_receipt",
    "filing_guide_receipt",
    "formation_receipt",
    "obligations_from_readiness",
    "operator_attestation",
    "prepare_registrations",
    "prepared_receipt",
    "readiness_summary",
    "reject_registration_numbers",
]
