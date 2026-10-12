"""Remuneration and conflicts: what the adviser is paid on each product, cited to a schedule, and the disclosure a recommendation carries.

An adviser's remuneration is a decision fact for the client: who pays the adviser, how much, on
which product, and whether the recommended product pays the adviser more than the alternatives.
This module holds three sealed artifacts. A *remuneration schedule* is the provider's or the
licensee's own schedule, line by line, every line cited to the document it came from (a line
without a citation is refused). A *conflicts register* records the arrangements that could bear
on a recommendation (ownership, referral arrangements, volume incentives, soft-dollar benefits,
related-party products, an approved product list), each with an opaque counterparty reference,
never a name. A *remuneration disclosure* is prepared per recommendation: it resolves the
schedule line for the recommended product (a product line beats a provider line beats nothing),
puts a figure on what the adviser earns over the horizon against each alternative, carries the
conflicts that reach the recommended provider or product, and names its findings in plain
sentences with the figures and their sources.

Jurisdiction tables (which remuneration kinds are conflicted for a family, the life-insurance
commission caps) are carried as rule-shaped rows with ``confirmed`` False, and every finding built
on them says so, mirroring ``finance_advice_rules``. Nothing here decides or ranks: the
disclosure describes and flags; the licensed adviser owns what is said to the client.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone  # parsing only; no clock is read anywhere in this module
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, ClassVar, Literal

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_identity import reject_identity_payload
from lightbulb.finance_advice_catalog import ResearchModel, SourceCitation
from lightbulb.finance_advice_engine import ClientState, Recommendation, Shortlist, ShortlistEntry

REMUNERATION_SCHEMA = "lightbulb.finance_advice_remuneration_schedule.v1"
CONFLICTS_SCHEMA = "lightbulb.finance_advice_conflicts_register.v1"
REMUNERATION_DISCLOSURE_SCHEMA = "lightbulb.finance_advice_remuneration_disclosure.v1"
MAX_LINES = 5000
NOT_CONFIRMED = "not yet confirmed by the operator"
DISCLAIMER = "This disclosure states what the adviser is paid, in figures cited to the schedule, and flags what a person must weigh; it decides nothing and it is not advice."

RemunerationKind = Literal["upfront_commission", "trail_commission", "fee_for_service", "volume_bonus", "referral_fee", "none", "unstated"]
ConflictKind = Literal["ownership", "referral_arrangement", "volume_incentive", "soft_dollar", "related_party_product", "approved_product_list"]
RemunerationFinding = Literal["recommended_pays_more", "schedule_missing_for_recommended", "conflicted_kind_for_family", "undisclosed_conflict", "cap_exceeded", "fee_for_service_only"]
Payer = Literal["provider", "client", "licensee"]
ResolvedBy = Literal["product", "provider", "none"]

# counterparties and payers are opaque refs or commitments; these keys never enter an entry
FORBIDDEN_COUNTERPARTY_KEYS = frozenset({"name", "counterparty_name", "legal_name", "trading_name", "first_name", "last_name", "full_name", "contact", "contact_name", "email", "email_address", "phone", "phone_number", "mobile", "address", "postal_address", "postcode", "abn", "acn", "account_number", "policy_number", "member_number", "bsb", "iban", "card_number", "date_of_birth", "dob", "tfn", "tax_file_number", "sin", "ssn", "national_id", "passport", "licence_number", "signature", "tenant_id", "company_id", "user_id"})
_INFORMATIONAL_FINDINGS = frozenset({"fee_for_service_only"})
_CURRENCY_BY_JURISDICTION = {"AU": "AUD", "CA": "CAD"}
_KIND_WORDS = {"upfront_commission": "upfront commission", "trail_commission": "trail commission", "fee_for_service": "fee for service", "volume_bonus": "volume bonus", "referral_fee": "referral fee", "none": "no remuneration", "unstated": "remuneration of an unstated kind"}
_CENTS = Decimal("0.01")
_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# --------------------------------------------------------------------------- #
# Jurisdiction tables. Rows are JurisdictionRule-shaped (finance_advice_rules) and carried with
# confirmed=False: every finding built on one says "not yet confirmed by the operator" until the
# operator confirms the row. Which products an exemption reaches is the operator's mapping.
# --------------------------------------------------------------------------- #

AU_CONFLICTED_KINDS: frozenset[str] = frozenset({"upfront_commission", "trail_commission", "volume_bonus", "referral_fee"})
AU_CONFLICTED_FAMILIES: frozenset[str] = frozenset({"investments"})
AU_CONFLICTED_REMUNERATION_RULE: dict[str, Any] = {
    "rule_ref": "au.advice.conflicted_remuneration",
    "jurisdiction": "AU",
    "verticals": (),
    "title": "Conflicted remuneration on financial product advice",
    "statement": "A benefit given to a licensee or representative that could reasonably be expected to influence the advice given to a retail client on a financial product is conflicted remuneration; commissions and volume-based benefits on investment products are the paradigm case, with exemptions the operator maps.",
    "effect": "disclosure_only",
    "source_url": "https://asic.gov.au/regulatory-resources/find-a-document/regulatory-guides/rg-246-conflicted-and-other-banned-remuneration/",
    "effective_from": "2013-07-01",
    "confirmed": False,
    "parameters": {"families": sorted(AU_CONFLICTED_FAMILIES), "kinds": sorted(AU_CONFLICTED_KINDS)},
}
AU_LIFE_COMMISSION_CAPS: tuple[dict[str, Any], ...] = (
    {
        "rule_ref": "au.life.commission_cap.upfront",
        "jurisdiction": "AU",
        "verticals": ("AU-32", "AU-33", "AU-34", "AU-35", "AU-44"),
        "title": "Life insurance upfront commission cap",
        "statement": "Upfront commission on a life risk insurance product is capped at 60% of the first year's premium, with a clawback over the first two years.",
        "effect": "disclosure_only",
        "source_url": "https://www.legislation.gov.au/F2017L00714/latest/text",
        "effective_from": "2020-01-01",
        "confirmed": False,
        "parameters": {"kind": "upfront_commission", "max_percent": "60", "clawback_years": 2},
    },
    {
        "rule_ref": "au.life.commission_cap.ongoing",
        "jurisdiction": "AU",
        "verticals": ("AU-32", "AU-33", "AU-34", "AU-35", "AU-44"),
        "title": "Life insurance ongoing commission cap",
        "statement": "Ongoing (trail) commission on a life risk insurance product is capped at 20% of the premium.",
        "effect": "disclosure_only",
        "source_url": "https://www.legislation.gov.au/F2017L00714/latest/text",
        "effective_from": "2020-01-01",
        "confirmed": False,
        "parameters": {"kind": "trail_commission", "max_percent": "20"},
    },
)


class AdviceRemunerationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceRemunerationError(code, message)


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENTS, rounding=ROUND_HALF_UP)


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value
    try:
        figure = Decimal(str(value).replace(",", "").replace("%", "").replace("$", "").strip())
    except Exception:  # noqa: BLE001
        return None
    return figure if figure.is_finite() else None


def _figure(value: Any, info: ValidationInfo) -> Decimal | None:
    """A model figure: None stays None; anything else is a finite Decimal or the field is refused."""
    if value is None or isinstance(value, Decimal) and value.is_finite():
        return value
    figure = _decimal(value)
    if figure is None:
        raise ValueError(f"AMOUNT_NOT_NUMERIC: {info.field_name} is a finite figure or absent")
    return figure


def _rule_stamp(row: Mapping[str, Any]) -> str:
    return f"{row['rule_ref']}, figures as published at {row['source_url']}, effective {row['effective_from']}{'' if row.get('confirmed') else '; ' + NOT_CONFIRMED}"


def _refuse_identity(value: Any, *, what: str) -> Any:
    if isinstance(value, Mapping):
        bad = sorted(str(key) for key in value if str(key).lower() in FORBIDDEN_COUNTERPARTY_KEYS)
        if bad:
            raise ValueError(f"COUNTERPARTY_IDENTITY_FORBIDDEN: {what} carries opaque refs or commitments, never {', '.join(bad)}")
    return value


def _refuse_address(value: str | None, *, what: str) -> None:
    """An opaque ref may carry '@' (the ref grammar allows it); an address-shaped value is refused wherever it appears."""
    reject_identity_payload(value, code="COUNTERPARTY_IDENTITY_FORBIDDEN")
    if value is not None and _ADDRESS.search(value):
        raise ValueError(f"COUNTERPARTY_IDENTITY_FORBIDDEN: {what} is an opaque ref, a commitment or plain text, never an address")


def _horizon(value: Any) -> int:
    """A whole number of years from 1 to 40; a string, float or bool is refused rather than truncated."""
    _require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 40, "HORIZON_OUT_OF_RANGE", "horizon_years is a whole number of years from 1 to 40")
    return int(value)


def _moment(value: str, *, end: bool) -> datetime:
    """A date or a UTC timestamp as a moment; a bare date bounds the whole day (its start, or the start of the next day when it is an end)."""
    if value.endswith("Z"):
        return parsed(value)
    day = datetime.fromisoformat(value)
    if day.tzinfo is not None or len(value) != 10:
        raise ValueError("a bare date is YYYY-MM-DD")
    day = day.replace(tzinfo=timezone.utc)
    return day + timedelta(days=1) if end else day


def _effective(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    try:
        if value.endswith("Z"):
            return timestamp(value, field_name=field_name)
        _moment(value, end=False)
    except ValueError as exc:
        raise ValueError(f"{field_name} is a date (YYYY-MM-DD) or an ISO-8601 UTC timestamp ending in Z") from exc
    return value


def _in_force(line: RemunerationLine, as_of: str) -> bool:
    """Whether the line is in force at the schedule date: a line without dates always is."""
    at = parsed(as_of)
    if line.effective_from is not None and at < _moment(line.effective_from, end=False):
        return False
    return line.effective_to is None or at < _moment(line.effective_to, end=True)


# --------------------------------------------------------------------------- #
# The schedule: cited lines
# --------------------------------------------------------------------------- #


class RemunerationLine(ResearchModel):
    """One line of the provider's or licensee's schedule: who pays what on which product, cited to the document that says so."""

    model_config = ConfigDict(hide_input_in_errors=True)

    provider_ref: OpaqueRef
    product_ref: OpaqueRef | None = None
    kind: RemunerationKind
    rate_percent: Decimal | None = Field(default=None, ge=0)
    amount: Decimal | None = Field(default=None, ge=0)
    currency: str | None = None
    payer: Payer
    basis: ShortText
    source: SourceCitation
    effective_from: str | None = None
    effective_to: str | None = None

    @field_validator("rate_percent", "amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _figure(value, info)

    @field_validator("effective_from", "effective_to")
    @classmethod
    def _dates(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _effective(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _cited(self) -> RemunerationLine:
        if not self.source.cited:
            raise ValueError("REMUNERATION_UNCITED: a remuneration line is cited to the schedule document with a verbatim quote, or it is refused")
        if self.kind in ("none", "unstated") and (self.rate_percent or self.amount):
            raise ValueError(f"REMUNERATION_LINE_INCONSISTENT: a line of kind {self.kind} carries no rate or amount; name the kind the figure is paid as")
        if self.effective_from is not None and self.effective_to is not None and _moment(self.effective_to, end=True) <= _moment(self.effective_from, end=False):
            raise ValueError("REMUNERATION_LINE_INCONSISTENT: effective_to is on or after effective_from")
        _refuse_address(self.provider_ref, what="provider_ref")
        _refuse_address(self.product_ref, what="product_ref")
        _refuse_address(self.basis, what="basis")
        return self

    @property
    def label(self) -> str:
        return self.product_ref or self.provider_ref

    @property
    def citation(self) -> str:
        title = self.source.document_title or "the schedule document"
        return f"{title}, {self.source.url}, retrieved {self.source.retrieved_at}"


class RemunerationSchedule(ResearchModel):
    """The lines a business is paid under, sealed as read on one date."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_id: str = Field(default=REMUNERATION_SCHEMA, alias="schema")
    business_ref: OpaqueRef
    jurisdiction: Literal["AU", "CA"]
    lines: tuple[RemunerationLine, ...] = Field(default_factory=tuple, max_length=MAX_LINES)
    as_of: str
    schedule_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> RemunerationSchedule:
        _refuse_address(self.business_ref, what="business_ref")
        digests = [stable_digest(line.to_dict()) for line in self.lines]
        if len(digests) != len(set(digests)):
            raise ValueError("REMUNERATION_LINE_DUPLICATE: the same line appears twice and would be counted twice")
        if not skip_digests(info) and self.schedule_digest != sealed_digest(RemunerationSchedule, self, "schedule_digest"):
            raise ValueError("schedule_digest does not match the schedule")
        return self

    def _matching(self, *, product_ref: str, provider_ref: str) -> tuple[tuple[RemunerationLine, ...], tuple[RemunerationLine, ...]]:
        product_lines = tuple(line for line in self.lines if line.product_ref == product_ref)
        provider_lines = tuple(line for line in self.lines if line.product_ref is None and line.provider_ref == provider_ref)
        return product_lines, provider_lines

    def lines_for(self, *, product_ref: str, provider_ref: str) -> tuple[tuple[RemunerationLine, ...], ResolvedBy]:
        """Every line in force at as_of at the most specific level that names the product or its provider, in schedule order."""
        product_lines, provider_lines = self._matching(product_ref=product_ref, provider_ref=provider_ref)
        live_product = tuple(line for line in product_lines if _in_force(line, self.as_of))
        if live_product:
            return live_product, "product"
        live_provider = tuple(line for line in provider_lines if _in_force(line, self.as_of))
        if live_provider:
            return live_provider, "provider"
        return (), "none"

    def dormant_for(self, *, product_ref: str, provider_ref: str) -> tuple[RemunerationLine, ...]:
        """The lines naming the product or its provider that are not in force at as_of and so are not read."""
        product_lines, provider_lines = self._matching(product_ref=product_ref, provider_ref=provider_ref)
        return tuple(line for line in (*product_lines, *provider_lines) if not _in_force(line, self.as_of))


def remuneration_schedule(business_ref: str, *, jurisdiction: str, lines: Sequence[RemunerationLine | Mapping[str, Any]], as_of: str) -> RemunerationSchedule:
    """Seal the schedule; a line without a source citation (URL, retrieval date and quote) is refused REMUNERATION_UNCITED."""
    parsed: list[dict[str, Any]] = []
    for index, raw in enumerate(lines):
        if isinstance(raw, RemunerationLine):
            parsed.append(raw.to_dict())
            continue
        payload = dict(detached(raw))
        source = payload.get("source")
        _require(isinstance(source, Mapping) and bool(str(source.get("url") or "").strip()) and bool(str(source.get("quote") or "").strip()), "REMUNERATION_UNCITED", f"line {index + 1} carries no source citation with a URL and a verbatim quote; every remuneration line is cited to the provider's or licensee's own document")
        parsed.append(payload)
    return seal(RemunerationSchedule, {"business_ref": business_ref, "jurisdiction": jurisdiction, "lines": parsed, "as_of": timestamp(as_of, field_name="as_of")}, "schedule_digest")


def remuneration_lines_for(schedule: RemunerationSchedule | Mapping[str, Any], *, product_ref: str, provider_ref: str) -> tuple[RemunerationLine, ...]:
    """Every line for the product, else every provider-level line, else nothing."""
    s = schedule if isinstance(schedule, RemunerationSchedule) else RemunerationSchedule.model_validate(dict(detached(schedule)))
    return s.lines_for(product_ref=product_ref, provider_ref=provider_ref)[0]


def remuneration_for(schedule: RemunerationSchedule | Mapping[str, Any], *, product_ref: str, provider_ref: str) -> RemunerationLine | None:
    """The first line that names the product, else the first provider-level line, else None (a product line beats a provider line beats None)."""
    lines = remuneration_lines_for(schedule, product_ref=product_ref, provider_ref=provider_ref)
    return lines[0] if lines else None


# --------------------------------------------------------------------------- #
# The conflicts register: opaque counterparties
# --------------------------------------------------------------------------- #


class ConflictEntry(StrictModel):
    """One arrangement that could bear on a recommendation; the counterparty is a ref or a commitment, never a name."""

    identity_refusal_code: ClassVar[str] = "COUNTERPARTY_IDENTITY_FORBIDDEN"

    conflict_ref: OpaqueRef
    kind: ConflictKind
    counterparty_ref: OpaqueRef
    applies_to_provider_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    applies_to_product_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    disclosure_text: BoundedText
    management: ShortText
    recorded_at: str

    @model_validator(mode="wrap")
    @classmethod
    def _no_identity(cls, value: Any, handler: Any) -> Any:
        return handler(_refuse_identity(value, what="a conflict entry"))

    @field_validator("applies_to_provider_refs", "applies_to_product_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("recorded_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="recorded_at")

    @model_validator(mode="after")
    def _opaque(self) -> ConflictEntry:
        if "@" in self.counterparty_ref:
            raise ValueError("COUNTERPARTY_IDENTITY_FORBIDDEN: a counterparty is an opaque ref or a commitment, never an address")
        if _ADDRESS.search(self.disclosure_text) or _ADDRESS.search(self.management):
            raise ValueError("COUNTERPARTY_IDENTITY_FORBIDDEN: the disclosure text and its management name no address; a counterparty is an opaque ref or a commitment")
        return self

    @property
    def business_wide(self) -> bool:
        """An entry that names no provider and no product is business-wide (an ownership or an approved product list, say) and reaches every recommendation; it is never hidden by its lack of scope."""
        return not self.applies_to_provider_refs and not self.applies_to_product_refs

    def reaches(self, *, provider_ref: str, product_ref: str) -> bool:
        return self.business_wide or provider_ref in self.applies_to_provider_refs or product_ref in self.applies_to_product_refs


class ConflictsRegister(StrictModel):
    identity_refusal_code: ClassVar[str] = "COUNTERPARTY_IDENTITY_FORBIDDEN"
    schema_id: str = Field(default=CONFLICTS_SCHEMA, alias="schema")
    business_ref: OpaqueRef
    entries: tuple[ConflictEntry, ...] = Field(default_factory=tuple, max_length=MAX_LINES)
    recorded_at: str
    register_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("recorded_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="recorded_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ConflictsRegister:
        _refuse_address(self.business_ref, what="business_ref")
        refs = [entry.conflict_ref for entry in self.entries]
        if len(refs) != len(set(refs)):
            raise ValueError("conflict_ref must be unique within a register")
        if not skip_digests(info) and self.register_digest != sealed_digest(ConflictsRegister, self, "register_digest"):
            raise ValueError("register_digest does not match the register")
        return self

    def reaching(self, *, provider_ref: str, product_ref: str) -> tuple[ConflictEntry, ...]:
        return tuple(entry for entry in self.entries if entry.reaches(provider_ref=provider_ref, product_ref=product_ref))


def conflicts_register(business_ref: str, entries: Sequence[ConflictEntry | Mapping[str, Any]], *, recorded_at: str) -> ConflictsRegister:
    """Seal the register; identity keys on an entry are refused before anything is read."""
    return seal(ConflictsRegister, {"business_ref": business_ref, "entries": [dict(detached(item)) for item in entries], "recorded_at": timestamp(recorded_at, field_name="recorded_at")}, "register_digest")


# --------------------------------------------------------------------------- #
# Arithmetic: what a line pays over a horizon
# --------------------------------------------------------------------------- #


def adviser_income(line: RemunerationLine | Mapping[str, Any], *, amount: Decimal | str | None, horizon_years: int) -> tuple[Decimal | None, tuple[str, ...]]:
    """The figure one line pays over the horizon and the assumptions it rests on: an upfront rate on the amount once, a trail rate per year on the amount held flat, a stated amount as stated."""
    ln = line if isinstance(line, RemunerationLine) else RemunerationLine.model_validate(dict(detached(line)))
    horizon_years = _horizon(horizon_years)
    base = _decimal(amount)
    _require(amount is None or (base is not None and base >= 0), "AMOUNT_NOT_NUMERIC", "amount is a non-negative finite figure, or None when no amount is stated")
    words = _KIND_WORDS[ln.kind]
    who = ln.label
    if ln.kind == "none":
        return Decimal("0.00"), (f"{who}: the schedule states no remuneration ({ln.citation})",)
    if ln.kind == "unstated":
        return None, (f"{who}: the schedule names remuneration of an unstated kind and no figure; the adviser states what is received ({ln.citation})",)
    per_year = ln.kind == "trail_commission"
    if ln.rate_percent is not None:
        if base is None:
            return None, (f"{who}: a {words} of {ln.rate_percent}% needs an amount to apply to and none is stated; the figure is shown as a rate only ({ln.citation})",)
        once = _money(base * ln.rate_percent / Decimal("100"))
        if per_year:
            total = _money(once * Decimal(int(horizon_years)))
            return total, (f"{who}: {words} of {ln.rate_percent}% per year on {base} held flat for {horizon_years} year(s) = {total}; no growth, repayment or lapse is assumed ({ln.citation})",)
        return once, (f"{who}: {words} of {ln.rate_percent}% of {base}, paid once = {once} ({ln.citation})",)
    if ln.amount is not None:
        if per_year:
            total = _money(ln.amount * Decimal(int(horizon_years)))
            return total, (f"{who}: {words} of {ln.amount} per year for {horizon_years} year(s) = {total} ({ln.citation})",)
        total = _money(ln.amount)
        return total, (f"{who}: {words} of {total} as stated, counted once ({ln.citation})",)
    return None, (f"{who}: the schedule names a {words} without a rate or an amount; the adviser states the figure ({ln.citation})",)


def _income_over(lines: Sequence[RemunerationLine], *, amount: Decimal | None, horizon_years: int) -> tuple[Decimal | None, list[str]]:
    """Sum the lines that have a figure; None when no line has one."""
    total: Decimal | None = None
    assumptions: list[str] = []
    for line in lines:
        figure, notes = adviser_income(line, amount=amount, horizon_years=horizon_years)
        assumptions.extend(notes)
        if figure is not None:
            total = figure if total is None else _money(total + figure)
    return total, assumptions


# --------------------------------------------------------------------------- #
# The disclosure per recommendation
# --------------------------------------------------------------------------- #


class AlternativeRemuneration(ResearchModel):
    model_config = ConfigDict(hide_input_in_errors=True)
    product_ref: OpaqueRef
    provider_ref: OpaqueRef
    product_name: str
    line: RemunerationLine | None = None
    lines: tuple[RemunerationLine, ...] = Field(default_factory=tuple)
    resolved_by: ResolvedBy = "none"
    income: Decimal | None = None

    @field_validator("lines", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("income", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _figure(value, info)


class RemunerationDisclosure(ResearchModel):
    """What the adviser earns on the recommended product against each alternative, the conflicts that reach it, and the findings, sealed."""

    model_config = ConfigDict(hide_input_in_errors=True)

    schema_id: str = Field(default=REMUNERATION_DISCLOSURE_SCHEMA, alias="schema")
    jurisdiction: Literal["AU", "CA"]
    family: ShortText
    vertical_id: str
    recommendation_digest: Sha256Digest
    shortlist_digest: Sha256Digest
    schedule_digest: Sha256Digest
    register_digest: Sha256Digest | None = None
    recommended_product_ref: OpaqueRef
    recommended_provider_ref: OpaqueRef
    recommended: RemunerationLine | None = None
    recommended_lines: tuple[RemunerationLine, ...] = Field(default_factory=tuple)
    resolved_by: ResolvedBy = "none"
    recommended_income: Decimal | None = None
    amount_basis: Decimal | None = None
    currency: str | None = None
    horizon_years: int = Field(ge=1, le=40)
    alternatives: tuple[AlternativeRemuneration, ...] = Field(default_factory=tuple)
    conflicts: tuple[ConflictEntry, ...] = Field(default_factory=tuple)
    findings: tuple[RemunerationFinding, ...] = Field(default_factory=tuple)
    statements: tuple[str, ...] = Field(default_factory=tuple)
    assumptions: tuple[str, ...] = Field(default_factory=tuple)
    missing: tuple[str, ...] = Field(default_factory=tuple)
    clear: bool
    disclaimer: str = DISCLAIMER
    prepared_at: str
    disclosure_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("recommended_lines", "alternatives", "conflicts", "findings", "statements", "assumptions", "missing", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("recommended_income", "amount_basis", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return _figure(value, info)

    @field_validator("prepared_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> RemunerationDisclosure:
        if self.clear != all(item in _INFORMATIONAL_FINDINGS for item in self.findings):
            raise ValueError("clear is true exactly when no finding other than fee_for_service_only is present")
        if not skip_digests(info) and self.disclosure_digest != sealed_digest(RemunerationDisclosure, self, "disclosure_digest"):
            raise ValueError("disclosure_digest does not match the disclosure")
        return self


def _amount_basis(state: ClientState | None, amount: Decimal | str | None, family: str) -> tuple[Decimal | None, list[str], list[str]]:
    """The client amount the schedule's rates apply to: the caller's figure, else the state's amount, else the premium facts for insurance."""
    if amount is not None:
        figure = _decimal(amount)
        _require(figure is not None and figure >= 0, "AMOUNT_NOT_NUMERIC", "amount is a non-negative figure")
        return figure, [f"rates are applied to the amount {figure} supplied by the caller"], []
    if state is None:
        return None, [], ["no client amount to apply the schedule's rates to; rate-based lines are shown as rates only"]
    facts = state.facts if isinstance(state.facts, Mapping) else {}
    if family == "insurance":
        # an insurance commission is a rate on the premium; the client's stated amount is the sum insured and is never the basis
        for key in ("annual_premium", "premium_per_year", "premium"):
            figure = _decimal(facts.get(key))
            if figure is not None and figure >= 0:
                return figure, [f"rates are applied to the client's fact {key} = {figure}, the premium"], []
        held = f"the client's stated amount {state.amount} is the sum insured, not a premium, and " if state.amount is not None else ""
        return None, [], [f"{held}the client state carries no premium to apply the schedule's rates to; rate-based lines are shown as rates only until a premium is supplied"]
    if state.amount is not None:
        return state.amount, [f"rates are applied to the client's stated amount {state.amount}"], []
    for key in ("amount", "balance", "contribution"):
        figure = _decimal(facts.get(key))
        if figure is not None and figure >= 0:
            return figure, [f"rates are applied to the client's fact {key} = {figure}"], []
    return None, [], ["the client state carries no amount to apply the schedule's rates to; rate-based lines are shown as rates only"]


def _line_sentence(who: str, line: RemunerationLine, *, figure: Decimal | None, currency: str | None, horizon_years: int) -> str:
    words = _KIND_WORDS[line.kind]
    ccy = f" {currency}" if currency else ""
    if line.kind == "none":
        return f"{who}: the adviser receives no remuneration ({line.citation})."
    if line.kind == "unstated":
        return f"{who}: the schedule names remuneration of an unstated kind and no figure; the adviser states what is received ({line.citation})."
    stated = f"{line.rate_percent}%" if line.rate_percent is not None else (f"{_money(line.amount)}{ccy}" if line.amount is not None else "an unstated figure")
    per = " per year" if line.kind == "trail_commission" else ""
    figure_text = "" if figure is None else (f" = {figure}{ccy} over {horizon_years} year(s)" if line.kind == "trail_commission" else f" = {figure}{ccy}, counted once")
    return f"{who}: the adviser receives {words} of {stated}{per}, paid by the {line.payer}{figure_text}; basis: {line.basis} ({line.citation})."


def remuneration_disclosure(schedule: RemunerationSchedule | Mapping[str, Any], recommendation: Recommendation | Mapping[str, Any], shortlist: Shortlist | Mapping[str, Any], *, register: ConflictsRegister | Mapping[str, Any] | None = None, state: ClientState | Mapping[str, Any] | None = None, family: str, horizon_years: int = 1, amount: Decimal | str | None = None, prepared_at: str) -> RemunerationDisclosure:
    """Resolve the schedule for the recommended product and each alternative, put figures on them, carry the conflicts that reach the recommendation, and name the findings."""
    sch = schedule if isinstance(schedule, RemunerationSchedule) else RemunerationSchedule.model_validate(dict(detached(schedule)))
    rec = recommendation if isinstance(recommendation, Recommendation) else Recommendation.model_validate(dict(detached(recommendation)))
    sl = shortlist if isinstance(shortlist, Shortlist) else Shortlist.model_validate(dict(detached(shortlist)))
    reg = None if register is None else (register if isinstance(register, ConflictsRegister) else ConflictsRegister.model_validate(dict(detached(register))))
    st = None if state is None else (state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state))))
    stamp = timestamp(prepared_at, field_name="prepared_at")
    horizon_years = _horizon(horizon_years)
    family = str(family).strip().lower()
    _require(bool(family), "FAMILY_UNSTATED", "family names the product family the disclosure is for (credit, deposits, insurance or investments)")
    _require(rec.shortlist_digest == sl.shortlist_digest, "DISCLOSURE_INPUTS_MISMATCH", "the recommendation was prepared from a different shortlist")
    _require(st is None or st.state_digest == rec.state_digest, "DISCLOSURE_INPUTS_MISMATCH", "the client state is not the one the recommendation was prepared from")
    expected = st.jurisdiction if st is not None else rec.vertical_id.split("-")[0]
    _require(sch.jurisdiction == expected, "DISCLOSURE_INPUTS_MISMATCH", f"the schedule is a {sch.jurisdiction} schedule; the recommendation is {expected} ({rec.vertical_id})")
    by_ref: dict[str, ShortlistEntry] = {entry.product_ref: entry for entry in sl.entries}
    primary = by_ref.get(rec.primary_product_ref)
    _require(primary is not None, "PRODUCT_NOT_SHORTLISTED", f"{rec.primary_product_ref} is not on the shortlist")
    assert primary is not None
    jurisdiction = sch.jurisdiction
    base, assumptions, missing = _amount_basis(st, amount, family)
    rec_lines, resolved = sch.lines_for(product_ref=primary.product_ref, provider_ref=primary.provider_ref)
    rec_income, notes = _income_over(rec_lines, amount=base, horizon_years=horizon_years)
    assumptions.extend(notes)
    dormant = sch.dormant_for(product_ref=primary.product_ref, provider_ref=primary.provider_ref)
    if dormant:
        assumptions.append(f"{len(dormant)} schedule line(s) naming the recommended product or its provider are not in force at {sch.as_of} and are not read")
    stated_currency = next((line.currency for line in rec_lines if line.currency), None)
    currency = stated_currency or _CURRENCY_BY_JURISDICTION.get(jurisdiction)
    if stated_currency is None and currency:
        assumptions.append(f"no schedule line for the recommended product names a currency; figures are taken to be in {currency}, the {jurisdiction} currency")
    alternative_refs = list(rec.alternatives) or [entry.product_ref for entry in sl.entries if entry.product_ref != primary.product_ref]
    assumptions.append("the alternatives compared are " + ("those the recommendation names" if rec.alternatives else "the other shortlisted products, because the recommendation names none"))
    alternatives: list[AlternativeRemuneration] = []
    for ref in alternative_refs:
        entry = by_ref.get(ref)
        if entry is None:
            missing.append(f"alternative {ref} is not on the shortlist; its remuneration is not compared")
            continue
        lines, how = sch.lines_for(product_ref=entry.product_ref, provider_ref=entry.provider_ref)
        income, notes = _income_over(lines, amount=base, horizon_years=horizon_years)
        assumptions.extend(notes)
        if not lines:
            missing.append(f"no schedule line covers the alternative {entry.product_name} ({entry.product_ref}) or its provider")
        alternatives.append(AlternativeRemuneration(product_ref=entry.product_ref, provider_ref=entry.provider_ref, product_name=entry.product_name, line=lines[0] if lines else None, lines=lines, resolved_by=how, income=income))
    findings: list[str] = []
    statements: list[str] = []
    recommended_label = f"the recommended {primary.product_name} ({primary.provider_name})"
    if rec_lines:
        for line in rec_lines:
            figure, _ = adviser_income(line, amount=base, horizon_years=horizon_years)
            statements.append(_line_sentence(recommended_label, line, figure=figure, currency=currency, horizon_years=horizon_years))
        if resolved == "provider":
            statements.append(f"{recommended_label}: the figures come from the provider-level line(s); no line names the product itself.")
    else:
        findings.append("schedule_missing_for_recommended")
        missing.append(f"no schedule line covers {recommended_label} or its provider")
        statements.append(f"{recommended_label}: the schedule {sch.schedule_digest[:12]} carries no line for the product or its provider; the adviser states what is received before the disclosure is given.")
    for alt in alternatives:
        label = f"the alternative {alt.product_name}"
        if alt.lines:
            for line in alt.lines:
                figure, _ = adviser_income(line, amount=base, horizon_years=horizon_years)
                statements.append(_line_sentence(label, line, figure=figure, currency=currency, horizon_years=horizon_years))
        else:
            statements.append(f"{label}: the schedule carries no line for the product or its provider.")
    currencies = sorted({line.currency for line in (*rec_lines, *(line for alt in alternatives for line in alt.lines)) if line.currency})
    if len(currencies) > 1:
        missing.append(f"the schedule lines compared carry more than one currency ({', '.join(currencies)}); figures are stated in each line's own currency and are not converted")
    known = [alt for alt in alternatives if alt.income is not None]
    unknown = [alt for alt in alternatives if alt.income is None]
    ccy = f" {currency}" if currency else ""
    if rec_income is not None and known and all(rec_income > alt.income for alt in known if alt.income is not None):
        findings.append("recommended_pays_more")
        against = "; ".join(f"{alt.product_name} {alt.income}{ccy}" for alt in known)
        tail = f"; no figure for {', '.join(alt.product_name for alt in unknown)}" if unknown else ""
        statements.append(f"The recommendation pays the adviser more than every alternative with a figure: {rec_income}{ccy} on {primary.product_name} against {against}{tail}. The client weighs this against the reasons given for the recommendation.")
    elif rec_income is not None and known:
        against = "; ".join(f"{alt.product_name} {alt.income}{ccy}" for alt in known)
        statements.append(f"The recommendation pays the adviser {rec_income}{ccy} on {primary.product_name} against {against}; it does not pay more than every alternative.")
    elif rec_income is not None:
        statements.append(f"The recommendation pays the adviser {rec_income}{ccy} on {primary.product_name}; no alternative has a figure to compare.")
    if jurisdiction == "AU" and family in AU_CONFLICTED_FAMILIES:
        conflicted = [line for line in rec_lines if line.kind in AU_CONFLICTED_KINDS]
        if conflicted:
            findings.append("conflicted_kind_for_family")
            kinds = ", ".join(dict.fromkeys(_KIND_WORDS[line.kind] for line in conflicted))
            statements.append(f"The {kinds} on {recommended_label} is a kind the conflicted-remuneration table names for {family} ({_rule_stamp(AU_CONFLICTED_REMUNERATION_RULE)}); whether an exemption reaches this product is the operator's mapping.")
    if jurisdiction == "AU":
        for row in AU_LIFE_COMMISSION_CAPS:
            if rec.vertical_id not in row["verticals"]:
                continue
            cap = Decimal(str(row["parameters"]["max_percent"]))
            for line in rec_lines:
                if line.kind == row["parameters"]["kind"] and line.rate_percent is not None and line.rate_percent > cap:
                    findings.append("cap_exceeded")
                    statements.append(f"The {_KIND_WORDS[line.kind]} of {line.rate_percent}% on {recommended_label} is above the {cap}% cap the table carries ({_rule_stamp(row)}); the figure is flagged, not judged, until the operator confirms the row.")
    conflicts: tuple[ConflictEntry, ...] = ()
    if reg is None:
        findings.append("undisclosed_conflict")
        missing.append("no conflicts register was supplied; whether an arrangement reaches the recommended provider or product is unknown")
        statements.append("No conflicts register was supplied, so no arrangement reaching the recommended provider or product has been disclosed.")
    else:
        conflicts = reg.reaching(provider_ref=primary.provider_ref, product_ref=primary.product_ref)
        for entry in conflicts:
            statements.append(f"Conflict {entry.conflict_ref} ({entry.kind.replace('_', ' ')}) reaches {recommended_label}: {entry.disclosure_text} Managed by: {entry.management}")
        if not conflicts:
            statements.append(f"The conflicts register {reg.register_digest[:12]} carries no arrangement reaching {recommended_label}.")
    if rec_lines and all(line.kind == "fee_for_service" for line in rec_lines):
        findings.append("fee_for_service_only")
        statements.append(f"{recommended_label}: the adviser is paid a fee for service only; no provider pays the adviser on this product.")
    unique_findings = list(dict.fromkeys(findings))
    clear = all(item in _INFORMATIONAL_FINDINGS for item in unique_findings)
    assumptions.append(f"figures are over {horizon_years} year(s) in {currency or 'the schedule currency'}, quantised to cents")
    return seal(RemunerationDisclosure, {
        "jurisdiction": jurisdiction,
        "family": family,
        "vertical_id": rec.vertical_id,
        "recommendation_digest": rec.recommendation_digest,
        "shortlist_digest": sl.shortlist_digest,
        "schedule_digest": sch.schedule_digest,
        "register_digest": reg.register_digest if reg is not None else None,
        "recommended_product_ref": primary.product_ref,
        "recommended_provider_ref": primary.provider_ref,
        "recommended": rec_lines[0].to_dict() if rec_lines else None,
        "recommended_lines": [line.to_dict() for line in rec_lines],
        "resolved_by": resolved,
        "recommended_income": rec_income,
        "amount_basis": base,
        "currency": currency,
        "horizon_years": int(horizon_years),
        "alternatives": [alt.to_dict() for alt in alternatives],
        "conflicts": [entry.to_dict() for entry in conflicts],
        "findings": unique_findings,
        "statements": statements,
        "assumptions": list(dict.fromkeys(assumptions)),
        "missing": list(dict.fromkeys(missing)),
        "clear": clear,
        "prepared_at": stamp,
    }, "disclosure_digest")


def disclosure_statements(disclosure: RemunerationDisclosure | Mapping[str, Any]) -> tuple[str, ...]:
    """The sealed statements in order, then the findings line and the disclaimer; what the record and the client document print."""
    d = disclosure if isinstance(disclosure, RemunerationDisclosure) else RemunerationDisclosure.model_validate(dict(detached(disclosure)))
    findings = ", ".join(item.replace("_", " ") for item in d.findings) if d.findings else "none"
    return (*d.statements, f"Findings: {findings}.", d.disclaimer)


REMUNERATION_MANIFEST: dict[str, Any] = {
    "schemas": {"schedule": REMUNERATION_SCHEMA, "register": CONFLICTS_SCHEMA, "disclosure": REMUNERATION_DISCLOSURE_SCHEMA},
    "kinds": list(RemunerationKind.__args__),
    "conflict_kinds": list(ConflictKind.__args__),
    "findings": list(RemunerationFinding.__args__),
    "informational_findings": sorted(_INFORMATIONAL_FINDINGS),
    "resolution": "a line naming the product beats a provider-level line beats none; only lines in force at the schedule's as_of are read (a line without dates always is) and every line at the winning level is summed; a conflict entry naming no provider and no product is business-wide and reaches every recommendation",
    "arithmetic": "an upfront rate is applied to the amount once; a trail rate per year on the amount held flat over the horizon; a stated amount is counted as stated; for insurance the basis is a premium fact, never the sum insured; every step is an assumption string",
    "tables": {"au_conflicted_remuneration": {**AU_CONFLICTED_REMUNERATION_RULE, "verticals": []}, "au_life_commission_caps": [{**row, "verticals": list(row["verticals"])} for row in AU_LIFE_COMMISSION_CAPS]},
    "hard_rules": [
        "every remuneration line is cited to the provider's or licensee's own document with a verbatim quote, or it is refused",
        "counterparties and payers are opaque refs or commitments; identity keys are refused before an entry is read",
        "a table row carried with confirmed=False is named 'not yet confirmed by the operator' in every finding built on it",
        "the disclosure states figures and flags findings; it never decides, ranks, or advises",
    ],
    "not_claimed": "the disclosure is evidence for the licensed adviser's own disclosure; which exemptions reach a product, and Canadian remuneration rules, are the operator's mapping and are not in the tables",
}

__all__ = [
    "AU_CONFLICTED_FAMILIES",
    "AU_CONFLICTED_KINDS",
    "AU_CONFLICTED_REMUNERATION_RULE",
    "AU_LIFE_COMMISSION_CAPS",
    "CONFLICTS_SCHEMA",
    "DISCLAIMER",
    "FORBIDDEN_COUNTERPARTY_KEYS",
    "MAX_LINES",
    "REMUNERATION_DISCLOSURE_SCHEMA",
    "REMUNERATION_MANIFEST",
    "REMUNERATION_SCHEMA",
    "AdviceRemunerationError",
    "AlternativeRemuneration",
    "ConflictEntry",
    "ConflictKind",
    "ConflictsRegister",
    "RemunerationDisclosure",
    "RemunerationFinding",
    "RemunerationKind",
    "RemunerationLine",
    "RemunerationSchedule",
    "adviser_income",
    "conflicts_register",
    "disclosure_statements",
    "remuneration_disclosure",
    "remuneration_for",
    "remuneration_lines_for",
    "remuneration_schedule",
]
