"""Quotes: rating profiles per vertical, quotes captured against them, and a client matched to the nearest profile.

Most insurance and much lending is quote-required: the provider prices the individual, and a
catalog can hold no list price. The engine cannot rank a product without a price, so the program
captures quotes against *rating profiles*, non-identifying combinations of the facts a provider
rates on (a 35-year-old non-smoker in NSW seeking $500,000 of term life), stores each quote as an
accepted observation whose applicability is the profile, and ranks a client on the quotes of the
profile that matches them. A quote is evidence of a price for that profile on that day from that
provider's own quote tool; it is never the client's price, and the shortlist says so.

Nothing here identifies a person: a profile carries decision facts only, the same facts the fact
find collects, and the client state is matched to it by distance, with every difference disclosed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import ConfigDict, Field, field_validator, model_validator

from lightbulb.company_engine_core import OpaqueRef, detached, parsed, seal, timestamp
from lightbulb.finance_advice_catalog import ProductCatalog, ResearchModel, VerticalRegistry, load_vertical_registry
from lightbulb.finance_advice_engine import ClientState, sector_family
from lightbulb.finance_advice_identity import reject_identity_payload
from lightbulb.finance_advice_observations import Observation, observe, published_catalog

QUOTE_PROFILE_SCHEMA = "lightbulb.finance_advice_quote_profile.v1"
QUOTE_CAPTURE_SCHEMA = "lightbulb.finance_advice_quote_capture.v1"
QUOTE_ADAPTER = "quote_capture"
QUOTE_VALIDITY_DAYS = 30
QUOTE_FIELD_PREFIX = "pricing:premium"
FORBIDDEN_PROFILE_KEYS = frozenset({"name", "first_name", "last_name", "email", "phone", "address", "date_of_birth", "dob", "tax_file_number", "sin", "ssn", "licence_number", "policy_number", "account_number", "quote_holder"})

# The rating facts each sector prices on, and the standard values the program captures quotes for.
# Engineering starting points: they name what a provider's quote tool asks, not what a client is.
_PROFILE_AXES: dict[str, dict[str, tuple[Any, ...]]] = {
    "life": {"age": (30, 40, 50), "smoker": (False, True), "sum_insured": (500000, 1000000)},
    "income_protection": {"age": (35, 45), "occupation_class": ("professional", "trades"), "monthly_benefit": (5000, 8000)},
    "health": {"cover_type": ("single", "family"), "tier": ("basic", "silver", "gold")},
    "motor": {"driver_age": (25, 40, 60), "vehicle_class": ("small_car", "family_suv"), "excess": ("standard",)},
    "home": {"sum_insured": (500000, 900000), "cover": ("building_and_contents",)},
    "travel": {"age": (30, 65), "trip_days": (14,), "destination": ("worldwide",)},
    "pet": {"animal": ("dog", "cat"), "age_years": (2, 7)},
    "mortgage_default": {"lvr_band": ("80.01-85", "90.01-95"), "amount": (500000,)},
    "credit": {"amount": (400000, 750000), "lvr_percent": (70, 90), "term_years": (25,), "purpose": ("owner_occupied",)},
    "deposits": {"amount": (10000, 50000), "term_months": (12,)},
    "investments": {"amount": (50000,), "horizon_years": (7,)},
}
_VERTICAL_AXES: dict[str, str] = {
    "AU-32": "life", "CA-35": "life", "AU-44": "life", "CA-46": "life",
    "AU-33": "income_protection", "AU-34": "life", "AU-35": "life", "CA-36": "income_protection", "CA-37": "life", "CA-38": "life",
    "AU-31": "health", "CA-39": "health",
    "AU-40": "motor", "AU-41": "motor", "CA-44": "motor",
    "AU-36": "home", "AU-37": "home", "AU-38": "home", "AU-39": "home", "CA-41": "home", "CA-42": "home", "CA-43": "home",
    "AU-42": "travel", "CA-40": "travel",
    "AU-43": "pet", "CA-45": "pet",
    "CA-48": "mortgage_default", "AU-45": "credit", "CA-47": "credit",
}
class AdviceQuoteError(ValueError):
    pass


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise AdviceQuoteError(f"{code}: {detail}")


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value).replace(",", "").replace("%", "").replace("$", "").strip())
    except (InvalidOperation, ValueError):
        return None


class QuoteProfile(ResearchModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    @model_validator(mode="before")
    @classmethod
    def _no_free_text_identity(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and isinstance(value.get("inputs"), Mapping):
            cls._no_identity(dict(value["inputs"]))
        reject_identity_payload(value)
        return value

    schema_id: str = Field(default=QUOTE_PROFILE_SCHEMA, alias="schema")
    profile_ref: str
    vertical_id: str
    jurisdiction: str
    label: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    axes: str

    @field_validator("inputs")
    @classmethod
    def _no_identity(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if key.lower() in FORBIDDEN_PROFILE_KEYS:
                raise ValueError(f"a rating profile carries decision facts, never {key}")
        return value


def profile_ref(vertical_id: str, inputs: Mapping[str, Any]) -> str:
    return "profile:" + _digest(vertical_id, dict(inputs))[:24]


def quote_axes_for(vertical_id: str, registry: VerticalRegistry | None = None) -> str:
    """The rating axes a vertical prices on: an explicit table first, else the sector family."""

    if vertical_id in _VERTICAL_AXES:
        return _VERTICAL_AXES[vertical_id]
    registry = registry or load_vertical_registry()
    family = sector_family(registry.vertical(vertical_id).sector)
    return {"credit": "credit", "deposits": "deposits", "investments": "investments", "insurance": "home"}.get(family, "credit")


def standard_profiles(vertical_id: str, registry: VerticalRegistry | None = None) -> tuple[QuoteProfile, ...]:
    """Every combination of the vertical's standard rating values, labelled in plain words."""

    registry = registry or load_vertical_registry()
    vertical = registry.vertical(vertical_id)
    axes = quote_axes_for(vertical_id, registry)
    table = _PROFILE_AXES[axes]
    combos: list[dict[str, Any]] = [{}]
    for key, values in table.items():
        combos = [{**combo, key: value} for combo in combos for value in values]
    out: list[QuoteProfile] = []
    for inputs in combos:
        label = ", ".join(f"{key.replace('_', ' ')} {('yes' if value else 'no') if isinstance(value, bool) else value}" for key, value in inputs.items())
        out.append(QuoteProfile(profile_ref=profile_ref(vertical_id, inputs), vertical_id=vertical_id, jurisdiction=vertical.jurisdiction, label=label, inputs=dict(inputs), axes=axes))
    return tuple(out)


class ProfileMatch(ResearchModel):
    profile_ref: str
    label: str
    distance: Decimal
    differences: tuple[str, ...] = Field(default_factory=tuple)
    exact: bool

    @field_validator("differences", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


_STATE_ALIASES: dict[str, tuple[str, ...]] = {"amount": ("amount", "sum_insured", "monthly_benefit"), "sum_insured": ("sum_insured", "amount"), "age": ("age", "driver_age"), "driver_age": ("driver_age", "age"), "lvr_percent": ("lvr_percent",), "term_years": ("term_years",), "purpose": ("purpose",), "region": ("region", "state")}


def _client_value(state: ClientState, key: str) -> Any:
    facts = dict(state.facts or {})
    for candidate in _STATE_ALIASES.get(key, (key,)):
        value = getattr(state, candidate, None) if candidate in ("amount", "lvr_percent", "term_years", "purpose", "region", "residency", "age_band", "income_band") else None
        if value is not None:
            return value
        if candidate in facts and facts[candidate] is not None:
            return facts[candidate]
    if key == "age" and state.age_band:
        digits = "".join(ch if ch.isdigit() else " " for ch in str(state.age_band)).split()
        if digits:
            return int(digits[0])
    if key == "lvr_band" and state.lvr_percent is not None:
        lvr = Decimal(str(state.lvr_percent))
        for band in _PROFILE_AXES["mortgage_default"]["lvr_band"]:
            low, high = band.split("-")
            if Decimal(low) <= lvr <= Decimal(high):
                return band
    return None


def match_profile(state: ClientState | Mapping[str, Any], profiles: Sequence[QuoteProfile | Mapping[str, Any]]) -> ProfileMatch | None:
    """The nearest rating profile to the client's decision facts, with every difference named; exact on categories, nearest on numbers."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    best: ProfileMatch | None = None
    for raw in profiles:
        profile = raw if isinstance(raw, QuoteProfile) else QuoteProfile.model_validate(dict(detached(raw)))
        if profile.vertical_id != s.vertical_id:
            continue
        distance = Decimal("0")
        differences: list[str] = []
        for key, wanted in profile.inputs.items():
            have = _client_value(s, key)
            if have is None:
                distance += Decimal("0.5")
                differences.append(f"{key}: the fact find does not state it; the profile assumes {wanted}")
                continue
            if isinstance(wanted, bool) or isinstance(wanted, str):
                if str(have).lower() != str(wanted).lower():
                    distance += Decimal("1")
                    differences.append(f"{key}: client {have}, profile {wanted}")
                continue
            want = _decimal(wanted)
            got = _decimal(have)
            if want is None or got is None:
                if str(have) != str(wanted):
                    distance += Decimal("1")
                    differences.append(f"{key}: client {have}, profile {wanted}")
                continue
            if want == 0:
                gap = Decimal("0") if got == 0 else Decimal("1")
            else:
                gap = abs(got - want) / abs(want)
            if gap > 0:
                distance += min(gap, Decimal("2"))
                differences.append(f"{key}: client {have}, profile {wanted} ({(gap * 100).quantize(Decimal('1'))}% apart)")
        candidate = ProfileMatch(profile_ref=profile.profile_ref, label=profile.label, distance=distance.quantize(Decimal("0.001")), differences=tuple(differences), exact=distance == 0)
        if best is None or candidate.distance < best.distance:
            best = candidate
    return best


class QuoteCapture(ResearchModel):
    """What a person captured from a provider's own quote tool for one rating profile. No client, no policy, no person."""

    schema_id: str = Field(default=QUOTE_CAPTURE_SCHEMA, alias="schema")
    vertical_id: str
    product_ref: OpaqueRef
    profile_ref: str
    profile_inputs: dict[str, Any] = Field(default_factory=dict)
    premium: Decimal
    unit: str
    currency: str | None = None
    payment_period: str | None = None
    quoted_at: str
    valid_until: str | None = None
    source_url: str
    quote_reference: str | None = None
    captured_by_ref: OpaqueRef
    evidence_ref: str | None = None
    notes: str | None = None

    @field_validator("premium", mode="before")
    @classmethod
    def _premium(cls, value: Any) -> Decimal:
        parsed_value = _decimal(value)
        if parsed_value is None or parsed_value < 0:
            raise ValueError("a premium is a non-negative number")
        return parsed_value

    @field_validator("source_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("a quote cites the provider's quote tool by URL")
        return value

    @field_validator("profile_inputs")
    @classmethod
    def _no_identity(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if key.lower() in FORBIDDEN_PROFILE_KEYS:
                raise ValueError(f"a quote profile carries decision facts, never {key}")
        return value


def quote_field(profile_ref_value: str) -> str:
    return f"{QUOTE_FIELD_PREFIX}[profile={profile_ref_value}]"


def quote_observation(capture: QuoteCapture | Mapping[str, Any], *, source_key: str, accepted_at: str) -> Observation:
    """A captured quote as an accepted observation: the capturing person is the acceptor, the profile is the applicability, the quote expires."""

    c = capture if isinstance(capture, QuoteCapture) else QuoteCapture.model_validate(dict(detached(capture)))
    quoted = timestamp(c.quoted_at, field_name="quoted_at")
    valid_until = c.valid_until or (parsed(quoted) + timedelta(days=QUOTE_VALIDITY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    applicability = {"profile_ref": c.profile_ref, **{k: v for k, v in c.profile_inputs.items()}, "payment_period": c.payment_period, "quote_reference": c.quote_reference, "source_url": c.source_url}
    proposed = observe(product_ref=c.product_ref, field=quote_field(c.profile_ref), value=str(c.premium), unit=c.unit, applicability={k: v for k, v in applicability.items() if v is not None}, source_key=source_key, observed_at=quoted, locator="provider quote tool", quote=f"{c.premium} {c.unit} quoted for {c.profile_ref}" + (f" ({c.quote_reference})" if c.quote_reference else ""), adapter=QUOTE_ADAPTER, source_effective_from=quoted, source_effective_to=valid_until)
    return proposed.model_copy(update={"status": "accepted", "accepted_at": timestamp(accepted_at, field_name="accepted_at"), "accepted_by_ref": c.captured_by_ref, "last_revalidated_at": quoted, "notes": (c.notes,) if c.notes else ()})


def catalog_with_quotes(catalog: ProductCatalog | Mapping[str, Any], observations: Sequence[Observation | Mapping[str, Any]], *, state: ClientState | Mapping[str, Any], profiles: Sequence[QuoteProfile | Mapping[str, Any]], as_of: str, knowledge_at: str | None = None) -> tuple[ProductCatalog, ProfileMatch | None, tuple[str, ...]]:
    """The published view carrying only the matched profile's quotes, and the disclosures a shortlist built on it must carry."""

    s = state if isinstance(state, ClientState) else ClientState.model_validate(dict(detached(state)))
    match = match_profile(s, profiles)
    kept: list[Observation] = []
    dropped_quotes = 0
    quoted_at: list[str] = []
    for raw in observations:
        item = raw if isinstance(raw, Observation) else Observation.model_validate(dict(detached(raw)))
        if item.adapter == QUOTE_ADAPTER or item.field.startswith(QUOTE_FIELD_PREFIX + "["):
            if match is not None and item.applicability.get("profile_ref") == match.profile_ref:
                kept.append(item)
                quoted_at.append(item.observed_at[:10])
            else:
                dropped_quotes += 1
            continue
        kept.append(item)
    view = published_catalog(catalog, kept, as_of=as_of, knowledge_at=knowledge_at)
    if match is not None and quoted_at:
        # a product priced by a captured quote carries quoted pricing: that is what the engine may rank
        quoted_products = {item.product_ref for item in kept if item.applicability.get("profile_ref") == match.profile_ref}
        body = view.to_dict()
        changed = False
        for product in body["products"]:
            if product["product_ref"] in quoted_products and product.get("pricing_kind") in ("quote_required", "unstated"):
                product["pricing_kind"] = "quoted"
                product["pricing_kind_as_stated"] = (product.get("pricing_kind_as_stated") or "quote_required") + "; priced by a captured quote for the matched rating profile"
                changed = True
        if changed:
            body.pop("catalog_digest", None)
            view = seal(ProductCatalog, body, "catalog_digest")
    disclosures: list[str] = []
    if match is None:
        disclosures.append("no rating profile exists for this vertical; every quote-required product stays unranked until a person obtains the client's own quote")
    elif not kept or not quoted_at:
        disclosures.append(f"no quote has been captured for the matched rating profile ({match.label}); quote-required products stay unranked until one is")
    else:
        when = ", ".join(sorted(set(quoted_at)))
        disclosures.append(f"premiums are quotes obtained on {when} for the rating profile '{match.label}', not the client's price; a provider prices the individual and the client's premium will differ")
        if match.differences:
            disclosures.append("the client differs from the quoted profile: " + "; ".join(match.differences))
    if dropped_quotes:
        disclosures.append(f"{dropped_quotes} quote(s) for other rating profiles were not used")
    return view, match, tuple(disclosures)


QUOTES_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_quotes.v1",
    "adapter": QUOTE_ADAPTER,
    "validity_days": QUOTE_VALIDITY_DAYS,
    "axes": {axes: sorted(table) for axes, table in _PROFILE_AXES.items()},
    "hard_rules": [
        "a rating profile carries decision facts only; a person's identity, contact, date of birth or policy number never enters one",
        "a quote is evidence of a price for that profile from the provider's own quote tool on that day; it is never the client's price, and the shortlist discloses the profile and every difference",
        "a quote expires (thirty days unless the provider states otherwise) and then stops ranking like any expired fact",
        "the capturing person is the acceptor of the quote observation; the platform records the capture, the SDK seals it",
    ],
}


__all__ = ["QUOTE_ADAPTER", "QUOTE_CAPTURE_SCHEMA", "QUOTE_PROFILE_SCHEMA", "QUOTE_VALIDITY_DAYS", "QUOTES_MANIFEST", "AdviceQuoteError", "ProfileMatch", "QuoteCapture", "QuoteProfile", "catalog_with_quotes", "match_profile", "profile_ref", "quote_axes_for", "quote_field", "quote_observation", "standard_profiles"]
