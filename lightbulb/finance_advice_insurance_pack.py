"""The insurance research schema (``fsa_insurance``) as per-vertical packs the map ingests.

The consolidated insurance catalog arrives as one file for two countries and fifty categories,
every field a record ``{value, unit, status, conditions, evidence_ids, gap_reason}``, evidence in
``coverage.evidence`` (a locator and the supporting text) and sources in ``coverage.sources``.
The map folds one vertical per pack, so this module *projects* the consolidated file into one
pack per registry vertical: products by ``primary_vertical``, the parties that issue or
distribute them plus the parties the register links to the category, the registers those
parties stand on, and a ledger of exactly the evidence the pack cites. Nothing is edited or
inferred beyond what the file states; every projection decision is written into the coverage
notes and the split report, and a category the vertical registry does not know is reported,
never guessed into a neighbour.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from lightbulb.company_engine_core import timestamp
from lightbulb.finance_advice_catalog import VerticalRegistry, load_vertical_registry
from lightbulb.finance_advice_research import suggested_pack_file_name

INSURANCE_ADAPTER = "fsa_insurance_split"
INSURANCE_SCHEMA_PREFIX = "fsa_insurance"

# The pack's subtypes against the registry's taxonomy, per vertical. A subtype the vertical's
# taxonomy does not resolve stays unclassified with the reason; nothing is inferred from a name.
SUBTYPE_CLASSES: dict[str, dict[str, str]] = {
    "AU-31": {"hospital": "hospital_cover", "extras": "extras_cover", "combined": "combined_cover", "ambulance": "ambulance_only_cover", "overseas_visitor": "overseas_visitor_cover"},
    "AU-32": {"term_life": "term_life_insurance"},
    "AU-35": {"critical_illness": "critical_illness_insurance", "trauma": "trauma_insurance"},
    "AU-36": {"home_building_contents": "combined_home_and_contents", "building": "building_insurance", "contents": "contents_insurance"},
    "AU-37": {"renters_contents": "renters_contents_insurance"},
    "AU-39": {"residential_strata": "residential_strata_insurance"},
    "AU-40": {"comprehensive_motor": "comprehensive_motor_insurance", "third_party_property_motor": "third_party_property_damage", "third_party_fire_theft": "third_party_fire_and_theft"},
    "AU-41": {"compulsory_motor_bodily_injury": "state_competitive_CTP", "public_motor_scheme": "state_single_scheme_CTP"},
    "AU-42": {"international_travel": "international_travel_insurance", "domestic_travel": "domestic_travel_insurance", "card_linked_travel": "credit_card_travel_cover", "annual_travel": "annual_multi_trip_travel_insurance"},
    "AU-43": {"pet_accident_illness": "accident_and_illness_pet_insurance", "pet_accident": "accident_only_pet_insurance"},
    "AU-44": {"funeral_life": "funeral_insurance", "funeral_bond": "funeral_bond"},
    "AU-45": {"creditor_payment_protection": "consumer_credit_insurance"},
    "AU-46": {"residential_owner_title": "owner_title_insurance", "lender_title": "lender_title_insurance"},
    "AU-47": {"caravan": "caravan_insurance", "boat": "boat_insurance", "motorhome": "motorhome_insurance"},
    "CA-35": {"term_life": "term_life_insurance", "whole_life": "whole_life_insurance", "universal_life": "universal_life_insurance"},
    "CA-36": {"disability_income": "individual_disability_income"},
    "CA-37": {"critical_illness": "critical_illness_insurance"},
    "CA-38": {"long_term_care": "long_term_care_insurance"},
    "CA-39": {"health_dental": "combined_health_and_dental", "visitor_health": "visitor_to_Canada_health_insurance"},
    "CA-40": {"international_travel": "international_travel_insurance", "annual_travel": "annual_multi_trip_travel_insurance", "domestic_travel": "domestic_travel_insurance"},
    "CA-41": {"home_building_contents": "homeowners_insurance"},
    "CA-42": {"condominium_unit_owner": "condominium_unit_owner_insurance", "tenant_contents": "tenant_insurance"},
    "CA-44": {"public_auto_basic": "public_auto_plan", "public_auto_injury": "public_auto_plan"},
    "CA-45": {"pet_accident_illness": "accident_and_illness_pet_insurance"},
    "CA-46": {"final_expense_life": "final_expense_life_insurance"},
    "CA-47": {"creditor_life_disability": "loan_creditor_insurance"},
    "CA-49": {"residential_owner_title": "owner_title_insurance"},
    "CA-50": {"motorhome": "RV_insurance", "boat": "boat_insurance", "motorcycle": "motorcycle_insurance"},
}
ELIGIBILITY_TERMS: dict[str, str] = {"maximum_issue_age": "maximum entry age", "minimum_entry_age": "minimum entry age", "maximum_lvr": "maximum LVR", "maximum_loan_amount": "maximum loan amount", "maximum_loan_term": "maximum loan term", "minimum_initial_investment": "minimum initial investment"}
REGULATOR_MARKERS = ("apra", "asic", "osfi", "amf", "fsra", "bcfsa", "fcnb", "insurance council", "superintendent", "regulator", "ministry", "government", "gov.", "cmhc", "commission", "privatehealth.gov.au", "phio", "afca", "assuris", "pacicc", "olhi", "gio", "ccir", "maic", "tac.vic", "maib", "sira", "ctp")


class AdviceInsurancePackError(ValueError):
    pass


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise AdviceInsurancePackError(f"{code}: {detail}")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _rec(value: Any) -> dict[str, Any]:
    """A field record; a bare value is a stated record with no evidence."""

    if isinstance(value, Mapping) and "value" in value and "status" in value:
        return dict(value)
    return {"value": value, "unit": None, "status": "stated" if value is not None else "not_stated", "conditions": [], "evidence_ids": [], "gap_reason": None}


def _stated(value: Any) -> Any:
    record = _rec(value)
    return record.get("value") if record.get("status") not in ("not_stated", "unresolved") else None


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _stamp(value: Any) -> str | None:
    """The file's timestamps carry a UTC offset (``+00:00``); the catalog's citations take ``Z``. Any other offset is converted to UTC."""

    text = _text(value)
    if text is None:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) or text.endswith("Z"):
        return text
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00", text):
        return text[:-6] + "Z"
    try:
        from datetime import datetime, timezone

        return datetime.fromisoformat(text).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return text


def _display(party: Mapping[str, Any]) -> str | None:
    """The name the file shows for a party, even when it marks the name unresolved; the row's legal_name_status says so."""

    display = party.get("display_name")
    shown = _text(display.get("value")) if isinstance(display, Mapping) else _text(display)
    return shown or _text(_stated(party.get("legal_name")))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Ledger
# --------------------------------------------------------------------------- #


def _source_type(publisher: str | None, artifact_type: str | None, document_type: str | None, url: str | None) -> str:
    haystack = " ".join(item.lower() for item in (publisher or "", url or "") if item)
    doc = (document_type or "").lower()
    if any(marker in haystack for marker in REGULATOR_MARKERS):
        return "regulator_register"
    if doc in ("pds", "pds_and_policy_wording", "specimen_contract", "incorporated_additional_information"):
        return "mandated_disclosure"
    if doc in ("premium_table", "benefit_comparison_chart", "benefits_guide"):
        return "provider_rate_schedule" if doc == "premium_table" else "provider_product_page"
    if doc in ("document_library", "product_library"):
        return "provider_terms"
    if (artifact_type or "").lower() == "pdf":
        return "provider_terms"
    return "provider_product_page"


class _Ledger:
    def __init__(self, consolidated: Mapping[str, Any]) -> None:
        coverage = consolidated.get("coverage") if isinstance(consolidated.get("coverage"), Mapping) else {}
        self.sources: dict[str, Mapping[str, Any]] = {str(item.get("source_id")): item for item in (coverage.get("sources") or ()) if isinstance(item, Mapping) and _text(item.get("source_id"))}
        self.evidence: dict[str, Mapping[str, Any]] = {str(item.get("evidence_id")): item for item in (coverage.get("evidence") or ()) if isinstance(item, Mapping) and _text(item.get("evidence_id"))}
        self.document_types: dict[str, str] = {}
        for product in consolidated.get("products") or ():
            for document in (product.get("documents") or ()) if isinstance(product, Mapping) else ():
                if isinstance(document, Mapping) and _text(document.get("source_id")) and _text(document.get("document_type")):
                    self.document_types.setdefault(str(document["source_id"]), str(document["document_type"]))
        self.used: dict[str, None] = {}

    def cite(self, ids: Sequence[str]) -> list[str]:
        out: list[str] = []
        for raw in ids:
            key = _text(raw)
            if key and (key in self.evidence or key in self.sources):
                self.used[key] = None
                out.append(key)
        return out

    def entries(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key in self.used:
            if key in self.evidence:
                ev = self.evidence[key]
                source = self.sources.get(str(ev.get("source_id") or ""), {})
                url = _text(ev.get("actual_url") or ev.get("canonical_url") or source.get("final_url") or source.get("canonical_url"))
                out.append({"source_id": key, "url": url, "title": _text(ev.get("document_title") or source.get("title")), "retrieved_at": _stamp(ev.get("retrieved_at") or source.get("retrieved_at")), "retrieval_status": "retrieved" if url else "source_definition_not_recovered", "source_type": _source_type(_text(ev.get("publisher") or source.get("publisher")), _text(source.get("artifact_type")), self.document_types.get(str(ev.get("source_id") or "")), url), "locator": _text(ev.get("locator")), "source_date": _text(source.get("publication_or_updated_date")), "quotes": [{"quote_id": key, "exact_quote": _text(ev.get("supporting_text")) or ""}] if _text(ev.get("supporting_text")) else [], "evidence_format": _text(ev.get("evidence_format")), "of_source": _text(ev.get("source_id"))})
            else:
                source = self.sources[key]
                url = _text(source.get("final_url") or source.get("canonical_url"))
                status = _text(source.get("access_status")) or "retrieved"
                out.append({"source_id": key, "url": url, "title": _text(source.get("title")), "retrieved_at": _stamp(source.get("retrieved_at")), "retrieval_status": status if url else "source_definition_not_recovered", "source_type": _source_type(_text(source.get("publisher")), _text(source.get("artifact_type")), self.document_types.get(key), url), "publisher": _text(source.get("publisher")), "source_date": _text(source.get("publication_or_updated_date")), "http_etag": source.get("http_etag"), "http_last_modified": source.get("http_last_modified"), "quotes": []})
        return out


# --------------------------------------------------------------------------- #
# Products
# --------------------------------------------------------------------------- #


def classify(vertical_id: str, subtype: str | None, product: Mapping[str, Any], registry: VerticalRegistry) -> tuple[str, str]:
    taxonomy = list(registry.vertical(vertical_id).taxonomy)
    sub = (subtype or "").strip()
    if vertical_id == "CA-47" and sub == "creditor_payment_protection":
        name = str(_stated(product.get("marketed_name")) or product.get("product_id") or "").lower()
        return ("credit_card_balance_insurance", "creditor payment protection on a card") if "card" in name else ("loan_creditor_insurance", "creditor payment protection on a loan")
    if vertical_id == "CA-48" and sub == "residential_mortgage_default":
        issuer = str(product.get("issuer_provider_id") or "").lower()
        payer = str(_stated((product.get("roles") or {}).get("premium_payer")) or "").lower()
        if "cmhc" in issuer:
            return "government_mortgage_loan_insurance", "the issuer is CMHC"
        if "borrower" in payer:
            return "borrower_paid_mortgage_default_insurance", "roles.premium_payer states the borrower funds the premium"
        return "unclassified", "premium payer not stated; borrower-paid, lender-paid or government not established"
    mapped = SUBTYPE_CLASSES.get(vertical_id, {}).get(sub)
    if mapped and mapped in taxonomy:
        return mapped, f"subtype {sub!r}"
    if sub in taxonomy:
        return sub, f"subtype {sub!r} is a taxonomy class"
    return "unclassified", f"subtype {sub or '(none)'} does not resolve to a class of {vertical_id}; the analyst classifies"


def _conditions_text(record: Mapping[str, Any]) -> str:
    conditions = [str(item) for item in (record.get("conditions") or ()) if _text(item)]
    return f" ({'; '.join(conditions)})" if conditions else ""


def _eligibility_lines(product: Mapping[str, Any], ledger: _Ledger) -> tuple[list[str], list[dict[str, Any]]]:
    lines: list[str] = []
    terms: list[dict[str, Any]] = []
    for block in ("eligibility", "underwriting"):
        for field, raw in (product.get(block) or {}).items():
            record = _rec(raw)
            value = record.get("value")
            if record.get("status") in ("not_stated", "unresolved") or value is None:
                continue
            unit = f" {record['unit']}" if record.get("unit") else ""
            lines.append(f"{block + ': ' if block == 'underwriting' else ''}{field}: {_render(value)}{unit}{_conditions_text(record)}")
            ids = ledger.cite([str(item) for item in (record.get("evidence_ids") or ())])
            if field in ("issue_age", "issue_ages") and isinstance(value, (list, tuple)) and len(value) == 2 and all(isinstance(item, (int, float)) for item in value):
                terms.append({"term": "minimum entry age", "value": value[0], "source_ids": ids})
                terms.append({"term": "maximum entry age", "value": value[1], "source_ids": ids})
            elif field in ELIGIBILITY_TERMS and isinstance(value, (int, float, str)):
                terms.append({"term": ELIGIBILITY_TERMS[field], "value": value, "source_ids": ids})
    return lines, terms


def _pricing_items(product: Mapping[str, Any], ledger: _Ledger) -> tuple[list[dict[str, Any]], str]:
    pricing = product.get("pricing") if isinstance(product.get("pricing"), Mapping) else {}
    currency = _text(pricing.get("currency")) or ("AUD" if str(product.get("country")) == "AU" else "CAD")
    items: list[dict[str, Any]] = []
    premium = _rec(pricing.get("premium"))
    if premium.get("status") not in ("not_stated", "unresolved") and premium.get("value") is not None:
        ids = ledger.cite([str(x) for x in (premium.get("evidence_ids") or ())])
        period = _stated(pricing.get("payment_period"))
        unit = f"{premium.get('unit') or currency}" + ({"monthly": "/month", "annual": "/year", "yearly": "/year", "one_time": " once-off"}.get(str(period or "").lower(), ""))
        items.append({"item": "premium", "value": premium["value"], "unit": unit, "conditions": {k: v for k, v in {"payment_period": period, "note": "; ".join(str(c) for c in premium.get("conditions") or ())}.items() if v}, "source_ids": ids, "quote_reference": ids[0] if ids else None})
    for observation in pricing.get("observations") or ():
        if not isinstance(observation, Mapping):
            continue
        ids = ledger.cite([str(x) for x in (observation.get("evidence_ids") or ())])
        base_conditions = {k: v for k, v in {"observation_type": _text(observation.get("observation_type")), "effective_date": _text(observation.get("effective_date")), "jurisdiction": _render(observation.get("jurisdiction") or observation.get("jurisdictions")) if observation.get("jurisdiction") or observation.get("jurisdictions") else None, "tax_levy_inclusion": _text(observation.get("tax_levy_inclusion") or observation.get("tax_included")), "note": "; ".join(str(c) for c in observation.get("conditions") or ()) or None}.items() if v}
        unit_label = _text(observation.get("unit") or observation.get("rate_unit"))
        for row in observation.get("rows") or ():
            if not isinstance(row, Mapping):
                continue
            descriptors = {k: v for k, v in row.items() if not isinstance(v, (int, float)) or isinstance(v, bool)}
            for column, value in row.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                name = column.replace("_", " ")
                if column in ("premium",):
                    unit = f"{observation.get('currency') or currency}"
                elif column.endswith("_percent") or unit_label in ("percent_of_loan_amount",):
                    name = "premium rate" if column == "total_loan_percent" else name
                    unit = "% of loan amount" if unit_label == "percent_of_loan_amount" else "%"
                else:
                    unit = unit_label or _text(observation.get("currency")) or currency
                items.append({"item": name, "value": value, "unit": unit, "conditions": {**base_conditions, **{k: _render(v) if not isinstance(v, str) else v for k, v in descriptors.items()}}, "source_ids": ids, "quote_reference": ids[0] if ids else None})
        if isinstance(observation.get("premium"), Mapping) and _stated(observation.get("premium")) is not None:
            record = _rec(observation.get("premium"))
            rec_ids = ledger.cite([str(x) for x in (record.get("evidence_ids") or ())]) or ids
            items.append({"item": "premium", "value": record["value"], "unit": f"{record.get('unit') or observation.get('currency') or currency}", "conditions": {**base_conditions, "rating_inputs": _render(observation.get("rating_inputs")) if observation.get("rating_inputs") else None, "variant_id": _text(observation.get("variant_id"))}, "source_ids": rec_ids, "quote_reference": rec_ids[0] if rec_ids else None})
    for fee in product.get("fees") or ():
        record = _rec(fee)
        if record.get("value") is None or record.get("status") in ("not_stated", "unresolved"):
            continue
        ids = ledger.cite([str(x) for x in (record.get("evidence_ids") or ())])
        items.append({"item": _text(record.get("name")) or "fee", "value": record["value"], "unit": _text(record.get("unit")) or currency, "conditions": {"note": "; ".join(str(c) for c in record.get("conditions") or ())} if record.get("conditions") else {}, "source_ids": ids, "quote_reference": ids[0] if ids else None})
    for benefit in product.get("benefits") or ():
        if not isinstance(benefit, Mapping):
            continue
        record = _rec(benefit.get("value"))
        value = record.get("value")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        ids = ledger.cite([str(x) for x in (record.get("evidence_ids") or ())])
        name = str(benefit.get("name") or "benefit").strip().lower()
        items.append({"item": name, "value": value, "unit": _text(record.get("unit")) or currency, "conditions": {k: v for k, v in {"benefit_status": _text(benefit.get("status")), "note": "; ".join(str(c) for c in record.get("conditions") or ()) or None}.items() if v}, "source_ids": ids, "quote_reference": ids[0] if ids else None})
    classification = str(pricing.get("classification") or "unavailable")
    kind = {"published_table": "list", "observed_anonymous_quote": "quoted", "public_illustration": "quoted", "quote_required": "quote_required", "unavailable": "unstated"}.get(classification, "unstated")
    return items, kind


def _key_terms(product: Mapping[str, Any], ledger: _Ledger) -> list[dict[str, Any]]:
    terms: list[dict[str, Any]] = []
    for field, raw in (product.get("contract_terms") or {}).items():
        record = _rec(raw)
        if record.get("value") is None or record.get("status") in ("not_stated", "unresolved"):
            continue
        ids = ledger.cite([str(x) for x in (record.get("evidence_ids") or ())])
        value = record["value"] if not record.get("unit") else {"value": record["value"], "unit": record["unit"]}
        terms.append({"term": field.replace("_", " "), "value": value, "source_ids": ids, "quote_reference": ids[0] if ids else None})
    subtype = _text(product.get("subtype"))
    if subtype:
        terms.append({"term": "subtype", "value": subtype, "source_ids": []})
    if _text(product.get("family_id")):
        terms.append({"term": "family", "value": str(product["family_id"]), "source_ids": []})
    variants = [str(_stated(item.get("marketed_name")) or item.get("variant_id")) for item in (product.get("variants") or ()) if isinstance(item, Mapping)]
    if variants:
        terms.append({"term": "variants", "value": variants, "source_ids": ledger.cite([str(x) for item in product.get("variants") or () if isinstance(item, Mapping) for x in (item.get("evidence_ids") or ())])})
    components = [str(_stated(item.get("marketed_name")) or item.get("component_id")) for item in (product.get("components") or ()) if isinstance(item, Mapping)]
    if components:
        terms.append({"term": "components", "value": components, "source_ids": []})
    benefits = [f"{item.get('name')}: {item.get('status')}" for item in (product.get("benefits") or ()) if isinstance(item, Mapping) and _text(item.get("name"))]
    if benefits:
        terms.append({"term": "benefits", "value": benefits, "source_ids": []})
    exclusions = [str(item.get("name")) for item in (product.get("exclusions") or ()) if isinstance(item, Mapping) and _text(item.get("name"))]
    if exclusions:
        terms.append({"term": "exclusions", "value": exclusions, "source_ids": []})
    optional = [str(item.get("name")) for item in (product.get("optional_benefits") or ()) if isinstance(item, Mapping) and _text(item.get("name"))]
    if optional:
        terms.append({"term": "optional benefits", "value": optional, "source_ids": []})
    return terms


def _confidence(product: Mapping[str, Any], has_pricing: bool) -> tuple[str, str]:
    scopes = product.get("confidence_by_scope") if isinstance(product.get("confidence_by_scope"), Mapping) else {}
    chosen = "pricing" if has_pricing else "benefits"
    value = str(scopes.get(chosen) or scopes.get("identity") or "unverified")
    if value not in ("verified", "single_source", "unverified"):
        value = "unverified"
    return value, f"confidence_by_scope={json.dumps(dict(scopes), sort_keys=True)}; product confidence taken from the {chosen} scope; extraction_status={product.get('extraction_status')}; contract_extraction_complete={product.get('contract_extraction_complete')}; declared_field_scope={product.get('declared_field_scope')}"


# --------------------------------------------------------------------------- #
# Providers and registers
# --------------------------------------------------------------------------- #


def _party_row(party: Mapping[str, Any], *, vertical_id: str, ledger: _Ledger, sources: Mapping[str, Mapping[str, Any]], with_products: bool) -> dict[str, Any]:
    legal = _rec(party.get("legal_name"))
    legal_name = _text(legal.get("value")) if legal.get("status") not in ("not_stated", "unresolved") else None
    display = _display(party) or legal_name
    identifiers = [item for item in (party.get("identifiers") or ()) if isinstance(item, Mapping) and _text(item.get("value"))]
    authorizations = [item for item in (party.get("authorization") or ()) if isinstance(item, Mapping)]
    first_auth = authorizations[0] if authorizations else {}
    authority = next((a for a in (first_auth.get("authorities") or ()) if isinstance(a, Mapping)), {})
    register_source = sources.get(str(authority.get("source_id") or ""), {})
    cite_ids = [str(x) for x in (legal.get("evidence_ids") or ())] + [str(x) for a in authorizations for x in (_rec(a.get("status")).get("evidence_ids") or ())]
    cited = ledger.cite(cite_ids)
    outcome = next((item for item in (party.get("offer_discovery_outcomes") or ()) if isinstance(item, Mapping) and str(item.get("vertical_id")) == vertical_id), {})
    row: dict[str, Any] = {
        "provider_key": str(party.get("provider_id")),
        "legal_name": legal_name,
        "legal_name_status": "explicit_primary_disclosure" if legal_name else f"legal_name_not_established; {party.get('legal_name_resolution_status') or 'unresolved'}; display name shown",
        "provider_name": display,
        "trading_names": [str(_stated(item) or "") for item in (party.get("trading_names") or ()) if _stated(item)],
        "register_identifier": _text(identifiers[0].get("value")) if identifiers else None,
        "register_identifier_type": _text(identifiers[0].get("identifier_type")) if identifiers else None,
        "identifiers": [{"type": _text(item.get("identifier_type")), "value": _text(item.get("value")), "issuing_authority": _text(item.get("issuing_authority"))} for item in identifiers],
        "licence_category": _text(party.get("entity_type")),
        "register_name": (f"{authority.get('publisher')}: {register_source.get('title')}" if authority.get("publisher") and register_source.get("title") else _text(authority.get("publisher"))) if authorizations else None,
        "registration_status": _text(_stated(first_auth.get("status"))) if authorizations else None,
        "register_url": _text(register_source.get("final_url") or register_source.get("canonical_url")) if authorizations else None,
        "retrieved_at": _stamp(register_source.get("retrieved_at")) or _stamp(party.get("last_checked")),
        "authorizations": [{"jurisdictions": list(a.get("jurisdictions") or ()), "class_or_population": _text(a.get("class_or_population")), "status": _stated(a.get("status")), "not_product_authorization": bool(a.get("not_product_authorization")), "verification_scope": _text(a.get("verification_scope"))} for a in authorizations],
        "official_domains": [str(item) for item in (party.get("official_domains") or ())],
        "roles": [str(item) for item in (party.get("roles") or ())],
        "source_ids": cited,
        "quote_reference": cited[0] if cited else None,
        "product_discovery_status": _text(outcome.get("outcome")) or ("products_identified" if with_products else None),
        "gaps": [str(item) for item in (party.get("gaps") or ()) if _text(item)],
        "confidence": _text(party.get("confidence")),
    }
    if not with_products:
        row["record_type"] = "census_identity_dossier"
        row["review_status"] = "census_identity_only"
    return row


def _register_rows(consolidated: Mapping[str, Any], *, country: str, source_ids: set[str], sources: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for register in consolidated.get("registers") or ():
        if not isinstance(register, Mapping) or str(register.get("country")) != country or str(register.get("source_id")) not in source_ids:
            continue
        source = sources.get(str(register.get("source_id")), {})
        title = _text(source.get("title")) or str(register.get("register_id"))
        out.append({
            "register_name": f"{source.get('publisher')}: {title}" if source.get("publisher") else title,
            "authority": _text(source.get("publisher")),
            "register_type": _text(register.get("purpose")),
            "jurisdiction": country,
            "url": _text(source.get("final_url") or source.get("canonical_url")),
            "retrieved_at": _stamp(register.get("retrieved_at") or source.get("retrieved_at")),
            "register_date": _text(register.get("snapshot_date")),
            "entry_count_reported": register.get("reported_row_count") if isinstance(register.get("reported_row_count"), int) else None,
            "entries_processed": register.get("captured_row_count") if isinstance(register.get("captured_row_count"), int) else None,
            "unique_entity_count": register.get("unique_entity_count"),
            "capture_status": _text(register.get("capture_status")),
            "limitations": [item for item in (_text(register.get("population_scope")), f"capture status: {register.get('capture_status')}" if register.get("capture_status") else None) if item],
        })
    return out


# --------------------------------------------------------------------------- #
# The split
# --------------------------------------------------------------------------- #


def split_insurance_catalog(consolidated: Mapping[str, Any], *, source_file_name: str, source_sha256: str | None = None, registry: VerticalRegistry | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """One pack per registry vertical from the consolidated insurance file, and the report of every projection decision."""

    registry = registry or load_vertical_registry()
    _require(all(isinstance(consolidated.get(key), list) for key in ("registers", "providers", "products")) and isinstance(consolidated.get("coverage"), Mapping), "INSURANCE_SHAPE_INVALID", "the consolidated file carries registers, providers, products and coverage")
    coverage = consolidated["coverage"]
    metadata = coverage.get("metadata") if isinstance(coverage.get("metadata"), Mapping) else {}
    schema = str(metadata.get("schema_version") or "")
    _require(schema.startswith(INSURANCE_SCHEMA_PREFIX), "INSURANCE_SCHEMA_UNKNOWN", f"schema_version {schema!r} is not an {INSURANCE_SCHEMA_PREFIX} schema")
    run_date = _text(metadata.get("execution_date")) or timestamp(str(metadata.get("execution_started_at") or "1970-01-01T00:00:00Z"), field_name="execution_started_at")[:10]
    parties: dict[str, Mapping[str, Any]] = {str(item.get("provider_id")): item for item in consolidated["providers"] if isinstance(item, Mapping) and _text(item.get("provider_id"))}
    sources: dict[str, Mapping[str, Any]] = {str(item.get("source_id")): item for item in (coverage.get("sources") or ()) if isinstance(item, Mapping) and _text(item.get("source_id"))}
    conflicts_by_product: dict[str, list[Mapping[str, Any]]] = {}
    for conflict in coverage.get("unresolved_conflicts") or ():
        if isinstance(conflict, Mapping) and _text(conflict.get("product_id")):
            conflicts_by_product.setdefault(str(conflict["product_id"]), []).append(conflict)
    unfinished = coverage.get("declared_field_scope_dictionary") if isinstance(coverage.get("declared_field_scope_dictionary"), Mapping) else {}
    category_unfinished = unfinished.get("category_specific_unfinished") if isinstance(unfinished.get("category_specific_unfinished"), Mapping) else {}
    limitations = [str(item) for item in (coverage.get("limitations") or ()) if _text(item)]

    by_vertical: dict[str, list[Mapping[str, Any]]] = {}
    skipped: list[dict[str, Any]] = []
    for product in consolidated["products"]:
        if not isinstance(product, Mapping):
            continue
        vertical_id = str(product.get("primary_vertical") or "")
        try:
            registry.vertical(vertical_id)
        except Exception:  # noqa: BLE001 - a category the registry does not know is reported, not guessed
            skipped.append({"product_id": product.get("product_id"), "primary_vertical": vertical_id, "reason": "vertical not in the registry"})
            continue
        by_vertical.setdefault(vertical_id, []).append(product)

    packs: dict[str, dict[str, Any]] = {}
    report: dict[str, Any] = {"adapter": INSURANCE_ADAPTER, "source_file_name": source_file_name, "source_sha256": source_sha256, "schema_version": schema, "run_date": run_date, "verticals": {}, "skipped_products": skipped, "unresolved_issuers": [], "classification": {}}
    for vertical_id, products in sorted(by_vertical.items()):
        vertical = registry.vertical(vertical_id)
        country = vertical.jurisdiction
        ledger = _Ledger(consolidated)
        rows: list[dict[str, Any]] = []
        names: dict[tuple[str, str], int] = {}
        party_ids: dict[str, bool] = {}
        classes: dict[str, int] = {}
        for product in products:
            issuer = _text(product.get("issuer_provider_id"))
            attributed_note = None
            if issuer is None or issuer not in parties:
                others = [item for item in (product.get("other_parties") or ()) if isinstance(item, Mapping) and _text(item.get("provider_id")) in parties]
                if not others:
                    report["unresolved_issuers"].append({"product_id": product.get("product_id"), "vertical_id": vertical_id, "reason": "no issuer and no linked party; not folded"})
                    continue
                issuer = str(others[0]["provider_id"])
                attributed_note = f"issuer unresolved; attributed to the linked party {_display(parties[issuer])} ({', '.join(str(r) for r in others[0].get('roles') or ())})"
                report["unresolved_issuers"].append({"product_id": product.get("product_id"), "vertical_id": vertical_id, "reason": attributed_note})
            party = parties[issuer]
            party_ids[issuer] = True
            for other in product.get("other_parties") or ():
                if isinstance(other, Mapping) and _text(other.get("provider_id")) in parties:
                    party_ids.setdefault(str(other["provider_id"]), False)
            name = _text(_stated(product.get("marketed_name"))) or str(product.get("product_id"))
            taxonomy_class, reason = classify(vertical_id, _text(product.get("subtype")), product, registry)
            classes[taxonomy_class] = classes.get(taxonomy_class, 0) + 1
            key = (issuer, name.lower() + "|" + taxonomy_class)
            if key in names:
                names[key] += 1
                name = f"{name} ({product.get('subtype') or 'variant'} {names[key]})"
            else:
                names[key] = 1
            pricing, kind = _pricing_items(product, ledger)
            eligibility, age_terms = _eligibility_lines(product, ledger)
            confidence, basis = _confidence(product, bool(pricing))
            product_sources = ledger.cite([str(x) for x in (product.get("source_ids") or ())] + [str(x) for x in (_rec(product.get("marketed_name")).get("evidence_ids") or ())] + [str(d.get("source_id")) for d in (product.get("documents") or ()) if isinstance(d, Mapping) and _text(d.get("source_id"))])
            gaps = [str(item) for item in (product.get("gaps") or ()) if _text(item)]
            gaps += [f"unresolved conflict at {c.get('field_path')}: {c.get('applicability_analysis') or c.get('status')}" for c in conflicts_by_product.get(str(product.get("product_id")), [])]
            gaps += [f"conflict: {_render(c)}" for c in (product.get("conflicts") or ()) if c]
            if attributed_note:
                gaps.append(attributed_note)
            if taxonomy_class == "unclassified":
                gaps.append(f"unclassified: {reason}")
            availability = _stated((product.get("availability") or {}).get("status")) if isinstance(product.get("availability"), Mapping) else None
            rows.append({
                "catalog_product_id": str(product.get("product_id")),
                "provider_key": issuer,
                "provider_name": _display(party) or issuer,
                "provider_legal_name": _text(_stated(party.get("legal_name"))),
                "issuer_legal_name": _text(_stated(party.get("legal_name"))) if not attributed_note else None,
                "product_name": name,
                "taxonomy_class": taxonomy_class,
                "classification_reason": reason,
                "record_granularity": _text(product.get("record_type")),
                "eligibility": eligibility,
                "pricing": pricing,
                "key_terms": age_terms + _key_terms(product, ledger),
                "effective_date": _text(_stated((product.get("dates") or {}).get("policy_effective"))) if isinstance(product.get("dates"), Mapping) else None,
                "pricing_kind": kind,
                "pricing_classification_as_stated": str((product.get("pricing") or {}).get("classification") or ""),
                "required_quote_inputs": list((product.get("pricing") or {}).get("required_quote_inputs") or ()),
                "quote_route": _text((product.get("pricing") or {}).get("quote_route")),
                "source_ids": product_sources,
                "confidence": confidence,
                "verification_basis": basis,
                "availability_status": _text(availability),
                "language": _text(product.get("language")),
                "gaps": gaps,
            })
        provider_rows: list[dict[str, Any]] = []
        register_source_ids: set[str] = set()
        for party_id, party in parties.items():
            has_products = party_ids.get(party_id, False)
            in_category = vertical_id in {str(item) for item in (party.get("product_categories") or ())} or any(str(item.get("vertical_id")) == vertical_id and str(item.get("outcome")) not in ("not_reviewed", "") for item in (party.get("offer_discovery_outcomes") or ()) if isinstance(item, Mapping))
            if party_id not in party_ids and not in_category:
                continue
            if str(party.get("country")) != country:
                continue
            provider_rows.append(_party_row(party, vertical_id=vertical_id, ledger=ledger, sources=sources, with_products=has_products))
            for auth in party.get("authorization") or ():
                for authority in (auth.get("authorities") or ()) if isinstance(auth, Mapping) else ():
                    if isinstance(authority, Mapping) and _text(authority.get("source_id")):
                        register_source_ids.add(str(authority["source_id"]))
        registers = _register_rows(consolidated, country=country, source_ids=register_source_ids, sources=sources)
        counts = {"verified": 0, "single_source": 0, "unverified": 0}
        for row in rows:
            counts[row["confidence"]] += 1
        category_count = next((item for item in (coverage.get("category_counts") or ()) if isinstance(item, Mapping) and str(item.get("vertical_id")) == vertical_id), {})
        pack = {
            "registers": registers,
            "providers": provider_rows,
            "products": rows,
            "coverage": {
                "vertical_id": vertical_id,
                "jurisdiction": country,
                "run_date": run_date,
                "batch_id": f"{vertical_id}-INS-01",
                "phase": f"initial_discovery_pass_{metadata.get('completion_status') or 'partial'}",
                "catalog_status": f"{INSURANCE_ADAPTER}: projected from {source_file_name}; {metadata.get('completion_status') or 'partial'}",
                "providers_captured": len(provider_rows),
                "providers_with_products_extracted": sum(1 for row in provider_rows if row.get("record_type") != "census_identity_dossier"),
                "products_extracted": len(rows),
                "products_verified": counts["verified"],
                "products_single_source": counts["single_source"],
                "products_unverified": counts["unverified"],
                "complete_national_provider_census": False,
                "product_extraction_exhaustive": False,
                "known_limitations": limitations + [f"{vertical_id}: {item}" for item in (category_unfinished.get(vertical_id) or ())] + ["Every product record is partially extracted; no category is certified complete (delivery README, 2026-09-06)."],
                "notes": [f"adapter={INSURANCE_ADAPTER}", f"source_file={source_file_name}", f"source_sha256={source_sha256 or 'unstated'}", f"schema_version={schema}", f"category_counts={json.dumps(category_count, sort_keys=True, default=str)}" if category_count else "category_counts=unstated", "products projected by primary_vertical; providers are the issuing and linked parties plus the parties the file links to this category; registers are those the providers' authorizations cite; the ledger holds exactly the evidence this pack cites"],
                "evidence_sources": ledger.entries(),
                "taxonomy_classes": classes,
            },
        }
        packs[vertical_id] = pack
        report["verticals"][vertical_id] = {"file_name": suggested_pack_file_name(vertical, 1, run_date + "T00:00:00Z"), "products": len(rows), "providers": len(provider_rows), "identity_only_providers": sum(1 for row in provider_rows if row.get("record_type") == "census_identity_dossier"), "registers": len(registers), "classes": classes, "pricing_facts": sum(len(row["pricing"]) for row in rows), "evidence_entries": len(pack["coverage"]["evidence_sources"])}
        report["classification"][vertical_id] = {row["catalog_product_id"]: f"{row['taxonomy_class']} ({row['classification_reason']})" for row in rows}
    return packs, report


def split_report_markdown(report: Mapping[str, Any]) -> str:
    lines = ["# Insurance catalog split", "", f"Source `{report.get('source_file_name')}` (sha256 {report.get('source_sha256') or 'unstated'}), schema {report.get('schema_version')}, run date {report.get('run_date')}, adapter `{report.get('adapter')}`.", ""]
    lines.append("| Vertical | Pack file | Products | Providers (identity only) | Registers | Pricing facts | Evidence entries |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for vertical_id, item in sorted((report.get("verticals") or {}).items()):
        lines.append(f"| {vertical_id} | `{item['file_name']}` | {item['products']} | {item['providers']} ({item['identity_only_providers']}) | {item['registers']} | {item['pricing_facts']} | {item['evidence_entries']} |")
    skipped = report.get("skipped_products") or []
    if skipped:
        lines += ["", f"## Not folded: {len(skipped)} record(s) in categories the vertical registry does not carry", ""]
        by_category: dict[str, int] = {}
        for item in skipped:
            by_category[str(item.get("primary_vertical"))] = by_category.get(str(item.get("primary_vertical")), 0) + 1
        lines += [f"- {category}: {count}" for category, count in sorted(by_category.items())]
    unresolved = report.get("unresolved_issuers") or []
    if unresolved:
        lines += ["", f"## Issuer unresolved: {len(unresolved)} record(s)", ""]
        lines += [f"- {item.get('product_id')} ({item.get('vertical_id')}): {item.get('reason')}" for item in unresolved]
    lines += ["", "## Classification", ""]
    for vertical_id, mapping in sorted((report.get("classification") or {}).items()):
        for product_id, verdict in sorted(mapping.items()):
            lines.append(f"- {vertical_id} {product_id}: {verdict}")
    return "\n".join(lines) + "\n"


__all__ = ["INSURANCE_ADAPTER", "SUBTYPE_CLASSES", "AdviceInsurancePackError", "classify", "split_insurance_catalog", "split_report_markdown"]
