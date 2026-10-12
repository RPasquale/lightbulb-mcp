"""Consumer Data Right product data (Australia): the data-holder register and the public product endpoints, read as packs.

The CDR's product-data APIs are public and unauthenticated: a data holder's ``publicBaseUri``
serves ``/cds-au/v1/banking/products`` (list, with ``updated-since``) and ``/{productId}``
(detail: lending and deposit rates, fees, eligibility, constraints, features, effective dates).
The CDR Register's public brand summary names every data holder brand with its ABN and base URI.

This module composes the requests the worker performs and turns the payloads the worker brings
back into the shapes the program already trusts: a census pack from the register, monitored
sources for the registry, and a *draft* pack per brand and vertical that goes through the same
checklist and promotion as any research draft. A structured feed earns ``verified`` at promotion;
nothing here publishes, and a rate without the conditions that govern it is not a fact.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import Any

from lightbulb.company_engine_core import timestamp
from lightbulb.finance_advice_catalog import provider_ref
from lightbulb.finance_advice_research import DRAFT_BASIS, DRAFT_PHASE
from lightbulb.finance_advice_sources import DEFAULT_CADENCE_HOURS, DEFAULT_FRESHNESS_HOURS, MonitoredSource, source_family, source_key

CDR_REGISTER_BRANDS_URL = "https://api.cdr.gov.au/cdr-register/v1/banking/data-holders/brands/summary"
CDR_PRODUCTS_PATH = "/cds-au/v1/banking/products"
CDR_PRODUCTS_VERSION = "3"
CDR_PRODUCT_DETAIL_VERSION = "5"
CDR_PRODUCT_DETAIL_MIN_VERSION = "3"
CDR_ADAPTER = "cdr_banking_products"
CDR_REGISTER_NAME = "CDR Register: banking data holder brands"
CDR_CATEGORY_VERTICALS: dict[str, tuple[str, ...]] = {
    "RESIDENTIAL_MORTGAGES": ("AU-05",),
    "CRED_AND_CHRG_CARDS": ("AU-04",),
    "TRANS_AND_SAVINGS_ACCOUNTS": ("AU-01", "AU-02"),
    "TERM_DEPOSITS": ("AU-03",),
    "PERS_LOANS": ("AU-08",),
    "OVERDRAFTS": ("AU-10",),
    "TRAVEL_CARDS": ("AU-15",),
    "MARGIN_LOANS": ("AU-23",),
}
VERTICAL_CATEGORIES: dict[str, str] = {vertical: category for category, verticals in CDR_CATEGORY_VERTICALS.items() for vertical in verticals}
_DURATION = re.compile(r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?$")


class AdviceCdrError(ValueError):
    pass


def _require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise AdviceCdrError(f"{code}: {detail}")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _percent(value: Any) -> str | None:
    """CDR rates are decimal fractions as strings (``"0.0579"``); the catalog states percent per year."""

    text = _text(value)
    if text is None:
        return None
    try:
        return str((Decimal(text) * 100).normalize()) if Decimal(text) != 0 else "0"
    except InvalidOperation:
        return None


def duration_months(value: Any) -> int | None:
    """An ISO-8601 duration such as ``P5Y`` or ``P18M`` as months; anything else is not a term."""

    text = _text(value)
    if text is None:
        return None
    match = _DURATION.match(text.upper())
    if not match:
        return None
    years, months, weeks, days = (int(item) if item else 0 for item in match.groups())
    if weeks or days:
        return None if not (years or months) else years * 12 + months
    return years * 12 + months if (years or months) else None


# --------------------------------------------------------------------------- #
# Register
# --------------------------------------------------------------------------- #


def _brands(summary: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    data = summary.get("data")
    if isinstance(data, Mapping):
        data = data.get("brands") or data.get("data")
    _require(isinstance(data, list), "CDR_REGISTER_SHAPE", "the brand summary carries a data list")
    return [item for item in data if isinstance(item, Mapping) and _text(item.get("brandName"))]


def brand_identity(brand: Mapping[str, Any]) -> dict[str, Any]:
    """What identifies the entity behind a brand: the legal entity name when the register carries it, else the brand with its ABN."""

    legal = _text(brand.get("legalEntityName")) or _text((brand.get("legalEntity") or {}).get("legalEntityName") if isinstance(brand.get("legalEntity"), Mapping) else None)
    name = legal or str(brand.get("brandName")).strip()
    return {
        "legal_name": name,
        "legal_name_status": "explicit_register_disclosure" if legal else "legal_name_not_established; brand name shown, the ABN identifies the entity",
        "brand_name": str(brand.get("brandName")).strip(),
        "abn": _text(brand.get("abn")),
        "acn": _text(brand.get("acn")),
        "public_base_uri": (_text(brand.get("publicBaseUri")) or "").rstrip("/"),
        "provider_key": _text(brand.get("dataHolderBrandId")) or _text(brand.get("interimId")),
        "industries": [str(item) for item in (brand.get("industries") or ()) if _text(item)],
        "last_updated": _text(brand.get("lastUpdated")),
    }


def cdr_register_to_pack(summary: Mapping[str, Any], *, retrieved_at: str, vertical_id: str, register_url: str = CDR_REGISTER_BRANDS_URL) -> dict[str, Any]:
    """The CDR Register's brand summary as a census pack: every banking data holder brand as an identity, no products."""

    stamp = timestamp(retrieved_at, field_name="retrieved_at")
    brands = [brand_identity(item) for item in _brands(summary) if "banking" in [str(x).lower() for x in (item.get("industries") or ("banking",))]]
    citation = {"source_id": "CDR_REGISTER", "url": register_url, "retrieved_at": stamp, "document_title": CDR_REGISTER_NAME, "source_type": "government_approval_register", "structured_feed": True, "quote": f"{len(brands)} data holder brands"}
    providers = []
    for brand in brands:
        providers.append({
            "provider_key": brand["provider_key"],
            "legal_name": brand["legal_name"],
            "legal_name_status": brand["legal_name_status"],
            "trading_names": [brand["brand_name"]] if brand["brand_name"] != brand["legal_name"] else [],
            "register_identifier": brand["abn"],
            "register_identifier_type": "ABN",
            "register_name": CDR_REGISTER_NAME,
            "register_url": register_url,
            "retrieved_at": stamp,
            "record_type": "census_identity_dossier",
            "review_status": "census_identity_only",
            "public_base_uri": brand["public_base_uri"],
            "sources": [citation],
            "gaps": [] if brand["public_base_uri"] else ["no publicBaseUri on the register entry; product data cannot be discovered"],
        })
    return {
        "registers": [{"register_name": CDR_REGISTER_NAME, "authority": "ACCC (Consumer Data Right Register)", "register_type": "data_holder_brand_register", "jurisdiction": "AU", "url": register_url, "retrieved_at": stamp, "entry_count_reported": len(brands)}],
        "providers": providers,
        "products": [],
        "coverage": {"vertical_id": vertical_id, "jurisdiction": "AU", "run_date": stamp[:10], "phase": "census_identity_from_cdr_register", "providers_on_register": len(brands), "providers_captured": len(brands), "providers_with_products": 0, "products_extracted": 0, "complete_national_provider_census": False, "known_limitations": ["The CDR Register lists data holder brands, not every credit provider: lenders outside the CDR are absent and stay on the ASIC registers.", "A brand is not a legal entity; where the summary carries no legal entity name the ABN identifies the entity and the name is not established."], "notes": [f"adapter={CDR_ADAPTER}", "census from the CDR Register brand summary"]},
    }


# --------------------------------------------------------------------------- #
# Monitored sources and requests
# --------------------------------------------------------------------------- #


def cdr_product_sources(brands: Sequence[Mapping[str, Any]], *, vertical_ids: Sequence[str]) -> tuple[MonitoredSource, ...]:
    """One monitored source per brand and product category: the public product list, polled with ``updated-since``."""

    out: list[MonitoredSource] = []
    for raw in brands:
        brand = brand_identity(raw) if "brandName" in raw else dict(raw)
        base = brand.get("public_base_uri")
        if not base:
            continue
        categories: dict[str, list[str]] = {}
        for vertical_id in vertical_ids:
            category = VERTICAL_CATEGORIES.get(vertical_id)
            if category:
                categories.setdefault(category, []).append(vertical_id)
        for category, verticals in sorted(categories.items()):
            url = base + CDR_PRODUCTS_PATH
            context = {"product-category": category, "effective": "CURRENT", "x-v": CDR_PRODUCTS_VERSION}
            out.append(MonitoredSource(source_key=source_key(url, context), url=url, jurisdiction="AU", vertical_ids=tuple(sorted(verticals)), provider_ref=provider_ref("AU", brand["legal_name"]), provider_name=brand["legal_name"], document_role="structured_feed", fetch_method="structured_api", request_context=context, extraction={"parser": CDR_ADAPTER, "version": CDR_PRODUCTS_VERSION, "detail_version": CDR_PRODUCT_DETAIL_VERSION, "brand": {"legal_name": brand["legal_name"], "brand_name": brand.get("brand_name"), "abn": brand.get("abn"), "provider_key": brand.get("provider_key"), "public_base_uri": base}}, source_family=source_family(url), cadence_hours=DEFAULT_CADENCE_HOURS["structured_feed"], freshness_hours=DEFAULT_FRESHNESS_HOURS["structured_feed"], source_ids_as_stated=(), document_title=f"CDR products: {brand.get('brand_name') or brand['legal_name']} / {category}", source_type_as_stated="structured_product_feed"))
    return tuple(out)


def cdr_sync_request(source: MonitoredSource | Mapping[str, Any], *, updated_since: str | None = None, page_size: int = 1000) -> dict[str, Any]:
    """The exact GET the worker performs for a product list; nothing is executed here."""

    src = source if isinstance(source, MonitoredSource) else MonitoredSource.model_validate(dict(source))
    _require(src.fetch_method == "structured_api" and src.extraction.get("parser") == CDR_ADAPTER, "NOT_A_CDR_SOURCE", "cdr_sync_request takes a CDR product source")
    params: dict[str, Any] = {"product-category": src.request_context.get("product-category"), "effective": src.request_context.get("effective", "CURRENT"), "page-size": page_size}
    if updated_since:
        params["updated-since"] = timestamp(updated_since, field_name="updated_since")
    return {"method": "GET", "url": src.url, "params": params, "headers": {"x-v": str(src.request_context.get("x-v", CDR_PRODUCTS_VERSION)), "x-min-v": CDR_PRODUCTS_VERSION, "Accept": "application/json"}, "adapter": CDR_ADAPTER}


def cdr_detail_request(source: MonitoredSource | Mapping[str, Any], product_id: str) -> dict[str, Any]:
    src = source if isinstance(source, MonitoredSource) else MonitoredSource.model_validate(dict(source))
    _require(bool(_text(product_id)), "PRODUCT_ID_REQUIRED", "a detail request names the productId")
    return {"method": "GET", "url": f"{src.url}/{product_id.strip()}", "params": {}, "headers": {"x-v": CDR_PRODUCT_DETAIL_VERSION, "x-min-v": CDR_PRODUCT_DETAIL_MIN_VERSION, "Accept": "application/json"}, "adapter": CDR_ADAPTER}


# --------------------------------------------------------------------------- #
# Products to a draft pack
# --------------------------------------------------------------------------- #


def _classify(vertical_id: str, product: Mapping[str, Any], detail: Mapping[str, Any]) -> tuple[str, str]:
    name = str(product.get("name") or "").lower()
    lending = [str(item.get("lendingRateType") or "").upper() for item in (detail.get("lendingRates") or ()) if isinstance(item, Mapping)]
    deposits = [str(item.get("depositRateType") or "").upper() for item in (detail.get("depositRates") or ()) if isinstance(item, Mapping)]
    features = {str(item.get("featureType") or "").upper() for item in (detail.get("features") or ()) if isinstance(item, Mapping)}
    if vertical_id == "AU-05":
        if "construction" in name:
            return "construction_loan", "name states construction"
        fixed, variable = "FIXED" in lending, any(kind in ("VARIABLE", "DISCOUNT", "INTRODUCTORY", "FLOATING", "MARKET_LINKED") for kind in lending)
        if fixed and not variable:
            return "fixed_home_loan", "every lending rate is FIXED"
        if variable and not fixed:
            return "variable_home_loan", "lending rates are variable and none is FIXED"
        if fixed and variable:
            return "unclassified", "fixed and variable lending rates on one product; the analyst splits or classifies"
        return "unclassified", "no lending rate on the detail"
    if vertical_id == "AU-04":
        for marker, klass in (("balance transfer", "balance_transfer_credit_card"), ("low rate", "low_rate_credit_card"), ("no annual fee", "low_fee_credit_card"), ("low fee", "low_fee_credit_card"), ("rewards", "rewards_credit_card"), ("points", "rewards_credit_card"), ("qantas", "rewards_credit_card"), ("velocity", "rewards_credit_card"), ("platinum", "rewards_credit_card")):
            if marker in name:
                return klass, f"name states {marker!r}"
        return "unclassified", "card class not stated in the name"
    if vertical_id == "AU-01":
        for marker, klass in (("pension", "concession_or_pensioner_account"), ("concession", "concession_or_pensioner_account"), ("youth", "youth_or_student_account"), ("student", "youth_or_student_account"), ("kids", "youth_or_student_account"), ("package", "packaged_transaction_account")):
            if marker in name:
                return klass, f"name states {marker!r}"
        return "everyday_transaction_account", "transaction account with no concession, youth or package marker"
    if vertical_id == "AU-02":
        if "BONUS" in deposits:
            return "bonus_interest_savings_account", "a BONUS deposit rate is stated"
        if "INTRODUCTORY" in deposits:
            return "introductory_rate_savings_account", "an INTRODUCTORY deposit rate is stated"
        if any(marker in name for marker in ("youth", "kids", "junior")):
            return "youth_savings_account", "name states youth"
        return "at_call_savings_account", "savings account with base or variable deposit rates"
    if vertical_id == "AU-03":
        return ("notice_deposit", "name states notice") if "notice" in name else ("fixed_term_deposit", "term deposit category")
    if vertical_id == "AU-08":
        for marker, klass in (("debt consolidation", "debt_consolidation_loan"), ("green", "green_personal_loan"), ("secured", "secured_personal_loan")):
            if marker in name:
                return klass, f"name states {marker!r}"
        return "unsecured_personal_loan", "personal loan with no secured, green or consolidation marker"
    if "OFFSET" in features and vertical_id == "AU-05":
        return "offset_account", "offset feature"
    return "unclassified", f"no classification rule for {vertical_id}"


def _wants(vertical_id: str, product: Mapping[str, Any], detail: Mapping[str, Any]) -> bool:
    category = str(product.get("productCategory") or "").upper()
    if VERTICAL_CATEGORIES.get(vertical_id) != category:
        return False
    if category == "TRANS_AND_SAVINGS_ACCOUNTS":
        savings = bool(detail.get("depositRates")) or any(marker in str(product.get("name") or "").lower() for marker in ("saver", "saving", "bonus"))
        return savings if vertical_id == "AU-02" else not savings
    return True


def _conditions(rate: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    kind = _text(rate.get("lendingRateType") or rate.get("depositRateType"))
    if kind:
        out["rate_type"] = kind.lower()
    months = duration_months(rate.get("additionalValue"))
    if months:
        out["term_months"] = months
        if months % 12 == 0:
            out["term_years"] = months // 12
    for key, name in (("loanPurpose", "loan_purpose"), ("repaymentType", "repayment_type"), ("interestPaymentDue", "interest_payment_due"), ("applicationFrequency", "application_frequency"), ("calculationFrequency", "calculation_frequency")):
        if _text(rate.get(key)):
            out[name] = str(rate[key]).lower()
    tiers = [item for item in (rate.get("tiers") or ()) if isinstance(item, Mapping)]
    if tiers:
        out["tiers"] = [{k: v for k, v in {"name": _text(t.get("name")), "unit": _text(t.get("unitOfMeasure")), "min": t.get("minimumValue"), "max": t.get("maximumValue")}.items() if v is not None} for t in tiers]
        for tier in tiers:
            if str(tier.get("unitOfMeasure") or "").upper() == "PERCENT" and tier.get("maximumValue") is not None and "lvr" in str(tier.get("name") or "").lower():
                out["lvr_max"] = tier.get("maximumValue")
    if _text(rate.get("additionalInfo")):
        out["note"] = str(rate["additionalInfo"])[:400]
    return out


def _fee_item(fee: Mapping[str, Any]) -> dict[str, Any] | None:
    name = _text(fee.get("name"))
    if name is None:
        return None
    fee_type = str(fee.get("feeType") or "").upper()
    currency = _text(fee.get("currency")) or "AUD"
    amount = _text(fee.get("amount"))
    if amount is not None:
        months = duration_months(fee.get("additionalValue"))
        if fee_type == "PERIODIC" and months == 12:
            unit = f"{currency}/year"
        elif fee_type == "PERIODIC" and months == 1:
            unit = f"{currency}/month"
        elif fee_type == "PERIODIC" and months:
            unit = f"{currency} per {months} months"
        elif fee_type == "TRANSACTION":
            unit = f"{currency}/transaction"
        else:
            unit = f"{currency} once-off"
        return {"item": name.lower(), "value": amount, "unit": unit, "conditions": {k: v for k, v in {"fee_type": fee_type.lower() or None, "note": _text(fee.get("additionalInfo"))}.items() if v}}
    for key, unit in (("transactionRate", "% of transaction"), ("balanceRate", "% of balance p.a."), ("accruedRate", "% p.a.")):
        if _text(fee.get(key)):
            return {"item": name.lower(), "value": _percent(fee.get(key)), "unit": unit, "conditions": {k: v for k, v in {"fee_type": fee_type.lower() or None, "note": _text(fee.get("additionalInfo"))}.items() if v}}
    return None


def cdr_products_to_draft_pack(products: Mapping[str, Any], details: Mapping[str, Mapping[str, Any]], *, brand: Mapping[str, Any], vertical_id: str, retrieved_at: str, batch_id: str, suggested_file_name: str | None = None) -> dict[str, Any]:
    """One brand's CDR products for one vertical as a draft pack in the map's shape; the analyst promotes it like any draft."""

    stamp = timestamp(retrieved_at, field_name="retrieved_at")
    _require(vertical_id in VERTICAL_CATEGORIES, "VERTICAL_NOT_IN_CDR", f"{vertical_id} has no CDR product category")
    identity = brand_identity(brand) if "brandName" in brand else dict(brand)
    base = str(identity.get("public_base_uri") or "").rstrip("/")
    _require(bool(base), "PUBLIC_BASE_URI_REQUIRED", "the brand names its publicBaseUri")
    listing = products.get("data") if isinstance(products.get("data"), Mapping) else {}
    rows = [item for item in (listing.get("products") or ()) if isinstance(item, Mapping) and _text(item.get("productId"))]
    list_url = base + CDR_PRODUCTS_PATH
    list_citation = {"source_id": "cdr_list", "url": list_url, "retrieved_at": stamp, "document_title": f"CDR product list: {identity.get('brand_name') or identity['legal_name']}", "source_type": "structured_product_feed", "structured_feed": True, "locator": "data.products", "quote": f"{len(rows)} products in category {VERTICAL_CATEGORIES[vertical_id]}"}
    drafted: list[dict[str, Any]] = []
    skipped: list[str] = []
    for row in rows:
        product_id = str(row["productId"]).strip()
        detail_payload = details.get(product_id) or {}
        detail = detail_payload.get("data") if isinstance(detail_payload.get("data"), Mapping) else (detail_payload if isinstance(detail_payload, Mapping) else {})
        if not _wants(vertical_id, row, detail):
            continue
        if not detail:
            skipped.append(f"{row.get('name')}: no detail payload; the list alone carries no rates or fees")
            continue
        name = str(row.get("name") or detail.get("name") or product_id).strip()
        taxonomy_class, reason = _classify(vertical_id, row, detail)
        detail_url = f"{list_url}/{product_id}"
        citation = {"source_id": "cdr_detail", "url": detail_url, "retrieved_at": stamp, "document_title": f"CDR product detail: {name}", "source_type": "structured_product_feed", "structured_feed": True, "locator": "data", "quote": f"productId {product_id}; lastUpdated {detail.get('lastUpdated') or row.get('lastUpdated')}"}
        pricing: list[dict[str, Any]] = []
        for index, rate in enumerate(item for item in (detail.get("lendingRates") or ()) if isinstance(item, Mapping)):
            value = _percent(rate.get("rate"))
            if value is None:
                continue
            conditions = _conditions(rate)
            pricing.append({"item": "interest rate", "value": value, "unit": "% p.a.", "conditions": conditions, "source_ids": ["cdr_detail"], "quote": f'lendingRates[{index}].rate "{rate.get("rate")}"', "locator": f"data.lendingRates[{index}]"})
            comparison = _percent(rate.get("comparisonRate"))
            if comparison is not None:
                pricing.append({"item": "comparison rate", "value": comparison, "unit": "% p.a.", "conditions": conditions, "source_ids": ["cdr_detail"], "quote": f'lendingRates[{index}].comparisonRate "{rate.get("comparisonRate")}"', "locator": f"data.lendingRates[{index}]"})
        for index, rate in enumerate(item for item in (detail.get("depositRates") or ()) if isinstance(item, Mapping)):
            value = _percent(rate.get("rate"))
            if value is None:
                continue
            kind = str(rate.get("depositRateType") or "").upper()
            item = {"BASE": "base interest rate", "BONUS": "bonus interest rate", "INTRODUCTORY": "introductory interest rate"}.get(kind, "interest rate")
            pricing.append({"item": item, "value": value, "unit": "% p.a.", "conditions": _conditions(rate), "source_ids": ["cdr_detail"], "quote": f'depositRates[{index}].rate "{rate.get("rate")}"', "locator": f"data.depositRates[{index}]"})
        for index, fee in enumerate(item for item in (detail.get("fees") or ()) if isinstance(item, Mapping)):
            parsed_fee = _fee_item(fee)
            if parsed_fee is not None:
                pricing.append({**parsed_fee, "source_ids": ["cdr_detail"], "quote": f'fees[{index}] "{fee.get("name")}" {fee.get("amount") or fee.get("transactionRate") or fee.get("balanceRate") or ""}'.strip(), "locator": f"data.fees[{index}]"})
        eligibility = []
        for item in (detail.get("eligibility") or ()):
            if isinstance(item, Mapping) and _text(item.get("eligibilityType")):
                value = _text(item.get("additionalValue")) or _text(item.get("additionalInfo"))
                eligibility.append(f"{str(item['eligibilityType']).upper()}: {value}" if value else str(item["eligibilityType"]).upper())
        key_terms: list[dict[str, Any]] = []
        for item in (detail.get("constraints") or ()):
            if not isinstance(item, Mapping) or not _text(item.get("constraintType")):
                continue
            kind = str(item["constraintType"]).upper()
            term = {"MIN_BALANCE": "minimum opening balance", "MAX_BALANCE": "maximum balance", "MIN_LIMIT": "minimum loan amount", "MAX_LIMIT": "maximum loan amount", "OPENING_BALANCE": "minimum opening deposit"}.get(kind, kind.lower())
            key_terms.append({"term": term, "value": item.get("additionalValue"), "source_ids": ["cdr_detail"]})
        for key, term in (("effectiveFrom", "effective_from"), ("effectiveTo", "effective_to"), ("lastUpdated", "last_updated"), ("applicationUri", "application_uri")):
            if _text(detail.get(key) or row.get(key)):
                key_terms.append({"term": term, "value": str(detail.get(key) or row.get(key)), "source_ids": ["cdr_detail"]})
        features = sorted({str(item.get("featureType")).upper() for item in (detail.get("features") or ()) if isinstance(item, Mapping) and _text(item.get("featureType"))})
        if features:
            key_terms.append({"term": "features", "value": features, "source_ids": ["cdr_detail"]})
        gaps = [] if taxonomy_class != "unclassified" else [f"unclassified: {reason}"]
        if not pricing:
            gaps.append("no rate or fee on the detail; the analyst confirms the product page")
        info = detail.get("additionalInformation") if isinstance(detail.get("additionalInformation"), Mapping) else {}
        drafted.append({
            "provider_name": identity.get("brand_name") or identity["legal_name"],
            "provider_legal_name": identity["legal_name"],
            "provider_key": identity.get("provider_key"),
            "catalog_product_id": product_id,
            "product_name": name,
            "taxonomy_class": taxonomy_class,
            "classification_reason": reason,
            "eligibility": eligibility,
            "pricing": pricing,
            "key_terms": key_terms,
            "effective_date": _text(detail.get("effectiveFrom") or row.get("effectiveFrom")),
            "pricing_kind": "list" if pricing else "unstated",
            "sources": [citation, list_citation],
            "confidence": "unverified",
            "verification_basis": DRAFT_BASIS,
            "availability_status": "current" if str(row.get("effectiveTo") or "") == "" else f"effective to {row.get('effectiveTo')}",
            "disclosure_links": {k: v for k, v in {"overview": _text(info.get("overviewUri")), "terms": _text(info.get("termsUri")), "eligibility": _text(info.get("eligibilityUri")), "fees_and_pricing": _text(info.get("feesAndPricingUri"))}.items() if v},
            "gaps": gaps,
        })
    next_page = bool((products.get("links") or {}).get("next")) if isinstance(products.get("links"), Mapping) else False
    return {
        "registers": [],
        "providers": [{"provider_key": identity.get("provider_key"), "legal_name": identity["legal_name"], "legal_name_status": identity.get("legal_name_status"), "trading_names": [identity["brand_name"]] if identity.get("brand_name") and identity["brand_name"] != identity["legal_name"] else [], "register_identifier": identity.get("abn"), "register_identifier_type": "ABN", "product_discovery_status": "draft_products_extracted_pending_promotion", "disposition": DRAFT_BASIS, "sources": [list_citation]}],
        "products": drafted,
        "coverage": {"vertical_id": vertical_id, "jurisdiction": "AU", "run_date": stamp[:10], "batch_id": batch_id, "phase": DRAFT_PHASE, "providers_captured": 1, "providers_with_products_extracted": 1 if drafted else 0, "products_extracted": len(drafted), "products_unverified": len(drafted), "complete_national_provider_census": False, "product_extraction_exhaustive": not next_page and not skipped, "known_limitations": ["CDR public product data as the data holder publishes it; the target market determination, full terms and any condition the API does not carry stay on the linked disclosures.", "A rate is stated with the term, purpose, repayment type and tiers the feed attaches; a rate the feed states without them is drafted as it is and stays unranked until a person confirms its applicability."] + (["list has a next page not read in this run"] if next_page else []) + [f"skipped: {item}" for item in skipped], "notes": [f"adapter={CDR_ADAPTER}", f"detail_version={CDR_PRODUCT_DETAIL_VERSION}"] + ([f"suggested_file_name={suggested_file_name}"] if suggested_file_name else [])},
    }


CDR_MANIFEST: dict[str, Any] = {
    "kind": "lightbulb.finance_advice_cdr.v1",
    "adapter": CDR_ADAPTER,
    "register": CDR_REGISTER_BRANDS_URL,
    "products_path": CDR_PRODUCTS_PATH,
    "versions": {"products": CDR_PRODUCTS_VERSION, "product_detail": CDR_PRODUCT_DETAIL_VERSION, "product_detail_min": CDR_PRODUCT_DETAIL_MIN_VERSION},
    "categories": {category: list(verticals) for category, verticals in CDR_CATEGORY_VERTICALS.items()},
    "hard_rules": [
        "public, unauthenticated product data only; no consumer data, no consent, no credentials",
        "the SDK composes requests and reads payloads; the worker performs the reads under the registry's allowlist",
        "a brand's products become a draft pack that passes the same checklist and promotion as any research draft; a structured feed earns verified at promotion",
        "a rate carries the term, purpose, repayment type and tiers the feed attaches; without them it is drafted and never ranked",
        "incremental reads use updated-since; a periodic full read reconciles what the increments missed",
    ],
}


__all__ = [
    "CDR_ADAPTER",
    "CDR_CATEGORY_VERTICALS",
    "CDR_MANIFEST",
    "CDR_PRODUCTS_PATH",
    "CDR_PRODUCTS_VERSION",
    "CDR_PRODUCT_DETAIL_VERSION",
    "CDR_REGISTER_BRANDS_URL",
    "CDR_REGISTER_NAME",
    "VERTICAL_CATEGORIES",
    "AdviceCdrError",
    "brand_identity",
    "cdr_detail_request",
    "cdr_product_sources",
    "cdr_products_to_draft_pack",
    "cdr_register_to_pack",
    "cdr_sync_request",
    "duration_months",
]
