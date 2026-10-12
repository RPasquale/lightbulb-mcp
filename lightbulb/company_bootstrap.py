"""Zero to running: propose a company's bundle from what is already connected, and keep the accepted bundle in the project.

Until now a company could not run anything without a hand-built bundle: an
operating plan, a workforce plan, a close plan and a dozen sealed supporting
plans, written as JSON by someone who knew every compiler.  And once built,
the whole bundle had to be passed on every call.  This module removes both.

``propose_company_bundle`` reads three things the platform already has: the
ledger's organisation record (name, base currency, country, financial year
end, tax basis), the connectors the project has bound, and, when one has
been recorded, the books snapshot.  From them it proposes a sealed
``BundleProposal``: the company ref, the archetype with the evidence it was
chosen on, the compiled bundle with the ledger-first intelligence plans
added, the account roles suggested by name for the owner to confirm, every
assumption it made, and for each connector what it unlocks and what is
still unbound.  Nothing is inferred silently: a jurisdiction the SDK does not
run companies in, or books kept in another currency than the jurisdiction's
home currency, is refused by name, and an archetype chosen for want of a
closer one says so.  Every archetype runs in each of the five jurisdictions
(``lightbulb.jurisdictions``); Xero's ``GB`` is read as ``UK``.

The organisation is read from Xero (``Organisations[1]``) or QuickBooks
Online (``CompanyInfo``).  QuickBooks keeps a company's books in its home
currency, which it sets from the company's country and never changes, so
the currency is taken from the country and said so under assumptions; the
books' own reports then state their currency and are refused if it differs.
Its financial year end is the day before the first month of its fiscal
year.  The books plan records which ledger was read, so the backfill plans
that ledger's reads.

``accept_bundle_proposal`` verifies the proposal and returns its bundle;
``persist_company_bundle`` keeps it under ``bundle:current`` in the project's
engine state store, amended by exactly one version when it changes, and
``load_company_bundle`` reads it back, so a console can be opened from the
project alone.  Accepting is the owner's confirmation of the suggested roles
and assumptions.  Nothing here reads a provider.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

BUNDLE_PROPOSAL_SCHEMA = "lightbulb.company_bundle_proposal.v1"
COMPANY_BUNDLE_RECORD_SCHEMA = "lightbulb.company_bundle_record.v1"
COMPANY_BUNDLE_ENGINE = "company_bundle"
COMPANY_BUNDLE_ENTITY = "bundle:current"
ORGANISATION_TOOLS: tuple[str, ...] = ("xero.get_organisation", "quickbooks.company_info", "quickbooks.get_company_info", "host.organisation")
# QuickBooks Online sets a company's home currency from its country and it cannot be changed.
QUICKBOOKS_HOME_CURRENCIES: dict[str, str] = {"AU": "AUD", "CA": "CAD", "US": "USD", "GB": "GBP", "UK": "GBP", "NZ": "NZD", "IE": "EUR", "FR": "EUR", "IN": "INR", "ZA": "ZAR", "SG": "SGD", "HK": "HKD", "MY": "MYR", "AE": "AED"}
_FISCAL_MONTHS: tuple[str, ...] = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december")
_MONTH_DAYS: tuple[int, ...] = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
BUSINESS_MODELS: tuple[str, ...] = ("services", "product", "subscription", "marketplace")
# The archetypes that fit each business model, nearest first.  The jurisdiction then decides which of them can run.
MODEL_ARCHETYPES: dict[str, tuple[str, ...]] = {
    "services": ("services_firm", "local_services"),
    "product": ("dtc_commerce",),
    "subscription": ("b2b_saas", "founder_led_saas"),
    "marketplace": ("marketplace", "two_sided_marketplace"),
}
# What a connector makes possible.  "today" reads work on a plain read; the rest wait on a governed read that carries the facts they need.
CONNECTOR_UNLOCKS: dict[str, dict[str, tuple[str, ...]]] = {
    "xero": {"today": ("books", "break_even", "working_capital", "cash_calendar", "customers", "intelligence_review", "backfill", "history", "calibrate"), "later": ("payables adoption", "receivables adoption")},
    "quickbooks": {"today": ("books", "break_even", "working_capital", "cash_calendar", "customers", "intelligence_review", "backfill", "history", "calibrate"), "later": ("payables adoption", "receivables adoption")},
    # V2145 governs stripe.list_subscription_invoices (lines, the paying charge and its funds) and stripe.list_payouts
    "stripe": {"today": ("subscription adoption", "settlements", "customer_cohorts"), "later": ()},
    "shopify": {"today": (), "later": ("product_margin", "product_portfolio", "stockouts", "returns_ledger", "customer_cohorts")},
    "square": {"today": (), "later": ("product_margin", "customer_cohorts")},
    "hubspot": {"today": (), "later": ("pipeline prospects", "pipeline_coverage", "win_loss")},
    "salesforce": {"today": (), "later": ("pipeline prospects", "pipeline_coverage", "win_loss")},
}
_PRODUCT_CONNECTORS = frozenset({"shopify", "square"})
_LEDGER_PLANS = ("books_snapshot", "break_even", "working_capital")


class CompanyBootstrapError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CompanyBootstrapError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def company_ref_from_name(name: str) -> str:
    """A stable, readable ref from a company's name: lower case, runs of anything else become one hyphen."""

    slug = re.sub(r"[^a-z0-9]+", "-", str(name or "").casefold()).strip("-")[:60].strip("-")
    _require(bool(slug), "COMPANY_NAME_UNUSABLE", f"no company ref can be made from the name {name!r}")
    return slug


class ConnectorUnlock(StrictModel):
    provider: ShortText
    connected: bool
    bound_to_project: bool
    unlocks_today: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    unlocks_later: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    next_step: ShortText

    @field_validator("unlocks_today", "unlocks_later", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class BundleProposal(StrictModel):
    schema_id: str = Field(default=BUNDLE_PROPOSAL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    company_name: ShortText
    currency: CurrencyCode
    country: ShortText
    financial_year_end: ShortText | None = None
    tax_basis: ShortText | None = None
    as_of: str
    business_model: ShortText
    archetype: ShortText
    archetype_evidence: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assumptions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    confirm: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    connectors: tuple[ConnectorUnlock, ...] = Field(default_factory=tuple, max_length=40)
    plans_added: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    bundle: dict[str, Any]
    bundle_digest: Sha256Digest
    books_digest: Sha256Digest | None = None
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=8)
    verdict: ShortText
    proposal_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("archetype_evidence", "assumptions", "confirm", "connectors", "plans_added", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BundleProposal":
        from lightbulb.company_cadence_runner import CadenceBundle

        bundle = CadenceBundle.model_validate(detached(self.bundle))
        if bundle.bundle_digest != self.bundle_digest:
            raise ValueError("bundle_digest names the proposed bundle, exactly")
        if bundle.company_ref != self.company_ref or bundle.operating_plan.blueprint.currency != self.currency:
            raise ValueError("SCOPE_MISMATCH: the proposed bundle is for this company and currency")
        if not skip_digests(info) and self.proposal_digest != sealed_digest(BundleProposal, self, "proposal_digest"):
            raise ValueError("proposal_digest must commit the exact proposal")
        return self

    def render(self) -> str:
        lines = [f"**Proposed bundle for {self.company_name}** ({self.company_ref}, {self.currency}, {self.country}): {self.verdict}"]
        lines.extend(f"- chosen on: {item}" for item in self.archetype_evidence)
        lines.extend(f"- assumed: {item}" for item in self.assumptions)
        lines.extend(f"- confirm: {item}" for item in self.confirm)
        lines.extend(f"- {row.provider}: {row.next_step}" for row in self.connectors)
        return "\n".join(lines)


def _quickbooks_organisation(info: Mapping[str, Any], assumptions: list[str]) -> dict[str, Any]:
    """A QuickBooks ``CompanyInfo`` in the organisation's terms: name, country, the home currency its country sets, and the year end."""

    country = str(info.get("Country") or dict(info.get("CompanyAddr") or {}).get("Country") or "").upper()
    country = "GB" if country == "UK" else country
    currency = QUICKBOOKS_HOME_CURRENCIES.get(country, "")
    _require(bool(currency) or not country, "ORGANISATION_INCOMPLETE", f"QuickBooks names the country {country}, whose home currency this SDK does not know")
    if currency:
        assumptions.append(f"the books are in {currency}: QuickBooks sets a company's home currency from its country ({country}) and the books' reports state theirs, which must agree")
    org: dict[str, Any] = {"Name": info.get("CompanyName"), "LegalName": info.get("LegalName"), "BaseCurrency": currency, "CountryCode": country}
    start = str(info.get("FiscalYearStartMonth") or "").casefold()
    if start in _FISCAL_MONTHS:
        end_month = (_FISCAL_MONTHS.index(start) - 1) % 12  # the year ends the month before it starts
        org["FinancialYearEndMonth"], org["FinancialYearEndDay"] = end_month + 1, _MONTH_DAYS[end_month]
    return org


def _organisation(source: Mapping[str, Any], *, as_of: str, assumptions: list[str]) -> tuple[dict[str, Any], str, str]:
    """The organisation record, the read's provenance digest, and the ledger it came from (``xero``, ``quickbooks`` or ``host``)."""

    from lightbulb.company_execution_bridge import ObservationProvenance

    _require(isinstance(source, Mapping) and source.get("provenance") is not None and source.get("payload") is not None, "SOURCE_NOT_SEALED", "the organisation source carries its provenance and the exact payload the read returned")
    read = ObservationProvenance.model_validate(detached(source["provenance"]))
    _require(read.provenance_digest != GENESIS_DIGEST and read.source_tool in ORGANISATION_TOOLS, "SOURCE_TOOL_MISMATCH", f"the organisation is read with one of {list(ORGANISATION_TOOLS)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(source["payload"])), "SOURCE_DIGEST_MISMATCH", "the organisation must be the exact output the read returned")
    _require(parsed(read.completed_at) <= parsed(as_of), "SOURCE_FROM_FUTURE", "the read must complete before the proposal is made")
    raw = detached(source["payload"])
    ledger = read.source_tool.split(".")[0]
    if ledger == "quickbooks":
        info = raw.get("CompanyInfo") if isinstance(raw, Mapping) else None
        _require(isinstance(info, Mapping), "ORGANISATION_SHAPE_UNKNOWN", "the QuickBooks read must carry one CompanyInfo")
        return _quickbooks_organisation(dict(info), assumptions), read.provenance_digest, ledger
    rows = raw.get("Organisations") if isinstance(raw, Mapping) else None
    _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], Mapping), "ORGANISATION_SHAPE_UNKNOWN", "the read must carry exactly one organisation")
    return dict(rows[0]), read.provenance_digest, ledger


def supported_jurisdictions() -> dict[tuple[str, str], tuple[str, ...]]:
    """The (country, currency) pairs a company runs in, and the archetypes for each: every archetype, in each jurisdiction's home currency."""

    from lightbulb.company_operating_system import COMPANY_OS_ARCHETYPES
    from lightbulb.jurisdictions import HOME_CURRENCIES

    return {(code, currency): tuple(sorted(COMPANY_OS_ARCHETYPES)) for code, currency in HOME_CURRENCIES.items()}


def propose_company_bundle(*, organisation: Mapping[str, Any], scope: Mapping[str, str], actor_ref: str, as_of: str, connectors: Sequence[Mapping[str, Any]] = (), books: Mapping[str, Any] | Any | None = None, archetype: str | None = None, company_ref: str | None = None, business_model: str | None = None) -> BundleProposal:
    """The sealed proposal from the organisation read, the project's connectors and, when recorded, the books."""

    from lightbulb.books_snapshot import compile_books_plan, suggest_account_roles, verify_books_snapshot
    from lightbulb.break_even import compile_break_even_plan
    from lightbulb.ledger_tie_out import compile_tie_out_plan
    from lightbulb.company_cadence_runner import build_bundle, compile_company_bundle
    from lightbulb.working_capital import compile_working_capital_plan

    at = timestamp(as_of, field_name="as_of")
    assumptions: list[str] = []
    org, org_digest, ledger = _organisation(organisation, as_of=at, assumptions=assumptions)
    name = str(org.get("Name") or org.get("LegalName") or "")
    currency, country = str(org.get("BaseCurrency") or "").upper(), str(org.get("CountryCode") or "").upper()
    _require(bool(name) and bool(currency) and bool(country), "ORGANISATION_INCOMPLETE", "the organisation states its name, base currency and country")
    _require(org.get("IsDemoCompany") is not True, "ORGANISATION_IS_DEMO", "the connected ledger is the provider's demo company, not a real set of books")
    ref = company_ref or company_ref_from_name(name)
    from lightbulb.jurisdictions import HOME_CURRENCIES, UnsupportedJurisdictionError, normalize_jurisdiction

    try:
        country = normalize_jurisdiction(country)
    except UnsupportedJurisdictionError:
        pass
    jurisdictions = supported_jurisdictions()
    candidates = jurisdictions.get((country, currency), ())
    if not candidates and country in HOME_CURRENCIES:
        _require(False, "JURISDICTION_UNSUPPORTED", f"a company in {country} runs its books in {HOME_CURRENCIES[country]}; these books are in {currency}")
    _require(bool(candidates), "JURISDICTION_UNSUPPORTED", f"no archetype runs in {country}/{currency}; the SDK runs {', '.join(f'{c}/{u}' for c, u in sorted(jurisdictions))}")

    snapshot = None if books is None else verify_books_snapshot(books)
    if snapshot is not None:
        _require(snapshot.currency == currency, "SOURCE_SCOPE_MISMATCH", f"the books are in {snapshot.currency}, the organisation's base currency is {currency}")
    rows = [dict(detached(item)) for item in connectors]
    providers = {str(row.get("provider", "")).lower(): row for row in rows}
    evidence: list[str] = []
    model = business_model
    if model is not None:
        _require(model in BUSINESS_MODELS, "BUSINESS_MODEL_UNKNOWN", f"{model} is not one of {BUSINESS_MODELS}")
        evidence.append(f"the business model {model} was stated")
    else:
        from lightbulb.books_snapshot import _LABOUR_WORDS

        stock = snapshot is not None and ((snapshot.inventory or 0) > 0 or any(item.startswith("inventory:") for item in snapshot.role_candidates))
        goods = [] if snapshot is None else [line.name for line in snapshot.lines if line.account_class == "cost_of_sales" and line.amount != 0 and not any(word in line.name.casefold() for word in _LABOUR_WORDS)]
        selling = sorted(_PRODUCT_CONNECTORS & set(providers))
        if selling:
            model = "product"
            evidence.append(f"a storefront is connected ({', '.join(selling)})")
        elif stock:
            model = "product"
            evidence.append("the books carry a stock account")
        elif goods:
            model = "product"
            evidence.append(f"the cost of sales includes goods, not only labour ({', '.join(goods[:3])})")
        else:
            model = "services"
            if snapshot is None:
                evidence.append("no storefront is connected and no books were recorded; services is the default until evidence says otherwise")
            elif snapshot.cost_of_sales > 0:
                evidence.append(f"no storefront or stock, and the cost of sales of {snapshot.cost_of_sales} {currency} is labour: revenue is read as fees for work")
            else:
                evidence.append("no storefront is connected and the books carry no cost of sales or stock, so revenue is read as fees for work")
    chosen = archetype
    if chosen is not None:
        _require(chosen in candidates, "ARCHETYPE_UNSUPPORTED", f"{chosen} does not run in {country}/{currency}; {', '.join(candidates)} do")
        evidence.append(f"the archetype {chosen} was stated")
    else:
        chosen = next((item for item in MODEL_ARCHETYPES[model] if item in candidates), None)
        if chosen is None:
            chosen = candidates[0]
            assumptions.append(f"no {model} archetype runs in {country}/{currency}; {chosen} is used as the nearest that does, and its engines may not all apply: pass archetype to choose another of {', '.join(candidates)}")
    bundle = compile_company_bundle(chosen, company_ref=ref, scope=dict(scope), actor_ref=actor_ref, start_at=at, jurisdiction=country)

    confirm: list[str] = []
    roles: dict[str, list[str]] = {}
    if snapshot is not None:
        for item in suggest_account_roles(snapshot.lines):
            roles.setdefault(item["role"], []).append(item["name"])
        for role, accounts in sorted(roles.items()):
            confirm.append(f"{role} is read from {', '.join(accounts)} (matched by account name)")
        if snapshot.cost_of_sales == 0 and snapshot.operating_expenses > 0:
            confirm.append("no cost is marked variable: name the accounts that move with sales in variable_accounts, or contribution equals revenue")
    else:
        assumptions.append("no books were recorded, so no account roles are proposed: record the books, then propose again")
    fy_day, fy_month = org.get("FinancialYearEndDay"), org.get("FinancialYearEndMonth")
    year_end = f"{int(fy_month):02d}-{int(fy_day):02d}" if isinstance(fy_day, int) and isinstance(fy_month, int) else None
    if year_end is None:
        assumptions.append("the organisation states no financial year end")
    from lightbulb.customer_ledger import compile_customer_ledger_plan

    books_overrides: dict[str, Any] = {"account_roles": roles} if roles else {}
    if ledger in ("xero", "quickbooks"):
        books_overrides["ledger"] = ledger
    plans = {
        "customer_ledger": compile_customer_ledger_plan(ref, currency=currency).to_dict(),
        "books_snapshot": compile_books_plan(ref, currency=currency, overrides=books_overrides or None).to_dict(),
        "break_even": compile_break_even_plan(ref, currency=currency).to_dict(),
        "working_capital": compile_working_capital_plan(ref, currency=currency).to_dict(),
        "ledger_tie_out": compile_tie_out_plan(ref, currency=currency).to_dict(),
    }
    values = {key: value for key, value in bundle.to_dict().items() if key != "bundle_digest"}
    values["supporting_plans"] = {**dict(values.get("supporting_plans") or {}), **plans}
    proposed = build_bundle(values)
    assumptions.append("break-even and working capital use their default targets (30-day receivables and payables, 60-day stock); change them in the plans once the business's own terms are known")

    unlocks: list[dict[str, Any]] = []
    if not {"xero", "quickbooks"} & set(providers):
        assumptions.append("the project lists no ledger connector, though the organisation was read from one: bind the ledger to this project")
    for provider in sorted(providers):
        row = providers.get(provider, {})
        connected = str(row.get("status", "")).lower() == "active" if row else False
        bound = bool(row.get("bound_to_project") or row.get("boundToThisProject") or row.get("bound"))
        table = CONNECTOR_UNLOCKS.get(provider, {"today": (), "later": ()})
        if not connected:
            step = "connect it, then bind it to this project"
        elif not bound:
            step = "connected for the company but not bound to this project: bind it, or nothing in this project can read it"
        elif table["today"]:
            step = f"ready: {', '.join(table['today'])}"
        elif table["later"]:
            step = f"bound; {', '.join(table['later'])} follow when the platform's governed reads carry the facts they need"
        else:
            step = "bound; no intelligence document reads it yet"
        unlocks.append({"provider": provider, "connected": connected, "bound_to_project": bound, "unlocks_today": list(table["today"]), "unlocks_later": list(table["later"]), "next_step": step[:300]})

    ready = sorted({item for row in unlocks if row["connected"] and row["bound_to_project"] for item in row["unlocks_today"]})
    verdict = f"{chosen} in {country}/{currency}, read as a {model} business; {len(plans)} ledger-first plan(s) added" + (f"; ready now: {', '.join(ready)}" if ready else "; nothing is ready until a ledger is connected and bound") + (f"; {len(confirm)} thing(s) to confirm" if confirm else "")
    payload = {
        "company_ref": ref, "company_name": name[:300], "currency": currency, "country": country, "financial_year_end": year_end, "tax_basis": None if not org.get("SalesTaxBasis") else str(org["SalesTaxBasis"])[:300], "as_of": at,
        "business_model": model, "archetype": chosen, "archetype_evidence": [item[:300] for item in evidence], "assumptions": [item[:300] for item in assumptions], "confirm": [item[:300] for item in confirm][:24], "connectors": unlocks,
        "plans_added": sorted(plans), "bundle": proposed.to_dict(), "bundle_digest": proposed.bundle_digest, "books_digest": None if snapshot is None else snapshot.snapshot_digest,
        "source_digests": [org_digest, *([] if snapshot is None else [snapshot.snapshot_digest])], "verdict": verdict[:300],
    }
    return seal(BundleProposal, {key: value for key, value in payload.items() if value is not None}, "proposal_digest")


def verify_bundle_proposal(value: Any) -> BundleProposal:
    return value if isinstance(value, BundleProposal) else BundleProposal.model_validate(dict(detached(value)))


def accept_bundle_proposal(proposal: BundleProposal | Mapping[str, Any]) -> dict[str, Any]:
    """The proposal's bundle, once the proposal verifies.  Accepting is the owner's confirmation of what it lists under confirm and assumed."""

    return dict(verify_bundle_proposal(proposal).bundle)


# --------------------------------------------------------------------------- #
# The bundle lives in the project
# --------------------------------------------------------------------------- #


def persist_company_bundle(store: Any, bundle: Mapping[str, Any] | Any, *, as_of: str) -> dict[str, Any]:
    """Keep the bundle under ``bundle:current`` in the project's engine state store; a changed bundle amends it by exactly one version, an identical one changes nothing."""

    from lightbulb.company_cadence_runner import build_bundle

    sealed = build_bundle(bundle if not isinstance(bundle, Mapping) else dict(detached(bundle)))
    at = timestamp(as_of, field_name="as_of")
    current = store.get(COMPANY_BUNDLE_ENGINE, COMPANY_BUNDLE_ENTITY)
    if current is not None:
        state = dict(current["state"])
        _require(dict(state.get("scope") or {}).get("project_id") == sealed.scope.get("project_id"), "SCOPE_MISMATCH", "the stored bundle belongs to another project")
        if state.get("state_digest") == sealed.bundle_digest:
            return {"entity_ref": COMPANY_BUNDLE_ENTITY, "version": int(state["version"]), "bundle_digest": sealed.bundle_digest, "unchanged": True}
    version = 1 if current is None else int(dict(current["state"])["version"]) + 1
    if current is not None:
        outgoing = dict(current["state"])
        # A version stored before versions were kept is kept as it is replaced: what ran under it (a cadence, a
        # worker's signed journals) is read under it, and carried onto the amendment.
        if store.get(COMPANY_BUNDLE_ENGINE, bundle_entity(outgoing["state_digest"])) is None:
            replaced = build_bundle(dict(outgoing["bundle"]))
            _require(replaced.bundle_digest == outgoing["state_digest"], "BUNDLE_RECORD_INVALID", "the stored bundle does not match its recorded digest")
            store.put(COMPANY_BUNDLE_ENGINE, bundle_entity(replaced.bundle_digest), {**outgoing, "status": "kept", "version": 1, "scope": replaced.engine_scope(bundle_entity(replaced.bundle_digest)), "bundle_version": int(outgoing["version"])}, expected_version=None, expected_state_digest=None)
    # The record's plan is the project itself: the store holds one bundle per project and refuses a plan change across versions.
    document = {"schema": COMPANY_BUNDLE_RECORD_SCHEMA, "status": "active", "plan_digest": stable_digest({"company_bundle": str(sealed.scope.get("project_id"))}), "version": version, "state_digest": sealed.bundle_digest, "scope": sealed.engine_scope(COMPANY_BUNDLE_ENTITY), "as_of": at, "bundle": sealed.to_dict()}
    # Every version is also kept under its own digest, written once: a state bound to the bundle it ran under (the
    # cadence) can always be read under that bundle, and followed onto the amended one with a proof.
    if store.get(COMPANY_BUNDLE_ENGINE, bundle_entity(sealed.bundle_digest)) is None:
        store.put(COMPANY_BUNDLE_ENGINE, bundle_entity(sealed.bundle_digest), {**document, "status": "kept", "version": 1, "scope": sealed.engine_scope(bundle_entity(sealed.bundle_digest)), "bundle_version": version}, expected_version=None, expected_state_digest=None)
    store.put(COMPANY_BUNDLE_ENGINE, COMPANY_BUNDLE_ENTITY, document, expected_version=version - 1, expected_state_digest=None if current is None else dict(current["state"])["state_digest"])
    return {"entity_ref": COMPANY_BUNDLE_ENTITY, "version": version, "bundle_digest": sealed.bundle_digest, "unchanged": False}


def bundle_entity(bundle_digest: str) -> str:
    return f"bundle:{bundle_digest}"


def kept_bundle(store: Any, bundle_digest: str) -> Any | None:
    """The bundle version kept under this digest, verified; ``None`` when that version was never kept (it predates keeping them)."""

    from lightbulb.company_cadence_runner import build_bundle

    record = store.get(COMPANY_BUNDLE_ENGINE, bundle_entity(bundle_digest))
    if record is None:
        return None
    state = dict(record["state"])
    _require(state.get("schema") == COMPANY_BUNDLE_RECORD_SCHEMA and state.get("state_digest") == bundle_digest, "BUNDLE_RECORD_INVALID", "the kept bundle record has an unknown shape or names another bundle")
    sealed = build_bundle(dict(state["bundle"]))
    _require(sealed.bundle_digest == bundle_digest, "BUNDLE_RECORD_INVALID", "the kept bundle does not match the digest it is kept under")
    return sealed


def earlier_bundle_digests(store: Any, bundle: Any) -> tuple[str, ...]:
    """The versions of this project's bundle kept before ``bundle``, newest first.

    What an amended bundle may carry on from: a checkpoint, a signed journal or an
    in-flight record written under one of these is this company's own work under an
    earlier version of its bundle.  Empty unless ``bundle`` is the project's current
    bundle, so a worker still holding an older version never adopts anything, and a
    digest the project never kept is never among them.
    """

    from lightbulb.company_engine_store import complete_engine_states

    digest = str(getattr(bundle, "bundle_digest", None) or dict(bundle).get("bundle_digest") or "")
    project_id = str(dict(getattr(bundle, "scope", None) or dict(bundle).get("scope") or {}).get("project_id") or "")
    current = store.get(COMPANY_BUNDLE_ENGINE, COMPANY_BUNDLE_ENTITY)
    if current is None or not digest:
        return ()
    state = dict(current["state"])
    if state.get("state_digest") != digest or dict(state.get("scope") or {}).get("project_id") != project_id:
        return ()
    version = int(state["version"])
    earlier: list[tuple[int, str]] = []
    for record in complete_engine_states(store, engine=COMPANY_BUNDLE_ENGINE, status="kept"):
        kept = dict(record["state"])
        kept_digest, kept_version = str(kept.get("state_digest") or ""), int(kept.get("bundle_version") or 0)
        if kept_digest and kept_digest != digest and 0 < kept_version < version and dict(kept.get("scope") or {}).get("project_id") == project_id:
            earlier.append((kept_version, kept_digest))
    return tuple(item for _, item in sorted(set(earlier), reverse=True))


def superseding_bundle(store: Any, bundle: Any) -> dict[str, Any] | None:
    """The project's current bundle when ``bundle`` is an earlier version of it the project keeps; else ``None``.

    What a host holding ``bundle`` runs instead: the owner amended it, and the
    amendment is the company's bundle now.  ``None`` while ``bundle`` is
    current, and for a bundle the project never kept or that names another
    company: a worker may run a bundle of its own beside the stored one, and
    that one is not followed.  Returns ``{"version", "bundle_digest", "bundle"}``
    with the current bundle verified.
    """

    digest = str(getattr(bundle, "bundle_digest", None) or dict(bundle).get("bundle_digest") or "")
    scope = dict(getattr(bundle, "scope", None) or dict(bundle).get("scope") or {})
    company_ref = getattr(bundle, "company_ref", None) or dict(bundle).get("company_ref")
    current = store.get(COMPANY_BUNDLE_ENGINE, COMPANY_BUNDLE_ENTITY)
    if current is None or not digest:
        return None
    state = dict(current["state"])
    if state.get("state_digest") == digest or dict(state.get("scope") or {}).get("project_id") != scope.get("project_id") or dict(state.get("bundle") or {}).get("company_ref") != company_ref:
        return None
    kept = store.get(COMPANY_BUNDLE_ENGINE, bundle_entity(digest))
    if kept is None or not 0 < int(dict(kept["state"]).get("bundle_version") or 0) < int(state["version"]):
        return None
    return {"version": int(state["version"]), "bundle_digest": str(state["state_digest"]), "bundle": load_company_bundle(store, project_id=scope.get("project_id"))}


def load_company_bundle(store: Any, *, project_id: str | None = None) -> dict[str, Any]:
    """The project's stored bundle, verified; ``LookupError`` when the project has none."""

    from lightbulb.company_cadence_runner import build_bundle

    current = store.get(COMPANY_BUNDLE_ENGINE, COMPANY_BUNDLE_ENTITY)
    if current is None:
        raise LookupError("this project holds no company bundle: propose one from the connected ledger and accept it")
    state = dict(current["state"])
    _require(state.get("schema") == COMPANY_BUNDLE_RECORD_SCHEMA, "BUNDLE_RECORD_INVALID", "the stored bundle record has an unknown shape")
    sealed = build_bundle(dict(state["bundle"]))
    _require(sealed.bundle_digest == state.get("state_digest"), "BUNDLE_RECORD_INVALID", "the stored bundle does not match its recorded digest")
    _require(project_id is None or sealed.scope.get("project_id") == project_id, "SCOPE_MISMATCH", "the stored bundle belongs to another project")
    return sealed.to_dict()


__all__ = [
    "BUNDLE_PROPOSAL_SCHEMA", "BUSINESS_MODELS", "COMPANY_BUNDLE_ENGINE", "COMPANY_BUNDLE_ENTITY", "COMPANY_BUNDLE_RECORD_SCHEMA", "CONNECTOR_UNLOCKS", "MODEL_ARCHETYPES", "ORGANISATION_TOOLS", "QUICKBOOKS_HOME_CURRENCIES",
    "BundleProposal", "CompanyBootstrapError", "ConnectorUnlock", "accept_bundle_proposal", "bundle_entity", "company_ref_from_name", "earlier_bundle_digests", "kept_bundle", "load_company_bundle", "persist_company_bundle", "propose_company_bundle", "superseding_bundle", "supported_jurisdictions", "verify_bundle_proposal",
]
