"""The price catalog: one replay-fenced catalog version per price change, from draft to published to superseded.

The deal desk priced from one price book and the SaaS blueprint carried
plan tiers, but no engine held the catalog as a thing with versions: which
prices were in force on a date, who approved a change, how much it moved,
when customers were told, and which version an account was still
grandfathered on.  ``PRICE_CATALOG_LIFECYCLE`` does:

    drafted -> approved -> published -> superseded    (terminal)
    drafted | approved | published -> withdrawn       (terminal, with a reason)

* ``draft_receipt`` opens a version from typed items; when a previous
  version is given (replayed, published) every increase and decrease is
  computed against it.
* ``approve`` consumes a ``pricing`` authority proof for the largest list
  price in the version; the approver is never the drafter.
* ``publish`` needs an effective date; when the version raises any price
  over the previous one, the effective date must give customers the
  plan's notice and the notice document's digest is retained.
* ``supersede`` consumes the replayed successor version once it is
  published with a later effective date.

``price_for`` answers what a reference cost on a date; ``tier_prices``
hands the SaaS blueprint its plan prices; ``price_change_notices`` lists
what customers must be told.  Nothing here changes a price anywhere,
messages anyone, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)

PRICE_CATALOG_KIND = "price_catalog"
PRICE_CATALOG_GOLDEN_LOOP = "commerce.price_book_to_published_prices@0.1.0"
PRICE_CATALOG_PLAN_SCHEMA = "lightbulb.price_catalog_plan.v1"
MAX_CATALOG_TRANSITIONS = 12
ItemKind = Literal["plan", "sku", "service", "rate"]
_HUNDRED = Decimal("100")

CATALOG_STATUSES: tuple[str, ...] = ("drafted", "approved", "published", "superseded", "withdrawn")
TERMINAL_CATALOG_STATUSES: frozenset[str] = frozenset({"superseded", "withdrawn"})
CATALOG_EVENTS: tuple[str, ...] = ("draft", "approve", "publish", "supersede", "withdraw")
_CATALOG_TABLE: dict[tuple[str, str], str] = {
    ("new", "draft"): "drafted",
    ("drafted", "approve"): "approved",
    ("approved", "publish"): "published",
    ("published", "supersede"): "superseded",
    ("drafted", "withdraw"): "withdrawn",
    ("approved", "withdraw"): "withdrawn",
    ("published", "withdraw"): "withdrawn",
}


class PriceCatalogError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PriceCatalogError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PriceCatalogPlan(StrictModel):
    """What the chain enforces: the catalog, its currency, the notice customers get before an increase, and grandfathering."""

    schema_id: str = Field(default=PRICE_CATALOG_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    catalog_ref: OpaqueRef
    notice_days_for_increase: int = Field(default=30, ge=0, le=365)
    grandfather_existing_accounts: bool = True
    max_increase_percent: Decimal | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_increase_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="max_increase_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PriceCatalogPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(PriceCatalogPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_price_catalog(company_ref: str, *, currency: str, catalog_ref: str, overrides: Mapping[str, Any] | None = None) -> PriceCatalogPlan:
    return seal(PriceCatalogPlan, {"company_ref": company_ref, "currency": str(currency).upper(), "catalog_ref": catalog_ref, **dict(overrides or {})}, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class PriceItem(StrictModel):
    item_ref: OpaqueRef
    kind: ItemKind
    unit: ShortText = "each"
    list_price: Decimal
    billing_period: Literal["once", "month", "year", "hour", "day"] = "once"

    @field_validator("list_price", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="list_price")
        if result < 0:
            raise ValueError("a list price is never negative")
        return result


class PriceChange(StrictModel):
    item_ref: OpaqueRef
    previous_price: Decimal | None = None
    new_price: Decimal
    change_percent: Decimal | None = None
    direction: Literal["increase", "decrease", "unchanged", "new", "removed"]

    @field_validator("previous_price", "new_price", "change_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class CatalogReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    version_ref: OpaqueRef | None = None
    items: tuple[PriceItem, ...] = Field(default_factory=tuple, max_length=500)
    drafter_ref: OpaqueRef | None = None
    previous_source: dict[str, Any] | None = None
    previous_plan: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    effective_from: str | None = None
    notice_sha256: Sha256Digest | None = None
    successor_source: dict[str, Any] | None = None
    successor_plan: dict[str, Any] | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "items", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("effective_from")
    @classmethod
    def _stamp(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="effective_from")


class CatalogLedger(StrictModel):
    catalog_ref: str | None = None
    version_ref: str | None = None
    items: tuple[PriceItem, ...] = Field(default_factory=tuple, max_length=500)
    drafter_ref: str | None = None
    drafted_at: str | None = None
    previous_version_ref: str | None = None
    previous_digest: str | None = None
    changes: tuple[PriceChange, ...] = Field(default_factory=tuple, max_length=600)
    increases: int = Field(default=0, ge=0)
    decreases: int = Field(default=0, ge=0)
    max_increase_percent: Decimal | None = None
    largest_list_price: Decimal = Field(default=Decimal("0"), validate_default=True)
    approved_at: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    published_at: str | None = None
    effective_from: str | None = None
    notice_sha256: str | None = None
    superseded_at: str | None = None
    successor_version_ref: str | None = None
    successor_digest: str | None = None
    withdraw_reason: str | None = None
    outcome: Literal["open", "superseded", "withdrawn"] = "open"

    @field_validator("items", "changes", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("largest_list_price", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="largest_list_price")

    @field_validator("max_increase_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="max_increase_percent", allow_negative=True)

    def price(self, item_ref: str) -> PriceItem | None:
        return next((item for item in self.items if item.item_ref == item_ref), None)


class CatalogEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    price_changed_at_provider: Literal[False] = False
    customer_notified: Literal[False] = False
    provider_read: Literal[False] = False


def _changes(previous: Sequence[PriceItem], current: Sequence[PriceItem]) -> list[PriceChange]:
    before = {item.item_ref: item for item in previous}
    after = {item.item_ref: item for item in current}
    out: list[PriceChange] = []
    for ref in sorted(set(before) | set(after)):
        old, new = before.get(ref), after.get(ref)
        if old is None and new is not None:
            out.append(PriceChange(item_ref=ref, new_price=new.list_price, direction="new"))
        elif new is None and old is not None:
            out.append(PriceChange(item_ref=ref, previous_price=old.list_price, new_price=Decimal("0"), direction="removed"))
        elif old is not None and new is not None:
            delta = _money(new.list_price - old.list_price)
            percent = None if old.list_price == 0 else (delta / old.list_price * _HUNDRED).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            direction = "increase" if delta > 0 else "decrease" if delta < 0 else "unchanged"
            out.append(PriceChange(item_ref=ref, previous_price=old.list_price, new_price=new.list_price, change_percent=percent, direction=direction))
    return out


def _bind_version(source: Mapping[str, Any] | None, plan_raw: Mapping[str, Any] | None, plan: PriceCatalogPlan, at: str, *, code: str) -> Any:
    require(source is not None and plan_raw is not None, code, "the other version must be the replayed catalog state and its plan")
    try:
        other_plan, other = PRICE_CATALOG_LIFECYCLE.bind(plan_raw, source)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, code, f"the version must replay against its exact plan: {exc}"[:300])
        raise AssertionError from exc
    require(other_plan.catalog_ref == plan.catalog_ref and other_plan.company_ref == plan.company_ref and other_plan.currency == plan.currency, "CATALOG_MISMATCH", "the other version belongs to another catalog, company, or currency")
    require(parsed(other.transition_history[-1].command.occurred_at) <= parsed(at), "VERSION_FROM_FUTURE", "the other version cannot come from the future")
    return other


def _apply_catalog(plan: PriceCatalogPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "draft":
        require(r.version_ref is not None and r.drafter_ref is not None and bool(r.items), "DRAFT_MISSING", "a version names itself, its drafter, and at least one priced item")
        unique([item.item_ref for item in r.items], label="catalog items")
        previous_items: list[PriceItem] = []
        if r.previous_source is not None or r.previous_plan is not None:
            previous = _bind_version(r.previous_source, r.previous_plan, plan, at, code="PREVIOUS_NOT_PROVEN")
            require(previous.status == "published", "PREVIOUS_NOT_PUBLISHED", f"the previous version is {previous.status}; a draft follows the published version")
            previous_items = list(previous.ledger.items)
            data.update({"previous_version_ref": previous.ledger.version_ref, "previous_digest": previous.state_digest})
        changes = _changes(previous_items, list(r.items)) if previous_items else []
        increases = [change for change in changes if change.direction == "increase"]
        max_increase = max((change.change_percent for change in increases if change.change_percent is not None), default=None)
        if plan.max_increase_percent is not None and max_increase is not None:
            require(max_increase <= plan.max_increase_percent, "INCREASE_ABOVE_PLAN", f"a {max_increase}% increase exceeds the plan's {plan.max_increase_percent}% ceiling", "await_approval")
        data.update({"catalog_ref": plan.catalog_ref, "version_ref": r.version_ref, "items": [item.to_dict() for item in r.items], "drafter_ref": r.drafter_ref, "drafted_at": at, "changes": [change.to_dict() for change in changes], "increases": len(increases), "decreases": sum(1 for change in changes if change.direction == "decrease"), "max_increase_percent": None if max_increase is None else str(max_increase), "largest_list_price": str(max(item.list_price for item in r.items))})
    elif event == "approve":
        require(r.authorization_proof is not None, "CATALOG_NOT_AUTHORIZED", f"publishing prices up to {data['largest_list_price']} {plan.currency} is a pricing decision; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof

        proof = require_authorization_proof(r.authorization_proof, category="pricing", amount=Decimal(str(data["largest_list_price"])), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
        require(proof.engine == PRICE_CATALOG_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        require(proof.approver_ref != data.get("drafter_ref"), "SEGREGATION_VIOLATED", "the drafter cannot approve their own prices")
        data.update({"approved_at": at, "approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref})
    elif event == "publish":
        require(r.effective_from is not None, "EFFECTIVE_DATE_MISSING", "a publication names the date the prices take effect")
        require(parsed(str(r.effective_from)) >= parsed(at), "EFFECTIVE_DATE_PAST", "prices take effect on or after publication, never retroactively")
        if int(data.get("increases", 0)) > 0 and data.get("previous_digest") is not None:
            notice = (parsed(str(r.effective_from)) - parsed(at)).days
            require(notice >= plan.notice_days_for_increase, "NOTICE_TOO_SHORT", f"an increase takes effect {notice} days after publication; the plan gives customers {plan.notice_days_for_increase} days")
            require(r.notice_sha256 is not None, "NOTICE_MISSING", "an increase publishes with the digest of the customer notice")
        data.update({"published_at": at, "effective_from": r.effective_from, "notice_sha256": r.notice_sha256})
    elif event == "supersede":
        successor = _bind_version(r.successor_source, r.successor_plan, plan, at, code="SUCCESSOR_NOT_PROVEN")
        require(successor.status == "published", "SUCCESSOR_NOT_PUBLISHED", f"the successor is {successor.status}")
        require(str(successor.ledger.previous_version_ref) == str(data.get("version_ref")), "SUCCESSOR_NOT_DESCENDED", "the successor was not drafted from this version")
        require(parsed(str(successor.ledger.effective_from)) > parsed(str(data["effective_from"])), "SUCCESSOR_NOT_LATER", "the successor takes effect after this version")
        data.update({"superseded_at": at, "successor_version_ref": successor.ledger.version_ref, "successor_digest": successor.state_digest, "outcome": "superseded"})
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    return next_status, data


PRICE_CATALOG_LIFECYCLE = LifecycleSpec(entity="price_catalog_version", schema_prefix=PRICE_CATALOG_KIND, statuses=CATALOG_STATUSES, terminal=TERMINAL_CATALOG_STATUSES, events=CATALOG_EVENTS, table=_CATALOG_TABLE, opening_event="draft", reason_events=("withdraw",), apply=_apply_catalog, ledger_model=CatalogLedger, receipt_model=CatalogReceipt, effect_boundary_model=CatalogEffectBoundary, plan_model=PriceCatalogPlan, max_transitions=MAX_CATALOG_TRANSITIONS)
PriceCatalogVersionState = PRICE_CATALOG_LIFECYCLE.State


def open_catalog_version(plan: PriceCatalogPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return PRICE_CATALOG_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_catalog_version(plan: PriceCatalogPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PRICE_CATALOG_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def draft_receipt(*, version_ref: str, drafter_ref: str, items: Sequence[Mapping[str, Any]], previous: Any = None, previous_plan: Any = None) -> dict[str, Any]:
    """The opening receipt: typed items, the drafter, and the replayed previous version when there is one."""

    parsed_items = [PriceItem.model_validate(dict(detached(item))).to_dict() for item in items]
    receipt: dict[str, Any] = {"version_ref": version_ref, "drafter_ref": drafter_ref, "items": parsed_items, "evidence_refs": [f"version:{version_ref}"]}
    if previous is not None:
        _require(previous_plan is not None, "PREVIOUS_NOT_PROVEN", "a previous version travels with its sealed plan")
        try:
            plan, state = PRICE_CATALOG_LIFECYCLE.bind(previous_plan, previous)
        except (ValueError, TypeError, KeyError) as exc:
            raise PriceCatalogError("PREVIOUS_NOT_PROVEN", "retain the original previous version and its sealed plan") from exc
        receipt.update({"previous_source": state.to_dict(), "previous_plan": plan.to_dict(), "evidence_refs": [*receipt["evidence_refs"], f"previous:{state.scope.entity_ref}:{state.state_digest[:16]}"]})
    return receipt


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def publication_receipt(*, effective_from: str, notice_sha256: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"effective_from": timestamp(effective_from, field_name="effective_from"), "evidence_refs": [f"effective:{effective_from}"]}
    if notice_sha256 is not None:
        receipt["notice_sha256"] = notice_sha256
        receipt["evidence_refs"].append(f"notice:{notice_sha256[:16]}")
    return receipt


def supersession_receipt(successor: Any, *, source_plan: Any) -> dict[str, Any]:
    try:
        plan, state = PRICE_CATALOG_LIFECYCLE.bind(source_plan, successor)
    except (ValueError, TypeError, KeyError) as exc:
        raise PriceCatalogError("SUCCESSOR_NOT_PROVEN", "retain the original successor version and its sealed plan") from exc
    _require(state.status == "published", "SUCCESSOR_NOT_PUBLISHED", f"the successor is {state.status}")
    return {"successor_source": state.to_dict(), "successor_plan": plan.to_dict(), "evidence_refs": [f"successor:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


# --------------------------------------------------------------------------- #
# What the catalog hands to the other engines
# --------------------------------------------------------------------------- #


def price_for(state: Any, *, source_plan: Any, item_ref: str, at: str) -> dict[str, Any]:
    """The list price an item carries on a date under this version: refused before the effective date or after supersession."""

    plan, bound = PRICE_CATALOG_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    stamp = timestamp(at, field_name="at")
    _require(bound.status in ("published", "superseded"), "VERSION_NOT_PUBLISHED", f"the version is {bound.status}")
    _require(parsed(str(ledger.effective_from)) <= parsed(stamp), "NOT_YET_EFFECTIVE", f"the version takes effect {ledger.effective_from}")
    item = ledger.price(item_ref)
    _require(item is not None, "ITEM_NOT_PRICED", f"{item_ref} is not in version {ledger.version_ref}")
    assert item is not None
    return {"item_ref": item_ref, "list_price": str(item.list_price), "currency": plan.currency, "unit": item.unit, "billing_period": item.billing_period, "version_ref": ledger.version_ref, "effective_from": ledger.effective_from, "superseded": bound.status == "superseded", "source_digest": bound.state_digest}


def tier_prices(state: Any, *, source_plan: Any) -> dict[str, str]:
    """Plan items as ``plan_ref -> monthly price``, the shape the SaaS blueprint's plans take."""

    _, bound = PRICE_CATALOG_LIFECYCLE.bind(source_plan, state)
    _require(bound.status in ("published", "superseded"), "VERSION_NOT_PUBLISHED", f"the version is {bound.status}")
    return {item.item_ref: str(item.list_price) for item in bound.ledger.items if item.kind == "plan"}


def price_change_notices(state: Any, *, source_plan: Any) -> list[dict[str, Any]]:
    """Every increase in this version against its predecessor, with the date customers must have been told by."""

    plan, bound = PRICE_CATALOG_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    if ledger.effective_from is None:
        return []
    notify_by = add_days(str(ledger.effective_from), -plan.notice_days_for_increase)
    return [{"item_ref": change.item_ref, "previous_price": str(change.previous_price), "new_price": str(change.new_price), "change_percent": None if change.change_percent is None else str(change.change_percent), "effective_from": ledger.effective_from, "notify_by": notify_by, "grandfathered_until_renewal": plan.grandfather_existing_accounts} for change in ledger.changes if change.direction == "increase"]


def draft_from_price_plan(price_plan: Mapping[str, Any] | Any, *, version_ref: str, drafter_ref: str, current: Any, current_plan: Any, item_refs: Sequence[str] | None = None) -> dict[str, Any]:
    """The opening receipt for the version that implements a sealed growth price plan: every named item (default all) moved by the plan's ratio, the previous version replayed, and the plan bound by digest.

    The growth engine plans a margin-guarded price move as a preregistered test; nothing published it. This draft
    stays a catalog transition: ``pricing`` authority still approves it by someone other than the drafter, and the
    notice period still runs for an increase. The price plan is not dispatchable by its planner, and it stays that
    way here; the plan's ratio is the only thing copied, and the receipt names the plan it came from.
    """

    from lightbulb.growth_profit import PricePlan

    plan = price_plan if isinstance(price_plan, PricePlan) else PricePlan.model_validate(dict(detached(price_plan)))
    _require(plan.dispatchable_by_planner is False, "PRICE_PLAN_DISPATCHABLE", "a price plan never dispatches itself; the catalog approves the version")
    try:
        catalog_plan, state = PRICE_CATALOG_LIFECYCLE.bind(current_plan, current)
    except (ValueError, TypeError, KeyError) as exc:
        raise PriceCatalogError("PREVIOUS_NOT_PROVEN", "retain the current version and its sealed plan") from exc
    _require(plan.currency == catalog_plan.currency, "PRICE_PLAN_CURRENCY_MISMATCH", f"the price plan moves {plan.currency} prices; the catalog is in {catalog_plan.currency}")
    ratio = plan.operation.price_change_ratio
    _require((ratio > 0) == (plan.operation.direction == "increase"), "PRICE_PLAN_INCOHERENT", "the plan's direction and ratio disagree")
    current_items = {item.item_ref: item for item in state.ledger.items}
    chosen = list(item_refs) if item_refs is not None else list(current_items)
    _require(bool(chosen), "PRICE_MOVE_EMPTY", "a price move names at least one item")
    unknown = [ref for ref in chosen if ref not in current_items]
    _require(not unknown, "ITEM_UNKNOWN", f"{', '.join(unknown)} not in version {state.ledger.version_ref}")
    items = []
    for item in state.ledger.items:
        raw = item.to_dict()
        if item.item_ref in chosen:
            raw["list_price"] = str((item.list_price * (Decimal("1") + ratio)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP))
        items.append(raw)
    receipt = draft_receipt(version_ref=version_ref, drafter_ref=drafter_ref, items=items, previous=state, previous_plan=catalog_plan)
    receipt["evidence_refs"] = [*receipt["evidence_refs"], f"price_plan:{plan.plan_digest[:16]}", f"price_move:{plan.operation.operation_ref}"]
    receipt["detail"] = f"implements price plan {plan.plan_ref} ({plan.objective}, {plan.operation.direction} {ratio}) on {len(chosen)} item(s)"
    return receipt


def catalog_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in CATALOG_STATUSES}
    published = [state for state in states if state.status == "published"]
    return {"versions": len(states), "by_status": counts, "in_force": [state.ledger.version_ref for state in published], "items_in_force": sum(len(state.ledger.items) for state in published), "increases_pending_notice": sum(state.ledger.increases for state in states if state.status in ("drafted", "approved"))}


PRICE_CATALOG_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PRICE_CATALOG_KIND,
    "golden_loop": PRICE_CATALOG_GOLDEN_LOOP,
    "stages": ["draft", "approve", "publish", "supersede"],
    "statuses": list(CATALOG_STATUSES),
    "events": list(CATALOG_EVENTS),
    "hops": {"draft": "typed items; changes computed against the replayed previous version", "approve": "pricing authority proof for the largest list price by someone other than the drafter", "publish": "an effective date on or after publication; increases need the plan's notice and the notice digest", "supersede": "the replayed successor, published, descended from this version, effective later"},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a price change is computed against the replayed previous version, never typed",
        "the drafter never approves their own prices",
        "an increase never takes effect before customers had the plan's notice, and never retroactively",
        "a version is superseded only by a published successor drafted from it",
    ],
}

__all__ = ["CATALOG_EVENTS", "CATALOG_STATUSES", "PRICE_CATALOG_GOLDEN_LOOP", "PRICE_CATALOG_KIND", "PRICE_CATALOG_LIFECYCLE", "PRICE_CATALOG_MANIFEST", "TERMINAL_CATALOG_STATUSES", "CatalogLedger", "CatalogReceipt", "PriceCatalogError", "PriceCatalogPlan", "PriceCatalogVersionState", "PriceChange", "PriceItem", "advance_catalog_version", "approval_receipt", "catalog_summary", "compile_price_catalog", "draft_from_price_plan", "draft_receipt", "open_catalog_version", "price_change_notices", "price_for", "publication_receipt", "supersession_receipt", "tier_prices"]
